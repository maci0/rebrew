# Rebrew Round-Trip Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `rebrew round-trip` — splice every matched (EXACT/RELOC) function's freshly-compiled bytes back into a copy of the original PE, hash the result against the original, exit non-zero on mismatch. Provides end-to-end ground truth that `rebrew verify`'s per-function comparison cannot.

**Architecture:** New CLI module `src/rebrew/round_trip.py` driving four stages: (1) enumerate matched functions via existing `iter_sources` / `iter_annotations` / `metadata`, (2) compile each via existing `compile_and_compare`, (3) apply COFF relocations and splice into a PE byte copy at the function's file offset, (4) hash + write reasm + report. Two helpers added — `core/matching.apply_coff_relocations` and `matcher/parsers.parse_obj_relocs_full` — to expose relocation type info that the existing `parse_obj_symbol_bytes` discards.

**Tech Stack:** Python 3.12+, Typer, LIEF (COFF + PE parsing), Rich, pytest, monkeypatch seam at `compile_and_compare`.

**Spec:** `docs/superpowers/specs/2026-05-20-rebrew-round-trip-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `src/rebrew/round_trip.py` | **Create** | CLI module, splice orchestration, reporting |
| `src/rebrew/matcher/parsers.py` | **Modify** | Add `parse_obj_relocs_full` returning type-aware reloc records |
| `src/rebrew/core/matching.py` | **Modify** | Add `apply_coff_relocations` + `UnresolvedSymbolError` |
| `src/rebrew/main.py` | **Modify** | Register `round_trip.app` under "Matching" panel |
| `pyproject.toml` | **Modify** | Add `rebrew-round-trip` script entry |
| `tests/test_parsers_relocs_full.py` | **Create** | Unit tests for `parse_obj_relocs_full` |
| `tests/test_apply_relocations.py` | **Create** | Unit tests for `apply_coff_relocations` |
| `tests/test_round_trip.py` | **Create** | End-to-end tests for the CLI module |
| `CLAUDE.md` | **Modify** | Add `round_trip.py` to module surface listing |
| `docs/CLI.md` | **Modify** | Document the new subcommand |

---

## Task 1: Reloc record dataclass + type-aware COFF parser

**Files:**
- Modify: `src/rebrew/matcher/parsers.py` (add `CoffRelocRecord` + `parse_obj_relocs_full`)
- Test: `tests/test_parsers_relocs_full.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_parsers_relocs_full.py
"""Tests for parse_obj_relocs_full: type-aware COFF relocation extraction."""

from pathlib import Path

import lief
import pytest

from rebrew.matcher.parsers import CoffRelocRecord, parse_obj_relocs_full


def _build_coff_with_one_dir32_reloc(tmp_path: Path) -> Path:
    """Drop a real MSVC-style COFF .obj on disk containing one DIR32 reloc.

    We bake the bytes directly because lief.COFF doesn't have a builder; the
    layout below is the minimum a LIEF parse will accept:
        - File header (machine=I386, 1 section, 2 symbols, no opt header)
        - One .text section, 8 bytes of code, 1 relocation entry
        - String table with the external symbol name "_extern_var"
    """
    obj = tmp_path / "fixture.obj"
    # Minimal handcrafted COFF — see Microsoft PE/COFF spec.
    # 20-byte file header
    code = b"\x90\x90\xa1\x00\x00\x00\x00\xc3"  # nop;nop; mov eax,[0]; ret
    # ... (full bytes elided here for brevity; see helper below)
    obj.write_bytes(_make_coff_blob(code, reloc_offset=2, reloc_type=0x0006, sym="_extern_var"))
    return obj


def test_parse_obj_relocs_full_returns_typed_records(tmp_path: Path) -> None:
    obj = _build_coff_with_one_dir32_reloc(tmp_path)
    records = parse_obj_relocs_full(obj, "_myfunc")
    assert len(records) == 1
    r = records[0]
    assert isinstance(r, CoffRelocRecord)
    assert r.offset == 2
    assert r.type == 0x0006  # IMAGE_REL_I386_DIR32
    assert r.symbol == "_extern_var"


def test_parse_obj_relocs_full_unknown_symbol_returns_empty(tmp_path: Path) -> None:
    obj = _build_coff_with_one_dir32_reloc(tmp_path)
    assert parse_obj_relocs_full(obj, "_does_not_exist") == []
```

The full `_make_coff_blob` helper is ~60 lines of `struct.pack` — write it in the same file as a private helper. Reference: Microsoft PE/COFF Specification §4 (File Header), §5 (Section Headers), §6 (Symbol Table), §7 (COFF Relocations).

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_parsers_relocs_full.py -v
```
Expected: FAIL — `ImportError: cannot import name 'CoffRelocRecord'`.

- [ ] **Step 3: Implement `CoffRelocRecord` + `parse_obj_relocs_full`**

Add to `src/rebrew/matcher/parsers.py` (near top, below `_collect_reloc_offsets`):

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class CoffRelocRecord:
    """One COFF relocation entry with its IMAGE_REL_I386_* type preserved."""

    offset: int      # byte offset inside the function's .text slice
    type: int        # IMAGE_REL_I386_* (0x06=DIR32, 0x14=REL32, ...)
    symbol: str      # target symbol name (with leading underscore on MSVC)


def parse_obj_relocs_full(obj_path: str | Path, symbol: str) -> list[CoffRelocRecord]:
    """Extract type-aware relocation records for ``symbol`` from a COFF .obj.

    Unlike ``parse_obj_symbol_bytes``, this preserves the IMAGE_REL_I386_*
    type so callers can apply (not just mask) relocations.
    """
    import lief

    coff = lief.COFF.parse(str(obj_path))
    if coff is None:
        return []

    target_sym = next(
        (s for s in coff.symbols if s.name == symbol and s.section is not None),
        None,
    )
    if target_sym is None:
        return []

    section = target_sym.section
    func_start = target_sym.value
    sec_offsets = sorted(
        s.value
        for s in coff.symbols
        if s.section is not None
        and s.section.name == section.name
        and not str(s.name).startswith("$")
    )
    func_end = len(bytes(section.content))
    idx = bisect.bisect_right(sec_offsets, func_start)
    if idx < len(sec_offsets):
        func_end = sec_offsets[idx]

    records: list[CoffRelocRecord] = []
    for r in section.relocations:
        rva = r.address
        if func_start <= rva < func_end:
            records.append(
                CoffRelocRecord(
                    offset=rva - func_start,
                    type=int(r.type),
                    symbol=_extract_reloc_name(r),
                )
            )
    return records
```

- [ ] **Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_parsers_relocs_full.py -v
```
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add src/rebrew/matcher/parsers.py tests/test_parsers_relocs_full.py
git commit -m "feat(parsers): type-aware COFF reloc extraction for round-trip"
```

---

## Task 2: `apply_coff_relocations` — patch .text bytes

**Files:**
- Modify: `src/rebrew/core/matching.py`
- Test: `tests/test_apply_relocations.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_apply_relocations.py
"""Tests for apply_coff_relocations."""

import struct

import pytest

from rebrew.core.matching import UnresolvedSymbolError, apply_coff_relocations
from rebrew.matcher.parsers import CoffRelocRecord


def _resolve(sym: str) -> int | None:
    return {"_g_var": 0x10025000, "_other_func": 0x10001500}.get(sym)


def test_dir32_writes_absolute_va() -> None:
    text = bytearray(b"\xa1\x00\x00\x00\x00\xc3")  # mov eax,[0]; ret
    relocs = [CoffRelocRecord(offset=1, type=0x0006, symbol="_g_var")]
    patched = apply_coff_relocations(
        bytes(text), relocs, _resolve, image_base=0x10000000, section_va=0x10001000
    )
    assert struct.unpack("<I", patched[1:5])[0] == 0x10025000


def test_rel32_writes_pc_relative_displacement() -> None:
    text = bytearray(b"\xe8\x00\x00\x00\x00")  # call <offset>
    # Function at section_va=0x10001000, reloc at offset 1, call target at
    # _other_func=0x10001500. Displacement = target - (section_va + offset + 4).
    relocs = [CoffRelocRecord(offset=1, type=0x0014, symbol="_other_func")]
    patched = apply_coff_relocations(
        bytes(text), relocs, _resolve, image_base=0x10000000, section_va=0x10001000
    )
    disp = struct.unpack("<i", patched[1:5])[0]
    assert disp == 0x10001500 - (0x10001000 + 1 + 4)


def test_unresolved_symbol_raises() -> None:
    text = bytearray(b"\xa1\x00\x00\x00\x00\xc3")
    relocs = [CoffRelocRecord(offset=1, type=0x0006, symbol="_undefined_thing")]
    with pytest.raises(UnresolvedSymbolError) as excinfo:
        apply_coff_relocations(
            bytes(text), relocs, _resolve, image_base=0x10000000, section_va=0x10001000
        )
    assert "_undefined_thing" in str(excinfo.value)


def test_unsupported_reloc_type_raises() -> None:
    text = bytearray(b"\xa1\x00\x00\x00\x00\xc3")
    relocs = [CoffRelocRecord(offset=1, type=0x0099, symbol="_g_var")]  # bogus type
    with pytest.raises(NotImplementedError):
        apply_coff_relocations(
            bytes(text), relocs, _resolve, image_base=0x10000000, section_va=0x10001000
        )
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_apply_relocations.py -v
```
Expected: FAIL — `ImportError: cannot import name 'apply_coff_relocations'`.

- [ ] **Step 3: Implement `apply_coff_relocations`**

Add to `src/rebrew/core/matching.py`:

```python
from collections.abc import Callable

from rebrew.matcher.parsers import CoffRelocRecord

# IMAGE_REL_I386_*
_REL_DIR32 = 0x0006
_REL_REL32 = 0x0014


class UnresolvedSymbolError(Exception):
    """Raised when a relocation references a symbol with no VA in the catalog."""

    def __init__(self, symbol: str) -> None:
        super().__init__(symbol)
        self.symbol = symbol


def apply_coff_relocations(
    text: bytes,
    relocs: list[CoffRelocRecord],
    resolve_va: Callable[[str], int | None],
    *,
    image_base: int,
    section_va: int,
) -> bytes:
    """Apply COFF relocations to a .text byte blob.

    For each relocation, read the addend at ``relocs[i].offset``, resolve the
    target VA via ``resolve_va(symbol)``, compute the patched value per the
    relocation type, and write it back as little-endian 32-bit.

    :param text: Raw bytes for a single function as compiled.
    :param relocs: Relocation records from ``parse_obj_relocs_full``.
    :param resolve_va: Callable mapping symbol → absolute VA (None if unknown).
    :param image_base: PE ImageBase (e.g. 0x10000000 for an MSVC6 DLL).
    :param section_va: VA of the function's start (used for REL32 PC-relative arithmetic).

    :raises UnresolvedSymbolError: Symbol not in the catalog.
    :raises NotImplementedError: Unsupported relocation type.
    """
    buf = bytearray(text)
    for r in relocs:
        sym = r.symbol.lstrip("_") if r.symbol.startswith("_") else r.symbol
        target_va = resolve_va(r.symbol) or resolve_va(sym)
        if target_va is None:
            raise UnresolvedSymbolError(r.symbol)

        addend = struct.unpack_from("<I", buf, r.offset)[0]
        if r.type == _REL_DIR32:
            value = (target_va + addend) & 0xFFFFFFFF
        elif r.type == _REL_REL32:
            pc = section_va + r.offset + 4
            value = (target_va + addend - pc) & 0xFFFFFFFF
        else:
            raise NotImplementedError(f"IMAGE_REL_I386_* type 0x{r.type:04x} not supported")

        struct.pack_into("<I", buf, r.offset, value)

    return bytes(buf)
```

- [ ] **Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_apply_relocations.py -v
```
Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add src/rebrew/core/matching.py tests/test_apply_relocations.py
git commit -m "feat(matching): apply_coff_relocations for round-trip splice"
```

---

## Task 3: VA resolver — compose function catalog + data metadata

**Files:**
- Modify: `src/rebrew/core/matching.py` (or create new module — see step 3)
- Test: extended `tests/test_apply_relocations.py` (no new file)

- [ ] **Step 1: Write the failing test**

```python
# Append to tests/test_apply_relocations.py
from types import SimpleNamespace

from rebrew.core.matching import build_symbol_resolver


def test_build_symbol_resolver_unions_funcs_and_data(tmp_path) -> None:
    funcs = {0x10001000: "DoThing", 0x10001500: "OtherFunc"}
    data = {"g_var": 0x10025000, "g_table": 0x10026000}
    resolve = build_symbol_resolver(funcs, data)

    assert resolve("DoThing") == 0x10001000
    assert resolve("_DoThing") == 0x10001000          # MSVC underscore prefix tolerated
    assert resolve("g_var") == 0x10025000
    assert resolve("does_not_exist") is None


def test_build_symbol_resolver_function_wins_on_collision() -> None:
    # If both maps have the same key (rare but possible), function VA wins —
    # data labels can shadow function names but never the other way.
    funcs = {0x10001000: "shared"}
    data = {"shared": 0x10025000}
    resolve = build_symbol_resolver(funcs, data)
    assert resolve("shared") == 0x10001000
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_apply_relocations.py::test_build_symbol_resolver_unions_funcs_and_data -v
```
Expected: FAIL — `ImportError: cannot import name 'build_symbol_resolver'`.

- [ ] **Step 3: Implement `build_symbol_resolver`**

Add to `src/rebrew/core/matching.py`:

```python
def build_symbol_resolver(
    funcs_by_va: dict[int, str],
    data_by_name: dict[str, int],
) -> Callable[[str], int | None]:
    """Compose a symbol → VA resolver from the function catalog + data metadata.

    Function names win on collision: a data label can never shadow a function
    name (caught in lint elsewhere). MSVC-style leading underscores in the
    caller's query are stripped on lookup.
    """
    by_name = {name: va for va, name in funcs_by_va.items()}

    def resolve(symbol: str) -> int | None:
        candidates = (symbol, symbol.lstrip("_") if symbol.startswith("_") else symbol)
        for s in candidates:
            if s in by_name:
                return by_name[s]
            if s in data_by_name:
                return data_by_name[s]
        return None

    return resolve
```

- [ ] **Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_apply_relocations.py -v
```
Expected: PASS, 6 tests total.

- [ ] **Step 5: Commit**

```bash
git add src/rebrew/core/matching.py tests/test_apply_relocations.py
git commit -m "feat(matching): build_symbol_resolver composing funcs + data catalogs"
```

---

## Task 4: CLI skeleton — `round_trip.py` argument surface

**Files:**
- Create: `src/rebrew/round_trip.py`
- Test: `tests/test_round_trip.py` (create — argument/help tests only here)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_round_trip.py
"""End-to-end tests for the rebrew round-trip CLI."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.round_trip import app


runner = CliRunner()


class TestRoundTripCli:
    def test_help_lists_required_flags(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        for flag in ("--json", "--out", "--no-write", "--filter", "--target"):
            assert flag in result.stdout

    def test_no_config_errors_cleanly(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["--json"])
        # require_config raises typer.Exit; treat any non-zero as success here.
        assert result.exit_code != 0
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_round_trip.py -v
```
Expected: FAIL — `ModuleNotFoundError: rebrew.round_trip`.

- [ ] **Step 3: Implement the CLI skeleton**

Create `src/rebrew/round_trip.py`:

```python
"""``rebrew round-trip`` — splice matched function bytes back into the target PE.

Pipeline: enumerate every EXACT/RELOC function from rebrew-function.toml,
compile each via the existing compile_and_compare path, apply COFF relocations
against the active target's function + data catalogs, splice the patched
bytes into a byte copy of the original PE at each function's file offset,
SHA-256 the result, write ``<binary>.reasm`` next to the original, exit
non-zero on any unexpected byte mismatch.

PROVEN functions are deliberately skipped — their bytes differ from the
original by design (semantic equivalence, not byte equivalence) — and are
reported as ``skipped_proven`` without altering the spliced PE.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import (
    EXIT_ERROR,
    EXIT_MISMATCH,
    EXIT_OK,
    TargetOption,
    error_exit,
    json_print,
    require_config,
)

console = Console(stderr=True)

app = typer.Typer(
    help="Splice every matched function back into the target PE and verify byte equality.",
    rich_markup_mode="rich",
)


@app.callback(invoke_without_command=True)
def main(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    out: Path | None = typer.Option(
        None, "--out", help="Override output PE path (default: <binary>.reasm next to target)"
    ),
    no_write: bool = typer.Option(
        False, "--no-write", help="Skip writing the reassembled PE; still emit the report"
    ),
    symbol_filter: str | None = typer.Option(
        None, "--filter", help="Only round-trip functions whose symbol contains this substring"
    ),
    target: str | None = TargetOption,
) -> None:
    cfg = require_config(target=target)
    raise typer.Exit(_run_round_trip(cfg, out=out, no_write=no_write,
                                     symbol_filter=symbol_filter, json_output=json_output))


def _run_round_trip(
    cfg, *, out: Path | None, no_write: bool, symbol_filter: str | None, json_output: bool
) -> int:
    """Top-level orchestration. Returns the process exit code."""
    # Placeholder — filled in Task 5.
    if json_output:
        json_print({"target": cfg.target, "spliced": 0, "match": True, "stub": True})
    return EXIT_OK


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
```

- [ ] **Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_round_trip.py -v
```
Expected: PASS, 2 tests.

- [ ] **Step 5: Commit**

```bash
git add src/rebrew/round_trip.py tests/test_round_trip.py
git commit -m "feat(round_trip): CLI skeleton + arg surface"
```

---

## Task 5: Splice pipeline — wire compile + apply + patch + hash

**Files:**
- Modify: `src/rebrew/round_trip.py`
- Test: append to `tests/test_round_trip.py`

- [ ] **Step 1: Write the failing test**

```python
# Append to tests/test_round_trip.py
from types import SimpleNamespace
from unittest.mock import MagicMock

from rebrew.round_trip import _run_round_trip


def _make_fake_cfg(tmp_path: Path) -> SimpleNamespace:
    """Minimal ProjectConfig stand-in for round-trip tests."""
    binary = tmp_path / "fake.dll"
    # 1 KiB blob with one function at offset 0x100 starting with NOPs.
    binary.write_bytes(b"\x00" * 0x100 + b"\x90\x90\x90\x90\xc3" + b"\x00" * 0xfb)
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    return SimpleNamespace(
        target="FAKE",
        binary=binary,
        source_dir=src_dir,
        metadata_dir=tmp_path,
        image_base=0x10000000,
    )


class TestSplicePipeline:
    def test_empty_project_round_trip_is_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No matched functions → reasm == original → exit 0."""
        cfg = _make_fake_cfg(tmp_path)
        # Stub the enumeration step to return zero functions.
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([], []))

        code = _run_round_trip(cfg, out=None, no_write=True, symbol_filter=None, json_output=False)
        assert code == EXIT_OK

    def test_compile_drift_marks_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A function in the splice set whose compile result fails to match
        the target bytes must be reported and exit 1."""
        cfg = _make_fake_cfg(tmp_path)
        fn = SimpleNamespace(
            symbol="_myfunc", va=0x10000100, size=5, status="EXACT",
            path=cfg.source_dir / "myfunc.c",
        )
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], []))
        # Compile produces bytes that DON'T match the original (different ret encoding).
        fake_result = SimpleNamespace(
            matched=False, status="MISMATCH",
            obj_bytes=b"", text_bytes=b"\xc3" * 5,
        )
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn: (fake_result, b"\xc3" * 5, []),
        )

        code = _run_round_trip(cfg, out=None, no_write=True, symbol_filter=None, json_output=False)
        assert code == EXIT_MISMATCH

    def test_clean_round_trip_writes_reasm(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Identical compile bytes → reasm hash == original hash → exit 0 and reasm file written."""
        cfg = _make_fake_cfg(tmp_path)
        fn = SimpleNamespace(
            symbol="_myfunc", va=0x10000100, size=5, status="EXACT",
            path=cfg.source_dir / "myfunc.c",
        )
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], []))
        # Identical bytes — splice should be a no-op at the byte level.
        original_slice = cfg.binary.read_bytes()[0x100:0x105]
        fake_result = SimpleNamespace(matched=True, status="EXACT")
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn: (fake_result, original_slice, []),
        )
        # File-offset resolver returns 0x100 for our fake VA.
        monkeypatch.setattr("rebrew.round_trip._va_to_offset", lambda cfg, va: 0x100)

        out = tmp_path / "fake.reasm"
        code = _run_round_trip(cfg, out=out, no_write=False, symbol_filter=None, json_output=False)
        assert code == EXIT_OK
        assert out.exists()
        assert out.read_bytes() == cfg.binary.read_bytes()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
uv run pytest tests/test_round_trip.py::TestSplicePipeline -v
```
Expected: FAIL — internals (`_collect_splice_set`, `_compile_and_extract`, `_va_to_offset`) don't exist.

- [ ] **Step 3: Wire the splice pipeline**

Replace the `_run_round_trip` body in `src/rebrew/round_trip.py`:

```python
from dataclasses import dataclass

from rebrew.binary_loader import load_binary, va_to_file_offset
from rebrew.cli import iter_annotations, iter_sources
from rebrew.compile import compile_and_compare
from rebrew.core.matching import (
    UnresolvedSymbolError,
    apply_coff_relocations,
    build_symbol_resolver,
)
from rebrew.matcher.parsers import parse_obj_relocs_full
from rebrew.metadata import read_function_metadata  # canonical reader from metadata.py


@dataclass
class _SpliceFn:
    symbol: str
    va: int
    size: int
    status: str
    path: Path


def _collect_splice_set(cfg, symbol_filter: str | None) -> tuple[list[_SpliceFn], list[_SpliceFn]]:
    """Walk every annotated function, partition into splice set and PROVEN-skip set."""
    splice: list[_SpliceFn] = []
    proven: list[_SpliceFn] = []
    for path, annotations in iter_annotations(iter_sources(cfg.source_dir, cfg), target=cfg.target):
        for ann in annotations:
            if symbol_filter and symbol_filter not in ann.symbol:
                continue
            md = read_function_metadata(cfg.metadata_dir, ann.module, ann.va)
            status = md.get("status", "STUB")
            fn = _SpliceFn(symbol=ann.symbol, va=ann.va,
                          size=md.get("size", 0), status=status, path=path)
            if status in ("EXACT", "RELOC"):
                splice.append(fn)
            elif status == "PROVEN":
                proven.append(fn)
    return splice, proven


def _compile_and_extract(cfg, fn: _SpliceFn):
    """Compile fn.path, return (CompareResult, function .text bytes, reloc records)."""
    result = compile_and_compare(fn.path, cfg)
    if not result.matched:
        return result, b"", []
    text, _ = result.obj_text_and_relocs        # canonical (text_bytes, reloc_dict) tuple
    relocs = parse_obj_relocs_full(result.obj_path, fn.symbol)
    return result, text, relocs


def _va_to_offset(cfg, va: int) -> int:
    info = load_binary(cfg.binary)
    return va_to_file_offset(info, va)


def _run_round_trip(cfg, *, out, no_write, symbol_filter, json_output) -> int:
    try:
        original = cfg.binary.read_bytes()
    except FileNotFoundError:
        error_exit(f"target binary missing: {cfg.binary}", json_mode=json_output)

    reasm = bytearray(original)
    mismatches: list[dict] = []

    splice_set, proven_set = _collect_splice_set(cfg, symbol_filter)

    # Build the VA resolver once — same for every function.
    funcs_by_va, data_by_name = _load_catalogs(cfg)
    resolve_va = build_symbol_resolver(funcs_by_va, data_by_name)

    for fn in splice_set:
        result, text, relocs = _compile_and_extract(cfg, fn)
        if not result.matched:
            mismatches.append(_mismatch(fn, "compile_drift", None))
            continue
        try:
            patched = apply_coff_relocations(
                text, relocs, resolve_va,
                image_base=cfg.image_base, section_va=fn.va,
            )
        except UnresolvedSymbolError as exc:
            mismatches.append(_mismatch(fn, "unresolved_symbol", exc.symbol))
            continue
        except NotImplementedError as exc:
            mismatches.append(_mismatch(fn, "reloc_application_failed", str(exc)))
            continue
        try:
            offset = _va_to_offset(cfg, fn.va)
        except ValueError:
            mismatches.append(_mismatch(fn, "rva_out_of_range", None))
            continue
        end = offset + fn.size
        if end > len(reasm) or len(patched) < fn.size:
            mismatches.append(_mismatch(fn, "oversize", None))
            continue
        reasm[offset:end] = patched[: fn.size]

    sha_original = hashlib.sha256(bytes(original)).hexdigest()
    sha_reasm = hashlib.sha256(bytes(reasm)).hexdigest()
    match = not mismatches and sha_original == sha_reasm

    out_path = out or cfg.binary.with_suffix(cfg.binary.suffix + ".reasm")
    if not no_write:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(bytes(reasm))

    report = {
        "target": cfg.target,
        "binary": str(cfg.binary),
        "out": str(out_path) if not no_write else None,
        "sha256_original": sha_original,
        "sha256_reasm": sha_reasm,
        "match": match,
        "spliced": len(splice_set) - len(mismatches),
        "skipped_proven": len(proven_set),
        "skipped_other": 0,
        "mismatches": mismatches,
    }
    if json_output:
        json_print(report)
    else:
        _render_rich(report)

    return EXIT_OK if match else EXIT_MISMATCH


def _mismatch(fn: _SpliceFn, reason: str, detail: str | None) -> dict:
    return {
        "symbol": fn.symbol,
        "va": f"0x{fn.va:08x}",
        "status": fn.status,
        "reason": reason,
        "detail": detail,
    }


def _load_catalogs(cfg) -> tuple[dict[int, str], dict[str, int]]:
    """Function catalog (VA → name) + union of every rebrew-data.toml (name → VA)."""
    from rebrew.catalog.registry import build_function_registry
    from rebrew.data_metadata import load_data_metadata

    funcs: dict[int, str] = {
        e["va"]: e["name"]
        for e in build_function_registry(cfg).values()
        if "va" in e and "name" in e
    }
    data: dict[str, int] = {}
    for path, _ in iter_annotations(iter_sources(cfg.source_dir, cfg), target=cfg.target):
        for (mod, va), meta in load_data_metadata(path.parent).items():
            if mod == cfg.target and "name" in meta:
                data[meta["name"]] = va
    return funcs, data


def _render_rich(report: dict) -> None:
    """Compact Rich summary mirroring `rebrew verify --summary`."""
    if report["match"]:
        console.print(
            f"[bold green]✔[/] round-trip clean: "
            f"{report['spliced']} functions spliced, "
            f"{report['skipped_proven']} PROVEN skipped"
        )
        return
    console.print(f"[bold red]✗[/] {len(report['mismatches'])} unexpected mismatches")
    for m in report["mismatches"]:
        console.print(f"  [yellow]{m['symbol']}[/] @ {m['va']} → {m['reason']}"
                      + (f" ({m['detail']})" if m.get("detail") else ""))
```

> **Implementation note:** `CompareResult.obj_text_and_relocs` and `read_function_metadata` may not exist under those exact names. Match the canonical readers in `rebrew/compile.py` and `rebrew/metadata.py` respectively — adjust imports during this step. If the function bytes are not exposed by `CompareResult`, call `parse_obj_symbol_bytes(result.obj_path, fn.symbol)` directly to get them.

- [ ] **Step 4: Run test to verify it passes**

```bash
uv run pytest tests/test_round_trip.py -v
```
Expected: PASS, 5 tests total (2 from Task 4 + 3 from Task 5).

- [ ] **Step 5: Commit**

```bash
git add src/rebrew/round_trip.py tests/test_round_trip.py
git commit -m "feat(round_trip): splice pipeline (compile + apply relocs + hash)"
```

---

## Task 6: Register the subcommand

**Files:**
- Modify: `src/rebrew/main.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: Add to `main.py` under the Matching panel**

Find the `app.add_typer(...)` block where `diff`, `prove`, etc. are registered. Add:

```python
from rebrew import round_trip as round_trip_mod
app.add_typer(round_trip_mod.app, name="round-trip", rich_help_panel="Matching")
```

- [ ] **Step 2: Add the script entry to `pyproject.toml`**

Under `[project.scripts]`:

```toml
rebrew-round-trip = "rebrew.round_trip:main_entry"
```

- [ ] **Step 3: Reinstall and smoke-test**

```bash
uv pip install -e .
uv run rebrew round-trip --help
uv run rebrew-round-trip --help
```
Expected: both print the usage block listing `--json`, `--out`, `--no-write`, `--filter`, `--target`.

- [ ] **Step 4: Run full test suite**

```bash
uv run pytest tests/ -q
```
Expected: PASS, no regressions.

- [ ] **Step 5: Commit**

```bash
git add src/rebrew/main.py pyproject.toml
git commit -m "feat(cli): wire rebrew round-trip subcommand"
```

---

## Task 7: Documentation surface

**Files:**
- Modify: `CLAUDE.md` (module surface listing)
- Modify: `docs/CLI.md`
- Modify: `src/rebrew/agent-skills/rebrew-matching/SKILL.md`

- [ ] **Step 1: `CLAUDE.md` — add `round_trip.py` to the file listing**

Find the block under `## Project Structure` that lists `# --- CLI tools ...`. Add (alphabetical-ish position):

```
├── round_trip.py        # Splice matched functions back into PE, verify byte equality
```

- [ ] **Step 2: `docs/CLI.md` — add a new section**

Append a section mirroring the existing `verify` / `prove` style:

```markdown
## `rebrew round-trip`

End-to-end correctness check: splice every EXACT/RELOC function's freshly
compiled bytes back into a copy of the target PE and verify byte equality.

```bash
rebrew round-trip                       # splice + write reasm + exit 1 on mismatch
rebrew round-trip --json                # machine-readable report
rebrew round-trip --out path/to/file    # override output PE path
rebrew round-trip --no-write            # in-memory only
rebrew round-trip --filter SUBSTR       # restrict to matching symbols
```

Catches relocation-application bugs and padding regressions that per-function
`rebrew verify` cannot expose. PROVEN functions are deliberately skipped.
```

- [ ] **Step 3: Add to the matching skill quick-reference**

In `src/rebrew/agent-skills/rebrew-matching/SKILL.md`, append a short section before the prove section:

```markdown
## 9. End-to-End Round-Trip

After `rebrew verify` reports all EXACT/RELOC, run round-trip to confirm
the matches actually splice back into a byte-identical PE:

\`\`\`bash
rebrew round-trip --json
\`\`\`

Exit 1 if anything mismatches. Use this in CI alongside `verify --compare`.
```

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md docs/CLI.md src/rebrew/agent-skills/rebrew-matching/SKILL.md
git commit -m "docs: surface rebrew round-trip in CLAUDE.md, CLI.md, matching skill"
```

---

## Task 8: Lint + format pass

- [ ] **Step 1: Lint**

```bash
uv run ruff check --fix src/ tests/
uv run ruff format src/ tests/
```

- [ ] **Step 2: Full test sweep**

```bash
uv run pytest tests/ -q
```
Expected: PASS, no skips besides the pre-existing optional-dep skips.

- [ ] **Step 3: Pre-commit on the whole tree**

```bash
uv run pre-commit run --all-files
```

- [ ] **Step 4: Commit any whitespace / lint touchups (if anything changed)**

```bash
git add -u
git commit -m "chore: ruff + pre-commit pass after round-trip"
```

---

## Out of Scope (defer to follow-ups)

- Parallel compile-and-splice (`-j N`)
- `--strict-padding` mode
- Round-trip surfaced in `rebrew status`
- Linking-based reassembly (the full splat approach)
