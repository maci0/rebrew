# Rebrew Round-Trip Design

**Date:** 2026-05-20
**Status:** Draft
**Owner:** maci

## Motivation

`rebrew verify` proves, per function, that the compiled `.obj` produces the
same bytes as the target binary's function (with relocation masking). It does
not actually patch those bytes into a binary and check the result.

The splat project's `add-win32-platform` branch demonstrates a different and
stronger signal: split a PE into pieces, reassemble it, and confirm the
output is byte-identical to the input. That round-trip caught reassembly
bugs that per-piece comparison missed — relocation application errors, file
alignment drift, padding overlap.

Rebrew should provide an analogous "ground truth" check: take every
function we believe is matched, splice the freshly-compiled bytes back into
a copy of the original PE at the right file offset, and verify the result
is byte-identical to the original. If anything mismatches, our matching
infrastructure is lying somewhere.

## Goals

1. Provide an end-to-end correctness check for the full match pipeline:
   compiler invocation, COFF parsing, relocation handling, padding trim,
   STATUS bookkeeping.
2. Produce a reassembled PE on disk so failures can be inspected with
   external tools (`xxd`, `radare2`, `diffoscope`).
3. Be CI-suitable: deterministic, exit code 1 on any unexpected mismatch.

## Non-Goals

- Full link-from-source à la splat. Rebrew does not own the linker, section
  layout, or import table generation. Round-trip works at the splice
  granularity only.
- Round-tripping `NEAR_MATCHING` / `STUB` functions. They have deltas by
  definition and would always fail.
- Cross-target round-trip. One target per invocation, like `verify`.

## User Surface

New CLI command:

```bash
rebrew round-trip                       # splice + hash + write reasm; exit 1 on mismatch
rebrew round-trip --json                # machine-readable report
rebrew round-trip --out path/to/file    # override default <binary>.reasm path
rebrew round-trip --no-write            # in-memory only; report still emitted
rebrew round-trip --filter SUBSTR       # only round-trip functions matching symbol substring
rebrew round-trip --target NAME         # standard TargetOption
```

Follows the established CLI tool pattern (see `src/rebrew/cli.py`):
- `TargetOption` + `require_config(target=...)`
- `Console(stderr=True)` for status output, raw `print` reserved for piped data
- `EXIT_OK` (0) when reasm matches, `EXIT_MISMATCH` (1) on any unexpected
  byte difference, `EXIT_ERROR` (2) on infrastructure failure
- `--json` flag emits structured output via `json_print(...)`
- `error_exit(msg, json_mode=json_output)` for fatal errors

## Splice Policy

The set of functions whose bytes get re-patched is partitioned three ways:

| STATUS | Action | Rationale |
|--------|--------|-----------|
| `EXACT` | Splice compiled bytes | Should be byte-identical by definition. |
| `RELOC` | Splice compiled bytes after applying relocations | Exercises reloc-application code path; this is the novel signal. |
| `PROVEN` | Skip (leave original bytes in place); report as `skipped_proven` | PROVEN means semantic equivalence with *different* bytes (reg alloc, instruction order). Splicing would guarantee mismatch by design. |
| `NEAR_MATCHING`, `STUB`, missing, etc. | Untouched | Out of scope. |

The `LIBRARY` status (CRT-source-derived) is treated the same as its
underlying STATUS (EXACT/RELOC/PROVEN/etc.).

## Pipeline

```
1. Load original PE
   bytes_orig = Path(target.binary).read_bytes()
   pe         = lief.parse(target.binary)         # section table only

2. Enumerate functions
   for path, annotations in iter_annotations(iter_sources(cfg), target=cfg.target):
       md = metadata.read(cfg.metadata_dir, module, va)
       if md.status not in {EXACT, RELOC, PROVEN}: continue
       record fn(path, va, size, status, symbol)

3. Compile + splice
   bytes_reasm = bytearray(bytes_orig)
   for fn in splice_set:
       result = compile_and_compare(fn.path, cfg)   # reuses cache
       if not result.matched: record_failure(fn, "compile_drift"); continue

       text_bytes, reloc_records, symbol_table = parse_coff(result.obj_bytes)
       patched_text = apply_coff_relocations(
           text_bytes,
           reloc_records,
           resolve_va = catalog_va_resolver(cfg),
       )

       offset = rva_to_file_offset(pe, fn.va - pe.imagebase)
       end    = offset + fn.size
       if end > len(bytes_reasm):
           record_failure(fn, "oversize"); continue
       bytes_reasm[offset:end] = patched_text[: fn.size]

   for fn in proven_set:
       record skipped_proven(fn)

4. Hash + write
   sha_orig  = sha256(bytes_orig).hexdigest()
   sha_reasm = sha256(bytes_reasm).hexdigest()
   match     = (sha_orig == sha_reasm) and (mismatches == [])
   if not --no-write:
       out_path.write_bytes(bytes_reasm)

5. Report + exit
   emit JSON or rich report
   exit EXIT_OK if match else EXIT_MISMATCH
```

## Module Layout

```
src/rebrew/
├── round_trip.py                # new — CLI module (TargetOption, --json, ...)
├── core/
│   └── matching.py              # + apply_coff_relocations(text, relocs, resolve_va) -> bytes
├── binary_loader.py             # + rva_to_file_offset(pe, rva) -> int
```

Registration: `main.py` imports `round_trip.app` and adds it via
`app.add_typer(round_trip.app, name="round-trip")`, mirroring how
`cfg`/`cache` are wired. `pyproject.toml` gains a
`rebrew-round-trip = "rebrew.round_trip:main_entry"` script entry.

`round_trip.py` follows the established single-command CLI pattern:

```python
import typer
from rich.console import Console
from rebrew.cli import TargetOption, require_config, EXIT_OK, EXIT_MISMATCH, EXIT_ERROR

console = Console(stderr=True)
app = typer.Typer(help="Splice matched functions back into the PE and verify byte equality.", rich_markup_mode="rich")

@app.callback(invoke_without_command=True)
def main(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    out: Path | None = typer.Option(None, "--out", help="Override output PE path"),
    no_write: bool = typer.Option(False, "--no-write", help="Skip writing reasm PE"),
    filter: str | None = typer.Option(None, "--filter", help="Only round-trip functions matching symbol substring"),
    target: str | None = TargetOption,
) -> None:
    cfg = require_config(target=target)
    ...

def main_entry() -> None:
    """Run the Typer CLI application."""
    app()

if __name__ == "__main__":
    main_entry()
```

## New Helpers

### `apply_coff_relocations(text, relocs, resolve_va) -> bytes`

Location: `src/rebrew/core/matching.py` (next to `smart_reloc_compare`,
which already grew a COFF-aware view of the world).

Signature:

```python
def apply_coff_relocations(
    text: bytes,
    relocs: list[CoffReloc],            # from matcher/parsers.py
    resolve_va: Callable[[str], int | None],
    *,
    image_base: int,
    section_va: int,                    # VA of the .text section, for IMAGE_REL_I386_REL32
) -> bytes:
    """Apply COFF relocation records to a .text byte blob.

    For each relocation, read the addend at relocs[i].offset, resolve the
    target VA via resolve_va(symbol), compute the patched value per the
    relocation type (IMAGE_REL_I386_DIR32, IMAGE_REL_I386_REL32, ...), and
    write it back. Unresolved symbols raise UnresolvedSymbolError with the
    name so the caller can record a per-function failure rather than
    abort the whole run.
    """
```

The resolver closes over the active target's function catalog (for code
references) and `rebrew-data.toml` (for data references). Both are already
loaded by existing tooling (`catalog.registry`, `data_metadata`); a thin
wrapper composes them into a single `resolve_va`.

### `rva_to_file_offset(pe, rva) -> int`

Location: `src/rebrew/binary_loader.py`.

Walks the PE section table (`pe.sections` from LIEF) and returns
`section.pointer_to_raw_data + (rva - section.virtual_address)` for the
section containing `rva`. Raises `ValueError` on RVA outside any section.

The LIEF Section objects expose these directly. No `struct.unpack`
necessary — matches the project's "use what we import" rule.

## Report Schema

```json
{
  "target":            "SERVER",
  "binary":            "original/server.dll",
  "out":               "original/server.dll.reasm",
  "sha256_original":   "8f3c...",
  "sha256_reasm":      "8f3c...",
  "match":             true,
  "spliced":           142,
  "skipped_proven":    3,
  "skipped_other":     0,
  "mismatches":        [
    {
      "symbol":      "BitReverse",
      "va":          "0x10008880",
      "file_offset": "0x7c80",
      "status":      "RELOC",
      "expected_sha":"...",
      "actual_sha":  "...",
      "reason":      "unresolved_symbol",
      "detail":      "g_unknown_global"
    }
  ]
}
```

`reason` enum: `compile_drift`, `unresolved_symbol`, `oversize`,
`byte_mismatch`, `reloc_application_failed`.

Non-JSON output is a Rich table mirroring the same fields, plus a one-line
verdict (`✔ round-trip clean: 142 functions, sha 8f3c…` /
`✗ 3 unexpected mismatches`).

## Edge Cases

| Case | Behavior |
|------|----------|
| Function size from metadata differs from compiled `.text` size | Splice exactly `size` bytes; trailing bytes from the `.obj` are discarded. If `.text` is shorter than `size`, record `oversize` (treated as the inverse case) and skip splice. |
| Function VA lies outside any PE section | Record `reason: rva_out_of_range`, skip splice. |
| Symbol referenced by reloc is not in either catalog | Record `unresolved_symbol`, skip splice; exit 1. |
| Multi-target file (`// FUNCTION: A 0x..` + `// FUNCTION: B 0x..`) | Only the active target is considered; other markers ignored. |
| No matched functions at all | Round-trip is vacuously clean; reasm == original; exit 0 with `spliced: 0`. |
| `--no-write` with mismatches | Still emit report and exit 1, but never touch disk. |
| `--out` writes to a path under the project | Allowed but excluded from cache invalidation; we do not auto-delete stale reasm files. |
| Concurrent runs | Single-target invocations are independent; reasm path is per-target so collisions are impossible unless the user passes a manual `--out` that clobbers. |

## Performance

Each splice-set function triggers one `compile_and_compare` call. That
function already consults `compile_cache.py`, so cache-warm runs amortise
to "read .obj from disk + apply relocations + memcpy". Expected runtime
for a 2000-function project: comparable to `rebrew verify` (~30s on a warm
cache), since the bulk of work is identical.

No parallelism in v1. The compile cache is the bottleneck mitigation;
adding `-j` is a follow-up if benchmarks justify it.

## Testing

Unit tests, one file per new helper, following the existing per-module
pattern (`tests/test_<module>.py`):

- `tests/test_core_matching_relocs.py`
  - Apply `IMAGE_REL_I386_DIR32` against synthetic relocs; assert exact
    bytes written.
  - `IMAGE_REL_I386_REL32`: assert PC-relative arithmetic matches expected
    `(target - (section_va + offset + 4))` displacement.
  - Unresolved symbol raises `UnresolvedSymbolError` with the name.
- `tests/test_binary_loader_rva.py`
  - Build an in-memory PE via `lief.PE.Builder` (already used in tests),
    assert `rva_to_file_offset` matches the LIEF section pointer math.
  - RVA outside any section → `ValueError`.
- `tests/test_round_trip.py`
  - Use the existing `_make_project(tmp_path, toml)` helper pattern with
    a tiny synthetic PE (single `.text` function) and a known-good `.c`
    source — confirm reasm hash == original hash and exit code 0.
  - With STATUS=NEAR_MATCHING in metadata, function is ignored; reasm ==
    original.
  - With one function marked EXACT but its `.c` mutated to produce
    different bytes, exit code 1 and report lists the function as
    `compile_drift`.

The end-to-end fixture lives entirely in-memory via `tmp_path`; no MSVC6
needed in CI. `compile_and_compare` is mocked at the seam — tests inject
a precomputed `CompareResult` rather than running Wine.

## Future Work (Out of Scope)

- `--parallel` / `-j N`: parallel compile-and-splice once benchmarks
  justify it.
- `--strict-padding`: also splice the trailing padding region between
  functions and require it to match. Catches alignment regressions not
  exposed by per-function comparison.
- Patch report → `rebrew status`: surface the round-trip pass/fail in the
  high-level project overview.
- Linking-based full reassembly (the splat approach), if rebrew ever
  needs to test linker-script-style flows.
