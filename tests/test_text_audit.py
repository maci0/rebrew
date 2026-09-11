"""Tests for rebrew text_audit — .text VA comparison against source markers.

The link pipeline is faked at the ``rebrew.data_layout`` boundary (link
objects + per-object symbol offsets) so the tests exercise the placement
arithmetic: per-TU .text contributions accumulate in link order onto the
built ``.text`` base VA, then each function's computed VA is compared with
its marker expectation.  The export-fallback path runs against a real
LIEF-parseable minimal PE from ``bin_util``.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import make_coff_obj, make_pe

FAKE_TEXT_VA = 0x1000

_TOML = """\
[project]
default_target = "game"

[targets.game]
binary = "game.exe"
marker = "GAME"
reversed_dir = "src"
function_list = "src/functions.txt"

[compiler]
profile = "msvc6"
command = "cl"
cflags = "/O2"
"""

_TWO_FUNCS_C = """\
// FUNCTION: GAME 0x00001000
// STATUS: EXACT
int alpha(void) { return 1; }
"""

_TWO_FILES_B = """\
// FUNCTION: GAME 0x00001020
// STATUS: EXACT
int beta(void) { return 2; }
"""


def _project(tmp_path: Path, sources: dict[str, str] | None = None) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(_TOML, encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    for name, text in (sources or {"a.c": _TWO_FUNCS_C}).items():
        (src / name).write_text(text, encoding="utf-8")
    (src / "functions.txt").write_text("", encoding="utf-8")
    (tmp_path / "build").mkdir(exist_ok=True)
    return tmp_path


def _patch_layout(
    monkeypatch: pytest.MonkeyPatch,
    *,
    text_base: int = FAKE_TEXT_VA,
    objects: list[tuple[int, dict[str, int]]] | None = None,
    fail: Exception | None = None,
) -> None:
    import rebrew.data_layout as dl
    import rebrew.text_audit as ta

    monkeypatch.setattr(ta, "built_text_va", lambda _dll: text_base)
    if fail is not None:
        monkeypatch.setattr(dl, "link_objects", lambda _root: (_ for _ in ()).throw(fail))
        return

    objs = [Path(f"/fake/obj{i}.obj") for i in range(len(objects or []))]

    def _offsets(obj: Path) -> tuple[int, dict[str, int]]:
        index = int(str(obj).removeprefix("/fake/obj").removesuffix(".obj"))
        assert objects is not None
        return objects[index]

    monkeypatch.setattr(dl, "link_objects", lambda _root: objs)
    monkeypatch.setattr(dl, "obj_text_symbol_offsets", _offsets)


def _export_pe(path: Path, names: list[str]) -> Path:
    """Minimal PE with an export table naming *names* at sequential RVAs."""
    code = b"\xc3" * 64
    text_va = 0x1000
    base = text_va + len(code)
    n = len(names)
    ftab, ntab, otab = 40, 40 + 4 * n, 40 + 8 * n
    strs = otab + 2 * n
    blob = bytearray(struct.pack("<IIHHIIIIIII", 0, 0, 0, 0, 0, 1, n, n, 0, 0, 0))
    rvas = [text_va + 4 * i for i in range(n)]
    for r in rvas:
        blob += struct.pack("<I", r)
    cur = strs
    name_rvas = []
    for nm in names:
        name_rvas.append(base + cur)
        cur += len(nm) + 1
    for r in name_rvas:
        blob += struct.pack("<I", r)
    for i in range(n):
        blob += struct.pack("<H", i)
    for nm in names:
        blob += nm.encode("ascii") + b"\x00"
    dll_name_rva = base + len(blob)
    blob += b"game.dll\x00"
    struct.pack_into("<I", blob, 12, dll_name_rva)
    struct.pack_into("<I", blob, 28, base + ftab)
    struct.pack_into("<I", blob, 32, base + ntab)
    struct.pack_into("<I", blob, 36, base + otab)
    raw = bytearray(make_pe(code))
    off = 0x200 + len(code)  # .text raw data starts at file offset 0x200
    raw[off : off + len(bytes(blob))] = bytes(blob)
    lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    struct.pack_into("<II", raw, lfanew + 24 + 0x60, base, len(blob))
    path.write_bytes(bytes(raw))
    return path


class TestTextAuditCli:
    def test_missing_built_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.text_audit import app

        monkeypatch.chdir(_project(tmp_path))
        result = CliRunner().invoke(app, [])
        assert result.exit_code == 2
        assert "server.dll" in result.output
        assert "not found" in " ".join(result.output.split())

    def test_custom_built_path_honored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.text_audit as ta
        from rebrew.text_audit import app

        monkeypatch.chdir(_project(tmp_path))
        (tmp_path / "build" / "other.dll").write_bytes(b"MZ")
        _patch_layout(monkeypatch, objects=[(16, {"_alpha": 0})])
        seen: list[Path] = []

        def _capture(root: Path, binary: Path) -> dict[str, int]:
            seen.append(binary)
            return ta.exported_symbol_vas(binary)

        monkeypatch.setattr(ta, "collect_actual_vas", _capture)
        result = CliRunner().invoke(app, ["--built", "build/other.dll", "--json"])
        assert result.exit_code == 0, result.output
        assert seen == [tmp_path / "build" / "other.dll"]

    def test_all_correct_reports_zero_misplaced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.text_audit import app

        monkeypatch.chdir(_project(tmp_path, {"a.c": _TWO_FUNCS_C, "b.c": _TWO_FILES_B}))
        (tmp_path / "build" / "server.dll").write_bytes(b"MZ")
        # alpha at base+0 of TU#1; beta at offset 0 of TU#2 → base + 0x20.
        _patch_layout(monkeypatch, objects=[(0x20, {"_alpha": 0}), (0x20, {"_beta": 0})])
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["functions"] == 2
        assert payload["found"] == 2
        assert payload["correct"] == 2
        assert payload["misplaced"] == 0
        assert payload["missing"] == 0

    def test_misplaced_function_exits_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.text_audit import app

        monkeypatch.chdir(_project(tmp_path, {"a.c": _TWO_FUNCS_C, "b.c": _TWO_FILES_B}))
        (tmp_path / "build" / "server.dll").write_bytes(b"MZ")
        # beta lands at base+0x10 instead of the marked 0x1020.
        _patch_layout(monkeypatch, objects=[(0x10, {"_alpha": 0}), (0x20, {"_beta": 0})])
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 1
        payload = json.loads(result.stdout)
        assert payload["correct"] == 1
        assert payload["misplaced"] == 1
        assert payload["missing"] == 0
        assert payload["misplaced_list"] == [
            {
                "symbol": "beta",
                "status": "MISPLACED",
                "expected": "0x1020",
                "actual": "0x1010",
                "delta": -16,
            }
        ]

    def test_terminal_output_lists_misplaced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.text_audit import app

        monkeypatch.chdir(_project(tmp_path, {"a.c": _TWO_FUNCS_C, "b.c": _TWO_FILES_B}))
        (tmp_path / "build" / "server.dll").write_bytes(b"MZ")
        _patch_layout(monkeypatch, objects=[(0x10, {"_alpha": 0}), (0x20, {"_beta": 0})])
        result = CliRunner().invoke(app, [])
        assert result.exit_code == 1
        assert "correct-VA: 1" in result.output
        assert "misplaced: 1" in result.output
        assert "beta" in result.output
        assert "exp 0x00001020" in result.output
        assert "our 0x00001010" in result.output

    def test_missing_function_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.text_audit import app

        monkeypatch.chdir(_project(tmp_path, {"a.c": _TWO_FUNCS_C, "b.c": _TWO_FILES_B}))
        (tmp_path / "build" / "server.dll").write_bytes(b"MZ")
        # beta has no .text symbol in the build — MISSING, not misplaced.
        _patch_layout(monkeypatch, objects=[(0x20, {"_alpha": 0})])
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["missing"] == 1
        assert payload["misplaced"] == 0
        assert payload["misplaced_list"][0]["status"] == "MISSING"

    def test_objdump_failure_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.text_audit import app

        monkeypatch.chdir(_project(tmp_path))
        (tmp_path / "build" / "server.dll").write_bytes(b"MZ")
        _patch_layout(monkeypatch, fail=RuntimeError("objdump exploded"))
        result = CliRunner().invoke(app, [])
        assert result.exit_code == 2
        assert "cannot inventory build objects" in result.output


class TestExportFallback:
    def test_lief_export_vas_are_image_base_correct(self, tmp_path: Path) -> None:
        from rebrew.text_audit import exported_symbol_vas

        pe = _export_pe(tmp_path / "game.dll", ["alpha", "beta"])
        assert exported_symbol_vas(pe) == {"alpha": 0x401000, "beta": 0x401004}

    def test_fallback_used_when_no_objects(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.data_layout as dl
        import rebrew.text_audit as ta

        monkeypatch.chdir(_project(tmp_path, {"a.c": _TWO_FUNCS_C}))
        pe = _export_pe(tmp_path / "build" / "server.dll", ["alpha"])
        monkeypatch.setattr(
            dl, "link_objects", lambda _root: (_ for _ in ()).throw(FileNotFoundError("no rsp"))
        )
        monkeypatch.setattr(ta, "built_text_va", lambda _dll: FAKE_TEXT_VA)
        actual = ta.collect_actual_vas(tmp_path, pe)
        assert actual == {"alpha": 0x401000}

    def test_obj_text_offsets_read_text_section(self, tmp_path: Path) -> None:
        from rebrew.data_layout import obj_text_symbol_offsets

        obj = tmp_path / "a.obj"
        obj.write_bytes(
            make_coff_obj(b"\x55\x8b\xec\xc3", func_symbol="_alpha", extra_funcs=[("_beta", 8)])
        )
        size, syms = obj_text_symbol_offsets(obj)
        assert size == 4
        assert syms == {"alpha": 0, "beta": 8}

    def test_audit_text_classification(self) -> None:
        from rebrew.text_audit import audit_text

        rows, n_ok, n_bad, n_missing = audit_text(
            {"a": 0x1000, "b": 0x1020, "c": 0x1040},
            {"a": 0x1000, "b": 0x1010},
        )
        assert (n_ok, n_bad, n_missing) == (1, 1, 1)
        assert [r["status"] for r in rows] == ["MISPLACED", "MISSING", "OK"]
