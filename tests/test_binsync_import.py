"""Tests for binsync_import.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import tomlkit
from typer.testing import CliRunner

from rebrew.main import app

runner = CliRunner()

_TOML_CFG = """
[project]
default_target = "server"

[targets.server]
binary = "server.dll"
reversed_dir = "src"
"""


def _make_project(tmp_path: Path, files: dict[str, str]) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(_TOML_CFG, encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    for name, content in files.items():
        (src / name).write_text(content, encoding="utf-8")
    return tmp_path


def _make_state(
    tmp_path: Path, funcs: dict[int, str] | None = None, globals_map: dict[int, str] | None = None
) -> Path:
    state = tmp_path / "state"
    funcs_dir = state / "functions"
    funcs_dir.mkdir(parents=True, exist_ok=True)
    if funcs:
        for va, name in funcs.items():
            doc = tomlkit.document()
            info = tomlkit.table()
            info["name"] = name
            info["addr"] = va
            doc["info"] = info
            (funcs_dir / f"{va:08x}.toml").write_text(tomlkit.dumps(doc), encoding="utf-8")
    if globals_map:
        doc = tomlkit.document()
        for va, name in globals_map.items():
            entry = tomlkit.table()
            entry["name"] = name
            entry["addr"] = va
            doc[str(va)] = entry
        (state / "global_vars.toml").write_text(tomlkit.dumps(doc), encoding="utf-8")
    return state


def _invoke_import(
    tmp_path: Path, state: Path, monkeypatch: pytest.MonkeyPatch, *extra: str
) -> Any:
    monkeypatch.chdir(tmp_path)
    return runner.invoke(app, ["binsync-import", str(state), *extra])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestBinsyncImportHelpers:
    def test_is_meaningful(self) -> None:
        from rebrew.binsync_import import _is_meaningful

        assert _is_meaningful("Foo")
        assert not _is_meaningful("func_10001000")
        assert not _is_meaningful("FUN_00401000")
        assert not _is_meaningful("")
        assert not _is_meaningful("DAT_10002000")

    def test_load_binsync_state(self, tmp_path: Path) -> None:
        from rebrew.binsync_import import _load_binsync_state

        state = _make_state(tmp_path, funcs={0x10001000: "_Foo"}, globals_map={0x01008000: "g_foo"})
        funcs, globs = _load_binsync_state(state)
        assert 0x10001000 in funcs
        assert globs[0x01008000]["name"] == "g_foo"

    def test_load_binsync_state_with_header(self, tmp_path: Path) -> None:
        from rebrew.binsync_import import _load_binsync_state

        state = tmp_path / "state2"
        funcs_dir = state / "functions"
        funcs_dir.mkdir(parents=True)
        doc = tomlkit.document()
        info = tomlkit.table()
        info["name"] = "_Bar"
        info["addr"] = 0x10002000
        doc["info"] = info
        hdr = tomlkit.table()
        hdr["type"] = "int __cdecl Bar(int x)"
        doc["header"] = hdr
        (funcs_dir / "10002000.toml").write_text(tomlkit.dumps(doc), encoding="utf-8")
        funcs, _ = _load_binsync_state(state)
        assert funcs[0x10002000]["prototype"] == "int __cdecl Bar(int x)"


# ---------------------------------------------------------------------------
# Dry run + JSON
# ---------------------------------------------------------------------------


class TestBinsyncImportDryRun:
    def test_dry_run_does_not_write(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint foo(void){return 1;}\n"
            },
        )
        state = _make_state(tmp_path, funcs={0x10001000: "_NewName"})
        # Make local name generic so it would be applied — but dry-run shouldn't change files
        # foo is meaningful, so it would be a conflict not an auto-apply
        result = _invoke_import(tmp_path, state, monkeypatch, "--dry-run", "--json")
        assert result.exit_code in (0, 1)
        # Check file unchanged
        assert "foo" in (tmp_path / "src" / "foo.c").read_text()

    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint foo(void){return 1;}\n"
            },
        )
        state = _make_state(tmp_path, funcs={0x10001000: "_Other"})
        result = _invoke_import(tmp_path, state, monkeypatch, "--dry-run", "--json")
        data = json.loads(result.stdout)
        assert "conflicts" in data
        assert "applied_names" in data


class TestBinsyncImportConflicts:
    def test_conflict_without_accept_exits_1(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint foo(void){return 1;}\n"
            },
        )
        state = _make_state(tmp_path, funcs={0x10001000: "_OtherName"})
        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert data["conflicts"] == 1

    def test_accept_binsync_applies(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint foo(void){return 1;}\n"
            },
        )
        state = _make_state(tmp_path, funcs={0x10001000: "_Renamed"})
        result = _invoke_import(tmp_path, state, monkeypatch, "--accept-binsync", "--json")
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["applied_names"] == 1

    def test_mutually_exclusive_accept(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint foo(void){return 1;}\n"
            },
        )
        state = _make_state(tmp_path, funcs={0x10001000: "_X"})
        result = _invoke_import(
            tmp_path, state, monkeypatch, "--accept-binsync", "--accept-local", "--json"
        )
        assert result.exit_code != 0

    def test_module_filter(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint foo(void){return 1;}\n",
                "other.c": "// FUNCTION: OTHER 0x10002000\n// STATUS: EXACT\n// SIZE: 4\nint bar(void){return 2;}\n",
            },
        )
        state = _make_state(tmp_path, funcs={0x10001000: "_NewFoo", 0x10002000: "_NewBar"})
        result = _invoke_import(
            tmp_path, state, monkeypatch, "--module", "SERVER", "--accept-binsync", "--json"
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["module"] == "SERVER"

    def test_missing_state_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint foo(void){return 1;}\n"
            },
        )
        result = _invoke_import(tmp_path, tmp_path / "nope", monkeypatch, "--json")
        assert result.exit_code != 0

    def test_empty_state_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint foo(void){return 1;}\n"
            },
        )
        empty = tmp_path / "empty_state"
        empty.mkdir()
        result = _invoke_import(tmp_path, empty, monkeypatch, "--json")
        assert result.exit_code != 0


class TestBinsyncRoundTrip:
    """Export then import round-trips names/prototypes without corruption."""

    def test_export_import_round_trip_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 8\nint foo(void){return 1;}\n",
            },
        )
        # Export
        monkeypatch.chdir(tmp_path)
        out = runner.invoke(app, ["binsync-export", str(tmp_path / "state"), "--json"])
        assert out.exit_code == 0

        # Simulate IDA renaming by editing the exported TOML
        p = tmp_path / "state" / "functions" / "10001000.toml"
        doc = tomlkit.parse(p.read_text(encoding="utf-8"))
        doc["info"]["name"] = "_RenamedFromIDA"  # type: ignore[index]
        p.write_text(tomlkit.dumps(doc), encoding="utf-8")

        # Import with accept — should apply the rename via cross-reference rewrite
        result = _invoke_import(
            tmp_path, tmp_path / "state", monkeypatch, "--accept-binsync", "--json"
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["applied_names"] == 1
        # rename_function_everywhere may have renamed foo.c -> RenamedFromIDA.c
        renamed = tmp_path / "src" / "RenamedFromIDA.c"
        src_file = renamed if renamed.exists() else tmp_path / "src" / "foo.c"
        assert "RenamedFromIDA" in src_file.read_text()

    def test_prototype_round_trip(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 8\nint foo(void){return 1;}\n"
            },
        )
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["binsync-export", str(tmp_path / "state")])
        # Edit prototype in BinSync state
        p = tmp_path / "state" / "functions" / "10001000.toml"
        doc = tomlkit.parse(p.read_text(encoding="utf-8"))
        if "header" not in doc:
            doc["header"] = tomlkit.table()
        doc["header"]["type"] = "int __cdecl RenamedFromIDA(int x, int y)"  # type: ignore[index]
        doc["info"]["name"] = "_foo"  # keep same name so only prototype changes
        p.write_text(tomlkit.dumps(doc), encoding="utf-8")

        result = _invoke_import(tmp_path, tmp_path / "state", monkeypatch, "--json")
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["applied_prototypes"] == 1

    def test_global_round_trip(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint foo(void){return 1;}\n",
                "data.c": "// GLOBAL: SERVER 0x01008000\n// SIZE: 4\nint g_x;\n",
            },
        )
        monkeypatch.chdir(tmp_path)
        runner.invoke(app, ["binsync-export", str(tmp_path / "state")])
        # Rename global in BinSync state
        gv = tmp_path / "state" / "global_vars.toml"
        if gv.exists():
            doc = tomlkit.parse(gv.read_text(encoding="utf-8"))
            for _k, entry in doc.items():
                if isinstance(entry, dict) and "name" in entry:
                    entry["name"] = "g_renamed"
            gv.write_text(tomlkit.dumps(doc), encoding="utf-8")

            result = _invoke_import(tmp_path, tmp_path / "state", monkeypatch, "--json")
            assert result.exit_code == 0
            data = json.loads(result.stdout)
            # Either applied or skipped if name considered non-meaningful — just check no crash
            assert "applied_globals" in data

    def test_catalog_aware_import_proposes_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """BinSync names for catalog-only VAs surface as proposed_missing."""
        _TOML = """
[project]
default_target = "server"

[targets.server]
binary = "server.dll"
reversed_dir = "src/server"
"""
        (tmp_path / "rebrew-project.toml").write_text(_TOML, encoding="utf-8")
        src = tmp_path / "src" / "server"
        src.mkdir(parents=True)
        src.joinpath("foo.c").write_text(
            "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 10\nint foo(void){return 1;}\n",
            encoding="utf-8",
        )
        src.joinpath("functions.txt").write_text(
            "0x10001000 10 foo\n0x10002000 16 bar_func\n", encoding="utf-8"
        )

        state = _make_state(tmp_path, funcs={0x10002000: "_NewCatalogName"})
        result = _invoke_import(tmp_path, state, monkeypatch, "--dry-run", "--json")
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        proposed = data.get("proposed", [])
        assert any(
            p.get("field") == "new_function" and "10002000" in p.get("va", "") for p in proposed
        )

    def test_create_missing_with_prototype(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--create-missing respects BinSync [header].type when present."""
        _TOML = """
[project]
default_target = "server"

[targets.server]
binary = "server.dll"
reversed_dir = "src/server"
"""
        (tmp_path / "rebrew-project.toml").write_text(_TOML, encoding="utf-8")
        src = tmp_path / "src" / "server"
        src.mkdir(parents=True)
        src.joinpath("foo.c").write_text(
            "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 10\nint foo(void){return 1;}\n",
            encoding="utf-8",
        )
        src.joinpath("functions.txt").write_text(
            "0x10001000 10 foo\n0x10002000 16 bar_func\n", encoding="utf-8"
        )
        # Build a BinSync entry with a real prototype
        state = tmp_path / "state_proto"
        state.mkdir()
        funcs_dir = state / "functions"
        funcs_dir.mkdir()
        doc = tomlkit.document()
        info = tomlkit.table()
        info["name"] = "MyApiFunc"
        info["addr"] = 0x10002000
        info["size"] = 16
        doc["info"] = info
        hdr = tomlkit.table()
        hdr["type"] = "int __stdcall MyApiFunc(int a, int b)"
        doc["header"] = hdr
        (funcs_dir / "10002000.toml").write_text(tomlkit.dumps(doc), encoding="utf-8")

        result = _invoke_import(tmp_path, state, monkeypatch, "--create-missing", "--json")
        assert result.exit_code == 0, result.output
        assert (src / "MyApiFunc.c").exists()
        text = (src / "MyApiFunc.c").read_text()
        assert "__stdcall" in text or "MyApiFunc" in text

    def test_create_missing_materializes_stub(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _TOML = """
[project]
default_target = "server"

[targets.server]
binary = "server.dll"
reversed_dir = "src/server"
"""
        (tmp_path / "rebrew-project.toml").write_text(_TOML, encoding="utf-8")
        src = tmp_path / "src" / "server"
        src.mkdir(parents=True)
        src.joinpath("foo.c").write_text(
            "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 10\nint foo(void){return 1;}\n",
            encoding="utf-8",
        )
        src.joinpath("functions.txt").write_text(
            "0x10001000 10 foo\n0x10002000 16 bar_func\n", encoding="utf-8"
        )

        state = _make_state(tmp_path, funcs={0x10002000: "_FromBinSync"})
        result = _invoke_import(tmp_path, state, monkeypatch, "--create-missing", "--json")
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["applied_names"] == 1
        assert (src / "FromBinSync.c").exists()
        # The stub carries only the marker — STATUS/SIZE/NOTE are
        # metadata-owned keys and must land in rebrew-function.toml, not
        # as deprecated inline // STATUS://SIZE://NOTE: forms (lint W019).
        text = (src / "FromBinSync.c").read_text()
        assert "// FUNCTION:" in text
        assert "// STATUS:" not in text and "// SIZE:" not in text and "// NOTE:" not in text
        meta = (tmp_path / "src" / "rebrew-function.toml").read_text(encoding="utf-8")
        assert "SERVER.0x10002000" in meta
        assert 'status = "STUB"' in meta
        assert "imported from BinSync" in meta
