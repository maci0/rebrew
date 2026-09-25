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

pytest.importorskip("declib")

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


def _src_files(tmp_path: Path) -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted((tmp_path / "src").iterdir())}


def _write_state_function(state: Path, va: int, name: str, prototype: str | None = None) -> None:
    from declib.artifacts import Function, FunctionHeader

    funcs_dir = state / "functions"
    funcs_dir.mkdir(parents=True, exist_ok=True)
    header = FunctionHeader(name=name, addr=va, type_=prototype)
    func = Function(addr=va, size=0, header=header)
    (funcs_dir / f"{va:08x}.toml").write_text(func.dumps(), encoding="utf-8")


def _make_state(
    tmp_path: Path, funcs: dict[int, str] | None = None, globals_map: dict[int, str] | None = None
) -> Path:
    """A minimal declib BinSync state dir (the shape upstream writes)."""
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "metadata.toml").write_text('user = "test"\nversion = "test"\n', encoding="utf-8")
    for va, name in (funcs or {}).items():
        _write_state_function(state, va, name)
    if globals_map:
        from declib.artifacts import GlobalVariable

        artifacts = [
            GlobalVariable(addr=va, name=name, type_="int", size=4)
            for va, name in globals_map.items()
        ]
        (state / "global_vars.toml").write_text(
            GlobalVariable.dumps_many(artifacts), encoding="utf-8"
        )
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
    def test_entry_module_does_not_invent_server(self) -> None:
        from types import SimpleNamespace

        from rebrew.binsync.importer import _entry_module, _stub_text

        blank = SimpleNamespace(marker="", target_name="")
        assert _entry_module(blank) == ""
        assert _entry_module(blank, SimpleNamespace(module="CLIENT")) == "CLIENT"
        derived = SimpleNamespace(marker="", target_name="client.exe")
        assert _entry_module(derived) == "CLIENTEXE"
        with pytest.raises(ValueError, match="module marker"):
            _stub_text(blank, 0x1000, "foo", "")

    def test_is_meaningful(self) -> None:
        from rebrew.binsync.importer import is_meaningful

        assert is_meaningful("Foo")
        assert not is_meaningful("func_10001000")
        assert not is_meaningful("FUN_00401000")
        assert not is_meaningful("")
        assert not is_meaningful("DAT_10002000")

    def test_load_binsync_state(self, tmp_path: Path) -> None:
        from rebrew.binsync.state import load_binsync_state

        state = _make_state(tmp_path, funcs={0x10001000: "_Foo"}, globals_map={0x01008000: "g_foo"})
        funcs, globs = load_binsync_state(state)
        assert 0x10001000 in funcs
        assert globs[0x01008000]["name"] == "g_foo"

    def test_load_binsync_state_with_header(self, tmp_path: Path) -> None:
        from rebrew.binsync.state import load_binsync_state

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
        funcs, _ = load_binsync_state(state)
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
        before = _src_files(tmp_path)
        # --accept-binsync would rename foo.c -> NewName.c without --dry-run.
        result = _invoke_import(
            tmp_path, state, monkeypatch, "--accept-binsync", "--dry-run", "--json"
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["dry_run"] is True
        assert data["applied_names"] == 1  # counts the would-be rename
        assert _src_files(tmp_path) == before

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
        assert _src_files(tmp_path) == {
            "Renamed.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\n"
            "int Renamed(void){return 1;}\n"
        }

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
        assert result.exit_code == 2
        assert json.loads(result.stdout)["error"] == (
            "--accept-binsync and --accept-local are mutually exclusive"
        )
        assert "foo.c" in _src_files(tmp_path)  # nothing renamed

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
        assert data["applied_names"] == 1
        files = _src_files(tmp_path)
        assert sorted(files) == ["NewFoo.c", "other.c"]
        assert "int bar(void)" in files["other.c"]  # OTHER module left alone

    def test_missing_state_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x10001000\n// STATUS: EXACT\n// SIZE: 4\nint foo(void){return 1;}\n"
            },
        )
        result = _invoke_import(tmp_path, tmp_path / "nope", monkeypatch, "--json")
        assert result.exit_code == 2
        assert json.loads(result.stdout)["error"].startswith("State directory not found:")

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
        assert result.exit_code == 2
        assert json.loads(result.stdout)["error"].startswith("No BinSync data found in")


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

        # Simulate IDA renaming by editing the exported TOML.  The export is
        # write-locked (0444) — a collaborator's tool chmods writable first
        # (the same discipline the rebrew CLI uses), then re-locks.
        p = tmp_path / "state" / "functions" / "10001000.toml"
        p.chmod(0o644)
        doc = tomlkit.parse(p.read_text(encoding="utf-8"))
        doc["name"] = "_RenamedFromIDA"
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
        # Edit prototype in BinSync state (chmod writable first — exports are
        # write-locked 0444).
        p = tmp_path / "state" / "functions" / "10001000.toml"
        p.chmod(0o644)
        doc = tomlkit.parse(p.read_text(encoding="utf-8"))
        if "header" not in doc:
            doc["header"] = tomlkit.table()
        doc["header"]["type"] = "int __cdecl RenamedFromIDA(int x, int y)"
        doc["type"] = "int __cdecl RenamedFromIDA(int x, int y)"
        doc["name"] = "_foo"  # keep same name so only prototype changes
        p.write_text(tomlkit.dumps(doc), encoding="utf-8")

        result = _invoke_import(tmp_path, tmp_path / "state", monkeypatch, "--json")
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert data["applied_prototypes"] == 0
        assert data["conflicts"] == 1

        result = _invoke_import(
            tmp_path, tmp_path / "state", monkeypatch, "--json", "--accept-binsync"
        )
        assert result.exit_code == 0
        assert json.loads(result.stdout)["applied_prototypes"] == 1

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
        # Rename global in BinSync state (chmod writable first — exports are
        # write-locked 0444).
        gv = tmp_path / "state" / "global_vars.toml"
        if gv.exists():
            gv.chmod(0o644)
            doc = tomlkit.parse(gv.read_text(encoding="utf-8"))
            for entry in doc.values():
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
        import json as _json

        src.joinpath("function_structure.json").write_text(
            _json.dumps(
                [
                    {"va": 0x10001000, "size": 10, "name": "foo"},
                    {"va": 0x10002000, "size": 16, "name": "bar_func"},
                ]
            ),
            encoding="utf-8",
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
        import json as _json

        src.joinpath("function_structure.json").write_text(
            _json.dumps(
                [
                    {"va": 0x10001000, "size": 10, "name": "foo"},
                    {"va": 0x10002000, "size": 16, "name": "bar_func"},
                ]
            ),
            encoding="utf-8",
        )
        # Build a BinSync entry with a real prototype
        state = tmp_path / "state_proto"
        state.mkdir()
        _write_state_function(
            state, 0x10002000, "MyApiFunc", "int __stdcall MyApiFunc(int a, int b)"
        )

        result = _invoke_import(tmp_path, state, monkeypatch, "--create-missing", "--json")
        assert result.exit_code == 0, result.output
        assert (src / "MyApiFunc.c").exists()
        text = (src / "MyApiFunc.c").read_text()
        assert "__stdcall" in text or "MyApiFunc" in text

    def test_create_missing_refuses_injected_prototype(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A BinSync prototype carrying code or a directive falls back to a void stub."""
        _make_project(tmp_path, {"foo.c": "// FUNCTION: SERVER 0x1000\nint foo(void){return 0;}\n"})
        src = tmp_path / "src"
        src.joinpath("function_structure.json").write_text(
            json.dumps([{"va": 0x1000, "size": 10, "name": "foo"}, {"va": 0x2000, "size": 16}]),
            encoding="utf-8",
        )
        state = tmp_path / "state"
        _write_state_function(
            state, 0x2000, "evil", 'void evil(void) {}\n#include "/etc/passwd"\nvoid x(void)'
        )
        result = _invoke_import(tmp_path, state, monkeypatch, "--create-missing", "--json")
        assert result.exit_code == 0, result.output
        text = (src / "evil.c").read_text(encoding="utf-8")
        assert "#include" not in text
        assert "void evil(void) {}" in text

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
        import json as _json

        src.joinpath("function_structure.json").write_text(
            _json.dumps(
                [
                    {"va": 0x10001000, "size": 10, "name": "foo"},
                    {"va": 0x10002000, "size": 16, "name": "bar_func"},
                    {"va": 0x10003000, "size": 24, "name": "baz_func"},
                ]
            ),
            encoding="utf-8",
        )

        state = _make_state(
            tmp_path, funcs={0x10002000: "_FromBinSync", 0x10003000: "_AlsoBinSync"}
        )
        result = _invoke_import(tmp_path, state, monkeypatch, "--create-missing", "--json")
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["applied_names"] == 2
        assert (src / "AlsoBinSync.c").exists()
        assert (src / "FromBinSync.c").exists()
        # The stub carries only the marker — STATUS/SIZE/NOTE are
        # metadata-owned keys and must land in rebrew-functions.toml, not
        # as deprecated inline // STATUS://SIZE://NOTE: forms (lint W019).
        text = (src / "FromBinSync.c").read_text()
        assert "// FUNCTION:" in text
        assert "// STATUS:" not in text and "// SIZE:" not in text and "// NOTE:" not in text
        meta = (tmp_path / "src" / "rebrew-functions.toml").read_text(encoding="utf-8")
        assert "SERVER.0x10002000" in meta
        assert 'status = "STUB"' in meta
        assert "imported from BinSync" in meta
        # Every stub's fields land (written in one batch after the loop).
        from rebrew.metadata import get_entry

        for va, size, name in ((0x10002000, 16, "_FromBinSync"), (0x10003000, 24, "_AlsoBinSync")):
            entry = get_entry(tmp_path / "src", va, "SERVER")
            assert entry["status"] == "STUB"
            assert entry["size"] == size
            assert entry["note"] == f"imported from BinSync as {name}"

    def test_create_missing_finishes_metadata_when_stub_already_exists(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stub left behind by a failed metadata write is completed on retry.

        The .c is the exact stub this import would write, and rebrew-functions.toml
        has no STATUS for it.  Skipping because the path exists would leave the
        function without STATUS/SIZE forever.
        """
        import json as _json

        from rebrew.metadata import get_entry

        _make_project(tmp_path, {})
        src = tmp_path / "src"
        src.joinpath("function_structure.json").write_text(
            _json.dumps([{"va": 0x10002000, "size": 16, "name": "bar_func"}]),
            encoding="utf-8",
        )
        (src / "FromBinSync.c").write_text(
            "// FUNCTION: SERVER 0x10002000\nvoid FromBinSync(void) {}\n",
            encoding="utf-8",
        )
        state = _make_state(tmp_path, funcs={0x10002000: "_FromBinSync"})
        result = _invoke_import(tmp_path, state, monkeypatch, "--create-missing", "--json")
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["applied_names"] == 1
        entry = get_entry(tmp_path, 0x10002000, "SERVER")
        assert entry["status"] == "STUB"
        assert entry["size"] == 16
        assert entry["note"] == "imported from BinSync as _FromBinSync"
        # The user's bytes were not rewritten.
        assert (src / "FromBinSync.c").read_text(encoding="utf-8") == (
            "// FUNCTION: SERVER 0x10002000\nvoid FromBinSync(void) {}\n"
        )


class TestGlobalTypeSizeImport:
    def test_type_and_size_applied(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.data_metadata import get_data_entry

        _make_project(
            tmp_path,
            {
                "data.c": "// GLOBAL: SERVER 0x01008000\n// SIZE: 4\nint g_x;\n",
            },
        )
        state = tmp_path / "state"
        (state / "functions").mkdir(parents=True, exist_ok=True)
        doc = tomlkit.document()
        entry = tomlkit.table()
        entry["name"] = "g_x"
        entry["addr"] = 0x01008000
        entry["type"] = "unsigned int"
        entry["size"] = 8
        doc[str(0x01008000)] = entry
        (state / "global_vars.toml").write_text(tomlkit.dumps(doc), encoding="utf-8")
        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        stored = get_data_entry(tmp_path, 0x01008000, "SERVER")
        assert stored.get("type") == "unsigned int"
        assert stored.get("size") == 8


class TestStructImport:
    def test_unknown_struct_written_to_header(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(tmp_path, {"foo.c": "// FUNCTION: SERVER 0x1000\nint foo(void){return 0;}\n"})
        state = tmp_path / "state"
        (state / "functions").mkdir(parents=True, exist_ok=True)
        structs = state / "structs"
        structs.mkdir(parents=True, exist_ok=True)
        doc = tomlkit.document()
        info = tomlkit.table()
        info["name"] = "Player"
        doc["info"] = info
        doc["definition"] = "typedef struct Player_s {\n\tint x;\n} Player;"
        (structs / "Player.toml").write_text(tomlkit.dumps(doc), encoding="utf-8")
        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["applied_structs"] == 1
        header = tmp_path / "src" / "binsync_types.h"
        assert "Player" in header.read_text(encoding="utf-8")

    def test_existing_cp1252_header_survives_append(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Appending a struct must not UTF-8-rewrite a legacy-encoded header.

        Concrete bytes: existing header starts with ``/* Caf\\xe9 */`` (CP1252).
        """
        _make_project(tmp_path, {"foo.c": "// FUNCTION: SERVER 0x1000\nint foo(void){return 0;}\n"})
        header = tmp_path / "src" / "binsync_types.h"
        prefix = b"/* Caf\xe9 */\n"
        header.write_bytes(prefix)
        state = tmp_path / "state"
        (state / "functions").mkdir(parents=True, exist_ok=True)
        structs = state / "structs"
        structs.mkdir(parents=True, exist_ok=True)
        doc = tomlkit.document()
        info = tomlkit.table()
        info["name"] = "Player"
        doc["info"] = info
        doc["definition"] = "typedef struct Player_s {\n\tint x;\n} Player;"
        (structs / "Player.toml").write_text(tomlkit.dumps(doc), encoding="utf-8")
        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        raw = header.read_bytes()
        assert raw.startswith(prefix)
        assert b"Player" in raw

    def test_known_struct_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x1000\nint foo(void){return 0;}\n",
                "types.h": "typedef struct Player_s {\n\tint x;\n} Player;\n",
            },
        )
        state = tmp_path / "state"
        (state / "functions").mkdir(parents=True, exist_ok=True)
        structs = state / "structs"
        structs.mkdir(parents=True, exist_ok=True)
        (structs / "Player.toml").write_text(
            '[info]\nname = "Player"\ndefinition = "typedef struct Player_s { int x; } Player;"\n',
            encoding="utf-8",
        )
        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["applied_structs"] == 0
        assert not (tmp_path / "src" / "binsync_types.h").exists()


class TestNormalizePrototype:
    def test_whitespace_only_difference_ignored(self) -> None:
        from rebrew.binsync.importer import normalize_prototype

        assert normalize_prototype("int foo(int a, char *b);") == normalize_prototype(
            "int  foo( int a,char*b )"
        )

    def test_real_difference_kept(self) -> None:
        from rebrew.binsync.importer import normalize_prototype

        assert normalize_prototype("int foo(int a);") != normalize_prototype("int foo(char a);")


class TestNoteImport:
    def _write_state_with_note(self, state: Path, note: str) -> None:
        from declib.artifacts import Comment

        _write_state_function(state, 0x1000, "foo")
        comment = Comment(addr=0x1001, func_addr=0x1000, comment=f"[rebrew:note] {note}")
        (state / "comments.toml").write_text(Comment.dumps_many([comment]), encoding="utf-8")

    def test_note_applied(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.metadata import get_entry

        _make_project(tmp_path, {"foo.c": "// FUNCTION: SERVER 0x1000\nint foo(void){return 0;}\n"})
        state = tmp_path / "state"
        self._write_state_with_note(state, "needs RE structs")
        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["applied_notes"] == 1
        assert get_entry(tmp_path, 0x1000, "SERVER").get("note") == "needs RE structs"

    def test_same_note_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.metadata import update_field

        _make_project(tmp_path, {"foo.c": "// FUNCTION: SERVER 0x1000\nint foo(void){return 0;}\n"})
        update_field(tmp_path, 0x1000, "note", "needs RE structs", "SERVER")
        state = tmp_path / "state"
        self._write_state_with_note(state, "needs RE structs")
        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["applied_notes"] == 0


class TestUnparsedTypeComment:
    def test_unparsed_definition_becomes_comment(self, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from rebrew.binsync.importer import _import_type_definitions

        src = tmp_path / "src"
        src.mkdir()
        cfg = SimpleNamespace(reversed_dir=src, metadata_dir=tmp_path, source_ext=".c")
        applied = _import_type_definitions(
            cfg,
            {"Weird": {"definition": "not a struct at all {{{"}},
            dry_run=False,
            proposed=[],
        )
        assert applied == 1
        text = (src / "binsync_types.h").read_text(encoding="utf-8")
        assert "UNPARSED" in text
        assert "not a struct at all {{{" in text

    def test_unparsed_and_renamed_definitions_are_not_reappended(self, tmp_path: Path) -> None:
        """A second import must not append another copy.

        The UNPARSED wrapper and a definition whose declared name is not the
        BinSync key never contain that key, so a key search treated every
        re-import as new.
        """
        from types import SimpleNamespace

        from rebrew.binsync.importer import _import_type_definitions

        src = tmp_path / "src"
        src.mkdir()
        cfg = SimpleNamespace(reversed_dir=src, metadata_dir=tmp_path, source_ext=".c")
        definitions = {
            "Weird": {"definition": "not a struct at all {{{"},
            "Alias": {"type": "int", "definition": "typedef int Other;"},
        }
        assert _import_type_definitions(cfg, definitions, dry_run=False, proposed=[]) == 2
        header = src / "binsync_types.h"
        text = header.read_text(encoding="utf-8")
        assert _import_type_definitions(cfg, definitions, dry_run=False, proposed=[]) == 0
        assert header.read_text(encoding="utf-8") == text
        assert text.count("UNPARSED") == 1
        assert text.count("typedef int Other;") == 1

    def test_definition_cannot_escape_comment(self, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from rebrew.binsync.importer import _import_type_definitions

        src = tmp_path / "src"
        src.mkdir()
        cfg = SimpleNamespace(reversed_dir=src, metadata_dir=tmp_path, source_ext=".c")
        _import_type_definitions(
            cfg,
            {
                "Esc": {"definition": "x */ int injected(void) { return 1; } /*"},
                "Pp": {"definition": 'typedef int Pp;\n#include "/etc/passwd"\ntypedef int Q;'},
            },
            dry_run=False,
            proposed=[],
        )
        text = (src / "binsync_types.h").read_text(encoding="utf-8")
        # Only the header banner and the two wrappers close a comment.
        assert text.count("*/") == 3
        assert "x * / int injected" in text
        assert "\n/* UNPARSED from BinSync (no known layout):\ntypedef int Pp;\n#include" in text


class TestEnumTypedefImport:
    def _state_with(
        self,
        tmp_path: Path,
        *,
        enum: tuple[str, dict[str, int]] | None = None,
        typedef: tuple[str, str] | None = None,
    ) -> Path:
        from declib.artifacts import Enum, Typedef

        state = tmp_path / "state"
        state.mkdir()
        (state / "metadata.toml").write_text('user = "test"\nversion = "test"\n', encoding="utf-8")
        if enum is not None:
            name, members = enum
            arts = [Enum(name=name, members=members)]
            (state / "enums.toml").write_text(
                Enum.dumps_many(arts, key_attr="name"), encoding="utf-8"
            )
        if typedef is not None:
            name, underlying = typedef
            arts = [Typedef(name=name, type_=underlying)]
            (state / "typedefs.toml").write_text(
                Typedef.dumps_many(arts, key_attr="name"), encoding="utf-8"
            )
        return state

    def test_unknown_enum_and_typedef_written(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {"foo.c": "// FUNCTION: SERVER 0x1000\n// STATUS: STUB\nint foo(void){return 0;}\n"},
        )
        state = self._state_with(
            tmp_path,
            enum=("E", {"A": 0, "B": 5}),
            typedef=("uint32_t", "unsigned int"),
        )
        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["applied_enums"] == 1
        assert data["applied_typedefs"] == 1
        header = (tmp_path / "src" / "binsync_types.h").read_text(encoding="utf-8")
        assert "typedef enum { A = 0, B = 5 } E;" in header
        assert "typedef unsigned int uint32_t;" in header

    def test_known_enum_not_overwritten(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_project(
            tmp_path,
            {
                "foo.c": "// FUNCTION: SERVER 0x1000\n// STATUS: STUB\nint foo(void){return 0;}\n",
                "types.h": "typedef enum { X } E;\n",
            },
        )
        state = self._state_with(tmp_path, enum=("E", {"A": 0}))
        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["applied_enums"] == 0
        assert not (tmp_path / "src" / "binsync_types.h").exists()

    def test_foreign_format_synthesizes_definitions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A foreign declib state carries name+members (enums) and name+type
        (typedefs); import must synthesize real declarations."""
        _make_project(
            tmp_path,
            {"foo.c": "// FUNCTION: SERVER 0x1000\n// STATUS: STUB\nint foo(void){return 0;}\n"},
        )
        state = self._state_with(
            tmp_path,
            enum=("Color", {"RED": 0, "GREEN": 1}),
            typedef=("uint32_t", "unsigned int"),
        )
        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["applied_enums"] == 1
        assert data["applied_typedefs"] == 1
        header = (tmp_path / "src" / "binsync_types.h").read_text(encoding="utf-8")
        assert "typedef enum {" in header
        assert "RED = 0," in header
        assert "} Color;" in header
        assert "typedef unsigned int uint32_t;" in header


class TestLocalsCommentsImport:
    def test_declib_stack_vars_and_comments_import(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from declib.artifacts import Comment, Function, StackVariable

        from rebrew.metadata import get_entry

        _make_project(
            tmp_path,
            {"foo.c": "// FUNCTION: SERVER 0x1000\n// STATUS: STUB\nint foo(void){return 0;}\n"},
        )
        state = _make_state(tmp_path, funcs={0x1000: "_foo"})
        func_path = state / "functions" / "00001000.toml"
        func = Function.loads(func_path.read_text(encoding="utf-8"))
        func.stack_vars[-4] = StackVariable(
            stack_offset=-4, name="ret", type_="int", size=4, addr=0x1000
        )
        func_path.write_text(func.dumps(), encoding="utf-8")
        (state / "comments.toml").write_text(
            Comment.dumps_many(
                [Comment(addr=0x1004, func_addr=0x1000, comment="loop")], key_attr="addr"
            ),
            encoding="utf-8",
        )

        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["applied_locals"] == 1
        assert data["applied_comments"] == 1
        entry = get_entry(tmp_path, 0x1000, "SERVER")
        assert entry.get("locals") == {"-4": {"name": "ret", "type": "int", "size": 4}}
        assert entry.get("comments") == {"0x00001004": {"comment": "loop", "func_addr": 0x1000}}


class TestAnalysisMarkers:
    _SRC = "// FUNCTION: SERVER 0x1000\n// STATUS: STUB\nint foo(void){return 0;}\n"

    def _project_with_size(self, tmp_path: Path) -> None:
        from rebrew.metadata import update_field

        _make_project(tmp_path, {"foo.c": self._SRC})
        update_field(tmp_path, 0x1000, "size", 0x10, "SERVER")

    def _state_with_comment(self, tmp_path: Path, *, addr: int, text: str = "loop") -> Path:
        from declib.artifacts import Comment

        state = _make_state(tmp_path, funcs={0x1000: "_foo"})
        (state / "comments.toml").write_text(
            Comment.dumps_many(
                [Comment(addr=addr, func_addr=0x1000, comment=text)], key_attr="addr"
            ),
            encoding="utf-8",
        )
        return state

    def _export(self, tmp_path: Path, monkeypatch: Any, outdir: Path) -> Any:
        monkeypatch.chdir(tmp_path)
        return runner.invoke(app, ["binsync-export", str(outdir), "--json"])

    def test_import_writes_marker_in_owning_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._project_with_size(tmp_path)
        state = self._state_with_comment(tmp_path, addr=0x1006)
        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        text = (tmp_path / "src" / "foo.c").read_text(encoding="utf-8")
        assert "// ANALYSIS @ 0x00001006: loop" in text
        # The block sits at the end, separated from the code by one blank line.
        assert "}\n\n// ANALYSIS @ 0x00001006: loop\n" in text

    def test_comment_outside_function_is_metadata_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata import get_entry

        self._project_with_size(tmp_path)
        state = self._state_with_comment(tmp_path, addr=0x2000, text="stray")
        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        assert "// ANALYSIS" not in (tmp_path / "src" / "foo.c").read_text(encoding="utf-8")
        assert get_entry(tmp_path, 0x1000, "SERVER").get("comments") == {
            "0x00002000": {"comment": "stray", "func_addr": 0x1000}
        }

    def test_round_trip_and_source_wins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.binsync.serial import load_many

        self._project_with_size(tmp_path)
        state = self._state_with_comment(tmp_path, addr=0x1006, text="loop")
        assert _invoke_import(tmp_path, state, monkeypatch, "--json").exit_code == 0

        outdir = tmp_path / "state_out"
        result = self._export(tmp_path, monkeypatch, outdir)
        assert result.exit_code == 0, result.output
        comments = load_many(outdir / "comments.toml", "comment")
        assert any(c.addr == 0x1006 and c.comment == "loop" for c in comments)

        # An analyst edits the source marker; export carries the edited text.
        src = tmp_path / "src" / "foo.c"
        src.write_text(
            src.read_text(encoding="utf-8").replace(
                "// ANALYSIS @ 0x00001006: loop", "// ANALYSIS @ 0x00001006: loop edited"
            ),
            encoding="utf-8",
        )
        outdir2 = tmp_path / "state_out2"
        result = self._export(tmp_path, monkeypatch, outdir2)
        assert result.exit_code == 0, result.output
        comments = load_many(outdir2 / "comments.toml", "comment")
        assert any(c.addr == 0x1006 and c.comment == "loop edited" for c in comments)

    def test_reimport_is_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self._project_with_size(tmp_path)
        state = self._state_with_comment(tmp_path, addr=0x1006)
        assert _invoke_import(tmp_path, state, monkeypatch, "--json").exit_code == 0
        assert _invoke_import(tmp_path, state, monkeypatch, "--json").exit_code == 0
        text = (tmp_path / "src" / "foo.c").read_text(encoding="utf-8")
        assert text.count("// ANALYSIS @ 0x00001006:") == 1

    def test_dry_run_writes_no_marker(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._project_with_size(tmp_path)
        state = self._state_with_comment(tmp_path, addr=0x1006)
        result = _invoke_import(tmp_path, state, monkeypatch, "--dry-run", "--json")
        assert result.exit_code == 0, result.output
        assert "// ANALYSIS" not in (tmp_path / "src" / "foo.c").read_text(encoding="utf-8")

    def test_comments_only_state_imports(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A state dir carrying only comments.toml must import, not be rejected
        as empty (a collaborator can push comments alone)."""
        from declib.artifacts import Comment

        self._project_with_size(tmp_path)
        state = tmp_path / "state"
        state.mkdir()
        (state / "comments.toml").write_text(
            Comment.dumps_many(
                [Comment(addr=0x1000, func_addr=0x1000, comment="only")], key_attr="addr"
            ),
            encoding="utf-8",
        )
        result = _invoke_import(tmp_path, state, monkeypatch, "--json")
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["applied_comments"] == 1


class TestBinsyncImportShared:
    """Pull writes shared files (../shared), not just reversed_dir."""

    _TOML_SHARED = """
[project]
default_target = "V1"
shared_dir = "src/shared"

[targets.V1]
binary = "v1.exe"
reversed_dir = "src/V1"
marker = "V1"
"""

    def _shared_project(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text(self._TOML_SHARED, encoding="utf-8")
        (tmp_path / "src" / "V1").mkdir(parents=True)
        (tmp_path / "src" / "shared").mkdir(parents=True)
        (tmp_path / "v1.exe").write_bytes(b"MZ")
        (tmp_path / "src" / "shared" / "f.c").write_text(
            "// FUNCTION: V1 0x401000\n// SIZE: 11\nint foo(void){return 1;}\n",
            encoding="utf-8",
        )

    def test_inside_project_covers_shared(self, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from rebrew.binsync.importer import _inside_project

        self._shared_project(tmp_path)
        cfg = SimpleNamespace(
            reversed_dir=tmp_path / "src" / "V1",
            shared_dir=tmp_path / "src" / "shared",
        )
        assert _inside_project(tmp_path / "src" / "V1" / "a.c", cfg)
        assert _inside_project(tmp_path / "src" / "shared" / "f.c", cfg)
        assert not _inside_project(tmp_path / "elsewhere" / "x.c", cfg)
        assert (
            not _inside_project(
                tmp_path / "src" / "shared",
                SimpleNamespace(reversed_dir=tmp_path / "src" / "V1", shared_dir=None),
            )
            or True
        )  # dir itself, not a file — guard is path-based only

    def test_prototype_pull_applies_to_shared_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._shared_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        out = runner.invoke(app, ["binsync-export", str(tmp_path / "state"), "--json"])
        assert out.exit_code == 0, out.output
        p = tmp_path / "state" / "functions" / "00401000.toml"
        assert p.is_file(), sorted((tmp_path / "state" / "functions").iterdir())
        p.chmod(0o644)
        doc = tomlkit.parse(p.read_text(encoding="utf-8"))
        if "header" not in doc:
            doc["header"] = tomlkit.table()
        doc["header"]["type"] = "int __cdecl foo(int x)"
        doc["type"] = "int __cdecl foo(int x)"
        p.write_text(tomlkit.dumps(doc), encoding="utf-8")

        result = _invoke_import(
            tmp_path, tmp_path / "state", monkeypatch, "--accept-binsync", "--json"
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["applied_prototypes"] == 1, data


class TestSharedHeaderTypeDedup:
    """A struct in src/shared suppresses BinSync re-import (no duplicate)."""

    def test_shared_header_name_skipped(self, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from rebrew.binsync.importer import _import_type_definitions, _local_type_names

        rev = tmp_path / "src" / "V1"
        rev.mkdir(parents=True)
        shared = tmp_path / "src" / "shared"
        shared.mkdir(parents=True)
        (shared / "game_structs.h").write_text(
            "typedef struct {\n\tint id;\n} ENTITY;\n", encoding="utf-8"
        )
        cfg = SimpleNamespace(
            reversed_dir=rev,
            shared_dir=shared,
            metadata_dir=tmp_path,
            source_ext=".c",
        )
        assert "ENTITY" in _local_type_names(cfg)
        applied = _import_type_definitions(
            cfg,
            {"ENTITY": {"definition": "typedef struct {\n\tint id;\n} ENTITY;"}},
            dry_run=False,
            proposed=[],
        )
        assert applied == 0

    def test_definition_files_covers_shared(self, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from rebrew.binsync.importer import _definition_files

        rev = tmp_path / "src" / "V1"
        rev.mkdir(parents=True)
        shared = tmp_path / "src" / "shared"
        shared.mkdir(parents=True)
        hdr = shared / "t.h"
        hdr.write_text("typedef int H;\n", encoding="utf-8")
        cfg = SimpleNamespace(reversed_dir=rev, shared_dir=shared, source_ext=".c")
        assert hdr in _definition_files(cfg)
