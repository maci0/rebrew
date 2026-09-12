"""Tests for rebrew.binsync.overlay: cross-target BinSync overlay.

Uses the synthetic two-PE fixture pattern from ``test_cross_import`` so
``extract_raw_bytes`` yields real x86 bytes at the target VAs.  Target A is
the source (its BinSync state carries the names); target B is the destination
(the command's default target).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import tomlkit
from bin_util import make_pe
from typer.testing import CliRunner

from rebrew.main import app

runner = CliRunner()

pytest.importorskip("declib")

# Shared 32-bit x86 blob, identical in both PEs but at different VAs.
F1 = bytes.fromhex("55 8b ec 8b 05 00 00 00 00 5d c3")
A_F1 = 0x401000  # a.exe: image_base 0x400000 + .text 0x1000 + offset 0x00
B_F1 = 0x401040  # b.exe: same code at +0x40


def _place(slots: dict[int, bytes], total: int) -> bytes:
    arr = bytearray(total)
    for off, blob in slots.items():
        arr[off : off + len(blob)] = blob
    return bytes(arr)


def _pe_a() -> bytes:
    return make_pe(_place({0x00: F1}, 0x10))


def _pe_b() -> bytes:
    return make_pe(_place({0x40: F1}, 0x50))


def _make_project(tmp_path: Path) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(
        "[project]\nname = 'probe'\ndefault_target = 'B'\n"
        "[compiler]\nprofile = 'msvc6'\ncommand = 'CL.EXE'\n"
        "[targets.A]\nbinary = 'a.exe'\nreversed_dir = 'src/a'\n"
        "function_list = 'src/a/functions.txt'\n"
        "[targets.B]\nbinary = 'b.exe'\nreversed_dir = 'src/b'\n"
        "function_list = 'src/b/functions.txt'\n",
        encoding="utf-8",
    )
    (tmp_path / "a.exe").write_bytes(_pe_a())
    (tmp_path / "b.exe").write_bytes(_pe_b())
    (tmp_path / "src" / "a").mkdir(parents=True)
    (tmp_path / "src" / "b").mkdir(parents=True)
    (tmp_path / "src" / "a" / "functions.txt").write_text(
        f"0x{A_F1:08x} {len(F1)} f1\n", encoding="utf-8"
    )
    (tmp_path / "src" / "b" / "functions.txt").write_text(
        f"0x{B_F1:08x} {len(F1)} f1\n", encoding="utf-8"
    )
    return tmp_path


def _write_dest(tmp_path: Path, local_name: str = "func_401040") -> Path:
    dest = tmp_path / "src" / "b" / "f1.c"
    dest.write_text(
        f"// FUNCTION: B 0x{B_F1:08x}\nvoid {local_name}(void) {{ }}\n", encoding="utf-8"
    )
    return dest


def _make_state(
    tmp_path: Path,
    *,
    name: str = "_Meaningful",
    target: str | None = "A",
    va: int = A_F1,
    prototype: str | None = None,
    note: str | None = None,
) -> Path:
    from declib.artifacts import Comment, Function, FunctionHeader

    state = tmp_path / "state"
    funcs = state / "functions"
    funcs.mkdir(parents=True)
    (state / "metadata.toml").write_text('user = "test"\nversion = "test"\n', encoding="utf-8")
    header = FunctionHeader(name=name, addr=va, type_=prototype)
    func = Function(addr=va, size=0, header=header)
    (funcs / f"{va:08x}.toml").write_text(func.dumps(), encoding="utf-8")
    if note is not None:
        comment = Comment(addr=va + 1, func_addr=va, comment=f"[rebrew:note] {note}")
        (state / "comments.toml").write_text(Comment.dumps_many([comment]), encoding="utf-8")
    if target is not None:
        manifest = tomlkit.document()
        manifest["target"] = target
        (state / "manifest.toml").write_text(tomlkit.dumps(manifest), encoding="utf-8")
    return state


def _invoke(tmp_path: Path, state: Path, *extra: str) -> Any:
    return runner.invoke(app, ["binsync-overlay", str(state), *extra], catch_exceptions=False)


def _dest_text(tmp_path: Path) -> str:
    src_b = tmp_path / "src" / "b"
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(src_b.glob("*.c")))


# A distinctive 16-byte global, placed inside .text at different offsets.
G_BLOB = bytes.fromhex("de ad be ef 01 02 03 04 05 06 07 08 09 0a 0b 0c")
G_SRC = 0x401020  # a.exe: .text offset 0x20
G_DST = 0x401060  # b.exe: .text offset 0x60


def _pe_a_global() -> bytes:
    return make_pe(_place({0x00: F1, 0x20: G_BLOB}, 0x30))


def _pe_b_global(*, duplicate: bool = False) -> bytes:
    slots: dict[int, bytes] = {0x40: F1, 0x60: G_BLOB}
    total = 0x70
    if duplicate:
        slots[0x80] = G_BLOB
        total = 0x90
    return make_pe(_place(slots, total))


def _make_global_state(tmp_path: Path) -> Path:
    """A declib BinSync state with only a global (no function entries)."""
    from declib.artifacts import GlobalVariable

    state = tmp_path / "state"
    state.mkdir(parents=True)
    (state / "metadata.toml").write_text('user = "test"\nversion = "test"\n', encoding="utf-8")
    gvar = GlobalVariable(addr=G_SRC, name="g_shared", type_="unsigned char[16]", size=len(G_BLOB))
    (state / "global_vars.toml").write_text(GlobalVariable.dumps_many([gvar]), encoding="utf-8")
    manifest = tomlkit.document()
    manifest["target"] = "A"
    (state / "manifest.toml").write_text(tomlkit.dumps(manifest), encoding="utf-8")
    return state


class TestOverlayNameTransfer:
    def test_meaningful_name_moves_to_different_va(self, tmp_path: Path, monkeypatch) -> None:
        """The same code at a different VA transfers its BinSync name."""
        _make_project(tmp_path)
        dest = _write_dest(tmp_path, local_name="func_401040")
        state = _make_state(tmp_path)
        monkeypatch.chdir(tmp_path)

        result = _invoke(tmp_path, state, "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["from_target"] == "A"
        assert payload["target"] == "B"
        assert payload["matches"] == 1
        assert payload["applied_names"] == 1
        text = dest.read_text(encoding="utf-8")
        assert "Meaningful" in text
        assert "func_401040" not in text


class TestDryRun:
    def test_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        dest = _write_dest(tmp_path, local_name="func_401040")
        state = _make_state(tmp_path)
        monkeypatch.chdir(tmp_path)

        result = _invoke(tmp_path, state, "--dry-run", "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["dry_run"] is True
        assert payload["applied_names"] == 1
        assert dest.exists()
        assert "func_401040" in dest.read_text(encoding="utf-8")
        assert not (tmp_path / "src" / "b" / "Meaningful.c").exists()


class TestConflict:
    def _setup(self, tmp_path: Path, monkeypatch) -> tuple[Path, Path]:
        _make_project(tmp_path)
        dest = _write_dest(tmp_path, local_name="LocalName")
        state = _make_state(tmp_path, name="_RemoteName")
        monkeypatch.chdir(tmp_path)
        return dest, state

    def test_conflict_without_accept_exits_1(self, tmp_path: Path, monkeypatch) -> None:
        dest, state = self._setup(tmp_path, monkeypatch)
        result = _invoke(tmp_path, state, "--json")
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert len(payload["conflicts"]) == 1
        conflict = payload["conflicts"][0]
        assert conflict["field"] == "name"
        assert conflict["local"].lstrip("_") == "LocalName"
        assert conflict["remote"] == "_RemoteName"
        assert dest.exists()
        assert "LocalName" in dest.read_text(encoding="utf-8")

    def test_accept_binsync_renames(self, tmp_path: Path, monkeypatch) -> None:
        dest, state = self._setup(tmp_path, monkeypatch)
        result = _invoke(tmp_path, state, "--accept-binsync", "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["applied_names"] == 1
        assert "RemoteName" in _dest_text(tmp_path)

    def test_accept_local_keeps_and_records_provenance(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.metadata import get_entry

        dest, state = self._setup(tmp_path, monkeypatch)
        result = _invoke(tmp_path, state, "--accept-local", "--json")
        assert result.exit_code == 0, result.output
        assert dest.exists()
        assert "LocalName" in dest.read_text(encoding="utf-8")
        assert get_entry(tmp_path / "src", B_F1, "B").get("ghidra") == "_RemoteName"


class TestResolutionErrors:
    def test_empty_state_dir_errors(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        _write_dest(tmp_path)
        empty = tmp_path / "empty_state"
        empty.mkdir()
        monkeypatch.chdir(tmp_path)

        result = _invoke(tmp_path, empty, "--from", "A", "--json")
        assert result.exit_code != 0
        assert "No BinSync" in result.output

    def test_from_equal_to_destination_errors(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        _write_dest(tmp_path)
        state = _make_state(tmp_path)
        monkeypatch.chdir(tmp_path)

        result = _invoke(tmp_path, state, "--from", "B", "--json")
        assert result.exit_code != 0
        assert "--from must name a different target" in result.output


class TestSourceResolution:
    def test_manifest_target_used_when_from_omitted(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        _write_dest(tmp_path, local_name="func_401040")
        state = _make_state(tmp_path, target="A")
        monkeypatch.chdir(tmp_path)

        result = _invoke(tmp_path, state, "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["from_target"] == "A"

    def test_missing_target_errors(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        _write_dest(tmp_path)
        state = _make_state(tmp_path, target=None)
        monkeypatch.chdir(tmp_path)

        result = _invoke(tmp_path, state, "--json")
        assert result.exit_code != 0
        assert "cannot determine the source target" in result.output


class TestPrototypeAndNote:
    def test_prototype_conflict_and_accept(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        dest = _write_dest(tmp_path, local_name="func_401040")
        state = _make_state(tmp_path, prototype="int Meaningful(int x)")
        monkeypatch.chdir(tmp_path)

        result = _invoke(tmp_path, state, "--fields", "prototype", "--json")
        assert result.exit_code == 1
        payload = json.loads(result.output)
        assert payload["conflicts"][0]["field"] == "prototype"
        assert "PROTOTYPE" not in dest.read_text(encoding="utf-8")

        result = _invoke(tmp_path, state, "--fields", "prototype", "--accept-binsync", "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["applied_prototypes"] == 1
        assert "// PROTOTYPE: int Meaningful(int x)" in dest.read_text(encoding="utf-8")

    def test_note_applied(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.metadata import get_entry

        _make_project(tmp_path)
        _write_dest(tmp_path, local_name="func_401040")
        state = _make_state(tmp_path, note="needs RE")
        monkeypatch.chdir(tmp_path)

        result = _invoke(tmp_path, state, "--fields", "note", "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["applied_notes"] == 1
        assert get_entry(tmp_path / "src", B_F1, "B").get("note") == "needs RE"


class TestJsonShape:
    def test_json_keys_documented(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        _write_dest(tmp_path, local_name="func_401040")
        state = _make_state(tmp_path)
        monkeypatch.chdir(tmp_path)

        result = _invoke(tmp_path, state, "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert set(payload) == {
            "state_dir",
            "from_target",
            "target",
            "dry_run",
            "matches",
            "applied_names",
            "applied_prototypes",
            "applied_notes",
            "applied_globals",
            "applied_structs",
            "applied_enums",
            "applied_typedefs",
            "applied_locals",
            "applied_comments",
            "skipped",
            "touched_vas",
            "conflicts",
            "proposed",
        }
        assert payload["touched_vas"] == [f"0x{B_F1:08x}"]


class TestFieldsAndModule:
    def test_fields_restrict_to_name(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        _write_dest(tmp_path, local_name="func_401040")
        state = _make_state(
            tmp_path, name="_Meaningful", prototype="int Meaningful(void)", note="remote note"
        )
        monkeypatch.chdir(tmp_path)

        result = _invoke(tmp_path, state, "--fields", "name", "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["applied_names"] == 1
        assert payload["applied_prototypes"] == 0
        assert payload["applied_notes"] == 0

    def test_unknown_field_errors(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        _write_dest(tmp_path)
        state = _make_state(tmp_path)
        monkeypatch.chdir(tmp_path)

        result = _invoke(tmp_path, state, "--fields", "bogus", "--json")
        assert result.exit_code != 0
        assert "unknown --fields" in result.output


class TestMatchGlobalsByContent:
    """The pure content matcher (no binaries)."""

    def test_unique_occurrence_maps(self) -> None:
        from rebrew.binsync.overlay import match_globals_by_content

        assert match_globals_by_content({0x10: b"ABCD"}, [(0x1000, b"xxABCDyy")]) == {0x10: 0x1002}

    def test_duplicate_in_one_span_not_mapped(self) -> None:
        from rebrew.binsync.overlay import match_globals_by_content

        assert match_globals_by_content({0x10: b"ABCD"}, [(0x1000, b"ABCD..ABCD")]) == {}

    def test_duplicate_across_spans_not_mapped(self) -> None:
        from rebrew.binsync.overlay import match_globals_by_content

        spans = [(0x1000, b"AB"), (0x2000, b"..AB")]
        assert match_globals_by_content({0x10: b"AB"}, spans) == {}

    def test_absent_not_mapped(self) -> None:
        from rebrew.binsync.overlay import match_globals_by_content

        assert match_globals_by_content({0x10: b"ABCD"}, [(0x1000, b"nope")]) == {}

    def test_empty_needle_skipped(self) -> None:
        from rebrew.binsync.overlay import match_globals_by_content

        assert match_globals_by_content({0x10: b""}, [(0x1000, b"AB")]) == {}


class TestGlobalOverlay:
    def _setup(self, tmp_path: Path, monkeypatch, *, duplicate: bool = False) -> Path:
        _make_project(tmp_path)
        (tmp_path / "a.exe").write_bytes(_pe_a_global())
        (tmp_path / "b.exe").write_bytes(_pe_b_global(duplicate=duplicate))
        state = _make_global_state(tmp_path)
        monkeypatch.chdir(tmp_path)
        return state

    def test_unique_global_maps_and_applies(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.data_metadata import get_data_entry

        state = self._setup(tmp_path, monkeypatch)
        result = _invoke(tmp_path, state, "--fields", "global", "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["applied_globals"] == 1
        assert payload["touched_vas"] == [f"0x{G_DST:08x}"]
        stored = get_data_entry(tmp_path / "src", G_DST, "B")
        assert stored.get("name") == "g_shared"
        assert stored.get("section") == ".text"
        assert stored.get("size") == 16

    def test_duplicate_global_not_mapped(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.data_metadata import get_data_entry

        state = self._setup(tmp_path, monkeypatch, duplicate=True)
        result = _invoke(tmp_path, state, "--fields", "global", "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["applied_globals"] == 0
        assert get_data_entry(tmp_path / "src", G_DST, "B") == {}

    def test_globals_opt_in_only(self, tmp_path: Path, monkeypatch) -> None:
        """The default --fields set does not touch globals."""
        from rebrew.data_metadata import get_data_entry

        state = self._setup(tmp_path, monkeypatch)
        result = _invoke(tmp_path, state, "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["applied_globals"] == 0
        assert get_data_entry(tmp_path / "src", G_DST, "B") == {}


class TestEnumTypedefOverlay:
    def _setup(self, tmp_path: Path, monkeypatch) -> Path:
        from declib.artifacts import Enum, Typedef

        _make_project(tmp_path)
        _write_dest(tmp_path, local_name="func_401040")
        state = _make_state(tmp_path)
        (state / "enums.toml").write_text(
            Enum.dumps_many([Enum(name="E", members={"A": 0, "B": 5})], key_attr="name"),
            encoding="utf-8",
        )
        (state / "typedefs.toml").write_text(
            Typedef.dumps_many([Typedef(name="uint32_t", type_="unsigned int")], key_attr="name"),
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        return state

    def test_enums_and_typedefs_import_into_destination(self, tmp_path: Path, monkeypatch) -> None:
        state = self._setup(tmp_path, monkeypatch)
        result = _invoke(tmp_path, state, "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["applied_enums"] == 1
        assert payload["applied_typedefs"] == 1
        header = tmp_path / "src" / "b" / "binsync_types.h"
        text = header.read_text(encoding="utf-8")
        assert "typedef enum { A = 0, B = 5 } E;" in text
        assert "typedef unsigned int uint32_t;" in text


class TestLocalsCommentsOverlay:
    def test_locals_and_shifted_comments_transferred(self, tmp_path: Path, monkeypatch) -> None:
        from declib.artifacts import Comment, Function, StackVariable

        from rebrew.metadata import get_entry

        _make_project(tmp_path)
        _write_dest(tmp_path, local_name="func_401040")
        state = _make_state(tmp_path)
        func_path = state / "functions" / f"{A_F1:08x}.toml"
        func = Function.loads(func_path.read_text(encoding="utf-8"))
        func.size = 0x10
        func.stack_vars[-4] = StackVariable(
            stack_offset=-4, name="ret", type_="int", size=4, addr=A_F1
        )
        func_path.write_text(func.dumps(), encoding="utf-8")
        comment = Comment(addr=A_F1 + 4, func_addr=A_F1, comment="loop")
        (state / "comments.toml").write_text(Comment.dumps_many([comment]), encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        result = _invoke(tmp_path, state, "--json")
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["applied_locals"] == 1
        assert payload["applied_comments"] == 1
        entry = get_entry(tmp_path / "src", B_F1, "B")
        assert entry.get("locals") == {"-4": {"name": "ret", "type": "int", "size": 4}}
        assert entry.get("comments") == {
            f"0x{B_F1 + 4:08x}": {"comment": "loop", "func_addr": B_F1}
        }
