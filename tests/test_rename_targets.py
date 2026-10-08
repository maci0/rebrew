"""``rebrew source rename`` on a three-target project sharing one source tree.

Targets SERVER, GOLDTL and GOLD scan the same ``src``. ``spiel.c`` is built
into all three; ``GOLDTL.citizen.c`` is a GOLDTL-only twin. Every test drives
the umbrella CLI and asserts the written sources, the stores, or the JSON
change list.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

import pytest

_PROJECT = """\
[project]
name = "p"
default_target = "server.dll"

[compiler]
profile = "msvc-6.0"
command = "CL.EXE"

[targets."server.dll"]
binary = "server.dll"
marker = "SERVER"
reversed_dir = "src"

[targets."tl.exe"]
binary = "tl.exe"
marker = "GOLDTL"
reversed_dir = "src"

[targets."gold.exe"]
binary = "gold.exe"
marker = "GOLD"
reversed_dir = "src"
"""

_GAME_H = """\
#ifndef GAME_H
#define GAME_H
typedef struct OfficeSlot {
    int type;
    int entityId;
} OfficeSlot;
typedef struct PlayerSlot {
    int entityId;
    char name[16];
} PlayerSlot;
extern char* g_entity_type_table;
extern int g_rowless;
void gm_InitEntitySlots(void);
int gm_ClientOnly(int a);
void gm_RowLess(void);
void lb_SendLobbyConfig(int player);
#endif
"""

_SPIEL_C = """\
#include "../game.h"
int g_rowless;
void gm_InitEntitySlots(void)
{
    g_entity_type_table = 0; /* g_entity_type_table is reset here */
    g_rowless = sizeof(OfficeSlot);
}
int gm_ClientOnly(int a)
{
    return a + 1;
}
void gm_RowLess(void)
{
    gm_InitEntitySlots();
}
"""

_LOBBY_C = """\
#include "../game.h"
struct Packet { int lb_SendLobbyConfig; };
void lb_SendLobbyConfig(int player)
{
    struct Packet p;
    p.lb_SendLobbyConfig = player;
    log_msg("lb_SendLobbyConfig(): sent");
    /* lb_SendLobbyConfig answers lb_ExPlayerReady */
}
"""

_SERVER_C = """\
#include "game.h"
void srv_Tick(OfficeSlot* slot, PlayerSlot* player)
{
    gm_InitEntitySlots();
    lb_SendLobbyConfig(1);
    slot->entityId = player->entityId;
    ((OfficeSlot*) g_entity_type_table)[2].entityId = 0;
}
"""

_COMMAND_C = """\
#include "game.h"
void cm_ExCreateCitizen(void)
{
}
void cm_Dispatch(void)
{
    cm_ExCreateCitizen();
}
"""

_TL_CITIZEN_C = """\
void cm_ExCreateCitizen(void)
{
}
void tl_Use(void)
{
    cm_ExCreateCitizen();
    gm_InitEntitySlots();
}
"""

_BSS_C = "char* g_entity_type_table;\n"

_FUNCTIONS: list[tuple[str, int, str, str]] = [
    ("SERVER", 0x10001000, "src/game/spiel.c", "gm_InitEntitySlots"),
    ("GOLDTL", 0x00401000, "src/game/spiel.c", "gm_InitEntitySlots"),
    ("GOLD", 0x00501000, "src/game/spiel.c", "gm_InitEntitySlots"),
    ("GOLDTL", 0x00401100, "src/game/spiel.c", "gm_ClientOnly"),
    ("SERVER", 0x10002000, "src/command/lobby.c", "lb_SendLobbyConfig"),
    ("SERVER", 0x10003000, "src/server.c", "srv_Tick"),
    ("SERVER", 0x10004000, "src/command.c", "cm_ExCreateCitizen"),
    ("SERVER", 0x10004100, "src/command.c", "cm_Dispatch"),
    ("GOLDTL", 0x00402000, "src/GOLDTL.citizen.c", "cm_ExCreateCitizen"),
    ("GOLDTL", 0x00402100, "src/GOLDTL.citizen.c", "tl_Use"),
]

_DATA = """\
["SERVER.0x100a8c30"]
file = "src/bss.c"
marker_type = "DATA"
name = "g_entity_type_table"
type = "char*"
size = 4
section = ".bss"

["GOLDTL.0x00868050"]
file = "src/game.h"
marker_type = "GLOBAL"
name = "g_entity_type_table"
type = "char*"
size = 4
storage_kind = "alias"

["GOLD.0x007e3f30"]
file = "src/game.h"
marker_type = "GLOBAL"
name = "g_entity_type_table"
type = "char*"
size = 4
storage_kind = "alias"

["SERVER.0x100a9000"]
file = "src/bss.c"
marker_type = "DATA"
name = "g_office_slots"
type = "OfficeSlot[12]"
size = 96
section = ".bss"
"""


def _project(tmp_path: Path) -> Path:
    from rebrew.metadata import save_metadata

    root = tmp_path / "proj"
    src = root / "src"
    for rel, text in {
        "game.h": _GAME_H,
        "game/spiel.c": _SPIEL_C,
        "command/lobby.c": _LOBBY_C,
        "server.c": _SERVER_C,
        "command.c": _COMMAND_C,
        "GOLDTL.citizen.c": _TL_CITIZEN_C,
        "bss.c": _BSS_C,
    }.items():
        path = src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    (root / "rebrew-project.toml").write_text(_PROJECT, encoding="utf-8")
    for binary in ("server.dll", "tl.exe", "gold.exe"):
        (root / binary).write_bytes(b"MZ")
    save_metadata(
        root,
        {
            (module, va): {
                "file": file,
                "name": name,
                "symbol": f"_{name}",
                "marker_type": "FUNCTION",
                "locals": {"0x8": {"name": "slot", "type": "OfficeSlot*", "size": 4}}
                if name == "srv_Tick"
                else {},
            }
            for module, va, file, name in _FUNCTIONS
        },
    )
    (root / "rebrew-data.toml").write_text(_DATA, encoding="utf-8")
    return root


def _run(root: Path, monkeypatch: pytest.MonkeyPatch, *args: str) -> Any:
    from typer.testing import CliRunner

    from rebrew.main import app

    monkeypatch.chdir(root)
    return CliRunner().invoke(app, ["source", "rename", *args])


def _text(root: Path, rel: str) -> str:
    return (root / "src" / rel).read_text(encoding="utf-8")


def _functions(root: Path) -> dict[str, Any]:
    return tomllib.loads((root / "rebrew-functions.toml").read_text(encoding="utf-8"))


def _data(root: Path) -> dict[str, Any]:
    return tomllib.loads((root / "rebrew-data.toml").read_text(encoding="utf-8"))


def _row(rows: dict[str, Any], module: str, va: int) -> dict[str, Any]:
    for key, value in rows.items():
        mod, _, va_text = key.rpartition(".")
        if mod == module and va_text.startswith("0x") and int(va_text, 16) == va:
            return value
    raise KeyError(f"{module}.0x{va:x}")


def _snapshot(root: Path) -> dict[Path, bytes]:
    return {p: p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


class TestFunctionIdentity:
    def test_selected_identity_rewrites_definition_declarations_and_callers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        result = _run(root, monkeypatch, "lb_SendLobbyConfig", "lb_ExPlayerReadyStatus")
        assert result.exit_code == 0, result.output
        lobby = _text(root, "command/lobby.c")
        assert "void lb_ExPlayerReadyStatus(int player)" in lobby
        # A member of the same spelling, a string and a comment are not the function.
        assert "struct Packet { int lb_SendLobbyConfig; };" in lobby
        assert "p.lb_SendLobbyConfig = player;" in lobby
        assert '"lb_SendLobbyConfig(): sent"' in lobby
        assert "/* lb_SendLobbyConfig answers" in lobby
        assert "void lb_ExPlayerReadyStatus(int player);" in _text(root, "game.h")
        assert "lb_ExPlayerReadyStatus(1);" in _text(root, "server.c")
        row = _row(_functions(root), "SERVER", 0x10002000)
        assert (row["name"], row["symbol"]) == ("lb_ExPlayerReadyStatus", "_lb_ExPlayerReadyStatus")

    def test_comments_are_rewritten_only_on_request(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        result = _run(root, monkeypatch, "lb_SendLobbyConfig", "lb_Ready", "--comments")
        assert result.exit_code == 0, result.output
        lobby = _text(root, "command/lobby.c")
        assert "/* lb_Ready answers lb_ExPlayerReady */" in lobby
        assert '"lb_SendLobbyConfig(): sent"' in lobby

    def test_dry_run_lists_every_edit_and_row_without_writing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        before = _snapshot(root)
        result = _run(
            root, monkeypatch, "lb_SendLobbyConfig", "lb_ExPlayerReadyStatus", "--dry-run", "--json"
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        edits = {(f["file"], e["line"], e["column"]) for f in payload["files"] for e in f["edits"]}
        assert edits == {
            ("src/command/lobby.c", 3, 6),
            ("src/game.h", 16, 6),
            ("src/server.c", 5, 5),
        }
        assert payload["rows"] == [
            {
                "store": "function",
                "module": "SERVER",
                "va": "0x10002000",
                "old": {"name": "lb_SendLobbyConfig", "symbol": "_lb_SendLobbyConfig"},
                "new": {"name": "lb_ExPlayerReadyStatus", "symbol": "_lb_ExPlayerReadyStatus"},
            }
        ]
        assert payload["dry_run"] is True
        assert _snapshot(root) == before

    def test_shared_definition_needs_all_modules(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        before = _snapshot(root)
        result = _run(root, monkeypatch, "gm_InitEntitySlots", "gm_KillAllSpieler")
        assert result.exit_code != 0
        assert "GOLDTL.0x00401000" in result.output
        assert "GOLD.0x00501000" in result.output
        assert "src/game/spiel.c" in result.output
        assert "--all-modules" in result.output
        assert _snapshot(root) == before

        result = _run(root, monkeypatch, "gm_InitEntitySlots", "gm_KillAllSpieler", "--all-modules")
        assert result.exit_code == 0, result.output
        rows = _functions(root)
        for module, va in (("SERVER", 0x10001000), ("GOLDTL", 0x401000), ("GOLD", 0x501000)):
            assert _row(rows, module, va)["name"] == "gm_KillAllSpieler"
        # The GOLDTL-only caller links the shared definition, so it follows.
        assert "gm_KillAllSpieler();" in _text(root, "GOLDTL.citizen.c")
        assert "gm_KillAllSpieler();" in _text(root, "server.c")

    def test_module_identity_renames_one_twin(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        result = _run(root, monkeypatch, "GOLDTL.0x00402000", "d3_AllocObjAnim")
        assert result.exit_code == 0, result.output
        tl = _text(root, "GOLDTL.citizen.c")
        assert "void d3_AllocObjAnim(void)" in tl
        assert "d3_AllocObjAnim();" in tl
        # The server's definition and its callers keep their name.
        assert _text(root, "command.c") == _COMMAND_C
        rows = _functions(root)
        assert _row(rows, "GOLDTL", 0x402000)["name"] == "d3_AllocObjAnim"
        assert _row(rows, "SERVER", 0x10004000)["name"] == "cm_ExCreateCitizen"

    def test_default_target_renames_its_twin_and_reports_the_other(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        result = _run(root, monkeypatch, "cm_ExCreateCitizen", "cm_ExAllocCharacter", "--json")
        assert result.exit_code == 0, result.output
        assert "void cm_ExAllocCharacter(void)" in _text(root, "command.c")
        assert _text(root, "GOLDTL.citizen.c") == _TL_CITIZEN_C
        notes = json.loads(result.stdout)["notes"]
        assert any("GOLDTL.0x00402000" in note for note in notes)

    def test_all_modules_renames_every_twin(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        result = _run(
            root, monkeypatch, "cm_ExCreateCitizen", "cm_ExAllocCharacter", "--all-modules"
        )
        assert result.exit_code == 0, result.output
        assert "cm_ExCreateCitizen" not in _text(root, "command.c")
        assert "cm_ExCreateCitizen" not in _text(root, "GOLDTL.citizen.c")
        rows = _functions(root)
        assert _row(rows, "GOLDTL", 0x402000)["name"] == "cm_ExAllocCharacter"
        assert _row(rows, "SERVER", 0x10004000)["name"] == "cm_ExAllocCharacter"

    def test_common_header_between_twins_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        header = root / "src" / "game.h"
        header.write_text(
            _GAME_H.replace("#endif", "void cm_ExCreateCitizen(void);\n#endif"), encoding="utf-8"
        )
        before = _snapshot(root)
        result = _run(root, monkeypatch, "cm_ExCreateCitizen", "cm_ExAllocCharacter")
        assert result.exit_code != 0
        assert "ambiguous" in result.output
        assert "game.h" in result.output
        assert _snapshot(root) == before

    def test_new_name_already_in_code_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        before = _snapshot(root)
        result = _run(root, monkeypatch, "lb_SendLobbyConfig", "gm_RowLess")
        assert result.exit_code != 0
        assert "duplicate symbol" in result.output
        assert _snapshot(root) == before

    @pytest.mark.parametrize(("module", "refused"), [("GOLDTL", False), ("SERVER", True)])
    def test_row_name_collision_counts_only_the_renamed_module(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, module: str, refused: bool
    ) -> None:
        """A library row of another image may carry the new name: that image links alone."""
        from rebrew.metadata import load_metadata, save_metadata

        root = _project(tmp_path)
        (root / "src" / "library_crt.h").write_text(
            "/* __crtMessageBoxA: LIBCMT */\n", encoding="utf-8"
        )
        rows = load_metadata(root)
        rows[(module, 0x00657000)] = {
            "file": "src/library_crt.h",
            "name": "__crtMessageBoxA",
            "symbol": "___crtMessageBoxA",
            "marker_type": "LIBRARY",
        }
        save_metadata(root, rows)
        before = _snapshot(root)
        result = _run(root, monkeypatch, "lb_SendLobbyConfig", "__crtMessageBoxA")
        if refused:
            assert result.exit_code != 0
            assert "duplicate symbol" in result.output
            assert _snapshot(root) == before
        else:
            assert result.exit_code == 0, result.output
            after = _functions(root)
            assert _row(after, "SERVER", 0x10002000)["name"] == "__crtMessageBoxA"
            assert _row(after, "GOLDTL", 0x00657000)["symbol"] == "___crtMessageBoxA"


class TestSourceLevelSymbol:
    def test_rowless_function_is_renamed_in_every_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        result = _run(root, monkeypatch, "gm_RowLess", "gm_KillAll", "--json")
        assert result.exit_code == 0, result.output
        assert "void gm_KillAll(void)\n" in _text(root, "game/spiel.c")
        assert "void gm_KillAll(void);" in _text(root, "game.h")
        assert json.loads(result.stdout)["rows"] == []

    def test_rowless_in_target_updates_the_other_modules_rows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        result = _run(root, monkeypatch, "gm_ClientOnly", "gm_GetGebaeudeHauptraum")
        assert result.exit_code == 0, result.output
        assert "int gm_GetGebaeudeHauptraum(int a)" in _text(root, "game/spiel.c")
        row = _row(_functions(root), "GOLDTL", 0x401100)
        assert (row["name"], row["symbol"]) == (
            "gm_GetGebaeudeHauptraum",
            "_gm_GetGebaeudeHauptraum",
        )

    def test_unknown_name_is_not_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        result = _run(root, monkeypatch, "nope_nothing", "x_new")
        assert result.exit_code != 0
        assert "Could not find function" in result.output


class TestDataRename:
    def test_shared_global_needs_all_modules(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        before = _snapshot(root)
        result = _run(root, monkeypatch, "g_entity_type_table", "lpGebaeudePROT", "--data")
        assert result.exit_code != 0
        assert "GOLDTL.0x00868050" in result.output
        assert _snapshot(root) == before

        result = _run(
            root, monkeypatch, "g_entity_type_table", "lpGebaeudePROT", "--data", "--all-modules"
        )
        assert result.exit_code == 0, result.output
        assert _text(root, "bss.c") == "char* lpGebaeudePROT;\n"
        assert "extern char* lpGebaeudePROT;" in _text(root, "game.h")
        spiel = _text(root, "game/spiel.c")
        assert "lpGebaeudePROT = 0; /* g_entity_type_table is reset here */" in spiel
        assert "(OfficeSlot*) lpGebaeudePROT)" in _text(root, "server.c")
        data = _data(root)
        for module, va in (("SERVER", 0x100A8C30), ("GOLDTL", 0x868050), ("GOLD", 0x7E3F30)):
            assert _row(data, module, va)["name"] == "lpGebaeudePROT"
            assert _row(data, module, va)["updated_by"] == "rename"

    def test_module_identity_selects_the_row(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        result = _run(
            root,
            monkeypatch,
            "GOLD.0x007e3f30",
            "lpGebaeudePROT",
            "--data",
            "--dry-run",
            "--json",
        )
        assert result.exit_code != 0
        payload = json.loads(result.stdout)
        assert "SERVER.0x100a8c30" in payload["error"]

    def test_rowless_global_is_renamed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        result = _run(root, monkeypatch, "g_rowless", "gm_RowlessCount", "--data")
        assert result.exit_code == 0, result.output
        spiel = _text(root, "game/spiel.c")
        assert "int gm_RowlessCount;" in spiel
        assert "gm_RowlessCount = sizeof(OfficeSlot);" in spiel
        assert "extern int gm_RowlessCount;" in _text(root, "game.h")


class TestTypeRename:
    def test_type_rename_rewrites_uses_and_row_types(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        result = _run(root, monkeypatch, "OfficeSlot", "OFFICE_SLOT", "--type")
        assert result.exit_code == 0, result.output
        header = _text(root, "game.h")
        assert "typedef struct OFFICE_SLOT {" in header
        assert "} OFFICE_SLOT;" in header
        assert "sizeof(OFFICE_SLOT)" in _text(root, "game/spiel.c")
        server = _text(root, "server.c")
        assert "void srv_Tick(OFFICE_SLOT* slot, PlayerSlot* player)" in server
        assert "((OFFICE_SLOT*) g_entity_type_table)" in server
        assert _row(_data(root), "SERVER", 0x100A9000)["type"] == "OFFICE_SLOT[12]"
        locals_ = _row(_functions(root), "SERVER", 0x10003000)["locals"]
        assert locals_["0x8"]["type"] == "OFFICE_SLOT*"

    def test_type_rename_onto_existing_type_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        before = _snapshot(root)
        result = _run(root, monkeypatch, "OfficeSlot", "PlayerSlot", "--type")
        assert result.exit_code != 0
        assert "already used" in result.output
        assert _snapshot(root) == before

    def test_unknown_type_is_refused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        root = _project(tmp_path)
        result = _run(root, monkeypatch, "gm_RowLess", "GM", "--type")
        assert result.exit_code != 0
        assert "no struct, union, enum or typedef" in result.output


class TestFieldRename:
    def test_field_rename_resolves_the_owning_struct(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        result = _run(root, monkeypatch, "OfficeSlot.entityId", "mplayerid", "--field")
        assert result.exit_code == 0, result.output
        header = _text(root, "game.h")
        assert "    int mplayerid;\n} OfficeSlot;" in header
        # PlayerSlot keeps its own member of the same name.
        assert "    int entityId;\n    char name[16];" in header
        server = _text(root, "server.c")
        assert "slot->mplayerid = player->entityId;" in server
        assert "((OfficeSlot*) g_entity_type_table)[2].mplayerid = 0;" in server

    def test_unresolved_access_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        (root / "src" / "unknown.c").write_text(
            "int f(void) { return lookup()->entityId; }\n", encoding="utf-8"
        )
        before = _snapshot(root)
        result = _run(root, monkeypatch, "OfficeSlot.entityId", "mplayerid", "--field")
        assert result.exit_code != 0
        assert "unknown.c:1" in result.output
        assert _snapshot(root) == before

    def test_existing_member_name_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        result = _run(root, monkeypatch, "OfficeSlot.entityId", "type", "--field")
        assert result.exit_code != 0
        assert "already has a member type" in result.output


class TestMsvcSyntax:
    def test_mask_keeps_offsets_and_parses_msvc_definitions(self) -> None:
        from rebrew.c_parser import mask_msvc_syntax, parse_c_source

        source = (
            "Bank* __cdecl load(Bank* bank)\n{\n\t__asm {\n\t\tmov edi, bank // keep\n\t}\n"
            "\treturn bank;\n}\n"
        )
        masked = mask_msvc_syntax(source)
        assert len(masked.encode()) == len(source.encode())
        assert "// keep" in masked
        assert "mov" not in masked and "__cdecl" not in masked
        tree, _data = parse_c_source(masked)
        assert [n.type for n in tree.root_node.children] == ["function_definition"]

    def test_asm_operand_and_pointer_returning_cdecl_definition(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        (root / "src" / "bss.c").write_text(
            "char* __cdecl g_lookup(void);\nchar* g_entity_type_table;\n", encoding="utf-8"
        )
        (root / "src" / "asm.c").write_text(
            "char* __cdecl g_lookup(void)\n{\n\t__asm {\n\t\tmov eax, g_entity_type_table\n\t}\n}\n",
            encoding="utf-8",
        )
        result = _run(
            root, monkeypatch, "g_entity_type_table", "lpGebaeudePROT", "--data", "--all-modules"
        )
        assert result.exit_code == 0, result.output
        assert "mov eax, lpGebaeudePROT" in _text(root, "asm.c")

    def test_field_resolution_through_msvc_and_initializers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        (root / "src" / "slots.c").write_text(
            '#include "game.h"\n'
            "#define SPARE g_spare.entityId\n"
            "extern PlayerSlot g_spare;\n"
            "OfficeSlot g_first = { .type = 1, .entityId = 2 };\n"
            "int __cdecl slot_id(OfficeSlot* slot)\n{\n"
            "\t__asm { mov eax, slot }\n"
            "\treturn slot->entityId + offsetof(OfficeSlot, entityId) + SPARE;\n}\n",
            encoding="utf-8",
        )
        result = _run(root, monkeypatch, "OfficeSlot.entityId", "mplayerid", "--field")
        assert result.exit_code == 0, result.output
        slots = _text(root, "slots.c")
        assert "#define SPARE g_spare.entityId" in slots
        assert "{ .type = 1, .mplayerid = 2 }" in slots
        assert "slot->mplayerid + offsetof(OfficeSlot, mplayerid) + SPARE" in slots


class TestStaticAndRollback:
    def test_static_definition_renames_only_its_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        (root / "src" / "a.c").write_text(
            "static int helper(void) { return 1; }\nint a(void) { return helper(); }\n",
            encoding="utf-8",
        )
        (root / "src" / "b.c").write_text(
            "static int helper(void) { return 2; }\nint b(void) { return helper(); }\n",
            encoding="utf-8",
        )
        from rebrew.metadata import save_metadata

        save_metadata(
            root,
            {
                ("SERVER", 0x10005000): {
                    "file": "src/a.c",
                    "name": "helper",
                    "symbol": "_helper",
                    "marker_type": "FUNCTION",
                }
            },
        )
        result = _run(root, monkeypatch, "SERVER.0x10005000", "a_helper")
        assert result.exit_code == 0, result.output
        assert "return a_helper();" in _text(root, "a.c")
        assert "helper" in _text(root, "b.c") and "a_helper" not in _text(root, "b.c")

    def test_failed_write_restores_sources_and_keeps_rows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.rename_ops as rename_ops

        root = _project(tmp_path)
        before = _snapshot(root)
        real_write = rename_ops.atomic_write_text

        def write(path: Path, text: str, *, encoding: str = "utf-8") -> None:
            if path.name == "server.c" and "lb_ExPlayerReadyStatus" in text:
                raise PermissionError(13, "read-only")
            real_write(path, text, encoding=encoding)

        monkeypatch.setattr(rename_ops, "atomic_write_text", write)
        result = _run(root, monkeypatch, "lb_SendLobbyConfig", "lb_ExPlayerReadyStatus")
        assert result.exit_code != 0
        assert "restored" in result.output
        assert _snapshot(root) == before
