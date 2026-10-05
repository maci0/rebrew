"""Tests for rebrew.lint_cflags — W029 redundant CFLAGS analysis and its --fix writer.

The `--fix` path edits the user's ``rebrew-project.toml``, so both halves are
pinned: what counts as redundant, and exactly which keys the writer may remove.
A key dropped while another level still supplies different flags would silently
change how a module compiles.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from rebrew.lint_cflags import (
    RedundantPreset,
    cflags_key,
    check_redundant_cflags,
    drop_redundant_presets,
    inline_equals_store,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PROJECT_TOML = """\
# project cflags
[compiler]
cflags = "/O2 /Gd"

[compiler.cflags_presets]
SERVER = "/Gd /O2"
CLIENT = "/O1"
"""


def _cfg(root: Path, **overrides: Any) -> Any:
    """A ProjectConfig stand-in: lint_cflags only ever getattr()s it."""
    defaults: dict[str, Any] = {
        "root": root,
        "target_name": "",
        "cflags": "/O2 /Gd",
        "cflags_explicit": True,
        "cflags_presets": {},
        "posix_style": False,
        "metadata_dir": root / "metadata",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _write_project(root: Path, text: str = PROJECT_TOML) -> Path:
    path = root / "rebrew-project.toml"
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Comparison keys
# ---------------------------------------------------------------------------


class TestCflagsKey:
    def test_flag_order_carries_no_meaning(self) -> None:
        assert cflags_key("/O2 /Gd") == cflags_key("/Gd /O2")

    def test_a_different_flag_set_is_a_different_key(self) -> None:
        assert cflags_key("/O2 /Gd") != cflags_key("/O2 /Gd /Ow")


class TestInlineEqualsStore:
    def test_cflags_compare_order_insensitively(self) -> None:
        assert inline_equals_store("CFLAGS", " /O2 /Gd ", "/Gd /O2") is True

    def test_other_keys_compare_as_stripped_strings(self) -> None:
        assert inline_equals_store("BLOCKER", " ring0 halt ", "ring0 halt") is True

    def test_a_differing_value_is_not_a_duplicate(self) -> None:
        """Deleting a differing inline copy would destroy information."""
        assert inline_equals_store("BLOCKER", "ring0 halt", "1B diff") is False
        assert inline_equals_store("CFLAGS", "/O2 /Gd", "/O1") is False

    def test_cflags_define_is_not_a_disagreement(self) -> None:
        assert inline_equals_store("CFLAGS", "/O2 /Gd", "/DREBREW_ALLOW_NAKED /Gd /O2") is True

    def test_size_compares_numerically(self) -> None:
        assert inline_equals_store("SIZE", "32", "0x20") is True
        assert inline_equals_store("SIZE", "31", "0x20") is False


# ---------------------------------------------------------------------------
# check_redundant_cflags
# ---------------------------------------------------------------------------


class TestCheckRedundantCflags:
    def test_no_config_reports_nothing(self) -> None:
        assert check_redundant_cflags(None) == ([], [])

    def test_a_preset_restating_project_cflags_is_a_hit(self) -> None:
        cfg = _cfg(Path("/nonexistent"), cflags_presets={"SERVER": "/Gd /O2"})
        presets, functions = check_redundant_cflags(cfg, {})
        assert [(p.module, p.cflags, p.inherited) for p in presets] == [
            ("SERVER", "/Gd /O2", "/O2 /Gd")
        ]
        assert functions == []
        assert presets[0].message() == "cflags_presets.SERVER = '/Gd /O2' (= project cflags)"

    def test_a_preset_that_adds_a_flag_is_kept(self) -> None:
        cfg = _cfg(Path("/nonexistent"), cflags_presets={"SERVER": "/O2 /Gd /Ow"})
        assert check_redundant_cflags(cfg, {})[0] == []

    def test_preset_keys_are_matched_case_insensitively(self) -> None:
        cfg = _cfg(Path("/nonexistent"), cflags_presets={"server": "/O2 /Gd"})
        assert [p.module for p in check_redundant_cflags(cfg, {})[0]] == ["server"]

    def test_function_cflags_restating_the_inherited_ladder_is_a_hit(self) -> None:
        cfg = _cfg(Path("/nonexistent"))
        metadata = {("SERVER", 0x1000): {"cflags": "/Gd /O2"}}
        presets, functions = check_redundant_cflags(cfg, metadata)
        assert presets == []
        assert [(f.module, f.va, f.cflags) for f in functions] == [("SERVER", 0x1000, "/Gd /O2")]
        assert functions[0].message() == "SERVER 0x1000: cflags '/Gd /O2' (= inherited '/O2 /Gd')"

    def test_function_cflags_that_add_a_flag_are_kept(self) -> None:
        cfg = _cfg(Path("/nonexistent"))
        metadata = {("SERVER", 0x1000): {"cflags": "/O2 /Gd /DREBREW_ALLOW_NAKED"}}
        assert check_redundant_cflags(cfg, metadata)[1] == []

    def test_an_entry_without_cflags_is_not_a_hit(self) -> None:
        cfg = _cfg(Path("/nonexistent"))
        metadata = {("SERVER", 0x1000): {"status": "EXACT"}, ("SERVER", 0x2000): {"cflags": ""}}
        assert check_redundant_cflags(cfg, metadata)[1] == []


# ---------------------------------------------------------------------------
# drop_redundant_presets
# ---------------------------------------------------------------------------


class TestDropRedundantPresets:
    def test_no_hits_touches_nothing(self, tmp_path: Path) -> None:
        path = _write_project(tmp_path)
        before = path.read_text(encoding="utf-8")
        assert drop_redundant_presets(_cfg(tmp_path), [], dry_run=False) == 0
        assert path.read_text(encoding="utf-8") == before

    def test_a_missing_project_file_is_a_no_op(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        hit = RedundantPreset(module="SERVER", cflags="/O2 /Gd", inherited="/O2 /Gd")
        assert drop_redundant_presets(cfg, [hit], dry_run=False) == 0

    def test_an_unparseable_project_file_is_left_alone(self, tmp_path: Path) -> None:
        path = _write_project(tmp_path, "[compiler\ncflags = \n")
        hit = RedundantPreset(module="SERVER", cflags="/O2 /Gd", inherited="/O2 /Gd")
        assert drop_redundant_presets(_cfg(tmp_path), [hit], dry_run=False) == 0
        assert path.read_text(encoding="utf-8") == "[compiler\ncflags = \n"

    def test_a_redundant_preset_is_removed_and_the_rest_survives(self, tmp_path: Path) -> None:
        import tomllib

        path = _write_project(tmp_path)
        hit = RedundantPreset(module="SERVER", cflags="/Gd /O2", inherited="/O2 /Gd")
        assert drop_redundant_presets(_cfg(tmp_path), [hit], dry_run=False) == 1

        text = path.read_text(encoding="utf-8")
        doc = tomllib.loads(text)
        assert doc["compiler"]["cflags_presets"] == {"CLIENT": "/O1"}
        # The rewrite is tomlkit in-place editing, not a re-serialization.
        assert "# project cflags" in text

    def test_the_last_preset_removes_the_empty_table(self, tmp_path: Path) -> None:
        import tomllib

        _write_project(
            tmp_path,
            '[compiler]\ncflags = "/O2 /Gd"\n\n[compiler.cflags_presets]\nSERVER = "/O2 /Gd"\n',
        )
        hit = RedundantPreset(module="SERVER", cflags="/O2 /Gd", inherited="/O2 /Gd")
        assert drop_redundant_presets(_cfg(tmp_path), [hit], dry_run=False) == 1
        assert (
            "cflags_presets"
            not in tomllib.loads((tmp_path / "rebrew-project.toml").read_text(encoding="utf-8"))[
                "compiler"
            ]
        )

    def test_dry_run_counts_without_writing(self, tmp_path: Path) -> None:
        path = _write_project(tmp_path)
        before = path.read_text(encoding="utf-8")
        hit = RedundantPreset(module="SERVER", cflags="/Gd /O2", inherited="/O2 /Gd")
        assert drop_redundant_presets(_cfg(tmp_path), [hit], dry_run=True) == 1
        assert path.read_text(encoding="utf-8") == before

    def test_a_target_override_with_other_flags_keeps_the_global_preset(
        self, tmp_path: Path
    ) -> None:
        """Dropping the global preset here would leave the module on the
        target's /O1 instead of the project default: a silent build change."""
        _write_project(
            tmp_path,
            """\
[compiler]
cflags = "/O2 /Gd"

[compiler.cflags_presets]
SERVER = "/O2 /Gd"

[targets.server_dll.compiler.cflags_presets]
SERVER = "/O1"
""",
        )
        hit = RedundantPreset(module="SERVER", cflags="/O2 /Gd", inherited="/O2 /Gd")
        assert (
            drop_redundant_presets(_cfg(tmp_path, target_name="server_dll"), [hit], dry_run=False)
            == 0
        )
        assert "SERVER" in (tmp_path / "rebrew-project.toml").read_text(encoding="utf-8")

    def test_a_redundant_target_preset_is_removed(self, tmp_path: Path) -> None:
        import tomllib

        _write_project(
            tmp_path,
            """\
[compiler]
cflags = "/O2 /Gd"

[targets.server_dll]
binary = "original/Server/server.dll"

[targets.server_dll.compiler.cflags_presets]
SERVER = "/O2 /Gd"
""",
        )
        hit = RedundantPreset(module="SERVER", cflags="/O2 /Gd", inherited="/O2 /Gd")
        assert (
            drop_redundant_presets(_cfg(tmp_path, target_name="server_dll"), [hit], dry_run=False)
            == 1
        )
        doc = tomllib.loads((tmp_path / "rebrew-project.toml").read_text(encoding="utf-8"))
        target = doc["targets"]["server_dll"]
        # The emptied [.. compiler] table goes with its last key; the target
        # itself and its other keys are untouched.
        assert target.get("compiler", {}).get("cflags_presets") is None
        assert target["binary"] == "original/Server/server.dll"

    def test_a_target_preset_is_kept_when_the_global_preset_supplies_other_flags(
        self, tmp_path: Path
    ) -> None:
        """The target preset restates project cflags, but removing it would
        hand the module the global /O1 instead — a silent build change."""
        import tomllib

        _write_project(
            tmp_path,
            """\
[compiler]
cflags = "/O2 /Gd"

[compiler.cflags_presets]
SERVER = "/O1"

[targets.server_dll.compiler.cflags_presets]
SERVER = "/O2 /Gd"
""",
        )
        hit = RedundantPreset(module="SERVER", cflags="/O2 /Gd", inherited="/O2 /Gd")
        assert (
            drop_redundant_presets(_cfg(tmp_path, target_name="server_dll"), [hit], dry_run=False)
            == 0
        )
        doc = tomllib.loads((tmp_path / "rebrew-project.toml").read_text(encoding="utf-8"))
        assert doc["targets"]["server_dll"]["compiler"]["cflags_presets"] == {"SERVER": "/O2 /Gd"}
        assert doc["compiler"]["cflags_presets"] == {"SERVER": "/O1"}

    def test_both_levels_restating_project_cflags_are_dropped(self, tmp_path: Path) -> None:
        import tomllib

        _write_project(
            tmp_path,
            """\
[compiler]
cflags = "/O2 /Gd"

[compiler.cflags_presets]
SERVER = "/Gd /O2"

[targets.server_dll]
binary = "original/Server/server.dll"

[targets.server_dll.compiler.cflags_presets]
SERVER = "/O2 /Gd"
""",
        )
        hit = RedundantPreset(module="SERVER", cflags="/Gd /O2", inherited="/O2 /Gd")
        assert (
            drop_redundant_presets(_cfg(tmp_path, target_name="server_dll"), [hit], dry_run=False)
            == 1
        )
        doc = tomllib.loads((tmp_path / "rebrew-project.toml").read_text(encoding="utf-8"))
        assert "cflags_presets" not in doc["compiler"]
        target = doc["targets"]["server_dll"]
        assert target.get("compiler", {}).get("cflags_presets") is None
        assert target["binary"] == "original/Server/server.dll"

    def test_a_hit_naming_an_unknown_module_writes_nothing(self, tmp_path: Path) -> None:
        path = _write_project(tmp_path)
        before = path.read_text(encoding="utf-8")
        hit = RedundantPreset(module="GHOST", cflags="/O2 /Gd", inherited="/O2 /Gd")
        assert drop_redundant_presets(_cfg(tmp_path), [hit], dry_run=False) == 0
        assert path.read_text(encoding="utf-8") == before
