"""Tests for rebrew orphans CLI — list/prune orphaned metadata blocks + drop."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner


def _mock_cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    cfg = SimpleNamespace(
        root=tmp_path,
        reversed_dir=tmp_path / "reversed",
        metadata_dir=tmp_path,
        marker="SERVER",
        source_ext=".c",
        shared_dir=None,
        function_list=tmp_path / "functions.txt",
        dll_exports={},
    )
    import rebrew.cli as cli_mod
    import rebrew.orphans as orph

    monkeypatch.setattr(cli_mod, "load_config", lambda **kw: cfg)
    monkeypatch.setattr(orph, "require_config", lambda **kw: cfg)
    return cfg


def _write_project(tmp_path: Path, matched_orphan: bool = False) -> None:
    src = tmp_path / "reversed"
    src.mkdir(exist_ok=True)
    (src / "foo.c").write_text(
        "// FUNCTION: SERVER 0x1000\nint foo(void){return 0;}\n", encoding="utf-8"
    )
    blocks = (
        '["SERVER.0x1000"]\nstatus = "STUB"\nsize = 16\n\n'
        '["SERVER.0x2000"]\nstatus = "STUB"\nsize = 16\n'
    )
    if matched_orphan:
        blocks += '\n["SERVER.0x3000"]\nstatus = "EXACT"\nsize = 16\n'
    (tmp_path / "rebrew-functions.toml").write_text(blocks, encoding="utf-8")


class TestOrphansList:
    def test_lists_orphan_leaves_live(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, [])
        assert res.exit_code == 0, res.output
        assert "0x2000" in res.output
        assert "0x1000" not in res.output

    def test_clean_tree_reports_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        (src / "foo.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint foo(void){return 0;}\n", encoding="utf-8"
        )
        (tmp_path / "rebrew-functions.toml").write_text(
            '["SERVER.0x1000"]\nstatus = "STUB"\n', encoding="utf-8"
        )
        res = CliRunner().invoke(app, [])
        assert res.exit_code == 0, res.output
        assert "No orphaned" in res.output

    def test_json_lists_orphans(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["--json"])
        assert res.exit_code == 0, res.output
        payload = json.loads(res.output)
        assert payload["orphans"] == [
            {
                "module": "SERVER",
                "va": "0x2000",
                "store": "rebrew-functions.toml",
                "status": "STUB",
            }
        ]


class TestOrphansPrune:
    def test_prune_deletes_only_orphan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["--prune"])
        assert res.exit_code == 0, res.output
        assert "deleted 1" in res.output
        assert get_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_entry(tmp_path, 0x1000, "SERVER").get("status") == "STUB"

    def test_prune_dry_run_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["--prune", "--dry-run"])
        assert res.exit_code == 0, res.output
        assert "would be deleted" in res.output
        assert get_entry(tmp_path, 0x2000, "SERVER").get("status") == "STUB"

    def test_prune_json_deletes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Regression: --prune --json used to short-circuit on the listing path
        and report pruned: 0 without deleting anything."""
        import json

        from rebrew.metadata import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["--prune", "--json"])
        assert res.exit_code == 0, res.output
        out = json.loads(res.output)
        assert out["pruned"] == 1
        assert get_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_entry(tmp_path, 0x1000, "SERVER").get("status") == "STUB"

    def test_prune_include_matched_json(self, tmp_path: Path, monkeypatch) -> None:
        """--prune --include-matched --json reports held_back 0 and prunes matched."""
        import json

        from rebrew.metadata import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path, matched_orphan=True)
        res = CliRunner().invoke(app, ["--prune", "--include-matched", "--json"])
        assert res.exit_code == 0, res.output
        out = json.loads(res.output)
        assert out["pruned"] == 2
        assert out["held_back"] == 0
        assert get_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_entry(tmp_path, 0x3000, "SERVER") == {}


class TestKnownSourceWidening:
    """Ghidra/exports-only VAs are known functions, not orphans.

    A metadata block whose VA appears only in the Ghidra structure cache or
    the export table must survive orphan pruning — the source marker may
    simply not be reversed yet.
    """

    def _project_with_extra_known(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> SimpleNamespace:
        from rebrew.config import FUNCTION_STRUCTURE_JSON

        cfg = _mock_cfg(tmp_path, monkeypatch)
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        (src / "foo.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint foo(void){return 0;}\n", encoding="utf-8"
        )
        (tmp_path / "rebrew-functions.toml").write_text(
            '["SERVER.0x1000"]\nstatus = "STUB"\n\n'
            '["SERVER.0x2000"]\nstatus = "STUB"\nsize = 16\n\n'
            '["SERVER.0x3000"]\nstatus = "STUB"\nsize = 16\n\n'
            '["SERVER.0x4000"]\nstatus = "STUB"\nsize = 16\n',
            encoding="utf-8",
        )
        (tmp_path / "functions.txt").write_text("0x1000 16 foo\n", encoding="utf-8")
        (src / FUNCTION_STRUCTURE_JSON).write_text(
            '[{"va": 8192, "size": 16, "name": "ghidra_fn"}]', encoding="utf-8"
        )
        cfg.dll_exports = {0x3000: "exp_fn"}
        return cfg

    def test_ghidra_and_export_vas_not_orphans(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        from rebrew.orphans import app

        self._project_with_extra_known(tmp_path, monkeypatch)
        res = CliRunner().invoke(app, ["--json"])
        assert res.exit_code == 0, res.output
        payload = json.loads(res.output)
        vas = sorted(o["va"] for o in payload["orphans"])
        # 0x2000 lives only in the Ghidra structure cache, 0x3000 only in
        # dll_exports — both are known functions, not orphans.
        assert "0x2000" not in vas
        assert "0x3000" not in vas
        assert "0x4000" in vas  # truly unknown → orphan

    def test_prune_keeps_ghidra_and_export_blocks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata import get_entry
        from rebrew.orphans import app

        self._project_with_extra_known(tmp_path, monkeypatch)
        res = CliRunner().invoke(app, ["--prune", "--include-matched"])
        assert res.exit_code == 0, res.output
        assert get_entry(tmp_path, 0x2000, "SERVER").get("status") == "STUB"
        assert get_entry(tmp_path, 0x3000, "SERVER").get("status") == "STUB"
        assert get_entry(tmp_path, 0x4000, "SERVER") == {}


class TestDataOrphansNameExemption:
    """A name never claims a data block: named entries with no VA marker
    are orphans like any other (stale names used to accumulate silently)."""

    def _data_project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_cfg(tmp_path, monkeypatch)
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        (src / "g.c").write_text("// GLOBAL: SERVER 0x1000\nint g_live;\n", encoding="utf-8")
        (tmp_path / "rebrew-data.toml").write_text(
            '["SERVER.0x1000"]\nname = "g_live"\nsection = ".data"\nsize = 4\n\n'
            '["SERVER.0x2000"]\nname = "g_stale"\nsection = ".data"\nsize = 4\n\n'
            '["SERVER.0x3000"]\nsection = ".data"\nsize = 4\n\n'
            '["SERVER.0x4000"]\nname = "import_slot"\nsection = ".idata"\nsize = 4\n',
            encoding="utf-8",
        )

    def test_named_stale_entry_is_orphan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        from rebrew.orphans import app

        self._data_project(tmp_path, monkeypatch)
        res = CliRunner().invoke(app, ["--json"])
        assert res.exit_code == 0, res.output
        vas = sorted(
            o["va"] for o in json.loads(res.output)["orphans"] if o["store"] == "rebrew-data.toml"
        )
        assert vas == ["0x2000", "0x3000"]

    def test_prune_deletes_named_stale_keeps_import_inventory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.data_metadata import get_data_entry
        from rebrew.orphans import app

        self._data_project(tmp_path, monkeypatch)
        res = CliRunner().invoke(app, ["--prune", "--include-matched"])
        assert res.exit_code == 0, res.output
        assert get_data_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_data_entry(tmp_path, 0x3000, "SERVER") == {}
        assert get_data_entry(tmp_path, 0x1000, "SERVER").get("name") == "g_live"
        assert get_data_entry(tmp_path, 0x4000, "SERVER").get("name") == "import_slot"


class TestOrphansDrop:
    def test_drop_by_va(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.metadata import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["drop", "0x2000"])
        assert res.exit_code == 0, res.output
        assert get_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_entry(tmp_path, 0x1000, "SERVER").get("status") == "STUB"

    def test_drop_missing_va_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["drop", "0x9999"])
        assert res.exit_code != 0
        assert "nothing to drop" in res.output

    def test_drop_dry_run_keeps_block(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["drop", "0x2000", "--dry-run"])
        assert res.exit_code == 0, res.output
        assert "Would drop" in res.output
        assert get_entry(tmp_path, 0x2000, "SERVER").get("status") == "STUB"


class TestBatchDeletes:
    def test_delete_entries_batch(self, tmp_path: Path) -> None:
        from rebrew.metadata import delete_entries_batch, get_entry, save_metadata

        save_metadata(
            tmp_path,
            {
                ("SERVER", 0x1000): {"status": "STUB"},
                ("SERVER", 0x2000): {"status": "STUB", "size": 16},
            },
        )
        assert delete_entries_batch(tmp_path, [("SERVER", 0x2000), ("SERVER", 0x9999)]) == 1
        assert get_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_entry(tmp_path, 0x1000, "SERVER").get("status") == "STUB"

    def test_delete_data_entries_batch(self, tmp_path: Path) -> None:
        from rebrew.data_metadata import delete_data_entries_batch, get_data_entry, set_data_field

        set_data_field(tmp_path, 0x1000, "section", ".data", module="SERVER")
        set_data_field(tmp_path, 0x2000, "section", ".rdata", module="SERVER")
        assert delete_data_entries_batch(tmp_path, [("SERVER", 0x2000)]) == 1
        assert get_data_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_data_entry(tmp_path, 0x1000, "SERVER").get("section") == ".data"

    def test_matched_orphan_held_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        (src / "foo.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint foo(void){return 0;}\n", encoding="utf-8"
        )
        (tmp_path / "rebrew-functions.toml").write_text(
            '["SERVER.0x1000"]\nstatus = "STUB"\n\n'
            '["SERVER.0x2000"]\nstatus = "EXACT"\nsize = 16\n\n'
            '["SERVER.0x3000"]\nstatus = "STUB"\n',
            encoding="utf-8",
        )
        res = CliRunner().invoke(app, ["--prune"])
        assert res.exit_code == 0, res.output
        assert "Holding back 1 matched" in res.output
        assert "deleted 1" in res.output
        assert get_entry(tmp_path, 0x2000, "SERVER").get("status") == "EXACT"
        assert get_entry(tmp_path, 0x3000, "SERVER") == {}

    def test_include_matched_prunes_all(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        (src / "foo.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint foo(void){return 0;}\n", encoding="utf-8"
        )
        (tmp_path / "rebrew-functions.toml").write_text(
            '["SERVER.0x1000"]\nstatus = "STUB"\n\n'
            '["SERVER.0x2000"]\nstatus = "EXACT"\nsize = 16\n',
            encoding="utf-8",
        )
        res = CliRunner().invoke(app, ["--prune", "--include-matched"])
        assert res.exit_code == 0, res.output
        assert get_entry(tmp_path, 0x2000, "SERVER") == {}
