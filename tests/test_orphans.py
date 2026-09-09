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
