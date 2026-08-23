"""Tests for rebrew blocker CLI — programmatic BLOCKER writer."""

from pathlib import Path

from typer.testing import CliRunner


def _mock_cfg(tmp_path: Path, monkeypatch) -> None:
    """Patch load_config / require_config to return a fake cfg rooted at tmp_path."""
    from types import SimpleNamespace

    cfg = SimpleNamespace(
        root=tmp_path,
        reversed_dir=tmp_path / "reversed",
        metadata_dir=tmp_path,
        marker="SERVER",
        function_list=tmp_path / "functions.txt",
        compiler_profile="msvc6",
    )
    # Used by metadata helpers + resolve_source_arg scan
    import rebrew.blocker as blk
    import rebrew.cli as cli_mod

    monkeypatch.setattr(cli_mod, "load_config", lambda **kw: cfg)
    monkeypatch.setattr(blk, "require_config", lambda **kw: cfg)
    # Also patch the source scan helpers to see the fake reversed dir
    return cfg


class TestBlockerSet:
    def test_set_by_file_writes_toml(self, tmp_path: Path, monkeypatch) -> None:
        import rebrew.metadata as meta

        cfg = _mock_cfg(tmp_path, monkeypatch)
        src_dir = cfg.reversed_dir
        src_dir.mkdir()
        f = src_dir / "foo.c"
        f.write_text("// FUNCTION: SERVER 0x401000\nint foo(){return 0;}\n", encoding="utf-8")
        from rebrew.blocker import app

        res = CliRunner().invoke(app, ["set", str(f), "needs RE structs"])
        assert res.exit_code == 0, res.output
        entry = meta.get_entry(cfg.metadata_dir, 0x401000, "SERVER")
        assert entry.get("blocker") == "needs RE structs"

    def test_set_by_va(self, tmp_path: Path, monkeypatch) -> None:
        import rebrew.metadata as meta

        cfg = _mock_cfg(tmp_path, monkeypatch)
        (cfg.reversed_dir).mkdir()
        (cfg.reversed_dir / "foo.c").write_text(
            "// FUNCTION: SERVER 0x401000\nint foo(){return 0;}\n", encoding="utf-8"
        )
        from rebrew.blocker import app

        res = CliRunner().invoke(app, ["set", "0x401000", "SEH helper"])
        assert res.exit_code == 0, res.output
        assert meta.get_entry(cfg.metadata_dir, 0x401000, "SERVER").get("blocker") == "SEH helper"

    def test_set_with_delta(self, tmp_path: Path, monkeypatch) -> None:
        import rebrew.metadata as meta

        cfg = _mock_cfg(tmp_path, monkeypatch)
        (cfg.reversed_dir).mkdir()
        (cfg.reversed_dir / "a.c").write_text(
            "// FUNCTION: SERVER 0x401000\nint a(){return 0;}\n", encoding="utf-8"
        )
        from rebrew.blocker import app

        res = CliRunner().invoke(app, ["set", "0x401000", "x", "--delta", "16"])
        assert res.exit_code == 0, res.output
        entry = meta.get_entry(cfg.metadata_dir, 0x401000, "SERVER")
        assert entry.get("blocker_delta") == 16

    def test_set_hex_delta(self, tmp_path: Path, monkeypatch) -> None:
        import rebrew.metadata as meta

        cfg = _mock_cfg(tmp_path, monkeypatch)
        (cfg.reversed_dir).mkdir()
        (cfg.reversed_dir / "a.c").write_text(
            "// FUNCTION: SERVER 0x401000\nint a(){return 0;}\n", encoding="utf-8"
        )
        from rebrew.blocker import app

        res = CliRunner().invoke(app, ["set", "0x401000", "x", "--delta", "0x10"])
        assert res.exit_code == 0
        assert meta.get_entry(cfg.metadata_dir, 0x401000, "SERVER").get("blocker_delta") == 16

    def test_set_dry_run_no_write(self, tmp_path: Path, monkeypatch) -> None:
        import rebrew.metadata as meta

        cfg = _mock_cfg(tmp_path, monkeypatch)
        (cfg.reversed_dir).mkdir()
        (cfg.reversed_dir / "a.c").write_text(
            "// FUNCTION: SERVER 0x401000\nint a(){return 0;}\n", encoding="utf-8"
        )
        from rebrew.blocker import app

        res = CliRunner().invoke(app, ["set", "0x401000", "should not persist", "--dry-run"])
        assert res.exit_code == 0
        assert meta.get_entry(cfg.metadata_dir, 0x401000, "SERVER") == {}


class TestBlockerClear:
    def test_clear(self, tmp_path: Path, monkeypatch) -> None:
        import rebrew.metadata as meta

        cfg = _mock_cfg(tmp_path, monkeypatch)
        (cfg.reversed_dir).mkdir()
        (cfg.reversed_dir / "a.c").write_text(
            "// FUNCTION: SERVER 0x401000\nint a(){return 0;}\n", encoding="utf-8"
        )
        from rebrew.blocker import app

        CliRunner().invoke(app, ["set", "0x401000", "to clear", "--delta", "3"])
        assert meta.get_entry(cfg.metadata_dir, 0x401000, "SERVER").get("blocker")
        res = CliRunner().invoke(app, ["clear", "0x401000"])
        assert res.exit_code == 0
        entry = meta.get_entry(cfg.metadata_dir, 0x401000, "SERVER")
        assert "blocker" not in entry and "blocker_delta" not in entry

    def test_clear_dry_run(self, tmp_path: Path, monkeypatch) -> None:
        import rebrew.metadata as meta

        cfg = _mock_cfg(tmp_path, monkeypatch)
        (cfg.reversed_dir).mkdir()
        (cfg.reversed_dir / "a.c").write_text(
            "// FUNCTION: SERVER 0x401000\nint a(){return 0;}\n", encoding="utf-8"
        )
        from rebrew.blocker import app

        CliRunner().invoke(app, ["set", "0x401000", "keep"])
        res = CliRunner().invoke(app, ["clear", "0x401000", "--dry-run"])
        assert res.exit_code == 0
        assert meta.get_entry(cfg.metadata_dir, 0x401000, "SERVER").get("blocker") == "keep"


class TestBlockerShow:
    def test_show_json(self, tmp_path: Path, monkeypatch) -> None:
        import json

        cfg = _mock_cfg(tmp_path, monkeypatch)
        (cfg.reversed_dir).mkdir()
        (cfg.reversed_dir / "a.c").write_text(
            "// FUNCTION: SERVER 0x401000\nint a(){return 0;}\n", encoding="utf-8"
        )
        from rebrew.blocker import app

        CliRunner().invoke(app, ["set", "0x401000", "hello", "--delta", "7"])
        res = CliRunner().invoke(app, ["show", "0x401000", "--json"])
        assert res.exit_code == 0
        data = json.loads(res.output)
        assert data["blocker"] == "hello"
        assert data["blocker_delta"] == 7


class TestBlockerJson:
    def test_set_json(self, tmp_path: Path, monkeypatch) -> None:
        import json

        cfg = _mock_cfg(tmp_path, monkeypatch)
        (cfg.reversed_dir).mkdir()
        (cfg.reversed_dir / "a.c").write_text(
            "// FUNCTION: SERVER 0x401000\nint a(){return 0;}\n", encoding="utf-8"
        )
        from rebrew.blocker import app

        res = CliRunner().invoke(app, ["set", "0x401000", "j", "--json"])
        assert res.exit_code == 0
        data = json.loads(res.output)
        assert data["written"] is True
        assert data["blocker"] == "j"
