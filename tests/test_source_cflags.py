"""Clearing saved compiler flags preserves earned status and all other metadata."""

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from typer.testing import CliRunner

from rebrew.app.main import app
from rebrew.config import ProjectConfig
from rebrew.metadata.functions import (
    get_entry,
    record_function_identity,
    update_field,
    update_source_status,
)


class TestClearCflags:
    def test_preview_clear_and_repeat_preserve_verdict(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path / "src", module="GAME")
        record_function_identity(
            cfg.metadata_dir,
            module="GAME",
            va=0x401000,
            file="src/f.c",
            kind="FUNCTION",
            name="f",
            symbol="_f",
        )
        update_field(cfg.metadata_dir, 0x401000, "cflags", "/G6", module="GAME")
        update_source_status(cfg.metadata_dir, "EXACT", va=0x401000, module="GAME")
        before = get_entry(cfg.metadata_dir, 0x401000, "GAME")
        path = cfg.metadata_dir / "rebrew-functions.toml"
        snapshot = path.read_bytes(), path.stat()
        with patch("rebrew.source_cflags.require_config", return_value=cfg):

            def invoke(*options: str) -> dict[str, Any]:
                result = CliRunner().invoke(
                    app, ["source", "clear-cflags", "0x401000", *options, "--json"]
                )
                assert result.exit_code == 0, result.output
                return json.loads(result.stdout)

            assert invoke("--dry-run")["previous_cflags"] == "/G6"
            assert (path.read_bytes(), path.stat()) == snapshot
            assert invoke()["cleared"]
            assert not invoke()["cleared"]
        after = get_entry(cfg.metadata_dir, 0x401000, "GAME")
        assert "cflags" not in after
        assert {k: v for k, v in after.items() if k not in {"updated_at", "updated_by"}} == {
            k: v for k, v in before.items() if k not in {"cflags", "updated_at", "updated_by"}
        }
