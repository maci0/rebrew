"""Selected inventory repairs preserve unrelated evidence and reject stale inputs."""

import json
import shutil
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from rebrew.catalog.inventory import repair_inventory_extents
from rebrew.config import ProjectConfig
from rebrew.metadata.functions import record_function_identity, update_source_status


def _project(tmp_path: Path) -> tuple[ProjectConfig, Path]:
    binary = tmp_path / "reference.exe"
    shutil.copy(Path(__file__).parent / "fixtures/mini_pe.exe", binary)
    source = tmp_path / "src"
    source.mkdir()
    inventory = source / "function_structure.json"
    inventory.write_text(
        json.dumps(
            [
                {"va": 0x401000, "size": 40, "name": "first", "reviewed_note": "keep"},
                {"va": 0x401020, "size": 16, "name": "other", "extra": {"confidence": 7}},
            ]
        )
    )
    return ProjectConfig(
        root=tmp_path, reversed_dir=source, target_binary=binary, module="GAME"
    ), inventory


class TestInventoryRepair:
    def test_selected_repair_preserves_other_rows_and_verdicts(self, tmp_path: Path) -> None:
        cfg, inventory = _project(tmp_path)
        original = json.loads(inventory.read_text())
        record_function_identity(
            cfg.metadata_dir,
            module="GAME",
            va=0x401000,
            file="src/f.c",
            kind="FUNCTION",
            name="f",
            symbol="_f",
            size=16,
        )
        update_source_status(cfg.metadata_dir, "EXACT", va=0x401000, module="GAME")
        metadata = cfg.metadata_dir / "rebrew-functions.toml"
        metadata_before = metadata.read_bytes(), metadata.stat()
        snapshot = inventory.read_bytes(), inventory.stat()
        preview = repair_inventory_extents(
            cfg, {0x401000: 16}, reason="complete native body", dry_run=True
        )
        assert (inventory.read_bytes(), inventory.stat()) == snapshot
        assert not inventory.with_suffix(".json.lock").exists()
        result = repair_inventory_extents(
            cfg,
            {0x401000: 16},
            reason="complete native body",
            expected_digest=preview["input_digest"],
        )
        document = json.loads(inventory.read_text())
        assert document[1] == original[1]
        assert document[0]["reviewed_note"] == "keep"
        assert document[0]["size"] == 16
        assert document[0]["extent_history"][0]["old_size"] == 40
        assert result["measurements_changed"] is False
        assert (metadata.read_bytes(), metadata.stat()) == metadata_before

    @pytest.mark.parametrize(
        "updates",
        [
            {0x401000: 0},
            {0x401000: 0x1000},
            {0x401000: 33},
            {0x401010: 4},
            {0x401000: 16, 0x401020: -1},
        ],
    )
    @pytest.mark.parametrize("dry_run", [True, False])
    def test_invalid_batch_changes_nothing(
        self, tmp_path: Path, updates: dict[int, int], dry_run: bool
    ) -> None:
        cfg, inventory = _project(tmp_path)
        before = inventory.read_bytes(), inventory.stat()
        with pytest.raises(ValueError):
            repair_inventory_extents(cfg, updates, reason="native evidence", dry_run=dry_run)
        assert (inventory.read_bytes(), inventory.stat()) == before
        assert not inventory.with_suffix(".json.lock").exists()

    @pytest.mark.parametrize("changed", ["binary", "inventory"])
    def test_complete_input_digest_rejects_changed_review(
        self, tmp_path: Path, changed: str
    ) -> None:
        cfg, inventory = _project(tmp_path)
        preview = repair_inventory_extents(cfg, {0x401000: 16}, reason="proof", dry_run=True)
        if changed == "binary":
            data = cfg.target_binary.read_bytes()
            cfg.target_binary.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        else:
            inventory.write_text(inventory.read_text() + "\n")
        before = inventory.read_bytes(), inventory.stat()
        with pytest.raises(ValueError, match="inputs changed"):
            repair_inventory_extents(
                cfg, {0x401000: 16}, reason="proof", expected_digest=preview["input_digest"]
            )
        assert (inventory.read_bytes(), inventory.stat()) == before

    def test_multiple_rows_publish_once(self, tmp_path: Path) -> None:
        from rebrew.utils import atomic_write_text

        cfg, _inventory = _project(tmp_path)
        with patch("rebrew.catalog.inventory.atomic_write_text", wraps=atomic_write_text) as write:
            repair_inventory_extents(cfg, {0x401000: 16, 0x401020: 8}, reason="native boundaries")
        assert write.call_count == 1

    @pytest.mark.parametrize(
        "document",
        [
            [{"va": 0x401000, "size": 16}, {"va": 0x401000, "size": 4}],
            [{"va": 0x401000, "size": 16, "_generated_by": "rebrew coverage catalog"}],
            [{"va": 0x401000, "size": 16}, "invalid row"],
        ],
    )
    def test_invalid_native_store_is_not_rewritten(
        self, tmp_path: Path, document: list[Any]
    ) -> None:
        cfg, inventory = _project(tmp_path)
        inventory.write_text(json.dumps(document))
        before = inventory.read_bytes(), inventory.stat()
        with pytest.raises(ValueError):
            repair_inventory_extents(cfg, {0x401000: 8}, reason="proof", dry_run=True)
        assert (inventory.read_bytes(), inventory.stat()) == before


class TestReviewedAdmission:
    def test_cli_admission_is_explicit_and_read_only_in_preview(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from rebrew.app.main import app

        cfg, inventory = _project(tmp_path)
        before = inventory.read_bytes(), inventory.stat()
        with patch("rebrew.inventory_repair.require_config", return_value=cfg):
            result = CliRunner().invoke(
                app,
                [
                    "binary",
                    "repair-extents",
                    "0x401030=3",
                    "--add-missing",
                    "--reason",
                    "native proof",
                    "--dry-run",
                    "--json",
                ],
            )
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["repairs"][0]["old_size"] is None
        assert (inventory.read_bytes(), inventory.stat()) == before

    def test_admission_preserves_existing_row_order(self, tmp_path: Path) -> None:
        cfg, inventory = _project(tmp_path)
        original = list(reversed(json.loads(inventory.read_text())))
        inventory.write_text(json.dumps(original))
        repair_inventory_extents(cfg, {0x401030: 3}, reason="native proof", add_missing=True)
        rows = json.loads(inventory.read_text())
        assert [r for r in rows if r["va"] != 0x401030] == original

    def test_admit_missing_function_preserves_existing_evidence(self, tmp_path: Path) -> None:
        cfg, inventory = _project(tmp_path)
        original = json.loads(inventory.read_text())
        snapshot = inventory.read_bytes(), inventory.stat()
        updates = {0x401000: 16, 0x401010: 3}
        preview = repair_inventory_extents(
            cfg, updates, reason="reviewed native entries", add_missing=True, dry_run=True
        )
        assert (inventory.read_bytes(), inventory.stat()) == snapshot
        assert not inventory.with_suffix(".json.lock").exists()
        repair_inventory_extents(
            cfg,
            updates,
            reason="reviewed native entries",
            add_missing=True,
            expected_digest=preview["input_digest"],
        )
        rows = json.loads(inventory.read_text())
        assert [r["va"] for r in rows] == [0x401000, 0x401010, 0x401020]
        assert rows[0]["reviewed_note"] == "keep"
        assert rows[2] == original[1]
        assert rows[1]["name"] == "fcn.00401010"
        assert rows[1]["size"] == 3
        assert rows[1]["extent_history"][0]["old_size"] is None
        assert not (cfg.metadata_dir / "rebrew-functions.toml").exists()
        before = inventory.read_bytes(), inventory.stat()
        result = repair_inventory_extents(
            cfg, updates, reason="reviewed native entries", add_missing=True
        )
        assert result["repairs"] == []
        assert (inventory.read_bytes(), inventory.stat()) == before

    @pytest.mark.parametrize("updates", [{0x401010: 3}, {0x40101F: 3}, {0x900000: 3}])
    def test_admission_rejects_overlap_and_noncode_without_writes(
        self, tmp_path: Path, updates: dict[int, int]
    ) -> None:
        cfg, inventory = _project(tmp_path)
        before = inventory.read_bytes(), inventory.stat()
        with pytest.raises(ValueError):
            repair_inventory_extents(
                cfg, updates, reason="reviewed native entry", add_missing=True, dry_run=True
            )
        assert (inventory.read_bytes(), inventory.stat()) == before

    @pytest.mark.parametrize("changed", ["updates", "reason", "add_missing"])
    def test_preview_binds_the_reviewed_operation(self, tmp_path: Path, changed: str) -> None:
        cfg, inventory = _project(tmp_path)
        preview = repair_inventory_extents(cfg, {0x401000: 16}, reason="native proof", dry_run=True)
        before = inventory.read_bytes(), inventory.stat()
        with pytest.raises(ValueError, match="inputs changed"):
            repair_inventory_extents(
                cfg,
                {0x401000: 8 if changed == "updates" else 16},
                reason="different proof" if changed == "reason" else "native proof",
                add_missing=changed == "add_missing",
                expected_digest=preview["input_digest"],
            )
        assert (inventory.read_bytes(), inventory.stat()) == before


class TestActualFileExtent:
    def test_truncated_binary_cannot_invent_file_backed_bytes(self, tmp_path: Path) -> None:
        from rebrew.formats.binary_loader import load_binary

        cfg, inventory = _project(tmp_path)
        section = load_binary(cfg.target_binary).sections[".text"]
        cfg.target_binary.write_bytes(cfg.target_binary.read_bytes()[: section.file_offset + 4])
        before = inventory.read_bytes(), inventory.stat()
        with pytest.raises(ValueError, match="complete file-backed executable span"):
            repair_inventory_extents(cfg, {0x401000: 16}, reason="proof", dry_run=True)
        assert (inventory.read_bytes(), inventory.stat()) == before
        assert not inventory.with_suffix(".json.lock").exists()


class TestReviewedInventoryProtection:
    def test_rediscovery_does_not_erase_reviewed_rows(self, tmp_path: Path) -> None:
        import typer

        from rebrew.discover import Discovery, main

        cfg, inventory = _project(tmp_path)
        repair_inventory_extents(cfg, {0x401000: 16}, reason="native body evidence")
        before = inventory.read_bytes(), inventory.stat()
        with (
            patch("rebrew.discover.resolve_binary_arg", return_value=cfg.target_binary),
            patch(
                "rebrew.discover.discover_functions",
                return_value=Discovery(functions=[(0x401000, 40, "f")]),
            ),
            pytest.raises(typer.Exit) as caught,
        ):
            main(
                binary=str(cfg.target_binary),
                output=str(inventory),
                min_size=1,
                json_output=True,
                target=None,
            )
        assert caught.value.exit_code == 2
        assert (inventory.read_bytes(), inventory.stat()) == before
