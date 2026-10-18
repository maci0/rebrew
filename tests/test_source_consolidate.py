"""The explicit two-store migration preserves evidence and rejects stale reviews."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
import tomlkit
from typer.testing import CliRunner

from rebrew.metadata.functions import (
    load_metadata,
    record_function_identity,
    save_metadata,
    update_field,
)
from rebrew.metadata.source_provenance import (
    consolidate_source_metadata,
    document_assembly,
    function_definition_hashes,
    load_source_files,
    load_source_provenance,
    rename_source_provenance,
    set_source_file,
)
from rebrew.source_consolidate import app
from rebrew.utils import load_tomllib


def _old_stores(root: Path) -> tuple[Path, Path]:
    function = root / "rebrew-functions.toml"
    source = root / "rebrew-source.toml"
    function.write_text(
        'format = 2\n["S.0x1000"]\nfile="one.c"\nname="one"\nkind="FUNCTION"\nstatus="EXACT"\nsize=12\n["S.0x1000".verification]\nmethod="original-receipt"\n'
    )
    doc = tomlkit.document()
    doc.update(
        {
            "format": 2,
            "definitions": {
                "one.c": {
                    "one": {"S": {"source_hash": "a" * 64, "evidence": "reviewed macro"}},
                    "helper": {
                        "S": {"source_hash": "b" * 64, "evidence": "inline assembly helper"}
                    },
                }
            },
            "files": {"support.c": {"S": {"purpose": "link displacement"}}},
        }
    )
    source.write_text(tomlkit.dumps(doc))
    return function, source


class TestSourceConsolidate:
    def test_preview_then_apply_preserves_rows_and_addressless_receipts(
        self, tmp_path: Path
    ) -> None:
        function, source = _old_stores(tmp_path)
        before = load_tomllib(function)
        original_bytes = function.read_bytes(), source.read_bytes()
        preview = consolidate_source_metadata(tmp_path, dry_run=True)
        assert (function.read_bytes(), source.read_bytes()) == original_bytes
        assert not list(tmp_path.glob("*.lock"))
        assert preview["functions"] == 1
        assert preview["definitions"] == 2
        assert preview["files"] == 1
        consolidate_source_metadata(tmp_path, expected_digest=preview["input_digest"])
        after = load_tomllib(function)
        assert after["format"] == 3
        assert after["S.0x1000"] == before["S.0x1000"]
        assert not source.exists()
        assert function.stat().st_mode & 0o222 == 0
        assert len(load_source_provenance(tmp_path)) == 2
        assert len(load_source_files(tmp_path)) == 1
        assert list(load_metadata(tmp_path)) == [("S", 0x1000)]
        again = consolidate_source_metadata(tmp_path, dry_run=True)
        assert not again["changed"]
        consolidate_source_metadata(tmp_path, expected_digest=again["input_digest"])

    @pytest.mark.parametrize("changed", ["function", "source"])
    def test_stale_digest_does_not_write_either_store(self, tmp_path: Path, changed: str) -> None:
        function, source = _old_stores(tmp_path)
        preview = consolidate_source_metadata(tmp_path, dry_run=True)
        path = function if changed == "function" else source
        path.write_bytes(path.read_bytes() + b"\n# concurrent edit\n")
        before = function.read_bytes(), source.read_bytes()
        with pytest.raises(ValueError, match="changed"):
            consolidate_source_metadata(tmp_path, expected_digest=preview["input_digest"])
        assert (function.read_bytes(), source.read_bytes()) == before

    def test_current_readers_reject_old_function_store_and_separate_source(
        self, tmp_path: Path
    ) -> None:
        function, source = _old_stores(tmp_path)
        for reader in (load_metadata, load_source_files, load_source_provenance):
            with pytest.raises(ValueError, match="consolidate"):
                reader(tmp_path)
        source.unlink()
        with pytest.raises(ValueError, match="format = 3"):
            load_metadata(tmp_path)
        function.unlink()
        source.write_text("format = 2\n[definitions]\n[files]\n")
        for reader in (load_metadata, load_source_files, load_source_provenance):
            with pytest.raises(ValueError, match="consolidate"):
                reader(tmp_path)

    def test_source_only_project_needs_no_va(self, tmp_path: Path) -> None:
        _, source = _old_stores(tmp_path)
        (tmp_path / "rebrew-functions.toml").unlink()
        preview = consolidate_source_metadata(tmp_path, dry_run=True)
        consolidate_source_metadata(tmp_path, expected_digest=preview["input_digest"])
        assert not source.exists()
        assert load_metadata(tmp_path) == {}
        assert len(load_source_provenance(tmp_path)) == 2

    def test_interrupted_retirement_can_resume_but_conflicts_are_not_merged(
        self, tmp_path: Path
    ) -> None:
        function, source = _old_stores(tmp_path)
        old_source = load_tomllib(source)
        doc = load_tomllib(function)
        doc["format"] = 3
        doc["source"] = {k: old_source[k] for k in ("definitions", "files")}
        function.write_text(tomlkit.dumps(doc))
        preview = consolidate_source_metadata(tmp_path, dry_run=True)
        consolidate_source_metadata(tmp_path, expected_digest=preview["input_digest"])
        assert not source.exists()
        source.write_text("format=2\n[definitions]\n[files]\n")
        with pytest.raises(ValueError, match="conflicts"):
            consolidate_source_metadata(tmp_path, dry_run=True)

    def test_whole_row_replacement_and_concurrent_granular_writes_keep_source(
        self, tmp_path: Path
    ) -> None:
        record_function_identity(
            tmp_path, module="S", va=0x1000, file="one.c", name="one", kind="FUNCTION"
        )
        set_source_file(tmp_path, "support.c", "S", "original")
        save_metadata(
            tmp_path,
            load_metadata(tmp_path),
            expected_hash=hashlib.sha256(
                (tmp_path / "rebrew-functions.toml").read_bytes()
            ).hexdigest(),
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(update_field, tmp_path, 0x1000, "note", "reviewed", module="S"),
                pool.submit(set_source_file, tmp_path, "support.c", "S", "updated"),
            ]
            for future in futures:
                future.result()
        assert load_metadata(tmp_path)[("S", 0x1000)]["note"] == "reviewed"
        assert load_source_files(tmp_path)[0].purpose == "updated"

    def test_rename_keeps_stale_hash_stale_and_current_hash_current(self, tmp_path: Path) -> None:
        file = tmp_path / "one.c"
        before = "void one(void) { __asm nop }\nvoid helper(void) { __asm nop }\n"
        after = before.replace("one", "renamed")
        file.write_text(before)
        document_assembly(tmp_path, file, "one", "S", "original assembly macro")
        document_assembly(tmp_path, file, "helper", "S", "reviewed helper")
        edited_before = before.replace("void helper(void)", "void helper(int ignored)")
        edited_after = after.replace("void helper(void)", "void helper(int ignored)")
        rename_source_provenance(
            tmp_path, {file: (edited_before, edited_after)}, symbol_rename=("one", "renamed")
        )
        records = {r.symbol: r for r in load_source_provenance(tmp_path)}
        assert records["renamed"].source_hash == function_definition_hashes(edited_after)["renamed"]
        assert records["helper"].source_hash != function_definition_hashes(edited_after)["helper"]

    def test_cli_preview_and_digest_apply(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _old_stores(tmp_path)
        from types import SimpleNamespace

        monkeypatch.setattr(
            "rebrew.source_consolidate.require_config",
            lambda **kwargs: SimpleNamespace(metadata_dir=tmp_path),
        )
        runner = CliRunner()
        preview = runner.invoke(app, ["--dry-run", "--json"])
        assert preview.exit_code == 0, preview.output
        import json

        report: dict[str, Any] = json.loads(preview.output)
        apply = runner.invoke(app, ["--expected-digest", report["input_digest"], "--json"])
        assert apply.exit_code == 0, apply.output
        assert not (tmp_path / "rebrew-source.toml").exists()
