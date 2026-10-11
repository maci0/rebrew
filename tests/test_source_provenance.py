"""Source-only assembly evidence stays definition-scoped and never earns a verdict."""

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.config import ProjectConfig
from rebrew.lint import lint_file
from rebrew.main import app
from rebrew.source_provenance import (
    SOURCE_PROVENANCE_FILENAME,
    document_assembly,
    function_definition_hashes,
    load_source_provenance,
)

SOURCE = (
    "/* ü: offsets must survive masking */\n"
    "static __inline void fill0(void) {\n    __asm { mov eax, 0 }\n}\n"
    "void other(void) {\n    __asm { mov eax, 1 }\n}\n"
)


def _source(root: Path) -> Path:
    file = root / "helpers.c"
    file.write_text(SOURCE, encoding="utf-8")
    return file


class TestSourceProvenance:
    def test_record_clear_and_noop_preserve_other_target(self, tmp_path: Path) -> None:
        file = _source(tmp_path)
        for module in ("client", "SERVER"):
            document_assembly(tmp_path, file, "fill0", module, "Original macro at 0x401000")
        path = tmp_path / SOURCE_PROVENANCE_FILENAME
        assert {r.module for r in load_source_provenance(tmp_path)} == {"CLIENT", "SERVER"}
        assert path.stat().st_mode & 0o777 == 0o444
        before = path.stat().st_mtime_ns
        document_assembly(tmp_path, file, "fill0", "CLIENT", "Original macro at 0x401000")
        assert path.stat().st_mtime_ns == before
        file.unlink()
        document_assembly(tmp_path, file, "fill0", "CLIENT", None)
        assert [r.module for r in load_source_provenance(tmp_path)] == ["SERVER"]
        document_assembly(tmp_path, file, "fill0", "SERVER", None)
        assert load_source_provenance(tmp_path) == ()
        assert not (tmp_path / "rebrew-functions.toml").exists()
        assert not (tmp_path / "rebrew-data.toml").exists()

    def test_dry_run_creates_no_store_or_lock(self, tmp_path: Path) -> None:
        file = _source(tmp_path)
        report = document_assembly(
            tmp_path, file, "fill0", "CLIENT", "Original macro", dry_run=True
        )
        assert report["dry_run"]
        assert list(tmp_path.iterdir()) == [file]

    def test_only_definition_changes_invalidate_hash(self) -> None:
        original = function_definition_hashes(SOURCE)
        assert original == function_definition_hashes("/* extra */\n" + SOURCE)
        changed = function_definition_hashes(SOURCE.replace("eax, 0", "eax, 2"))
        assert changed["fill0"] != original["fill0"]
        assert changed["other"] == original["other"]
        assert "fill0" not in function_definition_hashes(SOURCE + SOURCE)

    @pytest.mark.parametrize("evidence", ["", "  ", "x" * 2001])
    def test_invalid_evidence_does_not_write(self, tmp_path: Path, evidence: str) -> None:
        with pytest.raises(ValueError):
            document_assembly(tmp_path, _source(tmp_path), "fill0", "CLIENT", evidence)
        assert not (tmp_path / SOURCE_PROVENANCE_FILENAME).exists()

    @pytest.mark.parametrize(
        "content", ["", "broken = [", "format = 1.0\ndefinitions = {}", "format = 1\nunknown = {}"]
    )
    def test_corrupt_store_is_not_overwritten(self, tmp_path: Path, content: str) -> None:
        file = _source(tmp_path)
        path = tmp_path / SOURCE_PROVENANCE_FILENAME
        path.write_text(content)
        with pytest.raises(ValueError):
            document_assembly(tmp_path, file, "fill0", "CLIENT", "Original macro")
        assert path.read_text() == content

    def test_escape_and_missing_definition_are_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError):
            document_assembly(tmp_path / "child", _source(tmp_path), "fill0", "CLIENT", "Original")
        with pytest.raises(ValueError, match="unique parseable"):
            document_assembly(tmp_path, tmp_path / "helpers.c", "missing", "CLIENT", "Original")

    def test_concurrent_targets_are_not_lost(self, tmp_path: Path) -> None:
        file = _source(tmp_path)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(document_assembly, tmp_path, file, "fill0", m, "Original")
                for m in ("SERVER", "CLIENT")
            ]
            for future in futures:
                future.result()
        assert {r.module for r in load_source_provenance(tmp_path)} == {"CLIENT", "SERVER"}

    def test_symlink_escape_is_rejected(self, tmp_path: Path) -> None:
        file = _source(tmp_path)
        child = tmp_path / "child"
        child.mkdir()
        link = child / "helpers.c"
        link.symlink_to(file)
        with pytest.raises(ValueError):
            document_assembly(child, link, "fill0", "CLIENT", "Original")

    @pytest.mark.parametrize(
        "field,value", [("source_hash", '"wrong"'), ("status", '"EXACT"'), ("evidence", '""')]
    )
    def test_invalid_record_is_rejected_without_overwrite(
        self, tmp_path: Path, field: str, value: str
    ) -> None:
        file = _source(tmp_path)
        path = tmp_path / SOURCE_PROVENANCE_FILENAME
        content = (
            'format = 1\n[definitions."helpers.c".fill0.CLIENT]\n'
            'source_hash = "' + "0" * 64 + '"\nevidence = "Original"\n'
        )
        lines = [line for line in content.splitlines() if not line.startswith(field + " =")]
        content = "\n".join([*lines, f"{field} = {value}", ""])
        path.write_text(content)
        with pytest.raises(ValueError):
            document_assembly(tmp_path, file, "fill0", "CLIENT", "Original")
        assert path.read_text() == content


class TestAssemblyLint:
    def test_evidence_scopes_to_file_symbol_target_and_current_body(self, tmp_path: Path) -> None:
        file = _source(tmp_path)
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, marker="CLIENT")
        document_assembly(tmp_path, file, "fill0", "CLIENT", "Original macro at 0x401000")
        warnings = [m for _, c, m in lint_file(file, cfg).warnings if c == "W020"]
        assert len(warnings) == 1
        assert "other" in warnings[0]
        cfg.marker = "SERVER"
        assert len([c for _, c, _ in lint_file(file, cfg).warnings if c == "W020"]) == 2
        cfg.marker = "CLIENT"
        second = tmp_path / "second.c"
        second.write_text(SOURCE)
        assert len([c for _, c, _ in lint_file(second, cfg).warnings if c == "W020"]) == 2
        file.write_text(SOURCE.replace("eax, 0", "eax, 2"))
        assert len([c for _, c, _ in lint_file(file, cfg).warnings if c == "W020"]) == 2

    def test_provenance_does_not_allow_whole_function_naked_asm(self, tmp_path: Path) -> None:
        file = _source(tmp_path)
        file.write_text("__declspec(naked) void dump(void) { __asm { _emit 0x55 } }\n")
        document_assembly(tmp_path, file, "dump", "CLIENT", "Original assembly")
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, marker="CLIENT")
        assert any(c == "E023" for _, c, _ in lint_file(file, cfg).errors)

    def test_stale_missing_and_foreign_records_are_visible(self, tmp_path: Path) -> None:
        from rebrew.lint import _check_W031_source_provenance

        file = _source(tmp_path)
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, marker="CLIENT")
        cfg.all_markers = {"CLIENT", "SERVER"}
        for module in ("CLIENT", "SERVER"):
            document_assembly(tmp_path, file, "fill0", module, "Original")
        assert _check_W031_source_provenance(cfg) == []
        file.write_text(SOURCE.replace("eax, 0", "eax, 2"))
        results = _check_W031_source_provenance(cfg)
        assert len(results[0].warnings) == 1
        assert "stale" in results[0].warnings[0][2]
        assert "CLIENT:helpers.c:fill0" in results[0].warnings[0][2]
        file.unlink()
        assert "cannot be checked" in _check_W031_source_provenance(cfg)[0].warnings[0][2]
        _source(tmp_path)
        document_assembly(tmp_path, file, "fill0", "REMOVED", "Original")
        assert "unknown target" in _check_W031_source_provenance(cfg)[0].warnings[0][2]

    def test_malformed_store_never_exempts_assembly(self, tmp_path: Path) -> None:
        from rebrew.lint import _check_W031_source_provenance

        file = _source(tmp_path)
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, marker="CLIENT")
        (tmp_path / SOURCE_PROVENANCE_FILENAME).write_text("format = 1.0\ndefinitions = {}")
        assert len([c for _, c, _ in lint_file(file, cfg).warnings if c == "W020"]) == 2
        assert "invalid" in _check_W031_source_provenance(cfg)[0].warnings[0][2]

    def test_legacy_source_encoding_uses_the_same_definition_hash(self, tmp_path: Path) -> None:
        file = _source(tmp_path)
        file.write_bytes(
            SOURCE.replace("__asm { mov eax, 0 }", "/* ü */ __asm { mov eax, 0 }").encode("cp1252")
        )
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, marker="CLIENT")
        document_assembly(tmp_path, file, "fill0", "CLIENT", "Original macro")
        assert len([c for _, c, _ in lint_file(file, cfg).warnings if c == "W020"]) == 1


class TestDocumentAssemblyCLI:
    def test_umbrella_record_preview_clear_and_required_choice(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _source(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\nname = "probe"\ndefault_target = "client"\n'
            '[targets.client]\nbinary = "original.exe"\nmarker = "CLIENT"\nreversed_dir = "."\n'
            '[compiler]\nprofile = "msvc-6.0"\n'
        )
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        args = [
            "source",
            "document-assembly",
            "helpers.c",
            "--symbol",
            "fill0",
            "--json",
            "--target",
            "client",
        ]
        assert runner.invoke(app, args).exit_code != 0
        preview = runner.invoke(app, [*args, "--evidence", "Original macro", "--dry-run"])
        assert preview.exit_code == 0, preview.output
        assert json.loads(preview.stdout)["dry_run"]
        assert not (tmp_path / SOURCE_PROVENANCE_FILENAME).exists()
        recorded = runner.invoke(app, [*args, "--evidence", "Original macro"])
        assert recorded.exit_code == 0, recorded.output
        assert json.loads(recorded.stdout)["module"] == "CLIENT"
        assert [r.symbol for r in load_source_provenance(tmp_path)] == ["fill0"]
        cleared = runner.invoke(app, [*args, "--clear"])
        assert cleared.exit_code == 0, cleared.output
        assert load_source_provenance(tmp_path) == ()
