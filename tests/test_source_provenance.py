"""Source-only assembly evidence stays definition-scoped and never earns a verdict."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cli_json import cli_payload
from typer.testing import CliRunner

from rebrew.app.main import app
from rebrew.config import ProjectConfig
from rebrew.lint import lint_file
from rebrew.metadata.source_provenance import (
    SOURCE_PROVENANCE_FILENAME,
    document_assembly,
    function_definition_hashes,
    load_source_provenance,
)
from rebrew.rename_ops import RenamePlan

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

        file = _source(tmp_path)
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, marker="CLIENT")
        (tmp_path / SOURCE_PROVENANCE_FILENAME).write_text("format = 1.0\ndefinitions = {}")
        with pytest.raises(ValueError, match="source metadata requires format = 2"):
            lint_file(file, cfg)

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
        assert cli_payload(preview)["dry_run"]
        assert not (tmp_path / SOURCE_PROVENANCE_FILENAME).exists()
        recorded = runner.invoke(app, [*args, "--evidence", "Original macro"])
        assert recorded.exit_code == 0, recorded.output
        assert cli_payload(recorded)["module"] == "CLIENT"
        assert [r.symbol for r in load_source_provenance(tmp_path)] == ["fill0"]
        cleared = runner.invoke(app, [*args, "--clear"])
        assert cleared.exit_code == 0, cleared.output
        assert load_source_provenance(tmp_path) == ()


class TestRenameProvenance:
    def _plan(self, root: Path, *, move: bool = False) -> tuple[ProjectConfig, RenamePlan]:
        from rebrew.rename_ops import plan_symbol_rename

        cfg = ProjectConfig(root=root, reversed_dir=root, marker="CLIENT")
        return cfg, plan_symbol_rename(
            cfg,
            "fill0",
            "fill",
            store="function",
            definition_file=root / "helpers.c",
            require_ack=False,
            rename_file=move,
            new_filename="renamed.c" if move else None,
        )

    @pytest.mark.parametrize("stale", [False, True])
    def test_rename_preserves_targets_callers_and_stale_evidence(
        self, tmp_path: Path, stale: bool
    ) -> None:
        from rebrew.rename_ops import apply_rename_plan

        file = _source(tmp_path)
        file.write_text(SOURCE + "void caller(void) { fill0(); __asm { nop } }\n")
        for symbol in ("fill0", "caller"):
            for module in ("CLIENT", "SERVER"):
                document_assembly(tmp_path, file, symbol, module, f"Original {symbol} macro")
        old = {(r.symbol, r.module): r for r in load_source_provenance(tmp_path)}
        if stale:
            file.write_text(file.read_text().replace("mov eax, 0", "mov eax, 2"))
        cfg, plan = self._plan(tmp_path)
        apply_rename_plan(cfg, plan)
        hashes = function_definition_hashes(file.read_text())
        records = load_source_provenance(tmp_path)
        assert {(r.symbol, r.module) for r in records} == {
            (s, m) for s in ("fill", "caller") for m in ("CLIENT", "SERVER")
        }
        for record in records:
            before = old[("fill0" if record.symbol == "fill" else record.symbol, record.module)]
            assert record.evidence == before.evidence
            if stale and record.symbol == "fill":
                assert record.source_hash == before.source_hash != hashes[record.symbol]
            else:
                assert record.source_hash == hashes[record.symbol]

    def test_file_move_and_definition_name_follow_the_same_rename(self, tmp_path: Path) -> None:
        from rebrew.rename_ops import apply_rename_plan

        file = _source(tmp_path)
        document_assembly(tmp_path, file, "fill0", "CLIENT", "Original macro")
        cfg, plan = self._plan(tmp_path, move=True)
        apply_rename_plan(cfg, plan)
        new_file = tmp_path / "renamed.c"
        assert new_file.exists() and not file.exists()
        (record,) = load_source_provenance(tmp_path)
        assert (record.file, record.symbol) == ("renamed.c", "fill")
        assert record.source_hash == function_definition_hashes(new_file.read_text())["fill"]

    def test_corrupt_store_is_rejected_before_sources_change(self, tmp_path: Path) -> None:
        from rebrew.rename_ops import RenameError, apply_rename_plan

        file = _source(tmp_path)
        path = tmp_path / SOURCE_PROVENANCE_FILENAME
        path.write_text("invalid = [")
        cfg, plan = self._plan(tmp_path)
        with pytest.raises(RenameError, match="provenance"):
            apply_rename_plan(cfg, plan)
        assert file.read_text() == SOURCE
        assert path.read_text() == "invalid = ["

    def test_existing_destination_evidence_is_not_overwritten(self, tmp_path: Path) -> None:
        from rebrew.rename_ops import RenameError, apply_rename_plan

        file = _source(tmp_path)
        file.write_text(SOURCE + "void fill(void) { __asm { nop } }\n")
        document_assembly(tmp_path, file, "fill", "CLIENT", "Other reviewed macro")
        file.write_text(SOURCE)
        document_assembly(tmp_path, file, "fill0", "CLIENT", "Original macro")
        cfg, plan = self._plan(tmp_path)
        before = (tmp_path / SOURCE_PROVENANCE_FILENAME).read_bytes()
        with pytest.raises(RenameError, match="provenance"):
            apply_rename_plan(cfg, plan)
        assert file.read_text() == SOURCE
        assert (tmp_path / SOURCE_PROVENANCE_FILENAME).read_bytes() == before

    def test_failed_provenance_write_restores_the_source_and_move(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata import source_provenance
        from rebrew.rename_ops import RenameError, apply_rename_plan

        file = _source(tmp_path)
        document_assembly(tmp_path, file, "fill0", "CLIENT", "Original macro")
        path = tmp_path / SOURCE_PROVENANCE_FILENAME
        before = path.read_bytes()
        cfg, plan = self._plan(tmp_path, move=True)

        def fail_write(*args: object, **kwargs: object) -> None:
            raise OSError("cannot write provenance")

        monkeypatch.setattr(source_provenance, "atomic_write_locked", fail_write)
        with pytest.raises(RenameError, match="cannot write provenance"):
            apply_rename_plan(cfg, plan)
        assert file.read_text() == SOURCE
        assert not (tmp_path / "renamed.c").exists()
        assert path.read_bytes() == before

    def test_data_rename_refreshes_current_evidence_in_users(self, tmp_path: Path) -> None:
        from rebrew.rename_ops import apply_rename_plan, plan_symbol_rename

        file = _source(tmp_path)
        file.write_text("int counter;\n" + SOURCE.replace("mov eax, 1", "mov eax, counter"))
        document_assembly(tmp_path, file, "other", "CLIENT", "Original macro")
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, marker="CLIENT")
        plan = plan_symbol_rename(cfg, "counter", "total", store="data", require_ack=False)
        apply_rename_plan(cfg, plan)
        (record,) = load_source_provenance(tmp_path)
        assert record.symbol == "other" and "mov eax, total" in file.read_text()
        assert record.source_hash == function_definition_hashes(file.read_text())["other"]
