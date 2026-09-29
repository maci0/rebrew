"""The mypy gate's own coverage: what it checks, and that it never checks less.

``[tool.mypy] files`` is an allowlist: ``src/rebrew`` and ``tools`` are named as
directories, but every ``tests/`` module has to be listed one by one.  Removing
an entry therefore narrows the type check with nothing else in the tree noticing
— mypy is handed a smaller tree, reports less, and the job stays green.  The
policy the config itself states is "add a module here as it comes clean rather
than relaxing the gate for the tree", so the checked set is a floor that may
only rise.

``CHECKED_TESTS`` pins that floor.  It holds the modules that were clean when
this gate landed; a module is added to the list as it comes clean and never
taken out, so a shrinking list is a regression the diff shows.  Renaming a
test means renaming its entry in ``files`` and this tuple in the same change.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"

# The tests/ modules [tool.mypy] files covered when this gate landed.  A module
# comes off this list only by being deleted, and the same commit has to drop it
# from the allowlist.
CHECKED_TESTS: frozenset[str] = frozenset(
    {
        "bin_util.py",
        "cache_util.py",
        "html_validate.py",
        "pytest_ansi_env.py",
        "test_annotation_roundtrip.py",
        "test_apply_relocations.py",
        "test_asm.py",
        "test_ast_engine.py",
        "test_batch.py",
        "test_binsync_export.py",
        "test_binsync_state.py",
        "test_cache_cli.py",
        "test_calibrate_bss.py",
        "test_catalog.py",
        "test_catalog_models.py",
        "test_catalog_registry.py",
        "test_catalog_resilience.py",
        "test_cfg_ged.py",
        "test_check_layering.py",
        "test_check_sdist_wheel.py",
        "test_cli_visual.py",
        "test_cmake_flags.py",
        "test_cmake_sources.py",
        "test_coff_reloc.py",
        "test_compile_classify.py",
        "test_context.py",
        "test_core.py",
        "test_corpus_sweep.py",
        "test_coverage_db.py",
        "test_coverage_toml.py",
        "test_crypto_scan.py",
        "test_data_annotations.py",
        "test_data_layout.py",
        "test_docs_hygiene.py",
        "test_docs_links.py",
        "test_document_unmatched.py",
        "test_elf_fixture.py",
        "test_env_docs.py",
        "test_errors.py",
        "test_external_libs.py",
        "test_extract.py",
        "test_fixup.py",
        "test_flirt.py",
        "test_flirt_sigs.py",
        "test_import_cycles.py",
        "test_inline_strings.py",
        "test_link_order.py",
        "test_link_tools.py",
        "test_lint_cflags.py",
        "test_lint_deep.py",
        "test_main.py",
        "test_markers_toml_source.py",
        "test_match_fix_blocker.py",
        "test_match_parsing.py",
        "test_merge.py",
        "test_metadata_doc.py",
        "test_mutator_levers.py",
        "test_nested_dirs.py",
        "test_new_commands.py",
        "test_normalize_sdist.py",
        "test_onboarding.py",
        "test_order_sources.py",
        "test_orphans.py",
        "test_pe_symbols.py",
        "test_probe.py",
        "test_project_toml_example.py",
        "test_provenance_tags.py",
        "test_public_surface.py",
        "test_reccmp_adaptations.py",
        "test_refactor.py",
        "test_render_skills.py",
        "test_resource.py",
        "test_security_scan.py",
        "test_skill_commands_validate.py",
        "test_skills_extended.py",
        "test_skills_sync.py",
        "test_solutions.py",
        "test_source_ext.py",
        "test_span_contains.py",
        "test_split.py",
        "test_startup_blas.py",
        "test_strings.py",
        "test_struct_parser.py",
        "test_symbol_addrs.py",
        "test_target_defaults.py",
        "test_temp_dir_prefixes.py",
        "test_text_audit.py",
        "test_theme.py",
        "test_toolchain_detect_codegen.py",
        "test_types_cli.py",
        "test_verify_text.py",
        "test_verify_watch.py",
        "test_workspace_config.py",
        "test_workspace_public_api.py",
        "test_workspace_va.py",
        "test_xrefs.py",
        "thread_util.py",
    }
)


def _mypy_files() -> list[str]:
    config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    files: list[str] = config["tool"]["mypy"]["files"]
    return files


class TestMypyScope:
    def test_library_and_tools_are_checked_whole(self) -> None:
        """A directory entry, not a file list: narrowing these has the same effect."""
        files = _mypy_files()
        assert "src/rebrew" in files
        assert "tools" in files

    def test_checked_test_modules_never_shrink(self) -> None:
        files = _mypy_files()
        listed = {Path(f).name for f in files if f.startswith("tests/")}
        missing = sorted(CHECKED_TESTS - listed)
        assert not missing, (
            "tests/ modules dropped from the mypy allowlist, which the gate cannot "
            f"see through: {missing}"
        )

    def test_every_listed_test_module_exists(self) -> None:
        """A renamed or deleted module left in files is a hole in the gate."""
        missing = sorted(
            f for f in _mypy_files() if f.startswith("tests/") and not (ROOT / f).is_file()
        )
        assert not missing, f"mypy files entries with no file on disk: {missing}"

    def test_mypy_is_strict(self) -> None:
        """Every extra this gate depends on is a downgrade away from the floor."""
        config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        mypy = config["tool"]["mypy"]
        assert mypy["strict"] is True
        assert mypy["extra_checks"] is True
        assert "ignore-without-code" in mypy["enable_error_code"]
