"""Tests for rebrew data --annotate (// GLOBAL: marker insertion)."""

from __future__ import annotations

from pathlib import Path

from rebrew.data_annotate import annotate_globals


def _mk(src: Path) -> None:
    (src / "mod.c").write_text(
        "int g_a;\nvoid f(void) { g_b = 1; }\nint g_b;\n",
        encoding="utf-8",
    )


def test_annotate_inserts_markers(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    _mk(src)
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        '["SERVER.0x10027000"]\nname = "g_a"\nsection = ".data"\n'
        '["SERVER.0x10027004"]\nname = "g_b"\nsection = ".data"\n',
        encoding="utf-8",
    )
    per_file, skipped = annotate_globals(src, meta, "SERVER", dry_run=True)
    assert per_file == {"mod.c": 2}
    assert skipped == 0
    text = (src / "mod.c").read_text()
    assert "// GLOBAL: SERVER 0x10027000" not in text  # dry-run: not written


def test_annotate_writes_and_skips_existing(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "mod.c").write_text(
        "// GLOBAL: SERVER 0x10027000\nint g_a;\nint g_b;\n", encoding="utf-8"
    )
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        '["SERVER.0x10027000"]\nname = "g_a"\nsection = ".data"\n'
        '["SERVER.0x10027004"]\nname = "g_b"\nsection = ".data"\n',
        encoding="utf-8",
    )
    annotate_globals(src, meta, "SERVER", dry_run=False)
    text = (src / "mod.c").read_text()
    assert text.count("// GLOBAL:") == 2  # g_a skipped (marked), g_b added
    assert "// GLOBAL: SERVER 0x10027004\nint g_b;" in text

    # Rerun must be completely idempotent (0 files modified, text unchanged)
    per_file, skipped = annotate_globals(src, meta, "SERVER", dry_run=False)
    assert per_file == {}
    assert (src / "mod.c").read_text() == text


def test_annotate_skips_block_comment_markers(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "mod.c").write_text("/* GLOBAL: SERVER 0x10027000 */\nint g_a;\n", encoding="utf-8")
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        '["SERVER.0x10027000"]\nname = "g_a"\nsection = ".data"\n',
        encoding="utf-8",
    )
    per_file, _ = annotate_globals(src, meta, "SERVER", dry_run=False)
    assert per_file == {}
    assert (src / "mod.c").read_text() == "/* GLOBAL: SERVER 0x10027000 */\nint g_a;\n"


def test_annotate_reports_skipped_unnamed(tmp_path: Path) -> None:
    """Metadata entries without a `name` cannot anchor a marker — the run
    must report how many were skipped instead of a silent 0-marker no-op
    (regression: notepad's 31 data symbols are all unnamed)."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "mod.c").write_text("int g_a;\n", encoding="utf-8")
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        '["SERVER.0x10027000"]\nname = "g_a"\nsection = ".data"\n'
        '["SERVER.0x10027004"]\nsize = 4\nsection = ".bss"\n'
        '["SERVER.0x10027008"]\nsize = 8\nsection = ".data"\n',
        encoding="utf-8",
    )
    per_file, skipped = annotate_globals(src, meta, "SERVER", dry_run=True)
    assert per_file == {"mod.c": 1}  # only the named g_a
    assert skipped == 2  # the two unnamed entries


def test_annotate_uses_configured_source_ext(tmp_path: Path) -> None:
    """Discovery follows ``cfg.source_ext``; a raw ``rglob("*.c")`` missed
    ``.cpp`` sources (and the shared-sources root)."""
    from types import SimpleNamespace

    src = tmp_path / "src"
    src.mkdir()
    (src / "mod.cpp").write_text("int g_a;\n", encoding="utf-8")
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text('["SERVER.0x1000"]\nname = "g_a"\nsection = ".data"\n', encoding="utf-8")
    cfg = SimpleNamespace(source_ext=".c,.cpp", reversed_dir=src, shared_dir=None)
    per_file, _ = annotate_globals(src, meta, "SERVER", dry_run=True, cfg=cfg)
    assert per_file == {"mod.cpp": 1}


def test_annotate_duplicate_names_are_not_reported_unnamed(tmp_path: Path) -> None:
    """Two metadata entries sharing a name collapse in the symbol map; the
    skipped count must be the number of name-less entries, not the arithmetic
    difference."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "mod.c").write_text("int g_a;\n", encoding="utf-8")
    meta = tmp_path / "rebrew-data.toml"
    meta.write_text(
        '["SERVER.0x1000"]\nname = "g_a"\nsection = ".data"\n'
        '["SERVER.0x1004"]\nname = "g_a"\nsection = ".data"\n',
        encoding="utf-8",
    )
    per_file, skipped = annotate_globals(src, meta, "SERVER", dry_run=True)
    assert skipped == 0
    assert per_file == {"mod.c": 1}


def test_gen_header_skips_non_c_identifiers(tmp_path) -> None:
    """A decorated import symbol is a fine metadata name and a C syntax error.

    `__imp__GetLocalTime@4` names an IAT slot perfectly well, but the generated
    header is compiled, so emitting `extern void* __imp__GetLocalTime@4;` breaks
    every TU that includes it.  This is the real shape from guild-rebrew's
    crt_imports.c: a `// DATA:` marker with no declaration under it, whose name
    comes from the metadata.
    """
    from types import SimpleNamespace

    from rebrew.data_annotate import gen_globals_header
    from rebrew.data_metadata import set_data_field

    src = tmp_path / "src" / "SERVER"
    src.mkdir(parents=True)
    cfg = SimpleNamespace(
        root=tmp_path,
        target_name="SERVER",
        target_binary=tmp_path / "fake.dll",
        reversed_dir=src,
        metadata_dir=tmp_path,
        marker="SERVER",
        source_ext=".c",
    )
    (src / "imports.c").write_text(
        "// DATA: SERVER 0x1000\n// AUTO-GENERATED, no declaration follows\n",
        encoding="utf-8",
    )
    set_data_field(cfg.metadata_dir, 0x1000, "name", "__imp__GetLocalTime@4", "SERVER")
    set_data_field(cfg.metadata_dir, 0x1000, "type", "void*", "SERVER")
    set_data_field(cfg.metadata_dir, 0x1000, "section", ".idata", "SERVER")

    gen_globals_header(cfg, src)
    text = (src / "rebrew_globals.h").read_text(encoding="utf-8")
    assert "@" not in text, "a decorated symbol must never reach the compiled header"
