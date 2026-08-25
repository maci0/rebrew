"""Tests for rebrew data --annotate (// GLOBAL: marker insertion)."""

from __future__ import annotations

from pathlib import Path

from rebrew.data import annotate_globals


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
