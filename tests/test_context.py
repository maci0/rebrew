"""Tests for context.py — universal decompiler context file generation."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.context as context

runner = CliRunner()


def _patch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, files: list[Path]) -> SimpleNamespace:
    cfg = SimpleNamespace(
        target_binary=tmp_path / "x.dll",
        reversed_dir=tmp_path / "src",
        root=tmp_path,
        target_name="T",
        metadata_dir=tmp_path,
    )
    cfg.reversed_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(
        context, "require_config", lambda target=None, json_mode=False, root=None: cfg
    )
    monkeypatch.setattr(context, "iter_library_headers", lambda _d: files)
    monkeypatch.setattr(context, "iter_sources", lambda _d, cfg=None: [])
    return cfg


class TestContext:
    def test_collects_and_dedups_declarations(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hdr = tmp_path / "gfx.h"
        hdr.write_text(
            "typedef unsigned int uint32;\n"
            "struct Vec { int x; int y; };\n"
            "enum Color { RED, GREEN };\n"
            "void draw(struct Vec *v);\n",
            encoding="utf-8",
        )
        _patch(monkeypatch, tmp_path, [hdr])
        out = tmp_path / "ctx.c"
        r = CliRunner().invoke(context.app, ["--out", str(out)])
        assert r.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert "struct Vec { int x; int y; };" in text
        assert "typedef unsigned int uint32;" in text
        assert "enum Color { RED, GREEN };" in text
        assert "void draw(struct Vec *v);" in text
        # Dedup: the same struct declared twice yields one block.
        assert text.count("struct Vec {") == 1

    def test_dedups_across_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        a = tmp_path / "a.h"
        b = tmp_path / "b.h"
        a.write_text("struct Dup { int a; };\n", encoding="utf-8")
        b.write_text("struct Dup { int a; };\n", encoding="utf-8")
        _patch(monkeypatch, tmp_path, [a, b])
        out = tmp_path / "ctx.c"
        r = CliRunner().invoke(context.app, ["--out", str(out)])
        assert r.exit_code == 0
        assert out.read_text(encoding="utf-8").count("struct Dup {") == 1

    def test_unreadable_file_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        bad = tmp_path / "bad.h"
        bad.write_text("struct Broken {", encoding="utf-8")  # unparseable fragment
        _patch(monkeypatch, tmp_path, [bad])
        out = tmp_path / "ctx.c"
        r = CliRunner().invoke(context.app, ["--out", str(out)])
        assert r.exit_code == 0
        assert out.exists()
