"""Idempotency sweeps — running a CLI with --dry-run twice must yield
byte-identical output and leave the filesystem untouched.

Catches nondeterminism (dict ordering, timestamps, unordered iteration)
in dry-run reporting paths across the file-level and listing CLIs.
"""

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

runner = CliRunner()


def _tree_digest(root: Path) -> dict[str, str]:
    """Map every file under *root* to a sha256 of its bytes."""
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _single(va: int, symbol: str, *, status: str = "STUB") -> str:
    marker = "STUB" if status == "STUB" else "FUNCTION"
    name = symbol.lstrip("_")
    return (
        f"// {marker}: SERVER 0x{va:08x}\n"
        f"// STATUS: {status}\n"
        f"// ORIGIN: GAME\n"
        f"// SIZE: 64\n"
        f"// CFLAGS: /O2\n"
        "\n"
        f"int {name}(void) {{ return {va & 1}; }}\n"
    )


def _combined(result: Any) -> str:
    """stdout + stderr; the CLIs split user-facing reports across both."""
    return result.stdout + result.stderr


class TestMergeDryRunIdempotent:
    def test_twice_identical_output_and_no_writes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.merge import app

        a = _write(tmp_path / "a.c", _single(0x10001000, "_func_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_func_b"))
        out = tmp_path / "merged.c"
        monkeypatch.setattr(
            "rebrew.merge.require_config",
            lambda target=None, json_mode=False: SimpleNamespace(
                marker="SERVER", source_ext=".c", reversed_dir=tmp_path, metadata_dir=tmp_path
            ),
        )
        before = _tree_digest(tmp_path)
        args = ["--output", str(out), "--dry-run", str(a), str(b)]
        r1 = runner.invoke(app, args)
        r2 = runner.invoke(app, args)
        assert r1.exit_code == r2.exit_code == 0
        assert _combined(r1) == _combined(r2)
        assert _combined(r1).strip()  # dry-run reports something
        assert not out.exists()
        assert _tree_digest(tmp_path) == before


class TestSplitDryRunIdempotent:
    def test_twice_identical_output_and_no_writes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.split import app

        multi = _write(
            tmp_path / "multi.c",
            _single(0x10001000, "_func_a") + "\n" + _single(0x10002000, "_func_b"),
        )
        monkeypatch.setattr(
            "rebrew.split.require_config",
            lambda target=None, json_mode=False: SimpleNamespace(
                marker="SERVER", source_ext=".c", reversed_dir=tmp_path, metadata_dir=tmp_path
            ),
        )
        before = _tree_digest(tmp_path)
        args = ["--dry-run", str(multi)]
        r1 = runner.invoke(app, args)
        r2 = runner.invoke(app, args)
        assert r1.exit_code == r2.exit_code == 0
        assert _combined(r1) == _combined(r2)
        assert not (tmp_path / "func_a.c").exists()
        assert not (tmp_path / "func_b.c").exists()
        assert _tree_digest(tmp_path) == before


class TestLintDryRunIdempotent:
    TOML = """\
[project]
default_target = "server_dll"

[targets.server_dll]
binary = "original/Server/server.dll"
format = "pe"
arch = "x86_32"
reversed_dir = "src/server_dll"
marker = "SERVER"
"""

    def test_fix_dry_run_twice_identical(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.lint import app

        _write(tmp_path / "rebrew-project.toml", self.TOML)
        _write(tmp_path / "src/server_dll/foo.c", _single(0x10001000, "_func_a"))
        monkeypatch.chdir(tmp_path)
        before = _tree_digest(tmp_path)

        args = ["--fix", "--dry-run", "src/server_dll/foo.c"]
        r1 = runner.invoke(app, args)
        r2 = runner.invoke(app, args)
        assert r1.exit_code == r2.exit_code == 0
        assert _combined(r1) == _combined(r2)
        assert "Would migrate" in _combined(r1)  # exercised the --fix dry-run path
        assert _tree_digest(tmp_path) == before


class TestMatchAllDryRunIdempotent:
    def test_twice_identical_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.match import app

        for va, symbol in ((0x10001000, "_func_a"), (0x10002000, "_func_b")):
            _write(tmp_path / f"func_{va:08x}.c", _single(va, symbol))
        _write(
            tmp_path / "rebrew-functions.toml",
            '["SERVER.0x10001000"]\nsize = 64\n["SERVER.0x10002000"]\nsize = 128\n',
        )
        monkeypatch.setattr(
            "rebrew.match.require_config",
            lambda target=None, json_mode=False: SimpleNamespace(
                marker="SERVER",
                source_ext=".c",
                reversed_dir=tmp_path,
                metadata_dir=tmp_path,
                ignored_symbols=[],
                default_jobs=2,
            ),
        )
        args = ["--all", "--dry-run"]
        r1 = runner.invoke(app, args)
        r2 = runner.invoke(app, args)
        assert r1.exit_code == r2.exit_code == 0
        assert _combined(r1) == _combined(r2)
        assert "func_10001000.c" in _combined(r1)
