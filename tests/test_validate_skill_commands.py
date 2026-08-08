"""Unit tests for tools/validate_skill_commands.py — command extraction."""

import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import validate_skill_commands as vsc  # noqa: E402


def _md(content: str, tmp_path: Path) -> Path:
    p = tmp_path / "SKILL.md"
    p.write_text(content, encoding="utf-8")
    return p


class TestExtractCommands:
    def test_single_command_with_flags(self, tmp_path: Path) -> None:
        md = _md(
            "```bash\nrebrew test src/f.c --va 0x1000 --symbol _f\nrebrew diff src/f.c --mm\n```\n",
            tmp_path,
        )
        results = vsc._extract_commands(md)
        assert ("test", ["--va", "--symbol"]) in results
        assert ("diff", ["--mm"]) in results

    def test_multi_subcommand_absorbed(self, tmp_path: Path) -> None:
        md = _md("```bash\nrebrew cfg add-target --binary x.dll\n```\n", tmp_path)
        results = vsc._extract_commands(md)
        assert ("cfg add-target", ["--binary"]) in results

    def test_multi_subcommand_flag_second_token(self, tmp_path: Path) -> None:
        md = _md("```bash\nrebrew cache stats --json\n```\n", tmp_path)
        results = vsc._extract_commands(md)
        # "cache" is a multi-command group: the subsubcommand is absorbed,
        # and --json is in _SKIP_FLAGS.
        assert ("cache stats", []) in results

    def test_skips_placeholders_and_comments(self, tmp_path: Path) -> None:
        md = _md(
            "```bash\n"
            "# a comment\n"
            "rebrew <sub> foo\n"  # placeholder first-sub → skipped
            "rebrew skeleton <VA> --name foo  # inline comment\n"
            "not a rebrew line\n"
            "```\n",
            tmp_path,
        )
        # The placeholder-first line is skipped; the skeleton line survives
        # (its placeholder is in the second token, not the subcommand).
        assert vsc._extract_commands(md) == [("skeleton", ["--name"])]

    def test_skip_flags_filtered(self, tmp_path: Path) -> None:
        md = _md("```bash\nrebrew status --json --target x --help\n```\n", tmp_path)
        results = vsc._extract_commands(md)
        assert results == [("status", [])]


class TestRunHelp:
    def test_timeout_returns_false(self, monkeypatch) -> None:
        import subprocess

        def _run(*a, **k):
            raise subprocess.TimeoutExpired("uv", 30)

        monkeypatch.setattr(subprocess, "run", _run)
        assert vsc._run_help("test") == (False, "<timeout>")

    def test_filenotfound_returns_false(self, monkeypatch) -> None:
        import subprocess

        def _run(*a, **k):
            raise FileNotFoundError("uv")

        monkeypatch.setattr(subprocess, "run", _run)
        assert vsc._run_help("test") == (False, "<uv not found>")
