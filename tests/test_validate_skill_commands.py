"""Unit tests for tools/validate_skill_commands.py — command extraction."""

import subprocess
import sys
from pathlib import Path

import pytest

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
        # and --json is validated like any other flag.
        assert ("cache stats", ["--json"]) in results

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
        # Only the two flags every command carries are dropped; --json and
        # --target are the ones the skills cite most, so they are checked.
        assert results == [("status", ["--json", "--target"])]

    def test_mermaid_node_commands_are_extracted(self, tmp_path: Path) -> None:
        # The flowchart is what an agent reads first, so a flag that drifts
        # there has to fail the gate the same way a bash block does.
        md = _md(
            "```mermaid\n"
            "graph TD\n"
            "    Pick[Pick a function<br/>rebrew todo --json] --> Lint[rebrew lint --fix]\n"
            "    Bss[Check BSS<br/>rebrew data --bss --json]\n"
            "```\n",
            tmp_path,
        )
        results = vsc._extract_commands(md)
        assert ("todo", ["--json"]) in results
        assert ("lint", ["--fix"]) in results
        assert ("data", ["--bss", "--json"]) in results

    def test_mermaid_placeholder_is_not_a_subcommand(self, tmp_path: Path) -> None:
        md = _md("```mermaid\n    N[rebrew <cmd> 0x1]\n```\n", tmp_path)
        assert vsc._extract_commands(md) == []


class TestRunHelp:
    @pytest.mark.parametrize("returncode", [0, 1, 2])
    def test_exit_status_is_checked(self, monkeypatch: pytest.MonkeyPatch, returncode: int) -> None:
        result = subprocess.CompletedProcess(
            args=["rebrew", "missing", "--help"],
            returncode=returncode,
            stdout="\x1b[1mUsage\x1b[0m",
            stderr="diagnostic",
        )
        monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: result)
        assert vsc._run_help("missing") == (returncode == 0, "Usagediagnostic")

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


class TestProbeFailureMessage:
    def test_timeout_is_not_reported_as_a_stale_skill(self) -> None:
        msg = vsc._probe_failure_message("rebrew-workflow", "data", "<timeout>")
        assert "timeout" in msg
        assert "not a skill defect" in msg
        assert "subcommand not found" not in msg

    def test_missing_subcommand_is_reported_as_missing(self) -> None:
        msg = vsc._probe_failure_message("rebrew-workflow", "data", "Usage: no such command")
        assert msg.endswith("subcommand not found")

    def test_help_timeout_survives_a_cold_import(self) -> None:
        # A cold tree pays bytecode compilation for the whole rebrew import
        # graph under _HELP_WORKERS concurrent probes; the old 30s bound made
        # every one of them look like a stale skill.
        assert vsc._HELP_TIMEOUT_SECONDS >= 120
        assert vsc._HELP_WORKERS >= 1
