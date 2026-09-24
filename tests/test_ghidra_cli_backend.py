"""Tests for the ghidra-cli sync backend (IDEAS #24)."""

import contextlib
import os
import signal
import time
from pathlib import Path

from rebrew.ghidra.cli_backend import _op_to_args, apply_commands_via_cli


def _assert_grandchild_killed(pidfile: Path) -> None:
    """Poll until the pid in *pidfile* is gone or a zombie; kill it on failure.

    A missing or empty *pidfile* means the group kill landed before the
    grandchild recorded itself, so it is already dead.
    """
    text = pidfile.read_text() if pidfile.exists() else ""
    if not text.strip():
        return
    pid = int(text)
    stat = Path(f"/proc/{pid}/stat")

    def _alive() -> bool:
        try:
            return stat.read_text().rsplit(") ", 1)[1][0] != "Z"
        except FileNotFoundError:
            return False

    deadline = time.monotonic() + 5
    try:
        while _alive():
            assert time.monotonic() < deadline, "grandchild outlived the timeout kill"
            time.sleep(0.02)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)


class TestOpToArgs:
    """Op translation — the six sync op types map to ghidra-cli argv.

    Keys mirror what the producers emit (``addressOrSymbol``/``labelName``
    from commands.py, ``address`` for create-function, ``location`` for
    set-function-prototype).
    """

    def test_create_function(self) -> None:
        assert _op_to_args({"tool": "create-function", "args": {"address": "0x10001000"}}) == [
            "function",
            "create",
            "0x10001000",
        ]

    def test_create_label(self) -> None:
        assert _op_to_args(
            {"tool": "create-label", "args": {"addressOrSymbol": "0x10001000", "labelName": "_foo"}}
        ) == ["symbol", "create", "0x10001000", "_foo"]

    def test_set_comment_with_type(self) -> None:
        assert _op_to_args(
            {
                "tool": "set-comment",
                "args": {
                    "addressOrSymbol": "0x10001000",
                    "comment": "hi",
                    "commentType": "plate",
                },
            }
        ) == ["comment", "set", "0x10001000", "hi", "--comment-type", "plate"]

    def test_set_bookmark(self) -> None:
        """ghidra-cli 0.2.1 has no `bookmark` subcommand — the status
        category is represented as a plate comment at the address (the same
        visual marker, e.g. `/rebrew: EXACT`)."""
        assert _op_to_args(
            {
                "tool": "set-bookmark",
                "args": {
                    "addressOrSymbol": "0x10001000",
                    "category": "/rebrew",
                    "comment": "EXACT",
                },
            }
        ) == [
            "comment",
            "set",
            "0x10001000",
            "/rebrew: EXACT",
            "--comment-type",
            "PLATE",
        ]
        # without a comment the category alone is the marker
        assert _op_to_args(
            {
                "tool": "set-bookmark",
                "args": {"addressOrSymbol": "0x10001000", "category": "/rebrew"},
            }
        ) == [
            "comment",
            "set",
            "0x10001000",
            "/rebrew",
            "--comment-type",
            "PLATE",
        ]

    def test_parse_c_structure(self) -> None:
        assert _op_to_args(
            {"tool": "parse-c-structure", "args": {"cDefinition": "typedef int foo;"}}
        ) == ["type", "create", "typedef int foo;"]

    def test_set_function_prototype(self) -> None:
        assert _op_to_args(
            {
                "tool": "set-function-prototype",
                "args": {"location": "0x10001000", "signature": "int foo(int)"},
            }
        ) == ["function", "set-signature", "--target", "0x10001000", "--signature", "int foo(int)"]

    def test_unknown_tool_returns_none(self) -> None:
        assert _op_to_args({"tool": "nope", "args": {}}) is None

    def test_real_producer_output_translates(self) -> None:
        """Integration: the kept structural-op producers (bookmarks, function
        creation) must translate to non-empty ghidra-cli argv (regression for
        the addressOrSymbol/labelName key mismatch)."""
        from rebrew.ghidra.commands import build_bookmark_commands, build_new_function_commands

        entry = {
            "va": 0x10001000,
            "name": "my_func",
            "symbol": "_my_func",
            "status": "EXACT",
            "module": "SERVER",
            "size": 64,
            "cflags": "/O2",
            "marker_type": "FUNCTION",
        }
        bookmark_ops = build_bookmark_commands([entry], "/x.dll")
        assert bookmark_ops, "bookmark producer must emit operations"
        translated = [argv for op in bookmark_ops if (argv := _op_to_args(op)) is not None]
        assert len(translated) == len(bookmark_ops)
        for op, argv in zip(bookmark_ops, translated, strict=False):
            assert argv, "empty argv"
            assert argv[2] not in ("", "None"), f"empty address for {op['tool']}"

        # create-function ops translate too (empty registry → no ops).
        ops = build_new_function_commands({}, "/x.dll")
        assert ops == []


class TestApplyCommandsViaCli:
    def test_success_and_error_counts(self, monkeypatch) -> None:
        calls: list[list[str]] = []

        def fake_run(argv, capture_output=False, text=False, timeout=None, **_kwargs):
            calls.append(argv)
            rc = 0 if "set-signature" not in argv else 1
            return type("P", (), {"returncode": rc, "stdout": "", "stderr": "boom" if rc else ""})()

        monkeypatch.setattr("rebrew.ghidra.cli_backend.run_process_group", fake_run)
        commands = [
            {"tool": "create-function", "args": {"address": "0x1"}},
            {"tool": "set-function-prototype", "args": {"location": "0x2", "signature": "int f()"}},
            {"tool": "unknown-thing", "args": {}},
        ]
        ok, errs = apply_commands_via_cli(commands, program="/x.dll")
        assert ok == 1
        assert errs == 2  # one failed op + one unknown op
        assert calls[0][:3] == ["ghidra-cli", "function", "create"]
        assert "--program" in calls[0]
        assert "/x.dll" in calls[0]

    def test_already_exists_counts_as_success(self, monkeypatch) -> None:
        """Re-applying an existing label is an error for Ghidra but a success
        for the idempotent MCP path — the cli backend must match."""

        def fake_run(argv, capture_output=False, text=False, timeout=None, **_kwargs):
            return type(
                "P",
                (),
                {"returncode": 1, "stdout": "", "stderr": "DuplicateNameException: already exists"},
            )()

        monkeypatch.setattr("rebrew.ghidra.cli_backend.run_process_group", fake_run)
        ok, errs = apply_commands_via_cli(
            [{"tool": "create-label", "args": {"addressOrSymbol": "0x1", "labelName": "x"}}],
            program="",
        )
        assert ok == 1
        assert errs == 0

    def test_multiline_stacktrace_already_exists_counts_as_success(self, monkeypatch) -> None:
        """Ghidra JVM stack traces have the exception on line 1 and frame traces on
        subsequent lines — must still be recognized as idempotent success."""

        def fake_run(argv, capture_output=False, text=False, timeout=None, **_kwargs):
            return type(
                "P",
                (),
                {
                    "returncode": 1,
                    "stdout": "",
                    "stderr": (
                        "ghidra.util.exception.DuplicateNameException: already exists\n"
                        "\tat ghidra.program.database.symbol.SymbolManager.createCodeSymbol(SymbolManager.java:450)\n"
                        "\tat ghidra.app.cmd.label.AddLabelCmd.applyTo(AddLabelCmd.java:65)"
                    ),
                },
            )()

        monkeypatch.setattr("rebrew.ghidra.cli_backend.run_process_group", fake_run)
        ok, errs = apply_commands_via_cli(
            [{"tool": "create-label", "args": {"addressOrSymbol": "0x1", "labelName": "x"}}],
            program="",
        )
        assert ok == 1
        assert errs == 0

    def test_subprocess_error_counts_as_failure(self, monkeypatch) -> None:
        def fake_run(argv, capture_output=False, text=False, timeout=None, **_kwargs):
            raise OSError("no binary")

        monkeypatch.setattr("rebrew.ghidra.cli_backend.run_process_group", fake_run)
        ok, errs = apply_commands_via_cli(
            [{"tool": "create-label", "args": {"addressOrSymbol": "0x1", "labelName": "x"}}],
            program="",
        )
        assert ok == 0
        assert errs == 1

    def test_timeout_kills_ghidra_cli_grandchildren(self, tmp_path: Path) -> None:
        """A timed-out op counts as an error and its JVM-like grandchild dies
        with it instead of outliving the sync loop."""
        pidfile = tmp_path / "grandchild.pid"
        fake_cli = tmp_path / "ghidra-cli"
        fake_cli.write_text(
            f"#!/bin/sh\nsh -c 'echo $$ > \"{pidfile}\"; exec sleep 30' & wait\n",
            encoding="utf-8",
        )
        fake_cli.chmod(0o755)
        ok, errs = apply_commands_via_cli(
            [{"tool": "create-label", "args": {"addressOrSymbol": "0x1", "labelName": "x"}}],
            ghidra_cli=str(fake_cli),
            timeout=1,
        )
        assert (ok, errs) == (0, 1)
        _assert_grandchild_killed(pidfile)
