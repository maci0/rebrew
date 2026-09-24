"""ghidra-cli backend for sync push — alternative to ReVa MCP.

Translates the in-memory sync operation list into ``ghidra-cli`` subprocess
invocations.  Select via ``ghidra_backend = "cli"`` in ``rebrew-project.toml``
(default stays ``"reva"``); ``rebrew sync`` also falls back to it when MCP
fails before any operation is applied.  ghidra-cli keeps a
bridge with Ghidra loaded in memory, so the first call is slow (headless
spawn) and subsequent per-op calls are cheap TCP round-trips.

Only the push (apply) direction is covered; pull operations still use MCP.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any

from rich.console import Console

from rebrew.utils import run_process_group

# Local console: rebrew.ghidra must stay importable without rebrew.cli
# (library layering test).
console = Console(stderr=True)


def _op_to_args(op: dict[str, Any]) -> list[str] | None:
    """Translate one sync op into ghidra-cli argv (without --program).

    The producers emit ``addressOrSymbol``/``labelName`` (and ``address`` for
    create-function); both spellings are accepted.  Returns ``None`` for
    unknown tools (counted as errors by the caller).
    """
    tool = op.get("tool")
    args = op.get("args", {})

    def _addr() -> str:
        return str(args.get("address") or args.get("addressOrSymbol") or args.get("location") or "")

    if tool == "create-function":
        return ["function", "create", _addr()]
    if tool == "create-label":
        return ["symbol", "create", _addr(), str(args.get("labelName") or args.get("name") or "")]
    if tool == "set-comment":
        cmd = ["comment", "set", _addr(), str(args.get("comment") or "")]
        ctype = args.get("commentType")
        if ctype:
            cmd += ["--comment-type", str(ctype)]
        return cmd
    if tool == "set-bookmark":
        # ghidra-cli 0.2.1 has no `bookmark` subcommand; represent the status
        # bookmark as a plate comment instead (same visual marker at the
        # address, e.g. `rebrew: EXACT`).
        addr = _addr()
        category = str(args.get("category") or "rebrew")
        text = category
        if args.get("comment"):
            text = f"{category}: {args['comment']}"
        return ["comment", "set", addr, text, "--comment-type", "PLATE"]
    if tool == "parse-c-structure":
        # Note: ghidra-cli `type create` has no --category; the producer's
        # "/rebrew" category is intentionally dropped for the cli backend.
        return ["type", "create", str(args.get("cDefinition") or "")]
    if tool == "set-function-prototype":
        return [
            "function",
            "set-signature",
            "--target",
            _addr(),
            "--signature",
            str(args.get("signature") or ""),
        ]
    return None


def apply_commands_via_cli(
    commands: list[dict[str, Any]],
    *,
    program: str = "",
    project: str | None = None,
    ghidra_cli: str = "ghidra-cli",
    timeout: int = 300,
) -> tuple[int, int]:
    """Apply sync commands to Ghidra via the ghidra-cli binary.

    Returns ``(success_count, error_count)`` — same contract as
    ``apply_commands_via_mcp``.
    """
    success = 0
    errors = 0
    for op in commands:
        argv = _op_to_args(op)
        if argv is None:
            errors += 1
            console.print(f"[yellow]warning:[/yellow] unknown sync op: {op.get('tool')!r}")
            continue
        full = [ghidra_cli, *argv]
        if program:
            full += ["--program", program]
        if project:
            full += ["--project", project]
        try:
            # Group kill: ghidra-cli launches a JVM that would outlive a timeout.
            proc = run_process_group(
                full,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            console.print(
                f"[yellow]warning:[/yellow] ghidra-cli failed for {op.get('tool')}: {exc}"
            )
            errors += 1
            continue
        if proc.returncode == 0:
            success += 1
        else:
            combined = f"{proc.stdout or ''}\n{proc.stderr or ''}".strip()
            # Ghidra treats re-applying an existing label/comment/bookmark as
            # an error, but the MCP path counts it as success (idempotent
            # re-push). The CLI backend delegates to _is_idempotent_success so
            # both backends enforce the identical idempotency contract and
            # multi-line stack traces do not cause spurious failures.
            from rebrew.ghidra.client import _is_idempotent_success

            if _is_idempotent_success(op, combined) or any(
                marker in combined.lower()
                for marker in ("already exists", "duplicate", "already has")
            ):
                success += 1
                continue
            errors += 1
            op_args = op.get("args", {})
            addr = (
                op_args.get("address")
                or op_args.get("addressOrSymbol")
                or op_args.get("location")
                or ""
            )
            detail = combined.splitlines()
            last = detail[-1] if detail else ""
            console.print(
                f"[yellow]warning:[/yellow] ghidra-cli {op.get('tool')} "
                f"failed for {addr} (rc={proc.returncode}): {last}"
            )
    return success, errors


def resolve_ghidra_cli(cfg: Any) -> str | None:
    """Resolve the ghidra-cli binary for a project: PATH lookup first, then
    ``tools/ghidra-cli`` (must be an executable file).  ``None`` when neither
    exists — the doctor check and the sync call sites share this so the
    checked binary is the one actually invoked.
    """
    which_bin = shutil.which("ghidra-cli")
    if which_bin:
        return which_bin
    tools_bin = cfg.root / "tools" / "ghidra-cli"
    if tools_bin.is_file() and os.access(tools_bin, os.X_OK):
        return str(tools_bin)
    return None
