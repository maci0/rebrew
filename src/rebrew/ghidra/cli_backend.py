"""ghidra-cli backend for sync push — alternative to ReVa MCP.

Translates the sync operation list (``ghidra_commands.json``) into
``ghidra-cli`` subprocess invocations.  Select via ``ghidra_backend = "cli"``
in ``rebrew-project.toml`` (default stays ``"reva"``).  ghidra-cli keeps a
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
        # category as a plate comment instead (same visual marker at the
        # address — e.g. `rebrew/exact`).
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
            proc = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            console.print(
                f"[yellow]warning:[/yellow] ghidra-cli failed for {op.get('tool')}: {exc}"
            )
            errors += 1
            continue
        if proc.returncode == 0:
            success += 1
        else:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()
            last = detail[-1] if detail else ""
            # Ghidra treats re-applying an existing label/comment/bookmark as
            # an error, but the MCP path counts it as success (idempotent
            # re-push).  Match that: "already exists"-style failures are OK.
            if any(
                marker in last.lower() for marker in ("already exists", "duplicate", "already has")
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
            console.print(
                f"[yellow]warning:[/yellow] ghidra-cli {op.get('tool')} "
                f"failed for {addr} (rc={proc.returncode}): {last}"
            )
    return success, errors


def _run_json_cli(
    args: list[str],
    *,
    program: str = "",
    project: str | None = None,
    ghidra_cli: str = "ghidra-cli",
    timeout: int = 600,
) -> list[dict[str, Any]]:
    """Run a ghidra-cli list command with --json and parse the JSONL output.

    Returns the parsed result objects (one per line); malformed lines and
    non-zero exits yield nothing.
    """
    import json

    full = [ghidra_cli, *args, "--json"]
    if program:
        full += ["--program", program]
    if project:
        full += ["--project", project]
    try:
        proc = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        console.print(
            f"[yellow]warning:[/yellow] ghidra-cli {args[0]} {args[1] if len(args) > 1 else ''} failed: {exc}"
        )
        return []
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        console.print(
            f"[yellow]warning:[/yellow] ghidra-cli {args[0]} {args[1] if len(args) > 1 else ''} "
            f"failed (rc={proc.returncode}): {detail[-1] if detail else 'no output'}"
        )
        return []
    # Prefer a single JSON document (pretty-printed output); fall back to
    # one record per line (JSONL).
    try:
        whole = json.loads(proc.stdout)
        if isinstance(whole, dict):
            return [whole]
        if isinstance(whole, list):
            return [r for r in whole if isinstance(r, dict)]
    except json.JSONDecodeError:
        pass
    records: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            records.append(parsed)
    return records


def _to_va(addr: str | int | None) -> int | None:
    """Normalize a Ghidra address string (bare hex, e.g. ``10001000``) to int."""
    if isinstance(addr, int):
        return addr
    if isinstance(addr, str):
        s = addr.strip()
        if s[:2].lower() == "0x":
            try:
                return int(s, 16)
            except ValueError:
                return None
        if s and all(c in "0123456789abcdefABCDEF" for c in s):
            try:
                return int(s, 16)
            except ValueError:
                return None
    return None


def fetch_pull_data_via_cli(
    *,
    program: str = "",
    project: str | None = None,
    ghidra_cli: str = "ghidra-cli",
    timeout: int = 600,
) -> dict[str, list[dict[str, Any]]]:
    """Fetch functions/symbols/comments from Ghidra via ghidra-cli, shaped for
    the pull pipeline (``pull_ghidra_renames``).

    Returns ``{"functions": [...], "symbols": [...], "plate": [...], "pre": [...]}``
    with VAs as ints (the pull path's ``parse_ghidra_va`` accepts both).
    """
    functions: list[dict[str, Any]] = []
    symbols: list[dict[str, Any]] = []
    plate: list[dict[str, Any]] = []
    pre: list[dict[str, Any]] = []

    for rec in _run_json_cli(
        ["function", "list"],
        program=program,
        project=project,
        ghidra_cli=ghidra_cli,
        timeout=timeout,
    ):
        for fn in rec.get("functions", []):
            va = _to_va(fn.get("address"))
            if va is not None and fn.get("name"):
                functions.append({"va": va, "tool_name": fn["name"], "size": fn.get("size", 0)})

    for rec in _run_json_cli(
        ["symbol", "list"], program=program, project=project, ghidra_cli=ghidra_cli, timeout=timeout
    ):
        for sym in rec.get("symbols", []):
            # Only primary symbols — secondary/generic labels would clobber
            # real function names in the pull (the MCP path filters the same).
            if sym.get("is_primary") is False:
                continue
            va = _to_va(sym.get("address"))
            if va is not None and sym.get("name"):
                symbols.append({"va": va, "name": sym["name"], "type": sym.get("type", "")})

    for rec in _run_json_cli(
        ["comment", "list"],
        program=program,
        project=project,
        ghidra_cli=ghidra_cli,
        timeout=timeout,
    ):
        for cmt in rec.get("comments", []):
            va = _to_va(cmt.get("address"))
            ctype = str(cmt.get("type", "")).upper()
            if va is None or not cmt.get("text"):
                continue
            entry = {"address": va, "comment": cmt["text"]}
            if ctype == "PLATE":
                plate.append(entry)
            elif ctype == "PRE":
                pre.append(entry)

    return {"functions": functions, "symbols": symbols, "plate": plate, "pre": pre}


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
