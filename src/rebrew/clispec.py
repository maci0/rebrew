"""clispec 0.3 document for the rebrew umbrella CLI.

The document is built from the live Typer command tree. It does not read a
project, a credential, or the network. ``schema`` is the only caller.
"""

from __future__ import annotations

import re
from typing import Any

import typer

from rebrew import __version__

_RICH_TAG = re.compile(
    r"\[/?(?:bold|dim|cyan|green|yellow|red|italic|underline|white|blue|magenta)\]",
    re.IGNORECASE,
)

# Leaves whose commands only report state. Anything else is non-idempotent
# unless named in _IDEMPOTENT: this tree does not accept an idempotency key,
# so a retry is not declared safe.
_READ_ONLY_LEAVES = frozenset(
    {
        "check",
        "describe",
        "diff",
        "doctor",
        "dump",
        "explain",
        "findings",
        "info",
        "inspect",
        "lint",
        "list",
        "lookup",
        "preview",
        "query",
        "review",
        "schema",
        "search",
        "show",
        "stats",
        "status",
        "todo",
    }
)

# These edits already exit 0 when the requested state is in place and report
# ``changed`` in JSON. Do not add a command here without that field.
_IDEMPOTENT = frozenset({"cfg target remove", "cfg module remove"})

# Commands that prompt on a terminal and refuse without one unless this flag
# is set. The flag is also what JSON mode requires instead of prompting.
_CONFIRMATION = {
    "source merge": "--force",
    "source split": "--force",
    "cache clear": "--force",
    "cfg target remove": "--force",
    "cfg module remove": "--force",
    "coverage catalog": "--force",
}

_RETRY_NOTE = (
    " No idempotency key is accepted, so a retry is not a safe substitute for"
    " knowing whether the first run finished."
)

_GLOBAL_FLAGS = frozenset(
    {"--help", "-h", "--version", "-V", "--verbose", "-v", "--quiet", "-q", "--json"}
)


def build_schema(root: typer.Typer, *, path: str | None = None) -> dict[str, Any]:
    """Return the clispec document, optionally narrowed to *path*."""
    click_root = typer.main.get_command(root)
    commands = [_command(name, cmd) for name, cmd in _walk(click_root, "") if _matches(name, path)]
    commands.sort(key=lambda item: item["name"])
    return {
        "clispec": "0.3",
        "name": "rebrew",
        "version": __version__,
        "description": "Compiler-in-the-loop decompilation workbench.",
        "output": {"tty": "text", "piped": "text"},
        "global_args": [
            {
                "name": "--output",
                "short": "-o",
                "type": "string",
                "enum": ["auto", "text", "json"],
                "default": "auto",
                "description": (
                    "Format selected before the subcommand. auto stays text,"
                    " including when stdout is not a terminal. A command's own"
                    " --output after the command name is a destination path."
                ),
            },
            {
                "name": "--json",
                "type": "boolean",
                "default": False,
                "description": "Synonym for --output json. Ignored when --output text is set.",
            },
            {
                "name": "--verbose",
                "short": "-v",
                "type": "integer",
                "default": 0,
                "description": "Increase log verbosity (-v: info, -vv: debug).",
            },
            {
                "name": "--quiet",
                "short": "-q",
                "type": "boolean",
                "default": False,
                "description": "Cancel --verbose and leave logs at warning.",
            },
            {
                "name": "--version",
                "short": "-V",
                "type": "boolean",
                "default": False,
                "description": "Show version and exit.",
            },
        ],
        "commands": commands,
        "errors": [
            {
                "kind": "usage",
                "exit_code": 2,
                "retryable": False,
                "description": "The invocation was rejected before the command ran.",
            },
            {
                "kind": "failure",
                "exit_code": 2,
                "retryable": False,
                "description": "The command could not finish.",
            },
            {
                "kind": "confirmation_required",
                "exit_code": 2,
                "retryable": False,
                "description": "A confirmation prompt had no terminal. The hint names the bypass flag.",
            },
        ],
        "outcomes": [
            {
                "code": 1,
                "name": "mismatch",
                "description": (
                    "A check found a difference or a failed match."
                    " The report is on stdout. Not an error."
                ),
            }
        ],
    }


def _matches(name: str, path: str | None) -> bool:
    if not path:
        return True
    return name == path or name.startswith(path + " ")


def _walk(cmd: Any, prefix: str) -> list[tuple[str, Any]]:
    """Walk invocable commands. Typer groups are not ``click.Group`` instances."""
    from click import Context

    found: list[tuple[str, Any]] = []
    commands = getattr(cmd, "commands", None)
    if isinstance(commands, dict):
        if prefix and getattr(cmd, "invoke_without_command", False):
            found.append((prefix, cmd))
        ctx = Context(cmd, resilient_parsing=True)
        for name in cmd.list_commands(ctx):
            child = cmd.get_command(ctx, name)
            if child is None or getattr(child, "hidden", False):
                continue
            path = f"{prefix} {name}".strip()
            found.extend(_walk(child, path))
        return found
    if prefix:
        found.append((prefix, cmd))
    return found


def _command(path: str, cmd: Any) -> dict[str, Any]:
    leaf = path.rsplit(maxsplit=1)[-1]
    if path in _IDEMPOTENT:
        effects = "idempotent"
    elif leaf in _READ_ONLY_LEAVES:
        effects = "read_only"
    else:
        effects = "non_idempotent"
    description = _plain(str(cmd.help or cmd.short_help or path)) or path
    if effects == "non_idempotent":
        description += _RETRY_NOTE
    entry: dict[str, Any] = {
        "name": path,
        "description": description,
        "effects": effects,
    }
    if path == "skills list":
        entry["cardinality"] = "bounded"
        entry["output_fields"] = [
            {"name": "name", "type": "string"},
            {"name": "description", "type": "string"},
            {"name": "origin", "type": "string"},
        ]
    else:
        entry["cardinality"] = "single"
        entry["stdout_schema"] = {}
    args = _args(cmd)
    if args:
        entry["args"] = args
    bypass = _CONFIRMATION.get(path)
    if bypass is not None and _has_flag(cmd, bypass):
        entry["confirmation_bypass_arg"] = bypass
    return entry


def _plain(text: str) -> str:
    return " ".join(_RICH_TAG.sub("", text).split())


def _has_flag(cmd: Any, flag: str) -> bool:
    return any(flag in getattr(param, "opts", ()) for param in getattr(cmd, "params", ()))


def _args(cmd: Any) -> list[dict[str, Any]]:
    rendered: list[dict[str, Any]] = []
    for param in getattr(cmd, "params", ()):
        opts = list(getattr(param, "opts", ()) or ())
        if opts and opts[0] in _GLOBAL_FLAGS:
            continue
        if opts and opts[0] in {"--help", "-h"}:
            continue
        name = opts[0] if opts else (param.name or "arg")
        if name in _GLOBAL_FLAGS:
            continue
        spec: dict[str, Any] = {"name": name, "type": _arg_type(param)}
        shorts = [opt for opt in opts[1:] if len(opt) == 2 and opt.startswith("-")]
        if shorts:
            spec["short"] = shorts[0]
        if getattr(param, "required", False):
            spec["required"] = True
        default = _json_default(getattr(param, "default", None))
        if default is not _OMIT:
            spec["default"] = default
        choices = getattr(getattr(param, "type", None), "choices", None)
        if choices:
            spec["enum"] = [choice for choice in choices if _json_default(choice) is not _OMIT]
        help_text = _plain(str(getattr(param, "help", "") or ""))
        if help_text:
            spec["description"] = help_text
        rendered.append(spec)
    return rendered


def _arg_type(param: Any) -> str:
    scalar = _scalar_type(param)
    multiple = bool(getattr(param, "multiple", False))
    nargs = getattr(param, "nargs", 1)
    if multiple or (isinstance(nargs, int) and nargs < 0):
        return f"{scalar}[]"
    return scalar


def _scalar_type(param: Any) -> str:
    if getattr(param, "is_flag", False):
        return "boolean"
    type_name = type(getattr(param, "type", None)).__name__.lower()
    if "bool" in type_name:
        return "boolean"
    if "int" in type_name:
        return "integer"
    if "float" in type_name:
        return "number"
    if "path" in type_name or "file" in type_name:
        return "path"
    return "string"


class _Omit:
    pass


_OMIT = _Omit()


def _json_default(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return _OMIT
