"""security_scan.py - Rule-based security scanner over reversed C sources.

Matches unsafe C library calls on the tree-sitter AST: the callee identifier
and the argument nodes come from the ``call_expression``, never from a regex
over the raw text.  Six rules cover unbounded string copies, non-literal
format strings, command execution, unchecked memory copies, predictable
randomness, and variable-sized stack allocation; each rule carries its CWE,
severity, and confidence so a report can be triaged by risk.

The scan needs no project: a directory argument selects any C source tree,
and the project's reversed source directory is the default.  A finding is a
review indicator, not proof of an exploitable bug: the same call can be safe
in context.

Usage:
    rebrew security-scan [DIR] [--min-severity high|medium|low]
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import tree_sitter as ts
import typer
from rich.console import Console
from rich.table import Table

from rebrew.c_parser import _find_function_name, _node_text, _parse, get_ts_parser
from rebrew.cli import EXIT_ERROR, TargetOption, error_exit, json_print, require_config
from rebrew.sources import iter_sources

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Rule model
# ---------------------------------------------------------------------------

Level = Literal["high", "medium", "low"]

CheckKind = Literal["always", "string-literal", "integer-literal", "value-source"]

# Check kinds: how a matched call is decided to be a finding.
_CHECK_ALWAYS: CheckKind = "always"
_CHECK_STRING_LITERAL: CheckKind = "string-literal"
_CHECK_INTEGER_LITERAL: CheckKind = "integer-literal"
_CHECK_VALUE_SOURCE: CheckKind = "value-source"

#: tree-sitter node types treated as a literal string argument.
_STRING_LITERAL_TYPES = frozenset({"string_literal", "concatenated_string"})

#: tree-sitter node type for an integer literal argument.
_INTEGER_LITERAL_TYPE = "number_literal"

#: Longest source line kept in a finding's snippet, after trimming.
_SNIPPET_MAX_CHARS = 200

#: Severity levels, most severe first; drives ``--min-severity`` filtering and
#: the ``by_severity`` summary keys.
_SEVERITY_ORDER: tuple[str, ...] = ("high", "medium", "low")

_SEVERITY_COLORS: dict[str, str] = {"high": "red", "medium": "yellow", "low": "cyan"}


@dataclass(frozen=True)
class RuleFunction:
    """One callee a rule matches.

    *arg_index* is the argument a literal check inspects (``None`` for rules
    that inspect the call as a whole).
    """

    name: str
    arg_index: int | None = None


@dataclass(frozen=True)
class SecurityRule:
    """A named detection: CWE, severity, confidence, and the callees it matches."""

    rule: str
    cwe: str
    severity: Level
    confidence: Level
    description: str
    check: CheckKind
    functions: tuple[RuleFunction, ...]


#: Unbounded string copy: the destination write has no length limit.
_UNBOUNDED_COPY = SecurityRule(
    rule="unbounded-copy",
    cwe="CWE-120",
    severity="high",
    confidence="high",
    description="unbounded string copy",
    check=_CHECK_ALWAYS,
    functions=(
        RuleFunction("strcpy"),
        RuleFunction("strcat"),
        RuleFunction("sprintf"),
        RuleFunction("vsprintf"),
        RuleFunction("gets"),
        RuleFunction("lstrcpyA"),
        RuleFunction("lstrcpyW"),
        RuleFunction("lstrcatA"),
        RuleFunction("lstrcatW"),
        RuleFunction("wcscpy"),
        RuleFunction("wcscat"),
    ),
)

#: Format string: the format argument is not a string literal.  The argument
#: index differs per callee (printf 0, fprintf/sprintf 1, snprintf 2).
_FORMAT_STRING = SecurityRule(
    rule="format-string",
    cwe="CWE-134",
    severity="medium",
    confidence="medium",
    description="format argument is not a string literal",
    check=_CHECK_STRING_LITERAL,
    functions=(
        RuleFunction("printf", 0),
        RuleFunction("fprintf", 1),
        RuleFunction("sprintf", 1),
        RuleFunction("snprintf", 2),
        RuleFunction("vprintf", 0),
        RuleFunction("vfprintf", 1),
        RuleFunction("vsnprintf", 2),
    ),
)

#: Command execution: the call spawns a shell or a process.
_COMMAND_EXEC = SecurityRule(
    rule="command-exec",
    cwe="CWE-78",
    severity="medium",
    confidence="medium",
    description="spawns a shell command",
    check=_CHECK_ALWAYS,
    functions=(
        RuleFunction("system"),
        RuleFunction("popen"),
        RuleFunction("WinExec"),
        RuleFunction("ShellExecuteA"),
        RuleFunction("ShellExecuteW"),
        RuleFunction("CreateProcessA"),
        RuleFunction("CreateProcessW"),
    ),
)

#: Unchecked memory copy: the size argument is not an integer literal.
_UNCHECKED_MEMCPY = SecurityRule(
    rule="unchecked-memcpy",
    cwe="CWE-787",
    severity="low",
    confidence="low",
    description="size argument is not an integer literal",
    check=_CHECK_INTEGER_LITERAL,
    functions=(
        RuleFunction("memcpy", 2),
        RuleFunction("memmove", 2),
        RuleFunction("RtlCopyMemory", 2),
        RuleFunction("CopyMemory", 2),
    ),
)

#: Insecure random: a predictable generator feeds a value.
_INSECURE_RANDOM = SecurityRule(
    rule="insecure-random",
    cwe="CWE-338",
    severity="low",
    confidence="low",
    description="predictable value source",
    check=_CHECK_VALUE_SOURCE,
    functions=(
        RuleFunction("rand"),
        RuleFunction("srand"),
        RuleFunction("random"),
        RuleFunction("srandom"),
    ),
)

#: Stack allocation: a non-literal size drives the frame growth.
_STACK_ALLOC = SecurityRule(
    rule="stack-alloc",
    cwe="CWE-770",
    severity="low",
    confidence="low",
    description="stack allocation with a non-literal size",
    check=_CHECK_INTEGER_LITERAL,
    functions=(
        RuleFunction("alloca", 0),
        RuleFunction("_alloca", 0),
    ),
)

_RULES: tuple[SecurityRule, ...] = (
    _UNBOUNDED_COPY,
    _FORMAT_STRING,
    _COMMAND_EXEC,
    _UNCHECKED_MEMCPY,
    _INSECURE_RANDOM,
    _STACK_ALLOC,
)


def _build_rule_index() -> dict[str, tuple[tuple[SecurityRule, RuleFunction], ...]]:
    """Map each callee name to the ``(rule, function)`` entries matching it.

    A callee can belong to more than one rule (``sprintf`` is both an
    unbounded copy and a possible format string), so every entry is kept.
    """
    index: dict[str, list[tuple[SecurityRule, RuleFunction]]] = {}
    for rule in _RULES:
        for entry in rule.functions:
            index.setdefault(entry.name, []).append((rule, entry))
    return {name: tuple(entries) for name, entries in index.items()}


_RULE_INDEX: dict[str, tuple[tuple[SecurityRule, RuleFunction], ...]] = _build_rule_index()

# ---------------------------------------------------------------------------
# AST scan
# ---------------------------------------------------------------------------

_CALL_QUERY_SOURCE = """
(call_expression
  function: (identifier) @callee
  arguments: (argument_list) @args) @call
"""

_call_query: ts.Query | None = None


def _get_call_query(language: ts.Language) -> ts.Query:
    """Compile the call-expression query once per process."""
    global _call_query
    if _call_query is None:
        _call_query = ts.Query(language, _CALL_QUERY_SOURCE)
    return _call_query


def _first_node(captures: dict[str, list[ts.Node]], name: str) -> ts.Node | None:
    """First node for a named query capture, or ``None`` when absent."""
    nodes = captures.get(name)
    return nodes[0] if nodes else None


def _enclosing_function(call: ts.Node, source_bytes: bytes) -> str:
    """Name of the function definition containing *call*, or ``""``."""
    node = call.parent
    while node is not None:
        if node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            if declarator is None:
                return ""
            return _find_function_name(declarator, source_bytes) or ""
        node = node.parent
    return ""


def _is_value_source(call: ts.Node) -> bool:
    """True when the call's result is consumed rather than discarded.

    ``srand(1);`` is a statement (a seed); ``x = rand();`` and
    ``if (rand())`` consume the result.
    """
    parent = call.parent
    return parent is not None and parent.type != "expression_statement"


def _matches(
    rule: SecurityRule, entry: RuleFunction, call: ts.Node, args: Sequence[ts.Node]
) -> bool:
    """True when a matched call of *entry* satisfies *rule*'s check."""
    if rule.check == _CHECK_ALWAYS:
        return True
    if rule.check == _CHECK_VALUE_SOURCE:
        return _is_value_source(call)
    argument = None
    if entry.arg_index is not None and entry.arg_index < len(args):
        argument = args[entry.arg_index]
    if rule.check == _CHECK_STRING_LITERAL:
        return argument is None or argument.type not in _STRING_LITERAL_TYPES
    return argument is None or argument.type != _INTEGER_LITERAL_TYPE


def _snippet(lines: Sequence[str], row: int) -> str:
    """Trimmed source line at *row*, capped at :data:`_SNIPPET_MAX_CHARS`."""
    if row < 0 or row >= len(lines):
        return ""
    return lines[row].strip()[:_SNIPPET_MAX_CHARS]


def scan_source(text: str, *, file: str) -> list[dict[str, Any]]:
    """Scan one C source *text* and return findings attributed to *file*.

    Findings are sorted by line then rule.  Empty input, a source with a
    syntax error, and an unavailable tree-sitter runtime all yield ``[]``.
    """
    if not text.strip():
        return []
    parsed = get_ts_parser()
    if parsed is None:
        return []
    try:
        tree, source_bytes = _parse(text)
    except ImportError:
        return []
    _, language = parsed

    lines = text.splitlines()
    cursor = ts.QueryCursor(_get_call_query(language))
    findings: list[dict[str, Any]] = []
    for _pattern_index, captures in cursor.matches(tree.root_node):
        call = _first_node(captures, "call")
        callee_node = _first_node(captures, "callee")
        args_node = _first_node(captures, "args")
        if call is None or callee_node is None or args_node is None:
            continue
        callee = _node_text(callee_node, source_bytes)
        entries = _RULE_INDEX.get(callee)
        if not entries:
            continue
        args = args_node.named_children
        row = call.start_point[0]
        function = _enclosing_function(call, source_bytes)
        snippet = _snippet(lines, row)
        for rule, entry in entries:
            if not _matches(rule, entry, call, args):
                continue
            findings.append(
                {
                    "rule": rule.rule,
                    "cwe": rule.cwe,
                    "severity": rule.severity,
                    "confidence": rule.confidence,
                    "file": file,
                    "line": row + 1,
                    "function": function,
                    "snippet": snippet,
                    "message": f"{callee}(): {rule.description}",
                }
            )
    findings.sort(key=lambda finding: (finding["line"], finding["rule"]))
    return findings


def scan_paths(paths: Sequence[Path]) -> list[dict[str, Any]]:
    """Scan every path and return all findings sorted by file, line, then rule.

    An unreadable path is skipped; the remaining files still report.
    """
    findings: list[dict[str, Any]] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_source(text, file=str(path)))
    findings.sort(key=lambda finding: (finding["file"], finding["line"], finding["rule"]))
    return findings


def _source_files(directory: Path, *, recursive: bool) -> list[Path]:
    """``.c`` files under *directory* (recursive uses the project discovery rules)."""
    if not directory.is_dir():
        return []
    if recursive:
        return iter_sources(directory)
    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.suffix.lower() == ".c" and not path.is_symlink()
    )


def security_scan(directory: Path, *, recursive: bool = True) -> dict[str, Any]:
    """Scan every C source under *directory* and summarise the findings.

    Returns ``{"root", "files_scanned", "findings", "count", "by_severity"}``
    with findings sorted by file, line, then rule.  No findings is a valid
    result: every ``by_severity`` key is present with a zero default.
    """
    paths = _source_files(directory, recursive=recursive)
    findings = scan_paths(paths)
    by_severity: dict[str, int] = dict.fromkeys(_SEVERITY_ORDER, 0)
    for finding in findings:
        by_severity[str(finding["severity"])] += 1
    return {
        "root": str(directory),
        "files_scanned": len(paths),
        "findings": findings,
        "count": len(findings),
        "by_severity": by_severity,
    }


def _filter_result(result: dict[str, Any], min_severity: str) -> dict[str, Any]:
    """Drop findings below *min_severity* and recompute the summary counts."""
    limit = _SEVERITY_ORDER.index(min_severity)
    findings = [
        finding
        for finding in result["findings"]
        if _SEVERITY_ORDER.index(str(finding["severity"])) <= limit
    ]
    by_severity: dict[str, int] = dict.fromkeys(_SEVERITY_ORDER, 0)
    for finding in findings:
        by_severity[str(finding["severity"])] += 1
    return {**result, "findings": findings, "count": len(findings), "by_severity": by_severity}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Scan C sources for unsafe API use (unbounded copies, format strings, command execution).",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew security-scan · · · · · · · · · Scan the project's reversed sources\n\n"
        "  rebrew security-scan src/other · · · · Scan an arbitrary C source tree\n\n"
        "  rebrew security-scan --min-severity high Only high-severity findings\n\n"
        "  rebrew security-scan --json · · · · · · Machine-readable findings\n\n"
        "[bold]Rules (id, CWE, severity):[/bold]\n\n"
        "  unbounded-copy · · · strcpy/strcat/sprintf/gets/... (CWE-120, high)\n\n"
        "  format-string · · · · non-literal printf-family format (CWE-134, medium)\n\n"
        "  command-exec · · · · · system/popen/WinExec/... (CWE-78, medium)\n\n"
        "  unchecked-memcpy · · · non-literal memcpy/memmove size (CWE-787, low)\n\n"
        "  insecure-random · · · · rand/random used as a value (CWE-338, low)\n\n"
        "  stack-alloc · · · · · · alloca with a non-literal size (CWE-770, low)\n\n"
        "[dim]A finding is a review indicator: the call can be safe in context.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    directory: Path | None = typer.Argument(
        None, help="C source tree (default: the project's reversed sources)"
    ),
    min_severity: str = typer.Option(
        "low", "--min-severity", help="Minimum severity to report (high, medium, or low)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Scan C sources for unsafe API use and report findings by severity."""
    if min_severity not in _SEVERITY_ORDER:
        error_exit(
            f"invalid --min-severity {min_severity!r}; expected one of: {', '.join(_SEVERITY_ORDER)}",
            json_mode=json_output,
        )
    if directory is None:
        cfg = require_config(target=target, json_mode=json_output)
        directory = cfg.reversed_dir
    if not directory.is_dir():
        error_exit(
            f"source directory not found: {directory}", json_mode=json_output, code=EXIT_ERROR
        )

    result = _filter_result(security_scan(directory), min_severity)

    if json_output:
        json_print(result)
        return

    findings = result["findings"]
    if not findings:
        console.print(f"[yellow]No security findings in {directory}.[/]")
        return
    by_severity = result["by_severity"]
    console.print(
        f"[bold]{result['count']}[/] finding(s) across "
        f"[bold]{result['files_scanned']}[/] file(s) "
        f"(high: {by_severity['high']}, medium: {by_severity['medium']}, "
        f"low: {by_severity['low']}):"
    )
    table = Table()
    table.add_column("Severity", style="bold")
    table.add_column("Rule")
    table.add_column("CWE")
    table.add_column("File:Line")
    table.add_column("Function")
    table.add_column("Snippet", overflow="fold")
    for finding in findings:
        severity = str(finding["severity"])
        table.add_row(
            f"[{_SEVERITY_COLORS[severity]}]{severity}[/]",
            str(finding["rule"]),
            str(finding["cwe"]),
            f"{finding['file']}:{finding['line']}",
            str(finding["function"]),
            str(finding["snippet"]),
        )
    console.print(table)


def main_entry() -> None:
    """Run the Typer CLI application."""
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
