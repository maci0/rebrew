"""link-order — enforce VA-ordered sources into CMakeLists.txt SOURCES.

``rebrew order-sources`` prints the VA link order; this command writes that
order into the project's ``CMakeLists.txt`` so the link actually builds TUs
in position-aligned order, and ``--check`` gates drift in CI.

The ``set(SOURCES ...)`` block wins when present, else the first
``add_library``/``add_executable`` file list with source entries.  Only the
source entries inside the block are replaced in place — the target name,
keywords (``STATIC``, ``WIN32``, ...), generator expressions, quoting, and
every line outside the entries are preserved verbatim.

Usage:
    rebrew link-order [--apply] [--dry-run] [--check] [--json]
"""

from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import EXIT_MISMATCH, TargetOption, error_exit, json_print, require_config
from rebrew.order_sources import order_sources
from rebrew.sources import iter_sources, source_exts
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

app = typer.Typer(
    help="Enforce VA-ordered sources into CMakeLists.txt SOURCES (drift gate).",
    rich_markup_mode="rich",
)

_CMAKE_LISTS = "CMakeLists.txt"

_BLOCK_RE = re.compile(r"(?i)(?P<cmd>set|add_library|add_executable)[ \t]*\(")
_COMMENT_RE = re.compile(r"#[^\n]*")


@dataclass
class _Block:
    """One CMake source list: spans of its managed source tokens."""

    label: str
    close_idx: int
    managed: list[str]
    spans: list[tuple[int, int, str]]
    open_indent: str


def _matching_paren(text: str, open_idx: int) -> int | None:
    """Index of the ``)`` closing the paren at *open_idx* (None if unbalanced)."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _token_spans(text: str, start: int, end: int) -> list[tuple[int, int, str]]:
    """Split ``text[start:end]`` into ``(start, end, raw)`` tokens.

    Skips whitespace and ``#`` comments; quoted strings stay one token.
    """
    spans: list[tuple[int, int, str]] = []
    i = start
    while i < end:
        c = text[i]
        if c in " \t\r\n":
            i += 1
        elif c == "#":
            while i < end and text[i] != "\n":
                i += 1
        elif c == '"':
            j = i + 1
            while j < end and text[j] != '"':
                if text[j] == "\\":
                    j += 1
                j += 1
            j = min(j + 1, end)
            spans.append((i, j, text[i:j]))
            i = j
        elif c in "()":
            spans.append((i, i + 1, c))
            i += 1
        else:
            j = i
            while j < end and text[j] not in ' \t\r\n#"()':
                j += 1
            spans.append((i, j, text[i:j]))
            i = j
    return spans


def _line_indent(text: str, pos: int) -> str:
    """Leading whitespace of the line containing *pos*."""
    line_start = text.rfind("\n", 0, pos) + 1
    m = re.match(r"[ \t]*", text[line_start:])
    return m.group(0) if m else ""


def _parse_block(
    text: str, cmd: str, open_idx: int, close_idx: int, *, wanted: set[str]
) -> _Block | None:
    """Parse the paren body into managed source spans (None when not a source list)."""
    spans = [s for s in _token_spans(text, open_idx + 1, close_idx) if s[2] not in ("(", ")")]
    if cmd.lower() == "set":
        if not spans or spans[0][2] != "SOURCES":
            return None
        spans = spans[1:]
        label = "set(SOURCES ...)"
    else:
        label = f"{cmd}(...)"

    def _is_source(raw: str) -> bool:
        return bool(raw.strip('"')) and Path(raw.strip('"')).suffix.lower() in wanted

    managed_spans = [s for s in spans if _is_source(s[2])]
    if cmd.lower() != "set" and not managed_spans:
        return None
    managed = [raw.strip('"').replace("\\", "/") for _, _, raw in managed_spans]
    open_indent = _line_indent(text, open_idx)
    return _Block(label, close_idx, managed, managed_spans, open_indent)


def find_sources_block(text: str, wanted: set[str]) -> _Block | None:
    """Locate the managed SOURCES list in CMake *text*.

    ``set(SOURCES ...)`` wins when present, else the first
    ``add_library``/``add_executable`` list with source entries.  Returns
    None when neither exists.
    """
    fallback: _Block | None = None
    for m in _BLOCK_RE.finditer(text):
        open_idx = m.end() - 1
        close_idx = _matching_paren(text, open_idx)
        if close_idx is None:
            continue
        block = _parse_block(text, m.group("cmd"), open_idx, close_idx, wanted=wanted)
        if block is None:
            continue
        if block.label.startswith("set("):
            return block
        if fallback is None:
            fallback = block
    return fallback


def _abs_key(root: Path, token: str) -> str:
    cleaned = token.strip('"').replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return os.path.normpath(os.path.join(str(root), cleaned))


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def normalize_listed(root: Path, listed: list[str], by_key: dict[str, str]) -> list[str]:
    """Map listed tokens onto computed rel paths where they resolve to a source."""
    return [by_key.get(_abs_key(root, tok), tok) for tok in listed]


def _entry_sep(text: str, block: _Block) -> str:
    """Separator to join list entries: newline+indent in block style, space inline."""
    if len(block.spans) >= 2:
        gap = text[block.spans[-2][1] : block.spans[-1][0]]
        if "\n" in gap:
            return "\n" + _line_indent(text, block.spans[-1][0])
        return " "
    if block.spans:
        (start, end, _) = block.spans[0]
        head = text.rfind("\n", 0, start)
        tail = text.find("\n", end, block.close_idx)
        if head != -1 or tail != -1:
            return "\n" + _line_indent(text, start)
        return " "
    return "\n" + block.open_indent + "  "


def _quote(raw: str, entry: str) -> str:
    return f'"{entry}"' if raw.startswith('"') else entry


def render_block(text: str, block: _Block, ordered: list[str]) -> str:
    """Splice *ordered* entries over the block's managed spans, in place.

    Surplus listed entries are deleted with their preceding separator; new
    entries are appended after the last span.  Fixed tokens, quoting style
    (per position), comments, and surrounding text are untouched.
    """
    spans = block.spans
    if not spans:
        sep = _entry_sep(text, block)
        if sep == " ":
            return text[: block.close_idx] + " ".join(ordered) + " " + text[block.close_idx :]
        inner = sep.join(["", *ordered]) + "\n" + block.open_indent
        return text[: block.close_idx] + inner + text[block.close_idx :]
    sep = _entry_sep(text, block)
    out = text
    for i in range(min(len(spans), len(ordered)) - 1, -1, -1):
        start, end, raw = spans[i]
        out = out[:start] + _quote(raw, ordered[i]) + out[end:]
    for j in range(len(spans) - 1, len(ordered) - 1, -1):
        start, end, _ = spans[j]
        gap = out[spans[j - 1][1] : start] if j > 0 else ""
        if j > 0 and _COMMENT_RE.sub("", gap).strip():
            out = out[:start] + out[end:]
        else:
            anchor = spans[j - 1][1] if j > 0 else start
            out = out[:anchor] + out[end:]
    if len(ordered) > len(spans):
        anchor = spans[-1][1] + sum(
            len(_quote(spans[i][2], ordered[i])) - (spans[i][1] - spans[i][0])
            for i in range(len(spans))
        )
        extras = []
        for k in range(len(spans), len(ordered)):
            raw = spans[k][2] if k < len(spans) else ""
            extras.append(_quote(raw, ordered[k]))
        out = out[:anchor] + sep.join(["", *extras]) + out[anchor:]
    return out


def _drift_diff(current: list[str], ordered: list[str]) -> str:
    lines = difflib.unified_diff(
        current,
        ordered,
        fromfile=f"{_CMAKE_LISTS} (current)",
        tofile=f"{_CMAKE_LISTS} (VA order)",
        lineterm="",
    )
    return "\n".join(lines)


def _payload(
    cmake: Path,
    computed: list[str],
    current: list[str],
    in_sync: bool,
    applied: bool,
    dropped: list[str],
    diff: str,
) -> dict[str, object]:
    return {
        "cmake_lists": str(cmake),
        "ordered": computed,
        "current": current,
        "in_sync": in_sync,
        "applied": applied,
        "dropped": dropped,
        "diff": diff,
    }


@app.callback(invoke_without_command=True)
def main(
    apply: bool = typer.Option(False, "--apply", help="Rewrite the SOURCES block in VA order"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    check: bool = typer.Option(
        False, "--check", help="Exit 1 with a diff when the SOURCES block drifts from VA order"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Enforce the VA link order into CMakeLists.txt SOURCES (preview by default)."""
    if check and apply:
        error_exit("--check cannot be combined with --apply", json_mode=json_output)
    cfg = require_config(target=target, json_mode=json_output)
    files = iter_sources(cfg.reversed_dir, cfg)
    if not files:
        error_exit(f"no source files found in {cfg.reversed_dir}", json_mode=json_output)
    ordered_paths, _excluded = order_sources(files)
    by_key = {_abs_key(cfg.root, str(p)): _rel(cfg.root, p) for p in ordered_paths}
    computed = [_rel(cfg.root, p) for p in ordered_paths]

    cmake = cfg.root / _CMAKE_LISTS
    if not cmake.is_file():
        error_exit(f"{_CMAKE_LISTS} not found: {cmake}", json_mode=json_output)
    text = cmake.read_text(encoding="utf-8")
    block = find_sources_block(text, {ext.lower() for ext in source_exts(cfg)})
    if block is None:
        error_exit(
            f"no set(SOURCES ...) or add_library/add_executable source list in {cmake}",
            json_mode=json_output,
        )
    current = normalize_listed(cfg.root, block.managed, by_key)
    in_sync = current == computed
    dropped = [tok for tok in block.managed if tok not in computed]
    diff = "" if in_sync else _drift_diff(current, computed)

    if check:
        if json_output:
            json_print(_payload(cmake, computed, current, in_sync, False, dropped, diff))
        elif not in_sync:
            print(diff)
        else:
            console.print(
                f"[green]{_CMAKE_LISTS} SOURCES match VA order ({len(computed)} files)[/green]"
            )
        if not in_sync:
            raise typer.Exit(code=EXIT_MISMATCH)
        return

    if apply and not dry_run:
        if in_sync:
            console.print(f"[green]{_CMAKE_LISTS} SOURCES already in VA order[/green]")
        else:
            atomic_write_text(cmake, render_block(text, block, computed))
            console.print(
                f"[green]rewrote {block.label} in {cmake.name}: "
                f"{len(computed)} sources in VA order[/green]"
            )
            if dropped:
                names = ", ".join(dropped)
                console.print(
                    f"[yellow]dropped {len(dropped)} listed file(s) "
                    f"not in reversed_dir: {names}[/yellow]"
                )
        if json_output:
            json_print(_payload(cmake, computed, current, in_sync, True, dropped, diff))
        return

    for entry in computed:
        print(entry)
    if dry_run and diff:
        print(diff)
    if not in_sync:
        console.print(
            f"[yellow]{_CMAKE_LISTS} SOURCES differ from VA order "
            "— re-run with --apply to enforce[/yellow]"
        )
    if json_output:
        json_print(_payload(cmake, computed, current, in_sync, False, dropped, diff))


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
