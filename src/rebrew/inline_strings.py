"""inline-strings — materialize string-literal globals from the original binary.

Decompiled call sites often reference 1-byte placeholder globals
(``s_<hint>_<ADDR>``, defined in a link-stubs TU) instead of the actual
string.  Each placeholder name encodes the string's original .data address;
this command reads the string bytes from the reference binary at that address
and rewrites the use-site to an inline C literal, so the compiler emits the
real string into .data at the owning translation unit's link position
(placement fix).

Two modes (both default on):

- **inline** — replace token uses outside comments/``__asm`` blocks with
  inline literals (``push offset s_x`` inside naked asm must keep the symbol).
- **define** (skipped by ``--inline-only``) — for the remaining asm-referenced
  tokens, turn the file's ``extern char s_x[];`` into a real definition
  ``char s_x[N] = "<bytes>";`` so the string gets content AND lands in the
  owning TU's .data slot.  Tokens referenced from several files get exactly
  one owner definition (file with the most uses); the rest keep extern.

``--named`` is a separate mode that needs no binary: a file-scope
``char s_name[] = "text";`` whose every use is in its own file is replaced by
its literal at each use, and the definition and every ``extern char s_name[];``
in that file are removed.  MSVC6 emits a TU's string literals as ``??_C@``
COMDATs after the TU's plain ``.data``, so a literal pool that was spelled as
named arrays regains its original placement once inlined.

Usage:
    rebrew source inline-strings                    # inline + define
    rebrew source inline-strings --inline-only      # only the use-site rewrite
    rebrew source inline-strings --named            # same-file named arrays
    rebrew source inline-strings --files a.c b.c
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer

from rebrew.c_parser import parse_c_source
from rebrew.cli import TargetOption, console, json_print, require_config
from rebrew.data_layout import data_raw_from_binary, layout_geometry
from rebrew.metadata.data import data_rows_for_path, set_data_fields_batch
from rebrew.sources import files_with_ext
from rebrew.utils import (
    atomic_write_text,
    join_source_lines,
    read_source_text,
    split_source_lines,
)

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew source inline-strings --dry-run · · · · · Preview the globals, write nothing\n\n"
    "  rebrew source inline-strings --files src/a.c src/b.c · · Only these source files\n\n"
    "  rebrew source inline-strings --inline-only · · · · · Replace uses, add no new globals\n\n"
    "  rebrew source inline-strings --named --files src/a.c · Inline a.c's own char s_x[] pool\n"
)


app = typer.Typer(
    help="Inline string-literal globals (s_<hint>_<ADDR>) from the reference binary.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


def c_literal(data: bytes) -> str:
    """A C string literal for *data* (fixed-width octal escapes, no hex-merge risk)."""
    out = ['"']
    for b in data:
        if b == 0x5C:
            out.append("\\\\")
        elif b == 0x22:
            out.append('\\"')
        elif b == 0x0A:
            out.append("\\n")
        elif b == 0x0D:
            out.append("\\r")
        elif b == 0x09:
            out.append("\\t")
        elif b < 0x20 or b >= 0x7F:
            out.append(f"\\{b:03o}")
        else:
            out.append(chr(b))
    out.append('"')
    return "".join(out)


def _mask_keep_regions(text: str) -> bytearray:
    """Bytearray mask: b'1' = replaceable, b'0' = keep.

    Masks ``/* */`` and ``//`` comments, extern declaration lines, and
    ``__asm { }`` blocks (asm needs the symbol, not the literal).
    """
    n = len(text)
    mask = bytearray(b"1" * n)
    line_start = [0]
    for idx, ch in enumerate(text):
        if ch == "\n" and idx + 1 < n:
            line_start.append(idx + 1)
    i = 0
    in_asm = 0
    while i < n:
        if in_asm:
            if text[i] == "{":
                in_asm += 1
            elif text[i] == "}":
                in_asm -= 1
            mask[i] = 48
            i += 1
            continue
        if text.startswith("__asm", i) and (
            i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")
        ):
            while i < n and text[i] != "{":
                mask[i] = 48
                i += 1
            if i < n:
                mask[i] = 48
                in_asm = 1
                i += 1
            continue
        if text[i] in ('"', "'"):
            # A C string/char literal is not a replaceable token use: rewriting
            # a token inside it nests quotes and yields invalid C.  Masking the
            # span also stops a `//` inside a literal from starting a comment
            # (which silently protected the rest of the line).
            quote = text[i]
            mask[i] = 48
            i += 1
            while i < n:
                if text[i] == "\\":
                    mask[i] = 48
                    i += 1
                    if i < n:
                        mask[i] = 48
                        i += 1
                    continue
                if text[i] == "\n":  # unterminated literal: stop at end of line
                    break
                mask[i] = 48
                i += 1
                if text[i - 1] == quote:
                    break
            continue
        if text[i] == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                mask[i] = 48
                i += 1
            continue
        if text[i] == "/" and i + 1 < n and text[i + 1] == "*":
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                mask[i] = 48
                i += 1
            if i + 1 < n:
                mask[i] = mask[i + 1] = 48
                i += 2
            continue
        i += 1
    for ls in line_start:
        # ``find`` from *ls* is O(line); ``"\\n" in text[ls:]`` copied the
        # suffix then rescanned it — quadratic on multi-thousand-line TUs.
        nl = text.find("\n", ls)
        line = text[ls:nl] if nl >= 0 else text[ls:n]
        if line.lstrip().startswith("extern"):
            mask[ls : ls + len(line)] = b"0" * len(line)
    return mask


def _string_at(orig: bytes, va: int, data_base: int) -> bytes | None:
    """The NUL-terminated string at *va* in the reference's .data raw, or None."""
    off = va - data_base
    if off < 0 or off >= len(orig):
        return None
    end = orig.find(b"\x00", off)
    if end < 0:
        return None
    return orig[off:end]


def inline_string_uses(
    path: Path,
    orig: bytes,
    data_base: int,
    token_re: re.Pattern[str],
    cache: dict[int, bytes | None],
    dry_run: bool,
) -> int:
    """Rewrite *path*'s token uses to inline literals; returns the count."""
    text, encoding = read_source_text(path)
    mask = _mask_keep_regions(text)
    out: list[str] = []
    last = 0
    n_changed = 0
    for m in token_re.finditer(text):
        s, e = m.span()
        if b"0" in mask[s:e]:
            continue  # comment or asm
        va = int(m.group(1), 16)
        if va not in cache:
            cache[va] = _string_at(orig, va, data_base)
        data = cache[va]
        if data is None:
            continue
        out.append(text[last:s])
        out.append(c_literal(data))
        last = e
        n_changed += 1
    if n_changed:
        out.append(text[last:])
        if not dry_run:
            atomic_write_text(path, "".join(out), encoding=encoding)
        console.print(f"  {path}: {n_changed} string(s) inlined")
    return n_changed


def define_remaining_strings(
    files: list[Path],
    orig: bytes,
    data_base: int,
    token_re: re.Pattern[str],
    dry_run: bool,
) -> int:
    """Turn asm-referenced ``extern char s_x[];`` into definitions with content.

    Owner = the file with the most non-extern uses of the token (asm-referenced
    tokens have no inlinable uses left).  Returns the number of definitions.
    """
    pairs = {f: read_source_text(f) for f in files}
    texts = {f: text for f, (text, _enc) in pairs.items()}
    encodings = {f: enc for f, (_text, enc) in pairs.items()}

    def real_use_lines(text: str) -> list[str]:
        """Lines that count as token uses (no comments, no extern declarations)."""
        return [
            ln
            for ln in split_source_lines(text)
            if not ln.strip().startswith(("//", "*", "/*", "extern"))
        ]

    owner: dict[str, Path] = {}
    use_lines = {f: real_use_lines(text) for f, text in texts.items()}
    # One pass over every file's real-use lines: count token hits per file.
    # The previous loop compiled a fresh ``\\b{tok}\\b`` regex per token and
    # rescanned every file (O(tokens × files × lines)); projects with hundreds
    # of string placeholders paid that on every ``rebrew source inline-strings`` run.
    tok_counts: dict[str, dict[Path, int]] = defaultdict(lambda: defaultdict(int))
    for f, lines in use_lines.items():
        for ln in lines:
            for tok_m in token_re.finditer(ln):
                tok_counts[tok_m.group(0)][f] += 1
    for tok in sorted(tok_counts):
        counts = tok_counts[tok]
        # Zero-fill so tie-breaks follow use_lines insertion order.
        for f in use_lines:
            counts.setdefault(f, 0)
        owner[tok] = max(counts, key=counts.__getitem__)

    extern_re = re.compile(r"^(\s*)extern\s+(?:char|unsigned char)\s+")
    done = 0
    for f, text in texts.items():
        lines = split_source_lines(text)
        changed = False
        for i, ln in enumerate(lines):
            m = extern_re.match(ln)
            tm = token_re.search(ln) if m else None
            if not m or not tm:
                continue
            tok = tm.group(0)
            if tok not in owner or owner[tok] != f:
                continue
            va = int(tm.group(1), 16)
            data = _string_at(orig, va, data_base)
            if data is None:
                continue
            lines[i] = f"{m.group(1)}char {tok}[{len(data) + 1}] = {c_literal(data)};"
            changed = True
            done += 1
        if changed and not dry_run:
            atomic_write_text(f, join_source_lines(text, lines), encoding=encodings[f])
    return done


# ---------------------------------------------------------------------------
# --named: same-file char s_x[] = "..." definitions
# ---------------------------------------------------------------------------

#: Tree-sitter nodes whose text is never a token use.
_NON_CODE_NODES = frozenset({"comment", "string_literal", "char_literal", "system_lib_string"})
#: Parents that make an identifier a declared name rather than a use.
_DECLARING_PARENTS = frozenset(
    {
        "declaration",
        "init_declarator",
        "parameter_declaration",
        "preproc_def",
        "preproc_function_def",
    }
)


@dataclass
class _ParsedSource:
    """One source's UTF-8 bytes, non-code spans, and identifier nodes by name."""

    data: bytes
    non_code: list[tuple[int, int]] = field(default_factory=list)
    identifiers: dict[str, list[Any]] = field(default_factory=dict)


@dataclass
class NamedInline:
    """The outcome of :func:`inline_named_strings` for one file."""

    inlined: dict[str, int] = field(default_factory=dict)  # name -> use sites rewritten
    skipped: dict[str, str] = field(default_factory=dict)  # name -> reason


def _parse_source(text: str, prefix: str) -> tuple[Any, _ParsedSource]:
    """Parse *text*; collect non-code spans and identifiers starting with *prefix*."""
    tree, data = parse_c_source(text)
    parsed = _ParsedSource(data)
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in _NON_CODE_NODES:
            parsed.non_code.append((int(node.start_byte), int(node.end_byte)))
            continue
        if node.type == "identifier":
            name = data[node.start_byte : node.end_byte].decode("utf-8", "surrogateescape")
            if name.startswith(prefix):
                parsed.identifiers.setdefault(name, []).append(node)
        stack.extend(node.children)
    parsed.non_code.sort()
    return tree, parsed


def _code_occurrences(parsed: _ParsedSource, name: str) -> int:
    """Whole-word occurrences of *name* outside comments and literals."""
    count = 0
    word = re.compile(rb"\b" + re.escape(name.encode("utf-8")) + rb"\b")
    for m in word.finditer(parsed.data):
        if not any(s <= m.start() < e for s, e in parsed.non_code):
            count += 1
    return count


def _in_error(node: Any) -> bool:
    """True when *node* sits under a parse error (``__asm`` blocks parse as ERROR)."""
    parent = node.parent
    while parent is not None:
        if parent.type == "ERROR":
            return True
        parent = parent.parent
    return False


def _storage_classes(decl: Any, data: bytes) -> set[str]:
    return {
        data[c.start_byte : c.end_byte].decode()
        for c in decl.children
        if c.type == "storage_class_specifier"
    }


def _is_plain_char(decl: Any) -> bool:
    """The declaration's type is ``char`` (``const`` allowed; not ``unsigned char``)."""
    type_node = decl.child_by_field_name("type")
    return (
        type_node is not None and type_node.type == "primitive_type" and type_node.text == b"char"
    )


def _array_name(declarator: Any, data: bytes) -> str | None:
    """``name`` for an unsized ``name[]`` declarator, else None."""
    if declarator is None or declarator.type != "array_declarator":
        return None
    if declarator.child_by_field_name("size") is not None:
        return None
    inner = declarator.child_by_field_name("declarator")
    if inner is None or inner.type != "identifier":
        return None
    return data[inner.start_byte : inner.end_byte].decode("utf-8", "surrogateescape")


def _named_definitions(root: Any, data: bytes, prefix: str) -> dict[str, list[tuple[Any, bytes]]]:
    """File-scope ``[static] [const] char <prefix>x[] = "...";`` definitions by name."""
    found: dict[str, list[tuple[Any, bytes]]] = {}
    for decl in root.children:
        if decl.type != "declaration" or not _is_plain_char(decl):
            continue
        if _storage_classes(decl, data) - {"static"}:
            continue
        inits = decl.children_by_field_name("declarator")
        if len(inits) != 1 or inits[0].type != "init_declarator":
            continue
        value = inits[0].child_by_field_name("value")
        name = _array_name(inits[0].child_by_field_name("declarator"), data)
        if value is None or value.type not in ("string_literal", "concatenated_string"):
            continue
        if name is None or not name.startswith(prefix):
            continue
        found.setdefault(name, []).append((decl, data[value.start_byte : value.end_byte]))
    return found


def _extern_declarations(root: Any, data: bytes, names: set[str]) -> dict[str, list[Any]]:
    """Every ``extern`` declaration (any scope) that declares one of *names*."""
    found: dict[str, list[Any]] = {}
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "declaration" and "extern" in _storage_classes(node, data):
            for declarator in node.children_by_field_name("declarator"):
                inner = declarator
                while inner is not None and inner.type != "identifier":
                    inner = inner.child_by_field_name("declarator")
                if inner is not None:
                    name = data[inner.start_byte : inner.end_byte].decode(
                        "utf-8", "surrogateescape"
                    )
                    if name in names:
                        found.setdefault(name, []).append(node)
            continue
        stack.extend(node.children)
    return found


def _removal_span(data: bytes, start: int, end: int) -> tuple[int, int]:
    """The bytes to delete for a declaration at ``[start, end)``.

    A declaration alone on its line takes the whole line.  When the line
    before it is blank too (or it starts the file), one following blank line
    goes with it, so removing a blank-separated pool leaves one separator.
    """
    line_start = data.rfind(b"\n", 0, start) + 1
    line_end = data.find(b"\n", end)
    line_end = len(data) if line_end < 0 else line_end + 1
    if data[line_start:start].strip() or data[end:line_end].strip():
        return start, end
    prev_start = data.rfind(b"\n", 0, max(line_start - 1, 0)) + 1
    prev_blank = line_start == 0 or not data[prev_start:line_start].strip()
    next_end = data.find(b"\n", line_end)
    next_end = len(data) if next_end < 0 else next_end + 1
    if prev_blank and line_end < len(data) and not data[line_end:next_end].strip():
        line_end = next_end
    return line_start, line_end


def inline_named_strings(
    path: Path,
    prefix: str,
    others: list[Path],
    dry_run: bool,
) -> NamedInline:
    """Inline *path*'s own ``char <prefix>x[] = "...";`` definitions at their uses.

    A name is skipped, with the reason recorded, when any file in *others*
    mentions it outside comments and literals, when it has no use, when a use
    sits in ``__asm`` or other code the parser cannot read, or when the file
    redeclares it other than as ``extern char name[];``.  The initializer is
    copied byte-for-byte, so its escapes reach every use unchanged.
    """
    text, encoding = read_source_text(path)
    result = NamedInline()
    tree, parsed = _parse_source(text, prefix)
    data = parsed.data
    definitions = _named_definitions(tree.root_node, data, prefix)
    externs = _extern_declarations(tree.root_node, data, set(definitions))
    edits: list[tuple[int, int, bytes]] = []

    for name in sorted(definitions):
        if len(definitions[name]) > 1:
            result.skipped[name] = "defined more than once"
            continue
        decl, literal = definitions[name][0]
        removals = [decl, *externs.get(name, [])]
        bad_extern = next(
            (
                e
                for e in externs.get(name, [])
                if not _is_plain_char(e)
                or len(e.children_by_field_name("declarator")) != 1
                or _array_name(e.child_by_field_name("declarator"), data) != name
            ),
            None,
        )
        if bad_extern is not None:
            result.skipped[name] = f"line {bad_extern.start_point[0] + 1}: not extern char {name}[]"
            continue
        uses: list[Any] = []
        reason = ""
        for ident in parsed.identifiers.get(name, []):
            if any(r.start_byte <= ident.start_byte < r.end_byte for r in removals):
                continue
            line = ident.start_point[0] + 1
            if _in_error(ident):
                reason = f"line {line}: used in __asm or unparsed code"
                break
            if ident.parent is not None and (
                ident.parent.type.endswith("declarator") or ident.parent.type in _DECLARING_PARENTS
            ):
                reason = f"line {line}: redeclared"
                break
            uses.append(ident)
        if not reason and _code_occurrences(parsed, name) != len(parsed.identifiers.get(name, [])):
            reason = "used where the parser sees no identifier (macro body?)"
        if not reason:
            for other in others:
                other_text, _enc = read_source_text(other)
                if name in other_text and _code_occurrences(
                    _parse_source(other_text, prefix)[1], name
                ):
                    reason = f"used from {other}"
                    break
        if not reason and not uses:
            reason = "no uses"
        if reason:
            result.skipped[name] = reason
            continue
        for node in removals:
            start, end = _removal_span(data, int(node.start_byte), int(node.end_byte))
            edits.append((start, end, b""))
        edits.extend((int(u.start_byte), int(u.end_byte), literal) for u in uses)
        result.inlined[name] = len(uses)

    if edits and not dry_run:
        out = bytearray(data)
        for start, end, repl in sorted(edits, reverse=True):
            out[start:end] = repl
        new_text = bytes(out).decode("utf-8", "surrogateescape")
        atomic_write_text(path, new_text, encoding=encoding, errors="surrogateescape")
    for name, n in result.inlined.items():
        console.print(f"  {path}: {name} inlined at {n} use(s)")
    for name, why in result.skipped.items():
        console.print(f"  [yellow]{path}: {name} skipped: {why}[/yellow]")
    return result


def retype_data_rows(metadata_dir: Path, path: Path, names: set[str], dry_run: bool) -> list[str]:
    """Mark *path*'s data rows for *names* ``storage_kind = "literal"``.

    The inlined string is now a compiler literal, so the row keeps its VA and
    name but no longer describes a source definition.  Returns ``0xVA`` for
    each row changed (or that would change under *dry_run*).  A row's
    ``link_symbol`` and verdict are left alone: re-run ``rebrew verify --data``
    and record the literal's ``??_C@`` symbol with ``rebrew data set
    --link-symbol`` once the link map shows it.
    """
    updates = [
        {
            "module": module,
            "va": va,
            "fields": {"storage_kind": "literal"},
            "updated_by": "inline-strings",
        }
        for module, va, entry in data_rows_for_path(metadata_dir, path)
        if entry.get("name") in names and entry.get("storage_kind") != "literal"
    ]
    if updates and not dry_run:
        set_data_fields_batch(metadata_dir, updates)
    return [f"0x{u['va']:x}" for u in updates]


def _run_named(
    cfg: Any,
    targets: list[Path],
    others: list[Path],
    prefix: str,
    dry_run: bool,
    json_output: bool,
) -> None:
    """``--named`` driver: inline per file, retype data rows, report."""
    files: list[dict[str, Any]] = []
    for f in targets:
        res = inline_named_strings(f, prefix, [o for o in others if o != f], dry_run)
        rows = retype_data_rows(cfg.metadata_dir, f, set(res.inlined), dry_run)
        if res.inlined or res.skipped:
            files.append(
                {
                    "file": str(f),
                    "inlined": res.inlined,
                    "skipped": res.skipped,
                    "data_rows": rows,
                }
            )
    names = sum(len(r["inlined"]) for r in files)
    uses = sum(sum(r["inlined"].values()) for r in files)
    rows_total = sum(len(r["data_rows"]) for r in files)
    if json_output:
        json_print({"named": names, "inlined": uses, "data_rows": rows_total, "files": files})
    else:
        console.print(
            f"[green]inline-strings --named:[/green] {names} global(s) inlined at {uses} "
            f"use-site(s), {rows_total} data row(s) marked literal"
            f"{' (dry run)' if dry_run else ''}"
        )


@app.callback(invoke_without_command=True)
def main(
    files: list[Path] | None = typer.Option(None, "--files", help="Restrict to these files"),
    source_dir: Path | None = typer.Option(
        None, "--source-dir", help="Directory of reversed sources (default: config reversed_dir)"
    ),
    binary: Path | None = typer.Option(
        None, "--binary", help="Reference binary (default: config target_binary)"
    ),
    token_prefix: str = typer.Option(
        "s_", "--token-prefix", help="Placeholder token prefix (s_<hint>_<ADDR>)"
    ),
    inline_only: bool = typer.Option(False, "--inline-only", help="Skip --define materialization"),
    named: bool = typer.Option(
        False,
        "--named",
        help='Inline each file\'s own char <prefix>x[] = "..." definitions instead (no binary)',
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Inline string-literal globals from the reference binary into the sources."""
    from rebrew.cli import error_exit

    cfg = require_config(target=target, json_mode=json_output)
    if named and inline_only:
        error_exit("--named and --inline-only are separate modes", json_mode=json_output)

    src_dir = source_dir if source_dir is not None else cfg.reversed_dir
    # Shared sources carry string tokens too; an explicit --source-dir scans
    # only that directory.
    if source_dir is None:
        from rebrew.data_layout import scan_files

        shared_dir = getattr(cfg, "shared_dir", None)
        scanned = scan_files(src_dir, shared_dir)
    else:
        shared_dir = None
        scanned = sorted(src_dir.rglob("*.c"))
    targets = scanned
    if files:
        wanted = {p.name for p in files}
        targets = [f for f in targets if f.name in wanted]
    if not targets:
        error_exit(f"no .c sources found under {src_dir}", json_mode=json_output)

    if named:
        # Every source and header in the scanned trees can reference a name,
        # whatever --files selects for rewriting.
        others = list(scanned)
        for d in (src_dir, shared_dir):
            if d is not None and d.is_dir():
                others.extend(files_with_ext(d, {".h"}))
        _run_named(cfg, targets, others, token_prefix, dry_run, json_output)
        return

    bin_path = binary if binary is not None else cfg.target_binary
    if not bin_path.exists():
        error_exit(f"reference binary not found: {bin_path}", json_mode=json_output)

    try:
        data_base, _raw_end, _section_end = layout_geometry(cfg.root / "rebrew-project.toml")
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    orig = data_raw_from_binary(bin_path)
    token_re = re.compile(rf"\b{re.escape(token_prefix)}[A-Za-z0-9_]+_([0-9a-fA-F]{{6,8}})\b")

    cache: dict[int, bytes | None] = {}
    total = 0
    for f in targets:
        total += inline_string_uses(f, orig, data_base, token_re, cache, dry_run)

    defined = 0
    if not inline_only:
        defined = define_remaining_strings(targets, orig, data_base, token_re, dry_run)

    if json_output:
        json_print({"inlined": total, "defined": defined, "files": len(targets)})
    else:
        console.print(
            f"[green]inline-strings:[/green] {total} use-site(s) inlined, "
            f"{defined} string(s) defined{' (dry run)' if dry_run else ''}"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
