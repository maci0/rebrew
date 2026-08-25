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
- **define** (``--define``) — for the remaining asm-referenced tokens, turn
  the file's ``extern char s_x[];`` into a real definition
  ``char s_x[N] = "<bytes>";`` so the string gets content AND lands in the
  owning TU's .data slot.  Tokens referenced from several files get exactly
  one owner definition (file with the most uses); the rest keep extern.

Usage:
    rebrew inline-strings                    # inline + define
    rebrew inline-strings --inline-only      # only the use-site rewrite
    rebrew inline-strings --files a.c b.c
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import TargetOption, json_print, require_config
from rebrew.data_layout import data_raw_from_binary, layout_geometry

console = Console(stderr=True)

app = typer.Typer(
    help="Inline string-literal globals (s_<hint>_<ADDR>) from the reference binary.",
    rich_markup_mode="rich",
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
        line = text[ls : text.index("\n", ls) if "\n" in text[ls:] else n]
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
    text = path.read_text(encoding="utf-8", errors="replace")
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
            path.write_text("".join(out), encoding="utf-8")
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
    texts = {f: f.read_text(encoding="utf-8", errors="replace") for f in files}

    def real_uses(text: str) -> set[str]:
        uses: set[str] = set()
        for ln in text.splitlines():
            s = ln.strip()
            if (
                s.startswith("//")
                or s.startswith("*")
                or s.startswith("/*")
                or s.startswith("extern")
            ):
                continue
            uses.update(m.group(0) for m in token_re.finditer(ln))
        return uses

    owner: dict[str, Path] = {}
    for tok in sorted({t for text in texts.values() for t in real_uses(text)}):
        tok_re = re.compile(r"\b" + re.escape(tok) + r"\b")
        counts: dict[Path, int] = defaultdict(int)
        for other, text in texts.items():
            counts[other] += len(tok_re.findall(text))
        owner[tok] = max(counts, key=counts.__getitem__)

    extern_re = re.compile(r"^(\s*)extern\s+(?:char|unsigned char)\s+")
    done = 0
    for f, text in texts.items():
        lines = text.splitlines()
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
            f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return done


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
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Inline string-literal globals from the reference binary into the sources."""
    cfg = require_config(target=target, json_mode=json_output)

    src_dir = source_dir if source_dir is not None else cfg.reversed_dir
    bin_path = binary if binary is not None else cfg.target_binary
    if not bin_path.exists():
        from rebrew.cli import error_exit

        error_exit(f"reference binary not found: {bin_path}", json_mode=json_output)

    data_base, _raw_end, _section_end = layout_geometry(cfg.root / "rebrew-project.toml")
    orig = data_raw_from_binary(bin_path)
    token_re = re.compile(rf"\b{re.escape(token_prefix)}[A-Za-z0-9_]+_([0-9a-fA-F]{{6,8}})\b")

    scan_files = sorted(src_dir.rglob("*.c"))
    if files:
        scan_files = [f for f in scan_files if f.name in {p.name for p in files}]
    if not scan_files:
        from rebrew.cli import error_exit

        error_exit(f"no .c sources found under {src_dir}", json_mode=json_output)

    cache: dict[int, bytes | None] = {}
    total = 0
    for f in scan_files:
        total += inline_string_uses(f, orig, data_base, token_re, cache, dry_run)

    defined = 0
    if not inline_only:
        defined = define_remaining_strings(scan_files, orig, data_base, token_re, dry_run)

    if json_output:
        json_print({"inlined": total, "defined": defined, "files": len(scan_files)})
    else:
        console.print(
            f"[green]inline-strings:[/green] {total} use-site(s) inlined, "
            f"{defined} string(s) defined{' (dry run)' if dry_run else ''}"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
