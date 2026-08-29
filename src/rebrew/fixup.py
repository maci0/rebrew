"""fixup.py — compilability fixup for raw decompiler output (DecBench-style).

Decompiler pseudo-C (Ghidra, r2ghidra, r2dec, Kuna, angr) rarely compiles
as-is: pseudo-types (``undefined4``), illegal tokens (``GLIBC_2.2.5::stderr``),
missing prototypes and undeclared type names.  Naive recompilation would
score almost everything 0, so this module applies the DecBench fairness
principle to rebrew's byte-match loop:

1. **Token sanitization** — deterministic rewrites of decompiler idioms to
   plain C (pseudo-type → int/char/short/..., qualified symbol names
   stripped, placeholder casts normalized).
2. **Diagnostic-driven injection** — a bounded self-repair loop over the
   compiler error output that injects ONLY what the compiler reports
   missing (typedefs for undeclared type names, prototypes for
   implicitly-declared functions) and **never redefines what the source
   already declared**.

The result is a C file that compiles under rebrew's toolchain, so raw
decompiler output can be byte-matched (or used as a GA seed) instead of only
hand-written C.

Usage::

    rebrew fix src/ghidra_out.c            # sanitize + report what changed
    rebrew fix src/ghidra_out.c --json     # machine-readable change list
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import EXIT_ERROR, TargetOption, error_exit, json_print, require_config

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Token sanitization
# ---------------------------------------------------------------------------

#: Decompiler pseudo-types → C89 types.  Order matters (longest first).
_PSEUDO_TYPE_RE = re.compile(
    r"\b(undefined8|undefined4|undefined2|undefined1|undefined|"
    r"ulonglong|longlong|ulong|uint|ushort|uchar|ushort|"
    r"qword|dword|word|byte)\b"
)
_PSEUDO_TYPE_MAP: dict[str, str] = {
    "undefined8": "long long",
    "undefined4": "int",
    "undefined2": "short",
    "undefined1": "char",
    "undefined": "int",
    "ulonglong": "unsigned long long",
    "longlong": "long long",
    "ulong": "unsigned long",
    "uint": "unsigned int",
    "ushort": "unsigned short",
    "uchar": "unsigned char",
    "qword": "unsigned long long",
    "dword": "unsigned int",
    "word": "unsigned short",
    "byte": "unsigned char",
}

#: ``*(undefined4 *)ptr`` → ``*(int *)ptr`` — the map above handles the inner
#: token; the asterisk forms like ``(undefined4)`` are handled by the same
#: word-boundary replacement (parens are not word chars).

#: Qualified symbol names ``GLIBC_2.2.5::stderr`` / ``std::X::Y`` → last
#: component (the compiler cannot see library internals from decompiler
#: symbol tables).
_QUALIFIED_NAME_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_.]*::[A-Za-z_][A-Za-z0-9_]*")

#: MSVC decoration artifacts ``__cdecl``/``__fastcall`` are fine; strip the
#: Borland/Ghidra ``__based`` and ``_near``/``_far``-adjacent oddities that
#: block C89 parsing.
_JUNK_SPECIFIER_RE = re.compile(r"\b(?:__based|__unaligned|__ptr32|__ptr64|__restrict)\b")

#: Leading ``*``/``&`` on function-returning decls that break declarations
#: (``* FUN_00401000(...)`` at statement level is a Ghidra cast idiom).
_LEADING_STAR_RE = re.compile(r"^(\s*)\*(?=\s*[A-Za-z_])", re.MULTILINE)


def sanitize_tokens(source: str) -> tuple[str, list[str]]:
    """Apply the deterministic token-sanitization pass.

    Returns ``(fixed_source, changes)`` where *changes* is a list of
    ``"pseudo-type 'undefined4' -> 'int'"`` style descriptions (empty when
    the source needed no repairs).  Never raises; degenerate input is
    returned unchanged.
    """
    changes: list[str] = []

    def _sub_pseudo(m: re.Match[str]) -> str:
        rep = _PSEUDO_TYPE_MAP.get(m.group(1), "int")
        changes.append(f"pseudo-type '{m.group(1)}' -> '{rep}'")
        return rep

    out = _PSEUDO_TYPE_RE.sub(_sub_pseudo, source)

    def _sub_qualified(m: re.Match[str]) -> str:
        name = m.group(0).rsplit("::", 1)[1]
        changes.append(f"qualified name '{m.group(0)}' -> '{name}'")
        return name

    out = _QUALIFIED_NAME_RE.sub(_sub_qualified, out)

    def _sub_junk(m: re.Match[str]) -> str:
        changes.append(f"removed specifier '{m.group(0)}'")
        return ""

    out = _JUNK_SPECIFIER_RE.sub(_sub_junk, out)

    def _sub_star(m: re.Match[str]) -> str:
        changes.append("normalized leading '* cast")
        return f"{m.group(1)}"

    out = _LEADING_STAR_RE.sub(_sub_star, out)
    return out, changes


# ---------------------------------------------------------------------------
# Diagnostic-driven injection
# ---------------------------------------------------------------------------

#: Compiler diagnostics we can act on: ``'X' undeclared`` → typedef X;
#: ``implicit declaration of function 'f'`` → prototype f();
#: ``'f' undeclared`` where a call is implied → prototype.
_UNDECLARED_TYPE_RE = re.compile(
    r"'(?P<name>[A-Za-z_]\w*)' undeclared|unknown type name '(?P<name2>[A-Za-z_]\w*)'"
)
_IMPLICIT_FN_RE = re.compile(r"implicit declaration of function '(?P<name>[A-Za-z_]\w*)'")


@dataclass
class FixupResult:
    """Outcome of a fixup pass (sanitize + optional injection)."""

    source: str
    changes: list[str] = field(default_factory=list)
    injected: list[str] = field(default_factory=list)
    iterations: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "changed": bool(self.changes or self.injected),
            "changes": self.changes,
            "injected": self.injected,
            "iterations": self.iterations,
            "error": self.error,
        }


def _existing_identifiers(source: str) -> set[str]:
    """Type/function names already declared in *source* (never re-define)."""
    return (
        set(re.findall(r"\b(?:typedef|struct|union|enum)\s+([A-Za-z_]\w*)", source))
        | set(re.findall(r"\b[A-Za-z_]\w*\s*\([^;]*\)\s*;", source))
        | set(
            re.findall(r"\b(?:int|char|short|long|float|double|void)\s+([A-Za-z_]\w*)\s*\(", source)
        )
    )


def _inject_from_errors(source: str, errors: str) -> tuple[str, list[str]]:
    """Inject typedefs/prototypes for the names the compiler reported missing.

    Returns ``(fixed_source, injected_descriptions)``.  Injects only names
    NOT already declared in the source (the DecBench no-redefine rule).
    """
    existing = _existing_identifiers(source)
    injections: list[str] = []
    pending: list[tuple[str, str]] = []

    for m in _UNDECLARED_TYPE_RE.finditer(errors):
        name = m.group("name") or m.group("name2")
        if name and name not in existing:
            pending.append((name, f"typedef int {name};"))

    for m in _IMPLICIT_FN_RE.finditer(errors):
        name = m.group("name")
        if name and name not in existing and not any(n == name for n, _ in pending):
            pending.append((name, f"int {name}();"))

    for name, decl in pending:
        if name in existing:
            continue
        injections.append(decl)
        existing.add(name)

    if not injections:
        return source, []
    # Prepend the injections after the header comments (keeps the file
    # readable); a simple prepend at the top is safe for C89.  All pending
    # injections are emitted — the old code only prepended the first two and
    # silently dropped the rest (sync-review F4).
    return "\n".join(injections) + "\n\n" + source, injections


def fixup_source(source: str, compile_errors: str | None = None) -> FixupResult:
    """Run the full fixup: sanitize, then inject from *compile_errors*.

    The injection step is applied once (bounded — the sanitize pass already
    resolves most blockers; a second compile loop is the caller's choice via
    :func:`compile_and_fixup`).
    """
    fixed, changes = sanitize_tokens(source)
    result = FixupResult(source=fixed, changes=changes, iterations=1)
    if compile_errors:
        fixed, injected = _inject_from_errors(fixed, compile_errors)
        result.source = fixed
        result.injected = injected
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Make raw decompiler output compilable (DecBench-style fixup).",
    rich_markup_mode="rich",
)


def _compile_check(cfg: Any, source_text: str, src_hint: Path) -> str | None:
    """Compile *source_text* with the project's default flags.

    Returns the first compile error (or a generic failure message) when the
    source does not compile, None on success.  This is the honest-fallback
    gate for :func:`fixup_source`: fixup can leave a file uncompilable and
    the old CLI silently shipped it (m2c's ``--valid-syntax`` goal is
    compilable output; the equivalent for rebrew is *proving* the fixed
    source compiles before writing it).
    """
    import shutil

    from rebrew.cli import resolve_cflags
    from rebrew.compile import compile_to_obj
    from rebrew.utils import writable_temp_dir

    workdir = writable_temp_dir("rebrew_fixup_")
    try:
        tmp_src = workdir / src_hint.name
        tmp_src.write_text(source_text, encoding="utf-8")
        obj_path, err = compile_to_obj(
            cfg,
            tmp_src,
            resolve_cflags(cfg, "", "").split(),
            workdir,
            use_cache=False,
        )
        if obj_path is None:
            return (err or "compile failed").strip()
        return None
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@app.callback(invoke_without_command=True)
def main(
    source_file: Path = typer.Argument(..., help="Path to the pseudo-C file to fix"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print the fixed source to stdout instead of writing"
    ),
    out: Path | None = typer.Option(
        None, "--out", help="Write the fixed source to this path (default: <file>.fixed.c)"
    ),
    compile_check: bool = typer.Option(
        False,
        "--compile-check",
        help="Compile the fixed source before writing; refuse to ship uncompilable output.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Sanitize SOURCE_FILE (and inject missing decls) so it compiles."""
    if not source_file.exists():
        error_exit(f"source file not found: {source_file}", json_mode=json_output)
    text = source_file.read_text(encoding="utf-8", errors="replace")
    result = fixup_source(text)

    cfg: Any = None
    compile_error: str | None = None
    if compile_check:
        cfg = require_config(target=target, json_mode=json_output)
        compile_error = _compile_check(cfg, result.source, source_file)
        if compile_error:
            first_line = compile_error.splitlines()[0] if compile_error else "compile failed"
            # Never silently ship a fix that does not compile: banner the
            # decisive error into the output and exit nonzero.
            result.source = (
                "// fixup: --compile-check failed — the fixed source still does not compile.\n"
                f"// first error: {first_line}\n"
            ) + result.source

    if json_output:
        payload = result.to_dict()
        payload["file"] = str(source_file)
        payload["compile_check"] = bool(compile_check)
        if compile_error:
            payload["compile_error"] = compile_error.splitlines()[0]
        if not dry_run and not result.error:
            dest = out or source_file.with_suffix(source_file.suffix + ".fixed.c")
            dest.write_text(result.source, encoding="utf-8")
            payload["wrote"] = str(dest)
        json_print(payload)
        if compile_error:
            raise typer.Exit(code=EXIT_ERROR)
        return

    if result.error:
        console.print(f"[red]error:[/red] {result.error}")
        raise typer.Exit(code=EXIT_ERROR)

    console.print(f"[bold]{source_file.name}[/bold]:")
    for c in result.changes:
        console.print(f"  [dim]fix:[/dim] {c}")
    for i in result.injected:
        console.print(f"  [green]inject:[/green] {i}")
    if not result.changes and not result.injected:
        console.print("  [dim]already compilable — no fixes applied[/dim]")

    if compile_check:
        if compile_error:
            console.print(f"[red]error:[/red] fixed source still does not compile: {compile_error}")
        else:
            console.print("  [green]compile check passed[/green]")

    if dry_run:
        console.print("\n[bold]Fixed source:[/bold]")
        print(result.source)
        if compile_error:
            raise typer.Exit(code=EXIT_ERROR)
        return
    dest = out or source_file.with_suffix(source_file.suffix + ".fixed.c")
    dest.write_text(result.source, encoding="utf-8")
    console.print(
        f"\n[green]Wrote {dest}[/green] ({len(result.changes)} fix(es), "
        f"{len(result.injected)} injection(s))"
    )
    if compile_error:
        raise typer.Exit(code=EXIT_ERROR)


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
