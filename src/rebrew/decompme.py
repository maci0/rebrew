"""decompme — upload rebrew functions to decomp.me as collaborative scratches.

decomp.me (https://decomp.me) is the decomp-scene collaboration platform: a
"scratch" holds a function's assembly/object, a C seed, a context file, and a
compiler+flags, compiled server-side and diffed against the original.  Anyone
with the claim URL can fork and improve the C — the rebrew equivalent of
sharing a function for a second pair of eyes or a cloud permuter run.

This command builds the scratch from rebrew's own data:

- ``target_obj`` — the target function's bytes synthesized into a COFF object
  (the same writer the objdiff bridge uses; decomp.me assembles objects
  directly, which is the objdiff-proven path);
- ``source_code`` — the function's C from the annotated source file;
- ``context`` — the universal context file (``rebrew context``) unless
  ``--context``/``--no-context`` says otherwise;
- ``compiler``/``platform``/``compiler_flags`` — mapped from the project's
  toolchain and flags (decomp.me ships MSVC 4–8 for ``win32``/``msdos`` —
  rebrew's exact compiler family; override with ``--compiler``/``--platform``
  for anything else, e.g. console targets).

Anonymous create (like objdiff's integration): the response carries a
``claim_token``; the printed URL claims the scratch.

Usage:
    rebrew decompme src/game/func.c                # upload the first function
    rebrew decompme src/game/func.c --va 0x401000 # upload a specific VA
    rebrew decompme src/game/func.c --dry-run     # preview the payload
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import typer
from rich.console import Console

from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    parse_va,
    require_config,
)

console = Console(stderr=True)

app = typer.Typer(
    help="Upload a function to decomp.me as a collaborative scratch.",
    rich_markup_mode="rich",
)

_DEFAULT_API = "https://decomp.me"

#: rebrew toolchain → decomp.me compiler id (closest match).  decomp.me's
#: registry mirrors the MSVC line; anything else (gcc-pe, console compilers)
#: must be passed explicitly with ``--compiler``.
_COMPILER_MAP: dict[str, str] = {
    "msvc4": "msvc4.0",
    "msvc4.1": "msvc4.1",
    "msvc4.2": "msvc4.2",
    "msvc5": "msvc5.0",
    "msvc6": "msvc6.0",
    "msvc600sp1": "msvc6.0",
    "msvc600sp2": "msvc6.0",
    "msvc600sp3": "msvc6.0",
    "msvc600sp4": "msvc6.0",
    "msvc600sp5": "msvc6.0",
    "msvc600sp6": "msvc6.0",
    "msvc6.3": "msvc6.3",
    "msvc6.6": "msvc6.6",
    "msvc7": "msvc7.0",
    "msvc7.1": "msvc7.1",
    "msvc8": "msvc8.0",
    "msvc10": "msvc9.0",
}

#: Binary format → decomp.me platform.  PE x86_32 → win32; DOS (MZ/NE 16-bit)
#: → msdos.  ELF targets have no x86 platform on decomp.me — require an
#: explicit ``--platform``.
_FORMAT_TO_PLATFORM: dict[str, str] = {
    "pe": "win32",
    "mz": "msdos",
    "ne": "msdos",
}


def map_compiler(toolchain: str | None) -> str | None:
    """Best decomp.me compiler id for a rebrew *toolchain*, or None."""
    if not toolchain:
        return None
    return _COMPILER_MAP.get(toolchain)


def map_platform(binary_format: str | None) -> str | None:
    """decomp.me platform for a rebrew binary *format*, or None."""
    return _FORMAT_TO_PLATFORM.get((binary_format or "").lower())


def build_scratch_payload(
    cfg: Any,
    source: Path,
    *,
    va: int,
    size: int,
    symbol: str,
    name: str,
    compiler: str,
    platform: str,
    compiler_flags: str,
    context: str,
) -> dict[str, Any]:
    """Build the decomp.me multipart scratch payload.

    Returns ``{"data": {...}, "files": {"target_obj": (filename, bytes, ctype)}}``
    ready for :func:`httpx.post`.  The target object is synthesized from the
    reference binary's function bytes via the objdiff COFF writer.
    """
    from rebrew.binary_loader import extract_raw_bytes
    from rebrew.objdiff_project import write_coff_object

    raw = extract_raw_bytes(cfg.target_binary, va, size)
    if not raw:
        raise ValueError(f"failed to extract target bytes at 0x{va:08x}")
    import tempfile

    with tempfile.TemporaryDirectory(prefix="rebrew_decompme_") as tmp:
        obj = Path(tmp) / f"{source.stem}.o"
        write_coff_object(obj, [(symbol or name or f"func_{va:08x}", 0, raw)])
        obj_bytes = obj.read_bytes()

    diff_label = symbol or name or f"func_{va:08x}"
    data = {
        "compiler": compiler,
        "platform": platform,
        "compiler_flags": compiler_flags,
        "diff_label": diff_label,
        "diff_flags": json.dumps([f"--disassemble={diff_label}"]),
        "context": context,
        "source_code": source.read_text(encoding="utf-8", errors="replace"),
        "name": name or diff_label,
    }
    files = {"target_obj": (f"{source.stem}.o", obj_bytes, "application/octet-stream")}
    return {"data": data, "files": files}


def upload_scratch(
    payload: dict[str, Any], api: str = _DEFAULT_API, timeout: float = 60.0
) -> dict[str, Any]:
    """POST the scratch to decomp.me; returns the response dict.

    Raises :class:`RuntimeError` on transport failure or a non-2xx response
    (the body is included — decomp.me validation errors explain the reason).
    """
    try:
        resp = httpx.post(
            f"{api}/api/scratch",
            data=payload["data"],
            files=payload["files"],
            timeout=timeout,
        )
    except httpx.HTTPError as exc:
        raise RuntimeError(f"decomp.me request failed: {exc}") from exc
    if resp.status_code >= 400:
        raise RuntimeError(
            f"decomp.me rejected the scratch (HTTP {resp.status_code}): {(resp.text or '')[:500]}"
        )
    try:
        data: dict[str, Any] = resp.json()
    except ValueError as exc:
        raise RuntimeError(
            f"decomp.me returned an unparseable response: {resp.text[:200]}"
        ) from exc
    return data


def scratch_url(slug: str, claim_token: str, api: str = _DEFAULT_API) -> str:
    """The claim URL for a freshly-created scratch."""
    return f"{api}/scratch/{slug}/claim?token={claim_token}"


def _resolve_annotation(cfg: Any, source: Path, va: int | None) -> tuple[Any, int, int, str]:
    """Pick the annotation for *source* (by *va* or the first FUNCTION entry)."""
    from rebrew.annotation import parse_c_file_multi
    from rebrew.sources import target_marker

    annos = parse_c_file_multi(
        source, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
    )
    funcs = [a for a in annos if a.marker_type not in ("GLOBAL", "DATA")]
    if not funcs:
        raise ValueError(f"no function annotations in {source}")
    ann = funcs[0]
    if va is not None:
        for a in funcs:
            if a.va == va:
                ann = a
                break
        else:
            raise ValueError(f"no annotation for VA 0x{va:08x} in {source.name}")
    size = int(ann.size or 0)
    if size <= 0:
        raise ValueError(
            f"function 0x{ann.va:08x} has no size — add a SIZE annotation or pass --size"
        )
    symbol = str(ann.symbol or ann.name or f"func_{ann.va:08x}")
    return ann, int(ann.va), size, symbol


def _build_context(cfg: Any, context_path: Path | None, no_context: bool) -> str:
    """The scratch context: the given file, or ``rebrew context`` output."""
    if no_context:
        return ""
    if context_path is not None:
        return context_path.read_text(encoding="utf-8", errors="replace")
    from rebrew.context import _collect_context

    blocks, _count = _collect_context(cfg)
    return (
        "/* ctx.c - AUTO-GENERATED by `rebrew decompme` (from `rebrew context`).\n"
        " * Regenerate with `rebrew context`; pass --context FILE to override.\n"
        " */\n" + "\n\n".join(blocks) + ("\n" if blocks else "")
    )


@app.callback(invoke_without_command=True)
def main(
    source: str = typer.Argument(..., help="C source file for the function to upload"),
    va: str | None = typer.Option(
        None, "--va", help="Target VA in hex (default: first FUNCTION annotation)"
    ),
    size: int | None = typer.Option(
        None, "--size", help="Target size in bytes (default: annotation SIZE)"
    ),
    compiler: str | None = typer.Option(
        None,
        "--compiler",
        help="decomp.me compiler id (default: mapped from the project toolchain)",
    ),
    platform: str | None = typer.Option(
        None,
        "--platform",
        help="decomp.me platform id (default: win32/msdos from the binary format)",
    ),
    flags: str | None = typer.Option(
        None, "--flags", help="Compiler flags (default: the function's resolved cflags)"
    ),
    context: Path | None = typer.Option(
        None, "--context", help="C context file (default: auto-generated via `rebrew context`)"
    ),
    no_context: bool = typer.Option(False, "--no-context", help="Send an empty context"),
    api: str = typer.Option(_DEFAULT_API, "--api", help="decomp.me API base URL"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Upload SOURCE's function to decomp.me as a collaborative scratch."""
    cfg = require_config(target=target, json_mode=json_output)
    source_path = Path(source).resolve()
    if not source_path.exists():
        error_exit(f"source file not found: {source}", json_mode=json_output)

    va_int = parse_va(va, json_mode=json_output) if va else None
    try:
        ann, ann_va, ann_size, symbol = _resolve_annotation(cfg, source_path, va_int)
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    size_val = size or ann_size

    if compiler is None:
        from rebrew.cli import resolve_compile_overrides

        toolchain, cflags = resolve_compile_overrides(
            cfg,
            source_path.parent,
            getattr(ann, "toolchain", ""),
            getattr(ann, "cflags", ""),
            getattr(ann, "module", ""),
        )
        compiler = map_compiler(toolchain)
        if compiler is None:
            error_exit(
                f"no decomp.me compiler mapped for toolchain {toolchain or cfg.compiler_profile!r} — "
                "pass --compiler (decomp.me ids include msvc4.0..msvc8.0; see decomp.me/api/compilers)",
                json_mode=json_output,
            )
        flags = flags if flags is not None else cflags
    if platform is None:
        platform = map_platform(getattr(cfg, "binary_format", None) or getattr(cfg, "format", ""))
        if platform is None:
            error_exit(
                "no decomp.me platform mapped for this binary — pass --platform "
                "(win32, msdos, n64, gc_wii, ...)",
                json_mode=json_output,
            )
    flags_str = flags or ""

    context_text = _build_context(cfg, context, no_context)
    try:
        payload = build_scratch_payload(
            cfg,
            source_path,
            va=ann_va,
            size=size_val,
            symbol=symbol,
            name=str(ann.name or ""),
            compiler=compiler,
            platform=platform,
            compiler_flags=flags_str,
            context=context_text,
        )
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)

    if dry_run:
        if json_output:
            json_print(
                {
                    "dry_run": True,
                    "compiler": compiler,
                    "platform": platform,
                    "flags": flags_str,
                    "context_bytes": len(context_text),
                    "source_file": str(source_path),
                    "va": f"0x{ann_va:08x}",
                    "target_obj_bytes": len(payload["files"]["target_obj"][1]),
                }
            )
            return
        console.print("[bold]decomp.me scratch (dry-run, no upload):[/bold]")
        console.print(f"  compiler:    {compiler}")
        console.print(f"  platform:    {platform}")
        console.print(f"  flags:       {flags_str or '(none)'}")
        console.print(f"  function:    {symbol} @ 0x{ann_va:08x} ({size_val}B)")
        console.print(f"  context:     {len(context_text)} bytes")
        console.print(f"  target_obj:  {len(payload['files']['target_obj'][1])} bytes (COFF)")
        return

    try:
        result = upload_scratch(payload, api=api)
    except RuntimeError as exc:
        error_exit(str(exc), json_mode=json_output)

    slug = str(result.get("slug", ""))
    token = str(result.get("claim_token", ""))
    url = scratch_url(slug, token, api=api)
    if json_output:
        json_print(
            {
                "slug": slug,
                "claim_token": token,
                "url": url,
                "compiler": compiler,
                "platform": platform,
            }
        )
        return
    console.print(f"[green]Scratch created:[/green] {url}")
    console.print("[dim]Open the claim URL to keep the scratch; share it for collaboration.[/dim]")


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
