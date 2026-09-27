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

decomp.me has no idempotency key, so a re-run with an unchanged payload
would leave a second identical scratch behind.  The created slug is kept in
``.rebrew/decompme-uploads.json`` keyed by a digest of the payload, and a
repeat prints the same claim URL; ``--reupload`` opts out.

Usage:
    rebrew decompme src/game/func.c                # upload the first function
    rebrew decompme src/game/func.c --va 0x401000 # upload a specific VA
    rebrew decompme src/game/func.c --reupload     # force a second scratch
    rebrew decompme src/game/func.c --dry-run     # preview the payload
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

import typer

from rebrew.cli import (
    TargetOption,
    console,
    error_exit,
    json_print,
    parse_va,
    require_config,
    untrusted_text,
)
from rebrew.config import validate_http_url
from rebrew.errors import RebrewError
from rebrew.utils import (
    RETRYABLE_HTTP_STATUS,
    atomic_write_text,
    close_response,
    file_lock,
    read_source_text,
    retry_backoff_delay,
)

app = typer.Typer(
    help="Upload a function to decomp.me as a collaborative scratch.",
    rich_markup_mode="rich",
)

_DEFAULT_API = "https://decomp.me"

#: Server-issued ``slug`` / ``claim_token`` shape.  Both are spliced into the
#: claim URL and printed through Rich, so anything else is refused.
_SCRATCH_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")

#: rebrew profile → decomp.me compiler id (closest match).  decomp.me's
#: registry mirrors the MSVC line; anything else (mingw-16.2.0, console
#: compilers) must be passed explicitly with ``--compiler``.  msvc-7.0 maps to
#: the 7.1 id because its "7.0-win32" image carries the 7.1 compiler build.
_COMPILER_MAP: dict[str, str] = {
    "msvc4": "msvc4.0",
    "msvc-4.0": "msvc4.0",
    "msvc-4.1": "msvc4.1",
    "msvc-4.2": "msvc4.2",
    "msvc-5.0": "msvc5.0",
    "msvc-6.0": "msvc6.0",
    "msvc-6.0-sp1": "msvc6.0",
    "msvc-6.0-sp2": "msvc6.0",
    "msvc-6.0-sp3": "msvc6.0",
    "msvc-6.0-sp4": "msvc6.0",
    "msvc-6.0-sp5": "msvc6.0",
    "msvc-6.0-sp6": "msvc6.0",
    "msvc-7.0": "msvc7.1",
    "msvc-7.0-rtm": "msvc7.0",
    "msvc-7.0-sp1": "msvc7.0",
    "msvc-7.1": "msvc7.1",
    "msvc-7.1-sp1": "msvc7.1",
    "msvc-8.0": "msvc8.0",
    "msvc-8.0-sp1": "msvc8.0",
    "msvc-9.0": "msvc9.0",
    "msvc-9.0-sp1": "msvc9.0",
    "msvc-10.0": "msvc10.0",
    "msvc-10.0-sp1": "msvc10.0",
    "msvc-11.0": "msvc11.0",
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


def extract_function_text(text: str, name: str) -> str | None:
    """Isolate one function definition plus the file preamble from *text*.

    The preamble is everything before the first function definition
    (includes, typedefs, globals, prototypes) — what the snippet needs to
    compile standalone.  Returns None when the function cannot be isolated
    (no tree-sitter, no definitions, ambiguous name); the caller then falls
    back to the whole file.
    """
    from rebrew.c_parser import find_c_function_definitions

    defs = find_c_function_definitions(text)
    if not defs:
        return None
    idx: int | None = next((i for i, (n, _ln) in enumerate(defs) if n == name), None)
    if idx is None:
        if len(defs) != 1:
            return None
        idx = 0
    lines = text.splitlines(keepends=True)
    start = defs[idx][1]  # 1-based line of the selected definition
    end = defs[idx + 1][1] if idx + 1 < len(defs) else len(lines) + 1
    chunk = "".join(lines[: defs[0][1] - 1] + lines[start - 1 : end - 1])
    return chunk if chunk.strip() else None


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
    full_text, _encoding = read_source_text(source)
    c_name = name or (symbol.lstrip("_") if symbol else "") or diff_label
    source_code = extract_function_text(full_text, c_name) or full_text
    data = {
        "compiler": compiler,
        "platform": platform,
        "compiler_flags": compiler_flags,
        "diff_label": diff_label,
        "diff_flags": json.dumps([f"--disassemble={diff_label}"]),
        "context": context,
        "source_code": source_code,
        "name": name or diff_label,
    }
    files = {"target_obj": (f"{source.stem}.o", obj_bytes, "application/octet-stream")}
    return {"data": data, "files": files}


DecompmeErrorKind = Literal["network", "http", "validation", "protocol"]


@runtime_checkable
class HttpResponse(Protocol):
    """Reply members :func:`upload_scratch` / :func:`verify_compiler` read.

    An ``httpx.Response`` satisfies it.  ``close()`` is part of the contract
    here (the module-``httpx`` calls go through the top-level ``httpx.post``
    / ``httpx.get``, whose reply owns the connection); it is released
    through :func:`rebrew.utils.close_response`, which swallows a close
    failure so it cannot mask the request's own result.
    """

    @property
    def status_code(self) -> int: ...

    @property
    def text(self) -> str: ...

    def json(self) -> Any: ...

    def close(self) -> None: ...


@runtime_checkable
class HttpClient(Protocol):
    """Minimal HTTP surface :func:`upload_scratch` / :func:`verify_compiler` use.

    Matches an ``httpx.Client`` and any stand-in exposing ``.post`` / ``.get``,
    so a consumer test injects a fake instead of reaching the live service.
    Its replies must satisfy :class:`HttpResponse`.
    """

    def post(self, url: str, **kwargs: Any) -> HttpResponse: ...

    def get(self, url: str, **kwargs: Any) -> HttpResponse: ...


class DecompmeError(RebrewError, RuntimeError):
    """Failure communicating with or creating scratches on decomp.me.

    Structured fields allow callers to branch on error conditions:

    - ``kind`` — ``"network"`` / ``"http"`` / ``"validation"`` / ``"protocol"``
    - ``status_code`` — HTTP status when ``kind == "http"``, else ``None``
    - ``retryable`` — ``True`` for transport blips and transient HTTP codes
    """

    def __init__(
        self,
        message: str,
        *,
        kind: DecompmeErrorKind = "protocol",
        status_code: int | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.status_code = status_code
        self.retryable = retryable


def _post_scratch(
    post_fn: Any,
    url: str,
    payload: dict[str, Any],
    kw: dict[str, Any],
) -> dict[str, Any]:
    """One upload attempt: POST *payload* and validate the reply."""
    try:
        resp = post_fn(url, data=payload["data"], files=payload["files"], **kw)
    except Exception as exc:
        raise DecompmeError(
            f"decomp.me request failed: {exc}", kind="network", retryable=True
        ) from exc
    try:
        if resp.status_code >= 400:
            raise DecompmeError(
                f"decomp.me rejected the scratch (HTTP {resp.status_code}): "
                f"{(resp.text or '')[:500]}",
                kind="http",
                status_code=resp.status_code,
                retryable=resp.status_code in RETRYABLE_HTTP_STATUS,
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise DecompmeError(
                f"decomp.me returned an unparseable response: {resp.text[:200]}",
                kind="protocol",
            ) from exc
        if not isinstance(data, dict):
            raise DecompmeError(
                f"decomp.me returned {type(data).__name__}, expected an object", kind="protocol"
            )
        for key in ("slug", "claim_token"):
            value = data.get(key)
            if not isinstance(value, str) or not _SCRATCH_ID_RE.fullmatch(value):
                raise DecompmeError(
                    f"decomp.me returned an invalid {key}: {value!r:.80}", kind="protocol"
                )
        return data
    finally:
        close_response(resp)


def upload_scratch(
    payload: dict[str, Any],
    api: str = _DEFAULT_API,
    timeout: float = 60.0,
    *,
    client: HttpClient | None = None,
    retries: int = 0,
) -> dict[str, Any]:
    """POST the scratch to decomp.me; returns the response dict.

    Raises :class:`DecompmeError` (inherits :class:`RebrewError` and
    :class:`RuntimeError`) on transport failure, a non-2xx response
    (the body is included — decomp.me validation errors explain the reason),
    or a reply whose ``slug`` / ``claim_token`` are not URL-safe tokens.

    *client*, when given, must provide a ``.post(...)`` method.

    *retries* re-attempts a :class:`DecompmeError` with ``retryable=True``
    (transport blips and the transient HTTP statuses in
    ``RETRYABLE_HTTP_STATUS``), sleeping :func:`rebrew.utils.retry_backoff_delay`
    between attempts.  A rejection decomp.me explained (validation, other
    4xx) fails immediately; ``retries=0`` (default) is a single attempt.
    """
    import httpx  # deferred: ~46 ms of startup for non-decomp.me commands

    post_fn = client.post if client is not None else httpx.post
    kw: dict[str, Any] = {}
    if client is None:
        kw["timeout"] = timeout
    url = f"{api}/api/scratch"
    attempts = retries + 1
    last_exc: DecompmeError | None = None
    for attempt in range(attempts):
        try:
            return _post_scratch(post_fn, url, payload, kw)
        except DecompmeError as exc:
            last_exc = exc
            if not exc.retryable or attempt + 1 >= attempts:
                raise
            time.sleep(retry_backoff_delay(attempt))
    assert last_exc is not None  # attempts >= 1
    raise last_exc


def scratch_url(slug: str, claim_token: str, api: str = _DEFAULT_API) -> str:
    """The claim URL for a freshly-created scratch."""
    return f"{api}/scratch/{slug}/claim?token={claim_token}"


# --- Upload ledger ---------------------------------------------------------
#
# A decomp.me create always makes a new public scratch; decomp.me has no
# idempotency key, so a re-run of an unchanged `rebrew decompme` would pile up
# duplicate scratches.  The ledger maps a digest of the exact payload to the
# slug the first run got, and a repeat prints that claim URL instead of
# uploading again.  ``--reupload`` forces a fresh scratch.

#: Project-relative ledger path (``.rebrew/`` holds other tool-owned state).
_UPLOADS_REL_PATH = ".rebrew/decompme-uploads.json"

#: Entries older than this are dropped on write, so the ledger stays bounded.
_UPLOADS_RETENTION_SECONDS = 90 * 24 * 3600

#: Hard cap on ledger size, applied after the age prune.
_UPLOADS_MAX_ENTRIES = 500

#: Mode of the ledger file: it stores claim tokens, so no group/other access.
_UPLOADS_FILE_MODE = 0o600


def scratch_digest(payload: dict[str, Any], api: str) -> str:
    """Content digest of a scratch payload, the ledger's idempotency key.

    Covers every field the service receives (form data plus each uploaded
    file's name and bytes) and the service it goes to, so two runs of
    ``rebrew decompme`` share a digest exactly when decomp.me would receive
    the identical request.
    """
    h = hashlib.sha256()
    h.update(api.encode("utf-8"))
    for key in sorted(payload.get("data", {})):
        h.update(key.encode("utf-8"))
        h.update(b"\0")
        h.update(str(payload["data"][key]).encode("utf-8"))
        h.update(b"\0")
    for key in sorted(payload.get("files", {})):
        entry = payload["files"][key]
        filename, blob = entry[0], entry[1]
        h.update(key.encode("utf-8"))
        h.update(b"\0")
        h.update(str(filename).encode("utf-8"))
        h.update(b"\0")
        h.update(blob if isinstance(blob, bytes) else bytes(blob))
        h.update(b"\0")
    return h.hexdigest()


def _uploads_path(root: Path) -> Path:
    return root / _UPLOADS_REL_PATH


def read_uploads(root: Path) -> dict[str, dict[str, str]]:
    """The upload ledger as ``{digest: {slug, claim_token, api, at}}``.

    A missing, unreadable, or malformed file reads as empty: the ledger is a
    cache of remote state, and a corrupt one must degrade to a plain upload
    rather than fail the command.
    """
    try:
        raw = _uploads_path(root).read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    entries: dict[str, dict[str, str]] = {}
    for digest, entry in data.items():
        if not isinstance(digest, str) or not isinstance(entry, dict):
            continue
        if not isinstance(entry.get("slug"), str) or not isinstance(entry.get("claim_token"), str):
            continue
        entries[digest] = {k: str(v) for k, v in entry.items()}
    return entries


def recorded_upload(root: Path, digest: str, api: str) -> dict[str, str] | None:
    """The ledger entry for *digest* on *api*, or None when there is none.

    An entry recorded against a different service is not a match: the same
    payload uploaded elsewhere produced a different scratch.
    """
    entry = read_uploads(root).get(digest)
    if entry is None or entry.get("api") != api:
        return None
    return entry


def record_upload(root: Path, digest: str, slug: str, claim_token: str, api: str) -> None:
    """Remember the scratch created for *digest*, pruning aged-out entries.

    The ledger holds a decomp.me claim token, which is the credential that
    owns the uploaded scratch, so the file is written owner-only (0600) rather
    than the 0644 :func:`atomic_write_text` default.  The chmod runs on every
    write, not just the first, so a ledger created before this mode existed is
    tightened on the next run.

    Best-effort: a ledger that cannot be written (read-only project, full
    disk) must not turn a successful upload into a command failure, so the
    scratch is still created and only the dedup is lost.
    """
    path = _uploads_path(root)
    now = time.time()
    try:
        with file_lock(path.with_suffix(".lock")):
            entries = read_uploads(root)
            entries[digest] = {"slug": slug, "claim_token": claim_token, "api": api, "at": str(now)}
            fresh = {k: v for k, v in entries.items() if _is_recent(v, now)}
            if len(fresh) > _UPLOADS_MAX_ENTRIES:
                ordered = sorted(fresh.items(), key=lambda kv: float(kv[1].get("at", 0) or 0))
                fresh = dict(ordered[-_UPLOADS_MAX_ENTRIES:])
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(path, json.dumps(fresh, indent=2, sort_keys=True) + "\n")
            path.chmod(_UPLOADS_FILE_MODE)
    except OSError as exc:
        logging.warning(
            "decomp.me upload ledger not written (%s); the next run will upload again",
            exc,
        )


def _is_recent(entry: dict[str, str], now: float) -> bool:
    try:
        at = float(entry.get("at", 0) or 0)
    except ValueError:
        return False
    return now - at < _UPLOADS_RETENTION_SECONDS


def verify_compiler(
    compiler: str,
    api: str = _DEFAULT_API,
    timeout: float = 15.0,
    *,
    client: HttpClient | None = None,
) -> None:
    """Verify *compiler* exists in the decomp.me registry.

    Best-effort: on transport failure (e.g. Cloudflare bot protection on the
    registry endpoint) the upload itself will surface a rejection, so the
    check degrades to a warning.  Raises :class:`DecompmeError` only when the
    registry was reachable and the id is unknown — with the known ids as
    suggestions (the friendly check for non-MSVC toolchains that previously
    relied on the documented ``--compiler`` override).
    """
    import httpx

    get_fn = client.get if client is not None else httpx.get
    kw: dict[str, Any] = {}
    if client is None:
        kw["timeout"] = timeout
    try:
        resp = get_fn(f"{api}/api/compiler", **kw)
    except Exception as exc:
        console.print(
            f"[yellow]warning:[/yellow] decomp.me registry unreachable "
            f"({exc.__class__.__name__}) — skipping compiler check"
        )
        return
    try:
        if resp.status_code >= 400:
            console.print(
                f"[yellow]warning:[/yellow] decomp.me registry unavailable "
                f"(HTTP {resp.status_code}) — skipping compiler check"
            )
            return
        try:
            data = resp.json()
            compilers = data.get("compilers") or {}
        except ValueError:
            return
        if not isinstance(compilers, dict):
            return
        if compiler in compilers:
            return
        known = sorted(str(k) for k in compilers)
        hint = ", ".join(known[:8]) + ("…" if len(known) > 8 else "")
        raise DecompmeError(
            f"compiler {compiler!r} is not in the decomp.me registry "
            f"(available: {hint}) — pass --compiler with a valid id",
            kind="validation",
        )
    finally:
        close_response(resp)


def _resolve_annotation(
    cfg: Any, source: Path, va: int | None, size_override: int | None = None
) -> tuple[Any, int, int, str]:
    """Pick the annotation for *source* (by *va* or the first FUNCTION entry).

    *size_override* (the CLI ``--size``) supplies the size when the annotation
    has none — the check must not reject the very case ``--size`` exists for.
    """
    from rebrew.annotation import parse_c_file_multi
    from rebrew.sources import target_marker

    annos = parse_c_file_multi(
        source, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
    )
    funcs = [a for a in annos if a.is_function]
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
    size = size_override or int(ann.size or 0)
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
    from rebrew.context import collect_context

    blocks, _count = collect_context(cfg)
    return (
        "/* ctx.c - AUTO-GENERATED by `rebrew decompme` (from `rebrew context`).\n"
        " * Regenerate with `rebrew context`; pass --context FILE to override.\n"
        " */\n" + "\n\n".join(blocks) + ("\n" if blocks else "")
    )


@app.callback(invoke_without_command=True)
def main(
    source: str = typer.Argument(..., help="C source file for the function to upload"),
    va: str | None = typer.Option(None, "--va", help="Target VA in hex (default: from annotation)"),
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
    reupload: bool = typer.Option(
        False, "--reupload", help="Create a new scratch even if this payload was uploaded before"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Upload SOURCE's function to decomp.me as a collaborative scratch."""
    cfg = require_config(target=target, json_mode=json_output)
    try:
        api = validate_http_url(api, "--api")
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    if not api:
        error_exit("--api must be an http(s) URL with a host", json_mode=json_output)
    source_path = Path(source).resolve()
    if not source_path.exists():
        error_exit(f"source file not found: {source}", json_mode=json_output)

    va_int = parse_va(va, json_mode=json_output) if va else None
    try:
        ann, ann_va, ann_size, symbol = _resolve_annotation(cfg, source_path, va_int, size)
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    size_val = size or ann_size

    from rebrew.compile_overrides import resolve_compile_overrides

    # Resolve the flags regardless of --compiler: --flags defaults to the
    # function's resolved cflags, and skipping the resolution when the user
    # pins a compiler silently uploaded the scratch with no flags.
    toolchain, resolved_cflags = resolve_compile_overrides(
        cfg,
        source_path.parent,
        getattr(ann, "toolchain", ""),
        getattr(ann, "cflags", ""),
        getattr(ann, "module", ""),
    )
    if compiler is None:
        # ``resolve_compile_overrides`` returns None when no override names a
        # compiler — the project profile is the documented fallback.
        compiler = map_compiler(toolchain or cfg.compiler_profile)
        if compiler is None:
            error_exit(
                f"no decomp.me compiler mapped for toolchain {toolchain or cfg.compiler_profile!r} — "
                "pass --compiler (decomp.me ids include msvc4.0..msvc8.0; see decomp.me/api/compilers)",
                json_mode=json_output,
            )
    if flags is None:
        flags = resolved_cflags
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
    # UTF-8 bytes, not code points: the field is posted as form data, so that
    # is what decomp.me receives.  A context with a non-ASCII comment (a `é`
    # in a cp1252 source, an emoji) counted short under len(), and the figure
    # sat beside target_obj_bytes, which really is a byte count.
    context_bytes = len(context_text.encode("utf-8"))
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
                    "context_bytes": context_bytes,
                    "source_file": str(source_path),
                    "va": f"0x{ann_va:08x}",
                    "target_obj_bytes": len(payload["files"]["target_obj"][1]),
                }
            )
            return
        console.print("[bold]decomp.me scratch (dry-run, no upload):[/bold]")
        console.print(f"  compiler:    {compiler}")
        console.print(f"  platform:    {platform}")
        console.print(f"  flags:       {untrusted_text(flags_str) or '(none)'}")
        console.print(f"  function:    {untrusted_text(symbol)} @ 0x{ann_va:08x} ({size_val}B)")
        console.print(f"  context:     {context_bytes} bytes")
        console.print(f"  target_obj:  {len(payload['files']['target_obj'][1])} bytes (COFF)")
        return

    # Friendly registry check: catch a wrong compiler id before the upload
    # (best-effort — degrades to a warning when the registry is unreachable).
    # A dry run never uploads, so it makes no network call.
    try:
        verify_compiler(compiler, api=api)
    except RuntimeError as exc:
        error_exit(str(exc), json_mode=json_output)

    root = Path(getattr(cfg, "root", ".") or ".")
    digest = scratch_digest(payload, api)
    reused = None if reupload else recorded_upload(root, digest, api)

    if reused is not None:
        slug = reused["slug"]
        token = reused["claim_token"]
    else:
        try:
            result = upload_scratch(payload, api=api)
        except RuntimeError as exc:
            error_exit(str(exc), json_mode=json_output)
        slug = str(result.get("slug", ""))
        token = str(result.get("claim_token", ""))
        record_upload(root, digest, slug, token, api)

    url = scratch_url(slug, token, api=api)
    if json_output:
        json_print(
            {
                "slug": slug,
                "claim_token": token,
                "url": url,
                "compiler": compiler,
                "platform": platform,
                "reused": reused is not None,
            }
        )
        return
    if reused is not None:
        console.print(f"[green]Existing scratch:[/green] {url}")
        console.print(
            "[dim]Identical payload was already uploaded; pass --reupload to create a new one.[/dim]"
        )
        return
    console.print(f"[green]Scratch created:[/green] {url}")
    console.print("[dim]Open the claim URL to keep the scratch; share it for collaboration.[/dim]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()


__all__ = [
    "DecompmeError",
    "DecompmeErrorKind",
    "build_scratch_payload",
    "extract_function_text",
    "HttpClient",
    "HttpResponse",
    "map_compiler",
    "map_platform",
    "read_uploads",
    "record_upload",
    "recorded_upload",
    "scratch_digest",
    "scratch_url",
    "upload_scratch",
    "verify_compiler",
]
