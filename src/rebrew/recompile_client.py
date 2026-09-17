"""recompile_client.py — HTTP client for the recompile compile service.

The recompile service (sibling ``recompile`` checkout) exposes the same
pinned toolchain images rebrew compiles against locally
(``POST /api/v1/compile`` + ``GET /api/v1/artifacts/{id}{ext}``).  This
module is the thin transport: request building, artifact download, and
error mapping.  Routing policy (when the remote backend is used) lives in
:func:`rebrew.compile.compile_to_obj`; the service contract
(request/response field names) mirrors ``recompile/models.py``.

Every compile sent with ``emit_assembly=True`` also appends a
``{source, assembly, compiler, image, flags, ...}`` row to the service's
``train_data/train.jsonl`` — the opt-in tap that feeds resembl and LLM
training.  rebrew passes it through only when the caller asks (the GA's
``--collect-pairs`` path); ordinary test/verify compiles never set it.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urljoin, urlparse

#: Request cap mirrored from the service (recompile ``_MAX_FLAGS``): longer
#: flag lists 422 instead of compiling.
_MAX_FLAGS = 64

#: Single-flag length cap mirrored from the service (``_MAX_FLAG_LEN``).
_MAX_FLAG_LEN = 256

#: How a :class:`RecompileError` arose — callers branch on this instead of
#: matching message substrings.
RecompileErrorKind = Literal[
    "network",
    "http",
    "validation",
    "protocol",
]

#: Transient HTTP statuses that are safe to retry after a backoff.
_RETRYABLE_HTTP = frozenset({408, 425, 429, 500, 502, 503, 504})


@dataclass(frozen=True)
class RecompileResult:
    """Outcome of one remote compile (transport-level, pre-extraction)."""

    ok: bool
    obj_bytes: bytes | None = None
    log: str = ""
    compiler_version: str | None = None


class RecompileError(RuntimeError):
    """The recompile service cannot serve the request (unreachable, 4xx/5xx).

    Structured fields let callers recover without string-matching ``str(exc)``:

    - ``kind`` — ``"network"`` / ``"http"`` / ``"validation"`` / ``"protocol"``
    - ``status_code`` — HTTP status when ``kind == "http"``, else ``None``
    - ``retryable`` — ``True`` for transport blips and transient HTTP codes
    """

    def __init__(
        self,
        message: str,
        *,
        kind: RecompileErrorKind = "protocol",
        status_code: int | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.status_code = status_code
        self.retryable = retryable


def _same_origin_artifact_url(base_url: str, artifact_url: str) -> str:
    """Resolve *artifact_url* against *base_url*, refusing off-origin targets.

    A compromised or malicious recompile service must not be able to redirect
    the client at an arbitrary URL (SSRF / credentialed-fetch pivot).  Only
    http(s) URLs whose scheme+netloc match *base_url* are accepted; relative
    paths (including ``./`` forms) are joined onto the base.
    """
    base = urlparse(base_url)
    if base.scheme not in ("http", "https") or not base.netloc:
        raise RecompileError(
            f"recompile base URL must be http(s) with a host: {base_url!r}",
            kind="validation",
        )
    raw = artifact_url.strip()
    if not raw:
        raise RecompileError(
            "recompile service returned an empty artifact_url",
            kind="protocol",
        )
    # Protocol-relative (``//evil``) and absolute URLs are parsed as-is;
    # everything else is joined onto the compile base.
    if raw.startswith("//") or "://" in raw:
        resolved = urlparse(raw)
    else:
        resolved = urlparse(urljoin(base_url.rstrip("/") + "/", raw.lstrip("/")))
    if resolved.scheme != base.scheme or resolved.netloc != base.netloc:
        raise RecompileError(
            f"recompile artifact_url is not same-origin as {base_url!r}: {artifact_url!r}",
            kind="protocol",
        )
    if not resolved.path.startswith("/"):
        raise RecompileError(
            f"recompile artifact_url has no path: {artifact_url!r}",
            kind="protocol",
        )
    return resolved.geturl()


def compile_source(
    base_url: str,
    compiler: str,
    source: str,
    flags: list[str],
    *,
    filename: str = "input.c",
    timeout: float = 180.0,
    emit_assembly: bool = False,
    client: Any | None = None,
) -> RecompileResult:
    """Compile *source* via ``POST <base_url>/api/v1/compile``.

    Returns :class:`RecompileResult` with the downloaded artifact bytes on
    ``status == "ok"``.  A ``status == "error"`` reply maps to
    ``ok=False`` with the service log (compile failure, not transport
    failure).  Unreachable service / non-2xx / malformed replies raise
    :class:`RecompileError` — callers decide whether that is fatal or a
    local-docker fallback.

    *client*, when given, must be an ``httpx.Client`` (or compatible stand-in
    with ``.post`` / ``.get``).  The caller owns its lifetime; the function
    does not close it.  When omitted, one short-lived client covers both the
    compile POST and the artifact GET.
    """
    import httpx

    if len(flags) > _MAX_FLAGS:
        raise RecompileError(
            f"too many flags ({len(flags)} > {_MAX_FLAGS})",
            kind="validation",
        )
    for flag in flags:
        if len(flag) > _MAX_FLAG_LEN:
            raise RecompileError(
                f"flag too long ({len(flag)} > {_MAX_FLAG_LEN}): {flag[:40]}",
                kind="validation",
            )

    url = base_url.rstrip("/")
    payload = {
        "compiler": compiler,
        "source": source,
        "flags": flags,
        "filename": filename,
        "emit_assembly": emit_assembly,
    }

    # One client for POST + GET.  Injected clients are not closed here.
    cm: Any = nullcontext(client) if client is not None else httpx.Client(timeout=timeout)
    with cm as http:
        try:
            resp = http.post(f"{url}/api/v1/compile", json=payload)
        except Exception as exc:
            raise RecompileError(
                f"recompile service at {url} unreachable: {exc}",
                kind="network",
                retryable=True,
            ) from exc
        if resp.status_code != 200:
            raise RecompileError(
                f"recompile service returned HTTP {resp.status_code}: {resp.text[:300]}",
                kind="http",
                status_code=resp.status_code,
                retryable=resp.status_code in _RETRYABLE_HTTP,
            )
        try:
            body = resp.json()
        except Exception as exc:
            raise RecompileError(
                f"recompile service returned non-JSON: {exc}",
                kind="protocol",
            ) from exc
        if body.get("status") != "ok" or not body.get("artifact_url"):
            return RecompileResult(ok=False, log=str(body.get("log", "")))
        artifact_url = _same_origin_artifact_url(url, str(body["artifact_url"]))
        try:
            art = http.get(artifact_url)
        except Exception as exc:
            raise RecompileError(
                f"recompile artifact download failed: {exc}",
                kind="network",
                retryable=True,
            ) from exc
        if art.status_code != 200:
            raise RecompileError(
                f"recompile artifact download returned HTTP {art.status_code}: {art.text[:200]}",
                kind="http",
                status_code=art.status_code,
                retryable=art.status_code in _RETRYABLE_HTTP,
            )
        version = body.get("compiler_version") or None
        return RecompileResult(
            ok=True,
            obj_bytes=art.content,
            log=str(body.get("log", "")),
            compiler_version=str(version) if version else None,
        )
