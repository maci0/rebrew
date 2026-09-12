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

from dataclasses import dataclass

#: Request cap mirrored from the service (recompile ``_MAX_FLAGS``): longer
#: flag lists 422 instead of compiling.
_MAX_FLAGS = 64

#: Single-flag length cap mirrored from the service (``_MAX_FLAG_LEN``).
_MAX_FLAG_LEN = 256


@dataclass(frozen=True)
class RecompileResult:
    """Outcome of one remote compile (transport-level, pre-extraction)."""

    ok: bool
    obj_bytes: bytes | None = None
    log: str = ""
    compiler_version: str | None = None


class RecompileError(RuntimeError):
    """The recompile service cannot serve the request (unreachable, 4xx/5xx)."""


def compile_source(
    base_url: str,
    compiler: str,
    source: str,
    flags: list[str],
    *,
    filename: str = "input.c",
    timeout: float = 180.0,
    emit_assembly: bool = False,
) -> RecompileResult:
    """Compile *source* via ``POST <base_url>/api/v1/compile``.

    Returns :class:`RecompileResult` with the downloaded artifact bytes on
    ``status == "ok"``.  A ``status == "error"`` reply maps to
    ``ok=False`` with the service log (compile failure, not transport
    failure).  Unreachable service / non-2xx / malformed replies raise
    :class:`RecompileError` — callers decide whether that is fatal or a
    local-docker fallback.
    """
    import httpx

    if len(flags) > _MAX_FLAGS:
        raise RecompileError(f"too many flags ({len(flags)} > {_MAX_FLAGS})")
    for flag in flags:
        if len(flag) > _MAX_FLAG_LEN:
            raise RecompileError(f"flag too long ({len(flag)} > {_MAX_FLAG_LEN}): {flag[:40]}")

    url = base_url.rstrip("/")
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(
                f"{url}/api/v1/compile",
                json={
                    "compiler": compiler,
                    "source": source,
                    "flags": flags,
                    "filename": filename,
                    "emit_assembly": emit_assembly,
                },
            )
    except Exception as exc:
        raise RecompileError(f"recompile service at {url} unreachable: {exc}") from exc
    if resp.status_code != 200:
        raise RecompileError(
            f"recompile service returned HTTP {resp.status_code}: {resp.text[:300]}"
        )
    try:
        body = resp.json()
    except Exception as exc:
        raise RecompileError(f"recompile service returned non-JSON: {exc}") from exc
    if body.get("status") != "ok" or not body.get("artifact_url"):
        return RecompileResult(ok=False, log=str(body.get("log", "")))
    artifact_url = str(body["artifact_url"])
    if artifact_url.startswith("/"):
        artifact_url = f"{url}{artifact_url}"
    try:
        with httpx.Client(timeout=timeout) as client:
            art = client.get(artifact_url)
    except Exception as exc:
        raise RecompileError(f"recompile artifact download failed: {exc}") from exc
    if art.status_code != 200:
        raise RecompileError(
            f"recompile artifact download returned HTTP {art.status_code}: {art.text[:200]}"
        )
    version = body.get("compiler_version") or None
    return RecompileResult(
        ok=True,
        obj_bytes=art.content,
        log=str(body.get("log", "")),
        compiler_version=str(version) if version else None,
    )
