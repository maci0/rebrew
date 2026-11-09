"""compiler/recompile_client.py — HTTP client for the recompile compile service.

The recompile service (sibling ``recompile`` checkout) exposes the same
pinned toolchain images rebrew compiles against locally
(``POST /api/v1/compile`` + ``GET /api/v1/artifacts/{id}{ext}``).  This
module is the thin transport: request building, artifact download, and
error mapping.  Routing policy (when the remote backend is used) lives in
:func:`rebrew.compiler.compile.compile_to_obj`; the service contract
(request/response field names) mirrors ``recompile/models.py``.

``emit_assembly=True`` requests an assembly listing when the service supports
it. Current Recompile separates assembly output from training consent; this
client does not request corpus retention.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable
lazy import hashlib
lazy import json as _json
lazy import os
lazy import re
lazy import time
lazy from collections.abc import Callable, Mapping
lazy from contextlib import nullcontext
lazy from urllib.parse import urljoin, urlparse

from rebrew.errors import RebrewError
from rebrew.utils import (
    RETRYABLE_HTTP_STATUS,
    close_response,
    retry_backoff_delay,
    retry_log_detail,
)
lazy from rebrew import telemetry

log = logging.getLogger(__name__)

#: Request cap mirrored from the service (recompile ``_MAX_FLAGS``): longer
#: flag lists 422 instead of compiling.
_MAX_FLAGS = 64

#: Single-flag length cap mirrored from the service (``_MAX_FLAG_LEN``).
_MAX_FLAG_LEN = 256

#: Hard cap on a recompile artifact body. The response is fully buffered
#: in memory (``art.content``) before it is written to disk and parsed,
#: so without a cap a compromised/mitm'd recompile service (or a
#: misconfigured one) could force an OOM by returning an oversized
#: ``.obj``. A single-function COFF object is at most a few MiB for
#: MSVC/Watcom/DOS toolchains; 30 MiB is generous headroom while bounding
#: the allocation.
_MAX_ARTIFACT_BYTES = 30 * 1024**2

#: How a :class:`RecompileError` arose — callers branch on this instead of
#: matching message substrings.
RecompileErrorKind = Literal[
    "network",
    "http",
    "validation",
    "protocol",
]

#: Retryable statuses that may arrive AFTER the service already ran the
#: compile (and may have performed service-side retention).
_MAY_HAVE_COMPILED = frozenset({500, 502, 504})

#: Subset of :data:`RETRYABLE_HTTP_STATUS` meaning the service never ran the
#: compile.  Derived, not re-spelled: a new transient code added to the shared
#: set must default to "worth another attempt", not silently become a
#: re-POSTed ``emit_assembly`` that duplicates a service-side effect.
_UNPROCESSED_HTTP = RETRYABLE_HTTP_STATUS - _MAY_HAVE_COMPILED


@runtime_checkable
class HttpResponse(Protocol):
    """Reply members :func:`compile_source` reads off an :class:`HttpClient`.

    An ``httpx.Response`` satisfies it.  A consumer test double has to
    supply these five members (and nothing else): the transport reads the
    status, the body text for the error message, the decoded JSON body, the
    artifact bytes, and the response headers (for the Content-Length bound
    on the artifact).  ``close()`` is absent on purpose —
    :func:`rebrew.utils.close_response` probes for it, so a stand-in holding
    no connection is still a valid reply.
    """

    @property
    def status_code(self) -> int: ...

    @property
    def text(self) -> str: ...

    @property
    def content(self) -> bytes: ...

    @property
    def headers(self) -> Mapping[str, str]: ...

    def json(self) -> Any: ...


@runtime_checkable
class HttpClient(Protocol):
    """Minimal HTTP client surface used by :func:`compile_source`.

    Matches ``httpx.Client`` (``.post`` / ``.get``).  Inject a fake that
    implements this protocol in consumer tests — no live service required;
    its replies must satisfy :class:`HttpResponse`.
    """

    def post(
        self,
        url: str,
        *,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
        follow_redirects: bool = False,
    ) -> HttpResponse: ...

    def get(
        self, url: str, *, headers: Mapping[str, str] | None = None, follow_redirects: bool = False
    ) -> HttpResponse: ...


@dataclass(frozen=True)
class RecompileResult:
    """Outcome of one remote compile (transport-level, pre-extraction)."""

    ok: bool
    obj_bytes: bytes | None = None
    log: str = ""
    compiler_version: str | None = None
    #: The service's ExecutionProvenance block for this compile, verbatim; None
    #: when the service sent none (never a placeholder).
    execution: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict, like :meth:`CompareResult.to_dict`.

        ``obj_bytes`` is the one field left out: it is the compiled object, not
        a JSON value.  A consumer that stores a remote compile's verdict
        writes ``log``, ``compiler_version`` and ``execution`` and keeps the
        bytes itself.
        """
        return {
            "ok": self.ok,
            "log": self.log,
            "compiler_version": self.compiler_version,
            **({"execution": self.execution} if self.execution is not None else {}),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RecompileResult:
        """Rebuild a result from :meth:`to_dict` output (``obj_bytes`` is ``None``).

        A missing ``ok`` is a build error, not a silent ``False``: a verdict
        that reads as "the remote compile failed" is the wrong default to
        invent, so this raises :class:`RecompileError` with
        ``kind="protocol"`` and the caller handles it beside every other
        malformed-reply case.
        """
        raw_ok = data.get("ok")
        if not isinstance(raw_ok, bool):
            raise RecompileError(
                f"RecompileResult.from_dict needs a boolean 'ok', got {raw_ok!r}",
                kind="protocol",
            )
        execution = data.get("execution")
        return cls(
            ok=raw_ok,
            log=str(data.get("log", "")),
            compiler_version=data.get("compiler_version"),
            execution=execution if isinstance(execution, dict) else None,
        )


class RecompileError(RebrewError, RuntimeError):
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


#: Names the one in-cluster service host that may receive the API key over plain HTTP.
#: Unset means HTTPS only. The compensating control is the cluster NetworkPolicy, which
#: must let rebrew reach nothing but that service (docs/TOOLCHAIN.md).
_INSECURE_CLUSTER_HOST_ENV = "REBREW_RECOMPILE_INSECURE_CLUSTER_HOST"

#: Host suffixes of in-cluster Kubernetes Services; the configured host must end in one.
_CLUSTER_HOST_SUFFIXES = (".svc", ".svc.cluster.local")

#: Longest DNS name.
_MAX_HOST_CHARS = 253


def _insecure_cluster_host() -> str:
    """The configured in-cluster host allowed to take the API key over HTTP, or "".

    One host name of lowercase letters, digits, dots and hyphens, ending in ``.svc`` or
    ``.svc.cluster.local``. Anything else is a configuration error, so a typo cannot
    widen the exception.
    """
    raw = os.environ.get(_INSECURE_CLUSTER_HOST_ENV, "").strip()
    if not raw:
        return ""
    if (
        len(raw) > _MAX_HOST_CHARS
        or not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", raw)
        or ".." in raw
        or not raw.endswith(_CLUSTER_HOST_SUFFIXES)
    ):
        raise RecompileError(
            f"{_INSECURE_CLUSTER_HOST_ENV} must be one in-cluster service host ending in "
            ".svc or .svc.cluster.local",
            kind="validation",
        )
    return raw


def _same_origin_artifact_url(base_url: str, artifact_url: str) -> str:
    """Resolve *artifact_url* against *base_url*, refusing off-origin targets.

    A compromised or malicious recompile service must not be able to redirect
    the client at an arbitrary URL (SSRF / credentialed-fetch pivot).  Only
    http(s) URLs whose scheme+netloc match *base_url* are accepted; relative
    paths (including ``./`` forms) are joined onto the base.
    """
    try:
        base = urlparse(base_url)
    except ValueError as exc:
        raise RecompileError(
            f"invalid recompile base URL: {base_url!r}", kind="validation"
        ) from exc
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
    try:
        if raw.startswith("//") or "://" in raw:
            resolved = urlparse(raw)
        else:
            resolved = urlparse(urljoin(base_url.rstrip("/") + "/", raw.lstrip("/")))
    except ValueError as exc:
        raise RecompileError(
            f"recompile service returned an invalid artifact_url: {artifact_url!r}",
            kind="protocol",
        ) from exc
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


def _download_artifact(
    http: HttpClient,
    base_url: str,
    body: dict[str, Any],
    artifact_url: str,
    auth_headers: dict[str, str] | None = None,
) -> RecompileResult:
    """Fetch the artifact for an ``status == "ok"`` reply and build the result."""
    resolved = _same_origin_artifact_url(base_url, artifact_url)
    try:
        art = (
            http.get(resolved, headers=auth_headers, follow_redirects=False)
            if auth_headers
            else http.get(resolved)
        )
    except Exception as exc:
        raise RecompileError(
            f"recompile artifact download failed: {exc}",
            kind="network",
            retryable=True,
        ) from exc
    try:
        if art.status_code != 200:
            detail = art.text
            if auth_headers:
                detail = detail.replace(
                    auth_headers["Authorization"].removeprefix("Bearer "), "[redacted]"
                )
            raise RecompileError(
                f"recompile artifact download returned HTTP {art.status_code}: {detail[:200]}",
                kind="http",
                status_code=art.status_code,
                retryable=art.status_code in RETRYABLE_HTTP_STATUS,
            )
        # Bound the buffered artifact before it is handed to the caller
        # (who writes it to disk and parses it). Both the declared
        # Content-Length and the actual buffered length are checked.
        declared = ""
        try:
            declared = str(art.headers.get("content-length", "") or "").strip()
        except AttributeError, TypeError:
            declared = ""
        if declared.isdigit() and int(declared) > _MAX_ARTIFACT_BYTES:
            raise RecompileError(
                f"recompile artifact exceeds {_MAX_ARTIFACT_BYTES} bytes",
                kind="protocol",
            )
        obj_bytes = art.content
        if len(obj_bytes) > _MAX_ARTIFACT_BYTES:
            raise RecompileError(
                f"recompile artifact exceeds {_MAX_ARTIFACT_BYTES} bytes",
                kind="protocol",
            )
        version = body.get("compiler_version") or None
        execution = body.get("execution")
        return RecompileResult(
            ok=True,
            obj_bytes=obj_bytes,
            log=str(body.get("log", "")),
            compiler_version=str(version) if version else None,
            execution=execution if isinstance(execution, dict) else None,
        )
    finally:
        close_response(art)


def compile_source(
    base_url: str,
    compiler: str,
    source: str,
    flags: list[str] | tuple[str, ...] | str,
    *,
    filename: str = "input.c",
    timeout: float = 180.0,
    emit_assembly: bool = False,
    client: HttpClient | None = None,
    retries: int = 0,
    sleep: Callable[[float], None] | None = None,
) -> RecompileResult:
    """Compile *source* via ``POST <base_url>/api/v1/compile``.

    Returns :class:`RecompileResult` with the downloaded artifact bytes on
    ``status == "ok"``.  A ``status == "error"`` reply maps to
    ``ok=False`` with the service log (compile failure, not transport
    failure).  Unreachable service / non-2xx / malformed replies raise
    :class:`RecompileError` — callers decide whether that is fatal or a
    local-docker fallback.

    *client*, when given, must be an ``httpx.Client`` (or compatible stand-in
    with ``.post`` / ``.get``).  The caller owns its lifetime and its timeout
    settings; *timeout* is passed only to the client this function builds
    itself and is ignored for an injected *client*.  When omitted, one
    short-lived client covers both the compile POST and the artifact GET.

    ``REBREW_RECOMPILE_API_KEY`` supplies a bearer credential to this service and its
    same-origin artifact endpoint. Authenticated POST retries share one key for
    this invocation; neither key nor request is persisted across process restarts.
    Job-socket compiles use their own capability and never forward this credential.

    *retries* re-attempts after a :class:`RecompileError` with
    ``retryable=True``.  Non-retryable errors (validation, 4xx other than
    the transient set) fail immediately.  ``retries=0`` (default) preserves
    prior single-shot behaviour.  Between attempts, sleeps with exponential
    backoff (``0.25 * 2**attempt`` seconds, capped at 8s) so a recovering
    503 is not immediately re-hammered.

    *sleep* is that backoff's only time source, the same seam
    :func:`rebrew.decompme.upload_scratch` and
    :func:`rebrew.compiler.headless._wait_for_socket` take: inject a stepper to replay
    a retry sequence from virtual time instead of waiting it out.  Left unset
    it reads :func:`time.sleep` per attempt, so a patched clock is honoured.

    Once the compile POST returns ``status == "ok"``, retries never re-POST:
    Older services may retain assembly output as a side effect, so a lost
    artifact GET only retries the same ``artifact_url``. A failed
    ``emit_assembly`` POST is re-sent only when the service is treated as
    unprocessed (connect failure, 408/425/429/503); a read timeout or
    500/502/504 may follow a completed compile, so it fails instead.
    """
    import httpx

    configured_key = os.environ.get("REBREW_RECOMPILE_API_KEY", "")
    if retries < 0:
        raise RecompileError(
            f"retries must be >= 0, got {retries}",
            kind="validation",
        )
    flags_list = [f for f in flags.split() if f] if isinstance(flags, str) else list(flags)

    if len(flags_list) > _MAX_FLAGS:
        raise RecompileError(
            f"too many flags ({len(flags_list)} > {_MAX_FLAGS})",
            kind="validation",
        )
    for flag in flags_list:
        if len(flag) > _MAX_FLAG_LEN:
            raise RecompileError(
                f"flag too long ({len(flag)} > {_MAX_FLAG_LEN}): "
                f"{flag.replace(configured_key, '[redacted]')[:40] if configured_key else flag[:40]}",
                kind="validation",
            )

    # Fail fast on a mistyped base URL before opening a client / posting.
    display_base = base_url.replace(configured_key, "[redacted]") if configured_key else base_url
    try:
        parsed = urlparse(base_url.strip())
    except ValueError as exc:
        if configured_key:
            raise RecompileError(
                f"invalid recompile base URL: {display_base!r}", kind="validation"
            ) from None
        raise RecompileError(
            f"invalid recompile base URL: {display_base!r}", kind="validation"
        ) from exc
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RecompileError(
            f"recompile base URL must be http(s) with a host: {display_base!r}",
            kind="validation",
        )

    url = base_url.rstrip("/")
    api_key = configured_key
    if (
        os.environ.get("REBREW_JOB_COMPILE_SOCKET")
        and parsed.scheme == "http"
        and parsed.netloc == "rebrew-job"
    ):
        api_key = ""
    if api_key and (not api_key.isascii() or any(not 33 <= ord(c) <= 126 for c in api_key)):
        raise RecompileError("invalid REBREW_RECOMPILE_API_KEY", kind="validation")
    cluster_host = _insecure_cluster_host() if api_key else ""
    if (
        api_key
        and parsed.scheme != "https"
        and not (parsed.hostname and parsed.hostname == cluster_host)
    ):
        raise RecompileError("authenticated recompile service requires HTTPS", kind="validation")
    if api_key and (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise RecompileError(
            "authenticated recompile base URL has forbidden components", kind="validation"
        )
    safe_url = url.replace(api_key, "[redacted]") if api_key else url
    auth_headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
    # Idempotency-Key: deterministic digest of the logical compile (compiler,
    # source, flags, filename, emit_assembly) so a retry, a crash-restart, or a
    # re-run of the same compile in another process presents the same key.
    # The server can then dedup a duplicate POST (e.g. emit_assembly's
    # train.jsonl append) instead of treating each attempt as new.  Previously
    # unauthenticated calls sent no key at all, and authenticated calls sent a
    # fresh random token per invocation, so every retry looked new.
    _idem_digest = hashlib.sha256(
        _json.dumps(
            {
                "compiler": compiler,
                "source": source,
                "flags": flags_list,
                "filename": filename,
                "emit_assembly": emit_assembly,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:12]
    post_headers: dict[str, str] = {"Idempotency-Key": _idem_digest}
    if auth_headers:
        post_headers = {**auth_headers, "Idempotency-Key": _idem_digest}
    payload = {
        "compiler": compiler,
        "source": source,
        "flags": flags_list,
        "filename": filename,
        "emit_assembly": emit_assembly,
    }

    attempts = retries + 1
    last_exc: RecompileError | None = None
    nap = sleep if sleep is not None else time.sleep
    # Body + artifact_url from a successful compile POST.  Set once; retries
    # only re-GET so a successful compile is not repeated.
    pending: tuple[dict[str, Any], str] | None = None
    # Stopwatch for the terminal record: how long the run spent on a
    # dependency before giving up, which is the number an operator needs when
    # the service is the thing that changed.
    started_at = time.perf_counter()
    for attempt in range(attempts):
        # One client for POST + GET.  Injected clients are not closed here.
        cm: Any = (
            nullcontext(client) if client is not None else httpx.Client(timeout=timeout, trust_env=False)
        )
        try:
            with cm as http:
                if pending is None:
                    try:
                        with telemetry.span(
                            "recompile.compile", kind=telemetry.KIND_CLIENT
                        ) as sent:
                            sent.set("rebrew.compiler", compiler)
                            resp = http.post(
                                f"{url}/api/v1/compile",
                                json=payload,
                                headers={**post_headers, "traceparent": sent.traceparent},
                                follow_redirects=False,
                            )
                            sent.set("http.response.status_code", resp.status_code)
                            if resp.status_code >= 500:
                                sent.fail(f"status {resp.status_code}")
                    except Exception as exc:
                        never_sent = isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout))
                        raise RecompileError(
                            f"recompile service at {url} unreachable: {exc}",
                            kind="network",
                            retryable=never_sent or not emit_assembly,
                        ) from exc
                    try:
                        if resp.status_code != 200:
                            detail = (
                                resp.text.replace(api_key, "[redacted]") if api_key else resp.text
                            )
                            raise RecompileError(
                                f"recompile service returned HTTP {resp.status_code}: "
                                f"{detail[:300]}",
                                kind="http",
                                status_code=resp.status_code,
                                retryable=resp.status_code
                                in (_UNPROCESSED_HTTP if emit_assembly else RETRYABLE_HTTP_STATUS),
                            )
                        try:
                            body = resp.json()
                        except Exception as exc:
                            raise RecompileError(
                                f"recompile service returned non-JSON: {exc}",
                                kind="protocol",
                            ) from exc
                        if not isinstance(body, dict):
                            raise RecompileError(
                                f"recompile service returned {type(body).__name__}, "
                                "expected a JSON object",
                                kind="protocol",
                            )
                        status = body.get("status")
                        if status not in ("ok", "error"):
                            raise RecompileError(
                                f"recompile service returned unknown status {status!r}",
                                kind="protocol",
                            )
                        if status != "ok":
                            failure_log = str(body.get("log", ""))
                            if api_key:
                                failure_log = failure_log.replace(api_key, "[redacted]")
                            return RecompileResult(ok=False, log=failure_log)
                        artifact_url = body.get("artifact_url")
                        if not artifact_url:
                            raise RecompileError(
                                'recompile service returned status "ok" with no artifact_url',
                                kind="protocol",
                            )
                        if not isinstance(artifact_url, str):
                            raise RecompileError(
                                f"recompile service returned non-string artifact_url: "
                                f"{artifact_url!r}",
                                kind="protocol",
                            )
                        pending = (body, artifact_url)
                    finally:
                        close_response(resp)
                body, artifact_url = pending
                result = _download_artifact(http, url, body, artifact_url, auth_headers)
                if api_key:
                    result = RecompileResult(
                        ok=result.ok,
                        obj_bytes=result.obj_bytes,
                        log=result.log.replace(api_key, "[redacted]"),
                        compiler_version=(
                            result.compiler_version.replace(api_key, "[redacted]")
                            if result.compiler_version is not None
                            else None
                        ),
                        execution=result.execution,
                    )
                return result
        except RecompileError as exc:
            if api_key:
                exc.args = (str(exc).replace(api_key, "[redacted]"),)
                exc.__cause__ = None
                exc.__context__ = None
                exc.__suppress_context__ = True
            last_exc = exc
            if not exc.retryable or attempt + 1 >= attempts:
                # The last word on a dependency that is down: the retries
                # above logged each attempt that would be retried, so a run
                # with ``retries=0`` (the default, and what a batch compile of
                # many sources sends) logged nothing at all.  Its caller turns
                # the raise into a per-source compile error, so on the log
                # stream — the one a batch or GA run is grepped through — a
                # recompile backend that is unreachable, down, or rejecting
                # reads as a compiler that dislikes the source.  One record
                # per terminal failure, naming the service and the elapsed
                # time, is what makes "which dependency failed" answerable.
                log.warning(
                    "recompile %s gave up after %d attempt(s) over %.1fs (%s%s): %s",
                    safe_url,
                    attempt + 1,
                    time.perf_counter() - started_at,
                    exc.kind,
                    "" if exc.status_code is None else f" {exc.status_code}",
                    retry_log_detail(exc),
                )
                raise
            # Immediate re-POST of a 503/timeout hammers a recovering service;
            # exponential backoff (capped) gives it room without unbounded wait.
            delay = retry_backoff_delay(attempt)
            # One line per retry, before the sleep: a remote backend that is
            # failing and recovering otherwise spends the backoff in silence,
            # so a `rebrew test` run against a flaky service looks hung with no
            # record of which dependency is faulting or how long the wait is.
            log.warning(
                "recompile %s attempt %d/%d failed (%s%s), retrying in %.2fs: %s",
                safe_url,
                attempt + 1,
                attempts,
                exc.kind,
                "" if exc.status_code is None else f" {exc.status_code}",
                delay,
                retry_log_detail(exc),
            )
            nap(delay)
    assert last_exc is not None  # attempts >= 1
    raise last_exc


__all__ = [
    "HttpClient",
    "HttpResponse",
    "RecompileError",
    "RecompileErrorKind",
    "RecompileResult",
    "compile_source",
]
