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
import threading
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, Protocol, runtime_checkable
lazy import contextlib
lazy import os
lazy import re
lazy import secrets
lazy import time
lazy import unicodedata
lazy from collections.abc import Callable, Iterator, Mapping
lazy from contextlib import nullcontext
lazy from email.utils import parsedate_to_datetime
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

#: Single-flag cap mirrored from the service (``_MAX_FLAG_BYTES``).  The
#: service measures the NFC form's UTF-8 bytes, not Python characters: a
#: 200-character flag of two-byte code points is 400 bytes and is refused
#: there, so counting characters here would post a request the service 422s.
_MAX_FLAG_BYTES = 256

#: Recompile's verified artifact limit. The GET buffers the body before this
#: check, so the limit applies before writing or parsing, not during receipt.
_MAX_ARTIFACT_BYTES = 32 * 1024**2

#: Random bytes in one ``Idempotency-Key``; the service takes exactly 12
#: lowercase hex digits (recompile ``docs/API.md``).
_IDEMPOTENCY_KEY_BYTES = 6

#: Include bundle bounds mirrored from the service (recompile ``models.py``
#: ``MAX_INCLUDE_*``, ``docs/API.md`` "Include bundles"): a larger bundle 422s.
MAX_INCLUDE_FILES = 256
MAX_INCLUDE_FILE_BYTES = 2_000_000
MAX_INCLUDE_TOTAL_BYTES = 6_000_000
MAX_INCLUDE_PATH_BYTES = 1024

#: The ``GET /api/v1/features`` entry of a service that takes ``includes`` and
#: ``source_dir``.  An older service refuses those fields as unknown with a
#: bare 422, so a bundle is never sent before the service names it.
INCLUDE_BUNDLES_FEATURE = "include-bundles"

#: Where the service lists its optional request features (recompile
#: ``docs/API.md``).  Not ``/``: a hosted ingress sends that to Platform.
_FEATURES_PATH = "/api/v1/features"

#: Longest features reply read; the document is a few dozen bytes.
_MAX_FEATURES_BYTES = 64 * 1024

#: Base URLs whose features listed :data:`INCLUDE_BUNDLES_FEATURE` in this
#: process.  Only support is remembered, so an upgraded service is seen
#: without a restart.  A long-lived process can be handed many service URLs;
#: keep the positive memo bounded like the compiler-listing cache.
_bundle_services: set[str] = set()
_BUNDLE_SERVICES_MAX = 8
_bundle_services_lock = threading.Lock()

#: Where the service lists its compilers and whether this deployment can run
#: each (recompile ``docs/API.md``, ``GET /api/v1/compilers``).
_COMPILERS_PATH = "/api/v1/compilers"

#: The ``execution_status`` of a listed compiler this deployment has installed.
_ADMITTED = "admitted"

#: The ``code`` recompile refuses a compiler it has not installed with (400).
COMPILER_NOT_INSTALLED = "compiler_not_installed"

#: Seconds a listing is kept: recompile keeps its own answer that long
#: (``executor.ADMISSION_WINDOW_S``), and inside it a compiler listed
#: ``admitted`` is not refused as not installed.
_COMPILERS_WINDOW_SECONDS = 30.0

#: Longest listing reply read; the catalog is a few hundred rows.
_MAX_COMPILERS_BYTES = 4 * 1024**2

#: Listings kept at once; a process talks to one service, so the bound only
#: guards a long-lived one handed many URLs.
_COMPILERS_CACHE_MAX = 8

#: Base URL -> (monotonic time read, admitted ids or ``None``).
_compilers_cache: dict[str, tuple[float, frozenset[str] | None]] = {}
_compilers_cache_lock = threading.Lock()
#: One listing refresh per base URL.  Parallel verify workers otherwise all
#: miss the same 30-second window and stampede the service's catalog route.
_compilers_inflight: dict[str, threading.Event] = {}
#: Bounds one wait, not the whole refresh: a live leader keeps owning the read.
_COMPILERS_WAIT_TIMEOUT_S = 30.0

#: How a :class:`RecompileError` arose — callers branch on this instead of
#: matching message substrings.  ``service`` is a compile the service answered
#: but could not run; its ``error_code`` names why.  ``deadline`` is a compile
#: the call's deadline left no time to send or to retry.
RecompileErrorKind = Literal[
    "network",
    "http",
    "validation",
    "protocol",
    "service",
    "deadline",
]

#: Longest ``Retry-After`` honoured, in seconds: a longer one is waited this
#: long, so a malformed or hostile header cannot park a compile for hours.
MAX_RETRY_AFTER_SECONDS = 300

#: Seconds from its start a compile without a call deadline (a CLI run) waits
#: out capacity and throttle refusals before it reports the last one.
NO_DEADLINE_WAIT_SECONDS = 300

#: What one answer of the service says the compile's key cost: ``billed``,
#: ``free`` (nothing billed) or ``unknown`` (it may have been billed, and no
#: answer said).  A call ends with the cost of its last key
#: (:attr:`RecompileError.cost`); a call that returns a result was billed and
#: gave its verdict.
KeyCost = Literal["billed", "free", "unknown"]

#: What the client does after an answer: ``download`` the object (a compile's
#: ``status: "ok"``); take the answer as the ``verdict``; ``final``, no other
#: attempt; ``wait``, the same request after its ``Retry-After`` or the backoff,
#: until the call's deadline, spending no retry; ``retry``, the same request
#: after the backoff, spending one; ``new_key`` and ``new_key_wait``, the same as
#: ``retry`` and ``wait`` under a new ``Idempotency-Key``.
_NextStep = Literal["download", "verdict", "final", "wait", "retry", "new_key", "new_key_wait"]

#: The two routes a compile reads: ``POST /api/v1/compile`` and the artifact
#: download ``GET /api/v1/artifacts/{artifact_name}``.
_Route = Literal["compile", "artifact"]


@dataclass(frozen=True)
class _AnswerRule:
    """How the client reads one recompile answer (recompile ``docs/API.md``, "Client rules")."""

    #: What the answer says the key cost; ``None`` says nothing of it, so the key
    #: keeps what earlier answers left (a refused credential, a throttle).
    cost: KeyCost | None
    then: _NextStep


#: The ``code`` of a table row that holds for every code of its status that no
#: row of its own names.
_ANY_CODE = "*"

#: Every answer of recompile's compile and artifact routes, keyed by route, HTTP
#: status and code: the error body's ``code``, or for a compile's 200 its
#: ``error_code`` (``None`` for ``status: "ok"``).  The costs are rule 4 of the
#: client rules (recompile 14.0.1 ``docs/API.md``), the next steps rules 3, 5 and 7,
#: read so that they hold against every release a deployment may run, 12.0.0 to
#: 14.x: an answer settles a key as free only where every one of them says the key
#: was not billed.  A row read more cautiously than 14.0.1's table names the
#: release that needs it.  An answer no row names is read by its status: a 5xx
#: may have been billed and is final, anything else says nothing of the key and is
#: final.
_ANSWERS: Mapping[tuple[_Route, int, str | None], _AnswerRule] = MappingProxyType(
    {
        # The compile ran: an object to download, or the compiler's rejection.
        ("compile", 200, None): _AnswerRule("billed", "download"),
        ("compile", 200, "toolchain_failure"): _AnswerRule("billed", "verdict"),
        # The service's own failures bill nothing; capacity and a runner that is
        # not up are waited out, a failed publish is compiled again (rule 5).
        ("compile", 200, "capacity"): _AnswerRule("free", "new_key_wait"),
        ("compile", 200, "runner_unavailable"): _AnswerRule("free", "new_key_wait"),
        ("compile", 200, "publish_failed"): _AnswerRule("free", "new_key"),
        ("compile", 200, "timeout"): _AnswerRule("free", "final"),
        ("compile", 200, "provenance_unavailable"): _AnswerRule("free", "final"),
        ("compile", 200, "missing_artifact"): _AnswerRule("free", "final"),
        ("compile", 200, "replay_rejected"): _AnswerRule("free", "final"),
        # A new compile refused; a known key may get it before Platform looks the key
        # up (12.0.0, and 14.0.0 against Platform 0.28.1), so it settles nothing.
        ("compile", 400, "compiler_not_installed"): _AnswerRule(None, "final"),
        ("compile", 400, "compiler_unavailable"): _AnswerRule(None, "final"),
        ("compile", 400, "compiler_withdrawn"): _AnswerRule(None, "final"),
        ("compile", 400, "bundles_unsupported"): _AnswerRule(None, "final"),
        # Refused by this service before it reached Platform; the same request is
        # refused the same way.
        ("compile", 400, "invalid_idempotency_key"): _AnswerRule("free", "final"),
        ("compile", 400, "invalid_attribution"): _AnswerRule("free", "final"),
        ("compile", 400, "malformed_request"): _AnswerRule("free", "final"),
        ("compile", 400, _ANY_CODE): _AnswerRule(None, "final"),
        # A refused credential: rebrew gets no other one to resend the key with.
        # 12.0.0 relays Platform's 401 after the compile, and its maintenance pass
        # then bills the retained outcome: unknown even on a first attempt.
        ("compile", 401, "unauthenticated"): _AnswerRule("unknown", "final"),
        ("compile", 401, "authentication_required"): _AnswerRule(None, "final"),
        ("compile", 401, _ANY_CODE): _AnswerRule(None, "final"),
        # A new compile refused until the account can pay.  Before 14.0.1 a known key
        # may get it before Platform looks the key up, so it settles nothing.
        ("compile", 402, "model_credits_exhausted"): _AnswerRule(None, "final"),
        ("compile", 402, "allowance_exhausted"): _AnswerRule(None, "final"),
        # 14.0.0 relays it for a compile Platform 0.29.0 billed while the plan was removed.
        ("compile", 402, "workbench_plan_required"): _AnswerRule("unknown", "final"),
        ("compile", 402, _ANY_CODE): _AnswerRule(None, "final"),
        # Billed, and this credential may not receive the result.
        ("compile", 403, "billed_not_delivered"): _AnswerRule("billed", "final"),
        # 12.0.0 answers it after Platform settled (billed) the compile: no new key.
        ("compile", 403, "delivery_denied"): _AnswerRule("unknown", "final"),
        # 12.0.0 relays Platform's 403 after the compile, which its maintenance pass bills.
        ("compile", 403, "forbidden"): _AnswerRule("unknown", "final"),
        ("compile", 403, "cross_origin_write"): _AnswerRule(None, "final"),
        ("compile", 403, "cross_site_write"): _AnswerRule(None, "final"),
        ("compile", 403, "edge_required"): _AnswerRule(None, "final"),
        ("compile", 403, _ANY_CODE): _AnswerRule(None, "final"),
        ("compile", 405, _ANY_CODE): _AnswerRule(None, "final"),
        ("compile", 408, _ANY_CODE): _AnswerRule(None, "retry"),
        ("compile", 409, "admission_abandoned"): _AnswerRule("free", "new_key"),
        ("compile", 409, "admission_expired"): _AnswerRule("free", "new_key"),
        # 12.0.0 answers it for an admission Platform settled billed with no result.
        ("compile", 409, "result_unavailable"): _AnswerRule("unknown", "final"),
        ("compile", 409, "admission_unrecoverable"): _AnswerRule("unknown", "final"),
        ("compile", 409, "retained_output_unavailable"): _AnswerRule("billed", "final"),
        # "No for this request" (14.0.1), and 12.0.0 relays every Platform 409 under it,
        # a settlement's among them: it settles nothing, and the same key goes again.
        ("compile", 409, "admission_conflict"): _AnswerRule(None, "retry"),
        ("compile", 409, _ANY_CODE): _AnswerRule(None, "final"),
        ("compile", 410, "artifact_expired"): _AnswerRule("billed", "final"),
        ("compile", 410, _ANY_CODE): _AnswerRule(None, "final"),
        # Platform's cap, relayed by 12.0.0 before Platform looks the key up.
        ("compile", 413, "source_too_large"): _AnswerRule(None, "final"),
        ("compile", 413, "body_too_large"): _AnswerRule("free", "final"),
        ("compile", 413, _ANY_CODE): _AnswerRule(None, "final"),
        ("compile", 415, "unsupported_media_type"): _AnswerRule("free", "final"),
        ("compile", 415, _ANY_CODE): _AnswerRule(None, "final"),
        ("compile", 422, "validation_failed"): _AnswerRule("free", "final"),
        ("compile", 422, _ANY_CODE): _AnswerRule("free", "final"),
        # 12.0.0 relays Platform's refusal of the caller after the compile, as for 401.
        ("compile", 423, "account_under_review"): _AnswerRule("unknown", "final"),
        ("compile", 423, _ANY_CODE): _AnswerRule(None, "final"),
        ("compile", 425, _ANY_CODE): _AnswerRule(None, "retry"),
        ("compile", 429, "rate_limited"): _AnswerRule(None, "wait"),
        ("compile", 429, "concurrency_limit"): _AnswerRule(None, "wait"),
        ("compile", 429, "failure_throttle"): _AnswerRule(None, "wait"),
        ("compile", 429, "request_budget"): _AnswerRule(None, "wait"),
        ("compile", 429, _ANY_CODE): _AnswerRule(None, "wait"),
        ("compile", 500, _ANY_CODE): _AnswerRule("unknown", "retry"),
        ("compile", 502, _ANY_CODE): _AnswerRule("unknown", "retry"),
        ("compile", 503, "runtime_unavailable"): _AnswerRule("unknown", "wait"),
        ("compile", 503, "platform_unavailable"): _AnswerRule("unknown", "wait"),
        ("compile", 503, "settlement_pending"): _AnswerRule("unknown", "wait"),
        ("compile", 503, "store_unavailable"): _AnswerRule("unknown", "wait"),
        # The credit ledger did not answer a new compile's reservation: nothing was
        # admitted, and a key already admitted is replayed before the credit check.
        ("compile", 503, "credit_ledger_unavailable"): _AnswerRule("free", "wait"),
        ("compile", 503, _ANY_CODE): _AnswerRule("unknown", "wait"),
        ("compile", 504, _ANY_CODE): _AnswerRule("unknown", "retry"),
        # The edge's own answers (Cloudflare, "Troubleshooting Cloudflare 5XX errors"):
        # a lost reply, retried under the same key (rule 3).  520: the origin reset
        # the connection or sent an empty or unreadable reply; 524: the origin took
        # longer than 100 s to answer.  Both may follow an admitted compile.
        ("compile", 520, _ANY_CODE): _AnswerRule("unknown", "wait"),
        ("compile", 524, _ANY_CODE): _AnswerRule("unknown", "wait"),
        # 521: the origin refused the connection; 522: the connection to it timed
        # out; 523: the origin is unreachable.  The request never reached it.
        ("compile", 521, _ANY_CODE): _AnswerRule(None, "wait"),
        ("compile", 522, _ANY_CODE): _AnswerRule(None, "wait"),
        ("compile", 523, _ANY_CODE): _AnswerRule(None, "wait"),
        # A download follows a billed compile and changes nothing of its cost.
        ("artifact", 200, None): _AnswerRule(None, "verdict"),
        ("artifact", 401, _ANY_CODE): _AnswerRule(None, "final"),
        ("artifact", 403, _ANY_CODE): _AnswerRule(None, "final"),
        ("artifact", 404, "artifact_not_found"): _AnswerRule(None, "final"),
        ("artifact", 404, _ANY_CODE): _AnswerRule(None, "final"),
        ("artifact", 408, _ANY_CODE): _AnswerRule(None, "retry"),
        ("artifact", 409, "retained_output_unavailable"): _AnswerRule(None, "final"),
        ("artifact", 409, _ANY_CODE): _AnswerRule(None, "final"),
        ("artifact", 410, "artifact_expired"): _AnswerRule(None, "final"),
        ("artifact", 410, _ANY_CODE): _AnswerRule(None, "final"),
        ("artifact", 423, _ANY_CODE): _AnswerRule(None, "final"),
        ("artifact", 425, _ANY_CODE): _AnswerRule(None, "retry"),
        ("artifact", 429, _ANY_CODE): _AnswerRule(None, "wait"),
        ("artifact", 500, _ANY_CODE): _AnswerRule(None, "retry"),
        ("artifact", 502, _ANY_CODE): _AnswerRule(None, "retry"),
        # A dependency of the download did not answer: waited out (rule 7).
        ("artifact", 503, "platform_unavailable"): _AnswerRule(None, "wait"),
        ("artifact", 503, "store_unavailable"): _AnswerRule(None, "wait"),
        ("artifact", 503, "artifact_evidence_unavailable"): _AnswerRule(None, "wait"),
        ("artifact", 503, _ANY_CODE): _AnswerRule(None, "wait"),
        ("artifact", 504, _ANY_CODE): _AnswerRule(None, "retry"),
        # The same edge failures as the compile route; the billed compile's cost
        # is already settled, so only the artifact GET is repeated.
        ("artifact", 520, _ANY_CODE): _AnswerRule(None, "wait"),
        ("artifact", 524, _ANY_CODE): _AnswerRule(None, "wait"),
        ("artifact", 521, _ANY_CODE): _AnswerRule(None, "wait"),
        ("artifact", 522, _ANY_CODE): _AnswerRule(None, "wait"),
        ("artifact", 523, _ANY_CODE): _AnswerRule(None, "wait"),
    }
)

#: A compile POST that got no readable answer: sent and maybe admitted.
_LOST_REPLY = _AnswerRule("unknown", "retry")

#: A compile POST that never connected: nothing reached the service.
_NOT_SENT = _AnswerRule(None, "retry")


def _answer_rule(route: _Route, status: int, code: str | None) -> _AnswerRule:
    """The :data:`_ANSWERS` row of one answer, or the rule of its status when none names it."""
    rule = _ANSWERS.get((route, status, code)) or _ANSWERS.get((route, status, _ANY_CODE))
    if rule is not None:
        return rule
    if route == "compile" and status >= 500:
        return _AnswerRule("unknown", "final")
    return _AnswerRule(None, "final")


#: The ``error_code`` values of a compile's 200 the client reads; another is a
#: protocol error.
_COMPILE_FAILURES = frozenset(
    code for route, status, code in _ANSWERS if route == "compile" and status == 200 and code
)

#: Infrastructure failures of a compile the service refused before running it,
#: so a re-sent ``emit_assembly`` request cannot repeat a retention side effect.
_NOT_RUN_FAILURES = frozenset({"capacity"})

#: Shape of a recompile error ``code``; another value is not read.
_ERROR_CODE = re.compile(r"[a-z][a-z_]{0,63}")


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


#: The request header that names the Workbench work a compile is for (recompile
#: ``docs/API.md``, "Request"; recompile before 13 ignores it).
ATTRIBUTION_HEADER = "X-Relumea-Attribution"

#: Longest attribution member, in characters: recompile 13's bound, which it
#: enforces with ``400 invalid_attribution`` before admission, unbilled.  Checked
#: here first, so a malformed attribution is refused before anything is sent.
ATTRIBUTION_MEMBER_MAX_CHARS = 128


@dataclass(frozen=True)
class Attribution:
    """Who a compile is for inside the Workbench: organization, project, user and job.

    The caller of a dispatch op names it and every recompile call the op makes
    carries it in :data:`ATTRIBUTION_HEADER`.  Each member is 1 to
    :data:`ATTRIBUTION_MEMBER_MAX_CHARS` printable ASCII characters.
    """

    #: The Workbench organization's Platform account id.
    org: str
    #: The Workbench project id.
    project: str
    #: The subject of the person the Workbench acted for.
    user: str
    #: The Workbench job that sent the op.
    job: str

    def __post_init__(self) -> None:
        for name in ("org", "project", "user", "job"):
            value = getattr(self, name)
            if (
                not isinstance(value, str)
                or not 1 <= len(value) <= ATTRIBUTION_MEMBER_MAX_CHARS
                or any(not " " <= char <= "~" for char in value)
            ):
                raise ValueError(
                    f"attribution {name} must be 1 to {ATTRIBUTION_MEMBER_MAX_CHARS} "
                    "printable ASCII characters"
                )

    def header_value(self) -> str:
        """The JSON object sent in :data:`ATTRIBUTION_HEADER`."""
        import json

        return json.dumps(
            {"org": self.org, "project": self.project, "user": self.user, "job": self.job},
            separators=(",", ":"),
        )


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

    - ``kind`` — ``"network"`` / ``"http"`` / ``"validation"`` / ``"protocol"`` /
      ``"service"`` / ``"deadline"``
    - ``status_code`` — HTTP status when ``kind == "http"``, else ``None``
    - ``error_code`` — the service's failure kind when ``kind == "service"``
      (``capacity``, ``timeout``, ``runner_unavailable``, ``publish_failed``,
      ``provenance_unavailable``, ``missing_artifact``, ``replay_rejected``),
      the error body's ``code`` when ``kind == "http"`` and it sent one
      (recompile 11: ``admission_expired``, ``settlement_pending``, ...), else
      ``None``
    - ``retryable`` — ``True`` for transport blips, transient HTTP codes and
      the service's infrastructure failures
    - ``retry_after`` — the seconds the reply's ``Retry-After`` header asked
      to wait (at most :data:`MAX_RETRY_AFTER_SECONDS`), else ``None``

    ``cost`` is what the call's last key cost, set by :func:`compile_source` on the
    error it raises: ``"billed"`` when the service billed it and the call got no
    verdict (the object's download failed after ``status: "ok"``, or
    ``403 billed_not_delivered``, ``409 retained_output_unavailable``,
    ``410 artifact_expired``), ``"unknown"`` when it may have been billed and no
    answer under it said (a lost or unreadable reply, a 5xx other than
    ``credit_ledger_unavailable``, ``admission_unrecoverable``, an answer an
    earlier recompile release sends after billing such as ``403 delivery_denied``
    or a refused credential, and a throttle or other answer that says nothing of
    the key after one of those), else ``"free"``.  Each answer is read by one
    table, :data:`_ANSWERS`.
    """

    #: Set by :func:`compile_source` on the error it raises.
    cost: KeyCost = "free"
    #: What :func:`compile_source` does next, from the answer's table row.
    _then: _NextStep | None = None

    STRUCTURED_FIELDS = (*RebrewError.STRUCTURED_FIELDS, "error_code", "retry_after")

    def __init__(
        self,
        message: str,
        *,
        kind: RecompileErrorKind = "protocol",
        status_code: int | None = None,
        retryable: bool = False,
        error_code: str | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.status_code = status_code
        self.retryable = retryable
        self.error_code = error_code
        self.retry_after = retry_after


def _error_code(reply: HttpResponse) -> str | None:
    """The ``code`` of a recompile error body (``{"detail", "code"}``), or ``None``."""
    try:
        body = reply.json()
    except Exception:
        # Not a JSON body (a proxy's page, the body cap's plain-text 413): the
        # refusal is read by its status alone.
        return None
    code = body.get("code") if isinstance(body, dict) else None
    return code if isinstance(code, str) and _ERROR_CODE.fullmatch(code) else None


def _retry_after(value: str | None) -> float | None:
    """Seconds a ``Retry-After`` header asks to wait: delta-seconds or an HTTP-date."""
    if value is None:
        return None
    text = value.strip()
    if text.isdigit():
        seconds = float(text)
    else:
        try:
            when = parsedate_to_datetime(text)
        except TypeError, ValueError:
            return None
        if when.tzinfo is None:
            return None
        seconds = max(0.0, when.timestamp() - time.time())
    return min(seconds, float(MAX_RETRY_AFTER_SECONDS))


class ServiceGate:
    """Paces the compiles one process sends one recompile service.

    At most *concurrency* attempts run at once, and none starts while a
    ``Retry-After`` the service named is running: one throttled compile holds
    every compile of the process back instead of each one sending into the
    throttle.  :func:`compile_source` takes it as *gate*.
    """

    def __init__(self, concurrency: int) -> None:
        if concurrency < 1:
            raise ValueError(f"concurrency must be >= 1, got {concurrency}")
        self._slots = threading.BoundedSemaphore(concurrency)
        self._lock = threading.Lock()
        self._not_before = 0.0

    def hold_off(self, seconds: float) -> None:
        """Start no attempt for *seconds* from now (a later hold-off already set stands)."""
        with self._lock:
            self._not_before = max(self._not_before, time.monotonic() + seconds)

    @contextlib.contextmanager
    def attempt(self, deadline: float | None, sleep: Callable[[float], None]) -> Iterator[None]:
        """Hold a slot for one attempt, after the hold-off; refuse it past *deadline*.

        *deadline* is a :func:`time.monotonic` value or ``None``; *sleep* waits
        out the hold-off.  Raises :class:`RecompileError` (``kind="deadline"``)
        when the hold-off or a free slot comes later than *deadline*.
        """
        with self._lock:
            wait = self._not_before - time.monotonic()
        if wait > 0:
            if deadline is not None and time.monotonic() + wait > deadline:
                raise _deadline_refusal("the service's Retry-After runs past the call's deadline")
            sleep(wait)
        if deadline is None:
            self._slots.acquire()
        elif not self._slots.acquire(timeout=max(0.0, deadline - time.monotonic())):
            raise _deadline_refusal("no compile slot came free before the call's deadline")
        try:
            yield
        finally:
            self._slots.release()


def _deadline_refusal(why: str) -> RecompileError:
    return RecompileError(f"recompile not sent: {why}", kind="deadline")


def _answered(message: str, rule: _AnswerRule, **fields: Any) -> RecompileError:
    """A :class:`RecompileError` for one answer, retryable unless its *rule* is final."""
    error = RecompileError(message, retryable=rule.then != "final", **fields)
    error._then = rule.then
    return error


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
        art = http.get(resolved, headers=auth_headers, follow_redirects=False)
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
            code = _error_code(art)
            raise _answered(
                f"recompile artifact download returned HTTP {art.status_code}: {detail[:200]}",
                _answer_rule("artifact", art.status_code, code),
                kind="http",
                status_code=art.status_code,
                error_code=code,
                retry_after=_retry_after(art.headers.get("Retry-After")),
            )
        # Bound the buffered artifact before it is handed to the caller
        # (who writes it to disk and parses it). Both the declared
        # Content-Length and the actual buffered length are checked.
        declared = ""
        try:
            declared = str(art.headers.get("content-length", "") or "").strip()
        except AttributeError, TypeError:
            declared = ""
        try:
            declared_size = int(declared) if declared.isdigit() else 0
        except ValueError as exc:
            raise RecompileError(
                "recompile artifact Content-Length is invalid", kind="protocol"
            ) from exc
        if declared_size > _MAX_ARTIFACT_BYTES:
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


def _require_utf8(text: str, what: str) -> None:
    """Refuse *text* the service cannot receive: a lone surrogate has no UTF-8 form.

    A source read with ``surrogateescape`` (``compile_to_obj``) carries one per
    byte that is not UTF-8, such as a cp1252 comment.
    """
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise RecompileError(
            f"{what} is not UTF-8 text (character {exc.start}); "
            "the recompile service compiles UTF-8 text only",
            kind="validation",
        ) from None


def _check_bundle(includes: Mapping[str, str], source_dir: str) -> None:
    """Refuse a bundle over the service's bounds, or not UTF-8, before it is sent."""
    if len(includes) > MAX_INCLUDE_FILES:
        raise RecompileError(
            f"{len(includes)} include files exceed the service's {MAX_INCLUDE_FILES}",
            kind="validation",
        )
    total = 0
    for path in (source_dir, *includes):
        _require_utf8(path, "include path")
        if len(path.encode("utf-8")) > MAX_INCLUDE_PATH_BYTES:
            raise RecompileError(
                f"include path longer than {MAX_INCLUDE_PATH_BYTES} UTF-8 bytes: {path[:60]}",
                kind="validation",
            )
    for path, text in includes.items():
        _require_utf8(text, path)
        size = len(text.encode("utf-8"))
        if size > MAX_INCLUDE_FILE_BYTES:
            raise RecompileError(
                f"{path} is {size} bytes, over the service's {MAX_INCLUDE_FILE_BYTES} per file",
                kind="validation",
            )
        total += size
    if total > MAX_INCLUDE_TOTAL_BYTES:
        raise RecompileError(
            f"include files total {total} bytes, over the service's {MAX_INCLUDE_TOTAL_BYTES}",
            kind="validation",
        )


def accepts_include_bundles(base_url: str, *, client: HttpClient) -> bool:
    """Whether the service's ``GET /api/v1/features`` lists :data:`INCLUDE_BUNDLES_FEATURE`.

    A service older than include bundles answers 404 there, or a list without
    the feature; it would refuse the fields with a bare 422, so the caller
    refuses the compile instead.  The route needs no credential, so none is
    sent.  A transport failure or another reply raises :class:`RecompileError`
    (``network`` and transient HTTP codes are retryable).  Support is
    remembered per base URL for the life of the process.
    """
    url = base_url.rstrip("/")
    with _bundle_services_lock:
        if url in _bundle_services:
            return True
    try:
        reply = client.get(f"{url}{_FEATURES_PATH}", follow_redirects=False)
    except Exception as exc:
        raise RecompileError(
            f"recompile service at {url} unreachable: {exc}", kind="network", retryable=True
        ) from exc
    try:
        if reply.status_code == 404:
            return False
        if reply.status_code != 200:
            raise RecompileError(
                f"recompile service returned HTTP {reply.status_code} for {_FEATURES_PATH}",
                kind="http",
                status_code=reply.status_code,
                retryable=reply.status_code in RETRYABLE_HTTP_STATUS,
            )
        if len(reply.content) > _MAX_FEATURES_BYTES:
            raise RecompileError(f"recompile {_FEATURES_PATH} reply is too large", kind="protocol")
        try:
            body = reply.json()
        except Exception as exc:
            raise RecompileError(
                f"recompile service returned non-JSON for {_FEATURES_PATH}: {exc}",
                kind="protocol",
            ) from exc
    finally:
        close_response(reply)
    features = body.get("features") if isinstance(body, dict) else None
    if not isinstance(features, list):
        raise RecompileError(f"recompile {_FEATURES_PATH} has no feature list", kind="protocol")
    if INCLUDE_BUNDLES_FEATURE not in features:
        return False
    with _bundle_services_lock:
        if len(_bundle_services) >= _BUNDLE_SERVICES_MAX:
            _bundle_services.clear()
        _bundle_services.add(url)
    return True


def installed_compilers(base_url: str, *, client: HttpClient) -> frozenset[str] | None:
    """The compiler ids the service's ``GET /api/v1/compilers`` lists ``execution_status: "admitted"``.

    ``None`` when the listing does not say what the deployment can run, and
    nothing is then held back: no row reads ``admitted`` (recompile before 13
    lists every row ``unavailable``, and recompile 13 does when its runtime does
    not answer), or the route answers 404 (the jobs owner's compile mediator
    forwards no listing).  A compiler that is not installed after all is then
    refused by the service itself, ``400 compiler_not_installed``, unbilled.
    The route needs no credential, so none is sent.  A transport failure or
    another reply raises :class:`RecompileError` (``network`` and transient HTTP
    codes are retryable).  The answer is kept per base URL for
    :data:`_COMPILERS_WINDOW_SECONDS`, and so is a read that failed: for that
    window the listing reads ``None`` without being asked again, so a failing
    route costs one request per window, not one per compile.
    """
    url = base_url.rstrip("/")
    while True:
        with _compilers_cache_lock:
            cached = _compilers_cache.get(url)
            if cached is not None and time.monotonic() - cached[0] < _COMPILERS_WINDOW_SECONDS:
                return cached[1]
            event = _compilers_inflight.get(url)
            if event is None:
                event = threading.Event()
                _compilers_inflight[url] = event
                break
        # A peer owns this refresh.  Re-check after every bounded wait rather
        # than sending a duplicate when the leader is merely slow.
        event.wait(timeout=_COMPILERS_WAIT_TIMEOUT_S)
    try:
        try:
            answer = _read_installed_compilers(url, client)
        except RecompileError:
            _remember_compilers(url, None)
            raise
        _remember_compilers(url, answer)
        return answer
    finally:
        with _compilers_cache_lock:
            if _compilers_inflight.get(url) is event:
                del _compilers_inflight[url]
        event.set()


def _remember_compilers(url: str, answer: frozenset[str] | None) -> None:
    with _compilers_cache_lock:
        _compilers_cache.pop(url, None)
        while len(_compilers_cache) >= _COMPILERS_CACHE_MAX:
            _compilers_cache.pop(next(iter(_compilers_cache)))
        _compilers_cache[url] = (time.monotonic(), answer)


def _read_installed_compilers(url: str, client: HttpClient) -> frozenset[str] | None:
    """One read of :data:`_COMPILERS_PATH`, for :func:`installed_compilers`."""
    try:
        reply = client.get(f"{url}{_COMPILERS_PATH}", follow_redirects=False)
    except Exception as exc:
        raise RecompileError(
            f"recompile service at {url} unreachable: {exc}", kind="network", retryable=True
        ) from exc
    try:
        if reply.status_code == 404:
            rows: Any = []
        elif reply.status_code != 200:
            raise RecompileError(
                f"recompile service returned HTTP {reply.status_code} for {_COMPILERS_PATH}",
                kind="http",
                status_code=reply.status_code,
                retryable=reply.status_code in RETRYABLE_HTTP_STATUS,
            )
        elif len(reply.content) > _MAX_COMPILERS_BYTES:
            raise RecompileError(f"recompile {_COMPILERS_PATH} reply is too large", kind="protocol")
        else:
            try:
                rows = reply.json()
            except Exception as exc:
                raise RecompileError(
                    f"recompile service returned non-JSON for {_COMPILERS_PATH}: {exc}",
                    kind="protocol",
                ) from exc
    finally:
        close_response(reply)
    if not isinstance(rows, list) or not all(
        isinstance(row, dict) and isinstance(row.get("id"), str) for row in rows
    ):
        raise RecompileError(f"recompile {_COMPILERS_PATH} is not a compiler list", kind="protocol")
    admitted = frozenset(row["id"] for row in rows if row.get("execution_status") == _ADMITTED)
    return admitted or None


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
    includes: Mapping[str, str] | None = None,
    source_dir: str = "",
    gate: ServiceGate | None = None,
    deadline: float | None = None,
    attribution: Attribution | None = None,
) -> RecompileResult:
    """Compile *source* via ``POST <base_url>/api/v1/compile``.

    Returns :class:`RecompileResult` with the downloaded artifact bytes on
    ``status == "ok"``.  A ``status == "error"`` reply is read by its
    ``error_code``: ``toolchain_failure`` (the compiler rejected the source)
    maps to ``ok=False`` with the service log; the service's own failures
    raise :class:`RecompileError` with ``kind="service"`` and that
    ``error_code``, retryable for ``capacity``, ``runner_unavailable`` and
    ``publish_failed`` and final for ``timeout``, ``provenance_unavailable``,
    ``missing_artifact`` and ``replay_rejected``; a missing or unknown code is a
    protocol error.  Unreachable service / non-2xx /
    malformed replies raise :class:`RecompileError` — callers decide whether
    that is fatal or a local-docker fallback.

    *client*, when given, must be an ``httpx.Client`` (or compatible stand-in
    with ``.post`` / ``.get``).  The caller owns its lifetime and its timeout
    settings; *timeout* is passed only to the client this function builds
    itself and is ignored for an injected *client*.  When omitted, one
    short-lived client covers both the compile POST and the artifact GET.

    ``REBREW_RECOMPILE_API_KEY`` supplies a bearer credential to this service and its
    same-origin artifact endpoint. Job-socket compiles use their own capability and
    never forward this credential.

    Every call is one logical attempt with its own random ``Idempotency-Key``.
    Each answer is read by :data:`_ANSWERS`, which says what the key cost
    (:attr:`RecompileError.cost`) and what comes next.  A retry after a lost reply,
    the edge's ``520`` to ``524``, a 5xx or ``409 admission_conflict`` resends that
    key, so the service reconciles the attempt it may already have run instead of
    running another; a retry after a ``capacity``, ``runner_unavailable`` or
    ``publish_failed`` refusal, or a refusal whose ``code`` says the key can never
    yield a result and billed nothing in any recompile release
    (``admission_abandoned``, ``admission_expired``), is a new attempt with a new
    key, because a hosted service keeps the refusal under the old one (recompile's
    client rules, rule 5).  Every other refusal is final and never resent:
    ``timeout``, ``provenance_unavailable``, ``admission_unrecoverable``,
    ``result_unavailable``, ``delivery_denied`` and a refused credential among them,
    the last three unknown because recompile 12.0.0 sends them after billing.  A
    later call, including one after a failure or an image update, sends a new key
    and never replays an earlier call. Neither key nor request is persisted.

    A refusal that says the service has no room for the compile now (a
    ``capacity`` or ``runner_unavailable`` refusal, a 429, a 503), and the edge's
    ``520`` to ``524``, are waited out
    and tried again until *deadline*, a :func:`time.monotonic` value; without
    one, for :data:`NO_DEADLINE_WAIT_SECONDS` from the call's start.  *retries*
    re-attempts after any other :class:`RecompileError` with
    ``retryable=True`` (a 5xx other than 503, a lost reply, an unreadable
    artifact download); non-retryable errors (validation, 4xx other than the
    transient set) fail immediately, and ``retries=0`` (default) sends those
    once.  Before each attempt after the first, sleeps with exponential
    backoff (``0.25 * 2**n`` seconds, capped at 8s, *n* counting the waits or
    the retries so far) so a recovering service is not immediately
    re-hammered, or the reply's ``Retry-After`` when that is longer.  A wait
    that would end past *deadline* raises the last error now.

    *gate*, a :class:`ServiceGate` shared by the compiles of a process, runs
    each attempt in one of its slots after its hold-off, and a retryable
    reply's ``Retry-After`` holds the whole gate back, also when this call
    gives up on it; an attempt the gate cannot start before *deadline* raises
    ``kind="deadline"``, unsent.

    *sleep* is that backoff's only time source, the same seam
    :func:`rebrew.decompme.upload_scratch` and
    :func:`rebrew.compiler.headless._wait_for_socket` take: inject a stepper to replay
    a retry sequence from virtual time instead of waiting it out.  The wait
    bound counts what was slept when that runs ahead of the clock, so a stepper
    that returns at once still ends the waits.  Left unset it reads
    :func:`time.sleep` per attempt, so a patched clock is honoured.

    Once the compile POST returns ``status == "ok"``, retries never re-POST:
    Older services may retain assembly output as a side effect, so a lost
    artifact GET only retries the same ``artifact_url``.  A lost or unreadable
    POST reply and a 5xx are resent under the same key with the same body,
    ``emit_assembly`` or not: the service answers a known key with its first
    outcome.  An ``emit_assembly`` compile is retried under a new key only after
    ``capacity``, which the service refused before running it.

    *includes* (bundle path -> header text) and *source_dir* (the source's
    directory in that tree) are the include bundle: the service writes the
    headers at their paths and compiles the source in *source_dir*.  A bundle
    over the service's bounds or not UTF-8 is refused unsent; before the first
    POST the service's ``GET /api/v1/features`` must list ``include-bundles``
    (:func:`accepts_include_bundles`), else the call raises
    :class:`RecompileError` (``kind="validation"``) and nothing is compiled.
    Without a bundle neither field is sent, so an older service still compiles
    the source.

    *attribution*, when given, goes on every compile POST in
    :data:`ATTRIBUTION_HEADER`.
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
    for index, flag in enumerate(flags_list):
        # The service normalizes to NFC before it counts and before it
        # stores, so measure and send that form.  Counting characters let a
        # flag of 200 two-byte code points through and the service answered
        # 422; a decomposed spelling of a flag that composes under the cap
        # must still be sent, in the form the service fingerprints.
        flag = unicodedata.normalize("NFC", flag)
        flags_list[index] = flag
        _require_utf8(flag, "flag")
        flag_bytes = len(flag.encode("utf-8"))
        if flag_bytes > _MAX_FLAG_BYTES:
            shown = flag.replace(configured_key, "[redacted]") if configured_key else flag
            raise RecompileError(
                f"flag too long ({flag_bytes} > {_MAX_FLAG_BYTES} UTF-8 bytes): {shown[:40]}",
                kind="validation",
            )
    _require_utf8(compiler, "compiler")
    _require_utf8(filename, "filename")
    _require_utf8(source, "source")
    bundled = bool(includes) or bool(source_dir)
    if bundled:
        _check_bundle(includes or {}, source_dir)

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
    # The service replays the first outcome of a key (recompile docs/API.md),
    # so the key names this attempt, never its input: a digest of the input
    # made every later compile of an unchanged source a replay of the first.
    post_headers: dict[str, str] = {
        **(auth_headers or {}),
        "Idempotency-Key": secrets.token_hex(_IDEMPOTENCY_KEY_BYTES),
        **({} if attribution is None else {ATTRIBUTION_HEADER: attribution.header_value()}),
    }
    payload: dict[str, Any] = {
        "compiler": compiler,
        "source": source,
        "flags": flags_list,
        "filename": filename,
        "emit_assembly": emit_assembly,
    }
    if bundled:
        payload["source_dir"] = source_dir
        payload["includes"] = [
            {"path": path, "content": text} for path, text in sorted((includes or {}).items())
        ]
    # A bundle goes only to a service that names the feature (checked once, in
    # the first attempt, so a lost reply rides the retry rules below).
    bundle_checked = not bundled

    nap = sleep if sleep is not None else time.sleep
    started = time.monotonic()
    slept = 0.0

    def now() -> float:
        # The clock, or the waits slept when an injected sleep runs ahead of it.
        return max(time.monotonic(), started + slept)

    def wait(seconds: float) -> None:
        nonlocal slept
        slept += seconds
        nap(seconds)

    no_room_until = deadline if deadline is not None else started + NO_DEADLINE_WAIT_SECONDS
    failures = waits = 0
    # Body + artifact_url from a successful compile POST.  Set once; retries
    # only re-GET so a successful compile is not repeated.
    pending: tuple[dict[str, Any], str] | None = None
    # What the current key cost so far (see RecompileError.cost); a new key
    # starts free.
    cost: KeyCost = "free"

    def read(rule: _AnswerRule) -> None:
        nonlocal cost
        if rule.cost is not None:
            cost = rule.cost

    # Stopwatch for the terminal record: how long the run spent on a
    # dependency before giving up, which is the number an operator needs when
    # the service is the thing that changed.
    started_at = time.perf_counter()
    while True:
        if deadline is not None and now() >= deadline:
            refusal = _deadline_refusal("the call's deadline has passed")
            refusal.cost = cost
            raise refusal
        # One client for POST + GET.  Injected clients are not closed here.
        cm: Any = (
            nullcontext(client)
            if client is not None
            else httpx.Client(timeout=timeout, trust_env=False)
        )
        try:
            with gate.attempt(deadline, wait) if gate is not None else nullcontext(), cm as http:
                if not bundle_checked:
                    if not accepts_include_bundles(url, client=http):
                        raise RecompileError(
                            f"recompile service at {safe_url} does not accept include bundles "
                            f"(it does not list {INCLUDE_BUNDLES_FEATURE!r}); upgrade it, "
                            "or compile this source with a local backend",
                            kind="validation",
                        )
                    bundle_checked = True
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
                        rule = (
                            _NOT_SENT
                            if isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout))
                            else _LOST_REPLY
                        )
                        read(rule)
                        raise _answered(
                            f"recompile service at {url} unreachable: {exc}", rule, kind="network"
                        ) from exc
                    try:
                        if resp.status_code != 200:
                            code = _error_code(resp)
                            rule = _answer_rule("compile", resp.status_code, code)
                            read(rule)
                            detail = (
                                resp.text.replace(api_key, "[redacted]") if api_key else resp.text
                            )
                            raise _answered(
                                f"recompile service returned HTTP {resp.status_code}"
                                f"{f' ({code})' if code else ''}: {detail[:300]}",
                                rule,
                                kind="http",
                                status_code=resp.status_code,
                                error_code=code,
                                retry_after=_retry_after(resp.headers.get("Retry-After")),
                            )
                        # A 200 not yet read may be the key's billed result.
                        read(_LOST_REPLY)
                        try:
                            body = resp.json()
                        except Exception as exc:
                            raise RecompileError(
                                f"recompile service returned non-JSON: {exc}",
                                kind="protocol",
                                retryable=True,
                            ) from exc
                        if not isinstance(body, dict):
                            raise RecompileError(
                                f"recompile service returned {type(body).__name__}, "
                                "expected a JSON object",
                                kind="protocol",
                                retryable=True,
                            )
                        status = body.get("status")
                        if status not in ("ok", "error"):
                            raise RecompileError(
                                f"recompile service returned unknown status {status!r}",
                                kind="protocol",
                                retryable=True,
                            )
                        if (status == "ok" and body.get("error_code") is not None) or (
                            status == "error" and body.get("artifact_url") is not None
                        ):
                            raise RecompileError(
                                "recompile service returned contradictory verdict fields",
                                kind="protocol",
                                retryable=True,
                            )
                        if status != "ok":
                            failure_log = str(body.get("log", ""))
                            if api_key:
                                failure_log = failure_log.replace(api_key, "[redacted]")
                            code = body.get("error_code")
                            if not isinstance(code, str) or code not in _COMPILE_FAILURES:
                                raise RecompileError(
                                    "recompile service returned a failed compile with "
                                    f"unknown error_code {code!r}"[:300],
                                    kind="protocol",
                                    retryable=True,
                                )
                            rule = _answer_rule("compile", 200, code)
                            read(rule)
                            if rule.then == "verdict":
                                return RecompileResult(ok=False, log=failure_log)
                            if emit_assembly and code not in _NOT_RUN_FAILURES:
                                # The compile may have run and kept its assembly output.
                                rule = _AnswerRule(rule.cost, "final")
                            raise _answered(
                                f"recompile service could not compile ({code}): "
                                f"{failure_log[:300]}",
                                rule,
                                kind="service",
                                error_code=code,
                                retry_after=_retry_after(resp.headers.get("Retry-After")),
                            )
                        artifact_url = body.get("artifact_url")
                        if not artifact_url:
                            raise RecompileError(
                                'recompile service returned status "ok" with no artifact_url',
                                kind="protocol",
                                retryable=True,
                            )
                        if not isinstance(artifact_url, str):
                            raise RecompileError(
                                f"recompile service returned non-string artifact_url: "
                                f"{artifact_url!r}",
                                kind="protocol",
                                retryable=True,
                            )
                        read(_answer_rule("compile", 200, None))
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
            exc.cost = cost
            then = exc._then or ("retry" if exc.retryable else "final")
            if api_key:
                exc.args = (str(exc).replace(api_key, "[redacted]"),)
                exc.__cause__ = None
                exc.__context__ = None
                exc.__suppress_context__ = True
            # The service's Retry-After holds back every compile the gate
            # paces, the next call's as well as this call's next attempt: a
            # call that gives up here must not let the next one send at once.
            if exc.retryable and exc.retry_after and gate is not None:
                gate.hold_off(exc.retry_after)
            # An answer that asks to wait is waited out until the deadline;
            # another retryable one spends a retry.
            no_room = then in ("wait", "new_key_wait")
            if no_room:
                waits += 1
            else:
                failures += 1
            if not exc.retryable or (not no_room and failures > retries):
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
                    failures + waits,
                    time.perf_counter() - started_at,
                    exc.kind,
                    "" if exc.status_code is None else f" {exc.status_code}",
                    retry_log_detail(exc),
                )
                raise
            if then in ("new_key", "new_key_wait"):
                # The service answered this attempt, and a hosted recompile
                # keeps the answer under its key, or says the key can never
                # yield a result: the retry is a new attempt.
                post_headers["Idempotency-Key"] = secrets.token_hex(_IDEMPOTENCY_KEY_BYTES)
                cost = "free"
            # Immediate re-POST of a 503/timeout hammers a recovering service;
            # exponential backoff (capped) gives it room without unbounded wait,
            # and a Retry-After the service named is the least it is given.  With
            # a gate the Retry-After holds the gate, and the next attempt waits it
            # out there with every other compile of the process.
            delay = retry_backoff_delay((waits if no_room else failures) - 1)
            if exc.retry_after and gate is None:
                delay = max(delay, exc.retry_after)
            resumes = now() + max(delay, exc.retry_after or 0.0)
            until = no_room_until if no_room else deadline
            if until is not None and resumes > until:
                log.warning(
                    "recompile %s gave up after %d attempt(s) over %.1fs: its next attempt "
                    "would start past %s (%s%s): %s",
                    safe_url,
                    failures + waits,
                    time.perf_counter() - started_at,
                    "the call's deadline" if deadline is not None else "the wait for room",
                    exc.kind,
                    "" if exc.status_code is None else f" {exc.status_code}",
                    retry_log_detail(exc),
                )
                raise
            if no_room:
                # One line when the wait starts; a wait of many attempts is
                # summed up by the line that ends it.
                (log.warning if waits == 1 else log.debug)(
                    "recompile %s has no room for the compile (%s%s), waiting %.2fs and "
                    "trying again until %s: %s",
                    safe_url,
                    exc.kind,
                    "" if exc.status_code is None else f" {exc.status_code}",
                    max(delay, exc.retry_after or 0.0),
                    "the call's deadline"
                    if deadline is not None
                    else f"{NO_DEADLINE_WAIT_SECONDS} s have passed",
                    retry_log_detail(exc),
                )
            else:
                # One line per retry, before the sleep: a remote backend that is
                # failing and recovering otherwise spends the backoff in silence,
                # so a `rebrew test` run against a flaky service looks hung with no
                # record of which dependency is faulting or how long the wait is.
                log.warning(
                    "recompile %s attempt %d/%d failed (%s%s), retrying in %.2fs: %s",
                    safe_url,
                    failures,
                    retries + 1,
                    exc.kind,
                    "" if exc.status_code is None else f" {exc.status_code}",
                    delay,
                    retry_log_detail(exc),
                )
            wait(delay)


__all__ = [
    "ATTRIBUTION_HEADER",
    "ATTRIBUTION_MEMBER_MAX_CHARS",
    "COMPILER_NOT_INSTALLED",
    "INCLUDE_BUNDLES_FEATURE",
    "MAX_INCLUDE_FILES",
    "MAX_INCLUDE_FILE_BYTES",
    "MAX_INCLUDE_PATH_BYTES",
    "MAX_INCLUDE_TOTAL_BYTES",
    "MAX_RETRY_AFTER_SECONDS",
    "NO_DEADLINE_WAIT_SECONDS",
    "Attribution",
    "HttpClient",
    "HttpResponse",
    "KeyCost",
    "RecompileError",
    "RecompileErrorKind",
    "RecompileResult",
    "ServiceGate",
    "accepts_include_bundles",
    "compile_source",
    "installed_compilers",
]
