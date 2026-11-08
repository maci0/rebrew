"""telemetry.py — W3C trace context and OTLP/JSON span export, standard library only.

A span continues the caller's ``traceparent`` (the relumea backend sends one on every
dispatch call) and finished spans queue for a background thread that posts them to an
OTLP/HTTP collector (``<endpoint>/v1/traces``).  Without :func:`configure` spans still
carry context, so the outgoing ``traceparent`` of a request stays correct, but nothing is
exported.  A full queue drops spans; a request never waits for the collector.

The exporter is deliberately not the OpenTelemetry SDK: the SDK and its OTLP exporter add
protobuf and several packages to a worker that otherwise needs none.
"""

from __future__ import annotations

import contextlib
import contextvars
import logging
import queue
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
lazy import json
lazy import os
lazy import re
lazy import time
lazy import urllib.request
lazy from collections.abc import Callable, Iterator
lazy from typing import Any
lazy from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

#: Environment variable holding the collector's OTLP/HTTP base URL; unset leaves export off.
ENDPOINT_ENV = "REBREW_OTLP_ENDPOINT"

#: Environment variable that hands the open span to a child process (the W3C trace context variable).
TRACEPARENT_ENV = "TRACEPARENT"

#: Finished spans waiting for the exporter before new ones are dropped.
QUEUE_SIZE = 4096
#: Most spans one export request carries.
BATCH_SIZE = 256
#: Longest a finished span waits for a fuller batch, in seconds.
FLUSH_INTERVAL_SECONDS = 2.0
#: Seconds one export request may take.
EXPORT_TIMEOUT_SECONDS = 3.0
#: Seconds :func:`configure`'s shutdown waits for the queue to drain.
SHUTDOWN_SECONDS = 5.0

#: OTLP ``SpanKind`` and ``StatusCode`` values.
KIND_INTERNAL = 1
KIND_SERVER = 2
KIND_CLIENT = 3
STATUS_ERROR = 2

_TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")
_ZERO_TRACE = "0" * 32
_ZERO_SPAN = "0" * 16

type Attribute = str | int | float | bool


# ---------------------------------------------------------------------------
# Spans
# ---------------------------------------------------------------------------


@dataclass
class Span:
    """One timed operation; ``traceparent`` is what a child call sends."""

    name: str
    kind: int
    trace_id: str
    span_id: str
    parent_id: str
    start_ns: int
    attributes: dict[str, Attribute] = field(default_factory=dict)
    error: str | None = None
    end_ns: int = 0

    def set(self, key: str, value: Attribute) -> None:
        """Record one attribute."""
        self.attributes[key] = value

    def fail(self, message: str) -> None:
        """Mark the span failed; ``message`` must not carry request data."""
        self.error = message

    @property
    def traceparent(self) -> str:
        """The W3C ``traceparent`` header value naming this span as the parent."""
        return f"00-{self.trace_id}-{self.span_id}-01"


_current: contextvars.ContextVar[Span | None] = contextvars.ContextVar("rebrew_span", default=None)


def current() -> Span | None:
    """The innermost open span of this thread, or ``None``."""
    return _current.get()


def valid_traceparent(value: str | None) -> bool:
    """Whether ``value`` is a version-00 ``traceparent`` with non-zero trace and span ids."""
    match = _TRACEPARENT.match(value or "")
    return match is not None and match[1] != _ZERO_TRACE and match[2] != _ZERO_SPAN


def child_environment() -> dict[str, str]:
    """The environment a child process needs to continue the open span: empty outside one."""
    opened = current()
    return {} if opened is None else {TRACEPARENT_ENV: opened.traceparent}


@contextmanager
def span(name: str, *, kind: int = KIND_INTERNAL, traceparent: str | None = None) -> Iterator[Span]:
    """Open a span under ``traceparent`` (a valid inbound header) or the current span.

    An invalid inbound header is ignored and starts a new trace.  An exception marks the
    span failed and propagates.
    """
    parent = current()
    inbound = _TRACEPARENT.match(traceparent or "")
    if inbound is not None and valid_traceparent(traceparent):
        trace_id, parent_id = inbound[1], inbound[2]
    elif parent is not None:
        trace_id, parent_id = parent.trace_id, parent.span_id
    else:
        trace_id, parent_id = os.urandom(16).hex(), ""
    opened = Span(name, kind, trace_id, os.urandom(8).hex(), parent_id, time.time_ns())
    token = _current.set(opened)
    try:
        yield opened
    except BaseException as exc:
        opened.fail(type(exc).__name__)
        raise
    finally:
        _current.reset(token)
        opened.end_ns = time.time_ns()
        exporter = _exporter
        if exporter is not None:
            exporter.submit(opened)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def _value(value: Attribute) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": value}


def _wire(opened: Span) -> dict[str, Any]:
    wire: dict[str, Any] = {
        "traceId": opened.trace_id,
        "spanId": opened.span_id,
        "name": opened.name,
        "kind": opened.kind,
        "startTimeUnixNano": str(opened.start_ns),
        "endTimeUnixNano": str(opened.end_ns),
        "attributes": [{"key": k, "value": _value(v)} for k, v in opened.attributes.items()],
    }
    if opened.parent_id:
        wire["parentSpanId"] = opened.parent_id
    if opened.error is not None:
        wire["status"] = {"code": STATUS_ERROR, "message": opened.error}
    return wire


class _Exporter:
    def __init__(self, endpoint: str, service: str, version: str) -> None:
        self._url = f"{endpoint}/v1/traces"
        self._resource = {
            "attributes": [
                {"key": "service.name", "value": {"stringValue": service}},
                {"key": "service.version", "value": {"stringValue": version}},
            ]
        }
        self._queue: queue.Queue[Span | None] = queue.Queue(QUEUE_SIZE)
        self._thread = threading.Thread(target=self._run, name="rebrew-otlp", daemon=True)
        self._thread.start()

    def submit(self, opened: Span) -> None:
        # A full queue drops the span: a request never waits for the collector.
        with contextlib.suppress(queue.Full):
            self._queue.put_nowait(opened)

    def close(self) -> None:
        self._queue.put(None)
        self._thread.join(SHUTDOWN_SECONDS)

    def _run(self) -> None:
        done = False
        while not done:
            batch: list[Span] = []
            try:
                item = self._queue.get(timeout=FLUSH_INTERVAL_SECONDS)
            except queue.Empty:
                continue
            while True:
                if item is None:
                    done = True
                    break
                batch.append(item)
                if len(batch) >= BATCH_SIZE:
                    break
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
            if batch:
                self._post(batch)

    def _post(self, batch: list[Span]) -> None:
        body = json.dumps(
            {
                "resourceSpans": [
                    {
                        "resource": self._resource,
                        "scopeSpans": [
                            {"scope": {"name": "rebrew"}, "spans": [_wire(s) for s in batch]}
                        ],
                    }
                ]
            }
        ).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310  # configure() admits http(s) only
            self._url, body, {"Content-Type": "application/json"}, method="POST"
        )
        # An opener with no ProxyHandler: the collector is operator-configured, so
        # ambient `*_proxy` / `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` must not reroute
        # or re-TLS the span POST (matching the pinned downloaders' `trust_env=False`).
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=EXPORT_TIMEOUT_SECONDS):
                pass
        except OSError as exc:
            logger.warning("trace export failed: %s", type(exc).__name__)


_exporter: _Exporter | None = None


def configure(endpoint: str, service: str, version: str) -> Callable[[], None]:
    """Start exporting to the OTLP/HTTP collector at ``endpoint``; returns the shutdown.

    Raises :class:`ValueError` for an endpoint that is not an ``http(s)`` URL with a host.
    """
    global _exporter
    parts = urlsplit(endpoint)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username:
        raise ValueError(f"{ENDPOINT_ENV} must be an http(s) URL without credentials")
    exporter = _Exporter(endpoint.rstrip("/"), service, version)
    _exporter = exporter

    def shutdown() -> None:
        global _exporter
        _exporter = None
        exporter.close()

    return shutdown


def configure_from_env(service: str, version: str) -> Callable[[], None]:
    """:func:`configure` from :data:`ENDPOINT_ENV`; a no-op shutdown when it is unset."""
    endpoint = os.environ.get(ENDPOINT_ENV, "").strip()
    if not endpoint:
        return lambda: None
    return configure(endpoint, service, version)
