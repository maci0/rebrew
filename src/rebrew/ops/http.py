"""HTTP worker transport, admission caps, bearer auth, progress streaming, and metrics."""

from __future__ import annotations

import contextlib
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import override
lazy import hmac
lazy import select
lazy import socket
lazy import sys
lazy import time
lazy import traceback
lazy import typing
lazy from collections.abc import Callable, Collection, Mapping
lazy from email.utils import formatdate
lazy from typing import Any
lazy from urllib.parse import urlsplit

lazy import msgspec

from rebrew.ops.core import (
    BUSY_RETRY_AFTER_SECONDS,
    CALLER_GONE,
    CANCEL_POLL_SECONDS,
    CANCELLATION_VAR,
    CROSS_ORIGIN,
    DNS_TIMEOUT_SECONDS,
    ENGINE_ERROR,
    EXITS,
    HOST_NOT_ALLOWED,
    INVALID_REQUEST,
    LATENCY_BUCKETS_MS,
    MAX_CONNECTIONS,
    MAX_REQUEST_BYTES,
    METHOD_NOT_ALLOWED,
    PROGRESS_MEDIA_TYPE,
    PROGRESS_VAR,
    REPLY_HEADERS_VAR,
    REQUEST_IDS,
    SOCKET_TIMEOUT_SECONDS,
    TIMEOUT_HEADER,
    UNAUTHORIZED,
    UNKNOWN_OP,
    WORKER_BUSY,
    Cancellation,
    WorkerConfig,
    bounded,
    error_body,
    escape_log_text,
    logger,
    ops_binding,
    progress_frame,
    request_id,
    stamp_request,
    trace_id,
)
lazy from rebrew import telemetry
lazy from rebrew.utils import fold_host

_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
)
_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"


def allowed_hosts_for(host: str, port: int) -> frozenset[str]:
    """Host-header values the ops server must answer (DNS-rebinding guard).

    Mirrors the dashboard's allow-list: loopback binds accept their numeric
    and localhost aliases; a wildcard bind also accepts the machine's own
    addresses. Anything else gets 403 before the bearer check.
    """
    wildcard = host in ("0.0.0.0", "::", "")
    loopback = wildcard or host in ("127.0.0.1", "localhost", "::1")
    names = {host} if host else set()
    if loopback:
        names |= {"127.0.0.1", "localhost", "::1"}
    if wildcard:
        # getaddrinfo blocks with no timeout: a hung resolver would pin server
        # startup for the kernel timeout, so resolve on a thread and fall back
        # to loopback aliases (see DNS_TIMEOUT_SECONDS).
        _result: list[Any] = []
        _error: list[BaseException] = []

        def _resolve() -> None:
            try:
                import socket as _socket

                _result.append(_socket.getaddrinfo(_socket.gethostname(), None))
            except BaseException as exc:
                _error.append(exc)

        _thread = threading.Thread(target=_resolve, daemon=True)
        _thread.start()
        _thread.join(DNS_TIMEOUT_SECONDS)
        if _thread.is_alive():
            logger.warning(
                "ops: local interface resolution timed out after %ss; "
                "host allow-list falls back to loopback aliases",
                DNS_TIMEOUT_SECONDS,
            )
        elif _error:
            logger.warning(
                "ops: local interface resolution failed (%s); "
                "host allow-list falls back to loopback aliases",
                _error[0],
            )
        else:
            names |= {str(info[4][0]) for info in _result[0] if info[4]}
    hosts: set[str] = set()
    for name in names:
        display = f"[{name}]" if ":" in name else name
        hosts.add(fold_host(f"{display}:{port}"))
        if port == 80:
            hosts.add(fold_host(display))
    return frozenset(hosts)


class OpsServer(ThreadingHTTPServer):
    """HTTP server answering ``POST /<op>`` for one worker configuration and token.

    At most *concurrency* calls hold a slot at once, from reading the body
    to writing the reply; a call finding none free is answered 503.

    *answer* answers every ``POST /<name>`` with ``(status, reply)`` from the
    worker configuration, the name and the body; *ops* is the op names it
    serves, which bound the per-op metrics and the span names (any other name
    is ``/unknown``) and decide a non-POST answer: 405 ``Allow: POST`` for a
    served op, 404 otherwise.  Both default to rebrew's own (:data:`OPS`,
    :func:`dispatch`); another engine passes its op table and dispatcher.

    Carries request metrics (see :meth:`record_request` and
    :meth:`metrics_snapshot`) behind ``/health`` and ``/metrics`` on the
    same port: counters plus latency, so an operator can pivot from a
    metric anomaly to the access lines that name the op and its id.

    A graceful stop is :meth:`request_stop` (from a signal handler: refuse new
    calls and end :meth:`serve_forever`), then :meth:`drain` (wait for the calls
    in flight).
    """

    daemon_threads = True
    #: Instance-level so tests and embedded engines can lower the admission cap.
    _max_connections = MAX_CONNECTIONS

    def __init__(
        self,
        address: tuple[str, int],
        config: WorkerConfig,
        token: str,
        concurrency: int,
        allowed_hosts: frozenset[str] = frozenset(),
        *,
        ops: Collection[str] | None = None,
        answer: Callable[[WorkerConfig, str, bytes], tuple[int, bytes]] | None = None,
    ) -> None:
        super().__init__(address, OpsHandler)
        try:
            if ops is None:
                ops = ops_binding("OPS", {}).keys()
            if answer is None:
                answer = ops_binding("dispatch", None)
            self.config = config
            self.ops = frozenset(ops)
            self.answer = answer
            self.token = token
            self.slots = threading.BoundedSemaphore(concurrency)
            self._active = 0
            self._connections = 0
            self._connections_lock = threading.Lock()
            self._draining = False
            self._idle = threading.Condition()
            self.allowed_hosts = (
                ops_binding("_allowed_hosts_for", allowed_hosts_for)(
                    address[0], self.server_address[1]
                )
                | allowed_hosts
            )
            self._metrics_lock = threading.Lock()
            self._request_count = 0
            self._error_count = 0
            self._server_error_count = 0
            self._client_error_count = 0
            self._latency_ms_total = 0.0
            self._latency_ms_max = 0.0
            self._latency_ms_buckets = [0] * len(LATENCY_BUCKETS_MS)
            self._started_at = ops_binding("time", time).monotonic()
            self._busy_refusals = 0
            # Faults that escaped a handler thread.  ``record_request`` never sees
            # them (``send_response`` did not run), so without this counter a
            # handler that crashes on every call leaves /health and /metrics at
            # zero errors while the process dumps tracebacks.
            self._unhandled_errors = 0
            self.concurrency = concurrency
            # Per-op breakdown, bounded by the op set: one entry per known op
            # plus "/unknown" for paths outside it.  Without it a metric anomaly
            # cannot say which op is slow or failing; the access line names the
            # op but no counter does.
            self._per_op: dict[str, dict[str, float]] = {}
        except BaseException:
            # TCPServer has already bound and activated its socket. A failure in
            # post-bind setup must not leave that descriptor behind for a caller
            # that never received a server object to close.
            self.server_close()
            raise

    @override
    def process_request(self, request: Any, client_address: Any) -> None:
        """Bound accepted sockets before ``ThreadingHTTPServer`` spawns a thread."""
        with self._connections_lock:
            active = self._connections
            if active < self._max_connections:
                self._connections += 1
                refused = None
            else:
                refused = active
        if refused is not None:
            self._refuse_connection(request, client_address, refused)
            self.shutdown_request(request)
            return
        # The handler releases the slot. If its thread never starts, this accept
        # path must return the slot instead of permanently reducing the cap.
        handed_off = False
        try:
            super().process_request(request, client_address)
            handed_off = True
        finally:
            if not handed_off:
                with self._connections_lock:
                    self._connections -= 1

    @override
    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._connections_lock:
                self._connections -= 1

    def _refuse_connection(self, request: Any, client_address: Any, active: int) -> None:
        """Answer one over-cap connection without creating a handler thread."""
        request_id = f"r{next(REQUEST_IDS)}"
        detail = (
            f"too many connections in flight ({active} of {self._max_connections}); retry shortly"
        )
        body = error_body(WORKER_BUSY, detail, 503)
        with self._metrics_lock:
            self._busy_refusals += 1
        self.record_request(503, 0.0, "/unknown")
        logger.warning(
            "%s refusing connection from %s trace_id=%s: %d already in flight (cap %d)",
            request_id,
            escape_log_text(str(client_address)),
            trace_id(),
            active,
            self._max_connections,
        )
        if not isinstance(request, socket.socket):
            return
        lines = [
            "HTTP/1.1 503 Service Unavailable",
            f"Date: {formatdate(usegmt=True)}",
            f"Retry-After: {BUSY_RETRY_AFTER_SECONDS}",
            "Content-Type: application/json; charset=utf-8",
            f"Content-Length: {len(body)}",
            "Connection: close",
            f"X-Request-Id: {request_id}",
            *[f"{name}: {value}" for name, value in _SECURITY_HEADERS],
            f"Content-Security-Policy: {_CSP}",
        ]
        try:
            request.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
        except OSError as exc:
            logger.info(
                "%s client vanished before the refusal reached it trace_id=%s: %s",
                request_id,
                trace_id(),
                exc,
            )

    def request_stop(self) -> None:
        """Refuse every new call 503 and end :meth:`serve_forever`; later calls change nothing.

        Safe from a signal handler: the shutdown runs on its own thread.
        """
        with self._idle:
            if self._draining:
                return
            self._draining = True
        threading.Thread(target=self.shutdown, daemon=True).start()

    def drain(self, timeout: float) -> int:
        """Refuse every new call and wait up to *timeout* seconds for those in flight.

        Returns how many are still in flight, 0 once all have answered.
        """
        with self._idle:
            self._draining = True
            self._idle.wait_for(lambda: self._active == 0, timeout=timeout)
            return self._active

    def record_request(self, code: int, elapsed_ms: float, op: str = "/unknown") -> None:
        with self._metrics_lock:
            self._request_count += 1
            entry = self._per_op.setdefault(
                op, {"count": 0.0, "server_errors": 0.0, "client_errors": 0.0, "latency_ms": 0.0}
            )
            entry["count"] += 1
            entry["latency_ms"] += elapsed_ms
            if code >= 500:
                entry["server_errors"] += 1
            elif code >= 400:
                entry["client_errors"] += 1
            self._latency_ms_total += elapsed_ms
            self._latency_ms_max = max(self._latency_ms_max, elapsed_ms)
            for index, bound in enumerate(LATENCY_BUCKETS_MS):
                if elapsed_ms <= bound:
                    self._latency_ms_buckets[index] += 1
                    break
            else:
                self._latency_ms_buckets[-1] += 1
            if code >= 500:
                self._server_error_count += 1
                self._error_count += 1
            elif code >= 400:
                self._client_error_count += 1
                self._error_count += 1

    def record_unhandled(self) -> None:
        """Count a handler fault that escaped before a response was written."""
        with self._metrics_lock:
            self._unhandled_errors += 1

    @override
    def handle_error(self, request: Any, client_address: Any) -> None:
        """Log a handler fault with its request id instead of a bare traceback.

        ``socketserver.BaseServer.handle_error`` prints a rule-bracketed
        traceback straight to stderr: no stamp, no level, no correlation id,
        and no counter, so an operator cannot join it to the request that
        raised it and ``/health`` keeps reporting zero errors.  Mirrors the
        dashboard: a peer that went away is INFO with no count, a handler
        timeout is a WARNING with no count, and anything else is an ERROR
        with its traceback that counts as an unhandled fault.
        """
        exc = sys.exc_info()[1]
        req_id = request_id()
        peer = escape_log_text(str(client_address))
        if isinstance(exc, ConnectionError):
            logger.info(
                "%s client disconnected trace_id=%s: %s",
                req_id,
                trace_id(),
                type(exc).__name__,
            )
            return
        if isinstance(exc, TimeoutError):
            logger.warning(
                "%s handler timed out serving %s trace_id=%s: %s",
                req_id,
                peer,
                trace_id(),
                type(exc).__name__,
            )
            return
        self.record_unhandled()
        logger.error(
            "%s unhandled %s serving %s trace_id=%s\n%s",
            req_id,
            type(exc).__name__,
            peer,
            trace_id(),
            escape_log_text(traceback.format_exc().rstrip()),
        )

    def metrics_snapshot(
        self,
    ) -> tuple[dict[str, float | int], list[int], dict[str, dict[str, float]]]:
        with self._metrics_lock:
            return (
                {
                    "request_count": self._request_count,
                    "error_count": self._error_count,
                    "server_error_count": self._server_error_count,
                    "client_error_count": self._client_error_count,
                    "latency_ms_total": self._latency_ms_total,
                    "latency_ms_max": self._latency_ms_max,
                    "latency_ms_avg": (self._latency_ms_total / self._request_count)
                    if self._request_count
                    else 0.0,
                    "in_flight": self._active,
                    "busy_refusals": self._busy_refusals,
                    "unhandled_errors": self._unhandled_errors,
                    "uptime_seconds": ops_binding("time", time).monotonic() - self._started_at,
                },
                list(self._latency_ms_buckets),
                {op: dict(entry) for op, entry in self._per_op.items()},
            )


def accepts_progress(accept: str) -> bool:
    """Whether an ``Accept`` header names :data:`PROGRESS_MEDIA_TYPE`."""
    return any(
        part.split(";", 1)[0].strip().lower() == PROGRESS_MEDIA_TYPE for part in accept.split(",")
    )


class ProgressStream:
    """A ``serve`` answer as :data:`PROGRESS_MEDIA_TYPE`, started by the call's first count.

    A call that reports no count is answered as plain JSON, as to any other caller.
    """

    def __init__(self, handler: OpsHandler, cancellation: Cancellation) -> None:
        self._handler = handler
        self._cancellation = cancellation
        self.started = False

    def send(self, done: int, total: int) -> None:
        """Write one count, starting the answer on the first; a caller gone cancels the call."""
        try:
            if not self.started:
                self.started = True
                self._handler._start_stream()
            self._handler.wfile.write(progress_frame(done, total))
        except OSError:
            self._cancellation.cancel("the caller closed the connection", CALLER_GONE, 499)

    def finish(self, status: int, reply: bytes, headers: Mapping[str, str]) -> None:
        """Write the last line: the call's status, its ``Retry-After`` seconds when named, and its reply."""
        head: dict[str, Any] = {"status": status}
        if (retry := headers.get("Retry-After")) is not None:
            head["retry_after"] = int(retry)
        last = msgspec.json.encode(head)[:-1] + b', "reply": ' + reply + b"}\n"
        self._handler.wfile.write(last)
        self._handler._record_answer(status)


class OpsHandler(BaseHTTPRequestHandler):
    timeout: typing.ClassVar[float | None] = SOCKET_TIMEOUT_SECONDS
    #: Correlation id of the request in flight; stamped per request in
    #: ``handle_one_request`` so a keep-alive connection never reuses one.
    request_id: str = "-"
    #: Wall-clock start of the request in flight, for the access line.
    _request_started: float = 0.0

    @override
    def handle_one_request(self) -> None:  # (http.server API)
        self._request_started = time.perf_counter()
        self.request_id = f"r{next(REQUEST_IDS)}"
        stamp_request(self.request_id)
        super().handle_one_request()

    @override
    def log_request(
        self, code: int | str = "-", size: int | str = "-"
    ) -> None:  # (http.server API)
        """One INFO access line per answered request: id, op, status, and time.

        ``send_response`` calls this, so every refusal and reply logs exactly
        once.  The op comes from the request path (remote text, escaped);
        the elapsed time is the one number that says the engine, not the
        network, is what a slow call spent its time on.
        """
        elapsed_ms = (time.perf_counter() - self._request_started) * 1000.0
        op = (
            escape_log_text(urlsplit(getattr(self, "path", "") or "").path.removeprefix("/")) or "-"
        )
        logger.info(
            "%s %s %s %s %.1fms trace_id=%s",
            self.request_id,
            op,
            code,
            size,
            elapsed_ms,
            trace_id(),
        )

    @override
    def log_message(self, fmt: str, *args: Any) -> None:  # (http.server API)
        """Drop the stdlib's default access line: ``log_request`` already logs it.

        ``BaseHTTPRequestHandler.log_request`` delegates here, so without
        this the request would appear twice — once on the console in the
        stdlib format, once as the correlated ``logger`` record above.
        """

    @override
    def send_response(self, code: int, message: str | None = None) -> None:
        self._record_answer(code)
        self._send_status_line(code, message)

    def _record_answer(self, code: int) -> None:
        """Count, log and trace the answer's status; a progress stream does it when it ends."""
        elapsed_ms = (time.perf_counter() - self._request_started) * 1000.0
        with contextlib.suppress(AttributeError):
            raw_path = urlsplit(getattr(self, "path", "") or "").path
            op_name = raw_path.removeprefix("/")
            server = typing.cast("OpsServer", self.server)
            route = f"/{op_name}" if op_name in server.ops else "/unknown"
            server.record_request(code, elapsed_ms, route)
        self.log_request(code, getattr(self, "_response_size", "-"))
        opened = telemetry.current()
        if opened is not None and opened.kind == telemetry.KIND_SERVER:
            opened.set("http.response.status_code", int(code))
            if code >= 500:
                opened.fail(f"status {code}")

    def _send_status_line(self, code: int, message: str | None = None) -> None:
        # No Server banner: BaseHTTPRequestHandler would emit the Python
        # patch level to any caller that can reach the worker.
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())
        self.send_header("X-Request-Id", self.request_id)

    def _start_stream(self) -> None:
        """Send the head of a 200 :data:`PROGRESS_MEDIA_TYPE` answer, which ends when the connection closes."""
        self._send_status_line(200)
        self.send_header("Content-Type", PROGRESS_MEDIA_TYPE)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        for name, value in _SECURITY_HEADERS:
            self.send_header(name, value)
        self.send_header("Content-Security-Policy", _CSP)
        self.end_headers()
        self.close_connection = True

    @override
    def send_error(  # (http.server API)
        self, code: int, message: str | None = None, explain: str | None = None
    ) -> None:
        # http.server's own errors (400/414/431/505) must not leak the
        # stdlib HTML page or the request line; answer with the JSON envelope.
        # 501 means a method with no do_* handler (e.g. TRACE): route it
        # through _not_post so a known op answers 405 with Allow and an
        # unknown path 404, matching the GET/HEAD path instead of a 501
        # that no client of an ops endpoint can act on.
        if code == 501 and self.command:  # NOT_IMPLEMENTED
            self._not_post()
            return
        logger.log(
            logging.ERROR if code >= 500 else logging.WARNING,
            "%s rejected %s: code %d trace_id=%s",
            self.request_id,
            escape_log_text(getattr(self, "requestline", "") or "-"),
            code,
            trace_id(),
        )
        status = int(code)
        body = error_body(INVALID_REQUEST, "invalid request", status)
        self._response_size = len(body)
        self.send_response(status)
        self.send_header("Connection", "close")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for _name, _value in _SECURITY_HEADERS:
            self.send_header(_name, _value)
        self.send_header("Content-Security-Policy", _CSP)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send(
        self,
        status: int,
        body: bytes,
        headers: Mapping[str, str] | None = None,
        *,
        content_type: str = "application/json",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in _SECURITY_HEADERS:
            self.send_header(name, value)
        self.send_header("Content-Security-Policy", _CSP)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _refuse(self, code: str, detail: str, status: int) -> None:
        headers = {"WWW-Authenticate": 'Bearer realm="rebrew-ops"'} if status == 401 else None
        self._send(status, error_body(code, detail, status), headers)

    def _check_host(self, server: OpsServer) -> bool:
        if fold_host(self.headers.get("Host", "").strip()) in server.allowed_hosts:
            return True
        peer = getattr(self, "client_address", None)
        logger.warning(
            "%s rejected request with Host %r from %s trace_id=%s",
            self.request_id,
            escape_log_text(self.headers.get("Host", "")) or "-",
            escape_log_text(str(peer[0]) if peer else "-"),
            trace_id(),
        )
        self._refuse(
            HOST_NOT_ALLOWED, "request Host not allowed (wrong or missing Host header)", 403
        )
        return False

    def do_POST(self) -> None:  # (http.server API)
        name = urlsplit(self.path).path.removeprefix("/")
        served = typing.cast("OpsServer", self.server).ops
        route = f"/{name}" if name in served else "/unknown"  # the route is bounded by the op set
        with telemetry.span(
            f"POST {route}",
            kind=telemetry.KIND_SERVER,
            traceparent=self.headers.get("traceparent"),
        ) as opened:
            opened.set("http.request.method", "POST")
            opened.set("http.route", route)
            opened.set("rebrew.request_id", self.request_id)
            self._post()

    def _post(self) -> None:
        server = typing.cast("OpsServer", self.server)
        if not self._check_host(server):
            return
        # CSRF defense-in-depth: a browser sending a POST carries
        # Origin/Referer; a non-browser client (httpx, curl) does not. The
        # bearer check below is the real auth, but refusing a browser-origin
        # POST outright means a malicious page cannot probe the token with a
        # cross-origin form even if the token were somehow ambient.
        if self._cross_origin_browser_post():
            logger.warning("%s rejected cross-origin browser POST", self.request_id)
            self._refuse(CROSS_ORIGIN, "cross-origin browser POST is not allowed", 403)
            return
        # /health and /metrics are GET/HEAD on this server: a POST is a
        # wrong method for a served resource (405), not an unknown op (404).
        # Other paths fall through to the server's answer, which refuses a name
        # outside its ops (dispatch: 404).
        if urlsplit(self.path).path in ("/health", "/metrics"):
            self._send(
                405,
                error_body(METHOD_NOT_ALLOWED, "health and metrics are served with GET, HEAD", 405),
                {"Allow": "GET, HEAD"},
            )
            return
        given = self.headers.get("Authorization", "").encode("utf-8")
        if not hmac.compare_digest(given, f"Bearer {server.token}".encode()):
            logger.warning(
                "%s rejected unauthenticated request trace_id=%s",
                self.request_id,
                trace_id(),
            )
            self._refuse(UNAUTHORIZED, "a valid bearer token is required", 401)
            return
        with server._idle:
            admitted = not server._draining and server.slots.acquire(blocking=False)
            if admitted:
                server._active += 1
        if not admitted:
            with server._metrics_lock:
                server._busy_refusals += 1
            logger.warning("%s worker busy; returning 503 trace_id=%s", self.request_id, trace_id())
            body = error_body(WORKER_BUSY, "every worker slot is busy; retry later", 503)
            self._send(503, body, {"Retry-After": str(BUSY_RETRY_AFTER_SECONDS)})
            return
        try:
            self._answer(server)
        finally:
            with server._idle:
                server._active -= 1
                server.slots.release()
                server._idle.notify_all()

    def _cross_origin_browser_post(self) -> bool:
        """True when the request carries a browser Origin/Referer header.

        Browsers always send Origin on cross-origin POSTs and Referer on
        same-origin ones; a non-browser HTTP client sends neither.  Refusing
        the browser case costs nothing for legitimate callers (ops clients are
        httpx) and stops a malicious page from reaching the bearer check.
        """
        origin = self.headers.get("Origin")
        if origin is not None:
            # Any Origin value means a browser cross-origin (or same-origin
            # fetch) POST; server-to-server clients do not send it.
            return bool(origin.strip())
        referer = self.headers.get("Referer")
        return referer is not None and bool(referer.strip())

    def _answer(self, server: OpsServer) -> None:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        # CSRF defense-in-depth happens in _post before auth; this guard keeps
        # _answer safe if a future caller reaches it without _post's check.
        if self.headers.get("Origin") is not None or self.headers.get("Referer") is not None:
            self._refuse(CROSS_ORIGIN, "cross-origin browser POST is not allowed", 403)
            return
        if content_type != "application/json":
            self._refuse(INVALID_REQUEST, "Content-Type must be application/json", 415)
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._refuse(INVALID_REQUEST, "Content-Length is required", 411)
            return
        if not 0 <= length <= MAX_REQUEST_BYTES:
            self._refuse(INVALID_REQUEST, f"request exceeds {MAX_REQUEST_BYTES} bytes", 413)
            return
        cancellation = Cancellation()
        if (seconds := self.headers.get(TIMEOUT_HEADER)) is not None:
            try:
                budget = float(seconds)
            except ValueError:
                budget = 0.0
            if not 0 < budget < float("inf"):
                self._refuse(INVALID_REQUEST, f"{TIMEOUT_HEADER} must be positive seconds", 400)
                return
            cancellation.limit(
                ops_binding("time", time).monotonic() + budget,
                f"the call outlived its {TIMEOUT_HEADER}",
            )
        # Read in chunks under the same bound so a stalled or truncated
        # stream cannot leave a half-read buffer queued behind the socket
        # timeout: each chunk is a fresh read, and the total never exceeds
        # the declared length that was already validated above.
        chunks: list[bytes] = []
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                self._refuse(INVALID_REQUEST, "request body truncated", 400)
                return
            chunks.append(chunk)
            remaining -= len(chunk)
        body = b"".join(chunks)
        answered = threading.Event()
        watcher = threading.Thread(
            target=self._watch_caller, args=(cancellation, answered), daemon=True
        )
        token = CANCELLATION_VAR.set(cancellation)
        stream = (
            ProgressStream(self, cancellation)
            if accepts_progress(self.headers.get("Accept", ""))
            else None
        )
        progress = PROGRESS_VAR.set(None if stream is None else stream.send)
        headers: dict[str, str] = {}
        replied = REPLY_HEADERS_VAR.set(headers)
        watcher.start()
        try:
            status, reply = server.answer(
                server.config, urlsplit(self.path).path.removeprefix("/"), body
            )
        except EXITS:
            raise
        except BaseException:  # no call ends without a reply
            logger.exception("%s answer failed trace_id=%s", self.request_id, trace_id())
            server.record_unhandled()
            status = 500
            reply = error_body(ENGINE_ERROR, "the engine failed while answering this call", 500)
        finally:
            answered.set()
            REPLY_HEADERS_VAR.reset(replied)
            PROGRESS_VAR.reset(progress)
            CANCELLATION_VAR.reset(token)
            watcher.join()
        if stream is not None and stream.started:
            stream.finish(status, reply, headers)
        else:
            self._send(status, reply, headers or None)

    def _watch_caller(self, cancellation: Cancellation, answered: threading.Event) -> None:
        """Cancel the call once its caller closes the connection."""
        while not answered.wait(CANCEL_POLL_SECONDS):
            if self._caller_gone():
                cancellation.cancel("the caller closed the connection", CALLER_GONE, 499)
                return

    def _caller_gone(self) -> bool:
        """True when the caller closed (or reset) the connection, read without consuming.

        A caller only waits for the reply, so a readable socket at end of stream
        is a close; pipelined bytes are left for the next request.
        """
        try:
            readable, _, _ = select.select([self.connection], [], [], 0)
            return bool(readable) and self.connection.recv(1, socket.MSG_PEEK) == b""
        except OSError:
            return True

    def _not_post(self) -> None:
        server = typing.cast("OpsServer", self.server)
        if not self._check_host(server):
            return
        path = urlsplit(self.path).path
        if path in ("/health", "/metrics") and self.command in ("GET", "HEAD"):
            if not hmac.compare_digest(
                self.headers.get("Authorization", "").encode("utf-8"),
                f"Bearer {server.token}".encode(),
            ):
                self._refuse(UNAUTHORIZED, "a valid bearer token is required", 401)
                return
            snapshot, latency_buckets, per_op = server.metrics_snapshot()
            if path == "/health":
                payload = {
                    "status": "up",
                    "requests": snapshot["request_count"],
                    "errors": snapshot["error_count"],
                    "server_errors": snapshot["server_error_count"],
                    "client_errors": snapshot["client_error_count"],
                    "latency_ms_avg": round(snapshot["latency_ms_avg"], 3),
                    "latency_ms_max": round(snapshot["latency_ms_max"], 3),
                    "uptime_seconds": round(snapshot["uptime_seconds"], 3),
                    "concurrency": server.concurrency,
                    "busy_refusals": snapshot.get("busy_refusals", 0),
                    "unhandled_errors": snapshot.get("unhandled_errors", 0),
                    "trace_spans_dropped": telemetry.export_stats()["dropped"],
                    "trace_spans_failed": telemetry.export_stats()["failed"],
                }
                body = msgspec.json.encode(payload)
                self._send(200, body)
                return
            lines = [
                "# HELP rebrew_ops_requests_total Total ops requests answered.",
                "# TYPE rebrew_ops_requests_total counter",
                f"rebrew_ops_requests_total {snapshot['request_count']}",
                "# HELP rebrew_ops_errors_total Total ops requests answered with an error status.",
                "# TYPE rebrew_ops_errors_total counter",
                f"rebrew_ops_errors_total {snapshot['error_count']}",
                "# HELP rebrew_ops_server_errors_total Total ops requests answered with a 5xx status.",
                "# TYPE rebrew_ops_server_errors_total counter",
                f"rebrew_ops_server_errors_total {snapshot['server_error_count']}",
                "# HELP rebrew_ops_client_errors_total Total ops requests answered with a 4xx status.",
                "# TYPE rebrew_ops_client_errors_total counter",
                f"rebrew_ops_client_errors_total {snapshot['client_error_count']}",
                "# HELP rebrew_ops_latency_ms_total Total latency of answered ops requests, in milliseconds.",
                "# TYPE rebrew_ops_latency_ms_total counter",
                f"rebrew_ops_latency_ms_total {snapshot['latency_ms_total']:.3f}",
                "# HELP rebrew_ops_latency_ms_max Maximum latency of an answered ops request, in milliseconds.",
                "# TYPE rebrew_ops_latency_ms_max gauge",
                f"rebrew_ops_latency_ms_max {snapshot['latency_ms_max']:.3f}",
                "# HELP rebrew_ops_uptime_seconds Seconds since the server started.",
                "# TYPE rebrew_ops_uptime_seconds gauge",
                f"rebrew_ops_uptime_seconds {snapshot['uptime_seconds']:.3f}",
                "# HELP rebrew_ops_concurrency Configured number of calls answered at once.",
                "# TYPE rebrew_ops_concurrency gauge",
                f"rebrew_ops_concurrency {server.concurrency}",
                "# HELP rebrew_ops_in_flight Calls currently holding a worker slot.",
                "# TYPE rebrew_ops_in_flight gauge",
                f"rebrew_ops_in_flight {snapshot['in_flight']}",
                "# HELP rebrew_ops_busy_refusals_total Calls refused with 503 because no worker slot was free.",
                "# TYPE rebrew_ops_busy_refusals_total counter",
                f"rebrew_ops_busy_refusals_total {snapshot.get('busy_refusals', 0)}",
                "# HELP rebrew_ops_unhandled_errors_total Handler faults that escaped before a response was written.",
                "# TYPE rebrew_ops_unhandled_errors_total counter",
                f"rebrew_ops_unhandled_errors_total {snapshot.get('unhandled_errors', 0)}",
                "# HELP rebrew_ops_trace_spans_dropped_total Finished spans dropped because the export queue was full.",
                "# TYPE rebrew_ops_trace_spans_dropped_total counter",
                f"rebrew_ops_trace_spans_dropped_total {telemetry.export_stats()['dropped']}",
                "# HELP rebrew_ops_trace_spans_failed_total Finished spans lost to a failed export POST.",
                "# TYPE rebrew_ops_trace_spans_failed_total counter",
                f"rebrew_ops_trace_spans_failed_total {telemetry.export_stats()['failed']}",
                "# HELP rebrew_ops_latency Latency of answered ops requests, in milliseconds.",
                "# TYPE rebrew_ops_latency histogram",
                # The last bound is infinity, written +Inf as the exposition format spells it: one +Inf bucket.
                *(
                    f'rebrew_ops_latency_bucket{{le="{"+Inf" if bound == float("inf") else bound}"}} '
                    f"{sum(latency_buckets[: i + 1])}"
                    for i, bound in enumerate(LATENCY_BUCKETS_MS)
                ),
                f"rebrew_ops_latency_count {snapshot['request_count']}",
                f"rebrew_ops_latency_sum {snapshot['latency_ms_total']:.3f}",
                "# HELP rebrew_ops_per_op_requests_total Requests per op (bounded by the op set).",
                "# TYPE rebrew_ops_per_op_requests_total counter",
                *(
                    f'rebrew_ops_per_op_requests_total{{op="{op}"}} {int(entry["count"])}'
                    for op, entry in sorted(per_op.items())
                ),
                "# HELP rebrew_ops_per_op_server_errors_total 5xx responses per op.",
                "# TYPE rebrew_ops_per_op_server_errors_total counter",
                *(
                    f'rebrew_ops_per_op_server_errors_total{{op="{op}"}} {int(entry["server_errors"])}'
                    for op, entry in sorted(per_op.items())
                ),
                "# HELP rebrew_ops_per_op_client_errors_total 4xx responses per op.",
                "# TYPE rebrew_ops_per_op_client_errors_total counter",
                *(
                    f'rebrew_ops_per_op_client_errors_total{{op="{op}"}} {int(entry["client_errors"])}'
                    for op, entry in sorted(per_op.items())
                ),
                "# HELP rebrew_ops_per_op_latency_ms_total Total latency per op, in milliseconds.",
                "# TYPE rebrew_ops_per_op_latency_ms_total counter",
                *(
                    f'rebrew_ops_per_op_latency_ms_total{{op="{op}"}} {entry["latency_ms"]:.3f}'
                    for op, entry in sorted(per_op.items())
                ),
            ]
            body = ("\n".join(lines) + "\n").encode("utf-8")
            self._send(
                200,
                body,
                content_type="text/plain; version=0.0.4; charset=utf-8",
            )
            return
        # 404 before 405, like the dashboard: a path that names no op has no
        # resource to list methods for.  POST on the same unknown name
        # already answers 404 unknown-op, so a non-POST must too.  The
        # /health and /metrics branches above already answered a non-GET/HEAD
        # on those served resources, so a POST there never reaches here, and
        # any other non-POST here is 405 only for a known op.
        if path in ("/health", "/metrics"):
            self._send(
                405,
                error_body(METHOD_NOT_ALLOWED, "health and metrics are served with GET, HEAD", 405),
                {"Allow": "GET, HEAD"},
            )
            return
        name = path.removeprefix("/")
        if name not in typing.cast("OpsServer", self.server).ops:
            self._refuse(UNKNOWN_OP, f"unknown op: {bounded(name)}", 404)
            return
        self._send(
            405,
            error_body(METHOD_NOT_ALLOWED, "ops are called with POST", 405),
            {"Allow": "POST"},
        )

    do_GET = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _not_post
