"""dashboard.py – Read-only web dashboard over the coverage documents.

Serves the per-target ``db/coverage-<target>.toml`` written by ``rebrew
build-db`` over a tiny HTTP server with no dependencies beyond the stdlib.
Every endpoint is read-only: a document is only ever read, and non-GET/HEAD
requests are rejected with 405.

Endpoints
---------
``GET /``                      → HTML shell (functions, sections, globals, history)
``GET /app.js``                → deferred dashboard client (preloaded + ``defer``)
``GET /api/bootstrap``         → targets + first target's summary/functions (one RTT)
``GET /api/health``            → liveness probe (one real read of the target list)
``GET /api/targets``           → list of targets (includes count/total)
``GET /api/summary?target=``   → function stats + coverage % (target required)
``GET /api/functions?target=`` → function rows as arrays under ``cols`` (filters: status, module, q, limit, offset)
``GET /api/sections?target=``  → per-section cell stats (rows as arrays under ``cols``; includes count/total/limit/offset)
``GET /api/globals?target=``   → global data rows (filters: module, q, limit, offset; includes total)
``GET /api/history?target=``   → status-change history (filters: limit, offset; includes total)

``q`` matches a name or symbol substring on functions, and a name substring
on globals. A term of four or more hex digits, with an optional ``0x``
prefix, also matches that virtual address exactly. ``0x401000`` and
``00401000`` are the same address.

A present empty ``module=`` on ``/api/functions`` and ``/api/globals`` matches
rows whose module is blank. Omitting ``module`` does not filter. Summary
``by_module_counts`` keys are those stored strings (``""`` when unset).  A
repeated parameter takes its first value, and an unrecognised one is ignored.
Target-scoped endpoints return 400 when ``target`` is missing/empty and 404 when
the target is unknown, and a target IS a document: one readable
``coverage-<target>.toml`` in the configured directory.  A missing or
unparseable document is therefore an unknown target rather than a 500 — the
reader skips it with a log line and serves the rest, and ``function_stats`` is
DERIVED from the stored function rows, so the unreadable-metadata-row case the
SQLite dashboard answered 500 ``corrupt_function_stats`` for cannot arise.
``/api/bootstrap`` embeds the first target and degrades instead of failing: its
``summary`` and ``functions`` are ``null`` when the directory holds no readable
target, so an empty directory costs the target list and nothing else.
Non-GET/HEAD methods on a served path (including ones http.server does not
know) return 405 with ``Allow: GET, HEAD``; a path the server does not serve
returns 404 ``not_found`` whatever method it was asked for, since there is no
resource to list methods for.  Every error body is
``{"error": "<message>", "code": "<machine-readable code>"}``; branch on
``code`` (``missing_target``, ``unknown_target``, ``invalid_status``,
``not_found``, ``method_not_allowed``, ``host_not_allowed``,
``database_error`` (the whole directory yielded no readable document),
``internal_error``,
``server_busy`` for a connection refused because every handler slot is taken,
and ``bad_request`` / ``uri_too_long`` / ``header_fields_too_large`` /
``http_version_not_supported`` for malformed requests rejected before
routing, plus ``request_error`` for any other status raised there) and
show ``error`` to the reader.  Every response carries
``X-Request-Id: r<N>``, the same id the access and error log lines use, so
a reported failure is one grep away.
A ``status`` filter outside the STATUS vocabulary is 400
``invalid_status`` rather than an empty page, which would read as "this
target has no functions in that status".
A request that carries a body is answered with ``Connection: close`` (no
route reads one).  Requests whose ``Host`` header
does not match the bound host (or a loopback alias) are rejected with 403, so
a web page the analyst visits cannot reach the server via DNS rebinding.
List endpoints expose ``count`` (rows in this page), ``total`` (matching rows),
and the applied ``limit`` / ``offset``, plus ``paged`` so a client never has to
infer whether ``limit`` is a page size or a row count: it is ``true`` on
``/api/functions``, ``/api/globals``, and ``/api/history``, and ``false`` on
``/api/sections``, ``/api/targets``, and the top level of ``/api/bootstrap``,
which have no page (``offset`` is 0 and ``limit`` is the row count there).
A client that pages on ``limit`` steps by ``count``, not by ``limit``.
A missing, malformed, or non-positive ``limit`` uses 100 and larger values clamp
to 5000; a missing, malformed, or negative ``offset`` uses 0 and values past
rebrew's ``VA_MAX`` clamp to it.  Clients read the applied values back.
Successful 200 responses negotiate ``zstd`` then ``gzip`` (``Accept-Encoding``
quality weights; explicit ``coding;q=0`` beats ``*``), carry an ``ETag`` (HTML
or ``/app.js`` content hash, or a hash of every coverage document's stat plus
a hash of the request's path and query, so one validator never stands for two
different routes, targets, or filter selections), and use ``Cache-Control:
private,
no-cache`` so browsers can 304 without serving a stale body after ``build-db``;
the shell links ``/app.js?v=<content hash>``, which is ``immutable``.
``/api/health`` is the exception: it reads the documents, so it answers
``no-store`` with no ``ETag`` at all (see ``_UNCACHEABLE_ROUTES``).  It
also reports the running request, 5xx, and worst-latency totals plus the
in-flight connection count, so a probe can watch the error rate and the
saturation behind it while the server is up.
The server's own output is one stream: an access line per request (id, request
line, status, size, handler milliseconds), a WARNING for a request past
``_SLOW_REQUEST_MS``, an ERROR with an escaped traceback for a failure, and
every warning a route raises about its own data, each stamped with the id of
the request in flight.  A route-level warning reports a response the access
line shows as a plain 200 (a byte count past the section), so it carries the
id rather than leaving the operator to grep the message.  Off the server, the CLI reaches the same ``Dashboard`` with no
request in flight and those warnings report ``-``.
The rebrew mark is served from ``/favicon.svg`` rather than inlined as a data
URI: a linked icon still stops the per-load ``/favicon.ico`` 404, and keeps
443 B of near-incompressible payload out of the document the cold flight
budgets.  It is a tab icon, not first paint, so it fetches off the critical
path, and the shell links it content-hashed, so the browser fetches it once
and serves every later load from disk.
A matching ``If-None-Match`` on a routed path is answered 304 only when a GET
would answer 200 (target-scoped ones need a known ``target``; ``/api/summary``
a readable document; ``/api/functions`` a ``status`` inside the vocabulary),
without running the route's query.
The static HTML shell and ``/app.js`` are zstd- and
gzip-precompressed at import time (gzip ``mtime=0``, so a restart serves the
same bytes) so entry assets skip per-request compression CPU.  Their combined
wire size stays inside the RFC 6928 initial congestion window minus a
per-response header reserve, so a cold connection paints without an extra
round trip; a test pins that budget, and a change that does not fit pays for
itself in the client's own comment prose rather than in the budget.  As
measured: 12712 B zstd and 13315 B gzip against a 13320 B budget, so gzip has
5 B of room and zstd 608 B — a client-side edit budgets against gzip, and gzip
is the binding encoding.  The
reserve is what makes gzip the tight one, not the encoder: the two responses
send 567 and 599 B of headers as served, against the 640 B each is given.
The preloaded ``/api/bootstrap`` is a third cold-flight response (774 B gzip
plus 562 B of headers) and is deliberately outside that reserve, so the whole
three-response flight is budgeted against the entry assets alone: they carry
the first paint, and the bootstrap's tail
rides the second.  Remaining
JSON compresses per request at mid effort, except ``/api/bootstrap``: the cold
start needs it to paint, a client sends it once per load and 304s after that,
so it takes the same max effort the static blobs do.  The shell
``<head>`` preloads ``/api/bootstrap`` (``as=fetch`` + ``crossorigin`` +
``fetchpriority=high``) and ``/app.js`` (``as=script``); the deferred client
fetches with the default ``same-origin`` credentials, the mode ``crossorigin``
(anonymous) preloads with, so the cold-start payload reuses that preload.  Keeping JS out of the document lets the browser paint the loading
chrome before the script finishes downloading.
The shell carries the boot guard inline and runs it on ``DOMContentLoaded``,
which every deferred client precedes: a client that never reached its first
statement (aborted transfer, 5xx from a proxy, a syntax error) leaves a message
and a reload prompt instead of a permanent "Loading coverage…".  The policy
stays ``script-src 'self'`` plus that one script's ``sha256`` hash, never
``'unsafe-inline'``.  A
permanent Reload control re-runs the bootstrap in place, so an analyst picks up
a fresh ``build-db`` without a browser reload; the empty states name that
control instead of telling the reader to reload the page.  A status mark is one
quoted ``class`` attribute holding ``st`` plus the per-status class: unquoted,
the value would end at the space and every status in the tables would render in
the default ink.  JSON
uses compact separators; function/global/history/section rows are arrays under
``cols``.  Every text column in those rows is a JSON string: a NULL in the
database (a history row's ``old_status``/``new_status`` for a VA's first
recorded transition, a function with no module) is sent as ``""``, so a client
never has to null-check one route and not the next.  The handler speaks
HTTP/1.1 so browsers reuse one TCP connection for the shell, ``/app.js``,
bootstrap payload, and later filter fetches.
Every non-entry 200 carries ``Server-Timing: route;dur=<ms>`` so the browser's
Network panel separates query time from transfer time; the entry assets
omit it, since their cold flight is budgeted against the initial congestion
window and the value is a constant there.

The query layer (``Dashboard``) is separated from the HTTP plumbing so tests
exercise it without opening a socket.
"""

from __future__ import annotations

import base64
import errno
import gzip
import hashlib
import itertools
import json
import logging
import socket
import sys
import threading
import time
import traceback
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from email.utils import formatdate
from functools import cache
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar, Literal, override
from urllib.parse import parse_qs, urlparse

import typer
import zstandard
from rich.markup import escape

from rebrew import theme
from rebrew.annotation import FUNCTION_MARKERS
from rebrew.build_db import resolve_db_dir
from rebrew.cli import console, error_exit, json_print
from rebrew.compression import precompress
from rebrew.coverage_toml import (
    CoverageSnapshot,
    CoverageTomlError,
    Function,
    Global,
    load_all_coverage_from,
)
from rebrew.metadata import canonical_status
from rebrew.status_style import status_mark_groups
from rebrew.utils import floor_pct, strip_bidi_format
from rebrew.workspace import VA_MAX
from rebrew.workspace.status import COVERAGE_DB_STATUSES

log = logging.getLogger(__name__)

_LOG_CONTROL_CHARS = {code: f"\\x{code:02x}" for code in (*range(0x20), *range(0x7F, 0xA0))}
_LOG_CONTROL_CHARS[ord("\\")] = "\\\\"

#: Correlation id per request: the access line, the 5xx line, and the escaped
#: traceback all carry it, so an operator can pivot from a failure back to the
#: request that produced it even while other threads interleave their lines.
_REQUEST_IDS = itertools.count(1)
#: The request in flight on this thread.  ``socketserver`` hands a fault to
#: ``handle_error`` on the handler's own thread but not the handler instance,
#: so this is what lets that fault name the request it belongs to.
_REQUEST_LOCAL = threading.local()


def _stamp_request(request_id: str, line: str) -> None:
    """Record the correlation id and request line for the current thread."""
    _REQUEST_LOCAL.request_id = request_id
    _REQUEST_LOCAL.request_line = line


def _request_context() -> tuple[str, str]:
    """The stamped ``(request_id, request_line)``, escaped for the log stream."""
    request_id = getattr(_REQUEST_LOCAL, "request_id", "-")
    line = _escape_log_text(getattr(_REQUEST_LOCAL, "request_line", ""))
    return request_id, line or "-"


def _warn_request(message: str, *args: Any) -> None:
    """Warn with the request in flight named first, like the error lines are.

    A route's own warning (a byte count past the section size) explains a
    response the access line reports as a plain 200,
    so it has to carry the same id or the operator reading the page has to
    grep the message text to learn which request hit the bad row.  Off the
    server the same ``Dashboard`` serves the CLI, which has no request in
    flight and reports ``-``.
    """
    # Concatenated into a name first so the format string stays a plain
    # template with its arguments lazy; a literal ``+`` in the call is the
    # eager-format rule (G003), and the id is the one part of the line that
    # cannot be a caller-supplied placeholder.
    template = "%s " + message
    log.warning(template, _request_context()[0], *args)


#: Both log streams (access lines on ``console``, errors on ``log``) start with
#: this stamp, so one grep orders the whole server output.  Both are stamped in
#: UTC and label it: ``%(asctime)s`` defaults to localtime, so on a host in a
#: DST zone the error lines would sit an hour away from the access lines for
#: half the year and repeat a stamp on a fall-back night, and neither would
#: line up with the UTC stamps ``main`` writes.
_LOG_TIME_FORMAT = "%H:%M:%S UTC"
#: Level column, padded to the width of the longest name we emit (CRITICAL).
_LOG_LEVEL_FORMAT = "%(levelname)-8s"

_DEFAULT_LIMIT = 100
_MAX_LIMIT = 5000
#: Rows the preloaded cold-start payload carries.  The shell paints its first
#: frame from ``/`` alone, but the first *useful* frame needs this body too, and
#: it shares the initial congestion window with the shell and ``/app.js``.  A
#: first page is not a page: Show more continues from ``loadedCount`` against the
#: payload's real ``total``, so sizing this for paint rather than for browsing
#: costs no reach.  A full default page costs 377 B more on the wire (706 -> 1083
#: zstd at 40 rows) and 60 more rows of innerHTML before the page is interactive.
_BOOTSTRAP_FUNCTION_LIMIT = 40
#: The ``function_stats`` byte counts the summary percentages divide by.  All
#: three are validated the same way, so they are read as one set: a count the
#: summary ignores is still a count that can make the row unreadable.
_FUNCTION_STAT_BYTE_COUNTS = ("matched_bytes", "covered_bytes", "total_bytes")
_FUNCTION_COLS = ("va", "name", "symbol", "size", "status", "module", "files")
_GLOBAL_COLS = ("va", "name", "decl", "size", "module")
_HISTORY_COLS = ("va", "name", "old_status", "new_status", "changed_at")
#: Section rows ship in table-column order, so the SELECT order is this tuple's.
_SECTION_COLS = (
    "name",
    "size",
    "total_cells",
    "exact",
    "reloc",
    "near_match",
    "stub",
    "proven",
    "size_mismatch",
    "thunk",
    "data",
    "padding",
    "none",
    "other",
)
#: Routes that require ``?target=``.
_TARGET_ROUTES = frozenset(
    {
        "/api/summary",
        "/api/functions",
        "/api/sections",
        "/api/globals",
        "/api/history",
    }
)
#: Same-origin path the shell links for the mark.
_FAVICON_PATH = "/favicon.svg"
#: Paths ``Dashboard.handle`` serves; only these may short-circuit to 304.
_ROUTES = (
    frozenset({"/", "/app.js", _FAVICON_PATH, "/api/bootstrap", "/api/targets"}) | _TARGET_ROUTES
)
#: Routes that answer 200 but must carry no validator and no cache directive.
#: ``/api/health`` reads the documents, so a revalidated body would keep
#: reporting "ok" for a process whose coverage has since gone unreadable.
#: It is deliberately not in ``_ROUTES`` either: that stops the 304
#: short-circuit, while this stops the ``ETag`` a client could otherwise hold
#: and revalidate by hand.
_UNCACHEABLE_ROUTES = frozenset({"/api/health"})
#: Every path ``Dashboard.handle`` serves.  Membership is the 404-vs-405
#: decision: a path outside this set has no resource to carry an ``Allow``
#: header, so it answers ``not_found`` whatever method it was asked for.
_KNOWN_ROUTES = _ROUTES | _UNCACHEABLE_ROUTES
#: ``code`` for the errors http.server raises before routing (400/414/431/505);
#: any other parse error falls back to ``request_error``.
_HTTP_ERROR_CODES: dict[int, str] = {
    HTTPStatus.BAD_REQUEST: "bad_request",
    HTTPStatus.REQUEST_URI_TOO_LONG: "uri_too_long",
    HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE: "header_fields_too_large",
    HTTPStatus.HTTP_VERSION_NOT_SUPPORTED: "http_version_not_supported",
}
# Seconds a keep-alive connection may sit idle before its handler thread exits.
_KEEPALIVE_IDLE_TIMEOUT_S = 30.0
# Concurrent connections the server admits.  Each one costs a handler thread and a
# descriptor until the peer closes or the idle timeout fires, so the cap bounds
# both.  A browser holds a handful; 64 leaves room for parallel reloads.
_MAX_ACTIVE_CONNECTIONS = 64
# Handler time past which a request is reported as a slow outlier.  Every
# access line already carries its milliseconds; this names the ones no one
# would scroll back for, so a route that started costing a second says so on
# the stream instead of only showing up as the worst case in the shutdown
# totals.  Well above a served route (one stat per document plus an in-memory
# filter), so
# an ordinary load never reaches it.
_SLOW_REQUEST_MS = 500.0
# Seconds a refused connection is told to wait, in the ``Retry-After`` header of
# the 503 ``server_busy`` it is answered with.  One second is a slot that is
# about to free: a keep-alive handler is capped by ``_KEEPALIVE_IDLE_TIMEOUT_S``
# and by the client's own close, so a client that backs off this long almost
# always gets in on the first retry.
_BUSY_RETRY_AFTER_S = 1
# Below this size framing usually costs more than it saves on a LAN.
_MIN_COMPRESS_BYTES = 256
# Per-request dynamic JSON: mid effort (bodies are rebuilt every request).
_GZIP_LEVEL = 5
_ZSTD_LEVEL = 5
# The static HTML shell and the cold-start body take their max effort from
# rebrew.compression, which the report sidecars share.
# JSON the cold start cannot paint without, compressed at that same max effort.
# The entry assets are precompressed because they are fixed for the process;
# this body is rebuilt per request, but a client sends it about once per load
# and revalidates every one after that (ETag -> 304, no body).  Mid effort
# there spends 12.6% of the preloaded bootstrap body for ~1.1 ms of CPU, and
# that body shares the initial congestion window with the shell and /app.js.
_BOOTSTRAP_PATH = "/api/bootstrap"
#: Ceiling on the compressed cold-start body, over both negotiated encodings.
#: The preloaded bootstrap rides the same cold connection as the shell and
#: ``/app.js``, so it is bounded on its own: the shell and the client already
#: spend most of ``_ENTRY_WIRE_BUDGET_BYTES`` before any data is counted, which
#: leaves this payload no room to grow into.  A first page of
#: ``_BOOTSTRAP_FUNCTION_LIMIT`` rows measures 711 B (zstd) / 776 B (gzip);
#: the full interactive page measured 1083 / 1305 and is over this ceiling.
_BOOTSTRAP_WIRE_BUDGET_BYTES = 1024
#: RFC 6928 initial send window: 10 segments of 1460 B.  The entry assets have
#: to fit it on a cold connection or first paint waits an extra round trip.
_INITCWND_BYTES = 10 * 1460
#: Header bytes held back from that window for the entry responses.  Each
#: carries ~530 B as served, dominated by the shared security-header set; 640 B
#: per response leaves room for a longer CSP or Cache-Control value.  Two
#: static entry responses take part: the shell and ``/app.js``; the boot guard
#: is inline in the shell, so it costs none of its own.
_ENTRY_HEADER_RESERVE_BYTES = 2 * 640
_ENTRY_WIRE_BUDGET_BYTES = _INITCWND_BYTES - _ENTRY_HEADER_RESERVE_BYTES
_WireEncoding = Literal["zstd", "gzip"]
# Preference when several encodings share the same positive q-value.
_ENCODING_PREFERENCE: tuple[_WireEncoding, ...] = ("zstd", "gzip")
#: Filename shape :mod:`rebrew.coverage_toml` writes and reads: one document per
#: target.  Repeated here because the ETag and the freshness probe stat the
#: documents themselves, and a second spelling of the glob would name a
#: different set of files than the reader parses.  It is also the only place a
#: served response names a coverage file.
_COVERAGE_GLOB = "coverage-*.toml"


_APP_JS = """
const $ = (id) => document.getElementById(id);
let targets = [];
let searchTimer = null;
let globalsSearchTimer = null;
let functionsSeq = 0;
let summarySeq = 0;
let viewSeq = 0;
let functionsController = null;
let summaryController = null;
let viewController = null;
let loadedCount = 0;
let loadedGlobalsCount = 0;
let loadedHistoryCount = 0;
let retryAppend = false;
let retryGlobalsAppend = false;
let retryHistoryAppend = false;
let currentView = "functions";
// Filters restored from the URL hash before their options exist.
let pendingStatus = "";
let pendingModule = "";
// Hash ``module=`` (present, empty) restores the blank-module filter.
let pendingModuleBlank = false;
// Hash writes start once init has restored state, so a reload keeps it.
let hashReady = false;
// Target and view the hash was last written for: a change to either is a
// navigation Back returns to, the rest of the state rides along with it.
let lastNav = "";
let whenFormat = null;
const VIEWS = ["functions", "sections", "globals", "history"];
const PAGE_LIMIT = 100;
const PAGE_STEP = 500;
const PAGE_MAX = 5000;
const loadErrors = { summary: "", functions: "", view: "" };
const busyCounts = new Map();
const viewLoaded = { functions: false, sections: false, globals: false, history: false };
async function get(path, signal) {
  // Default credentials ("same-origin") match the anonymous crossorigin
  // preload, so the cold-start bootstrap reuses it.
  let r;
  try {
    r = await fetch(path, { signal });
  } catch (error) {
    if (signal && signal.aborted) throw error;
    throw new Error("the dashboard server did not respond; check that rebrew dashboard is still running");
  }
  if (!r.ok) {
    // Error bodies are {"error": "<message>", "code": "<code>"}; show the reason.
    let detail = "";
    try {
      detail = (await r.json()).error || "";
    } catch (error) {
      detail = "";  // Non-JSON body (proxy page): the status code alone is all we have.
    }
    throw new Error("server returned " + r.status + (detail ? ", " + detail : ""));
  }
  return r.json();
}
// " (reason)" suffix for a load-error message; empty when there is none.
const reason = (error) => (error && error.message ? " (" + error.message + ")" : "");
async function whileBusy(id, operation) {
  const element = $(id);
  const count = (busyCounts.get(id) || 0) + 1;
  busyCounts.set(id, count);
  element.setAttribute("aria-busy", "true");
  try {
    return await operation();
  } finally {
    const remaining = (busyCounts.get(id) || 1) - 1;
    busyCounts.set(id, remaining);
    if (remaining === 0) element.setAttribute("aria-busy", "false");
  }
}
// One table, not one per matched character: esc() runs per cell per row.
const ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const ESCAPE_RE = /[&<>"']/g;
function esc(s) {
  return String(s).replace(ESCAPE_RE, (c) => ESCAPES[c]);
}
function formatWhen(value) {
  if (!value) return "";
  // Rebrew stores UTC instants; a zone-less date-time reads as local wall time
  // under Date.parse, so pin it with Z.
  let raw = String(value).trim();
  if (/^\\d{4}-\\d{2}-\\d{2}[Tt ]\\d{2}:\\d{2}(:\\d{2}(\\.\\d+)?)?$/.test(raw)) {
    raw += "Z";
  }
  const parsed = Date.parse(raw);
  if (Number.isNaN(parsed)) return String(value);
  try {
    // One shared formatter: toLocaleString(options) builds one per call
    // (~117 ms vs 3 ms for 5000 rows).  timeZoneName is required: without it
    // a fall-back hour prints twice.
    whenFormat ??= new Intl.DateTimeFormat(undefined, {
      year: "numeric", month: "short", day: "numeric",
      hour: "numeric", minute: "2-digit",
      timeZoneName: "short",
    });
    return whenFormat.format(parsed);
  } catch (error) {
    return String(value);
  }
}
function setFunctionsEmptyMessage() {
  const el = $("empty-state");
  if (filtersActive()) {
    const m = moduleFilterState();
    const onlyQuery = !$("status").value && !m.blank && !m.value && !!$("q").value.trim();
    if (onlyQuery) {
      el.innerHTML = "No functions match this search. <button type='button' id='empty-clear-fn' class='link-button'>Clear search</button> or try another query.";
    } else {
      el.innerHTML = "No functions match these filters. <button type='button' id='empty-clear-fn' class='link-button'>Clear filters</button>, or broaden Status and Module.";
    }
    const btn = $("empty-clear-fn");
    if (btn) btn.onclick = () => $("clear-filters").click();
  } else {
    el.innerHTML = "No functions for this target yet. Match work, run <code>rebrew build-db</code>, then choose Reload.";
  }
}
function setGlobalsEmptyMessage() {
  const el = $("globals-empty");
  if ($("gq").value.trim()) {
    el.innerHTML = "No globals match this search. <button type='button' id='empty-clear-gq' class='link-button'>Clear search</button> or try another name.";
    const btn = $("empty-clear-gq");
    if (btn) btn.onclick = () => $("clear-filters").click();
  } else {
    el.innerHTML = "No globals recorded for this target. Annotate globals, run <code>rebrew build-db</code>, then choose Reload.";
  }
}
function syncError() {
  const message = loadErrors.summary
    || (currentView === "functions" ? loadErrors.functions : "")
    || (currentView !== "functions" ? loadErrors.view : "");
  if (message) {
    // Announce once via role=alert; keep status live region for load counts only.
    $("dashboard-error").textContent = message;
    $("dashboard-error").hidden = false;
  } else {
    $("dashboard-error").textContent = "";
    $("dashboard-error").hidden = true;
  }
  $("retry-summary").hidden = !loadErrors.summary;
  $("retry-functions").hidden = !(loadErrors.functions && currentView === "functions");
  const showViewRetry = !!(loadErrors.view && currentView !== "functions");
  $("retry-view").hidden = !showViewRetry;
  // The one view whose load reports through its own button never shows this.
  $("retry-view").textContent = "Retry" + (currentView === "functions" ? "" : " " + currentView);
}
// Hiding or disabling the focused control drops focus to <body> (WCAG 2.4.3),
// so move it to the first usable id.  No-op when focus is held.
function restoreFocus(ids) {
  const active = document.activeElement;
  if (active && active !== document.body) return;
  for (const id of ids) {
    const el = $(id);
    if (el && !el.disabled && !el.closest("[hidden]")) {
      el.focus();
      return;
    }
  }
}
function setLoadError(source, message) {
  loadErrors[source] = message || "";
  syncError();
}
function moduleFilterState() {
  const select = $("module");
  const chosen = select.selectedOptions && select.selectedOptions[0];
  if (chosen && chosen.dataset && chosen.dataset.filter === "blank") {
    return { blank: true, value: "" };
  }
  return { blank: false, value: select.value || "" };
}
function selectAnyModule() {
  const select = $("module");
  select.value = "";
  pendingModule = "";
  pendingModuleBlank = false;
  // Two options share value="": "any" is first, "(no module)" is data-filter=blank.
  const any = select.querySelector && select.querySelector("option[value='']");
  if (any && (!any.dataset || any.dataset.filter !== "blank")) any.selected = true;
}
function filtersActive() {
  if (currentView === "globals") return !!$("gq").value.trim();
  if (currentView !== "functions") return false;
  const moduleState = moduleFilterState();
  return !!($("status").value || moduleState.blank || moduleState.value || $("q").value.trim());
}
function updateFilterActions() {
  // Keep the control mounted so enabling Clear does not shove the tablist down.
  const canFilter = currentView === "functions" || currentView === "globals";
  $("filter-actions").hidden = !canFilter;
  $("clear-filters").disabled = !filtersActive();
  $("clear-filters").textContent = currentView === "globals" ? "Clear search" : "Clear filters";
  // With a target per tab, the title is the only orientation cue.
  const t = $("target").value;
  if (t) {
    document.title = t + " - " + currentView[0].toUpperCase() + currentView.slice(1)
      + " - Rebrew coverage";
  }
  writeHash();
}
function writeHash() {
  if (!hashReady) return;
  const params = new URLSearchParams({ target: $("target").value });
  if (currentView !== "functions") params.set("view", currentView);
  const status = $("status").value || pendingStatus;
  const moduleState = moduleFilterState();
  if (status) params.set("status", status);
  if (moduleState.blank || pendingModuleBlank) params.set("module", "");
  else if (moduleState.value || pendingModule) params.set("module", moduleState.value || pendingModule);
  if ($("q").value.trim()) params.set("q", $("q").value.trim());
  if ($("gq").value.trim()) params.set("gq", $("gq").value.trim());
  // A view or target change is a place Back can return to, so it gets its
  // own entry; filter edits replace it, or typing floods the history.
  const url = "#" + params;
  if (lastNav === $("target").value + "|" + currentView) history.replaceState(null, "", url);
  else {
    lastNav = $("target").value + "|" + currentView;
    history.pushState(null, "", url);
  }
}
function syncViewChrome() {
  const isFunctions = currentView === "functions";
  const isGlobals = currentView === "globals";
  $("filter-status").hidden = !isFunctions;
  $("filter-module").hidden = !isFunctions;
  $("filter-q").hidden = !isFunctions;
  $("filter-gq").hidden = !isGlobals;
  VIEWS.forEach(name => {
    $("view-" + name).hidden = name !== currentView;
  });
  document.querySelectorAll("#views button[data-view]").forEach(btn => {
    const on = btn.getAttribute("data-view") === currentView;
    btn.classList.toggle("active", on);
    btn.setAttribute("aria-selected", on ? "true" : "false");
    btn.tabIndex = on ? 0 : -1;
  });
  updateFilterActions();
  syncCardActive();
  syncError();
}
function syncCardActive() {
  // Status cards filter Functions only; pressed on another view, a card would
  // claim a filter that view is not applying.
  const current = currentView === "functions" ? $("status").value : "";
  document.querySelectorAll("#cards button[data-status]").forEach(btn => {
    const on = btn.getAttribute("data-status") === current;
    btn.classList.toggle("active", on);
    btn.setAttribute("aria-pressed", on ? "true" : "false");
  });
}
function setStatusOptions(byStatus) {
  const select = $("status");
  const previous = select.value || pendingStatus;
  const names = Object.keys(byStatus || {}).sort();
  select.innerHTML = "<option value=''>any</option>"
    + names.map(s => "<option value='" + esc(s) + "'>" + esc(s) + "</option>").join("");
  if (previous && names.includes(previous)) select.value = previous;
  else select.value = "";
}
function setModuleOptions(byModule) {
  const select = $("module");
  const previous = pendingModuleBlank ? "" : (select.value || pendingModule);
  const wasBlank = pendingModuleBlank || moduleFilterState().blank;
  const names = Object.keys(byModule || {}).filter((m) => m !== "").sort();
  const hasBlank = !!(byModule && Object.prototype.hasOwnProperty.call(byModule, ""));
  let html = "<option value=''>any</option>";
  if (hasBlank) html += "<option value='' data-filter='blank'>(no module)</option>";
  html += names.map((m) => "<option value='" + esc(m) + "'>" + esc(m) + "</option>").join("");
  select.innerHTML = html;
  if (!wasBlank && previous && names.includes(previous)) select.value = previous;
  else if (wasBlank && hasBlank) {
    const blank = select.querySelector("option[data-filter=blank]");
    if (blank) blank.selected = true;
    else select.value = "";
  } else select.value = "";
  // Pending stays until renderSummary: loadSummary paints an empty menu first.
}
function setListPageMessage(opts) {
  const { count, total, noun, nounOne, hintId, moreWrapId, moreBtnId, tip, tipCapped } = opts;
  const hint = $(hintId);
  const more = moreWrapId ? $(moreWrapId) : null;  // null: sections is unpaged
  if (!total) {
    // "No functions match" is a claim about the filters, not the target.
    $("results-status").textContent = "No " + noun + (filtersActive() ? " match" : " yet");
    hint.hidden = true;
    hint.textContent = "";
    if (more) more.hidden = true;
    return;
  }
  if (count < total) {
    const msg = "Showing " + count + " of " + total + " " + noun;
    const capped = count >= PAGE_MAX;
    $("results-status").textContent = msg;
    hint.textContent = msg + ". " + (capped ? tipCapped : tip);
    hint.hidden = false;
    const next = Math.min(count + PAGE_STEP, total, PAGE_MAX);
    more.hidden = capped;
    // The label counts this click; the running total is in the hint.
    const step = next - count;
    $(moreBtnId).textContent = "Show " + step + " more " + (step === 1 ? nounOne : noun);
  } else {
    $("results-status").textContent = count + " " + (count === 1 ? nounOne : noun) + " shown";
    hint.textContent = "Showing " + (count === 1 ? ("1 " + nounOne) : (count + " " + noun));
    hint.hidden = false;
    if (more) more.hidden = true;
  }
}
// Drop rows, hint, and Show more before a fresh load: the busy veil is
// translucent, so stale rows would read as the new page's data.
function resetList(tableId, hintId, moreWrapId) {
  $(tableId).querySelector("tbody").innerHTML = "";
  $(hintId).hidden = true;
  if (moreWrapId) $(moreWrapId).hidden = true;
}
function resetPaging() {
  loadedCount = 0;
  retryAppend = false;
}
function resetGlobalsPaging() {
  loadedGlobalsCount = 0;
  retryGlobalsAppend = false;
}
function resetHistoryPaging() {
  loadedHistoryCount = 0;
  retryHistoryAppend = false;
}
function statusMark(s) {
  return /^[A-Z][A-Z0-9_]*$/.test(s || "") ? "st status-" + s : "";
}
function statusText(s) {
  const text = esc(s || "");
  const mark = statusMark(s);
  return mark ? "<span class='" + mark + "'>" + text + "</span>" : text;
}
// Rows are positional arrays named by the response's ``cols``.
const rowHtml = (r) => {
  return "<tr><td class=va>" + esc(r[0] ?? "") + "</td><td>" + esc(r[1] || "")
    + "</td><td>" + esc(r[2] || "") + "</td><td>" + esc(r[3] ?? "")
    + "</td><td>" + statusText(r[4] || "") + "</td><td>" + esc(r[5] || "")
    + "</td><td>" + esc(r[6] || "") + "</td></tr>";
};
function renderFunctions(data, options) {
  const append = !!(options && options.append);
  const body = $("rows").querySelector("tbody");
  if (append) {
    body.insertAdjacentHTML("beforeend", data.functions.map(rowHtml).join(""));
    loadedCount += data.functions.length;
  } else {
    loadedCount = data.functions.length;
    body.innerHTML = data.functions.map(rowHtml).join("");
  }
  const total = data.total ?? data.count;
  const shown = append ? loadedCount : data.count;
  setListPageMessage({
    count: shown,
    total,
    noun: "functions",
    nounOne: "function",
    hintId: "results-hint",
    moreWrapId: "show-more-wrap",
    moreBtnId: "show-more",
    tip: "Use Show more below, or narrow Status, Module, or Search.",
    tipCapped: "Narrow Status, Module, or Search: display stops at " + PAGE_MAX + " rows.",
  });
  setFunctionsEmptyMessage();
  $("empty-state").hidden = shown !== 0;
  $("results").hidden = shown === 0;
}
async function loadFunctions(options) {
  const grow = !!(options && options.append);
  const t = $("target").value; if (!t) return;
  const seq = ++functionsSeq;
  if (functionsController) functionsController.abort();
  functionsController = new AbortController();
  const { signal } = functionsController;
  const offset = grow ? loadedCount : 0;
  const params = new URLSearchParams({
    target: t,
    limit: String(grow ? PAGE_STEP : PAGE_LIMIT),
    offset: String(offset),
  });
  if ($("status").value) params.set("status", $("status").value);
  const moduleState = moduleFilterState();
  if (moduleState.blank) params.set("module", "");
  else if (moduleState.value) params.set("module", moduleState.value);
  if ($("q").value.trim()) params.set("q", $("q").value.trim());
  updateFilterActions();
  try {
    setLoadError("functions", "");
    $("results").hidden = false;
    $("empty-state").hidden = true;
    if (!grow) resetList("rows", "results-hint", "show-more-wrap");
    // aria-busy only: a polite-live "Loading…" per debounced keystroke is
    // chatter (WCAG 4.1.3).
    const data = await whileBusy("results", () => get("/api/functions?" + params, signal));
    if (seq !== functionsSeq || signal.aborted) return;
    viewLoaded.functions = true;
    renderFunctions(data, { append: grow });
  } catch (error) {
    if (seq !== functionsSeq || signal.aborted) return;
    retryAppend = grow;
    if (!grow) {
      loadedCount = 0;
      $("rows").querySelector("tbody").innerHTML = "";
    }
    $("results").hidden = loadedCount === 0;
    $("empty-state").hidden = true;
    $("show-more-wrap").hidden = true;
    $("results-hint").hidden = true;
    setLoadError("functions", grow && loadedCount > 0
      ? "Could not load more functions" + reason(error) + ". The rows already shown are unchanged; use Retry functions to fetch the next page again."
      : "Functions could not be loaded" + reason(error) + ". Use Retry functions to try again with the same filters.");
  }
}
function renderSummary(s) {
  const byStatus = s.function_stats.by_status || {};
  setStatusOptions(byStatus);
  setModuleOptions(s.function_stats.by_module_counts || {});
  pendingStatus = "";
  pendingModule = "";
  pendingModuleBlank = false;
  $("status").disabled = false;
  $("module").disabled = false;
  const cards = [
    ["Functions", s.function_stats.total, null,
      "Total functions for this target"],
    ["Matched", (s.coverage_pct ?? 0).toFixed(1) + "%", null,
      "Share of .text bytes in byte-matched (EXACT or RELOC) functions"],
    ["Identified", (s.identified_pct ?? 0).toFixed(1) + "%", null,
      "Share of .text bytes covered by any known function, including stubs"],
  ];
  // Same order as the Status select.
  for (const k of Object.keys(byStatus).sort()) cards.push([k, byStatus[k], k, "Filter Functions by " + k]);
  // A div cannot be named, so title rides in a visually-hidden span after the
  // visible text (WCAG 2.5.3); a button exposes title as a description.
  $("cards").innerHTML = cards.map(([k, v, status, title]) => {
    const mark = status ? statusMark(status) : "";
    const label = mark ? "<span class='label " + mark + "'>" : "<span class=label>";
    const inner = "<span class=value>" + esc(v) + "</span>" + label + esc(k) + "</span>";
    if (status) {
      const pressed = currentView === "functions" && $("status").value === status;
      const active = pressed ? " active" : "";
      return "<button type=button class='card" + active + "' data-status='" + esc(status)
        + "' title='" + esc(title) + "' aria-pressed='" + (pressed ? "true" : "false") + "'>"
        + inner + "</button>";
    }
    return "<div class=card title='" + esc(title) + "'>" + inner
      + "<span class=visually-hidden>, " + esc(title) + "</span></div>";
  }).join("");
  $("summary").hidden = false;
  updateFilterActions();
}
async function loadSummary() {
  const t = $("target").value; if (!t) return;
  const seq = ++summarySeq;
  if (summaryController) summaryController.abort();
  summaryController = new AbortController();
  const { signal } = summaryController;
  setStatusOptions({});
  setModuleOptions({});
  $("status").disabled = true;
  $("module").disabled = true;
  $("cards").innerHTML = "<p>Loading coverage summary…</p>";
  $("summary").hidden = false;
  updateFilterActions();
  try {
    setLoadError("summary", "");
    const s = await whileBusy("summary", () =>
      get("/api/summary?target=" + encodeURIComponent(t), signal));
    if (seq !== summarySeq || signal.aborted) return;
    renderSummary(s);
  } catch (error) {
    if (seq !== summarySeq || signal.aborted) return;
    $("cards").innerHTML = "";
    $("summary").hidden = true;
    $("status").disabled = false;  // loadSummary disabled them
    $("module").disabled = false;
    setLoadError("summary", "Coverage summary could not be loaded" + reason(error) + ". Use Retry summary to try again.");
  }
}
function scheduleSearch() {
  clearTimeout(searchTimer);
  updateFilterActions();
  searchTimer = setTimeout(() => {
    resetPaging();
    loadFunctions();
  }, 200);
}
function scheduleGlobalsSearch() {
  clearTimeout(globalsSearchTimer);
  updateFilterActions();
  globalsSearchTimer = setTimeout(() => {
    resetGlobalsPaging();
    loadGlobals();
  }, 200);
}
function onStatusChange() {
  resetPaging();
  syncCardActive();
  updateFilterActions();
  loadFunctions();
}
function onModuleChange() {
  resetPaging();
  updateFilterActions();
  loadFunctions();
}
const sectionRowHtml = (r) => {
  return "<tr><td>" + esc(r[0] || "") + "</td><td>"
    + esc(r[1] ?? "") + "</td><td>" + esc(r[2] ?? "") + "</td><td>"
    + esc(r[3] ?? 0) + "</td><td>" + esc(r[4] ?? 0) + "</td><td>"
    + esc(r[5] ?? 0) + "</td><td>" + esc(r[6] ?? 0) + "</td><td>"
    + esc(r[7] ?? 0) + "</td><td>" + esc(r[8] ?? 0) + "</td><td>"
    + esc(r[9] ?? 0) + "</td><td>" + esc(r[10] ?? 0) + "</td><td>"
    + esc(r[11] ?? 0) + "</td><td>" + esc(r[12] ?? 0) + "</td><td>"
    + esc(r[13] ?? 0) + "</td></tr>";
};
function renderSections(data) {
  const rows = data.sections || [];
  const body = $("sections-rows").querySelector("tbody");
  body.innerHTML = rows.map(sectionRowHtml).join("");
  $("sections-empty").hidden = rows.length !== 0;
  $("sections-results").hidden = rows.length === 0;
  // Unpaged, so the shared message counts the rows as the whole list.
  setListPageMessage({
    count: rows.length,
    total: rows.length,
    noun: "sections",
    nounOne: "section",
    hintId: "sections-hint",
    moreWrapId: null,
  });
}
const globalRowHtml = (r) => {
  return "<tr><td class=va>" + esc(r[0] ?? "") + "</td><td>" + esc(r[1] || "")
    + "</td><td>" + esc(r[2] || "") + "</td><td>" + esc(r[3] ?? "")
    + "</td><td>" + esc(r[4] || "") + "</td></tr>";
};
function renderGlobals(data, options) {
  const append = !!(options && options.append);
  const body = $("globals-rows").querySelector("tbody");
  const rows = data.globals || [];
  if (append) {
    body.insertAdjacentHTML("beforeend", rows.map(globalRowHtml).join(""));
    loadedGlobalsCount += rows.length;
  } else {
    loadedGlobalsCount = rows.length;
    body.innerHTML = rows.map(globalRowHtml).join("");
  }
  const total = data.total ?? loadedGlobalsCount;
  setGlobalsEmptyMessage();
  $("globals-empty").hidden = loadedGlobalsCount !== 0;
  $("globals-results").hidden = loadedGlobalsCount === 0;
  setListPageMessage({
    count: loadedGlobalsCount,
    total,
    noun: "globals",
    nounOne: "global",
    hintId: "globals-hint",
    moreWrapId: "globals-show-more-wrap",
    moreBtnId: "show-more-globals",
    tip: "Use Show more below, or narrow the search.",
    tipCapped: "Narrow the search: display stops at " + PAGE_MAX + " rows.",
  });
  updateFilterActions();
}
const historyRowHtml = (r) => {
  // A blank old status is the first recorded change, not a missing value.
  return "<tr><td class=va>" + esc(r[0] ?? "") + "</td><td>" + esc(r[1] || "")
    + "</td><td>" + statusText(r[2] || "(first change)") + "</td><td>" + statusText(r[3] || "")
    + "</td><td>" + esc(formatWhen(r[4])) + "</td></tr>";
};
function renderHistory(data, options) {
  const append = !!(options && options.append);
  const body = $("history-rows").querySelector("tbody");
  const rows = data.history || [];
  if (append) {
    body.insertAdjacentHTML("beforeend", rows.map(historyRowHtml).join(""));
    loadedHistoryCount += rows.length;
  } else {
    loadedHistoryCount = rows.length;
    body.innerHTML = rows.map(historyRowHtml).join("");
  }
  $("history-empty").hidden = loadedHistoryCount !== 0;
  $("history-results").hidden = loadedHistoryCount === 0;
  const total = data.total ?? loadedHistoryCount;
  setListPageMessage({
    count: loadedHistoryCount,
    total,
    noun: "history entries",
    nounOne: "history entry",
    hintId: "history-hint",
    moreWrapId: "history-show-more-wrap",
    moreBtnId: "show-more-history",
    tip: "Use Show more below to load older entries.",
    tipCapped: "Display stops at " + PAGE_MAX + " rows.",
  });
}
async function loadSections() {
  const t = $("target").value; if (!t) return;
  const seq = ++viewSeq;
  if (viewController) viewController.abort();
  viewController = new AbortController();
  const { signal } = viewController;
  $("sections-empty").hidden = true;
  resetList("sections-rows", "sections-hint");
  $("sections-results").hidden = false;
  try {
    setLoadError("view", "");
    const data = await whileBusy("sections-results", () =>
      get("/api/sections?target=" + encodeURIComponent(t), signal));
    if (seq !== viewSeq || signal.aborted) return;
    viewLoaded.sections = true;
    renderSections(data);
  } catch (error) {
    if (seq !== viewSeq || signal.aborted) return;
    $("sections-results").hidden = true;
    $("sections-empty").hidden = true;
    $("sections-hint").hidden = true;
    setLoadError("view", "Sections could not be loaded" + reason(error) + ". Use Retry sections to try again.");
  }
}
async function loadGlobals(options) {
  const grow = !!(options && options.append);
  const t = $("target").value; if (!t) return;
  const seq = ++viewSeq;
  if (viewController) viewController.abort();
  viewController = new AbortController();
  const { signal } = viewController;
  const offset = grow ? loadedGlobalsCount : 0;
  const params = new URLSearchParams({
    target: t,
    limit: String(grow ? PAGE_STEP : PAGE_LIMIT),
    offset: String(offset),
  });
  if ($("gq").value.trim()) params.set("q", $("gq").value.trim());
  updateFilterActions();
  $("globals-empty").hidden = true;
  if (!grow) resetList("globals-rows", "globals-hint", "globals-show-more-wrap");
  $("globals-results").hidden = false;
  try {
    setLoadError("view", "");
    const data = await whileBusy("globals-results", () =>
      get("/api/globals?" + params, signal));
    if (seq !== viewSeq || signal.aborted) return;
    viewLoaded.globals = true;
    renderGlobals(data, { append: grow });
  } catch (error) {
    if (seq !== viewSeq || signal.aborted) return;
    retryGlobalsAppend = grow;
    if (!grow) {
      loadedGlobalsCount = 0;
      $("globals-rows").querySelector("tbody").innerHTML = "";
    }
    $("globals-results").hidden = loadedGlobalsCount === 0;
    $("globals-empty").hidden = true;
    $("globals-show-more-wrap").hidden = true;
    $("globals-hint").hidden = true;
    setLoadError("view", grow && loadedGlobalsCount > 0
      ? "Could not load more globals" + reason(error) + ". The rows already shown are unchanged; use Retry globals to fetch the next page again."
      : "Globals could not be loaded" + reason(error) + ". Use Retry globals to try again.");
  }
}
async function loadHistory(options) {
  const grow = !!(options && options.append);
  const t = $("target").value; if (!t) return;
  const seq = ++viewSeq;
  if (viewController) viewController.abort();
  viewController = new AbortController();
  const { signal } = viewController;
  const offset = grow ? loadedHistoryCount : 0;
  const params = new URLSearchParams({
    target: t,
    limit: String(grow ? PAGE_STEP : PAGE_LIMIT),
    offset: String(offset),
  });
  $("history-empty").hidden = true;
  if (!grow) resetList("history-rows", "history-hint", "history-show-more-wrap");
  $("history-results").hidden = false;
  try {
    setLoadError("view", "");
    const data = await whileBusy("history-results", () =>
      get("/api/history?" + params, signal));
    if (seq !== viewSeq || signal.aborted) return;
    viewLoaded.history = true;
    renderHistory(data, { append: grow });
  } catch (error) {
    if (seq !== viewSeq || signal.aborted) return;
    retryHistoryAppend = grow;
    if (!grow) {
      loadedHistoryCount = 0;
      $("history-rows").querySelector("tbody").innerHTML = "";
    }
    $("history-results").hidden = loadedHistoryCount === 0;
    $("history-empty").hidden = true;
    $("history-show-more-wrap").hidden = true;
    $("history-hint").hidden = true;
    setLoadError("view", grow && loadedHistoryCount > 0
      ? "Could not load more history" + reason(error) + ". The rows already shown are unchanged; use Retry history to fetch the next page again."
      : "History could not be loaded" + reason(error) + ". Use Retry history to try again.");
  }
}
function loadCurrentView(force) {
  if (currentView === "functions") {
    if (force || !viewLoaded.functions) { resetPaging(); return loadFunctions(); }
    return;
  }
  if (currentView === "sections" && (force || !viewLoaded.sections)) return loadSections();
  if (currentView === "globals" && (force || !viewLoaded.globals)) {
    if (force) resetGlobalsPaging();
    return loadGlobals();
  }
  if (currentView === "history" && (force || !viewLoaded.history)) {
    if (force) resetHistoryPaging();
    return loadHistory();
  }
}
function setView(name) {
  if (!VIEWS.includes(name)) return;
  currentView = name;
  if (currentView !== "functions") clearTimeout(searchTimer);
  if (currentView !== "globals") clearTimeout(globalsSearchTimer);
  setLoadError("view", "");
  syncViewChrome();
  loadCurrentView(false);
}
function bindControls() {
  // One document holds every view, so Back returns to the previous one:
  // assignment (not addEventListener) keeps re-binding idempotent.
  globalThis.onpopstate = () => { void start(); };
  $("target").onchange = () => {
    $("status").value = "";
    selectAnyModule();
    pendingStatus = "";
    $("q").value = "";
    $("gq").value = "";
    // Every view now shows the old target; each reloads when next shown.
    VIEWS.forEach((name) => (viewLoaded[name] = false));
    resetPaging();
    resetGlobalsPaging();
    resetHistoryPaging();
    updateFilterActions();
    clearTimeout(searchTimer);
    clearTimeout(globalsSearchTimer);
    void Promise.all([loadSummary(), (async () => {
      if (currentView === "functions") await loadFunctions();
      else await loadCurrentView(true);
    })()]);
  };
  $("status").onchange = onStatusChange;
  $("module").onchange = onModuleChange;
  $("q").oninput = scheduleSearch;
  $("q").onkeydown = (ev) => {
    if (ev.key === "Enter") {
      clearTimeout(searchTimer);
      resetPaging();
      loadFunctions();
    } else if (ev.key === "Escape" && $("q").value) {
      if (ev.preventDefault) ev.preventDefault();
      $("q").value = "";
      clearTimeout(searchTimer);
      resetPaging();
      loadFunctions();
      updateFilterActions();
    }
  };
  $("gq").oninput = scheduleGlobalsSearch;
  $("gq").onkeydown = (ev) => {
    if (ev.key === "Enter") {
      clearTimeout(globalsSearchTimer);
      resetGlobalsPaging();
      loadGlobals();
    } else if (ev.key === "Escape" && $("gq").value) {
      if (ev.preventDefault) ev.preventDefault();
      $("gq").value = "";
      clearTimeout(globalsSearchTimer);
      resetGlobalsPaging();
      loadGlobals();
      updateFilterActions();
    }
  };
  $("clear-filters").onclick = () => {
    if (currentView === "globals") {
      $("gq").value = "";
      clearTimeout(globalsSearchTimer);
      resetGlobalsPaging();
      loadGlobals();
      updateFilterActions();
      restoreFocus(["gq", "main"]);
      return;
    }
    $("status").value = "";
    selectAnyModule();
    pendingStatus = "";
    $("q").value = "";
    resetPaging();
    syncCardActive();
    updateFilterActions();
    clearTimeout(searchTimer);
    loadFunctions();
    restoreFocus(["q", "main"]);
  };
  $("reload").onclick = async () => {
    $("reload").disabled = true;
    $("reload").textContent = "Reloading…";
    try {
      await start();
    } finally {
      $("reload").disabled = false;
      $("reload").textContent = "Reload";
    }
    restoreFocus(["target", "main"]);
  };
  $("retry-summary").onclick = async () => {
    await loadSummary();
    restoreFocus(["retry-summary", "main"]);
  };
  $("retry-functions").onclick = async () => {
    await loadFunctions({ append: retryAppend });
    restoreFocus(["retry-functions", "results", "main"]);
  };
  $("retry-view").onclick = async () => {
    if (currentView === "globals" && retryGlobalsAppend && loadedGlobalsCount > 0) {
      await loadGlobals({ append: true });
    } else if (currentView === "history" && retryHistoryAppend && loadedHistoryCount > 0) {
      await loadHistory({ append: true });
    } else {
      await loadCurrentView(true);
    }
    restoreFocus(["retry-view", currentView + "-results", "results", "main"]);
  };
  $("show-more").onclick = async () => {
    retryAppend = true;
    $("show-more").disabled = true;
    $("show-more").textContent = "Loading more functions…";
    try {
      await loadFunctions({ append: true });
    } finally {
      $("show-more").disabled = false;
    }
    restoreFocus(["show-more", "retry-functions", "results", "main"]);
  };
  $("show-more-globals").onclick = async () => {
    retryGlobalsAppend = true;
    $("show-more-globals").disabled = true;
    $("show-more-globals").textContent = "Loading more globals…";
    try {
      await loadGlobals({ append: true });
    } finally {
      $("show-more-globals").disabled = false;
    }
    restoreFocus(["show-more-globals", "retry-view", "globals-results", "main"]);
  };
  $("show-more-history").onclick = async () => {
    retryHistoryAppend = true;
    $("show-more-history").disabled = true;
    $("show-more-history").textContent = "Loading more history…";
    try {
      await loadHistory({ append: true });
    } finally {
      $("show-more-history").disabled = false;
    }
    restoreFocus(["show-more-history", "retry-view", "history-results", "main"]);
  };
  $("cards").onclick = (ev) => {
    const btn = ev.target.closest("button[data-status]");
    if (!btn) return;
    if (currentView !== "functions") setView("functions");
    const status = btn.getAttribute("data-status");
    $("status").value = ($("status").value === status) ? "" : status;
    onStatusChange();
  };
  $("views").onclick = (ev) => {
    const btn = ev.target.closest("button[data-view]");
    if (!btn) return;
    setView(btn.getAttribute("data-view"));
  };
  $("views").onkeydown = (ev) => {
    const tab = ev.target.closest("button[data-view]");
    if (!tab || !$("views").contains(tab)) return;
    const tabs = Array.from($("views").querySelectorAll("button[data-view]"));
    const current = tabs.indexOf(tab);
    if (current < 0) return;
    let next = -1;
    if (ev.key === "ArrowRight" || ev.key === "ArrowDown") next = (current + 1) % tabs.length;
    else if (ev.key === "ArrowLeft" || ev.key === "ArrowUp") next = (current - 1 + tabs.length) % tabs.length;
    else if (ev.key === "Home") next = 0;
    else if (ev.key === "End") next = tabs.length - 1;
    else return;
    ev.preventDefault();
    const nextTab = tabs[next];
    setView(nextTab.getAttribute("data-view"));
    nextTab.focus();
  };
}
async function init() {
  const boot = await get("/api/bootstrap");
  $("boot-status").hidden = true;
  // A reload re-reads the documents, so nothing already painted counts as loaded.
  VIEWS.forEach((name) => (viewLoaded[name] = false));
  $("reload").hidden = false;
  targets = boot.targets || [];
  bindControls();
  $("no-targets").hidden = !!targets.length;
  if (!targets.length) {
    $("results-status").textContent = "No targets in the coverage documents";
    return;
  }
  $("controls").hidden = false;
  $("views").hidden = false;
  $("target").innerHTML = targets.map(t =>
    "<option value='" + esc(t) + "'>" + esc(t) + "</option>").join("");
  const saved = new URLSearchParams(location.hash.slice(1));
  if (targets.includes(saved.get("target"))) $("target").value = saved.get("target");
  // The hash is the whole navigation state, so a hash without a view names the
  // first one: Back to an entry written before the reader switched views
  // returns to Functions rather than keeping the view they left.
  currentView = VIEWS.includes(saved.get("view")) ? saved.get("view") : "functions";
  pendingStatus = saved.get("status") || "";
  pendingModule = saved.get("module") || "";
  pendingModuleBlank = saved.has("module") && !saved.get("module");
  $("q").value = saved.get("q") || "";
  $("gq").value = saved.get("gq") || "";
  // The bootstrap payload covers the first target with no filters.
  const bootFits = $("target").value === targets[0];
  syncViewChrome();
  let summaryLoad = null;
  if (boot.summary && bootFits) {
    setLoadError("summary", "");
    renderSummary(boot.summary);
  } else {
    summaryLoad = loadSummary();
    // Restored Status/Module values become options only once the summary
    // renders; without them, functions and the view load alongside it.
    if (pendingStatus || pendingModule || pendingModuleBlank) await summaryLoad;
  }
  // The restored state is where this session already is, so the first write
  // replaces the entry the reader arrived on rather than stacking a copy of it.
  lastNav = $("target").value + "|" + currentView;
  hashReady = true;
  updateFilterActions();
  const moduleState = moduleFilterState();
  const unfiltered = !$("status").value && !moduleState.blank && !moduleState.value && !$("q").value.trim();
  let functionsLoad = null;
  if (boot.functions && bootFits && unfiltered) {
    setLoadError("functions", "");
    $("results").hidden = false;
    viewLoaded.functions = true;
    renderFunctions(boot.functions);
  } else {
    functionsLoad = loadFunctions();
  }
  const viewLoad = currentView === "functions" ? null : loadCurrentView(false);
  await Promise.all([summaryLoad, functionsLoad, viewLoad]);
}
function start() {
  return init().catch(error => {
    $("boot-status").hidden = true;
    $("reload").hidden = true;
    $("retry-summary").textContent = "Reload dashboard";
    setLoadError("summary", "Dashboard failed to load" + reason(error)
      + ". Use Reload dashboard to try again.");
    $("retry-summary").onclick = async () => {
      setLoadError("summary", "");
      $("retry-summary").textContent = "Retry summary";
      $("boot-status").hidden = false;
      $("boot-status").textContent = "Loading coverage…";
      await start();
      restoreFocus(["target", "main"]);
    };
    $("retry-summary").focus();
  });
}
// Set before start() so the boot guard sees a client that ran; synchronous, so
// the guard's DOMContentLoaded check (which a deferred client always precedes)
// sees a client that got this far.
globalThis.__rebrewBooted = true;
start();
"""

#: Reports a client that never reached its top-level statement (transfer
#: aborted, 5xx from a proxy, a syntax error); without it the shell would sit
#: on "Loading coverage..." forever with no control that does anything.  The
#: shell is fully static, so the failed state can only be detected from script.
#: Inline in the shell (under a ``script-src`` hash, see ``_BOOT_GUARD_HASH``).
#: It runs on ``DOMContentLoaded``, which a deferred client always precedes, so
#: a client that never reached its first statement is reported the same way an
#: aborted transfer or a parse error is.
_BOOT_GUARD_JS = (
    'document.addEventListener("DOMContentLoaded", () => {\n'
    "  if (globalThis.__rebrewBooted) return;\n"
    '  const s = document.getElementById("boot-status");\n'
    '  if (s) s.textContent = "The dashboard client failed to load. Reload to retry.";\n'
    "  // The failed client is what normally reveals the Reload button.\n"
    '  const b = document.getElementById("reload");\n'
    "  if (b) {\n"
    "    b.hidden = false;\n"
    "    b.onclick = () => location.reload();\n"
    "  }\n"
    "});"
)

_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rebrew coverage dashboard</title>
<link rel="preload" href="/api/bootstrap" as="fetch" crossorigin fetchpriority="high">
<link rel="preload" href="__APP_JS_URL__" as="script">
<link rel="icon" href="__FAVICON__" type="image/svg+xml">
<style>
  body { font-family: var(--rb-sans); margin: 1.5rem;
    background: var(--rb-sunken); color: var(--rb-ink); }
  .skip-link { position: absolute; left: -9999px; top: 0; z-index: 100;
    padding: .5rem 1rem; background: var(--rb-surface); color: var(--rb-accent);
    text-decoration: underline; }
  .skip-link:focus { left: 1rem; top: 1rem; }
  .filters { display: flex; flex-wrap: wrap; gap: .5rem 1rem; align-items: end;
    margin-bottom: .5rem; }
  .filters > div { display: flex; flex-direction: column; gap: .25rem; font-size: var(--rb-size-note); }
  select, input { min-height: 2.75rem; padding: .3rem .5rem; min-width: 10rem;
    font: inherit; border: 1px solid var(--rb-line); border-radius: var(--rb-radius);
    background: var(--rb-surface); color: inherit; }
  :focus-visible { outline: 3px solid var(--rb-accent); outline-offset: 2px; }
  h1 { font-size: var(--rb-size-title); margin-bottom: .25rem; }
  .cards { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0;
    min-height: 4.3rem; }
  .card { border: 1px solid var(--rb-line); border-radius: var(--rb-radius);
    padding: .9rem 1.1rem; min-width: 110px; background: var(--rb-surface); }
  button.card { font: inherit; color: inherit; text-align: left; cursor: pointer; }
  button.card:hover { border-color: var(--rb-line-hi); background: var(--rb-hover); }
  button.card:active { background: var(--rb-pressed); }
  button.card.active, .views button.active { border-color: var(--rb-accent);
    border-width: 2px; box-shadow: 0 0 0 2px var(--rb-ring); }
  /* Weight marks the selected card and tab without relying on border colour (WCAG 1.4.1). */
  button.card.active .label, .views button.active { font-weight: 700; }
  .card .value { font-size: var(--rb-size-value); font-weight: 700; display: block; }
  .label { color: var(--rb-muted); font-size: var(--rb-size-caption); }
__STATUS_CSS__
  .table-scroll { overflow-x: auto; position: relative; min-height: 6rem; }
  .table-scroll[aria-busy="true"]::after {
    content: "Loading…"; position: absolute; inset: 0; display: flex; align-items: center;
    justify-content: center; background: var(--rb-veil);
    font-size: var(--rb-size-note); color: var(--rb-muted);
  }
  .visually-hidden { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem;
    font-size: var(--rb-size-cell); background: var(--rb-surface); }
  th, td { border-bottom: 1px solid var(--rb-line); padding: .3rem .5rem; text-align: left; }
  /* A demangled name or a long path is one unbreakable token, and a table at
     100% width lets that token set the row's width: on a wide monitor the
     Status column ends up a screen away from the VA it belongs to. `anywhere`
     lowers the cell's intrinsic minimum, so the column wraps instead. */
  td { overflow-wrap: anywhere; }
  th { background: var(--rb-sunken); white-space: nowrap; font-weight: 600; }
  tbody tr:hover { background: var(--rb-hover); }
  td.va, code { font-family: var(--rb-mono); }
  #dashboard-error { color: var(--rb-note-ink); background: var(--rb-note-bg);
    border: 1px solid var(--rb-note-ink); border-radius: var(--rb-radius);
    padding: .6rem .8rem; margin: .75rem 0; }
  #empty-state, #no-targets { color: var(--rb-faint); margin: 1rem 0; }
  #results-hint, #globals-hint, #history-hint, #sections-hint {
    color: var(--rb-faint); font-size: var(--rb-size-note); margin: .25rem 0 .5rem; }
  #filter-actions, #show-more-wrap, #globals-show-more-wrap, #history-show-more-wrap,
  #retry-bar { margin: .35rem 0 .75rem; }
  .btn { min-height: 2.75rem; padding: .3rem .75rem; border: 1px solid var(--rb-line);
    border-radius: var(--rb-radius); background: var(--rb-surface);
    color: inherit; font: inherit; cursor: pointer; }
  .btn:hover:not(:disabled) { border-color: var(--rb-line-hi); background: var(--rb-hover); }
  .btn:active:not(:disabled) { background: var(--rb-pressed); }
  button:disabled { opacity: .55; cursor: not-allowed; }
  .views { display: flex; flex-wrap: wrap; gap: .35rem; margin: .75rem 0 .25rem; }
  .views .btn { padding: .3rem .85rem; }
  .view-panel[hidden] { display: none; }
  .link-button { background: none; border: none; padding: 0; color: var(--rb-accent);
    text-decoration: underline; font: inherit; cursor: pointer; }
  .link-button:hover { color: var(--rb-accent-hi); }
  @media (max-width: 40rem) {
    body { margin: 1rem; }
    select, input { min-width: 0; width: 100%; }
    .filters > div { flex: 1 1 100%; }
    .card { min-width: 0; flex: 1 1 6rem; padding: .4rem .6rem; }
    .views .btn { flex: 1 1 auto; text-align: center; }
  }
  @media (forced-colors: active) {
    button.card.active, .views button.active {
      border: 2px solid Highlight;
      box-shadow: none;
    }
    :focus-visible { outline-color: Highlight; }
    #dashboard-error { border-color: CanvasText; color: CanvasText; background: Canvas; }
    .table-scroll[aria-busy="true"]::after {
      background: Canvas;
      color: CanvasText;
      border: 1px solid CanvasText;
    }
__STATUS_FORCED__
  }
  @media (prefers-reduced-motion: reduce) {
    * { transition: none !important; animation: none !important; }
  }
  /* Skip layout/paint for off-screen rows on large result pages. */
  tbody tr { content-visibility: auto; contain-intrinsic-size: auto 2.2rem; }
</style>
<noscript><style>#boot-status { display: none; }</style></noscript>
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
<main id="main" tabindex="-1">
<h1>Rebrew coverage</h1>
<p id="boot-status" role="status">Loading coverage…</p>
<noscript><p id="no-script">The dashboard needs JavaScript to load coverage data.
  Enable it for this page, then reload.</p></noscript>
<p id="no-targets" hidden>No targets found in the coverage documents. Run
  <code>rebrew build-db</code> for this project, then choose Reload.</p>
<div id="controls" class="filters" hidden role="group" aria-label="Coverage filters">
<div>
<label for="target">Target</label>
<select id="target"></select>
</div>
<div id="filter-status">
<label for="status">Status</label>
<select id="status"><option value="">any</option></select>
</div>
<div id="filter-module">
<label for="module">Module</label>
<select id="module"><option value="">any</option></select>
</div>
<div id="filter-q">
<label for="q">Search name, symbol, or address</label>
<input id="q" type="search" size="24" placeholder="e.g. WinMain or 0x401000" autocomplete="off">
</div>
<div id="filter-gq" hidden>
<label for="gq">Search name or address</label>
<input id="gq" type="search" size="24" placeholder="e.g. g_flag or 0x401000" autocomplete="off">
</div>
</div>
<div id="filter-actions" hidden>
<button type="button" class="btn" id="clear-filters">Clear filters</button>
</div>
<div id="views" class="views" hidden role="tablist" aria-label="Coverage views">
<button type="button" role="tab" id="tab-functions" data-view="functions"
  aria-controls="view-functions" class="btn active" aria-selected="true" tabindex="0">Functions</button>
<button type="button" class="btn" role="tab" id="tab-sections" data-view="sections"
  aria-controls="view-sections" aria-selected="false" tabindex="-1">Sections</button>
<button type="button" class="btn" role="tab" id="tab-globals" data-view="globals"
  aria-controls="view-globals" aria-selected="false" tabindex="-1">Globals</button>
<button type="button" class="btn" role="tab" id="tab-history" data-view="history"
  aria-controls="view-history" aria-selected="false" tabindex="-1">History</button>
</div>
<section id="summary" aria-labelledby="summary-heading" aria-busy="false" hidden>
<h2 class="visually-hidden" id="summary-heading">Coverage summary</h2>
<div class="cards" id="cards" role="group" aria-label="Coverage metrics"></div>
</section>
<p class="visually-hidden" id="results-status" role="status" aria-live="polite"></p>
<p id="dashboard-error" role="alert" hidden></p>
<div id="retry-bar" role="group" aria-label="Reload and retry">
<button type="button" class="btn" id="reload" hidden>Reload</button>
<button type="button" class="btn" id="retry-summary" hidden>Retry summary</button>
<button type="button" class="btn" id="retry-functions" hidden>Retry functions</button>
<button type="button" class="btn" id="retry-view" hidden>Retry</button>
</div>
<div id="view-functions" class="view-panel" role="tabpanel" tabindex="0" aria-labelledby="tab-functions">
<p id="results-hint" hidden></p>
<p id="empty-state" hidden></p>
<div id="results" class="table-scroll" tabindex="0" role="region"
  aria-label="Function results" aria-busy="false" hidden>
<table id="rows"><caption class="visually-hidden">Functions matching the selected filters</caption><thead><tr>
  <th scope="col">VA</th><th scope="col">Name</th><th scope="col">Symbol</th>
  <th scope="col">Size</th><th scope="col">Status</th>
  <th scope="col">Module</th><th scope="col">Files</th>
</tr></thead><tbody></tbody></table>
</div>
<div id="show-more-wrap" hidden>
<button type="button" class="btn" id="show-more">Show more functions</button>
</div>
</div>
<div id="view-sections" class="view-panel" role="tabpanel" tabindex="0" aria-labelledby="tab-sections" hidden>
<p id="sections-hint" hidden></p>
<p id="sections-empty" hidden>No section stats for this target. Run
  <code>rebrew build-db</code> for this project, then choose Reload.</p>
<div id="sections-results" class="table-scroll" tabindex="0" role="region"
  aria-label="Section results" aria-busy="false" hidden>
<table id="sections-rows"><caption class="visually-hidden">Per-section cell stats</caption><thead><tr>
  <th scope="col">Section</th><th scope="col">Size</th><th scope="col">Cells</th>
  <th scope="col">Exact</th><th scope="col">Reloc</th><th scope="col">Near</th>
  <th scope="col">Stub</th><th scope="col">Proven</th><th scope="col">Size mismatch</th>
  <th scope="col">Thunk</th><th scope="col">Data</th><th scope="col">Padding</th>
  <th scope="col">Unclassified</th><th scope="col">Other</th>
</tr></thead><tbody></tbody></table>
</div>
</div>
<div id="view-globals" class="view-panel" role="tabpanel" tabindex="0" aria-labelledby="tab-globals" hidden>
<p id="globals-hint" hidden></p>
<p id="globals-empty" hidden></p>
<div id="globals-results" class="table-scroll" tabindex="0" role="region"
  aria-label="Global results" aria-busy="false" hidden>
<table id="globals-rows"><caption class="visually-hidden">Global data symbols</caption><thead><tr>
  <th scope="col">VA</th><th scope="col">Name</th><th scope="col">Decl</th>
  <th scope="col">Size</th><th scope="col">Module</th>
</tr></thead><tbody></tbody></table>
</div>
<div id="globals-show-more-wrap" hidden>
<button type="button" class="btn" id="show-more-globals">Show more globals</button>
</div>
</div>
<div id="view-history" class="view-panel" role="tabpanel" tabindex="0" aria-labelledby="tab-history" hidden>
<p id="history-hint" hidden></p>
<p id="history-empty" hidden>No status changes recorded yet. History appears after
  <code>rebrew build-db</code> when function statuses change.</p>
<div id="history-results" class="table-scroll" tabindex="0" role="region"
  aria-label="History results" aria-busy="false" hidden>
<table id="history-rows"><caption class="visually-hidden">Recent status changes</caption><thead><tr>
  <th scope="col">VA</th><th scope="col">Name</th>
  <th scope="col">Old status</th><th scope="col">New status</th>
  <th scope="col">When</th>
</tr></thead><tbody></tbody></table>
</div>
<div id="history-show-more-wrap" hidden>
<button type="button" class="btn" id="show-more-history">Show more history</button>
</div>
</div>
</main>
<script src="__APP_JS_URL__" defer></script>
<script>__BOOT_GUARD_JS__</script>
</body>
</html>
"""

_APP_JS_BYTES = _APP_JS.encode("utf-8")
_APP_JS_VERSION = hashlib.sha256(_APP_JS_BYTES).hexdigest()[:16]
_APP_JS_ETAG = f'"{_APP_JS_VERSION}"'
_BOOT_GUARD_JS_BYTES = _BOOT_GUARD_JS.encode("utf-8")
#: ``script-src`` source expression for the inline guard, so the shell keeps a
#: strict policy while carrying the guard instead of fetching it.
_BOOT_GUARD_HASH = (
    "sha256-" + base64.b64encode(hashlib.sha256(_BOOT_GUARD_JS_BYTES).digest()).decode()
)
#: Content-hashed so the shell can cache each client immutable.
_APP_JS_URL = f"/app.js?v={_APP_JS_VERSION}"
#: Every request a cold load makes for the document and its clients, in
#: document order.  Their wire bytes share one initial congestion window.
_ENTRY_PATHS = ("/", _APP_JS_URL)
#: The mark, served rather than inlined. A percent-encoded data URI is 443 B
#: of near-incompressible payload in the document that has to fit the initial
#: congestion window, and a tab icon is not first paint: linked, it costs the
#: cold flight nothing.
_FAVICON_SVG = theme.FAVICON_SVG
_FAVICON_SVG_BYTES = _FAVICON_SVG.encode("utf-8")
_FAVICON_VERSION = hashlib.sha256(_FAVICON_SVG_BYTES).hexdigest()[:16]
_FAVICON_ETAG = f'"{_FAVICON_VERSION}"'
#: Carries the same content hash the client does. The browser asks for the
#: icon on every load, and ``private, no-cache`` made that a revalidation
#: round trip per page; hashed, it is immutable and fetched once.
_FAVICON_URL = f"{_FAVICON_PATH}?v={_FAVICON_VERSION}"


def _dashboard_status_css() -> str:
    """Status text rules from ``STATUS_HEX``. DISPATCH is a graph fill only.

    One rule per mark, not per status: the shell ships inside a fixed
    cold-load byte budget, and the six machine verdicts share the error red.
    """
    lines: list[str] = []
    for statuses, color in status_mark_groups():
        weight = "" if statuses == ("UNKNOWN",) else " font-weight: 600;"
        # .label is equally specific and comes first, so this rule colors
        # the summary cards and the table cells alike.
        selectors = ", ".join(f".status-{name}" for name in statuses)
        lines.append(f"  {selectors} {{ color: {color};{weight} }}")
    return "\n".join(lines)


def _dashboard_status_forced() -> str:
    """One forced-colors rule so status marks follow the system palette.

    Every mark carries the shared ``st`` class, so this stays one selector
    however many statuses the mark table holds.
    """
    return "    .st { color: CanvasText; font-weight: 700; }"


# The shell links the content-hashed URL, so only that URL is cached immutable.
_INDEX_HTML = _INDEX_HTML.replace("__STATUS_CSS__", _dashboard_status_css()).replace(
    "__STATUS_FORCED__", _dashboard_status_forced()
)
# Token references resolve to their theme values, so the shell is one file.
_INDEX_HTML = theme.inline(_INDEX_HTML)
_INDEX_HTML = (
    _INDEX_HTML.replace("__APP_JS_URL__", _APP_JS_URL)
    .replace("__BOOT_GUARD_JS__", _BOOT_GUARD_JS)
    .replace("__FAVICON__", _FAVICON_URL)
)
_INDEX_HTML_BYTES = _INDEX_HTML.encode("utf-8")
_INDEX_ETAG = '"' + hashlib.sha256(_INDEX_HTML_BYTES).hexdigest()[:16] + '"'
_CACHE_REVALIDATE = "private, no-cache"
_CACHE_IMMUTABLE = "private, max-age=31536000, immutable"


#: The entry assets compress at max effort (zstd 19 runs at MB/s), which cost
#: ~10 ms of import time on every `rebrew` invocation because CLI composition
#: imports this module for every command.  Build them on the first request that
#: serves an asset instead; the server is the only caller.
@cache
def _index_html_zstd() -> bytes:
    return precompress(_INDEX_HTML_BYTES, "zstd") or _INDEX_HTML_BYTES


@cache
def _index_html_gzip() -> bytes:
    return precompress(_INDEX_HTML_BYTES, "gzip") or _INDEX_HTML_BYTES


@cache
def _app_js_zstd() -> bytes:
    return precompress(_APP_JS_BYTES, "zstd") or _APP_JS_BYTES


@cache
def _app_js_gzip() -> bytes:
    return precompress(_APP_JS_BYTES, "gzip") or _APP_JS_BYTES


@cache
def _favicon_zstd() -> bytes:
    return precompress(_FAVICON_SVG_BYTES, "zstd") or _FAVICON_SVG_BYTES


@cache
def _favicon_gzip() -> bytes:
    return precompress(_FAVICON_SVG_BYTES, "gzip") or _FAVICON_SVG_BYTES


def _int_param(params: dict[str, list[str]], name: str, default: int) -> int:
    """Parse a positive int page-size query param, clamped to ``[1, _MAX_LIMIT]``.

    Missing, empty, non-numeric, or non-positive values fall back to *default*
    so ``limit=0`` / ``limit=-1`` never silently return an empty page.
    """
    values = params.get(name)
    raw = values[0] if values else None
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (ValueError, TypeError):
        return default
    if value <= 0:
        return default
    return min(value, _MAX_LIMIT)


def _offset_param(params: dict[str, list[str]], name: str, default: int = 0) -> int:
    """Parse a non-negative int skip query param (e.g. ``offset``).

    Missing, empty, non-numeric, or negative values fall back to *default*.
    Zero is valid.  Values are **not** capped at ``_MAX_LIMIT`` — that bound
    is for page size only; clamping skip would make rows past the cap
    unreachable via ``limit``+``offset`` pagination.  They are clamped to
    ``VA_MAX`` so an oversized skip is an empty page, not a 500.
    """
    values = params.get(name)
    raw = values[0] if values else None
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (ValueError, TypeError):
        return default
    if value < 0:
        return default
    return min(value, VA_MAX)


def _opt_query(params: dict[str, list[str]], name: str) -> str | None:
    """Return a stripped optional query value, or None when missing/blank."""
    values = params.get(name)
    raw = values[0] if values else None
    if raw is None:
        return None
    stripped = raw.strip()
    return stripped or None


def _query_scope(query: str) -> str:
    """Short suffix naming one path+query pair, or ``""`` when there is none.

    Raw request bytes are not put in the tag: an attacker-chosen path or
    query would then control a response header, and the tag grows without
    bound.  A truncated hash keeps the ETag header a fixed size and still
    separates every representation the server routes on.
    """
    if not query:
        return ""
    return "-" + hashlib.sha256(query.encode("utf-8", "surrogateescape")).hexdigest()[:8]


def _module_query(params: dict[str, list[str]]) -> str | None:
    """Module filter: None when absent, else the stripped value.

    A present empty value matches rows stored with a blank module. This is
    not :func:`_opt_query`: a blank ``target`` is missing, a blank ``module``
    is a value. Callers must parse the query with ``keep_blank_values=True``
    or ``module=`` never arrives.
    """
    if "module" not in params:
        return None
    values = params["module"]
    return (values[0] if values else "").strip()


def _byte_count(value: Any) -> int:
    """Return a non-negative byte count, or raise ValueError.

    Absent and JSON null are 0. Only a real ``int`` counts: ``bool`` is an
    ``int`` subclass (``int(True) == 1``), and a float would truncate.
    """
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"byte count must be a non-negative int, got {value!r}")
    if value < 0:
        raise ValueError(f"negative byte count {value}")
    return value


#: ASCII A-Z to a-z: the whole of SQLite's default LIKE folding, which is the
#: folding the search used to run inside.  ``str.lower`` would also fold
#: non-ASCII and ``str.casefold`` more so (``ß`` to ``ss``), matching rows the
#: SQL query never returned; keeping the table keeps the served rows identical.
_ASCII_FOLD = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _va_query(term: str) -> int | None:
    """Integer address when *term* is hex, else ``None``.

    Four or more hex digits, optional ``0x`` prefix. ``0x401000`` and
    ``00401000`` name the same address. Shorter text stays a name search
    so ``add`` is not read as ``0xadd``.
    """
    text = term.strip()
    if len(text) >= 2 and text[0] == "0" and text[1] in "xX":
        text = text[2:]
    if len(text) < 4 or len(text) > 16:
        return None
    if any(c not in "0123456789abcdefABCDEF" for c in text):
        return None
    value = int(text, 16)
    if value > VA_MAX:
        return None
    return value


def _name_match(term: str, va: int, *texts: str) -> bool:
    """Whether one row matches *term*: an exact VA, or a substring of *texts*.

    The Python restatement of the WHERE clause the SQLite reader built:
    ``(name LIKE ? ESCAPE '\\\\' OR symbol LIKE ? ESCAPE '\\\\' OR va = ?)`` with
    the pattern ``%term%`` and the term's own wildcards escaped first.  That
    pattern is a literal substring test, so escaping and re-unwrapping the
    wildcards buys nothing here — what has to be reproduced is the folding
    (:data:`_ASCII_FOLD`) and NULL, which matched nothing through LIKE and is
    the empty string here.
    """
    wanted = _va_query(term)
    if wanted is not None and va == wanted:
        return True
    needle = term.translate(_ASCII_FOLD)
    return any(needle in (text or "").translate(_ASCII_FOLD) for text in texts)


#: The mapping one request reads, pinned for its duration.  ``bootstrap`` and
#: ``handle`` each build one response from more than one collection, and the
#: loader re-stats the directory on every call: two calls in one response can
#: straddle a rebuild and pair one build's targets with the next build's rows.
#: The SQLite reader pinned the same window with one read transaction; a frozen
#: snapshot makes a single collection consistent, and this makes the response
#: consistent.  Nested scopes reuse the outer pin and only the outermost
#: restores it, so a route that calls another route still reads one build.
_CURRENT_SNAPSHOTS: ContextVar[Mapping[str, CoverageSnapshot] | None] = ContextVar(
    "rebrew_dashboard_snapshots", default=None
)


def _readable_snapshots(dashboard: Dashboard) -> Mapping[str, CoverageSnapshot]:
    """The dashboard's snapshots, refusing a directory that yields none.

    The one rule behind the two probes that must not answer "ok" over an empty
    page: ``rebrew dashboard``'s startup check and ``/api/health``.  A project
    that never ran ``build-db`` has no documents, and a directory whose every
    document is corrupt reads the same way — either way there is nothing to
    serve, and the reader that skips an unreadable document says so on the log
    stream rather than here.
    """
    snapshots = dashboard.snapshots()
    if not snapshots:
        raise CoverageTomlError(
            f"{dashboard.db_dir}: no readable coverage document (run 'rebrew build-db' first)"
        )
    return snapshots


def _history_va(row: Mapping[str, Any]) -> int:
    """A history row's VA, 0 for a document that stores nothing usable there.

    The column was ``INTEGER NOT NULL CHECK (va >= 0)``, so the SQLite reader
    had no absent case to render (that is why its ``if va is not None`` arm
    never fired).  Only a hand-edited document reaches the fallback, and 0 is
    the value the same CHECK would have allowed.
    """
    va = row.get("va")
    # bool is an int subclass; ``va = true`` is not an address.
    return va if isinstance(va, int) and not isinstance(va, bool) and va >= 0 else 0


def _history_text(value: Any) -> str:
    """A history text column as ``str``, for a row read out of a document.

    TOML has no null, and the writer stores a transition's absent
    old/new status as the empty string; this is the same answer for anything
    that is not text, so a hand-edited row cannot crash a page.
    """
    return value if isinstance(value, str) else ""


def _coverage_etag(db_dir: Path) -> str:
    """A short tag for the coverage documents' current bytes.

    The old validator was ``mtime_ns``-``size`` of ``coverage.db``.  The
    documents are one per target, so the tag has to cover all of them: tagging
    from the newest file would leave a validator held for target A looking
    current after target B was rebuilt.  The per-file stats are hashed rather
    than concatenated so the header stays a fixed size however many targets a
    project grows.  An absent or unreadable directory hashes to the same value
    every time, which never matches a tag from a readable one.
    """
    parts: list[str] = []
    for path in sorted(db_dir.glob(_COVERAGE_GLOB)):
        try:
            st = path.stat()
        except OSError:
            continue
        parts.append(f"{path.name}:{st.st_mtime_ns:x}:{st.st_size:x}")
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


class Dashboard:
    """Read-only view over one project's coverage documents.

    *db_dir* is the DIRECTORY holding ``coverage-<target>.toml``, not a database
    file: the reader resolves one document per target from it, and it is also
    what the validator and the liveness probe stat.  *load* defaults to
    :func:`rebrew.coverage_toml.load_all_coverage_from`, which memoizes on the
    stat of every document in the directory and returns THE SAME mapping while
    none of them moved, so a request that changes nothing costs one stat per
    document and no parse.
    """

    def __init__(
        self,
        db_dir: Path,
        *,
        load: Callable[[Path], Mapping[str, CoverageSnapshot]] = load_all_coverage_from,
        served: Callable[[], dict[str, Any]] | None = None,
        expose_paths: bool = True,
    ) -> None:
        self.db_dir = Path(db_dir)
        self._load = load
        #: Running server totals the probe reports; ``None`` off the HTTP
        #: server (tests, direct queries), where no request has been served.
        self.served = served
        #: Whether a wire response may carry the absolute coverage directory.
        #: False on a non-loopback bind, where any client that can reach the
        #: host would otherwise learn the operator's project path.
        self.expose_paths = expose_paths

    def snapshots(self) -> Mapping[str, CoverageSnapshot]:
        """Every readable target's snapshot, keyed by target name.

        Returns the pinned mapping when a request scope holds one (see
        :data:`_CURRENT_SNAPSHOTS`), so a response built from several calls
        reads one build.
        """
        pinned = _CURRENT_SNAPSHOTS.get()
        if pinned is not None:
            return pinned
        return self._load(self.db_dir)

    @contextmanager
    def _snapshot_scope(self) -> Iterator[None]:
        """Pin one mapping for the duration of one response."""
        if _CURRENT_SNAPSHOTS.get() is not None:
            yield
            return
        token = _CURRENT_SNAPSHOTS.set(self._load(self.db_dir))
        try:
            yield
        finally:
            _CURRENT_SNAPSHOTS.reset(token)

    def targets(self) -> list[str]:
        """The readable targets, in the order the SQL ``ORDER BY target`` gave.

        ``targets()`` served the SQLite dashboard from ``SELECT DISTINCT target
        FROM metadata``; a target is now a document, so it is the set of files
        that parsed.  Sorted because a directory listing's order is not a fact.
        """
        return sorted(self.snapshots())

    def bootstrap(self) -> dict[str, Any]:
        """Targets plus the first target's summary/functions in one payload.

        Collapses the HTML app's cold-start waterfall (targets → summary +
        functions) into a single round trip.  Filter/paging still use the
        dedicated endpoints after the first paint.  The nested reads share one
        pinned snapshot.
        """
        with self._snapshot_scope():
            targets = self.targets()
            payload: dict[str, Any] = {
                "targets": targets,
                "count": len(targets),
                "total": len(targets),
                "limit": len(targets),
                "offset": 0,
                "paged": False,
                "target": None,
                "summary": None,
                "functions": None,
            }
            if not targets:
                return payload
            target = targets[0]
            payload["target"] = target
            payload["summary"] = self._summary_lookup(target)
            if payload["summary"] is not None:
                payload["functions"] = self.functions(target, limit=_BOOTSTRAP_FUNCTION_LIMIT)
            # Scrubbed on the way out of this method, not only on the wire: the
            # summary carries the snapshot's frozen ``MappingProxyType``, which
            # ``json.dumps`` refuses, and this is a public payload builder rather
            # than a private step.  ``_json`` scrubs again, which is idempotent
            # and therefore the same bytes.  Annotated rather than returned
            # straight through: ``_scrub_invisible`` answers ``Any``, and this
            # method's promise is the payload shape.
            scrubbed: dict[str, Any] = _scrub_invisible(payload)
            return scrubbed

    def _summary_lookup(self, target: str) -> dict[str, Any] | None:
        """The summary payload for *target*, or ``None`` when it has no document.

        Two answers, not three: ``function_stats`` is DERIVED from the stored
        function rows (``coverage_toml._derive_function_stats``), so the
        unreadable-metadata-row case the SQLite reader answered with a 500
        cannot happen — the aggregates are integers by construction.  A
        document that does not parse at all is not a target here (the loader
        skips it and logs), which is the same 404 an unknown target gets.
        """
        snapshot = self.snapshots().get(target)
        if snapshot is None:
            return None
        stats = snapshot.function_stats
        # Headline coverage = byte-matched (EXACT/RELOC) bytes / text size;
        # the old covered_bytes summed every function's size, so an all-STUB
        # binary reported ~100% "coverage".  Identified bytes
        # (incl. stubs) stays available as a separate field.
        matched_b, identified_b, total_b = (
            _byte_count(stats.get(name)) for name in _FUNCTION_STAT_BYTE_COUNTS
        )
        # A byte count past the .text size (stale SIZE fields, a function span
        # outside .text) divides to 102.4%, and the coverage cards would render
        # that as a broken number.  The share is capped at a full section and
        # the excess is logged rather than shown.
        for name, value in (("matched_bytes", matched_b), ("covered_bytes", identified_b)):
            if total_b and value > total_b:
                _warn_request(
                    "function_stats for %r: %s is %d, past the %d-byte .text; capping",
                    target,
                    name,
                    value,
                    total_b,
                )
        return {
            "target": target,
            "function_stats": stats,
            "coverage_pct": floor_pct(min(matched_b, total_b) if total_b else matched_b, total_b),
            "identified_pct": floor_pct(
                min(identified_b, total_b) if total_b else identified_b, total_b
            ),
        }

    def functions(
        self,
        target: str,
        *,
        status: str | None = None,
        module: str | None = None,
        q: str | None = None,
        limit: int = _DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        snapshot = self.snapshots().get(target)
        rows: list[Function] = []
        if snapshot is not None:
            wanted_status = canonical_status(status) if status else None
            for fn in snapshot.functions:
                # Code rows only, and the filter is the same one the COUNT
                # total ran over, so the page and the total cannot disagree.
                if fn.markerType not in FUNCTION_MARKERS:
                    continue
                if wanted_status is not None and fn.status != wanted_status:
                    continue
                if module is not None and fn.module != module:
                    continue
                if q and not _name_match(q, fn.va, fn.name, fn.symbol):
                    continue
                rows.append(fn)
        # VA order, which is the file's own order (the writer sorts by VA) and
        # the ORDER BY this read used to carry.  Sorted here rather than
        # trusted: a hand-edited document's row order is not a fact.  The
        # ordering check is O(n) and settles the common writer-sorted case,
        # which is the whole page for an unfiltered request.
        if any(rows[i - 1].va > rows[i].va for i in range(1, len(rows))):
            rows.sort(key=lambda fn: fn.va)
        page = rows[offset : offset + limit]
        return {
            "target": target,
            "count": len(page),
            "total": len(rows),
            "limit": limit,
            "offset": offset,
            "paged": True,
            "cols": list(_FUNCTION_COLS),
            "functions": [
                [
                    f"0x{fn.va:08x}",
                    fn.name,
                    fn.symbol,
                    fn.size,
                    fn.status,
                    fn.module,
                    _files_display(fn.files),
                ]
                for fn in page
            ],
        }

    def sections(self, target: str) -> dict[str, Any]:
        # One pass: the section_name is the key of the document's
        # ``[sections."…"]`` table, so the join the SQLite reader used to reach
        # the section's own size is a field lookup.  Rows ship as arrays under
        # ``cols`` like every other list route; a per-row key costs more than
        # the numbers it labels once a target has a few hundred sections, and
        # this response is never paged.
        snapshot = self.snapshots().get(target)
        rows: list[list[Any]] = []
        if snapshot is not None:
            for name, section in sorted(snapshot.sections.items()):
                counts = section.bucket_counts
                # The served column order (``_SECTION_COLS``) is the bucket
                # name order: the SQLite SELECT aliased ``exact_count`` and its
                # siblings, and the reader named the counts after the columns
                # they are served in, so this is a key lookup per column.  A
                # column the reader does not emit is a KeyError here rather
                # than a silent zero.
                rows.append([name, section.size, *(counts[column] for column in _SECTION_COLS[2:])])
        return {
            "target": target,
            "count": len(rows),
            "total": len(rows),
            "limit": len(rows),
            "offset": 0,
            "paged": False,
            "cols": list(_SECTION_COLS),
            "sections": rows,
        }

    def globals(
        self,
        target: str,
        *,
        module: str | None = None,
        q: str | None = None,
        limit: int = _DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        snapshot = self.snapshots().get(target)
        rows: list[Global] = []
        if snapshot is not None:
            for item in snapshot.globals:
                if module is not None and item.module != module:
                    continue
                if q and not _name_match(q, item.va, item.name):
                    continue
                rows.append(item)
        rows.sort(key=lambda item: item.va)
        page = rows[offset : offset + limit]
        return {
            "target": target,
            "count": len(page),
            "total": len(rows),
            "limit": limit,
            "offset": offset,
            "paged": True,
            "cols": list(_GLOBAL_COLS),
            "globals": [
                [f"0x{item.va:08x}", item.name, item.decl, item.size, item.module] for item in page
            ],
        }

    def history(
        self, target: str, *, limit: int = _DEFAULT_LIMIT, offset: int = 0
    ) -> dict[str, Any]:
        snapshot = self.snapshots().get(target)
        rows = list(reversed(snapshot.history)) if snapshot is not None else []
        page = rows[offset : offset + limit]
        by_va = snapshot.functions_by_va if snapshot is not None else {}
        return {
            "target": target,
            "count": len(page),
            "total": len(rows),
            "limit": limit,
            "offset": offset,
            "paged": True,
            "cols": list(_HISTORY_COLS),
            "history": [
                [
                    f"0x{_history_va(row):08x}",
                    # A VA with no current function row (removed since) keeps
                    # name ''.  The SQLite reader LEFT JOINed ``functions`` for
                    # exactly this field.
                    (by_va[_history_va(row)].name if _history_va(row) in by_va else ""),
                    # old_status/new_status are absent for a VA's first recorded
                    # transition.  Sent as "" like every other text column
                    # here, so a client reading rows under `cols` never has to
                    # null-check one route and not the others.
                    _history_text(row.get("old_status")),
                    _history_text(row.get("new_status")),
                    _history_text(row.get("changed_at")),
                ]
                for row in page
            ],
        }

    def target_known(self, target: str) -> bool:
        """True when *target* has a readable coverage document."""
        if not target:
            return False
        return target in self.snapshots()

    def has_representation(self, path: str, query: dict[str, list[str]]) -> bool:
        """True when a GET of routed *path* would answer 200 (so 304 may stand in).

        Every precondition the route itself rejects on has to be replayed
        here, or a revalidation answers 304 for a request the same GET
        answers 400/404/500 with: the client would read a stale body as the
        current one instead of being told its query was wrong.
        """
        if path not in _TARGET_ROUTES:
            return True
        target = _opt_query(query, "target") or ""
        if path == "/api/summary":
            return bool(target) and self._summary_lookup(target) is not None
        if not self.target_known(target):
            return False
        if path == "/api/functions":
            # A status outside the stored vocabulary makes the route answer
            # 400, not an empty page, so no representation exists to stand in
            # for.
            status = _opt_query(query, "status")
            if status is not None and canonical_status(status) not in COVERAGE_DB_STATUSES:
                return False
        return True

    def response_etag(self, path: str) -> str:
        """Strong shell/asset etag; weak coverage+request etag so rebuilds invalidate JSON caches.

        The weak tag covers the path and query as well as the coverage
        documents: a validator identifies one representation, and two routes on
        the same target answer different bodies.  Tagging everything with the
        documents alone let a validator held from
        ``/api/functions?target=a`` answer 304 for ``/api/summary?target=a``,
        and the client then rendered one endpoint's cached rows under the
        other's labels.
        """
        parsed = urlparse(path)
        if parsed.path == "/":
            return _INDEX_ETAG
        if parsed.path == "/app.js":
            return _APP_JS_ETAG
        if parsed.path == _FAVICON_PATH:
            return _FAVICON_ETAG
        scope = _query_scope(f"{parsed.path}?{parsed.query}" if parsed.query else "")
        return f'W/"{_coverage_etag(self.db_dir)}{scope}"'

    def handle(self, method: str, path: str, query: dict[str, list[str]]) -> tuple[int, str, str]:
        """Route a request.  Returns (status, content-type, body)."""
        parsed = urlparse(path)
        # 404 before 405: a path this server does not serve has no resource to
        # list methods for, and ``Allow: GET, HEAD`` on a 405 for an unknown
        # path advertises a resource that does not exist.  A GET of the same
        # unknown path already answers ``not_found``.
        if parsed.path not in _KNOWN_ROUTES:
            return self._error(404, "not_found", f"no such endpoint {parsed.path!r}")
        if method not in ("GET", "HEAD"):
            return self._error(
                405, "method_not_allowed", "method not allowed (read-only; GET, HEAD only)"
            )
        if parsed.path == "/":
            return 200, "text/html; charset=utf-8", _INDEX_HTML
        if parsed.path == "/app.js":
            return 200, "application/javascript; charset=utf-8", _APP_JS
        if parsed.path == _FAVICON_PATH:
            return 200, "image/svg+xml", _FAVICON_SVG
        if parsed.path == "/api/bootstrap":
            return self._json(200, self.bootstrap())
        if parsed.path == "/api/health":
            # Liveness plus one real read of the coverage documents: a process
            # whose db/ has been moved, emptied, or filled with unreadable
            # documents must report 500, not a cheerful 200 over an empty page.
            # The read is the loader's own stat-keyed scan, not the full query
            # chain, so a slow route cannot make the probe flap.  The running
            # request and 5xx totals ride along: otherwise the only error count
            # the server has is the one it prints when it stops, so a run that
            # fails every query still probes "ok" for its whole life.  So does
            # the in-flight connection gauge, the count admission refuses on.
            payload: dict[str, Any] = {
                "status": "ok",
                "targets": len(_readable_snapshots(self)),
            }
            if self.expose_paths:
                # Named for what it is: a directory of coverage documents.
                # The old key was `db`, from the SQLite store this replaced.
                payload["coverage_dir"] = str(self.db_dir)
            if self.served is not None:
                payload.update(self.served())
            return self._json(200, payload)
        if parsed.path == "/api/targets":
            targets = self.targets()
            return self._json(
                200,
                {
                    "targets": targets,
                    "count": len(targets),
                    "total": len(targets),
                    "limit": len(targets),
                    "offset": 0,
                    "paged": False,
                },
            )

        # Every path above answered; the rest are the target-scoped routes,
        # which all require ?target=.
        target = _opt_query(query, "target") or ""
        if not target:
            return self._error(400, "missing_target", "missing required query parameter 'target'")
        with self._snapshot_scope():
            if parsed.path == "/api/summary":
                # Single document read: no document → 404 unknown target,
                # otherwise 200.  Avoids a second target_known probe on the
                # happy path while keeping status codes accurate.
                result = self._summary_lookup(target)
                if result is None:
                    return self._error(404, "unknown_target", f"unknown target {target!r}")
                return self._json(200, result)
            if not self.target_known(target):
                return self._error(404, "unknown_target", f"unknown target {target!r}")
            if parsed.path == "/api/functions":
                status = _opt_query(query, "status")
                if status is not None and canonical_status(status) not in COVERAGE_DB_STATUSES:
                    # An unknown status is a client mistake, not an empty
                    # page: matching nothing reads as "this target has no
                    # STTUB functions", which is a wrong answer.  The
                    # accepted set is the one a stored row can hold, so
                    # every status the summary renders links to its own
                    # filtered list.
                    return self._error(
                        400,
                        "invalid_status",
                        f"unknown status {status!r} (expected one of {sorted(COVERAGE_DB_STATUSES)})",
                    )
                return self._json(
                    200,
                    self.functions(
                        target,
                        status=status,
                        module=_module_query(query),
                        q=_opt_query(query, "q"),
                        limit=_int_param(query, "limit", _DEFAULT_LIMIT),
                        offset=_offset_param(query, "offset", 0),
                    ),
                )
            if parsed.path == "/api/sections":
                return self._json(200, self.sections(target))
            if parsed.path == "/api/globals":
                return self._json(
                    200,
                    self.globals(
                        target,
                        module=_module_query(query),
                        q=_opt_query(query, "q"),
                        limit=_int_param(query, "limit", _DEFAULT_LIMIT),
                        offset=_offset_param(query, "offset", 0),
                    ),
                )
            # Named, not a fall-through: a path that reaches here is in
            # ``_KNOWN_ROUTES`` and not one of the branches above, so the
            # unguarded tail this replaces would have served ``/api/history``'s
            # rows under whatever path the client asked for.  That is a silent
            # wrong answer rather than a visible failure, and the only way it
            # happens is a new entry in ``_TARGET_ROUTES`` with no branch.
            if parsed.path == "/api/history":
                return self._json(
                    200,
                    self.history(
                        target,
                        limit=_int_param(query, "limit", _DEFAULT_LIMIT),
                        offset=_offset_param(query, "offset", 0),
                    ),
                )
            # Unreachable while ``_KNOWN_ROUTES`` and these branches agree.
            # 404 rather than a raise: the client asked for a path this server
            # does not serve, which is exactly what the 404 above the 405
            # answers, and an exception here would surface as 500
            # ``internal_error`` for a client-side mistake.
            return self._error(404, "not_found", f"no such endpoint {parsed.path!r}")

    @staticmethod
    def _json(status: int, payload: dict[str, Any]) -> tuple[int, str, str]:
        return (
            status,
            "application/json; charset=utf-8",
            json.dumps(_scrub_invisible(payload), separators=(",", ":")),
        )

    @staticmethod
    def _error(status: int, code: str, message: str) -> tuple[int, str, str]:
        """JSON error envelope: a stable ``code`` plus the human ``error`` text.

        ``code`` is what a client branches on; ``error`` stays prose for the
        dashboard's own error line and for anyone reading the response.
        """
        return Dashboard._json(status, {"error": message, "code": code})


def _scrub_invisible(value: Any) -> Any:
    """*value* with invisible bidi and zero-width formatting characters removed.

    Row text reaches a response from a target binary, BinSync state, or an
    import table.  Those characters render as nothing while reordering or
    hiding the text around them, so a name or status cell can be made to read
    as something else.  Scrubbed once on the way out rather than in the
    client, which keeps the entry assets inside the cold-load wire budget.

    Keys are scrubbed too, not just values: ``/api/summary`` returns
    ``function_stats`` from the target's document, so a key is as
    target-controlled as a name cell.  Two keys that differ only in invisible
    characters collapse to one; the client reads fixed keys, so a dropped
    duplicate costs nothing, while an unscrubbed one can reorder the text
    around it on screen.

    Any ``Mapping`` is rebuilt as a plain ``dict``, not just a ``dict``: the
    snapshot hands over ``MappingProxyType`` (that is what makes it frozen), and
    a proxy is not JSON-serializable.  Rebuilding is also what lets the keys be
    scrubbed, which a proxy cannot do in place.
    """
    if isinstance(value, str):
        return strip_bidi_format(value)
    if isinstance(value, list):
        return [_scrub_invisible(item) for item in value]
    if isinstance(value, Mapping):
        return {
            (strip_bidi_format(key) if isinstance(key, str) else key): _scrub_invisible(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        # The reader hands over tuples where the document stores a list
        # (a function's ``files``); this response never contains one, but a
        # route that echoed a snapshot field would otherwise raise here.
        return [_scrub_invisible(item) for item in value]
    return value


def _files_display(files: Sequence[str]) -> str:
    """Join a function's file list for the table cell.

    The database stored ``json.dumps(files)`` and the old reader decoded it
    back, with a fast path for the common ``["a.c"]``-shaped payloads; the TOML
    reader hands the list over already decoded, so the decode and its fast path
    are gone and only the join is left.  Each item is ``str``-ed because the
    writer stringifies whatever the catalog put in the list, so a number in
    there still renders.
    """
    return ", ".join(str(name) for name in files)


def _local_interface_ips() -> set[str]:
    """The host's own addresses, for a wildcard bind's Host allow-list.

    A wildcard bind (``--host 0.0.0.0``) has no single expected Host: users
    reach it as ``localhost``, ``127.0.0.1``, or one of the machine's own
    addresses, and the previous allow-list held only the literal wildcard, so
    every real request was 403'd.  Resolver-based (no netlink walk): an
    unresolvable hostname just yields an empty set.
    """
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None)
    except OSError:
        return set()
    return {str(info[4][0]) for info in infos if info[4]}


def allowed_hosts_for(host: str, port: int) -> frozenset[str]:
    """Host-header values that must be accepted for a server bound to *host*:*port*.

    Loopback binds also accept their numeric/localhost aliases (users open
    ``localhost`` and ``127.0.0.1`` interchangeably); anything else would
    break normal use.  Every other Host value is rejected by
    :func:`_host_allowed`, which keeps browser-based attackers (DNS
    rebinding against ``127.0.0.1``, cross-site reads of the JSON APIs)
    from reaching the dashboard.

    A wildcard bind (``0.0.0.0`` / ``::`` / empty) listens on every interface,
    so its aliases also cover loopback and the machine's own addresses —
    without them the documented ``--host 0.0.0.0`` produced a server that
    answered only a literal ``Host: 0.0.0.0``.
    """
    wildcard = host in ("0.0.0.0", "::", "")
    loopback = wildcard or host in ("127.0.0.1", "localhost", "::1")
    names = {host} if host else set()
    if loopback:
        names |= {"127.0.0.1", "localhost", "::1"}
    if wildcard:
        names |= _local_interface_ips()
    hosts: set[str] = set()
    for name in names:
        display = f"[{name}]" if ":" in name else name
        hosts.add(f"{display}:{port}".lower())
        if port == 80:  # default port may be omitted in a Host header
            hosts.add(display.lower())
    return frozenset(hosts)


def _host_allowed(host_header: str, allowed: frozenset[str]) -> bool:
    """True when the request's Host header matches one of *allowed* exactly."""
    return host_header.strip().lower() in allowed


def _parse_accept_encoding(accept_encoding: str) -> dict[str, float]:
    """Map coding → q-value (missing codings are absent; invalid q → 0)."""
    accepted: dict[str, float] = {}
    for part in accept_encoding.lower().split(","):
        coding, *parameters = part.split(";")
        coding = coding.strip()
        if coding not in ("gzip", "zstd", "*"):
            continue
        weight = 1.0
        for parameter in parameters:
            name, _, value = parameter.partition("=")
            if name.strip() == "q":
                try:
                    weight = float(value.strip())
                except ValueError:
                    weight = 0.0
                break
        if not (0 <= weight <= 1):
            weight = 0.0
        accepted[coding] = weight
    return accepted


def _encoding_q(accepted: dict[str, float], coding: str) -> float:
    """Effective q for *coding*; an explicit ``coding;q=0`` beats ``*``."""
    if coding in accepted:
        return accepted[coding]
    return accepted.get("*", 0.0)


def _negotiate_encoding(accept_encoding: str) -> _WireEncoding | None:
    """Pick ``zstd`` or ``gzip`` by q-value; zstd wins ties."""
    accepted = _parse_accept_encoding(accept_encoding)
    best: _WireEncoding | None = None
    best_q = 0.0
    for coding in _ENCODING_PREFERENCE:
        weight = _encoding_q(accepted, coding)
        if weight <= 0:
            continue
        # Strictly higher q wins; equal q keeps the earlier preference entry.
        if best is None or weight > best_q:
            best = coding
            best_q = weight
    return best


def _compress(body: bytes, encoding: _WireEncoding) -> bytes:
    """Compress *body* at the per-request effort for *encoding*.

    Gzip ``mtime=0`` like every other compressor here: the ETag is the
    uncompressed hash, so two identical bodies must produce identical gzip
    bytes or the same tag serves a different body across requests.
    """
    if encoding == "zstd":
        return zstandard.ZstdCompressor(level=_ZSTD_LEVEL).compress(body)
    return gzip.compress(body, compresslevel=_GZIP_LEVEL, mtime=0)


def _maybe_compress(
    body: bytes, accept_encoding: str, *, cold_start: bool = False
) -> tuple[bytes, _WireEncoding | None]:
    """Return ``(body, encoding)``; compress only when it shrinks the wire bytes.

    *cold_start* picks the max-effort levels for the preloaded bootstrap body;
    see ``_BOOTSTRAP_PATH``.
    """
    if len(body) < _MIN_COMPRESS_BYTES:
        return body, None
    encoding = _negotiate_encoding(accept_encoding)
    if encoding is None:
        return body, None
    if cold_start:
        # Same levels the import-time static blobs use, and the same
        # "did it shrink" rule: this body goes out once per load and is a 304
        # on every load after, so the extra effort is paid about once and buys
        # bytes inside the initial congestion window.
        compressed = precompress(body, encoding)
        return (body, None) if compressed is None else (compressed, encoding)
    compressed = _compress(body, encoding)
    if len(compressed) >= len(body):
        return body, None
    return compressed, encoding


def _precompressed_static(
    accept_encoding: str,
    *,
    zstd_blob: bytes | None,
    gzip_blob: bytes | None,
    raw: bytes,
) -> tuple[bytes, _WireEncoding | None]:
    """Serve an import-time precompressed blob for the negotiated encoding."""
    encoding = _negotiate_encoding(accept_encoding)
    if encoding == "zstd" and zstd_blob is not None:
        return zstd_blob, "zstd"
    if encoding == "gzip" and gzip_blob is not None:
        return gzip_blob, "gzip"
    return raw, None


def _if_none_match(header: str, etag: str) -> bool:
    """True when *header* is ``*`` or lists *etag* (weak/strong compare on value)."""
    raw = header.strip()
    if not raw:
        return False
    if raw == "*":
        return True
    for part in raw.split(","):
        candidate = part.strip()
        if candidate == etag:
            return True
        # RFC 9110 weak comparison: strip a leading W/ on either side.
        if candidate.startswith("W/") and candidate[2:] == etag:
            return True
        if etag.startswith("W/") and etag[2:] == candidate:
            return True
    return False


def _success_cache_control(path: str, query: dict[str, list[str]]) -> str:
    """Immutable for the current content-hashed asset URLs; revalidate everything else."""
    if path in _UNCACHEABLE_ROUTES:
        return "no-store"
    # Each hashed URL pins bytes that cannot change under it, so a stale
    # mark or client is a new URL, not a revalidation.  An unhashed request
    # for the same path revalidates, which is what a hand-typed URL gets.
    if path == "/app.js" and _opt_query(query, "v") == _APP_JS_VERSION:
        return _CACHE_IMMUTABLE
    if path == _FAVICON_PATH and _opt_query(query, "v") == _FAVICON_VERSION:
        return _CACHE_IMMUTABLE
    return _CACHE_REVALIDATE


#: Browser hardening on every response, including the 403 and the 503, which
#: are written before (or without) a handler.  Shared so a response built
#: outside ``_Handler`` cannot carry a weaker set than one built inside it.
#: The CSP keeps CSS inline in the shell and JS same-origin at /app.js, and
#: confines JSON fetching to same-origin; ``data:`` images carry the inline
#: mark that stops a /favicon.ico 404 per load.
_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
)
#: Content-Security-Policy, sent after ``Cache-Control`` on every response.
#: The inline boot guard is allowed by its exact hash rather than
#: 'unsafe-inline'; the rest of the shell's JS is same-origin /app.js.
_CSP = (
    f"default-src 'none'; script-src 'self' '{_BOOT_GUARD_HASH}'; "
    "style-src 'unsafe-inline'; "
    "connect-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'"
)


def _security_headers(cache_control: str) -> tuple[tuple[str, str], ...]:
    """The hardening set every response carries, in wire order.

    ``Cache-Control`` is the one member that differs per status, and it rides
    with the rest so a response reads the same whichever of the two writers
    emitted it.
    """
    return (*_SECURITY_HEADERS, ("Cache-Control", cache_control), ("Content-Security-Policy", _CSP))


def _send_over_capacity(
    request: socket.socket | tuple[bytes, socket.socket], request_id: str, active: int, cap: int
) -> None:
    """Answer a connection refused by the admission cap with 503 ``server_busy``.

    Written straight to the accepted socket, since no handler exists to route
    it.  Same envelope, same hardening, same ``X-Request-Id`` every routed
    response carries, plus ``Retry-After``: a client that is being shed should
    be able to tell "come back in a second" from "the server died", and a bare
    close tells it neither.  A peer that hung up mid-write is not a fault.
    """
    body = json.dumps(
        {
            "error": f"too many connections in flight ({active} of {cap}); retry shortly",
            "code": "server_busy",
        },
        separators=(",", ":"),
    ).encode()
    if not isinstance(request, socket.socket):
        # A non-socket get_request (a UNIX-family server sharing this code)
        # has no HTTP response to write; the caller still closes the request.
        log.info("%s cannot write a refusal to a %s", request_id, type(request).__name__)
        return
    # A 5xx is a 5xx wherever it is written: ``log_request`` counts one for a
    # routed response, and a run that is being shed is a run the error total on
    # ``/api/health`` and at shutdown has to show.
    with _Handler._stats_lock:
        _Handler._server_errors += 1
    lines = [
        "HTTP/1.1 503 Service Unavailable",
        # IMF-fixdate: RFC 9110 requires the English day/month names, and
        # email.utils is where they are hardcoded.  strftime reads them from
        # the process LC_TIME, so it emits "Mi., 28 Sep 2026" wherever
        # something set a non-C locale.
        f"Date: {formatdate(usegmt=True)}",
        f"Retry-After: {_BUSY_RETRY_AFTER_S}",
        "Content-Type: application/json; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
        f"X-Request-Id: {request_id}",
    ]
    lines += [f"{name}: {value}" for name, value in _security_headers("no-store")]
    try:
        request.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
    except OSError as exc:
        log.info("%s client vanished before the refusal reached it: %s", request_id, exc)


def _escape_log_text(text: str) -> str:
    return strip_bidi_format(text).translate(_LOG_CONTROL_CHARS)


def _stamped(level: str, message: str) -> str:
    """The leading stamp every line on the server's console stream carries.

    Access lines, error records, and the lifecycle lines around a run all
    start with it, so one timestamp column orders the whole stream and one
    grep finds a request by id.
    """
    return f"{time.strftime(_LOG_TIME_FORMAT, time.gmtime())} {level:<8} {message}"


def _server_notice(level: str, message: str) -> None:
    """Write one lifecycle line (bind, warning, shutdown) to the log stream.

    ``message`` is Rich markup; the surrounding text is local (host, port,
    resolved path), never request-derived.
    """
    console.print(_stamped(level, message), soft_wrap=True)


def _attach_server_log_handler() -> Callable[[], None]:
    """Send this module's ERROR/WARNING lines to the same console as the access log.

    Without a handler, ``logging`` falls back to ``lastResort``: bare messages
    on stderr with no timestamp, interleaved with stamped access lines.  The
    formatter below gives the errors the same leading stamp and a level column,
    so the server's whole output is one greppable stream.

    Returns a disposer.  Attaching mutates the module logger (a handler, the
    level, ``propagate``), and the run that installs it ends without restoring
    it: a long-lived process that serves the dashboard and then logs again keeps
    a handler writing to the finished run's console, and ``propagate = False``
    silences the root logger besides.  The disposer restores all three.
    """
    handler = logging.StreamHandler(console.file)
    handler_formatter = logging.Formatter(
        f"%(asctime)s {_LOG_LEVEL_FORMAT} %(message)s", _LOG_TIME_FORMAT
    )
    handler_formatter.converter = time.gmtime
    handler.setFormatter(handler_formatter)
    handler.set_name("rebrew-dashboard")
    replaced = [existing for existing in log.handlers if existing.get_name() == handler.get_name()]
    for existing in replaced:
        log.removeHandler(existing)
    previous_level = log.level
    previous_propagate = log.propagate
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False

    def restore() -> None:
        _remove_identity(log.handlers, handler)
        for existing in replaced:
            log.addHandler(existing)
        log.setLevel(previous_level)
        log.propagate = previous_propagate

    return restore


def _remove_identity(items: list[Any], item: Any) -> None:
    """Remove *item* from *items* by identity, not equality.

    Two handlers compare equal (``Logger`` compares nothing, but ``Handler``
    does not implement ``__eq__`` and a future subclass might), and removing
    the wrong one would restore a stranger's handler.
    """
    for index, candidate in enumerate(items):
        if candidate is item:
            del items[index]
            return


def _log_failed_request(reason: str, path: str, exc: BaseException, request_id: str) -> None:
    """One ERROR line per failed request: id, reason, path, and a scrubbed traceback.

    The traceback used to ride along on a ``log.debug(..., exc_info=True)``,
    which Python drops without a DEBUG-configured handler: a handler bug
    reached the client as a bare 500 and the operator got nothing but
    ``repr(exc)``.  It is formatted here rather than passed as ``exc_info``
    because an exception raised on a request carries remote-controlled text
    (a route's query value, a DB row) into its frames, and that must be
    escaped before it reaches a terminal, exactly as ``log_message`` escapes
    the request line.  ``request_id`` is the id on the request's access line.
    """
    frames = "".join(traceback.format_exception(exc)).rstrip()
    log.error(
        "%s %s for %s\n%s", request_id, reason, _escape_log_text(path), _escape_log_text(frames)
    )


class _Handler(BaseHTTPRequestHandler):
    dashboard: Dashboard
    #: Host headers this server must answer; everything else gets 403.
    allowed_hosts: frozenset[str] = frozenset()
    # Browsers speak HTTP/1.1; keep the TCP connection open across the HTML
    # shell plus /api/bootstrap (and later filter fetches) instead of a fresh
    # handshake per request.  Content-Length is set on every response so
    # persistent connections stay framed correctly.
    protocol_version = "HTTP/1.1"
    # Socket timeout (StreamRequestHandler.setup): an idle or half-open
    # keep-alive client is dropped instead of pinning its handler thread and
    # descriptor for the server's lifetime.
    timeout: ClassVar[float | None] = _KEEPALIVE_IDLE_TIMEOUT_S
    # Headers and body leave as two writes on an unbuffered socket, so Nagle
    # holds the body's first segment until the header block is acknowledged:
    # a delayed-ACK round trip on the critical path to first byte.
    disable_nagle_algorithm = True
    #: Access-log clock for the request in flight (see handle_one_request).
    _request_started: float
    #: Correlation id stamped per request; ``"-"`` until the first one is parsed.
    _request_id: str = "-"
    #: Body length the access line reports; ``"-"`` until a body is built.
    _response_size: int | str = "-"
    #: Served-request totals, printed once when the server stops.
    _stats_lock: ClassVar[threading.Lock] = threading.Lock()
    _requests: ClassVar[int] = 0
    _server_errors: ClassVar[int] = 0
    _slowest_ms: ClassVar[float] = 0.0

    @classmethod
    def reset_served_totals(cls) -> None:
        """Zero the lifetime totals, so a run reports its own requests only."""
        with cls._stats_lock:
            cls._requests = 0
            cls._server_errors = 0
            cls._slowest_ms = 0.0

    def _respond(self, method: str) -> None:
        # getattr: requestline is set by parse_request, and a handler built
        # without a socket (tests) has none to correlate on.
        _stamp_request(self._request_id, getattr(self, "requestline", ""))
        if not _host_allowed(self.headers.get("Host", ""), self.allowed_hosts):
            status, content_type, body = self.dashboard._error(
                403, "host_not_allowed", "request Host not allowed (wrong or missing Host header)"
            )
            body_bytes = body.encode("utf-8")
            self._response_size = len(body_bytes)
            self.send_response(403)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body_bytes)))
            self._write_security_headers(cache_control="no-store")
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(body_bytes)
            return

        # Read the ETag (asset hash or DB mtime) BEFORE the query: a
        # ``build-db`` swap between query and stat would otherwise tag the old
        # body with the new ETag, and the browser would revalidate that stale
        # body as fresh until the next rebuild.  An old ETag on a new body
        # only costs one extra refetch.  A matching If-None-Match on a routed
        # GET/HEAD answers 304 without running the query.  A target-scoped
        # route without ``?target=``, with an unknown target, or with a
        # ``status`` outside the vocabulary has no representation to
        # revalidate (``If-None-Match: *`` and the DB-wide ETag included), so
        # it falls through to its 400/404.
        etag = self.dashboard.response_etag(self.path)
        parsed = urlparse(self.path)
        # keep_blank_values: a present ``module=`` filters blank modules.
        query = parse_qs(parsed.query, keep_blank_values=True)
        logged_error = False
        route_started = time.perf_counter()
        try:
            # The target probe reads the coverage documents, so it shares the
            # 500 guard below.
            if (
                method in ("GET", "HEAD")
                and parsed.path in _ROUTES
                and _if_none_match(self.headers.get("If-None-Match", ""), etag)
                and self.dashboard.has_representation(parsed.path, query)
            ):
                status, content_type, body = HTTPStatus.NOT_MODIFIED, "", ""
            else:
                status, content_type, body = self.dashboard.handle(method, self.path, query)
        except CoverageTomlError as exc:
            # An unreadable coverage directory must answer 500 JSON instead of
            # killing the handler thread with no response at all.  This is the
            # shape the removed SQLite read-error handler had and keeps its
            # ``database_error`` code: the loader skips one unreadable DOCUMENT
            # (a target the user can still see the others beside), while this
            # covers the whole directory yielding nothing, which only
            # ``/api/health`` asks about.  The detail stays on the log stream
            # only — LAN clients must not learn paths from the wire body.
            _log_failed_request("dashboard query failed", self.path, exc, self._request_id)
            logged_error = True
            status, content_type, body = self.dashboard._error(
                500, "database_error", "database error"
            )
        except Exception as exc:  # last-resort handler guard
            # Any other unexpected error (a bug in a route, an OSError on a
            # sidecar read) gets the same treatment: without this the thread
            # dies and the client sees a connection reset instead of a 500.
            _log_failed_request("dashboard handler failed", self.path, exc, self._request_id)
            logged_error = True
            status, content_type, body = self.dashboard._error(
                500, "internal_error", "internal server error"
            )
        if status >= 500 and not logged_error:
            # A route that answers 500 on its own (corrupt function_stats) is
            # a server-side failure with no exception to attach: the request
            # line names the path and the caller's own log explains the row.
            log.error(
                "%s dashboard %s %s returned %d",
                self._request_id,
                method,
                _escape_log_text(self.path),
                status,
            )
        if status == HTTPStatus.NOT_MODIFIED:
            self._send_not_modified(etag, _success_cache_control(parsed.path, query))
            return

        body_bytes = body.encode("utf-8")
        encoding: _WireEncoding | None = None
        entry_asset = False
        if status == 200:
            # Shell HTML and the static clients are immutable for a given
            # process: serve the import-time zstd/gzip blobs instead of
            # recompressing every request.
            accept = self.headers.get("Accept-Encoding", "")
            if body is _INDEX_HTML:
                entry_asset = True
                body_bytes, encoding = _precompressed_static(
                    accept,
                    zstd_blob=_index_html_zstd(),
                    gzip_blob=_index_html_gzip(),
                    raw=_INDEX_HTML_BYTES,
                )
            elif body is _APP_JS:
                entry_asset = True
                body_bytes, encoding = _precompressed_static(
                    accept,
                    zstd_blob=_app_js_zstd(),
                    gzip_blob=_app_js_gzip(),
                    raw=_APP_JS_BYTES,
                )
            elif body is _FAVICON_SVG:
                body_bytes, encoding = _precompressed_static(
                    accept,
                    zstd_blob=_favicon_zstd(),
                    gzip_blob=_favicon_gzip(),
                    raw=_FAVICON_SVG_BYTES,
                )
            else:
                body_bytes, encoding = _maybe_compress(
                    body_bytes, accept, cold_start=parsed.path == _BOOTSTRAP_PATH
                )

        self._response_size = len(body_bytes)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        # An uncacheable route answers 200 with no validator: the probe's
        # ETag, once handed out, would outlive the document read that
        # produced it, and a client revalidating it by hand gets a stale
        # "ok" for coverage that has since gone unreadable.
        cacheable = status == 200 and parsed.path not in _UNCACHEABLE_ROUTES
        if cacheable:
            self.send_header("ETag", etag)
        if encoding:
            self.send_header("Content-Encoding", encoding)
        if status == 200:
            self.send_header("Vary", "Accept-Encoding")
            if not entry_asset:
                # Route cost, so the Network panel separates the query from
                # the transfer.  The entry assets are excluded: their cold
                # flight is budgeted against the initial congestion window
                # and a constant reads the same in every request.
                route_ms = (time.perf_counter() - route_started) * 1000.0
                self.send_header("Server-Timing", f"route;dur={route_ms:.1f}")
        self._write_security_headers(
            cache_control=(
                _success_cache_control(parsed.path, query) if status == 200 else "no-store"
            )
        )
        if status == 405:
            self.send_header("Allow", "GET, HEAD")
        self.end_headers()
        # HEAD: headers only (RFC 9110); body length still advertised.
        if method != "HEAD":
            self.wfile.write(body_bytes)

    def _send_not_modified(self, etag: str, cache_control: str) -> None:
        self.send_response(304)
        self.send_header("ETag", etag)
        self.send_header("Vary", "Accept-Encoding")
        self._write_security_headers(cache_control=cache_control)
        self.end_headers()

    def _write_security_headers(self, *, cache_control: str) -> None:
        """Browser hardening shared by every response, including early 403s.

        Successful GETs may be stored but must revalidate (ETag → 304) so a
        ``rebrew build-db`` rebuild is never served as a silent stale page; the
        content-hashed /app.js URL is immutable.  Errors stay no-store so a
        failed probe is not sticky.
        """
        for name, value in _security_headers(cache_control):
            self.send_header(name, value)

    @override
    def end_headers(self) -> None:
        # Every route is body-less and never reads rfile, so a request body
        # would be parsed as the next pipelined request.  Close instead.
        # send_header("Connection", "close") also sets close_connection.
        # headers is unset when send_error fires before parse_request (414).
        headers = getattr(self, "headers", None)
        if headers is not None and (
            headers.get("Content-Length", "0").strip() not in ("", "0")
            or headers.get("Transfer-Encoding")
        ):
            self.send_header("Connection", "close")
        super().end_headers()

    def do_GET(self) -> None:  # (http.server API)
        self._respond("GET")

    def do_HEAD(self) -> None:
        self._respond("HEAD")

    @override
    def send_response(self, code: int, message: str | None = None) -> None:
        """Status line, ``Date``, and the request id; no ``Server`` banner.

        ``BaseHTTPRequestHandler.send_response`` also emits ``Server:
        BaseHTTP/0.6 Python/<patch>``.  It is 38 bytes on every response,
        charged against the per-response header reserve on the cold-load
        congestion window, and it names the interpreter patch level to a LAN
        client that has no use for it.

        ``X-Request-Id`` carries the same ``r<N>`` the access and error log
        lines use, so a caller holding a 500 can hand the operator one token.
        """
        self.log_request(code, self._response_size)
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())
        self.send_header("X-Request-Id", self._request_id)

    @override
    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        """Answer http.server's own errors with the routes' JSON envelope.

        http.server raises 501 only for a method with no ``do_*`` handler;
        every method but GET/HEAD goes through ``_respond`` for the documented
        405 + ``Allow``.  Parse errors (400/414/431/505) keep their status but
        drop the stdlib HTML page and close the connection.
        """
        if code == HTTPStatus.NOT_IMPLEMENTED and self.command:
            self._respond(self.command)
            return
        _stamp_request(self._request_id, getattr(self, "requestline", ""))
        status = HTTPStatus(code)
        # Rejected before routing, so there is no route to log the failure:
        # the record carries the id of the request whose access line is in the
        # stream, at the level the status deserves (a malformed request is the
        # client's, a 5xx is ours), instead of a bare INFO line with no id.
        log.log(
            logging.ERROR if code >= 500 else logging.WARNING,
            "%s rejected %s: code %d, message %s",
            self._request_id,
            _escape_log_text(getattr(self, "requestline", "")) or "-",
            code,
            _escape_log_text(message or status.phrase),
        )
        # Scrub like every routed body (``Dashboard._json``): http.server's own
        # messages quote the request line, so an RLO in a crafted request would
        # otherwise reach the client as unscrubbed formatting text.
        body = json.dumps(
            {
                "error": strip_bidi_format(message) if message else status.phrase,
                "code": _HTTP_ERROR_CODES.get(code, "request_error"),
            },
            separators=(",", ":"),
        ).encode()
        self._response_size = len(body)
        self.send_response(code, message)
        self.send_header("Connection", "close")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._write_security_headers(cache_control="no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    @override
    def log_message(self, fmt: str, *args: Any) -> None:  # quiet default logging
        # markup=False: the logged request line is remote-controlled text; a
        # path like "/[bold]x" must not be interpreted as Rich markup (log
        # tampering / terminal escape injection).  soft_wrap: a long request
        # line must stay one log entry instead of wrapping into several.  The
        # stamp and level match the ``log`` records, so the access line and the
        # error line for one request sort and read as one stream.
        console.print(
            _escape_log_text(_stamped("INFO", f"{self.address_string()} {fmt % args}")),
            markup=False,
            soft_wrap=True,
        )

    @override
    def handle_one_request(self) -> None:  # (http.server API)
        # Access-log clock: stamped per request so log_request can report how
        # long the handler took.  A keep-alive connection runs many requests
        # through one handler instance, so this cannot be set once at init.
        # The correlation id is stamped here too, for the same reason: one
        # id per request, shared by the access line and every error line it
        # produces.
        self._request_started = time.perf_counter()
        self._request_id = f"r{next(_REQUEST_IDS)}"
        self._response_size = "-"
        # Reset the line with the id: a parse error never reaches ``_respond``,
        # and a stale line from the previous request on this keep-alive thread
        # would point a fault at the wrong request.
        _stamp_request(self._request_id, "")
        super().handle_one_request()

    @override
    def log_request(
        self, code: int | str = "-", size: int | str = "-"
    ) -> None:  # (http.server API)
        """Request line, status, handler time, and the served-request totals."""
        started = getattr(self, "_request_started", None)
        elapsed_ms = 0.0 if started is None else (time.perf_counter() - started) * 1000.0
        status = int(code) if str(code).lstrip("-").isdigit() else 0
        with self._stats_lock:
            type(self)._requests += 1
            if status >= 500:
                type(self)._server_errors += 1
            type(self)._slowest_ms = max(type(self)._slowest_ms, elapsed_ms)
        if elapsed_ms >= _SLOW_REQUEST_MS:
            # An outlier, not a fault: the access line already reports the
            # status, and this reports the one number that says the route is
            # the problem.  The request line is remote text, so it is escaped
            # like every other request-derived string on this stream.
            log.warning(
                "%s slow request %.1fms: %s",
                self._request_id,
                elapsed_ms,
                _escape_log_text(getattr(self, "requestline", "-")),
            )
        self.log_message(
            '%s "%s" %s %s %.1fms',
            self._request_id,
            self.requestline,
            str(code),
            str(size),
            elapsed_ms,
        )


#: Connections holding a handler thread right now, with the lock guarding it.
#: Module-level, like ``_Handler``'s counters, so the number ``/api/health``
#: reports is the number admission compares against ``_MAX_ACTIVE_CONNECTIONS``.
_ACTIVE_LOCK = threading.Lock()
_ACTIVE_CONNECTIONS = 0


def _reserve_connection_slot(cap: int) -> int | None:
    """Take one handler slot, or report the in-flight count when the cap is full.

    Returns the count that refused the connection, so the caller logs and
    answers with the same number.
    """
    global _ACTIVE_CONNECTIONS
    with _ACTIVE_LOCK:
        if cap <= _ACTIVE_CONNECTIONS:
            return _ACTIVE_CONNECTIONS
        _ACTIVE_CONNECTIONS += 1
        return None


def _release_connection_slot() -> None:
    global _ACTIVE_CONNECTIONS
    with _ACTIVE_LOCK:
        _ACTIVE_CONNECTIONS -= 1


def active_connections() -> int:
    """Connections currently holding a handler thread (a gauge, not a total)."""
    with _ACTIVE_LOCK:
        return _ACTIVE_CONNECTIONS


def served_totals() -> dict[str, Any]:
    """Running totals and the in-flight gauge for ``/api/health``.

    Read under the same lock that ``log_request`` updates, so the probe never
    reports a total from a torn read.  ``active_connections`` is a gauge
    alongside them: a run shedding clients at the in-flight cap logs a refusal
    per connection, but without the count a probe watching the probe has no way
    to see the saturation building before the refusals start.
    """
    with _Handler._stats_lock:
        totals = {
            "requests": _Handler._requests,
            "server_errors": _Handler._server_errors,
            "slowest_ms": round(_Handler._slowest_ms, 1),
        }
    totals["active_connections"] = active_connections()
    return totals


class _DashboardServer(ThreadingHTTPServer):
    """Server that reports a fault on the same stream as the access log.

    ``socketserver.BaseServer.handle_error`` prints a bare rule-bracketed
    traceback straight to stderr: no stamp, no level, no correlation id, and
    no counter.  A client that closed the connection between our status line and
    its body (routine on a keep-alive server) therefore dumped a stack trace an
    operator could neither read as part of the request stream nor pivot back
    to.  The override sends both cases through ``log`` with the stamped request
    id, and keeps a vanished client out of the server-error total that the
    shutdown line reports.
    """

    #: Connections allowed to hold a handler thread at once; see
    #: ``_MAX_ACTIVE_CONNECTIONS``.  Instance-level so a test can lower it.
    _max_active_connections: int = _MAX_ACTIVE_CONNECTIONS

    @property
    def _active(self) -> int:
        """Connections currently holding a handler slot.

        The count is the module's, not this instance's (see
        :data:`_ACTIVE_CONNECTIONS`), so ``/api/health`` reports the same number
        admission decides on.  Read-only: a slot is taken and given back by
        :func:`_reserve_connection_slot` and :func:`_release_connection_slot`,
        never by assigning to it.
        """
        return active_connections()

    @override
    def process_request(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: Any
    ) -> None:
        """Admit a connection only while a handler slot is free.

        ``ThreadingHTTPServer`` spends one OS thread and one descriptor per
        accepted socket, for as long as the peer holds it, and the per-handler
        idle timeout is the only thing that ends that.  A client that opens
        connections and then says nothing therefore grows both counts without
        bound, so the connection past the cap is answered 503 ``server_busy``
        and closed.  The refusal is a response, not a bare close: a client that
        sees the connection drop has to guess between "the server died" and
        "try again", while 503 plus ``Retry-After`` says both, in the same
        error envelope every other failure uses.
        """
        active = _reserve_connection_slot(self._max_active_connections)
        if active is not None:
            # Its own correlation id, not the accept thread's unset one, so the
            # refusal the client holds points at the line the log carries.
            request_id = f"r{next(_REQUEST_IDS)}"
            _stamp_request(request_id, "")
            log.warning(
                "%s refusing connection from %s: %d already in flight (cap %d)",
                request_id,
                _escape_log_text(str(client_address)),
                active,
                self._max_active_connections,
            )
            _send_over_capacity(request, request_id, active, self._max_active_connections)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            _release_connection_slot()
            raise

    @override
    def process_request_thread(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: Any
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            _release_connection_slot()

    @override
    def handle_error(
        self, request: socket.socket | tuple[bytes, socket.socket], client_address: Any
    ) -> None:
        exc = sys.exc_info()[1]
        request_id, line = _request_context()
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            # The peer hung up before the response was written.  Nothing the
            # server can do about it, so it is not a fault: INFO, and no
            # contribution to the error count.
            log.info("%s client disconnected serving %s", request_id, line)
            return
        with _Handler._stats_lock:
            _Handler._server_errors += 1
        log.error(
            "%s unhandled %s from %s serving %s\n%s",
            request_id,
            type(exc).__name__,
            _escape_log_text(str(client_address)),
            line,
            _escape_log_text(traceback.format_exc().rstrip()),
        )


app = typer.Typer(
    help="Serve a read-only web dashboard over the coverage documents.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Usage:[/bold]\n\n"
        "  rebrew build-db · · · · · · · · Write db/coverage-<target>.toml first\n\n"
        "  rebrew dashboard · · · · · · · Serve on http://127.0.0.1:8000\n\n"
        "  rebrew dashboard --port 9000 · Custom port\n\n"
        "  rebrew dashboard --json · · · · Print bind URL + db path, then exit\n\n"
        "[bold]Endpoints:[/bold]\n\n"
        "  / · · · · · · · · · · · · HTML shell (targets, summary, function search)\n\n"
        "  /app.js · · · · · · · · · Deferred dashboard client\n\n"
        "  /api/bootstrap · · · · · · Targets + first target summary/functions\n\n"
        "  /api/health · · · · · · · · Liveness: server up + coverage readable\n\n"
        "  /api/targets · · · · · · List targets\n\n"
        "  /api/summary?target= · · Coverage stats (target required)\n\n"
        "  /api/functions?target= · Function rows (status/module/q/limit/offset)\n\n"
        "  /api/sections?target= · · Per-section cell stats\n\n"
        "  /api/globals?target= · · Global data rows (module/q/limit/offset)\n\n"
        "  /api/history?target= · · Status-change history (limit/offset)\n\n"
        "[dim]Read-only: the documents are opened for reading only. "
        "Target-scoped routes need ?target= "
        "(400 if missing, 404 if unknown; a target is one readable "
        "coverage-<target>.toml; an unknown status= is "
        "400, not an empty page). A present empty "
        "module= matches a blank module. Non-GET/HEAD on a served route → 405 "
        "with Allow: GET, HEAD; a path the server does not serve → 404 whatever "
        "the method; a directory yielding no readable document → 500 "
        "database_error on /api/health. A connection past the in-flight cap → "
        "503 server_busy with Retry-After. Error bodies are "
        '{"error": "<message>", "code": "<code>"}; branch on code.[/dim]'
    ),
)


@app.callback(invoke_without_command=True)
def main(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
    root: Path | None = typer.Option(None, "--root", help="Project root directory"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Serve the coverage documents as a read-only web dashboard."""
    root_dir = root.resolve() if root else Path.cwd().resolve()
    db_dir = resolve_db_dir(root_dir, json_output=json_output)

    # Fail fast on a directory with nothing readable in it: the same rule
    # /api/health probes, so a run that starts is a run whose probe can answer.
    try:
        _readable_snapshots(Dashboard(db_dir))
    except CoverageTomlError as exc:
        error_exit(str(exc), json_mode=json_output)

    if json_output:
        # Machine-readable probe: emit the bind URL and the coverage directory,
        # then exit.  Starting the server here would hang every ``rebrew
        # dashboard --json | jq`` consumer (and mix the later "serving…" line
        # onto stderr).
        json_print({"url": f"http://{host}:{port}", "coverage_dir": str(db_dir)})
        return

    # Non-loopback binds expose the read-only coverage API with no auth
    # (SECURITY.md).  Warn once at startup so ``--host 0.0.0.0`` is never silent.
    if host not in ("127.0.0.1", "localhost", "::1"):
        _server_notice(
            "WARNING",
            f"[yellow]warning:[/] dashboard bound to {escape(host)}:{port} with no "
            "authentication — any client that can reach this host can read the "
            "coverage documents",
        )

    try:
        server = _DashboardServer((host, port), _Handler)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            error_exit(
                f"Port {port} on {host} is already in use (another dashboard or server?). "
                "Stop it, or pick a free port with --port.",
            )
        raise
    # Request handlers must not keep the process alive after Ctrl+C.  A daemon
    # thread is left out of ThreadingMixIn._threads, so server_close()'s join
    # has nothing to wait on and returns while an idle keep-alive client is
    # still up; block_on_close is deliberately not set either.
    server.daemon_threads = True
    _Handler.dashboard = Dashboard(
        db_dir,
        served=served_totals,
        expose_paths=host in ("127.0.0.1", "localhost", "::1"),
    )
    _Handler.allowed_hosts = allowed_hosts_for(host, port)
    _Handler.reset_served_totals()
    _server_notice(
        "INFO",
        f"[green]Rebrew dashboard on http://{escape(host)}:{port}[/] — "
        f"[dim]serving {escape(str(db_dir))} (Ctrl+C to stop)[/dim]",
    )
    restore_log = _attach_server_log_handler()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _server_notice("INFO", "[dim]Dashboard stopped.[/dim]")
    except Exception as exc:
        # A fault in the accept loop otherwise reaches the operator as a raw
        # traceback, unstamped, on a stream the shutdown line has just declared
        # a normal stop.  Record it with the stamp and level the rest of the
        # run uses, then let it propagate as the non-zero exit it is.
        _log_failed_request("dashboard server failed", "the accept loop", exc, "-")
        raise
    finally:
        server.server_close()
        # Lifetime totals: the per-request access line says how one request
        # went, this says how the run went (volume, 5xx count, worst latency).
        # /api/health carries the same numbers while the run is still going.
        totals = served_totals()
        _server_notice(
            "INFO",
            f"[dim]served {totals['requests']} requests, "
            f"{totals['server_errors']} server errors, "
            f"slowest {totals['slowest_ms']:.1f}ms[/dim]",
        )
        # Last: the totals line is the run's own output, so the log stream it
        # shares is restored only once the run has said everything.
        restore_log()


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
