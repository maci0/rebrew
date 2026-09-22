"""dashboard.py – Read-only web dashboard over the coverage database.

Serves the SQLite ``coverage.db`` (built by ``rebrew build-db``) over a tiny
HTTP server with no dependencies beyond the stdlib.  Every endpoint is
read-only: the database is opened in ``mode=ro`` and non-GET requests are
rejected with 405.

Endpoints
---------
``GET /``                      → HTML shell (functions, sections, globals, history)
``GET /app.js``                → deferred dashboard client (preloaded + ``defer``)
``GET /api/bootstrap``         → targets + first target's summary/functions (one RTT)
``GET /api/targets``           → list of targets (includes count/total)
``GET /api/summary?target=``   → function stats + coverage % (target required)
``GET /api/functions?target=`` → function rows as arrays under ``cols`` (filters: status, module, q, limit, offset)
``GET /api/sections?target=``  → per-section cell stats (includes count/total/limit/offset)
``GET /api/globals?target=``   → global data rows (filters: q, limit, offset; includes total)
``GET /api/history?target=``   → status-change history (filters: limit, offset; includes total)

Target-scoped endpoints return 400 when ``target`` is missing/empty and 404 when
the target is unknown.  ``GET /api/summary`` returns 500 when the target's
``function_stats`` metadata row exists but is unreadable (corrupt JSON or a
non-object), so clients are not told the target is missing.  Non-GET/HEAD
methods return 405 with ``Allow: GET, HEAD``.  A request that carries a body is
answered with ``Connection: close`` (no route reads one).  Requests whose ``Host`` header
does not match the bound host (or a loopback alias) are rejected with 403, so
a web page the analyst visits cannot reach the server via DNS rebinding.
List endpoints expose ``count`` (rows in this page), ``total`` (matching rows),
and the applied ``limit`` / ``offset`` (offset is 0 when the endpoint has no page;
``/api/sections``, ``/api/targets``, and ``/api/bootstrap`` always report offset 0).
Successful 200 responses negotiate ``zstd`` then ``gzip`` (``Accept-Encoding``
quality weights; explicit ``coding;q=0`` beats ``*``), carry an ``ETag`` (HTML
or ``/app.js`` content hash, or DB mtime), and use ``Cache-Control: private,
no-cache`` so browsers can 304 without serving a stale body after ``build-db``.
A matching ``If-None-Match`` on a routed path is answered 304 before any
SQLite query runs.
The static HTML shell and ``/app.js`` client are zstd- and gzip-precompressed at
import time so entry assets skip per-request compression CPU.  The shell
``<head>`` preloads ``/api/bootstrap`` (``as=fetch`` + ``crossorigin`` +
``fetchpriority=high``) and ``/app.js`` (``as=script``); the deferred client
fetches with ``credentials: omit`` so the cold-start payload can reuse that
preload.  Keeping JS out of the document lets the browser paint the loading
chrome before the script finishes downloading.
JSON uses compact separators; function/global/history rows are arrays under
``cols``.  The handler speaks HTTP/1.1 so browsers reuse one TCP connection for
the shell, ``/app.js``, bootstrap payload, and later filter fetches.

The query layer (``Dashboard``) is separated from the HTTP plumbing so tests
exercise it without opening a socket.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qs, urlparse

import typer
import zstandard
from rich.console import Console
from rich.markup import escape

from rebrew.build_db import resolve_db_dir
from rebrew.cli import error_exit, json_print
from rebrew.workspace import open_sqlite_ro

console = Console(stderr=True)
log = logging.getLogger(__name__)

_LOG_CONTROL_CHARS = {code: f"\\x{code:02x}" for code in (*range(0x20), *range(0x7F, 0xA0))}
_LOG_CONTROL_CHARS[ord("\\")] = "\\\\"

_DEFAULT_LIMIT = 100
_MAX_LIMIT = 5000
_FUNCTION_COLS = ("va", "name", "symbol", "size", "status", "module", "files")
_GLOBAL_COLS = ("va", "name", "decl", "size", "module")
_HISTORY_COLS = ("va", "name", "old_status", "new_status", "changed_at")
#: Paths ``Dashboard.handle`` serves; only these may short-circuit to 304.
_ROUTES = frozenset(
    {
        "/",
        "/app.js",
        "/api/bootstrap",
        "/api/targets",
        "/api/summary",
        "/api/functions",
        "/api/sections",
        "/api/globals",
        "/api/history",
    }
)
# Below this size framing usually costs more than it saves on a LAN.
_MIN_COMPRESS_BYTES = 256
# Per-request dynamic JSON: mid effort (bodies are rebuilt every request).
_GZIP_LEVEL = 5
_ZSTD_LEVEL = 5
# Static HTML shell: max effort once at import; served precompressed thereafter.
_GZIP_PRECOMPRESS_LEVEL = 9
_ZSTD_PRECOMPRESS_LEVEL = 19
_WireEncoding = Literal["zstd", "gzip"]
# Preference when several encodings share the same positive q-value.
_ENCODING_PREFERENCE: tuple[_WireEncoding, ...] = ("zstd", "gzip")
#: Request-scoped connection so nested query methods share one SQLite handle.
_CURRENT_CONN: ContextVar[sqlite3.Connection | None] = ContextVar(
    "rebrew_dashboard_conn", default=None
)


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
let pageLimit = 100;
let currentView = "functions";
// Filters restored from the URL hash before their options exist.
let pendingStatus = "";
let pendingModule = "";
// Hash writes start once init has restored state, so a reload keeps it.
let hashReady = false;
const VIEWS = ["functions", "sections", "globals", "history"];
const PAGE_STEP = 500;
const PAGE_MAX = 5000;
const loadErrors = { summary: "", functions: "", view: "" };
const busyCounts = new Map();
const viewLoaded = { sections: false, globals: false, history: false };
async function get(path, signal) {
  // credentials:omit matches <link rel=preload as=fetch crossorigin> so the
  // cold-start bootstrap fetch can reuse the preload cache.
  const r = await fetch(path, { signal, credentials: "omit" });
  if (!r.ok) throw new Error(path + " -> " + r.status);
  return r.json();
}
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
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}
function formatWhen(value) {
  if (!value) return "";
  // Rebrew stores UTC instants (ISO-8601).  Zone-less forms must not be
  // parsed as the browser's local wall time: Date.parse treats a bare
  // "YYYY-MM-DDTHH:MM:SS" as local, which shifts the display by the host
  // offset and becomes Invalid Date in a spring-forward gap (e.g. 02:30
  // on America/New_York transition night).
  let raw = String(value).trim();
  if (/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}(:\\d{2}(\\.\\d+)?)?$/.test(raw)) {
    raw += "Z";
  }
  const parsed = Date.parse(raw);
  if (Number.isNaN(parsed)) return String(value);
  try {
    return new Date(parsed).toLocaleString(undefined, {
      dateStyle: "medium", timeStyle: "short",
    });
  } catch (error) {
    return String(value);
  }
}
function setFunctionsEmptyMessage() {
  const el = $("empty-state");
  if (filtersActive()) {
    el.textContent = "No functions match these filters. Use Clear filters, or set Status and Module to any.";
  } else {
    el.innerHTML = "No functions for this target yet. Match work, run <code>rebrew build-db</code>, then reload.";
  }
}
function setGlobalsEmptyMessage() {
  const el = $("globals-empty");
  if ($("gq").value.trim()) {
    el.textContent = "No globals match this search. Clear the search or try another name.";
  } else {
    el.innerHTML = "No globals recorded for this target. Annotate globals, run <code>rebrew build-db</code>, then reload.";
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
  if (currentView === "sections") $("retry-view").textContent = "Retry sections";
  else if (currentView === "globals") $("retry-view").textContent = "Retry globals";
  else if (currentView === "history") $("retry-view").textContent = "Retry history";
  else $("retry-view").textContent = "Retry";
}
function setLoadError(source, message) {
  loadErrors[source] = message || "";
  syncError();
}
function filtersActive() {
  if (currentView === "globals") return !!$("gq").value.trim();
  if (currentView !== "functions") return false;
  return !!($("status").value || $("module").value || $("q").value.trim());
}
function updateFilterActions() {
  // Keep the control mounted on filterable views so enabling Clear does not
  // shove the tablist down when the first filter is applied.
  const canFilter = currentView === "functions" || currentView === "globals";
  $("filter-actions").hidden = !canFilter;
  $("clear-filters").disabled = !filtersActive();
  writeHash();
}
function writeHash() {
  if (!hashReady) return;
  const params = new URLSearchParams({ target: $("target").value });
  if (currentView !== "functions") params.set("view", currentView);
  const status = $("status").value || pendingStatus;
  const module = $("module").value || pendingModule;
  if (status) params.set("status", status);
  if (module) params.set("module", module);
  if ($("q").value.trim()) params.set("q", $("q").value.trim());
  if ($("gq").value.trim()) params.set("gq", $("gq").value.trim());
  history.replaceState(null, "", "#" + params);
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
  syncError();
}
function syncCardActive() {
  const current = $("status").value;
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
  const previous = select.value || pendingModule;
  const names = Object.keys(byModule || {}).filter((m) => m !== "").sort();
  select.innerHTML = "<option value=''>any</option>"
    + names.map(m => {
      const label = m || "(unnamed)";
      return "<option value='" + esc(m) + "'>" + esc(label) + "</option>";
    }).join("");
  if (previous && names.includes(previous)) select.value = previous;
  else select.value = "";
}
function setResultsMessage(count, total) {
  const hint = $("results-hint");
  const more = $("show-more-wrap");
  if (!total) {
    $("results-status").textContent = "No functions match";
    hint.hidden = true;
    hint.textContent = "";
    more.hidden = true;
    return;
  }
  if (count < total) {
    const msg = "Showing " + count + " of " + total + " matching functions (page limit)";
    const capped = count >= PAGE_MAX;
    $("results-status").textContent = msg;
    hint.textContent = capped
      ? msg + ". Narrow Status, Module, or Search — display stops at "
        + PAGE_MAX + " rows."
      : msg + ". Use Show more below, or narrow Status, Module, or Search.";
    hint.hidden = false;
    const next = Math.min(count + PAGE_STEP, total, PAGE_MAX);
    more.hidden = capped;
    $("show-more").textContent = "Show more (up to " + next + ")";
  } else {
    const msg = count + " function" + (count === 1 ? "" : "s") + " shown";
    $("results-status").textContent = msg;
    hint.hidden = true;
    hint.textContent = "";
    more.hidden = true;
  }
}
function setListPageMessage(opts) {
  const { count, total, noun, hintId, moreWrapId, moreBtnId, tip, tipCapped } = opts;
  const hint = $(hintId);
  const more = $(moreWrapId);
  if (!total) {
    $("results-status").textContent = "No " + noun + " match";
    hint.hidden = true;
    hint.textContent = "";
    more.hidden = true;
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
    $(moreBtnId).textContent = "Show more (up to " + next + ")";
  } else {
    $("results-status").textContent = count + " " + noun + " shown";
    hint.hidden = true;
    hint.textContent = "";
    more.hidden = true;
  }
}
function resetPaging() {
  pageLimit = 100;
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
const rowHtml = (f) => {
  const r = Array.isArray(f)
    ? f
    : [f.va, f.name, f.symbol, f.size, f.status, f.module, f.files];
  return "<tr><td class=va>" + esc(r[0] ?? "") + "</td><td>" + esc(r[1] || "")
    + "</td><td>" + esc(r[2] || "") + "</td><td>" + esc(r[3] ?? "")
    + "</td><td>" + esc(r[4] || "") + "</td><td>" + esc(r[5] || "")
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
  setResultsMessage(shown, total);
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
    limit: String(grow ? PAGE_STEP : pageLimit),
    offset: String(offset),
  });
  if ($("status").value) params.set("status", $("status").value);
  if ($("module").value) params.set("module", $("module").value);
  if ($("q").value.trim()) params.set("q", $("q").value.trim());
  updateFilterActions();
  try {
    setLoadError("functions", "");
    $("results").hidden = false;
    $("empty-state").hidden = true;
    $("show-more-wrap").hidden = true;
    // Busy state via aria-busy only — avoid polite-live "Loading…" chatter on
    // every debounced search keystroke (WCAG 4.1.3).
    const data = await whileBusy("results", () => get("/api/functions?" + params, signal));
    if (seq !== functionsSeq || signal.aborted) return;
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
    if (grow && loadedCount > 0) {
      setLoadError("functions", "Could not load more functions. The rows already shown are unchanged; use Retry functions to fetch the next page again.");
    } else {
      setLoadError("functions", "Functions could not be loaded. Use Retry functions to try again with the same filters.");
    }
  }
}
function renderSummary(s) {
  const byStatus = s.function_stats.by_status || {};
  setStatusOptions(byStatus);
  setModuleOptions(s.function_stats.by_module_counts || {});
  pendingStatus = "";
  pendingModule = "";
  $("status").disabled = false;
  $("module").disabled = false;
  const cards = [
    ["Functions", s.function_stats.total, null,
      "Total functions for this target"],
    ["Matched", (s.coverage_pct ?? 0).toFixed(1) + "%", null,
      "Share of .text bytes at EXACT, RELOC, or PROVEN"],
    ["Identified", (s.identified_pct ?? 0).toFixed(1) + "%", null,
      "Share of .text bytes covered by any known function, including stubs"],
  ];
  for (const [k, v] of Object.entries(byStatus)) cards.push([k, v, k, "Filter by " + k]);
  // The title text rides in a visually-hidden span, not aria-label: a div
  // cannot be named, and the name must start with the visible text (WCAG 2.5.3).
  $("cards").innerHTML = cards.map(([k, v, status, title]) => {
    const inner = "<span class=value>" + esc(v) + "</span>"
      + "<span class=label>" + esc(k) + "</span>"
      + "<span class=visually-hidden>, " + esc(title) + "</span>";
    if (status) {
      const pressed = $("status").value === status;
      const active = pressed ? " active" : "";
      return "<button type=button class='card" + active + "' data-status='" + esc(status)
        + "' title='" + esc(title) + "' aria-pressed='" + (pressed ? "true" : "false") + "'>"
        + inner + "</button>";
    }
    return "<div class=card title='" + esc(title) + "'>" + inner + "</div>";
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
    setLoadError("summary", "Coverage summary could not be loaded. Use Retry summary to try again.");
  }
}
function scheduleSearch() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    resetPaging();
    loadFunctions();
  }, 200);
}
function scheduleGlobalsSearch() {
  clearTimeout(globalsSearchTimer);
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
function renderSections(data) {
  const rows = data.sections || [];
  const body = $("sections-rows").querySelector("tbody");
  body.innerHTML = rows.map(s => "<tr><td>" + esc(s.name || "") + "</td><td>"
    + esc(s.size ?? "") + "</td><td>" + esc(s.total_cells ?? "") + "</td><td>"
    + esc(s.exact ?? 0) + "</td><td>" + esc(s.reloc ?? 0) + "</td><td>"
    + esc(s.near_match ?? 0) + "</td><td>" + esc(s.stub ?? 0) + "</td><td>"
    + esc(s.proven ?? 0) + "</td><td>" + esc(s.other ?? 0) + "</td></tr>").join("");
  $("sections-empty").hidden = rows.length !== 0;
  $("sections-results").hidden = rows.length === 0;
  $("results-status").textContent = rows.length
    ? rows.length + " section" + (rows.length === 1 ? "" : "s")
    : "No sections";
}
const globalRowHtml = (g) => {
  const r = Array.isArray(g)
    ? g
    : [g.va, g.name, g.decl, g.size, g.module];
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
    hintId: "globals-hint",
    moreWrapId: "globals-show-more-wrap",
    moreBtnId: "show-more-globals",
    tip: "Use Show more below, or narrow the search.",
    tipCapped: "Narrow the search — display stops at " + PAGE_MAX + " rows.",
  });
  updateFilterActions();
}
const historyRowHtml = (h) => {
  const r = Array.isArray(h)
    ? h
    : [h.va, h.name, h.old_status, h.new_status, h.changed_at];
  return "<tr><td class=va>" + esc(r[0] ?? "") + "</td><td>" + esc(r[1] || "")
    + "</td><td>" + esc(r[2] || "") + "</td><td>" + esc(r[3] || "")
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
    setLoadError("view", "Sections could not be loaded. Use Retry sections to try again.");
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
    limit: String(grow ? PAGE_STEP : 100),
    offset: String(offset),
  });
  if ($("gq").value.trim()) params.set("q", $("gq").value.trim());
  updateFilterActions();
  $("globals-empty").hidden = true;
  $("globals-hint").hidden = true;
  $("globals-show-more-wrap").hidden = true;
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
    $("globals-hint").hidden = true;
    $("globals-show-more-wrap").hidden = true;
    if (grow && loadedGlobalsCount > 0) {
      setLoadError("view", "Could not load more globals. The rows already shown are unchanged; use Retry globals to fetch the next page again.");
    } else {
      setLoadError("view", "Globals could not be loaded. Use Retry globals to try again.");
    }
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
    limit: String(grow ? PAGE_STEP : 100),
    offset: String(offset),
  });
  $("history-empty").hidden = true;
  $("history-hint").hidden = true;
  $("history-show-more-wrap").hidden = true;
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
    $("history-hint").hidden = true;
    $("history-show-more-wrap").hidden = true;
    if (grow && loadedHistoryCount > 0) {
      setLoadError("view", "Could not load more history. The rows already shown are unchanged; use Retry history to fetch the next page again.");
    } else {
      setLoadError("view", "History could not be loaded. Use Retry history to try again.");
    }
  }
}
function loadCurrentView(force) {
  if (currentView === "functions") {
    if (force) { resetPaging(); loadFunctions(); }
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
  setLoadError("view", "");
  syncViewChrome();
  loadCurrentView(false);
}
function bindControls() {
  $("target").onchange = () => {
    $("status").value = "";
    $("module").value = "";
    pendingStatus = "";
    pendingModule = "";
    $("q").value = "";
    $("gq").value = "";
    viewLoaded.sections = false;
    viewLoaded.globals = false;
    viewLoaded.history = false;
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
  $("gq").oninput = scheduleGlobalsSearch;
  $("clear-filters").onclick = () => {
    if (currentView === "globals") {
      $("gq").value = "";
      clearTimeout(globalsSearchTimer);
      resetGlobalsPaging();
      loadGlobals();
      updateFilterActions();
      return;
    }
    $("status").value = "";
    $("module").value = "";
    pendingStatus = "";
    pendingModule = "";
    $("q").value = "";
    resetPaging();
    syncCardActive();
    updateFilterActions();
    clearTimeout(searchTimer);
    loadFunctions();
  };
  $("retry-summary").onclick = () => loadSummary();
  $("retry-functions").onclick = () => loadFunctions({ append: retryAppend });
  $("retry-view").onclick = () => {
    if (currentView === "globals" && retryGlobalsAppend && loadedGlobalsCount > 0) {
      loadGlobals({ append: true });
      return;
    }
    if (currentView === "history" && retryHistoryAppend && loadedHistoryCount > 0) {
      loadHistory({ append: true });
      return;
    }
    loadCurrentView(true);
  };
  $("show-more").onclick = () => {
    retryAppend = true;
    loadFunctions({ append: true });
  };
  $("show-more-globals").onclick = () => {
    retryGlobalsAppend = true;
    loadGlobals({ append: true });
  };
  $("show-more-history").onclick = () => {
    retryHistoryAppend = true;
    loadHistory({ append: true });
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
  targets = boot.targets || [];
  if (!targets.length) {
    $("no-targets").hidden = false;
    $("results-status").textContent = "No targets in coverage.db";
    return;
  }
  $("controls").hidden = false;
  $("views").hidden = false;
  $("target").innerHTML = targets.map(t =>
    "<option value='" + esc(t) + "'>" + esc(t) + "</option>").join("");
  const saved = new URLSearchParams(location.hash.slice(1));
  if (targets.includes(saved.get("target"))) $("target").value = saved.get("target");
  if (VIEWS.includes(saved.get("view"))) currentView = saved.get("view");
  pendingStatus = saved.get("status") || "";
  pendingModule = saved.get("module") || "";
  $("q").value = saved.get("q") || "";
  $("gq").value = saved.get("gq") || "";
  // The bootstrap payload covers the first target with no filters.
  const bootFits = $("target").value === targets[0];
  bindControls();
  syncViewChrome();
  if (boot.summary && bootFits) {
    setLoadError("summary", "");
    renderSummary(boot.summary);
  } else {
    await loadSummary();
  }
  hashReady = true;
  updateFilterActions();
  const unfiltered = !$("status").value && !$("module").value && !$("q").value.trim();
  if (boot.functions && bootFits && unfiltered) {
    setLoadError("functions", "");
    $("results").hidden = false;
    renderFunctions(boot.functions);
  } else {
    await loadFunctions();
  }
  loadCurrentView(false);
}
function start() {
  init().catch(error => {
    $("boot-status").hidden = true;
    $("retry-summary").textContent = "Reload dashboard";
    setLoadError("summary", "Dashboard failed to load: " + error.message
      + ". Use Reload dashboard to try again.");
    $("retry-summary").onclick = () => {
      setLoadError("summary", "");
      $("retry-summary").textContent = "Retry summary";
      $("boot-status").hidden = false;
      $("boot-status").textContent = "Loading coverage…";
      start();
    };
    $("retry-summary").focus();
  });
}
start();
"""

_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rebrew coverage dashboard</title>
<link rel="preload" href="/api/bootstrap" as="fetch" crossorigin fetchpriority="high">
<link rel="preload" href="/app.js" as="script">
<style>
  body { font-family: system-ui, sans-serif; margin: 1.5rem; color: #1a1a1a; }
  .skip-link { position: absolute; left: -9999px; top: 0; z-index: 100;
    padding: .5rem 1rem; background: #fff; color: #005fcc; text-decoration: underline; }
  .skip-link:focus { left: 1rem; top: 1rem; }
  .filters { display: flex; flex-wrap: wrap; gap: .5rem 1rem; align-items: end;
    margin-bottom: .5rem; }
  .filters > div { display: flex; flex-direction: column; gap: .25rem; font-size: .9rem; }
  select, input { min-height: 2.75rem; padding: .3rem .5rem; min-width: 10rem;
    border: 1px solid #767676; }
  :focus-visible { outline: 3px solid #005fcc; outline-offset: 2px; }
  h1 { margin-bottom: .25rem; }
  .cards { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
  .card { border: 1px solid #767676; border-radius: 6px; padding: .6rem 1rem; min-width: 110px;
    background: #fff; }
  button.card { font: inherit; color: inherit; text-align: left; cursor: pointer; }
  button.card:hover { border-color: #444; }
  button.card.active { border-color: #005fcc; border-width: 2px; box-shadow: 0 0 0 2px rgba(0,95,204,.25); }
  .card .value { font-size: 1.4rem; font-weight: 700; display: block; }
  .card .label { color: #444; }
  .table-scroll { overflow-x: auto; position: relative; }
  .table-scroll[aria-busy="true"]::after {
    content: "Loading…"; position: absolute; inset: 0; display: flex; align-items: center;
    justify-content: center; background: rgba(255,255,255,.7); font-size: .95rem; color: #444;
  }
  .visually-hidden { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
    overflow: hidden; clip: rect(0, 0, 0, 0); white-space: nowrap; border: 0; }
  table { border-collapse: collapse; width: 100%; margin-top: 1rem; font-size: .85rem; }
  th, td { border: 1px solid #767676; padding: .3rem .5rem; text-align: left; }
  th { background: #f5f5f5; }
  td.va { font-family: monospace; }
  #dashboard-error { color: #9a3412; background: #fff7ed; border: 1px solid #9a3412;
    border-radius: 6px; padding: .6rem .8rem; margin: .75rem 0; }
  #empty-state, #no-targets { color: #555; margin: 1rem 0; }
  #results-hint { color: #555; font-size: .9rem; margin: .25rem 0 0; }
  #filter-actions, #show-more-wrap, #globals-show-more-wrap, #history-show-more-wrap,
  #retry-bar { margin: .35rem 0 .75rem; }
  #clear-filters, #show-more, #show-more-globals, #show-more-history,
  #retry-functions, #retry-summary, #retry-view {
    min-height: 2.75rem; padding: .3rem .75rem; border: 1px solid #767676; background: #fff; color: inherit; }
  #clear-filters:disabled { opacity: .55; cursor: not-allowed; }
  .views { display: flex; flex-wrap: wrap; gap: .35rem; margin: .75rem 0 .25rem; }
  .views button { min-height: 2.75rem; padding: .3rem .85rem; font: inherit; cursor: pointer;
    border: 1px solid #767676; border-radius: 6px; background: #fff; color: inherit; }
  .views button:hover { border-color: #444; }
  .views button.active { border-color: #005fcc; border-width: 2px; box-shadow: 0 0 0 2px rgba(0,95,204,.25); }
  .view-panel[hidden] { display: none; }
  @media (max-width: 40rem) {
    body { margin: 1rem; }
    select, input { min-width: 0; width: 100%; }
    .filters > div { flex: 1 1 100%; }
  }
  @media (forced-colors: active) {
    button.card.active, .views button.active {
      border: 2px solid Highlight;
      box-shadow: none;
    }
    :focus-visible { outline-color: Highlight; }
    #dashboard-error { border-color: CanvasText; color: CanvasText; background: Canvas; }
  }
  @media (prefers-reduced-motion: reduce) {
    * { transition: none !important; animation: none !important; }
  }
  /* Skip layout/paint for off-screen rows on large result pages. */
  tbody tr { content-visibility: auto; contain-intrinsic-size: auto 2.2rem; }
</style>
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
<main id="main" tabindex="-1">
<h1>Rebrew coverage</h1>
<p id="boot-status" role="status">Loading coverage…</p>
<p id="no-targets" hidden>No targets found in coverage.db. Run
  <code>rebrew build-db</code> for this project, then reload.</p>
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
<label for="q">Search name or symbol</label>
<input id="q" type="search" size="24" placeholder="e.g. WinMain" autocomplete="off">
</div>
<div id="filter-gq" hidden>
<label for="gq">Search global name</label>
<input id="gq" type="search" size="24" placeholder="e.g. g_flag" autocomplete="off">
</div>
</div>
<div id="filter-actions" hidden>
<button type="button" id="clear-filters">Clear filters</button>
</div>
<div id="views" class="views" hidden role="tablist" aria-label="Coverage views">
<button type="button" role="tab" id="tab-functions" data-view="functions"
  aria-controls="view-functions" class="active" aria-selected="true" tabindex="0">Functions</button>
<button type="button" role="tab" id="tab-sections" data-view="sections"
  aria-controls="view-sections" aria-selected="false" tabindex="-1">Sections</button>
<button type="button" role="tab" id="tab-globals" data-view="globals"
  aria-controls="view-globals" aria-selected="false" tabindex="-1">Globals</button>
<button type="button" role="tab" id="tab-history" data-view="history"
  aria-controls="view-history" aria-selected="false" tabindex="-1">History</button>
</div>
<section id="summary" aria-labelledby="summary-heading" aria-busy="false" hidden>
<h2 class="visually-hidden" id="summary-heading">Coverage summary</h2>
<div class="cards" id="cards" role="group" aria-label="Coverage metrics"></div>
</section>
<p class="visually-hidden" id="results-status" role="status" aria-live="polite"></p>
<p id="dashboard-error" role="alert" hidden></p>
<div id="retry-bar" role="group" aria-label="Retry failed loads">
<button type="button" id="retry-summary" hidden>Retry summary</button>
<button type="button" id="retry-functions" hidden>Retry functions</button>
<button type="button" id="retry-view" hidden>Retry</button>
</div>
<div id="view-functions" class="view-panel" role="tabpanel" aria-labelledby="tab-functions">
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
<button type="button" id="show-more">Show more functions</button>
</div>
</div>
<div id="view-sections" class="view-panel" role="tabpanel" aria-labelledby="tab-sections" hidden>
<p id="sections-empty" hidden>No section stats for this target. Run
  <code>rebrew build-db</code> for this project, then reload.</p>
<div id="sections-results" class="table-scroll" tabindex="0" role="region"
  aria-label="Section results" aria-busy="false" hidden>
<table id="sections-rows"><caption class="visually-hidden">Per-section cell stats</caption><thead><tr>
  <th scope="col">Section</th><th scope="col">Size</th><th scope="col">Cells</th>
  <th scope="col">Exact</th><th scope="col">Reloc</th><th scope="col">Near</th>
  <th scope="col">Stub</th><th scope="col">Proven</th><th scope="col">Other</th>
</tr></thead><tbody></tbody></table>
</div>
</div>
<div id="view-globals" class="view-panel" role="tabpanel" aria-labelledby="tab-globals" hidden>
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
<button type="button" id="show-more-globals">Show more globals</button>
</div>
</div>
<div id="view-history" class="view-panel" role="tabpanel" aria-labelledby="tab-history" hidden>
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
<button type="button" id="show-more-history">Show more history</button>
</div>
</div>
</main>
<script src="/app.js" defer></script>
</body>
</html>
"""

_INDEX_HTML_BYTES = _INDEX_HTML.encode("utf-8")
_INDEX_ETAG = '"' + hashlib.sha256(_INDEX_HTML_BYTES).hexdigest()[:16] + '"'
_APP_JS_BYTES = _APP_JS.encode("utf-8")
_APP_JS_ETAG = '"' + hashlib.sha256(_APP_JS_BYTES).hexdigest()[:16] + '"'


def _precompress(raw: bytes, encoding: _WireEncoding) -> bytes | None:
    """Return a max-effort blob when it shrinks *raw*, else ``None``."""
    if encoding == "zstd":
        compressed = zstandard.ZstdCompressor(level=_ZSTD_PRECOMPRESS_LEVEL).compress(raw)
    else:
        compressed = gzip.compress(raw, compresslevel=_GZIP_PRECOMPRESS_LEVEL)
    return compressed if len(compressed) < len(raw) else None


_INDEX_HTML_ZSTD = _precompress(_INDEX_HTML_BYTES, "zstd")
_INDEX_HTML_GZIP = _precompress(_INDEX_HTML_BYTES, "gzip")
_APP_JS_ZSTD = _precompress(_APP_JS_BYTES, "zstd")
_APP_JS_GZIP = _precompress(_APP_JS_BYTES, "gzip")


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
    unreachable via ``limit``+``offset`` pagination.
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
    return value


def _opt_query(params: dict[str, list[str]], name: str) -> str | None:
    """Return a stripped optional query value, or None when missing/blank."""
    values = params.get(name)
    raw = values[0] if values else None
    if raw is None:
        return None
    stripped = raw.strip()
    return stripped or None


def _escape_like(term: str) -> str:
    """Escape LIKE wildcards so user input is matched literally.

    Mirrors recoverage's _escape_like: `%`, `_`, and `\\` are escaped and the
    query must add ``ESCAPE '\\'``.
    """
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class Dashboard:
    """Read-only query layer over a ``coverage.db`` file."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        """Yield a read-only connection, closed on every exit path.

        Nested callers reuse the same handle (one connect per request).
        ``sqlite3.Connection`` used directly as a context manager only
        commits/rolls back the transaction — it never closes.  Under the
        threaded HTTP server that would leave one GC-dependent connection
        per request; closing here releases the handle deterministically.
        """
        existing = _CURRENT_CONN.get()
        if existing is not None:
            yield existing
            return
        # Percent-encode the path (``open_sqlite_ro`` / ``sqlite_ro_uri``): a
        # raw ``file:{p}?mode=ro`` truncates or rewrites names that contain
        # ``?`` / ``#`` / ``%``.  ``query_only`` is a second write gate.
        conn = open_sqlite_ro(self.db_path)
        token = _CURRENT_CONN.set(conn)
        try:
            yield conn
        finally:
            _CURRENT_CONN.reset(token)
            conn.close()

    def targets(self) -> list[str]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT DISTINCT target FROM metadata WHERE key = 'function_stats' ORDER BY target"
            ).fetchall()
        return [r[0] for r in rows]

    def bootstrap(self) -> dict[str, Any]:
        """Targets plus the first target's summary/functions in one payload.

        Collapses the HTML app's cold-start waterfall (targets → summary +
        functions) into a single round trip.  Filter/paging still use the
        dedicated endpoints after the first paint.  Nested queries share one
        SQLite connection.
        """
        with self._conn():
            targets = self.targets()
            payload: dict[str, Any] = {
                "targets": targets,
                "count": len(targets),
                "total": len(targets),
                "limit": len(targets),
                "offset": 0,
                "target": None,
                "summary": None,
                "functions": None,
            }
            if not targets:
                return payload
            target = targets[0]
            payload["target"] = target
            payload["summary"] = self.summary(target)
            if payload["summary"] is not None:
                payload["functions"] = self.functions(target, limit=_DEFAULT_LIMIT)
            return payload

    def _summary_lookup(
        self, target: str
    ) -> tuple[Literal["missing", "corrupt", "ok"], dict[str, Any] | None]:
        """One-query summary read: missing row vs corrupt vs usable payload.

        Keeps the HTTP layer from mapping corrupt ``function_stats`` to
        ``404 unknown target`` (the row is present; the value is unreadable).
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value FROM metadata WHERE target = ? AND key = 'function_stats'",
                (target,),
            ).fetchone()
        if row is None:
            return "missing", None
        try:
            stats = json.loads(row[0])
        except (json.JSONDecodeError, TypeError) as exc:
            # Corrupt metadata must not present as a real 0% summary — that
            # looks like an empty target and hides the broken row.
            log.warning(
                "Ignoring corrupt function_stats for target %r: %s",
                target,
                exc,
            )
            return "corrupt", None
        if not isinstance(stats, dict):
            log.warning(
                "Ignoring non-object function_stats for target %r (%s)",
                target,
                type(stats).__name__,
            )
            return "corrupt", None
        # Headline coverage = reversed bytes (EXACT/RELOC/PROVEN) / text size.
        # Not byte-identity: PROVEN bytes differ from the target (verify's
        # _STATUS_RANK puts PROVEN below RELOC for that reason). —
        # the old covered_bytes summed every function's size, so an all-STUB
        # binary reported ~100% "coverage" (db-review F1).  Identified bytes
        # (incl. stubs) stays available as a separate field.
        covered = int(stats.get("matched_bytes") or 0)
        identified = int(stats.get("covered_bytes") or 0)
        # total_b comes solely from function_stats — the old fallback read a
        # second metadata row (key='summary') and probed its ".text" size, but
        # nothing writes a ".text" key there, so the branch never fired.
        total_b = int(stats.get("total_bytes") or 0)
        return "ok", {
            "target": target,
            "function_stats": stats,
            "coverage_pct": round(covered / total_b * 100.0, 1) if total_b else 0.0,
            "identified_pct": round(identified / total_b * 100.0, 1) if total_b else 0.0,
        }

    def summary(self, target: str) -> dict[str, Any] | None:
        """Coverage stats for *target*, or None when missing/unreadable."""
        _kind, payload = self._summary_lookup(target)
        return payload

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
        where = ["target = ?"]
        args: list[Any] = [target]
        if status:
            where.append("status = ?")
            args.append(status)
        if module:
            where.append("module = ?")
            args.append(module)
        if q:
            where.append("(name LIKE ? ESCAPE '\\' OR symbol LIKE ? ESCAPE '\\')")
            args.extend([f"%{_escape_like(q)}%", f"%{_escape_like(q)}%"])
        # Exclude non-function rows; must remain in *where* for the COUNT total.
        where.append("markerType NOT IN ('GLOBAL', 'DATA')")
        where_sql = " AND ".join(where)
        query = (
            "SELECT va, name, symbol, size, status, module, files "
            f"FROM functions WHERE {where_sql} ORDER BY va, module LIMIT ? OFFSET ?"
        )
        with self._conn() as conn:
            rows = conn.execute(query, [*args, limit, offset]).fetchall()
            # Short first page: COUNT equals len(rows). Skip the second scan.
            # A later empty/short page still needs COUNT (offset past the end).
            if offset == 0 and len(rows) < limit:
                total = len(rows)
            else:
                total = conn.execute(
                    f"SELECT COUNT(*) FROM functions WHERE {where_sql}",
                    args,
                ).fetchone()[0]
        return {
            "target": target,
            "count": len(rows),
            "total": total,
            "limit": limit,
            "offset": offset,
            "cols": list(_FUNCTION_COLS),
            "functions": [
                [
                    f"0x{r[0]:08x}" if r[0] else "???",
                    r[1] or "",
                    r[2] or "",
                    r[3],
                    r[4] or "",
                    r[5] or "",
                    _files_display(r[6]),
                ]
                for r in rows
            ],
        }

    def sections(self, target: str) -> dict[str, Any]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT section_name, total_cells, exact_count, reloc_count, "
                "near_match_count, stub_count, padding_count, data_count, "
                "thunk_count, none_count, proven_count, size_mismatch_count, "
                "other_count "
                "FROM section_cell_stats WHERE target = ? ORDER BY section_name",
                (target,),
            ).fetchall()
            sizes = dict(
                conn.execute(
                    "SELECT name, size FROM sections WHERE target = ?", (target,)
                ).fetchall()
            )
        sections = [
            {
                "name": r[0],
                "size": sizes.get(r[0]),
                "total_cells": r[1],
                "exact": r[2] or 0,
                "reloc": r[3] or 0,
                "near_match": r[4] or 0,
                "stub": r[5] or 0,
                "padding": r[6] or 0,
                "data": r[7] or 0,
                "thunk": r[8] or 0,
                "none": r[9] or 0,
                "proven": r[10] or 0,
                "size_mismatch": r[11] or 0,
                "other": r[12] or 0,
            }
            for r in rows
        ]
        return {
            "target": target,
            "count": len(sections),
            "total": len(sections),
            "limit": len(sections),
            "offset": 0,
            "sections": sections,
        }

    def globals(
        self,
        target: str,
        *,
        q: str | None = None,
        limit: int = _DEFAULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, Any]:
        where = ["target = ?"]
        args: list[Any] = [target]
        if q:
            where.append("name LIKE ? ESCAPE '\\'")
            args.append(f"%{_escape_like(q)}%")
        where_sql = " AND ".join(where)
        with self._conn() as conn:
            rows = conn.execute(
                f"SELECT va, name, decl, size, module FROM globals WHERE "
                f"{where_sql} ORDER BY va LIMIT ? OFFSET ?",
                [*args, limit, offset],
            ).fetchall()
            # Same short-page COUNT skip as functions: first page only.
            if offset == 0 and len(rows) < limit:
                total = len(rows)
            else:
                total = conn.execute(
                    f"SELECT COUNT(*) FROM globals WHERE {where_sql}",
                    args,
                ).fetchone()[0]
        return {
            "target": target,
            "count": len(rows),
            "total": total,
            "limit": limit,
            "offset": offset,
            "cols": list(_GLOBAL_COLS),
            "globals": [
                [
                    f"0x{r[0]:08x}" if r[0] else "???",
                    r[1] or "",
                    r[2] or "",
                    r[3],
                    r[4] or "",
                ]
                for r in rows
            ],
        }

    def history(
        self, target: str, *, limit: int = _DEFAULT_LIMIT, offset: int = 0
    ) -> dict[str, Any]:
        with self._conn() as conn:
            rows = conn.execute(
                # A VA with no current function row (removed since) keeps name ''.
                "SELECT h.va, f.name, h.old_status, h.new_status, h.changed_at "
                "FROM history h LEFT JOIN functions f ON f.target = h.target AND f.va = h.va "
                "WHERE h.target = ? ORDER BY h.id DESC LIMIT ? OFFSET ?",
                (target, limit, offset),
            ).fetchall()
            if offset == 0 and len(rows) < limit:
                total = len(rows)
            else:
                total = conn.execute(
                    "SELECT COUNT(*) FROM history WHERE target = ?",
                    (target,),
                ).fetchone()[0]
        return {
            "target": target,
            "count": len(rows),
            "total": total,
            "limit": limit,
            "offset": offset,
            "cols": list(_HISTORY_COLS),
            "history": [
                [
                    f"0x{r[0]:08x}" if r[0] else "???",
                    r[1] or "",
                    r[2],
                    r[3],
                    r[4],
                ]
                for r in rows
            ],
        }

    def target_known(self, target: str) -> bool:
        """True when *target* has function_stats metadata (same criterion as summary)."""
        if not target:
            return False
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM metadata WHERE target = ? AND key = 'function_stats' LIMIT 1",
                (target,),
            ).fetchone()
        return row is not None

    def response_etag(self, path: str) -> str:
        """Strong shell/asset etag; weak DB etag so rebuilds invalidate JSON caches."""
        parsed = urlparse(path)
        if parsed.path == "/":
            return _INDEX_ETAG
        if parsed.path == "/app.js":
            return _APP_JS_ETAG
        try:
            st = self.db_path.stat()
        except OSError:
            return 'W/"0"'
        return f'W/"{st.st_mtime_ns:x}-{st.st_size:x}"'

    def handle(self, method: str, path: str, query: dict[str, list[str]]) -> tuple[int, str, str]:
        """Route a request.  Returns (status, content-type, body)."""
        if method not in ("GET", "HEAD"):
            return self._json(405, {"error": "method not allowed (read-only; GET, HEAD only)"})
        parsed = urlparse(path)
        if parsed.path == "/":
            return 200, "text/html; charset=utf-8", _INDEX_HTML
        if parsed.path == "/app.js":
            return 200, "application/javascript; charset=utf-8", _APP_JS
        if parsed.path == "/api/bootstrap":
            return self._json(200, self.bootstrap())
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
                },
            )

        # All remaining endpoints require ?target=
        if parsed.path in (
            "/api/summary",
            "/api/functions",
            "/api/sections",
            "/api/globals",
            "/api/history",
        ):
            target = _opt_query(query, "target") or ""
            if not target:
                return self._json(400, {"error": "missing required query parameter 'target'"})
            with self._conn():
                if parsed.path == "/api/summary":
                    # Single stats-row read: missing → 404, corrupt → 500 (not
                    # "unknown"), ok → 200.  Avoids a second target_known probe
                    # on the happy path while keeping status codes accurate.
                    kind, result = self._summary_lookup(target)
                    if kind == "missing":
                        return self._json(404, {"error": f"unknown target {target!r}"})
                    if kind == "corrupt" or result is None:
                        return self._json(500, {"error": "corrupt function_stats metadata"})
                    return self._json(200, result)
                if not self.target_known(target):
                    return self._json(404, {"error": f"unknown target {target!r}"})
                if parsed.path == "/api/functions":
                    return self._json(
                        200,
                        self.functions(
                            target,
                            status=_opt_query(query, "status"),
                            module=_opt_query(query, "module"),
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
                            q=_opt_query(query, "q"),
                            limit=_int_param(query, "limit", _DEFAULT_LIMIT),
                            offset=_offset_param(query, "offset", 0),
                        ),
                    )
                return self._json(
                    200,
                    self.history(
                        target,
                        limit=_int_param(query, "limit", _DEFAULT_LIMIT),
                        offset=_offset_param(query, "offset", 0),
                    ),
                )
        return self._json(404, {"error": f"no such endpoint {parsed.path!r}"})

    @staticmethod
    def _json(status: int, payload: dict[str, Any]) -> tuple[int, str, str]:
        return (
            status,
            "application/json; charset=utf-8",
            json.dumps(payload, separators=(",", ":")),
        )


def _load_list(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(v) for v in value] if isinstance(value, list) else []


def _files_display(raw: str | None) -> str:
    """Join the stored JSON files list for the table cell.

    ``build_db`` writes ``json.dumps(files)``. The common cell is ``[]``,
    ``["a.c"]``, or ``["a.c", "b.h"]`` — slice that; ``json.loads`` only for
    escaped or odd payloads.
    """
    if not raw or raw == "[]":
        return ""
    if raw.startswith('["') and raw.endswith('"]') and "\\" not in raw:
        inner = raw[2:-2]
        if '",' not in inner:
            return inner
        return inner.replace('", "', ", ").replace('","', ", ")
    return ", ".join(_load_list(raw))


def _local_interface_ips() -> set[str]:
    """The host's own addresses, for a wildcard bind's Host allow-list.

    A wildcard bind (``--host 0.0.0.0``) has no single expected Host: users
    reach it as ``localhost``, ``127.0.0.1``, or one of the machine's own
    addresses, and the previous allow-list held only the literal wildcard, so
    every real request was 403'd.  Resolver-based (no netlink walk): an
    unresolvable hostname just yields an empty set.
    """
    import socket

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
    """Compress *body* at the per-request effort for *encoding*."""
    if encoding == "zstd":
        return zstandard.ZstdCompressor(level=_ZSTD_LEVEL).compress(body)
    return gzip.compress(body, compresslevel=_GZIP_LEVEL)


def _maybe_compress(body: bytes, accept_encoding: str) -> tuple[bytes, _WireEncoding | None]:
    """Return ``(body, encoding)``; compress only when it shrinks the wire bytes."""
    if len(body) < _MIN_COMPRESS_BYTES:
        return body, None
    encoding = _negotiate_encoding(accept_encoding)
    if encoding is None:
        return body, None
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


def _escape_log_text(text: str) -> str:
    return text.translate(_LOG_CONTROL_CHARS)


class _Handler(BaseHTTPRequestHandler):
    dashboard: Dashboard
    #: Host headers this server must answer; everything else gets 403.
    allowed_hosts: frozenset[str] = frozenset()
    # Browsers speak HTTP/1.1; keep the TCP connection open across the HTML
    # shell plus /api/bootstrap (and later filter fetches) instead of a fresh
    # handshake per request.  Content-Length is set on every response so
    # persistent connections stay framed correctly.
    protocol_version = "HTTP/1.1"

    def _respond(self, method: str) -> None:
        if not _host_allowed(self.headers.get("Host", ""), self.allowed_hosts):
            status, content_type, body = self.dashboard._json(
                403, {"error": "request Host not allowed (wrong or missing Host header)"}
            )
            body_bytes = body.encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body_bytes)))
            self._write_security_headers(cacheable=False)
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(body_bytes)
            return

        # Read the ETag (asset hash or DB mtime) BEFORE the query: a
        # ``build-db`` swap between query and stat would otherwise tag the old
        # body with the new ETag, and the browser would revalidate that stale
        # body as fresh until the next rebuild.  An old ETag on a new body
        # only costs one extra refetch.  A matching If-None-Match on a routed
        # GET/HEAD answers 304 without running the query.
        etag = self.dashboard.response_etag(self.path)
        if (
            method in ("GET", "HEAD")
            and urlparse(self.path).path in _ROUTES
            and _if_none_match(self.headers.get("If-None-Match", ""), etag)
        ):
            self._send_not_modified(etag)
            return

        query = parse_qs(urlparse(self.path).query)
        try:
            status, content_type, body = self.dashboard.handle(method, self.path, query)
        except sqlite3.Error as exc:
            # A vanished/corrupt database must answer 500 JSON instead of
            # killing the handler thread with no response at all.  Keep the
            # sqlite detail on stderr only — LAN clients must not learn paths
            # or schema strings from the wire body.
            console.print(
                f"[red]dashboard query failed:[/red] "
                f"{escape(_escape_log_text(self.path))}: {escape(_escape_log_text(str(exc)))}"
            )
            status, content_type, body = self.dashboard._json(500, {"error": "database error"})
        except Exception as exc:  # last-resort handler guard
            # Any other unexpected error (a bug in a route, an OSError on a
            # sidecar read) gets the same treatment: without this the thread
            # dies and the client sees a connection reset instead of a 500.
            # escape(): self.path is remote-controlled and must not be
            # interpreted as Rich markup (terminal escape / log injection).
            console.print(
                f"[red]dashboard handler failed:[/red] "
                f"{escape(_escape_log_text(self.path))}: {escape(_escape_log_text(repr(exc)))}"
            )
            log.debug("dashboard handler error for %s", _escape_log_text(self.path), exc_info=True)
            status, content_type, body = self.dashboard._json(
                500, {"error": "internal server error"}
            )

        body_bytes = body.encode("utf-8")
        encoding: _WireEncoding | None = None
        if status == 200:
            # Shell HTML and /app.js are immutable for a given process: serve
            # the import-time zstd/gzip blobs instead of recompressing every
            # request.
            accept = self.headers.get("Accept-Encoding", "")
            if body is _INDEX_HTML:
                body_bytes, encoding = _precompressed_static(
                    accept,
                    zstd_blob=_INDEX_HTML_ZSTD,
                    gzip_blob=_INDEX_HTML_GZIP,
                    raw=_INDEX_HTML_BYTES,
                )
            elif body is _APP_JS:
                body_bytes, encoding = _precompressed_static(
                    accept,
                    zstd_blob=_APP_JS_ZSTD,
                    gzip_blob=_APP_JS_GZIP,
                    raw=_APP_JS_BYTES,
                )
            else:
                body_bytes, encoding = _maybe_compress(body_bytes, accept)

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        if status == 200:
            self.send_header("ETag", etag)
        if encoding:
            self.send_header("Content-Encoding", encoding)
        if status == 200:
            self.send_header("Vary", "Accept-Encoding")
        self._write_security_headers(cacheable=(status == 200))
        if status == 405:
            self.send_header("Allow", "GET, HEAD")
        self.end_headers()
        # HEAD: headers only (RFC 9110); body length still advertised.
        if method != "HEAD":
            self.wfile.write(body_bytes)

    def _send_not_modified(self, etag: str) -> None:
        self.send_response(304)
        self.send_header("ETag", etag)
        self.send_header("Vary", "Accept-Encoding")
        self._write_security_headers(cacheable=True)
        self.end_headers()

    def _write_security_headers(self, *, cacheable: bool) -> None:
        """Browser hardening shared by every response, including early 403s."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=()",
        )
        # Successful GETs may be stored but must revalidate (ETag → 304) so a
        # ``rebrew build-db`` rebuild is never served as a silent stale page.
        # Errors stay no-store so a failed probe is not sticky.
        if cacheable:
            self.send_header("Cache-Control", "private, no-cache")
        else:
            self.send_header("Cache-Control", "no-store")
        # CSS stays inline in the shell; JS is same-origin /app.js.  Fetching
        # JSON is same-origin only — keeps any future escaping of API data
        # from loading third-party resources or phoning home.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self'; form-action 'none'; base-uri 'none'",
        )

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

    def do_POST(self) -> None:
        self._respond("POST")

    def do_PUT(self) -> None:
        self._respond("PUT")

    def do_DELETE(self) -> None:
        self._respond("DELETE")

    def do_PATCH(self) -> None:
        self._respond("PATCH")

    def do_OPTIONS(self) -> None:
        self._respond("OPTIONS")

    def do_TRACE(self) -> None:
        self._respond("TRACE")

    def do_CONNECT(self) -> None:
        self._respond("CONNECT")

    def log_message(self, fmt: str, *args: Any) -> None:  # quiet default logging
        # markup=False: the logged request line is remote-controlled text; a
        # path like "/[bold]x" must not be interpreted as Rich markup (log
        # tampering / terminal escape injection).
        console.print(_escape_log_text(f"  {self.address_string()} {fmt % args}"), markup=False)


app = typer.Typer(
    help="Serve a read-only web dashboard over the coverage database.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Usage:[/bold]\n\n"
        "  rebrew build-db · · · · · · · · Build db/coverage.db first\n\n"
        "  rebrew dashboard · · · · · · · Serve on http://127.0.0.1:8000\n\n"
        "  rebrew dashboard --port 9000 · Custom port\n\n"
        "  rebrew dashboard --json · · · · Print bind URL + db path, then exit\n\n"
        "[bold]Endpoints:[/bold]\n\n"
        "  / · · · · · · · · · · · · HTML shell (targets, summary, function search)\n\n"
        "  /app.js · · · · · · · · · Deferred dashboard client\n\n"
        "  /api/bootstrap · · · · · · Targets + first target summary/functions\n\n"
        "  /api/targets · · · · · · List targets\n\n"
        "  /api/summary?target= · · Coverage stats (target required)\n\n"
        "  /api/functions?target= · Function rows (status/module/q/limit/offset)\n\n"
        "  /api/sections?target= · · Per-section cell stats\n\n"
        "  /api/globals?target= · · Global data rows (q/limit/offset)\n\n"
        "  /api/history?target= · · Status-change history (limit/offset)\n\n"
        "[dim]Read-only: DB opened mode=ro. Target-scoped routes need ?target= "
        "(400 if missing, 404 if unknown; /api/summary → 500 if function_stats "
        "is corrupt). Non-GET/HEAD → 405.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host"),
    port: int = typer.Option(8000, "--port", "-p", help="Bind port"),
    root: Path | None = typer.Option(None, "--root", help="Project root directory"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Serve the coverage database as a read-only web dashboard."""
    root_dir = root.resolve() if root else Path.cwd().resolve()
    db_dir = resolve_db_dir(root_dir, json_output=json_output)
    db_path = db_dir / "coverage.db"
    if not db_path.exists():
        error_exit(
            f"No coverage database at {db_path}. Run 'rebrew build-db' first.",
            json_mode=json_output,
        )

    # Fail fast on an unreadable/incompatible database.
    try:
        Dashboard(db_path).targets()
    except sqlite3.Error as exc:
        error_exit(f"Cannot open database {db_path}: {exc}", json_mode=json_output)

    if json_output:
        # Machine-readable probe: emit bind URL + db path and exit.  Starting
        # the server here would hang every ``rebrew dashboard --json | jq``
        # consumer (and mix the later "serving…" line onto stderr).
        json_print({"url": f"http://{host}:{port}", "db": str(db_path)})
        return

    # Non-loopback binds expose the read-only coverage API with no auth
    # (SECURITY.md).  Warn once at startup so ``--host 0.0.0.0`` is never silent.
    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            f"[yellow]warning:[/] dashboard bound to {host}:{port} with no authentication "
            "— any client that can reach this host can read coverage.db"
        )

    server = ThreadingHTTPServer((host, port), _Handler)
    # Request handlers must not keep the process alive after Ctrl+C:
    # ThreadingMixIn defaults to non-daemon threads + block_on_close, so
    # server_close() waited on every in-flight (or stuck) client until the
    # OS closed the socket.  Daemon threads die with the main thread.
    server.daemon_threads = True
    _Handler.dashboard = Dashboard(db_path)
    _Handler.allowed_hosts = allowed_hosts_for(host, port)
    console.print(
        f"[green]Rebrew dashboard on http://{host}:{port}[/] — "
        f"[dim]serving {db_path} (Ctrl+C to stop)[/dim]"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("[dim]Dashboard stopped.[/dim]")
    finally:
        server.server_close()


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
