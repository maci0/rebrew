"""dashboard.py – Read-only web dashboard over the coverage database.

Serves the SQLite ``coverage.db`` (built by ``rebrew build-db``) over a tiny
HTTP server with no dependencies beyond the stdlib.  Every endpoint is
read-only: the database is opened in ``mode=ro`` and non-GET requests are
rejected with 405.

Endpoints
---------
``GET /``                      → HTML app (functions, sections, globals, history)
``GET /api/bootstrap``         → targets + first target's summary/functions (one RTT)
``GET /api/targets``           → list of targets (includes count/total)
``GET /api/summary?target=``   → function stats + coverage % (target required)
``GET /api/functions?target=`` → function rows as arrays under ``cols`` (filters: status, module, q, limit, offset)
``GET /api/sections?target=``  → per-section cell stats (includes count/total)
``GET /api/globals?target=``   → global data rows (filter: q, limit; includes total)
``GET /api/history?target=``   → status-change history (limit; includes total)

Target-scoped endpoints return 400 when ``target`` is missing/empty and 404 when
the target is unknown.  Non-GET/HEAD methods return 405 with ``Allow: GET, HEAD``.
Requests whose ``Host`` header does not match the bound host (or a loopback
alias) are rejected with 403, so a web page the analyst visits cannot reach
the server via DNS rebinding.
List endpoints expose ``count`` (rows in this page), ``total`` (matching rows),
and the applied ``limit`` / ``offset`` (offset is 0 when the endpoint has no page).
Successful 200 responses negotiate ``gzip`` when the client accepts it, carry an
``ETag`` (HTML content hash or DB mtime), and use ``Cache-Control: private,
no-cache`` so browsers can 304 without serving a stale body after ``build-db``.
The static HTML shell is gzip-precompressed at import time so the entry document
skips per-request compression CPU.  JSON uses compact separators.

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
from typing import Any
from urllib.parse import parse_qs, urlparse

import typer
from rich.console import Console
from rich.markup import escape

from rebrew.build_db import resolve_db_dir
from rebrew.cli import error_exit, json_print
from rebrew.workspace import sqlite_ro_uri

console = Console(stderr=True)
log = logging.getLogger(__name__)

_LOG_CONTROL_CHARS = {code: f"\\x{code:02x}" for code in (*range(0x20), *range(0x7F, 0xA0))}
_LOG_CONTROL_CHARS[ord("\\")] = "\\\\"

_SQLITE_TIMEOUT_SECONDS = 30.0
_DEFAULT_LIMIT = 100
_MAX_LIMIT = 5000
_FUNCTION_COLS = ("va", "name", "symbol", "size", "status", "module", "files")
# Below this size gzip's framing usually costs more than it saves on a LAN.
_MIN_GZIP_BYTES = 256
# Per-request dynamic JSON: mid effort (bodies are rebuilt every request).
_GZIP_LEVEL = 5
# Static HTML shell: max effort once at import; served precompressed thereafter.
_GZIP_PRECOMPRESS_LEVEL = 9
#: Request-scoped connection so nested query methods share one SQLite handle.
_CURRENT_CONN: ContextVar[sqlite3.Connection | None] = ContextVar(
    "rebrew_dashboard_conn", default=None
)


_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rebrew coverage dashboard</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 1.5rem; color: #1a1a1a; }
  .skip-link { position: absolute; left: -9999px; top: 0; z-index: 100;
    padding: .5rem 1rem; background: #fff; color: #005fcc; text-decoration: underline; }
  .skip-link:focus { left: 1rem; top: 1rem; }
  .filters { display: flex; flex-wrap: wrap; gap: .5rem 1rem; align-items: end;
    margin-bottom: .5rem; }
  .filters > div { display: flex; flex-direction: column; gap: .25rem; font-size: .9rem; }
  select, input { min-height: 2.75rem; padding: .3rem .5rem; min-width: 10rem; }
  :focus-visible { outline: 3px solid #005fcc; outline-offset: 2px; }
  h1 { margin-bottom: .25rem; }
  .cards { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
  .card { border: 1px solid #ccc; border-radius: 6px; padding: .6rem 1rem; min-width: 110px;
    background: #fff; }
  button.card { font: inherit; color: inherit; text-align: left; cursor: pointer; }
  button.card:hover { border-color: #888; }
  button.card.active { border-color: #005fcc; box-shadow: 0 0 0 2px rgba(0,95,204,.25); }
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
  th, td { border: 1px solid #ddd; padding: .3rem .5rem; text-align: left; }
  th { background: #f5f5f5; }
  td.va { font-family: monospace; }
  #dashboard-error { color: #9a3412; background: #fff7ed; border: 1px solid #fed7aa;
    border-radius: 6px; padding: .6rem .8rem; margin: .75rem 0; }
  #empty-state, #no-targets { color: #555; margin: 1rem 0; }
  #results-hint { color: #555; font-size: .9rem; margin: .25rem 0 0; }
  #filter-actions, #show-more-wrap, #retry-bar { margin: .35rem 0 .75rem; }
  #clear-filters, #show-more, #retry-functions, #retry-summary, #retry-view {
    min-height: 2.75rem; padding: .3rem .75rem; }
  .views { display: flex; flex-wrap: wrap; gap: .35rem; margin: .75rem 0 .25rem; }
  .views button { min-height: 2.75rem; padding: .3rem .85rem; font: inherit; cursor: pointer;
    border: 1px solid #ccc; border-radius: 6px; background: #fff; color: inherit; }
  .views button:hover { border-color: #888; }
  .views button.active { border-color: #005fcc; box-shadow: 0 0 0 2px rgba(0,95,204,.25); }
  .view-panel[hidden] { display: none; }
  @media (max-width: 40rem) {
    body { margin: 1rem; }
    select, input { min-width: 0; width: 100%; }
    .filters > div { flex: 1 1 100%; }
  }
</style>
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
<main id="main">
<h1>Rebrew coverage</h1>
<p id="boot-status">Loading coverage…</p>
<p id="no-targets" hidden>No targets found in coverage.db. Run
  <code>rebrew build-db</code> for this project, then reload.</p>
<div id="controls" class="filters" hidden>
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
<nav id="views" class="views" hidden aria-label="Coverage views">
<button type="button" data-view="functions" class="active">Functions</button>
<button type="button" data-view="sections">Sections</button>
<button type="button" data-view="globals">Globals</button>
<button type="button" data-view="history">History</button>
</nav>
<section id="summary" aria-labelledby="summary-heading" aria-busy="false" hidden>
<h2 class="visually-hidden" id="summary-heading">Coverage summary</h2>
<div class="cards" id="cards"></div>
</section>
<p class="visually-hidden" id="results-status" role="status" aria-live="polite"></p>
<p id="dashboard-error" role="alert" hidden></p>
<div id="retry-bar">
<button type="button" id="retry-summary" hidden>Retry summary</button>
<button type="button" id="retry-functions" hidden>Retry functions</button>
<button type="button" id="retry-view" hidden>Retry</button>
</div>
<div id="view-functions" class="view-panel">
<p id="results-hint" hidden></p>
<p id="empty-state" hidden>No functions match these filters. Use Clear filters, or set Status and Module to any.</p>
<div id="show-more-wrap" hidden>
<button type="button" id="show-more">Show more functions</button>
</div>
<div id="results" class="table-scroll" tabindex="0" role="region"
  aria-label="Function results" aria-busy="false" hidden>
<table id="rows"><caption class="visually-hidden">Functions matching the selected filters</caption><thead><tr>
  <th scope="col">VA</th><th scope="col">Name</th><th scope="col">Symbol</th>
  <th scope="col">Size</th><th scope="col">Status</th>
  <th scope="col">Module</th><th scope="col">Files</th>
</tr></thead><tbody></tbody></table>
</div>
</div>
<div id="view-sections" class="view-panel" hidden>
<p id="sections-empty" hidden>No section stats for this target.</p>
<div id="sections-results" class="table-scroll" tabindex="0" role="region"
  aria-label="Section results" aria-busy="false" hidden>
<table id="sections-rows"><caption class="visually-hidden">Per-section cell stats</caption><thead><tr>
  <th scope="col">Section</th><th scope="col">Size</th><th scope="col">Cells</th>
  <th scope="col">Exact</th><th scope="col">Reloc</th><th scope="col">Near</th>
  <th scope="col">Stub</th><th scope="col">Proven</th><th scope="col">Other</th>
</tr></thead><tbody></tbody></table>
</div>
</div>
<div id="view-globals" class="view-panel" hidden>
<p id="globals-empty" hidden>No globals match this search. Clear the search or try another name.</p>
<div id="globals-results" class="table-scroll" tabindex="0" role="region"
  aria-label="Global results" aria-busy="false" hidden>
<table id="globals-rows"><caption class="visually-hidden">Global data symbols</caption><thead><tr>
  <th scope="col">VA</th><th scope="col">Name</th><th scope="col">Decl</th>
  <th scope="col">Size</th><th scope="col">Module</th>
</tr></thead><tbody></tbody></table>
</div>
</div>
<div id="view-history" class="view-panel" hidden>
<p id="history-empty" hidden>No status-change history for this target yet.</p>
<div id="history-results" class="table-scroll" tabindex="0" role="region"
  aria-label="History results" aria-busy="false" hidden>
<table id="history-rows"><caption class="visually-hidden">Recent status changes</caption><thead><tr>
  <th scope="col">VA</th><th scope="col">Old</th><th scope="col">New</th>
  <th scope="col">When</th>
</tr></thead><tbody></tbody></table>
</div>
</div>
</main>
<script>
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
let retryAppend = false;
let pageLimit = 100;
let currentView = "functions";
const PAGE_STEP = 500;
const PAGE_MAX = 5000;
const loadErrors = { summary: "", functions: "", view: "" };
const busyCounts = new Map();
const viewLoaded = { sections: false, globals: false, history: false };
async function get(path, signal) {
  const r = await fetch(path, { signal });
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
function syncError() {
  const message = loadErrors.summary
    || (currentView === "functions" ? loadErrors.functions : "")
    || (currentView !== "functions" ? loadErrors.view : "");
  if (message) {
    $("results-status").textContent = message;
    $("dashboard-error").textContent = message;
    $("dashboard-error").hidden = false;
  } else {
    $("dashboard-error").textContent = "";
    $("dashboard-error").hidden = true;
  }
  $("retry-summary").hidden = !loadErrors.summary;
  $("retry-functions").hidden = !(loadErrors.functions && currentView === "functions");
  $("retry-view").hidden = !(loadErrors.view && currentView !== "functions");
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
  $("filter-actions").hidden = !filtersActive();
}
function syncViewChrome() {
  const isFunctions = currentView === "functions";
  const isGlobals = currentView === "globals";
  $("filter-status").hidden = !isFunctions;
  $("filter-module").hidden = !isFunctions;
  $("filter-q").hidden = !isFunctions;
  $("filter-gq").hidden = !isGlobals;
  ["functions", "sections", "globals", "history"].forEach(name => {
    $("view-" + name).hidden = name !== currentView;
  });
  document.querySelectorAll("#views button[data-view]").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-view") === currentView);
  });
  updateFilterActions();
  syncError();
}
function syncCardActive() {
  const current = $("status").value;
  document.querySelectorAll("#cards button[data-status]").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-status") === current);
  });
}
function setStatusOptions(byStatus) {
  const select = $("status");
  const previous = select.value;
  const names = Object.keys(byStatus || {}).sort();
  select.innerHTML = "<option value=''>any</option>"
    + names.map(s => "<option value='" + esc(s) + "'>" + esc(s) + "</option>").join("");
  if (previous && names.includes(previous)) select.value = previous;
  else select.value = "";
}
function setModuleOptions(byModule) {
  const select = $("module");
  const previous = select.value;
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
    $("results-status").textContent = msg;
    hint.textContent = msg + ". Use Show more, or narrow Status, Module, or Search.";
    hint.hidden = false;
    const next = Math.min(count + PAGE_STEP, total, PAGE_MAX);
    more.hidden = count >= PAGE_MAX || count >= total;
    $("show-more").textContent = "Show more (up to " + next + ")";
  } else {
    const msg = count + " function" + (count === 1 ? "" : "s") + " shown";
    $("results-status").textContent = msg;
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
    $("results-status").textContent = "Loading functions…";
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
  $("cards").innerHTML = cards.map(([k, v, status, title]) => {
    if (status) {
      const active = $("status").value === status ? " active" : "";
      return "<button type=button class='card" + active + "' data-status='" + esc(status)
        + "' title='" + esc(title) + "'>"
        + "<span class=value>" + esc(v) + "</span>"
        + "<span class=label>" + esc(k) + "</span></button>";
    }
    return "<div class=card title='" + esc(title) + "'><span class=value>" + esc(v) + "</span>"
      + "<span class=label>" + esc(k) + "</span></div>";
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
  globalsSearchTimer = setTimeout(() => loadGlobals(), 200);
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
function renderGlobals(data) {
  const rows = data.globals || [];
  const body = $("globals-rows").querySelector("tbody");
  body.innerHTML = rows.map(g => "<tr><td class=va>" + esc(g.va || "") + "</td><td>"
    + esc(g.name || "") + "</td><td>" + esc(g.decl || "") + "</td><td>"
    + esc(g.size ?? "") + "</td><td>" + esc(g.module || "") + "</td></tr>").join("");
  const total = data.total ?? rows.length;
  $("globals-empty").hidden = rows.length !== 0;
  $("globals-results").hidden = rows.length === 0;
  $("results-status").textContent = total
    ? "Showing " + rows.length + " of " + total + " globals"
    : "No globals match";
  updateFilterActions();
}
function renderHistory(data) {
  const rows = data.history || [];
  const body = $("history-rows").querySelector("tbody");
  body.innerHTML = rows.map(h => "<tr><td class=va>" + esc(h.va || "") + "</td><td>"
    + esc(h.old_status || "") + "</td><td>" + esc(h.new_status || "") + "</td><td>"
    + esc(h.changed_at || "") + "</td></tr>").join("");
  $("history-empty").hidden = rows.length !== 0;
  $("history-results").hidden = rows.length === 0;
  const total = data.total ?? rows.length;
  $("results-status").textContent = total
    ? "Showing " + rows.length + " of " + total + " history entries"
    : "No history";
}
async function loadSections() {
  const t = $("target").value; if (!t) return;
  const seq = ++viewSeq;
  if (viewController) viewController.abort();
  viewController = new AbortController();
  const { signal } = viewController;
  $("sections-empty").hidden = true;
  $("sections-results").hidden = false;
  $("results-status").textContent = "Loading sections…";
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
    setLoadError("view", "Sections could not be loaded. Use Retry to try again.");
  }
}
async function loadGlobals() {
  const t = $("target").value; if (!t) return;
  const seq = ++viewSeq;
  if (viewController) viewController.abort();
  viewController = new AbortController();
  const { signal } = viewController;
  const params = new URLSearchParams({ target: t });
  if ($("gq").value.trim()) params.set("q", $("gq").value.trim());
  updateFilterActions();
  $("globals-empty").hidden = true;
  $("globals-results").hidden = false;
  $("results-status").textContent = "Loading globals…";
  try {
    setLoadError("view", "");
    const data = await whileBusy("globals-results", () =>
      get("/api/globals?" + params, signal));
    if (seq !== viewSeq || signal.aborted) return;
    viewLoaded.globals = true;
    renderGlobals(data);
  } catch (error) {
    if (seq !== viewSeq || signal.aborted) return;
    $("globals-results").hidden = true;
    $("globals-empty").hidden = true;
    setLoadError("view", "Globals could not be loaded. Use Retry to try again.");
  }
}
async function loadHistory() {
  const t = $("target").value; if (!t) return;
  const seq = ++viewSeq;
  if (viewController) viewController.abort();
  viewController = new AbortController();
  const { signal } = viewController;
  $("history-empty").hidden = true;
  $("history-results").hidden = false;
  $("results-status").textContent = "Loading history…";
  try {
    setLoadError("view", "");
    const data = await whileBusy("history-results", () =>
      get("/api/history?target=" + encodeURIComponent(t), signal));
    if (seq !== viewSeq || signal.aborted) return;
    viewLoaded.history = true;
    renderHistory(data);
  } catch (error) {
    if (seq !== viewSeq || signal.aborted) return;
    $("history-results").hidden = true;
    $("history-empty").hidden = true;
    setLoadError("view", "History could not be loaded. Use Retry to try again.");
  }
}
function loadCurrentView(force) {
  if (currentView === "functions") {
    if (force) { resetPaging(); loadFunctions(); }
    return;
  }
  if (currentView === "sections" && (force || !viewLoaded.sections)) return loadSections();
  if (currentView === "globals" && (force || !viewLoaded.globals)) return loadGlobals();
  if (currentView === "history" && (force || !viewLoaded.history)) return loadHistory();
}
function setView(name) {
  if (!["functions", "sections", "globals", "history"].includes(name)) return;
  currentView = name;
  setLoadError("view", "");
  syncViewChrome();
  loadCurrentView(false);
}
function bindControls() {
  $("target").onchange = () => {
    $("status").value = "";
    $("module").value = "";
    $("q").value = "";
    $("gq").value = "";
    viewLoaded.sections = false;
    viewLoaded.globals = false;
    viewLoaded.history = false;
    resetPaging();
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
      loadGlobals();
      updateFilterActions();
      return;
    }
    $("status").value = "";
    $("module").value = "";
    $("q").value = "";
    resetPaging();
    syncCardActive();
    updateFilterActions();
    clearTimeout(searchTimer);
    loadFunctions();
  };
  $("retry-summary").onclick = () => loadSummary();
  $("retry-functions").onclick = () => loadFunctions({ append: retryAppend });
  $("retry-view").onclick = () => loadCurrentView(true);
  $("show-more").onclick = () => {
    retryAppend = true;
    loadFunctions({ append: true });
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
  bindControls();
  syncViewChrome();
  if (boot.summary) {
    setLoadError("summary", "");
    renderSummary(boot.summary);
  } else {
    await loadSummary();
  }
  if (boot.functions) {
    setLoadError("functions", "");
    $("results").hidden = false;
    renderFunctions(boot.functions);
  } else {
    await loadFunctions();
  }
}
function start() {
  init().catch(error => {
    $("boot-status").hidden = true;
    setLoadError("summary", "Dashboard failed to load: " + error.message
      + ". Use Retry summary to try again.");
    $("retry-summary").onclick = () => {
      setLoadError("summary", "");
      $("boot-status").hidden = false;
      $("boot-status").textContent = "Loading coverage…";
      start();
    };
  });
}
start();
</script>
</body>
</html>
"""

_INDEX_HTML_BYTES = _INDEX_HTML.encode("utf-8")
_INDEX_ETAG = '"' + hashlib.sha256(_INDEX_HTML_BYTES).hexdigest()[:16] + '"'
_precompressed = gzip.compress(_INDEX_HTML_BYTES, compresslevel=_GZIP_PRECOMPRESS_LEVEL)
_INDEX_HTML_GZIP: bytes | None = (
    _precompressed if len(_precompressed) < len(_INDEX_HTML_BYTES) else None
)


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
        # Percent-encode the path (``sqlite_ro_uri``): a raw ``file:{p}?mode=ro``
        # truncates or rewrites names that contain ``?`` / ``#`` / ``%``.
        conn = sqlite3.connect(
            sqlite_ro_uri(self.db_path), uri=True, timeout=_SQLITE_TIMEOUT_SECONDS
        )
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

    def summary(self, target: str) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value FROM metadata WHERE target = ? AND key = 'function_stats'",
                (target,),
            ).fetchone()
        if row is None:
            return None
        try:
            stats = json.loads(row[0])
        except (json.JSONDecodeError, TypeError):
            stats = {
                "total": 0,
                "covered_bytes": 0,
                "matched_bytes": 0,
                "total_bytes": 0,
                "by_status": {},
            }
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
        return {
            "target": target,
            "function_stats": stats,
            "coverage_pct": round(covered / total_b * 100.0, 1) if total_b else 0.0,
            "identified_pct": round(identified / total_b * 100.0, 1) if total_b else 0.0,
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
        self, target: str, *, q: str | None = None, limit: int = _DEFAULT_LIMIT
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
                f"{where_sql} ORDER BY va LIMIT ?",
                [*args, limit],
            ).fetchall()
            if len(rows) < limit:
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
            "offset": 0,
            "globals": [
                {
                    "va": f"0x{r[0]:08x}" if r[0] else "???",
                    "name": r[1] or "",
                    "decl": r[2] or "",
                    "size": r[3],
                    "module": r[4] or "",
                }
                for r in rows
            ],
        }

    def history(self, target: str, *, limit: int = _DEFAULT_LIMIT) -> dict[str, Any]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT va, old_status, new_status, changed_at FROM history "
                "WHERE target = ? ORDER BY id DESC LIMIT ?",
                (target, limit),
            ).fetchall()
            if len(rows) < limit:
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
            "offset": 0,
            "history": [
                {
                    "va": f"0x{r[0]:08x}" if r[0] else "???",
                    "old_status": r[1],
                    "new_status": r[2],
                    "changed_at": r[3],
                }
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
        """Strong HTML etag; weak DB etag so rebuilds invalidate JSON caches."""
        parsed = urlparse(path)
        if parsed.path == "/":
            return _INDEX_ETAG
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
                    result = self.summary(target)
                    if result is None:
                        return self._json(404, {"error": f"unknown target {target!r}"})
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
                        ),
                    )
                return self._json(
                    200,
                    self.history(
                        target,
                        limit=_int_param(query, "limit", _DEFAULT_LIMIT),
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


def _accepts_gzip(accept_encoding: str) -> bool:
    """Honor gzip quality weights, with explicit gzip overriding the wildcard."""
    accepted: dict[str, bool] = {}
    for part in accept_encoding.lower().split(","):
        coding, *parameters = part.split(";")
        coding = coding.strip()
        if coding not in ("gzip", "*"):
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
        accepted[coding] = 0 < weight <= 1
    return accepted.get("gzip", accepted.get("*", False))


def _maybe_gzip(body: bytes, accept_encoding: str) -> tuple[bytes, str | None]:
    """Return ``(body, encoding)``; compress only when it shrinks the wire bytes."""
    if len(body) < _MIN_GZIP_BYTES or not _accepts_gzip(accept_encoding):
        return body, None
    compressed = gzip.compress(body, compresslevel=_GZIP_LEVEL)
    if len(compressed) >= len(body):
        return body, None
    return compressed, "gzip"


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

        etag: str | None = None
        if status == 200:
            etag = self.dashboard.response_etag(self.path)
            if _if_none_match(self.headers.get("If-None-Match", ""), etag):
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Vary", "Accept-Encoding")
                self._write_security_headers(cacheable=True)
                self.end_headers()
                return

        body_bytes = body.encode("utf-8")
        encoding: str | None = None
        if status == 200:
            # Entry document is immutable for a given process: serve the
            # import-time gzip blob instead of recompressing every request.
            accept = self.headers.get("Accept-Encoding", "")
            if body is _INDEX_HTML and _INDEX_HTML_GZIP is not None and _accepts_gzip(accept):
                body_bytes = _INDEX_HTML_GZIP
                encoding = "gzip"
            else:
                body_bytes, encoding = _maybe_gzip(body_bytes, accept)

        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        if etag is not None:
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
        # The app is inline-JS/CSS only and fetches same-origin JSON — this
        # keeps any future escaping of API data from loading external
        # resources or phoning home.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self'; form-action 'none'; base-uri 'none'",
        )

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
        "[bold]Endpoints:[/bold]\n\n"
        "  / · · · · · · · · · · · · HTML app (targets, summary, function search)\n\n"
        "  /api/bootstrap · · · · · · Targets + first target summary/functions\n\n"
        "  /api/targets · · · · · · List targets\n\n"
        "  /api/summary?target= · · Coverage stats (target required)\n\n"
        "  /api/functions?target= · Function rows (status/module/q/limit/offset)\n\n"
        "  /api/sections?target= · · Per-section cell stats\n\n"
        "  /api/globals?target= · · Global data rows\n\n"
        "  /api/history?target= · · Status-change history\n\n"
        "[dim]Read-only: DB opened mode=ro. Target-scoped routes need ?target= "
        "(400 if missing, 404 if unknown). Non-GET/HEAD → 405.[/dim]"
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
        json_print({"url": f"http://{host}:{port}", "db": str(db_path)})

    # Non-loopback binds expose the read-only coverage API with no auth
    # (SECURITY.md).  Warn once at startup so ``--host 0.0.0.0`` is never silent.
    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            f"[yellow]warning:[/] dashboard bound to {host}:{port} with no authentication "
            "— any client that can reach this host can read coverage.db"
        )

    server = ThreadingHTTPServer((host, port), _Handler)
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
    """Run the Typer CLI application (standalone single-command form)."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
