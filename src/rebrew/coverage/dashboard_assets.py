"""Embedded HTML/JS/SVG assets and precompressed payloads for the dashboard server."""

from __future__ import annotations

from functools import cache
lazy import base64
lazy import hashlib
lazy import json

from rebrew.compression import precompress
from rebrew.status_style import STATUS_LEGEND_ORDER, STATUS_SUMMARIES, status_text_css
from rebrew.theme import FAVICON_SVG as FAVICON_SVG
from rebrew.theme import inline

FAVICON_PATH = "/favicon.svg"
# Zone-less date-times are UTC.  Held as a raw string so the digit-class
# escapes are JS escapes, not Python ones, then spliced into the client.
ZONELESS_INSTANT_RE = r"/^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/"

#: The report's one-line status meanings, in the same canonical order. The
#: dashboard renders only the tokens present in the selected target's summary.
STATUS_REFERENCE_JS = json.dumps(
    [
        [status, STATUS_SUMMARIES[status]]
        for status in STATUS_LEGEND_ORDER
        if status in STATUS_SUMMARIES
    ],
    ensure_ascii=True,
    separators=(",", ":"),
)

APP_JS = """
const $ = (id) => document.getElementById(id);
const STATUS_REFERENCE = __STATUS_REFERENCE__;
let targets = [];
let searchTimer = null;
let globalsSearchTimer = null;
let functionsSeq = 0;
let summarySeq = 0;
let viewSeq = 0;
let initSeq = 0;
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
let pendingStatus = "";
let pendingModule = "";
// Hash ``module=`` (present, empty) restores the blank-module filter.
let pendingModuleBlank = false;
// Hash writes start once init has restored state, so a reload keeps it.
let hashReady = false;
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
  let r;
  try {
    r = await fetch(path, { signal });
  } catch (error) {
    if (signal && signal.aborted) throw error;
    throw new Error("the dashboard server did not respond; check that rebrew coverage serve is still running");
  }
  if (!r.ok) {
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
  // Zone-less date-times are stored in UTC.
  let raw = String(value).trim();
  if (__ZONELESS_INSTANT_RE__.test(raw)) {
    raw += "Z";
  }
  const parsed = Date.parse(raw);
  if (Number.isNaN(parsed)) return String(value);
  try {
    // Reuse the formatter and distinguish repeated daylight-saving hours.
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
  if (filtersActive("functions")) {
    const m = moduleFilterState();
    const onlyQuery = !$("status").value && !m.blank && !m.value && !!$("q").value.trim();
    if (onlyQuery) {
      // Named as the Clear control below it, which clears the whole set.
      el.innerHTML = "No functions match this search. <button type='button' id='empty-clear-fn' class='link-button'>Clear filters</button> or try another query.";
    } else {
      el.innerHTML = "No functions match these filters. <button type='button' id='empty-clear-fn' class='link-button'>Clear filters</button>, or broaden Status and Module.";
    }
    bindEmptyClear("empty-clear-fn", "q");
  } else {
    el.innerHTML = "No functions recorded for this target yet. Register their source bindings, then <button id='empty-r-fn' class='link-button'>Reload</button>.";
  }
}
function bindEmptyClear(btnId, inputId) {
  const btn = $(btnId);
  if (btn) btn.onclick = () => { $(inputId).focus(); $("clear-filters").click(); };
}
function setGlobalsEmptyMessage() {
  const el = $("globals-empty");
  if (filtersActive("globals")) {
    el.innerHTML = "No globals match this search. <button type='button' id='empty-clear-gq' class='link-button'>Clear search</button> or try another name.";
    bindEmptyClear("empty-clear-gq", "gq");
  } else {
    el.innerHTML = "No globals recorded for this target yet. Register globals in data metadata, then <button id='empty-r-gq' class='link-button'>Reload</button>.";
  }
}
function syncError() {
  const message = loadErrors.summary
    || (currentView === "functions" ? loadErrors.functions : "")
    || (currentView !== "functions" ? loadErrors.view : "");
  const box = $("dashboard-error");
  // A new alert scrolls into view: it renders above the tables, off screen.
  // role=alert announces every textContent write, and this runs on every view
  // switch, so an unchanged message must not be rewritten (WCAG 4.1.3).
  if (message && message !== box.textContent) {
    box.textContent = message;
    box.hidden = false;
    box.scrollIntoView?.({ block: "nearest" });
  } else if (message) {
    box.hidden = false;
  } else {
    box.textContent = "";
    box.hidden = true;
  }
  // Reload re-reads every input, so it is the way out of any load failure.
  if (loadErrors.summary || loadErrors.functions || loadErrors.view) $("reload").hidden = false;
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
function filtersActive(view = currentView) {
  if (view === "globals") return !!$("gq").value.trim();
  if (view !== "functions") return false;
  const moduleState = moduleFilterState();
  return !!($("status").value || moduleState.blank || moduleState.value || $("q").value.trim());
}
function updateFilterActions() {
  // Mounted even when hidden, so enabling Clear never moves the tabs.
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
  const current = currentView === "functions" ? $("status").value : "";
  document.querySelectorAll("#cards button[data-status]").forEach(btn => {
    const on = btn.getAttribute("data-status") === current;
    btn.classList.toggle("active", on);
    btn.setAttribute("aria-pressed", on ? "true" : "false");
  });
}
function renderStatusReference(byStatus) {
  const rows = STATUS_REFERENCE.filter(([status]) =>
    Object.prototype.hasOwnProperty.call(byStatus, status));
  $("status-reference-list").innerHTML = rows.map(([status, meaning]) =>
    "<dt class='" + statusMark(status) + "'>" + esc(status) + "</dt><dd>" + esc(meaning) + "</dd>").join("");
  $("status-reference").hidden = rows.length === 0;
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
  const { count, total, noun, nounOne, hintId, moreWrapId, moreBtnId, tip, tipCapped, filtered } = opts;
  const hint = $(hintId);
  const more = moreWrapId ? $(moreWrapId) : null;  // null: sections is unpaged
  if (!total) {
    // "No functions match" is a claim about the filters, not the target.
    $("results-status").textContent = "No " + noun + (filtered ? " match" : " yet");
    hint.hidden = true;
    hint.textContent = "";
    if (more) more.hidden = true;
    return;
  }
  if (count < total) {
    const msg = "Showing " + count + " of " + total + " " + noun;
    const capped = count >= PAGE_MAX;
    $("results-status").textContent = msg;
    const tail = capped ? tipCapped : tip;
    hint.textContent = tail ? msg + ". " + tail : msg;
    hint.hidden = false;
    const next = Math.min(count + PAGE_STEP, total, PAGE_MAX);
    if (more) {
      more.hidden = capped;
      // The label counts this click; the running total is in the hint.
      const step = next - count;
      $(moreBtnId).textContent = "Show " + step + " more " + (step === 1 ? nounOne : noun);
    }
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
function statusCell(s) {
  const mark = statusMark(s);
  return (mark ? "<td class='" + mark + "'>" : "<td>") + esc(s) + "</td>";
}
// Rows are positional arrays named by the response's ``cols``.
const rowHtml = (r) => {
  return "<tr><td class=va>" + esc(r[0] ?? "") + "</td><td>" + esc(r[1] || "")
    + "</td><td>" + esc(r[2] || "") + "</td><td>" + esc(r[3] ?? "")
    + "</td>" + statusCell(r[4] || "") + "<td>" + esc(r[5] || "")
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
    filtered: filtersActive("functions"),
  });
  setFunctionsEmptyMessage();
  $("empty-state").hidden = shown !== 0;
  $("results").hidden = shown === 0;
  viewLoaded.functions = true;
  syncError();
}
async function loadFunctions(options) {
  const grow = !!(options && options.append && viewLoaded.functions);
  clearTimeout(searchTimer);
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
    if (!grow) {
      resetPaging();
      viewLoaded.functions = false;
      resetList("rows", "results-hint", "show-more-wrap");
    }
    // aria-busy only: a polite-live "Loading…" per debounced keystroke is
    // chatter (WCAG 4.1.3).
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
    // Loaded rows keep the count that hints at them.
    if (!loadedCount) {
      $("show-more-wrap").hidden = true;
      $("results-hint").hidden = true;
    }
    setLoadError("functions", grow && loadedCount > 0
      ? "Could not load more functions" + reason(error) + ". The rows already shown are unchanged; use Retry functions to fetch the next page again."
      : "Functions could not be loaded" + reason(error) + ". Use Retry functions to try again with the same filters.");
  }
}
function renderSummary(s) {
  const byStatus = s.function_stats.by_status || {};
  renderStatusReference(byStatus);
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
    ["Matched coverage", (s.coverage_pct ?? 0).toFixed(1) + "%", null,
      "Share of .text bytes in byte-matched functions and identified libraries. Alignment padding is not included."],
    ["Identified coverage", (s.identified_pct ?? 0).toFixed(1) + "%", null,
      "Share of .text bytes covered by any known function, including stubs"],
  ];
  // Same order as the Status select.
  for (const k of Object.keys(byStatus).sort()) cards.push([k, byStatus[k], k, "Filter Functions by " + k]);
  // A div cannot be named, so title rides in a visually-hidden span after the
  // visible text (WCAG 2.5.3); a button exposes its hint as an accessible
  // description, so a screen-reader user hears "Filter Functions by EXACT"
  // without it leaking into the accessible name.
  $("cards").innerHTML = cards.map(([k, v, status, title], i) => {
    const mark = status ? statusMark(status) : "";
    const label = mark ? "<span class='label " + mark + "'>" : "<span class=label>";
    const inner = "<span class=value>" + esc(v) + "</span> " + label + esc(k) + "</span>";
    const hintId = "card-desc-" + i;
    if (status) {
      const pressed = currentView === "functions" && $("status").value === status;
      const active = pressed ? " active" : "";
      return "<button type=button class='card" + active + "' data-status='" + esc(status)
        + "' aria-describedby='" + hintId + "' aria-pressed='" + (pressed ? "true" : "false") + "'>"
        + inner + "<span class=visually-hidden id='" + hintId + "'>" + esc(title) + "</span></button>";
    }
    return "<div class=card>" + inner
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
  $("status-reference").hidden = true;
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
    return true;
  } catch (error) {
    if (seq !== summarySeq || signal.aborted) return;
    $("cards").innerHTML = "";
    $("summary").hidden = true;
    $("status").disabled = false;  // loadSummary disabled them
    $("module").disabled = false;
    setLoadError("summary", "Function coverage could not be loaded" + reason(error) + ". Use Retry summary to try again.");
    return false;
  }
}
function scheduleSearch() {
  // Leaving before the debounce fires cancels the load, so the cached rows no
  // longer match the text still in the box. Reload them if the reader returns.
  viewLoaded.functions = false;
  if (functionsController) functionsController.abort();
  clearTimeout(searchTimer);
  updateFilterActions();
  searchTimer = setTimeout(() => {
    resetPaging();
    loadFunctions();
  }, 200);
}
function scheduleGlobalsSearch() {
  viewLoaded.globals = false;
  if (viewController) viewController.abort();
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
  syncError();
  // Unpaged, so the shared message counts the rows as the whole list.
  setListPageMessage({
    count: rows.length,
    total: rows.length,
    noun: "sections",
    nounOne: "section",
    hintId: "sections-hint",
    moreWrapId: null,
    filtered: false,
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
    filtered: filtersActive("globals"),
  });
  viewLoaded.globals = true;
  updateFilterActions();
  syncError();
}
const historyRowHtml = (r) => {
  // A blank old status is the first recorded change, not a missing value.
  return "<tr><td class=va>" + esc(r[0] ?? "") + "</td><td>" + esc(r[1] || "")
    + "</td>" + statusCell(r[2] || "(first change)") + statusCell(r[3] || "")
    + "<td>" + esc(formatWhen(r[4])) + "</td></tr>";
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
  syncError();
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
    filtered: false,
  });
}
async function loadSections() {
  const t = $("target").value; if (!t) return;
  const seq = ++viewSeq;
  if (viewController) viewController.abort();
  viewController = new AbortController();
  const { signal } = viewController;
  $("sections-empty").hidden = true;
  viewLoaded.sections = false;
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
  const grow = !!(options && options.append && viewLoaded.globals);
  clearTimeout(globalsSearchTimer);
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
  if (!grow) {
    resetGlobalsPaging();
    viewLoaded.globals = false;
    resetList("globals-rows", "globals-hint", "globals-show-more-wrap");
  }
  $("globals-results").hidden = false;
  try {
    setLoadError("view", "");
    const data = await whileBusy("globals-results", () =>
      get("/api/globals?" + params, signal));
    if (seq !== viewSeq || signal.aborted) return;
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
    // Loaded rows keep the count that hints at them.
    if (!loadedGlobalsCount) {
      $("globals-show-more-wrap").hidden = true;
      $("globals-hint").hidden = true;
    }
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
  if (!grow) {
    viewLoaded.history = false;
    resetList("history-rows", "history-hint", "history-show-more-wrap");
  }
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
    // Loaded rows keep the count that hints at them.
    if (!loadedHistoryCount) {
      $("history-show-more-wrap").hidden = true;
      $("history-hint").hidden = true;
    }
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
  // A request for the view being left must not repaint or fail the view the
  // reader just opened. Cached destinations start no request of their own, so
  // cancel the old one here rather than relying on the next loader to abort it.
  if (name !== currentView) {
    viewSeq++;
    if (viewController) viewController.abort();
  }
  currentView = name;
  if (currentView !== "functions") clearTimeout(searchTimer);
  if (currentView !== "globals") clearTimeout(globalsSearchTimer);
  setLoadError("view", "");
  syncViewChrome();
  loadCurrentView(false);
}
function bindControls() {
  // One document holds every view, so Back returns to the previous one:
  // assignment keeps re-binding idempotent.
  // Back rebuilds every control, so the focused one is gone and the browser
  // drops focus to <body> (WCAG 2.4.3).
  globalThis.onpopstate = () => { void start().then(() => restoreFocus(["main"])); };
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
    $("retry-summary").disabled = true;
    try {
      const loaded = await loadSummary();
      // Saved Status and Module filters become usable only when the summary
      // restores their options. Reload rows that may have used the empty fallback.
      if (loaded) {
        viewLoaded.functions = false;
        if (currentView === "functions") {
          resetPaging();
          await loadFunctions();
        }
      }
    } finally {
      $("retry-summary").disabled = false;
    }
    restoreFocus(["retry-summary", "main"]);
  };
  $("retry-functions").onclick = async () => {
    $("retry-functions").disabled = true;
    try {
      await loadFunctions({ append: retryAppend });
    } finally {
      $("retry-functions").disabled = false;
    }
    restoreFocus(["retry-functions", "results", "main"]);
  };
  $("retry-view").onclick = async () => {
    $("retry-view").disabled = true;
    try {
      if (currentView === "globals" && retryGlobalsAppend && loadedGlobalsCount > 0) {
        await loadGlobals({ append: true });
      } else if (currentView === "history" && retryHistoryAppend && loadedHistoryCount > 0) {
        await loadHistory({ append: true });
      } else {
        await loadCurrentView(true);
      }
    } finally {
      $("retry-view").disabled = false;
    }
    restoreFocus(["retry-view", currentView + "-results", "results", "main"]);
  };
  $("show-more").onclick = async () => {
    retryAppend = true;
    $("show-more").disabled = true;
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
    const wasFunctions = currentView === "functions";
    if (!wasFunctions) setView("functions");
    const status = btn.getAttribute("data-status");
    // Cards read as unpressed outside Functions, so clicking one there applies
    // that status even when the hidden Functions view already had it selected.
    $("status").value = wasFunctions && $("status").value === status ? "" : status;
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
  // A reload or Back navigation can arrive while a page append is still in
  // flight.  Invalidate those responses before awaiting the new bootstrap so
  // an old offset cannot append to the freshly rendered first page.
  const seq = ++initSeq;
  functionsSeq++;
  summarySeq++;
  viewSeq++;
  if (functionsController) functionsController.abort();
  if (summaryController) summaryController.abort();
  if (viewController) viewController.abort();
  clearTimeout(searchTimer);
  clearTimeout(globalsSearchTimer);
  let boot;
  try {
    boot = await get("/api/bootstrap");
  } catch (error) {
    if (seq !== initSeq) return;
    throw error;
  }
  if (seq !== initSeq) return;
  $("boot-status").hidden = true;
  VIEWS.forEach((name) => (viewLoaded[name] = false));
  $("reload").hidden = false;
  targets = boot.targets || [];
  if (boot.failures) {
    $("boot-status").textContent = Object.entries(boot.failures).map(([target, error]) => target + ": " + error).join("; ");
    $("boot-status").hidden = false;
  }
  bindControls();
  $("no-targets").hidden = !!targets.length;
  if (!targets.length) {
    $("controls").hidden = true;
    $("views").hidden = true;
    $("summary").hidden = true;
    VIEWS.forEach((name) => ($("view-" + name).hidden = true));
    $("target").innerHTML = "";
    $("target").disabled = true;
    loadErrors.summary = loadErrors.functions = loadErrors.view = "";
    syncError();
    document.title = "Rebrew coverage dashboard";
    $("results-status").textContent = "No targets in the coverage documents";
    return;
  }
  $("controls").hidden = false;
  $("views").hidden = false;
  $("target").innerHTML = targets.map(t =>
    "<option value='" + esc(t) + "'>" + esc(t) + "</option>").join("");
  $("target").disabled = false;
  const saved = new URLSearchParams(location.hash.slice(1));
  const savedTarget = saved.get("target");
  const targetRestored = targets.includes(savedTarget);
  $("target").value = targetRestored ? savedTarget : targets[0];
  // The hash is the whole navigation state, so a hash without a view names the
  // first one: Back to an entry written before the reader switched views
  // returns to Functions rather than keeping the view they left.
  currentView = VIEWS.includes(saved.get("view")) ? saved.get("view") : "functions";
  // Filters belong to the named target. A stale link must not silently apply
  // them to the first target in the list.
  pendingStatus = targetRestored ? saved.get("status") || "" : "";
  pendingModule = targetRestored ? saved.get("module") || "" : "";
  pendingModuleBlank = targetRestored && saved.has("module") && !saved.get("module");
  $("q").value = targetRestored ? saved.get("q") || "" : "";
  $("gq").value = targetRestored ? saved.get("gq") || "" : "";
  // The hash is authoritative. Drop values left by the entry being navigated
  // away from before the summary restores the saved options.
  $("status").value = "";
  $("module").value = "";
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
  if (seq !== initSeq) return;
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
    // syncError reveals the shared Reload button for every load failure, but a
    // failed bootstrap runs before bindControls(). Give it the same recovery
    // action so the visible button is not inert on the first failure.
    $("reload").onclick = $("retry-summary").onclick;
    $("retry-summary").focus();
  });
}
document.addEventListener?.("click", (ev) => {
  const b = ev.target.closest && ev.target.closest("button[id^='empty-r-']");
  if (b) $("reload").click();
});
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
#: Inline in the shell (under a ``script-src`` hash, see ``BOOT_GUARD_HASH``).
#: It runs on ``DOMContentLoaded``, which a deferred client always precedes, so
#: a client that never reached its first statement is reported the same way an
#: aborted transfer or a parse error is.
BOOT_GUARD_JS = (
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

#: The shell.  The selected card and tab are marked with a ``box-shadow``
#: ring rather than a thicker border: a border that grows the box re-lays out
#: every card and tab after the selected one, which on a wrapped tab strip
#: moves the control the reader is aiming at.  Weight marks the selection too,
#: so it survives a forced-colors palette (WCAG 1.4.1).  Notes on the shell's
#: rules belong here, not in the ``<style>`` block, which ships on the cold
#: flight.
#:
#: The ``[hidden]`` reset is load-bearing and needs ``!important`` to be.  The
#: user-agent sheet's ``[hidden] { display: none }`` is a plain type selector, so
#: any author ``display`` on the same element outranks it -- and ``.filters``,
#: ``.filters > div`` and ``.views`` are flex containers, while every filter
#: control plus the tab strip and the filter bar ship ``hidden``.  Without the
#: reset Status, Module and both search boxes stayed painted and stayed in the
#: tab order on the Sections, Globals and History views, where none of them
#: applies (WCAG 2.4.3): a keyboard user tabbed through four dead controls per
#: view, and ``#filter-q`` and ``#filter-gq`` sat side by side on Globals as two
#: search boxes when only one of them works there.  The reset also carries the
#: no-JS path, since the client is what reveals ``#views``/``#controls``/
#: ``#summary``: a client that never runs leaves them hidden instead of painting
#: an empty filter bar over the boot status.  It replaces the ``.view-panel
#: [hidden]`` one-off, which guarded one element of the same kind.
#:
#: The reset has to fit the cold flight, so ``overflow-wrap: anywhere`` moved
#: onto the shared ``th, td`` rule to pay for it: it is inert on ``th``, which is
#: nowrap, so the ``td`` rule it replaced bought nothing.  The other reclaim
#: tried here, folding the two ``.views button.active`` rules together, is not
#: safe -- it demotes the selected card's status mark from 700 to 600, because
#: the per-mark ``font-weight`` then outranks the inherited one.
INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rebrew coverage dashboard</title>
<link rel="preload" href="/api/bootstrap" as="fetch" crossorigin fetchpriority="high">
<link rel="preload" href="__APP_JS_URL__" as="script" fetchpriority="high">
<link rel="icon" href="__FAVICON__" type="image/svg+xml" sizes="16x16" fetchpriority="low">
<style>
  [hidden] { display: none !important; }
  body { font-family: var(--rb-sans); line-height: var(--rb-leading-body); margin: 1.5rem;
    background: var(--rb-sunken); color: var(--rb-ink); }
  .skip-link { position: absolute; left: -9999px; top: 0; z-index: 100;
    padding: .5rem 1rem; background: var(--rb-surface); color: var(--rb-accent);
    text-decoration: underline; }
  .skip-link:focus-visible { left: 1rem; top: 1rem; }
  .filters { display: flex; flex-wrap: wrap; gap: .5rem 1rem; align-items: end;
    margin-bottom: .5rem; }
  .filters > div { display: flex; flex-direction: column; gap: .25rem; font-size: var(--rb-size-note); }
  select, input { min-height: 2.75rem; padding: .3rem .5rem; min-width: 10rem;
    font: inherit; border: 1px solid var(--rb-line); border-radius: var(--rb-radius);
    background: var(--rb-surface); color: inherit; }
  :focus-visible { outline: 3px solid var(--rb-accent); outline-offset: 2px; }
  h1 { font-size: var(--rb-size-title); letter-spacing: var(--rb-track-display);
    margin: -1.5rem -1.5rem 1rem; padding: .75rem 1.5rem;
    background: var(--rb-ink); color: var(--rb-surface); }
  h2 { font-size: var(--rb-size-heading); letter-spacing: var(--rb-track-display); margin: 1.5rem 0 .5rem; }
  .cards { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0;
    min-height: 4.3rem; }
  .card { border: 1px solid var(--rb-line); border-radius: var(--rb-radius);
    padding: .9rem 1.1rem; min-width: 110px; background: var(--rb-surface); }
  button.card { font: inherit; color: inherit; text-align: left; cursor: pointer; min-height: 2.75rem; }
  button.card:hover { border-color: var(--rb-line-hi); background: var(--rb-hover); }
  button.card:active { background: var(--rb-pressed); }
  button.card.active, .views button.active { border-color: var(--rb-accent);
    box-shadow: 0 0 0 2px var(--rb-ring); }
  button.card.active .label, .views button.active { font-weight: 700; }
  .card .value { font-size: var(--rb-size-value); font-weight: 700; display: block; }
  .label { color: var(--rb-muted); font-size: var(--rb-size-caption); letter-spacing: var(--rb-track-label); }
  .legend { background: var(--rb-surface); border: 1px solid var(--rb-line);
    border-radius: var(--rb-radius); padding: .6rem 1.1rem; margin: 0 0 1rem; }
  .legend > summary { cursor: pointer; font-weight: 600; min-height: 2.75rem;
    padding: .35rem 0; display: flex; align-items: center; }
  .legend dl { display: grid; grid-template-columns: max-content 1fr;
    gap: .35rem 1.25rem; margin: .75rem 0 .25rem; }
  .legend dt { font-family: var(--rb-mono); font-weight: 600; }
  .legend dd { margin: 0; }
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
  th, td { border-bottom: 1px solid var(--rb-line); padding: .3rem .5rem; text-align: left;
    overflow-wrap: anywhere; }
  th { background: var(--rb-sunken); white-space: nowrap; font-weight: 600; }
  tbody tr:hover { background: var(--rb-hover); }
  td.va, code { font-family: var(--rb-mono); }
  td.va { white-space: nowrap; }
  #dashboard-error { color: var(--rb-note-ink); background: var(--rb-note-bg);
    border: 1px solid var(--rb-note-ink); border-radius: var(--rb-radius);
    padding: .6rem .8rem; margin: .75rem 0; }
  #empty-state, #no-targets, #sections-empty, #globals-empty, #history-empty { color: var(--rb-faint); margin: 1rem 0; }
  #results-hint, #globals-hint, #history-hint, #sections-hint {
    color: var(--rb-faint); font-size: var(--rb-size-note); margin: .25rem 0 .5rem; }
  #filter-actions, #show-more-wrap, #globals-show-more-wrap, #history-show-more-wrap,
  #retry-bar { margin: .35rem 0 .75rem; }
  .btn { min-height: 2.75rem; padding: .3rem .75rem; border: 1px solid var(--rb-line);
    border-radius: var(--rb-radius); background: var(--rb-surface);
    color: inherit; font: inherit; cursor: pointer; }
  .btn:hover:not(:disabled) { border-color: var(--rb-line-hi); background: var(--rb-hover); }
  .btn:active:not(:disabled) { background: var(--rb-pressed); }
  button:disabled { background: var(--rb-pressed); cursor: not-allowed; }
  .views { display: flex; flex-wrap: wrap; gap: .35rem; margin: .75rem 0 .25rem; }
  .views .btn { padding: .3rem .85rem; }
  .link-button { background: none; border: none; padding: .3rem 0; min-height: 2.75rem;
    color: var(--rb-accent); text-decoration: underline; font: inherit; cursor: pointer; }
  .link-button:hover { color: var(--rb-accent-hi); }
  @media (max-width: 40rem) {
    body { margin: 1rem; }
    h1 { margin: -1rem -1rem 1rem; padding: .75rem 1rem; }
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
  tbody tr { content-visibility: auto; contain-intrinsic-size: auto 2.2rem; }
</style>
<noscript><style>#boot-status { display: none; }</style></noscript>
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
<main id="main" tabindex="-1">
<h1>0x Rebrew coverage</h1>
<p id="boot-status" role="status">Loading coverage…</p>
<noscript><p id="no-script">The dashboard needs JavaScript to load coverage data.
  Enable it for this page, then reload.</p></noscript>
<p id="no-targets" hidden>No readable targets. Check project inputs or the selected snapshots, then <button id="empty-r-targets" class="link-button">Reload</button>.</p>
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
<div id="controls" class="filters" hidden role="group" aria-label="Coverage filters">
<div>
<label for="target">Target</label>
<select id="target" disabled></select>
</div>
<div id="filter-status">
<label for="status">Status</label>
<select id="status" disabled><option value="">any</option></select>
</div>
<div id="filter-module">
<label for="module">Module</label>
<select id="module" disabled><option value="">any</option></select>
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
<section id="summary" aria-labelledby="summary-heading" aria-busy="false" hidden>
<h2 id="summary-heading">Function coverage</h2>
<div class="cards" id="cards" role="group" aria-label="Function coverage metrics"></div>
<details id="status-reference" class="legend" hidden><summary>Status reference</summary><dl id="status-reference-list"></dl></details>
</section>
<p class="visually-hidden" id="results-status" role="status" aria-live="polite"></p>
<p id="dashboard-error" role="alert" hidden></p>
<div id="retry-bar" role="group" aria-label="Reload and retry">
<button type="button" class="btn" id="reload" hidden>Reload</button>
<button type="button" class="btn" id="retry-summary" hidden>Retry summary</button>
<button type="button" class="btn" id="retry-functions" hidden>Retry functions</button>
<button type="button" class="btn" id="retry-view" hidden>Retry</button>
</div>
<div id="view-functions" class="view-panel" role="tabpanel" tabindex="-1" aria-labelledby="tab-functions">
<h2 class="visually-hidden">Functions</h2>
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
<div id="view-sections" class="view-panel" role="tabpanel" tabindex="-1" aria-labelledby="tab-sections" hidden>
<h2 class="visually-hidden">Sections</h2>
<p id="sections-hint" hidden></p>
<p id="sections-empty" hidden>No section stats for this target yet. Check the target binary, then <button id="empty-r-sections" class="link-button">Reload</button>.</p>
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
<div id="view-globals" class="view-panel" role="tabpanel" tabindex="-1" aria-labelledby="tab-globals" hidden>
<h2 class="visually-hidden">Globals</h2>
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
<div id="view-history" class="view-panel" role="tabpanel" tabindex="-1" aria-labelledby="tab-history" hidden>
<h2 class="visually-hidden">Status history</h2>
<p id="history-hint" hidden></p>
<p id="history-empty" hidden>No status changes recorded for this target yet. Comparisons record history, then <button id="empty-r-history" class="link-button">Reload</button>.</p>
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
<script src="__APP_JS_URL__" defer fetchpriority="high"></script>
<script>__BOOT_GUARD_JS__</script>
</body>
</html>
"""

APP_JS = APP_JS.replace("__STATUS_REFERENCE__", STATUS_REFERENCE_JS).replace(
    "__ZONELESS_INSTANT_RE__", ZONELESS_INSTANT_RE
)


def script_for_wire(source: str) -> str:
    """Drop full-line comments from a script every cold load downloads.

    The comments document the client for the people editing it. A browser
    never reads them, and they still cost the compressed body that gates
    interactivity. A line that is only a comment is removed. A comment after
    code stays: cutting that needs a real parse, and those lines are few.
    """
    kept = [line for line in source.splitlines() if not line.lstrip().startswith("//")]
    if source.endswith("\n"):
        return "\n".join(kept) + "\n"
    return "\n".join(kept)


#: What ``/app.js`` sends. ``APP_JS`` keeps the comments the tests and the
#: bun harness execute against; the wire copy is the same program without
#: the lines a browser cannot use.
APP_JS_WIRE = script_for_wire(APP_JS)
APP_JS_BYTES = APP_JS_WIRE.encode("utf-8")
APP_JS_VERSION = hashlib.sha256(APP_JS_BYTES).hexdigest()[:16]
APP_JS_ETAG = f'"{APP_JS_VERSION}"'
BOOT_GUARD_JS_BYTES = BOOT_GUARD_JS.encode("utf-8")
#: ``script-src`` source expression for the inline guard, so the shell keeps a
#: strict policy while carrying the guard instead of fetching it.
BOOT_GUARD_HASH = (
    "sha256-" + base64.b64encode(hashlib.sha256(BOOT_GUARD_JS_BYTES).digest()).decode()
)
#: Content-hashed so the shell can cache each client immutable.
APP_JS_URL = f"/app.js?v={APP_JS_VERSION}"
#: Every request a cold load makes for the document and its clients, in
#: document order.  Their wire bytes share one initial congestion window.
ENTRY_PATHS = ("/", APP_JS_URL)
#: The mark, served rather than inlined. A percent-encoded data URI is 443 B
#: of near-incompressible payload in the document that has to fit the initial
#: congestion window, and a tab icon is not first paint: linked, it costs the
#: cold flight nothing.
FAVICON_SVG_BYTES = FAVICON_SVG.encode("utf-8")
FAVICON_VERSION = hashlib.sha256(FAVICON_SVG_BYTES).hexdigest()[:16]
FAVICON_ETAG = f'"{FAVICON_VERSION}"'
#: Carries the same content hash the client does. The browser asks for the
#: icon on every load, and ``private, no-cache`` made that a revalidation
#: round trip per page; hashed, it is immutable and fetched once.
#: The shell marks it ``fetchpriority="low"`` because it is discovered in the
#: head beside the two entry assets and the preloaded bootstrap, all four on
#: the one cold connection: an unprioritized icon queues with the resources
#: that paint and spends its 208 gzip bytes and ~600 B of header reserve on
#: the initial window ahead of them.
FAVICON_URL = f"{FAVICON_PATH}?v={FAVICON_VERSION}"


def _dashboard_status_css() -> str:
    """Status text rules indented for the dashboard shell.

    The shell ships inside a fixed cold-load byte budget, so the shared
    generator keeps the six machine verdicts on one error-red rule.
    """
    return status_text_css("  ")


def _dashboard_status_forced() -> str:
    """One forced-colors rule so status marks follow the system palette.

    Every mark carries the shared ``st`` class, so this stays one selector
    however many statuses the mark table holds.
    """
    return "    .st { color: CanvasText; font-weight: 700; }"


# The heading carries the same ink title band the report pages open on, bled to
# the page edge by the negative margin that matches ``body``'s own inset, so the
# two HTML surfaces read as one tool.  Its padding matches the report header's.
# The shell links the content-hashed URL, so only that URL is cached immutable.
INDEX_HTML = INDEX_HTML.replace("__STATUS_CSS__", _dashboard_status_css()).replace(
    "__STATUS_FORCED__", _dashboard_status_forced()
)
# Token references resolve to their theme values, so the shell is one file.
INDEX_HTML = inline(INDEX_HTML)
INDEX_HTML = (
    INDEX_HTML.replace("__APP_JS_URL__", APP_JS_URL)
    .replace("__BOOT_GUARD_JS__", BOOT_GUARD_JS)
    .replace("__FAVICON__", FAVICON_URL)
)
INDEX_HTML_BYTES = INDEX_HTML.encode("utf-8")
INDEX_ETAG = '"' + hashlib.sha256(INDEX_HTML_BYTES).hexdigest()[:16] + '"'
CACHE_REVALIDATE = "private, no-cache"
CACHE_IMMUTABLE = "private, max-age=31536000, immutable"


#: The entry assets compress at max effort (zstd 19 runs at MB/s), which cost
#: ~10 ms of import time on every `rebrew` invocation because CLI composition
#: imports this module for every command.  Build them on the first request that
#: serves an asset instead; the server is the only caller.
@cache
def index_html_zstd() -> bytes:
    return precompress(INDEX_HTML_BYTES, "zstd") or INDEX_HTML_BYTES


@cache
def index_html_gzip() -> bytes:
    return precompress(INDEX_HTML_BYTES, "gzip") or INDEX_HTML_BYTES


@cache
def app_js_zstd() -> bytes:
    return precompress(APP_JS_BYTES, "zstd") or APP_JS_BYTES


@cache
def app_js_gzip() -> bytes:
    return precompress(APP_JS_BYTES, "gzip") or APP_JS_BYTES


@cache
def favicon_zstd() -> bytes:
    return precompress(FAVICON_SVG_BYTES, "zstd") or FAVICON_SVG_BYTES


@cache
def favicon_gzip() -> bytes:
    return precompress(FAVICON_SVG_BYTES, "gzip") or FAVICON_SVG_BYTES


__all__ = [
    "APP_JS",
    "APP_JS_BYTES",
    "APP_JS_ETAG",
    "APP_JS_URL",
    "APP_JS_VERSION",
    "APP_JS_WIRE",
    "BOOT_GUARD_HASH",
    "BOOT_GUARD_JS",
    "BOOT_GUARD_JS_BYTES",
    "CACHE_IMMUTABLE",
    "CACHE_REVALIDATE",
    "ENTRY_PATHS",
    "FAVICON_ETAG",
    "FAVICON_PATH",
    "FAVICON_SVG",
    "FAVICON_SVG_BYTES",
    "FAVICON_URL",
    "FAVICON_VERSION",
    "INDEX_ETAG",
    "INDEX_HTML",
    "INDEX_HTML_BYTES",
    "STATUS_REFERENCE_JS",
    "ZONELESS_INSTANT_RE",
    "app_js_gzip",
    "app_js_zstd",
    "favicon_gzip",
    "favicon_zstd",
    "index_html_gzip",
    "index_html_zstd",
    "script_for_wire",
]
