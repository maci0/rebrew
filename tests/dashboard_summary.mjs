import assert from "node:assert/strict";

import { installDom, loadApp } from "./dashboard_dom.mjs";

installDom(
  () => ({
    value: "",
    innerHTML: "",
    textContent: "",
    hidden: true,
    attributes: {},
    setAttribute(name, value) { this.attributes[name] = value; },
    querySelector() { return this; },
    querySelectorAll() { return []; },
    insertAdjacentHTML(position, html) { this.innerHTML += html; },
  }),
  // Focus is not modeled here; report it as held so restoreFocus is a no-op.
  { activeElement: {} },
);
const pending = [];
globalThis.fetch = (path, options) => {
  if (path === "/api/bootstrap") return Promise.resolve({ ok: true, json: async () => ({ targets: [] }) });
  const signal = options && options.signal;
  const entry = { path, get aborted() { return signal ? signal.aborted : false; } };
  pending.push(entry);
  return new Promise((resolve, reject) => {
    entry.resolve = resolve;
    entry.reject = reject;
  });
};
globalThis.AbortController = class {
  constructor() { this.signal = { aborted: false }; }
  abort() {
    this.signal.aborted = true;
    this.aborted = true;
  }
};
const { loadSummary, bindControls, renderSections, renderGlobals, renderHistory, renderSummary, setView } =
  await loadApp([
    "loadSummary",
    "bindControls",
    "renderSections",
    "renderGlobals",
    "renderHistory",
    "renderSummary",
    "setView",
  ]);
const element = (id) => document.getElementById(id);
const summary = (status) => ({
  function_stats: { total: 1, by_status: { [status]: 1 } },
  coverage_pct: 50,
  identified_pct: 100,
});

for (const staleFailure of [false, true]) {
  element("target").value = "old_target";
  const oldRequest = loadSummary();
  const oldResponse = pending.shift();
  assert.equal(oldResponse.aborted, false);
  element("target").value = "new_target";
  const newRequest = loadSummary();
  assert.equal(oldResponse.aborted, true, "superseded request must be aborted");
  const newResponse = pending.shift();
  assert.equal(element("status").disabled, true);
  assert.doesNotMatch(element("status").innerHTML, /EXACT|STUB/);
  assert.match(element("cards").innerHTML, /Loading coverage summary/);
  assert.doesNotMatch(element("cards").innerHTML, /data-status/);
  assert.match(oldResponse.path, /target=old_target$/);
  assert.match(newResponse.path, /target=new_target$/);
  assert.equal(newResponse.aborted, false);
  newResponse.resolve({ ok: true, json: async () => summary("EXACT") });
  await newRequest;
  assert.match(element("status").innerHTML, /EXACT/);
  assert.equal(element("status").disabled, false);
  assert.match(element("cards").innerHTML, /EXACT/);
  // Button cards: hint only in title (the description), never repeated in the name.
  assert.match(element("cards").innerHTML, /<button[^>]*title='Filter Functions by EXACT'[^>]*><span class=value>1<\/span><span class='label st status-EXACT'>EXACT<\/span><\/button>/);
  assert.match(element("cards").innerHTML, /<div class=card title='Total functions for this target'>.*<span class=visually-hidden>, Total functions for this target<\/span><\/div>/);
  const options = element("status").innerHTML;
  const cards = element("cards").innerHTML;
  if (staleFailure) oldResponse.reject(new Error("Old target failed"));
  else oldResponse.resolve({ ok: true, json: async () => summary("STUB") });
  await oldRequest;
  assert.equal(element("status").innerHTML, options);
  assert.equal(element("cards").innerHTML, cards);
  assert.equal(element("dashboard-error").hidden, true);
}

const failedRequest = loadSummary();
pending.shift().reject(new Error("Connection lost"));
await failedRequest;
assert.equal(element("summary").hidden, true);
assert.equal(element("cards").innerHTML, "");
assert.equal(element("status").disabled, true);
assert.equal(element("dashboard-error").hidden, false);
assert.match(element("dashboard-error").textContent, /Retry summary/);
assert.equal(element("retry-summary").hidden, false);

const recoveredRequest = loadSummary();
pending.shift().resolve({ ok: true, json: async () => summary("STUB") });
await recoveredRequest;
assert.equal(element("summary").hidden, false);
assert.equal(element("status").disabled, false);
assert.match(element("cards").innerHTML, /STUB/);
assert.equal(element("dashboard-error").hidden, true);

bindControls();
element("target").value = "tgt";
element("status").value = "STUB";
element("q").value = "  win ";
element("show-more").onclick();
const failed = pending.shift();
assert.match(failed.path, /target=tgt/);
assert.match(failed.path, /status=STUB/);
assert.match(failed.path, /limit=500&offset=0/);
assert.match(failed.path, /q=win/);
failed.reject(new Error("Connection lost"));
await new Promise(resolve => setImmediate(resolve));
assert.equal(element("results").hidden, true);
assert.equal(element("empty-state").hidden, true);
assert.equal(element("show-more-wrap").hidden, true);
assert.equal(element("dashboard-error").hidden, false);
assert.match(element("dashboard-error").textContent, /Retry functions/);
assert.equal(element("retry-functions").hidden, false);

const retried = element("retry-functions").onclick();
const retryResponse = pending.shift();
assert.equal(retryResponse.path, failed.path);
assert.equal(element("retry-functions").hidden, true);
retryResponse.resolve({
  ok: true,
  json: async () => ({ count: 1, total: 1, functions: [["0x1", "win", "", 0, "", "", ""]] }),
});
await retried;
assert.equal(element("dashboard-error").hidden, true);
assert.equal(element("results").hidden, false);
assert.match(element("rows").innerHTML, /0x1/);
assert.equal(element("retry-functions").hidden, true);
assert.equal(element("target").value, "tgt");
assert.equal(element("status").value, "STUB");
assert.equal(element("q").value, "  win ");

const rowsBeforeFailure = element("rows").innerHTML;
element("show-more").onclick();
const failedGrow = pending.shift();
assert.match(failedGrow.path, /limit=500&offset=1/);
failedGrow.reject(new Error("Connection lost"));
await new Promise(resolve => setImmediate(resolve));
assert.equal(element("rows").innerHTML, rowsBeforeFailure);
assert.equal(element("results").hidden, false);
assert.equal(element("empty-state").hidden, true);
assert.equal(element("dashboard-error").hidden, false);
assert.match(element("dashboard-error").textContent, /next page/);
assert.equal(element("retry-functions").hidden, false);

const retriedGrow = element("retry-functions").onclick();
const retryGrowResponse = pending.shift();
assert.equal(retryGrowResponse.path, failedGrow.path);
retryGrowResponse.resolve({
  ok: true,
  json: async () => ({ count: 1, total: 2, functions: [["0x2", "lose", "", 0, "", "", ""]] }),
});
await retriedGrow;
assert.equal(element("dashboard-error").hidden, true);
const grownRows = element("rows").innerHTML;
assert.match(grownRows, /0x1/);
assert.match(grownRows, /0x2/);
assert.match(grownRows, /win/);
assert.match(grownRows, /lose/);

element("show-more").onclick();
const failedAppend = pending.shift();
assert.match(failedAppend.path, /limit=500&offset=2/);
failedAppend.reject(new Error("Connection lost"));
await new Promise(resolve => setImmediate(resolve));
assert.equal(element("results").hidden, false);
assert.equal(element("retry-functions").hidden, false);
assert.equal(element("show-more-wrap").hidden, true);
assert.match(element("dashboard-error").textContent, /next page/);
assert.match(element("rows").innerHTML, /0x1/);
assert.match(element("rows").innerHTML, /0x2/);

const retriedAppend = element("retry-functions").onclick();
const retryDelta = pending.shift();
assert.equal(retryDelta.path, failedAppend.path);
retryDelta.resolve({
  ok: true,
  json: async () => ({ count: 1, total: 3, functions: [["0x3", "draw", "", 0, "", "", ""]] }),
});
await retriedAppend;
assert.equal(element("retry-functions").hidden, true);
const grown = element("rows").innerHTML;
assert.match(grown, /0x1/);
assert.match(grown, /0x2/);
assert.match(grown, /0x3/);
assert.match(grown, /win/);
assert.match(grown, /lose/);
assert.match(grown, /draw/);

element("show-more").onclick();
const tail = pending.shift();
assert.match(tail.path, /limit=500&offset=3/);
tail.resolve({ ok: true, json: async () => ({ count: 0, total: 3, functions: [] }) });
await new Promise(resolve => setImmediate(resolve));
const finalRows = element("rows").innerHTML;
assert.equal(element("results").hidden, false);
assert.equal(element("empty-state").hidden, true);
assert.match(finalRows, /0x1/);
assert.match(finalRows, /0x2/);
assert.match(finalRows, /0x3/);
assert.equal(element("show-more-wrap").hidden, true);
assert.equal(element("retry-functions").hidden, true);
assert.equal(pending.length, 0);

// Every counted cell state gets a column, so a row's cells sum to its Cells total.
// Sections has no filters of its own, so the shared message reports a bare
// count: clear the function filters this harness left on the controls.
element("status").value = "";
element("q").value = "";
renderSections({ sections: [[
  ".text", 64, 66, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
]] });
const cells = [...element("sections-rows").innerHTML.matchAll(/<td>([^<]*)<\/td>/g)].map(m => m[1]);
assert.deepEqual(cells, [".text", "64", "66", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"]);
assert.equal(cells.slice(3).reduce((sum, n) => sum + Number(n), 0), 66);
// Sections counts itself like every other view ("1 section shown", not "1
// sections"), and an empty list reads the same way the others do.
assert.equal(element("results-status").textContent, "1 section shown");
assert.equal(element("sections-hint").textContent, "Showing 1 section");
assert.equal(element("sections-hint").hidden, false);
renderSections({ sections: [] });
assert.equal(element("results-status").textContent, "No sections yet");
assert.equal(element("sections-hint").hidden, true);
assert.equal(element("sections-empty").hidden, false);

// One row reads "1 global shown", not "1 globals shown".
renderGlobals({ total: 1, globals: [["0x10", "g_one", "int g_one", 4, ""]] });
assert.equal(element("results-status").textContent, "1 global shown");
renderGlobals({ total: 2, globals: [["0x10", "g_a", "", 4, ""], ["0x14", "g_b", "", 4, ""]] });
assert.equal(element("results-status").textContent, "2 globals shown");
renderGlobals({ total: 3, globals: [["0x10", "g_a", "", 4, ""], ["0x14", "g_b", "", 4, ""]] });

// Show more on a paged list keeps the rows it already counted, so the count
// hint above them stays on screen (and true) while the next page loads.
bindControls();
const hintBefore = element("globals-hint").textContent;
assert.match(hintBefore, /Showing 2 of 3 globals/);
const growing = element("show-more-globals").onclick();
const growResponse = pending.shift();
assert.match(growResponse.path, /limit=500&offset=2/);
assert.equal(element("globals-hint").hidden, false, "the count hint survives the grow");
assert.equal(element("globals-hint").textContent, hintBefore);
growResponse.resolve({
  ok: true,
  json: async () => ({ count: 1, total: 3, globals: [["0x18", "g_c", "", 4, ""]] }),
});
await growing;
assert.equal(element("globals-hint").hidden, false);
assert.equal(element("globals-hint").textContent, "Showing 3 globals");
assert.equal(element("results-status").textContent, "3 globals shown");

// History timestamps: zone-less UTC instants go through the shared formatter
// (zone abbreviation included); unparseable values pass through.
const when = (iso) => new Intl.DateTimeFormat(undefined, {
  year: "numeric", month: "short", day: "numeric",
  hour: "numeric", minute: "2-digit",
  timeZoneName: "short",
}).format(new Date(iso));
renderHistory({ total: 3, history: [
  ["0x10", "f", "STUB", "EXACT", "2026-01-02T03:04:05"],
  ["0x14", "g", "STUB", "RELOC", "2026-03-04T05:06:00Z"],
  ["0x18", "h", "STUB", "EXACT", "not a date"],
] });
// The class attribute is quoted: the marks carry a space ("st status-X"), and
// an unquoted value would truncate at it and drop the colour class.
assert.match(element("history-rows").innerHTML, /<span class='st status-STUB'>STUB<\/span>/);
assert.match(element("history-rows").innerHTML, /<span class='st status-EXACT'>EXACT<\/span>/);
assert.match(element("history-rows").innerHTML, /<span class='st status-RELOC'>RELOC<\/span>/);
const stamps = [...element("history-rows").innerHTML.matchAll(/<td>([^<]*)<\/td><\/tr>/g)].map(m => m[1]);
assert.deepEqual(stamps, [when("2026-01-02T03:04:05Z"), when("2026-03-04T05:06:00Z"), "not a date"]);

// A VA's first recorded transition has no old status, and the server sends ""
// for it.  An empty status cell reads as a missing value, so the cell says
// what it means instead.
renderHistory({ total: 1, history: [["0x1c", "i", "", "EXACT", "2026-01-02T03:04:05"]] });
assert.match(element("history-rows").innerHTML, /<td>\(first change\)<\/td>/);
assert.doesNotMatch(element("history-rows").innerHTML, /status-\(first change\)/);

// A status card filters the Functions view only.  On Globals the Status select
// is hidden and the rows are not filtered, so no card may read as pressed
// there; a summary that arrives while Globals is on screen must paint the
// same way, or the highlight claims a filter the table is not applying.
setView("globals");
element("status").value = "EXACT";
renderSummary(summary("EXACT"));
assert.match(element("cards").innerHTML, /aria-pressed='false'/);
setView("functions");
renderSummary(summary("EXACT"));
assert.match(element("cards").innerHTML, /aria-pressed='true'/);
