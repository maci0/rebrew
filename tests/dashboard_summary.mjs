import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = readFileSync(0, "utf8");
const elements = new Map();
globalThis.document = {
  getElementById(id) {
    if (!elements.has(id)) {
      elements.set(id, {
        value: "",
        innerHTML: "",
        textContent: "",
        hidden: true,
        attributes: {},
        setAttribute(name, value) { this.attributes[name] = value; },
        querySelector() { return this; },
        querySelectorAll() { return []; },
        insertAdjacentHTML(position, html) { this.innerHTML += html; },
      });
    }
    return elements.get(id);
  },
  querySelectorAll() { return []; },
  // Focus is not modeled here; report it as held so restoreFocus is a no-op.
  activeElement: {},
};
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
const { loadSummary, bindControls, renderSections, renderGlobals, renderHistory } = await import(
  "data:text/javascript;base64," + Buffer.from(source + "\nexport { loadSummary, bindControls, renderSections, renderGlobals, renderHistory };\n").toString("base64")
);
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
  assert.match(element("cards").innerHTML, /<button[^>]*title='Filter by EXACT'[^>]*><span class=value>1<\/span><span class='label status-EXACT'>EXACT<\/span><\/button>/);
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
  json: async () => ({ count: 1, total: 1, functions: [{ va: "0x1", name: "win" }] }),
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
  json: async () => ({ count: 1, total: 2, functions: [{ va: "0x2", name: "lose" }] }),
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
  json: async () => ({ count: 1, total: 3, functions: [{ va: "0x3", name: "draw" }] }),
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
renderSections({ sections: [{
  name: ".text", size: 64, total_cells: 66, exact: 1, reloc: 2, near_match: 3, stub: 4,
  proven: 5, size_mismatch: 6, thunk: 7, data: 8, padding: 9, none: 10, other: 11,
}] });
const cells = [...element("sections-rows").innerHTML.matchAll(/<td>([^<]*)<\/td>/g)].map(m => m[1]);
assert.deepEqual(cells, [".text", "64", "66", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"]);
assert.equal(cells.slice(3).reduce((sum, n) => sum + Number(n), 0), 66);

// One row reads "1 global shown", not "1 globals shown".
renderGlobals({ total: 1, globals: [["0x10", "g_one", "int g_one", 4, ""]] });
assert.equal(element("results-status").textContent, "1 global shown");
renderGlobals({ total: 2, globals: [["0x10", "g_a", "", 4, ""], ["0x14", "g_b", "", 4, ""]] });
assert.equal(element("results-status").textContent, "2 globals shown");

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
assert.match(element("history-rows").innerHTML, /<span class=status-STUB>STUB<\/span>/);
assert.match(element("history-rows").innerHTML, /<span class=status-EXACT>EXACT<\/span>/);
assert.match(element("history-rows").innerHTML, /<span class=status-RELOC>RELOC<\/span>/);
const stamps = [...element("history-rows").innerHTML.matchAll(/<td>([^<]*)<\/td><\/tr>/g)].map(m => m[1]);
assert.deepEqual(stamps, [when("2026-01-02T03:04:05Z"), when("2026-03-04T05:06:00Z"), "not a date"]);
