import assert from "node:assert/strict";

import { installStubDom, loadApp } from "./dashboard_dom.mjs";

installStubDom({ hidden: false, title: "Rebrew coverage dashboard" });

const summary = {
  function_stats: { total: 1, by_status: { EXACT: 1 }, by_module_counts: { game: 1 } },
  coverage_pct: 100,
  identified_pct: 100,
};
const functionPage = {
  count: 1,
  total: 1,
  functions: [["0x00401000", "WinMain", "_WinMain", 16, "EXACT", "game", "game/main.c"]],
};

const requested = [];
let functionsFail = false;
let sectionsFail = false;
globalThis.fetch = async (path) => {
  const url = new URL(path, "http://127.0.0.1:8000");
  requested.push(url.pathname);
  if ((url.pathname === "/api/functions" && functionsFail)
    || (url.pathname === "/api/sections" && sectionsFail)) {
    return { ok: false, status: 500, json: async () => ({ error: "database error" }) };
  }
  const body = url.pathname === "/api/bootstrap"
    ? { targets: ["a.exe"], summary, functions: functionPage }
    : url.pathname === "/api/summary" ? summary
    : url.pathname === "/api/functions" ? functionPage
    : { sections: [[".text", 64, 66, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]] };
  return { ok: true, json: async () => body };
};

document.getElementById("target").value = "a.exe";

const { start, setView, loadSections } = await loadApp(["start", "setView", "loadSections"]);
await start();

const el = (id) => document.getElementById(id);
const countFunctions = () => requested.filter((p) => p === "/api/functions").length;

// Pressing Enter in a search input fires `search` after `keydown`. Binding both
// to the debounced scheduler fetched the same page twice, and the second load
// aborted the first the reader was already waiting on.
assert.equal(
  typeof el("q").onsearch,
  "undefined",
  "the search box has no second `search` binding to double-fetch through",
);
const before = countFunctions();
el("q").value = "Win";
el("q").oninput();
el("q").onkeydown({ key: "Enter" });
await new Promise((resolve) => setTimeout(resolve, 400));
assert.equal(
  countFunctions(),
  before + 1,
  "Enter in the search box fetches the page once",
);

// A failed load empties the panel and hides Show more, so the paging hint
// pointing at that button must go too: it otherwise sends the reader after a
// control that is gone. The banner carries the reason and the retry.
functionsFail = true;
setView("globals");
await new Promise((resolve) => setImmediate(resolve));
setView("functions");
el("status").value = "EXACT";
el("status").onchange();
await new Promise((resolve) => setImmediate(resolve));
assert.equal(el("show-more-wrap").hidden, true, "Show more is gone after the failure");
assert.equal(
  el("results-hint").hidden,
  true,
  "the hint pointing at Show more is cleared with it",
);
assert.match(el("dashboard-error").textContent, /Retry functions/);
assert.equal(el("retry-functions").hidden, false, "the retry is offered");

// Sections is unpaged but shares the message path: a failure must clear its
// hint too, or it keeps claiming rows the panel no longer shows. A loaded
// view is cached, so the second load is called directly.
setView("sections");
await new Promise((resolve) => setImmediate(resolve));
assert.match(el("sections-hint").textContent, /Showing 1 section/);
sectionsFail = true;
await loadSections();
assert.equal(el("sections-results").hidden, true, "the section table is gone");
assert.equal(el("sections-hint").hidden, true, "its stale count hint is cleared");
assert.match(el("dashboard-error").textContent, /Retry sections/);
assert.equal(el("retry-view").hidden, false, "the retry is offered");
