import assert from "node:assert/strict";

import { installStubDom, loadApp } from "./dashboard_dom.mjs";

installStubDom({ hidden: false, title: "Rebrew coverage dashboard" });

const summary = {
  function_stats: { total: 1200, by_status: { EXACT: 1200 }, by_module_counts: { game: 1200 } },
  coverage_pct: 100,
  identified_pct: 100,
};
const functionPage = {
  count: 1,
  total: 1200,
  functions: [["0x00401000", "WinMain", "_WinMain", 16, "EXACT", "game", "game/main.c"]],
};
const globalsPage = {
  count: 1,
  total: 900,
  globals: [["0x00402000", "g_flag", "int g_flag", 4, "game"]],
};

let failNext = false;
globalThis.fetch = async (path) => {
  const url = new URL(path, "http://127.0.0.1:8000");
  if (failNext) {
    return { ok: false, status: 500, json: async () => ({ error: "database error" }) };
  }
  const body = url.pathname === "/api/bootstrap"
    ? { targets: ["a.exe"], summary, functions: functionPage }
    : url.pathname === "/api/summary" ? summary
    : url.pathname === "/api/functions" ? functionPage
    : url.pathname === "/api/globals" ? globalsPage
    : { sections: [], history: [] };
  return { ok: true, json: async () => body };
};

document.getElementById("target").value = "a.exe";

const { start, setView } = await loadApp(["start", "setView"]);
await start();

const el = (id) => document.getElementById(id);

// A page that fails to append leaves the rows already loaded on screen, so the
// count stays with them: a table of results with no idea how many of the match
// it is showing is the worse state. The hint names Show more, so Show more
// stays too, ready to fetch the page the failure swallowed.
assert.match(el("results-hint").textContent, /Showing 1 of 1200 functions/);
failNext = true;
await el("show-more").onclick();
failNext = false;
assert.equal(el("results").hidden, false, "the rows already loaded stay on screen");
assert.equal(el("show-more-wrap").hidden, false, "Show more stays to fetch the missing page");
assert.equal(el("show-more").disabled, false, "and is usable again");
assert.equal(
  el("results-hint").hidden,
  false,
  "the count stays while the loaded rows do",
);
assert.match(
  el("results-hint").textContent,
  /Showing 1 of 1200 functions\. Use Show more below/,
  "the hint still counts what is shown and the button that extends it",
);
assert.match(el("dashboard-error").textContent, /Retry functions/);

// Same for the paged globals list, which shares the message path.
setView("globals");
await new Promise((resolve) => setImmediate(resolve));
assert.match(el("globals-hint").textContent, /Showing 1 of 900 globals/);
failNext = true;
await el("show-more-globals").onclick();
failNext = false;
assert.equal(el("globals-results").hidden, false, "the loaded globals stay on screen");
assert.equal(el("globals-show-more-wrap").hidden, false, "Show more stays for globals");
assert.match(
  el("globals-hint").textContent,
  /Showing 1 of 900 globals\. Use Show more below/,
  "the globals count stays while the loaded rows do",
);
assert.match(el("dashboard-error").textContent, /Retry globals/);
