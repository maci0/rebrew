import assert from "node:assert/strict";

import { installStubDom, loadApp } from "./dashboard_dom.mjs";

installStubDom({ hidden: false, title: "Rebrew coverage dashboard" });

const summary = {
  function_stats: { total: 1, by_status: { EXACT: 1 }, by_module_counts: { game: 1 } },
  coverage_pct: 100,
  identified_pct: 100,
};
const functionPage = (name) => ({
  count: 1,
  total: 1,
  functions: [["0x00401000", name, name, 16, "EXACT", "game", "game/foo.c"]],
});
const globalsPage = {
  count: 1,
  total: 1,
  globals: [["0x00403000", "g_flag", "int g_flag", 4, "game"]],
};

const requested = [];
globalThis.fetch = async (path) => {
  const url = new URL(path, "http://127.0.0.1:8000");
  requested.push(url.pathname);
  const body = url.pathname === "/api/bootstrap"
    ? { targets: ["a.exe"], summary, functions: functionPage("WinMain") }
    : url.pathname === "/api/summary" ? summary
    : url.pathname === "/api/functions" ? functionPage("Searched")
    : url.pathname === "/api/globals" ? globalsPage
    : {};
  return { ok: true, json: async () => body };
};

// A real <select> takes the first option's value when its markup is assigned;
// the stub does not, so seed it the way the browser would.
document.getElementById("target").value = "a.exe";

const { start, setView } = await loadApp(["start", "setView"]);
await start();

const el = (id) => document.getElementById(id);
assert.match(el("rows").innerHTML, /WinMain/, "the boot page renders its rows");

// Type into the Functions search, then switch views inside the 200 ms debounce
// window. The pending debounce belongs to the view that scheduled it: firing it
// after the switch spends a query and a full table render on a view the reader
// has already left.
el("q").value = "Win";
el("q").oninput();
setView("globals");
await new Promise((resolve) => setTimeout(resolve, 400));

assert.match(
  el("globals-rows").innerHTML,
  /g_flag/,
  "the switched-to view renders its rows",
);
assert.equal(
  requested.filter((path) => path === "/api/globals").length,
  1,
  "the globals view was fetched once",
);
assert.equal(
  requested.filter((path) => path === "/api/functions").length,
  0,
  "the Functions view was not queried behind the reader's back",
);
