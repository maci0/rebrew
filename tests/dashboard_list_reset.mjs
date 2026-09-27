import assert from "node:assert/strict";

import { installStubDom, loadApp } from "./dashboard_dom.mjs";

installStubDom({ hidden: false, title: "Rebrew coverage dashboard" });

const summary = {
  function_stats: { total: 2, by_status: { EXACT: 1, STUB: 1 }, by_module_counts: { game: 2 } },
  coverage_pct: 50,
  identified_pct: 100,
};
const page = (va, name) => ({
  count: 1,
  total: 1,
  functions: [[va, name, name, 16, "EXACT", "game", "game/foo.c"]],
});
globalThis.fetch = async (path) => {
  const url = new URL(path, "http://127.0.0.1:8000");
  const body = url.pathname === "/api/bootstrap"
    ? { targets: ["a.exe", "b.exe"], summary, functions: page("0x00401000", "WinMain") }
    : url.pathname === "/api/summary" ? summary
    : url.pathname === "/api/functions" ? page("0x00501000", "Other")
    : {};
  return { ok: true, json: async () => body };
};

// A real <select> takes the first option's value when its markup is assigned;
// the stub does not, so seed it the way the browser would.
document.getElementById("target").value = "a.exe";

const { start } = await loadApp(["start"]);
await start();  // the module already ran start() on import; this awaits a fresh run

const el = (id) => document.getElementById(id);
assert.match(el("rows").innerHTML, /WinMain/, "the boot page renders its rows");
assert.equal(document.title, "a.exe - Functions - Rebrew coverage", "the title names the target");

// A target switch must not leave the previous target's rows under the loading
// veil, which is translucent.
const target = el("target");
target.value = "b.exe";
void target.onchange();
assert.equal(el("rows").innerHTML, "", "the old rows are gone before the new page lands");
assert.equal(document.title, "b.exe - Functions - Rebrew coverage", "the title follows the target");
