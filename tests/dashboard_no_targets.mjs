import assert from "node:assert/strict";

import { installDom, loadApp } from "./dashboard_dom.mjs";

const elements = installDom(
  (id) => ({
    value: id === "target" ? "t" : "",
    innerHTML: "",
    textContent: "",
    hidden: true,
    attributes: {},
    setAttribute(name, value) { this.attributes[name] = value; },
    querySelector() { return this; },
    querySelectorAll() { return []; },
    insertAdjacentHTML(position, html) { this.innerHTML += html; },
    focus() {},
  }),
  { activeElement: {} },
);
globalThis.location = { hash: "" };
globalThis.history = { replaceState() {}, pushState() {} };

const summary = {
  function_stats: { by_status: { EXACT: 1 }, by_module_counts: { "": 1 }, total: 1 },
  coverage_pct: 10,
  identified_pct: 20,
};
let boot = 0;
globalThis.fetch = (path) => {
  const url = path.split("?")[0];
  if (url === "/api/bootstrap") {
    return Promise.resolve({
      ok: true,
      json: async () => (boot === 0
        ? { targets: [] }
        : { targets: ["t"], summary, functions: { count: 1, total: 1, functions: [["0x10", "f", "f", 1, "EXACT", "", "f.c"]] } }),
    });
  }
  if (url === "/api/summary") return Promise.resolve({ ok: true, json: async () => summary });
  return Promise.resolve({ ok: true, json: async () => ({ count: 0, total: 0 }) });
};
globalThis.AbortController = class {
  constructor() { this.signal = { aborted: false }; }
  abort() { this.signal.aborted = true; }
};

const { start } = await loadApp(["start"]);
for (let i = 0; i < 50 && elements.get("reload").hidden; i++) {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

// The empty state must offer the Reload it names: previously the note said
// "choose Reload" while Reload sat below, hidden behind the unrevealed
// retry bar, leaving the reader with no visible way to act on it.
assert.equal(elements.get("no-targets").hidden, false);
assert.equal(elements.get("reload").hidden, false, "Reload is reachable from the empty state");

boot = 1;
await elements.get("reload").onclick();
assert.equal(elements.get("no-targets").hidden, true);
assert.equal(elements.get("controls").hidden, false);
assert.match(elements.get("rows").innerHTML, /f/);
