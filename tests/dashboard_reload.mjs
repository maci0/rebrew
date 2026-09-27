import assert from "node:assert/strict";

import { installDom, loadApp } from "./dashboard_dom.mjs";

const elements = installDom(
  (id) => ({
    // init() compares the select's value with the first target to decide
    // whether the bootstrap payload already covers the on-screen view.
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
  // Focus is not modeled here; report it as held so restoreFocus is a no-op.
  { activeElement: {} },
);
globalThis.location = { hash: "" };
globalThis.history = { replaceState() {} };

const summary = {
  function_stats: { by_status: { EXACT: 1 }, by_module_counts: { "": 1 }, total: 1 },
  coverage_pct: 10,
  identified_pct: 20,
};
const firstPage = { count: 1, total: 1, functions: [["0x10", "first", "first", 1, "EXACT", "", "f.c"]] };
const secondPage = { count: 1, total: 1, functions: [["0x10", "second", "second", 1, "EXACT", "", "f.c"]] };

let boot = 0;
const bootCalls = [];
globalThis.fetch = (path) => {
  const url = path.split("?")[0];
  if (url === "/api/bootstrap") {
    bootCalls.push(path);
    return Promise.resolve({
      ok: true,
      json: async () => ({ targets: ["t"], summary, functions: boot ? secondPage : firstPage }),
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
// The client boots itself at the end of the module; wait for that run.
for (let i = 0; i < 50 && elements.get("reload").hidden; i++) {
  await new Promise((resolve) => setTimeout(resolve, 0));
}
assert.equal(typeof start, "function");
assert.equal(elements.get("reload").hidden, false);
const booted = bootCalls.length;
assert.equal(booted, 1);
assert.match(elements.get("rows").innerHTML, /first/);

// The database moved on (rebrew build-db in another terminal): Reload re-reads
// it without a browser reload, so the rows on screen follow.
boot = 1;
const pending = elements.get("reload").onclick();
assert.equal(elements.get("reload").textContent, "Reloading…");
assert.equal(elements.get("reload").disabled, true);
await pending;
assert.equal(bootCalls.length, booted + 1);
assert.match(elements.get("rows").innerHTML, /second/);
assert.equal(elements.get("reload").textContent, "Reload");
assert.equal(elements.get("reload").disabled, false);
