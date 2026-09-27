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

// 0: an empty coverage.db, the state a first run lands in before build-db.
// 1 and 2: populated, so the reload path still has rows to replace.
let boot = 0;
const bootCalls = [];
globalThis.fetch = (path) => {
  const url = path.split("?")[0];
  if (url === "/api/bootstrap") {
    bootCalls.push(path);
    return Promise.resolve({
      ok: true,
      json: async () => (boot === 0
        ? { targets: [] }
        : { targets: ["t"], summary, functions: boot === 1 ? firstPage : secondPage }),
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
// An empty database is the state a first run lands in: the page says so and
// offers the one control that can change it.
assert.equal(elements.get("no-targets").hidden, false);
assert.equal(document.getElementById("controls").hidden, true);

// Following that instruction (rebrew build-db, then Reload) must clear the
// "no targets" message.  Left up, it contradicts the rows now on screen.
boot = 1;
await elements.get("reload").onclick();
assert.equal(bootCalls.length, booted + 1);
assert.equal(elements.get("no-targets").hidden, true);
assert.equal(elements.get("controls").hidden, false);
assert.match(elements.get("rows").innerHTML, /first/);

// The database moved on (rebrew build-db in another terminal): Reload re-reads
// it without a browser reload, so the rows on screen follow.
boot = 2;
const pending = elements.get("reload").onclick();
assert.equal(elements.get("reload").textContent, "Reloading…");
assert.equal(elements.get("reload").disabled, true);
await pending;
assert.equal(bootCalls.length, booted + 2);
assert.match(elements.get("rows").innerHTML, /second/);
assert.equal(elements.get("reload").textContent, "Reload");
assert.equal(elements.get("reload").disabled, false);
