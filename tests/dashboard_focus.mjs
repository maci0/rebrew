import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = readFileSync(0, "utf8");
const elements = new Map();
const parents = { "show-more": "show-more-wrap" };
const body = { id: "body" };
const isWithin = (el, ancestor) => {
  for (let node = el; node; node = node.parent) if (node === ancestor) return true;
  return false;
};
globalThis.document = {
  body,
  activeElement: body,
  getElementById(id) {
    if (!elements.has(id)) {
      let hidden = id !== "main";
      const el = {
        id,
        value: "",
        innerHTML: "",
        textContent: "",
        disabled: false,
        attributes: {},
        classList: { toggle() {} },
        get parent() { return parents[id] ? document.getElementById(parents[id]) : null; },
        get hidden() { return hidden; },
        // Browser focus fixup: hiding the focused element or an ancestor
        // moves focus to <body>.
        set hidden(value) {
          hidden = value;
          if (value && isWithin(document.activeElement, el)) document.activeElement = body;
        },
        setAttribute(name, value) { this.attributes[name] = value; },
        querySelector() { return this; },
        querySelectorAll() { return []; },
        insertAdjacentHTML(position, html) { this.innerHTML += html; },
        closest(selector) {
          assert.equal(selector, "[hidden]");
          for (let node = this; node; node = node.parent) if (node.hidden) return node;
          return null;
        },
        focus() { document.activeElement = this; },
      };
      elements.set(id, el);
    }
    return elements.get(id);
  },
  querySelectorAll() { return []; },
};
globalThis.location = { hash: "#target=a" };
globalThis.history = { replaceState() {} };
const row = (i) => ["0x" + i.toString(16), "f" + i, "", 1, "EXACT", "", ""];
const page = (n) => Array.from({ length: n }, (_, i) => row(i));
const summary = { function_stats: { total: 150, by_status: { EXACT: 150 }, by_module_counts: {} } };
let releaseMore;
globalThis.fetch = async (path) => {
  let payload = {};
  if (path === "/api/bootstrap") {
    payload = { targets: ["a"], summary, functions: { functions: page(100), count: 100, total: 150 } };
  } else if (path.startsWith("/api/functions")) {
    await new Promise((resolve) => { releaseMore = resolve; });
    payload = { functions: page(50), count: 50, total: 150 };
  }
  return { ok: true, json: async () => payload };
};

const { init } = await import(
  "data:text/javascript;base64," + Buffer.from(source + "\nexport { init };\n").toString("base64")
);
await init();
await new Promise((resolve) => setTimeout(resolve, 0));

const el = (id) => document.getElementById(id);
assert.equal(el("show-more-wrap").hidden, false, "Show more is offered for a partial page");
el("show-more").focus();
const click = el("show-more").onclick();
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(el("show-more-wrap").hidden, false, "Show more stays mounted while the next page loads");
assert.equal(document.activeElement, el("show-more"), "focus stays on Show more during the load");
releaseMore();
await click;
assert.equal(el("show-more-wrap").hidden, true, "Show more is gone once every row is loaded");
assert.equal(document.activeElement, el("results"), "focus lands on the results table, not <body>");
