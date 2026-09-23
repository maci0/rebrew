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
        classList: { toggle() {} },
        setAttribute(name, value) { this.attributes[name] = value; },
        querySelector() { return this; },
        querySelectorAll() { return []; },
        insertAdjacentHTML(position, html) { this.innerHTML += html; },
        focus() {},
      });
    }
    return elements.get(id);
  },
  querySelectorAll() { return []; },
};
// Non-first target without Status/Module: the bootstrap payload does not fit.
globalThis.location = { hash: "#target=b&view=globals&q=Win" };
globalThis.history = { replaceState() {} };
const summary = { function_stats: { total: 1, by_status: { EXACT: 1 }, by_module_counts: {} } };
const paths = [];
const held = [];
globalThis.fetch = (path) => {
  paths.push(path);
  let body = {};
  if (path === "/api/bootstrap") {
    body = { targets: ["a", "b"], summary, functions: { functions: [], count: 0, total: 0 } };
    return Promise.resolve({ ok: true, json: async () => body });
  }
  if (path.startsWith("/api/summary")) body = summary;
  else if (path.startsWith("/api/functions")) body = { functions: [], count: 0, total: 0 };
  else if (path.startsWith("/api/globals")) body = { globals: [], total: 0 };
  // Hold every follow-up response until all have been requested.
  return new Promise((resolve) => held.push(() => resolve({ ok: true, json: async () => body })));
};

const { init } = await import(
  "data:text/javascript;base64," + Buffer.from(source + "\nexport { init };\n").toString("base64")
);
const booted = init();
for (let i = 0; i < 5; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));

assert.ok(paths.includes("/api/summary?target=b"), "summary requested: " + paths);
assert.ok(
  paths.some((p) => p.startsWith("/api/functions") && /target=b/.test(p) && /q=Win/.test(p)),
  "functions requested while the summary is in flight: " + paths,
);
assert.ok(
  paths.some((p) => p.startsWith("/api/globals") && /target=b/.test(p)),
  "active view requested while the summary is in flight: " + paths,
);

held.forEach((release) => release());
await booted;
const el = (id) => document.getElementById(id);
assert.equal(el("status").disabled, false, "status select enabled after the summary renders");
assert.equal(el("view-globals").hidden, false, "saved view is shown");
