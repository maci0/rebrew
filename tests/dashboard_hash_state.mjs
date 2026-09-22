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
globalThis.location = { hash: "#target=b&view=globals&status=EXACT&module=GAME&q=Win&gq=g_" };
const hashes = [];
globalThis.history = { replaceState(state, title, url) { hashes.push(url); } };
const paths = [];
const summary = { function_stats: { total: 1, by_status: { EXACT: 1 }, by_module_counts: { GAME: 1 } } };
globalThis.fetch = async (path) => {
  paths.push(path);
  let body = {};
  if (path === "/api/bootstrap") {
    body = { targets: ["a", "b"], summary, functions: { functions: [], count: 0, total: 0 } };
  } else if (path.startsWith("/api/summary")) body = summary;
  else if (path.startsWith("/api/functions")) body = { functions: [], count: 0, total: 0 };
  else if (path.startsWith("/api/globals")) body = { globals: [], total: 0 };
  return { ok: true, json: async () => body };
};

const { init, setView } = await import(
  "data:text/javascript;base64," + Buffer.from(source + "\nexport { init, setView };\n").toString("base64")
);
await init();
await new Promise((resolve) => setTimeout(resolve, 0));

const el = (id) => document.getElementById(id);
assert.equal(el("target").value, "b", "saved target is selected");
assert.equal(el("status").value, "EXACT", "saved status survives the summary load");
assert.equal(el("module").value, "GAME", "saved module survives the summary load");
assert.equal(el("view-globals").hidden, false, "saved view is shown");
assert.ok(paths.includes("/api/summary?target=b"), "bootstrap summary for target a is not reused");
const functions = paths.find((p) => p.startsWith("/api/functions"));
assert.match(functions, /target=b/);
assert.match(functions, /status=EXACT/);
assert.match(functions, /module=GAME/);
assert.match(functions, /q=Win/);
assert.ok(paths.some((p) => p.startsWith("/api/globals") && /q=g_/.test(p)), "globals load with saved search");
const last = new URLSearchParams(hashes.at(-1).slice(1));
assert.equal(last.get("target"), "b");
assert.equal(last.get("view"), "globals");
assert.equal(last.get("status"), "EXACT");
assert.equal(last.get("module"), "GAME");
assert.equal(last.get("q"), "Win");
assert.equal(last.get("gq"), "g_");

// Switching target on another tab must not leave the old target's functions.
el("target").value = "a";
el("target").onchange();
await new Promise((resolve) => setTimeout(resolve, 0));
paths.length = 0;
setView("functions");
await new Promise((resolve) => setTimeout(resolve, 0));
assert.ok(
  paths.some((p) => p.startsWith("/api/functions") && /target=a/.test(p)),
  "functions reload for the new target when the tab is shown",
);
