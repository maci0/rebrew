import assert from "node:assert/strict";

import { installDom, loadApp, stubElement } from "./dashboard_dom.mjs";

// The Clear control the empty state renders exists only while that message is
// on screen, and the re-render that answers its click destroys it.  The fake
// ``innerHTML`` setter reproduces the browser's focus fixup: focus moves to
// <body> when the focused element leaves the document.
const renderedChildren = { "empty-state": ["empty-clear-fn"], "globals-empty": ["empty-clear-gq"] };
installDom((id) => {
  const el = stubElement(id, { hidden: id !== "main" });
  el.click = () => { if (el.onclick) return el.onclick(); };
  const kids = renderedChildren[id];
  if (kids) {
    let html = "";
    Object.defineProperty(el, "innerHTML", {
      get() { return html; },
      set(value) {
        html = value;
        if (kids.includes(document.activeElement.id)) document.activeElement = document.body;
      },
    });
  }
  return el;
});
globalThis.location = { hash: "#target=a" };
globalThis.history = { replaceState() {}, pushState() {} };
const summary = { function_stats: { total: 150, by_status: { EXACT: 150 }, by_module_counts: {} } };
const row = (i) => ["0x" + i.toString(16), "f" + i, "", 1, "EXACT", "", ""];
globalThis.fetch = async (path) => {
  let payload = {};
  if (path === "/api/bootstrap") {
    payload = {
      targets: ["a"],
      summary,
      functions: { functions: Array.from({ length: 3 }, (_, i) => row(i)), count: 3, total: 3 },
    };
  } else if (path.startsWith("/api/summary")) {
    payload = summary;
  } else if (path.startsWith("/api/functions")) {
    payload = { functions: [], count: 0, total: 0 };
  }
  return { ok: true, json: async () => payload };
};

const { init, loadFunctions } = await loadApp(["init", "loadFunctions"]);
await init();
const el = (id) => document.getElementById(id);
assert.equal(el("rows").innerHTML !== "", true, "the first page rendered before the search");

el("q").value = "WinMain";
await loadFunctions();
await new Promise((resolve) => setTimeout(resolve, 0));
assert.match(el("empty-state").innerHTML, /No functions match this search/);
const clear = el("empty-clear-fn");
assert.ok(clear.onclick, "the message offers a Clear control");
clear.focus();
clear.onclick();
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(el("q").value, "", "the click cleared the search");
assert.equal(
  document.activeElement,
  el("q"),
  "focus lands on the search box the message tells the reader to use next, not on <body>"
);
