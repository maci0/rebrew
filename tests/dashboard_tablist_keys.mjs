import assert from "node:assert/strict";

import { installDom, loadApp, stubElement } from "./dashboard_dom.mjs";

const VIEWS = ["functions", "sections", "globals", "history"];
const body = { id: "body" };
const elements = new Map();

const tabButton = (view) => {
  const el = stubElement("tab-" + view);
  el.tabIndex = 0;
  el.attributes["data-view"] = view;
  el.getAttribute = (name) => el.attributes[name];
  el.closest = (selector) => (selector === "button[data-view]" ? el : null);
  return el;
};
const tabs = VIEWS.map(tabButton);
const views = stubElement("views");
views.hidden = false;
views.contains = (node) => tabs.includes(node);
views.querySelectorAll = () => tabs;

globalThis.document = {
  getElementById(id) {
    if (id === "views") return views;
    if (!elements.has(id)) elements.set(id, stubElement(id, { hidden: false }));
    return elements.get(id);
  },
  querySelectorAll(selector) {
    return selector === "#views button[data-view]" ? tabs : [];
  },
  body,
  activeElement: body,
};
globalThis.location = { hash: "" };
globalThis.history = { replaceState() {}, pushState() {} };

globalThis.fetch = async (path) => {
  const url = new URL(path, "http://127.0.0.1:8000");
  const body = url.pathname === "/api/bootstrap"
    ? { targets: ["a.exe"], summary: summary(), functions: functionsPage() }
    : url.pathname === "/api/summary" ? summary()
    : url.pathname === "/api/functions" ? functionsPage()
    : {};
  return { ok: true, json: async () => body };
};
function summary() {
  return {
    function_stats: { total: 1, by_status: { EXACT: 1 }, by_module_counts: { game: 1 } },
    coverage_pct: 100,
    identified_pct: 100,
  };
}
function functionsPage() {
  return {
    count: 1,
    total: 1,
    functions: [["0x00401000", "WinMain", "WinMain", 16, "EXACT", "game", "game/foo.c"]],
  };
}

const { start } = await loadApp(["start"]);
await start();
document.getElementById("target").value = "a.exe";

const press = (tab, key) => {
  let prevented = false;
  views.onkeydown({ key, target: tab, preventDefault() { prevented = true; } });
  return prevented;
};
const active = () => document.activeElement.id.replace("tab-", "");

assert.equal(active(), "body", "focus starts outside the tablist");

// Arrow keys move focus and switch the view in one step (WCAG 2.1.1, 2.4.3).
let current = "functions";
for (const [key, expected] of [
  ["ArrowRight", "sections"],
  ["ArrowDown", "globals"],
  ["ArrowRight", "history"],
  ["ArrowRight", "functions"],  // wraps to the first tab
  ["ArrowLeft", "history"],     // and back the other way
  ["ArrowUp", "globals"],
  ["Home", "functions"],
  ["End", "history"],
]) {
  assert.ok(press(tabs[VIEWS.indexOf(current)], key), `${key} is handled`);
  assert.equal(active(), expected, `${key} moves focus to ${expected}`);
  assert.equal(tabs[VIEWS.indexOf(expected)].attributes["aria-selected"], "true", expected);
  assert.equal(tabs[VIEWS.indexOf(expected)].tabIndex, 0, "the selected tab is the one tab stop");
  current = expected;
}

// Roving tabindex: exactly one tab is in the tab order at a time.
press(tabs[3], "Home");
assert.deepEqual(tabs.map((t) => t.tabIndex), [0, -1, -1, -1]);
assert.deepEqual(tabs.map((t) => t.attributes["aria-selected"]), ["true", "false", "false", "false"]);

// A key the widget does not own is left to the browser.
current = "functions";
assert.equal(press(tabs[VIEWS.indexOf(current)], "a"), false, "an unbound key is not swallowed");
assert.equal(press(tabs[VIEWS.indexOf(current)], "Enter"), false, "Enter stays the button's own");
assert.equal(active(), "functions", "an unbound key does not move focus");

console.log("dashboard tablist keyboard: ok");
