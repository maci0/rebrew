import assert from "node:assert/strict";

import { installDom, loadApp, stubElement } from "./dashboard_dom.mjs";

// Focus lands on <body> the way the browser drops it when the focused
// control is destroyed, which is what a Back navigation does: the hash is
// restored and every view is rebuilt from it.
const body = { id: "body" };
const elements = installDom((id) => stubElement(id, { hidden: id !== "main" }), {
  body,
  activeElement: body,
});
globalThis.location = { hash: "" };
globalThis.history = { replaceState() {}, pushState() {} };

const summary = {
  function_stats: { total: 1, by_status: { EXACT: 1 }, by_module_counts: { GAME: 1 } },
};
globalThis.fetch = async (path) => {
  let payload = {};
  if (path === "/api/bootstrap") {
    payload = { targets: ["a"], summary, functions: { functions: [], count: 0, total: 0 } };
  } else if (path.startsWith("/api/summary")) payload = summary;
  else if (path.startsWith("/api/functions")) payload = { functions: [], count: 0, total: 0 };
  return { ok: true, json: async () => payload };
};

await loadApp([]);
// The client boots itself at the end of the module; wait for that run.
for (let i = 0; i < 50 && elements.get("reload").hidden; i++) {
  await new Promise((resolve) => setTimeout(resolve, 0));
}
assert.equal(document.activeElement.id, "body", "boot leaves focus where the browser put it");

// Back rebuilds the views, so the control the reader was on is gone.
globalThis.onpopstate();
for (let i = 0; i < 50 && document.activeElement === body; i++) {
  await new Promise((resolve) => setTimeout(resolve, 0));
}
assert.equal(
  document.activeElement.id,
  "main",
  "a navigation that drops focus leaves the reader on the content, not on <body>",
);
