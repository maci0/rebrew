import assert from "node:assert/strict";

import { installStubDom, loadApp } from "./dashboard_dom.mjs";

installStubDom();
let respond = async () => ({
  ok: false,
  status: 500,
  json: async () => ({ error: "database error" }),
});
globalThis.fetch = (path) => respond(path);

const { start } = await loadApp(["start"]);
await start();
await start();  // the module already ran start() once on import; this awaits a fresh run

const el = (id) => document.getElementById(id);
assert.equal(el("dashboard-error").hidden, false, "boot failure is shown");
assert.match(
  el("dashboard-error").textContent,
  /Dashboard failed to load \(server returned 500, database error\)\. Use Reload dashboard/,
  "the server's error reason reaches the user",
);
// The alert sits above the tables, so a repeat of the same failure must not
// yank the reader away from wherever they are; a new one must reach them.
assert.equal(el("dashboard-error").scrolled, 1, "the first alert scrolls itself into view");

respond = async () => { throw new TypeError("Failed to fetch"); };
await el("retry-summary").onclick();
assert.match(
  el("dashboard-error").textContent,
  /\(the dashboard server did not respond; check that rebrew dashboard is still running\)/,
  "a dead server is named instead of a raw fetch error",
);
assert.equal(el("dashboard-error").scrolled, 2, "a different alert scrolls itself into view");
