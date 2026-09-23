import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = readFileSync(0, "utf8");
const elements = new Map();
const body = { id: "body" };
globalThis.document = {
  body,
  activeElement: body,
  getElementById(id) {
    if (!elements.has(id)) {
      elements.set(id, {
        id,
        value: "",
        innerHTML: "",
        textContent: "",
        hidden: id !== "main",
        disabled: false,
        setAttribute() {},
        closest() { return null; },
        focus() { document.activeElement = this; },
      });
    }
    return elements.get(id);
  },
  querySelectorAll() { return []; },
};
globalThis.location = { hash: "" };
globalThis.history = { replaceState() {} };
let respond = async () => ({
  ok: false,
  status: 500,
  json: async () => ({ error: "database error" }),
});
globalThis.fetch = (path) => respond(path);

const { start } = await import(
  "data:text/javascript;base64," + Buffer.from(source + "\nexport { start };\n").toString("base64")
);
await start();
await start();  // the module already ran start() once on import; this awaits a fresh run

const el = (id) => document.getElementById(id);
assert.equal(el("dashboard-error").hidden, false, "boot failure is shown");
assert.match(
  el("dashboard-error").textContent,
  /Dashboard failed to load \(server returned 500, database error\)\. Use Reload dashboard/,
  "the server's error reason reaches the user",
);

respond = async () => { throw new TypeError("Failed to fetch"); };
await el("retry-summary").onclick();
assert.match(
  el("dashboard-error").textContent,
  /\(the dashboard server did not respond; check that rebrew dashboard is still running\)/,
  "a dead server is named instead of a raw fetch error",
);
