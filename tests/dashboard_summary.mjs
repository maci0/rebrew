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
        setAttribute(name, value) { this.attributes[name] = value; },
        querySelector() { return this; },
      });
    }
    return elements.get(id);
  },
};
const pending = [];
globalThis.fetch = (path, options) => {
  if (path === "/api/bootstrap") return Promise.resolve({ ok: true, json: async () => ({ targets: [] }) });
  const signal = options && options.signal;
  const entry = { path, get aborted() { return signal ? signal.aborted : false; } };
  pending.push(entry);
  return new Promise((resolve, reject) => {
    entry.resolve = resolve;
    entry.reject = reject;
  });
};
globalThis.AbortController = class {
  constructor() { this.signal = { aborted: false }; }
  abort() {
    this.signal.aborted = true;
    this.aborted = true;
  }
};
const { loadSummary } = await import(
  "data:text/javascript;base64," + Buffer.from(source + "\nexport { loadSummary };\n").toString("base64")
);
const element = (id) => document.getElementById(id);
const summary = (status) => ({
  function_stats: { total: 1, by_status: { [status]: 1 } },
  coverage_pct: 50,
  identified_pct: 100,
});

for (const staleFailure of [false, true]) {
  element("target").value = "old_target";
  const oldRequest = loadSummary();
  const oldResponse = pending.shift();
  assert.equal(oldResponse.aborted, false);
  element("target").value = "new_target";
  const newRequest = loadSummary();
  assert.equal(oldResponse.aborted, true, "superseded request must be aborted");
  const newResponse = pending.shift();
  assert.match(oldResponse.path, /target=old_target$/);
  assert.match(newResponse.path, /target=new_target$/);
  assert.equal(newResponse.aborted, false);
  newResponse.resolve({ ok: true, json: async () => summary("EXACT") });
  await newRequest;
  assert.match(element("status").innerHTML, /EXACT/);
  assert.match(element("cards").innerHTML, /EXACT/);
  const options = element("status").innerHTML;
  const cards = element("cards").innerHTML;
  if (staleFailure) oldResponse.reject(new Error("Old target failed"));
  else oldResponse.resolve({ ok: true, json: async () => summary("STUB") });
  await oldRequest;
  assert.equal(element("status").innerHTML, options);
  assert.equal(element("cards").innerHTML, cards);
  assert.equal(element("dashboard-error").hidden, true);
}
