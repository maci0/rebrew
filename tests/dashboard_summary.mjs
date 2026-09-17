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
        insertAdjacentHTML(position, html) { this.innerHTML += html; },
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
const { loadSummary, bindControls } = await import(
  "data:text/javascript;base64," + Buffer.from(source + "\nexport { loadSummary, bindControls };\n").toString("base64")
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
  assert.equal(element("status").disabled, true);
  assert.doesNotMatch(element("status").innerHTML, /EXACT|STUB/);
  assert.match(element("cards").innerHTML, /Loading coverage summary/);
  assert.doesNotMatch(element("cards").innerHTML, /data-status/);
  assert.match(oldResponse.path, /target=old_target$/);
  assert.match(newResponse.path, /target=new_target$/);
  assert.equal(newResponse.aborted, false);
  newResponse.resolve({ ok: true, json: async () => summary("EXACT") });
  await newRequest;
  assert.match(element("status").innerHTML, /EXACT/);
  assert.equal(element("status").disabled, false);
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

const failedRequest = loadSummary();
pending.shift().reject(new Error("Connection lost"));
await failedRequest;
assert.equal(element("summary").hidden, true);
assert.equal(element("cards").innerHTML, "");
assert.equal(element("status").disabled, true);
assert.equal(element("dashboard-error").hidden, false);
assert.match(element("dashboard-error").textContent, /Reload the page/);

const recoveredRequest = loadSummary();
pending.shift().resolve({ ok: true, json: async () => summary("STUB") });
await recoveredRequest;
assert.equal(element("summary").hidden, false);
assert.equal(element("status").disabled, false);
assert.match(element("cards").innerHTML, /STUB/);
assert.equal(element("dashboard-error").hidden, true);

bindControls();
element("target").value = "tgt";
element("status").value = "STUB";
element("q").value = "  win ";
element("show-more").onclick();
const failed = pending.shift();
assert.match(failed.path, /target=tgt/);
assert.match(failed.path, /status=STUB/);
assert.match(failed.path, /limit=500&offset=0/);
assert.match(failed.path, /q=win/);
failed.reject(new Error("Connection lost"));
await new Promise(resolve => setImmediate(resolve));
assert.equal(element("results").hidden, true);
assert.equal(element("empty-state").hidden, true);
assert.equal(element("show-more-wrap").hidden, true);
assert.equal(element("dashboard-error").hidden, false);
assert.match(element("dashboard-error").textContent, /Retry functions/);
assert.equal(element("retry-functions").hidden, false);

const retried = element("retry-functions").onclick();
const retryResponse = pending.shift();
assert.equal(retryResponse.path, failed.path);
assert.equal(element("retry-functions").hidden, true);
retryResponse.resolve({
  ok: true,
  json: async () => ({ count: 1, total: 1, functions: [{ va: "0x1", name: "win" }] }),
});
await retried;
assert.equal(element("dashboard-error").hidden, true);
assert.equal(element("results").hidden, false);
assert.match(element("rows").innerHTML, /0x1/);
assert.equal(element("retry-functions").hidden, true);
assert.equal(element("target").value, "tgt");
assert.equal(element("status").value, "STUB");
assert.equal(element("q").value, "  win ");

const rowsBeforeFailure = element("rows").innerHTML;
element("show-more").onclick();
const failedGrow = pending.shift();
assert.match(failedGrow.path, /limit=500&offset=1/);
failedGrow.reject(new Error("Connection lost"));
await new Promise(resolve => setImmediate(resolve));
assert.equal(element("rows").innerHTML, rowsBeforeFailure);
assert.equal(element("results").hidden, false);
assert.equal(element("empty-state").hidden, true);
assert.equal(element("dashboard-error").hidden, false);
assert.match(element("dashboard-error").textContent, /next page/);
assert.equal(element("retry-functions").hidden, false);

const retriedGrow = element("retry-functions").onclick();
const retryGrowResponse = pending.shift();
assert.equal(retryGrowResponse.path, failedGrow.path);
retryGrowResponse.resolve({
  ok: true,
  json: async () => ({ count: 1, total: 2, functions: [{ va: "0x2", name: "lose" }] }),
});
await retriedGrow;
assert.equal(element("dashboard-error").hidden, true);
const grownRows = element("rows").innerHTML;
assert.match(grownRows, /0x1/);
assert.match(grownRows, /0x2/);
assert.match(grownRows, /win/);
assert.match(grownRows, /lose/);

element("show-more").onclick();
const appended = pending.shift();
assert.match(appended.path, /limit=500&offset=2/);
appended.resolve({
  ok: true,
  json: async () => ({
    count: 1,
    total: 3,
    functions: [{ va: "0x3", name: "third" }],
  }),
});
await new Promise(resolve => setImmediate(resolve));
const rows = element("rows").innerHTML;
assert.match(rows, /0x1/);
assert.match(rows, /0x2/);
assert.match(rows, /win/);
assert.match(rows, /lose/);
assert.equal(pending.length, 0);
