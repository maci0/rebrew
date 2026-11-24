import assert from "node:assert/strict";

import { installStubDom, loadApp } from "./dashboard_dom.mjs";

installStubDom({ hidden: false, title: "Rebrew coverage dashboard" });

const summary = {
	function_stats: {
		total: 600,
		by_status: { EXACT: 600 },
		by_module_counts: { game: 600 },
	},
	coverage_pct: 100,
	identified_pct: 100,
};
const firstPage = {
	count: 1,
	total: 600,
	functions: [["0x00401000", "first", "first", 16, "EXACT", "game", "game/foo.c"]],
};
const appendPage = {
	count: 1,
	total: 600,
	functions: [["0x00401010", "stale", "stale", 16, "EXACT", "game", "game/foo.c"]],
};

let bootCalls = 0;
let resolveAppend = null;
let appendStarted = false;
globalThis.fetch = async (path) => {
	const url = new URL(path, "http://127.0.0.1:8000");
	if (url.pathname === "/api/bootstrap") {
		bootCalls += 1;
		return { ok: true, json: async () => ({ targets: ["t"], summary, functions: firstPage }) };
	}
	if (url.pathname === "/api/functions" && url.searchParams.get("offset") === "1") {
		appendStarted = true;
		return new Promise((resolve) => {
			resolveAppend = resolve;
		});
	}
	return { ok: true, json: async () => ({ count: 0, total: 0 }) };
};

const until = async (predicate) => {
	for (let i = 0; i < 100 && !predicate(); i++) {
		await new Promise((resolve) => setTimeout(resolve, 0));
	}
	assert.ok(predicate(), "the dashboard reached the expected state");
};

// A real <select> takes the first option's value when its markup is assigned;
// the stub does not, so seed it the way the browser would.
document.getElementById("target").value = "t";

await loadApp([]);
const el = (id) => document.getElementById(id);
await until(() => el("rows").innerHTML.includes("first") && typeof el("reload").onclick === "function");
assert.equal(bootCalls, 1, "the initial bootstrap completed");

const append = el("show-more").onclick();
await until(() => appendStarted);
assert.equal(typeof resolveAppend, "function", "the append request is in flight");

// Reload must not wait for the old page: its bootstrap already carries the
// first page.  When that old request finishes, it must not extend the new page.
await el("reload").onclick();
assert.equal(bootCalls, 2, "reload fetched a fresh bootstrap");
assert.match(el("rows").innerHTML, /first/, "the fresh first page is visible");

resolveAppend({ ok: true, json: async () => appendPage });
await append;
await Promise.resolve();

assert.doesNotMatch(el("rows").innerHTML, /stale/, "the pre-reload append is discarded");
assert.match(el("rows").innerHTML, /first/, "the fresh first page stays intact");
