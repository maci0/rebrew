import assert from "node:assert/strict";

import { installStubDom, loadApp } from "./dashboard_dom.mjs";

// A saved filter cannot be applied until its Status and Module options exist.
// If that summary load fails, retrying it must reload Functions with the saved
// filters instead of leaving the unfiltered fallback rows under restored controls.
installStubDom({ hash: "#target=b&status=EXACT&module=GAME&q=Win", hidden: false });
const summary = {
	function_stats: {
		total: 1,
		by_status: { EXACT: 1 },
		by_module_counts: { GAME: 1 },
	},
};
let failSummary = true;
const functionRequests = [];
globalThis.fetch = async (path) => {
	const url = new URL(path, "http://127.0.0.1:8000");
	let body;
	if (url.pathname === "/api/bootstrap") {
		body = { targets: ["a", "b"] };
	} else if (url.pathname === "/api/summary") {
		if (failSummary) {
			return {
				ok: false,
				status: 500,
				json: async () => ({ error: "database error" }),
			};
		}
		body = summary;
	} else if (url.pathname === "/api/functions") {
		functionRequests.push(url);
		body = {
			count: 1,
			total: 1,
			functions: [["0x10", "WinMain", "WinMain", 16, "EXACT", "GAME", "main.c"]],
		};
	} else {
		body = {};
	}
	return { ok: true, json: async () => body };
};

await loadApp([]);
const el = (id) => document.getElementById(id);
for (let i = 0; i < 50 && (functionRequests.length < 1 || el("dashboard-error").hidden); i++) {
	await new Promise((resolve) => setTimeout(resolve, 0));
}
assert.equal(functionRequests.length, 1, "the fallback Functions page loaded");
assert.doesNotMatch(functionRequests[0].search, /status=/, "the unavailable status was not applied");
assert.doesNotMatch(functionRequests[0].search, /module=/, "the unavailable module was not applied");
assert.match(el("dashboard-error").textContent, /Retry summary/);

failSummary = false;
await el("retry-summary").onclick();
assert.equal(el("status").value, "EXACT", "the retry restores the saved status");
assert.equal(el("module").value, "GAME", "the retry restores the saved module");
assert.equal(functionRequests.length, 2, "the retry reloads Functions with the restored filters");
assert.match(functionRequests[1].search, /status=EXACT/);
assert.match(functionRequests[1].search, /module=GAME/);
assert.match(functionRequests[1].search, /q=Win/);
