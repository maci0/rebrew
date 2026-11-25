import assert from "node:assert/strict";

import { installStubDom, loadApp } from "./dashboard_dom.mjs";

installStubDom({ hidden: false, title: "Rebrew coverage dashboard" });

const summary = {
	function_stats: {
		total: 1,
		by_status: { EXACT: 1 },
		by_module_counts: { game: 1 },
	},
	coverage_pct: 100,
	identified_pct: 100,
};
const functionPage = (name) => ({
	count: 1,
	total: 1,
	functions: [["0x00401000", name, name, 16, "EXACT", "game", "game/foo.c"]],
});
const globalsPage = {
	count: 1,
	total: 1,
	globals: [["0x00403000", "g_flag", "int g_flag", 4, "game"]],
};
const searchedGlobalsPage = {
	count: 1,
	total: 1,
	globals: [["0x00403000", "g_searched", "int g_searched", 4, "game"]],
};
const historyPage = {
	count: 1,
	total: 1,
	history: [["0x00401000", "WinMain", "STUB", "EXACT", "2026-01-02T03:04:05Z"]],
};

const requested = [];
let holdGlobals = false;
let releaseGlobals = null;
globalThis.fetch = async (path) => {
	const url = new URL(path, "http://127.0.0.1:8000");
	requested.push(url.pathname);
	if (url.pathname === "/api/globals" && holdGlobals) {
		return new Promise((resolve) => {
			releaseGlobals = resolve;
		});
	}
	const body =
		url.pathname === "/api/bootstrap"
			? { targets: ["a.exe"], summary, functions: functionPage("WinMain") }
			: url.pathname === "/api/summary"
				? summary
				: url.pathname === "/api/functions"
					? functionPage("Searched")
					: url.pathname === "/api/globals"
						? url.searchParams.has("q")
							? searchedGlobalsPage
							: globalsPage
						: url.pathname === "/api/history"
							? historyPage
							: {};
	return { ok: true, json: async () => body };
};

// A real <select> takes the first option's value when its markup is assigned;
// the stub does not, so seed it the way the browser would.
document.getElementById("target").value = "a.exe";

const { start, setView } = await loadApp(["start", "setView"]);
await start();

const el = (id) => document.getElementById(id);
assert.match(el("rows").innerHTML, /WinMain/, "the boot page renders its rows");

// Type into the Functions search, then switch views inside the 200 ms debounce
// window. The pending debounce belongs to the view that scheduled it: firing it
// after the switch spends a query and a full table render on a view the reader
// has already left.
el("q").value = "Win";
el("q").oninput();
setView("globals");
await new Promise((resolve) => setTimeout(resolve, 400));

assert.match(
	el("globals-rows").innerHTML,
	/g_flag/,
	"the switched-to view renders its rows",
);
assert.equal(
	requested.filter((path) => path === "/api/globals").length,
	1,
	"the globals view was fetched once",
);
assert.equal(
	requested.filter((path) => path === "/api/functions").length,
	0,
	"the Functions view was not queried behind the reader's back",
);

// Returning to a view whose search was canceled must apply the text still in
// its box. Reusing the cached unfiltered rows would claim a search that never
// ran.
setView("functions");
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(
	requested.filter((path) => path === "/api/functions").length,
	1,
	"Functions reloads when the reader returns to its pending search",
);
assert.match(el("rows").innerHTML, /Searched/);
assert.match(el("q").value, /Win/);

// Globals owns the other debounced search and follows the same rule.
el("gq").value = "g_";
el("gq").oninput();
setView("functions");
await new Promise((resolve) => setTimeout(resolve, 400));
assert.equal(
	requested.filter((path) => path === "/api/globals").length,
	1,
	"the Globals search was not queried behind the reader's back",
);
setView("globals");
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(
	requested.filter((path) => path === "/api/globals").length,
	2,
	"Globals reloads when the reader returns to its pending search",
);
assert.match(el("globals-rows").innerHTML, /g_searched/);
assert.equal(el("gq").value, "g_");

// A failed request for Globals must not blank or report an error over cached
// History after the reader has already switched away from Globals.
setView("history");
await new Promise((resolve) => setTimeout(resolve, 0));
assert.match(el("history-rows").innerHTML, /WinMain/);
holdGlobals = true;
setView("globals");
el("gq").value = "g_flag";
el("gq").onkeydown({ key: "Enter" });
assert.equal(
	typeof releaseGlobals,
	"function",
	"the Globals request is in flight",
);
setView("history");
releaseGlobals({
	ok: false,
	status: 500,
	json: async () => ({ error: "database error" }),
});
await new Promise((resolve) => setImmediate(resolve));
holdGlobals = false;
assert.equal(
	el("dashboard-error").hidden,
	true,
	"the abandoned failure is not shown",
);
assert.equal(
	el("retry-view").hidden,
	true,
	"History offers no unrelated retry",
);
assert.equal(
	el("history-results").hidden,
	false,
	"History keeps its loaded rows",
);
assert.match(el("history-rows").innerHTML, /WinMain/);
