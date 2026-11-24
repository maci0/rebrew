import assert from "node:assert/strict";

import { installStubDom, loadApp } from "./dashboard_dom.mjs";

// Functions loads while Globals is the active tab. Its empty state must describe
// the restored function filters, not whichever filters belong to the visible tab.
installStubDom({ hash: "#target=b&view=globals&q=Win" });
const summary = {
	function_stats: {
		total: 1,
		by_status: { EXACT: 1 },
		by_module_counts: { game: 1 },
	},
};
globalThis.fetch = async (path) => {
	let body = {};
	if (path === "/api/bootstrap") {
		body = {
			targets: ["a", "b"],
			summary,
			functions: { functions: [], count: 0, total: 0 },
		};
	} else if (path.startsWith("/api/summary")) body = summary;
	else if (path.startsWith("/api/functions"))
		body = { functions: [], count: 0, total: 0 };
	else if (path.startsWith("/api/globals"))
		body = { globals: [], count: 0, total: 0 };
	return { ok: true, json: async () => body };
};

const { init, setView } = await loadApp(["init", "setView"]);
await init();
const el = (id) => document.getElementById(id);
assert.equal(el("view-globals").hidden, false, "the saved tab is active");
assert.match(
	el("empty-state").innerHTML,
	/No functions match this search/,
	"the hidden Functions empty state names its own search",
);
assert.doesNotMatch(
	el("empty-state").innerHTML,
	/No functions recorded/,
	"a filtered empty result is not reported as an empty target",
);
setView("functions");
assert.equal(el("view-functions").hidden, false);
assert.match(el("empty-state").innerHTML, /No functions match this search/);
