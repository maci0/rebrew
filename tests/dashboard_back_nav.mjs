import assert from "node:assert/strict";

import { installDom, loadApp, stubElement } from "./dashboard_dom.mjs";

const entries = [];
const body = { id: "body" };
const elements = installDom(
	(id) => {
		const el = stubElement(id, { hidden: true });
		// A real <select> takes the first option's value when its markup is
		// assigned; the stub does not, so seed it the way the browser would.
		if (id === "target") el.value = "a";
		return el;
	},
	{ body, activeElement: body },
);
globalThis.location = { hash: "" };
globalThis.history = {
	replaceState(_state, _title, url) {
		entries.push(["replace", url]);
	},
	pushState(_state, _title, url) {
		entries.push(["push", url]);
	},
};

const summary = {
	function_stats: {
		total: 1,
		by_status: { EXACT: 1 },
		by_module_counts: { GAME: 1 },
	},
};
let boots = 0;
globalThis.fetch = async (path) => {
	let body = {};
	if (path === "/api/bootstrap") {
		boots += 1;
		body = {
			targets: ["a", "b"],
			summary,
			functions: { functions: [], count: 0, total: 0 },
		};
	} else if (path.startsWith("/api/summary")) body = summary;
	else if (path.startsWith("/api/functions"))
		body = { functions: [], count: 0, total: 0 };
	else if (path.startsWith("/api/globals")) body = { globals: [], total: 0 };
	return { ok: true, json: async () => body };
};

const { setView } = await loadApp(["setView"]);
// The client boots itself at the end of the module; wait for that run.
for (let i = 0; i < 50 && elements.get("reload").hidden; i++) {
	await new Promise((resolve) => setTimeout(resolve, 0));
}

const el = (id) => elements.get(id);
assert.deepEqual(
	entries.filter(([kind]) => kind === "push"),
	[],
	"boot replaces the entry the reader arrived on instead of pushing a copy of it",
);
assert.equal(
	entries.at(-1)[1],
	"#target=a",
	"the restored state is written to the hash",
);

// Typing a query is not a navigation: it must not cost a Back press.
entries.length = 0;
el("q").value = "Win";
el("q").oninput();
await new Promise((resolve) => setTimeout(resolve, 400));
assert.equal(
	entries.filter(([kind]) => kind === "push").length,
	0,
	"a search pushes no history entry",
);
assert.match(entries.at(-1)[1], /q=Win/, "the search rides in the hash");

entries.length = 0;
setView("globals");
await new Promise((resolve) => setTimeout(resolve, 0));
assert.deepEqual(
	entries.filter(([kind]) => kind === "push"),
	[["push", "#target=a&view=globals&q=Win"]],
	"a view change pushes one entry",
);

// Back to the entry the reader came from restores that view.
globalThis.location.hash = "#target=a&q=Win";
globalThis.onpopstate();
for (let i = 0; i < 50 && el("view-functions").hidden; i++) {
	await new Promise((resolve) => setTimeout(resolve, 0));
}
assert.equal(
	el("view-functions").hidden,
	false,
	"Back returns to the Functions view",
);
assert.equal(el("view-globals").hidden, true, "the Globals view is left");
assert.deepEqual(
	entries.at(-1),
	["replace", "#target=a&q=Win"],
	"restoring replaces the entry Back moved to instead of stacking a copy of it",
);

// Back must also restore the filters, including removing a filter that was
// selected after the earlier history entry was written.
el("status").value = "EXACT";
el("module").value = "GAME";
globalThis.location.hash = "#target=a&q=Win";
const beforeBack = boots;
globalThis.onpopstate();
for (let i = 0; i < 50 && boots === beforeBack; i++) {
	await new Promise((resolve) => setTimeout(resolve, 0));
}
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(el("status").value, "", "Back clears a status absent from the restored hash");
assert.equal(el("module").value, "", "Back clears a module absent from the restored hash");
assert.equal(el("q").value, "Win", "Back keeps the restored search");

globalThis.location.hash = "#target=a&status=EXACT&module=GAME&q=Other";
globalThis.onpopstate();
for (let i = 0; i < 50 && el("q").value !== "Other"; i++) {
	await new Promise((resolve) => setTimeout(resolve, 0));
}
assert.equal(el("status").value, "EXACT", "Back restores the saved status");
assert.equal(el("module").value, "GAME", "Back restores the saved module");
assert.equal(el("q").value, "Other", "Back restores the saved search");
