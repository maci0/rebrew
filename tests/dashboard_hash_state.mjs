import assert from "node:assert/strict";

import { installStubDom, loadApp } from "./dashboard_dom.mjs";

const hashes = [];
installStubDom({
	hash: "#target=b&view=globals&status=EXACT&module=GAME&q=Win&gq=g_",
	hidden: true,
	history: {
		replaceState(_state, _title, url) {
			hashes.push(url);
		},
		pushState(_state, _title, url) {
			hashes.push(url);
		},
	},
});
const paths = [];
const summary = {
	function_stats: {
		total: 1,
		by_status: { EXACT: 1 },
		by_module_counts: { GAME: 1 },
	},
};
globalThis.fetch = async (path) => {
	paths.push(path);
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
	else if (path.startsWith("/api/globals")) body = { globals: [], total: 0 };
	return { ok: true, json: async () => body };
};

const { init, setView } = await loadApp(["init", "setView"]);
await init();
await new Promise((resolve) => setTimeout(resolve, 0));

const el = (id) => document.getElementById(id);
assert.equal(el("target").value, "b", "saved target is selected");
assert.equal(
	el("status").value,
	"EXACT",
	"saved status survives the summary load",
);
assert.equal(
	el("module").value,
	"GAME",
	"saved module survives the summary load",
);
assert.equal(el("view-globals").hidden, false, "saved view is shown");
assert.ok(
	paths.includes("/api/summary?target=b"),
	"bootstrap summary for target a is not reused",
);
const functions = paths.find((p) => p.startsWith("/api/functions"));
assert.match(functions, /target=b/);
assert.match(functions, /status=EXACT/);
assert.match(functions, /module=GAME/);
assert.match(functions, /q=Win/);
assert.ok(
	paths.some((p) => p.startsWith("/api/globals") && /q=g_/.test(p)),
	"globals load with saved search",
);
const last = new URLSearchParams(hashes.at(-1).slice(1));
assert.equal(last.get("target"), "b");
assert.equal(last.get("view"), "globals");
assert.equal(last.get("status"), "EXACT");
assert.equal(last.get("module"), "GAME");
assert.equal(last.get("q"), "Win");
assert.equal(last.get("gq"), "g_");

// Switching target on another tab must not leave the old target's functions.
el("target").value = "a";
el("target").onchange();
await new Promise((resolve) => setTimeout(resolve, 0));
paths.length = 0;
setView("functions");
await new Promise((resolve) => setTimeout(resolve, 0));
assert.ok(
	paths.some((p) => p.startsWith("/api/functions") && /target=a/.test(p)),
	"functions reload for the new target when the tab is shown",
);

// A link whose target was removed still opens the dashboard, but its filters
// belong to that missing target. Applying them to the fallback target would
// silently replace the intended result set with an unrelated empty one.
globalThis.location.hash =
	"#target=removed&view=globals&status=EXACT&module=GAME&q=Win&gq=g_";
el("target").value = "";
paths.length = 0;
hashes.length = 0;
await init();
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(
	el("target").value,
	"a",
	"a stale target falls back to the first target",
);
assert.equal(
	el("status").value,
	"",
	"stale status is not applied to the fallback target",
);
assert.equal(
	el("module").value,
	"",
	"stale module is not applied to the fallback target",
);
assert.equal(el("q").value, "", "stale function search is not applied");
assert.equal(el("gq").value, "", "stale globals search is not applied");
assert.equal(el("view-globals").hidden, false, "the saved view still opens");
assert.ok(
	paths.some((p) => p.startsWith("/api/globals") && !p.includes("q=")),
	"globals load without the stale target's search",
);
assert.ok(
	!paths.some(
		(p) => p.startsWith("/api/functions") && /status=|module=|q=/.test(p),
	),
	"no request carries the stale target's filters",
);
const fallback = new URLSearchParams(hashes.at(-1).slice(1));
assert.equal(fallback.get("target"), "a");
assert.equal(fallback.get("view"), "globals");
for (const key of ["status", "module", "q", "gq"]) {
	assert.equal(
		fallback.has(key),
		false,
		`${key} is removed from the stale link`,
	);
}
