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
globalThis.fetch = async () => ({
  ok: false,
  status: 500,
  json: async () => ({ error: "database error" }),
});

const { formatWhen } = await import(
  "data:text/javascript;base64," + Buffer.from(source + "\nexport { formatWhen };\n").toString("base64")
);

assert.equal(
  Intl.DateTimeFormat().resolvedOptions().timeZone,
  "America/New_York",
  "the fall-back assertions need the America/New_York zone",
);

// Zone-less forms are UTC instants, same as an explicit Z.  A space or a
// lowercase "t" is still local to Date.parse unless a Z is appended.
assert.equal(formatWhen("2026-09-26T15:04:05"), formatWhen("2026-09-26T15:04:05Z"));
assert.equal(formatWhen("2026-09-26 15:04:05"), formatWhen("2026-09-26T15:04:05Z"));
assert.equal(formatWhen("2026-09-26t15:04:05"), formatWhen("2026-09-26T15:04:05Z"));

// Spring-forward gap: 02:30 does not exist in New York.  Parsed as local it
// lands on 03:30 EDT (07:30Z).  The stored reading is 02:30 UTC.
assert.equal(formatWhen("2026-03-08T02:30:00"), formatWhen("2026-03-08T02:30:00Z"));
assert.notEqual(formatWhen("2026-03-08T02:30:00"), formatWhen("2026-03-08T07:30:00Z"));
assert.equal(formatWhen("2026-03-08 02:30:00"), formatWhen("2026-03-08T02:30:00Z"));

// An offset that is already present is kept.  +02:00 is not rewritten as UTC.
assert.equal(formatWhen("2026-09-26T15:04:05+00:00"), formatWhen("2026-09-26T15:04:05Z"));
assert.equal(formatWhen("2026-09-26T17:04:05+02:00"), formatWhen("2026-09-26T15:04:05Z"));

// Fall-back: 05:30Z and 06:30Z are both 1:30 AM locally, an hour apart.
const wall = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
  timeZone: "America/New_York",
});
const first = Date.parse("2026-11-01T05:30:00Z");
const second = Date.parse("2026-11-01T06:30:00Z");
assert.equal(wall.format(first), wall.format(second), "the wall clock repeats");
assert.notEqual(formatWhen("2026-11-01T05:30:00Z"), formatWhen("2026-11-01T06:30:00+00:00"));
assert.notEqual(formatWhen("2026-11-01T05:30:00Z"), formatWhen("2026-11-01T06:30:00Z"));

assert.equal(formatWhen(""), "");
assert.equal(formatWhen("not-a-date"), "not-a-date");
