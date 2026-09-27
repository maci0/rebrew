import { readFileSync } from "node:fs";

/** Load the dashboard JS (piped to stdin) and export *names* from it. */
export async function loadApp(names) {
  const source = readFileSync(0, "utf8");
  const module = source + "\nexport { " + names.join(", ") + " };\n";
  return import("data:text/javascript;base64," + Buffer.from(module).toString("base64"));
}

/** Install a global `document` whose getElementById mints each element from *make*. */
export function installDom(make, extras = {}) {
  const elements = new Map();
  globalThis.document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, make(id));
      return elements.get(id);
    },
    querySelectorAll() { return []; },
    ...extras,
  };
  return elements;
}
