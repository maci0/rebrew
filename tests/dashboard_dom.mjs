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

/** An inert element stub: the members the dashboard reads, with no real DOM behind them. */
export function stubElement(id, { hidden = id !== "main" } = {}) {
  return {
    id,
    value: "",
    innerHTML: "",
    textContent: "",
    hidden,
    disabled: false,
    setAttribute(name, value) { this.attributes[name] = value; },
    attributes: {},
    classList: { toggle() {} },
    insertAdjacentHTML(_where, html) { this.innerHTML += html; },
    querySelector() { return this; },
    querySelectorAll() { return []; },
    closest() { return null; },
    focus() { document.activeElement = this; },
  };
}

/** installDom of stubElement, plus the `location` and `history` globals the dashboard reads at boot. */
export function installStubDom({ hash = "", hidden, history, ...extras } = {}) {
  const body = { id: "body" };
  const elements = installDom((id) => stubElement(id, { hidden }), { body, activeElement: body, ...extras });
  globalThis.location = { hash };
  globalThis.history = history || { replaceState() {} };
  return elements;
}
