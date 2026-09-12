# 014 — The CLI is a component graph

## Status

Accepted

## Context

The umbrella CLI concentrated four concerns in `main.py`: the Typer app
object, a help-panel table keyed by command name, the list of command
registrations, and third-party plugin discovery.  Built-in commands took a
path distinct from plugins, and the panel table was a second name-keyed
structure that had to be kept in sync with the command list by hand.

## Decision

Compose the CLI from components, following the composition discipline of
Cordis (Shi, Zhang & Cui, "A Programming Paradigm for Spatiotemporal
Composability", arXiv:2608.25512):

- `rebrew.plugin` provides the runtime: one `Context` type carrying both
  halves of the paradigm (the service table is the coeffect half, the inverse
  accumulator the effect half), the `Component` protocol (`needs` is the
  coeffect specification), `CoeffectScope` (reactive resolution),
  `activate()` (fail-fast startup registration), and `CliComponent`.
- A service provision is an effect whose inverse is the key's restriction, so
  `unprovide` or disposal withdraws it, and the binding is reverted with the
  rest of the accumulator.
- `CoeffectScope` classifies every change to the service table against each
  component's specification: a component activates when its dependencies
  appear, and is deactivated, reverting exactly the effects that activation
  installed, when a needed service is withdrawn.
- `rebrew.builtins` declares every built-in tool as one `CliComponent`
  (name, module, help, panel, group flag).  There is no second table.
- `rebrew.main` builds the app, publishes it as the `cli` service, and
  activates the packaged components plus any third-party components from the
  `rebrew.commands` / `rebrew.multicommands` entry-point groups.
- Mounting a command or group is a reversible effect: its disposer removes
  exactly the registration it added.

## Consequences

- Built-ins and third-party plugins follow one path.  A plugin name that
  collides with a built-in is skipped with a warning rather than shadowing
  it.
- A component that cannot be imported degrades to an `[unavailable]` stub
  under its declared panel; one broken plugin never takes the CLI down.
- The help panel lives next to the tool, so the section and the command can
  no longer drift the way the name-keyed table allowed.
- Coeffects are reactive: a service published by one component (or a plugin
  loaded later) activates its dependents without a hand-maintained order, and
  a withdrawn service reverts exactly the dependents it had activated.
- The loader tier of the paper (configuration reconciliation and hot module
  replacement) is deliberately not built.  A CLI process composes once and has
  no module to swap; `CoeffectScope` is the seam a long-lived host (the
  dashboard) would drive instead.
- Tests that regex-parsed `main.py` for the command list now read
  `BUILTIN_COMPONENTS`.
