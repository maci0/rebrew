# ADR-014: The CLI is a component graph

- **Status**: Accepted
- **Date**: 2026-09

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
  `activate()` (startup registration onto a `CoeffectScope`), and
  `CliComponent`. A missing declared service leaves the component inactive;
  it does not raise.
- A service provision is an effect whose inverse is the key's restriction, so
  `unprovide` or disposal withdraws it, and the binding is reverted with the
  rest of the accumulator. Each inverse is armed: `_Effect.revert` fires it
  at most once, so overlapping `Context.dispose` and `CoeffectScope.close`
  cannot run it twice.
- `CoeffectScope` is a fiber on its context (`ctx.effect(self.close)`).
  Disposing the context closes the scope. `close` is idempotent.
- `CoeffectScope` classifies every change to the service table against each
  component's specification: a component activates when its dependencies
  appear, and is deactivated, reverting exactly the effects that activation
  installed, when a needed service is withdrawn.
- `rebrew.builtins` is the packaged manifest: every tool it lists is one
  `CliComponent` (name, module, help, panel, group flag), so the help
  panel lives on the tool's own row rather than a separate name-keyed
  table.  The one packaged component outside the manifest
  (`import-splat`) is declared in `rebrew.main._EXTRA_COMPONENTS` with
  the same shape, because the manifest is pinned to bundled agent skills.
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
  `activate()` itself does not fail on unmet `needs`; those components stay
  inactive until a later provision. The CLI process provides `cli` and
  `console` before activation, so packaged tools mount immediately.
  Three refinements landed after the initial composition: every scope on the
  chain classifies every change (not just the nearest), provision is
  single-source across forks (no shadowing), and `unprovide` deactivates
  dependents newest-first before running the inverse (Theorem 70 order).
- The loader tier of the paper (configuration reconciliation and hot module
  replacement) is deliberately not built.  A CLI process composes once and has
  no module to swap; `CoeffectScope` is the seam a long-lived host (the
  dashboard) would drive instead.
- Tests that regex-parsed `main.py` for the command list now read
  `BUILTIN_COMPONENTS`.
