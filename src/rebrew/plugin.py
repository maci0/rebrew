"""plugin.py — component/context runtime for spatiotemporal composability.

Implements the composition discipline of Cordis (Shi, Zhang & Cui, "A
Programming Paradigm for Spatiotemporal Composability", arXiv:2608.25512) at
rebrew's composition points.  A unit of functionality is a *component*:

* it publishes services under stable keys in a :class:`Context` and reaches
  sibling services by key rather than importing an implementation;
* it declares the services it needs (its *coeffects*) in ``needs``, so
  activation order falls out of the declaration instead of a hand-maintained
  sequence;
* it declares services it needs and the runtime reacts to their availability:
  :class:`CoeffectScope` re-classifies every change to the service table
  against each component's ``needs`` (Definition 22), activating the component
  when the specification becomes satisfied and deactivating it when a needed
  service is withdrawn; and
* every change it makes is an *effect* with an inverse the context holds, run
  in reverse on disposal (Theorem 16), so deactivation reverts exactly what the
  component added and leaves its siblings' effects interleaved but untouched.

A service provision is itself such an effect: its inverse is the restriction of
the key (Definition 20), so ``unprovide`` or disposal withdraws the binding.

The CLI is composed this way.  Built-in tools and third-party plugins are the
same kind of :class:`CliComponent`; the umbrella app in :mod:`rebrew.main` is
the ``"cli"`` service they mount onto.  The loader tier of the paper
(configuration reconciliation and hot module replacement) is deliberately not
built: a CLI process composes once and has no module to swap, and
:class:`CoeffectScope` is the seam a long-lived host would drive instead.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import typer
from rich.console import Console
from rich.markup import escape

from rebrew.cli import EXIT_ERROR
from rebrew.registry import Registration, RegistryError, import_registration

Disposer = Callable[[], None]

COMMANDS_GROUP = "rebrew.commands"
MULTI_COMMANDS_GROUP = "rebrew.multicommands"

#: Service keys.  Components resolve these instead of importing the objects.
CLI_SERVICE = "cli"
CONSOLE_SERVICE = "console"


class Panel:
    """Rich help panels that group commands in ``--help``."""

    PROJECT_SETUP = "Project Setup"
    DEVELOPMENT = "Development"
    ANALYSIS = "Analysis"
    MATCHING = "Matching"
    EXPORT_SYNC = "Export & Sync"
    PLUGINS = "Plugins"

    ALL: tuple[str, ...] = (
        PROJECT_SETUP,
        DEVELOPMENT,
        ANALYSIS,
        MATCHING,
        EXPORT_SYNC,
        PLUGINS,
    )


class ComponentError(RuntimeError):
    """A component could not activate: unknown service, duplicate, or bad shape."""


@dataclass
class _Effect:
    """One tracked context transformation: its inverse, and the key it binds.

    ``key`` is set for a service provision, whose inverse is the restriction of
    that key (Definition 20: ``set(k, v)`` has inverse ``σ ↦ σ ∖ k``), so the
    provision can be undone on its own while the other effects are retained.
    """

    dispose: Disposer
    key: str | None = None


class Context:
    """The unified effect and coeffect context (the context paradigm).

    One type carries both halves of the paradigm:

    * the *coeffect* half is the service table components resolve by key;
    * the *effect* half is the accumulator of inverses, held in registration
      order and run in reverse, so disposal reverts exactly what was installed.

    A provision is an effect: ``provide`` records the restriction of its key as
    the inverse, and ``unprovide`` runs that inverse alone.  Every change to the
    table notifies the attached :class:`CoeffectScope`, which is what makes the
    coeffects reactive.  ``_owners`` names the component currently applying, so
    the effects one activation installs can be reverted on their own.
    """

    def __init__(self, parent: Context | None = None) -> None:
        self._parent = parent
        self._services: dict[str, Any] = {}
        self._effects: list[_Effect] = []
        self._owners: list[list[_Effect]] = []
        self._disposed = False
        self._on_change: Callable[[], None] | None = None

    # -- coeffect half: the dependency table --------------------------------

    def provide(self, key: str, value: Any) -> None:
        """Bind *value* at *key*; the binding is an effect.

        The key may not already be bound in this context (Definition 20's
        precondition).  The inverse is the restriction of the key, recorded on
        the accumulator, so ``unprovide`` or disposal withdraws the binding.
        """
        if self._disposed:
            raise ComponentError("context is disposed; cannot provide services")
        if key in self._services:
            raise ComponentError(f"service {key!r} is already provided")
        self._services[key] = value
        self._record(_Effect(dispose=self._restrict(key), key=key))
        self._changed()

    def unprovide(self, key: str) -> None:
        """Withdraw *key*, running exactly its binding's inverse."""
        if key not in self._services:
            raise ComponentError(f"service {key!r} is not provided")
        for index, effect in enumerate(self._effects):
            if effect.key == key:
                del self._effects[index]
                # The inverse (restriction) notifies the scope itself.
                effect.dispose()
                break

    def _restrict(self, key: str) -> Disposer:
        """The inverse of binding *key*: drop it from this context's table."""

        def dispose() -> None:
            self._services.pop(key, None)
            self._changed()

        return dispose

    def resolve(self, key: str) -> Any:
        """Return the service under *key*, searching enclosing contexts."""
        ctx: Context | None = self
        while ctx is not None:
            if key in ctx._services:
                return ctx._services[key]
            ctx = ctx._parent
        raise ComponentError(f"service {key!r} is not provided")

    def has(self, key: str) -> bool:
        ctx: Context | None = self
        while ctx is not None:
            if key in ctx._services:
                return True
            ctx = ctx._parent
        return False

    # -- effect half: the inverse accumulator --------------------------------

    def effect(self, dispose: Disposer) -> None:
        """Record a disposer; it runs, in reverse order, at ``dispose()``."""
        self._record(_Effect(dispose=dispose))

    def _record(self, effect: _Effect) -> None:
        if self._disposed:
            raise ComponentError("context is disposed; cannot install effects")
        self._effects.append(effect)
        if self._owners:
            self._owners[-1].append(effect)

    def _forget(self, effect: _Effect) -> None:
        """Drop *effect* from the accumulator without running it."""
        _remove_identity(self._effects, effect)

    def fork(self) -> Context:
        """A derived context that resolves services through this one."""
        return Context(parent=self)

    @property
    def disposed(self) -> bool:
        return self._disposed

    def dispose(self) -> None:
        """Revert every effect in reverse registration order."""
        if self._disposed:
            return
        self._disposed = True
        # Detach the scope first: withdrawing the provisions as they revert
        # must not reclassify anything during teardown.
        self._on_change = None
        while self._effects:
            self._effects.pop().dispose()

    def _changed(self) -> None:
        """A service table change: hand it to the nearest attached scope."""
        ctx: Context | None = self
        while ctx is not None:
            if ctx._on_change is not None:
                ctx._on_change()
                return
            ctx = ctx._parent


@runtime_checkable
class Component(Protocol):
    """Anything the loader can activate.

    ``needs`` is the coeffect specification: the service keys that must be
    available before ``apply`` runs (Definition 21).  ``apply`` installs the
    component's effects on the context; the scope records them, so deactivation
    reverts exactly those.
    """

    needs: tuple[str, ...]

    def apply(self, ctx: Context) -> None: ...


@dataclass
class _Entry:
    """A registered component and the effects of its current activation."""

    component: Component
    needs: tuple[str, ...]
    #: The effects ``apply`` installed, or ``None`` while the component is
    #: inactive (its specification is unsatisfied).
    effects: list[_Effect] | None = None


class CoeffectScope:
    """Reactive coeffect resolution over one :class:`Context` (Definition 22).

    Each component's ``needs`` is a coeffect specification.  Every change to
    the service table is classified against every specification, so a component
    activates when its dependencies become available (``activating``) and is
    reverted when they are withdrawn (``deactivating``).  An activation's
    effects are owned by its entry and run in reverse on deactivation
    (Theorem 16), so one component reverts exactly its own residue.
    """

    def __init__(self, ctx: Context) -> None:
        self._ctx = ctx
        self._entries: list[_Entry] = []
        self._settling = False
        ctx._on_change = self._classify

    def add(self, component: Component) -> None:
        """Register *component*; it activates as soon as its needs are met."""
        self._entries.append(_Entry(component=component, needs=tuple(component.needs)))
        self._classify()

    def unresolved(self) -> list[Component]:
        """Registered components whose specification is still unsatisfied."""
        return [entry.component for entry in self._entries if entry.effects is None]

    def close(self) -> None:
        """Deactivate every entry, newest first."""
        self._ctx._on_change = None
        self._settling = True
        try:
            for entry in reversed(self._entries):
                self._deactivate(entry)
        finally:
            self._entries.clear()
            self._settling = False

    def _satisfied(self, needs: tuple[str, ...]) -> bool:
        return all(self._ctx.has(key) for key in needs)

    def _classify(self) -> None:
        """Drive activation and deactivation from the current satisfaction.

        Activating one component may provide a service another is waiting on,
        so the pass repeats until no specification changes status.  Reentrant
        calls (a change made while classifying) are absorbed into that loop.
        """
        if self._settling:
            return
        self._settling = True
        try:
            changed = True
            while changed:
                changed = False
                for entry in self._entries:
                    satisfied = self._satisfied(entry.needs)
                    if satisfied and entry.effects is None:
                        entry.effects = self._activate(entry.component)
                        changed = True
                    elif not satisfied and entry.effects is not None:
                        self._deactivate(entry)
                        changed = True
        finally:
            self._settling = False

    def _activate(self, component: Component) -> list[_Effect]:
        owned: list[_Effect] = []
        self._ctx._owners.append(owned)
        try:
            component.apply(self._ctx)
        finally:
            self._ctx._owners.pop()
        return owned

    def _deactivate(self, entry: _Entry) -> None:
        effects = entry.effects or []
        entry.effects = None
        for effect in reversed(effects):
            self._ctx._forget(effect)
            effect.dispose()


def activate(components: Iterable[Component], ctx: Context) -> CoeffectScope:
    """Activate every component whose declared services are available.

    The startup composition: registers each component on a
    :class:`CoeffectScope` and raises when a specification is never satisfied,
    naming the missing services and the components left waiting.  The returned
    scope stays reactive, so a service provided later still activates its
    dependents, and disposing it reverts every component.
    """
    scope = CoeffectScope(ctx)
    for component in components:
        scope.add(component)
    unresolved = scope.unresolved()
    if unresolved:
        missing = sorted({key for c in unresolved for key in c.needs if not ctx.has(key)})
        waiting = ", ".join(_component_name(c) for c in unresolved)
        raise ComponentError(f"unresolved service dependencies {missing} for components: {waiting}")
    return scope


def _component_name(component: Component) -> str:
    name = getattr(component, "name", None)
    return name if isinstance(name, str) else type(component).__name__


def _remove_identity(items: list[Any], item: Any) -> None:
    """Remove *item* from *items* by identity, not equality.

    Dataclass equality would match an equal-but-distinct registration (two
    commands built from the same help text), so removal must be identity-based.
    """
    for index, candidate in enumerate(items):
        if candidate is item:
            del items[index]
            return


def _track_registration(app: typer.Typer, *, is_group: bool, registered: Any, ctx: Context) -> None:
    """Record an effect that unregisters *registered* from *app*.

    Mounting a command or group is a reversible side effect: disposal removes
    exactly the entry this call added, so a component can be deactivated
    without disturbing registrations that surround it.
    """

    def dispose() -> None:
        items = app.registered_groups if is_group else app.registered_commands
        _remove_identity(items, registered)

    ctx.effect(dispose)


def make_stub_app(module: str, error: Exception, console: Console) -> typer.Typer:
    """A Typer app that reports a component that could not be loaded."""
    stub = typer.Typer(help=f"[unavailable] {module}")

    @stub.callback(invoke_without_command=True)
    def _stub_main() -> None:
        console.print(f"[red]Error:[/red] could not load '{escape(module)}': {escape(str(error))}")
        raise typer.Exit(code=EXIT_ERROR)

    return stub


def make_stub_command(module: str, error: Exception, console: Console) -> Callable[[], None]:
    """A command callable that reports why its module could not be loaded."""

    def _stub() -> None:
        console.print(f"[red]Error:[/red] could not load '{escape(module)}': {escape(str(error))}")
        raise typer.Exit(code=EXIT_ERROR)

    return _stub


def _app_help(app: typer.Typer, fallback: str) -> str:
    help_text = getattr(app.info, "help", None)
    return help_text or fallback


def _app_epilog(app: typer.Typer) -> str | None:
    epilog = getattr(app.info, "epilog", None)
    return epilog if isinstance(epilog, str) else None


@dataclass(frozen=True)
class CliComponent(Component):
    """One CLI tool, mounted as a Typer command or group.

    Built-ins and third-party entry points are both built as ``CliComponent``;
    ``module``/``attr`` name the target (``attr`` empty means "module form":
    the module's ``main`` callable, or its ``app`` for a group).
    """

    name: str
    module: str
    help: str
    panel: str
    is_group: bool = False
    attr: str = ""
    origin: str = "builtin"
    needs: tuple[str, ...] = field(default_factory=tuple)

    @property
    def group(self) -> str:
        return MULTI_COMMANDS_GROUP if self.is_group else COMMANDS_GROUP

    def apply(self, ctx: Context) -> None:
        app: typer.Typer = ctx.resolve(CLI_SERVICE)
        console: Console = ctx.resolve(CONSOLE_SERVICE)
        registration = Registration(
            name=self.name,
            module=self.module,
            attr=self.attr,
            group=self.group,
            origin=self.origin,
        )
        try:
            obj = import_registration(registration)
        except RegistryError as exc:
            self._mount_unavailable(app, console, exc, ctx)
            return
        if self.is_group:
            self._mount_group(app, console, obj, ctx)
        else:
            self._mount_command(app, console, obj, ctx)

    def _mount_group(self, app: typer.Typer, console: Console, obj: Any, ctx: Context) -> None:
        group_app = obj if isinstance(obj, typer.Typer) else getattr(obj, "app", None)
        if not isinstance(group_app, typer.Typer):
            self._mount_unavailable(
                app,
                console,
                RegistryError(
                    f"bad CLI plugin {self.name!r} from {self.origin} "
                    f"({self.module}): expected a typer.Typer app, "
                    f"got {type(obj).__name__}"
                ),
                ctx,
            )
            return
        app.add_typer(
            group_app,
            name=self.name,
            help=_app_help(group_app, self.help),
            rich_help_panel=self.panel,
        )
        registered_group = app.registered_groups[-1]
        _track_registration(app, is_group=True, registered=registered_group, ctx=ctx)

    def _mount_command(self, app: typer.Typer, console: Console, obj: Any, ctx: Context) -> None:
        if self.attr:
            command = obj
            help_text = (getattr(obj, "__doc__", None) or self.help).strip()
            epilog = None
        else:
            command = getattr(obj, "main", None)
            module_app = getattr(obj, "app", None)
            if not callable(command) or not isinstance(module_app, typer.Typer):
                self._mount_unavailable(
                    app,
                    console,
                    RegistryError(
                        f"bad CLI plugin {self.name!r} from {self.origin} "
                        f"({self.module}): module exposes no callable 'main' "
                        f"and a typer app"
                    ),
                    ctx,
                )
                return
            help_text = _app_help(module_app, self.help)
            epilog = _app_epilog(module_app)
        if not callable(command):
            self._mount_unavailable(
                app,
                console,
                RegistryError(
                    f"bad CLI plugin {self.name!r} from {self.origin} "
                    f"({self.module}): expected a callable, got {type(command).__name__}"
                ),
                ctx,
            )
            return
        app.command(
            name=self.name,
            help=help_text,
            epilog=epilog,
            rich_help_panel=self.panel,
        )(command)
        registered_command = app.registered_commands[-1]
        _track_registration(app, is_group=False, registered=registered_command, ctx=ctx)

    def _mount_unavailable(
        self, app: typer.Typer, console: Console, error: Exception, ctx: Context
    ) -> None:
        help_text = f"[unavailable] {self.help}"
        if self.is_group:
            app.add_typer(
                make_stub_app(self.module, error, console),
                name=self.name,
                help=help_text,
                rich_help_panel=self.panel,
            )
            registered_group = app.registered_groups[-1]
            _track_registration(app, is_group=True, registered=registered_group, ctx=ctx)
        else:
            app.command(name=self.name, help=help_text, rich_help_panel=self.panel)(
                make_stub_command(self.module, error, console)
            )
            registered_command = app.registered_commands[-1]
            _track_registration(app, is_group=False, registered=registered_command, ctx=ctx)


def entry_point_components(existing: set[str], console: Console) -> list[CliComponent]:
    """Third-party CLI components from the plugin entry-point groups.

    A name already present (a packaged command) is skipped with a warning on
    stderr: a plugin must not shadow a built-in.  Malformed registrations keep
    degrading to an ``[unavailable]`` stub, so one broken plugin never takes
    the CLI down.
    """
    from rebrew.registry import entry_point_registrations

    components: list[CliComponent] = []
    for group, is_group in ((COMMANDS_GROUP, False), (MULTI_COMMANDS_GROUP, True)):
        for registration in entry_point_registrations(group):
            if registration.name in existing:
                console.print(
                    f"[yellow]warning:[/yellow] duplicate CLI command "
                    f"{registration.name!r} from {registration.origin} ignored "
                    f"(a built-in already uses that name)"
                )
                continue
            components.append(
                CliComponent(
                    name=registration.name,
                    module=registration.module,
                    attr=registration.attr,
                    help=registration.name,
                    panel=Panel.PLUGINS,
                    is_group=is_group,
                    origin=registration.origin,
                )
            )
            existing.add(registration.name)
    return components
