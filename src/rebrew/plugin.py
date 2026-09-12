"""plugin.py — component/context runtime for spatiotemporal composability.

Implements the composition discipline of Cordis (Shi, Zhang & Cui, "A
Programming Paradigm for Spatiotemporal Composability", arXiv:2608.25512) at
rebrew's composition points.  A unit of functionality is a *component*:

* it publishes services under stable keys in a :class:`Context` and reaches
  sibling services by key rather than importing an implementation;
* it declares the services it needs (its *coeffects*) in ``needs``, so
  activation order falls out of the declaration instead of a hand-maintained
  sequence; and
* every registration it installs is an *effect* with a disposer, held by the
  context, so deactivation reverts exactly what the component added.

The CLI is composed this way.  Built-in tools and third-party plugins are the
same kind of :class:`CliComponent`; the umbrella app in :mod:`rebrew.main` is
the ``"cli"`` service they mount onto.
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


class Context:
    """A service container and effect scope.

    Services are looked up by key; ``effect`` records a disposer the context
    owns.  Disposal runs the effects in reverse registration order, so a
    component's residue is fully reverted.
    """

    def __init__(self, parent: Context | None = None) -> None:
        self._parent = parent
        self._services: dict[str, Any] = {}
        self._effects: list[Disposer] = []
        self._disposed = False

    def provide(self, key: str, value: Any) -> None:
        """Publish *value* under *key*; a key is provided exactly once."""
        if key in self._services:
            raise ComponentError(f"service {key!r} is already provided")
        self._services[key] = value

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

    def effect(self, dispose: Disposer) -> None:
        """Record a disposer; it runs, in reverse order, at ``dispose()``."""
        if self._disposed:
            raise ComponentError("context is disposed; cannot install effects")
        self._effects.append(dispose)

    def fork(self) -> Context:
        """A child context that resolves services through this one."""
        return Context(parent=self)

    @property
    def disposed(self) -> bool:
        return self._disposed

    def dispose(self) -> None:
        """Revert every effect in reverse registration order."""
        if self._disposed:
            return
        self._disposed = True
        while self._effects:
            self._effects.pop()()


@runtime_checkable
class Component(Protocol):
    """Anything the loader can activate.

    ``needs`` is the coeffect declaration: the service keys that must be
    available before ``apply`` runs.  ``apply`` installs the component's
    effects on the context.
    """

    needs: tuple[str, ...]

    def apply(self, ctx: Context) -> None: ...


def activate(components: Iterable[Component], ctx: Context) -> None:
    """Activate every component whose declared services are available.

    Components activate in dependency order; one whose ``needs`` are never
    satisfied raises :class:`ComponentError` naming the missing services and
    the components left waiting.
    """
    pending = list(components)
    while pending:
        deferred: list[Component] = []
        for component in pending:
            if all(ctx.has(key) for key in component.needs):
                component.apply(ctx)
            else:
                deferred.append(component)
        if len(deferred) == len(pending):
            missing = sorted({key for c in deferred for key in c.needs if not ctx.has(key)})
            waiting = ", ".join(_component_name(c) for c in deferred)
            raise ComponentError(
                f"unresolved service dependencies {missing} for components: {waiting}"
            )
        pending = deferred


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
