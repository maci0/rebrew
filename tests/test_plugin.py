"""Tests for the component/context runtime (rebrew.plugin)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest
import typer
from rich.console import Console

from rebrew.plugin import (
    CLI_SERVICE,
    CONSOLE_SERVICE,
    CliComponent,
    CoeffectScope,
    ComponentError,
    Context,
    Panel,
    activate,
)


class TestContext:
    def test_provide_twice_raises(self) -> None:
        ctx = Context()
        ctx.provide("a", 1)
        with pytest.raises(ComponentError, match="already provided"):
            ctx.provide("a", 2)

    def test_resolve_missing_raises(self) -> None:
        with pytest.raises(ComponentError, match="not provided"):
            Context().resolve("nope")

    def test_resolve_walks_parent(self) -> None:
        parent = Context()
        parent.provide("a", 1)
        child = parent.fork()
        assert child.resolve("a") == 1
        assert child.has("a")
        assert not parent.has("b")

    def test_effects_run_in_reverse_order(self) -> None:
        ctx = Context()
        order: list[str] = []
        ctx.effect(lambda: order.append("first"))
        ctx.effect(lambda: order.append("second"))
        ctx.dispose()
        assert order == ["second", "first"]

    def test_dispose_is_idempotent(self) -> None:
        ctx = Context()
        calls: list[int] = []
        ctx.effect(lambda: calls.append(1))
        ctx.dispose()
        ctx.dispose()
        assert calls == [1]

    def test_effect_after_dispose_raises(self) -> None:
        ctx = Context()
        ctx.dispose()
        assert ctx.disposed
        with pytest.raises(ComponentError, match="disposed"):
            ctx.effect(lambda: None)

    def test_provide_is_revertible(self) -> None:
        """A provision is an effect: its inverse is the key's restriction."""
        ctx = Context()
        ctx.provide("a", 1)
        assert ctx.resolve("a") == 1
        ctx.unprovide("a")
        assert not ctx.has("a")

    def test_unprovide_absent_raises(self) -> None:
        with pytest.raises(ComponentError, match="not provided"):
            Context().unprovide("nope")

    def test_dispose_withdraws_provisions(self) -> None:
        ctx = Context()
        ctx.provide("a", 1)
        ctx.dispose()
        assert not ctx.has("a")
        with pytest.raises(ComponentError, match="disposed"):
            ctx.provide("b", 2)


@dataclass
class _Component:
    """A test component that can publish a service and record activation."""

    needs: tuple[str, ...] = ()
    provides: tuple[tuple[str, Any], ...] = ()
    log: list[str] = field(default_factory=list)
    name: str = "component"

    def apply(self, ctx: Context) -> None:
        self.log.append(self.name)
        for key, value in self.provides:
            ctx.provide(key, value)


class TestActivate:
    def test_activates_a_component_with_no_needs(self) -> None:
        comp = _Component(name="a")
        activate([comp], Context())
        assert comp.log == ["a"]

    def test_declared_dependency_decides_order(self) -> None:
        """A component needing a service activates only after its provider."""
        ctx = Context()
        provider = _Component(name="provider", provides=(("svc", 42),))
        consumer = _Component(name="consumer", needs=("svc",))
        # Consumer listed first on purpose; the declaration fixes the order.
        activate([consumer, provider], ctx)
        assert provider.log == ["provider"]
        assert consumer.log == ["consumer"]

    def test_unsatisfied_needs_report_missing_services(self) -> None:
        ctx = Context()
        comp = _Component(name="lonely", needs=("missing",))
        with pytest.raises(ComponentError, match="missing"):
            activate([comp], ctx)

    def test_dependency_cycle_reports_waiting_components(self) -> None:
        ctx = Context()
        a = _Component(name="a", needs=("b_svc",))
        b = _Component(name="b", needs=("a_svc",))
        with pytest.raises(ComponentError, match="unresolved service dependencies"):
            activate([a, b], ctx)


@dataclass
class _RevertibleComponent:
    """A component that records activation and reverts through an effect."""

    needs: tuple[str, ...] = ()
    log: list[str] = field(default_factory=list)

    def apply(self, ctx: Context) -> None:
        self.log.append("on")
        ctx.effect(lambda: self.log.append("off"))


class TestReactiveCoeffects:
    def test_component_activates_when_its_service_appears(self) -> None:
        """A change classified as activating runs the component's effects."""
        ctx = Context()
        scope = CoeffectScope(ctx)
        comp = _RevertibleComponent(needs=("svc",))
        scope.add(comp)
        assert comp.log == []
        ctx.provide("svc", 1)
        assert comp.log == ["on"]

    def test_withdrawn_service_deactivates_and_reverts(self) -> None:
        """A deactivating change applies the accumulator, reverting residue."""
        ctx = Context()
        scope = CoeffectScope(ctx)
        comp = _RevertibleComponent(needs=("svc",))
        scope.add(comp)
        ctx.provide("svc", 1)
        ctx.unprovide("svc")
        assert comp.log == ["on", "off"]
        assert scope.unresolved() == [comp]

    def test_deactivation_leaves_siblings_untouched(self) -> None:
        """Reverting one component does not disturb another's effects."""
        ctx = Context()
        scope = CoeffectScope(ctx)
        steady = _RevertibleComponent()
        dependent = _RevertibleComponent(needs=("svc",))
        scope.add(steady)
        scope.add(dependent)
        ctx.provide("svc", 1)
        ctx.unprovide("svc")
        assert steady.log == ["on"]
        assert dependent.log == ["on", "off"]

    def test_a_component_that_provides_activates_its_waiter(self) -> None:
        """Activation may satisfy another specification in the same pass."""
        ctx = Context()
        scope = CoeffectScope(ctx)
        waiter = _RevertibleComponent(needs=("svc",))
        provider = _Component(name="provider", provides=(("svc", 7),))
        scope.add(waiter)
        scope.add(provider)
        assert waiter.log == ["on"]
        assert ctx.resolve("svc") == 7

    def test_close_deactivates_every_entry(self) -> None:
        ctx = Context()
        scope = CoeffectScope(ctx)
        comp = _RevertibleComponent(needs=("svc",))
        scope.add(comp)
        ctx.provide("svc", 1)
        scope.close()
        assert comp.log == ["on", "off"]
        assert scope.unresolved() == []


class TestCliComponent:
    def _context(self, app: typer.Typer) -> Context:
        ctx = Context()
        ctx.provide(CLI_SERVICE, app)
        ctx.provide(CONSOLE_SERVICE, Console(stderr=True))
        return ctx

    def test_mounts_command_and_disposer_removes_it(self) -> None:
        app = typer.Typer()
        ctx = self._context(app)
        component = CliComponent(
            name="diag", module="rebrew.diagnose", help="diag", panel=Panel.ANALYSIS
        )
        activate([component], ctx)
        assert [c.name for c in app.registered_commands] == ["diag"]
        ctx.dispose()
        assert app.registered_commands == []

    def test_mounts_group_and_disposer_removes_it(self) -> None:
        app = typer.Typer()
        ctx = self._context(app)
        component = CliComponent(
            name="lib",
            module="rebrew.library",
            help="lib",
            panel=Panel.PROJECT_SETUP,
            is_group=True,
        )
        activate([component], ctx)
        assert [g.name for g in app.registered_groups] == ["lib"]
        ctx.dispose()
        assert app.registered_groups == []

    def test_broken_module_mounts_unavailable_stub(self) -> None:
        app = typer.Typer()
        ctx = self._context(app)
        component = CliComponent(
            name="broken", module="rebrew.no_such_module", help="x", panel=Panel.PLUGINS
        )
        activate([component], ctx)
        assert [c.name for c in app.registered_commands] == ["broken"]
        assert app.registered_commands[0].rich_help_panel == Panel.PLUGINS

    def test_wrong_kind_group_mounts_unavailable_stub(self) -> None:
        app = typer.Typer()
        ctx = self._context(app)
        component = CliComponent(
            name="wrong",
            module="rebrew.diagnose",
            attr="main",
            help="x",
            panel=Panel.PLUGINS,
            is_group=True,
        )
        activate([component], ctx)
        assert [g.name for g in app.registered_groups] == ["wrong"]


class TestBuiltinManifest:
    def test_names_and_modules_are_unique(self) -> None:
        from rebrew.builtins import BUILTIN_COMPONENTS

        names = [c.name for c in BUILTIN_COMPONENTS]
        modules = [c.module for c in BUILTIN_COMPONENTS]
        assert len(names) == len(set(names))
        assert len(modules) == len(set(modules))

    def test_panels_are_declared(self) -> None:
        from rebrew.builtins import BUILTIN_COMPONENTS

        assert all(c.panel in Panel.ALL for c in BUILTIN_COMPONENTS)
