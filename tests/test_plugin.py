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


def test_plugin_public_all() -> None:
    """Star-imports must not leak typing/stdlib names into consumer namespaces."""
    import rebrew.plugin as plug

    assert plug.__all__ == [
        "CLI_SERVICE",
        "COMMANDS_GROUP",
        "CONSOLE_SERVICE",
        "CliComponent",
        "CoeffectScope",
        "Component",
        "ComponentError",
        "Context",
        "Disposer",
        "MULTI_COMMANDS_GROUP",
        "Panel",
        "activate",
        "entry_point_components",
        "make_stub_app",
        "make_stub_command",
    ]
    for name in plug.__all__:
        assert getattr(plug, name, None) is not None, name
    ns: dict[str, Any] = {}
    exec("from rebrew.plugin import *", ns)  # noqa: S102
    exported = {k for k in ns if not k.startswith("_")}
    assert exported == set(plug.__all__)


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

    def test_fork_after_dispose_raises(self) -> None:
        """Dispose is terminal: forking a dead context would attach a new
        child to an owner whose inverses already ran."""
        ctx = Context()
        ctx.dispose()
        with pytest.raises(ComponentError, match="disposed"):
            ctx.fork()

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
    services: tuple[tuple[str, Any], ...] = ()
    log: list[str] = field(default_factory=list)
    name: str = "component"
    order: list[str] | None = None

    @property
    def provides(self) -> tuple[str, ...]:
        return tuple(key for key, _ in self.services)

    def apply(self, ctx: Context) -> None:
        self.log.append(self.name)
        if self.order is not None:
            self.order.append(self.name)
        for key, value in self.services:
            ctx.provide(key, value)


class TestActivate:
    def test_activates_a_component_with_no_needs(self) -> None:
        comp = _Component(name="a")
        activate([comp], Context())
        assert comp.log == ["a"]

    def test_declared_dependency_decides_order(self) -> None:
        """A component needing a service activates only after its provider."""
        ctx = Context()
        order: list[str] = []
        provider = _Component(name="provider", services=(("svc", 42),), order=order)
        consumer = _Component(name="consumer", needs=("svc",), order=order)
        # Consumer listed first on purpose; the declaration fixes the order.
        activate([consumer, provider], ctx)
        assert order == ["provider", "consumer"]
        assert ctx.resolve("svc") == 42

    def test_unsatisfied_needs_stay_inactive_until_provided(self) -> None:
        ctx = Context()
        comp = _Component(name="lonely", needs=("missing",))
        scope = activate([comp], ctx)
        assert scope.unresolved() == [comp]
        ctx.provide("missing", 42)
        assert comp.log == ["lonely"]
        ctx.unprovide("missing")
        assert scope.unresolved() == [comp]

    def test_dependency_cycle_stays_inactive(self) -> None:
        ctx = Context()
        a = _Component(name="a", needs=("b_svc",))
        b = _Component(name="b", needs=("a_svc",))
        scope = activate([a, b], ctx)
        assert scope.unresolved() == [a, b]


@dataclass
class _RevertibleComponent:
    """A component that records activation and reverts through an effect."""

    needs: tuple[str, ...] = ()
    provides: tuple[str, ...] = ()
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

    def test_provider_swap_reactivates_against_new_value(self) -> None:
        """Withdraw-then-reprovide (a provider swap) deactivates and then
        reactivates the dependent with the NEW binding — no component may
        assume a coeffect is eternal."""
        ctx = Context()
        scope = CoeffectScope(ctx)
        seen: list[object] = []

        class _Watch:
            needs = ("svc",)
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                seen.append(ctx.resolve("svc"))
                ctx.effect(lambda: seen.append("off"))

        scope.add(_Watch())
        ctx.provide("svc", "v1")
        ctx.unprovide("svc")
        ctx.provide("svc", "v2")
        assert seen == ["v1", "off", "v2"]
        ctx.dispose()
        assert seen == ["v1", "off", "v2", "off"]

    def test_fork_scope_reacts_to_parent_table_changes(self) -> None:
        """A scope on a forked context activates when the parent's provision
        appears and deactivates when it is withdrawn: Definition 22 covers
        every context that resolves the key, not just the nearest."""
        parent = Context()
        child = parent.fork()
        scope = CoeffectScope(child)
        comp = _RevertibleComponent(needs=("svc",))
        scope.add(comp)
        assert comp.log == []
        parent.provide("svc", 1)
        assert comp.log == ["on"]
        parent.unprovide("svc")
        assert comp.log == ["on", "off"]
        assert scope.unresolved() == [comp]

    def test_disposed_fork_detached_from_parent(self) -> None:
        """Disposing a fork removes it from the parent's child list — the
        parent must not retain a disposed context past its owner."""
        parent = Context()
        child = parent.fork()
        assert parent._children == [child]
        child.dispose()
        assert parent._children == []
        parent.dispose()

    def test_nested_fork_scope_sees_root_provision_and_withdrawal(self) -> None:
        """The cascade is transitive: a grandchild scope reacts to a change
        made two contexts above it, in both directions."""
        root = Context()
        mid = root.fork()
        leaf = mid.fork()
        scope = CoeffectScope(leaf)
        comp = _RevertibleComponent(needs=("svc",))
        scope.add(comp)
        root.provide("svc", "deep")
        assert comp.log == ["on"]
        root.unprovide("svc")
        assert comp.log == ["on", "off"]
        assert scope.unresolved() == [comp]

    def test_parent_scope_ignores_child_provision(self) -> None:
        """Lookup is one-directional: an ancestor's components must not
        resolve a descendant's key. A spec whose provider lives below stays
        inactive — missing provider, no crash, no downward reach."""
        parent = Context()
        scope = CoeffectScope(parent)
        comp = _RevertibleComponent(needs=("child_key",))
        scope.add(comp)
        child = parent.fork()
        child.provide("child_key", 1)
        assert comp.log == []
        assert scope.unresolved() == [comp]
        child.dispose()
        parent.dispose()

    def test_withdrawal_inside_activation_is_stable(self) -> None:
        """An activation cannot invalidate the dependency it committed to."""
        ctx = Context()

        class _Suicidal:
            needs = ("x",)
            provides: tuple[str, ...] = ()

            def apply(self, c: Context) -> None:
                c.unprovide("x")

        scope = CoeffectScope(ctx)
        scope.add(_Suicidal())
        with pytest.raises(ComponentError, match="not owned"):
            ctx.provide("x", 1)
        assert ctx.resolve("x") == 1
        assert scope.unresolved() == []

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
        provider = _Component(name="provider", services=(("svc", 7),))
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

    def test_dispose_closes_scope_and_reverts_once(self) -> None:
        ctx = Context()
        scope = CoeffectScope(ctx)
        comp = _RevertibleComponent()
        scope.add(comp)
        ctx.dispose()
        assert comp.log == ["on", "off"]
        scope.close()
        ctx.dispose()
        assert comp.log == ["on", "off"]

    def test_close_then_dispose_reverts_once(self) -> None:
        ctx = Context()
        scope = CoeffectScope(ctx)
        comp = _RevertibleComponent()
        scope.add(comp)
        scope.close()
        ctx.dispose()
        assert comp.log == ["on", "off"]

    def test_add_after_close_does_not_activate(self) -> None:
        ctx = Context()
        scope = CoeffectScope(ctx)
        scope.close()
        late = _RevertibleComponent()
        scope.add(late)
        assert late.log == []


class TestCliComponent:
    @pytest.mark.parametrize("is_group", [False, True])
    def test_lazy_export_failure_mounts_stub_and_preserves_other_commands(
        self, monkeypatch: pytest.MonkeyPatch, is_group: bool
    ) -> None:
        import sys
        from types import ModuleType

        from typer.testing import CliRunner

        module = ModuleType("cordis_lazy_cli")

        def missing(name: str) -> Any:
            raise ValueError(f"lazy export {name} failed")

        def healthy() -> None:
            """A healthy sibling command."""

        monkeypatch.setattr(module, "healthy", healthy, raising=False)
        monkeypatch.setattr(module, "__getattr__", missing, raising=False)
        monkeypatch.setitem(sys.modules, module.__name__, module)
        app = typer.Typer()

        @app.callback()
        def root() -> None:
            pass

        ctx = self._context(app)
        broken = CliComponent(
            name="broken",
            module=module.__name__,
            help="x",
            panel=Panel.PLUGINS,
            is_group=is_group,
        )
        sibling = CliComponent(
            name="healthy", module=module.__name__, attr="healthy", help="x", panel=Panel.PLUGINS
        )
        scope = activate([broken, sibling], ctx)
        assert scope.unresolved() == []
        result = CliRunner().invoke(app, ["broken"])
        assert result.exit_code == 2 and "lazy export" in result.output
        assert CliRunner().invoke(app, ["healthy"]).exit_code == 0
        scope.close()
        assert app.registered_commands == [] and app.registered_groups == []
        ctx.dispose()

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

    def test_wrong_kind_error_carries_structured_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.plugin as plug
        from rebrew.registry import RegistryError

        seen: list[Exception] = []
        real = plug.make_stub_app

        def _capture(module: str, error: Exception, console: Console) -> typer.Typer:
            seen.append(error)
            return real(module, error, console)

        monkeypatch.setattr(plug, "make_stub_app", _capture)
        app = typer.Typer()
        component = CliComponent(
            name="wrong",
            module="rebrew.diagnose",
            attr="main",
            help="x",
            panel=Panel.PLUGINS,
            is_group=True,
            origin="entry-point",
        )
        activate([component], self._context(app))
        [error] = seen
        assert isinstance(error, RegistryError)
        assert (error.group, error.name, error.origin) == (
            plug.MULTI_COMMANDS_GROUP,
            "wrong",
            "entry-point",
        )


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


class _Probe:
    """Minimal Component: records apply calls, optionally provides."""

    def __init__(
        self,
        name: str,
        needs: tuple[str, ...] = (),
        provides: dict[str, Any] | None = None,
        calls: list[str] | None = None,
    ) -> None:
        self._name = name
        self.needs = needs
        self._provides = provides or {}
        self.provides = tuple(self._provides)
        self.calls = calls if calls is not None else []

    def apply(self, ctx: Context) -> None:
        self.calls.append(self._name)
        for key, value in self._provides.items():
            ctx.provide(key, value)


class TestMultiScope:
    """Every change classifies against every scope (Definition 22)."""

    def test_two_scopes_on_one_context_both_classify(self) -> None:
        ctx = Context()
        first = _Probe("first", needs=("a",))
        second = _Probe("second", needs=("a",))
        CoeffectScope(ctx).add(first)
        CoeffectScope(ctx).add(second)
        ctx.provide("a", 1)
        assert first.calls == ["first"]
        assert second.calls == ["second"]

    def test_closed_scope_stops_classifying(self) -> None:
        ctx = Context()
        first = _Probe("first", needs=("a",))
        scope = CoeffectScope(ctx)
        scope.add(first)
        scope.close()
        ctx.provide("a", 1)
        assert first.calls == []


class TestSingleSource:
    """A key binds once across the whole lookup chain."""

    def test_fork_cannot_shadow_parent_key(self) -> None:
        parent = Context()
        parent.provide("a", 1)
        with pytest.raises(ComponentError, match="already provided"):
            parent.fork().provide("a", 2)


class TestDependentFirstWithdrawal:
    """Dependents deactivate before their provider's withdrawal lands."""

    def test_dependent_reverts_before_provider(self) -> None:
        ctx = Context()
        provider = _Probe("provider", provides={"a": 1})
        dependent = _Probe("dependent", needs=("a",))
        scope = CoeffectScope(ctx)
        scope.add(provider)
        scope.add(dependent)
        assert dependent.calls == ["dependent"]

        # Withdraw the base service: newest-first deactivation means each
        # entry reverts while "a" is still resolvable.
        resolutions: list[bool] = []
        orig_deactivate = scope._deactivate

        def _spying(entry: Any) -> None:
            resolutions.append(ctx.has("a"))
            orig_deactivate(entry)

        scope._deactivate = _spying  # type: ignore[method-assign]
        try:
            ctx.unprovide("a")
        finally:
            scope._deactivate = orig_deactivate  # type: ignore[method-assign]
        # Withdrawing a component-owned service retires its whole provider;
        # the consumer still tears down before the binding disappears.
        assert resolutions == [True, True]
        assert dependent.calls == ["dependent"]
        assert provider.calls == ["provider"]


class TestCliComponentNeeds:
    def test_default_needs_declares_cli_services(self) -> None:
        """CliComponent.apply resolves both services, so both are declared:
        withdrawing either deactivates every mounted component."""
        import typer

        from rebrew.plugin import CLI_SERVICE, CONSOLE_SERVICE, CliComponent, CoeffectScope, Context

        ctx = Context()
        app = typer.Typer()
        from rich.console import Console

        ctx.provide(CLI_SERVICE, app)
        ctx.provide(CONSOLE_SERVICE, Console())
        scope = CoeffectScope(ctx)
        comp = CliComponent(name="probe", module="rebrew.status", help="h", panel="Development")
        assert comp.needs == (CLI_SERVICE, CONSOLE_SERVICE)
        scope.add(comp)
        assert len(app.registered_commands) == 1
        ctx.unprovide(CONSOLE_SERVICE)
        assert app.registered_commands == []


class TestMidApplyFailure:
    def test_failed_apply_leaves_no_residue(self) -> None:
        """Effects installed before apply() raises belong to no live entry;
        _activate reverts them inline so nothing orphans."""

        class _Boom:
            needs: tuple[str, ...] = ()
            provides: tuple[str, ...] = ("half",)

            def apply(self, ctx: Context) -> None:
                ctx.provide("half", 1)
                raise RuntimeError("mid-apply failure")

        ctx = Context()
        scope = CoeffectScope(ctx)
        with pytest.raises(RuntimeError, match="mid-apply failure"):
            scope.add(_Boom())
        assert not ctx.has("half")
        assert [effect.key for effect in ctx._effects] == [None]
        assert scope.unresolved() == []


class TestCompositionLifecycle:
    @pytest.mark.parametrize("operation", ["remove", "close", "withdraw", "dispose"])
    def test_provider_retirement_cannot_interrupt_consumer_activation(self, operation: str) -> None:
        host = Context()
        provider = _Component(services=(("resource", object()),))
        providers = activate([provider], host)
        seen: list[Any] = []

        class _Consumer:
            needs = ("resource",)
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                ctx.effect(lambda: seen.append(ctx.resolve("resource")))
                with pytest.raises(ComponentError, match="activation"):
                    if operation == "remove":
                        providers.remove(provider)
                    elif operation == "close":
                        providers.close()
                    elif operation == "withdraw":
                        host.unprovide("resource")
                    else:
                        host.dispose()

        consumers = activate([_Consumer()], host)
        assert consumers.unresolved() == []
        assert host.has("resource") and not host.disposed
        providers.close()
        assert len(seen) == 1 and not host.has("resource")
        host.dispose()

    def test_rejected_close_preserves_remaining_cleanup_and_scope_can_close_later(self) -> None:
        host = Context()
        host.provide("base", 1)
        seen: list[int] = []
        views: list[Context] = []

        class _Consumer:
            needs = ("base",)
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                views.append(ctx)
                ctx.effect(lambda: seen.append(ctx.resolve("base")))

        scope = activate([_Consumer()], host)
        views[0].effect(scope.close)
        with pytest.raises(ComponentError, match="teardown"):
            host.unprovide("base")
        assert seen == [1] and views[0].disposed
        assert not host.has("base")
        scope.close()
        assert scope.unresolved() == []
        host.dispose()

    @pytest.mark.parametrize("fail_cleanup", [False, True])
    def test_cleanup_changes_settle_after_consumers_finish(self, fail_cleanup: bool) -> None:
        host = Context()
        host.provide("base", 1)
        seen: list[str] = []

        class _Consumer:
            needs = ("base", "resource")
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                def finish() -> None:
                    assert host.has("resource")
                    seen.append("consumer")
                    if fail_cleanup:
                        raise ValueError("cleanup failed")

                ctx.effect(finish)
                ctx.effect(lambda: host.provide("trigger", 1))

        class _Provider:
            needs = ("base",)
            provides = ("resource",)

            def apply(self, ctx: Context) -> None:
                ctx.provide("resource", object())
                ctx.effect(lambda: seen.append("provider"))

        class _Late:
            needs = ("trigger",)
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                seen.append("late")

        # The consumer's scope receives the host withdrawal first.
        activate([_Consumer()], host)
        activate([_Provider()], host)
        activate([_Late()], host)
        if fail_cleanup:
            with pytest.raises(ValueError, match="cleanup failed"):
                host.unprovide("base")
        else:
            host.unprovide("base")
        assert seen[0] == "consumer"
        assert sorted(seen[1:]) == ["late", "provider"]
        assert not host.has("resource")
        host.dispose()

    @pytest.mark.parametrize("separate_scopes", [False, True])
    @pytest.mark.parametrize(
        "operation", ["remove", "close", "remove_provider", "close_provider", "withdraw", "dispose"]
    )
    def test_cleanup_rejects_circular_teardown(self, separate_scopes: bool, operation: str) -> None:
        host = Context()
        host.provide("base", 1)
        seen: list[str] = []
        provider = _Component(services=(("resource", object()),))
        provider_scope = activate([provider], host)
        consumer_scope = CoeffectScope(host) if separate_scopes else provider_scope

        class _Consumer:
            needs = ("base", "resource")
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                def finish() -> None:
                    assert ctx.resolve("base") == 1
                    assert host.has("resource")
                    seen.append("finished")

                def circular() -> None:
                    with pytest.raises(ComponentError, match="teardown"):
                        if operation == "remove":
                            consumer_scope.remove(consumer)
                        elif operation == "close":
                            consumer_scope.close()
                        elif operation == "remove_provider":
                            provider_scope.remove(provider)
                        elif operation == "close_provider":
                            provider_scope.close()
                        elif operation == "withdraw":
                            host.unprovide("resource")
                        else:
                            host.dispose()

                ctx.effect(finish)
                ctx.effect(circular)

        consumer = _Consumer()
        consumer_scope.add(consumer)
        host.unprovide("base")
        assert seen == ["finished"]
        assert consumer_scope.unresolved() == [consumer]
        assert host.has("resource") and not host.disposed
        host.dispose()
        assert not host.has("resource")

    def test_close_during_apply_reverts_late_effects(self) -> None:
        ctx = Context()
        scope = CoeffectScope(ctx)
        log: list[str] = []

        class _Closes:
            needs: tuple[str, ...] = ()
            provides: tuple[str, ...] = ("late",)

            def apply(self, c: Context) -> None:
                scope.close()
                c.provide("late", 1)
                c.effect(lambda: log.append("off"))

        scope.add(_Closes())
        assert log == ["off"]
        assert not ctx.has("late")
        assert ctx._effects == []

    def test_cleanup_preserves_all_failures(self) -> None:
        ctx = Context()
        ctx.provide("service", 1)

        def _fail(message: str) -> None:
            raise RuntimeError(message)

        ctx.effect(lambda: _fail("first"))
        ctx.effect(lambda: _fail("second"))
        with pytest.raises(ExceptionGroup) as caught:
            ctx.dispose()
        assert [str(error) for error in caught.value.exceptions] == ["second", "first"]
        assert not ctx.has("service")

    def test_activation_and_cleanup_failures_are_both_reported(self) -> None:
        ctx = Context()

        class _Fail:
            needs: tuple[str, ...] = ()
            provides: tuple[str, ...] = ("half",)

            def apply(self, c: Context) -> None:
                c.provide("half", 1)

                def _cleanup() -> None:
                    raise ValueError("cleanup failed")

                c.effect(_cleanup)
                raise RuntimeError("apply failed")

        with pytest.raises(ExceptionGroup) as caught:
            activate([_Fail()], ctx)
        assert [str(error) for error in caught.value.exceptions] == [
            "apply failed",
            "cleanup failed",
        ]
        assert not ctx.has("half")
        assert ctx._effects == []

    def test_failed_composition_rolls_back_previously_active_components(self) -> None:
        ctx = Context()
        stable = _RevertibleComponent()

        class _Fail:
            needs: tuple[str, ...] = ()
            provides: tuple[str, ...] = ("half",)

            def apply(self, c: Context) -> None:
                c.provide("half", 1)
                raise RuntimeError("apply failed")

        with pytest.raises(RuntimeError, match="apply failed"):
            activate([stable, _Fail()], ctx)
        assert stable.log == ["on", "off"]
        assert not ctx.has("half")
        assert ctx._on_change == []

    def test_failed_provider_is_never_visible_to_other_scopes(self) -> None:
        ctx = Context()
        consumer = _RevertibleComponent(needs=("half",))
        activate([consumer], ctx)

        class _Fail:
            needs: tuple[str, ...] = ()
            provides: tuple[str, ...] = ("half",)

            def apply(self, c: Context) -> None:
                c.provide("half", 1)
                assert consumer.log == []
                raise RuntimeError("apply failed")

        with pytest.raises(RuntimeError, match="apply failed"):
            CoeffectScope(ctx).add(_Fail())
        assert consumer.log == []

    def test_successful_provider_commits_to_other_scopes(self) -> None:
        ctx = Context()
        consumer = _RevertibleComponent(needs=("service",))
        activate([consumer], ctx)

        class _Provider:
            needs: tuple[str, ...] = ()
            provides: tuple[str, ...] = ("service",)

            def apply(self, c: Context) -> None:
                c.provide("service", 1)
                assert consumer.log == []

        activate([_Provider()], ctx)
        assert consumer.log == ["on"]

    @pytest.mark.parametrize("operation", ["withdraw", "close", "dispose"])
    def test_transitive_teardown_keeps_dependencies_available(self, operation: str) -> None:
        ctx = Context()
        ctx.provide("base", 1)
        log: list[str] = []

        class _Provider:
            needs = ("base",)
            provides: tuple[str, ...] = ("middle",)

            def apply(self, c: Context) -> None:
                c.effect(lambda: log.append(f"provider:{c.resolve('base')}"))
                c.provide("middle", 2)

        class _Consumer:
            needs = ("middle",)
            provides: tuple[str, ...] = ()

            def apply(self, c: Context) -> None:
                c.effect(lambda: log.append(f"consumer:{c.resolve('middle')}"))

        # Registration order is the reverse of activation order.
        scope = activate([_Consumer(), _Provider()], ctx)
        if operation == "withdraw":
            ctx.unprovide("base")
        elif operation == "close":
            scope.close()
        else:
            ctx.dispose()
        assert log == ["consumer:2", "provider:1"]

    def test_cross_scope_teardown_precedes_provider_effects(self) -> None:
        ctx = Context()
        ctx.provide("base", 1)
        log: list[str] = []

        class _Provider:
            needs = ("base",)
            provides: tuple[str, ...] = ("middle",)

            def apply(self, c: Context) -> None:
                c.provide("middle", 2)
                c.effect(lambda: log.append("provider"))

        class _Consumer:
            needs = ("middle",)
            provides: tuple[str, ...] = ()

            def apply(self, c: Context) -> None:
                c.effect(lambda: log.append(f"consumer:{c.resolve('middle')}"))

        activate([_Provider()], ctx)
        activate([_Consumer()], ctx)
        ctx.unprovide("base")
        assert log == ["consumer:2", "provider"]

    def test_disposing_parent_disposes_descendants_before_services(self) -> None:
        parent = Context()
        parent.provide("base", 1)
        child = parent.fork()
        leaf = child.fork()
        log: list[int] = []
        leaf.effect(lambda: log.append(leaf.resolve("base")))
        parent.dispose()
        assert log == [1]
        assert child.disposed and leaf.disposed
        assert not leaf.has("base")

    def test_fork_created_by_component_is_owned(self) -> None:
        ctx = Context()
        ctx.provide("base", 1)
        children: list[Context] = []
        log: list[str] = []

        class _Parent:
            needs = ("base",)
            provides: tuple[str, ...] = ()

            def apply(self, c: Context) -> None:
                child = c.fork()
                children.append(child)
                child.effect(lambda: log.append("off"))

        activate([_Parent()], ctx)
        ctx.unprovide("base")
        assert log == ["off"]
        assert children[0].disposed

    def test_dispose_runs_remaining_cleanup_after_failure(self) -> None:
        ctx = Context()
        ctx.provide("service", 1)
        log: list[str] = []
        ctx.effect(lambda: log.append("first"))

        def _fail() -> None:
            raise RuntimeError("cleanup failed")

        ctx.effect(_fail)
        ctx.effect(lambda: log.append("last"))
        with pytest.raises(RuntimeError, match="cleanup failed"):
            ctx.dispose()
        assert log == ["last", "first"]
        assert not ctx.has("service")
        ctx.dispose()
        assert log == ["last", "first"]

    def test_cancelled_apply_rolls_back(self) -> None:
        ctx = Context()

        class _Cancelled:
            needs: tuple[str, ...] = ()
            provides: tuple[str, ...] = ("half",)

            def apply(self, c: Context) -> None:
                c.provide("half", 1)
                raise KeyboardInterrupt

        scope = CoeffectScope(ctx)
        with pytest.raises(KeyboardInterrupt):
            scope.add(_Cancelled())
        assert not ctx.has("half")

    def test_scope_on_disposed_context_leaves_no_callback(self) -> None:
        ctx = Context()
        ctx.dispose()
        with pytest.raises(ComponentError, match="disposed"):
            CoeffectScope(ctx)
        assert ctx._on_change == []

    def test_withdrawing_sibling_binding_does_not_deactivate_consumer(self) -> None:
        root = Context()
        left, right = root.fork(), root.fork()
        left.provide("service", "left")
        right.provide("service", "right")
        consumer = _RevertibleComponent(needs=("service",))
        activate([consumer], left)
        right.unprovide("service")
        assert consumer.log == ["on"]

    def test_parent_cannot_shadow_existing_descendant_binding(self) -> None:
        root = Context()
        root.fork().provide("service", 1)
        with pytest.raises(ComponentError, match="already provided"):
            root.provide("service", 2)


class TestConfinedContext:
    @pytest.mark.parametrize("operation", ["resolve", "has"])
    def test_child_must_declare_a_parents_provision(self, operation: str) -> None:
        host = Context()

        class _Child:
            needs: tuple[str, ...] = ()
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                with pytest.raises(ComponentError, match="undeclared"):
                    getattr(ctx, operation)("service")

        class _Parent:
            needs: tuple[str, ...] = ()
            provides = ("service",)

            def apply(self, ctx: Context) -> None:
                ctx.provide("service", 1)
                activate([_Child()], ctx)

        activate([_Parent()], host)
        host.dispose()

    def test_nested_consumer_of_late_parent_provision_drains_first(self) -> None:
        host = Context()
        seen: list[int] = []

        class _Child:
            needs = ("service",)
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                ctx.effect(lambda: seen.append(ctx.resolve("service")))

        class _Parent:
            needs: tuple[str, ...] = ()
            provides = ("service",)

            def apply(self, ctx: Context) -> None:
                activate([_Child()], ctx)
                ctx.provide("service", 1)

        activate([_Parent()], host)
        host.dispose()
        assert seen == [1]
        assert not host.has("service")

    def test_unloading_provider_excludes_all_provisions_from_new_activation(self) -> None:
        host = Context()
        late = _RevertibleComponent(needs=("second", "trigger"))

        class _Consumer:
            needs = ("first",)
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                ctx.effect(lambda: host.provide("trigger", 3))

        provider = _Component(services=(("first", 1), ("second", 2)))
        scope = activate([provider, _Consumer(), late], host)
        scope.remove(provider)
        assert late.log == []
        host.dispose()

    def test_scope_rejected_during_unload_leaves_no_callback(self) -> None:
        host = Context()
        host.provide("base", 1)
        views: list[Context] = []

        class _Consumer:
            needs = ("base",)
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                views.append(ctx)

                def reject() -> None:
                    with pytest.raises(ComponentError, match="unloading"):
                        CoeffectScope(ctx)

                ctx.effect(reject)

        activate([_Consumer()], host)
        host.unprovide("base")
        assert views[0]._on_change == []
        host.dispose()

    def test_failed_reactive_activation_does_not_strand_healthy_siblings(self) -> None:
        host = Context()
        calls: list[str] = []

        class _Broken:
            needs = ("base",)
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                calls.append("broken")
                raise RuntimeError("activation failed")

        healthy = _RevertibleComponent(needs=("base",))
        scope = activate([_Broken(), healthy], host)
        with pytest.raises(RuntimeError, match="activation failed"):
            host.provide("base", 1)
        assert healthy.log == ["on"] and scope.unresolved() == []
        host.provide("unrelated", 2)
        assert calls == ["broken"]
        host.dispose()
        assert healthy.log == ["on", "off"]

    def test_diverted_activation_reserves_provisions_until_rollback(self) -> None:
        host = Context()

        class _Diverted:
            needs: tuple[str, ...] = ()
            provides = ("service",)

            def apply(self, ctx: Context) -> None:
                ctx.dispose()
                with pytest.raises(ComponentError, match="reserved"):
                    host.provide("service", "replacement")
                ctx.provide("service", "late installation")

        scope = activate([_Diverted()], host)
        assert host._services == {} and host._reservations == {}
        assert scope.unresolved() == []
        host.provide("service", "replacement")
        assert host.resolve("service") == "replacement"
        host.dispose()

    def test_withdrawing_one_provision_retires_the_complete_provider(self) -> None:
        host = Context()
        views: list[Context] = []
        log: list[str] = []

        class _Provider:
            needs: tuple[str, ...] = ()
            provides = ("first", "second")

            def apply(self, ctx: Context) -> None:
                views.append(ctx)
                ctx.provide("first", 1)
                ctx.provide("second", 2)
                ctx.effect(lambda: log.append("provider"))

        scope = activate([_Provider()], host)
        host.unprovide("first")
        assert host._services == {} and host._reservations == {}
        assert log == ["provider"]
        assert views[0].disposed
        assert scope.unresolved() == []
        host.provide("unrelated", 3)
        assert log == ["provider"]

    def test_context_disposal_retires_its_own_instantiation(self) -> None:
        host = Context()
        views: list[Context] = []
        log: list[int] = []

        class _Repeated:
            needs: tuple[str, ...] = ()
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                index = len(views)
                views.append(ctx)
                ctx.effect(lambda: log.append(index))

        component = _Repeated()
        scope = activate([component, component], host)
        views[1].dispose()
        assert log == [1]
        assert not views[0].disposed and views[1].disposed
        scope.close()
        assert log == [1, 0]

    def test_replacing_provider_reactivates_consumer_even_for_equal_values(self) -> None:
        host = Context()
        old = _Component(services=(("service", 1),))
        new = _Component(services=(("service", 1),))
        consumer = _RevertibleComponent(needs=("service",))
        scope = activate([consumer, old], host)
        scope.remove(old)
        assert consumer.log == ["on", "off"]
        scope.add(new)
        assert consumer.log == ["on", "off", "on"]
        host.dispose()
        assert consumer.log == ["on", "off", "on", "off"]

    def test_activation_order_and_reload_history_reach_same_service_table(self) -> None:
        from itertools import permutations

        for order in permutations(range(3)):
            host = Context()
            host.provide("base", 1)
            components = (
                _Component(needs=("base",), services=(("first", 2),)),
                _Component(needs=("first",), services=(("second", 3),)),
                _Component(needs=("second",)),
            )
            scope = activate([components[index] for index in order], host)
            assert host._services == {"base": 1, "first": 2, "second": 3}
            assert scope.unresolved() == []
            host.unprovide("base")
            assert host._services == {}
            host.provide("base", 1)
            assert host._services == {"base": 1, "first": 2, "second": 3}
            assert scope.unresolved() == []
            host.dispose()
            assert host._services == {} and host._reservations == {}

    @pytest.mark.parametrize("operation", ["resolve", "has", "unprovide", "provide"])
    def test_sibling_services_are_inaccessible(self, operation: str) -> None:
        host = Context()
        host.provide("sibling", 1)
        views: list[Context] = []

        class _Component:
            needs: tuple[str, ...] = ()
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                views.append(ctx)

        scope = activate([_Component()], host)
        view = views[0]
        with pytest.raises(ComponentError):
            if operation == "provide":
                view.provide("sibling", 2)
            else:
                getattr(view, operation)("sibling")
        assert host.resolve("sibling") == 1
        scope.close()

    def test_provisions_are_reserved_before_activation_and_released_on_removal(self) -> None:
        host = Context()
        provider = _Component(needs=("missing",), services=(("service", 1),))
        scope = activate([provider], host)
        with pytest.raises(ComponentError, match="reserved"):
            CoeffectScope(host).add(_Component(services=(("service", 2),)))
        with pytest.raises(ComponentError, match="reserved"):
            host.provide("service", 3)
        scope.remove(provider)
        replacement = _Component(services=(("service", 4),))
        scope.add(replacement)
        assert host.resolve("service") == 4
        scope.remove(replacement)
        assert not host.has("service")
        host.provide("service", 5)
        scope.close()

    def test_missing_declared_provision_rolls_back(self) -> None:
        host = Context()
        log: list[str] = []

        class _Incomplete:
            needs: tuple[str, ...] = ()
            provides = ("first", "missing")

            def apply(self, ctx: Context) -> None:
                ctx.provide("first", 1)
                ctx.effect(lambda: log.append("off"))

        with pytest.raises(ComponentError, match="did not provide"):
            activate([_Incomplete()], host)
        assert log == ["off"]
        assert not host.has("first")
        assert host._children == [] and host._reservations == {}

    def test_committed_bindings_survive_cleanup_then_view_expires(self) -> None:
        host = Context()
        original = object()
        host.provide("service", original)
        views: list[Context] = []
        seen: list[Any] = []

        class _Consumer:
            needs = ("service",)
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                views.append(ctx)
                ctx.effect(lambda: seen.append(ctx.resolve("service")))
                ctx.effect(ctx.dispose)

        activate([_Consumer()], host)
        host.unprovide("service")
        assert seen == [original]
        with pytest.raises(ComponentError, match="disposed"):
            views[0].resolve("service")
        with pytest.raises(ComponentError, match="disposed"):
            views[0].effect(lambda: None)
        replacement = object()
        host.provide("service", replacement)
        assert views[1].resolve("service") is replacement
        host.dispose()

    def test_fork_cannot_bypass_declared_access(self) -> None:
        host = Context()
        host.provide("sibling", 1)

        class _Consumer:
            needs: tuple[str, ...] = ()
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                child = ctx.fork()
                with pytest.raises(ComponentError, match="undeclared"):
                    child.resolve("sibling")
                with pytest.raises(ComponentError, match="undeclared"):
                    child.has("sibling")

        activate([_Consumer()], host)
        host.dispose()

    @pytest.mark.parametrize("forked", [False, True])
    def test_nested_component_has_its_own_committed_view(self, forked: bool) -> None:
        host = Context()
        host.provide("parent", 1)
        host.provide("child", 2)
        log: list[str] = []

        class _Child:
            needs = ("child",)
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                assert ctx.resolve("child") == 2
                assert ctx.resolve("parent") == 1
                assert ctx.has("parent")
                ctx.effect(lambda: log.append(f"child:{ctx.resolve('child')}"))

        class _Parent:
            needs = ("parent",)
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                ctx.effect(lambda: log.append(f"parent:{ctx.resolve('parent')}"))
                activate([_Child()], ctx.fork() if forked else ctx)

        activate([_Parent()], host)
        host.unprovide("parent")
        assert log == ["child:2", "parent:1"]

    def test_later_effect_belongs_to_original_component(self) -> None:
        host = Context()
        host.provide("service", 1)
        views: list[Context] = []
        log: list[str] = []

        class _First:
            needs = ("service",)
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                views.append(ctx)

        class _Second:
            needs: tuple[str, ...] = ()
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                views[0].effect(lambda: log.append("first"))
                ctx.effect(lambda: log.append("second"))

        scope = activate([_First(), _Second()], host)
        host.unprovide("service")
        assert log == ["first"]
        scope.close()
        assert log == ["first", "second"]

    def test_self_disposal_retires_component(self) -> None:
        host = Context()
        calls: list[str] = []

        class _Retires:
            needs: tuple[str, ...] = ()
            provides: tuple[str, ...] = ()

            def apply(self, ctx: Context) -> None:
                calls.append("on")
                ctx.effect(lambda: calls.append("off"))
                ctx.dispose()

        scope = activate([_Retires()], host)
        host.provide("unrelated", 1)
        assert calls == ["on", "off"]
        assert scope.unresolved() == []
        assert host._children == []


class TestEntryPointComponents:
    def test_third_party_mounts_and_disposer_removes_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Entry-point-provided component: full mount → dispose → unmounted.

        DSH testing.md requires one dispose test per registration repaired or
        added; builtins have theirs (TestCliComponent), third-party plugins
        did not until now.
        """
        from types import SimpleNamespace

        import rebrew.plugin as plugin_mod

        fake_ep = SimpleNamespace(name="third", value="rebrew.diagnose", group="rebrew.commands")

        class _FakeEntryPoints:
            def select(self, *, group: str) -> list[Any]:
                return [fake_ep] if group == "rebrew.commands" else []

        monkeypatch.setattr("rebrew.registry.entry_points", lambda: _FakeEntryPoints())
        components, warnings = plugin_mod.entry_point_components(set())
        assert warnings == []
        assert [(c.name, c.origin) for c in components] == [("third", "entry-point")]
        app = typer.Typer()
        ctx = Context()
        ctx.provide(CLI_SERVICE, app)
        ctx.provide(CONSOLE_SERVICE, Console(stderr=True))
        activate(components, ctx)
        assert [c.name for c in app.registered_commands] == ["third"]
        ctx.dispose()
        assert app.registered_commands == []

    def test_duplicate_name_warns_and_keeps_builtin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from types import SimpleNamespace

        import rebrew.plugin as plugin_mod

        fake_ep = SimpleNamespace(name="status", value="rebrew.status", group="rebrew.commands")

        class _FakeEntryPoints:
            def select(self, *, group: str) -> list[Any]:
                return [fake_ep] if group == "rebrew.commands" else []

        monkeypatch.setattr("rebrew.registry.entry_points", lambda: _FakeEntryPoints())
        components, warnings = plugin_mod.entry_point_components({"status"})
        assert components == []
        assert len(warnings) == 1 and "status" in warnings[0]
