"""plugin.py — component/context runtime for spatiotemporal composability.

Implements the composition discipline of Cordis (Shi, Zhang & Cui, "A
Programming Paradigm for Spatiotemporal Composability", arXiv:2608.25512) at
rebrew's composition points.  A unit of functionality is a *component*:

* it publishes services under stable keys in a :class:`Context` and reaches
  sibling services by key rather than importing an implementation;
* it declares the services it needs (its *coeffects*) in ``needs``, and the
  runtime reacts to their availability: :class:`CoeffectScope` re-classifies
  every change to the service table against each component's ``needs``
  (Definition 22), activating the component when the specification becomes
  satisfied and deactivating it when a needed service is withdrawn — so
  activation order falls out of the declaration instead of a hand-maintained
  sequence; and
* every change it makes is an *effect* with an inverse the context holds, run
  in reverse on disposal (Theorem 16), so deactivation reverts exactly what the
  component added and leaves its siblings' effects interleaved but untouched.

``provides`` reserves a component's service keys before activation. Components
receive a scoped Context with a committed dependency view (Definition 55 and
Algorithm 6); it permits declared access and ownership-based withdrawal and
expires after teardown. Python plugins are trusted: external mutations still
require correct, independent inverses, as CLI registrations have. The runtime
checks the context API rather than sandboxing arbitrary Python or proving the
paper's commutativity premises for user-supplied callbacks.

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

import contextlib
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from functools import partial
from typing import Any, Protocol, override, runtime_checkable

import typer
from rich.console import Console
from rich.markup import escape

from rebrew.cli import EXIT_ERROR
from rebrew.errors import RebrewError
from rebrew.registry import Registration, RegistryError, import_registration

Disposer = Callable[[], None]


def _run_cleanup(disposers: Iterable[Disposer]) -> None:
    """Attempt every inverse, preserving failures after the remaining cleanup."""
    errors: list[BaseException] = []
    for dispose in disposers:
        try:
            dispose()
        except BaseException as exc:
            # Cancellation must not strand the rest of an inverse accumulator.
            errors.append(exc)
    _raise_errors(errors)


def _raise_errors(errors: list[BaseException]) -> None:
    """Preserve one failure or report all failures from independent operations."""
    if len(errors) == 1:
        raise errors[0]
    if errors:
        raise BaseExceptionGroup("component cleanup failed", errors)


def _rollback(dispose: Disposer, failure: BaseException) -> None:
    """Keep the original failure when rollback also raises."""
    try:
        dispose()
    except BaseException as cleanup:
        raise BaseExceptionGroup(
            "component activation and rollback failed", [failure, cleanup]
        ) from None


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


class ComponentError(RebrewError, RuntimeError):
    """A component violates declaration, access, ownership, or lifecycle contracts."""


@dataclass
class _Effect:
    """One tracked context transformation: its inverse, and the key it binds.

    ``key`` is set for a service provision, whose inverse is the restriction of
    that key (Definition 20: ``set(k, v)`` has inverse ``σ ↦ σ ∖ k``), so the
    provision can be undone on its own while the other effects are retained.
    ``armed`` is the once-guard: ``revert`` fires the inverse at most once, so
    overlapping teardown paths (context dispose and scope close) cannot run it
    twice.
    """

    dispose: Disposer
    key: str | None = None
    armed: bool = True

    def revert(self) -> None:
        if not self.armed:
            return
        self.armed = False
        self.dispose()


class Context:
    """The unified effect and coeffect context (the context paradigm).

    One type carries both halves of the paradigm:

    * the *coeffect* half is the service table components resolve by key;
    * the *effect* half is the accumulator of inverses, held in registration
      order and run in reverse, so disposal reverts exactly what was installed.

    A provision is an effect: ``provide`` records the restriction of its key as
    the inverse, and ``unprovide`` runs that inverse alone.  Every change to the
    table notifies the attached :class:`CoeffectScope`, which is what makes the
    coeffects reactive.  ``_owners`` is an activation stack: each entry
    collects the effects one activation installs so they can be reverted
    as a group.
    """

    def __init__(self, parent: Context | None = None) -> None:
        self._parent = parent
        self._children: list[Context] = []
        self._services: dict[str, Any] = {}
        self._withdrawing: set[str] = set()
        self._pending: set[str] = set()
        self._reservations: dict[str, _Entry] = {}
        self._effects: list[_Effect] = []
        self._owners: list[list[_Effect]] = []
        self._activating_needs: list[tuple[str, ...]] = []
        self._disposed = False
        self._on_change: list[Callable[[], None]] = []
        self._parent_effect: _Effect | None = None

    # -- coeffect half: the dependency table --------------------------------

    def provide(self, key: str, value: Any) -> None:
        """Bind *value* at *key*; the binding is an effect.

        The key may not already be bound in this context or any enclosing one
        (single-source disjointness: a fork that shadowed a parent key would
        silently multiplex one key to two values).  The inverse is the
        restriction of the key, recorded on the accumulator, so ``unprovide``
        or disposal withdraws the binding.
        """
        if self._disposed:
            raise ComponentError("context is disposed; cannot provide services")
        for ctx in self._scope_chain():
            reservation = ctx._reservations.get(key)
            if reservation is not None and not (
                reservation.view is not None
                and any(owner is reservation.view._effects for owner in self._owners)
            ):
                raise ComponentError(f"service {key!r} is reserved by a component")
        if self.has(key) or any(key in child._services for child in self._descendants()):
            raise ComponentError(f"service {key!r} is already provided")
        self._services[key] = value
        self._record(_Effect(dispose=self._restrict(key), key=key))
        self._changed()

    def unprovide(self, key: str) -> None:
        """Withdraw *key*, retiring its provider when component-owned.

        Dependents deactivate first: every scope on the chain reverts entries
        needing *key* while the binding is still resolvable, so no component
        reverts against a half-withdrawn table (Theorem 70).
        """
        if key not in self._services:
            raise ComponentError(f"service {key!r} is not provided")
        self._guard_withdrawal(key)
        reservation = self._reservations.get(key)
        if reservation is not None and reservation.view is not None:
            reservation.view.dispose()
            return
        for effect in self._effects:
            if effect.key == key:
                self._forget(effect)
                effect.revert()
                break

    def _begin_withdrawal(self, key: str) -> None:
        """Hide a binding from new activations, then drain its actual consumers."""
        if key in self._withdrawing:
            return
        self._withdrawing.add(key)
        disposers: list[Disposer] = []
        for ctx in self._scope_chain():
            for callback in list(ctx._on_change):
                scope = getattr(callback, "__self__", None)
                if isinstance(scope, CoeffectScope) and scope._ctx._binding_context(key) is self:
                    disposers.append(partial(scope._withdraw_key, key))
        _run_cleanup(disposers)

    def _guard_withdrawal(self, key: str) -> None:
        """Keep a binding alive through a synchronous consumer transition."""
        if any(
            ctx._binding_context(key) is self and key in needs
            for ctx in self._scope_chain()
            for needs in ctx._activating_needs
        ):
            raise ComponentError(
                f"cannot withdraw service {key!r} during activation of its consumer"
            )
        if any(
            isinstance(ctx, _ComponentContext)
            and ctx._unloading
            and not ctx.disposed
            and key in ctx._committed
            and ctx._host._binding_context(key) is self
            for ctx in self._scope_chain()
        ):
            raise ComponentError(f"cannot withdraw service {key!r} during consumer teardown")

    def _guard_disposal(self) -> None:
        """Keep an enclosing lifetime alive until its current inverse returns."""
        if any(
            isinstance(ctx, _ComponentContext) and ctx._unloading and not ctx.disposed
            for ctx in (self, *self._descendants())
        ):
            raise ComponentError("cannot dispose an enclosing context during component teardown")
        for ctx in (self, *self._descendants()):
            for key in ctx._services:
                ctx._guard_withdrawal(key)

    def _restrict(self, key: str) -> Disposer:
        """The inverse of binding *key*: drop it from this context's table."""

        def dispose() -> None:
            def restrict() -> None:
                self._services.pop(key, None)
                self._withdrawing.discard(key)
                self._changed()

            _run_cleanup((lambda: self._begin_withdrawal(key), restrict))

        return dispose

    def resolve(self, key: str) -> Any:
        """Return the service under *key*, searching enclosing contexts."""
        if key in self._services:
            return self._services[key]
        if self._parent is not None:
            return self._parent.resolve(key)
        raise ComponentError(f"service {key!r} is not provided")

    def has(self, key: str) -> bool:
        if key in self._services:
            return True
        return self._parent is not None and self._parent.has(key)

    def _binding_context(self, key: str) -> Context | None:
        if key in self._services:
            return self
        return self._parent._binding_context(key) if self._parent is not None else None

    def _storage(self) -> Context:
        return self

    def _available(self, key: str) -> bool:
        owner = self._binding_context(key)
        reservation = owner._reservations.get(key) if owner is not None else None
        provider = reservation.view if reservation is not None else None
        return (
            owner is not None
            and not owner._disposed
            and key not in owner._withdrawing
            and key not in owner._pending
            and (provider is None or not (provider._unloading or provider._retired))
        )

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
        """A derived context that resolves services through this one.

        The fork is registered as a child so table changes and withdrawals
        on this context reach scopes attached below it (Definition 22
        covers every context that can resolve the key, not just the
        nearest).  Disposing the fork detaches it.
        """
        if self._disposed:
            raise ComponentError("context is disposed; cannot fork")
        child = Context(parent=self)
        self._children.append(child)
        effect = _Effect(dispose=child.dispose)
        child._parent_effect = effect
        self._record(effect)
        return child

    # ponytail: no isolation realms or service interception (paper Def 24-27);
    # fork() shares the parent's table. Add isolate()/intercept() when a
    # component needs a private service view or a proxied dependency.

    @property
    def disposed(self) -> bool:
        return self._disposed

    def dispose(self) -> None:
        """Revert every effect in reverse registration order."""
        if self._disposed:
            return
        self._guard_disposal()
        self._disposed = True
        if self._parent is not None:
            # A disposed fork must not stay reachable from its parent.
            _remove_identity(self._parent._children, self)
            if self._parent_effect is not None:
                self._parent._forget(self._parent_effect)
                self._parent_effect.armed = False
        # Keep scopes reachable until teardown finishes: a provider must
        # still find its consumers while its accumulator is being reverted.
        scopes = [
            scope
            for callback in self._on_change
            if isinstance(scope := getattr(callback, "__self__", None), CoeffectScope)
        ]

        def revert_effects() -> None:
            def inverses() -> Iterator[Disposer]:
                while self._effects:
                    yield self._effects.pop().revert

            _run_cleanup(inverses())

        try:
            _run_cleanup(
                [child.dispose for child in reversed(self._children)]
                + [scope.close for scope in reversed(scopes)]
                + [revert_effects]
            )
        finally:
            self._on_change.clear()
            self._parent = None

    def _descendants(self) -> Iterator[Context]:
        for child in self._children:
            yield child
            yield from child._descendants()

    def _scope_chain(self) -> Iterator[Context]:
        """Yield this context, its enclosing contexts, and every derived context.

        One visited-guarded traversal: both a table change (``_changed``) and
        a withdrawal (``unprovide``) must reach every scope whose components
        resolve through this chain, in either direction (Definition 22).
        """
        visited: set[int] = set()
        stack: list[Context | None] = [self]
        while stack:
            ctx = stack.pop()
            if ctx is None or id(ctx) in visited:
                continue
            visited.add(id(ctx))
            yield ctx
            stack.append(ctx._parent)
            stack.extend(ctx._children)

    def _changed(self) -> None:
        """A service table change: hand it to every attached scope.

        Definition 22 classifies every change against every specification, so
        every scope on the enclosing chain and below this context reclassifies
        — not just the nearest.
        """
        callbacks: list[Disposer] = []
        seen: set[int] = set()
        for ctx in self._scope_chain():
            for callback in list(ctx._on_change):
                if id(callback) not in seen:
                    seen.add(id(callback))
                    callbacks.append(callback)
        _run_cleanup(callbacks)


@runtime_checkable
class Component(Protocol):
    """Anything the loader can activate.

    ``needs`` is the coeffect specification: the service keys that must be
    available before ``apply`` runs (Definition 21).  ``apply`` installs the
    component's effects on its scoped context. ``provides`` reserves the keys
    it owns (Definition 48); successful activation installs all of them
    (Definition 76). The scope records effects so deactivation reverts those
    alone. Retained contexts reject access after their activation ends.
    """

    needs: tuple[str, ...]
    provides: tuple[str, ...]

    def apply(self, ctx: Context) -> None: ...


@dataclass
class _Entry:
    """A registered component and the effects of its current activation."""

    component: Component
    needs: tuple[str, ...]
    provides: tuple[str, ...]
    view: _ComponentContext | None = None
    #: The effects ``apply`` installed, or ``None`` while the component is
    #: inactive (its specification is unsatisfied).
    effects: list[_Effect] | None = None


class _ComponentContext(Context):
    """An activation's declared access, committed bindings, and own effects.

    This checks the public context API; Python plugins remain trusted code.
    A disposer must undo its own changes to a resolved service, as CLI mounts
    do by removing their exact registration rather than resetting the app.
    """

    def __init__(self, scope: CoeffectScope, entry: _Entry) -> None:
        super().__init__(parent=scope._ctx)
        self._scope = scope
        self._entry = entry
        self._host = scope._ctx._storage()
        self._committed = {
            key: owner._services[key]
            for key in entry.needs
            if (owner := scope._ctx._binding_context(key)) is not None
        }
        self._installing = True
        self._unloading = False
        self._retired = False
        scope._ctx._children.append(self)

    @override
    def _storage(self) -> Context:
        return self._host

    @override
    def _binding_context(self, key: str) -> Context | None:
        return self._host._binding_context(key)

    @override
    def resolve(self, key: str) -> Any:
        if self.disposed:
            raise ComponentError("component context is disposed; cannot resolve services")
        if key in self._committed:
            return self._committed[key]
        if key in self._entry.provides:
            return self._host.resolve(key)
        ancestor = self._parent
        while ancestor is not None:
            if isinstance(ancestor, _ComponentContext) and key in ancestor._entry.needs:
                return ancestor.resolve(key)
            ancestor = ancestor._parent
        raise ComponentError(f"service {key!r} is undeclared by this component")

    @override
    def has(self, key: str) -> bool:
        if self.disposed:
            raise ComponentError("component context is disposed; cannot read services")
        if key in self._committed:
            return True
        if key in self._entry.provides:
            return self._host.has(key)
        ancestor = self._parent
        while ancestor is not None:
            if isinstance(ancestor, _ComponentContext) and key in ancestor._entry.needs:
                return ancestor.has(key)
            ancestor = ancestor._parent
        raise ComponentError(f"service {key!r} is undeclared by this component")

    @override
    def provide(self, key: str, value: Any) -> None:
        if self.disposed or self._unloading:
            raise ComponentError("component context is disposed; cannot provide services")
        if key not in self._entry.provides:
            raise ComponentError(f"service {key!r} is an undeclared provision")
        if self._installing:
            self._host._pending.add(key)
        self._host._owners.append(self._effects)
        try:
            self._host.provide(key, value)
        finally:
            self._host._owners.pop()

    @override
    def unprovide(self, key: str) -> None:
        if self.disposed:
            raise ComponentError("component context is disposed; cannot withdraw services")
        if not any(effect.key == key and effect.armed for effect in self._effects):
            raise ComponentError(f"service {key!r} is not owned by this component")
        self.dispose()

    @override
    def dispose(self) -> None:
        if not self.disposed and not self._retired and not self._unloading:
            self._scope._remove_entry(self._entry)

    @override
    def _record(self, effect: _Effect) -> None:
        if self._unloading and not self.disposed:
            raise ComponentError("component context is unloading; cannot install effects")
        super()._record(effect)

    @override
    def fork(self) -> Context:
        if self._unloading and not self.disposed:
            raise ComponentError("component context is unloading; cannot fork")
        return super().fork()

    def _finish(self) -> None:
        self._disposed = True
        self._host._pending.difference_update(self._entry.provides)
        self._committed.clear()
        self._effects.clear()
        if self._parent is not None:
            _remove_identity(self._parent._children, self)
            self._parent = None


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
        if ctx.disposed:
            raise ComponentError("context is disposed; cannot attach a scope")
        self._ctx = ctx
        self._entries: list[_Entry] = []
        self._settling = False
        self._bulk = False
        self._closed = False
        # Disposing the context closes every registration owned by this scope.
        ctx.effect(self.close)
        self._lifetime_effect = ctx._effects[-1]
        ctx._on_change.append(self._classify)

    def add(self, component: Component) -> None:
        """Register *component*; it activates as soon as its needs are met."""
        if self._closed:
            return
        for field in ("needs", "provides"):
            keys = getattr(component, field, None)
            if not isinstance(keys, tuple) or not all(isinstance(key, str) and key for key in keys):
                raise ComponentError(f"component {field} must be a tuple of nonempty service keys")
            if len(set(keys)) != len(keys):
                raise ComponentError(f"component {field} contains duplicate service keys")
        entry = _Entry(
            component=component, needs=tuple(component.needs), provides=tuple(component.provides)
        )
        storage = self._ctx._storage()
        for key in entry.provides:
            if storage._binding_context(key) is not None or any(
                key in ctx._reservations or key in ctx._services for ctx in storage._scope_chain()
            ):
                raise ComponentError(f"service {key!r} is already provided or reserved")
        for key in entry.provides:
            storage._reservations[key] = entry
        self._entries.append(entry)
        # A bulk registration runs one classify pass instead of one per
        # component: activation cascades are already resolved by the loop
        # inside _classify, so per-add passes are quadratic for nothing.
        if not self._bulk and not self._settling:
            self._classify()

    def remove(self, component: Component) -> None:
        """Retire one registration by identity and revert its activation."""
        for entry in self._entries:
            if entry.component is component:
                self._remove_entry(entry)
                return

    def _remove_entry(self, entry: _Entry) -> None:
        self._guard_teardown((entry,))
        if entry.view is not None:
            entry.view._retired = True
        _remove_identity(self._entries, entry)
        try:
            self._deactivate(entry)
        finally:
            self._release(entry)

    def unresolved(self) -> list[Component]:
        """Registered components whose specification is still unsatisfied."""
        return [entry.component for entry in self._entries if entry.effects is None]

    def close(self) -> None:
        """Deactivate every entry, newest first."""
        if self._closed:
            return
        self._guard_teardown(self._entries)
        self._closed = True
        self._settling = True
        try:
            _run_cleanup(partial(self._deactivate, entry) for entry in reversed(self._entries))
        finally:
            with contextlib.suppress(ValueError):
                self._ctx._on_change.remove(self._classify)
            for entry in self._entries:
                self._release(entry)
            self._entries.clear()
            self._settling = False
            self._ctx._forget(self._lifetime_effect)
            self._lifetime_effect.armed = False

    def _guard_teardown(self, entries: Iterable[_Entry]) -> None:
        """Reject synchronous retirement that would interrupt a running inverse."""
        for entry in entries:
            if entry.view is not None:
                entry.view._guard_disposal()
            for key in entry.provides:
                self._ctx._storage()._guard_withdrawal(key)

    def _release(self, entry: _Entry) -> None:
        if entry.view is not None and entry.view._installing:
            # A diverted activation still owns its provisions until rollback.
            return
        reservations = self._ctx._storage()._reservations
        for key in entry.provides:
            if reservations.get(key) is entry:
                del reservations[key]

    def _satisfied(self, needs: tuple[str, ...]) -> bool:
        ctx: Context | None = self._ctx
        while ctx is not None:
            if ctx.disposed or (
                isinstance(ctx, _ComponentContext) and (ctx._unloading or ctx._retired)
            ):
                return False
            ctx = ctx._parent
        return all(self._ctx._available(key) for key in needs)

    def _withdraw_key(self, key: str) -> None:
        """Deactivate every active entry needing *key*, newest first.

        Called by ``unprovide`` before the binding is withdrawn, so each
        dependent reverts while the service is still resolvable.
        """
        settling = self._settling
        self._settling = True
        try:
            _run_cleanup(
                partial(self._deactivate, entry)
                for entry in reversed(self._entries)
                if entry.effects is not None and key in entry.needs
            )
        finally:
            self._settling = settling

    def _classify(self) -> None:
        """Drive activation and deactivation from the current satisfaction.

        Activating one component may provide a service another is waiting on,
        so the pass repeats until no specification changes status.  Reentrant
        calls (a change made while classifying) are absorbed into that loop.
        Before a provider's inverses run, _revert drains the actual consumers
        of its bindings across scopes. That dependency order is independent
        of registration order (Theorem 70).
        """
        if self._closed or self._settling:
            return
        # Table changes made by an inverse settle after that teardown finishes.
        # Reentering another scope now could unload its provider underneath the
        # current consumer, whose effects have already left its entry.
        if any(
            isinstance(ctx, _ComponentContext) and ctx._unloading and not ctx.disposed
            for ctx in self._ctx._scope_chain()
        ):
            return
        self._settling = True
        errors: list[BaseException] = []
        try:
            changed = True
            while changed and not self._closed:
                changed = False
                for entry in self._entries:
                    if self._closed:
                        break
                    satisfied = self._satisfied(entry.needs)
                    if satisfied and entry.effects is None:
                        try:
                            entry.effects = self._activate(entry)
                        except BaseException as exc:
                            _remove_identity(self._entries, entry)
                            self._release(entry)
                            errors.append(exc)
                            changed = True
                            break
                        try:
                            self._ctx._changed()
                        except BaseException as exc:
                            errors.append(exc)
                        changed = True
                for entry in reversed(self._entries):
                    if entry.effects is not None and not self._satisfied(entry.needs):
                        try:
                            self._deactivate(entry)
                        except BaseException as exc:
                            errors.append(exc)
                        changed = True
        finally:
            self._settling = False
        _raise_errors(errors)

    def _activate(self, entry: _Entry) -> list[_Effect]:
        view = _ComponentContext(self, entry)
        entry.view = view
        owned = view._effects
        self._ctx._activating_needs.append(entry.needs)
        try:
            entry.component.apply(view)
            if self._closed or self._ctx.disposed or view._retired:
                view._unloading = True
                _run_cleanup((lambda: self._revert(owned), view._finish, self._ctx._changed))
            else:
                missing = set(entry.provides) - {
                    effect.key for effect in owned if effect.armed and effect.key is not None
                }
                if missing:
                    raise ComponentError(
                        f"component did not provide declared services: {sorted(missing)}"
                    )
                view._host._pending.difference_update(entry.provides)
        except BaseException as exc:
            # A mid-apply failure must not leave orphaned residue: effects
            # already installed belong to no live entry (entry.effects stays
            # None), so no later deactivation would revert them. Revert here.
            view._unloading = True
            try:
                _rollback(
                    lambda: _run_cleanup(
                        (lambda: self._revert(owned), view._finish, self._ctx._changed)
                    ),
                    exc,
                )
            finally:
                view._finish()
            raise
        finally:
            self._ctx._activating_needs.pop()
            view._installing = False
            if view._retired:
                self._release(entry)
        return owned

    def _deactivate(self, entry: _Entry) -> None:
        if entry.view is not None and entry.view._installing:
            entry.view._retired = True
            return
        effects = entry.effects or []
        entry.effects = None
        if entry.view is not None:
            entry.view._unloading = True
        _run_cleanup(
            [lambda: self._revert(effects)]
            + ([entry.view._finish] if entry.view is not None else [])
            + [self._ctx._changed]
        )

    def _revert(self, effects: list[_Effect]) -> None:
        """Drain dependents before any of their provider's inverses run."""

        def revert(effect: _Effect) -> None:
            self._ctx._storage()._forget(effect)
            effect.revert()

        _run_cleanup(
            [
                partial(self._ctx._storage()._begin_withdrawal, effect.key)
                for effect in effects
                if effect.key is not None and effect.armed
            ]
            + [partial(revert, effect) for effect in reversed(effects)]
        )


def activate(components: Iterable[Component], ctx: Context) -> CoeffectScope:
    """Activate every component whose declared services are available.

    The startup composition registers each component on a
    :class:`CoeffectScope`. Components with unavailable declared services stay
    inactive; a later provision activates them. The returned scope remains
    reactive, and closing it reverts every active component.
    """
    scope = CoeffectScope(ctx)
    scope._bulk = True
    try:
        for component in components:
            scope.add(component)
        scope._bulk = False
        scope._classify()
    except BaseException as exc:
        _rollback(scope.close, exc)
        raise
    finally:
        scope._bulk = False
    return scope


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


def make_stub_command(module: str, error: Exception, console: Console) -> Callable[[], None]:
    """A command callable that reports why its module could not be loaded."""

    def _stub() -> None:
        console.print(f"[red]error:[/red] could not load '{escape(module)}': {escape(str(error))}")
        raise typer.Exit(code=EXIT_ERROR)

    return _stub


def make_stub_app(module: str, error: Exception, console: Console) -> typer.Typer:
    """A Typer app that reports a component that could not be loaded."""
    stub = typer.Typer(help=f"[unavailable] {module}")
    stub.callback(invoke_without_command=True)(make_stub_command(module, error, console))
    return stub


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
    # Every apply() resolves CLI_SERVICE + CONSOLE_SERVICE, so every
    # component declares them: withdrawing either service deactivates its
    # dependents instead of leaving them mounted on a stale app.
    needs: tuple[str, ...] = (CLI_SERVICE, CONSOLE_SERVICE)
    provides: tuple[str, ...] = ()

    @property
    def group(self) -> str:
        return MULTI_COMMANDS_GROUP if self.is_group else COMMANDS_GROUP

    @override
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
            if self.is_group:
                self._mount_group(app, console, obj, ctx)
            else:
                self._mount_command(app, console, obj, ctx)
        except RegistryError as exc:
            self._mount_unavailable(app, console, exc, ctx)

    def _bad_plugin(self, detail: str) -> RegistryError:
        return RegistryError(
            f"bad CLI plugin {self.name!r} from {self.origin} ({self.module}): {detail}",
            group=self.group,
            name=self.name,
            origin=self.origin,
        )

    def _plugin_attribute(self, obj: Any, name: str) -> Any:
        """Inspect an export before mounting, retaining the unavailable fallback."""
        try:
            return getattr(obj, name, None)
        except Exception as exc:
            raise self._bad_plugin(f"cannot read {name!r} ({type(exc).__name__}: {exc})") from exc

    def _mount_group(self, app: typer.Typer, console: Console, obj: Any, ctx: Context) -> None:
        group_app = obj if isinstance(obj, typer.Typer) else self._plugin_attribute(obj, "app")
        if not isinstance(group_app, typer.Typer):
            self._mount_unavailable(
                app,
                console,
                self._bad_plugin(f"expected a typer.Typer app, got {type(obj).__name__}"),
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
            doc = self._plugin_attribute(obj, "__doc__")
            help_text = (doc if isinstance(doc, str) and doc else self.help).strip()
            epilog = None
        else:
            command = self._plugin_attribute(obj, "main")
            module_app = self._plugin_attribute(obj, "app")
            if not callable(command) or not isinstance(module_app, typer.Typer):
                self._mount_unavailable(
                    app,
                    console,
                    self._bad_plugin("module exposes no callable 'main' and a typer app"),
                    ctx,
                )
                return
            help_text = _app_help(module_app, self.help)
            epilog = _app_epilog(module_app)
        if not callable(command):
            self._mount_unavailable(
                app,
                console,
                self._bad_plugin(f"expected a callable, got {type(command).__name__}"),
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


def entry_point_components(existing: set[str]) -> tuple[list[CliComponent], list[str]]:
    """Third-party CLI components from the plugin entry-point groups.

    Returns ``(components, warnings)``: duplicate names (a plugin must not
    shadow a built-in) come back as data — discovery runs before any context
    exists, so the caller prints them through CONSOLE_SERVICE.  Malformed
    registrations keep degrading to an ``[unavailable]`` stub, so one broken
    plugin never takes the CLI down.
    """
    from rebrew.registry import entry_point_registrations

    components: list[CliComponent] = []
    warnings: list[str] = []
    for group, is_group in ((COMMANDS_GROUP, False), (MULTI_COMMANDS_GROUP, True)):
        for registration in entry_point_registrations(group):
            if registration.name in existing:
                warnings.append(
                    f"duplicate CLI command {registration.name!r} from "
                    f"{registration.origin} ignored (name already registered)"
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
    return components, warnings


__all__ = [
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
