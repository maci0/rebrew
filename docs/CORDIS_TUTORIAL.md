# Cordis component tutorial

Build a service provider and a command registration, replace the provider,
then tear down their contributions. This example uses only the public
`rebrew.plugin` API and a small in-memory command book. It needs no binary,
project config, Docker image, or network connection.

For concepts and exact API behavior, read the [Cordis guide](CORDIS.md).
The real CLI uses Typer registrations through `CliComponent`; the same
ownership rule applies to both.

## Run the example

From an installed contributor checkout ([setup](DEVELOPMENT.md)), save the following block as
`/tmp/rebrew_cordis_demo.py`, then run:

```bash
uv run --frozen python /tmp/rebrew_cordis_demo.py
```

```python
"""Demonstrate owned component lifetimes without external services."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import cast

from rebrew.plugin import Context, activate


@dataclass
class CommandBook:
    commands: dict[str, Callable[[], str]] = field(default_factory=dict)


@dataclass
class GreetingProvider:
    message: str
    needs: tuple[str, ...] = ()
    provides: tuple[str, ...] = ("greeting",)

    def apply(self, ctx: Context) -> None:
        ctx.provide("greeting", self.message)


@dataclass
class GreetingCommand:
    events: list[str]
    needs: tuple[str, ...] = ("commands", "greeting")
    provides: tuple[str, ...] = ()

    def apply(self, ctx: Context) -> None:
        book = cast(CommandBook, ctx.resolve("commands"))
        message = cast(str, ctx.resolve("greeting"))
        if "hello" in book.commands:
            raise ValueError("hello is already registered")

        def hello() -> str:
            return f"{message}, Rebrew!"

        book.commands["hello"] = hello

        def undo() -> None:
            if book.commands.get("hello") is hello:
                del book.commands["hello"]
            # Committed dependencies remain readable during cleanup.
            self.events.append(f"unmounted:{ctx.resolve('greeting')}")

        ctx.effect(undo)
        self.events.append(f"mounted:{message}")


def main() -> None:
    host = Context()
    book = CommandBook()

    def unrelated() -> str:
        return "another owner's command"

    book.commands["other"] = unrelated
    events: list[str] = []
    command = GreetingCommand(events)
    host.provide("commands", book)

    try:
        scope = activate([command], host)
        assert scope.unresolved() == [command]
        assert "hello" not in book.commands
        print(f"waiting: {len(scope.unresolved())}")

        original = GreetingProvider("Hello")
        scope.add(original)
        assert scope.unresolved() == []
        print(book.commands["hello"]())

        scope.remove(original)
        assert scope.unresolved() == [command]
        assert "hello" not in book.commands
        print(f"after removal: {len(scope.unresolved())} waiting")

        replacement = GreetingProvider("Welcome back")
        scope.add(replacement)
        assert scope.unresolved() == []
        print(book.commands["hello"]())

        scope.close()
        scope.close()  # Teardown is idempotent.
        assert "hello" not in book.commands
        assert not host.has("greeting")
        assert book.commands["other"] is unrelated
        print(f"remaining: {','.join(book.commands)}")
        print("events: " + " -> ".join(events))
    finally:
        host.dispose()

    host.dispose()
    assert host.disposed and not host.has("commands")


if __name__ == "__main__":
    main()
```

Expected stdout:

```text
waiting: 1
Hello, Rebrew!
after removal: 1 waiting
Welcome back, Rebrew!
remaining: other
events: mounted:Hello -> unmounted:Hello -> mounted:Welcome back -> unmounted:Welcome back
```

## Follow the lifetime

1. The host supplies `commands`. `GreetingCommand` also needs `greeting`, so
   registration leaves it waiting and performs no command-book mutation.
2. `GreetingProvider` reserves and installs `greeting`. Its successful
   activation makes that binding available, allowing the command to mount.
3. Removing the provider first unmounts its dependent command. The command's
   inverse can resolve the original greeting during cleanup. Provider
   retirement then removes the binding and releases its reservation.
4. Adding the replacement creates a new provider binding and a new command
   activation. The waiting command uses the replacement's message.
5. Closing the scope drains the new command and provider. The unrelated
   registration survives because the inverse removes only its own callable.
   Host disposal then withdraws the host-owned command-book service.

The declarations express the dependency graph; the host does not manually
call the command's `apply()` when a provider changes. Keeping only `message`
inside the command callable also avoids using an expired activation context
after unmounting.

## Try dependency loss instead of retirement

To observe automatic reactivation without removing a provider registration,
pause before the `scope.remove(original)` step and call `host.unprovide("commands")`.
The command unmounts while the greeting provider remains active. Restore the
host-owned service with `host.provide("commands", book)` and the command
mounts again against the same greeting. Then continue with the original
provider retirement and replacement steps. The additional unmount and mount
change the event sequence, so the printed output differs from the transcript above.

Withdrawing `greeting` has different ownership: it is component-owned, so
`host.unprovide("greeting")` retires its whole provider. Restoring it requires
registering a provider again. See [lifecycle and ownership](CORDIS.md#lifecycle-and-ownership).

## Compose an owned child

Run this as a separate file with the same command. The parent declares
`prefix`, and the child inherits that committed dependency while declaring
its own `suffix`. Its fork and nested scope belong to the parent activation.
Record the parent's cleanup before the child acquisition to get the LIFO
order shown here.

```python
"""Demonstrate inherited dependencies and owned nested composition."""

from rebrew.plugin import Context, activate


class Child:
    needs = ("suffix",)
    provides: tuple[str, ...] = ()

    def apply(self, ctx: Context) -> None:
        message = ctx.resolve("prefix") + ctx.resolve("suffix")
        print(f"child on: {message}")
        ctx.effect(lambda: print(f"child off: {ctx.resolve('prefix')}{ctx.resolve('suffix')}"))


class Parent:
    needs = ("prefix",)
    provides: tuple[str, ...] = ()

    def apply(self, ctx: Context) -> None:
        ctx.effect(lambda: print(f"parent off: {ctx.resolve('prefix')}"))
        activate([Child()], ctx.fork())


host = Context()
host.provide("prefix", "hello")
host.provide("suffix", "!")
try:
    parent = Parent()
    scope = activate([parent], host)
    host.unprovide("prefix")
    assert scope.unresolved() == [parent]
finally:
    host.dispose()
```

Expected stdout:

```text
child on: hello!
child off: hello!
parent off: hello
```

Inherited access covers the parent's declared dependencies. If the parent
publishes a new service, the child instead names it in its own `needs`;
activation then waits for the parent to commit that provision. See
[dependency declarations](CORDIS.md#declare-dependencies-and-provisions).

## Recover from activation failure

Run this independent example to see rollback and explicit recovery. Providing
`ready` starts the waiting component, but its first activation fails after
installing a binding and recording cleanup. The partial binding is rolled
back, the failed registration is removed, and an unrelated change cannot
retry it. Repairing the object and registering it again starts a new attempt.

```python
"""Demonstrate rollback and explicit registration after activation failure."""

from rebrew.plugin import CoeffectScope, Context


class Provider:
    needs = ("ready",)
    provides = ("service",)

    def __init__(self) -> None:
        self.fail = True
        self.attempts = 0
        self.cleaned: list[str] = []

    def apply(self, ctx: Context) -> None:
        self.attempts += 1
        ctx.provide("service", "recovered")
        ctx.effect(lambda: self.cleaned.append(ctx.resolve("ready")))
        if self.fail:
            raise ValueError("deliberate failure")


host = Context()
provider = Provider()
try:
    scope = CoeffectScope(host)
    scope.add(provider)
    try:
        host.provide("ready", "ready")
    except ValueError as error:
        print(f"activation: {error}")
    assert not host.has("service") and scope.unresolved() == []
    print(f"after failure: service={host.has('service')}, waiting={len(scope.unresolved())}")
    host.provide("unrelated", 1)
    print(f"after unrelated change: attempts={provider.attempts}")
    provider.fail = False
    scope.add(provider)
    print(f"after explicit registration: {host.resolve('service')}")
    scope.close()
    assert provider.cleaned == ["ready", "ready"]
    print(f"cleanup: {len(provider.cleaned)}")
finally:
    host.dispose()
```

Expected stdout:

```text
activation: deliberate failure
after failure: service=False, waiting=0
after unrelated change: attempts=1
after explicit registration: recovered
cleanup: 2
```

When several inverses fail, cleanup still attempts all of them and reports
their errors in an exception group. This does not establish that the external
resources were restored; the component author must repair failing inverses.
See [failure behavior](CORDIS.md#failure-behavior) for cancellation, circular
teardown requests, and the atomic startup helper's rollback boundary.

## Check the examples in CI

[`test_cordis_docs.py`](../tests/test_cordis_docs.py) executes every Python block
on this page and compares stdout with its transcript. Run the check with:

```bash
make test-one T=tests/test_cordis_docs.py
```

Continue with the [recipes and API reference](CORDIS.md#public-runtime-api)
or the [command contributor checklist](ADDING_A_COMMAND.md).
