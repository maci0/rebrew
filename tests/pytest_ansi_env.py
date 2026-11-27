"""ANSI-safe env for the pytest suite (matches ``make test`` / CI).

Loaded via ``[tool.pytest.ini_options] addopts = -p pytest_ansi_env`` so a
bare ``uv run --frozen pytest`` (documented in AGENTS.md) cannot fail when
``FORCE_COLOR`` / ``GITHUB_ACTIONS`` make typer/Rich split option names and
version digits across escape sequences.  Not a fixture conftest — env only.

The same plugin turns on pytest-xdist for a full-suite invocation, with
work stealing: the default ``load`` scheduler hands each worker a fixed
share up front, so the subprocess-heavy tests at the end left most workers
idle (106 s against 59 s for the same CPU time on 32 workers).  A
``python -m slipcover`` run stays one process: it sets ``SLIPCOVER_ENABLED``
(the slipcover pytest plugin is loaded on every run, so it is not that
signal), and ``make coverage`` shards serial slipcover runs instead.

After collection every process moves the collected graph (modules, test
items, fixtures) to the permanent GC generation and raises the young
threshold, as the ``rebrew`` CLI does at startup: cyclic collections during
the tests rescanned that graph. Objects the tests allocate stay collectable.

Before and after every test it empties ``rebrew.decompiler``'s backend probe
cache, which keeps a decompiler's state for 30 s: a test that fakes a probe
(``shutil.which``, a kuna that answers) otherwise leaves the decompiler offered
to whichever test runs next in the process.

It also makes every LIEF parse and format check given ``bytes`` (or a
``bytearray`` or ``memoryview``) raise ``TypeError``: LIEF's binding reads a
``bytes`` argument that spells an existing path as that file and opens it
(``b"."`` opened the working directory), so rebrew hands LIEF a path string,
an ``io.BytesIO`` or a list of ints, never bytes.

Every test gets a private ``XDG_CACHE_HOME`` path, created on first use. Rebrew keeps the unshare
image-tag record, exported images, its temp dirs, Wine prefixes and the PE layout
cache there: a test that faked an image digest read the id a real compile had
recorded in the developer's cache (and recorded its fake id there). A test that
needs another cache home sets ``XDG_CACHE_HOME`` itself.
"""

from __future__ import annotations

import gc
import os
import uuid
from typing import Any
lazy from collections.abc import Iterator

import pytest

# Applied at plugin import — before CliRunner tests invoke typer/Rich.
os.environ["NO_COLOR"] = "1"
# A reply member an op builds and rebrew.ops_replies does not declare fails the test.
os.environ["REBREW_OPS_STRICT_REPLIES"] = "1"
os.environ["TERM"] = "dumb"
os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"

_SERIAL_FLAGS = frozenset({"--collect-only", "--pdb", "--trace"})

#: Young-generation GC threshold for the test run (CPython's is 2000), the
#: value ``rebrew.app.main`` uses. With the freeze below, a full ``-n auto``
#: run took 2,437 G -> 2,380 G user-space instructions; the freeze alone
#: 2,391 G.
_GC_YOUNG_THRESHOLD = 20_000


def pytest_collection_finish() -> None:
    """Freeze the collected graph out of cyclic GC passes; see the module docstring."""
    gc.freeze()
    gc.set_threshold(_GC_YOUNG_THRESHOLD, *gc.get_threshold()[1:])


@pytest.fixture(autouse=True)
def _isolated_cache_home(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    """A private per-test cache path; see the module docstring.

    A private ``MonkeyPatch``: requesting the shared ``monkeypatch`` fixture here
    made it outlive a test's own teardown, which then refreshed the toolchain
    registry with that test's overlay variable still set.
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("XDG_CACHE_HOME", str(tmp_path_factory.getbasetemp() / uuid.uuid4().hex))
        patch.delenv("LOCALAPPDATA", raising=False)
        yield


def _forget_decompiler_states() -> None:
    from rebrew import decompiler

    with decompiler._states_lock:
        decompiler._states.clear()


def pytest_runtest_setup(item: Any) -> None:
    """Start every test with no decompiler probe cached; see the module docstring."""
    del item
    _forget_decompiler_states()


def pytest_runtest_teardown(item: Any, nextitem: Any) -> None:
    """Leave no decompiler probe a test faked to the next one."""
    del item, nextitem
    _forget_decompiler_states()


#: LIEF's entry points that take a path or a buffer, by module attribute path.
_LIEF_ENTRY_POINTS = (
    ("", "parse"),
    ("PE", "parse"),
    ("ELF", "parse"),
    ("COFF", "parse"),
    ("MachO", "parse"),
    ("", "is_pe"),
    ("", "is_elf"),
    ("", "is_macho"),
)


def _refuse_lief_bytes() -> None:
    """Wrap each LIEF entry point to raise on a ``bytes`` argument from rebrew's own code.

    A test may hand LIEF bytes it built (a PE holds NUL bytes, which LIEF never
    reads as a path); the guard holds the shipped code, the caller one frame up.
    """
    import sys
    from pathlib import Path

    import lief

    import rebrew

    package = str(Path(rebrew.__file__).parent)

    for module_name, name in _LIEF_ENTRY_POINTS:
        module = getattr(lief, module_name) if module_name else lief
        real = getattr(module, name)

        def guarded(source: Any, *args: Any, _real: Any = real, **kwargs: Any) -> Any:
            if isinstance(source, (bytes, bytearray, memoryview)) and sys._getframe(
                1
            ).f_code.co_filename.startswith(package):
                raise TypeError(
                    "LIEF was given bytes, which it opens as a path when they spell one;"
                    " pass io.BytesIO(data)"
                )
            return _real(source, *args, **kwargs)

        setattr(module, name, guarded)


def pytest_configure() -> None:
    """Re-assert guards if an earlier plugin cleared them."""
    _refuse_lief_bytes()
    os.environ["NO_COLOR"] = "1"
    os.environ["TERM"] = "dumb"
    os.environ["_TYPER_FORCE_DISABLE_TERMINAL"] = "1"


def _explicit_workers(args: list[str]) -> bool:
    """True when the caller already chose a worker count or turned xdist off."""
    for index, arg in enumerate(args):
        if arg in {"-n", "--numprocesses"} or arg.startswith("--numprocesses="):
            return True
        if arg.startswith("-n") and not arg.startswith("--"):
            rest = arg[2:]
            if rest in {"auto", "logical"} or rest.isdigit():
                return True
        plugin = ""
        if arg == "-p" and index + 1 < len(args):
            plugin = args[index + 1]
        elif arg.startswith("-p") and not arg.startswith("--"):
            plugin = arg[2:]
        if plugin in {"no:xdist", "noxdist"}:
            return True
    return False


def _full_suite(early_config: Any) -> bool:
    """True for a bare pytest or an invocation whose only path is ``tests``."""
    paths = list(getattr(early_config.known_args_namespace, "file_or_dir", None) or [])
    for raw in paths:
        norm = str(raw).replace("\\", "/").rstrip("/")
        if norm.startswith("./"):
            norm = norm[2:]
        if norm != "tests":
            return False
    return True


def pytest_load_initial_conftests(early_config: Any, parser: Any, args: list[str]) -> None:
    """Inject ``-n auto --dist worksteal`` for the full suite once xdist has registered ``-n``.

    Subsets (a file, a node id, any path other than ``tests``), collection,
    debugging, ``SLIPCOVER_ENABLED``, and an explicit ``-n`` stay one process.
    Workers re-enter this hook; ``PYTEST_XDIST_WORKER`` stops the injection.
    """
    del parser
    if os.environ.get("PYTEST_XDIST_WORKER") or os.environ.get("SLIPCOVER_ENABLED"):
        return
    if _explicit_workers(args):
        return
    if any(flag in args for flag in _SERIAL_FLAGS):
        return
    if not _full_suite(early_config):
        return
    if not early_config.pluginmanager.has_plugin("xdist"):
        return
    # Leading, so a --dist the caller passes still wins.
    args[:0] = ["-n", "auto", "--dist", "worksteal"]
