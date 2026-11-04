"""The matcher package's lazy export fill must tolerate re-entry.

``_load_mutator_exports`` imports ``.mutator``, and that import runs
``rebrew.mutations`` entry-point plugins.  A plugin that composes a packaged
operator asks this package for it while the fill still holds the export lock,
so the lock cannot be a plain ``Lock``.
"""

import importlib
import threading
lazy from types import ModuleType

import pytest

from rebrew import matcher


class TestLazyExportReentrancy:
    def test_plugin_import_can_reenter_the_export_lock(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A mutation plugin importing a matcher export must not deadlock."""

        def reentrant_import(name: str, package: str) -> ModuleType:
            if name == ".mutator":
                # Stand in for a plugin that asks the package for an export
                # during the fill, which takes the same lock.
                with matcher._LAZY_EXPORT_LOCK:
                    pass
            return importlib.import_module(name, package)

        monkeypatch.setattr(matcher, "_mutator_loaded", False)
        monkeypatch.setattr(matcher, "import_module", reentrant_import)
        done = threading.Event()

        def load() -> None:
            matcher._load_mutator_exports()
            done.set()

        worker = threading.Thread(target=load, name="lazy-export", daemon=True)
        worker.start()
        assert done.wait(5.0), "matcher export fill deadlocked on its own lock"
        worker.join(5.0)
        assert not worker.is_alive()
