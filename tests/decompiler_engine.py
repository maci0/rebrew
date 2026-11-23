"""An engine that offers the named decompiler backends, whatever is installed on the host.

The ops refuse a decompiler that cannot run here before any work
(``rebrew.decompiler.backend_state``); a test that fakes the decompiler itself
declares which backends the engine offers with :func:`offer_decompilers`.
"""

from __future__ import annotations

import pytest

from rebrew import decompiler


def offer_decompilers(monkeypatch: pytest.MonkeyPatch, *names: str) -> None:
    """Make *names* available; every other backend is checked as on the host."""
    real = decompiler._check
    monkeypatch.setattr(decompiler, "_states", {})
    monkeypatch.setattr(
        decompiler,
        "_check",
        lambda name, endpoint: (
            decompiler.BackendState(name, "available") if name in names else real(name, endpoint)
        ),
    )
