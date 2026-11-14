"""A recompile service stand-in for ops tests that compile remotely.

``serve_recompile`` answers the remote backend's client in-process: its
``GET /api/v1/features`` list, and every compile as a toolchain rejection.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest


def serve_recompile(
    monkeypatch: pytest.MonkeyPatch,
    *,
    features: list[str] | None,
    error_code: str = "toolchain_failure",
) -> list[dict[str, Any]]:
    """Answer remote compiles with a recompile stand-in; return the compile bodies it got.

    *features* is its ``GET /api/v1/features`` list; ``None`` is a release
    older than the route (404).  Every compile fails with *error_code*: by
    default a toolchain rejection, the compiler's verdict on the source; an
    infrastructure code (``runner_unavailable``) is the service's own failure.
    """
    from rebrew.compiler import compile as compile_module

    posted: list[dict[str, Any]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/features":
            if features is None:
                return httpx.Response(404, json={"detail": "Not Found"})
            return httpx.Response(200, json={"features": features})
        if request.method == "POST" and request.url.path == "/api/v1/compile":
            posted.append(json.loads(request.content))
            return httpx.Response(
                200,
                json={"status": "error", "error_code": error_code, "log": "error C2065"},
            )
        return httpx.Response(404, json={"detail": "Not Found"})

    client = httpx.Client(transport=httpx.MockTransport(handle))
    monkeypatch.setattr("rebrew.compiler.recompile_client._bundle_services", set())
    monkeypatch.setattr(compile_module, "_shared_recompile_client", lambda _timeout: client)
    monkeypatch.setattr(compile_module, "_recompile_release", lambda _client: None)
    return posted
