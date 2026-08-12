"""Unit tests for the recompile service (no docker required)."""

from fastapi.testclient import TestClient
from recompile.app import app
from recompile.compilers import list_compilers, resolve_image

client = TestClient(app)


def test_catalog_has_image_toolchains() -> None:
    compilers = list_compilers()
    ids = {c.id for c in compilers}
    assert {"msvc6", "msvc1.52", "delphi16", "watcom"} <= ids
    for c in compilers:
        assert c.version
        assert c.target.startswith("win")


def test_resolve_image() -> None:
    assert resolve_image("msvc6") == "rebrew/msvc:6.0-win32"
    assert resolve_image("msvc1.52") == "rebrew/msvc:1.52-win16"
    assert resolve_image("delphi16") == "rebrew/delphi:1.0-win16"
    assert resolve_image("watcom") == "rebrew/watcom:2.0-win32"
    assert resolve_image("gcc-pe") is None  # host-only


def test_compilers_route() -> None:
    r = client.get("/api/v1/compilers")
    assert r.status_code == 200
    payload = r.json()
    assert isinstance(payload, list)
    assert any(c["id"] == "msvc6" for c in payload)


def test_compile_unknown_compiler_400() -> None:
    r = client.post(
        "/api/v1/compile",
        json={"compiler": "gcc-pe", "source": "int f(void){return 0;}\n"},  # host-only
    )
    assert r.status_code == 400


def test_artifact_traversal_blocked() -> None:
    r = client.get("/api/v1/artifacts/..%2F..%2Fetc%2Fpasswd")
    assert r.status_code == 404
