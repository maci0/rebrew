"""Remote compiles ship the project headers a source reads (relumea ADR 0010, decision 4).

The local and remote backends compile the same source, flags and headers to the
same object bytes.  The remote side here is a stand-in for the recompile
service that applies its published include-bundle contract (recompile
``docs/API.md``, "Include bundles": headers at their paths, the source at
``source_dir/filename``, the compiler run in ``source_dir``); recompile's own
``tests/test_include_bundles.py`` proves the service compiles a bundle as the
project tree compiles in place.  Both sides run the host C compiler.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from rebrew.compiler import compile as compile_module
from rebrew.compiler.compile import compile_to_obj
from rebrew.compiler.recompile_client import RecompileError, compile_source
from rebrew.compiler.toolchain_spec import ToolchainSpec

_URL = "http://recompile.test"

#: A project whose source reads headers through each rule a bundle must keep:
#: its own directory before the include directories (plant.h is in both), the
#: include directories in order (shared.h is in both), a #pragma once header
#: reached by two spellings, and __FILE__ expanded in the source, directly and
#: through a header macro.
_TREE = {
    "src/game/plant.c": (
        '#include "plant.h"\n'
        '#include "../common/once.h"\n'
        "#include <shared.h>\n"
        '#include "once.h"\n'
        "const char *source_file = __FILE__;\n"
        "const char *macro_file = PLANT_FILE;\n"
        "int f(void) { return PLANT + SHARED + ONCE + NESTED; }\n"
    ),
    "src/game/plant.h": "#define PLANT 1\n#define PLANT_FILE __FILE__\n",
    "include/plant.h": '#define PLANT 2\n#define PLANT_FILE "wrong"\n',
    "include/shared.h": '#include "nested.h"\n#define SHARED 3\n',
    "include/nested.h": "#define NESTED 4\n",
    "src/common/shared.h": "#define SHARED 5\n",
    "src/common/once.h": "#pragma once\nstruct once_s { int x; };\n#define ONCE 6\n",
}


def _host_cc() -> str:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("needs a host C compiler (cc) on PATH")
    return compiler


def _project(root: Path, tree: dict[str, str] = _TREE) -> Path:
    for path, text in tree.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text, encoding="utf-8")
    return root / "src/game/plant.c"


def _cfg(root: Path, *, remote: bool) -> SimpleNamespace:
    return SimpleNamespace(
        root=root,
        compiler_profile="hostcc-1.0",
        compiler_includes="",
        base_cflags="-Iinclude -Isrc/common",
        compile_timeout=60,
        defines=[],
        recompile_url=_URL if remote else "",
        recompile_retries=0,
        execution_backend="",
    )


class _Recompile:
    """The recompile HTTP contract, compiling with the host C compiler."""

    def __init__(self, work: Path, *, features: tuple[str, ...] = ("include-bundles",)) -> None:
        self.work = work
        self.features = features
        self.compiles: list[dict[str, Any]] = []
        self.artifact = b""

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v1/features":
            if not self.features:
                # A release older than the route: FastAPI's 404.
                return httpx.Response(404, json={"detail": "Not Found"})
            return httpx.Response(200, json={"features": list(self.features)})
        if request.method == "POST" and request.url.path == "/api/v1/compile":
            payload = json.loads(request.content)
            self.compiles.append(payload)
            tree = self.work / f"job{len(self.compiles)}"
            for item in payload.get("includes", []):
                (tree / item["path"]).parent.mkdir(parents=True, exist_ok=True)
                (tree / item["path"]).write_bytes(item["content"].encode("utf-8"))
            cwd = tree / payload.get("source_dir", "")
            cwd.mkdir(parents=True, exist_ok=True)
            (cwd / payload["filename"]).write_bytes(payload["source"].encode("utf-8"))
            # The service is another machine: an include directory that names
            # a path on this host does not exist there.
            flags = [
                flag
                for flag in payload["flags"]
                if not (flag.startswith(("-I", "/I")) and Path(flag[2:]).is_absolute())
            ]
            done = subprocess.run(
                [_host_cc(), *flags, payload["filename"]],
                cwd=cwd,
                capture_output=True,
                text=True,
                check=False,
            )
            if done.returncode != 0:
                return httpx.Response(
                    200,
                    json={
                        "status": "error",
                        "error_code": "toolchain_failure",
                        "log": done.stderr,
                    },
                )
            self.artifact = (cwd / (Path(payload["filename"]).stem + ".o")).read_bytes()
            return httpx.Response(
                200,
                json={
                    "status": "ok",
                    "artifact_url": "/api/v1/artifacts/0123456789ab.o",
                    "log": "",
                },
            )
        if request.method == "GET" and request.url.path == "/api/v1/artifacts/0123456789ab.o":
            return httpx.Response(200, content=self.artifact)
        return httpx.Response(404, json={"detail": "not found"})

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = httpx.Client(transport=httpx.MockTransport(self.handle))
        # Each test is a fresh service: forget what an earlier one advertised.
        monkeypatch.setattr("rebrew.compiler.recompile_client._bundle_services", set())
        monkeypatch.setattr(compile_module, "_shared_recompile_client", lambda _timeout: client)
        monkeypatch.setattr(compile_module, "_recompile_release", lambda _client: None)


@pytest.fixture
def host_toolchain(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """``hostcc-1.0``: a native posix toolchain that runs the host C compiler."""
    compiler = _host_cc()
    spec = ToolchainSpec(
        name="hostcc-1.0",
        image=None,
        binary="cc",
        runtime="native",
        flags_style="posix",
        obj_ext=".o",
    )
    monkeypatch.setattr(
        compile_module, "toolchain_registry", SimpleNamespace(TOOLCHAINS={"hostcc-1.0": spec})
    )
    monkeypatch.setattr("rebrew.compiler.toolchain.vendored_binary", lambda _spec: Path(compiler))
    monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
    monkeypatch.delenv("REBREW_JOB_COMPILE_SOCKET", raising=False)
    # The report is per process; restore it so later tests read their own.
    monkeypatch.setattr(compile_module, "_last_remote_compile", None)


def _compile(cfg: SimpleNamespace, source: Path, workdir: Path) -> tuple[str | None, str]:
    workdir.mkdir()
    return compile_to_obj(cfg, source, "", workdir, use_cache=False, obj_name="plant.o")


class TestLocalAndRemoteAgree:
    @pytest.mark.usefixtures("host_toolchain")
    def test_a_source_that_reads_headers_compiles_to_the_same_bytes(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        root = tmp_path / "project"
        source = _project(root)
        local, error = _compile(_cfg(root, remote=False), source, tmp_path / "local")
        assert local is not None, error
        service = _Recompile(tmp_path / "service")
        service.install(monkeypatch)
        remote, error = _compile(_cfg(root, remote=True), source, tmp_path / "remote")
        assert remote is not None, error
        assert Path(remote).read_bytes() == Path(local).read_bytes()
        assert b"plant.c\x00" in Path(local).read_bytes()
        assert b"wrong" not in Path(local).read_bytes(), "the source's own plant.h wins"

    @pytest.mark.usefixtures("host_toolchain")
    def test_the_bundle_is_the_closure_with_relative_include_dirs(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        root = tmp_path / "project"
        source = _project(root)
        service = _Recompile(tmp_path / "service")
        service.install(monkeypatch)
        _obj, error = _compile(_cfg(root, remote=True), source, tmp_path / "remote")
        assert not error
        (sent,) = service.compiles
        assert sent["source_dir"] == "src/game"
        assert sent["filename"] == "plant.c"
        assert [item["path"] for item in sent["includes"]] == [
            "include/nested.h",
            "include/shared.h",
            "src/common/once.h",
            "src/game/plant.h",
        ]
        assert sent["flags"] == ["-I.", "-I../../include", "-I../common", "-c"]
        assert str(root) not in json.dumps(sent), "no host path leaves the machine"

    @pytest.mark.usefixtures("host_toolchain")
    def test_a_source_without_project_headers_sends_no_bundle(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A service older than bundles keeps compiling header-free sources."""
        root = tmp_path / "project"
        source = _project(root, {"src/game/plant.c": "int f(void) { return 1; }\n"})
        service = _Recompile(tmp_path / "service", features=())
        service.install(monkeypatch)
        obj, error = _compile(_cfg(root, remote=True), source, tmp_path / "remote")
        assert obj is not None, error
        (sent,) = service.compiles
        assert "includes" not in sent and "source_dir" not in sent


class TestVersionSkew:
    @pytest.mark.usefixtures("host_toolchain")
    def test_a_service_without_include_bundles_is_refused_before_the_compile(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        root = tmp_path / "project"
        source = _project(root)
        service = _Recompile(tmp_path / "service", features=())
        service.install(monkeypatch)
        errors: list[Any] = []
        workdir = tmp_path / "remote"
        workdir.mkdir()
        obj, error = compile_to_obj(
            _cfg(root, remote=True), source, "", workdir, use_cache=False, backend_errors=errors
        )
        assert obj is None
        assert "does not accept include bundles" in error
        assert service.compiles == [], "nothing the old service would refuse is sent"
        (refusal,) = errors
        assert isinstance(refusal, RecompileError) and refusal.kind == "validation"

    def test_the_client_checks_the_feature_once_per_service(self) -> None:
        probes: list[str] = []

        def handle(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/v1/features":
                probes.append(request.method)
                return httpx.Response(200, json={"features": ["include-bundles"]})
            if request.url.path == "/api/v1/compile":
                return httpx.Response(
                    200, json={"status": "ok", "artifact_url": "/api/v1/artifacts/0123456789ab.o"}
                )
            return httpx.Response(200, content=b"OBJ")

        client = httpx.Client(transport=httpx.MockTransport(handle))
        for _ in range(2):
            result = compile_source(
                "http://once.test",
                "gcc-14.2.0",
                "int f;\n",
                ["-c"],
                filename="f.c",
                client=client,
                includes={"inc/a.h": "int a;\n"},
                source_dir="src",
            )
            assert result.ok
        assert probes == ["GET"]


class TestUnshippableSources:
    @pytest.mark.usefixtures("host_toolchain")
    @pytest.mark.parametrize(
        ("tree", "reason"),
        [
            (
                {"src/game/plant.c": "#define H <x.h>\n#include H\nint f;\n"},
                "computes an #include",
            ),
            (
                {"src/game/plant.c": '#include "plant.h"\nint f;\n', "src/game/plant.h": None},
                "not UTF-8",
            ),
        ],
    )
    def test_a_source_whose_headers_cannot_ship_is_refused(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        tree: dict[str, str | None],
        reason: str,
    ) -> None:
        root = tmp_path / "project"
        source = _project(root, {k: v for k, v in tree.items() if v is not None})
        for path, text in tree.items():
            if text is None:
                (root / path).write_bytes(b"/* Gr\xfc\xdfe */\n#define X 1\n")
        service = _Recompile(tmp_path / "service")
        service.install(monkeypatch)
        errors: list[Any] = []
        workdir = tmp_path / "remote"
        workdir.mkdir()
        obj, error = compile_to_obj(
            _cfg(root, remote=True), source, "", workdir, use_cache=False, backend_errors=errors
        )
        assert obj is None
        assert reason in error
        assert service.compiles == []
        assert errors and isinstance(errors[0], RecompileError)

    def test_a_bundle_over_the_service_bounds_is_refused_unsent(self) -> None:
        def handle(request: httpx.Request) -> httpx.Response:
            raise AssertionError(f"nothing is sent: {request.method} {request.url}")

        client = httpx.Client(transport=httpx.MockTransport(handle))
        with pytest.raises(RecompileError, match="include files") as raised:
            compile_source(
                "http://bounds.test",
                "gcc-14.2.0",
                "int f;\n",
                [],
                client=client,
                includes={f"inc/h{i}.h": "" for i in range(257)},
            )
        assert raised.value.kind == "validation"


class TestShippedHeadersAreReported:
    @pytest.mark.usefixtures("host_toolchain")
    def test_the_last_remote_compile_names_the_headers_it_shipped(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """``rebrew test --json`` reports them, so a verdict can name what it read."""
        import hashlib

        from rebrew.compiler.compile import last_remote_compile

        root = tmp_path / "project"
        source = _project(root)
        _Recompile(tmp_path / "service").install(monkeypatch)
        obj, error = _compile(_cfg(root, remote=True), source, tmp_path / "remote")
        assert obj is not None, error
        report = last_remote_compile()
        assert report is not None
        assert report["source_dir"] == "src/game"
        assert report["includes"] == [
            {"path": path, "sha256": hashlib.sha256(_TREE[path].encode()).hexdigest()}
            for path in (
                "include/nested.h",
                "include/shared.h",
                "src/common/once.h",
                "src/game/plant.h",
            )
        ]
