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
import threading
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
    """The recompile HTTP contract, compiling with the host C compiler.

    Compiles may arrive concurrently: each gets its own job number, tree and
    artifact.
    """

    def __init__(self, work: Path, *, features: tuple[str, ...] = ("include-bundles",)) -> None:
        self.work = work
        self.features = features
        self.compiles: list[dict[str, Any]] = []
        self.artifacts: dict[str, bytes] = {}
        self._lock = threading.Lock()

    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v1/features":
            if not self.features:
                # A release older than the route: FastAPI's 404.
                return httpx.Response(404, json={"detail": "Not Found"})
            return httpx.Response(200, json={"features": list(self.features)})
        if request.method == "POST" and request.url.path == "/api/v1/compile":
            payload = json.loads(request.content)
            with self._lock:
                self.compiles.append(payload)
                job = f"{len(self.compiles):012x}"
            tree = self.work / f"job{job}"
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
            with self._lock:
                self.artifacts[job] = (cwd / (Path(payload["filename"]).stem + ".o")).read_bytes()
            return httpx.Response(
                200,
                json={"status": "ok", "artifact_url": f"/api/v1/artifacts/{job}.o", "log": ""},
            )
        prefix = "/api/v1/artifacts/"
        if request.method == "GET" and request.url.path.startswith(prefix):
            with self._lock:
                artifact = self.artifacts.get(request.url.path[len(prefix) :].removesuffix(".o"))
            if artifact is not None:
                return httpx.Response(200, content=artifact)
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
    def test_the_compare_result_names_the_headers_it_shipped(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """``rebrew test --json`` reports them, so a verdict can name what it read."""
        import hashlib

        from rebrew.compiler.compile import compile_and_compare

        root = tmp_path / "project"
        source = _project(root)
        _Recompile(tmp_path / "service").install(monkeypatch)
        cmp = compile_and_compare(
            _cfg(root, remote=True), source, "f", b"\x00" * 8, "", use_cache=False
        )
        report = cmp.remote_compile
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


class TestToolchainHeadersStayInTheImage:
    @pytest.mark.usefixtures("host_toolchain")
    def test_the_sdk_include_directory_is_not_shipped(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """``[compiler] includes`` under ``toolchain/`` is the image's own SDK tree."""
        root = tmp_path / "project"
        source = _project(
            root,
            {
                "src/game/plant.c": '#include <sdk.h>\n#include "plant.h"\nint f;\n',
                "src/game/plant.h": "#define PLANT 1\n",
            },
        )
        sdk = root / "toolchain/msvc/6.0-win32/source/VC98/Include"
        sdk.mkdir(parents=True)
        (sdk / "sdk.h").write_bytes(b"/* \xa9 vendor */\n#define SDK 1\n")
        cfg = _cfg(root, remote=True)
        cfg.compiler_includes = str(sdk)
        service = _Recompile(tmp_path / "service")
        service.install(monkeypatch)
        workdir = tmp_path / "remote"
        workdir.mkdir()
        compile_to_obj(cfg, source, "", workdir, use_cache=False)
        (sent,) = service.compiles
        assert [item["path"] for item in sent["includes"]] == ["src/game/plant.h"]
        assert not any("toolchain" in flag for flag in sent["flags"])


class TestConcurrentCompilesReportTheirOwn:
    @pytest.mark.usefixtures("host_toolchain")
    def test_each_result_names_its_own_remote_compile(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Two compiles in one process (``ops serve`` threads) each report their own.

        The first waits between its compile and its report until the second
        has finished, the order a busy worker can take.
        """
        from rebrew.compiler.compile import compile_and_compare
        from rebrew.test import build_result_dict_from_compare

        root = tmp_path / "project"
        bundled = _project(root)
        plain = root / "src/game/plain.c"
        plain.write_text("int g(void) { return 2; }\n", encoding="utf-8")
        _Recompile(tmp_path / "service").install(monkeypatch)
        cfg = _cfg(root, remote=True)
        second_done = threading.Event()
        real_extract = compile_module._extract_and_compare

        def extract_after_the_second(*args: Any, **kwargs: Any) -> Any:
            if threading.current_thread().name == "first":
                assert second_done.wait(30), "the second compile never finished"
            return real_extract(*args, **kwargs)

        monkeypatch.setattr(compile_module, "_extract_and_compare", extract_after_the_second)
        reports: dict[str, dict[str, Any]] = {}

        def verify(name: str, source: Path, symbol: str) -> None:
            cmp = compile_and_compare(cfg, source, symbol, b"\x00" * 8, "", use_cache=False)
            reports[name] = build_result_dict_from_compare(
                str(source), symbol, "0x0", 8, cmp, b"\x00" * 8
            )["compile"]
            if name == "second":
                second_done.set()

        first = threading.Thread(target=verify, args=("first", bundled, "f"), name="first")
        first.start()
        second = threading.Thread(target=verify, args=("second", plain, "g"), name="second")
        second.start()
        first.join(60)
        second.join(60)
        assert [item["path"] for item in reports["first"]["includes"]] == [
            "include/nested.h",
            "include/shared.h",
            "src/common/once.h",
            "src/game/plant.h",
        ]
        assert "includes" not in reports["second"]


class TestOneSearchOrder:
    @pytest.mark.usefixtures("host_toolchain")
    def test_batch_single_file_and_remote_compiles_read_the_same_headers(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Source directory, then the flags' include directories, then ``[compiler] includes``.

        That is MSVC's order with ``[compiler] includes`` as ``INCLUDE``
        (searched after every ``/I``); ``shared.h`` in the includes directory
        is searched last, so ``include/shared.h`` wins everywhere.
        """
        from rebrew.compiler.compile import precompile_batch

        root = tmp_path / "project"
        source = _project(root)
        (root / "src/game/other.c").write_text("int other(void) { return 1; }\n", encoding="utf-8")
        (root / "inc_last").mkdir()
        (root / "inc_last/shared.h").write_text("#define SHARED 9\n", encoding="utf-8")
        monkeypatch.setattr(
            "rebrew.compiler.overrides.resolve_compile_overrides", lambda *a, **k: (None, "")
        )

        def cfg(*, remote: bool) -> SimpleNamespace:
            made = _cfg(root, remote=remote)
            made.compiler_includes = str(root / "inc_last")
            made.reversed_dir = root / "src/game"
            return made

        single, error = _compile(cfg(remote=False), source, tmp_path / "single")
        assert single is not None, error
        entries = [
            SimpleNamespace(filepath="plant.c", toolchain="", cflags="", module="", name="f"),
            SimpleNamespace(filepath="other.c", toolchain="", cflags="", module="", name="o"),
        ]
        batch = precompile_batch(cfg(remote=False), entries)
        assert id(entries[0]) in batch, "plant.c was not batch-built"
        _Recompile(tmp_path / "service").install(monkeypatch)
        remote, error = _compile(cfg(remote=True), source, tmp_path / "remote")
        assert remote is not None, error
        local_bytes = Path(single).read_bytes()
        assert Path(batch[id(entries[0])]).read_bytes() == local_bytes
        assert Path(remote).read_bytes() == local_bytes


class TestARejectionIsNotAFailureToRun:
    @pytest.mark.usefixtures("host_toolchain")
    def test_a_rejected_source_carries_no_error_and_a_missing_compiler_does(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """``COMPILE_ERROR`` without ``error`` is the toolchain's verdict on the source."""
        from rebrew.compiler.compile import compile_and_compare
        from rebrew.compiler.toolchain import ToolchainError

        root = tmp_path / "project"
        source = _project(root, {"src/game/plant.c": "int f(void) { return nope; }\n"})
        rejected = compile_and_compare(
            _cfg(root, remote=False), source, "f", b"\x00", "", use_cache=False
        )
        assert rejected.status == "COMPILE_ERROR" and rejected.error is None
        assert "nope" in rejected.message

        def missing(_spec: object) -> None:
            return None

        monkeypatch.setattr("rebrew.compiler.toolchain.vendored_binary", missing)
        not_run = compile_and_compare(
            _cfg(root, remote=False), source, "f", b"\x00", "", use_cache=False
        )
        assert not_run.status == "COMPILE_ERROR"
        assert isinstance(not_run.error, ToolchainError)
