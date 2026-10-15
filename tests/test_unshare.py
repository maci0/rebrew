"""Opt-in namespace runner, immutable inputs and failure/cleanup contracts."""

from __future__ import annotations

import io
import json
import os
import platform
import shutil
import subprocess
import tarfile
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from rebrew.compiler import unshare
from rebrew.compiler.toolchain import (
    TOOLCHAINS,
    ToolchainError,
    run_toolchain,
)
from rebrew.config import ProjectConfig

_IMAGE_ID = "sha256:" + "a" * 64


def _info() -> dict[str, Any]:
    return {
        "Id": _IMAGE_ID,
        "Config": {
            "User": "rebrew",
            "Entrypoint": ["/bin/probe"],
            "Env": ["HOME=/home/rebrew", "WINEPREFIX=/opt/wineprefix", "PATH=/bin"],
        },
    }


def _fake_execution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[dict[str, Any]]:
    rootfs = tmp_path / "image"
    rootfs.mkdir()
    monkeypatch.setattr(unshare, "prepare_backend", lambda: tmp_path / "helper")
    monkeypatch.setattr(unshare, "_cache_root", lambda: tmp_path / "cache")
    monkeypatch.setattr(unshare, "_image", lambda *_: (rootfs, _info()))
    calls: list[dict[str, Any]] = []

    def command(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        profile = json.loads(Path(args[1]).read_text())
        calls.append(profile)
        return subprocess.CompletedProcess(args, 0, "compiled", "")

    monkeypatch.setattr(unshare, "_command", command)
    return calls


class TestUnshareRouting:
    def test_default_still_runs_container_cli(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import rebrew.compiler.toolchain as tc

        commands = []
        monkeypatch.setattr(tc, "docker_available", lambda: True)
        monkeypatch.setattr(tc, "container_runtime", lambda: "docker")

        def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            commands.append(args)
            return subprocess.CompletedProcess(args, 0, "ok", "")

        monkeypatch.setattr(tc.subprocess, "run", run)
        result = run_toolchain(
            TOOLCHAINS["msvc-6.0-sp5"], ["f.c"], workdir=tmp_path, image_id=_IMAGE_ID
        )
        assert result.backend == "docker"
        assert commands[0][:3] == ["docker", "run", "--rm"]

    def test_experimental_keeps_pinned_identity_and_argv(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        calls = []

        def direct(image: str, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            calls.append((image, args, kwargs))
            return subprocess.CompletedProcess(args, 2, "compiler diagnostic", "")

        monkeypatch.setattr(unshare, "run_unshare", direct)
        result = run_toolchain(
            TOOLCHAINS["msvc-6.0-sp5"],
            ["/DVALUE=a b", "f.c"],
            workdir=tmp_path,
            image_id=_IMAGE_ID,
            execution_backend="unshare",
        )
        assert result.returncode == 2 and result.backend == "unshare"
        assert calls[0][0] == _IMAGE_ID
        assert calls[0][1] == ["/DVALUE=a b", "f.c"]
        assert calls[0][2]["entrypoint"] == "/usr/local/bin/cl"

    @pytest.mark.parametrize("image_id", [None, "sha256:short", "mutable:tag"])
    def test_missing_pin_is_not_a_docker_fallback(
        self, tmp_path: Path, image_id: str | None
    ) -> None:
        with pytest.raises(ToolchainError, match="admitted immutable"):
            run_toolchain(
                TOOLCHAINS["msvc-6.0-sp5"],
                [],
                workdir=tmp_path,
                image_id=image_id,
                execution_backend="unshare",
            )

    def test_unsupported_profile_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ToolchainError, match="32-bit MSVC"):
            run_toolchain(
                TOOLCHAINS["gcc-14.2.0"],
                [],
                workdir=tmp_path,
                image_id=_IMAGE_ID,
                execution_backend="unshare",
            )

    def test_namespace_error_is_not_a_docker_fallback(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        def fail(*args: Any, **kwargs: Any) -> None:
            raise unshare.UnshareError("user namespaces blocked")

        monkeypatch.setattr(unshare, "run_unshare", fail)
        with pytest.raises(ToolchainError, match="namespaces blocked"):
            run_toolchain(
                TOOLCHAINS["msvc-6.0-sp5"],
                [],
                workdir=tmp_path,
                image_id=_IMAGE_ID,
                execution_backend="unshare",
            )


class TestUnshareProfile:
    def test_private_profile_and_cleanup(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        calls = _fake_execution(monkeypatch, tmp_path)
        result = unshare.run_unshare(
            _IMAGE_ID,
            ["/c", "file name.c"],
            entrypoint=None,
            workdir=tmp_path,
            mounts=[(str(tmp_path), "/sdk/include")],
            env={"SOURCE_DATE_EPOCH": "123"},
            timeout=5,
        )
        assert result.returncode == 0
        profile = calls[0]
        assert profile["process"]["args"] == ["/bin/probe", "/c", "file name.c"]
        assert "SOURCE_DATE_EPOCH=123" in profile["process"]["env"]
        assert profile["root"]["readonly"]
        assert profile["process"]["noNewPrivileges"]
        assert all(value == [] for value in profile["process"]["capabilities"].values())
        assert next(m for m in profile["mounts"] if m["destination"] == "/sdk/include")[
            "options"
        ] == ["rbind", "ro", "nosuid", "nodev"]
        assert {n["type"] for n in profile["linux"]["namespaces"]} == {
            "user",
            "pid",
            "mount",
            "network",
            "uts",
            "ipc",
            "cgroup",
        }
        state_source = next(
            m["source"] for m in profile["mounts"] if m["destination"] == "/home/rebrew"
        )
        assert not Path(state_source).parents[1].exists()

    def test_setup_failure_is_not_compiler_diagnostic(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _fake_execution(monkeypatch, tmp_path)
        monkeypatch.setattr(
            unshare,
            "_command",
            lambda args, **kw: subprocess.CompletedProcess(
                args, 125, "", "rebrew-unshare: unshare: denied"
            ),
        )
        with pytest.raises(unshare.UnshareError, match="unshare: denied"):
            unshare.run_unshare(
                _IMAGE_ID, [], entrypoint=None, workdir=tmp_path, mounts=[], env={}, timeout=5
            )

    def test_compiler_exit_125_preserved(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _fake_execution(monkeypatch, tmp_path)
        monkeypatch.setattr(
            unshare,
            "_command",
            lambda args, **kw: subprocess.CompletedProcess(args, 125, "compiler failed", ""),
        )
        result = unshare.run_unshare(
            _IMAGE_ID, [], entrypoint=None, workdir=tmp_path, mounts=[], env={}, timeout=5
        )
        assert result.returncode == 125

    def test_invalid_pin_precedes_preparation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def unexpected() -> None:
            pytest.fail("must validate before preparation")

        monkeypatch.setattr(unshare, "prepare_backend", unexpected)
        with pytest.raises(unshare.UnshareError, match="immutable"):
            unshare.run_unshare(
                "tag", [], entrypoint=None, workdir=Path(), mounts=[], env={}, timeout=5
            )

    def test_unsupported_host_has_no_build_side_effect(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(unshare.platform, "system", lambda: "Windows")
        with pytest.raises(unshare.UnshareError, match="Linux x86_64"):
            unshare.prepare_backend()

    def test_timeout_becomes_actionable_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def timeout(*args: Any, **kwargs: Any) -> None:
            raise subprocess.TimeoutExpired("runner", 1)

        monkeypatch.setattr(unshare, "run_process_group", timeout)
        with pytest.raises(unshare.UnshareError, match="timed out"):
            unshare._command(["runner"], timeout=1)


class TestUnshareArchive:
    @pytest.mark.parametrize("member_name", ["../escape", "/absolute", "dir/../../escape"])
    def test_refuses_traversal(self, tmp_path: Path, member_name: str) -> None:
        archive = tmp_path / "image.tar"
        with tarfile.open(archive, "w") as out:
            member = tarfile.TarInfo(member_name)
            member.size = 1
            out.addfile(member, io.BytesIO(b"x"))
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        with pytest.raises(unshare.UnshareError, match="unsafe"):
            unshare._unpack(archive, rootfs)
        assert not (tmp_path / "escape").exists()

    def test_does_not_extract_through_absolute_symlink(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        archive = tmp_path / "image.tar"
        with tarfile.open(archive, "w") as out:
            link = tarfile.TarInfo("link")
            link.type = tarfile.SYMTYPE
            link.linkname = str(outside)
            out.addfile(link)
            member = tarfile.TarInfo("link/payload")
            member.size = 1
            out.addfile(member, io.BytesIO(b"x"))
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        with pytest.raises(FileExistsError):
            unshare._unpack(archive, rootfs)
        assert not (outside / "payload").exists()

    def test_absolute_links_installed_after_regular_bytes(self, tmp_path: Path) -> None:
        archive = tmp_path / "image.tar"
        with tarfile.open(archive, "w") as out:
            member = tarfile.TarInfo("bin/tool")
            member.size = 1
            member.mode = 0o755
            out.addfile(member, io.BytesIO(b"x"))
            link = tarfile.TarInfo("tool")
            link.type = tarfile.SYMTYPE
            link.linkname = "/bin/tool"
            out.addfile(link)
        rootfs = tmp_path / "rootfs"
        rootfs.mkdir()
        unshare._unpack(archive, rootfs)
        assert (rootfs / "bin/tool").read_bytes() == b"x"
        assert (rootfs / "tool").readlink() == Path("/bin/tool")


class TestUnshareCacheIdentity:
    def test_verify_identity_separates_default_and_experiment(self, tmp_path: Path) -> None:
        from rebrew.verify_hash import compiler_config_hash

        cfg = ProjectConfig(root=tmp_path)
        normal = compiler_config_hash(cfg)
        experimental = compiler_config_hash(replace(cfg, execution_backend="unshare"))
        assert normal != experimental
        assert compiler_config_hash(cfg) == normal

    def test_object_identity_separates_default_and_experiment(self, tmp_path: Path) -> None:
        import rebrew.compiler.compile as compiler

        cfg = ProjectConfig(root=tmp_path)
        spec = TOOLCHAINS["msvc-6.0-sp5"]
        args = (spec, "int f(void){return 1;}", "f.c", ["/O2"], "", tmp_path, None, ".c")
        normal = compiler._cache_key_for(cfg, *args, image_id=_IMAGE_ID)
        experimental = compiler._cache_key_for(
            replace(cfg, execution_backend="unshare"), *args, image_id=_IMAGE_ID
        )
        assert normal and experimental and normal != experimental

    def test_host_plugin_cache_cannot_bypass_image_requirement(self, tmp_path: Path) -> None:
        import sys

        import rebrew.compiler.compile as compiler
        from rebrew.compiler.toolchain import ToolchainSpec

        cfg = ProjectConfig(root=tmp_path)
        spec = ToolchainSpec(name="host-probe", image=None, binary=sys.executable)
        args = (spec, "int f(void){return 1;}", "f.c", [], "", tmp_path, None, ".c")
        assert compiler._cache_key_for(cfg, *args) is not None
        assert compiler._cache_key_for(replace(cfg, execution_backend="unshare"), *args) is None

    def test_experiment_does_not_enter_multi_source_batch(self, tmp_path: Path) -> None:
        from rebrew.compiler.compile import precompile_batch

        cfg = ProjectConfig(root=tmp_path, execution_backend="unshare")
        assert precompile_batch(cfg, [object(), object()]) == {}


class TestUnshareCli:
    def test_flag_help(self) -> None:
        from rebrew.verify import app

        result = CliRunner().invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "--experimental-unshare" in result.output

    def test_remote_conflict_before_probe(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import rebrew.verify as verify

        cfg = ProjectConfig(root=tmp_path, recompile_url="http://127.0.0.1:1234")
        monkeypatch.setattr(verify, "require_config", lambda **kw: cfg)
        result = CliRunner().invoke(verify.app, ["--experimental-unshare", "--json"])
        assert result.exit_code == 2
        assert "remote recompile" in result.output
        assert not cfg.execution_backend

    def test_preflight_failure_writes_no_metadata(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import rebrew.compiler.toolchain as tc
        import rebrew.verify as verify

        cfg = ProjectConfig(root=tmp_path)
        monkeypatch.setattr(verify, "require_config", lambda **kw: cfg)

        def denied(spec: Any) -> None:
            raise ToolchainError("user namespaces blocked")

        monkeypatch.setattr(tc, "check_experimental_unshare", denied)
        result = CliRunner().invoke(verify.app, ["--experimental-unshare", "--json"])
        assert result.exit_code == 2 and "namespaces blocked" in result.output
        assert not cfg.execution_backend
        assert list(tmp_path.iterdir()) == []


def _native_rootfs(tmp_path: Path) -> Path:
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() == 0:
        pytest.skip("requires unprivileged Linux x86_64")
    cc = shutil.which("cc")
    pkg = shutil.which("pkg-config")
    if not cc or not pkg or subprocess.run([pkg, "--exists", "json-c"]).returncode:
        pytest.skip("requires cc and json-c development files")
    source = tmp_path / "probe.c"
    source.write_text(r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "fail")) return 7;
    if (argc > 1 && !strcmp(argv[1], "exit125")) { fputs("compiler exit 125\n", stderr); return 125; }
    if (getuid() != 1000 || getgid() != 1000 || prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0) != 1) return 10;
    for (int c=0; c<=CAP_LAST_CAP; ++c) if (prctl(PR_CAPBSET_READ,c,0,0,0) != 0) return 11;
    if (argc > 1 && !strcmp(argv[1], "sleep")) {
        if (!fork()) setsid();
        for (;;) {
            FILE *f=fopen("/work/heartbeat", "a"); if (!f) return 12;
            fputs("x", f); fclose(f); usleep(20000);
        }
    }
    char ns[128]; ssize_t n=readlink("/proc/self/ns/net",ns,sizeof(ns)-1); if(n<0)return 13; ns[n]=0;
    if (!strcmp(ns,getenv("HOST_NET"))) return 14;
    FILE *header=fopen("/sdk/include/value.h", "r"); if(!header)return 15;
    char text[32]; if(!fgets(text,sizeof(text),header)||strcmp(text,"SEVEN\n"))return 16; fclose(header);
    if (fopen("/sdk/include/should-not-write", "w")) return 17;
    if (fopen("/etc/should-not-write", "w")) return 18;
    if (fopen("/opt/wineprefix/written", "r")) return 19;
    FILE *f=fopen("/opt/wineprefix/written", "w"); if(!f)return 20; fclose(f);
    f=fopen("/home/rebrew/written", "w"); if(!f)return 21; fclose(f);
    f=fopen("/work/output", "w"); if(!f)return 22; fputs("MATCH",f); fclose(f);
    puts("OK"); return 0;
}
""")
    rootfs = tmp_path / "rootfs"
    for path in (
        "bin",
        "dev",
        "proc",
        "sys",
        "tmp",
        "work",
        "etc",
        "home/rebrew",
        "opt/wineprefix",
    ):
        (rootfs / path).mkdir(parents=True, exist_ok=True)
    compiled = subprocess.run(
        [cc, "-static", "-O2", str(source), "-o", str(rootfs / "bin/probe")],
        capture_output=True,
        text=True,
    )
    if compiled.returncode and any(
        word in compiled.stderr
        for word in ("cannot find -lc", "cannot find crt", "cannot find -lgcc")
    ):
        pytest.skip("static C runtime not installed")
    assert compiled.returncode == 0, compiled.stderr
    return rootfs


class TestUnshareNative:
    def test_overlay_includes_concurrency_and_timeout(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from concurrent.futures import ThreadPoolExecutor

        rootfs = _native_rootfs(tmp_path)
        cache = tmp_path / "cache"
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
        monkeypatch.setattr(unshare, "_image", lambda *_: (rootfs, _info()))
        sdk = tmp_path / "sdk"
        sdk.mkdir()
        (sdk / "value.h").write_text("SEVEN\n")
        env = {"HOST_NET": str(Path("/proc/self/ns/net").readlink())}

        def invoke(
            work: Path, args: list[str], timeout: int = 5
        ) -> subprocess.CompletedProcess[str]:
            work.mkdir(exist_ok=True)
            return unshare.run_unshare(
                _IMAGE_ID,
                args,
                entrypoint=None,
                workdir=work,
                mounts=[(str(sdk), "/sdk/include")],
                env=env,
                timeout=timeout,
            )

        first = tmp_path / "work-one"
        try:
            result = invoke(first, [])
        except unshare.UnshareError as exc:
            if any(
                s in str(exc)
                for s in (
                    "clone user/pid: Operation not permitted",
                    "unshare: Operation not permitted",
                    "rootless overlay mount (requires user-namespace overlayfs): Operation not permitted",
                    "Function not implemented",
                )
            ):
                pytest.skip(f"host disables rootless namespace/overlay support: {exc}")
            raise
        assert result.stdout == "OK\n" and result.returncode == 0
        assert (first / "output").read_text() == "MATCH"
        assert not (sdk / "should-not-write").exists()
        assert not (rootfs / "home/rebrew/written").exists()
        assert not (rootfs / "sdk").exists()
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = [pool.submit(invoke, tmp_path / f"parallel-{i}", []) for i in range(2)]
            assert [job.result().returncode for job in jobs] == [0, 0]
        assert invoke(first, ["fail"]).returncode == 7
        assert invoke(first, ["exit125"]).returncode == 125
        with pytest.raises(unshare.UnshareError, match="timed out"):
            invoke(first, ["sleep"], timeout=1)
        # A child that called setsid must also stop: PID-namespace teardown,
        # rather than the caller's process-group kill alone, owns its lifetime.
        heartbeat = first / "heartbeat"
        assert heartbeat.exists()
        import time

        previous = heartbeat.stat().st_size
        time.sleep(0.1)
        assert heartbeat.stat().st_size == previous
        assert list((cache / "rebrew/tmp").iterdir()) == []


class TestExecutionBackendConfig:
    @pytest.mark.parametrize("backend", ["docker", "podman", "unshare"])
    def test_project_and_target_override(self, tmp_path: Path, backend: str) -> None:
        from rebrew.config import load_config

        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "game"\n'
            '[compiler]\nexecution_backend = "docker"\n'
            '[targets.game]\nbinary = "game.exe"\n'
            f'[targets.game.compiler]\nexecution_backend = "{backend}"\n'
        )
        cfg = load_config(root=tmp_path)
        assert cfg.execution_backend == backend
        assert cfg.as_dict()["execution_backend"] == backend

    @pytest.mark.parametrize(
        "value", ['"container"', '"experimental-unshare"', '"runc"', "true", "7"]
    )
    def test_invalid_backend_rejected(self, tmp_path: Path, value: str) -> None:
        from rebrew.config import ConfigError, load_config

        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "game"\n'
            f"[compiler]\nexecution_backend = {value}\n"
            '[targets.game]\nbinary = "game.exe"\n'
        )
        with pytest.raises(ConfigError, match="execution_backend must be"):
            load_config(root=tmp_path)

    def test_configured_unshare_preflights_without_flag(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import rebrew.compiler.toolchain as tc
        import rebrew.verify as verify

        cfg = ProjectConfig(root=tmp_path, execution_backend="unshare")
        monkeypatch.setattr(verify, "require_config", lambda **kw: cfg)

        def denied(spec: Any) -> None:
            raise ToolchainError("namespace preflight denied")

        monkeypatch.setattr(tc, "check_experimental_unshare", denied)
        result = CliRunner().invoke(verify.app, ["--json"])
        assert result.exit_code == 2 and "namespace preflight denied" in result.output
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.parametrize("backend", ["docker", "podman"])
    def test_explicit_backend_controls_image_run_and_kill(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, backend: str
    ) -> None:
        import rebrew.compiler.toolchain as tc

        commands: list[list[str]] = []
        monkeypatch.setenv(
            "REBREW_CONTAINER_RUNTIME", "podman" if backend == "docker" else "docker"
        )
        monkeypatch.setattr(tc, "docker_available", lambda runtime=None: True)
        monkeypatch.setattr(tc, "image_present", lambda *a, **kw: True)

        def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            commands.append(args)
            if "run" in args:
                raise subprocess.TimeoutExpired(args, 1)
            return subprocess.CompletedProcess(args, 0, "", "")

        monkeypatch.setattr(tc.subprocess, "run", run)
        with pytest.raises(ToolchainError, match="invocation failed"):
            tc.run_toolchain(
                TOOLCHAINS["msvc-6.0-sp5"], [], workdir=tmp_path, execution_backend=backend
            )
        assert [cmd[:2] for cmd in commands] == [[backend, "run"], [backend, "kill"]]

    def test_daemon_image_memos_are_separate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.compiler.toolchain as tc

        monkeypatch.setattr(tc, "_toolchain_digest_cache", {})

        def inspect(args: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                args, 0, "sha256:" + ("a" if args[0] == "docker" else "b") * 64, ""
            )

        monkeypatch.setattr(tc.subprocess, "run", inspect)
        assert tc.cached_image_digest("same:tag", runtime="docker") == "sha256:" + "a" * 64
        assert tc.cached_image_digest("same:tag", runtime="podman") == "sha256:" + "b" * 64
        tc.invalidate_toolchain_digest("same:tag")
        assert not tc._toolchain_digest_cache

    def test_runtime_like_image_name_cannot_collide(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.compiler.toolchain as tc

        monkeypatch.setenv("REBREW_CONTAINER_RUNTIME", "docker")
        monkeypatch.setattr(tc, "_toolchain_digest_cache", {})
        monkeypatch.setattr(tc, "_image_presence", {})
        monkeypatch.setattr(tc, "docker_available", lambda runtime=None: True)

        def inspect(args: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
            named = args[-1] == "docker:tag"
            digest = "sha256:" + ("a" if named else "b") * 64
            return subprocess.CompletedProcess(
                args, 0 if "--format" in args or named else 1, digest, ""
            )

        monkeypatch.setattr(tc.subprocess, "run", inspect)
        assert tc.cached_image_digest("docker:tag") == "sha256:" + "a" * 64
        assert tc.cached_image_digest("tag", runtime="docker") == "sha256:" + "b" * 64
        assert tc.image_present("docker:tag")
        assert not tc.image_present("tag", runtime="docker")
        tc.invalidate_toolchain_digest("tag")
        assert tc.cached_image_digest("docker:tag") == "sha256:" + "a" * 64


class TestUnshareCleanup:
    def test_interruption_removes_private_bundle(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        _fake_execution(monkeypatch, tmp_path)
        bundle = tmp_path / "rebrew_unshare_interrupted"
        bundle.mkdir()
        monkeypatch.setattr(unshare, "writable_temp_dir", lambda *_: bundle)

        def interrupt(*a: Any, **kw: Any) -> None:
            restricted = bundle / "upper" / "work"
            restricted.mkdir()
            restricted.chmod(0)
            raise KeyboardInterrupt

        monkeypatch.setattr(unshare, "_command", interrupt)
        with pytest.raises(KeyboardInterrupt):
            unshare.run_unshare(
                _IMAGE_ID, [], entrypoint=None, workdir=tmp_path, mounts=[], env={}, timeout=1
            )
        assert not bundle.exists()

    def test_abandoned_mode_zero_overlay_is_swept(self, tmp_path: Path) -> None:
        from rebrew.compiler.temp_dirs import sweep_stale_temp_dirs

        bundle = tmp_path / "rebrew_unshare_abandoned"
        restricted = bundle / "overlay-work" / "work"
        restricted.mkdir(parents=True)
        restricted.chmod(0)
        outside = tmp_path / "unrelated"
        outside.mkdir()
        outside.chmod(0o500)
        (bundle / "external-link").symlink_to(outside, target_is_directory=True)
        assert sweep_stale_temp_dirs(tmp_path, age_s=0) == [bundle]
        assert outside.stat().st_mode & 0o777 == 0o500
        outside.chmod(0o700)


class TestUnshareParentDeath:
    @pytest.mark.parametrize("victim", ["launcher", "caller", "interrupt"])
    def test_sigkill_stops_detached_descendants(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, victim: str
    ) -> None:
        import signal
        import sys
        import time

        rootfs = _native_rootfs(tmp_path)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        helper = unshare.prepare_backend()
        bundle = tmp_path / "bundle"
        work = tmp_path / "work"
        work.mkdir()
        for name in ("rootfs", "upper", "overlay-work"):
            (bundle / name).mkdir(parents=True)
        profile = unshare._profile(rootfs, _info(), bundle, ["sleep"], None, work, [], {})
        config = bundle / "config.json"
        config.write_text(json.dumps(profile))
        # A real caller lets the kernel deliver PDEATHSIG after caller SIGKILL.
        script = (
            "import subprocess,sys; "
            "p=subprocess.Popen(sys.argv[1:]); "
            "print(p.pid,flush=True); p.wait()"
        )
        with (tmp_path / "diagnostic").open("w+") as diagnostic:
            caller = subprocess.Popen(
                [sys.executable, "-c", script, str(helper), str(config)],
                stdout=subprocess.PIPE,
                stderr=diagnostic,
                text=True,
            )
            assert caller.stdout is not None
            launcher = int(caller.stdout.readline())
            heartbeat = work / "heartbeat"
            try:
                deadline = time.monotonic() + 5
                while (
                    not heartbeat.exists() and caller.poll() is None and time.monotonic() < deadline
                ):
                    time.sleep(0.02)
                if not heartbeat.exists():
                    diagnostic.seek(0)
                    detail = diagnostic.read()
                    if "Operation not permitted" in detail or "Function not implemented" in detail:
                        pytest.skip(f"host disables namespace/overlay support: {detail}")
                    pytest.fail(f"native fixture did not start: {detail}")
                os.kill(
                    caller.pid if victim == "caller" else launcher,
                    signal.SIGINT if victim == "interrupt" else signal.SIGKILL,
                )
                caller.wait(timeout=5)
                # Detached descendants would continue appending after either parent died.
                time.sleep(0.2)
                size = heartbeat.stat().st_size
                time.sleep(0.2)
                assert heartbeat.stat().st_size == size
            finally:
                if caller.poll() is None:
                    caller.kill()
                    caller.wait(timeout=5)
                caller.stdout.close()
                for parent, directories, _ in os.walk(bundle, followlinks=False):
                    for name in directories:
                        directory = Path(parent) / name
                        if not directory.is_symlink():
                            directory.chmod(directory.stat().st_mode | 0o700)
                shutil.rmtree(bundle)


class TestUnshareImagePreparation:
    @pytest.mark.parametrize("fail_export", [False, True])
    def test_stopped_export_container_and_staging_are_removed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, fail_export: bool
    ) -> None:
        commands: list[list[str]] = []

        def command(args: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
            commands.append(args)
            if args[1:3] == ["image", "inspect"]:
                return subprocess.CompletedProcess(args, 0, json.dumps([_info()]), "")
            if args[1] == "export":
                if fail_export:
                    return subprocess.CompletedProcess(args, 1, "", "export failed")
                with tarfile.open(args[args.index("--output") + 1], "w") as archive:
                    entry = tarfile.TarInfo("probe")
                    entry.size = 1
                    archive.addfile(entry, io.BytesIO(b"x"))
            return subprocess.CompletedProcess(args, 0, "", "")

        monkeypatch.setattr(unshare, "_command", command)
        if fail_export:
            with pytest.raises(unshare.UnshareError, match="export failed"):
                unshare._image(tmp_path, _IMAGE_ID)
        else:
            filesystem, info = unshare._image(tmp_path, _IMAGE_ID)
            assert (filesystem / "probe").read_bytes() == b"x" and info == _info()
            before = len(commands)
            assert unshare._image(tmp_path, _IMAGE_ID) == (filesystem, info)
            assert len(commands) == before
        assert commands[-1][1:3] == ["rm", "--force"]
        assert not list((tmp_path / "images").glob("prepare-*"))
