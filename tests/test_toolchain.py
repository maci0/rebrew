"""Tests for rebrew.toolchain — standardized toolchain invocation."""

from __future__ import annotations

from pathlib import Path

import pytest

from rebrew.toolchain import (
    TOOLCHAINS,
    ToolchainError,
    ToolchainSpec,
    get_toolchain,
    run_toolchain,
)


class _FakeProc:
    def __init__(self, rc: int = 0, out: str = "", err: str = "") -> None:
        self.returncode = rc
        self.stdout = out
        self.stderr = err


def _monkey_docker(monkeypatch, *, available: bool = True, image: bool = True) -> list[list[str]]:
    """Fake docker availability + image presence + capture invocations."""
    calls: list[list[str]] = []

    def _run(cmd, **kwargs):
        calls.append(cmd)
        return _FakeProc(0, "compiled ok", "")

    monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: available)
    monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: available and image)
    monkeypatch.setattr("rebrew.toolchain.subprocess.run", _run)
    return calls


class TestRegistry:
    def test_known_toolchains(self) -> None:
        assert {"msvc6", "delphi16", "gcc-pe"} <= set(TOOLCHAINS)

    def test_get_unknown_raises(self) -> None:
        with pytest.raises(ToolchainError, match="unknown toolchain"):
            get_toolchain("nope")

    def test_delphi16_host_binary_name(self) -> None:
        # The host executable is DCC.EXE (uppercase on disk); the docker
        # image's ENTRYPOINT is the dcc wrapper, so no command is passed.
        spec = TOOLCHAINS["delphi16"]
        assert spec.binary == "DCC.EXE"
        assert spec.image_binary is None

    def test_family_derived_from_image_tag(self) -> None:
        """The toolchain-images/ top-level dir is the unversioned family
        (Godbolt-style), derived from the image repository — never the
        version-encoded profile id (msvc1.52 -> msvc/, delphi16 ->
        delphi/)."""
        assert TOOLCHAINS["msvc6"].family == "msvc"
        assert TOOLCHAINS["msvc1.52"].family == "msvc"
        assert TOOLCHAINS["delphi16"].family == "delphi"
        assert TOOLCHAINS["watcom"].family == "watcom"
        # host-only spec: falls back to its name
        assert TOOLCHAINS["gcc-pe"].family == "gcc-pe"


class TestRunToolchain:
    def test_docker_backend_uses_image_and_mount(self, tmp_path: Path, monkeypatch) -> None:
        spec = ToolchainSpec(name="t", image="rebrew/t:latest", binary="cl", image_binary="cl")
        calls = _monkey_docker(monkeypatch)
        r = run_toolchain(spec, ["/c", "f.c"], workdir=tmp_path)
        assert r.backend == "docker"
        assert r.ok
        assert calls[0][:5] == ["docker", "run", "--rm", "-v", f"{tmp_path.resolve()}:/work"]
        assert calls[0][5:9] == ["-w", "/work", "rebrew/t:latest", "cl"]
        assert calls[0][9:] == ["/c", "f.c"]

    def test_docker_entrypoint_image_passes_no_command(self, tmp_path: Path, monkeypatch) -> None:
        """image_binary=None means the image ENTRYPOINT is the compiler —
        no command is appended after the image tag (Godbolt convention)."""
        spec = ToolchainSpec(name="t", image="rebrew/t:latest", binary="wcc386")
        calls = _monkey_docker(monkeypatch)
        run_toolchain(spec, ["-zq", "f.c"], workdir=tmp_path)
        assert calls[0][8:] == ["-zq", "f.c"]

    def test_docker_uses_image_binary_shim(self, tmp_path: Path, monkeypatch) -> None:
        spec = ToolchainSpec(
            name="t", image="rebrew/t:latest", binary="DCC.EXE", image_binary="dcc"
        )
        calls = _monkey_docker(monkeypatch)
        run_toolchain(spec, ["hello.dpr"], workdir=tmp_path)
        assert calls[0][8] == "dcc"

    def test_host_fallback_uses_vendored_path(self, tmp_path: Path, monkeypatch) -> None:
        dcc = tmp_path / "delphi-1.0-win16" / "DCC.EXE"
        dcc.parent.mkdir(parents=True)
        dcc.write_bytes(b"MZ")
        spec = ToolchainSpec(
            name="t", image=None, binary="DCC.EXE", host_path=tmp_path / "delphi-1.0-win16"
        )
        calls: list[list[str]] = []

        def _run(cmd, **kwargs):
            calls.append(cmd)
            return _FakeProc(1, "", "err")

        monkeypatch.setattr("rebrew.toolchain.subprocess.run", _run)
        r = run_toolchain(spec, ["x.dpr"], workdir=tmp_path)
        assert r.backend == "host"
        assert not r.ok
        assert calls[0][0] == str(dcc)

    def test_host_fallback_wine_runtime_prefixes_wine(self, tmp_path: Path, monkeypatch) -> None:
        """A wine-runtime spec without an image (msvc420/msvc5) must invoke
        the vendored PE through the wine loader — the old host fallback
        exec'd CL.EXE directly, which can never run on Linux (EACCES)."""
        cl = tmp_path / "vc" / "bin" / "CL.EXE"
        cl.parent.mkdir(parents=True)
        cl.write_bytes(b"MZ")
        spec = ToolchainSpec(
            name="t",
            image=None,
            binary="cl",
            runtime="wine",
            host_path=tmp_path / "vc",
            host_bin="Bin",
        )
        calls: list[list[str]] = []

        def _run(cmd, **kwargs):
            calls.append(cmd)
            return _FakeProc(0, "", "")

        monkeypatch.setattr("rebrew.toolchain.subprocess.run", _run)
        monkeypatch.setattr("rebrew.toolchain.os.environ", {"HOME": str(tmp_path)})
        r = run_toolchain(spec, ["/c", "t.c"], workdir=tmp_path)
        assert r.backend == "host"
        assert r.ok
        assert calls[0] == ["wine", str(cl), "/c", "t.c"]

    def test_no_backend_raises(self, tmp_path: Path, monkeypatch) -> None:
        _monkey_docker(monkeypatch, available=False, image=False)
        monkeypatch.setattr("rebrew.toolchain.shutil.which", lambda *a, **k: None)
        spec = ToolchainSpec(name="t", image="rebrew/t:latest", binary="nope")
        with pytest.raises(ToolchainError, match="no host binary"):
            run_toolchain(spec, [], workdir=tmp_path)


class TestCli:
    def test_list_registered_in_umbrella(self) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["toolchain", "list", "--json"])
        assert result.exit_code == 0, result.output
        import json

        data = json.loads(result.stdout)
        assert {t["name"] for t in data["toolchains"]} >= {
            "msvc5",
            "msvc420",
            "msvc6",
            "delphi16",
        }

    def test_unknown_status_errors(self) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["toolchain", "status", "nope"])
        assert result.exit_code != 0

    def test_pull_host_only_errors(self, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: False)
        result = CliRunner().invoke(umbrella, ["toolchain", "pull", "gcc-pe"])
        assert result.exit_code == 2
        assert "host-only" in result.output

    def test_pull_unknown_errors(self) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["toolchain", "pull", "nope"])
        assert result.exit_code == 2
        assert "unknown toolchain" in result.output

    def test_detect_json_standalone(self, tmp_path: Path, monkeypatch) -> None:
        """`toolchain detect` works without a project; no profile keys in JSON."""
        import json

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella
        from rebrew.toolchain_detect import ToolchainInfo

        bin_path = tmp_path / "x.exe"
        bin_path.write_bytes(b"MZ\x90\x00")
        monkeypatch.chdir(tmp_path)  # no rebrew-project.toml here — standalone mode
        info = ToolchainInfo(
            family="msvc",
            version_hint="MSVC 6.0",
            confidence="high",
            detected_by="die",
            evidence=["Compiler: Microsoft Visual C/C++"],
        )
        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", lambda p: info)
        result = CliRunner().invoke(umbrella, ["toolchain", "detect", str(bin_path), "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["family"] == "msvc"
        assert data["version_hint"] == "MSVC 6.0"
        assert data["confidence"] == "high"
        assert "msvc6" in data["compatible_profiles"]
        assert "profile" not in data and "aligned" not in data

    def test_detect_alignment_mismatch(self, tmp_path: Path, monkeypatch) -> None:
        """A project profile that cannot byte-match the detection is flagged."""
        import json

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella
        from rebrew.toolchain_detect import ToolchainInfo

        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\nname = "t"\ndefault_target = "main"\n'
            '[targets."main"]\nbinary = "original/x.exe"\n'
            '[compiler]\nprofile = "msvc6"\n'
        )
        bin_path = tmp_path / "x.exe"
        bin_path.write_bytes(b"MZ\x90\x00")
        monkeypatch.chdir(tmp_path)
        info = ToolchainInfo(
            family="msvc",
            version_hint="16-bit MSVC-style NE",
            confidence="medium",
            detected_by="heuristics",
            arch="x86_16",
        )
        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", lambda p: info)
        result = CliRunner().invoke(umbrella, ["toolchain", "detect", "x.exe", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["profile"] == "msvc6"
        assert data["aligned"] is False
        assert "msvc1.52" in data["explanation"]

    def test_detect_missing_binary_errors(self, tmp_path: Path, monkeypatch) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(umbrella, ["toolchain", "detect", "nope.exe", "--json"])
        assert result.exit_code == 2
        data = json.loads(result.stdout)
        assert data["error"] and data["code"] == 2

    def test_build_host_only_errors(self, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["toolchain", "build", "gcc-pe"])
        assert result.exit_code == 2
        assert "host-only" in result.output

    def test_build_missing_dockerfile_errors(self, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        monkeypatch.setattr("rebrew.toolchain_cli.Path.exists", lambda self: False)
        result = CliRunner().invoke(umbrella, ["toolchain", "build", "watcom"])
        assert result.exit_code == 2
        assert "Dockerfile" in result.output


class TestPullToolchain:
    """pull_toolchain treats locally-present images as a successful no-op
    (they are built via `toolchain build`, not pulled from a registry)."""

    def test_already_present_skips_docker_pull(self, monkeypatch) -> None:
        from rebrew.toolchain import pull_toolchain

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: True)
        called: list[str] = []
        monkeypatch.setattr(
            "rebrew.toolchain.subprocess.run",
            lambda *a, **k: called.append(a) or type("R", (), {"returncode": 0})(),
        )
        tag, was_present = pull_toolchain("msvc6")
        assert tag == "rebrew/msvc:6.0-win32"
        assert was_present is True
        assert not called  # no docker pull subprocess for a local image

    def test_absent_image_does_pull(self, monkeypatch) -> None:
        from rebrew.toolchain import pull_toolchain

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        monkeypatch.setattr(
            "rebrew.toolchain.subprocess.run",
            lambda *a, **k: type("R", (), {"returncode": 0})(),
        )
        tag, was_present = pull_toolchain("msvc6")
        assert tag == "rebrew/msvc:6.0-win32"
        assert was_present is False

    def test_cli_reports_already_present(self, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: True)
        result = CliRunner().invoke(umbrella, ["toolchain", "pull", "msvc6", "--json"])
        assert result.exit_code == 0
        assert '"already_present": true' in result.output
        assert '"pulled": "rebrew/msvc:6.0-win32"' in result.output


class TestResolveBinaryCaseInsensitive:
    """DOS-era vendored trees use uppercase subdirs (BIN) — the resolver
    must match host_bin case-insensitively (MSVC 1.52 regression)."""

    def test_uppercase_bin_resolves(self, tmp_path: Path) -> None:
        from rebrew.toolchain import ToolchainSpec, _resolve_binary

        (tmp_path / "BIN").mkdir()
        (tmp_path / "BIN" / "CL.EXE").write_bytes(b"")
        spec = ToolchainSpec(
            name="msvc1.52",
            image=None,
            binary="CL.EXE",
            host_bin="Bin",  # spec says Bin, disk says BIN
            host_path=str(tmp_path),
        )
        resolved = _resolve_binary(spec)
        assert resolved == str(tmp_path / "BIN" / "CL.EXE")

    def test_exact_case_still_works(self, tmp_path: Path) -> None:
        from rebrew.toolchain import ToolchainSpec, _resolve_binary

        (tmp_path / "Bin").mkdir()
        (tmp_path / "Bin" / "cl").write_bytes(b"")
        spec = ToolchainSpec(
            name="watcom",
            image=None,
            binary="cl",
            host_bin="Bin",
            host_path=str(tmp_path),
        )
        assert _resolve_binary(spec) == str(tmp_path / "Bin" / "cl")

    def test_exe_suffix_tolerated_in_subdir(self, tmp_path: Path) -> None:
        """binary="cl" must resolve CL.EXE in the host_bin subdir (vendored
        Windows trees store the .exe; specs name the bare binary)."""
        from rebrew.toolchain import ToolchainSpec, _resolve_binary

        (tmp_path / "Bin").mkdir()
        (tmp_path / "Bin" / "CL.EXE").write_bytes(b"")
        spec = ToolchainSpec(
            name="msvc5",
            image=None,
            binary="cl",
            host_bin="Bin",
            host_path=str(tmp_path),
        )
        assert _resolve_binary(spec) == str(tmp_path / "Bin" / "CL.EXE")

    def test_exe_suffix_tolerated_at_root(self, tmp_path: Path) -> None:
        """binary="cl" must also resolve cl.exe directly in host_path."""
        from rebrew.toolchain import ToolchainSpec, _resolve_binary

        (tmp_path / "cl.exe").write_bytes(b"")
        spec = ToolchainSpec(
            name="msvc5",
            image=None,
            binary="cl",
            host_path=str(tmp_path),
        )
        assert _resolve_binary(spec) == str(tmp_path / "cl.exe")

    def test_status_uses_shared_resolver(self, monkeypatch, tmp_path: Path) -> None:
        """toolchain status must agree with _resolve_binary (case-insensitive
        host_bin) instead of its own case-sensitive path check."""
        import json

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        (tmp_path / "BIN").mkdir()
        (tmp_path / "BIN" / "CL.EXE").write_bytes(b"")
        monkeypatch.setattr(
            "rebrew.toolchain.TOOLCHAINS",
            {
                "msvc1.52": __import__(
                    "rebrew.toolchain", fromlist=["ToolchainSpec"]
                ).ToolchainSpec(
                    name="msvc1.52",
                    image=None,
                    binary="CL.EXE",
                    host_bin="Bin",
                    host_path=str(tmp_path),
                )
            },
        )
        result = CliRunner().invoke(umbrella, ["toolchain", "status", "msvc1.52", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["host_binary_present"] is True


class TestDosboxHostFallbackGuard:
    """run_toolchain must not exec a DOS binary natively when the image is
    absent — dosbox-runtime specs fail with a clear routing error instead
    of a cryptic Permission denied / Exec format error."""

    def test_msvc152_dosbox_guard(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.toolchain import TOOLCHAINS, ToolchainError, run_toolchain

        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        with pytest.raises(ToolchainError, match="dosbox-runtime"):
            run_toolchain(TOOLCHAINS["msvc1.52"], ["t.c", "/O1"], workdir=tmp_path)

    def test_delphi16_dosbox_guard(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.toolchain import TOOLCHAINS, ToolchainError, run_toolchain

        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        with pytest.raises(ToolchainError, match="dosbox-runtime"):
            run_toolchain(TOOLCHAINS["delphi16"], ["hello.dpr"], workdir=tmp_path)

    def test_watcom_host_fallback_unaffected(self, tmp_path: Path, monkeypatch) -> None:
        """native-runtime toolchains keep the plain vendored-host fallback."""
        from rebrew.toolchain import TOOLCHAINS, run_toolchain

        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        spec = TOOLCHAINS["watcom"]
        # watcom has no vendored host on this box in CI — force resolution to fail
        # with the resolver error, NOT the dosbox guard (proves the guard doesn't
        # fire for native-runtime specs).
        monkeypatch.setattr(
            "rebrew.toolchain._resolve_binary",
            lambda spec: (_ for _ in ()).throw(ToolchainError("no host binary")),
        )
        with pytest.raises(ToolchainError, match="no host binary"):
            run_toolchain(spec, ["-zq", "f.c"], workdir=tmp_path)


class TestVc98Wrap:
    """MSVC 6.0's master layout wraps the tree in VC98/ (classic install
    layout — every legacy tools/MSVC600/VC98/... reference expects it); the
    decomp.me tarball is flat, so vendor and the docker image re-wrap."""

    def test_msvc6_source_wraps(self) -> None:
        from rebrew.toolchain import _SOURCES

        assert _SOURCES["msvc6"].vc98_wrap is True

    def test_other_sources_do_not_wrap(self) -> None:
        from rebrew.toolchain import _SOURCES

        for name, src in _SOURCES.items():
            if name != "msvc6":
                assert src.vc98_wrap is False, name

    def test_old_msvc_sources_pinned(self) -> None:
        """msvc400/msvc420/msvc5 must have pinned, sha256-verified sources:
        their host trees are smoke-gated for byte-reproducibility, so a fresh
        clone must be able to reproduce them via `rebrew toolchain vendor`
        (they were vendored but unpinnable before)."""
        from rebrew.toolchain import _SOURCES

        for name, expected_dir in (
            ("msvc400", "msvc/4.0-win32"),
            ("msvc420", "msvc/4.2-win32"),
            ("msvc5", "msvc/5.0-win32"),
        ):
            src = _SOURCES[name]
            assert src.host_dir == expected_dir, name
            assert src.url.startswith("https://") and src.sha256, name
            assert len(src.sha256) == 64, name
            assert src.layout == "tar-strip1", name


class TestCompatLinks:
    """ensure_compat_links recreates the gitignored tools/<alias> symlinks
    that legacy projects resolve tool paths through."""

    def _make_tree(self, tmp_path: Path, family: str = "msvc", version: str = "6.0-win32") -> Path:
        tree = tmp_path / "toolchain" / family / version
        (tree / "VC98" / "Bin").mkdir(parents=True)
        (tree / "VC98" / "Bin" / "CL.EXE").write_bytes(b"MZ")
        return tree

    def test_creates_legacy_alias(self, tmp_path: Path) -> None:
        from rebrew.toolchain_cli import ensure_compat_links

        self._make_tree(tmp_path)
        created = ensure_compat_links(tmp_path)
        names = {c.name for c in created}
        assert "MSVC600" in names
        link = tmp_path / "tools" / "MSVC600"
        assert link.is_symlink()
        assert (link / "VC98" / "Bin" / "CL.EXE").exists()

    def test_skips_missing_trees(self, tmp_path: Path) -> None:
        from rebrew.toolchain_cli import ensure_compat_links

        # No toolchain tree at all — nothing dangling should be created.
        created = ensure_compat_links(tmp_path)
        assert created == []
        assert not (tmp_path / "tools").exists() or not list((tmp_path / "tools").iterdir())

    def test_does_not_clobber_existing_link(self, tmp_path: Path) -> None:
        from rebrew.toolchain_cli import ensure_compat_links

        self._make_tree(tmp_path)
        tools = tmp_path / "tools"
        tools.mkdir()
        other = tmp_path / "somewhere-else"
        other.mkdir()
        (tools / "MSVC600").symlink_to(other, target_is_directory=True)
        created = ensure_compat_links(tmp_path)
        assert (tools / "MSVC600").readlink() == other
        assert not any(c.name == "MSVC600" for c in created)


class TestDockerfileSanity:
    """The toolchain Dockerfiles must stay parseable — a prior commit that
    added OCI labels to toolchain/base/Dockerfile accidentally deleted the
    leading `RUN dpkg --add-architecture i386` line, leaving a lone
    `&& apt-get update` that broke `rebrew toolchain build` for EVERY
    image (build_cmd rebuilds base first).  Static, CI-safe checks (no
    docker required) pin the structure."""

    _REPO = Path(__file__).resolve().parents[1]

    def _read(self, rel: str) -> str:
        return (self._REPO / rel).read_text(encoding="utf-8")

    def test_base_apt_block_has_run(self) -> None:
        text = self._read("toolchain/base/Dockerfile")
        # The apt block must be a single RUN continuation — a lone
        # `&& apt-get` (missing RUN) is a parse error.
        idx = text.index("&& apt-get update")
        prefix = text[:idx]
        assert "RUN dpkg --add-architecture i386" in prefix, (
            "base Dockerfile apt block lost its RUN prefix"
        )

    def test_no_lone_continuation_after_label_blocks(self) -> None:
        """Every tracked Dockerfile: any `&& ` line must be preceded (within
        the same block) by a `RUN ` line — the OCI-label insertion pattern
        dropped RUN prefixes in some files."""
        for f in sorted(Path(self._REPO / "toolchain").rglob("Dockerfile")):
            if "linux-x64" in str(f):
                continue
            lines = f.read_text(encoding="utf-8").splitlines()
            in_run = False
            for ln in lines:
                if ln.startswith("RUN "):
                    in_run = True
                    continue
                if ln.strip().startswith("&& ") and not in_run:
                    raise AssertionError(f"{f.relative_to(self._REPO)}: '&&' without RUN: {ln!r}")
                if ln.strip() and not ln.startswith((" ", "\t")) and not ln.startswith("#"):
                    in_run = False  # new instruction (RUN/LABEL/ENV/COPY/...)

    def test_every_image_spec_dockerfile_is_tracked(self) -> None:
        """Every image-backed toolchain must have its Dockerfile in git — a
        fresh clone must be able to rebuild the image (tc16/tc20 images
        were built from UNTRACKED Dockerfiles, silently unreproducible)."""
        import subprocess

        from rebrew.toolchain import TOOLCHAINS

        tracked = set(
            subprocess.run(
                ["git", "ls-files", "toolchain/"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.splitlines()
        )
        missing = []
        for name, spec in TOOLCHAINS.items():
            if spec.image is None:
                continue
            tag, verarch = spec.image.rsplit(":", 1)
            df = f"toolchain/{spec.family}/{verarch}/Dockerfile"
            if df not in tracked:
                missing.append(f"{name} ({df})")
        assert not missing, (
            "image-backed toolchains with untracked Dockerfiles (a fresh "
            "clone cannot rebuild them): " + ", ".join(missing)
        )


class TestSmokePrintGoldens:
    """`toolchain smoke --print-goldens` recomputes the masked hashes
    without comparing (the regeneration path for _SMOKE_GOLDEN after a
    toolchain source change)."""

    def test_print_goldens_emits_masked_hash(self, tmp_path: Path, monkeypatch, capsys) -> None:
        import hashlib
        import json
        import subprocess
        from types import SimpleNamespace

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        obj = b"OBJ" + b"\x01\x02\x03\x04" + b"TAIL"

        def _fake_run(cmd, **kwargs):  # noqa: ARG001
            # docker run ... image /c t.c → writes the object into /work (the
            # mounted host workdir /tmp/rebrew-smoke).
            from pathlib import Path

            (Path("/tmp/rebrew-smoke") / "t.obj").write_bytes(obj)
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr(subprocess, "run", _fake_run)
        result = CliRunner().invoke(
            umbrella, ["toolchain", "smoke", "msvc6", "--print-goldens", "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert set(payload) == {"goldens"}
        # msvc6 mask is (4,8): the TimeDateStamp is zeroed before hashing.
        masked = bytearray(obj)
        masked[4:8] = b"\x00" * 4
        assert payload["goldens"]["msvc6"] == hashlib.sha256(bytes(masked)).hexdigest()


class TestPullToolchainHint:
    """pull on an absent locally-built image must point at `toolchain
    build` — rebrew images are built from pinned sources, not on a
    registry, so a raw docker-pull failure is a dead end."""

    def test_pull_failure_suggests_build(self, monkeypatch) -> None:
        from types import SimpleNamespace

        from rebrew.toolchain import ToolchainError, pull_toolchain

        def _fake_run(cmd, **kwargs):  # noqa: ARG001
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"pull access denied")

        monkeypatch.setattr("rebrew.toolchain.docker_available", lambda: True)
        monkeypatch.setattr("rebrew.toolchain._image_present", lambda tag: False)
        monkeypatch.setattr("rebrew.toolchain.subprocess.run", _fake_run)
        with pytest.raises(ToolchainError, match="toolchain build msvc420"):
            pull_toolchain("msvc420")
