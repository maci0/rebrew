"""Tests for decompme.py — decomp.me scratch uploader."""

import json
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.decompme as decompme

runner = CliRunner()


def _ann(va: int = 0x401000, size: int = 16, name: str = "func_a", symbol: str = "_func_a"):
    return SimpleNamespace(
        va=va,
        size=size,
        name=name,
        symbol=symbol,
        marker_type="FUNCTION",
        module="GAME",
        toolchain="msvc6",
        cflags="/O2",
    )


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        target_binary=tmp_path / "x.dll",
        reversed_dir=tmp_path / "src",
        root=tmp_path,
        target_name="T",
        metadata_dir=tmp_path,
        compiler_profile="msvc6",
        binary_format="pe",
        source_ext=".c",
        marker="T",
        cflags="/O2 /Gd",
    )


class TestMappings:
    def test_compiler_map(self) -> None:
        assert decompme.map_compiler("msvc6") == "msvc6.0"
        assert decompme.map_compiler("msvc600sp6") == "msvc6.0"
        assert decompme.map_compiler("msvc7.1") == "msvc7.1"
        assert decompme.map_compiler("gcc-pe") is None  # must be explicit
        assert decompme.map_compiler(None) is None

    def test_platform_map(self) -> None:
        assert decompme.map_platform("PE") == "win32"
        assert decompme.map_platform("mz") == "msdos"
        assert decompme.map_platform("ne") == "msdos"
        assert decompme.map_platform("elf") is None


class TestBuildPayload:
    def test_payload_shape(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir).mkdir(exist_ok=True)
        src = cfg.reversed_dir / "func_a.c"
        src.write_text(
            "// FUNCTION: T 0x401000\n// SIZE: 16\nint func_a(void){return 0;}\n", encoding="utf-8"
        )
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes",
            lambda p, va, size: b"\x55\x8b\xec\x5d\xc3" * 3,
        )
        payload = decompme.build_scratch_payload(
            cfg,
            src,
            va=0x401000,
            size=16,
            symbol="_func_a",
            name="func_a",
            compiler="msvc6.0",
            platform="win32",
            compiler_flags="/O1",
            context="struct Vec { int x; };\n",
        )
        data = payload["data"]
        assert data["compiler"] == "msvc6.0"
        assert data["platform"] == "win32"
        assert data["compiler_flags"] == "/O1"
        assert data["diff_label"] == "_func_a"
        assert json.loads(data["diff_flags"]) == ["--disassemble=_func_a"]
        assert "struct Vec" in data["context"]
        assert "func_a" in data["source_code"]
        assert data["name"] == "func_a"
        fname, fbytes, ftype = payload["files"]["target_obj"]
        assert fname.endswith(".o")
        assert ftype == "application/octet-stream"
        # The uploaded object is a valid i386 COFF.
        assert struct.unpack_from("<H", fbytes, 0)[0] == 0x014C

    def test_missing_target_bytes_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _cfg(tmp_path)
        src = tmp_path / "f.c"
        src.write_text("int f(void){return 0;}\n", encoding="utf-8")
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda *a, **k: b"")
        with pytest.raises(ValueError, match="failed to extract"):
            decompme.build_scratch_payload(
                cfg,
                src,
                va=0x1000,
                size=8,
                symbol="f",
                name="f",
                compiler="msvc6.0",
                platform="win32",
                compiler_flags="",
                context="",
            )


class TestUpload:
    def test_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: dict = {}

        def _fake_post(url, **kwargs):
            calls["url"] = url
            calls["data"] = kwargs.get("data")
            calls["files"] = kwargs.get("files")
            return SimpleNamespace(
                status_code=201, json=lambda: {"slug": "abc123", "claim_token": "tok"}
            )

        monkeypatch.setattr("rebrew.decompme.httpx.post", _fake_post)
        result = decompme.upload_scratch(
            {"data": {"compiler": "x"}, "files": {"target_obj": ("a.o", b"\x00", "x")}}
        )
        assert result == {"slug": "abc123", "claim_token": "tok"}
        assert calls["url"] == "https://decomp.me/api/scratch"
        assert calls["data"] == {"compiler": "x"}

    def test_http_error_surfaced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _fake_post(url, **kwargs):
            return SimpleNamespace(status_code=400, text="Unknown compiler: nope")

        monkeypatch.setattr("rebrew.decompme.httpx.post", _fake_post)
        with pytest.raises(RuntimeError, match="Unknown compiler"):
            decompme.upload_scratch({"data": {}, "files": {}})

    def test_transport_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        def _fake_post(url, **kwargs):
            raise httpx.ConnectError("boom")

        monkeypatch.setattr("rebrew.decompme.httpx.post", _fake_post)
        with pytest.raises(RuntimeError, match="boom"):
            decompme.upload_scratch({"data": {}, "files": {}})

    def test_scratch_url(self) -> None:
        assert decompme.scratch_url("abc", "tok") == "https://decomp.me/scratch/abc/claim?token=tok"


class TestCli:
    def _patch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> tuple[SimpleNamespace, Path]:
        cfg = _cfg(tmp_path)
        cfg.reversed_dir.mkdir(exist_ok=True)
        src = cfg.reversed_dir / "func_a.c"
        src.write_text(
            "// FUNCTION: T 0x401000\n// SIZE: 16\nint func_a(void){return 0;}\n", encoding="utf-8"
        )
        monkeypatch.setattr(decompme, "require_config", lambda target=None, json_mode=False: cfg)
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes",
            lambda p, va, size: b"\x55\x8b\xec\x5d\xc3" * 3,
        )
        monkeypatch.setattr(
            "rebrew.annotation.parse_c_file_multi",
            lambda p, target_name=None, metadata_dir=None: [_ann()],
        )
        monkeypatch.setattr(
            "rebrew.cli.resolve_compile_overrides", lambda cfg, d, a, b, c: ("msvc6", "/O1")
        )
        monkeypatch.setattr(
            "rebrew.context._collect_context", lambda cfg: (["struct Vec { int x; };"], 1)
        )
        return cfg, src

    def test_dry_run_no_upload(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg, src = self._patch(tmp_path, monkeypatch)
        r = runner.invoke(decompme.app, ["--dry-run", str(src)])
        assert r.exit_code == 0
        assert "compiler:    msvc6.0" in r.output
        assert "platform:    win32" in r.output
        assert "no upload" in r.output

    def test_json_dry_run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg, src = self._patch(tmp_path, monkeypatch)
        r = runner.invoke(decompme.app, ["--dry-run", "--json", str(src)])
        assert r.exit_code == 0
        data = json.loads(r.stdout)
        assert data["dry_run"] is True
        assert data["compiler"] == "msvc6.0"
        assert data["platform"] == "win32"
        assert data["va"] == "0x00401000"

    def test_unmapped_toolchain_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg, src = self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.cli.resolve_compile_overrides", lambda cfg, d, a, b, c: ("gcc-pe", "-O2")
        )
        r = runner.invoke(decompme.app, ["--dry-run", str(src)])
        assert r.exit_code == 2
        assert "--compiler" in r.output

    def test_upload_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg, src = self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.decompme.httpx.post",
            lambda url, **kw: SimpleNamespace(
                status_code=201, json=lambda: {"slug": "abc", "claim_token": "tok"}
            ),
        )
        r = runner.invoke(decompme.app, [str(src)])
        assert r.exit_code == 0
        assert "https://decomp.me/scratch/abc/claim?token=tok" in r.output

    def test_upload_rejection(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg, src = self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.decompme.httpx.post",
            lambda url, **kw: SimpleNamespace(status_code=400, text="Unknown platform: nope"),
        )
        r = runner.invoke(decompme.app, [str(src)])
        assert r.exit_code == 2
        assert "Unknown platform" in r.output


class TestVerifyCompiler:
    def test_known_compiler_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        def _fake_get(url, timeout):
            return SimpleNamespace(
                status_code=200,
                json=lambda: {
                    "compilers": {"msvc6.0": {"platform": "win32"}},
                    "platforms": {"win32": {}},
                },
            )

        monkeypatch.setattr(httpx, "get", _fake_get)
        decompme.verify_compiler("msvc6.0")  # must not raise

    def test_unknown_compiler_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        def _fake_get(url, timeout):
            return SimpleNamespace(
                status_code=200,
                json=lambda: {"compilers": {"msvc6.0": {}, "msvc7.1": {}}, "platforms": {}},
            )

        monkeypatch.setattr(httpx, "get", _fake_get)
        with pytest.raises(RuntimeError, match="not in the decomp.me registry"):
            decompme.verify_compiler("gcc-pe")
        with pytest.raises(RuntimeError, match="msvc6.0"):
            decompme.verify_compiler("nope")  # suggestion lists known ids

    def test_transport_failure_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        def _fake_get(url, timeout):
            raise httpx.ConnectError("cf")

        monkeypatch.setattr(httpx, "get", _fake_get)
        decompme.verify_compiler("msvc6.0")  # warning, no raise

    def test_http_error_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        monkeypatch.setattr(
            httpx, "get", lambda url, timeout: SimpleNamespace(status_code=403, text="cf")
        )
        decompme.verify_compiler("msvc6.0")  # warning, no raise
