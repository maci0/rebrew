"""Tests for wibo download and runner integration helpers."""

import hashlib
import json
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.doctor import _PASS, _WARN, check_runner
from rebrew.wibo import _WIBO_API_URL, _wibo_asset_name, download_wibo, ensure_wibo, find_wibo


class _FakeHTTPResponse:
    def __init__(self, payload: str) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return self._payload.encode("utf-8")

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        del exc_type, exc, tb


class TestWiboAssetName:
    def test_linux_x86_64(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux", raising=False)
        monkeypatch.setattr("platform.machine", lambda: "x86_64")
        assert _wibo_asset_name() == "wibo-x86_64"

    def test_linux_i686(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux", raising=False)
        monkeypatch.setattr("platform.machine", lambda: "i686")
        assert _wibo_asset_name() == "wibo-i686"

    def test_darwin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "darwin", raising=False)
        monkeypatch.setattr("platform.machine", lambda: "arm64")
        assert _wibo_asset_name() == "wibo-macos"

    def test_unsupported_platform(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "platform", "win32", raising=False)
        monkeypatch.setattr("platform.machine", lambda: "AMD64")
        with pytest.raises(RuntimeError, match="Unsupported platform"):
            _wibo_asset_name()


class TestFindWibo:
    def test_not_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.wibo.shutil.which", lambda _name: None)
        assert find_wibo(tmp_path) is None

    def test_found_in_path(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        path_wibo = tmp_path / "wibo"
        path_wibo.write_bytes(b"binary")
        monkeypatch.setattr("rebrew.wibo.shutil.which", lambda _name: str(path_wibo))
        assert find_wibo(tmp_path) == path_wibo

    def test_found_project_local(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.wibo.shutil.which", lambda _name: None)
        local_wibo = tmp_path / "tools" / "wibo"
        local_wibo.parent.mkdir(parents=True)
        local_wibo.write_bytes(b"binary")
        assert find_wibo(tmp_path) == local_wibo


class TestDownloadWibo:
    def test_downloads_and_makes_executable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dest = tmp_path / "tools" / "wibo"
        fake_binary = b"fake-wibo-binary"
        digest = hashlib.sha256(fake_binary).hexdigest()

        payload = json.dumps(
            {
                "tag_name": "v0.9.0",
                "assets": [
                    {
                        "name": "wibo-x86_64",
                        "browser_download_url": "https://example.invalid/wibo-x86_64",
                        "digest": f"sha256:{digest}",
                    }
                ],
            }
        )

        monkeypatch.setattr(sys, "platform", "linux", raising=False)
        monkeypatch.setattr("platform.machine", lambda: "x86_64")

        def _fake_urlopen(url: str) -> _FakeHTTPResponse:
            assert url == _WIBO_API_URL
            return _FakeHTTPResponse(payload)

        def _fake_urlretrieve(url: str, out: Path) -> tuple[str, object]:
            assert url == "https://example.invalid/wibo-x86_64"
            Path(out).write_bytes(fake_binary)
            return (str(out), object())

        monkeypatch.setattr("rebrew.wibo.urllib.request.urlopen", _fake_urlopen)
        monkeypatch.setattr("rebrew.wibo.urllib.request.urlretrieve", _fake_urlretrieve)

        version = download_wibo(dest)
        assert version == "v0.9.0"
        assert dest.read_bytes() == fake_binary
        mode = dest.stat().st_mode
        assert mode & stat.S_IXUSR
        assert mode & stat.S_IXGRP
        assert mode & stat.S_IXOTH

    def test_sha256_verification_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dest = tmp_path / "tools" / "wibo"

        payload = json.dumps(
            {
                "tag_name": "v0.9.0",
                "assets": [
                    {
                        "name": "wibo-x86_64",
                        "browser_download_url": "https://example.invalid/wibo-x86_64",
                        "digest": "sha256:" + ("0" * 64),
                    }
                ],
            }
        )

        monkeypatch.setattr(sys, "platform", "linux", raising=False)
        monkeypatch.setattr("platform.machine", lambda: "x86_64")
        monkeypatch.setattr(
            "rebrew.wibo.urllib.request.urlopen", lambda _url: _FakeHTTPResponse(payload)
        )
        monkeypatch.setattr(
            "rebrew.wibo.urllib.request.urlretrieve",
            lambda _url, out: (str(out), Path(out).write_bytes(b"wrong-binary")),
        )

        with pytest.raises(RuntimeError, match="SHA256 mismatch"):
            download_wibo(dest)
        assert not dest.exists()

    def test_missing_asset_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        dest = tmp_path / "tools" / "wibo"
        payload = json.dumps({"tag_name": "v0.9.0", "assets": []})

        monkeypatch.setattr(sys, "platform", "linux", raising=False)
        monkeypatch.setattr("platform.machine", lambda: "x86_64")
        monkeypatch.setattr(
            "rebrew.wibo.urllib.request.urlopen", lambda _url: _FakeHTTPResponse(payload)
        )

        with pytest.raises(RuntimeError, match="asset not found"):
            download_wibo(dest)


class TestEnsureWibo:
    def test_already_exists_returns_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        existing = tmp_path / "tools" / "wibo"
        existing.parent.mkdir(parents=True)
        existing.write_bytes(b"binary")

        monkeypatch.setattr("rebrew.wibo.find_wibo", lambda _root: existing)
        assert ensure_wibo(tmp_path) == existing

    def test_downloads_when_missing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("rebrew.wibo.find_wibo", lambda _root: None)
        calls: list[Path] = []

        def _fake_download(dest: Path, *, quiet: bool = False) -> str:
            del quiet
            calls.append(dest)
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"binary")
            return "v0.9.0"

        monkeypatch.setattr("rebrew.wibo.download_wibo", _fake_download)
        result = ensure_wibo(tmp_path)
        assert result == tmp_path / "tools" / "wibo"
        assert calls == [tmp_path / "tools" / "wibo"]


class TestDoctorCheckRunner:
    def test_no_runner_passes(self, tmp_path: Path) -> None:
        cfg = SimpleNamespace(compiler_runner="", root=tmp_path)
        result = check_runner(cfg)
        assert result.status == _PASS
        assert "No runner configured" in result.message

    def test_wibo_found_passes(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        found = tmp_path / "tools" / "wibo"
        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda _name: None)
        monkeypatch.setattr("rebrew.wibo.find_wibo", lambda _root: found)
        cfg = SimpleNamespace(compiler_runner="wibo", root=tmp_path)
        result = check_runner(cfg)
        assert result.status == _PASS
        assert str(found) in result.message

    def test_wibo_missing_warns(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda _name: None)
        monkeypatch.setattr("rebrew.wibo.find_wibo", lambda _root: None)
        cfg = SimpleNamespace(compiler_runner="wibo", root=tmp_path)
        result = check_runner(cfg)
        assert result.status == _WARN
        assert "install-wibo" in result.fix

    def test_wine_passes(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr("rebrew.doctor.shutil.which", lambda _name: None)
        cfg = SimpleNamespace(compiler_runner="wine", root=tmp_path)
        result = check_runner(cfg)
        assert result.status == _PASS
        assert "checked by compiler check" in result.message
