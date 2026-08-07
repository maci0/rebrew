"""Tests for wibo download and runner integration helpers."""

import hashlib
import json
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import rebrew.wibo as wibo_mod
from rebrew.doctor import _PASS, _WARN, check_runner
from rebrew.wibo import _WIBO_API_URL, _wibo_asset_name, download_wibo, ensure_wibo, find_wibo


class _FakeHTTPResponse:
    """Minimal mock for httpx.Response."""

    def __init__(self, payload: str | bytes, status_code: int = 200) -> None:
        if isinstance(payload, str):
            self.content = payload.encode("utf-8")
            self.text = payload
        else:
            self.content = payload
            self.text = payload.decode("utf-8", errors="replace")
        self.status_code = status_code

    def json(self) -> dict:  # type: ignore[type-arg]
        return json.loads(self.text)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def _release_payload(digest: str) -> str:
    """Build the GitHub release metadata payload used by download_wibo tests."""
    return json.dumps(
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


def _mock_wibo_http(monkeypatch: pytest.MonkeyPatch, payload: str, binary: bytes) -> None:
    """Patch platform + httpx.get so download_wibo fetches *payload*/*binary*."""
    monkeypatch.setattr(sys, "platform", "linux", raising=False)
    monkeypatch.setattr("platform.machine", lambda: "x86_64")

    def _fake_httpx_get(url: str, **kwargs: object) -> _FakeHTTPResponse:
        if url == _WIBO_API_URL:
            return _FakeHTTPResponse(payload)
        return _FakeHTTPResponse(binary)

    monkeypatch.setattr("rebrew.wibo.httpx.get", _fake_httpx_get)


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
        _mock_wibo_http(monkeypatch, _release_payload(digest), fake_binary)

        version = download_wibo(dest)
        assert version == "v0.9.0"
        assert dest.read_bytes() == fake_binary
        mode = dest.stat().st_mode
        assert mode & stat.S_IXUSR

    def test_sha256_verification_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dest = tmp_path / "tools" / "wibo"
        _mock_wibo_http(monkeypatch, _release_payload("0" * 64), b"wrong-binary")

        with pytest.raises(RuntimeError, match="SHA256 mismatch"):
            download_wibo(dest)
        assert not dest.exists()

    def test_missing_asset_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        dest = tmp_path / "tools" / "wibo"
        payload = json.dumps({"tag_name": "v0.9.0", "assets": []})

        monkeypatch.setattr(sys, "platform", "linux", raising=False)
        monkeypatch.setattr("platform.machine", lambda: "x86_64")
        monkeypatch.setattr(
            "rebrew.wibo.httpx.get",
            lambda _url, **kwargs: _FakeHTTPResponse(payload),
        )

        with pytest.raises(RuntimeError, match="asset not found"):
            download_wibo(dest)

    def test_invalid_release_json_has_context(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dest = tmp_path / "tools" / "wibo"
        monkeypatch.setattr(
            "rebrew.wibo.httpx.get",
            lambda _url, **kwargs: _FakeHTTPResponse("{not json"),
        )

        with pytest.raises(RuntimeError, match="Invalid JSON in wibo release metadata"):
            download_wibo(dest)

    def test_temp_fd_closed_when_fdopen_fails(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dest = tmp_path / "tools" / "wibo"
        fake_binary = b"fake-wibo-binary"
        digest = hashlib.sha256(fake_binary).hexdigest()
        _mock_wibo_http(monkeypatch, _release_payload(digest), fake_binary)

        real_close = wibo_mod.os.close
        closed_fds: list[int] = []

        def _fake_fdopen(_fd: int, _mode: str) -> object:
            raise OSError("fdopen failed")

        def _recording_close(fd: int) -> None:
            closed_fds.append(fd)
            real_close(fd)

        monkeypatch.setattr("rebrew.wibo.os.fdopen", _fake_fdopen)
        monkeypatch.setattr("rebrew.wibo.os.close", _recording_close)

        with pytest.raises(OSError, match="fdopen failed"):
            download_wibo(dest)

        assert closed_fds
        assert not dest.exists()
        assert not list(dest.parent.glob(".wibo_*"))


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
