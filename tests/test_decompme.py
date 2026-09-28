"""Tests for decompme.py — decomp.me scratch uploader."""

import json
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.decompme as decompme

runner = CliRunner()


class TestHttpProtocols:
    """The reply contract a consumer's test double has to satisfy."""

    def test_httpx_response_satisfies_http_response(self) -> None:
        import httpx

        assert isinstance(httpx.Response(200, content=b"{}"), decompme.HttpResponse)

    def test_reply_without_close_is_rejected(self) -> None:
        """The module-``httpx`` reply owns a connection the transport releases.

        Typing the reply is what surfaces a stand-in missing ``close()`` at
        check time instead of as an ``AttributeError`` on the first upload.
        """
        from typing import Any

        class _NoClose:
            status_code = 200
            text = "{}"

            def json(self) -> Any:
                return {}

        assert not isinstance(_NoClose(), decompme.HttpResponse)

    def test_httpx_client_satisfies_http_client(self) -> None:
        import httpx

        assert isinstance(httpx.Client(), decompme.HttpClient)


def _ann(va: int = 0x401000, size: int = 16, name: str = "func_a", symbol: str = "_func_a"):
    from rebrew.annotation import Annotation

    return Annotation(
        va=va,
        size=size,
        name=name,
        symbol=symbol,
        marker_type="FUNCTION",
        module="GAME",
        toolchain="msvc-6.0",
        cflags="/O2",
        filepath="func_a.c",
    )


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        target_binary=tmp_path / "x.dll",
        reversed_dir=tmp_path / "src",
        root=tmp_path,
        target_name="T",
        metadata_dir=tmp_path,
        compiler_profile="msvc-6.0",
        binary_format="pe",
        source_ext=".c",
        marker="T",
        cflags="/O2 /Gd",
    )


class TestMappings:
    def test_compiler_map(self) -> None:
        assert decompme.map_compiler("msvc-6.0") == "msvc6.0"
        assert decompme.map_compiler("msvc-6.0-sp6") == "msvc6.0"
        assert decompme.map_compiler("msvc-7.1") == "msvc7.1"  # canonical VC 7.1
        assert decompme.map_compiler("msvc-7.0") == "msvc7.1"  # same 13.10.3077 build
        assert decompme.map_compiler("msvc-7.0-rtm") == "msvc7.0"  # the genuine VC 7.0
        assert decompme.map_compiler("msvc-10.0") == "msvc10.0"
        assert decompme.map_compiler("msvc-11.0") == "msvc11.0"
        assert decompme.map_compiler("mingw-16.2.0") is None  # must be explicit
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

    def test_legacy_encoding_decoded_not_replaced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A non-UTF-8 source must not upload U+FFFD for its legacy bytes."""
        cfg = _cfg(tmp_path)
        cfg.reversed_dir.mkdir(exist_ok=True)
        src = cfg.reversed_dir / "func_a.c"
        src.write_bytes(b"// FUNCTION: T 0x401000\n// \xa9 note\nint func_a(void){return 0;}\n")
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes", lambda p, va, size: b"\x55\x8b\xec\x5d\xc3"
        )
        payload = decompme.build_scratch_payload(
            cfg,
            src,
            va=0x401000,
            size=5,
            symbol="_func_a",
            name="func_a",
            compiler="msvc6.0",
            platform="win32",
            compiler_flags="/O1",
            context="",
        )
        assert "\ufffd" not in payload["data"]["source_code"]

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


class TestFunctionIsolation:
    """The scratch uploads the selected function (+ preamble), not the file."""

    def test_extracts_selected_function_with_preamble(self) -> None:
        from rebrew.decompme import extract_function_text

        text = (
            '#include "types.h"\n'
            "typedef int myint;\n"
            "\n"
            "int func_a(void){return 0;}\n"
            "\n"
            "int func_b(void){return 1;}\n"
        )
        chunk = extract_function_text(text, "func_b")
        assert chunk is not None
        assert "func_b" in chunk
        assert "func_a" not in chunk.replace("func_b", "")
        assert '#include "types.h"' in chunk
        assert "typedef int myint;" in chunk

    def test_first_function_gets_no_preamble_duplication(self) -> None:
        from rebrew.decompme import extract_function_text

        text = '#include "types.h"\n\nint func_a(void){return 0;}\n\nint func_b(void){return 1;}\n'
        chunk = extract_function_text(text, "func_a")
        assert chunk is not None
        assert "func_b" not in chunk
        assert '#include "types.h"' in chunk

    def test_unknown_name_returns_none(self) -> None:
        from rebrew.decompme import extract_function_text

        text = "int func_a(void){return 0;}\n\nint func_b(void){return 1;}\n"
        assert extract_function_text(text, "missing") is None

    def test_payload_uploads_only_selected_function(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _cfg(tmp_path)
        cfg.reversed_dir.mkdir(exist_ok=True)
        src = cfg.reversed_dir / "two.c"
        src.write_text(
            '#include "types.h"\n\nint func_a(void){return 0;}\n\nint func_b(void){return 1;}\n',
            encoding="utf-8",
        )
        monkeypatch.setattr(
            "rebrew.binary_loader.extract_raw_bytes", lambda p, va, size: b"\x90" * 16
        )
        payload = decompme.build_scratch_payload(
            cfg,
            src,
            va=0x401000,
            size=16,
            symbol="_func_b",
            name="func_b",
            compiler="msvc6.0",
            platform="win32",
            compiler_flags="/O1",
            context="",
        )
        code = payload["data"]["source_code"]
        assert "func_b" in code
        assert "func_a" not in code.replace("func_b", "")
        assert '#include "types.h"' in code


class TestUpload:
    def test_success(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: dict = {}
        closed: list[bool] = []

        def _fake_post(url, **kwargs):
            calls["url"] = url
            calls["data"] = kwargs.get("data")
            calls["files"] = kwargs.get("files")
            return SimpleNamespace(
                status_code=201,
                json=lambda: {"slug": "abc123", "claim_token": "tok"},
                close=lambda: closed.append(True),
            )

        monkeypatch.setattr("httpx.post", _fake_post)
        result = decompme.upload_scratch(
            {"data": {"compiler": "x"}, "files": {"target_obj": ("a.o", b"\x00", "x")}}
        )
        assert result == {"slug": "abc123", "claim_token": "tok"}
        assert calls["url"] == "https://decomp.me/api/scratch"
        assert calls["data"] == {"compiler": "x"}
        assert closed == [True]

    def test_http_error_surfaced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        closed: list[bool] = []

        def _fake_post(url, **kwargs):
            return SimpleNamespace(
                status_code=400,
                text="Unknown compiler: nope",
                close=lambda: closed.append(True),
            )

        monkeypatch.setattr("httpx.post", _fake_post)
        with pytest.raises(RuntimeError, match="Unknown compiler"):
            decompme.upload_scratch({"data": {}, "files": {}})
        assert closed == [True]

    def test_transport_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        def _fake_post(url, **kwargs):
            raise httpx.ConnectError("boom")

        monkeypatch.setattr("httpx.post", _fake_post)
        with pytest.raises(RuntimeError, match="boom"):
            decompme.upload_scratch({"data": {}, "files": {}})

    @pytest.mark.parametrize(
        "body",
        [
            ["abc"],
            {"claim_token": "tok"},
            {"slug": "abc/../x", "claim_token": "tok"},
            {"slug": "abc", "claim_token": "tok&next=https://evil"},
            {"slug": "[link=https://evil]abc", "claim_token": "tok"},
            {"slug": "abc", "claim_token": 123},
        ],
    )
    def test_untrusted_reply_rejected(self, monkeypatch: pytest.MonkeyPatch, body: object) -> None:
        monkeypatch.setattr(
            "httpx.post",
            lambda url, **kw: SimpleNamespace(
                status_code=201, json=lambda: body, close=lambda: None
            ),
        )
        with pytest.raises(RuntimeError, match="decomp.me returned"):
            decompme.upload_scratch({"data": {}, "files": {}})

    def test_scratch_url(self) -> None:
        assert decompme.scratch_url("abc", "tok") == "https://decomp.me/scratch/abc/claim?token=tok"

    def test_retries_a_transient_status_then_succeeds(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts: list[int] = []

        def _fake_post(url, **kwargs):
            attempts.append(len(attempts))
            if len(attempts) == 1:
                return SimpleNamespace(status_code=503, text="busy", close=lambda: None)
            return SimpleNamespace(
                status_code=201,
                json=lambda: {"slug": "abc123", "claim_token": "tok"},
                close=lambda: None,
            )

        monkeypatch.setattr("httpx.post", _fake_post)
        monkeypatch.setattr("time.sleep", lambda _s: None)
        result = decompme.upload_scratch({"data": {}, "files": {}}, retries=1)
        assert result == {"slug": "abc123", "claim_token": "tok"}
        assert len(attempts) == 2

    def test_retries_a_transport_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        calls: list[int] = []

        def _fake_post(url, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise httpx.ConnectError("boom")
            return SimpleNamespace(
                status_code=201,
                json=lambda: {"slug": "abc123", "claim_token": "tok"},
                close=lambda: None,
            )

        monkeypatch.setattr("httpx.post", _fake_post)
        monkeypatch.setattr("time.sleep", lambda _s: None)
        decompme.upload_scratch({"data": {}, "files": {}}, retries=1)
        assert len(calls) == 2

    def test_does_not_retry_after_the_request_was_sent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A read timeout can follow a create that already landed.

        decomp.me has no idempotency key, so a second POST would orphan a
        public scratch; the run must fail instead.
        """
        import httpx

        calls: list[int] = []

        def _fake_post(url, **kwargs):
            calls.append(1)
            raise httpx.ReadTimeout("no reply")

        monkeypatch.setattr("httpx.post", _fake_post)
        monkeypatch.setattr("time.sleep", lambda _s: None)
        with pytest.raises(RuntimeError, match="no reply"):
            decompme.upload_scratch({"data": {}, "files": {}}, retries=3)
        assert len(calls) == 1

    def test_retries_stop_on_a_rejection(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[int] = []

        def _fake_post(url, **kwargs):
            calls.append(1)
            return SimpleNamespace(status_code=400, text="bad", close=lambda: None)

        monkeypatch.setattr("httpx.post", _fake_post)
        with pytest.raises(RuntimeError, match="bad"):
            decompme.upload_scratch({"data": {}, "files": {}}, retries=3)
        assert len(calls) == 1  # an explained rejection is not worth another attempt

    def test_retries_give_up_after_the_configured_attempts(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[int] = []

        def _fake_post(url, **kwargs):
            calls.append(1)
            return SimpleNamespace(status_code=503, text="busy", close=lambda: None)

        monkeypatch.setattr("httpx.post", _fake_post)
        monkeypatch.setattr("time.sleep", lambda _s: None)
        with pytest.raises(RuntimeError, match="busy"):
            decompme.upload_scratch({"data": {}, "files": {}}, retries=2)
        assert len(calls) == 3  # retries counts re-attempts, not the first try

    def test_injected_client_replaces_the_transport(self) -> None:
        """A consumer test injects a client and never reaches decomp.me."""
        calls: list[tuple[str, dict]] = []

        class FakeClient:
            def post(self, url: str, **kwargs: object) -> object:
                calls.append((url, kwargs))
                return SimpleNamespace(
                    status_code=201,
                    json=lambda: {"slug": "abc123", "claim_token": "tok"},
                    close=lambda: None,
                )

        result = decompme.upload_scratch(
            {"data": {"compiler": "x"}, "files": {}}, client=FakeClient()
        )
        assert result == {"slug": "abc123", "claim_token": "tok"}
        assert calls[0][0] == "https://decomp.me/api/scratch"
        assert "timeout" not in calls[0][1]  # the caller owns the client's timeout


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
            "rebrew.compile_overrides.resolve_compile_overrides",
            lambda cfg, d, a, b, c: ("msvc-6.0", "/O1"),
        )
        monkeypatch.setattr(
            "rebrew.context.collect_context", lambda cfg: (["struct Vec { int x; };"], 1)
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

    def test_json_dry_run_context_bytes_are_utf8_bytes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg, src = self._patch(tmp_path, monkeypatch)
        ctx = tmp_path / "ctx.c"
        text = "/* café \U0001f600 */\nstruct Vec { int x; };"
        ctx.write_text(text, encoding="utf-8")
        r = runner.invoke(decompme.app, ["--dry-run", "--json", "--context", str(ctx), str(src)])
        assert r.exit_code == 0
        data = json.loads(r.stdout)
        assert data["context_bytes"] == len(text.encode("utf-8"))
        assert data["context_bytes"] > len(text)

    def test_unmapped_toolchain_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg, src = self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.compile_overrides.resolve_compile_overrides",
            lambda cfg, d, a, b, c: ("mingw-16.2.0", "-O2"),
        )
        r = runner.invoke(decompme.app, ["--dry-run", str(src)])
        assert r.exit_code == 2
        assert "--compiler" in r.output

    def test_size_flag_supplies_missing_annotation_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`--size` must rescue an annotation without SIZE (its own error
        message tells the user to pass the flag)."""
        cfg, src = self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.annotation.parse_c_file_multi",
            lambda p, target_name=None, metadata_dir=None: [_ann(size=0)],
        )
        r = runner.invoke(decompme.app, ["--dry-run", "--size", "32", str(src)])
        assert r.exit_code == 0
        assert "(32B)" in r.output

    def test_none_toolchain_falls_back_to_project_profile(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`resolve_compile_overrides` returns None when no override names a
        compiler; the project profile is the documented fallback."""
        cfg, src = self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.compile_overrides.resolve_compile_overrides",
            lambda cfg, d, a, b, c: (None, "/O2 /Gd"),
        )
        r = runner.invoke(decompme.app, ["--dry-run", "--json", str(src)])
        assert r.exit_code == 0
        assert json.loads(r.stdout)["compiler"] == "msvc6.0"

    def test_compiler_flag_still_resolves_default_flags(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Passing `--compiler` must not drop the resolved-cflags default."""
        cfg, src = self._patch(tmp_path, monkeypatch)
        r = runner.invoke(decompme.app, ["--dry-run", "--json", "--compiler", "msvc6.0", str(src)])
        assert r.exit_code == 0
        assert json.loads(r.stdout)["flags"] == "/O1"

    def test_upload_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg, src = self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "httpx.post",
            lambda url, **kw: SimpleNamespace(
                status_code=201,
                json=lambda: {"slug": "abc", "claim_token": "tok"},
                close=lambda: None,
            ),
        )
        r = runner.invoke(decompme.app, [str(src)])
        assert r.exit_code == 0
        assert "https://decomp.me/scratch/abc/claim?token=tok" in r.output

    def test_upload_rejection(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg, src = self._patch(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "httpx.post",
            lambda url, **kw: SimpleNamespace(
                status_code=400, text="Unknown platform: nope", close=lambda: None
            ),
        )
        r = runner.invoke(decompme.app, [str(src)])
        assert r.exit_code == 2
        assert "Unknown platform" in r.output

    def test_second_run_reuses_scratch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unchanged re-run must not leave a second scratch on decomp.me."""
        cfg, src = self._patch(tmp_path, monkeypatch)
        calls: list[str] = []

        def fake_post(url: str, **kw: object) -> SimpleNamespace:
            calls.append(url)
            slug = f"abc{len(calls)}"
            return SimpleNamespace(
                status_code=201,
                json=lambda: {"slug": slug, "claim_token": "tok"},
                close=lambda: None,
            )

        monkeypatch.setattr("httpx.post", fake_post)
        first = runner.invoke(decompme.app, ["--json", str(src)])
        assert first.exit_code == 0
        assert json.loads(first.stdout)["reused"] is False

        second = runner.invoke(decompme.app, ["--json", str(src)])
        assert second.exit_code == 0
        data = json.loads(second.stdout)
        assert data["reused"] is True
        assert data["slug"] == "abc1"
        assert calls == ["https://decomp.me/api/scratch"]

    def test_reupload_forces_a_new_scratch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg, src = self._patch(tmp_path, monkeypatch)
        calls: list[str] = []

        def fake_post(url: str, **kw: object) -> SimpleNamespace:
            calls.append(url)
            return SimpleNamespace(
                status_code=201,
                json=lambda: {"slug": f"abc{len(calls)}", "claim_token": "tok"},
                close=lambda: None,
            )

        monkeypatch.setattr("httpx.post", fake_post)
        runner.invoke(decompme.app, [str(src)])
        again = runner.invoke(decompme.app, ["--json", "--reupload", str(src)])
        assert again.exit_code == 0
        data = json.loads(again.stdout)
        assert data["reused"] is False
        assert data["slug"] == "abc2"
        assert len(calls) == 2

    def test_changed_payload_uploads_again(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ledger keys on payload content, so an edited function is new."""
        cfg, src = self._patch(tmp_path, monkeypatch)
        calls: list[str] = []

        def fake_post(url: str, **kw: object) -> SimpleNamespace:
            calls.append(url)
            return SimpleNamespace(
                status_code=201,
                json=lambda: {"slug": f"abc{len(calls)}", "claim_token": "tok"},
                close=lambda: None,
            )

        monkeypatch.setattr("httpx.post", fake_post)
        runner.invoke(decompme.app, [str(src)])
        src.write_text(
            "// FUNCTION: T 0x401000\n// SIZE: 16\nint func_a(void){return 1;}\n",
            encoding="utf-8",
        )
        again = runner.invoke(decompme.app, ["--json", str(src)])
        assert again.exit_code == 0
        assert json.loads(again.stdout)["reused"] is False
        assert len(calls) == 2


class TestUploadLedger:
    def _payload(self, source: str = "int f(void){return 0;}", blob: bytes = b"\x01") -> dict:
        return {
            "data": {"compiler": "msvc6.0", "platform": "win32", "source_code": source},
            "files": {"target_obj": ("f.o", blob, "application/octet-stream")},
        }

    def test_digest_tracks_every_field(self) -> None:
        base = decompme.scratch_digest(self._payload(), "https://decomp.me")
        assert base == decompme.scratch_digest(self._payload(), "https://decomp.me")
        assert base != decompme.scratch_digest(
            self._payload(source="int f(void){return 1;}"), "https://decomp.me"
        )
        assert base != decompme.scratch_digest(self._payload(blob=b"\x02"), "https://decomp.me")
        assert base != decompme.scratch_digest(self._payload(), "https://staging.decomp.me")

    def test_recorded_upload_round_trip(self, tmp_path: Path) -> None:
        payload = self._payload()
        digest = decompme.scratch_digest(payload, "https://decomp.me")
        assert decompme.recorded_upload(tmp_path, digest, "https://decomp.me") is None
        decompme.record_upload(tmp_path, digest, "abc", "tok", "https://decomp.me")
        entry = decompme.recorded_upload(tmp_path, digest, "https://decomp.me")
        assert entry is not None
        assert entry["slug"] == "abc"
        assert entry["claim_token"] == "tok"

    def test_ledger_is_owner_only(self, tmp_path: Path) -> None:
        """The ledger stores claim tokens, so it must not be group/world readable."""
        digest = decompme.scratch_digest(self._payload(), "https://decomp.me")
        decompme.record_upload(tmp_path, digest, "abc", "tok", "https://decomp.me")
        mode = (tmp_path / ".rebrew" / "decompme-uploads.json").stat().st_mode
        assert mode & 0o077 == 0

    def test_ledger_mode_is_tightened_on_rewrite(self, tmp_path: Path) -> None:
        """A ledger written world-readable by an older rebrew is chmod'ed on rewrite."""
        digest = decompme.scratch_digest(self._payload(), "https://decomp.me")
        decompme.record_upload(tmp_path, digest, "abc", "tok", "https://decomp.me")
        path = tmp_path / ".rebrew" / "decompme-uploads.json"
        path.chmod(0o644)
        decompme.record_upload(tmp_path, "other", "def", "tok2", "https://decomp.me")
        assert path.stat().st_mode & 0o077 == 0

    def test_entry_does_not_match_another_api(self, tmp_path: Path) -> None:
        digest = decompme.scratch_digest(self._payload(), "https://decomp.me")
        decompme.record_upload(tmp_path, digest, "abc", "tok", "https://decomp.me")
        assert decompme.recorded_upload(tmp_path, digest, "https://staging.decomp.me") is None

    def test_expired_entries_are_pruned(self, tmp_path: Path) -> None:
        digest = decompme.scratch_digest(self._payload(), "https://decomp.me")
        decompme.record_upload(tmp_path, digest, "abc", "tok", "https://decomp.me")
        path = tmp_path / ".rebrew" / "decompme-uploads.json"
        stale = json.loads(path.read_text(encoding="utf-8"))
        stale[digest]["at"] = "0"
        path.write_text(json.dumps(stale), encoding="utf-8")
        decompme.record_upload(tmp_path, "other", "def", "tok2", "https://decomp.me")
        assert decompme.recorded_upload(tmp_path, digest, "https://decomp.me") is None
        assert "other" in decompme.read_uploads(tmp_path)

    def test_corrupt_ledger_reads_as_empty(self, tmp_path: Path) -> None:
        path = tmp_path / ".rebrew" / "decompme-uploads.json"
        path.parent.mkdir(parents=True)
        path.write_text("{not json", encoding="utf-8")
        assert decompme.read_uploads(tmp_path) == {}

    def test_unwritable_ledger_is_not_fatal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A scratch that exists remotely must not be lost to a local write error."""
        digest = decompme.scratch_digest(self._payload(), "https://decomp.me")

        def boom(*args: object, **kw: object) -> None:
            raise OSError("read-only file system")

        monkeypatch.setattr(decompme, "atomic_write_text", boom)
        decompme.record_upload(tmp_path, digest, "abc", "tok", "https://decomp.me")
        assert decompme.read_uploads(tmp_path) == {}


class TestVerifyCompiler:
    def test_known_compiler_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        closed: list[bool] = []

        def _fake_get(url, timeout):
            return SimpleNamespace(
                status_code=200,
                json=lambda: {
                    "compilers": {"msvc6.0": {"platform": "win32"}},
                    "platforms": {"win32": {}},
                },
                close=lambda: closed.append(True),
            )

        monkeypatch.setattr(httpx, "get", _fake_get)
        assert decompme.verify_compiler("msvc6.0") is None
        assert closed == [True]

    def test_unknown_compiler_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        def _fake_get(url, timeout):
            return SimpleNamespace(
                status_code=200,
                json=lambda: {"compilers": {"msvc6.0": {}, "msvc7.1": {}}, "platforms": {}},
                close=lambda: None,
            )

        monkeypatch.setattr(httpx, "get", _fake_get)
        with pytest.raises(RuntimeError, match="not in the decomp.me registry"):
            decompme.verify_compiler("mingw-16.2.0")
        with pytest.raises(RuntimeError, match="msvc6.0"):
            decompme.verify_compiler("nope")  # suggestion lists known ids

    def test_transport_failure_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        def _fake_get(url, timeout):
            raise httpx.ConnectError("cf")

        monkeypatch.setattr(httpx, "get", _fake_get)
        assert decompme.verify_compiler("msvc6.0") is None

    def test_http_error_degrades(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        monkeypatch.setattr(
            httpx,
            "get",
            lambda url, timeout: SimpleNamespace(status_code=403, text="cf", close=lambda: None),
        )
        assert decompme.verify_compiler("msvc6.0") is None

    def test_injected_client_replaces_the_transport(self) -> None:
        calls: list[str] = []

        class FakeClient:
            def get(self, url: str, **kwargs: object) -> object:
                calls.append(url)
                return SimpleNamespace(
                    status_code=200,
                    json=lambda: {"compilers": {"msvc6.0": {}}, "platforms": {}},
                    close=lambda: None,
                )

        assert decompme.verify_compiler("msvc6.0", client=FakeClient()) is None
        assert calls == ["https://decomp.me/api/compiler"]
