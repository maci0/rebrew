"""CLI tests for rebrew flirt — main() with stubbed signature loading."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.flirt import app


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        root=tmp_path,
        target_binary=tmp_path / "x.dll",
        reversed_dir=tmp_path / "src",
    )


def _patch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    sigs: list | None = None,
    text_bytes: bytes = b"\x90" * 0x200,
    sections: dict | None = None,
) -> SimpleNamespace:
    cfg = _cfg(tmp_path)
    (tmp_path / "x.dll").write_bytes(b"MZ" + b"\x00" * 100)
    monkeypatch.setattr("rebrew.flirt.require_config", lambda **kw: cfg)
    monkeypatch.setattr("rebrew.flirt.load_signatures", lambda d: sigs if sigs is not None else [])

    class _EmptyMatcher:
        def match(self, data):
            return []

    monkeypatch.setattr("rebrew.flirt.flirt.compile", lambda sigs: _EmptyMatcher())
    monkeypatch.setattr(
        "rebrew.flirt.load_binary",
        lambda p: SimpleNamespace(
            data=text_bytes,
            sections=sections
            if sections is not None
            else {
                ".text": SimpleNamespace(
                    file_offset=0, size=len(text_bytes), raw_size=len(text_bytes), va=0x1000
                )
            },
        ),
    )
    return cfg


class TestFlirtCli:
    def test_no_signatures_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(tmp_path, monkeypatch, sigs=[])
        result = CliRunner().invoke(app, ["--json", str(tmp_path)])
        assert result.exit_code != 0
        assert "No signatures loaded" in result.output

    def test_no_text_section_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(
            tmp_path,
            monkeypatch,
            sigs=["sig1"],
            sections={"__DATA": SimpleNamespace(file_offset=0, size=4, raw_size=4, va=0x2000)},
        )
        result = CliRunner().invoke(app, ["--json", str(tmp_path)])
        assert result.exit_code != 0
        assert "Could not find .text section" in result.output

    def test_tiny_text_warning(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(tmp_path, monkeypatch, sigs=["sig1"], text_bytes=b"\x90" * 16)
        result = CliRunner().invoke(app, ["--json", str(tmp_path)])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["matches"] == []
        assert "too small" in data["warning"]

    def test_matches_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        class _M:
            def __init__(self, names) -> None:
                self.names = names

        class _Matcher:
            def match(self, data):
                return [_M([("printf", 0, 0)])]

        # 0x40 bytes of ret-stubs: each C3 ends a 1-byte function at stride.
        _patch(tmp_path, monkeypatch, sigs=["sig1"], text_bytes=b"\x90" * 0x10 + b"\xc3" * 0x30)
        monkeypatch.setattr("rebrew.flirt.flirt.compile", lambda sigs: _Matcher())
        result = CliRunner().invoke(app, ["--json", str(tmp_path)])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["match_count"] >= 1
        assert data["matches"][0]["names"] == ["printf"]

    def test_ambiguous_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        class _M:
            def __init__(self, names) -> None:
                self.names = names

        class _Matcher:
            def match(self, data):
                names = [(f"fn{i}", 0, 0) for i in range(10)]
                return [_M(names)]

        _patch(tmp_path, monkeypatch, sigs=["sig1"], text_bytes=b"\x90" * 0x10 + b"\xc3" * 0x30)
        monkeypatch.setattr("rebrew.flirt.flirt.compile", lambda sigs: _Matcher())
        result = CliRunner().invoke(app, ["--json", str(tmp_path)])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        # 10 names > _MAX_AMBIGUOUS → skipped.
        assert data["match_count"] == 0
        assert data["skipped_ambiguous"] >= 1
