"""CLI tests for rebrew library scan-signatures — main() with stubbed signature loading."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from cli_json import cli_payload
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
    monkeypatch.setattr(
        "rebrew.flirt.load_signatures_for", lambda dirs, arch: sigs if sigs is not None else []
    )

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
        data = cli_payload(result)
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
        data = cli_payload(result)
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
        data = cli_payload(result)
        # 10 names > _MAX_AMBIGUOUS → skipped.
        assert data["match_count"] == 0
        assert data["skipped_ambiguous"] >= 1

    @pytest.mark.parametrize("show_ambiguous", [False, True])
    def test_broad_signature_name_dedup_is_linear(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, show_ambiguous: bool
    ) -> None:
        class CountedName(str):
            __slots__ = ()
            comparisons = 0
            __hash__ = str.__hash__

            def __eq__(self, other: object) -> bool:
                type(self).comparisons += 1
                return str.__eq__(self, other)

        labels = [CountedName(f"candidate_{i}") for i in range(2000)]

        class Matcher:
            def match(self, data):
                return [
                    SimpleNamespace(names=[("", 0, 0)] + [(n, 0, 0) for n in labels[:1000]]),
                    SimpleNamespace(names=[(n, 0, 0) for n in labels]),
                ]

        _patch(tmp_path, monkeypatch, sigs=["sig1"], text_bytes=b"\x90" * 32)
        monkeypatch.setattr("rebrew.flirt.flirt.compile", lambda sigs: Matcher())
        args = ["--json"]
        if show_ambiguous:
            args.append("--show-ambiguous")
        args.append(str(tmp_path))
        result = CliRunner().invoke(app, args)
        comparisons = CountedName.comparisons
        assert result.exit_code == 0, result.output
        data = cli_payload(result)
        assert data["match_count"] == 0
        assert data["skipped_ambiguous"] == 1
        if show_ambiguous:
            from rebrew.flirt import _MAX_AMBIGUOUS_REPORT

            assert data["ambiguous_matches"] == [
                {
                    "va": "0x00001000",
                    "size": 32,
                    "names": [f"candidate_{i}" for i in range(_MAX_AMBIGUOUS_REPORT)],
                    "more": True,
                }
            ]
        else:
            assert data["ambiguous_matches"] == []
        assert comparisons < len(labels) * 4


class TestFlirtSigsDirEnv:
    def test_missing_env_dir_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(tmp_path, monkeypatch, sigs=[object()])
        monkeypatch.setenv("REBREW_FLIRT_SIGS_DIR", str(tmp_path / "typo"))
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code != 0
        assert "REBREW_FLIRT_SIGS_DIR" in cli_payload(result)["error"]


class TestFlirtInit:
    def test_copies_repo_sigs(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.flirt import _init_project_sigs

        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "a.pat").write_bytes(b"---\n")
        (repo / "b.sig").write_bytes(b"---\n")
        monkeypatch.setenv("REBREW_FLIRT_SIGS_DIR", str(repo))
        cfg = _cfg(tmp_path)

        _init_project_sigs(cfg, False)
        assert (tmp_path / "flirt_sigs" / "a.pat").exists()
        assert (tmp_path / "flirt_sigs" / "b.sig").exists()

        # Idempotent: existing files never overwritten.
        (tmp_path / "flirt_sigs" / "a.pat").write_bytes(b"custom")
        _init_project_sigs(cfg, False)
        assert (tmp_path / "flirt_sigs" / "a.pat").read_bytes() == b"custom"

    def test_missing_repo_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import typer

        from rebrew.flirt import _init_project_sigs

        monkeypatch.setenv("REBREW_FLIRT_SIGS_DIR", str(tmp_path / "nope"))
        with pytest.raises(typer.Exit):
            _init_project_sigs(_cfg(tmp_path), False)


class TestSignatureSetup:
    @pytest.mark.parametrize("matched_only", [False, True])
    def test_explicit_setup_copies_signatures_and_preserves_project_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, matched_only: bool
    ) -> None:

        from rebrew import flirt as module
        from rebrew.app.main import app as umbrella

        repo = tmp_path / "shared"
        repo.mkdir()
        (repo / "crt.sig").write_bytes(b"shared-crt")
        (repo / "other.sig").write_bytes(b"shared-other")
        dest = tmp_path / "flirt_sigs"
        dest.mkdir()
        (dest / "crt.sig").write_bytes(b"project-crt")
        monkeypatch.setattr(module, "require_config", lambda **kw: SimpleNamespace(root=tmp_path))
        monkeypatch.setattr(module, "_flirt_sigs_repo", lambda: repo)
        monkeypatch.setattr(module, "_detect_crt_linkage", lambda cfg: "static")
        monkeypatch.setattr(module, "_matched_sig_names", lambda linkage: {"crt.sig"})
        args = ["library", "init-signatures", "--json"]
        if matched_only:
            args.append("--matched-only")
        result = CliRunner().invoke(umbrella, args)
        assert result.exit_code == 0, result.output
        assert (dest / "crt.sig").read_bytes() == b"project-crt"
        assert (dest / "other.sig").exists() is not matched_only
        data = cli_payload(result)
        assert data["copied"] == (0 if matched_only else 1)
        assert data["linkage"] == ("static" if matched_only else "")
