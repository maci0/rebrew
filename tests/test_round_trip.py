"""End-to-end tests for the rebrew round-trip CLI."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.cli import EXIT_MISMATCH, EXIT_OK
from rebrew.round_trip import _run_round_trip, app

runner = CliRunner()


class TestRoundTripCli:
    def test_help_lists_required_flags(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        for flag in ("--json", "--out", "--no-write", "--filter", "--target"):
            assert flag in result.stdout

    def test_no_config_errors_cleanly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["--json"])
        # require_config raises typer.Exit; treat any non-zero as success here.
        assert result.exit_code != 0


def _make_fake_cfg(tmp_path: Path) -> SimpleNamespace:
    """Minimal ProjectConfig stand-in for round-trip tests.

    Field names match the canonical ones in ``config.py`` so that production
    code paths can read them without translation.
    """
    binary = tmp_path / "fake.dll"
    # 1 KiB blob with one function at offset 0x100 starting with NOPs.
    binary.write_bytes(b"\x00" * 0x100 + b"\x90\x90\x90\x90\xc3" + b"\x00" * 0xFB)
    src_dir = tmp_path / "src" / "FAKE"
    src_dir.mkdir(parents=True)
    return SimpleNamespace(
        target_name="FAKE",
        target_binary=binary,
        reversed_dir=src_dir,
        image_base=0x10000000,
        dll_exports={},
    )


class TestSplicePipeline:
    def test_empty_project_round_trip_is_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No matched functions → reasm == original → exit 0."""
        cfg = _make_fake_cfg(tmp_path)
        # Stub enumeration + catalog loading — neither has annotated sources to walk.
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))

        code = _run_round_trip(cfg, out=None, no_write=True, symbol_filter=None, json_output=False)
        assert code == EXIT_OK

    def test_compile_drift_marks_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A function in the splice set whose compile result fails must be
        reported and exit non-zero."""
        cfg = _make_fake_cfg(tmp_path)
        fn = SimpleNamespace(
            symbol="_myfunc",
            va=0x10000100,
            size=5,
            status="EXACT",
            path=cfg.reversed_dir / "myfunc.c",
            module="FAKE",
            cflags=["/O2"],
        )
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))
        # _compile_and_extract returns (text, relocs, ok, detail).
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn, work_dir: (b"", [], False, "cl.exe failed"),
        )

        code = _run_round_trip(cfg, out=None, no_write=True, symbol_filter=None, json_output=False)
        assert code == EXIT_MISMATCH

    def test_clean_round_trip_writes_reasm(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Identical compile bytes + correct file offset → reasm hash equals original."""
        cfg = _make_fake_cfg(tmp_path)
        fn = SimpleNamespace(
            symbol="_myfunc",
            va=0x10000100,
            size=5,
            status="EXACT",
            path=cfg.reversed_dir / "myfunc.c",
            module="FAKE",
            cflags=["/O2"],
        )
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))
        # Identical bytes (no relocs) → splice is a byte-level no-op.
        original_slice = cfg.target_binary.read_bytes()[0x100:0x105]
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn, work_dir: (original_slice, [], True, ""),
        )
        # Stub the PE loader so we don't need a real PE to compute file offset.
        from types import SimpleNamespace as SN

        fake_info = SN()
        monkeypatch.setattr("rebrew.round_trip.load_binary", lambda p: fake_info)
        monkeypatch.setattr("rebrew.round_trip.va_to_file_offset", lambda info, va: 0x100)

        out = tmp_path / "fake.reasm"
        code = _run_round_trip(cfg, out=out, no_write=False, symbol_filter=None, json_output=False)
        assert code == EXIT_OK
        assert out.exists()
        assert out.read_bytes() == cfg.target_binary.read_bytes()
