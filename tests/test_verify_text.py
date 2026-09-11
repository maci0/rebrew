"""Tests for ``rebrew verify --text`` — the .text placement gate.

The heavy lifting (``audit_text`` classification) lives in
``rebrew.text_audit`` and is covered there; these tests cover the verify
integration: the flag defaults off, an aligned build passes, a misplaced
function fails the gate in both human and ``--json`` output, and the JSON
payload carries the text verdict block.
"""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.cli import EXIT_ERROR, EXIT_MISMATCH


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        root=tmp_path,
        target_name="SERVER",
        target_binary=tmp_path / "fake.dll",
        db_dir=tmp_path / "db",
        default_jobs=2,
    )


def _ann(va: int) -> object:
    from rebrew.annotation import Annotation

    return Annotation(
        va=va,
        name="my_func",
        symbol="_my_func",
        module="SERVER",
        status="STUB",
        size=64,
        marker_type="FUNCTION",
        filepath="f.c",
    )


def _patch_flow(monkeypatch: pytest.MonkeyPatch, cfg: SimpleNamespace) -> None:
    monkeypatch.setattr("rebrew.verify.require_config", lambda **kw: cfg)
    monkeypatch.setattr(
        "rebrew.verify.prepare_entries",
        lambda cfg, full, json_output: ([_ann(0x1000)], 1, 0, [], [], 0, [], []),
    )
    monkeypatch.setattr("rebrew.verify.run_verification", lambda *a, **k: (0, 0, [], [], []))
    monkeypatch.setattr("rebrew.verify._load_previous_report", lambda *a: (None, None))
    monkeypatch.setattr("rebrew.verify._save_verify_cache", lambda *a, **k: None)
    monkeypatch.setattr("rebrew.verify._apply_or_preview_status", lambda *a, **k: None)


def _patch_text(
    monkeypatch: pytest.MonkeyPatch,
    *,
    expected: dict[str, int] | None = None,
    actual: dict[str, int] | None = None,
) -> None:
    monkeypatch.setattr(
        "rebrew.verify._expected_text_functions",
        lambda cfg: dict(expected if expected is not None else {"f": 0x1000}),
    )
    monkeypatch.setattr(
        "rebrew.text_audit.collect_actual_vas",
        lambda root, built: dict(actual if actual is not None else {"f": 0x1000}),
    )


def _make_built(tmp_path: Path) -> Path:
    built = tmp_path / "build" / "SERVER"
    built.parent.mkdir(parents=True, exist_ok=True)
    built.write_bytes(b"MZ")
    return built


class TestVerifyText:
    def test_flag_off_by_default(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without --text no placement check runs and the report carries null."""
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        _patch_flow(monkeypatch, cfg)
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0
        assert json.loads(result.output)["text"] is None

    def test_aligned_build_passes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        _patch_flow(monkeypatch, cfg)
        _patch_text(monkeypatch)
        _make_built(tmp_path)
        result = CliRunner().invoke(app, ["--text", "--json"])
        assert result.exit_code == 0
        text = json.loads(result.output)["text"]
        assert text["functions"] == 1
        assert text["correct"] == 1
        assert text["misplaced"] == 0
        assert text["misplaced_list"] == []

    def test_misplaced_fails_gate(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        _patch_flow(monkeypatch, cfg)
        _patch_text(monkeypatch, actual={"f": 0x1010})
        _make_built(tmp_path)
        result = CliRunner().invoke(app, ["--text", "--json"])
        assert result.exit_code == EXIT_MISMATCH
        text = json.loads(result.output)["text"]
        assert text["misplaced"] == 1
        assert text["misplaced_list"] == [
            {
                "symbol": "f",
                "status": "MISPLACED",
                "expected": "0x1000",
                "actual": "0x1010",
                "delta": 16,
            }
        ]

    def test_json_carries_text_verdicts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The payload shape mirrors text-audit: counts plus the bad-row list."""
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        _patch_flow(monkeypatch, cfg)
        _patch_text(
            monkeypatch,
            expected={"f": 0x1000, "g": 0x2000},
            actual={"f": 0x1000},
        )
        _make_built(tmp_path)
        result = CliRunner().invoke(app, ["--text", "--json"])
        assert result.exit_code == 0  # missing is reported, not gated
        text = json.loads(result.output)["text"]
        assert text == {
            "functions": 2,
            "found": 1,
            "correct": 1,
            "misplaced": 0,
            "missing": 1,
            "misplaced_list": [
                {
                    "symbol": "g",
                    "status": "MISSING",
                    "expected": "0x2000",
                    "actual": None,
                    "delta": None,
                }
            ],
        }

    def test_human_output_lists_misplaced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        _patch_flow(monkeypatch, cfg)
        _patch_text(monkeypatch, actual={"f": 0x1010})
        _make_built(tmp_path)
        result = CliRunner().invoke(app, ["--text"])
        assert result.exit_code == EXIT_MISMATCH
        assert "misplaced: 1" in result.output
        assert "MISPLACED" in result.output

    def test_missing_built_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        _patch_flow(monkeypatch, cfg)
        _patch_text(monkeypatch)
        result = CliRunner().invoke(app, ["--text"])
        assert result.exit_code == EXIT_ERROR
        assert "build the project first" in " ".join(result.output.split())
