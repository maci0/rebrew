"""Tests for rebrew.extract — candidate list building and show command."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import typer

from rebrew.extract import cmd_extract, detect_reversed_vas, load_functions


def _make_cfg(tmp_path: Path, **overrides: object) -> SimpleNamespace:
    defaults: dict[str, Any] = {
        "root": tmp_path,
        "target_name": "TEST",
        "target_binary": tmp_path / "test.dll",
        "binary_format": "pe",
        "arch": "x86_32",
        "reversed_dir": tmp_path / "src",
        "metadata_dir": tmp_path,
        "function_list": tmp_path / "functions.txt",
        "bin_dir": tmp_path / "bin",
        "source_ext": ".c",
        "marker": "TEST",
        "iat_thunks": [],
        "ignored_symbols": [],
        "library_modules": set(),
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# detect_reversed_vas
# ---------------------------------------------------------------------------


class TestDetectReversedVas:
    def test_nonexistent_dir_returns_empty(self, tmp_path: Path) -> None:
        result = detect_reversed_vas(tmp_path / "nonexistent")
        assert result == set()

    def test_empty_dir_returns_empty(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        result = detect_reversed_vas(src)
        assert result == set()


# ---------------------------------------------------------------------------
# load_functions
# ---------------------------------------------------------------------------


class TestLoadFunctions:
    def test_load_from_txt(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        (tmp_path / "functions.txt").write_text(
            "0x00001000 48 func_a\n0x00002000 120 func_b\n",
            encoding="utf-8",
        )
        funcs = load_functions(cfg)  # type: ignore[arg-type]
        assert len(funcs) == 2
        assert funcs[0]["va"] == 0x1000
        assert funcs[0]["size"] == 48
        assert funcs[0]["name"] == "func_a"

    def test_no_function_list_raises(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        import pytest

        with pytest.raises(FileNotFoundError):
            load_functions(cfg)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# E1 — --size override through show_candidate (the injection lives there)
# ---------------------------------------------------------------------------


class TestShowCandidateSizeOverride:
    """The --size override candidate injection lives in show_candidate
    (extract.py), not cmd_extract — these tests must exercise that real
    logic, not rebuild the override list by hand."""

    def _run_show(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        catalog: list[tuple[int, int, str]],
        va: str,
        size: int | None,
    ) -> tuple[list[tuple[int, int]], Path]:
        import rebrew.extract as ex

        cfg = _make_cfg(tmp_path)

        captured: list[list[tuple[int, int, str]]] = []

        def _fake_setup(
            *_args: object, **_kw: object
        ) -> tuple[Any, list[tuple[int, int, str]], Path]:
            captured.append(list(catalog))
            return cfg, list(catalog), cfg.target_binary

        extracted: list[tuple[int, int]] = []

        def _fake_extract(binary_info: Any, v: int, sz: int) -> bytes:
            extracted.append((v, sz))
            return b"\x55\x8b\xec" * (sz // 3 or 1)

        monkeypatch.setattr(ex, "_setup_candidates", _fake_setup)
        monkeypatch.setattr(ex, "load_binary", lambda *_a: MagicMock())
        monkeypatch.setattr(ex, "extract_bytes_at_va", _fake_extract)
        monkeypatch.setattr(ex, "disasm_bytes", lambda code, v, cfg=None: "nop")

        ex.show_candidate(va=va, size=size)
        assert captured and captured[0] == catalog  # untouched input list
        return extracted, cfg.bin_dir

    def test_size_override_replaces_catalog_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--size 42 on a VA whose catalog entry says 200 must extract 42 bytes."""
        catalog = [(0x1000, 200, "func_a"), (0x2000, 50, "func_b")]
        extracted, bin_dir = self._run_show(tmp_path, monkeypatch, catalog, "0x1000", 42)

        assert extracted == [(0x1000, 42)]
        assert (bin_dir / "func_0x00001000.bin").read_bytes() == b"\x55\x8b\xec" * 14

    def test_size_override_allows_already_reversed_va(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--size lets a VA absent from the candidate list still be extracted."""
        catalog: list[tuple[int, int, str]] = [(0x2000, 50, "func_b")]
        extracted, _bin_dir = self._run_show(tmp_path, monkeypatch, catalog, "0x1000", 64)

        assert extracted == [(0x1000, 64)]

    def test_no_size_flag_keeps_catalog_entry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without --size the catalog-recorded size is used as-is."""
        catalog = [(0x1000, 200, "func_a"), (0x2000, 50, "func_b")]
        extracted, _bin_dir = self._run_show(tmp_path, monkeypatch, catalog, "0x1000", None)

        assert extracted == [(0x1000, 200)]


class TestCmdExtractErrors:
    def test_missing_va_exits_nonzero_in_json_mode(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cfg = _make_cfg(tmp_path)
        mock_binary = MagicMock()

        with pytest.raises(typer.Exit) as exc_info:
            cmd_extract(
                mock_binary,
                [(0x2000, 50, "func_b")],
                0x1000,
                tmp_path / "bin",
                cfg=cfg,  # type: ignore[arg-type]
                json_output=True,
            )

        assert exc_info.value.exit_code == 1
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert payload["code"] == 1
        assert "0x00001000" in payload["error"]


# -------------------------------------------------------------------------
# _setup_candidates: function-structure-cache merge (tooling sweep round)
# -------------------------------------------------------------------------


class TestSetupCandidatesStructureMerge:
    """`rebrew extract list` returned 0 candidates on projects whose
    functions.txt is stale relative to the Ghidra/RE-tool structure cache
    (function_structure.json) — the universe `rebrew status` counts.
    Uncovered structure-cache VAs must surface as candidates."""

    def test_uncovered_structure_vas_are_candidates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        import rebrew.extract as ex
        from rebrew.extract import _setup_candidates

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        cfg = _make_cfg(tmp_path, reversed_dir=src, metadata_dir=tmp_path)
        monkeypatch.setattr(ex, "require_config", lambda target=None, **kw: cfg)
        # functions.txt lists ONE covered function (with a .c annotation);
        # the structure cache adds a second function with no source file.
        (src / "func_a.c").write_text(
            "// FUNCTION: TEST 0x1000\n// SIZE: 48\nint func_a(void) { return 0; }\n",
            encoding="utf-8",
        )
        (tmp_path / "functions.txt").write_text("0x00001000 48 func_a\n", encoding="utf-8")
        (src / "function_structure.json").write_text(
            json.dumps(
                [
                    {"va": 0x1000, "size": 48, "name": "func_a", "tool_name": "FUN_00001000"},
                    {"va": 0x2000, "size": 120, "name": "func_b", "tool_name": "FUN_00002000"},
                ]
            ),
            encoding="utf-8",
        )
        _cfg, candidates, _exe = _setup_candidates(None, True, None, 0, 10_000_000)
        assert [c[0] for c in candidates] == [0x2000]  # only the uncovered one
        assert candidates[0][1] == 120
        assert "func_b" in candidates[0][2]
