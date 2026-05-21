"""Tests for rebrew.extract — candidate list building and show command."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

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
# E1 — --size override in cmd_extract
# ---------------------------------------------------------------------------


class TestCmdExtractSizeOverride:
    def test_size_override_replaces_catalog_size(self, tmp_path: Path) -> None:
        """When --size N is passed the override candidate entry is used."""
        cfg = _make_cfg(tmp_path)
        bin_dir = tmp_path / "bin"

        # Candidates list: VA 0x1000 with catalog size 200
        candidates = [(0x1000, 200, "func_a"), (0x2000, 50, "func_b")]

        extracted: list[tuple[int, int]] = []

        def _fake_extract(binary_info: Any, va: int, size: int) -> bytes:
            extracted.append((va, size))
            return b"\x55\x8b\xec" * (size // 3 or 1)

        mock_binary = MagicMock()

        with (
            patch("rebrew.extract.extract_bytes_at_va", side_effect=_fake_extract),
            patch("rebrew.extract.disasm_bytes", return_value="nop"),
        ):
            # Build override candidates list the same way show_candidate does it
            size_override = 42
            target_va = 0x1000
            override_candidates = [(target_va, size_override, f"0x{target_va:08X}")] + [
                c for c in candidates if c[0] != target_va
            ]
            cmd_extract(
                mock_binary,
                override_candidates,
                target_va,
                bin_dir,
                cfg=cfg,  # type: ignore[arg-type]
            )

        # The override size (42) should have been used, not the catalog size (200)
        assert extracted == [(0x1000, 42)]

    def test_size_override_allows_already_reversed_va(self, tmp_path: Path) -> None:
        """With --size override, VA not in candidate list can still be extracted."""
        cfg = _make_cfg(tmp_path)
        bin_dir = tmp_path / "bin"

        # Candidates list does NOT include 0x1000 (already reversed)
        candidates: list[tuple[int, int, str]] = [(0x2000, 50, "func_b")]

        extracted: list[tuple[int, int]] = []

        def _fake_extract(binary_info: Any, va: int, size: int) -> bytes:
            extracted.append((va, size))
            return b"\x90" * size

        mock_binary = MagicMock()

        with (
            patch("rebrew.extract.extract_bytes_at_va", side_effect=_fake_extract),
            patch("rebrew.extract.disasm_bytes", return_value="nop"),
        ):
            # Inject override candidate (simulating what show_candidate does)
            target_va = 0x1000
            size_override = 64
            override_candidates = [(target_va, size_override, f"0x{target_va:08X}")] + [
                c for c in candidates if c[0] != target_va
            ]
            cmd_extract(
                mock_binary,
                override_candidates,
                target_va,
                bin_dir,
                cfg=cfg,  # type: ignore[arg-type]
            )

        assert extracted == [(0x1000, 64)]


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
        assert payload["status"] == "ERROR"
        assert "0x00001000" in payload["error"]
