"""Tests for the rebrew flirt module -- pure-function helpers."""

from pathlib import Path

import pytest

from rebrew.flirt import find_func_size, iter_match_offsets, load_signatures

# ---------------------------------------------------------------------------
# find_func_size
# ---------------------------------------------------------------------------


class TestFindFuncSize:
    """Tests for find_func_size() function boundary estimation."""

    def test_ret_c3(self) -> None:
        """Finds C3 (ret) and returns offset + 1."""
        code = b"\x55\x8b\xec\xc3"  # push ebp; mov ebp, esp; ret
        size = find_func_size(code, 0)
        assert size == 4  # 0..3 inclusive, ret at index 3

    def test_ret_c2_imm16(self) -> None:
        """Finds C2 xx xx (ret imm16) and returns offset + 3."""
        code = b"\x55\x8b\xec\xc2\x08\x00"  # push ebp; mov ebp, esp; ret 8
        size = find_func_size(code, 0)
        assert size == 6

    def test_offset_nonzero(self) -> None:
        """Works with non-zero start offset."""
        code = b"\xcc\xcc\x55\x8b\xec\xc3"  # padding, then push/mov/ret
        size = find_func_size(code, 2)
        assert size == 4

    def test_no_ret_returns_max_scan(self) -> None:
        """When no ret is found, returns max_scan length."""
        code = bytes(100)  # 100 zero bytes, no ret
        size = find_func_size(code, 0)
        assert size == 100

    def test_ret_c2_near_end(self) -> None:
        """C2 at end-2 still works if there are 2 more bytes."""
        code = b"\x55\xc2\x04\x00"
        size = find_func_size(code, 0)
        assert size == 4

    def test_max_scan_capped_at_4096(self) -> None:
        """Max scan is capped at 4096 bytes."""
        code = bytes(8192)  # 8K of zeros
        size = find_func_size(code, 0)
        assert size == 4096

    def test_empty_at_offset(self) -> None:
        """When offset == len(code), max_scan is 0."""
        code = b"\xc3"
        size = find_func_size(code, 1)
        assert size == 0


class TestIterMatchOffsets:
    def test_too_small_returns_empty(self) -> None:
        assert list(iter_match_offsets(31, stride=16, min_window=32)) == []

    def test_exact_window_includes_zero(self) -> None:
        assert list(iter_match_offsets(32, stride=16, min_window=32)) == [0]

    def test_includes_final_valid_offset(self) -> None:
        assert list(iter_match_offsets(64, stride=16, min_window=32)) == [0, 16, 32]


# ---------------------------------------------------------------------------
# load_signatures
# ---------------------------------------------------------------------------


class TestLoadSignatures:
    """Tests for load_signatures() -- filesystem tests."""

    def test_missing_directory(self, tmp_path: Path) -> None:
        """Returns empty list when directory doesn't exist."""
        sigs = load_signatures(str(tmp_path / "nonexistent"))
        assert sigs == []

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Returns empty list when directory has no .sig/.pat files."""
        sig_dir = tmp_path / "sigs"
        sig_dir.mkdir()
        sigs = load_signatures(str(sig_dir))
        assert sigs == []

    def test_no_flirt_module(self, monkeypatch) -> None:
        """Returns empty list when flirt module is not available."""
        import rebrew.flirt as flirt_mod

        monkeypatch.setattr(flirt_mod, "flirt", None)
        sigs = load_signatures("/some/dir")
        assert sigs == []


class TestSmallSectionGuard:
    """Edge cases for find_func_size with very small inputs."""

    def test_tiny_code_with_ret(self) -> None:
        """Even very small code should find a ret if present."""
        code = bytes([0xC3])  # just a ret
        size = find_func_size(code, 0)
        assert size == 1

    def test_empty_code(self) -> None:
        """Empty code (offset == len) should return 0."""
        code = b""
        size = find_func_size(code, 0)
        assert size == 0  # min(4096, 0) = 0


class TestCliSurface:
    def test_help_lists_va_flag(self) -> None:
        """--va (single-function check) is part of the CLI contract."""
        from typer.testing import CliRunner

        from rebrew.flirt import app

        result = CliRunner().invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "--va" in result.stdout

    def test_va_out_of_section_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        from typer.testing import CliRunner

        import rebrew.flirt as flirt_mod

        monkeypatch.setattr(
            flirt_mod,
            "require_config",
            lambda target=None, json_mode=False: SimpleNamespace(
                root=tmp_path, target_binary=tmp_path / "x.dll"
            ),
        )
        monkeypatch.setattr(flirt_mod, "load_signatures", lambda d: [object()])
        monkeypatch.setattr(
            flirt_mod,
            "flirt",
            SimpleNamespace(
                compile=lambda s: object(), parse_sig=lambda b: [], parse_pat=lambda b: []
            ),
        )
        monkeypatch.setattr(
            flirt_mod,
            "load_binary",
            lambda p: SimpleNamespace(
                sections={".text": SimpleNamespace(va=0x1000, file_offset=0, raw_size=64)},
                data=b"\xcc" * 64,
            ),
        )
        result = CliRunner().invoke(flirt_mod.app, ["--va", "0x2000"])
        assert result.exit_code != 0
        assert "outside .text" in result.output


class TestAmbiguousReporting:
    """--show-ambiguous keeps multi-candidate matches instead of dropping them."""

    def _setup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, matcher: object) -> None:
        from types import SimpleNamespace

        import rebrew.flirt as flirt_mod

        monkeypatch.setattr(
            flirt_mod,
            "require_config",
            lambda target=None, json_mode=False: SimpleNamespace(
                root=tmp_path, target_binary=tmp_path / "x.dll"
            ),
        )
        monkeypatch.setattr(flirt_mod, "load_signatures", lambda d: [object()])
        monkeypatch.setattr(
            flirt_mod,
            "flirt",
            SimpleNamespace(
                compile=lambda s: matcher, parse_sig=lambda b: [], parse_pat=lambda b: []
            ),
        )
        monkeypatch.setattr(
            flirt_mod,
            "load_binary",
            lambda p: SimpleNamespace(
                sections={".text": SimpleNamespace(va=0x1000, file_offset=0, raw_size=64)},
                data=b"\xcc" * 64,
            ),
        )

    def test_ambiguous_kept_with_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        from typer.testing import CliRunner

        import rebrew.flirt as flirt_mod

        class FakeMatch:
            names = [
                ("_isalpha", "public", 0),
                ("_isupper", "public", 0),
                ("_islower", "public", 0),
                ("_isdigit", "public", 0),
            ]

        class FakeMatcher:
            def match(self, buf: bytes) -> list[object]:
                return [FakeMatch()]

        self._setup(tmp_path, monkeypatch, FakeMatcher())
        result = CliRunner().invoke(flirt_mod.app, ["--show-ambiguous", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["match_count"] == 0  # all four are ambiguous
        assert data["skipped_ambiguous"] >= 1
        assert len(data["ambiguous_matches"]) >= 1
        first = data["ambiguous_matches"][0]
        assert first["names"] == ["_isalpha", "_isupper", "_islower", "_isdigit"]
        assert first["more"] is False

    def test_ambiguous_empty_without_flag(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        from typer.testing import CliRunner

        import rebrew.flirt as flirt_mod

        class FakeMatch:
            names = [
                ("_a", "public", 0),
                ("_b", "public", 0),
                ("_c", "public", 0),
                ("_d", "public", 0),
            ]

        class FakeMatcher:
            def match(self, buf: bytes) -> list[object]:
                return [FakeMatch()]

        self._setup(tmp_path, monkeypatch, FakeMatcher())
        result = CliRunner().invoke(flirt_mod.app, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["skipped_ambiguous"] >= 1
        assert data["ambiguous_matches"] == []  # not collected by default

    def test_names_capped_at_report_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        from typer.testing import CliRunner

        import rebrew.flirt as flirt_mod

        class FakeMatch:
            names = [(f"_fn{i}", "public", 0) for i in range(30)]

        class FakeMatcher:
            def match(self, buf: bytes) -> list[object]:
                return [FakeMatch()]

        self._setup(tmp_path, monkeypatch, FakeMatcher())
        result = CliRunner().invoke(flirt_mod.app, ["--show-ambiguous", "--json"])
        data = json.loads(result.stdout)
        first = data["ambiguous_matches"][0]
        assert len(first["names"]) == flirt_mod._MAX_AMBIGUOUS_REPORT
        assert first["more"] is True


class TestSmallTextSectionSchema:
    """A tiny .text section must still emit the full JSON schema (the old
    early return used different keys and skipped the --va check entirely)."""

    def _setup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, raw_size: int) -> None:
        from types import SimpleNamespace

        import rebrew.flirt as flirt_mod

        monkeypatch.setattr(
            flirt_mod,
            "require_config",
            lambda target=None, json_mode=False: SimpleNamespace(
                root=tmp_path, target_binary=tmp_path / "x.dll"
            ),
        )
        monkeypatch.setattr(flirt_mod, "load_signatures", lambda d: [object()])
        monkeypatch.setattr(
            flirt_mod,
            "flirt",
            SimpleNamespace(
                compile=lambda s: object(), parse_sig=lambda b: [], parse_pat=lambda b: []
            ),
        )
        monkeypatch.setattr(
            flirt_mod,
            "load_binary",
            lambda p: SimpleNamespace(
                sections={".text": SimpleNamespace(va=0x1000, file_offset=0, raw_size=raw_size)},
                data=b"\xcc" * raw_size,
            ),
        )

    def test_small_text_full_schema(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from typer.testing import CliRunner

        import rebrew.flirt as flirt_mod

        self._setup(tmp_path, monkeypatch, raw_size=16)
        result = CliRunner().invoke(flirt_mod.app, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        for key in (
            "binary",
            "sig_dir",
            "signature_count",
            "text_size",
            "min_size",
            "match_count",
            "skipped_ambiguous",
            "matches",
            "ambiguous_matches",
        ):
            assert key in data
        assert data["text_size"] == 16
        assert "warning" in data
        assert data["matches"] == []

    def test_small_text_va_check_runs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        from typer.testing import CliRunner

        import rebrew.flirt as flirt_mod

        self._setup(tmp_path, monkeypatch, raw_size=16)
        # VA 0x1005 is inside the 16-byte .text (0x1000..0x1010) → check runs
        # (no match expected: find_func_size of cc bytes → 16 ≥ min_size, but
        # the fake matcher returns no matches).
        result = CliRunner().invoke(flirt_mod.app, ["--json", "--va", "0x1005"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["match_count"] == 0

    def test_small_text_va_out_of_section_still_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        import rebrew.flirt as flirt_mod

        self._setup(tmp_path, monkeypatch, raw_size=16)
        result = CliRunner().invoke(flirt_mod.app, ["--va", "0x2000"])
        assert result.exit_code != 0
        assert "outside .text" in result.output
