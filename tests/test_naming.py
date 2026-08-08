"""Tests for naming.py — name normalization, delta parsing, difficulty, filenames."""

from types import SimpleNamespace

from rebrew.naming import (
    estimate_difficulty,
    make_filename,
    normalize_name,
    parse_byte_delta,
    sanitize_name,
)


class TestNormalizeName:
    def test_imp_prefix(self) -> None:
        assert normalize_name("__imp__printf") == "printf"

    def test_cdecl_leading_underscore(self) -> None:
        assert normalize_name("_func_a") == "func_a"

    def test_stdcall_suffix(self) -> None:
        assert normalize_name("_func@8") == "func"

    def test_double_underscore_untouched(self) -> None:
        # "__imp" lacks the trailing underscore, so the __imp_ prefix doesn't match.
        assert normalize_name("__imp") == "__imp"
        assert normalize_name("__imp_foo") == "foo"

    def test_already_normal(self) -> None:
        assert normalize_name("func_b") == "func_b"

    def test_case_insensitive(self) -> None:
        assert normalize_name("FUNC_A") == "func_a"


class TestParseByteDelta:
    def test_small_diff(self) -> None:
        assert parse_byte_delta("(2B diff)") == 2

    def test_diff_with_colon(self) -> None:
        assert parse_byte_delta("24B diff:") == 24

    def test_vs_pattern(self) -> None:
        assert parse_byte_delta("229B vs 205B") == 24

    def test_none_for_unparseable(self) -> None:
        assert parse_byte_delta("no delta here") is None

    def test_empty_string(self) -> None:
        assert parse_byte_delta("") is None


class TestEstimateDifficulty:
    def test_ignored_symbol(self) -> None:
        level, reason = estimate_difficulty(100, "__imp_foo", ignored={"__imp_foo"})
        assert level == 0
        assert "ignored" in reason

    def test_library_module_small(self) -> None:
        cfg = SimpleNamespace(library_modules={"MSVCRT"})
        level, _ = estimate_difficulty(50, "f", module="MSVCRT", cfg=cfg)
        assert level == 2

    def test_library_module_large(self) -> None:
        cfg = SimpleNamespace(library_modules={"MSVCRT"})
        level, _ = estimate_difficulty(200, "f", module="MSVCRT", cfg=cfg)
        assert level == 3

    def test_size_tiers(self) -> None:
        assert estimate_difficulty(50, "f")[0] == 1
        assert estimate_difficulty(100, "f")[0] == 2
        assert estimate_difficulty(200, "f")[0] == 3
        assert estimate_difficulty(300, "f")[0] == 4
        assert estimate_difficulty(500, "f")[0] == 5


class TestSanitizeName:
    def test_fun_prefix(self) -> None:
        assert sanitize_name("FUN_10001000") == "func_10001000"

    def test_special_chars_replaced(self) -> None:
        assert sanitize_name("my-func!name") == "my_func_name"

    def test_leading_digit_prefixed(self) -> None:
        assert sanitize_name("123abc") == "_123abc"

    def test_all_invalid_becomes_unnamed(self) -> None:
        assert sanitize_name("!!!") == "unnamed"

    def test_underscore_collapse(self) -> None:
        assert sanitize_name("a__b") == "a_b"


class TestMakeFilename:
    def test_custom_name_wins(self) -> None:
        assert make_filename(0x1000, "FUN_10001000", custom_name="my_func") == "my_func.c"

    def test_fun_uses_hex(self) -> None:
        assert make_filename(0x1000, "FUN_10001000") == "func_10001000.c"

    def test_sanitized_ghidra_name(self) -> None:
        # sanitize_name preserves case; only special chars are replaced.
        assert make_filename(0x1000, "BitReverse") == "BitReverse.c"

    def test_custom_extension(self) -> None:
        cfg = SimpleNamespace(source_ext=".cpp")
        assert make_filename(0x1000, "FUN_10001000", cfg=cfg) == "func_10001000.cpp"


class TestDetectUnmatchablePatterns:
    def _run(self, monkeypatch, raw: bytes, size: int, name: str = "") -> str | None:
        from rebrew.naming import detect_unmatchable

        binary = SimpleNamespace()
        monkeypatch.setattr("rebrew.naming.extract_bytes_at_va", lambda *a, **k: raw)
        return detect_unmatchable(0x1000, size, binary, name=name)

    def test_single_ret(self, monkeypatch) -> None:
        assert self._run(monkeypatch, b"\xc3\x90\x90", 2) == "single-byte RET stub"

    def test_int3_padding(self, monkeypatch) -> None:
        assert self._run(monkeypatch, b"\xcc\xcc\xcc", 2) == "INT3 padding"

    def test_nop_padding(self, monkeypatch) -> None:
        assert self._run(monkeypatch, b"\x90\x90\x90", 2) == "NOP padding"

    def test_iat_jmp_thunk(self, monkeypatch) -> None:
        assert self._run(monkeypatch, b"\xff\x25\x00\x10\x00\x00", 6) == "IAT jmp [addr] thunk"

    def test_seh_handler(self, monkeypatch) -> None:
        assert (
            self._run(monkeypatch, b"\x64\xa1\x00\x00\x00\x00\x8b\x00", 8)
            == "SEH handler (fs:[0] access)"
        )

    def test_bt_instruction(self, monkeypatch) -> None:
        # 0f a3 c8 = bt eax, ecx
        assert self._run(monkeypatch, b"\x0f\xa3\xc8\xc3", 4) == "ASM-origin CRT (BT/BTS)"

    def test_repne_scasb(self, monkeypatch) -> None:
        assert self._run(monkeypatch, b"\xf2\xae\xc3", 3) == "ASM-origin CRT (repne scasb)"

    def test_rep_movsb(self, monkeypatch) -> None:
        assert self._run(monkeypatch, b"\xf3\xa4\xc3", 3) == "ASM-origin CRT (rep movs)"

    def test_normal_code_returns_none(self, monkeypatch) -> None:
        assert self._run(monkeypatch, b"\x55\x8b\xec\x5d\xc3", 5) is None


class TestDetectUnmatchableConfig:
    def test_iat_thunk_config(self) -> None:
        from rebrew.naming import detect_unmatchable

        assert detect_unmatchable(0x1000, 10, None, iat_thunks={0x1000}) == "IAT thunk (config)"

    def test_ignored_symbol(self) -> None:
        from rebrew.naming import detect_unmatchable

        assert (
            detect_unmatchable(0x1000, 10, None, ignored_symbols={"_chkstk"}, name="_chkstk")
            == "ignored symbol: _chkstk"
        )

    def test_no_binary_returns_none(self) -> None:
        from rebrew.naming import detect_unmatchable

        assert detect_unmatchable(0x1000, 10, None) is None

    def test_no_bytes_returns_none(self, monkeypatch) -> None:
        from rebrew.naming import detect_unmatchable

        monkeypatch.setattr("rebrew.naming.extract_bytes_at_va", lambda *a, **k: None)
        assert detect_unmatchable(0x1000, 10, SimpleNamespace()) is None
