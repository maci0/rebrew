"""Tests for catalog/registry.py size resolution and entry factories."""

import struct

from rebrew.catalog.loaders import make_func_entry
from rebrew.catalog.registry import (
    _resolve_canonical_size,
    is_jump_table,
)


class TestResolveCanonicalSize:
    def test_none(self) -> None:
        assert _resolve_canonical_size({}, 0x1000, None, 0, 0) == (0, "none")

    def test_list_only(self) -> None:
        assert _resolve_canonical_size({"list": 64}, 0x1000, None, 0, 0) == (
            64,
            "list (only source)",
        )

    def test_ghidra_only(self) -> None:
        assert _resolve_canonical_size({"ghidra": 32}, 0x1000, None, 0, 0) == (
            32,
            "ghidra (only source)",
        )

    def test_ghidra_larger(self) -> None:
        sizes = {"list": 32, "ghidra": 64}
        assert _resolve_canonical_size(sizes, 0x1000, None, 0, 0) == (
            64,
            "ghidra (larger or equal)",
        )

    def test_no_binary_data(self) -> None:
        sizes = {"list": 64, "ghidra": 32}
        assert _resolve_canonical_size(sizes, 0x1000, None, 0, 0) == (
            32,
            "ghidra (no binary data to verify)",
        )

    def test_extra_out_of_range(self) -> None:
        sizes = {"list": 64, "ghidra": 32}
        # text_data only 60 bytes; list_end (0x1040-0x1000=64) exceeds it.
        assert _resolve_canonical_size(sizes, 0x1000, b"\x90" * 60, 0x1000, 0x100) == (
            32,
            "ghidra (extra bytes out of range)",
        )

    def test_extra_all_padding(self) -> None:
        sizes = {"list": 64, "ghidra": 32}
        data = b"\x55\x89" + b"\xcc" * 62  # ghidra_end=2; extra = 62 CCs
        assert _resolve_canonical_size(sizes, 0x1000, data, 0x1000, 0x1000) == (
            64,
            "list (includes tail padding)",
        )

    def test_extra_jump_table(self) -> None:
        sizes = {"list": 64, "ghidra": 32}
        # extra (32 bytes) = 8 pointers into .text [0x1000, 0x2000).
        # Function body occupies [0:32]; the extra region is the jump table.
        table = b"".join(struct.pack("<I", 0x1000 + i * 4) for i in range(8))
        data = b"\x90" * 32 + table + b"\x90" * 30  # 64 bytes total
        assert _resolve_canonical_size(sizes, 0x1000, data, 0x1000, 0x1000) == (
            64,
            "list (includes jump table)",
        )

    def test_extra_back_jump(self) -> None:
        sizes = {"list": 64, "ghidra": 32}
        # E9 rel=-6 → target = base(32) + 0 + 5 - 6 = 31, inside [0, 32).
        extra = b"\xe9\xfa\xff\xff\xff" + b"\x90" * 27  # 64 bytes total
        data = b"\x90" * 32 + extra
        assert _resolve_canonical_size(sizes, 0x1000, data, 0x1000, 0x1000) == (
            64,
            "list (includes out-of-line code)",
        )

    def test_unrecognized_extra(self) -> None:
        # Extra bytes contain a ret (0xC3) but are otherwise unrecognized ->
        # fall back to Ghidra's (smaller) size.
        sizes = {"list": 64, "ghidra": 32}
        data = b"\x90" * 32 + (b"\x01\x02\x03\xc3" * 8)  # 64 bytes total
        assert _resolve_canonical_size(sizes, 0x1000, data, 0x1000, 0x1000) == (
            32,
            "ghidra (unrecognized extra bytes)",
        )

    def test_extra_code_tail_no_terminator(self) -> None:
        # Straight-line code with no ret and no padding is the same function's
        # tail — Ghidra truncated the size; trust the list size.
        sizes = {"list": 64, "ghidra": 32}
        data = b"\x90" * 32 + b"\x31\xc7\x00\x10\x37\xc7\x00\x10" * 4
        assert _resolve_canonical_size(sizes, 0x1000, data, 0x1000, 0x1000) == (
            64,
            "list (code tail, no terminator)",
        )

    def test_extra_ret_imm_no_terminator(self) -> None:
        # ret imm16 (0xC2) also counts as a terminator.
        sizes = {"list": 64, "ghidra": 32}
        data = b"\x90" * 32 + b"\x01\x02\xc2\x04" * 8
        assert _resolve_canonical_size(sizes, 0x1000, data, 0x1000, 0x1000) == (
            32,
            "ghidra (unrecognized extra bytes)",
        )

    def test_extra_code_tail_wins_over_padding_heuristic_order(self) -> None:
        # Mixed: padding first then code with no ret -> still the code tail
        # rule (padding check only fires when the WHOLE extra is padding).
        sizes = {"list": 40, "ghidra": 32}
        data = b"\x90" * 32 + b"\xcc" * 4 + b"\x31\xc7\x00\x10"
        assert _resolve_canonical_size(sizes, 0x1000, data, 0x1000, 0x1000) == (
            40,
            "list (code tail, no terminator)",
        )


class TestIsJumpTable:
    def test_pointers_into_text(self) -> None:
        data = b"".join(struct.pack("<I", 0x1000 + i * 4) for i in range(4))
        assert is_jump_table(data, 0x1000, 0x1000) is True

    def test_non_pointer_bytes(self) -> None:
        assert is_jump_table(b"\x01\x02\x03\x04\x05\x06\x07\x08", 0x1000, 0x1000) is False


class TestEntryFactories:
    def test_make_func_entry(self) -> None:
        assert make_func_entry(0x1000, 64, "_f") == {"va": 0x1000, "size": 64, "name": "_f"}
