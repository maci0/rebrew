"""Tests for catalog/registry.py size resolution and entry factories."""

import struct

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

    def test_code_tail_probe_is_x86_only(self) -> None:
        # 0xC3/0xC2 are the x86 ret encodings, so the "no terminator" probe
        # must not run on another arch: no ARM or MIPS tail ever contains
        # them, and running it there made every such function claim the list
        # size.  A non-x86 target takes the conservative default.
        sizes = {"list": 64, "ghidra": 32}
        data = b"\x90" * 32 + b"\x31\xc7\x00\x10\x37\xc7\x00\x10" * 4
        assert _resolve_canonical_size(sizes, 0x1000, data, 0x1000, 0x1000) == (
            64,
            "list (code tail, no terminator)",
        )
        for arch in ("arm32", "mips32", "ppc32"):
            assert _resolve_canonical_size(sizes, 0x1000, data, 0x1000, 0x1000, arch) == (
                32,
                "ghidra (unrecognized extra bytes)",
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

    def test_pointer_width_follows_arch(self) -> None:
        """A 64-bit table is read at 8-byte stride, not mis-strided as 4."""
        data = b"".join(struct.pack("<Q", 0x1000 + i * 8) for i in range(4))
        assert is_jump_table(data, 0x1000, 0x1000, arch="x86_64") is True
        # Read 4 bytes at a time the low dwords still land in .text, so the
        # old 4-byte path accepted this too; the reverse is the real trap.
        assert is_jump_table(data, 0x1000, 0x1000, arch="x86_32") is False

    def test_byte_order_follows_arch(self) -> None:
        """MIPS is big-endian, so a big-endian table is the one that matches."""
        data = b"".join(struct.pack(">I", 0x1000 + i * 4) for i in range(4))
        assert is_jump_table(data, 0x1000, 0x1000, arch="mips32") is True
        assert is_jump_table(data, 0x1000, 0x1000, arch="x86_32") is False

    def test_image_endian_overrides_arch_default(self) -> None:
        """A little-endian MIPS build (PlayStation) reads little-endian.

        The arch default says big-endian; the image header says otherwise and
        wins, the way it does for the instruction stream.
        """
        data = b"".join(struct.pack("<I", 0x1000 + i * 4) for i in range(4))
        assert is_jump_table(data, 0x1000, 0x1000, arch="mips32", endian="little") is True
        # The same bytes under the arch default are not a table.
        assert is_jump_table(data, 0x1000, 0x1000, arch="mips32") is False

    def test_hotpatch_prefix_before_32bit_table(self) -> None:
        """``mov edi, edi`` before a 32-bit pointer pair is still a jump table.

        The two-byte hotpatch makes the slice length 2 mod 4. Rejecting any
        slice whose length is not a multiple of the pointer width dropped the
        table before the prefix skip ran.
        """
        pointers = b"".join(struct.pack("<I", 0x1000 + i * 4) for i in range(2))
        assert is_jump_table(b"\x8b\xff" + pointers, 0x1000, 0x1000) is True

    def test_one_nop_does_not_align_a_table(self) -> None:
        """A single NOP leaves the pointer slots off a 4-byte boundary."""
        pointers = b"".join(struct.pack("<I", 0x1000 + i * 4) for i in range(2))
        assert is_jump_table(b"\x90" + pointers, 0x1000, 0x1000) is False

    def test_hotpatch_jump_table_extends_canonical_size(self) -> None:
        """The size resolver counts a hotpatch-prefixed table in the list size."""
        extra = b"\x8b\xff" + b"".join(struct.pack("<I", 0x1000 + i * 4) for i in range(2))
        data = b"\xc3" * 32 + extra
        sizes = {"ghidra": 32, "list": 32 + len(extra)}
        assert _resolve_canonical_size(sizes, 0x1000, data, 0x1000, 0x1000) == (
            32 + len(extra),
            "list (includes jump table)",
        )

    def test_big_endian_image_header_on_little_endian_arch(self) -> None:
        """A BE image of a normally-LE arch reads big-endian, not reversed."""
        data = b"".join(struct.pack(">I", 0x1000 + i * 4) for i in range(4))
        assert is_jump_table(data, 0x1000, 0x1000, arch="x86_32", endian="big") is True
        assert is_jump_table(data, 0x1000, 0x1000, arch="x86_32") is False

    def test_canonical_size_uses_image_endianness(self) -> None:
        """``_resolve_canonical_size`` passes the target's byte order through.

        Ghidra saw 32 bytes, the list saw 40, and the 8 extra are a LE
        pointer pair — a jump table on a little-endian MIPS build.
        """
        extra = b"".join(struct.pack("<I", 0x1000 + i * 4) for i in range(2))
        data = b"\x90" * 32 + extra
        sizes = {"ghidra": 32, "list": 40}
        assert _resolve_canonical_size(sizes, 0x1000, data, 0x1000, 0x1000, "mips32", "little") == (
            40,
            "list (includes jump table)",
        )
        # Without the header the arch default rejects the same bytes.
        assert _resolve_canonical_size(sizes, 0x1000, data, 0x1000, 0x1000, "mips32") != (
            40,
            "list (includes jump table)",
        )
