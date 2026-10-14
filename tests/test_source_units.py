"""Native source paths must be attributed only inside bounded instruction windows."""

import hashlib
import struct
from pathlib import Path
from typing import Any

from bin_util import append_pe_section, make_pe

from rebrew.formats.binary_loader import load_binary
from rebrew.source_units import source_unit_evidence


def _image(tmp_path: Path, code: bytes) -> Any:
    data = b"C:\\old\\first.c\0".ljust(32, b"\0") + b"Units/msx/msx.c\0"
    path = tmp_path / "reference.exe"
    path.write_bytes(append_pe_section(make_pe(code), ".rdata", data))
    return load_binary(path)


class TestSourceUnits:
    def test_verified_body_follows_internal_jump_without_decoding_skipped_table(
        self, tmp_path: Path
    ) -> None:
        code = b"\xeb\x05\x68" + struct.pack("<I", 0x500000)
        code += b"\x68" + struct.pack("<I", 0x500020) + b"\xc3"
        function = {
            "va": 0x401000,
            "size": len(code),
            "status": "RELOC",
            "verification": {
                "reference_size": str(len(code)),
                "reference_hash": hashlib.sha256(code).hexdigest(),
            },
        }
        result = source_unit_evidence(_image(tmp_path, code), [function])
        paths = {p["path"]: p["references"] for p in result["paths"]}
        assert paths["C:\\old\\first.c"] == []
        assert len(paths["Units/msx/msx.c"]) == 1
        assert paths["Units/msx/msx.c"][0]["instruction_va"] == 0x401007

    def test_unmapped_inventory_address_has_no_owner_claim(self, tmp_path: Path) -> None:
        result = source_unit_evidence(_image(tmp_path, b"\xc3"), [{"va": 0x900000, "size": 6}])
        assert result["refused"] == [{"function_va": 0x900000, "reason": "no mapped bytes"}]

    def test_merged_discovery_extent_cannot_claim_the_next_body(self, tmp_path: Path) -> None:
        first = b"\x68" + struct.pack("<I", 0x500000) + b"\xc3"
        second = b"\x68" + struct.pack("<I", 0x500020) + b"\xc3"
        info = _image(tmp_path, first + second)
        report = source_unit_evidence(info, [{"va": 0x401000, "size": 12}])
        paths = {p["path"]: p["references"] for p in report["paths"]}
        assert len(paths["C:\\old\\first.c"]) == 1
        assert paths["Units/msx/msx.c"] == []
        ref = paths["C:\\old\\first.c"][0]
        assert ref["function_size"] == ref["scan_size"] == 6
        assert ref["instruction_va"] == 0x401000
        assert ref["extent_kind"] == "ret"

    def test_conflicting_paths_and_shared_bindings_stay_visible(self, tmp_path: Path) -> None:
        code = b"\x68" + struct.pack("<I", 0x500000)
        code += b"\x68" + struct.pack("<I", 0x500020) + b"\xc3"
        info = _image(tmp_path, code)
        bindings = [{"module": "GOLD", "va": 0x401000}, {"module": "GOLDTL", "va": 0x501000}]
        function = {
            "va": 0x401000,
            "size": 11,
            "file": "src/shared.c",
            "bindings": bindings,
            "status": "RELOC",
            "verification": {
                "reference_hash": hashlib.sha256(code).hexdigest(),
                "reference_size": "11",
            },
        }
        result = source_unit_evidence(info, [function])
        assert len(result["conflicts"]) == 1
        assert result["conflicts"][0]["function_va"] == 0x401000
        for path in result["paths"]:
            ref = path["references"][0]
            assert ref["source"] == "src/shared.c"
            assert ref["bindings"] == bindings
            assert ref["extent_kind"] == "verified-reference"

    def test_jump_prefix_is_not_a_complete_body(self, tmp_path: Path) -> None:
        code = b"\x68" + struct.pack("<I", 0x500000) + b"\xeb\x00\xc3"
        result = source_unit_evidence(_image(tmp_path, code), [{"va": 0x401000, "size": 8}])
        ref = result["paths"][0]["references"][0]
        assert ref["function_size"] is None
        assert ref["scan_size"] == 7
        assert ref["extent_kind"] == "jmp"

    def test_unterminated_body_has_no_owner_claim(self, tmp_path: Path) -> None:
        code = b"\x68" + struct.pack("<I", 0x500000) + b"\x90"
        result = source_unit_evidence(_image(tmp_path, code), [{"va": 0x401000, "size": 6}])
        assert result["refused"] == [{"function_va": 0x401000, "reason": "no native terminator"}]
        assert all(not path["references"] for path in result["paths"])


class TestReachableCodeBounds:
    def test_internal_branch_into_an_instruction_refuses(self, tmp_path: Path) -> None:
        import pytest

        from rebrew.analysis import reachable_code

        # Conditional branch reaches the middle of the following push immediate.
        code = b"\x75\x01\x68\x00\x00\x50\x00\xc3"
        with pytest.raises(ValueError, match="overlaps"):
            reachable_code(_image(tmp_path, code), 0x401000, len(code))

    def test_truncated_reachable_instruction_refuses(self, tmp_path: Path) -> None:
        import pytest

        from rebrew.analysis import reachable_code

        with pytest.raises(ValueError, match="cannot decode"):
            reachable_code(_image(tmp_path, b"\x68\x01"), 0x401000, 2)
