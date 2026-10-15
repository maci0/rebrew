"""Reject incomplete literal and native identity proofs without mutating verdicts."""

import hashlib
import struct
from pathlib import Path
from unittest.mock import patch

import pytest
from bin_util import make_coff_obj, make_pe

from rebrew.coff_reloc import build_name_to_va
from rebrew.config import ProjectConfig
from rebrew.formats.binary_loader import load_binary
from rebrew.metadata.functions import get_entry, record_function_identity, set_fields
from rebrew.native_review import review_native_identity
from rebrew.object_evidence import audit_literals, literal_size, native_span, object_function


def _object(
    value: bytes, name: str = "??_C@_03HASH@abc?$AA@", *, addend: int = 0, kind: int = 6
) -> bytes:
    code = b"\xb8" + struct.pack("<I", addend) + b"\xc3\xcc\xcc"
    return make_coff_obj(
        code + value,
        relocs=[(1, kind, name)],
        func_symbol="_helper",
        section_symbols=[(name, 8)],
        extra_funcs=[("_boundary", 8)],
    )


def _project(
    tmp_path: Path, native: bytes, obj: bytes, size: int = 8
) -> tuple[ProjectConfig, Path]:
    binary = tmp_path / "native.exe"
    binary.write_bytes(make_pe(native))
    cfg = ProjectConfig(
        root=tmp_path, reversed_dir=tmp_path / "src", target_binary=binary, marker="GAME"
    )
    cfg.reversed_dir.mkdir()
    object_path = tmp_path / "helper.obj"
    object_path.write_bytes(obj)
    record_function_identity(
        cfg.metadata_dir,
        module="GAME",
        va=0x401000,
        file="runtime.h",
        name="attributed_name",
        symbol="_attributed_name",
        kind="LIBRARY",
        size=size,
    )
    return cfg, object_path


class TestLiteralEvidence:
    @pytest.mark.parametrize(
        ("name", "size"),
        [
            ("??_C@_03HASH@abc", 4),
            ("??_C@_1M@HASH@", 12),
            ("__real@3f800000", 4),
            ("__real@8@4008fa00000000000000", 8),
        ],
    )
    def test_compiler_declared_extent(self, name: str, size: int) -> None:
        assert literal_size(name) == size

    @pytest.mark.parametrize("name", ["$SG123", "__real@garbage", "??_C@_2M@", "??_C@_0?M@"])
    def test_unknown_extent_is_rejected(self, name: str) -> None:
        with pytest.raises(ValueError, match="extent"):
            literal_size(name)

    def test_complete_embedded_nul_and_native_selected_pool(self, tmp_path: Path) -> None:
        value = b"a\0b\0"
        cfg, obj = _project(
            tmp_path,
            b"\xb8"
            + struct.pack("<I", 0x401010)
            + b"\xc3\xcc\xcc"
            + b"a\0x\0"
            + b"\xcc" * 4
            + value,
            _object(value),
        )
        result = audit_literals(
            object_function(obj.read_bytes(), "_helper", 8),
            load_binary(cfg.target_binary),
            0x401000,
        )
        assert result["complete"]
        assert result["literals"][0]["native_va"] == 0x401010
        assert result["literals"][0]["size"] == 4
        assert not result["placement_verified"] and not result["ownership_verified"]
        # A matching prefix before an embedded NUL cannot hide a wrong suffix.
        cfg.target_binary.write_bytes(
            make_pe(b"\xb8" + struct.pack("<I", 0x401008) + b"\xc3\xcc\xcc" + b"a\0x\0")
        )
        assert not audit_literals(
            object_function(obj.read_bytes(), "_helper", 8),
            load_binary(cfg.target_binary),
            0x401000,
        )["complete"]

    def test_interior_addend(self, tmp_path: Path) -> None:
        value = b"abc\0"
        cfg, obj = _project(
            tmp_path,
            b"\xb8" + struct.pack("<I", 0x401009) + b"\xc3\xcc\xcc" + value,
            _object(value, addend=1),
        )
        result = audit_literals(
            object_function(obj.read_bytes(), "_helper", 8),
            load_binary(cfg.target_binary),
            0x401000,
        )
        assert result["complete"] and result["literals"][0]["native_va"] == 0x401008

    @pytest.mark.parametrize(("name", "kind"), [("$SG123", 6), ("??_C@_03HASH@", 20)])
    def test_unsupported_never_complete(self, tmp_path: Path, name: str, kind: int) -> None:
        cfg, obj = _project(
            tmp_path,
            b"\xb8" + struct.pack("<I", 0x401008) + b"\xc3\xcc\xccabc\0",
            _object(b"abc\0", name, kind=kind),
        )
        result = audit_literals(
            object_function(obj.read_bytes(), "_helper", 8),
            load_binary(cfg.target_binary),
            0x401000,
        )
        assert not result["complete"] and result["literals"][0]["status"] == "unsupported"

    def test_actual_eof_bounds(self, tmp_path: Path) -> None:
        cfg, _ = _project(tmp_path, b"\xc3", make_coff_obj(b"\xc3\xcc\xcc\xcc"), size=4)
        cfg.target_binary.write_bytes(cfg.target_binary.read_bytes()[:513])
        with pytest.raises(ValueError, match="actual file|file-backed"):
            native_span(load_binary(cfg.target_binary), 0x401000, 4)

    def test_partial_lief_relocation_parse_is_rejected(self) -> None:
        raw = bytearray(make_coff_obj(b"\x90\x90\x90\xc3"))
        struct.pack_into("<I", raw, 20 + 24, len(raw) + 100)
        struct.pack_into("<H", raw, 20 + 32, 1)
        with pytest.raises(ValueError, match="relocation table"):
            object_function(bytes(raw), "_myfunc", 4)

    def test_data_section_cannot_establish_function_identity(self) -> None:
        with pytest.raises(ValueError, match="executable code"):
            object_function(
                make_coff_obj(b"\x90\x90\x90\xc3", section_chars=0x40000040), "_myfunc", 4
            )

    def test_partial_function_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="extends beyond"):
            object_function(make_coff_obj(b"\x55\x89\xe5\xc3"), "_myfunc", 1)

    def test_only_reported_alignment_is_excluded(self) -> None:
        function = object_function(make_coff_obj(b"\xc3\xcc\xcc\xcc"), "_myfunc", 1)
        assert function.code == b"\xc3" and function.excluded_padding == 3


class TestReviewedNativeIdentity:
    def test_preview_is_read_only_and_apply_only_establishes_exact_name(
        self, tmp_path: Path
    ) -> None:
        cfg, obj = _project(
            tmp_path,
            b"\xb8" + struct.pack("<I", 0x401008) + b"\xc3\xcc\xccabc\0",
            _object(b"abc\0"),
        )
        before = {p: (p.read_bytes(), p.stat()) for p in tmp_path.rglob("*") if p.is_file()}
        preview = review_native_identity(
            cfg, 0x401000, obj, "_helper", reason="review", dry_run=True
        )
        assert before == {p: (p.read_bytes(), p.stat()) for p in tmp_path.rglob("*") if p.is_file()}
        assert "_helper" not in build_name_to_va(cfg)
        original = get_entry(cfg.metadata_dir, 0x401000, "GAME")
        review_native_identity(
            cfg, 0x401000, obj, "_helper", reason="review", expected_digest=preview["input_digest"]
        )
        row = get_entry(cfg.metadata_dir, 0x401000, "GAME")
        assert {k: v for k, v in row.items() if k != "native_identity"} == original
        assert build_name_to_va(cfg)["_helper"] == 0x401000
        assert "attributed_name" not in build_name_to_va(cfg)
        cfg.target_binary.write_bytes(cfg.target_binary.read_bytes() + b"changed")
        assert "_helper" not in build_name_to_va(cfg)

    @pytest.mark.parametrize("change", ["code", "literal", "extent", "object"])
    def test_failed_or_stale_proofs_never_publish(self, tmp_path: Path, change: str) -> None:
        cfg, obj = _project(
            tmp_path,
            b"\xb8" + struct.pack("<I", 0x401008) + b"\xc3\xcc\xccabc\0",
            _object(b"abc\0"),
        )
        preview = review_native_identity(
            cfg, 0x401000, obj, "_helper", reason="review", dry_run=True
        )
        if change == "object":
            obj.write_bytes(obj.read_bytes() + b"changed")
        elif change == "extent":
            set_fields(cfg.metadata_dir, 0x401000, {"size": 4}, module="GAME")
        else:
            raw = bytearray(cfg.target_binary.read_bytes())
            raw[0x200 + (5 if change == "code" else 10)] ^= 1
            cfg.target_binary.write_bytes(raw)
        with pytest.raises(ValueError, match="changed"):
            review_native_identity(
                cfg,
                0x401000,
                obj,
                "_helper",
                reason="review",
                expected_digest=preview["input_digest"],
            )
        assert "native_identity" not in get_entry(cfg.metadata_dir, 0x401000, "GAME")
        if change != "object":
            with pytest.raises(ValueError):
                review_native_identity(cfg, 0x401000, obj, "_helper", reason="review")

    def test_generic_writer_cannot_forge_review(self, tmp_path: Path) -> None:
        cfg, obj = _project(
            tmp_path,
            b"\xc3\xcc\xcc\xcc",
            make_coff_obj(b"\xc3\xcc\xcc\xcc", func_symbol="_helper"),
            4,
        )
        preview = review_native_identity(
            cfg, 0x401000, obj, "_helper", reason="review", dry_run=True
        )
        with pytest.raises(ValueError, match="record_native_identity"):
            set_fields(
                cfg.metadata_dir,
                0x401000,
                {"native_identity": preview["native_identity"]},
                module="GAME",
            )

    def test_wrong_callee_is_rejected(self, tmp_path: Path) -> None:
        code = b"\xe8\0\0\0\0\xc3\xcc\xcc"
        cfg, obj = _project(
            tmp_path,
            b"\xe8" + struct.pack("<I", 0x100) + code[5:],
            make_coff_obj(code, relocs=[(1, 20, "_callee")], func_symbol="_helper"),
        )
        with (
            patch("rebrew.native_review.build_name_to_va", return_value={"_callee": 0x401200}),
            pytest.raises(ValueError, match="code/operand"),
        ):
            review_native_identity(cfg, 0x401000, obj, "_helper", reason="review")
        assert "native_identity" not in get_entry(cfg.metadata_dir, 0x401000, "GAME")

    def test_recheck_under_writer_lock(self, tmp_path: Path) -> None:
        cfg, obj = _project(
            tmp_path,
            b"\xc3\xcc\xcc\xcc",
            make_coff_obj(b"\xc3\xcc\xcc\xcc", func_symbol="_helper"),
            4,
        )
        from rebrew.metadata.native_identity import record_native_identity

        preview = review_native_identity(
            cfg, 0x401000, obj, "_helper", reason="review", dry_run=True
        )
        before = (cfg.metadata_dir / "rebrew-functions.toml").read_bytes()
        obj.write_bytes(b"changed")
        with pytest.raises(ValueError, match="input changed"):
            record_native_identity(
                cfg.metadata_dir,
                "GAME",
                0x401000,
                preview["native_identity"],
                expected_digest=hashlib.sha256(before).hexdigest(),
                expected_inputs={obj: "a" * 64},
            )
        assert (cfg.metadata_dir / "rebrew-functions.toml").read_bytes() == before
