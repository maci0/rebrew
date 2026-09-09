"""Unit tests for verify --data byte comparison of built data sections."""

from pathlib import Path


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class TestVerifyDataBytes:
    def test_matching_symbols_verify(self, tmp_path: Path) -> None:
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(
            meta,
            '["SERVER.0x1000"]\nname = "g_a"\nsize = 4\nsection = ".data"\n',
        )
        res = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"\x01\x02\x03\x04"},
            actual={0x1000: b"\x01\x02\x03\x04"},
            sizes={0x1000: 4},
        )
        assert res["matched"] == 1
        assert res["mismatched"] == []
        assert res["missing"] == []

    def test_content_mismatch_attributed_per_symbol(self, tmp_path: Path) -> None:
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(
            meta,
            '["SERVER.0x1000"]\nname = "g_a"\nsize = 4\nsection = ".data"\n'
            '["SERVER.0x1010"]\nname = "g_b"\nsize = 4\nsection = ".data"\n',
        )
        res = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"\x01\x02\x03\x04", 0x1010: b"\xaa\xbb\xcc\xdd"},
            actual={0x1000: b"\x01\x02\x03\x04", 0x1010: b"\xaa\xbb\xcc\x00"},
            sizes={0x1000: 4, 0x1010: 4},
        )
        assert res["matched"] == 1
        assert len(res["mismatched"]) == 1
        assert res["mismatched"][0]["name"] == "g_b"
        assert res["mismatched"][0]["first_diff"] == 3

    def test_missing_symbol_reported(self, tmp_path: Path) -> None:
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(
            meta,
            '["SERVER.0x1000"]\nname = "g_a"\nsize = 4\nsection = ".data"\n',
        )
        res = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"\x01\x02\x03\x04"},
            actual={},
            sizes={0x1000: 4},
        )
        assert res["matched"] == 0
        assert res["missing"] == ["g_a"]


class TestSectionFilter:
    def test_rdata_only_symbol_skipped_for_data(self, tmp_path: Path) -> None:
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        meta.write_text(
            '["SERVER.0x1000"]\nname = "g_c"\nsize = 2\nsection = ".rdata"\n',
            encoding="utf-8",
        )
        res = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"\x01\x02"},
            actual={0x1000: b"\xff\xff"},
            sizes={0x1000: 2},
            sections=(".data",),
        )
        assert res == {"matched": 0, "mismatched": [], "missing": []}

    def test_unsectioned_symbol_skipped(self, tmp_path: Path) -> None:
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        meta.write_text('["SERVER.0x1000"]\nname = "g_x"\nsize = 2\n', encoding="utf-8")
        res = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"\x01\x02"},
            actual={0x1000: b"\x01\x02"},
            sizes={0x1000: 2},
        )
        assert res == {"matched": 0, "mismatched": [], "missing": []}
