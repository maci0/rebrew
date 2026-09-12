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


class TestSectionSymbolBytesBounds:
    """Reads clamp to the owning section's mapped extent; an oversized
    SIZE is an error, not a silent cross-section read."""

    def _meta(self, tmp_path: Path, size: int, va: int = 0x1000) -> Path:
        meta = tmp_path / "rebrew-data.toml"
        meta.write_text(
            f'["SERVER.{va:#x}"]\nname = "g_a"\nsize = {size}\nsection = ".data"\n',
            encoding="utf-8",
        )
        return meta

    def _fake_info(self, monkeypatch, size: int, raw_size: int, data: bytes):  # type: ignore[no-untyped-def]
        from types import SimpleNamespace

        info = SimpleNamespace(
            sections={
                ".data": SimpleNamespace(
                    name=".data", va=0x1000, size=size, raw_size=raw_size, file_offset=0
                )
            },
            data=data,
        )
        monkeypatch.setattr("rebrew.binary_loader.load_binary", lambda _p: info)
        return info

    def test_in_extent_reads_section_bytes(
        self,
        tmp_path: Path,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        import pytest

        pytest.importorskip("lief")
        from rebrew.data_verify import section_symbol_bytes

        self._fake_info(monkeypatch, size=0x20, raw_size=0x20, data=bytes(range(0x20)))
        by_va, sizes = section_symbol_bytes(
            metadata_path=self._meta(tmp_path, 4), binary_path=tmp_path / "x.dll"
        )
        assert by_va[0x1000] == b"\x00\x01\x02\x03"
        assert sizes[0x1000] == 4

    def test_oversized_symbol_raises_not_cross_section(
        self,
        tmp_path: Path,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        import pytest

        pytest.importorskip("lief")
        from rebrew.data_verify import section_symbol_bytes

        # Symbol runs 8 bytes past the .data mapped extent: must raise,
        # never read the neighbor section's bytes.
        self._fake_info(monkeypatch, size=0x10, raw_size=0x10, data=bytes(range(0x40)))
        with pytest.raises(ValueError, match="overruns section"):
            section_symbol_bytes(
                metadata_path=self._meta(tmp_path, 0x18), binary_path=tmp_path / "x.dll"
            )

    def test_bss_tail_symbol_skipped_without_bytes(
        self,
        tmp_path: Path,
        monkeypatch,  # type: ignore[no-untyped-def]
    ) -> None:
        import pytest

        pytest.importorskip("lief")
        from rebrew.data_verify import section_symbol_bytes

        # Inside the mapped extent but past raw_size (zero-fill tail):
        # no file bytes exist, so the symbol is skipped (caller: missing).
        self._fake_info(monkeypatch, size=0x20, raw_size=0x10, data=bytes(range(0x10)))
        by_va, sizes = section_symbol_bytes(
            metadata_path=self._meta(tmp_path, 4, va=0x1010),
            binary_path=tmp_path / "x.dll",
        )
        assert by_va == {}
        assert sizes == {}
