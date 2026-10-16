"""Unit tests for verify --data byte comparison of built data sections."""

from pathlib import Path

import pytest
from source_util import write_store_fixture


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class TestCoverageReporting:
    """A count of matches is meaningless without the denominator.

    Regression for the guild-rebrew case: verify --data printed "122
    matched, 0 mismatched, 0 missing" over metadata holding 329 symbols,
    because symbols with no file bytes (the zero-fill tail) never reach
    `sizes` and so were invisible rather than reported as skipped.
    """

    def test_full_coverage(self, tmp_path: Path) -> None:
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(
            meta,
            'format = 2\n["SERVER.0x1000"]\nname = "g_a"\nsize = 4\nsection = ".data"\n["SERVER.0x2000"]\nname = "g_b"\nsize = 4\nsection = ".data"\n',
        )
        res = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"\x01\x02\x03\x04", 0x2000: b"\x05\x06\x07\x08"},
            actual={0x1000: b"\x01\x02\x03\x04", 0x2000: b"\x05\x06\x07\x08"},
            sizes={0x1000: 4, 0x2000: 4},
        )
        assert res["matched"] == 2
        assert (res["compared"], res["total"], res["not_comparable"]) == (2, 2, 0)
        assert res["coverage"] == 1.0

    def test_symbol_with_no_file_bytes_is_counted_not_hidden(self, tmp_path: Path) -> None:
        """The guild-rebrew case: 2 named, 1 comparable, so coverage is 50%."""
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(
            meta,
            'format = 2\n["SERVER.0x1000"]\nname = "g_a"\nsize = 4\nsection = ".data"\n["SERVER.0x2000"]\nname = "g_bss"\nsize = 4\nsection = ".data"\n',
        )
        res = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"\x01\x02\x03\x04"},
            actual={0x1000: b"\x01\x02\x03\x04"},
            sizes={0x1000: 4},  # 0x2000 absent: zero-fill tail, no file bytes
        )
        assert res["matched"] == 1
        assert res["mismatched"] == []
        assert (res["compared"], res["total"], res["not_comparable"]) == (1, 2, 1)
        assert res["coverage"] == 0.5

    def test_out_of_scope_section_counted_in_total(self, tmp_path: Path) -> None:
        """A .rdata symbol under sections=('.data',) is not comparable either."""
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(
            meta,
            'format = 2\n["SERVER.0x1000"]\nname = "g_a"\nsize = 2\nsection = ".data"\n["SERVER.0x3000"]\nname = "g_r"\nsize = 2\nsection = ".rdata"\n',
        )
        res = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"\x01\x02", 0x3000: b"\x03\x04"},
            actual={0x1000: b"\x01\x02", 0x3000: b"\x03\x04"},
            sizes={0x1000: 2, 0x3000: 2},
            sections=(".data",),
        )
        assert res["matched"] == 1
        assert (res["compared"], res["total"], res["not_comparable"]) == (1, 2, 1)

    def test_empty_metadata_does_not_divide_by_zero(self, tmp_path: Path) -> None:
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(meta, "format = 2\n")
        res = verify_data_bytes(metadata_path=meta, expected={}, actual={}, sizes={})
        assert res["coverage"] == 0.0
        assert (res["compared"], res["total"]) == (0, 0)

    def test_unnamed_symbol_not_counted(self, tmp_path: Path) -> None:
        """Unnamed inventory cannot be attributed, so it is not in the total."""
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(meta, 'format = 2\n["SERVER.0x1000"]\nsize = 2\nsection = ".data"\n')
        res = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"\x01\x02"},
            actual={0x1000: b"\x01\x02"},
            sizes={0x1000: 2},
        )
        assert res["total"] == 0
        assert res["coverage"] == 0.0


class TestVerifyDataBytes:
    @pytest.mark.parametrize(
        "type_str", ["char[COUNT]", "char[]", "char[0]", "struct Large", "void (*)(int)"]
    )
    def test_unresolved_extent_cannot_verify_a_matching_prefix(
        self, tmp_path: Path, type_str: str
    ) -> None:
        from rebrew.data_verify import verify_data_bytes
        from rebrew.metadata.data import set_data_fields_batch

        meta = tmp_path / "rebrew-data.toml"
        set_data_fields_batch(
            tmp_path,
            [
                {
                    "module": "SERVER",
                    "va": 0x1000,
                    "fields": {"name": "g_a", "type": type_str, "section": ".data"},
                }
            ],
        )
        report = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"A" * 64},
            actual={0x1000: b"A" * 32 + b"X" * 32},
            sizes={0x1000: 64},
        )
        assert report["matched"] == report["compared"] == 0
        assert report["results"][0]["status"] == "UNCHECKED"
        set_data_fields_batch(
            tmp_path, [{"module": "SERVER", "va": 0x1000, "fields": {"size": 64}}]
        )
        report = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"A" * 64},
            actual={0x1000: b"A" * 32 + b"X" * 32},
            sizes={0x1000: 64},
        )
        assert report["results"][0]["status"] == "DRIFT"

    def test_duplicate_key_spellings_count_as_one_symbol(self, tmp_path: Path) -> None:
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(
            meta,
            'format = 2\n["SERVER.0x00001000"]\nname="g_a"\nsize=4\nsection=".data"\n["SERVER.0X1000"]\nname="g_a"\nnote="same identity"\n',
        )
        import pytest

        with pytest.raises(ValueError, match="duplicate metadata keys"):
            verify_data_bytes(
                metadata_path=meta,
                expected={0x1000: b"abcd"},
                actual={0x1000: b"abcd"},
                sizes={0x1000: 4},
            )

    def test_equal_truncated_bytes_cannot_verify_a_larger_symbol(self, tmp_path: Path) -> None:
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(meta, 'format = 2\n["SERVER.0x1000"]\nname = "g_a"\nsize = 4\nsection = ".data"\n')
        report = verify_data_bytes(
            metadata_path=meta, expected={0x1000: b"ab"}, actual={0x1000: b"ab"}, sizes={0x1000: 4}
        )
        assert report["matched"] == report["compared"] == 0
        assert report["results"][0]["status"] == "UNCHECKED"
        report = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"abcd"},
            actual={0x1000: b"ab"},
            sizes={0x1000: 4},
        )
        assert report["matched"] == 0
        assert report["missing"] == ["g_a"]

    def test_module_va_identity_survives_name_and_address_aliases(self, tmp_path: Path) -> None:
        from types import SimpleNamespace

        from rebrew.data_verify import verify_data_bytes
        from rebrew.metadata.data import set_data_fields_batch

        set_data_fields_batch(
            tmp_path,
            [
                {
                    "module": "SERVER",
                    "va": 0x1000,
                    "fields": {"name": "shared", "size": 2, "section": ".data"},
                },
                {
                    "module": "LIB",
                    "va": 0x1000,
                    "fields": {"name": "long_alias", "size": 4, "section": ".data"},
                },
                {
                    "module": "SERVER",
                    "va": 0x2000,
                    "fields": {"name": "shared", "size": 2, "section": ".data"},
                },
                {
                    "module": "OTHER",
                    "va": 0x1000,
                    "fields": {"name": "foreign", "size": 2, "section": ".data"},
                },
            ],
        )
        report = verify_data_bytes(
            metadata_path=tmp_path / "rebrew-data.toml",
            expected={0x1000: b"abcd", 0x2000: b"ef"},
            actual={0x1000: b"abXd", 0x2000: b"eX"},
            sizes={0x1000: 4, 0x2000: 2},
            cfg=SimpleNamespace(module="SERVER", target_modules={"SERVER", "OTHER"}),
        )
        assert report["total"] == report["compared"] == 3
        assert report["matched"] == 1
        assert {(r["module"], r["va"]): r["status"] for r in report["results"]} == {
            ("SERVER", "0x1000"): "VERIFIED",
            ("LIB", "0x1000"): "DRIFT",
            ("SERVER", "0x2000"): "DRIFT",
        }

    def test_matching_symbols_verify(self, tmp_path: Path) -> None:
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(
            meta,
            'format = 2\n["SERVER.0x1000"]\nname = "g_a"\nsize = 4\nsection = ".data"\n',
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
            'format = 2\n["SERVER.0x1000"]\nname = "g_a"\nsize = 4\nsection = ".data"\n["SERVER.0x1010"]\nname = "g_b"\nsize = 4\nsection = ".data"\n',
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
            'format = 2\n["SERVER.0x1000"]\nname = "g_a"\nsize = 4\nsection = ".data"\n',
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
        write_store_fixture(
            meta,
            'format = 2\n["SERVER.0x1000"]\nname = "g_c"\nsize = 2\nsection = ".rdata"\n',
            encoding="utf-8",
        )
        res = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"\x01\x02"},
            actual={0x1000: b"\xff\xff"},
            sizes={0x1000: 2},
            sections=(".data",),
        )
        assert res["matched"] == 0
        assert res["mismatched"] == []
        assert res["missing"] == []
        assert (res["compared"], res["total"]) == (0, 1)

    def test_unsectioned_symbol_skipped(self, tmp_path: Path) -> None:
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        write_store_fixture(
            meta, 'format = 2\n["SERVER.0x1000"]\nname = "g_x"\nsize = 2\n', encoding="utf-8"
        )
        res = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: b"\x01\x02"},
            actual={0x1000: b"\x01\x02"},
            sizes={0x1000: 2},
        )
        assert res["matched"] == 0
        assert res["mismatched"] == []
        assert res["missing"] == []
        assert (res["compared"], res["total"]) == (0, 1)


class TestSectionSymbolBytesBounds:
    def test_alias_read_keeps_the_largest_extent(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.data_verify import section_symbol_bytes

        self._fake_info(monkeypatch, size=16, raw_size=16, data=b"abcdefghijklmnop")
        meta = tmp_path / "rebrew-data.toml"
        _write(
            meta,
            'format = 2\n["SERVER.0x1000"]\nname = "long"\nsize = 8\nsection = ".data"\n["LIB.0x1000"]\nname = "short"\nsize = 2\nsection = ".data"\n',
        )
        by_va, sizes = section_symbol_bytes(metadata_path=meta, binary_path=tmp_path / "ref.dll")
        assert sizes[0x1000] == 8
        assert by_va[0x1000] == b"abcdefgh"

    """Reads clamp to the owning section's mapped extent; an oversized
    SIZE is an error, not a silent cross-section read."""

    def _meta(self, tmp_path: Path, size: int, va: int = 0x1000) -> Path:
        meta = tmp_path / "rebrew-data.toml"
        write_store_fixture(
            meta,
            f'format = 2\n["SERVER.{va:#x}"]\nname = "g_a"\nsize = {size}\nsection = ".data"\n',
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
        monkeypatch.setattr("rebrew.formats.binary_loader.load_binary", lambda _p: info)
        return info

    def test_in_extent_reads_section_bytes(
        self,
        tmp_path: Path,
        monkeypatch,
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
        monkeypatch,
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
        monkeypatch,
    ) -> None:
        import pytest

        pytest.importorskip("lief")
        from rebrew.data_verify import section_symbol_bytes

        # Inside the mapped extent but past raw_size: the loader supplies
        # zeros, and that is what the compare sees.
        self._fake_info(monkeypatch, size=0x20, raw_size=0x10, data=bytes(range(0x10)))
        zero_fill: set[int] = set()
        by_va, sizes = section_symbol_bytes(
            metadata_path=self._meta(tmp_path, 4, va=0x1010),
            binary_path=tmp_path / "x.dll",
            zero_fill=zero_fill,
        )
        assert by_va[0x1010] == b"\x00\x00\x00\x00"
        assert sizes[0x1010] == 4
        assert zero_fill == {0x1010}

    def test_bss_symbol_past_short_virtual_size_is_skipped(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        import pytest

        pytest.importorskip("lief")
        from rebrew.data_verify import section_symbol_bytes

        # Declared size runs past a built image whose VirtualSize is shorter
        # than the reference. The symbol starts in the zero-fill tail, so
        # there are still no file bytes to read and no overrun to report.
        self._fake_info(monkeypatch, size=0x18, raw_size=0x10, data=bytes(range(0x10)))
        by_va, sizes = section_symbol_bytes(
            metadata_path=self._meta(tmp_path, 0x20, va=0x1010),
            binary_path=tmp_path / "x.dll",
        )
        assert by_va == {}
        assert sizes == {}

    def test_straddle_reads_file_prefix_plus_zeros(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        import pytest

        pytest.importorskip("lief")
        from rebrew.data_verify import section_symbol_bytes

        self._fake_info(monkeypatch, size=0x20, raw_size=0x10, data=bytes(range(0x10)))
        by_va, sizes = section_symbol_bytes(
            metadata_path=self._meta(tmp_path, 8, va=0x100C),
            binary_path=tmp_path / "x.dll",
        )
        assert by_va[0x100C] == bytes(range(0x0C, 0x10)) + b"\x00\x00\x00\x00"
        assert sizes[0x100C] == 8

    def test_bss_and_idata_use_the_section_that_holds_the_bytes(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        from types import SimpleNamespace

        import pytest

        pytest.importorskip("lief")
        from rebrew.data_verify import section_symbol_bytes

        info = SimpleNamespace(
            sections={
                ".data": SimpleNamespace(
                    name=".data", va=0x2000, size=0x20, raw_size=0x10, file_offset=0
                ),
                ".rdata": SimpleNamespace(
                    name=".rdata", va=0x1000, size=0x10, raw_size=0x10, file_offset=0x10
                ),
            },
            data=b"\x00" * 0x10 + b"\x11\x22\x33\x44" + b"\x00" * 12,
        )
        monkeypatch.setattr("rebrew.formats.binary_loader.load_binary", lambda _p: info)
        meta = tmp_path / "rebrew-data.toml"
        write_store_fixture(
            meta,
            'format = 2\n["SERVER.0x2010"]\nname = "g_bss"\nsize = 4\nsection = ".bss"\n["SERVER.0x1000"]\nname = "imp"\nsize = 4\nsection = ".idata"\n',
            encoding="utf-8",
        )
        by_va, sizes = section_symbol_bytes(metadata_path=meta, binary_path=tmp_path / "x.dll")
        assert by_va[0x2010] == b"\x00\x00\x00\x00"
        assert by_va[0x1000] == b"\x11\x22\x33\x44"
        assert sizes == {0x2010: 4, 0x1000: 4}


def test_size_falls_back_to_declared_type(tmp_path: Path, monkeypatch) -> None:
    """`size` is optional metadata; the declared type must size the symbol.

    guild-rebrew carries 310 data entries with ZERO `size` fields and 303
    `type` fields.  Skipping sizeless entries meant `rebrew verify --data`
    compared nothing at all and still printed "0 matched, 0 mismatched, 0
    missing" -- a pass that had verified nothing.
    """
    from types import SimpleNamespace

    from rebrew import data_verify

    meta = tmp_path / "rebrew-data.toml"
    _write(
        meta,
        'format = 2\n["SERVER.0x10001000"]\nname = "g_typed"\nsection = ".data"\ntype = "char[4]"\n["SERVER.0x10001004"]\nname = "g_sized"\nsection = ".data"\nsize = 4\n["SERVER.0x10001008"]\nname = "g_untyped"\nsection = ".data"\n',
    )

    sec = SimpleNamespace(name=".data", va=0x10001000, size=0x100, raw_size=0x100, file_offset=0)
    info = SimpleNamespace(sections={".data": sec}, data=bytes(range(16)) * 16)
    monkeypatch.setattr(data_verify, "load_binary", lambda _p: info, raising=False)
    monkeypatch.setattr("rebrew.formats.binary_loader.load_binary", lambda _p: info, raising=False)

    _by_va, sizes = data_verify.section_symbol_bytes(
        metadata_path=meta, binary_path=tmp_path / "fake.dll"
    )
    # typed and explicitly-sized symbols are both read; the one with neither is not
    assert sizes[0x10001000] == 4, "declared type must size the symbol"
    assert sizes[0x10001004] == 4
    assert 0x10001008 not in sizes


class TestUncoveredZeroFill:
    def test_unmapped_reference_storage_is_missing(self, tmp_path: Path, monkeypatch) -> None:
        from types import SimpleNamespace

        from rebrew.data_verify import section_symbol_bytes, verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(
            meta,
            'format = 2\n["SERVER.0x1040"]\nname = "inside"\nsize = 4\nsection = ".data"\n["SERVER.0x1100"]\nname = "outside"\nsize = 4\nsection = ".data"\n',
        )

        def image(path: Path):
            sec = SimpleNamespace(
                name=".data",
                va=0x1000,
                size=0x200 if path.name == "ref.dll" else 0x100,
                raw_size=0x20,
                file_offset=0,
            )
            return SimpleNamespace(sections={".data": sec}, data=bytes(0x20))

        monkeypatch.setattr("rebrew.formats.binary_loader.load_binary", image)
        ref, ref_sizes = section_symbol_bytes(metadata_path=meta, binary_path=tmp_path / "ref.dll")
        built, built_sizes = section_symbol_bytes(
            metadata_path=meta, binary_path=tmp_path / "built.dll"
        )
        assert 0x1100 not in built
        report = verify_data_bytes(
            metadata_path=meta, expected=ref, actual=built, sizes={**built_sizes, **ref_sizes}
        )
        assert report["matched"] == 1
        assert report["missing"] == ["outside"]


class TestPlacement:
    """Bytes at the reference VA cannot see a symbol the link put elsewhere.

    Regression for the guild-rebrew BSS case: every zero-filled symbol compared
    equal to the reference while the link map placed them 0x13ac bytes late.
    """

    META = 'format = 2\n["SERVER.0x1000"]\nname = "g_init"\nsize = 4\nsection = ".data"\n["SERVER.0x2000"]\nname = "g_zero"\nsize = 4\nsection = ".bss"\n["SERVER.0x3000"]\nname = "g_unmapped"\nsize = 4\nsection = ".data"\n'

    def _run(self, tmp_path: Path, built_symbols: dict[str, int] | None) -> dict:
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(meta, self.META)
        same = {0x1000: b"\x01\x02\x03\x04", 0x2000: bytes(4), 0x3000: b"\x05\x06\x07\x08"}
        return verify_data_bytes(
            metadata_path=meta,
            expected=same,
            actual=dict(same),
            sizes={0x1000: 4, 0x2000: 4, 0x3000: 4},
            built_symbols=built_symbols,
        )

    def test_without_a_map_bytes_alone_give_verified(self, tmp_path: Path) -> None:
        res = self._run(tmp_path, None)
        assert {r["name"]: r["status"] for r in res["results"]} == {
            "g_init": "VERIFIED",
            "g_zero": "VERIFIED",
            "g_unmapped": "VERIFIED",
        }
        assert (res["exact"], res["displaced"], res["unplaced"]) == (0, [], 0)

    def test_map_separates_exact_displaced_and_unplaced(self, tmp_path: Path) -> None:
        res = self._run(tmp_path, {"_g_init": 0x1000, "_g_zero": 0x33AC})
        rows = {r["name"]: r for r in res["results"]}
        assert rows["g_init"]["status"] == "EXACT"
        assert rows["g_zero"]["status"] == "DISPLACED"
        assert (rows["g_zero"]["built_va"], rows["g_zero"]["delta"]) == ("0x33ac", 0x13AC)
        assert rows["g_unmapped"]["status"] == "VERIFIED"
        assert res["exact"] == 1
        assert [d["name"] for d in res["displaced"]] == ["g_zero"]
        assert res["unplaced"] == 1
        assert res["matched"] == 3

    def test_recorded_link_symbol_wins_over_the_cdecl_name(self, tmp_path: Path) -> None:
        from rebrew.data_verify import verify_data_bytes

        meta = tmp_path / "rebrew-data.toml"
        _write(
            meta,
            'format = 2\n["SERVER.0x1000"]\nname = "argc"\nlink_symbol = "___argc"\nsize = 4\nsection = ".data"\n',
        )
        res = verify_data_bytes(
            metadata_path=meta,
            expected={0x1000: bytes(4)},
            actual={0x1000: bytes(4)},
            sizes={0x1000: 4},
            built_symbols={"_argc": 0x9000, "___argc": 0x1000},
        )
        assert res["results"][0]["status"] == "EXACT"

    def test_link_map_symbols_skips_functions_and_imports(self) -> None:
        from rebrew.data_verify import link_map_symbols

        text = (
            "  Address         Publics by Value              Rva+Base     Lib:Object\n"
            " 0001:00000000       _gm_Open                   10001000 f   spiel.obj\n"
            " 0002:0000012c       __imp__FlushFileBuffers@4  1002412c     KERNEL32:KERNEL32.dll\n"
            " 0003:00000010       _g_zero                    10003010     bss_late:bss_late.obj\n"
            " 0003:00000014       _g_common                  10003014     <common>\n"
            " 0003:00000018       _g_zero                    10003018     other.obj\n"
        )
        assert link_map_symbols(text) == {"_g_zero": 0x10003010, "_g_common": 0x10003014}
