"""Regression tests for the archive and OMF16 parse speedups and their benchmark inputs."""

from __future__ import annotations

import random
import struct
from pathlib import Path

from rebrew.formats.archives import parse_archive
from rebrew.formats.omf16 import Omf16Module, parse_obj_omf16, parse_omf16
from tools import bench_perf10_formats as bench


def _record(rtype: int, body: bytes) -> bytes:
    raw = bytes([rtype]) + struct.pack("<H", len(body) + 1) + body
    return raw + bytes([-sum(raw) & 0xFF])


def _ledata(offset: int, chunk: bytes) -> bytes:
    return _record(0xA0, b"\x01" + struct.pack("<H", offset) + chunk)


class TestBenchInputs:
    def test_archive_fixture_round_trips(self, tmp_path: Path) -> None:
        data, expected = bench._build_archive(random.Random(bench._SEED))
        lib = tmp_path / "bench.lib"
        lib.write_bytes(data)
        got = list(parse_archive(str(lib)))
        assert got == expected
        assert len(got) == bench._AR_MEMBERS
        assert any(len(body) % 2 for _, body in got)
        assert any(name.startswith("long_") for name, _ in got)

    def test_omf16_fixtures_report_exact_relocs(self, tmp_path: Path) -> None:
        rng = random.Random(bench._SEED)
        funcs = [bench._function(rng) for _ in range(40)]
        for build, tag in ((bench._build_unoptimized, "u"), (bench._build_optimized, "o")):
            data, expected = build(funcs)
            obj = tmp_path / f"{tag}.obj"
            obj.write_bytes(data)
            assert len(expected) == len(funcs)
            for name, want in expected.items():
                assert want[1]
                assert parse_obj_omf16(obj, name) == want

    def test_omf16_absent_symbol_is_none(self, tmp_path: Path) -> None:
        data, _ = bench._build_unoptimized([bench._function(random.Random(1))])
        obj = tmp_path / "u.obj"
        obj.write_bytes(data)
        assert parse_obj_omf16(obj, "_absent") == (None, {})


class TestArchiveHeaders:
    def _archive(self, *members: tuple[bytes, bytes], size_override: bytes | None = None) -> bytes:
        out = bytearray(b"!<arch>\n")
        for name, body in members:
            if len(out) % 2:
                out.append(0x0A)
            size = size_override or str(len(body)).encode()
            out += bench._ar_header(name, 0)[:48] + size.ljust(10) + b"`\n" + body
        return bytes(out)

    def test_odd_bodies_are_padded_and_names_trimmed(self, tmp_path: Path) -> None:
        lib = tmp_path / "a.lib"
        lib.write_bytes(self._archive((b"a.o/", b"abc"), (b"b.o/", b"defg")))
        assert list(parse_archive(str(lib))) == [("a.o", b"abc"), ("b.o", b"defg")]

    def test_non_numeric_size_stops_iteration(self, tmp_path: Path) -> None:
        lib = tmp_path / "a.lib"
        lib.write_bytes(
            self._archive((b"a.o/", b"abcd"))
            + self._archive((b"b.o/", b"x"), size_override=b"zz")[8:]
        )
        assert list(parse_archive(str(lib))) == [("a.o", b"abcd")]

    def test_truncated_trailing_header_is_ignored(self, tmp_path: Path) -> None:
        lib = tmp_path / "a.lib"
        lib.write_bytes(self._archive((b"a.o/", b"abcd")) + b"b.o/" + b" " * 20)
        assert list(parse_archive(str(lib))) == [("a.o", b"abcd")]


class TestOmf16Code:
    def test_ledata_gap_is_zero_filled_and_overlap_overwrites(self) -> None:
        data = (
            _ledata(0, b"\x01\x02\x03\x04") + _ledata(6, b"\x09\x09") + _ledata(2, b"\xaa\xbb\xcc")
        )
        mod = parse_omf16(data)
        assert isinstance(mod, Omf16Module)
        assert mod.code == b"\x01\x02\xaa\xbb\xcc\x00\x09\x09"

    def test_ledata_checksum_byte_is_dropped_for_tcc_records(self) -> None:
        # TCC/wcc16 records sum to 0 mod 256 including the trailing checksum byte.
        body = b"\x01" + struct.pack("<H", 0) + b"\x10\x20\x30"
        header = bytes([0xA0]) + struct.pack("<H", len(body) + 1)
        checksum = -(sum(header) + sum(body)) & 0xFF
        mod = parse_omf16(header + body + bytes([checksum]))
        assert mod.code == b"\x10\x20\x30"

    def test_c2_records_follow_ledata_and_publics_keep_printable_names(self) -> None:
        pub = (
            bytes([3])
            + b"_ab"
            + struct.pack("<H", 1)
            + bytes([2])
            + b"\x01\x02"
            + struct.pack("<H", 0)
        )
        data = _ledata(0, b"\x90\x91") + _record(0x90, pub)
        mod = parse_omf16(data)
        assert mod.publics == {"_ab": 1}
        c2 = _record(0xC2, b"\x00" * 9 + b"\xc3\xc3")
        assert parse_omf16(data + c2).code == b"\x90\x91\xc3\xc3"

    def test_name_lists_skip_non_printable_names(self) -> None:
        names = bytes([2]) + b"ok" + bytes([2]) + b"\x01\x02" + bytes([3]) + b"a b"
        mod = parse_omf16(_record(0x96, names) + _record(0xC2, b"\x00" * 9 + b"\xc3\xc3"))
        assert mod.names == ["ok", "a b"]


class TestOmf16Threads:
    def test_concurrent_lookups_match_serial(self, tmp_path: Path) -> None:
        from concurrent.futures import ThreadPoolExecutor

        rng = random.Random(bench._SEED)
        funcs = [bench._function(rng) for _ in range(60)]
        data, expected = bench._build_optimized(funcs)
        obj = tmp_path / "o.obj"
        obj.write_bytes(data)
        names = list(expected) * 8
        with ThreadPoolExecutor(max_workers=8) as pool:
            got = list(pool.map(lambda n: parse_obj_omf16(obj, n), names))
        assert got == [expected[n] for n in names]
