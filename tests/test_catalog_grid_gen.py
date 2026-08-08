"""Tests for catalog/grid.generate_data_json — absorption, gap classification, cells."""

import struct
from pathlib import Path
from types import SimpleNamespace

from rebrew.annotation import Annotation
from rebrew.catalog.grid import generate_data_json

TEXT_VA = 0x1000
TEXT_SIZE = 0x3000


def _blob() -> bytearray:
    """Synthetic .text: functions, jump table, back-jump stub, thunk, label regions.

    Blob offsets are section-relative (VA - TEXT_VA); file_offset of .text is 0.
    """
    blob = bytearray(b"\xcc" * TEXT_SIZE)

    def put(va: int, data: bytes) -> None:
        blob[va - TEXT_VA : va - TEXT_VA + len(data)] = data

    # fn_a at 0x1000, size 0x40 (ends 0x1040)
    put(0x1000, b"\x55\x8b\xec\x83\xec\x10\x5d\xc3")
    # jump table 0x1040-0x1060 (8 pointers into .text) → absorbed into fn_a
    put(
        0x1040,
        b"".join(
            struct.pack("<I", v)
            for v in (0x1005, 0x100A, 0x100F, 0x1014, 0x1019, 0x101E, 0x1023, 0x1028)
        ),
    )
    # fn_b at 0x1060, size 0x20 (ends 0x1080)
    put(0x1060, b"\x55\x8b\xec\x5d\xc3")
    # back-jump gap 0x1080-0x1090: short jmp back into fn_b → absorbed
    put(0x1080, b"\xeb\xe0" + b"\x01" * 14)
    # fn_c at 0x1090, size 0x20 (ends 0x10B0)
    put(0x1090, b"\x55\x8b\xec\x5d\xc3")
    # thunk region 0x10B0-0x1120 (0x70 bytes, not pointer-like) → NOT absorbed
    blob[0x10B0 - TEXT_VA : 0x1120 - TEXT_VA] = b"\x00" * 0x70
    # fn_d at 0x1120, size 0x20 (ends 0x1140)
    put(0x1120, b"\x55\x8b\xec\x5d\xc3")
    # mid-gap label region 0x1400-0x1450 (non-padding, non-pointer) → NOT absorbed
    blob[0x1400 - TEXT_VA : 0x1450 - TEXT_VA] = bytes(range(1, 0x51))
    # fn_o at 0x1500, size 0x20 (ends 0x1520)
    put(0x1500, b"\x55\x8b\xec\x5d\xc3")
    # label region 0x1520-0x1530 right at fn_o's end → absorbed into fn_o
    blob[0x1520 - TEXT_VA : 0x1530 - TEXT_VA] = b"\x11" * 0x10
    # small non-code gap 0x1530-0x1540 → absorbed via the catch-all
    blob[0x1530 - TEXT_VA : 0x1540 - TEXT_VA] = b"\x01" * 0x10
    # fn_e at 0x1540, size 0x20
    put(0x1540, b"\x55\x8b\xec\x5d\xc3")
    return blob


def _ann(
    va: int,
    name: str,
    status: str,
    size: int,
    marker_type: str = "FUNCTION",
) -> Annotation:
    return Annotation(
        va=va,
        name=name,
        symbol=f"_{name}",
        module="SERVER",
        status=status,
        size=size,
        cflags="/O2",
        marker_type=marker_type,
        filepath=f"src/SERVER/{name}.c",
    )


def _labels() -> dict:
    return {
        0x1400: SimpleNamespace(size=0x50, state="data", label="jpt_1400"),
        0x1520: SimpleNamespace(size=0x10, state="data", label="jpt_1520"),
    }


def _patch_binary(
    monkeypatch,
    blob: bytes,
    *,
    labels: dict | None = None,
    globals_dict: dict | None = None,
    sections_va: int = TEXT_VA,
    sections_size: int = TEXT_SIZE,
    load_binary_raises: bool = False,
) -> SimpleNamespace:
    """Monkeypatch binary/section/label loading so generate_data_json is hermetic.

    The grid now derives sections from a single load_binary() result, so the
    fake BinaryInfo carries the full section set that sections_from_info() maps
    back into the {va, size, fileOffset} dict.
    """
    info = SimpleNamespace(
        image_base=sections_va,
        text_raw_offset=0,
        data=blob,
        sections={
            ".text": SimpleNamespace(
                va=sections_va, size=sections_size, file_offset=0, raw_size=sections_size
            ),
            ".data": SimpleNamespace(
                va=0x5000, size=0x40, file_offset=sections_size, raw_size=0x40
            ),
            ".bss": SimpleNamespace(va=0x5040, size=0x1000, file_offset=0, raw_size=0x1000),
        },
    )
    if load_binary_raises:

        def _boom(*_a: object, **_k: object) -> object:
            raise OSError("bad binary")

        monkeypatch.setattr("rebrew.binary_loader.load_binary", _boom)
    else:
        monkeypatch.setattr("rebrew.binary_loader.load_binary", lambda p: info)
    monkeypatch.setattr(
        "rebrew.catalog.grid.load_ghidra_data_labels",
        lambda src: labels if labels is not None else {},
    )
    monkeypatch.setattr(
        "rebrew.catalog.grid.get_globals",
        lambda src, cfg=None: globals_dict if globals_dict is not None else {},
    )
    return info


class TestGenerateDataJsonGrid:
    def _entries(self) -> list[Annotation]:
        return [
            _ann(0x1000, "fn_a", "EXACT", 0x40),
            _ann(0x1060, "fn_b", "RELOC", 0x20),
            _ann(0x1090, "fn_c", "STUB", 0x20),
            _ann(0x1120, "fn_d", "NEAR_MATCHING", 0x20),
            _ann(0x1500, "fn_o", "STUB", 0x20),
            _ann(0x1540, "fn_e", "STUB", 0x20),
            _ann(0x1700, "fn_z", "STUB", 0),  # zero size → skipped
            _ann(0x2000, "g_global", "EXACT", 0, marker_type="GLOBAL"),
            _ann(0x9999, "fn_out", "STUB", 0x20),  # outside all sections
        ]

    def _registry(self) -> dict:
        return {
            0x1000: {"canonical_size": 0x40, "is_thunk": False},
            0x1060: {"canonical_size": 0x20, "is_thunk": False},
            0x1090: {"canonical_size": 0x20, "is_thunk": False},
            0x1120: {"canonical_size": 0x20, "is_thunk": False},
            0x10B0: {"canonical_size": 0x70, "is_thunk": True, "ghidra_name": "thunk_x"},
        }

    def _run(
        self,
        monkeypatch,
        tmp_path: Path,
        *,
        labels: dict | None = None,
        globals_dict: dict | None = None,
    ) -> dict:
        blob = _blob()
        bin_path = tmp_path / "fake.dll"
        bin_path.write_bytes(bytes(blob))
        _patch_binary(
            monkeypatch,
            bytes(blob),
            labels=labels if labels is not None else _labels(),
            globals_dict=globals_dict or {0x5000: {"name": "g_x"}},
        )
        return generate_data_json(
            self._entries(),
            [{"va": 0x1540, "size": 0x20}],
            text_size=TEXT_SIZE,
            bin_path=bin_path,
            registry=self._registry(),
            src_dir=tmp_path / "src",
            root_dir=tmp_path,
        )

    def test_absorption_and_summary(self, monkeypatch, tmp_path: Path) -> None:
        data = self._run(monkeypatch, tmp_path)
        fn = data["functions"]

        # fn_a absorbed the 0x20 jump table (0x40 → 0x60).
        assert fn["0x00001000"]["size"] == 0x60
        # fn_b absorbed the 0x10 back-jump stub (0x20 → 0x30).
        assert fn["0x00001060"]["size"] == 0x30
        # fn_o absorbed the 0x10 label region AND the 0x10 catch-all gap
        # (0x20 → 0x40), across two absorption rounds.
        assert fn["0x00001500"]["size"] == 0x40
        # fn_e (funcs_by_va fallback size) is untouched.
        assert fn["0x00001540"]["size"] == 0x20

        # Zero-size and GLOBAL entries are absent from the functions map.
        assert "0x00001700" not in fn
        assert "0x00002000" not in fn

    def test_global_outside_sections_warns(self, monkeypatch, tmp_path: Path, caplog) -> None:
        """A data global whose VA falls outside every section must be surfaced
        (R4): silently dropping it makes the catalog look complete while the
        global is missing from the coverage DB."""
        import logging

        blob = _blob()
        bin_path = tmp_path / "fake.dll"
        bin_path.write_bytes(bytes(blob))
        _patch_binary(
            monkeypatch,
            bytes(blob),
            globals_dict={
                0x5000: {"name": "g_in_data"},
                0x9999: {"name": "g_outside"},
            },
        )
        with caplog.at_level(logging.WARNING, logger="rebrew.catalog.grid"):
            generate_data_json(
                self._entries(),
                [{"va": 0x1540, "size": 0x20}],
                text_size=TEXT_SIZE,
                bin_path=bin_path,
                registry=self._registry(),
                src_dir=tmp_path / "src",
                root_dir=tmp_path,
            )
        assert any("outside every section" in r.message for r in caplog.records)
        assert any("0x00009999" in r.message for r in caplog.records)

    def test_status_counters(self, monkeypatch, tmp_path: Path) -> None:
        data = self._run(monkeypatch, tmp_path)
        fn = data["functions"]

        # Status counters: EXACT/RELOC/NEAR_MATCHING each 1, STUB = 5
        # (fn_c, fn_o, fn_e, fn_z, fn_out).
        s = data["summary"]
        assert s["totalFunctions"] == 8
        assert s["exactMatches"] == 1
        assert s["relocMatches"] == 1
        assert s["nearMatchCount"] == 1
        assert s["stubCount"] == 5
        assert s["matchedFunctions"] == 2  # exact + reloc; NEAR_MATCHING is not matched

        # Summary coverage is cell-based (functions + padding + data + thunks).
        # Function cells: fn_a 0x60 + fn_b 0x30 + fn_c 0x20 + fn_d 0x20 +
        # fn_o 0x40 + fn_e 0x20 = 0x130.
        assert s["coveredBytes"] == s["paddingBytes"] + s["dataBytes"] + s["thunkBytes"] + 0x130
        assert s["coveragePercent"] == round(s["coveredBytes"] / TEXT_SIZE * 100.0, 2)
        assert s["textSize"] == TEXT_SIZE

        # SHA-256 of each function body was computed from the blob.
        assert fn["0x00001000"]["sha256"] != ""
        # Out-of-section function falls back to image_base-relative offsets.
        out = fn["0x00009999"]
        assert out["fileOffset"] == 0x9999 - TEXT_VA

    def test_cells_classification(self, monkeypatch, tmp_path: Path) -> None:
        data = self._run(monkeypatch, tmp_path)
        text = data["sections"][".text"]
        cells = text["cells"]
        assert text["unitBytes"] == 64
        assert text["columns"] == 64

        by_state: dict[str, list] = {}
        for c in cells:
            by_state.setdefault(c["state"], []).append(c)

        # Thunk gap classified with label + parent function.
        thunk = by_state.get("thunk")
        assert thunk and thunk[0]["label"] == "thunk_x"
        assert thunk[0]["parent_function"] == "0x00001090"  # fn_c ends at thunk start
        # Data gap (Ghidra label) classified with label.
        data_cells = by_state.get("data")
        assert data_cells and data_cells[0]["label"] == "jpt_1400"
        # Padding gap classified.
        assert by_state.get("padding")

        # State counts: exact/reloc/stub/near_matching cells present.
        assert any(c["state"] == "exact" for c in cells)
        assert any(c["state"] == "reloc" for c in cells)
        assert any(c["state"] == "stub" for c in cells)
        assert any(c["state"] == "near_matching" for c in cells)

        # Byte accounting in the summary.
        s = data["summary"]
        assert s["thunkBytes"] == 0x70
        assert s["dataBytes"] == 0x50  # only the surviving mid-gap label
        assert s["paddingBytes"] > 0

    def test_cells_column_wrap(self, monkeypatch, tmp_path: Path) -> None:
        """The long padding tail spans more than 64 columns → row wrap."""
        data = self._run(monkeypatch, tmp_path)
        cells = data["sections"][".text"]["cells"]
        # Cells stay within one row's column budget; spans never exceed 64.
        assert all(c["span"] <= 64 for c in cells)
        # The padding tail alone is > 4096 bytes → spans 65+ columns total.
        padding_cells = [c for c in cells if c["state"] == "padding"]
        assert sum(c["end"] - c["start"] for c in padding_cells) > 64 * 64

    def test_bss_data_sections(self, monkeypatch, tmp_path: Path) -> None:
        data = self._run(monkeypatch, tmp_path)
        bss = data["sections"][".bss"]
        assert bss["unitBytes"] == 4096
        d = data["sections"][".data"]
        assert d["unitBytes"] == 16
        # The global at 0x5000 produced a cell in .data.
        data_cells = d["cells"]
        assert any(c["state"] == "exact" for c in data_cells)

    def test_original_dll_path(self, monkeypatch, tmp_path: Path) -> None:
        data = self._run(monkeypatch, tmp_path)
        assert data["paths"]["originalDll"] == "/fake.dll"

    def test_original_dll_path_fallback_name(self, monkeypatch, tmp_path: Path) -> None:
        blob = bytes(_blob())
        bin_path = tmp_path / "fake.dll"
        bin_path.write_bytes(blob)
        _patch_binary(monkeypatch, blob)
        # root_dir does NOT contain bin_path → falls back to the bare name.
        data = generate_data_json(
            self._entries(),
            [],
            text_size=TEXT_SIZE,
            bin_path=bin_path,
            registry=self._registry(),
            src_dir=tmp_path / "src",
            root_dir=tmp_path / "elsewhere",
        )
        assert data["paths"]["originalDll"] == "/fake.dll"

    def test_load_binary_failure_falls_back(self, monkeypatch, tmp_path: Path) -> None:
        """load_binary raising OSError → sections still fall back to .text."""
        blob = bytes(_blob())
        bin_path = tmp_path / "fake.dll"
        bin_path.write_bytes(blob)
        _patch_binary(monkeypatch, blob, load_binary_raises=True)
        data = generate_data_json([self._entries()[0]], [], text_size=TEXT_SIZE, bin_path=bin_path)
        text = data["sections"][".text"]
        assert text["size"] == TEXT_SIZE
        # No binary data → no hashes, no absorption.
        assert data["functions"]["0x00001000"]["sha256"] == ""

    def test_function_at_section_end(self, monkeypatch, tmp_path: Path) -> None:
        """A function whose end lands exactly on sec_size is skipped in absorption."""
        size = 0x100
        blob = bytearray(b"\xcc" * size)
        blob[0xE0:0xF0] = b"\x55\x8b\xec\x5d\xc3\xcc\xcc\xcc\xcc\xcc\xcc"
        bin_path = tmp_path / "end.dll"
        bin_path.write_bytes(bytes(blob))
        _patch_binary(monkeypatch, bytes(blob), sections_size=size)
        entries = [_ann(TEXT_VA + 0xE0, "fn_tail", "EXACT", 0x20)]
        data = generate_data_json(entries, [], text_size=size, bin_path=bin_path)
        fn = data["functions"][f"0x{TEXT_VA + 0xE0:08x}"]
        assert fn["size"] == 0x20


class TestGenerateDataJsonNoBinary:
    """Without a binary: fallback .text section, 'none' gap states, no hashes."""

    def test_no_binary_fallback_section(self) -> None:
        entries = [
            _ann(0x0, "fn_a", "EXACT", 0x40),
            _ann(0x40, "fn_b", "STUB", 0x20),
        ]
        data = generate_data_json(entries, [], text_size=0x200)
        text = data["sections"][".text"]
        assert text["va"] == 0
        assert text["size"] == 0x200
        # No binary → no function hashes.
        assert data["functions"]["0x00000000"]["sha256"] == ""
        # Gap between the two functions has no classification → state "none".
        states = {c["state"] for c in text["cells"]}
        assert "none" in states
        assert "exact" in states


class TestAbsorptionRegression:
    """Regression: an absorbed jump table must not re-absorb the next function."""

    def test_absorbed_gap_does_not_eat_next_function(self, monkeypatch, tmp_path: Path) -> None:
        # fn_a (0x0-0x40) + jump table (0x40-0x60) + fn_b (0x60-0x80, small).
        # Round 1 absorbs the table into fn_a → fn_a end == fn_b start.
        # Round 2 must NOT absorb fn_b's body (bisect_left semantics).
        size = 0x200
        blob = bytearray(b"\xcc" * size)
        blob[0:8] = b"\x55\x8b\xec\x5d\xc3\xcc\xcc\xcc"
        blob[0x40:0x60] = b"".join(
            struct.pack("<I", v)
            for v in (0x1005, 0x100A, 0x100F, 0x1014, 0x1019, 0x101E, 0x1023, 0x1028)
        )
        blob[0x60:0x68] = b"\x55\x8b\xec\x5d\xc3\xcc\xcc\xcc"
        bin_path = tmp_path / "reg.dll"
        bin_path.write_bytes(bytes(blob))
        _patch_binary(monkeypatch, bytes(blob), sections_va=0x1000, sections_size=size)
        entries = [
            _ann(0x1000, "fn_a", "EXACT", 0x40),
            _ann(0x1060, "fn_b", "STUB", 0x20),
        ]
        data = generate_data_json(entries, [], text_size=size, bin_path=bin_path)
        fn = data["functions"]
        assert fn["0x00001000"]["size"] == 0x60  # absorbed exactly the table
        assert fn["0x00001060"]["size"] == 0x20  # fn_b untouched


class TestSingleBinaryParse:
    """The grid derives sections and layout from ONE load_binary() call."""

    def test_exactly_one_parse(self, monkeypatch, tmp_path: Path) -> None:
        size = 0x40
        blob = bytes(_blob()[:size])
        bin_path = tmp_path / "once.dll"
        bin_path.write_bytes(blob)
        calls: dict[str, int] = {"n": 0}

        def _counting_load(_p: object) -> object:
            calls["n"] += 1
            return SimpleNamespace(
                image_base=0x1000,
                text_raw_offset=0,
                data=blob,
                sections={
                    ".text": SimpleNamespace(va=0x1000, size=size, file_offset=0, raw_size=size)
                },
            )

        monkeypatch.setattr("rebrew.binary_loader.load_binary", _counting_load)
        monkeypatch.setattr("rebrew.catalog.grid.load_ghidra_data_labels", lambda src: {})
        monkeypatch.setattr("rebrew.catalog.grid.get_globals", lambda src, cfg=None: {})
        entries = [_ann(TEXT_VA, "fn_a", "EXACT", 0x20)]
        data = generate_data_json(entries, [], text_size=size, bin_path=bin_path)
        assert calls["n"] == 1
        assert data["sections"][".text"]["size"] == size

    def test_missing_binary_never_parses(self, monkeypatch, tmp_path: Path) -> None:
        calls: dict[str, int] = {"n": 0}
        monkeypatch.setattr(
            "rebrew.binary_loader.load_binary",
            lambda p: calls.__setitem__("n", calls["n"] + 1),
        )
        monkeypatch.setattr("rebrew.catalog.grid.load_ghidra_data_labels", lambda src: {})
        monkeypatch.setattr("rebrew.catalog.grid.get_globals", lambda src, cfg=None: {})
        entries = [_ann(TEXT_VA, "fn_a", "EXACT", 0x20)]
        generate_data_json(entries, [], text_size=0x40, bin_path=tmp_path / "nope.dll")
        assert calls["n"] == 0


class TestUnannotatedBoundaries:
    """Unannotated registry functions must bound absorption.

    A function in the registry (e.g. from the disassembler's function list)
    that has no .c annotation yet must NOT have its bytes absorbed into the
    preceding annotated function — otherwise the coverage DB inflates the
    predecessor and hides a real, un-reversed function.
    """

    def test_unannotated_function_not_absorbed(self, monkeypatch, tmp_path: Path) -> None:
        from rebrew.catalog.registry import RegistryEntry

        size = 0x100
        blob = bytearray(b"\xcc" * size)
        # fn_a (annotated, 0x0-0x40) | fcn_mid (unannotated, 0x40-0x60) | fn_b (annotated, 0x60-0x80)
        blob[0x00:0x08] = b"\x55\x8b\xec\x5d\xc3\xcc\xcc\xcc"
        blob[0x40:0x48] = b"\x55\x8b\xec\x5d\xc3\xcc\xcc\xcc"
        blob[0x60:0x68] = b"\x55\x8b\xec\x5d\xc3\xcc\xcc\xcc"
        bin_path = tmp_path / "reg.dll"
        bin_path.write_bytes(bytes(blob))
        _patch_binary(monkeypatch, bytes(blob), sections_va=0x1000, sections_size=size)

        registry: dict[int, RegistryEntry] = {
            0x1000: {
                "detected_by": ["list"],
                "size_by_tool": {"list": 0x40},
                "list_name": "fn_a",
                "ghidra_name": "",
                "is_thunk": False,
                "is_export": False,
                "canonical_size": 0x40,
                "size_reason": "list (only source)",
            },
            0x1040: {
                "detected_by": ["list"],
                "size_by_tool": {"list": 0x20},
                "list_name": "fcn.10001040",
                "ghidra_name": "",
                "is_thunk": False,
                "is_export": False,
                "canonical_size": 0x20,
                "size_reason": "list (only source)",
            },
            0x1060: {
                "detected_by": ["list"],
                "size_by_tool": {"list": 0x20},
                "list_name": "fn_b",
                "ghidra_name": "",
                "is_thunk": False,
                "is_export": False,
                "canonical_size": 0x20,
                "size_reason": "list (only source)",
            },
        }
        entries = [
            _ann(0x1000, "fn_a", "EXACT", 0x40),
            _ann(0x1060, "fn_b", "STUB", 0x20),
        ]
        data = generate_data_json(entries, [], text_size=size, bin_path=bin_path, registry=registry)
        fn = data["functions"]
        # fn_a must stay 0x40 — the 0x40-0x60 unannotated function is a boundary.
        assert fn["0x00001000"]["size"] == 0x40
        assert fn["0x00001060"]["size"] == 0x20
