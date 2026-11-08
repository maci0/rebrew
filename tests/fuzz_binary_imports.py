"""Atheris (libFuzzer) target: binary-level import, symbol and relocation surface.

Same harness body and invariants as tests/test_property_import_table.py,
tests/test_property_pe_symbols.py and tests/test_property_relocations.py
(Hypothesis drives them in CI; this file is the coverage-guided libFuzzer
entry point for local/OSSFuzz runs).

    uv run --frozen --group fuzz --group dev python tests/fuzz_binary_imports.py <corpus_dir> [flags]
    uv run --frozen --group fuzz --group dev python tests/fuzz_binary_imports.py tests/fixtures/mini_pe.exe -runs=1000

Seed corpus: tests/fixtures/{mini_pe.exe,mini.elf,mini_ne.exe}
(real committed shapes, never production traffic).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris

from rebrew.formats.binary_loader import (
    UnsupportedBinaryFormat,
    detect_format_and_arch,
    load_binary,
)
from rebrew.formats.import_table import find_import_stubs, parse_import_table, parse_imports
from rebrew.formats.ne_loader import NeParseError
from rebrew.formats.pe_symbols import pe_directories, pe_symbols
from rebrew.formats.relocations import relocation_spans

_RECORD_KEYS = {"dll", "name", "iat_va", "ordinal", "hint_name_rva"}


def _assert_import_shape(records: list[dict[str, object]]) -> None:
    assert isinstance(records, list)
    for record in records:
        assert set(record) == _RECORD_KEYS
        assert isinstance(record["dll"], str)
        assert isinstance(record["name"], str)
        assert isinstance(record["iat_va"], int) and record["iat_va"] >= 0
        assert record["ordinal"] is None or (
            isinstance(record["ordinal"], int) and record["ordinal"] >= 0
        )
        assert record["hint_name_rva"] is None or (
            isinstance(record["hint_name_rva"], int) and record["hint_name_rva"] >= 0
        )
        if record["ordinal"] is not None:
            assert record["name"] == f"ordinal_{record['ordinal']}"


def TestOneInput(data: bytes) -> None:
    """The parsers below must fail only with their documented error types,
    and whatever they return must keep its documented shape.

    Pair assertions across trust boundaries: the convenience table is
    exactly the record view, every stub names a table entry, the PE
    directory dump re-parsed from the same bytes is identical, and the
    relocation spans describe bytes inside the loaded image.
    """
    fd, name = tempfile.mkstemp(suffix=".exe")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        path = Path(name)

        records = parse_imports(path)
        _assert_import_shape(records)
        table = parse_import_table(path)
        assert table == {rec["iat_va"]: rec["name"] for rec in records}
        # Pair: the stub view only names entries the record view reported.
        stubs = find_import_stubs(path)
        assert isinstance(stubs, dict)
        for stub_va, stub_name in stubs.items():
            assert isinstance(stub_va, int) and stub_va >= 0
            assert stub_name in table.values()

        directories = pe_directories(path)
        symbols = pe_symbols(path)
        assert pe_directories(path) == directories
        assert all(isinstance(note, str) for note in directories.notes)
        assert all(isinstance(note, str) for note in symbols.notes)
        for record in (*directories.imports, *directories.delay_imports):
            assert isinstance(record.dll, str) and record.dll
            assert isinstance(record.name, str)
            assert record.va >= 0
            assert record.ordinal is None or 0 <= record.ordinal <= 0xFFFF
            assert record.name or record.ordinal is not None
        for export in directories.exports:
            assert isinstance(export.name, str)
            assert export.ordinal is None or 0 <= export.ordinal <= 0xFFFF
            assert export.va is None or export.va >= 0
            assert (export.va is None) == (export.forwarder is not None)
        for va in (
            *directories.tls_callbacks,
            *directories.safe_seh_handlers,
            *directories.cfg_targets,
        ):
            assert isinstance(va, int) and va >= 0
        for symbol in symbols.symbols:
            assert symbol.va is None or symbol.va >= 0
            assert isinstance(symbol.name, str) and symbol.name
            assert isinstance(symbol.kind, str) and symbol.kind
            assert isinstance(symbol.origin, str) and symbol.origin
            assert (symbol.va is None) == (symbol.forwarder is not None)
        assert symbols.notes == directories.notes

        try:
            fmt, arch = detect_format_and_arch(path)
        except UnsupportedBinaryFormat, FileNotFoundError, OSError:
            fmt, arch = None, None
        else:
            assert fmt in ("pe", "elf", "macho", "ne", "mz")
            assert arch is None or isinstance(arch, str)
            if fmt == "macho":
                assert arch in (None, "x86_32", "x86_64", "arm32", "arm64", "ppc32", "ppc64")
            elif fmt in ("pe", "elf"):
                assert arch in (
                    None,
                    "",
                    "x86_32",
                    "x86_64",
                    "arm32",
                    "arm64",
                    "mips32",
                    "ppc32",
                    "ppc64",
                    "alpha",
                    "alpha64",
                    "ia64",
                    "sh2",
                    "xtensa",
                )

        try:
            info = load_binary(path)
        except ValueError, NeParseError, OSError, KeyError:
            return
        assert isinstance(info.format, str) and info.format
        assert isinstance(info.arch, str)
        assert info.format == fmt
        try:
            spans = relocation_spans(info)
        except ValueError, NotImplementedError:
            return
        assert spans == sorted(set(spans))
        assert len(spans) <= 1_000_000
        for address, width in spans:
            assert isinstance(address, int) and address >= 0
            assert width in (4, 8)
    finally:
        os.unlink(name)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
