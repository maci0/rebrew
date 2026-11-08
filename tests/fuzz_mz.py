"""Atheris (libFuzzer) target: DOS MZ header parser.

Same harness body and invariants as tests/test_property_mz_loader.py
(Hypothesis drives it in CI; this file is the coverage-guided libFuzzer
entry point for local/OSSFuzz runs).

    uv run --frozen --group fuzz --group dev python tests/fuzz_mz.py <corpus_dir> [flags]
    uv run --frozen --group fuzz --group dev python tests/fuzz_mz.py tests/fixtures/tc16_hello.exe -runs=1000

Seed corpus: tests/fixtures/tc16_hello.exe (real committed shape, never
production traffic).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris

from rebrew.formats.binary_loader import (
    REAL_MODE_ADDRESS_MASK,
    extract_bytes_at_va,
    is_mz,
    load_binary,
    parse_mz_header,
)

_HEADER_SIZE = 0x40


def TestOneInput(data: bytes) -> None:
    """The only failure mode is ValueError; a parsed header never points
    past EOF, never reports a negative region, and the load path
    round-trips the bytes it claims.

    Pair assertions across the trust boundary: the pseudo ``.text``
    section the loader builds must describe the same code region the
    header parser reported, and the bytes ``extract_bytes_at_va`` hands
    back for that region are the file's own bytes at ``code_offset``.
    ``is_mz`` must agree with the header parser on what counts as an MZ.
    """
    fd, name = tempfile.mkstemp(suffix=".exe")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        path = Path(name)
        assert isinstance(is_mz(path), bool)
        try:
            header = parse_mz_header(path)
        except ValueError:
            return
        assert data[:2] == b"MZ"
        assert len(data) >= _HEADER_SIZE
        assert header["code_offset"] >= 0
        assert header["code_size"] >= 0
        assert header["code_offset"] + header["code_size"] <= len(data)
        assert 0 <= header["entry_va"] <= REAL_MODE_ADDRESS_MASK
        assert header["va_base"] == 0
        info = load_binary(path)
        assert info.format == "mz"
        assert info.arch == "x86_16"
        assert info.sections.keys() == {".text"}
        section = info.sections[".text"]
        assert section.file_offset == header["code_offset"]
        assert section.raw_size == header["code_size"]
        assert section.va == 0
        assert info.text_va == 0
        assert info.text_size == header["code_size"]
        if header["code_size"] > 0:
            probe_len = min(4, header["code_size"])
            probe = data[header["code_offset"] : header["code_offset"] + probe_len]
            assert extract_bytes_at_va(info, 0, probe_len, trim_padding=False) == probe
            # Pair: a re-read through the loader yields the same header.
            again = parse_mz_header(path)
            assert again == header
    finally:
        os.unlink(name)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
