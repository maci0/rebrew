"""Atheris (libFuzzer) target: BinSync serial loader.

Same harness body and invariants as tests/test_property_binsync_serial.py
(Hypothesis drives it in CI; this file is the coverage-guided libFuzzer
entry point for local/OSSFuzz runs).

    uv run --frozen python tests/fuzz_binsync_serial.py <corpus_dir> [flags]
    uv run --frozen python tests/fuzz_binsync_serial.py tests/fixtures/binsync_serial -runs=1000

Seed corpus: tests/fixtures/binsync_serial/*.toml (one dumps() output
per artifact kind, per the review rule that seeds come from real
committed shapes, never production traffic).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris

from rebrew.binsync import serial

_KINDS = ("function", "struct", "enum", "typedef", "comment", "global_variable")


def TestOneInput(data: bytes) -> None:
    """Loader must never raise (except ValueError); parsed artifacts
    must round-trip dumps -> loads -> dumps to identical bytes."""
    fd, name = tempfile.mkstemp(suffix=".toml")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        for kind in _KINDS:
            for many in (False, True):
                try:
                    if many:
                        arts = serial.load_many(Path(name), kind)
                    else:
                        art = serial.load_artifact(Path(name), kind)
                        arts = [] if art is None else [art]
                except ValueError:
                    continue
                assert isinstance(arts, list)
                for art in arts:
                    text = art.dumps()
                    assert isinstance(text, str)
                    assert type(art).loads(text).dumps() == text
    finally:
        os.unlink(name)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
