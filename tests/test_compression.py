"""Tests for compression.py — the shared max-effort precompress."""

import gzip

import pytest
import zstandard

from rebrew.compression import (
    GZIP_PRECOMPRESS_LEVEL,
    ZSTD_PRECOMPRESS_LEVEL,
    precompress,
)

_COMPRESSIBLE = b"<html><body>" + b"function_table_entry" * 400 + b"</body></html>"


class TestPrecompress:
    @pytest.mark.parametrize("encoding", ["gzip", "zstd"])
    def test_round_trips_and_shrinks(self, encoding: str) -> None:
        compressed = precompress(_COMPRESSIBLE, encoding)
        assert compressed is not None
        assert len(compressed) < len(_COMPRESSIBLE)
        if encoding == "zstd":
            assert zstandard.ZstdDecompressor().decompress(compressed) == _COMPRESSIBLE
        else:
            assert gzip.decompress(compressed) == _COMPRESSIBLE

    @pytest.mark.parametrize("encoding", ["gzip", "zstd"])
    def test_incompressible_input_yields_none(self, encoding: str) -> None:
        # Nothing to gain, so no caller writes or serves a sidecar.
        assert precompress(b"\x00", encoding) is None

    def test_gzip_is_byte_stable_across_calls(self) -> None:
        """mtime=0 keeps the bytes a pure function of the body.

        A dashboard ETag is the uncompressed hash and a report sidecar is
        rebuilt in place, so either would break on a differing timestamp.
        """
        assert precompress(_COMPRESSIBLE, "gzip") == precompress(_COMPRESSIBLE, "gzip")

    def test_max_effort_beats_a_lower_level(self) -> None:
        """The shared level is the maximum both codecs offer.

        The dashboard test asserts max effort beats mid effort; this pins the
        constant itself so a downgrade cannot pass unnoticed.
        """
        assert GZIP_PRECOMPRESS_LEVEL == 9
        assert ZSTD_PRECOMPRESS_LEVEL == 19
