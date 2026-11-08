"""Property-based fuzz tests for the coverage input contract validators.

``rebrew.coverage_input_contract.canonical_coverage_input`` and
``canonical_verification_records`` are the trust-boundary codecs for the
retained coverage path: both take untrusted Python values decoded from an
ops request body (``ReportRequest.coverage_input`` /
``verification_records`` via ``ops.parse_request``) and must fail only with
``CoverageInputError`` — never ``TypeError``, ``KeyError``,
``UnicodeEncodeError``, or a bare ``struct``/``hashlib`` error — and any
accepted value must re-canonicalise byte-identically (pair assertion across
the digest boundary: ``coverage_input_digest`` of a canonical payload must
equal the payload's own digest, and re-decoding canonical bytes must
reproduce them).

The contract tests in ``test_coverage_input_contract.py`` pin a handful of
hand-picked vectors; this harness fuzzes the full input space: arbitrary
JSON values, structure-aware envelopes/records built from the valid
``contract()`` shape with mutated fields, and raw bytes through the
canonical-bytes → decode → re-canonicalise round-trip.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.coverage_input_contract import (
    CoverageInputError,
    canonical_coverage_input,
    canonical_verification_records,
    coverage_input_digest,
    verification_records_digest,
)

_MAX_EXAMPLES = 150

_JSON_SCALAR = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=True, allow_infinity=True)
    | st.text(max_size=24)
)
_JSON_VALUE = st.recursive(
    _JSON_SCALAR,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(max_size=8), children, max_size=3),
    ),
    max_leaves=12,
)


def _valid_envelope() -> dict[str, Any]:
    return {
        "version": 1,
        "analysis_manifest": "d" * 64,
        "verification_digest": hashlib.sha256(b"[]").hexdigest(),
        "source_revision": "a" * 64,
        "generation": "c" * 32,
        "binary_sha256": "b" * 64,
        "target": "target",
        "readset": [
            {
                "path": "src/a.c",
                "present": True,
                "origin": "source",
                "digest": hashlib.sha256(b"source").hexdigest(),
                "size": 6,
            }
        ],
    }


def _valid_record() -> dict[str, Any]:
    return {
        "verification_id": "v",
        "source": "src/add.c",
        "source_sha256": "a" * 64,
        "va": 0x401120,
        "size": 4,
        "status": "SIZE_MISMATCH",
        "match_count": 0,
        "total": 5,
        "obj_size": 5,
        "reloc_count": 0,
        "result_digest": "b" * 64,
    }


@st.composite
def _mutated_envelope(draw: st.DrawFn) -> Any:
    """A valid envelope with 1-4 fields replaced by arbitrary JSON values."""
    envelope = _valid_envelope()
    keys = draw(st.lists(st.sampled_from(list(envelope)), min_size=1, max_size=4, unique=True))
    for key in keys:
        envelope[key] = draw(_JSON_VALUE)
    return envelope


@st.composite
def _mutated_records(draw: st.DrawFn) -> Any:
    """A list of 0-3 valid records with random fields replaced."""
    count = draw(st.integers(min_value=0, max_value=3))
    records = []
    for _ in range(count):
        record = _valid_record()
        if draw(st.booleans()):
            keys = draw(
                st.lists(st.sampled_from(list(record)), min_size=1, max_size=3, unique=True)
            )
            for key in keys:
                record[key] = draw(_JSON_VALUE)
        records.append(record)
    return records


class TestCanonicalEnvelopeNeverCrashes:
    @given(_JSON_VALUE)
    @settings(max_examples=_MAX_EXAMPLES)
    def test_arbitrary_value_only_raises_coverage_error(self, raw: Any) -> None:
        try:
            canonical = canonical_coverage_input(raw)
        except CoverageInputError:
            return
        # Accepted values are canonical: re-decoding them reproduces them.
        assert isinstance(canonical, bytes)
        assert canonical_coverage_input(json.loads(canonical)) == canonical
        assert coverage_input_digest(json.loads(canonical)) == hashlib.sha256(canonical).hexdigest()

    @given(_mutated_envelope())
    @settings(max_examples=_MAX_EXAMPLES)
    def test_mutated_envelope_only_raises_coverage_error(self, raw: Any) -> None:
        try:
            canonical = canonical_coverage_input(raw)
        except CoverageInputError:
            return
        assert canonical_coverage_input(json.loads(canonical)) == canonical
        # Re-canonicalisation is idempotent across the digest boundary.
        assert coverage_input_digest(json.loads(canonical)) == hashlib.sha256(canonical).hexdigest()

    @given(st.binary(max_size=512))
    @settings(max_examples=_MAX_EXAMPLES)
    def test_raw_bytes_only_raise_coverage_error(self, raw: bytes) -> None:
        try:
            value = json.loads(raw)
        except ValueError:
            return
        try:
            canonical_coverage_input(value)
        except CoverageInputError:
            return


class TestCanonicalRecordsNeverCrashes:
    @given(_JSON_VALUE)
    @settings(max_examples=_MAX_EXAMPLES)
    def test_arbitrary_value_only_raises_coverage_error(self, raw: Any) -> None:
        try:
            canonical = canonical_verification_records(raw)
        except CoverageInputError:
            return
        assert isinstance(canonical, bytes)
        assert canonical_verification_records(json.loads(canonical)) == canonical
        assert verification_records_digest(json.loads(canonical)) == hashlib.sha256(canonical).hexdigest()

    @given(_mutated_records())
    @settings(max_examples=_MAX_EXAMPLES)
    def test_mutated_records_only_raise_coverage_error(self, raw: Any) -> None:
        try:
            canonical = canonical_verification_records(raw)
        except CoverageInputError:
            return
        assert canonical_verification_records(json.loads(canonical)) == canonical
        assert verification_records_digest(json.loads(canonical)) == hashlib.sha256(canonical).hexdigest()


class TestCanonicalInvariants:
    @given(st.sampled_from(["a" * 64, "b" * 64, "x", "", "A" * 64]))
    @settings(max_examples=50)
    def test_sha_fields_must_be_lowercase_hex64(self, digest: str) -> None:
        envelope = _valid_envelope()
        envelope["source_revision"] = digest
        try:
            canonical_coverage_input(envelope)
        except CoverageInputError:
            return
        assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)

    @given(
        st.integers(min_value=-(2**63), max_value=2**63),
        st.integers(min_value=-(2**63), max_value=2**63),
    )
    @settings(max_examples=100)
    def test_record_counts_must_be_consistent(self, size: int, obj_size: int) -> None:
        record = _valid_record()
        record["size"] = size
        record["obj_size"] = obj_size
        record["total"] = max(size, obj_size) if size > 0 else 0
        record["match_count"] = 0
        try:
            canonical_verification_records([record])
        except CoverageInputError:
            return
        # Accepted: counts obey the documented status arithmetic.
        assert record["total"] == max(record["size"], record["obj_size"])
        assert record["match_count"] <= min(record["size"], record["obj_size"])

    def test_valid_envelope_roundtrip(self) -> None:
        envelope = _valid_envelope()
        canonical = canonical_coverage_input(envelope)
        assert canonical_coverage_input(json.loads(canonical)) == canonical

    def test_valid_records_roundtrip(self) -> None:
        records = [_valid_record()]
        canonical = canonical_verification_records(records)
        assert canonical_verification_records(json.loads(canonical)) == canonical


class TestNamedSnapshotManifestTypes:
    """Non-str manifests must be refused with OpsError (400), never AttributeError."""

    def test_non_string_manifests_refused(self) -> None:
        from types import SimpleNamespace

        import pytest

        from rebrew import ops
        from rebrew.named_snapshot import _capture_files, _validate_manifest

        def fake_req(**kw: Any) -> Any:
            base: dict[str, Any] = {
                "source_manifest": "{}",
                "source_snapshot_sha256": "a" * 64,
                "files": [],
                "analysis_manifest": "{}",
                "analysis_manifest_sha256": "a" * 64,
                "sha256": "a" * 64,
                "rebrew_target": "t",
                "generation": "a" * 32,
                "analysis_files": [],
                "attested_registry_digest": "",
            }
            base.update(kw)
            return SimpleNamespace(**base)

        for bad in (123, None, True, b"{}", ["{}"], {"a": 1}):
            with pytest.raises(ops.OpsError):
                _validate_manifest(fake_req(source_manifest=bad))
            with pytest.raises(ops.OpsError):
                _capture_files(None, fake_req(analysis_manifest=bad))
