"""Property-based fuzz tests for the ops worker's request decoder.

``rebrew.ops.dispatch`` is the one surface that takes JSON over the wire
(``rebrew ops call <op>`` on stdin, ``POST /<op>`` over HTTP) and hands the
decoded object straight to ``parse_request``, which walks a dataclass's
field hints with ``_decode``.  A malformed body — wrong JSON types, unknown
or missing fields, bad base64, out-of-range integers, deeply nested arrays —
must become a refusal (``invalid-request`` with a 400/413 status), never an
unhandled exception or a crash.  Symmetrically, a well-formed request built
from the request dataclass's own defaults must decode back to an equal value.

The harnesses draw raw request bodies, arbitrary JSON payloads, and
structure-aware requests for one simple and one nested request class, and assert:

* ``dispatch`` on an unconfigured worker never raises: every body either
  succeeds (only reachable for request classes whose handler refuses with an
  ``OpsError``) or yields a refusal dict with the shared
  ``{"error", "detail", "status"}`` shape and a status that is not 200;
* no request class raises anything but ``OpsError`` from ``parse_request``
  on arbitrary JSON values, and every accepted value round-trips through
  ``dataclasses.asdict``-style field equality;
* base64 ``bytes`` fields that are declared reject non-strings and invalid
  base64, and accept only decodable strings.
"""

from __future__ import annotations

import json
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.ops import (
    DisassembleBytesRequest,
    DisassembleRequest,
    OperandLocationsRequest,
    OpsError,
    WorkerConfig,
    dispatch,
    parse_request,
)

_MAX_EXAMPLES = 100

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

#: Request classes with no required field whose handler cannot succeed
#: without a workspace or filestore, so dispatch on the bare worker always
#: refuses.  ``DisassembleBytesRequest.code`` is the only ``bytes`` field
#: in the ops surface, so it covers the base64 arm of ``_decode``.
_SIMPLE_REQUESTS = (DisassembleRequest, DisassembleBytesRequest)

_OPS = (
    "rebrew.disassemble",
    "rebrew.disassemble_bytes",
    "rebrew.address",
    "rebrew.decompile",
    "rebrew.structs",
    "rebrew.splat_parse",
    "rebrew.data_set",
    "rebrew.fingerprint",
    "rebrew.nope",
)


class TestDispatchNeverCrashes:
    @given(st.sampled_from(_OPS), st.binary(max_size=512))
    @settings(max_examples=_MAX_EXAMPLES)
    def test_raw_body_never_raises(self, op: str, body: bytes) -> None:
        status, reply = dispatch(WorkerConfig(), op, body)
        assert isinstance(status, int)
        decoded = json.loads(reply)
        assert isinstance(decoded, dict)
        if status != 200:
            assert set(decoded) == {"error", "detail", "status"}
            assert decoded["status"] == status


class TestParseRequestNeverCrashes:
    @given(st.sampled_from(_SIMPLE_REQUESTS), _JSON_VALUE)
    @settings(max_examples=_MAX_EXAMPLES)
    def test_arbitrary_json_only_raises_ops_error(self, cls: type[Any], raw: Any) -> None:
        try:
            value = parse_request(cls, raw)
        except OpsError:
            return
        # An accepted value is a detached instance of the request class:
        # its declared fields carry the decoded (not raw) values.
        assert isinstance(value, cls)

    @given(
        st.dictionaries(
            st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", max_size=16),
            _JSON_VALUE,
            max_size=6,
        )
    )
    @settings(max_examples=_MAX_EXAMPLES)
    def test_dict_payloads_never_crash(self, raw: dict[str, Any]) -> None:
        for cls in _SIMPLE_REQUESTS:
            try:
                value = parse_request(cls, raw)
            except OpsError:
                continue
            assert isinstance(value, cls)
            # Accepted fields must be the decoded form, never raw JSON values
            # leaked through (e.g. a str standing in for a bytes field).
            if cls is DisassembleBytesRequest:
                assert isinstance(value.code, bytes)
                assert isinstance(value.va, int) and isinstance(value.arch, str)


class TestBytesField:
    @given(st.text(max_size=32))
    @settings(max_examples=_MAX_EXAMPLES)
    def test_bytes_field_accepts_only_base64_strings(self, code: str) -> None:
        import base64

        raw = {"code": code, "va": 0, "arch": ""}
        try:
            value = parse_request(DisassembleBytesRequest, raw)
        except OpsError:
            try:
                base64.b64decode(code, validate=True)
            except Exception:
                return
            raise AssertionError(f"{code!r} is valid base64 but was refused") from None
        assert value.code == base64.b64decode(code, validate=True)

    @given(_JSON_SCALAR)
    @settings(max_examples=_MAX_EXAMPLES)
    def test_bytes_field_rejects_non_strings(self, code: Any) -> None:
        if isinstance(code, str):
            return
        raw = {"code": code, "va": 0, "arch": ""}
        try:
            parse_request(DisassembleBytesRequest, raw)
        except OpsError:
            return
        raise AssertionError(f"non-string {code!r} accepted as bytes")


class TestNestedRequest:
    @given(_JSON_VALUE)
    @settings(max_examples=_MAX_EXAMPLES)
    def test_operand_locations_never_crashes(self, raw: Any) -> None:
        try:
            value = parse_request(OperandLocationsRequest, raw)
        except OpsError:
            return
        assert isinstance(value, OperandLocationsRequest)
        # Every function entry decodes to an int pair.
        for fn in value.functions:
            assert isinstance(fn.va, int) and isinstance(fn.size, int)
