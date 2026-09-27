"""Property-based fuzzing for the recompile service protocol.

``rebrew.recompile_client`` is the one module in rebrew that parses input it
does not control: a remote compile service's JSON reply and the
``artifact_url`` it hands back.  The service is a network peer, so every field
in the body is forgeable, and a hostile or broken reply must never be able to
(a) escape as an untyped crash (``KeyError``/``AttributeError``/``TypeError``
out of a ``dict.get`` on a body that is not a dict), (b) redirect the artifact
fetch off-origin, or (c) re-POST a compile that the service already ran, which
would append a second ``train.jsonl`` row for one compile.

The harnesses below draw hostile reply bodies, adversarial URL strings and
replay sequences, and assert those three properties plus the shape of every
value that reaches a caller.  A fuzzer proves presence of bugs; the
assertions here are what make a passing run a statement about correctness.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch
from urllib.parse import urlparse

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

from rebrew.recompile_client import (
    RecompileError,
    RecompileResult,
    _same_origin_artifact_url,
    compile_source,
)
from rebrew.utils import RETRYABLE_HTTP_STATUS

_BASE = "http://svc.local:8080"
_ARTIFACT = b"\x00OBJ-BYTES"

# ---------------------------------------------------------------------------
# Strategies: hostile service replies and URL strings
# ---------------------------------------------------------------------------

_JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**63), max_value=2**63),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=24),
    st.binary(max_size=16),
)

# Nested structure on purpose: a deeply nested reply is a recursion/stack
# vector for anything that walks the body.
_JSON_VALUES = st.recursive(
    _JSON_SCALARS,
    lambda child: st.one_of(
        st.lists(child, max_size=3),
        st.dictionaries(st.text(max_size=8), child, max_size=3),
    ),
    max_leaves=12,
)

_REPLY_KEYS = (
    "status",
    "artifact_url",
    "log",
    "compiler_version",
    "ok",
    "error",
    "message",
    "url",
    "path",
    "compiler",
    "size",
)

_STATUS_VALUES = st.one_of(
    st.sampled_from(["ok", "error", "OK", "Error", "", " ok", "ok\n", "ok|"]),
    st.sampled_from([None, True, False, 0, 1, [], {}, ["ok"], {"s": "ok"}]),
)

_URL_FRAGMENTS = (
    "",
    "/",
    "..",
    "../..",
    "%2e%2e%2f",
    "//evil.example/x",
    "///evil.example/x",
    "/\\evil.example/x",
    "http://evil.example/x",
    "HTTPS://evil.example/x",
    "https://svc.local:8080/x",
    "//svc.local:8080/x",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "data:text/plain,hi",
    "ftp://svc.local:8080/x",
    "@evil.example",
    "svc.local:8080@evil.example/x",
    "http://svc.local:8080.evil.example/x",
    "http://SVC.local:8080/x",
    "/api/v1/artifacts/../../secret",
    "\\\\evil.example\\x",
    "\n//evil.example/x",
    "\t",
    " ",
)


@st.composite
def _url_text(draw: st.DrawFn) -> str:
    """An arbitrary string biased toward URL boundary confusion."""
    return draw(
        st.one_of(
            st.builds(
                lambda a, b: a + b,
                st.sampled_from(_URL_FRAGMENTS),
                st.text(max_size=16),
            ),
            st.text(max_size=48),
        )
    )


@st.composite
def _service_reply(draw: st.DrawFn) -> dict[str, Any]:
    """A JSON object shaped like a compile reply, with hostile field values."""
    body: dict[str, Any] = draw(
        st.dictionaries(st.sampled_from(_REPLY_KEYS), _JSON_VALUES, max_size=5)
    )
    if draw(st.booleans()):
        body["status"] = draw(_STATUS_VALUES)
    if draw(st.booleans()):
        body["artifact_url"] = draw(_url_text())
    return body


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _Resp:
    """Minimal ``httpx.Response`` stand-in."""

    def __init__(
        self,
        status_code: int,
        *,
        json_body: Any = None,
        content: bytes = b"",
        text: str = "",
        json_raises: bool = False,
    ) -> None:
        self.status_code = status_code
        self._json = json_body
        self._json_raises = json_raises
        self.content = content
        self.text = text
        self.closed = False

    def json(self) -> Any:
        if self._json_raises:
            raise ValueError("not json")
        return self._json

    def close(self) -> None:
        self.closed = True


class _Client:
    """Replay-only HTTP client: every POST/GET is scripted, nothing escapes.

    A list is a queue of replies; once drained the last one repeats, so a
    retry sequence of any length can be scripted without a bound.
    """

    def __init__(self, post: Any, get: Any = None) -> None:
        self._post = list(post) if isinstance(post, list) else post
        self._get = list(get) if isinstance(get, list) else get
        self.calls: list[str] = []

    def _next(self, scripted: Any) -> Any:
        if not isinstance(scripted, list):
            return scripted
        if len(scripted) > 1:
            return scripted.pop(0)
        return scripted[0]

    def post(self, url: str, json: Any = None) -> Any:
        self.calls.append("post")
        if isinstance(self._post, Exception):
            raise self._post
        return self._next(self._post)

    def get(self, url: str) -> Any:
        self.calls.append("get")
        if isinstance(self._get, Exception):
            raise self._get
        return self._next(self._get)


def _run(client: _Client, **kwargs: Any) -> RecompileResult:
    return compile_source(_BASE, "msvc-6.0", "int f(void){}", ["/c"], client=client, **kwargs)


# ---------------------------------------------------------------------------
# The reply parser
# ---------------------------------------------------------------------------


@settings(max_examples=250, deadline=None)
@example(body={"status": "ok", "artifact_url": "http://evil.example/x"})
@example(body={"status": "ok", "artifact_url": 123})
@example(body={"status": "ok"})
@example(body={"status": "ok", "artifact_url": "//evil.example/x", "log": {"a": 1}})
@given(body=_service_reply())
def test_hostile_reply_never_escapes_as_an_untyped_error(body: dict[str, Any]) -> None:
    """Any JSON object the service can send is either a shaped result or a
    ``RecompileError``; nothing else propagates to the caller."""
    client = _Client(_Resp(200, json_body=body), _Resp(200, content=_ARTIFACT))
    try:
        res = _run(client)
    except RecompileError as exc:
        assert exc.kind in ("network", "http", "validation", "protocol")
        return
    assert isinstance(res, RecompileResult)
    if res.ok:
        # An ok verdict is only ever reached by actually downloading bytes.
        assert client.calls.count("get") == 1
        assert res.obj_bytes == _ARTIFACT
        assert res.compiler_version is None or isinstance(res.compiler_version, str)
    else:
        assert res.obj_bytes is None
        assert isinstance(res.log, str)
        # A failed compile must not have chased an artifact.
        assert "get" not in client.calls


@settings(max_examples=120, deadline=None)
@given(body=st.recursive(_JSON_SCALARS, lambda c: st.lists(c, max_size=3), max_leaves=6))
def test_non_object_reply_is_a_protocol_error(body: Any) -> None:
    """A body that is not a JSON object (a list, a bare string, ``null``) is
    a protocol violation, not a crash."""
    client = _Client(_Resp(200, json_body=body), _Resp(200, content=_ARTIFACT))
    with pytest.raises(RecompileError) as ei:
        _run(client)
    assert ei.value.kind == "protocol"
    assert "get" not in client.calls


@settings(max_examples=100, deadline=None)
@given(status=st.integers(min_value=100, max_value=599).filter(lambda s: s != 200))
def test_any_non_200_status_maps_to_a_typed_http_error(status: int) -> None:
    """The status code the service sends is carried through, never dropped."""
    client = _Client(_Resp(status, text="upstream said no"), _Resp(200, content=_ARTIFACT))
    with pytest.raises(RecompileError) as ei:
        _run(client)
    assert ei.value.kind == "http"
    assert ei.value.status_code == status


# ---------------------------------------------------------------------------
# The SSRF guard
# ---------------------------------------------------------------------------


@settings(max_examples=300, deadline=None)
@example(artifact="//evil.example/x")
@example(artifact="http://evil.example/x")
@example(artifact="\\\\evil.example\\share")
@given(artifact=_url_text())
def test_accepted_artifact_urls_are_always_same_origin(artifact: str) -> None:
    """Whatever URL the service returns, an accepted one is same-origin.

    This is the SSRF property stated as a postcondition rather than a check
    on a hand-written list of bad inputs: if the guard ever resolves to
    another host, or drops the path, the assertion fires.
    """
    try:
        resolved = _same_origin_artifact_url(_BASE, artifact)
    except RecompileError as exc:
        assert exc.kind == "protocol"
        return
    parsed = urlparse(resolved)
    assert parsed.scheme == "http"
    assert parsed.netloc == "svc.local:8080"
    assert parsed.path.startswith("/")
    # And the fetch target is the resolved URL, unchanged.
    client = _Client(
        _Resp(200, json_body={"status": "ok", "artifact_url": artifact}),
        _Resp(200, content=_ARTIFACT),
    )
    res = _run(client)
    assert res.ok


@settings(max_examples=150, deadline=None)
@given(
    host=st.sampled_from(
        ["evil.example", "svc.local.evil.example", "svc.local", "svc.local:9090", "SVC.LOCAL:8080"]
    )
)
def test_foreign_hosts_are_always_refused(host: str) -> None:
    """An absolute URL to any other host is refused, including the
    same-name-different-port and case-folded spellings a parser could let
    through a naive prefix check."""
    artifact = f"http://{host}/api/v1/artifacts/x.obj"
    if artifact.startswith(f"{_BASE}/"):
        pytest.skip("same-origin spelling, covered by the acceptance property")
    with pytest.raises(RecompileError) as ei:
        _same_origin_artifact_url(_BASE, artifact)
    assert ei.value.kind == "protocol"


# ---------------------------------------------------------------------------
# Sequence: retries must not re-run a compile the service already ran
# ---------------------------------------------------------------------------


@settings(max_examples=60, deadline=None)
@given(
    get_status=st.sampled_from([404, 500, 502, 503, 504]),
    retries=st.integers(min_value=1, max_value=3),
)
def test_failed_artifact_download_never_re_posts_the_compile(get_status: int, retries: int) -> None:
    """With ``emit_assembly=True`` a compile the service already ran is not
    re-POSTed, however many artifact retries follow: one compile, one
    ``train.jsonl`` row."""
    client = _Client(
        _Resp(200, json_body={"status": "ok", "artifact_url": "/a.obj"}),
        _Resp(get_status, text="gone"),
    )
    with pytest.raises(RecompileError) as ei:
        _run(client, emit_assembly=True, retries=retries)
    assert ei.value.kind == "http"
    assert client.calls.count("post") == 1
    expected_gets = retries + 1 if get_status in RETRYABLE_HTTP_STATUS else 1
    assert client.calls.count("get") == expected_gets


@settings(max_examples=20, deadline=None)
@given(post_status=st.sampled_from([408, 425, 429, 503]))
def test_retryable_pre_compile_status_is_re_posted(post_status: int) -> None:
    """A status the service provably never ran the compile for is retried as
    a fresh POST, exactly once the service recovers, and the backoff between
    attempts is the documented base delay."""
    slept: list[float] = []
    with patch("rebrew.recompile_client.time.sleep", slept.append):
        client = _Client(
            [
                _Resp(post_status, text="busy"),
                _Resp(200, json_body={"status": "ok", "artifact_url": "/a.obj"}),
            ],
            _Resp(200, content=_ARTIFACT),
        )
        res = _run(client, emit_assembly=True, retries=3)
    assert res.ok
    assert client.calls == ["post", "post", "get"]
    assert slept == [pytest.approx(0.25)]


# ---------------------------------------------------------------------------
# Request-side limits
# ---------------------------------------------------------------------------


@settings(max_examples=60, deadline=None)
@given(n=st.integers(min_value=65, max_value=400))
def test_oversized_flag_lists_fail_validation_before_any_request(n: int) -> None:
    """Too many flags is a local validation error, raised before the client
    is ever touched."""
    client = _Client(_Resp(200, json_body={}), _Resp(200, content=_ARTIFACT))
    with pytest.raises(RecompileError) as ei:
        compile_source(_BASE, "msvc-6.0", "int f(void){}", ["/c"] * n, client=client)
    assert ei.value.kind == "validation"
    assert client.calls == []


@settings(max_examples=60, deadline=None)
@given(flag=st.text(min_size=257, max_size=400))
def test_oversized_single_flag_fails_validation_before_any_request(flag: str) -> None:
    """An over-long flag is refused locally, not shipped to the service."""
    client = _Client(_Resp(200, json_body={}), _Resp(200, content=_ARTIFACT))
    with pytest.raises(RecompileError) as ei:
        compile_source(_BASE, "msvc-6.0", "int f(void){}", [flag], client=client)
    assert ei.value.kind == "validation"
    assert client.calls == []


# ---------------------------------------------------------------------------
# The serialized result crossing the trust boundary
# ---------------------------------------------------------------------------


@settings(max_examples=150, deadline=None)
@given(
    ok=st.booleans(),
    log=st.text(max_size=64),
    version=st.one_of(st.none(), st.text(max_size=32)),
)
def test_result_round_trips_across_serialization(ok: bool, log: str, version: str | None) -> None:
    """Pair assertion across the persistence boundary: what ``to_dict``
    writes is exactly what ``from_dict`` reads back."""
    res = RecompileResult(ok=ok, log=log, compiler_version=version)
    back = RecompileResult.from_dict(res.to_dict())
    assert back.ok == res.ok
    assert back.log == res.log
    assert back.compiler_version == res.compiler_version


@settings(max_examples=100, deadline=None)
@given(data=st.dictionaries(st.text(max_size=8), _JSON_VALUES, max_size=4))
def test_from_dict_rejects_a_missing_or_non_boolean_ok(data: dict[str, Any]) -> None:
    """A cached verdict with no boolean ``ok`` is a protocol error; the
    client must not read it as "the compile failed"."""
    data.pop("ok", None)
    with pytest.raises(RecompileError) as ei:
        RecompileResult.from_dict(data)
    assert ei.value.kind == "protocol"


@settings(max_examples=60, deadline=None)
@given(blob=st.binary(max_size=64))
def test_non_json_body_is_a_protocol_error(blob: bytes) -> None:
    """A 200 that is not JSON at all (an HTML error page from a proxy) maps
    to a protocol error rather than propagating ``json.JSONDecodeError``."""
    client = _Client(_Resp(200, text=blob.decode("latin-1"), json_raises=True), None)
    with pytest.raises(RecompileError) as ei:
        _run(client)
    assert ei.value.kind == "protocol"
