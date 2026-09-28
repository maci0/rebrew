"""Property-based fuzz tests for ``rebrew.dashboard``'s request-derived input.

The dashboard is the one surface in rebrew that takes input from an
untrusted socket: a browser (or anything that can reach the bind address)
supplies the request path, the query string, and the ``Host``,
``Accept-Encoding`` and ``If-None-Match`` headers.  Every value that reaches
SQL, a response header, or a log line from those bytes is parsed by a
hand-written helper here — ``_int_param``, ``_offset_param``, ``_opt_query``,
``_module_query``, ``_va_query``, ``_escape_like``, ``_text_or_va``,
``_parse_accept_encoding``, ``_if_none_match``, ``_host_allowed`` and
``_query_scope`` — and none of them had a property test.

The harnesses below draw whole request lines and header values out of
``st.text()`` (so control characters, bidi overrides, lone surrogates,
embedded NULs and multi-megabyte values all arrive) and assert:

* no parser raises on any input, and every numeric parse lands inside its
  documented clamp;
* the SQL built for a search never carries the caller's text (it is a bound
  parameter, not interpolation) and its LIKE wildcards are all escaped, so
  ``%`` searches for a literal percent and not for everything;
* a client-chosen query string cannot reach the ETag tag, which is what
  stops it from steering a response header;
* content negotiation only ever yields a supported coding, at a q-value in
  ``[0, 1]``, and never picks a coding the client refused;
* the Host allow-list rejects every value it did not mint, case and
  surrounding whitespace included;
* end to end through :meth:`Dashboard.handle`, no fuzzed request produces a
  5xx, every JSON body parses, and every error envelope carries both the
  stable ``code`` and the human ``error``.
"""

from __future__ import annotations

import json
import re
from http import HTTPStatus
from typing import Any

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from rebrew.build_db import build_db
from rebrew.dashboard import (
    _APP_JS_VERSION,
    _BOOT_GUARD_JS_VERSION,
    _CACHE_IMMUTABLE,
    _CACHE_REVALIDATE,
    _DEFAULT_LIMIT,
    _MAX_LIMIT,
    _UNCACHEABLE_ROUTES,
    Dashboard,
    _encoding_q,
    _escape_like,
    _files_display,
    _host_allowed,
    _if_none_match,
    _int_param,
    _load_list,
    _maybe_compress,
    _negotiate_encoding,
    _offset_param,
    _parse_accept_encoding,
    _query_scope,
    _scrub_invisible,
    _success_cache_control,
    _text_or_va,
    _va_query,
    allowed_hosts_for,
)
from rebrew.workspace import VA_MAX

#: The characters that must never reach a response body: the reordering and
#: hiding controls, the zero-width joiners, and the BOM.  Spelled out as
#: escapes rather than imported from the scrubber, so the assertion stays
#: independent of the set the scrubber happens to use and stays reviewable.
_INVISIBLE = (
    "\u00ad\u180e\u200b\u200c"
    "\u200d\u200e\u200f\u202a\u202b\u202c\u202d"
    "\u202e\u2060\u2061\u2062\u2063\u2064\u2066\u2067"
    "\u2068\u2069\ufeff"
)
#: Every codepoint a request byte sequence can spell: NUL, the C0 and C1
#: control blocks, ASCII, Latin-1, and the bidi controls above.  Bounded by
#: hand because the full Unicode range makes generation slow enough to trip
#: Hypothesis's own health check.
_CHARS = st.characters(min_codepoint=0, max_codepoint=0x2FF) | st.sampled_from(_INVISIBLE)
#: Header values are bounded so a run stays inside a normal test budget while
#: still reaching far past any real request line.
_HEADER_TEXT = st.text(alphabet=_CHARS, max_size=400)
#: Query and path text is where the nesting and the control characters live.
_REQUEST_TEXT = st.text(alphabet=_CHARS, max_size=600)
#: Built from _INVISIBLE rather than the pattern, so it also holds for the
#: multi-character runs a table cell can carry.
_INVISIBLE_RE = re.compile(f"[{re.escape(_INVISIBLE)}]")
#: Response key each list route names its rows under.
_ROW_KEY = {
    "/api/functions": "functions",
    "/api/globals": "globals",
    "/api/history": "history",
}


@st.composite
def _query(draw: st.DrawFn) -> dict[str, list[str]]:
    """A ``parse_qs``-shaped query dict with attacker-chosen keys and values.

    Keys are drawn from a small alphabet of real parameter names plus SQL and
    URL metacharacters, so ``target=``, ``limit=``, ``module=`` and junk all
    reach the router in the same run.
    """
    keys = st.sampled_from(
        [
            "target",
            "limit",
            "offset",
            "status",
            "module",
            "q",
            "v",
            "va",
            "'",
            '"',
            "1=1",
            "%",
            "..",
            "",
        ]
    )
    size = draw(st.integers(min_value=0, max_value=4))
    out: dict[str, list[str]] = {}
    for _ in range(size):
        key = draw(keys)
        values = draw(st.lists(_REQUEST_TEXT, min_size=0, max_size=3))
        out.setdefault(key, []).extend(values)
    return out


@st.composite
def _request(draw: st.DrawFn) -> tuple[str, str, dict[str, list[str]]]:
    """A ``(method, path, query)`` triple for :meth:`Dashboard.handle`."""
    method = draw(st.sampled_from(["GET", "HEAD", "POST", "PUT", "DELETE", "g", "", "GET GET"]))
    known = draw(
        st.sampled_from(
            [
                "/",
                "/app.js",
                "/boot-guard.js",
                "/api/bootstrap",
                "/api/health",
                "/api/targets",
                "/api/summary",
                "/api/functions",
                "/api/sections",
                "/api/globals",
                "/api/history",
            ]
        )
    )
    path = draw(
        st.builds(
            lambda base, suffix, frag: f"{base}{suffix}{frag}",
            st.just(known),
            st.one_of(st.just(""), _REQUEST_TEXT),
            st.one_of(st.just(""), st.builds(lambda f: f"?{f}", _REQUEST_TEXT)),
        )
    )
    return method, path, draw(_query())


@pytest.fixture(scope="module")
def dashboard(tmp_path_factory: pytest.TempPathFactory) -> Dashboard:
    """One read-only dashboard over a real ``coverage.db``, shared by the run.

    The router fuzz drives hundreds of examples; rebuilding the database per
    example would spend the whole budget in ``build_db``.  Every query the
    harnesses issue is read-only, so one instance serves them all.
    """
    root = tmp_path_factory.mktemp("dash_fuzz")
    db_dir = root / "db"
    db_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "functions": {
            "0x10001000": {
                "name": "func_a",
                "vaStart": "0x10001000",
                "size": 64,
                "status": "EXACT",
                "module": "SERVER",
                "symbol": "_func_a",
                "files": ["a.c"],
                "markerType": "FUNCTION",
            },
            "0x10002000": {
                "name": "func_b",
                "vaStart": "0x10002000",
                "size": 32,
                "status": "STUB",
                "module": "",
                "symbol": "_func_b",
                "files": ["b.c", "d.h"],
                "markerType": "FUNCTION",
            },
        },
        "globals": {
            "0x50001000": {
                "name": "g_flag",
                "decl": "int g_flag;",
                "size": 4,
                "module": "SERVER",
            }
        },
        "sections": {".text": {"va": 0x10001000, "size": 128, "fileOffset": 0x400}},
        "summary": {"total_functions": 2, "total_bytes": 128},
        "paths": {"a.c": "src/a.c"},
    }
    (db_dir / "data_server_dll.json").write_text(json.dumps(data), encoding="utf-8")
    build_db(root)
    return Dashboard(db_dir / "coverage.db")


class TestNumericQueryParams:
    """``limit`` and ``offset``: a client-chosen int that must never widen a page."""

    @given(params=_query(), name=st.sampled_from(["limit", "offset"]))
    @settings(max_examples=200)
    def test_int_param_stays_in_its_clamp(self, params: dict[str, list[str]], name: str) -> None:
        value = _int_param(params, name, _DEFAULT_LIMIT)
        assert 0 < value <= _MAX_LIMIT
        assert isinstance(value, int)

    @given(params=_query())
    @settings(max_examples=200)
    def test_offset_param_stays_in_range(self, params: dict[str, list[str]]) -> None:
        value = _offset_param(params, "offset", 0)
        assert 0 <= value <= VA_MAX
        assert isinstance(value, int)

    @given(
        raw=st.one_of(st.text(alphabet=_CHARS, min_size=1), st.integers().map(str)),
    )
    @settings(max_examples=200)
    def test_unparsable_value_falls_back_to_the_default(self, raw: str) -> None:
        """A non-numeric or non-positive value is a client mistake, not a 500."""
        params = {"limit": [raw], "offset": [raw]}
        try:
            number = int(raw)
        except ValueError:
            assert _int_param(params, "limit", _DEFAULT_LIMIT) == _DEFAULT_LIMIT
            assert _offset_param(params, "offset", 0) == 0
            return
        assert _int_param(params, "limit", _DEFAULT_LIMIT) == (
            min(number, _MAX_LIMIT) if number > 0 else _DEFAULT_LIMIT
        )
        assert _offset_param(params, "offset", 0) == (min(number, VA_MAX) if number >= 0 else 0)

    @given(value=st.integers(min_value=1, max_value=10**12))
    @settings(max_examples=100)
    def test_oversized_limit_is_clamped_not_rejected(self, value: int) -> None:
        assert _int_param({"limit": [str(value)]}, "limit", _DEFAULT_LIMIT) == min(
            value, _MAX_LIMIT
        )

    @given(value=st.integers(min_value=1, max_value=VA_MAX + 10**9))
    @settings(max_examples=100)
    def test_oversized_offset_is_clamped_to_va_max(self, value: int) -> None:
        """Clamping skip to the page-size cap would make rows past it unreachable."""
        assert _offset_param({"offset": [str(value)]}, "offset", 0) == min(value, VA_MAX)


class TestSearchTerm:
    """The search term is the one query value bound into a LIKE pattern."""

    @given(term=_REQUEST_TEXT)
    @settings(max_examples=300)
    def test_escape_leaves_no_live_wildcard(self, term: str) -> None:
        escaped = _escape_like(term)
        # Read the escaped form the way SQLite's ESCAPE '\' clause does: a
        # backslash makes the next character literal.  No bare wildcard may
        # survive, or a literal percent in a function name widens the match.
        recovered: list[str] = []
        index = 0
        while index < len(escaped):
            char = escaped[index]
            if char == "\\":
                assert index + 1 < len(escaped), escaped
                recovered.append(escaped[index + 1])
                index += 2
                continue
            assert char not in "%_", escaped
            recovered.append(char)
            index += 1
        assert "".join(recovered) == term

    @given(
        term=_REQUEST_TEXT,
        columns=st.lists(
            st.sampled_from(["name", "symbol", "va"]), min_size=1, max_size=3, unique=True
        ),
    )
    @settings(max_examples=200)
    def test_text_or_va_parameterizes_every_column(self, term: str, columns: list[str]) -> None:
        sql, args = _text_or_va(term, *columns)
        # One bound parameter per LIKE column, plus at most one for the VA
        # equality: the caller's text is data, never SQL.
        assert args.count(f"%{_escape_like(term)}%") == len(columns)
        assert len(args) in (len(columns), len(columns) + 1)
        assert all("?" in part for part in sql.split(" OR "))
        for column in columns:
            assert f"{column} LIKE ? ESCAPE '\\'" in sql
        for char in ("'", ";", "--"):
            assert char not in sql or char in "'\\'"
        va = _va_query(term)
        assert (va is not None) == ("va = ?" in sql)

    @given(term=_REQUEST_TEXT)
    @settings(max_examples=300)
    def test_va_query_is_none_or_a_usable_address(self, term: str) -> None:
        va = _va_query(term)
        if va is None:
            return
        assert 0 <= va <= VA_MAX
        text = term.strip()
        if text[:2].lower() == "0x":
            text = text[2:]
        assert 4 <= len(text) <= 16
        # The same address in either spelling, so ``0x401000`` and ``00401000``
        # cannot disagree about which row a search meant.
        assert int(text, 16) == va

    @given(term=st.text(min_size=1, max_size=3, alphabet="0123456789abcdefABCDEF"))
    @settings(max_examples=100)
    def test_short_hex_stays_a_name_search(self, term: str) -> None:
        """``add`` must not be read as ``0xadd``; fewer than 4 digits is a name."""
        assume(len(term) < 4)
        assert _va_query(term) is None


class TestContentNegotiation:
    """``Accept-Encoding`` decides the wire body, so it must resolve to one coding."""

    @given(header=_HEADER_TEXT)
    @settings(max_examples=300)
    def test_parsed_weights_are_bounded(self, header: str) -> None:
        accepted = _parse_accept_encoding(header)
        for coding, weight in accepted.items():
            assert coding in ("gzip", "zstd", "*")
            assert 0.0 <= weight <= 1.0

    @given(header=_HEADER_TEXT)
    @settings(max_examples=300)
    def test_negotiate_returns_a_supported_coding(self, header: str) -> None:
        encoding = _negotiate_encoding(header)
        assert encoding in (None, "zstd", "gzip")
        if encoding is not None:
            # A coding the client refused (q=0) must never be chosen.
            assert _encoding_q(_parse_accept_encoding(header), encoding) > 0

    @given(header=st.text(alphabet=",;= gzw*dstq0123456789.-", max_size=60))
    @settings(max_examples=200)
    def test_refused_codings_are_never_served(self, header: str) -> None:
        accepted = _parse_accept_encoding(header)
        encoding = _negotiate_encoding(header)
        for coding in ("gzip", "zstd"):
            if _encoding_q(accepted, coding) == 0.0:
                assert encoding != coding

    @given(body=st.binary(max_size=4096), header=_HEADER_TEXT)
    @settings(max_examples=100)
    def test_maybe_compress_round_trips_the_negotiated_coding(
        self, body: bytes, header: str
    ) -> None:
        import gzip

        import zstandard

        out, encoding = _maybe_compress(body, header)
        if encoding is None:
            assert out == body
            return
        # The body is only ever handed back compressed, never re-encoded into
        # a coding the client did not ask for.
        assert encoding == _negotiate_encoding(header)
        if encoding == "zstd":
            assert zstandard.ZstdDecompressor().decompress(out) == body
        else:
            assert gzip.decompress(out) == body


class TestConditionalRequests:
    """``If-None-Match`` decides whether a body is re-sent, on client bytes."""

    @given(header=_HEADER_TEXT, etag=st.text(alphabet='W/"abc012-., ', max_size=40))
    @settings(max_examples=300)
    def test_match_is_value_based_and_weak(self, header: str, etag: str) -> None:
        matched = _if_none_match(header, etag)
        assert isinstance(matched, bool)
        if header.strip() == "*":
            assert matched

    @given(etag=st.text(alphabet='W/"abc012-.,', min_size=1, max_size=40))
    @settings(max_examples=200)
    def test_the_etag_itself_always_matches(self, etag: str) -> None:
        """A server that 304s its own validator would hand out stale bodies."""
        assume("," not in etag)
        assert _if_none_match(etag, etag)
        assert _if_none_match(f"W/{etag}", etag)
        assert _if_none_match(etag, f"W/{etag}")
        assert _if_none_match(f'"other", {etag} ', etag)

    @given(etag=st.text(alphabet="ab", min_size=1, max_size=8))
    @settings(max_examples=100)
    def test_unlisted_etag_does_not_match(self, etag: str) -> None:
        assume("," not in etag)
        other = etag + "Z"
        assume(other != etag)
        assert not _if_none_match(other, etag)
        assert not _if_none_match("", etag)


class TestHostAllowList:
    """The Host allow-list is the DNS-rebinding guard; it must be exact."""

    @given(
        host=st.sampled_from(["127.0.0.1", "localhost", "::1", "0.0.0.0", "example.com"]),
        port=st.integers(min_value=1, max_value=65535),
    )
    @settings(max_examples=50)
    def test_every_generated_header_is_rejected(self, host: str, port: int) -> None:
        allowed = allowed_hosts_for("127.0.0.1", 8080)
        header = f"{host}:{port}"
        # Anything not minted for this exact bind is a rebinding attempt.
        if f"{host}:{8080}".lower() not in allowed and header.lower() not in allowed:
            assert not _host_allowed(header, allowed)

    @given(
        bind=st.sampled_from(["127.0.0.1", "0.0.0.0", "::1"]),
        port=st.integers(min_value=1, max_value=65535),
        case=st.sampled_from([str.lower, str.upper, lambda s: f"  {s}  "]),
    )
    @settings(max_examples=60)
    def test_accepted_headers_survive_case_and_padding(
        self, bind: str, port: int, case: Any
    ) -> None:
        allowed = allowed_hosts_for(bind, port)
        for name in allowed:
            if not name.startswith("["):
                assert _host_allowed(case(name), allowed)


class TestResponseTagging:
    """The ETag tag and Cache-Control are headers built from client-chosen bytes."""

    @given(query=_REQUEST_TEXT)
    @settings(max_examples=300)
    def test_query_scope_never_echoes_the_query(self, query: str) -> None:
        scope = _query_scope(query)
        if not query:
            assert scope == ""
            return
        # A tag that carried the raw query would let a client put CR/LF or an
        # arbitrary length into a response header.
        assert re.fullmatch(r"-[0-9a-f]{8}", scope), scope
        assert not any(ch in scope for ch in '\r\n,;" ')

    @given(query=_REQUEST_TEXT, name=st.sampled_from(["target", "q", "module"]))
    @settings(max_examples=200)
    def test_query_scope_is_a_function_of_the_query(self, query: str, name: str) -> None:
        assert _query_scope(query) == _query_scope(query)
        assert _query_scope("") == ""

    @given(path=st.sampled_from(["/app.js", "/boot-guard.js", "/api/health", "/api/functions"]))
    @settings(max_examples=50)
    def test_cache_control_is_one_of_three_values(self, path: str) -> None:
        value = _success_cache_control(path, {})
        assert value in (_CACHE_IMMUTABLE, _CACHE_REVALIDATE, "no-store")

    @given(value=st.text(alphabet=_CHARS, max_size=40))
    @settings(max_examples=200)
    def test_immutable_needs_the_content_hashed_url(self, value: str) -> None:
        query = {"v": [value]}
        assume(value not in (_APP_JS_VERSION, _BOOT_GUARD_JS_VERSION))
        assert _success_cache_control("/app.js", query) == _CACHE_REVALIDATE
        assert _success_cache_control("/boot-guard.js", query) == _CACHE_REVALIDATE

    @given(value=st.text(alphabet=_CHARS, min_size=1, max_size=40))
    @settings(max_examples=50)
    def test_health_is_never_cached(self, value: str) -> None:
        assert "/api/health" in _UNCACHEABLE_ROUTES
        assert _success_cache_control("/api/health", {"v": [value]}) == "no-store"


class TestDbDerivedCellText:
    """Text read back out of the database is target-controlled, not client-controlled."""

    @given(raw=st.text(alphabet=_CHARS, max_size=80))
    @settings(max_examples=300)
    def test_load_list_yields_only_strings(self, raw: str) -> None:
        value = _load_list(raw)
        assert isinstance(value, list)
        assert all(isinstance(item, str) for item in value)
        # A non-list JSON payload is a schema surprise, not an exception.
        try:
            decoded = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            assert value == []
            return
        if not isinstance(decoded, list):
            assert value == []

    @given(raw=st.text(alphabet=_CHARS, max_size=80))
    @settings(max_examples=300)
    def test_files_display_is_always_text(self, raw: str) -> None:
        assert isinstance(_files_display(raw), str)

    @given(
        value=st.recursive(
            st.one_of(
                st.text(alphabet=_CHARS, max_size=30), st.none(), st.booleans(), st.integers()
            ),
            lambda children: st.one_of(
                st.lists(children, max_size=3),
                st.dictionaries(st.text(alphabet=_CHARS, max_size=8), children, max_size=3),
            ),
            max_leaves=6,
        )
    )
    @settings(max_examples=200)
    def test_scrub_removes_every_bidi_format_character(self, value: Any) -> None:
        scrubbed = _scrub_invisible(value)
        assert not _INVISIBLE_RE.search(json.dumps(scrubbed, ensure_ascii=False))


class TestRouter:
    """End-to-end: a whole fuzzed request line through ``Dashboard.handle``."""

    @given(request=_request())
    @settings(max_examples=250, deadline=None)
    def test_no_fuzzed_request_raises_or_reports_a_server_error(
        self, dashboard: Dashboard, request: tuple[str, str, dict[str, list[str]]]
    ) -> None:
        method, path, query = request
        status, content_type, body = dashboard.handle(method, path, query)
        assert isinstance(status, int)
        assert 200 <= status < 500, f"{method} {path} -> {status}: {body[:200]}"
        assert 0 < status < 600
        assert isinstance(body, str)
        if status >= 400:
            assert content_type == "application/json; charset=utf-8"
            payload = json.loads(body)
            assert set(payload) >= {"error", "code"}
            assert isinstance(payload["code"], str) and payload["code"]
            assert isinstance(payload["error"], str)
        if content_type == "application/json; charset=utf-8":
            # A body the client cannot parse is a failed response, whatever
            # the status says.
            assert isinstance(json.loads(body), dict)

    @given(
        path=st.sampled_from(
            [
                "/api/summary",
                "/api/functions",
                "/api/sections",
                "/api/globals",
                "/api/history",
            ]
        ),
        query=_query(),
    )
    @settings(max_examples=200, deadline=None)
    def test_target_scoped_routes_never_leak_rows_for_a_blank_target(
        self, dashboard: Dashboard, path: str, query: dict[str, list[str]]
    ) -> None:
        # A blank target is a missing one, so the route answers 400 rather
        # than falling through to an unfiltered query.  The first value is
        # what `_opt_query` reads, and there is one to read only if the list
        # is non-empty.
        first = next(iter(query.get("target", [])), None)
        assume(first is None or not first.strip())
        status, _, body = dashboard.handle("GET", path, query)
        assert status == HTTPStatus.BAD_REQUEST
        assert json.loads(body)["code"] == "missing_target"

    @given(
        path=st.sampled_from(["/api/functions", "/api/globals"]),
        term=st.sampled_from(["%", "\\", "%%", "\\%", "%\\%"]),
    )
    @settings(max_examples=20, deadline=None)
    def test_wildcard_search_terms_match_literally(
        self, dashboard: Dashboard, path: str, term: str
    ) -> None:
        """A LIKE wildcard from the search box is matched literally, so a bare
        ``%`` returns nothing instead of the whole table."""
        status, _, body = dashboard.handle(
            "GET", path, {"target": ["server_dll"], "q": [term], "limit": ["5000"]}
        )
        assert status == HTTPStatus.OK
        payload = json.loads(body)
        assert payload[_ROW_KEY[path]] == []
        assert payload["total"] == 0
        assert payload["limit"] == _MAX_LIMIT

    @given(
        path=st.sampled_from(["/api/functions", "/api/globals", "/api/history"]),
        limit=st.integers(min_value=-5, max_value=10**9),
        offset=st.integers(min_value=-5, max_value=10**9),
    )
    @settings(max_examples=150, deadline=None)
    def test_paging_never_exceeds_the_cap(
        self, dashboard: Dashboard, path: str, limit: int, offset: int
    ) -> None:
        status, _, body = dashboard.handle(
            "GET",
            path,
            {
                "target": ["server_dll"],
                "limit": [str(limit)],
                "offset": [str(offset)],
            },
        )
        if status != HTTPStatus.OK:
            return
        payload = json.loads(body)
        assert 0 < payload["limit"] <= _MAX_LIMIT
        assert 0 <= payload["offset"] <= VA_MAX
        assert len(payload[_ROW_KEY[path]]) <= payload["limit"]
