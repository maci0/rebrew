"""Hypothesis fuzz for the security scanner's untrusted input.

``rebrew.security_scan.scan_source`` takes C source text that came from a
directory the user pointed at, and reports each unsafe call it finds.  The
findings are what a reviewer triages, so the harness asserts the properties
that make a report trustworthy rather than only that the scan returns: every
finding carries the rule's own CWE/severity/confidence, names a line that
exists in the source, and quotes the source text of that line.  Hostile text
(NUL bytes, astral-plane code points, unbalanced braces, calls outside any
function) must be parsed or skipped, never crash the scan.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from rebrew.c_parser import get_ts_parser
from rebrew.security_scan import _RULES, _SNIPPET_MAX_CHARS, scan_source
from rebrew.utils import split_source_lines

#: rule name -> the rule it must have come from, so a finding cannot invent
#: a severity or a CWE that the rule table never declares.
_BY_RULE = {rule.rule: rule for rule in _RULES}

_CALLEES = tuple(sorted({entry.name for rule in _RULES for entry in rule.functions}))

#: Fragments that push the parser into error-recovery: unbalanced delimiters,
#: a stray NUL, an astral-plane identifier, an unterminated string/comment.
_HOSTILE = (
    "",
    "/*",
    "*/",
    '"unterminated',
    "'",
    "{",
    "}",
    "\x00",
    "\U0001f600 int x = 1;",
    "#include <stdio.h>\n#define ",
    "\t\r\n  ",
)

_ARGS = ("", "(a)", "(a, b)", '(a, "%s")', "(a, 4)", "()", "(a, b, c, d)")


@st.composite
def _sources(draw: st.DrawFn) -> str:
    """C-ish text: a function body around rule callees, plus hostile noise."""
    body = "".join(
        f"    {_CALLEES[callee_index % len(_CALLEES)]}{_ARGS[arg_index % len(_ARGS)]};\n"
        for callee_index, arg_index in draw(
            st.lists(st.tuples(st.integers(0, 64), st.integers(0, 64)), max_size=6)
        )
    )
    noise = "".join(draw(st.sampled_from(_HOSTILE)) for _ in range(draw(st.integers(0, 3))))
    return (
        f"{noise}\nvoid fuzzed(char *a, char *b) {{\n{body}{noise}}}\n"
        f"{draw(st.sampled_from(_HOSTILE))}"
    )


def _require_parser() -> None:
    if get_ts_parser() is None:
        pytest.skip("tree-sitter C runtime unavailable")


@given(_sources(), st.text(alphabet=st.characters(), max_size=12))
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_findings_match_the_rule_table_and_the_source_lines(text: str, file: str) -> None:
    """Every finding is backed by a declared rule and by a real source line."""
    _require_parser()
    findings: list[dict[str, Any]] = scan_source(text, file=file)
    assert findings == sorted(findings, key=lambda f: (f["line"], f["rule"]))
    assert findings == scan_source(text, file=file)
    lines = split_source_lines(text)
    for finding in findings:
        rule = _BY_RULE[finding["rule"]]
        assert finding["cwe"] == rule.cwe
        assert finding["severity"] == rule.severity
        assert finding["confidence"] == rule.confidence
        assert finding["file"] == file
        assert 1 <= finding["line"] <= len(lines)
        assert finding["snippet"] == lines[finding["line"] - 1].strip()[:_SNIPPET_MAX_CHARS]
        assert finding["message"].endswith(rule.description)
        assert "(): " in finding["message"]


@given(st.text(max_size=400))
@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_arbitrary_text_never_raises(text: str) -> None:
    """Any text, including a syntax error or one that is only whitespace,
    scans to a well-formed list without raising."""
    _require_parser()
    for finding in scan_source(text, file="fuzz.c"):
        assert finding["rule"] in _BY_RULE
        assert finding["line"] >= 1


def test_a_planted_call_is_reported() -> None:
    """The harness reaches real rules: an unconditional unsafe call is found
    and attributed to its enclosing function, so a passing fuzz run above is
    a scan of live paths and not an empty parse."""
    _require_parser()
    findings = scan_source("void fuzzed(char *d, char *s) {\n    strcpy(d, s);\n}\n", file="fuzz.c")
    assert [f["rule"] for f in findings] == ["unbounded-copy"]
    assert findings[0]["function"] == "fuzzed"


def test_checks_that_suppress_are_respected() -> None:
    """A literal format string and a literal size are not findings; the same
    calls with computed arguments are."""
    _require_parser()
    literal = scan_source('void f(void) { printf("hi"); memcpy(a, b, 4); }', file="f.c")
    assert literal == []
    computed = scan_source("void f(void) { printf(fmt); memcpy(a, b, n); }", file="f.c")
    assert {finding["rule"] for finding in computed} == {"format-string", "unchecked-memcpy"}
