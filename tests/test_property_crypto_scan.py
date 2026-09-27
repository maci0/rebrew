"""Hypothesis fuzz for the crypto scanner's untrusted inputs.

``rebrew.crypto_scan`` searches raw section bytes for algorithm constant
tables and matches import/function names read out of a target binary.  Both
inputs come from the file being analyzed, so the harness asserts the
invariants that make a finding trustworthy: a reported VA must land inside
its section and must actually be the table bytes at that offset, the finding
list must be sorted, and no name may be reported twice.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.crypto_scan import (
    _HIGH_CONFIDENCE,
    _MEDIUM_CONFIDENCE,
    _TABLE_NEEDLES,
    constant_findings,
    name_findings,
)

#: A needle by name -> bytes, so the harness can re-derive what a finding claims.
_BY_NAME: dict[str, bytes] = {}
for _label, _needle in _TABLE_NEEDLES:
    _BY_NAME.setdefault(_label, _needle)

_SEED_TABLES = tuple(_BY_NAME.values())


@given(
    st.lists(
        st.tuples(st.integers(0, 3), st.integers(0, 0xFFFF_FFFF), st.binary(max_size=48)),
        min_size=1,
        max_size=3,
        unique_by=lambda entry: entry[0],
    )
)
@settings(max_examples=200, deadline=None)
def test_constant_findings_match_the_bytes_they_claim(
    sections: list[tuple[int, int, bytes]],
) -> None:
    """Every finding must be backed by the table bytes at the reported VA."""
    named = [(f".s{index}", va, blob) for index, va, blob in sections]
    findings = constant_findings(named)
    assert findings == sorted(findings, key=lambda f: (f["va"], f["name"]))
    for finding in findings:
        needle = _BY_NAME[finding["name"]]
        hosts = [
            (section_va, blob)
            for name, section_va, blob in named
            if name == finding["section"]
            and section_va <= finding["va"]
            and finding["va"] - section_va + len(needle) <= len(blob)
        ]
        assert hosts, f"finding outside its section: {finding}"
        section_va, blob = max(hosts, key=lambda host: host[0])
        offset = finding["va"] - section_va
        assert blob[offset : offset + len(needle)] == needle
        assert finding["kind"] == "constant"
        assert finding["confidence"] == _HIGH_CONFIDENCE


@given(st.binary(max_size=64), st.integers(0, 0xFFFF), st.integers(0, 0xFFFF))
@settings(max_examples=200, deadline=None)
def test_constant_findings_find_a_spliced_table(
    junk: bytes, table_index: int, section_va: int
) -> None:
    """A table spliced into noise is found at its own VA; unrelated bytes are
    never reported."""
    needle = _SEED_TABLES[table_index % len(_SEED_TABLES)]
    at = len(junk) // 2
    blob = junk[:at] + needle + junk[at:]
    findings = constant_findings([(".rdata", section_va, blob)])
    hit = [f for f in findings if f["va"] == section_va + at]
    assert hit, f"embedded table not reported: {findings}"
    assert all(
        blob[f["va"] - section_va : f["va"] - section_va + len(_BY_NAME[f["name"]])]
        == _BY_NAME[f["name"]]
        for f in findings
    )


_symbols = st.text(
    alphabet=st.characters(min_codepoint=0, max_codepoint=0x2FFF), max_size=24
).filter(lambda name: name.strip("\x00") == name and name != "")


@given(
    st.lists(st.dictionaries(st.text(max_size=8), st.text(max_size=8), max_size=2), max_size=4),
    st.lists(_symbols, max_size=6),
)
@settings(max_examples=200, deadline=None)
def test_name_findings_report_each_name_once(
    junk_imports: list[dict[str, str]], names: list[str]
) -> None:
    """Names are matched at most once, imports rank high, functions medium, and
    an unparseable import record is skipped rather than crashing."""
    imports = [*junk_imports, *({"name": name} for name in names)]
    findings = name_findings(imports, names)
    reported = [f["name"] for f in findings]
    assert len(reported) == len(set(reported))
    for finding in findings:
        expected = _HIGH_CONFIDENCE if finding["kind"] == "import" else _MEDIUM_CONFIDENCE
        assert finding["confidence"] == expected
        assert finding["detail"]


@given(st.text(max_size=32), st.text(max_size=32))
@settings(max_examples=200, deadline=None)
def test_name_findings_survive_hostile_names(import_name: str, function_name: str) -> None:
    """Control characters, markup, and regex metacharacters in a symbol name are
    either matched as a plain substring or ignored — never interpreted."""
    findings = name_findings([{"name": import_name}], [function_name])
    for finding in findings:
        assert finding["name"] in (import_name, function_name)


def test_empty_sections_yield_nothing() -> None:
    assert constant_findings([]) == []
    assert name_findings([], []) == []


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17])
def test_sections_shorter_than_a_needle(size: int) -> None:
    """A section too small to hold any table yields no finding."""
    assert constant_findings([(".data", 0x1000, b"\x00" * size)]) == []
