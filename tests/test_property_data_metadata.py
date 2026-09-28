"""Property-based fuzz tests for the ``rebrew-data.toml`` qualified-key parser.

:func:`rebrew.data_metadata.iter_data_symbols` is the canonical reader for
raw data-metadata documents.  Its input is a hand-edited file that also
carries a third-party import path, so both the key text and the field
values are untrusted.  The properties below pin the contract its callers
rely on (``data_annotate``, ``data_layout``, ``gen_link_stubs``):

* it never raises on any string-keyed document, whatever the value type;
* every yielded VA comes from a key spelled in plain ASCII hex after the
  last dot, so a key that ``int()`` would have accepted through underscores,
  padding, or a non-ASCII digit set is skipped rather than read as an
  address nobody wrote;
* the module keeps every dot but the last one;
* ``section`` filtering is a subset of the unfiltered scan, and the
  ``fields`` dict is the caller's own object, not a copy.
"""

from __future__ import annotations

from typing import Any

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from rebrew.data_metadata import DATA_METADATA_FIELDS, iter_data_symbols

#: Characters ``int(s, 16)`` accepts beyond ASCII hex: an embedded
#: underscore, padding whitespace, a sign, and any Unicode decimal digit.
#: A key built from these reads as a different VA under ``int()``, which is
#: the misparse the parser must reject.
_LENIENT_CHARS = "_ \t+-٠۰۱۲۳۴۵۶۷۸۹०१२३४५६७८९"

_MODULES = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd", "Zs", "Po")),
    min_size=0,
    max_size=6,
)
_VA_HEX = st.text(alphabet="0123456789abcdefABCDEF", min_size=1, max_size=8)
_JUNK_VA = st.text(alphabet=_LENIENT_CHARS, min_size=1, max_size=4)
_SECTIONS = st.sampled_from([".data", ".bss", ".rdata", ".text", ""])
_FIELDS = st.dictionaries(
    st.sampled_from(list(DATA_METADATA_FIELDS) + ["not-a-field"]),
    st.one_of(
        st.text(max_size=12),
        st.integers(min_value=-(2**20), max_value=2**20),
        st.booleans(),
        st.none(),
    ),
    max_size=4,
)


def _canonical_keys() -> st.SearchStrategy[dict[str, dict[str, Any]]]:
    return st.dictionaries(
        st.tuples(_MODULES, st.just("."), _VA_HEX).map(lambda t: f"{t[0]}.{t[2]}"),
        st.fixed_dictionaries(
            {"section": _SECTIONS},
            optional={f: st.text(max_size=8) for f in DATA_METADATA_FIELDS if f != "section"},
        ),
        max_size=5,
    )


class TestIterDataSymbols:
    @given(
        doc=st.dictionaries(
            st.text(max_size=10),
            st.one_of(
                _FIELDS,
                st.text(max_size=6),
                st.integers(),
                st.none(),
                st.lists(st.text(max_size=4)),
            ),
            max_size=6,
        )
    )
    @settings(max_examples=200)
    def test_never_raises(self, doc: dict[str, Any]) -> None:
        """A malformed document is skipped, never fatal."""
        entries = list(iter_data_symbols(doc, None))
        assert len(entries) == len(list(iter_data_symbols(doc, section=None)))
        for module, va, fields in entries:
            assert isinstance(module, str)
            assert isinstance(va, int)
            assert va >= 0
            assert isinstance(fields, dict)

    @given(
        key=st.tuples(_MODULES, st.just("."), st.sampled_from(["", "0x", "0X"]), _VA_HEX).map(
            lambda t: f"{t[0]}.{t[2]}{t[3]}"
        ),
        doc=_canonical_keys(),
    )
    @settings(max_examples=200)
    def test_canonical_key_round_trips(self, key: str, doc: dict[str, Any]) -> None:
        """A key written as ``MODULE.VA`` or ``MODULE.0xVA`` reads back as that VA."""
        module, _, addr_text = key.rpartition(".")
        digits = addr_text[2:] if addr_text[:2].lower() == "0x" else addr_text
        merged = dict(doc)
        merged[key] = {"section": ".data"}
        assert (module, int(digits, 16), merged[key]) in list(iter_data_symbols(merged, None))

    @given(module=_MODULES, tail=_JUNK_VA, section=_SECTIONS)
    @settings(max_examples=200)
    def test_non_canonical_address_is_skipped(self, module: str, tail: str, section: str) -> None:
        """An address ``int()`` would read as hex digits is not an address.

        ``"MOD.1_0"``, ``"MOD. 0x10"``, ``"MOD.-4"`` and a non-ASCII digit
        each parse to a VA under ``int(s, 16)``.  Reading them would make a
        reloc resolve against an address the writer never named.
        """
        assume(module != "" and "." not in module)
        assume(any(ch in _LENIENT_CHARS for ch in tail))
        doc = {f"{module}.{tail}": {"section": section}}
        assert list(iter_data_symbols(doc, None)) == []

    @given(module=_MODULES)
    @settings(max_examples=100)
    def test_module_keeps_every_dot_but_the_last(self, module: str) -> None:
        """``MOD.SUB.0x10`` splits after the final dot, never the first."""
        assume(module != "")
        doc = {f"{module}.0x10": {"section": ".data"}}
        entries = list(iter_data_symbols(doc, None))
        if entries:
            assert entries[0][0] == module

    @given(
        doc=st.dictionaries(
            st.text(max_size=8), st.one_of(_FIELDS, st.text(max_size=4)), max_size=6
        ),
        section=_SECTIONS,
    )
    @settings(max_examples=200)
    def test_section_filter_is_a_subset(self, doc: dict[str, Any], section: str) -> None:
        """Filtering by section narrows the scan and never widens it."""
        assume(section != ".nonexistent")
        unfiltered = list(iter_data_symbols(doc, None))
        filtered = list(iter_data_symbols(doc, section))
        assert all(entry in unfiltered for entry in filtered)
        assert all(fields.get("section") == section for _, _, fields in filtered)
