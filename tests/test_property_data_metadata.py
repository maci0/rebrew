"""Property checks for current-only qualified data documents and isolated reads."""

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.metadata.data import iter_data_symbols
from rebrew.metadata.document import qualified_key


class TestDataDocuments:
    @given(
        module=st.sampled_from(["SERVER", "CLIENT", "a.b", "srv.0x10", "café"]),
        va=st.integers(min_value=0, max_value=2**64 - 1),
        section=st.sampled_from([".data", ".rdata", ".bss"]),
        size=st.integers(min_value=0, max_value=2**30),
    )
    def test_qualified_rows_round_trip_and_filter(
        self, module: str, va: int, section: str, size: int
    ) -> None:
        fields = {"name": "g", "size": size, "section": section}
        doc = {"format": 2, qualified_key(module, va): fields}
        assert list(iter_data_symbols(doc, None)) == [(module, va, fields)]
        assert list(iter_data_symbols(doc, section)) == [(module, va, fields)]
        assert list(iter_data_symbols(doc, ".text")) == []
        returned = next(iter_data_symbols(doc, None))[2]
        returned["name"] = "changed"
        assert fields["name"] == "g"

    @given(
        st.dictionaries(
            st.text(max_size=12), st.one_of(st.none(), st.integers(), st.text()), max_size=6
        )
    )
    @settings(max_examples=200)
    def test_untrusted_documents_are_valid_or_explicitly_rejected(
        self, doc: dict[str, Any]
    ) -> None:
        try:
            entries = list(iter_data_symbols(doc, None))
        except ValueError:
            return
        assert doc.get("format") == 2
        assert all(
            module and va >= 0 and isinstance(fields, dict) for module, va, fields in entries
        )

    @pytest.mark.parametrize(
        "key",
        ["0x1000", "SERVER.1000", "SERVER.0x1_0", "SERVER.0x١0", "SERVER.0x-4", "SERVER.0x10 "],
    )
    def test_old_or_non_ascii_address_shapes_are_rejected(self, key: str) -> None:
        with pytest.raises(ValueError, match="MODULE.0xVA"):
            list(iter_data_symbols({"format": 2, key: {"size": 4}}, None))

    @given(va=st.integers(min_value=1, max_value=2**32 - 1))
    def test_duplicate_spellings_fail_instead_of_merging(self, va: int) -> None:
        doc = {"format": 2, f"S.0x{va:08x}": {"size": 4}, f"S.0X{va:X}": {"name": "alias"}}
        with pytest.raises(ValueError, match="duplicate"):
            list(iter_data_symbols(doc, None))

    @pytest.mark.parametrize("field", ["marker_type", "bogus", "SIZE"])
    def test_unknown_and_retired_fields_are_rejected(self, field: str) -> None:
        with pytest.raises(ValueError):
            list(iter_data_symbols({"format": 2, "S.0x1000": {field: 4}}, None))
