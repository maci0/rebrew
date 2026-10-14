"""Property checks for address-only source binding and explicit parse failures."""

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.metadata.anchors import add_address_anchor, parse_address_anchors


class TestAddressProperties:
    @given(
        st.integers(min_value=0, max_value=2**64 - 1),
        st.sampled_from(["S", "SERVER", "CLIENT_2", "GAME.EXE"]),
    )
    def test_round_trip(self, va: int, module: str) -> None:
        source = add_address_anchor("int f(void) { return 3; }\n", module, va, "f")
        anchors = parse_address_anchors(source)
        assert [(a.module, a.va, a.name) for a in anchors] == [(module, va, "f")]
        assert add_address_anchor(source, module, va, "f") == source

    @settings(max_examples=150)
    @given(st.text(max_size=500))
    def test_arbitrary_source_returns_bindings_or_explicit_error(self, source: str) -> None:
        try:
            anchors = parse_address_anchors(source)
        except ValueError:
            return
        assert all(a.kind in {"FUNCTION", "DATA"} and a.definition_line > a.line for a in anchors)
