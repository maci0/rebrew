"""Unicode folding of symbol names in the dependency graph's focus lookup."""

import unicodedata

from rebrew.depgraph import _focus_graph


def _nodes(*names):
    return {
        n: {"status": "EXACT", "va": 0x1000 + i, "size": 0, "file": "", "symbol": n}
        for i, n in enumerate(names)
    }


def test_focus_resolves_nfd_symbol_from_nfc_input() -> None:
    nfd = unicodedata.normalize("NFD", "café")
    assert nfd != "café"
    nodes = _nodes(nfd, "other")
    got, _edges, _de = _focus_graph(nodes, [(nfd, "other")], "café")
    assert nfd in got


def test_focus_resolves_sharp_s_spelling() -> None:
    nodes = _nodes("straße", "other")
    got, _edges, _de = _focus_graph(nodes, [("straße", "other")], "STRASSE")
    assert "straße" in got


def test_focus_still_resolves_plain_name_and_va() -> None:
    nodes = _nodes("main", "helper")
    edges = [("main", "helper")]
    got, ge, _de = _focus_graph(nodes, edges, "main")
    assert set(got) == {"main", "helper"}
    assert ge == edges
    got_va, _, _ = _focus_graph(nodes, edges, "0x1000")
    assert "main" in got_va
