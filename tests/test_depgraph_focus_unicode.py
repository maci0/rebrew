"""Unicode folding of symbol names in the dependency graph's focus lookup."""

import unicodedata

from rebrew.depgraph import _focus_graph, _register_spellings
from rebrew.utils import fold_ident


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


def test_callee_spelling_folds_to_the_annotation_node() -> None:
    """A library header spelling the extern NFC reaches an NFD symbol."""
    nfd = unicodedata.normalize("NFD", "café")
    lookup: dict[str, str] = {}
    _register_spellings(lookup, nfd, "node-key")
    # The call site folds the callee exactly as build_graph does.
    assert lookup.get(fold_ident("café")) == "node-key"
    assert lookup.get(fold_ident("Café")) == "node-key"
    assert lookup.get(fold_ident("unknown_fn"), "unknown_fn") == "unknown_fn"


def test_callee_spelling_folds_case() -> None:
    lookup: dict[str, str] = {}
    _register_spellings(lookup, "straße", "node-key")
    assert lookup.get(fold_ident("STRASSE")) == "node-key"


def test_decorated_symbol_reaches_the_c_call() -> None:
    """A C call reaches a decorated symbol.

    ``lstrip("_")`` registered ``hook@@12`` and ``@keeps@4`` as
    themselves, so a call to ``hook`` or ``keeps`` missed the node.
    ``__foo`` was registered as ``foo``. A cdecl ``_bar`` still reaches
    ``bar``.
    """
    lookup: dict[str, str] = {}
    _register_spellings(lookup, "hook@@12", "hook-key")
    _register_spellings(lookup, "@keeps@4", "keeps-key")
    _register_spellings(lookup, "_sleepish@4", "sleep-key")
    _register_spellings(lookup, "__foo", "under-key")
    _register_spellings(lookup, "_bar", "bar-key")
    assert lookup.get(fold_ident("hook")) == "hook-key"
    assert lookup.get(fold_ident("keeps")) == "keeps-key"
    assert lookup.get(fold_ident("sleepish")) == "sleep-key"
    assert lookup.get(fold_ident("_foo")) == "under-key"
    assert lookup.get(fold_ident("foo")) != "under-key"
    assert lookup.get(fold_ident("bar")) == "bar-key"
