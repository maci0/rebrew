"""Property-based fuzz tests for the metadata TOML readers.

``rebrew-functions.toml`` and ``rebrew-data.toml`` are read on nearly every
CLI path through :func:`load_metadata_doc`, and a parse failure there is
swallowed into an empty table, so a malformed file does not crash: it makes
the whole store look empty and every entry recompile.  The harnesses below
feed the reader raw text (well-formed tables, junk, control characters,
truncations) and assert the invariants a caller depends on:

* the reader never raises and every key it returns is a qualified
  ``(module, va)`` with a non-negative ``int`` VA;
* the qualified-key algebra round-trips: ``qualified_key`` output re-parses
  to the NFC-normalized module and the same VA, and a resolved key always
  parses back to the ``(module, va)`` it was asked for;
* crossing the write boundary, everything a caller writes with
  ``build_metadata_doc`` + ``tomlkit.dumps`` reads back identically through
  ``load_metadata_doc`` (the before-write/after-read pair);
* the two spellings of one VA merge instead of splitting the fields.
"""

from __future__ import annotations

import tempfile
import unicodedata
from pathlib import Path
from typing import Any

import tomlkit
from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.metadata_doc import (
    MetadataDocCache,
    build_metadata_doc,
    build_metadata_key_index,
    canonical_va_key,
    load_metadata_doc,
    parse_metadata_doc,
    parse_metadata_key,
    qualified_key,
    resolve_metadata_key,
)
from rebrew.utils import toml_safe

_CANONICAL_ORDER = ("STATUS", "SIZE", "CFLAGS", "TOOLCHAIN", "BLOCKER")

# Module names: plain, NFD (a macOS-written key), empty, and one carrying a
# dot, which is the separator the key algebra splits on.
_modules = st.one_of(
    # "srv.0x10" pins the VA-suffix split: the module carries the ``.0x``
    # marker itself, so a first-occurrence split drops the entry.
    st.sampled_from(["", "SERVER", "CLIENT", "a.b", "..0x", "0x0", "srv.0x10"]),
    st.text(alphabet=st.characters(min_codepoint=1, max_codepoint=0x2FF), max_size=6),
)
_vas = st.integers(min_value=0, max_value=0xFFFFFFFF)
_values = st.one_of(
    st.integers(),
    st.booleans(),
    st.text(max_size=12),
    st.text(alphabet=st.characters(min_codepoint=1, max_codepoint=0x1F), max_size=8),
)
_fields = st.sampled_from(_CANONICAL_ORDER + ("CFLAGSS", "TOOLCHIAN", "x"))
#: Modules that name an entry.  ``qualified_key`` spells a module-less entry
#: as a bare VA, and the readers accept only the qualified form, so the two
#: tests that need a read-back restrict themselves to a non-empty module (see
#: :meth:`TestKeyAlgebra.test_module_less_key_is_write_only`).
_named_modules = _modules.filter(bool)
#: Modules the writers can serialize: a control character in the target name
#: makes the key unreadable rather than re-homed, which
#: :meth:`TestDocumentReader.test_control_character_key_fails_loudly` pins.
_serializable_modules = _named_modules.filter(
    lambda m: all(ord(ch) >= 0x20 or ch in "\t\n" for ch in m)
)


def _entry() -> st.SearchStrategy[dict[str, Any]]:
    return st.dictionaries(_fields, _values, min_size=1, max_size=4)


@st.composite
def _store(draw: st.DrawFn) -> dict[tuple[str, int], dict[str, Any]]:
    return {
        draw(st.tuples(_serializable_modules, _vas)): draw(_entry())
        for _ in range(draw(st.integers(0, 4)))
    }


def _load(path: Path, tmp_root: Path, name: str) -> dict[tuple[str, int], dict[str, Any]]:
    cache: MetadataDocCache = {}
    return load_metadata_doc(path, cache, name, deepcopy=False)


class TestKeyAlgebra:
    def test_qualified_key_round_trips(self) -> None:
        @given(module=_named_modules, va=_vas)
        @settings(max_examples=200)
        def check(module: str, va: int) -> None:
            parsed = parse_metadata_key(qualified_key(module, va))
            assert parsed == (unicodedata.normalize("NFC", module), va)

        check()

    def test_module_less_key_is_write_only(self) -> None:
        @given(va=_vas)
        @settings(max_examples=100)
        def check(va: int) -> None:
            bare = qualified_key(None, va)
            assert bare == f"0x{va:08x}"
            assert parse_metadata_key(bare) is None
            assert parse_metadata_doc({bare: {"STATUS": "EXACT"}}) == {}

        check()

    def test_resolved_key_parses_to_the_requested_entry(self) -> None:
        @given(module=_named_modules, va=_vas)
        @settings(max_examples=200)
        def check(module: str, va: int) -> None:
            doc = {qualified_key(module, va): {}, "OTHER.0x10": {}}
            resolved = resolve_metadata_key(doc, module, va)
            assert resolved in doc
            assert parse_metadata_key(resolved) == parse_metadata_key(qualified_key(module, va))

        check()

    def test_canonical_va_key_is_idempotent(self) -> None:
        @given(va=st.one_of(_vas, st.text(max_size=8), st.integers()))
        @settings(max_examples=200)
        def check(va: Any) -> None:
            once = canonical_va_key(va)
            assert canonical_va_key(once) == once

        check()

    def test_duplicate_spellings_merge_into_one_entry(self) -> None:
        @given(module=_named_modules, va=_vas, a=_entry(), b=_entry())
        @settings(max_examples=200)
        def check(module: str, va: int, a: dict[str, Any], b: dict[str, Any]) -> None:
            want = parse_metadata_key(qualified_key(module, va))
            assert want is not None
            doc = {f"{module}.0x{va:x}": dict(a), qualified_key(module, va): dict(b)}
            parsed = parse_metadata_doc(doc)
            assert list(parsed) == [want]
            entry = parsed[want]
            for field, value in b.items():
                assert entry[field] == value

        check()


class TestDocumentReader:
    def test_arbitrary_file_text_never_raises(self, tmp_path: Path) -> None:
        @given(text=st.text(max_size=200), use_raw=st.booleans(), raw=st.binary(max_size=200))
        @settings(max_examples=200, deadline=None)
        def check(text: str, use_raw: bool, raw: bytes) -> None:
            # A fresh directory per example: the reader caches per resolved
            # path behind an (mtime, size, inode) fingerprint, so rewriting one
            # path in place can serve the previous example's table.
            root = Path(tempfile.mkdtemp(dir=tmp_path))
            path = root / "rebrew-functions.toml"
            if use_raw:
                path.write_bytes(raw)
            else:
                path.write_bytes(text.encode("utf-8", "surrogatepass"))
            loaded = _load(path, tmp_path, "metadata")
            for module, va in loaded:
                assert isinstance(module, str)
                assert isinstance(va, int) and va >= 0
                assert parse_metadata_key(qualified_key(module, va)) == (module, va)

        check()

    def test_written_entries_read_back_identically(self, tmp_path: Path) -> None:
        @given(store=_store())
        @settings(max_examples=200, deadline=None)
        def check(store: dict[tuple[str, int], dict[str, Any]]) -> None:
            root = Path(tempfile.mkdtemp(dir=tmp_path))
            safe = {k: {f: toml_safe(v) for f, v in e.items()} for k, e in store.items()}
            path = root / "rebrew-functions.toml"
            path.write_text(tomlkit.dumps(build_metadata_doc(safe, _CANONICAL_ORDER)))
            loaded = _load(path, tmp_path, "metadata")
            assert set(loaded) == set(store)
            for key, entry in loaded.items():
                assert entry == safe[key]

        check()

    def test_control_character_key_fails_loudly(self, tmp_path: Path) -> None:
        """A control character in a target name is not a serialization fix.

        ``toml_safe`` strips controls from field values, but rewriting a KEY
        would re-home the entry: the sanitized key parses to a different
        ``(module, va)``, so a write that looked successful would read back
        as a miss.  The write stays unsanitized and the read reports the
        file as unparseable, which is a warning naming the file rather than
        a silent lookup failure.
        """
        path = tmp_path / "rebrew-functions.toml"
        store = {("SRV\x1b", 0x24000): {"STATUS": "EXACT"}}
        path.write_text(tomlkit.dumps(build_metadata_doc(store, _CANONICAL_ORDER)))
        assert _load(path, tmp_path, "metadata") == {}

    def test_key_index_matches_the_linear_scan(self) -> None:
        @given(modules=st.lists(_named_modules, min_size=1, max_size=4), va=_vas)
        @settings(max_examples=200)
        def check(modules: list[str], va: int) -> None:
            doc = {qualified_key(m, va): {} for m in modules}
            key_index = build_metadata_key_index(doc)
            for module in modules:
                wanted = parse_metadata_key(qualified_key(module, va))
                assert wanted is not None
                linear = resolve_metadata_key(doc, module, va)
                indexed = resolve_metadata_key(doc, module, va, index=key_index)
                assert parse_metadata_key(linear) == wanted
                assert parse_metadata_key(indexed) == wanted

        check()
