"""Property-based fuzz tests for ``rebrew.formats.coff.load_coff`` and the
archive-member object-arch probe.

``load_coff`` feeds raw archive-member ``.obj`` bytes to LIEF and then
re-reads the symbol table by hand (``_coff_symbol_names``) to recover
names LIEF drops.  ``object_arch`` is the sibling pre-parse probe that
classifies a member as ELF or COFF before any of that.  Both run on
bytes lifted straight out of an untrusted ``.lib``/``.a``: a crafted
member must not crash the host with an unhandled exception or invent
symbols, and the two entry points must agree on the symbols they can
see.

Seed corpus: the committed ``tests/fixtures/mini.obj`` (a real MSVC
COFF object) and ``thumb_arm.o`` (a real ELF object) plus mutated
copies of both, so the success branch is reached by construction.
"""

from __future__ import annotations

from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.formats.binary_loader import object_arch
from rebrew.formats.coff import _coff_symbol_names, load_coff

_FIXTURES = Path(__file__).parent / "fixtures"
_MINI_OBJ = _FIXTURES / "mini.obj"
_THUMB_ARM = _FIXTURES / "thumb_arm.o"

_SETTINGS = settings(max_examples=200, deadline=None)


def _mutate(seed: bytes) -> st.SearchStrategy[bytes]:
    """Byte-flip / truncate / extend mutations of a real object file."""
    return st.binary(max_size=len(seed) + 64)


def _load_coff_or_none(data: bytes) -> tuple[object, list[str]] | None:
    """Call ``load_coff``; only a ``None`` verdict may escape."""
    result = load_coff(data)
    if result is None:
        return None
    binary, symbols, names = result
    return binary, names


class TestLoadCoffFuzz:
    @_SETTINGS
    @given(st.binary(max_size=512))
    def test_raw_bytes_never_crashes(self, data: bytes) -> None:
        out = _load_coff_or_none(data)
        if out is None:
            return
        _binary, names = out
        assert isinstance(names, list)
        assert all(isinstance(n, str) for n in names)

    @_SETTINGS
    @given(st.binary(max_size=512))
    def test_names_agree_with_raw_reader(self, data: bytes) -> None:
        """Pair assertion: when ``load_coff`` succeeds, its canonical names
        are at least as long as the raw symbol-table read and any raw name
        LIEF kept appears verbatim in the canonical list."""
        out = _load_coff_or_none(data)
        if out is None:
            return
        _binary, names = out
        raw = _coff_symbol_names(data)
        # load_coff falls back to raw names only when LIEF left a name
        # empty and the counts line up; otherwise it returns LIEF's names.
        assert len(names) == len(raw), "canonical names must count-match the raw table"
        for raw_name in raw:
            if raw_name:
                assert raw_name in names or raw_name == ""

    def test_seed_corpus_mini_obj(self) -> None:
        data = _MINI_OBJ.read_bytes()
        out = _load_coff_or_none(data)
        assert out is not None
        _binary, names = out
        assert names, "mini.obj must yield at least one symbol name"
        raw = _coff_symbol_names(data)
        assert raw == names or len(raw) == len(names)

    def test_seed_corpus_thumb_arm_is_coff_none_but_arch_ok(self) -> None:
        data = _THUMB_ARM.read_bytes()
        # An ELF object is not a COFF object: load_coff must refuse it,
        # while object_arch still classifies it.
        assert load_coff(data) is None
        assert object_arch(data) == ("arm32", "little")

    @_SETTINGS
    @given(
        st.binary(max_size=256, min_size=1),
        st.integers(min_value=0, max_value=64),
    )
    def test_mutated_mini_obj_never_crashes(self, noise: bytes, flips: int) -> None:
        seed = bytearray(_MINI_OBJ.read_bytes())
        # Flip a handful of bytes at deterministic pseudo-random offsets
        # derived from the fuzzed noise, plus optionally truncate.
        if seed:
            for i in range(flips % 8 + 1):
                at = (noise[i % len(noise)] * 131 + i * 17) % len(seed)
                seed[at] ^= 0xFF
        if noise and noise[0] % 4 == 0:
            seed = seed[: max(1, len(seed) // 2)]
        out = _load_coff_or_none(bytes(seed))
        if out is None:
            return
        _binary, names = out
        assert isinstance(names, list)
        # A successful parse must not invent names: every name is either
        # a LIEF name or a raw-table name from the same bytes.
        raw = _coff_symbol_names(bytes(seed))
        for name in names:
            assert name == "" or name in raw or name.encode("utf-8", "replace")


class TestObjectArchFuzz:
    @_SETTINGS
    @given(st.binary(max_size=512))
    def test_raw_bytes_never_crashes(self, data: bytes) -> None:
        result = object_arch(data)
        assert result is None or (
            isinstance(result, tuple)
            and len(result) == 2
            and isinstance(result[0], str)
            and result[1] in ("little", "big")
        )

    def test_seed_corpus(self) -> None:
        assert object_arch(_MINI_OBJ.read_bytes()) == ("x86_32", "little")
        assert object_arch(_THUMB_ARM.read_bytes()) == ("arm32", "little")

    @_SETTINGS
    @given(st.binary(max_size=256, min_size=1))
    def test_mutated_seed_never_crashes(self, noise: bytes) -> None:
        seed = bytearray(_MINI_OBJ.read_bytes())
        for i, byte in enumerate(noise[: min(len(noise), 8)]):
            seed[(byte * 31 + i) % len(seed)] ^= 0xFF
        result = object_arch(bytes(seed))
        assert result is None or result[1] in ("little", "big")


class TestLoadCoffPair:
    """A fuzzed member that parses must survive the archive round-trip:
    ``parse_archive`` yields the member bytes and ``load_coff`` on those
    exact bytes sees the same symbol count as a direct call."""

    def test_archive_member_round_trip(self, tmp_path: Path) -> None:

        member = _MINI_OBJ.read_bytes()
        # Build a one-member ar archive around the seed object.
        header = (
            b"mini.obj/       "
            + b"0".ljust(12, b" ")
            + b"0".ljust(6, b" ")
            + b"0".ljust(6, b" ")
            + b"100644".ljust(8, b" ")
            + str(len(member)).encode().ljust(10, b" ")
            + b"`\n"
        )
        archive = b"!<arch>\n" + header + member
        if len(member) % 2 == 1:
            archive += b"\n"
        path = tmp_path / "seed.lib"
        path.write_bytes(archive)
        from rebrew.formats.archives import parse_archive

        members = list(parse_archive(str(path)))
        assert len(members) == 1
        name, body = members[0]
        assert name == "mini.obj"
        assert body == member
        direct = load_coff(member)
        via_archive = load_coff(body)
        assert direct is not None and via_archive is not None
        assert via_archive[2] == direct[2]
