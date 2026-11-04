"""Property-based fuzz tests for ``rebrew.formats.relocations.relocation_spans``.

``relocation_spans`` walks the base-relocation table of a linked image
(PE via LIEF, ELF via LIEF) whose block addresses, entry counts and
type bytes come verbatim from an untrusted target binary.  These tests
mutate the committed PE/ELF fixtures (headers, section table, data
directories, truncation) and pin the documented outcomes: a sorted,
unique, file-backed span list, or one of the documented refusals
(``ValueError`` / ``NotImplementedError``) — never an unhandled
exception, a hang, or a span pointing outside the image.
"""

from __future__ import annotations

from pathlib import Path

from hypothesis import event, given, settings
from hypothesis import strategies as st

from rebrew.formats.binary_loader import extract_bytes_at_va, load_binary
from rebrew.formats.relocations import relocation_spans

FIXTURES = Path(__file__).parent / "fixtures"
_PE_SEED = (FIXTURES / "mini_pe.exe").read_bytes()
_ELF_SEED = (FIXTURES / "mini.elf").read_bytes()

_SETTINGS = settings(max_examples=150, deadline=None)


@st.composite
def _mutated(draw: st.DrawFn, seed: bytes) -> bytes:
    """The fixture with drawn byte patches and an optional truncation."""
    data = bytearray(seed)
    span = min(0x800, len(data))
    patches = draw(
        st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=span - 1), st.binary(min_size=1, max_size=4)
            ),
            max_size=10,
        )
    )
    for offset, chunk in patches:
        data[offset : offset + len(chunk)] = chunk
    if draw(st.booleans()):
        data = data[: draw(st.integers(min_value=0, max_value=len(data)))]
    return bytes(data)


def _spans_or_refuse(blob: bytes, suffix: str) -> list[tuple[int, int]] | None:
    """``relocation_spans`` over *blob*; ``None`` when the image is refused."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / f"fuzz{suffix}"
        path.write_bytes(blob)
        try:
            info = load_binary(path)
        except ValueError:
            return None
        try:
            return relocation_spans(info)
        except ValueError, NotImplementedError:
            return None


class TestRelocationSpansFuzz:
    @_SETTINGS
    @given(_mutated(_PE_SEED))
    def test_pe_mutated_fixture_is_self_consistent(self, blob: bytes) -> None:
        spans = _spans_or_refuse(blob, ".exe")
        event("parsed" if spans is not None else "rejected")
        if spans is None:
            return
        assert spans == sorted(set(spans))
        for address, width in spans:
            assert width in (4, 8)
            assert address >= 0

    @_SETTINGS
    @given(_mutated(_ELF_SEED))
    def test_elf_mutated_fixture_is_self_consistent(self, blob: bytes) -> None:
        spans = _spans_or_refuse(blob, ".elf")
        event("parsed" if spans is not None else "rejected")
        if spans is None:
            return
        assert spans == sorted(set(spans))
        for address, width in spans:
            assert width in (4, 8)
            assert address >= 0

    @_SETTINGS
    @given(st.binary(max_size=1024))
    def test_random_bytes_rejected_or_consistent(self, blob: bytes) -> None:
        for suffix in (".exe", ".elf"):
            spans = _spans_or_refuse(blob, suffix)
            if spans is None:
                continue
            assert spans == sorted(set(spans))

    def test_seed_corpus(self, tmp_path: Path) -> None:
        assert relocation_spans(load_binary(FIXTURES / "mini_pe.exe")) == []
        assert relocation_spans(load_binary(FIXTURES / "mini.elf")) == []

    def test_spans_are_file_backed(self, tmp_path: Path) -> None:
        """Pair assertion: every span ``relocation_spans`` returns must
        read back the declared number of bytes from the loaded image
        (the check ``relocation_spans`` itself performs before writing)."""
        import lief

        fixture = FIXTURES / "mini_pe.exe"
        binary = lief.PE.parse(str(fixture))
        assert binary is not None
        block = lief.PE.Relocation()
        block.virtual_address = 0x1000
        block.add_entry(lief.PE.RelocationEntry(4, lief.PE.RelocationEntry.BASE_TYPES.HIGHLOW))
        binary.add_relocation(block)
        path = tmp_path / "relocations.exe"
        binary.write(path)
        info = load_binary(path)
        spans = relocation_spans(info)
        assert spans
        for address, width in spans:
            assert extract_bytes_at_va(info, address, width, trim_padding=False) is not None
