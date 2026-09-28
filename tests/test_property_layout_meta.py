"""Property-based fuzz tests for ``rebrew.layout_meta`` on untrusted images.

``extract_layout`` is the whole of ``rebrew gen-layout``: it walks a reference
PE the user points the CLI at and pulls the import directory, the export
directory, the ``.reloc`` block chain and two sparse ``.text`` maps out of it.
Every count, RVA, offset and string length in that walk is read straight out
of the file, so all of them are forgeable, and the walk is the one place where
a forged count walks off the end of the buffer or loops on a self-referential
block chain.  The harnesses below feed ``test_postlink.make_full_pe`` -- a PE
carrying real imports, an export directory and a relocation block, so every
success branch is reachable -- with byte patches over the header, section
table, data directories and block chains, plus truncations and raw random
bytes, and assert:

* the only failure mode is ``ValueError`` -- never ``struct.error``,
  ``IndexError``, ``StopIteration`` or an unbounded walk;
* an extracted layout is self-consistent: the stored header is a prefix of
  the file, every sparse ``.text`` offset lies inside the ``.text`` raw size
  the same run just read, and an export VA is image-relative;
* the package survives the persistence boundary: what
  :func:`write_package` renders to disk, :func:`load_package` reads back is
  the layout that was extracted (a pair assertion across the text package).
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from test_postlink import make_full_pe

from rebrew.gen_layout import fmt_layout_toml
from rebrew.layout_meta import extract_layout, load_package, write_package
from rebrew.pe_headers import pe_header

#: Patches land in the header block, which is where the parser branches.
_MUTATE_SPAN = 0x400
#: Truncation cuts land around the header/section-table boundary.
_TRUNCATE_MIN = 0x20


def _seed_pe() -> bytes:
    """A PE with every structure ``extract_layout`` reads."""
    return make_full_pe(
        code=b"\xc3" + b"\x55\x8b\xec" * 64,
        imports=[("KERNEL32.dll", ["GetLocalTime", "WriteFile"]), ("USER32.dll", ["MessageBoxA"])],
        data=bytes(range(64)),
        reloc_bytes=struct.pack("<II", 0x1000, 8) + struct.pack("<HH", 0x3020, 0),
    )


_SEED = _seed_pe()

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


@pytest.fixture(scope="module")
def pkg_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Module-scoped scratch dir: hypothesis rejects function-scoped fixtures."""
    return tmp_path_factory.mktemp("layout_meta_fuzz")


#: RVA/size fields the walker branches on: the section table and the 16 data
#: directories.  Patching the whole header span instead rejects ~2/3 of the
#: drawn images at ``pe_header`` and the success paths never get reached.
_HOT_SPANS: list[tuple[int, int]] = []
#: Index of the data-directory span in ``_HOT_SPANS`` (the branch fields).
_DATA_DIR_SPAN = 1


def _init_hot_spans() -> None:
    e = struct.unpack_from("<I", _SEED, 0x3C)[0]
    nsec = struct.unpack_from("<H", _SEED, e + 6)[0]
    opt = e + 24
    optsz = struct.unpack_from("<H", _SEED, e + 20)[0]
    _HOT_SPANS.append((opt, opt + optsz))  # optional header: image base, sizes
    _HOT_SPANS.append((opt + 96, opt + 96 + 16 * 8))  # data directories
    _HOT_SPANS.append((opt + optsz, opt + optsz + 40 * nsec))  # section table


_init_hot_spans()


@st.composite
def _images(draw: st.DrawFn) -> bytes:
    """The seed PE with drawn byte patches, an optional truncation, or noise."""
    kind = draw(st.integers(min_value=0, max_value=2))
    if kind == 2:
        return draw(st.binary(max_size=4096))

    data = bytearray(_SEED)
    for _ in range(draw(st.integers(min_value=1, max_value=12))):
        if draw(st.booleans()):
            off = draw(st.integers(min_value=0, max_value=min(_MUTATE_SPAN, len(data)) - 1))
        else:
            lo, hi = draw(st.sampled_from(_HOT_SPANS))
            off = draw(st.integers(min_value=lo, max_value=hi - 1))
        data[off] = draw(st.integers(min_value=0, max_value=255))
    if kind == 1:
        return bytes(data[: draw(st.integers(min_value=_TRUNCATE_MIN, max_value=len(data)))])
    return bytes(data)


@st.composite
def _surviving_images(draw: st.DrawFn) -> bytes:
    """Images that survive ``extract_layout``, with the branch fields patched.

    Patching the data directories perturbs every RVA the walker follows
    (import, export, IAT) without disturbing the header geometry that
    ``pe_header`` gates on, so the success paths stay reachable instead of
    being filtered out.
    """
    data = bytearray(_SEED)
    for _ in range(draw(st.integers(min_value=1, max_value=6))):
        lo, hi = _HOT_SPANS[_DATA_DIR_SPAN]
        off = draw(st.integers(min_value=lo, max_value=hi - 1))
        data[off] = draw(st.integers(min_value=0, max_value=255))
    out = bytes(data)
    try:
        extract_layout(out)
    except ValueError:
        assume(False)
    return out


@settings(max_examples=200, deadline=None)
@given(_images())
def test_extract_layout_fails_only_with_valueerror(data: bytes) -> None:
    """A forged image is rejected, never crashed on.

    ``gen-layout`` catches ``ValueError`` and turns it into ``error_exit``;
    any other exception is a traceback on the user's terminal.
    """
    try:
        extract_layout(data, "fuzz.dll")
    except ValueError:
        return


@settings(max_examples=100, deadline=None)
@given(_surviving_images())
def test_extracted_layout_is_self_consistent(data: bytes) -> None:
    """What the extractor reports agrees with the bytes it was handed."""
    meta = extract_layout(data, "fuzz.dll")

    assert meta.target == "fuzz.dll"
    assert data.startswith(meta.header), "stored header is not a prefix of the file"
    assert len(meta.header) <= len(data)

    text = meta.section(".text")
    text_len = len(data[text.raw_ptr : text.raw_ptr + text.raw])
    assert all(off < text_len for off in meta.operands), "operand offset past .text raw end"
    assert all(off < text_len for off in meta.calls), "call offset past .text raw end"

    assert all(e["va"] >= meta.image_base for e in meta.exports)
    assert len(meta.reloc) <= len(data)


@settings(max_examples=50, deadline=None)
@given(_surviving_images())
def test_layout_package_round_trips(pkg_dir: Path, data: bytes) -> None:
    """The text package is a faithful persistence of the extracted layout."""
    meta = extract_layout(data, "fuzz.dll")
    write_package(meta, pkg_dir, fmt_toml=lambda m: fmt_layout_toml(m, [], []))

    loaded = load_package(pkg_dir)
    assert loaded.header == meta.header
    assert loaded.iat == meta.iat
    assert loaded.prefix == meta.prefix
    assert loaded.bookkeeping == meta.bookkeeping
    assert loaded.data == meta.data
    assert loaded.reloc == meta.reloc
    assert loaded.operands == meta.operands
    assert loaded.calls == meta.calls
    assert loaded.image_base == meta.image_base
    assert loaded.exp_rva == meta.exp_rva
    assert loaded.export_stamp == meta.export_stamp
    assert [s.as_dict() for s in loaded.sections] == [s.as_dict() for s in meta.sections]
    assert [i.as_dict() for i in loaded.imports] == [i.as_dict() for i in meta.imports]


@settings(max_examples=100, deadline=None)
@given(_images())
def test_parse_pe_geometry_matches_extract(data: bytes) -> None:
    """``pe_header`` is the gate ``extract_layout`` reads its geometry from."""
    try:
        extract_layout(data, "fuzz.dll")
    except ValueError:
        return
    e, nsec, optsz, opt, image_base = pe_header(data)
    assert opt + optsz + 40 * nsec <= len(data)
    assert struct.unpack_from("<I", data, opt + 28)[0] == image_base
