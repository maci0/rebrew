"""Property-based fuzzing for the post-link layout-coverage mapper.

``postlink.map_coverage`` reads a 4-byte value at a ``.text``-relative offset
taken from a layout package — offsets and values that come out of a target
binary and a ``rebrew-layout.toml``, both untrusted.  A forged offset either
lands outside the built image or inside a different instruction, and a forged
section table moves the ``.rdata``/``.data`` spans the reference test compares
against.  ``check_text_alignment`` then turns the ratio into a build break.

The harnesses below pair a built image with a layout package whose every field
is drawable, and assert:

* a forged offset or a truncated image never escapes as ``struct.error`` or
  ``IndexError`` — an unreadable dword is skipped, not fatal;
* the counters are well formed: each is within ``[0, total]``, and the totals
  are exactly the number of layout-map entries handed in;
* every count that lands is explained — an entry past the end of the built
  image cannot be counted, and a call context only validates when the recorded
  two-byte prefix and suffix really sit either side of the dword (a pair
  assertion across the map's read side);
* ``check_text_alignment`` accepts exactly when the coverage it computes is at
  or above the published floor.
"""

from __future__ import annotations

import contextlib
import shutil
import struct
import tempfile
from pathlib import Path
lazy from collections.abc import Callable

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st
from memory_cap import address_space_cap
from test_postlink import (
    FORGED_HEADER_CASES,
    FORGED_PACKAGE_CASES,
    PackageEdit,
    apply_package_edit,
    forge_pe,
    make_full_pe,
    operand_seed,
    write_pkg,
)

from rebrew.buildsys.layout_meta import LayoutMetadata, SectionMeta
from rebrew.buildsys.postlink import FIXER_ORDER as FIXER_NAMES
from rebrew.formats.binary_model import BinaryInfo, SectionInfo

_u16 = st.integers(min_value=0, max_value=0xFFFF)
_u32 = st.integers(min_value=0, max_value=0xFFFFFFFF)
#: The opcode a call-map row records before its dword, or none.
_CALL_OPCODE = st.sampled_from((None, 0xE8, 0xE9))


def _meta_and_info(
    text_off: int,
    text_vs: int,
    operands: dict[int, int],
    calls: dict[int, tuple[int, int, int, int | None]],
) -> tuple[LayoutMetadata, BinaryInfo]:
    """A layout package holding only the named layout-map entries, paired with
    a ``BinaryInfo`` whose ``.text`` starts at *text_off* in a built image."""
    sections = [
        SectionMeta(name=".text", va=0, vs=text_vs, raw=text_vs, raw_ptr=text_off, chars=0),
        SectionMeta(name=".rdata", va=0x2000, vs=0, raw=0, raw_ptr=0, chars=0),
        SectionMeta(name=".data", va=0x3000, vs=0, raw=0, raw_ptr=0, chars=0),
    ]
    meta = LayoutMetadata(
        target="fuzz",
        image_base=0,
        link_options=[],
        sections=sections,
        exports=[],
        imports=[],
        header=b"",
        iat=b"",
        prefix=b"",
        bookkeeping=b"",
        data=b"",
        reloc=b"",
        operands=operands,
        calls=calls,
        exp_rva=0,
        export_stamp=(0, 0),
    )
    info = BinaryInfo(path=Path("built"), format="pe")
    info.sections = {
        ".text": SectionInfo(
            name=".text", va=0, size=text_vs, file_offset=text_off, raw_size=text_vs
        )
    }
    return meta, info


@st.composite
def _layout_and_built(draw: st.DrawFn) -> tuple[bytes, LayoutMetadata, BinaryInfo]:
    """A built image, a layout package describing it, and the ``BinaryInfo``
    the mapper reads sections from.

    ``text_off`` puts the built ``.text`` at an arbitrary file offset (often
    past EOF, which the mapper must tolerate), and the operand/call offsets are
    drawn from a range that spans both in-bounds and out-of-bounds positions.
    """
    built = draw(st.binary(min_size=0, max_size=512))
    text_off = draw(st.integers(min_value=0, max_value=len(built) + 8))
    text_vs = draw(st.integers(min_value=0, max_value=max(1, len(built))))
    rdata_va = draw(_u32)
    rdata_vs = draw(st.integers(min_value=0, max_value=0x10000))
    data_va = draw(_u32)
    data_vs = draw(st.integers(min_value=0, max_value=0x10000))
    image_base = draw(st.sampled_from([0, 0x400000, draw(_u32)]))

    sections = [
        SectionMeta(name=".text", va=0, vs=text_vs, raw=text_vs, raw_ptr=text_off, chars=0),
        SectionMeta(name=".rdata", va=rdata_va, vs=rdata_vs, raw=rdata_vs, raw_ptr=0, chars=0),
        SectionMeta(name=".data", va=data_va, vs=data_vs, raw=data_vs, raw_ptr=0, chars=0),
    ]

    n_operands = draw(st.integers(min_value=0, max_value=6))
    n_calls = draw(st.integers(min_value=0, max_value=4))
    operands = {
        draw(st.integers(min_value=0, max_value=max(0, len(built)) + 8)): draw(_u32)
        for _ in range(n_operands)
    }
    calls = {
        draw(st.integers(min_value=0, max_value=max(0, len(built)) + 8)): (
            draw(_u32),
            draw(_u16),
            draw(_u16),
            draw(_CALL_OPCODE),
        )
        for _ in range(n_calls)
    }

    meta = LayoutMetadata(
        target="fuzz",
        image_base=image_base,
        link_options=[],
        sections=sections,
        exports=[],
        imports=[],
        header=b"",
        iat=b"",
        prefix=b"",
        bookkeeping=b"",
        data=b"",
        reloc=b"",
        operands=operands,
        calls=calls,
        exp_rva=0,
        export_stamp=(0, 0),
    )
    info = BinaryInfo(path=Path("built"), format="pe", image_base=image_base)
    info.sections = {
        ".text": SectionInfo(
            name=".text",
            va=0,
            size=text_vs,
            file_offset=text_off,
            raw_size=max(0, len(built) - text_off),
        )
    }
    return built, meta, info


@settings(max_examples=300, deadline=None)
@given(_layout_and_built())
def test_map_coverage_counts_are_well_formed(
    data: tuple[bytes, LayoutMetadata, BinaryInfo],
) -> None:
    """Fuzz: a forged layout package against an arbitrary built image.  The
    mapper never raises on a dword it cannot read, and every counter it
    returns is bounded by the number of entries it was asked about."""
    from rebrew.buildsys.postlink import map_coverage

    built, meta, info = data
    op_ok, op_total, call_ok, call_total = map_coverage(built, meta, info)
    assert op_total == len(meta.operands)
    assert call_total == len(meta.calls)
    assert 0 <= op_ok <= op_total
    assert 0 <= call_ok <= call_total


@settings(max_examples=300, deadline=None)
@given(st.integers(min_value=0, max_value=0x400), st.integers(min_value=0, max_value=64))
def test_map_coverage_skips_unreadable_dwords(built_size: int, slack: int) -> None:
    """Every layout-map entry whose dword starts at or past the end of the
    built image is skipped, so a package full of out-of-range offsets scores
    zero rather than raising or counting a read it never made."""
    from rebrew.buildsys.postlink import map_coverage

    built = bytes(built_size)
    off = built_size + slack
    meta, info = _meta_and_info(off, len(built), {0: 0xDEADBEEF}, {0: (0xDEADBEEF, 0, 0, 0xE8)})
    assert map_coverage(built, meta, info) == (0, 1, 0, 1)


@settings(max_examples=200, deadline=None)
@given(st.binary(min_size=8, max_size=256), _u16, _u16)
def test_map_coverage_validates_a_call_context(built: bytes, pre: int, suf: int) -> None:
    """Pair assertion across the map's read side: a call entry whose dword does
    not hold the reference value still validates when the two-byte context the
    package recorded really sits either side of it, and does not when the
    preceding byte is not a call opcode."""
    from rebrew.buildsys.postlink import map_coverage

    off = 3
    val = 0xDEADBEEF
    body = bytearray(built)
    body[off : off + 4] = struct.pack("<I", val ^ 0xFFFFFFFF)
    body[off - 3 : off - 1] = pre.to_bytes(2, "big")
    body[off + 4 : off + 6] = suf.to_bytes(2, "big")

    for opcode, expected in ((0xE8, 1), (0xE9, 0), (0x90, 0)):
        body[off - 1] = opcode
        meta, info = _meta_and_info(0, len(bytes(body)), {}, {off: (val, pre, suf, 0xE8)})
        assert map_coverage(bytes(body), meta, info) == (0, 0, expected, 1)


@settings(max_examples=200, deadline=None)
@given(_layout_and_built())
def test_check_text_alignment_agrees_with_coverage(
    data: tuple[bytes, LayoutMetadata, BinaryInfo],
) -> None:
    """``check_text_alignment`` breaks the build on exactly the ratios below the
    published floor, and stays silent on a package with no layout-map entries
    at all."""
    from rebrew.buildsys.postlink import MIN_LAYOUT_MAP_COVERAGE, check_text_alignment, map_coverage

    built, meta, info = data
    op_ok, op_total, call_ok, call_total = map_coverage(built, meta, info)
    total = op_total + call_total
    aligned = total == 0 or (op_ok + call_ok) / total >= MIN_LAYOUT_MAP_COVERAGE
    if aligned:
        check_text_alignment(built, meta, info)
    else:
        with pytest.raises(ValueError, match="position-aligned"):
            check_text_alignment(built, meta, info)


# ---------------------------------------------------------------------------
# The whole fixer chain over a mutated PE pair
# ---------------------------------------------------------------------------


#: A four-section PE with imports, exports and a relocation block.
_SEED_PE = make_full_pe(
    imports=[("KERNEL32.dll", ["GetLocalTime", "WriteFile"]), ("USER32.dll", ["MessageBoxA"])],
    timestamp=0x60000000,
    checksum=0x4D328,
)


#: Patch window: the DOS stub, COFF/optional headers, the section table and the
#: two data directories — the fields every fixer's precondition reads.  Past it
#: lies section content whose corruption only produces ordinary mismatches.
_MUTATE_SPAN = 0x800


@st.composite
def _mutated_pe(draw: st.DrawFn) -> bytes:
    """The seed PE with drawn byte patches and an optional truncation."""
    data = bytearray(_SEED_PE)
    span = min(_MUTATE_SPAN, len(data))
    for offset, chunk in draw(
        st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=span - 1), st.binary(min_size=1, max_size=4)
            ),
            max_size=10,
        )
    ):
        data[offset : offset + len(chunk)] = chunk
    if draw(st.booleans()):
        data = data[: draw(st.integers(min_value=0, max_value=len(data)))]
    return bytes(data)


def _forged_header_examples(test: Callable[..., None]) -> Callable[..., None]:
    """Pin every ``FORGED_HEADER_CASES`` input (all fixers) as an explicit example.

    Each is a forged section or header size that once sized a multi-gigabyte
    allocation in the chain or, for the VirtualSize case, indexed past the image.
    """
    for _case, built_fields, ref_fields, _message in FORGED_HEADER_CASES:
        test = example(forge_pe(_SEED_PE, built_fields), forge_pe(_SEED_PE, ref_fields), [])(test)
    return test


@settings(max_examples=40, deadline=None)
@given(
    _mutated_pe(),
    _mutated_pe(),
    st.lists(st.sampled_from(FIXER_NAMES), unique=True),
)
@_forged_header_examples
def test_run_fixers_reports_only_valueerror(
    built: bytes, reference: bytes, fixer_names: list[str]
) -> None:
    """``ValueError`` is the fixers' whole failure vocabulary.

    ``rebrew build postlink`` catches ``ValueError`` and turns it into an
    ``error_exit``; any other exception reaching the CLI is a traceback.  Both
    inputs are forgeable — the built link and the reference binary the user
    points the command at — and a mutated section table deletes a section name
    outright, so every lookup in the chain must degrade to ``ValueError`` rather
    than a bare ``KeyError`` / ``struct.error`` / ``IndexError``.  A mutated
    size field must not size an allocation either: the chain runs under an
    address-space cap, so one that does fails as ``MemoryError``.
    """
    from rebrew.buildsys.postlink import run_fixers

    with tempfile.TemporaryDirectory() as td:
        built_path = Path(td) / "built.dll"
        ref_path = Path(td) / "ref.dll"
        built_path.write_bytes(built)
        ref_path.write_bytes(reference)
        try:
            with address_space_cap():
                patched, reports = run_fixers(built_path, ref_path, fixer_names or None)
        except ValueError:
            return
        # On success the patched image is a byte string and every requested
        # fixer reports exactly once, in FIXER_ORDER order.  An empty
        # selection means "all fixers", which is what run_fixers(None) runs.
        requested = set(fixer_names) if fixer_names else set(FIXER_NAMES)
        assert isinstance(patched, bytes)
        assert reports
        assert [r.name for r in reports] == [n for n in FIXER_NAMES if n in requested]


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=256))
def test_map_coverage_refuses_a_textless_image(blob: bytes) -> None:
    """A built image with no ``.text`` section is a ``ValueError``, not a
    ``KeyError``: the section name comes from the file, so a corrupted table
    removes it, and every caller of the mapper catches ``ValueError``."""
    from rebrew.buildsys.postlink import map_coverage

    meta, info = _meta_and_info(0, len(blob), {}, {})
    info.sections = {}  # the built image declares no section at all
    with pytest.raises(ValueError, match=r"no \.text section"):
        map_coverage(blob, meta, info)


# ---------------------------------------------------------------------------
# Forged layout packages through the CLIs
# ---------------------------------------------------------------------------

#: ``rebrew-layout.toml`` paths one drawn edit replaces or deletes.
_PACKAGE_FIELDS: list[tuple[str | int, ...]] = [
    ("layout",),
    *[
        ("layout", key)
        for key in (
            "target",
            "image_base",
            "link_options",
            "sections",
            "exports",
            "imports",
            "export_stamp",
            "exp_rva",
        )
    ],
    *[
        ("layout", "sections", index, key)
        for index in range(4)
        for key in ("name", "va", "vs", "raw", "ptr", "chars")
    ],
    *[("layout", "imports", 0, key) for key in ("dll", "name", "ordinal", "iat")],
]

#: Replacement values; ``None`` deletes the field.  TOML integers are 64-bit.
_TOML_VALUES = st.one_of(
    st.none(),
    st.integers(min_value=-(1 << 40), max_value=1 << 40),
    st.booleans(),
    st.text(alphabet="0x1.ab", max_size=4),
    st.lists(st.integers(min_value=-1, max_value=1 << 33), max_size=3),
)

_HEX_BLOBS = ("header.hex", "iat.hex", "prefix.hex", "bookkeeping.hex", "data.hex", "reloc.hex")

_PROJECT_TOML = (
    '[project]\ndefault_target = "game"\n'
    '[targets.game]\nbinary = "game.dll"\nreversed_dir = "src"\n'
)


#: The reference and built image every forged package is checked against.
_OPERAND_SEED = operand_seed()


@pytest.fixture(scope="module")
def pristine_pkg(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The unedited layout package for ``_OPERAND_SEED``, which each example copies."""
    return write_pkg(tmp_path_factory.mktemp("postlink_pkg"), _OPERAND_SEED, "game")


def _literal(value: int) -> str:
    return f"-{-value:#x}" if value < 0 else f"{value:#x}"


@st.composite
def _package_edits(draw: st.DrawFn) -> list[PackageEdit]:
    """At most one ``rebrew-layout.toml`` edit (so its key path still exists),
    sparse-map rows of any arity and width, and an optional blob truncation."""
    edits: list[PackageEdit] = []
    if draw(st.booleans()):
        edits.append(("layout", draw(st.sampled_from(_PACKAGE_FIELDS)), draw(_TOML_VALUES)))
    for name in draw(st.lists(st.sampled_from(("operands.txt", "calls.txt")), max_size=3)):
        row = draw(
            st.lists(st.integers(min_value=-(1 << 33), max_value=1 << 33), min_size=1, max_size=6)
        )
        edits.append(("append", name, " ".join(_literal(v) for v in row)))
    if draw(st.booleans()):
        edits.append(
            (
                "truncate",
                draw(st.sampled_from(_HEX_BLOBS)),
                draw(st.integers(min_value=0, max_value=0x300)),
            )
        )
    return edits


def _forged_package_examples(test: Callable[..., None]) -> Callable[..., None]:
    """Pin every ``FORGED_PACKAGE_CASES`` package, an operand past the built
    image, and an export directory whose stamp crosses the end of the file."""
    for _case, edits, _message in FORGED_PACKAGE_CASES:
        test = example(edits)(test)
    test = example([("append", "operands.txt", "0x7ffffff0 0x403010")])(test)
    return example([("layout", ("layout", "exp_rva"), 0x4000 + 0x200 - 4)])(test)


@settings(max_examples=60, deadline=None)
@given(_package_edits())
@_forged_package_examples
def test_forged_package_exits_cleanly(pristine_pkg: Path, edits: list[PackageEdit]) -> None:
    """``rebrew build postlink --layout`` and ``rebrew build residue`` read the
    same hand-editable package.  On any forgery both finish with exit 0 or the
    error envelope's exit 2, never a traceback: postlink writes its output
    exactly when it succeeds, and neither touches the built image."""
    from typer.testing import CliRunner

    from rebrew.buildsys.postlink import app as postlink_app
    from rebrew.buildsys.residue import app as residue_app
    from rebrew.cli import EXIT_ERROR

    seed = _OPERAND_SEED
    runner = CliRunner()
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "rebrew-project.toml").write_text(_PROJECT_TOML, encoding="utf-8")
        (root / "game.dll").write_bytes(seed)
        built = root / "build" / "game"
        built.parent.mkdir()
        built.write_bytes(seed)
        pkg = root / "layout" / "game"
        shutil.copytree(pristine_pkg, pkg)
        for edit in edits:
            apply_package_edit(pkg, edit)
        out = root / "out.dll"
        with address_space_cap():
            postlink = runner.invoke(
                postlink_app,
                ["--json", "--layout", str(pkg), "-o", str(out), str(built)],
                env={"COLUMNS": "200"},
            )
            with contextlib.chdir(root):
                residue = runner.invoke(residue_app, ["--json"], env={"COLUMNS": "200"})
        assert postlink.exit_code in (0, EXIT_ERROR), postlink.exception
        assert out.exists() == (postlink.exit_code == 0)
        assert residue.exit_code in (0, EXIT_ERROR), residue.exception
        assert built.read_bytes() == seed
