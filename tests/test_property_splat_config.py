"""Property-based fuzzing for the splat config reader above the YAML subset.

A splat config is a third-party file: it comes from another project's repo,
unreviewed, and drives a bulk import that writes into a rebrew project.  The
YAML subset reader itself is fuzzed in ``test_property_parsers``; this
harness fuzzes the layer above it — :func:`parse_splat_config` — where every
value the reader produced is re-typed, cross-referenced and resolved against
the filesystem, and where a wrong value becomes a wrong write rather than a
visible crash.

The configs are drawn from a structure-aware line grammar (real options,
segments, subsegments and rom-end sentinels, with junk and hostile scalars
mixed in) rather than from random bytes, so the fuzzer reaches the
cross-reference logic instead of bouncing off the reader.  Every accepted
config is then checked against the invariants the importer relies on.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from hypothesis import assume, example, given, settings
from hypothesis import strategies as st

from rebrew.splat_config import SUPPORTED_PLATFORM, SplatConfig, parse_splat_config

# ---------------------------------------------------------------------------
# Strategies: a splat config, drawn line by line
# ---------------------------------------------------------------------------

#: Values a real splat config carries, versus the spellings that must be
#: rejected.  Every hostile value is drawn behind a mostly-good draw, so the
#: fuzzer reaches the model instead of stopping at the validation gate.
_GOOD_NAME = st.text(alphabet="abcxyzABCXYZ0123456789_.-", min_size=1, max_size=12)
_HOSTILE_NAME = st.sampled_from(["", " ", ".", "..", "../escape", "a:b", "*", "!", "0", "TEXT"])

_GOOD_KIND = st.sampled_from(["text", "rodata", "data", "bss", "code", "rom", "pad"])
_HOSTILE_KIND = st.sampled_from(["", "TEXT", ".text", "weird kind", "*", "!!"])

_GOOD_PLATFORM = st.sampled_from([SUPPORTED_PLATFORM, SUPPORTED_PLATFORM.upper()])
_HOSTILE_PLATFORM = st.sampled_from(["ps2", "n64", "", "pe", "pe ", "pe\n", "*", "linux"])

_GOOD_COMPILER = st.sampled_from(["msvc", "IDO", "cc", "gcc", "MSVC", "watcom-2.0-win32"])
_HOSTILE_COMPILER = st.sampled_from(["", " ", "*", "!!!", "compiler"])

_GOOD_PATH = st.sampled_from(
    [
        "original/game.z64",
        "original/game.exe",
        "build/game.z64",
        "sym/game.txt",
        "game.z64",
    ]
)
_HOSTILE_PATH = st.sampled_from(
    [
        "..",
        "../..",
        "/abs/original/game.z64",
        "~/game.z64",
        "a/../../b",
        "",
        " ",
        ".",
        "./",
        "C:\\orig\\game.exe",
        "a\x00b",
        "*",
        "[a, b]",
    ]
)

#: Hostile shares: 1 in 7 draws is a value the reader must reject.
_HOSTILE_CHANCE = st.integers(min_value=0, max_value=6)


@st.composite
def _name(draw: st.DrawFn) -> str:
    return draw(_HOSTILE_NAME) if draw(_HOSTILE_CHANCE) == 0 else draw(_GOOD_NAME)


@st.composite
def _kind(draw: st.DrawFn) -> str:
    return draw(_HOSTILE_KIND) if draw(_HOSTILE_CHANCE) == 0 else draw(_GOOD_KIND)


@st.composite
def _platform(draw: st.DrawFn) -> str:
    return draw(_HOSTILE_PLATFORM) if draw(_HOSTILE_CHANCE) == 0 else draw(_GOOD_PLATFORM)


@st.composite
def _compiler(draw: st.DrawFn) -> str:
    return draw(_HOSTILE_COMPILER) if draw(_HOSTILE_CHANCE) == 0 else draw(_GOOD_COMPILER)


@st.composite
def _path(draw: st.DrawFn) -> str:
    return draw(_HOSTILE_PATH) if draw(_HOSTILE_CHANCE) == 0 else draw(_GOOD_PATH)


#: Integers, plus the spellings that must be rejected.  Mostly good, so the
#: rom_start / rom_end cross-reference is actually exercised.
_GOOD_ADDRESS = st.one_of(
    st.integers(min_value=0, max_value=0xFFFFFF).map(hex),
    st.integers(min_value=0, max_value=0xFFFFFF),
)
_HOSTILE_ADDRESS = st.sampled_from(
    ["0x", "0xZZ", "", "-", "-1", "0b1010", "1_000", "12abc", " 0x1000 ", "true", "null"]
)


@st.composite
def _address(draw: st.DrawFn) -> str:
    if draw(_HOSTILE_CHANCE) == 0:
        return draw(_HOSTILE_ADDRESS)
    value = draw(_GOOD_ADDRESS)
    return value if isinstance(value, str) else hex(value)


@st.composite
def _subsegment_lines(draw: st.DrawFn) -> list[str]:
    """One ``subsegments:`` item, in either the flow or the mapping spelling."""
    style = draw(st.sampled_from(["flow", "flow", "mapping", "short"]))
    if style == "flow":
        return [f'      - [{draw(_address())}, "{draw(_kind())}", {draw(_name())}]']
    if style == "mapping":
        return [
            f"      - start: {draw(_address())}",
            f"        type: {draw(_kind())}",
            f"        name: {draw(_name())}",
        ]
    return [f"      - [{draw(_address())}]"]


@st.composite
def _segment_lines(draw: st.DrawFn) -> list[str]:
    """One segment entry, usually carrying a type, an address and subs."""
    lines = [f"  - name: {draw(_name())}"]
    if draw(st.booleans()):
        lines.append(f"    type: {draw(_kind())}")
    if draw(st.booleans()):
        lines.append(f"    start: {draw(_address())}")
    if draw(st.booleans()):
        lines.append(f"    vram: {draw(_address())}")
    if draw(st.booleans()):
        lines.append(f"    bss_size: {draw(_address())}")
    if draw(st.booleans()):
        lines.append("    subsegments:")
        for _ in range(draw(st.integers(min_value=0, max_value=3))):
            lines.extend(draw(_subsegment_lines()))
    return lines


_OPTION_KEYS = (
    "target_path",
    "platform",
    "compiler",
    "base_path",
    "basename",
    "symbol_addrs_path",
    "symbol_addrs_paths",
    "undefined_funcs_auto_path",
    "undefined_syms_auto_path",
    "elf_path",
    "unknown_option",
)


@st.composite
def _option_value(draw: st.DrawFn, key: str) -> str:
    """The value an option key actually takes, hostile values included."""
    if key == "platform":
        return draw(_platform())
    if key == "compiler":
        return draw(_compiler())
    if key in ("basename", "unknown_option"):
        return draw(_name())
    if key == "symbol_addrs_paths":
        return draw(st.sampled_from(["sym/a.txt", "sym/a.txt,sym/b.txt", "[sym/a.txt]", ""]))
    return draw(_path())


@st.composite
def _config_text(draw: st.DrawFn) -> str:
    """A whole splat config: options, segments, junk lines and a random tail.

    Required fields are present unless a draw drops them, so most inputs get
    past validation and the fuzzer spends its budget in the model.
    """
    lines: list[str] = []
    if draw(st.booleans()):
        lines.append("---")
    if draw(st.booleans()):
        lines.append(f"# {draw(_name())}")
    if draw(st.booleans()):
        lines.append(f"{draw(st.sampled_from(['unknown', 'name', 'files']))}: 1")
    options = ["options:"]
    for key in ("target_path", "platform", "compiler"):
        if draw(st.integers(min_value=0, max_value=19)) == 0:
            continue  # a required option is missing: the reader must reject
        options.append(f"  {key}: {draw(_option_value(key))}")
    for key in draw(
        st.lists(st.sampled_from(_OPTION_KEYS[3:]), min_size=0, max_size=3, unique=True)
    ):
        value = draw(st.one_of(_path(), _name(), _address()))
        options.append(f"  {key}: {value}")
    lines.extend(options)
    if draw(st.integers(min_value=0, max_value=19)) != 0:
        lines.append("segments:")
        for _ in range(draw(st.integers(min_value=1, max_value=3))):
            if draw(st.sampled_from([False, False, False, True])):
                lines.append(f"  - [{draw(_address())}]")  # rom-end sentinel
            else:
                lines.extend(draw(_segment_lines()))
    for _ in range(draw(st.integers(min_value=0, max_value=1))):
        lines.append(draw(st.sampled_from(["...", "\tindented: 1", "  ", "- dangling", "}{"])))
    if draw(st.booleans()):
        lines.append(f"{draw(_name())}: {draw(_name())}")
    return "\n".join(lines) + ("\n" if draw(st.booleans()) else "")


@st.composite
def _valid_config_text(draw: st.DrawFn) -> str:
    """A config that satisfies every required field, so the fuzzer spends
    its whole budget past the validation gate and inside the model."""
    options = [
        f"  target_path: {draw(_GOOD_PATH)}",
        f"  platform: {draw(_GOOD_PLATFORM)}",
        f"  compiler: {draw(_GOOD_COMPILER)}",
    ]
    for key, strategy in (
        ("base_path", _GOOD_PATH),
        ("basename", _GOOD_NAME),
        ("symbol_addrs_path", _GOOD_PATH),
        ("undefined_funcs_auto_path", _GOOD_PATH),
        ("undefined_syms_auto_path", _GOOD_PATH),
    ):
        if draw(st.booleans()):
            options.append(f"  {key}: {draw(strategy)}")
    segments: list[str] = []
    for _ in range(draw(st.integers(min_value=1, max_value=3))):
        segments.append(f"  - name: {draw(_GOOD_NAME)}")
        segments.append(f"    type: {draw(_GOOD_KIND)}")
        if draw(st.booleans()):
            segments.append(f"    start: {draw(_address())}")
        if draw(st.sampled_from([True, True, False])):
            segments.append("    subsegments:")
            for _ in range(draw(st.integers(min_value=0, max_value=2))):
                segments.append(
                    f'      - [{draw(_address())}, "{draw(_GOOD_KIND)}", {draw(_GOOD_NAME)}]'
                )
    if draw(st.booleans()):
        segments.append(f"  - [{draw(_address())}]")
    return "\n".join(["options:", *options, "segments:", *segments]) + "\n"


def _parse(tmpdir: str, text: str | bytes) -> SplatConfig:
    path = Path(tmpdir) / "config.yaml"
    path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
    return parse_splat_config(path)


def _assert_model_invariants(cfg: SplatConfig) -> None:
    """The properties the importer reads without re-checking them."""
    assert cfg.platform == SUPPORTED_PLATFORM
    # Every path in the model is absolute: the reader resolves against the
    # config's own directory so later `relative_to(root)` calls are safe.
    assert cfg.base_path.is_absolute()
    assert cfg.target_path is not None and cfg.target_path.is_absolute()
    if cfg.elf_path is not None:
        assert cfg.elf_path.is_absolute()
    for sym in cfg.symbol_addrs_paths:
        assert sym.is_absolute()
    if cfg.undefined_funcs_auto_path is not None:
        assert cfg.undefined_funcs_auto_path.is_absolute()
    if cfg.undefined_syms_auto_path is not None:
        assert cfg.undefined_syms_auto_path.is_absolute()
    # A config that parsed lists at least one segment, and every segment's
    # reported size is the end-minus-start of the span it claims to cover.
    assert cfg.segments
    for seg in cfg.segments:
        assert isinstance(seg.name, str)
        assert isinstance(seg.kind, str)
        if seg.rom_start is None or seg.rom_end is None or seg.rom_end < seg.rom_start:
            assert seg.rom_size is None
        else:
            assert seg.rom_size == seg.rom_end - seg.rom_start
        for sub in seg.subsegments:
            assert isinstance(sub.name, str)
            assert not sub.kind.startswith(".")  # leading dot stripped
        # subsegment_at is the vram cross-reference the importer resolves
        # names through: a hit must really contain the address asked for.
        for va in (-1, 0, 0x1000, 0x1000000, 0xFFFFFFFF):
            hit = seg.subsegment_at(va)
            if hit is None or seg.vram is None or seg.rom_start is None:
                continue
            index = next(i for i, sub in enumerate(seg.subsegments) if sub is hit)
            sub_end = (
                seg.subsegments[index + 1].rom_start
                if index + 1 < len(seg.subsegments)
                else seg.rom_end
            )
            lo = seg.vram + (hit.rom_start - seg.rom_start)
            hi = seg.vram + (sub_end - seg.rom_start)
            assert lo <= va < hi
    # Ignored keys are deduplicated on (key, reason).
    seen: set[tuple[str, str]] = set()
    for item in cfg.ignored:
        pair = (item.key, item.reason)
        assert pair not in seen
        seen.add(pair)


# ---------------------------------------------------------------------------
# Harnesses
# ---------------------------------------------------------------------------


@settings(max_examples=250, deadline=None)
@given(text=_config_text())
# Two equal subsegments: the invariant must locate the hit by identity, since
# `list.index` returns the first equal one and its span is empty.
@example(
    text="options:\n  target_path: ..\n  platform: win32\n  compiler: msvc\nsegments:\n"
    "  - name: \n    start: 0x0\n    vram: 0x0\n    subsegments:\n      - [0x0]\n"
    "      - [0x0]\n  - [0x0]\n  - name: \n    start: 0x1"
)
def test_arbitrary_config_text_is_rejected_or_modelled(text: str) -> None:
    """Any config text either raises ``ValueError`` naming the problem or
    returns a model that satisfies every importer invariant — never a
    ``KeyError``, ``IndexError`` or ``TypeError`` from re-typing a value."""
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            cfg = _parse(tmpdir, text)
        except ValueError:
            return
        _assert_model_invariants(cfg)


@settings(max_examples=250, deadline=None)
@given(text=_valid_config_text())
def test_well_formed_config_reaches_the_model(text: str) -> None:
    """Configs that pass the required-field gate must survive the round into
    a model.  Only unsupported values (a non-PE platform, a non-integer
    address) may stop them, and those stop with ``ValueError``."""
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            cfg = _parse(tmpdir, text)
        except ValueError as exc:
            # Every rejection must say what was wrong, not just fail.
            assert str(exc)
            return
        _assert_model_invariants(cfg)


@settings(max_examples=200, deadline=None)
@given(blob=st.binary(max_size=512))
def test_non_utf8_config_bytes_are_rejected_cleanly(blob: bytes) -> None:
    """A config file that is not UTF-8 (a Latin-1 splat config, a truncated
    download) surfaces as ``ValueError``, not a ``UnicodeDecodeError``."""
    assume(blob != b"")
    with tempfile.TemporaryDirectory() as tmpdir, pytest.raises(ValueError):
        _parse(tmpdir, blob)


@settings(max_examples=100, deadline=None)
@given(missing_key=st.sampled_from(["target_path", "platform", "compiler"]))
def test_a_missing_required_option_is_named(missing_key: str) -> None:
    """The three required options are genuinely required: dropping one is a
    ``ValueError`` that names it, so the import fails at the config, not
    later with an ``AttributeError``."""
    options = {
        "target_path": "  target_path: original/game.z64",
        "platform": "  platform: win32",
        "compiler": "  compiler: msvc",
    }
    del options[missing_key]
    text = "\n".join(
        ["options:", *options.values(), "segments:", "  - name: .text", "    start: 0x1000"]
    )
    with tempfile.TemporaryDirectory() as tmpdir, pytest.raises(ValueError) as ei:
        _parse(tmpdir, text)
    assert missing_key in str(ei.value)
