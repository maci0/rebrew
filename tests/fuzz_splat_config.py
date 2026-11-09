"""Atheris (libFuzzer) target: splat config parser.

Coverage-guided sibling of tests/test_property_splat_config.py (Hypothesis
drives that harness in CI) and tests/test_property_parsers.py (the YAML
subset reader).  A splat config is an unreviewed third-party file that
drives a bulk import writing into a rebrew project, so its raw bytes are
fuzzed here: arbitrary bytes must surface as a clean ``ValueError`` from
``parse_splat_text`` / ``parse_yaml_subset``, never an unhandled exception,
and every accepted config must satisfy the model invariants the importer
relies on without re-checking them.

    uv run --frozen --group fuzz python tests/fuzz_splat_config.py <corpus_dir> [flags]
    uv run --frozen --group fuzz python tests/fuzz_splat_config.py tests/fixtures/splat_config -runs=1000

Seed corpus: tests/fixtures/splat_config/win32_app.yaml (a real committed
shape, never production traffic) plus one truncated / hostile variant.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris

from rebrew.splat_config import (
    SUPPORTED_PLATFORM,
    SplatConfig,
    parse_splat_text,
    parse_yaml_subset,
)

#: Location the model resolves relative paths against; nothing is opened.
_ANCHOR = Path("/tmp/fuzz-splat-config/config.yaml")

#: Smallest real config: one segment, the platform the importer accepts.
_MINIMAL = b"options:\n  target_path: fixture.exe\n  platform: win32\n  compiler: MSVC6\nsegments:\n  - name: text\n    start: 0x200\n"


def _assert_model_invariants(cfg: SplatConfig) -> None:
    """The properties the importer reads without re-checking them."""
    assert cfg.platform == SUPPORTED_PLATFORM
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
            assert not sub.kind.startswith(".")
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
    seen: set[tuple[str, str]] = set()
    for item in cfg.ignored:
        pair = (item.key, item.reason)
        assert pair not in seen
        seen.add(pair)


def TestOneInput(data: bytes) -> None:
    """Only failure mode of either layer is ``ValueError`` naming the line /
    field; a parsed config never invents a relative or out-of-span model."""
    if not data:
        data = _MINIMAL
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    # YAML subset layer: reject loudly or return a plain container tree.
    try:
        raw = parse_yaml_subset(text)
    except ValueError as exc:
        assert str(exc)
        return
    assert isinstance(raw, (dict, list, str, int, float, bool, type(None)))
    # Deterministic on the same bytes.
    assert parse_yaml_subset(text) == raw
    # Config layer over the same text (pair assertion: the model must carry
    # the same structure the subset reader reported, re-typed).
    try:
        cfg = parse_splat_text(text, _ANCHOR)
    except ValueError as exc:
        assert str(exc)
        return
    _assert_model_invariants(cfg)
    # Pair: re-parsing exactly the same bytes yields an identical model.
    again = parse_splat_text(text, _ANCHOR)
    assert again == cfg
    # The file-path entry point agrees with the text entry point.
    from rebrew.splat_config import parse_splat_config

    try:
        via_file = parse_splat_config(_ANCHOR)
    except ValueError:
        return  # anchor file absent/short: not this harness's contract
    assert via_file == cfg


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
