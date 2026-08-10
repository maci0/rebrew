"""gen_fixtures.py — regenerate the checked-in binary fixtures.

The files under ``tests/fixtures/`` are tiny synthetic binaries built by
hand (no wine, no vendored toolchain) so the parse/compare/reloc paths —
and the ``gen_flirt_pat`` → ``flirt`` pipeline — run end-to-end in CI:

    mini.obj      COFF object: two x86 functions, a DIR32 and a REL32 reloc
    mini_pe.exe   Minimal PE containing the same code (+ one KERNEL32 import)
    mini.elf      Minimal ELF32 (EM_386) with the same code
    mini.lib      COFF archive wrapping mini.obj (FLIRT generation input)

``tests/test_binary_fixtures.py`` regenerates everything in memory and
asserts the checked-in bytes are byte-identical, so the fixtures and this
script can never drift apart.

Usage::

    python tools/gen_fixtures.py          # (re)write tests/fixtures/
    python tools/gen_fixtures.py --check  # verify files match, no write

Also importable for tests::

    from tools.gen_fixtures import build_all
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = ROOT / "tests" / "fixtures"

# ---------------------------------------------------------------------------
# Fixture content
# ---------------------------------------------------------------------------
# _func1 @ 0x00: push ebp; mov ebp, esp; mov eax, [_extern_var]; pop ebp; ret
#               DIR32 reloc (0x06) on the imm32 at offset 5.
# _func2 @ 0x10: push ebp; mov ebp, esp; call _callee; pop ebp; ret
#               REL32 reloc (0x14) on the imm32 at offset 4 (func2-relative).
# Functions are separated and tail-padded with 0xCC (int3), matching MSVC's
# inter-function padding convention so rebrew's rstrip(0xCC/0x90) trims it.
FUNC1 = bytes.fromhex("55 8b ec 8b 05 00 00 00 00 5d c3")
FUNC2 = bytes.fromhex("55 8b ec e8 00 00 00 00 5d c3")
FUNC2_OFFSET = 0x10  # int3 padding separates the two functions
CODE = FUNC1 + b"\xcc" * (FUNC2_OFFSET - len(FUNC1)) + FUNC2 + b"\xcc\xcc"

# VAs inside mini_pe.exe / mini.elf (image_base 0x400000 + .text at 0x1000).
FUNC1_VA = 0x401000
FUNC2_VA = 0x401010
EXTERN_VA = 0x402000  # catalog entry for _extern_var (DIR32 validation)
CALLEE_VA = 0x402010  # catalog entry for _callee (REL32 validation)

_COFF_RELOCS: list[tuple[int, int, str]] = [
    (5, 0x06, "_extern_var"),  # DIR32 inside _func1
    (0x14, 0x14, "_callee"),  # REL32 inside _func2 (4 bytes past func2 start)
]


def build_all() -> dict[str, bytes]:
    """Return {fixture_filename: bytes} for every checked-in fixture."""
    # Import here so loading this module is side-effect free; the builders
    # live in tests/bin_util.py (pytest inserts tests/ into sys.path too).
    sys.path.insert(0, str(ROOT / "tests"))
    import bin_util

    obj = bin_util.make_coff_obj(
        CODE,
        relocs=_COFF_RELOCS,
        func_symbol="_func1",
        func_value=0,
        extra_funcs=[("_func2", FUNC2_OFFSET)],
    )
    return {
        "mini.obj": obj,
        "mini_pe.exe": bin_util.make_pe(CODE, imports=[("KERNEL32.dll", ["GetTickCount"])]),
        "mini.elf": bin_util.make_elf(CODE, image_base=0x400000, text_va=0x401000),
        "mini.lib": bin_util.make_lib_archive([("mini.obj", obj)]),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Regenerate the checked-in binary fixtures in tests/fixtures/"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify fixtures match the generator (exit 1 on drift) without writing",
    )
    args = parser.parse_args()

    generated = build_all()
    if args.check:
        drift = [
            name for name, data in generated.items() if (FIXTURES_DIR / name).read_bytes() != data
        ]
        if drift:
            print(f"fixtures out of date: {', '.join(sorted(drift))}")
            print("run: python tools/gen_fixtures.py")
            sys.exit(1)
        print(f"{len(generated)} fixtures up to date")
        return

    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    for name, data in sorted(generated.items()):
        (FIXTURES_DIR / name).write_bytes(data)
        print(f"wrote {FIXTURES_DIR / name} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
