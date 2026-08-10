"""Round-trip integration tests for the decomp.me MSVC toolchains.

Each test compiles a snippet with one of the vendored decomp.me toolchains
(msvc6.3, msvc6.6, msvc7.0 under tools/), extracts the function bytes from
the produced COFF object, and re-runs the compile+compare pipeline — the
profile is proven when the result classifies EXACT (compile → parse →
byte-compare all agree).

These tests SKIP when wine or the toolchain tarballs are not present (they
are gitignored; fetch from the OmniBlade decomp.me release mirror — see
docs/TOOLCHAIN.md).
"""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.compile import _extract_and_compare, compile_to_obj

_REPO = Path(__file__).resolve().parents[1]
_TOOLS = _REPO / "tools"

SNIPPET = """
int f(int n)
{
    int i, s = 0;
    for (i = 0; i < n; i++)
        s += i * 3 + (i >> 2);
    return s;
}
"""


def _cfg(root: Path, toolchain: str) -> SimpleNamespace:
    """Build a compile config for a vendored toolchain, tolerating the
    decomp.me (msvc6.3/6.6/7.0, lowercase, Bin) and archaic-msvc
    (MSVC420/MSVC500, uppercase, bin) layouts."""
    candidates = [
        ("Bin", "CL.EXE"),
        ("Bin", "cl.exe"),
        ("bin", "CL.EXE"),
        ("bin", "cl.exe"),
    ]
    cl = next(
        (
            _TOOLS / toolchain / d / n
            for d, n in candidates
            if (_TOOLS / toolchain / d / n).exists()
        ),
        _TOOLS / toolchain / "Bin" / "CL.EXE",
    )
    inc = next(
        (
            _TOOLS / toolchain / d
            for d in ("Include", "include")
            if (_TOOLS / toolchain / d).is_dir()
        ),
        _TOOLS / toolchain / "Include",
    )
    return SimpleNamespace(
        root=root,
        compiler_command=f"wine {cl}",
        compiler_runner="wine",
        compiler_includes=inc,
        compiler_libs=Path(""),
        compiler_profile="msvc6",
        base_cflags="/nologo /c /MT",
        compile_timeout=90,
        msvc_env=lambda: {},
    )


def _toolchain_available(toolchain: str) -> bool:
    candidates = [
        _TOOLS / toolchain / "Bin" / "CL.EXE",
        _TOOLS / toolchain / "bin" / "CL.EXE",
        _TOOLS / toolchain / "Bin" / "cl.exe",
        _TOOLS / toolchain / "bin" / "cl.exe",
    ]
    return any(c.exists() for c in candidates) and shutil.which("wine") is not None


def _compile_extract_compare(tmp_path: Path, toolchain: str, cflags: list[str]) -> str:
    """Compile SNIPPET, extract _f, re-compare, return status."""
    src = tmp_path / "rt.c"
    src.write_text(SNIPPET, encoding="utf-8")
    cfg = _cfg(tmp_path, toolchain)
    workdir = tmp_path / "work"
    workdir.mkdir(exist_ok=True)

    obj_path, err = compile_to_obj(cfg, src, cflags, workdir, use_cache=False)
    assert obj_path is not None, f"compile failed: {err}"

    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs

    obj_bytes, _, _ = parse_obj_symbol_and_relocs(obj_path, "_f")
    assert obj_bytes is not None, "_f symbol not found in object"

    # Re-run the compare stage against the freshly compiled bytes.
    res = _extract_and_compare(obj_path, "_f", obj_bytes, section_va=0x1000)
    return res.status


@pytest.mark.parametrize(
    ("toolchain", "cflags"),
    [
        ("msvc6.3", ["/O2", "/Gd"]),
        ("msvc6.6", ["/O2", "/Gd"]),
        ("msvc7.0", ["/O2", "/Ob0", "/Gd"]),
        ("MSVC420", ["/O2", "/Gd"]),
        ("MSVC500", ["/O2", "/Gd"]),
    ],
)
def test_toolchain_roundtrip_exact(tmp_path: Path, toolchain: str, cflags: list[str]) -> None:
    if not _toolchain_available(toolchain):
        pytest.skip(f"{toolchain} toolchain not vendored (see docs/TOOLCHAIN.md)")
    status = _compile_extract_compare(tmp_path, toolchain, cflags)
    assert status == "EXACT", f"{toolchain} round-trip expected EXACT, got {status}"
