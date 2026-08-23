"""Round-trip integration tests for the rebrew docker toolchain images.

Each test compiles a snippet with one of the docker toolchain images
(rebrew/msvc:<ver>-win32 — the byte-identical containerization of the
archaic-msvc / decomp.me sources), extracts the function bytes from the
produced COFF object, and re-runs the compile+compare pipeline — the
profile is proven when the result classifies EXACT (compile → parse →
byte-compare all agree).

These tests SKIP when docker is unavailable or the image is not built
locally (run `rebrew toolchain build <name>` first).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.compile import _extract_and_compare, compile_to_obj

_REPO = Path(__file__).resolve().parents[1]

SNIPPET = """
int f(int n)
{
    int i, s = 0;
    for (i = 0; i < n; i++)
        s += i * 3 + (i >> 2);
    return s;
}
"""


#: Legacy vendored toolchain dir -> rebrew profile (docker image).
_TOOLCHAIN_PROFILES = {
    "msvc-7.0-win32": "msvc7",
    "msvc-4.2-win32": "msvc420",
    "msvc-5.0-win32": "msvc5",
    "msvc-4.0-win32": "msvc400",
}


def _cfg(root: Path, toolchain: str) -> SimpleNamespace:
    """Build a compile config that routes through the toolchain's docker
    image (execution is docker-only; the vendored tree is never exec'd)."""
    profile = _TOOLCHAIN_PROFILES.get(toolchain, "msvc6")
    return SimpleNamespace(
        root=root,
        compiler_command="",
        compiler_runner="",
        compiler_includes=root,
        compiler_libs=Path(""),
        compiler_profile=profile,
        base_cflags="/nologo /c /MT",
        compile_timeout=180,
        msvc_env=lambda: {},
        posix_style=False,
    )


def _toolchain_available(toolchain: str) -> bool:
    """True when the toolchain's docker image is built locally."""
    from rebrew.toolchain import TOOLCHAINS, image_present

    profile = _TOOLCHAIN_PROFILES.get(toolchain, "msvc6")
    spec = TOOLCHAINS[profile]
    return spec.image is not None and image_present(spec.image)


def _compile_extract_compare(tmp_path: Path, toolchain: str, cflags: list[str]) -> str:
    """Compile SNIPPET, extract _f, re-compare, return status."""
    src = tmp_path / "rt.c"
    src.write_text(SNIPPET, encoding="utf-8")
    cfg = _cfg(tmp_path, toolchain)
    # The compile workdir must be docker-visible (mounted at /work), so it
    # lives under the repo's .cache/ instead of pytest's tmp dir.
    workdir = _REPO / ".cache" / "rt" / toolchain
    workdir.mkdir(parents=True, exist_ok=True)
    for stale in workdir.iterdir():
        stale.unlink(missing_ok=True)

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
        ("msvc600sp3", ["/O2", "/Gd"]),
        ("msvc600sp6", ["/O2", "/Gd"]),
        ("msvc-7.0-win32", ["/O2", "/Ob0", "/Gd"]),
        ("msvc-4.2-win32", ["/O2", "/Gd"]),
        ("msvc-5.0-win32", ["/O2", "/Gd"]),
        ("msvc-4.0-win32", ["/O2", "/Gd"]),
    ],
)
def test_toolchain_roundtrip_exact(tmp_path: Path, toolchain: str, cflags: list[str]) -> None:
    if not _toolchain_available(toolchain):
        pytest.skip(
            f"{toolchain} docker image not built (run `rebrew toolchain build <name>` first)"
        )
    status = _compile_extract_compare(tmp_path, toolchain, cflags)
    assert status == "EXACT", f"{toolchain} round-trip expected EXACT, got {status}"
