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

import os
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.compiler.compile import _extract_and_compare, compile_to_obj

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


def _cfg(root: Path, profile: str) -> SimpleNamespace:
    """Build a compile config that routes through the profile's docker image
    (execution is docker-only; the vendored tree is never exec'd)."""
    return SimpleNamespace(
        root=root,
        compiler_command="",
        compiler_runner="",
        compiler_includes=root,
        compiler_libs=Path(""),
        compiler_profile=profile,
        base_cflags="/nologo /c /MT",
        compile_timeout=180,
        msvc_env=dict,
        posix_style=False,
    )


def _image_present(profile: str) -> bool:
    """True when the profile's docker image is built locally.

    ``TOOLCHAINS[profile]`` raises for an unregistered name, so a typo fails
    the test instead of running another profile's image.
    """
    from rebrew.compiler.toolchain import TOOLCHAINS, image_present

    spec = TOOLCHAINS[profile]
    return spec.image is not None and image_present(spec.image)


def _compile_extract_compare(tmp_path: Path, profile: str, cflags: list[str]) -> str:
    """Compile SNIPPET, extract _f, re-compare, return status."""
    src = tmp_path / "rt.c"
    src.write_text(SNIPPET, encoding="utf-8")
    cfg = _cfg(tmp_path, profile)
    # The compile workdir must be docker-visible (mounted at /work), so it
    # lives under the repo's .cache/ instead of pytest's tmp dir.  The name
    # carries the pid and a fresh suffix: a shared per-toolchain directory
    # would have two concurrent runs deleting each other's staged sources.
    workdir = _REPO / ".cache" / "rt" / f"{profile}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    workdir.mkdir(parents=True, exist_ok=True)

    obj_path, err = compile_to_obj(cfg, src, cflags, workdir, use_cache=False)
    assert obj_path is not None, f"compile failed: {err}"

    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs

    obj_bytes, _, _ = parse_obj_symbol_and_relocs(obj_path, "_f")
    assert obj_bytes is not None, "_f symbol not found in object"

    # Re-run the compare stage against the freshly compiled bytes.
    res = _extract_and_compare(obj_path, "_f", obj_bytes, section_va=0x1000)
    return res.status


@pytest.mark.parametrize(
    ("profile", "cflags"),
    [
        ("msvc-6.0-sp3", ["/O2", "/Gd"]),
        ("msvc-6.0-sp6", ["/O2", "/Gd"]),
        ("msvc-7.0", ["/O2", "/Ob0", "/Gd"]),
        ("msvc-4.2", ["/O2", "/Gd"]),
        ("msvc-5.0", ["/O2", "/Gd"]),
        ("msvc-4.0", ["/O2", "/Gd"]),
    ],
)
def test_toolchain_roundtrip_exact(tmp_path: Path, profile: str, cflags: list[str]) -> None:
    if not _image_present(profile):
        pytest.skip(
            f"{profile} docker image not built (run `rebrew toolchain build {profile}` first)"
        )
    status = _compile_extract_compare(tmp_path, profile, cflags)
    assert status == "EXACT", f"{profile} round-trip expected EXACT, got {status}"
