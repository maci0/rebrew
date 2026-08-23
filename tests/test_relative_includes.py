"""
Relative project-include regression: the docker-only compile path must
resolve project-relative includes (the /work source copy is flat, so the
project root + include dirs are same-path mounted into the container).
"""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.compile import compile_and_compare, compile_to_obj
from rebrew.toolchain import toolchains_repo

_REPO = Path(__file__).resolve().parents[1]

#: A vendored-tree include path under the rebrew-toolchains checkout — the
#: docker layer skips bind-mounting these (the image bakes its own), so the
#: relative-include machinery gets exercised without docker recreating
#: stray host dirs.
_INSTALL_INCLUDES = str(toolchains_repo() / "msvc" / "6.0-win32" / "VC98" / "Include")


def _image_available(profile: str) -> bool:
    from rebrew.toolchain import TOOLCHAINS, image_present

    spec = TOOLCHAINS[profile]
    return spec.image is not None and image_present(spec.image)


def _project(name: str) -> tuple[Path, Path, Path]:
    """A docker-visible mini project: src/server_c/f.c including
    ../../Units/Error/error.h (the guild-rebrew layout).  Lives under the
    repo .cache so the container mount can see it."""
    root = _REPO / ".cache" / "rt-includes" / name
    shutil.rmtree(root, ignore_errors=True)
    server_c = root / "src" / "server_c"
    errdir = root / "Units" / "Error"
    server_c.mkdir(parents=True)
    errdir.mkdir(parents=True)
    (errdir / "error.h").write_text("int error_code(void);\n", encoding="utf-8")
    src = server_c / "f.c"
    src.write_text(
        '#include "../../Units/Error/error.h"\n' + "int exit_code(void){ return error_code(); }\n",
        encoding="utf-8",
    )
    return root, src, errdir / "error.h"


@pytest.mark.skipif(
    not _image_available("msvc6"),
    reason="rebrew/msvc:6.0-win32 image not built (run `rebrew toolchain build msvc6`)",
)
def test_relative_include_resolves_through_image() -> None:
    """compile_to_obj on a source with a relative ../../ include must not
    fail with C1083 — the project root is same-path mounted."""
    root, src, _ = _project("one")
    cfg = SimpleNamespace(
        root=root,
        compiler_profile="msvc6",
        compiler_command="",
        compiler_runner="",
        compiler_includes=_INSTALL_INCLUDES,  # skipped (image has its own)
        base_cflags="/nologo /c",
        compile_timeout=180,
        posix_style=False,
        cflags_presets={},
        cflags="",
        cflags_explicit=False,
    )
    work = root / "work"
    work.mkdir(exist_ok=True)
    obj, err = compile_to_obj(cfg, src, ["/O1"], work, use_cache=False)
    assert obj is not None, f"relative include failed: {err}"
    assert Path(obj).exists()


@pytest.mark.skipif(
    not _image_available("msvc6"),
    reason="rebrew/msvc:6.0-win32 image not built (run `rebrew toolchain build msvc6`)",
)
def test_relative_include_deep_nesting() -> None:
    """Three-level ../../../ include still resolves (the root mount covers
    arbitrary depth)."""
    root = _REPO / ".cache" / "rt-includes" / "deep"
    shutil.rmtree(root, ignore_errors=True)
    deep = root / "a" / "b" / "c"
    errdir = root / "Units" / "Error"
    deep.mkdir(parents=True)
    errdir.mkdir(parents=True)
    (errdir / "error.h").write_text("int error_code(void);\n", encoding="utf-8")
    src = deep / "f.c"
    src.write_text(
        '#include "../../../Units/Error/error.h"\n' + "int g(void){ return error_code(); }\n",
        encoding="utf-8",
    )
    cfg = SimpleNamespace(
        root=root,
        compiler_profile="msvc6",
        compiler_command="",
        compiler_runner="",
        compiler_includes=_INSTALL_INCLUDES,
        base_cflags="/nologo /c",
        compile_timeout=180,
        posix_style=False,
        cflags_presets={},
        cflags="",
        cflags_explicit=False,
    )
    work = root / "work"
    work.mkdir(exist_ok=True)
    obj, err = compile_to_obj(cfg, src, ["/O1"], work, use_cache=False)
    assert obj is not None, f"deep relative include failed: {err}"


@pytest.mark.skipif(
    not _image_available("msvc6"),
    reason="rebrew/msvc:6.0-win32 image not built (run `rebrew toolchain build msvc6`)",
)
def test_compile_and_compare_resolves_relative_include() -> None:
    """The batch path (compile_and_compare — rebrew test / verify) compiles
    a relative-include source without COMPILE_ERROR."""
    root, src, _ = _project("compare")
    cfg = SimpleNamespace(
        root=root,
        compiler_profile="msvc6",
        compiler_command="",
        compiler_runner="",
        compiler_includes=_INSTALL_INCLUDES,
        base_cflags="/nologo /c",
        compile_timeout=180,
        posix_style=False,
        cflags_presets={},
        cflags="",
        cflags_explicit=False,
    )
    # empty target bytes: the compile stage is what matters — it must not
    # be COMPILE_ERROR (C1083).
    res = compile_and_compare(cfg, src, "_exit_code", b"", [], use_cache=False)
    assert res.status != "COMPILE_ERROR", getattr(res, "message", "")
