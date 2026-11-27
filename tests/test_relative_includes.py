"""Project-relative includes must resolve through the container's same-path root mount."""

from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any
lazy from collections.abc import Iterator

import pytest

from rebrew.compiler.compile import compile_and_compare, compile_to_obj
from rebrew.compiler.toolchain import TOOLCHAINS, image_present
from rebrew.compiler.toolchain_paths import toolchains_repo

_IMAGE = TOOLCHAINS["msvc-6.0"].image
pytestmark = pytest.mark.skipif(
    not _IMAGE or not image_present(_IMAGE),
    reason="rebrew/msvc:6.0-win32 image not built (run `rebrew toolchain build msvc-6.0`)",
)


@pytest.fixture
def cfg() -> Iterator[SimpleNamespace]:
    """Give each compile a private project under the Docker-visible checkout."""
    cache = Path(__file__).resolve().parents[1] / ".cache"
    cache.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rt-includes-", dir=cache) as directory:
        root = Path(directory)
        headers = root / "Units" / "Error"
        headers.mkdir(parents=True)
        (headers / "error.h").write_text("int error_code(void);\n", encoding="utf-8")
        yield SimpleNamespace(
            root=root,
            compiler_profile="msvc-6.0",
            compiler_command="",
            compiler_runner="",
            compiler_includes=str(toolchains_repo() / "msvc" / "6.0-win32" / "VC98" / "Include"),
            base_cflags="/nologo /c",
            compile_timeout=180,
            posix_style=False,
            cflags_presets={},
            cflags="",
            cflags_explicit=False,
        )


def _source(root: Path, subdir: str, include: str) -> Path:
    src = root / subdir / "f.c"
    src.parent.mkdir(parents=True)
    src.write_text(
        f'#include "{include}/Units/Error/error.h"\nint exit_code(void){{ return error_code(); }}\n',
        encoding="utf-8",
    )
    return src


@pytest.mark.parametrize(("subdir", "include"), [("src/server_c", "../.."), ("a/b/c", "../../..")])
def test_relative_include_resolves_through_image(cfg: Any, subdir: str, include: str) -> None:
    src = _source(cfg.root, subdir, include)
    work = cfg.root / "work"
    work.mkdir()
    obj, err = compile_to_obj(cfg, src, ["/O1"], work, use_cache=False)
    assert obj is not None, err
    assert Path(obj).is_file()


def test_compile_and_compare_resolves_relative_include(cfg: Any) -> None:
    """The batch verification entry point must also produce bytes for the same source."""
    src = _source(cfg.root, "src/server_c", "../..")
    res = compile_and_compare(cfg, src, "_exit_code", b"", [], use_cache=False)
    assert res.full_obj_bytes, res.message
