"""rebrew — compiler-in-the-loop decompilation workbench.

A toolkit for binary-matching game reversing, providing a genetic algorithm
engine, annotation pipeline, verification framework, and CLI tools for
reconstructing exact C source from compiled binaries.

Library consumers typically import submodules directly, for example:

* ``rebrew.errors`` — ``RebrewError``, the base of every error raised below
* ``rebrew.compile`` — ``CompareResult``, ``compile_and_compare``
* ``rebrew.config`` — ``ProjectConfig``, ``load_config``, ``ConfigError``
* ``rebrew.sources`` — ``iter_sources``, ``iter_library_headers``
* ``rebrew.toolchain`` — ``ToolchainError``, ``get_toolchain``, ``require_toolchains_repo``
* ``rebrew.recompile_client`` — remote compile transport
* ``rebrew.registry`` / ``rebrew.plugin`` — entry-point extension hooks
* ``rebrew.workspace`` — stdlib-light project/root and coverage.db helpers
* ``rebrew.matcher`` — GA mutations and scoring
* ``rebrew.ghidra`` — ``McpError``, ``McpErrorKind``, structural ReVa ops

Importing any ``rebrew`` submodule also caps the OpenBLAS/OMP thread pool
at one thread unless ``OPENBLAS_NUM_THREADS`` / ``OMP_NUM_THREADS`` are
already set — see the block below.
"""

import os

# NumPy's bundled OpenBLAS starts a full-width thread pool at import and
# busy-spins it while the rest of the interpreter loads.  Importing
# rebrew.main measured 1.7-2.1 CPU-seconds of startup against 0.20 with a
# single thread (wall 0.24 -> 0.20) — every CLI invocation paid it, and it
# fought --jobs verify / GA batches for cores.  rebrew's array work (reloc
# fixing, similarity scoring) is small-array work that gains nothing from
# the pool.  setdefault keeps an explicit user choice authoritative.
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

__version__ = "2.8.0"

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "CompareResult": ("rebrew.compile", "CompareResult"),
    "ConfigError": ("rebrew.config", "ConfigError"),
    "ProjectConfig": ("rebrew.config", "ProjectConfig"),
    "RebrewError": ("rebrew.errors", "RebrewError"),
    "ToolchainError": ("rebrew.toolchain", "ToolchainError"),
    "compile_and_compare": ("rebrew.compile", "compile_and_compare"),
    "get_toolchain": ("rebrew.toolchain", "get_toolchain"),
    "iter_library_headers": ("rebrew.sources", "iter_library_headers"),
    "iter_sources": ("rebrew.sources", "iter_sources"),
    "load_config": ("rebrew.config", "load_config"),
}


def __getattr__(name: str) -> object:
    if name in _LAZY_EXPORTS:
        mod_name, attr_name = _LAZY_EXPORTS[name]
        import importlib

        mod = importlib.import_module(mod_name)
        val: object = getattr(mod, attr_name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + list(_LAZY_EXPORTS.keys()))


__all__ = ["__version__"]
