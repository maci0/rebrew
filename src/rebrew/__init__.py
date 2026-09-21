"""rebrew — compiler-in-the-loop decompilation workbench.

A toolkit for binary-matching game reversing, providing a genetic algorithm
engine, annotation pipeline, verification framework, and CLI tools for
reconstructing exact C source from compiled binaries.

Library consumers typically import submodules directly, for example:

* ``rebrew.compile`` — ``CompareResult``, ``compile_and_compare``
* ``rebrew.config`` — ``ProjectConfig``, ``load_config``
* ``rebrew.sources`` — ``iter_sources``, ``iter_library_headers``
* ``rebrew.toolchain`` — ``ToolchainError``, ``get_toolchain``, ``require_toolchains_repo``
* ``rebrew.recompile_client`` — remote compile transport
* ``rebrew.registry`` / ``rebrew.plugin`` — entry-point extension hooks
* ``rebrew.workspace`` — stdlib-light project/root and coverage.db helpers
* ``rebrew.matcher`` — GA mutations and scoring
* ``rebrew.ghidra`` — ``McpError``, ``McpErrorKind``, structural ReVa ops
"""

__version__ = "2.6.0"

__all__ = ["__version__"]
