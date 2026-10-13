"""compiler — compile execution and the compile cache.

`compile.py` compiles a source and compares it against the target bytes,
`toolchain.py` resolves a profile and runs its docker image, `cache.py` keys
and stores compile results, and `overrides.py` / `context.py` decide the
flags and declarations one compile is pinned to.

Import submodules by name (``rebrew.compiler.compile``, …); this package
exports no public names of its own.
"""

__all__: list[str] = []
