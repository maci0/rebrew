"""recompile.online — compiler-as-a-service API.

Submits C source with a toolchain id (msvc6, msvc1.52, watcom, delphi16,
gcc-pe) and returns the compiled artifact, executing each compile inside the
matching toolchain container (``rebrew/msvc:6.0-win32`` etc.) so the
environment is sandboxed and reproducible.
"""

__version__ = "0.1.0"
