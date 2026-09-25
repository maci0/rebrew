"""Regression guard: the rebrew package must have no module-level import cycles.

Backs ``tools/detect_cycles.py``; a cycle would mean some ``import rebrew.X``
order can fail at load time.
"""

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _load_detect_cycles() -> object:
    spec = importlib.util.spec_from_file_location(
        "detect_cycles", _ROOT / "tools" / "detect_cycles.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_no_module_level_import_cycles() -> None:
    detect_cycles = _load_detect_cycles().detect_cycles
    cycles = detect_cycles(str(_ROOT / "src" / "rebrew"))
    assert cycles == [], f"Module-level import cycles found: {cycles}"


def test_shared_libraries_do_not_import_command_modules() -> None:
    """PE parsing, pseudo-C rewrite, and the decompiler backends load on their own.

    ``link-sweep`` and Kuna seeding call the first two as libraries.  The
    decompiler backends fetch text; the ``rebrew fix`` command is a caller
    of the rewrite, and importing a backend must leave that command unloaded.
    """
    import subprocess
    import sys

    code = (
        "import rebrew.decompiler, rebrew.pe_image, rebrew.pseudo_c, sys\n"
        "bad = [n for n in ('rebrew.cli', 'rebrew.gen_layout', 'rebrew.fixup') if n in sys.modules]\n"
        "raise SystemExit(0 if not bad else ','.join(bad))\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
