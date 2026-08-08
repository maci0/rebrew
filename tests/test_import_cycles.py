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
