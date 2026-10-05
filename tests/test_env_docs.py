"""Guard the runtime env-var documentation against drift.

Two directions, both over the names the code actually mentions:

* every ``REBREW_*`` name in ``src/`` and ``tools/`` (minus the compile-time
  defines, CMake variables emitted for generated projects, and C header guards
  below) appears in ``docs/CONFIG.md`` *and* in ``.env.example``;
* every ``REBREW_*`` name in ``.env.example`` is read somewhere, so the
  template cannot advertise a knob that does not exist.  The names below that
  never reach the process environment are exempt from both directions:
  ``.env.example`` lists some of them precisely to say "not a knob"
  (``REBREW_XVFB_AUTH``).
"""

from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_NAME_RE = re.compile(r"REBREW_[A-Z0-9_]+")

#: REBREW_* names that never reach the process environment: preprocessor
#: defines (``-DREBREW_ALLOW_NAKED``), CMake variables the generated
#: ``rebrew build cmake-sources`` CMakeLists consumes, a generated C header guard,
#: a binsync state-dir marker, the ownership cookie rebrew stamps on its own
#: Xvfb child (read back from ``/proc``, never set by the analyst), and
#: Python identifier fragments.
_NOT_ENV_VARS = frozenset(
    {
        "REBREW_ALLOW_NAKED",
        "REBREW_DEBUG_INFO",
        "REBREW_DIR",
        "REBREW_EXTERNAL_LIBS",
        "REBREW_GLOBALS_H",
        # Generated CMake-local variables, not process environment settings.
        "REBREW_CMAKE_AR_COMMAND",
        "REBREW_EXECUTABLE",
        "REBREW_LINK_EXE",
        "REBREW_LLM_",
        "REBREW_NAKED",
        "REBREW_FLIRT_SIGS_DIR_ENV",
        "REBREW_PROJECTS_ROOT_ENV",
        "REBREW_SKILLS_DIR_ENV",
        "REBREW_SOURCES",
        "REBREW_STATE_VERSION",
        "REBREW_TOML",
        "REBREW_XVFB_AUTH",
    }
)


def _source_names() -> set[str]:
    names: set[str] = set()
    for root in ("src", "tools"):
        for path in (_REPO / root).rglob("*.py"):
            names.update(_NAME_RE.findall(path.read_text(encoding="utf-8", errors="replace")))
    return names - _NOT_ENV_VARS


class TestEnvVarDocs:
    def test_every_env_var_is_documented(self) -> None:
        doc = (_REPO / "docs" / "CONFIG.md").read_text(encoding="utf-8")
        example = (_REPO / ".env.example").read_text(encoding="utf-8")
        undocumented = sorted(
            name for name in _source_names() if name not in doc or name not in example
        )
        assert not undocumented, f"undocumented env vars: {undocumented}"

    def test_env_example_has_no_phantom_vars(self) -> None:
        example = (_REPO / ".env.example").read_text(encoding="utf-8")
        known = _source_names() | _NOT_ENV_VARS
        phantom = sorted({name for name in _NAME_RE.findall(example) if name not in known})
        assert not phantom, f".env.example documents vars the code never reads: {phantom}"
