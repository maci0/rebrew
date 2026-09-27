"""Guard rebrew-project.toml.example against drift from the loader's schema.

The example is the only complete list of every ``rebrew-project.toml`` key an
operator can copy, and ``load_config`` only *warns* on a key it does not know,
so both directions are invisible until a user hits them: a template typo
(``outputdir``) warns on every run, and a key the loader gained after the
template was written is documented nowhere.  Matching the shape of
``test_env_docs``, the two directions are checked over the names the loader
knows, counting a key documented in a comment (the template shows most
options commented out) as documented.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from rebrew.config import (
    _KNOWN_CACHE_KEYS,
    _KNOWN_COMPILER_KEYS,
    _KNOWN_LINK_KEYS,
    _KNOWN_LINT_KEYS,
    _KNOWN_LLM_KEYS,
    _KNOWN_TOP_KEYS,
    KNOWN_PROJECT_KEYS,
    KNOWN_TARGET_KEYS,
)

_REPO = Path(__file__).resolve().parents[1]
_EXAMPLE = _REPO / "rebrew-project.toml.example"

#: Keys written by a command rather than a human (``rebrew cfg set-cflags`` /
#: ``rebrew cfg add-module`` / ``rebrew gen-layout --layout-config``).  The
#: template names all three as comments, so they read as documented; they are
#: excluded from the key sets a hand-edited file is expected to carry.
_MACHINE_WRITTEN = frozenset({"cflags_presets", "origins", "layout"})


def _example_text() -> str:
    return _EXAMPLE.read_text(encoding="utf-8")


def _example() -> dict[str, object]:
    return tomllib.loads(_example_text())


def _as_table(raw: object, label: str) -> dict[str, object]:
    """The table *raw* holds, or an empty table when the section is absent."""
    from rebrew.config import _as_table as loader_table

    return loader_table(raw, label)


def _section(raw: dict[str, object], dotted: str) -> dict[str, object]:
    """The table at a dotted path, or an empty table when a level is absent."""
    table: dict[str, object] = raw
    for part in dotted.split("."):
        table = _as_table(table.get(part, {}), part)
    return table


class TestProjectTomlExample:
    def test_template_parses_and_uses_known_sections(self) -> None:
        """Every section the template declares is one the loader recognises.

        A misspelled section is the misspell case ``load_config`` only warns
        about, and the template is what a new project starts from.
        """
        raw = _example()
        unknown = set(raw) - _KNOWN_TOP_KEYS
        assert not unknown, f"rebrew-project.toml.example: unknown sections {sorted(unknown)}"
        assert "targets" in raw, "the example declares no [targets.*]"

    def test_template_sets_no_unknown_key(self) -> None:
        """Every key the template actually sets is one the loader recognises."""
        raw = _example()
        for section, known in (
            ("project", KNOWN_PROJECT_KEYS),
            ("project.lint", _KNOWN_LINT_KEYS),
            ("compiler", _KNOWN_COMPILER_KEYS),
            ("link", _KNOWN_LINK_KEYS),
            ("llm", _KNOWN_LLM_KEYS),
            ("cache", _KNOWN_CACHE_KEYS),
        ):
            table = _section(raw, section)
            unknown = set(table) - known
            assert not unknown, f"[{section}]: unknown keys {sorted(unknown)}"

        targets = _section(raw, "targets")
        for name, target in targets.items():
            table = _as_table(target, f"targets.{name}")
            unknown = set(table) - KNOWN_TARGET_KEYS
            assert not unknown, f"[targets.{name}]: unknown keys {sorted(unknown)}"
            compiler = _as_table(table.get("compiler", {}), f"targets.{name}.compiler")
            unknown = set(compiler) - _KNOWN_COMPILER_KEYS
            assert not unknown, f"[targets.{name}.compiler]: unknown keys {sorted(unknown)}"

    def test_every_known_key_is_documented(self) -> None:
        """A key the loader accepts but the template never names is undocumented."""
        text = _example_text()
        for label, keys in (
            ("[project]", KNOWN_PROJECT_KEYS),
            ("[project.lint]", _KNOWN_LINT_KEYS),
            ("[compiler]", _KNOWN_COMPILER_KEYS - _MACHINE_WRITTEN),
            ("[link]", _KNOWN_LINK_KEYS),
            ("[llm]", _KNOWN_LLM_KEYS),
            ("[cache]", _KNOWN_CACHE_KEYS),
            ("[targets.*]", KNOWN_TARGET_KEYS - _MACHINE_WRITTEN),
        ):
            undocumented = sorted(key for key in keys if key not in text)
            assert not undocumented, (
                f"rebrew-project.toml.example: {label} never documents {undocumented}"
            )
