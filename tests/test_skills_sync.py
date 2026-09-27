"""test_skills_sync.py – .agents/skills must mirror src/rebrew/agent-skills.

``src/rebrew/agent-skills/`` is the canonical, packaged skill tree (served by
``rebrew skills``); ``rebrew init`` renders it into a project's
``.agents/skills/`` directory with ``<target>`` replaced by the target name.
This repo's own ``.agents/skills/`` is such a rendered copy (target
``bench``).  The two trees have drifted before — this test pins them.

Fix on failure (from repo root)::

    make gen-skills
    cp src/rebrew/PRINCIPLES.md PRINCIPLES.md   # only if the principles drift
"""

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src" / "rebrew" / "agent-skills"
_RENDERED = _REPO_ROOT / ".agents" / "skills"
_PRINCIPLES_SRC = _REPO_ROOT / "src" / "rebrew" / "PRINCIPLES.md"

#: Target name this repo's .agents/skills/ copy was rendered with.
RENDER_TARGET = "bench"


def _render(text: str) -> str:
    """Mirror the placeholder substitution in rebrew.init._copy_agent_skills."""
    return text.replace("<target>", RENDER_TARGET)


def _files(root: Path) -> dict[str, Path]:
    return {p.relative_to(root).as_posix(): p for p in root.rglob("*") if p.is_file()}


class TestSkillsSync:
    def test_canonical_tree_exists(self) -> None:
        assert (_SRC / "rebrew-workflow" / "SKILL.md").is_file()

    def test_rendered_tree_exists(self) -> None:
        assert (_RENDERED / "rebrew-workflow" / "SKILL.md").is_file()

    def test_file_sets_match(self) -> None:
        assert set(_files(_SRC)) == set(_files(_RENDERED))

    def test_contents_match_after_substitution(self) -> None:
        stale = []
        for rel, src_path in sorted(_files(_SRC).items()):
            want = _render(src_path.read_text(encoding="utf-8"))
            got = _files(_RENDERED)[rel].read_text(encoding="utf-8")
            if want != got:
                stale.append(rel)
        assert stale == [], (
            f"{stale} drifted from src/rebrew/agent-skills/; run 'make gen-skills' to re-render"
        )


class TestPrinciplesSync:
    """The checked-in root PRINCIPLES.md is a copy of the packaged one.

    ``rebrew init --check`` compares a project's PRINCIPLES.md byte for
    byte against ``src/rebrew/PRINCIPLES.md``, so this repo is drifted the
    moment the packaged copy moves without the root.  ``docs/PRINCIPLES.md``
    is a symlink and must stay one, or it drifts silently instead.
    """

    def test_root_copy_matches_packaged(self) -> None:
        stale = (_REPO_ROOT / "PRINCIPLES.md").read_bytes()
        assert stale == _PRINCIPLES_SRC.read_bytes(), (
            "PRINCIPLES.md drifted from src/rebrew/PRINCIPLES.md; copy the packaged file over it"
        )

    def test_docs_entry_is_a_symlink(self) -> None:
        docs_copy = _REPO_ROOT / "docs" / "PRINCIPLES.md"
        assert docs_copy.is_symlink(), "docs/PRINCIPLES.md must symlink src/rebrew/PRINCIPLES.md"
        assert docs_copy.resolve() == _PRINCIPLES_SRC.resolve()


class TestSkillFacts:
    def test_workflow_lists_every_metadata_field(self) -> None:
        from rebrew.metadata import METADATA_FIELDS

        text = (_SRC / "rebrew-workflow" / "SKILL.md").read_text(encoding="utf-8")
        missing = sorted(f for f in METADATA_FIELDS if f not in text)
        assert missing == [], f"rebrew-workflow SKILL.md metadata key list lacks {missing}"
