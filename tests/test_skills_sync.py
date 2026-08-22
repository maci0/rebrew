"""test_skills_sync.py – .agents/skills must mirror src/rebrew/agent-skills.

``src/rebrew/agent-skills/`` is the canonical, packaged skill tree (served by
``rebrew skills``); ``rebrew init`` renders it into a project's
``.agents/skills/`` directory with ``<target>`` replaced by the target name.
This repo's own ``.agents/skills/`` is such a rendered copy (target
``bench``).  The two trees have drifted before — this test pins them.

Fix on failure (from repo root)::

    rm -rf .agents/skills
    cp -r src/rebrew/agent-skills .agents/skills
    find .agents/skills -name '*.md' -exec sed -i 's/<target>/bench/g' {} +
"""

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src" / "rebrew" / "agent-skills"
_RENDERED = _REPO_ROOT / ".agents" / "skills"

#: Target name this repo's .agents/skills/ copy was rendered with.
RENDER_TARGET = "bench"


def _render(text: str) -> str:
    """Mirror the placeholder substitution in rebrew.init._copy_agent_skills."""
    return text.replace("<target>", RENDER_TARGET)


def _files(root: Path) -> dict[str, Path]:
    return {str(p.relative_to(root)): p for p in root.rglob("*") if p.is_file()}


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
            f"{stale} drifted from src/rebrew/agent-skills/; "
            "see this file's docstring for the re-render command"
        )
