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

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src" / "rebrew" / "agent-skills"
_RENDERED = _REPO_ROOT / ".agents" / "skills"
_PRINCIPLES_SRC = _REPO_ROOT / "src" / "rebrew" / "PRINCIPLES.md"

#: Target name this repo's .agents/skills/ copy was rendered with.
RENDER_TARGET = "bench"

#: PRD 08 success metric: a SKILL.md must load in one agent fetch.
MAX_SKILL_LINES = 250

#: Hosts index a skill's description in full; past this the trigger tail is
#: invisible at selection time, which is the only time a description is read.
MAX_DESCRIPTION_CHARS = 1024


def _render(text: str) -> str:
    """Mirror the placeholder substitution in rebrew.init._copy_agent_skills."""
    return text.replace("<target>", RENDER_TARGET)


def _files(root: Path) -> dict[str, Path]:
    return {p.relative_to(root).as_posix(): p for p in root.rglob("*") if p.is_file()}


def _skills() -> dict[str, str]:
    """Every packaged SKILL.md, keyed by its skill name (its directory)."""
    return {
        rel.split("/")[0]: path.read_text(encoding="utf-8")
        for rel, path in _files(_SRC).items()
        if rel.endswith("/SKILL.md")
    }


def _frontmatter() -> dict[str, str]:
    """Frontmatter block of every packaged SKILL.md, keyed by skill name."""
    return {name: text.split("---", 2)[1] for name, text in _skills().items()}


def _name(frontmatter: str) -> str:
    match = re.search(r"^name:\s*(\S+)", frontmatter, re.M)
    return match.group(1) if match else ""


def _flattened_description(frontmatter: str) -> str:
    """Collapse a folded (``>-``) or plain description to the string a host sees."""
    lines: list[str] = []
    capture = False
    for line in frontmatter.splitlines():
        if line.startswith("description:"):
            capture = True
            lines.append(line.split(":", 1)[1])
        elif capture and re.match(r"^\s+\S", line):
            lines.append(line)
        else:
            capture = False
    return re.sub(r"\s+", " ", " ".join(lines)).strip()


def _referenced(skill: str, text: str) -> set[str]:
    """Reference paths a SKILL.md body points an agent at.

    A bare ``references/x.md`` belongs to the referring skill; an explicit
    ``<other-skill>/references/x.md`` is a cross-skill pointer, and is what
    makes a handoff to a sibling's reference unambiguous.
    """
    return {
        f"{prefix.rstrip('/') or skill}/references/{m}"
        for prefix, m in re.findall(r"((?:rebrew-[a-z-]+/)?)references/([a-z0-9-]+\.md)", text)
    }


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

    def test_skill_files_stay_under_the_fetch_budget(self) -> None:
        """PRD 08: SKILL.md stays under 250 lines so an agent loads it whole."""
        oversized = {
            rel: len(path.read_text(encoding="utf-8").splitlines())
            for rel, path in sorted(_files(_SRC).items())
            if path.suffix == ".md"
            and len(path.read_text(encoding="utf-8").splitlines()) > MAX_SKILL_LINES
        }
        assert oversized == {}, (
            f"{oversized} exceed the {MAX_SKILL_LINES}-line budget from docs/prd/08-agent-skills.md"
        )


class TestSkillFrontmatter:
    """Frontmatter is what the host indexes, so its shape is load-bearing.

    A missing ``name``/``description`` silently drops a skill from discovery,
    a ``name`` that disagrees with its directory splits one skill across two
    identities, and a description past the index cap is a trigger list whose
    tail the host never sees.
    """

    def test_every_skill_declares_name_and_description(self) -> None:
        incomplete = {
            rel: text.split("---", 2)[1]
            for rel, text in _frontmatter().items()
            if not re.search(r"^name:\s*\S", text, re.M)
            or not re.search(r"^description:\s*\S", text, re.M)
        }
        assert incomplete == {}, f"{sorted(incomplete)} lack a frontmatter name or description"

    def test_name_matches_its_directory(self) -> None:
        mismatched = {
            rel: _name(text)
            for rel, text in _frontmatter().items()
            if _name(text) != rel.split("/")[0]
        }
        assert mismatched == {}, f"{mismatched} declare a name that differs from their directory"

    def test_descriptions_fit_the_index(self) -> None:
        oversized = {rel: len(_flattened_description(text)) for rel, text in _frontmatter().items()}
        oversized = {rel: n for rel, n in oversized.items() if n > MAX_DESCRIPTION_CHARS}
        assert oversized == {}, (
            f"{oversized} exceed the {MAX_DESCRIPTION_CHARS}-char description budget; "
            "the trigger vocabulary past the cap is never indexed"
        )


class TestSkillLinks:
    """Progressive disclosure is a promise: a dangling reference file is a
    section the agent is told to read and cannot."""

    def test_referenced_files_exist(self) -> None:
        dangling = {
            rel: sorted(_referenced(rel, text) - set(_files(_SRC)))
            for rel, text in _skills().items()
        }
        dangling = {rel: missing for rel, missing in dangling.items() if missing}
        assert dangling == {}, f"{dangling} point at reference files the package does not ship"

    def test_reference_files_are_referenced(self) -> None:
        skills = _skills()
        orphaned = sorted(
            rel
            for rel in _files(_SRC)
            if "/references/" in rel
            and not _referenced(rel.split("/")[0], skills[rel.split("/")[0]])
        )
        assert orphaned == [], f"{orphaned} are shipped but no SKILL.md points at them"


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
    """A skill that quotes a closed value set is stale the moment the code moves.

    ``validate_skill_commands.py`` proves every documented *flag* still
    resolves, but a flag's accepted values are invisible to a ``--help``
    probe: renamed a tier or a decompiler backend, every flag still checks
    out and the skill sends the agent a value the CLI rejects. These pin the
    sets the skills spell out.
    """

    def test_workflow_lists_every_metadata_field(self) -> None:
        from rebrew.metadata import METADATA_FIELDS

        text = (_SRC / "rebrew-workflow" / "SKILL.md").read_text(encoding="utf-8")
        missing = sorted(f for f in METADATA_FIELDS if f not in text)
        assert missing == [], f"rebrew-workflow SKILL.md metadata key list lacks {missing}"

    def test_workflow_lists_every_todo_category(self) -> None:
        from rebrew.todo import _CATEGORY_COLORS

        text = (_SRC / "rebrew-workflow" / "SKILL.md").read_text(encoding="utf-8")
        missing = sorted(c for c in _CATEGORY_COLORS if c not in text)
        assert missing == [], f"rebrew-workflow SKILL.md 'todo -c' list lacks {missing}"

    def test_intake_lists_every_decompiler_backend(self) -> None:
        from rebrew.decompiler import BACKENDS

        text = (_SRC / "rebrew-intake" / "SKILL.md").read_text(encoding="utf-8")
        missing = sorted(b for b in (*BACKENDS, "ghidra", "auto") if b not in text)
        assert missing == [], f"rebrew-intake SKILL.md --decomp-backend list lacks {missing}"

    def test_flag_sweep_table_matches_the_engine(self) -> None:
        """The reference quotes a combination count per tier; recompute them.

        A tier's count is the product of the flag axes it selects, so a flag
        added to or dropped from an axis silently changes the cost the skill
        tells the agent it is about to pay.
        """
        import math
        import re

        import rebrew.matcher.compiler as compiler
        from rebrew.matcher import MSVC_SWEEP_TIERS

        text = (_SRC / "rebrew-matching/references/flag-sweep.md").read_text(encoding="utf-8")
        documented = {
            tier: int(count.replace(",", ""))
            for tier, count in re.findall(r"^\| `(\w+)` \| ([\d,]+) \|", text, re.M)
        }

        profile = "msvc-6.0"
        flags, tiers = compiler.refresh_flag_sets()
        # A profile without a plugin sweep set takes the packaged default,
        # the same fallback generate_flag_combinations applies.
        actual = {
            tier: math.prod(len(axis) for axis in compiler._flags_to_axes(flags[profile], ids))
            for tier, ids in tiers.get(profile, MSVC_SWEEP_TIERS).items()
        }

        assert documented == actual, (
            f"flag-sweep.md tier table {documented} no longer matches the engine {actual}"
        )
