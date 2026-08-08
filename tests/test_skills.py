"""Tests for rebrew.skills — skill discovery and display commands."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from rebrew.skills import _find_skill, _list_skills, _parse_frontmatter
from rebrew.skills import app as skills_app

runner = CliRunner()

# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------


class TestParseFrontmatter:
    def test_basic_frontmatter(self) -> None:
        text = "---\nname: my-skill\ndescription: A test skill.\nlicense: MIT\n---\n# Body\n"
        fm = _parse_frontmatter(text)
        assert fm["name"] == "my-skill"
        assert fm["description"] == "A test skill."
        assert fm["license"] == "MIT"

    def test_no_frontmatter(self) -> None:
        text = "# Just a markdown file\nNo frontmatter here.\n"
        fm = _parse_frontmatter(text)
        assert fm == {}

    def test_description_with_colon(self) -> None:
        text = "---\nname: foo\ndescription: Does X: and Y.\n---\n"
        fm = _parse_frontmatter(text)
        assert fm["description"] == "Does X: and Y."


class TestListSkills:
    def test_returns_list(self) -> None:
        skills = _list_skills()
        # The real agent-skills dir should have entries
        assert isinstance(skills, list)

    def test_each_entry_has_name(self) -> None:
        for s in _list_skills():
            assert "name" in s
            assert s["name"]

    def test_each_entry_has_description(self) -> None:
        for s in _list_skills():
            assert "description" in s

    def test_all_known_skills_present(self) -> None:
        names = {s["name"] for s in _list_skills()}
        assert "rebrew-workflow" in names
        assert "rebrew-intake" in names
        assert "rebrew-matching" in names


class TestFindSkill:
    def test_finds_by_frontmatter_name(self) -> None:
        path = _find_skill("rebrew-workflow")
        assert path is not None
        assert path.is_file()
        assert path.name == "SKILL.md"

    def test_finds_by_dir_name(self) -> None:
        # Directory name and frontmatter name should both resolve
        path = _find_skill("rebrew-intake")
        assert path is not None

    def test_returns_none_for_missing(self) -> None:
        assert _find_skill("no-such-skill-xyz") is None


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestCLISkillsList:
    def test_list_exits_zero(self) -> None:
        result = runner.invoke(skills_app, ["list"])
        assert result.exit_code == 0

    def test_list_shows_known_skills(self) -> None:
        result = runner.invoke(skills_app, ["list"])
        assert "rebrew-workflow" in result.output

    def test_list_json_output(self) -> None:
        result = runner.invoke(skills_app, ["list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "skills" in data
        names = [s["name"] for s in data["skills"]]
        assert "rebrew-workflow" in names
        assert "rebrew-intake" in names

    def test_list_json_has_description(self) -> None:
        result = runner.invoke(skills_app, ["list", "--json"])
        data = json.loads(result.output)
        for s in data["skills"]:
            assert "description" in s
            assert s["description"]


class TestCLISkillsShow:
    def test_show_known_skill(self) -> None:
        result = runner.invoke(skills_app, ["show", "rebrew-workflow"])
        assert result.exit_code == 0
        # Should contain at least the skill title
        assert "rebrew" in result.output.lower() or "workflow" in result.output.lower()

    def test_show_unknown_skill_fails(self) -> None:
        result = runner.invoke(skills_app, ["show", "no-such-skill-xyz"])
        assert result.exit_code != 0

    def test_show_json_output(self) -> None:
        result = runner.invoke(skills_app, ["show", "rebrew-workflow", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "rebrew-workflow"
        assert "content" in data
        assert "description" in data

    def test_show_content_is_non_empty(self) -> None:
        result = runner.invoke(skills_app, ["show", "rebrew-intake", "--json"])
        data = json.loads(result.output)
        assert len(data["content"]) > 100  # SKILL.md is not trivially short


class TestSkillsEdgeCases:
    def test_list_skills_missing_dir(self, monkeypatch) -> None:
        from pathlib import Path

        import rebrew.skills as skills

        monkeypatch.setattr(skills, "_SKILLS_DIR", Path("/nonexistent/skills"))
        assert skills._list_skills() == []

    def test_find_skill_missing_dir(self, monkeypatch) -> None:
        from pathlib import Path

        import rebrew.skills as skills

        monkeypatch.setattr(skills, "_SKILLS_DIR", Path("/nonexistent/skills"))
        assert skills._find_skill("x") is None

    def test_list_skills_skips_non_md_dirs(self, tmp_path, monkeypatch) -> None:
        import rebrew.skills as skills

        (tmp_path / "no_skill_md").mkdir()
        (tmp_path / "with_skill").mkdir()
        (tmp_path / "with_skill" / "SKILL.md").write_text(
            "---\nname: demo\n---\n", encoding="utf-8"
        )
        monkeypatch.setattr(skills, "_SKILLS_DIR", tmp_path)
        names = [s["name"] for s in skills._list_skills()]
        assert names == ["demo"]

    def test_find_by_directory_name(self, tmp_path, monkeypatch) -> None:
        import rebrew.skills as skills

        (tmp_path / "myname").mkdir()
        md = tmp_path / "myname" / "SKILL.md"
        md.write_text("no frontmatter", encoding="utf-8")
        monkeypatch.setattr(skills, "_SKILLS_DIR", tmp_path)
        assert skills._find_skill("myname") == md
