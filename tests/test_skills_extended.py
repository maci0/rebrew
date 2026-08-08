"""Tests for rebrew skills.py — discovery, frontmatter matching, CLI fallbacks."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import rebrew.skills as skills


def _skill_dir(tmp_path: Path, name: str, frontmatter_name: str | None = None) -> Path:
    d = tmp_path / name
    d.mkdir()
    fm_name = frontmatter_name or name
    (d / "SKILL.md").write_text(
        f"---\nname: {fm_name}\ndescription: Does the thing. More detail.\n---\n\n# Guide\n",
        encoding="utf-8",
    )
    return d


class TestFindSkill:
    def test_match_by_dir_name(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _skill_dir(tmp_path, "my-skill")
        monkeypatch.setattr(skills, "_SKILLS_DIR", tmp_path)
        assert skills._find_skill("my-skill") is not None

    def test_match_by_frontmatter_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _skill_dir(tmp_path, "dir-name", frontmatter_name="display-name")
        monkeypatch.setattr(skills, "_SKILLS_DIR", tmp_path)
        assert skills._find_skill("display-name") is not None

    def test_missing_dir_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(skills, "_SKILLS_DIR", Path("/nonexistent/skills"))
        assert skills._find_skill("x") is None

    def test_not_found_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _skill_dir(tmp_path, "a")
        monkeypatch.setattr(skills, "_SKILLS_DIR", tmp_path)
        assert skills._find_skill("zzz") is None


class TestSkillsCli:
    def test_list_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _skill_dir(tmp_path, "rebrew-workflow", frontmatter_name="rebrew-workflow")
        monkeypatch.setattr(skills, "_SKILLS_DIR", tmp_path)
        result = CliRunner().invoke(skills.app, ["list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["skills"][0]["name"] == "rebrew-workflow"

    def test_list_empty_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(skills, "_SKILLS_DIR", tmp_path)
        result = CliRunner().invoke(skills.app, ["list"])
        assert result.exit_code == 0
        assert "No skills found" in result.output

    def test_show_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _skill_dir(tmp_path, "rebrew-intake")
        monkeypatch.setattr(skills, "_SKILLS_DIR", tmp_path)
        result = CliRunner().invoke(skills.app, ["show", "rebrew-intake", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["name"] == "rebrew-intake"
        assert "# Guide" in data["content"]

    def test_show_not_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _skill_dir(tmp_path, "a")
        monkeypatch.setattr(skills, "_SKILLS_DIR", tmp_path)
        result = CliRunner().invoke(skills.app, ["show", "missing"])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_show_markdown_fallback(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _skill_dir(tmp_path, "rebrew-intake")
        monkeypatch.setattr(skills, "_SKILLS_DIR", tmp_path)

        def _boom(text):
            raise RuntimeError("no markdown")

        monkeypatch.setattr("rich.markdown.Markdown", _boom)
        result = CliRunner().invoke(skills.app, ["show", "rebrew-intake"])
        assert result.exit_code == 0
        # Fallback plain output lands on CliRunner-captured stdout.
        assert "# Guide" in result.stdout
