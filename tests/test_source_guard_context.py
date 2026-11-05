"""Guard plans preserve directive bytes and surface incompatible declarations."""

lazy from pathlib import Path

import pytest

from rebrew.source_guard_context import guard_contexts


def test_exact_nested_and_else_directives_preserve_source(tmp_path: Path) -> None:
    source = tmp_path / "a.c"
    original = (
        b"  #if FIRST\r\n/* comment */\r\nint first(void) { return 1; }\r\n"
        b"#elif SECOND\r\n#if INNER\r\nint second(void) { return 2; }\r\n#endif\r\n"
        b"#else\r\nint other(void) { return 3; }\r\n#endif\r\n"
    )
    source.write_bytes(original)
    report = guard_contexts([source])
    rows = {row["name"]: row for row in report["definitions"]}
    assert [g["directive"] for g in rows["second"]["guards"]] == [
        "  #if FIRST\r\n",
        "#elif SECOND\r\n",
        "#if INNER\r\n",
    ]
    assert [g["directive"] for g in rows["other"]["guards"]] == [
        "  #if FIRST\r\n",
        "#elif SECOND\r\n",
        "#else\r\n",
    ]
    assert report["inputs"][0]["source"].encode() == original
    assert not report["source_changed"] and not report["rewrite_supported"]
    assert source.read_bytes() == original


def test_conflicting_prototypes_are_explicit(tmp_path: Path) -> None:
    a, b = tmp_path / "a.c", tmp_path / "b.c"
    a.write_text(
        "#ifndef REBREW_SERVER\nvoid f(char *, unsigned int, const char *);\n"
        "int walk(void) { return 1; }\n#endif\n"
    )
    b.write_text("void f(char *, int, const char *);\nint animation(void) { return 2; }\n")
    report = guard_contexts([a, b])
    assert [x["name"] for x in report["declaration_conflicts"]] == ["f"]
    assert len(report["declaration_conflicts"][0]["declarations"]) == 2


def test_unbalanced_conditionals_refused(tmp_path: Path) -> None:
    source = tmp_path / "a.c"
    source.write_text("#if FEATURE\nint f(void) { return 0; }\n")
    with pytest.raises(ValueError, match="parse is incomplete"):
        guard_contexts([source])


def test_digest_guard_rejects_stale_plan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from rebrew.config import ProjectConfig
    from rebrew.source_organize import app

    source = tmp_path / "a.c"
    source.write_text("int f(void) { return 1; }\n")
    cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, module="SERVER", target_name="SERVER")
    monkeypatch.setattr("rebrew.source_organize.require_config", lambda **kwargs: cfg)
    monkeypatch.setattr("rebrew.source_organize.organization_configs", lambda cfg: [cfg])
    monkeypatch.setattr(
        "rebrew.source_organize.review_organization",
        lambda *a, **kw: {"input_digest": "current", "unknown": [], "problems": []},
    )
    result = CliRunner().invoke(
        app, ["guards", str(source), "--expected-digest", "stale", "--json"]
    )
    assert result.exit_code != 0 and "inputs changed" in result.output
    assert source.read_text() == "int f(void) { return 1; }\n"


def test_guards_refuse_config_change_during_target_loading(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from rebrew.config import ProjectConfig
    from rebrew.source_organize import app

    config = tmp_path / "rebrew-project.toml"
    config.write_text('[metadata]\nbackend = "toml"\n')
    source = tmp_path / "a.c"
    source.write_text("int f(void) { return 1; }\n")
    cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path, module="SERVER", target_name="SERVER")
    monkeypatch.setattr("rebrew.source_organize.require_config", lambda **kwargs: cfg)

    def change_config(context: ProjectConfig) -> list[ProjectConfig]:
        config.write_text('[metadata]\nbackend = "toml"\n# changed\n')
        return [context]

    monkeypatch.setattr("rebrew.source_organize.organization_configs", change_config)
    result = CliRunner().invoke(app, ["guards", str(source), "--json"])
    assert result.exit_code != 0 and "config changed" in result.output


def test_conflicting_definition_and_declaration_are_reported(tmp_path: Path) -> None:
    source = tmp_path / "a.c"
    source.write_text("void f(unsigned int);\nvoid f(int value) {}\n")
    assert guard_contexts([source])["declaration_conflicts"][0]["name"] == "f"


def test_msvc_calling_convention_preserves_original_offsets(tmp_path: Path) -> None:
    source = tmp_path / "a.c"
    original = "#ifndef SERVER\nvoid __cdecl f(int x) { }\n#endif\n"
    source.write_text(original)
    report = guard_contexts([source])
    definition = report["definitions"][0]
    raw = original.encode()
    assert raw[definition["start"] : definition["end"]] == b"void __cdecl f(int x) { }"
    assert definition["guards"][0]["directive"] == "#ifndef SERVER\n"


def test_multi_function_declaration_refused(tmp_path: Path) -> None:
    source = tmp_path / "a.c"
    source.write_text("int f(int), g(int);\nint g(float);\n")
    with pytest.raises(ValueError, match="multiple function declarators"):
        guard_contexts([source])


def test_parameter_comment_does_not_create_conflict(tmp_path: Path) -> None:
    source = tmp_path / "a.c"
    source.write_text("int f(int a /* x */);\nint f(int a){return a;}\n")
    assert guard_contexts([source])["declaration_conflicts"] == []


def test_conflicting_branch_declarations_retain_guard_context(tmp_path: Path) -> None:
    source = tmp_path / "a.c"
    source.write_text("#ifdef REBREW_GOLD\nint f(int);\n#else\nint f(float);\n#endif\n")
    conflict = guard_contexts([source])["declaration_conflicts"][0]
    assert conflict["overlap"] == "unassessed"
    assert [x["guards"][-1]["directive"] for x in conflict["declarations"]] == [
        "#ifdef REBREW_GOLD\n",
        "#else\n",
    ]
    raw = source.read_bytes()
    assert [raw[x["start"] : x["end"]] for x in conflict["declarations"]] == [
        b"int f(int);",
        b"int f(float);",
    ]
