"""Configured comment dialects preserve syntax-bound address identity."""

from types import SimpleNamespace
lazy from pathlib import Path

import pytest

from rebrew.config import AddressCommentFormat, address_comments_for_file, load_config
from rebrew.errors import ConfigError
from rebrew.metadata.anchors import add_address_anchor, address_comment, parse_address_anchors
from rebrew.metadata.bindings import read_source_bindings
from rebrew.source_register import plan_registration


class TestCommentFormats:
    @pytest.mark.parametrize(
        "style, expected",
        [
            ("c89", "/* ADDRESS: MAIN 0x00001000 */"),
            ("cpp", "// ADDRESS: MAIN 0x00001000"),
            ("delphi", "{ ADDRESS: MAIN 0x00001000 }"),
        ],
    )
    def test_builtin_round_trip(self, style: str, expected: str) -> None:
        syntax = AddressCommentFormat(style=style)
        declaration = "procedure Run; begin end;" if style == "delphi" else "void Run(void) {}"
        assert address_comment("MAIN", 0x1000, syntax=syntax) == expected
        source = add_address_anchor(declaration + "\r\n", "MAIN", 0x1000, "Run", syntax=syntax)
        assert source == expected + "\r\n" + declaration + "\r\n"
        assert add_address_anchor(source, "MAIN", 0x1000, "Run", syntax=syntax) == source
        (anchor,) = parse_address_anchors(source, syntax=syntax)
        assert (anchor.module, anchor.va, anchor.name, anchor.definition_line) == (
            "MAIN",
            0x1000,
            "Run",
            2,
        )

    def test_custom_body_regex_and_template_and_cache_isolation(self) -> None:
        syntax = AddressCommentFormat(
            regex=r"NATIVE (?P<module>\S+)@(?P<va>0x[0-9a-f]+)",
            template="/* NATIVE $module@$va */",
        )
        source = add_address_anchor(
            "int Run(void) { return 1; }\n", "MAIN", 0x1000, "Run", syntax=syntax
        )
        assert parse_address_anchors(source) == []
        assert parse_address_anchors(source, syntax=syntax)[0].name == "Run"
        assert parse_address_anchors(source) == []

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"style": "typo"},
            {"regex": "["},
            {"regex": r"ADDRESS: (\S+) (0x[0-9a-f]+)"},
            {"template": "/* $module $va $unknown */"},
            {"template": "/* ADDRESS: $module $va */\n"},
            {"style": "delphi", "template": "/* ADDRESS: $module $va */"},
            {"regex": r"NATIVE (?P<module>\S+) (?P<va>0x[0-9a-f]+)"},
            {"template": "/* ADDRESS: $module $va */ code /* */"},
        ],
    )
    def test_invalid_configuration_is_rejected(self, kwargs: dict[str, str]) -> None:
        with pytest.raises(ConfigError):
            AddressCommentFormat(**kwargs)

    def test_delphi_implementation_only_strings_comments_and_forward_declarations(self) -> None:
        syntax = AddressCommentFormat(style="delphi")
        source = (
            "unit U;\ninterface\nprocedure Run;\nimplementation\n"
            "const S = '{ ADDRESS: WRONG 0x9999 }';\n"
            "{ disabled (* ADDRESS: WRONG 0x8888 *) }\n"
            "procedure Later; forward;\n"
            "{ ADDRESS: MAIN 0x1000 }\nprocedure Run; far;\nbegin end;\n"
            "(* ADDRESS: MAIN 0x2000 *)\nprocedure TForm.Click(Sender: TObject);\nbegin end;\nend.\n"
        )
        anchors = parse_address_anchors(source, syntax=syntax)
        assert [(a.name, a.va) for a in anchors] == [("Run", 0x1000), ("TForm.Click", 0x2000)]
        assert add_address_anchor(source, "MAIN", 0x1000, "Run", syntax=syntax) == source

    @pytest.mark.parametrize(
        "following",
        [
            "{$IFDEF X}\nprocedure Run; begin end;",
            "procedure Run; forward;",
            "procedure Run; external;",
            "var A, B: Integer;",
            "",
            "begin Run; end;",
        ],
    )
    def test_delphi_refuses_unbound_addresses(self, following: str) -> None:
        with pytest.raises(ValueError, match="exactly one"):
            parse_address_anchors(
                "{ ADDRESS: MAIN 0x1000 }\n" + following,
                syntax=AddressCommentFormat(style="delphi"),
            )


class TestCommentConfiguration:
    def test_custom_intake_and_prune_preserve_edited_stubs(self, tmp_path: Path) -> None:
        from rebrew.intake import classify_all, prune_stale_stubs

        (tmp_path / "rebrew-project.toml").write_text(
            "[project.address_comments]\n"
            "regex = 'NATIVE (?P<module>\\S+)@(?P<va>0x[0-9a-f]+)'\n"
            'template = "/* NATIVE $module@$va */"\n'
            '[targets.main]\nmodule="MAIN"\nreversed_dir="src"\n'
        )
        sources = tmp_path / "src"
        sources.mkdir()
        assert (
            classify_all(
                tmp_path,
                sources,
                "MAIN",
                [(0x1000, 4, "a"), (0x2000, 4, "b")],
                "unknown",
                "",
                metadata_dir=tmp_path,
            )
            == 2
        )
        edited = sources / "fcn_00002000.c"
        edited.write_text(edited.read_text().replace("\n}", "\n    return;\n}"))
        assert (
            prune_stale_stubs(
                tmp_path, sources, "MAIN", [], metadata_dir=tmp_path, prior_inventory=[]
            )
            == 1
        )
        assert edited.is_file()
        assert "NATIVE MAIN@0x00002000" in edited.read_text()

    def test_custom_comments_survive_source_merge(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.merge import app
        from rebrew.metadata.functions import record_function_rows

        (tmp_path / "rebrew-project.toml").write_text(
            "[project.address_comments]\n"
            "regex = 'NATIVE (?P<module>\\S+)@(?P<va>0x[0-9a-f]+)'\n"
            'template = "/* NATIVE $module@$va */"\n'
            '[targets.main]\nbinary = "original.exe"\nmodule = "MAIN"\nreversed_dir = "src"\n'
        )
        cfg = load_config(root=tmp_path, target="main")
        cfg.reversed_dir.mkdir()
        sources = []
        for name, va in (("first", 0x1000), ("second", 0x2000)):
            path = cfg.reversed_dir / f"{name}.c"
            path.write_text(
                address_comment("MAIN", va, syntax=cfg.address_comments)
                + f"\nint {name}(void) {{ return 1; }}\n"
            )
            sources.append(path)
        rows, _ = plan_registration(cfg, sources)
        record_function_rows(cfg.metadata_dir, rows)
        monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfg)
        output = cfg.reversed_dir / "combined.c"
        result = CliRunner().invoke(app, ["--force", "--output", str(output), *map(str, sources)])
        assert result.exit_code == 0, result.output
        assert [
            (a.name, a.va)
            for a in parse_address_anchors(output.read_text(), syntax=cfg.address_comments)
        ] == [("first", 0x1000), ("second", 0x2000)]
        assert "ADDRESS:" not in output.read_text()

    def test_shared_source_conflicts_and_configuration_edits(self, tmp_path: Path) -> None:
        config = tmp_path / "rebrew-project.toml"
        config.write_text(
            '[targets.a.address_comments]\nstyle="c89"\n[targets.b.address_comments]\nstyle="delphi"\n'
        )
        source = tmp_path / "src/shared/f.c"
        with pytest.raises(ConfigError, match="incompatible"):
            address_comments_for_file(source)
        config.write_text('[project.address_comments]\nstyle="cpp"\n')
        assert address_comments_for_file(source).style == "cpp"
        config.write_text('[project.address_comments]\nstyle="delphi"\n')
        assert address_comments_for_file(source).style == "delphi"

    def test_project_target_override_registration_and_metadata_read(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text(
            '[project.address_comments]\nstyle = "cpp"\n'
            '[targets.main]\nbinary = "original.exe"\nmodule = "MAIN"\nreversed_dir = "src"\nsource_ext = ".pas"\n'
            '[targets.main.address_comments]\nstyle = "delphi"\n'
        )
        source = tmp_path / "src" / "U.pas"
        source.parent.mkdir()
        source.write_text("{ ADDRESS: MAIN 0x1000 }\nprocedure Run; begin end;\n")
        cfg = load_config(root=tmp_path, target="main")
        assert cfg.address_comments.style == "delphi"
        assert cfg.as_dict()["address_comments"]["style"] == "delphi"
        assert address_comments_for_file(source) == cfg.address_comments
        functions, data = plan_registration(cfg, [source])
        assert functions[0]["identity"]["name"] == "Run"
        assert data == []
        bindings = read_source_bindings(source, metadata_dir=tmp_path)
        assert [(a.name, a.va) for a in bindings] == [("Run", 0x1000)]

    def test_custom_configuration_reaches_registration_and_bindings(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text(
            "[project.address_comments]\n"
            "regex = 'NATIVE (?P<module>\\S+)@(?P<va>0x[0-9a-f]+)'\n"
            'template = "/* NATIVE $module@$va */"\n'
            '[targets.main]\nbinary = "original.exe"\nmodule = "MAIN"\nreversed_dir = "src"\n'
        )
        source = tmp_path / "src" / "f.c"
        source.parent.mkdir()
        source.write_text("/* NATIVE MAIN@0x00001000 */\nint Run(void) { return 0; }\n")
        cfg = load_config(root=tmp_path, target="main")
        functions, _ = plan_registration(cfg, [source])
        assert functions[0]["va"] == 0x1000
        assert read_source_bindings(source, metadata_dir=tmp_path)[0].name == "Run"

    def test_delphi_source_state_is_rejected(self, tmp_path: Path) -> None:
        source = tmp_path / "U.pas"
        source.write_text("{ STATUS: EXACT }\n{ ADDRESS: MAIN 0x1000 }\nprocedure Run; begin end;")
        cfg = SimpleNamespace(
            root=tmp_path,
            metadata_dir=tmp_path,
            target_modules={"MAIN"},
            address_comments=AddressCommentFormat(style="delphi"),
        )
        with pytest.raises(ValueError, match="metadata tags"):
            plan_registration(cfg, [source])
