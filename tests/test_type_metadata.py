"""Durable, target-scoped type identity and layout evidence."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cli_json import cli_payload

from rebrew.types import parse_structs


def _project(root: Path) -> Any:
    (root / "types.h").write_text("typedef struct ITEM { int value; } ITEM;\n")
    (root / "a.exe").write_bytes(b"native")
    return SimpleNamespace(
        root=root,
        metadata_dir=root,
        module="A",
        target_modules=["A", "B"],
        target_binary=root / "a.exe",
        compiler_profile="test",
        cflags="",
        base_cflags="",
        compiler_includes=None,
        shared_dir=None,
    )


class TestTypeMetadata:
    def test_tag_and_typedef_spelling_both_identify_the_definition(self) -> None:
        from rebrew.type_metadata import struct_definition_names

        assert struct_definition_names("typedef struct ITEM { int x; } Item;") == {"ITEM", "Item"}
        assert struct_definition_names("typedef struct ITEM { int x; } ITEM;") == {"ITEM"}

    @pytest.mark.parametrize("change", ["header", "flags", "binary", "defines"])
    def test_input_changes_stale_evidence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
    ) -> None:
        from rebrew.type_metadata import bind_type, check_types

        cfg = _project(tmp_path)
        (tmp_path / "types.h").write_text(
            '#include "dep.h"\ntypedef struct ITEM { int value; } ITEM;\n'
        )
        (tmp_path / "dep.h").write_text("/* initial */\n")
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        if change == "header":
            (tmp_path / "dep.h").write_text("/* changed */\n")
        elif change == "flags":
            cfg.base_cflags = "/Zp1"
        elif change == "defines":
            cfg.defines = ["GOLD"]
        else:
            (tmp_path / "a.exe").write_bytes(b"different native")
        assert "stale" in check_types(cfg)[0]["issue"]

    @pytest.mark.parametrize(
        "field,value",
        [
            pytest.param("size", True),
            pytest.param("size", -1),
            pytest.param("native_size", 1),
            pytest.param("extent", []),
            pytest.param("offsets", {"value": 4}),
            pytest.param("symbol", "ITEM; bad()"),
            pytest.param("evidence", ""),
        ],
    )
    def test_invalid_record_never_replaces_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
    ) -> None:
        from rebrew.type_metadata import bind_type

        cfg = _project(tmp_path)
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        args: dict[str, Any] = {
            "size": 4,
            "native_size": 4,
            "extent": "allocation",
            "evidence": "native",
            "offsets": {},
            "symbol": "ITEM",
        }
        bind_type(cfg, "engine.item", Path("types.h"), **args)
        before = (tmp_path / "rebrew-types.toml").read_bytes()
        args[field] = value
        with pytest.raises(ValueError):
            bind_type(cfg, "engine.item", Path("types.h"), **args)
        assert (tmp_path / "rebrew-types.toml").read_bytes() == before

    def test_compile_race_and_symlink_escape(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type

        cfg = _project(tmp_path)

        def changed(*args: Any) -> None:
            (tmp_path / "types.h").write_text(
                "typedef struct ITEM { int value; int other; } ITEM;\n"
            )

        monkeypatch.setattr("rebrew.type_metadata.compile_type", changed)
        with pytest.raises(ValueError, match="changed during"):
            bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        assert not (tmp_path / "rebrew-types.toml").exists()
        (tmp_path / "outside.h").symlink_to(tmp_path.parent / "other.h")
        with pytest.raises(ValueError):
            bind_type(
                cfg, "engine.item", Path("outside.h"), "ITEM", 4, 4, "allocation", "native", {}
            )

    def test_lint_reports_stale_bindings(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.lint import _check_W031_type_metadata
        from rebrew.type_metadata import bind_type

        cfg = _project(tmp_path)
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        assert _check_W031_type_metadata(cfg) == []
        cfg.base_cflags = "/Zp1"
        assert _check_W031_type_metadata(cfg)[0].warnings

    def test_conditional_fields_are_not_a_complete_layout(self) -> None:
        types = parse_structs(
            "typedef struct ITEM { int x;\n#ifdef GOLD\nint y;\n#endif\nint z; } ITEM;"
        )
        assert not types["ITEM"].complete
        assert types["ITEM"].fields == [("x", "int", 0)]

    def test_bind_then_stale_and_rebind_keeps_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type, check_types, load_types

        cfg = _project(tmp_path)
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(
            cfg,
            "engine.item",
            Path("types.h"),
            "ITEM",
            4,
            4,
            "allocation",
            "A:0x401000 allocation",
            {"value": 0},
        )
        assert check_types(cfg) == []
        assert len(load_types(tmp_path)) == 1
        assert (tmp_path / "rebrew-types.toml").stat().st_mode & 0o777 == 0o444
        (tmp_path / "types.h").write_text("typedef struct ITEM { int value; int other; } ITEM;\n")
        assert "stale" in check_types(cfg)[0]["issue"]
        bind_type(
            cfg,
            "engine.item",
            Path("types.h"),
            "ITEM",
            8,
            8,
            "allocation",
            "reviewed new extent",
            {"value": 0},
        )
        assert load_types(tmp_path)[0]["id"] == "engine.item"
        assert check_types(cfg) == []

    def test_compiler_failure_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type

        cfg = _project(tmp_path)

        def fail(*args: Any) -> None:
            raise ValueError("layout compile failed")

        monkeypatch.setattr("rebrew.type_metadata.compile_type", fail)
        with pytest.raises(ValueError, match="layout compile"):
            bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        assert not (tmp_path / "rebrew-types.toml").exists()

    def test_target_variants_and_duplicate_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type, check_types, load_types

        cfg = _project(tmp_path)
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "stride", "native stride", {})
        cfg.module = "B"
        cfg.base_cflags = "/DGOLD"
        bind_type(
            cfg, "engine.item", Path("types.h"), "ITEM", 4, 8, "allocation", "partial view", {}
        )
        assert len(load_types(tmp_path)) == 2
        assert check_types(cfg) == []
        with pytest.raises(ValueError, match="already bound"):
            bind_type(cfg, "other", Path("types.h"), "ITEM", 4, 8, "allocation", "native", {})
        with pytest.raises(ValueError, match="already bound"):
            bind_type(
                cfg,
                "other",
                Path("types.h"),
                "ITEM",
                4,
                8,
                "allocation",
                "native",
                {},
                dry_run=True,
            )

    def test_dry_run_no_compile_and_corrupt_store_preserved(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type

        cfg = _project(tmp_path)

        def fail(*args: Any) -> None:
            pytest.fail("dry run compiled")

        monkeypatch.setattr("rebrew.type_metadata.compile_type", fail)
        bind_type(
            cfg,
            "engine.item",
            Path("types.h"),
            "ITEM",
            4,
            4,
            "allocation",
            "native",
            {},
            dry_run=True,
        )
        assert not (tmp_path / "rebrew-types.toml").exists()
        store = tmp_path / "rebrew-types.toml"
        store.write_text("not valid [")
        with pytest.raises(ValueError):
            bind_type(
                cfg,
                "engine.item",
                Path("types.h"),
                "ITEM",
                4,
                4,
                "allocation",
                "native",
                {},
                dry_run=True,
            )
        assert store.read_text() == "not valid ["

    def test_ambiguous_definition_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type

        cfg = _project(tmp_path)
        (tmp_path / "types.h").write_text(
            "#ifdef GOLD\ntypedef struct ITEM { int a; } ITEM;\n#else\ntypedef struct ITEM { int b; } ITEM;\n#endif\n"
        )
        with pytest.raises(ValueError, match="unique"):
            bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})


class TestTypeCLI:
    def test_bind_and_check_json_and_stale_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        from typer.testing import CliRunner

        from rebrew.types_cli import app

        cfg = _project(tmp_path)
        cfg.reversed_dir = tmp_path
        monkeypatch.setattr("rebrew.types_cli.require_config", lambda **kwargs: cfg)
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        monkeypatch.setattr("rebrew.sources.iter_sources", lambda *args: [])
        runner = CliRunner()
        args = [
            "bind",
            "engine.item",
            "types.h",
            "ITEM",
            "--size",
            "4",
            "--native-size",
            "4",
            "--evidence",
            "native",
            "--field",
            "value=0",
            "--json",
        ]
        bound = runner.invoke(app, args)
        assert bound.exit_code == 0, bound.output
        assert cli_payload(bound)["id"] == "engine.item"
        current = runner.invoke(app, ["check", "--compile", "--json"])
        assert current.exit_code == 0, current.output
        assert cli_payload(current)["type_findings"] == []
        cfg.base_cflags = "/Zp1"
        stale = runner.invoke(app, ["check", "--json"])
        assert stale.exit_code == 1, stale.output
        assert "stale" in cli_payload(stale)["type_findings"][0]["issue"]
        assert runner.invoke(app, ["check"]).exit_code == 1

    def test_generated_probe_uses_type_and_target_flags(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.config import ProjectConfig
        from rebrew.type_metadata import compile_type

        (tmp_path / "types.h").write_text("struct ITEM { int value; };\n")
        (tmp_path / "includes").mkdir()
        cfg = ProjectConfig(
            root=tmp_path,
            reversed_dir=tmp_path,
            base_cflags="/Iincludes",
            defines=["GOLD"],
            shared_dir=tmp_path / "includes",
        )

        def fake_compile(
            config: Any, source: Path, flags: list[str], workdir: Path, **kwargs: Any
        ) -> tuple[str, str]:
            text = source.read_text()
            assert "sizeof(struct ITEM) == 4" in text
            assert "offsetof(struct ITEM, value) == 0" in text
            assert config.defines == ["GOLD"]
            assert str(tmp_path / "includes") in config.base_cflags
            assert flags == ["/O2"]
            assert kwargs["use_cache"] is False
            assert kwargs["extra_include_dirs"] == [str(tmp_path)]
            return "checked.obj", ""

        monkeypatch.setattr("rebrew.compiler.compile.compile_to_obj", fake_compile)
        compile_type(
            cfg,
            {
                "file": "types.h",
                "symbol": "ITEM",
                "size": 4,
                "offsets": {"value": 0},
                "cflags": "/O2",
            },
        )
