"""Unit tests for the shared parsed type model."""

from pathlib import Path

from rebrew.types import StructDef, parse_structs


class TestParseStructs:
    def test_flat_struct_offsets(self) -> None:
        structs = parse_structs("typedef struct { int x; char y; short z; } Foo;")
        foo = structs["Foo"]
        assert isinstance(foo, StructDef)
        assert foo.fields == [("x", "int", 0), ("y", "char", 4), ("z", "short", 6)]
        assert foo.size == 8

    def test_pointer_and_array(self) -> None:
        structs = parse_structs("typedef struct { int *p; char buf[8]; } Bar;")
        bar = structs["Bar"]
        assert bar.fields == [("p", "int *", 0), ("buf", "char[8]", 4)]
        assert bar.size == 12

    def test_named_struct_tag(self) -> None:
        structs = parse_structs("struct Baz { int a; int b; };")
        assert structs["Baz"].size == 8

    def test_forward_reference_resolves(self) -> None:
        """A field typed as a struct declared LATER still gets its size."""
        structs = parse_structs(
            "typedef struct { Inner inner; int tail; } Outer;\n"
            "typedef struct { int a; int b; } Inner;"
        )
        outer = structs["Outer"]
        assert outer.complete
        assert [f[2] for f in outer.fields] == [0, 8]
        assert outer.size == 12

    def test_unknown_returns_empty(self) -> None:
        assert parse_structs("int x;") == {}
        assert parse_structs("") == {}


class TestStructSizes:
    def test_known_type_sizes(self) -> None:
        from rebrew.types import type_size

        assert type_size("int") == 4
        assert type_size("char") == 1
        assert type_size("short") == 2
        assert type_size("long") == 4
        assert type_size("float") == 4
        assert type_size("double") == 8
        assert type_size("void *") == 4
        assert type_size("char[16]") == 16
        assert type_size("int[4]") == 16

    def test_unknown_type_is_none(self) -> None:
        from rebrew.types import type_size

        assert type_size("struct Unknown") is None
        assert type_size("") is None

    def test_array_of_double_aligns_to_eight(self) -> None:
        """An array aligns by its element: ``double arr[2]`` is 8-aligned."""
        s = parse_structs("typedef struct { char c; double arr[2]; } S;")["S"]
        assert [f[2] for f in s.fields] == [0, 8]
        assert s.size == 24

    def test_array_of_int_still_aligns_to_four(self) -> None:
        s = parse_structs("typedef struct { char c; int arr[2]; } S;")["S"]
        assert [f[2] for f in s.fields] == [0, 4]
        assert s.size == 12


class TestCheckStruct:
    def test_clean_declaration(self) -> None:
        from rebrew.types import check_struct, parse_structs

        structs = parse_structs("typedef struct { int x; char y; } Foo;")
        assert check_struct(structs["Foo"], {0: 4, 4: 1}) == []

    def test_missing_offset(self) -> None:
        from rebrew.types import check_struct, parse_structs

        structs = parse_structs("typedef struct { int x; } Foo;")
        findings = check_struct(structs["Foo"], {0: 4, 8: 4})
        assert findings == [{"offset": 8, "evidenced_width": 4, "issue": "missing"}]

    def test_narrow_field(self) -> None:
        from rebrew.types import check_struct, parse_structs

        structs = parse_structs("typedef struct { char x; } Foo;")
        findings = check_struct(structs["Foo"], {0: 4})
        assert findings == [{"offset": 0, "evidenced_width": 4, "issue": "width", "field": "x"}]

    def test_nested_struct_field_span_resolved(self) -> None:
        """A read inside a nested-struct field is not reported as missing when
        the known-structs map supplies its size."""
        from rebrew.types import check_struct, parse_structs

        structs = parse_structs(
            "typedef struct { int a; int b; } Inner;\n"
            "typedef struct { char c; Inner inner; int tail; } Outer;"
        )
        # Without the map the "Inner" span is zero-width and this read is
        # reported missing.
        assert check_struct(structs["Outer"], {4: 4}, known_structs=structs) == []


class TestCollectEvidence:
    def test_named_evidence_merged(self, tmp_path: Path) -> None:
        from rebrew.types_cli import collect_evidence

        dec = tmp_path / "f.dec.c"
        dec.write_text(
            "void f(Player *p) {\n  p->field_0 = 1;\n  int x = *(int *)(p + 4);\n}\n",
            encoding="utf-8",
        )
        ev = collect_evidence([dec])
        assert set(ev) == {"Player"} or "Player" in ev
        assert ev["Player"][0] >= 1


class TestRewriteParamType:
    def test_rewrites_indexed_param(self) -> None:
        from rebrew.types import rewrite_param_type

        src = "int __cdecl foo(int a, void *p) { return a; }\n"
        out = rewrite_param_type(src, "foo", 1, "Player *")
        assert out == "int __cdecl foo(int a, Player *p) { return a; }\n"

    def test_missing_function_returns_none(self) -> None:
        from rebrew.types import rewrite_param_type

        assert rewrite_param_type("int foo(void) { return 0; }\n", "bar", 0, "int") is None

    def test_bad_index_returns_none(self) -> None:
        from rebrew.types import rewrite_param_type

        assert rewrite_param_type("int foo(int a) { return a; }\n", "foo", 3, "int") is None


class TestApplyTypeCli:
    def _cfg(self, tmp_path: Path):
        from types import SimpleNamespace

        return SimpleNamespace(
            root=tmp_path,
            reversed_dir=tmp_path / "src",
            metadata_dir=tmp_path,
            source_ext=".c",
            marker="SERVER",
        )

    def test_apply_rewrites_param(self, tmp_path: Path, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.types_cli import app

        src = tmp_path / "src"
        src.mkdir()
        f = src / "foo.c"
        f.write_text("int __cdecl foo(int a, void *p) { return a; }\n", encoding="utf-8")
        monkeypatch.setattr("rebrew.types_cli.require_config", lambda **kw: self._cfg(tmp_path))
        res = CliRunner().invoke(app, ["apply-type", "foo", "--param", "1", "--type", "Player *"])
        assert res.exit_code == 0, res.output
        assert "Player *p" in f.read_text(encoding="utf-8")

    def test_apply_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.types_cli import app

        src = tmp_path / "src"
        src.mkdir()
        f = src / "foo.c"
        before = "int __cdecl foo(int a, void *p) { return a; }\n"
        f.write_text(before, encoding="utf-8")
        monkeypatch.setattr("rebrew.types_cli.require_config", lambda **kw: self._cfg(tmp_path))
        res = CliRunner().invoke(
            app, ["apply-type", "foo", "--param", "1", "--type", "Player *", "--dry-run"]
        )
        assert res.exit_code == 0, res.output
        assert f.read_text(encoding="utf-8") == before
