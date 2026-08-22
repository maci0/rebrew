"""Tests for name_decomp.py — applying known struct names to decompiler output."""

from rebrew.name_decomp import apply_known_names, struct_field_layout


class TestFieldLayout:
    def test_typed_fields_and_gaps(self) -> None:
        lay = struct_field_layout(
            "typedef struct player_slot {\n\tint flags;\n\tchar gap_0004[0x264260];\n} player_slot;\n"
        )
        assert lay.complete
        assert lay.fields[0] == ("flags", 4)
        assert lay.fields[4] == ("gap_0004", 0x264260)
        assert lay.size == 0x264264

    def test_opaque_and_multi_dim_arrays(self) -> None:
        lay = struct_field_layout(
            "typedef struct md {\n\tchar field_0[0xc];\n\tchar tbl[2][4];\n} md;\n"
        )
        assert lay.complete
        assert lay.fields[0] == ("field_0", 0xC)
        assert lay.fields[0xC] == ("tbl", 8)

    def test_pointer_and_unsigned_fields(self) -> None:
        lay = struct_field_layout("typedef struct p {\n\tunsigned short w;\n\tint *next;\n} p;\n")
        assert lay.complete
        assert lay.fields[0] == ("w", 2)
        assert lay.fields[2] == ("next", 4)

    def test_bitfield_marks_incomplete(self) -> None:
        lay = struct_field_layout("typedef struct bf {\n\tint a : 4;\n\tint b;\n} bf;\n")
        assert not lay.complete

    def test_embedded_struct_marks_incomplete(self) -> None:
        lay = struct_field_layout("typedef struct emb {\n\tstruct inner x;\n\tint b;\n} emb;\n")
        assert not lay.complete


class TestApplyKnownNames:
    _DEFS = {
        "command_s": (
            "typedef struct command_s {\n"
            "\tchar gap_0000[0x3];\n"
            "\tchar field_3;\n"
            "\tchar gap_0004[0x2];\n"
            "\tint field_6;\n"
            "\tchar gap_000A[0x6];\n"
            "\tchar field_10;\n"
            "\tchar gap_0011[0x3];\n"
            "\tint field_14;\n"
            "\tint field_18;\n"
            "} command_s;\n"
        ),
    }

    _KUNA = """unsigned int sub_1000d350(int a0,int a1,char *a2) // return-dupe
{
  short *v2;
  v2 = a0;
  *(char *)(a0 + 0x10) = dat_10030b6c;
  if (*(int *)(a0 + 0x12) != -1) {
    v3 = a0 + 0x14;
    sub_1000b1c0(a0 + 0x10);
    x = *(unsigned int *)&v2[10];
    y = *(int *)(a0 + 0x18);
  }
  return 0;
}
"""

    def test_param_typed_and_accesses_rewritten(self) -> None:
        out = apply_known_names(self._KUNA, self._DEFS)
        code = out.code
        lines = code.split("\n")
        assert lines[0].startswith("unsigned int sub_1000d350(command_s *a0,int a1,char *a2)")
        assert "a0->field_10 = dat_10030b6c;" in code
        assert "v3 = &a0->field_14;" in code
        assert "sub_1000b1c0(&a0->field_10);" in code
        assert "y = a0->field_18;" in code
        # array-index form through the alias (v2 = a0; short *v2 → elem 2, idx 10 → 0x14)
        assert "x = v2->field_14;" in code
        # offset inside a declared gap (0x12 ⊂ gap_0011) is left alone
        assert "if (*(int *)(a0 + 0x12) != -1)" in code
        # unmatched params untouched
        assert "int a1,char *a2" in lines[0]
        # applied report
        a0_applied = [a for a in out.applied if a["var"] == "a0"]
        assert len(a0_applied) == 1
        assert a0_applied[0]["struct"] == "command_s"
        assert set(a0_applied[0]["offsets"]) == {"0x10", "0x12", "0x18"}

    def test_width_mismatch_keeps_cast(self) -> None:
        text = "int a0;\n*(short *)(a0 + 0x18) = 1;\n"
        out = apply_known_names(text, self._DEFS)
        assert "*(short *)&a0->field_18 = 1;" in out.code

    def test_named_cast_type_untouched(self) -> None:
        text = "int a0;\nx = *(OtherType *)(a0 + 0x14);\n"
        out = apply_known_names(text, self._DEFS)
        assert "*(OtherType *)(a0 + 0x14)" in out.code

    def test_unmatched_var_untouched(self) -> None:
        text = "int a5;\n*(int *)(a5 + 0x50) = 1;\n"
        out = apply_known_names(text, self._DEFS)
        assert out.code == text
        assert out.applied == []

    def test_global_address_offsets_untouched(self) -> None:
        # 0x100358A0 is an image-base address, not a field — no rewrite.
        text = "int a0;\na0 = idx * 0x21c;\nx = *(short *)(a0 + 0x100358A0);\n"
        out = apply_known_names(text, self._DEFS)
        assert "*(short *)(a0 + 0x100358A0)" in out.code

    def test_no_definitions_no_change(self) -> None:
        text = "int a0;\n*(char *)(a0 + 0x10) = 1;\n"
        out = apply_known_names(text, {})
        assert out.code == text
        assert out.applied == []

    def test_smallest_struct_wins(self) -> None:
        defs = {
            "big_s": (
                "typedef struct big_s {\n\tchar gap_0000[0x10];\n\tchar field_10;\n"
                "\tchar gap_0011[0x3];\n\tint field_14;\n\tchar tail[0x20];\n} big_s;\n"
            ),
            "sml_s": (
                "typedef struct sml_s {\n\tchar gap_0000[0x10];\n\tchar field_10;\n"
                "\tchar gap_0011[0x3];\n\tint field_14;\n} sml_s;\n"
            ),
        }
        text = "int a0;\n*(char *)(a0 + 0x10) = 1;\n*(int *)(a0 + 0x14) = 2;\n"
        out = apply_known_names(text, defs)
        assert out.applied[0]["struct"] == "sml_s"
        assert "a0->field_10 = 1;" in out.code
        assert "a0->field_14 = 2;" in out.code

    def test_incomplete_struct_never_matches(self) -> None:
        defs = {"bf": "typedef struct bf {\n\tint a : 4;\n\tchar field_10;\n} bf;\n"}
        text = "int a0;\n*(char *)(a0 + 0x10) = 1;\n"
        out = apply_known_names(text, defs)
        assert out.code == text

    def test_unsigned_return_type_not_clobbered(self) -> None:
        text = "unsigned int sub_1000efb0(int a0) // return-dupe\n{\n  if (*(char *)(a0 + 0x10) == 1) return 0;\n}\n"
        out = apply_known_names(text, self._DEFS)
        assert out.code.startswith("unsigned int sub_1000efb0(command_s *a0)")


class TestCli:
    def test_decompile_named_via_mocked_backend(self, tmp_path, monkeypatch) -> None:
        import json
        from types import SimpleNamespace

        from typer.testing import CliRunner

        import rebrew.main as main_mod

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True)
        (src / "f.c").write_text(
            "// FUNCTION: SERVER 0x401000\n"
            "typedef struct command_s {\n"
            "\tchar gap_0000[0x10];\n"
            "\tchar field_10;\n"
            "\tchar gap_0011[0x3];\n"
            "\tint field_14;\n"
            "} command_s;\n"
            "int f(void) { return 0; }\n",
            encoding="utf-8",
        )
        (src / "functions.txt").write_text("0x00401000 8 f\n", encoding="utf-8")
        cfg = SimpleNamespace(
            target_name="SERVER",
            target_binary=tmp_path / "x.exe",
            reversed_dir=src,
            metadata_dir=tmp_path,
            function_list=src / "functions.txt",
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
        )
        monkeypatch.setattr("rebrew.name_decomp.require_config", lambda **kw: cfg)

        def _fake_fetch(backend, binary, va, root):
            return "int a0;\n*(char *)(a0 + 0x10) = 1;\n*(int *)(a0 + 0x14) = 2;\n", backend

        monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", _fake_fetch)
        result = CliRunner().invoke(main_mod.app, ["decompile", "0x401000", "--named", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["backend"] == "kuna"
        assert data["named"] is True
        assert "a0->field_10 = 1;" in data["code"]
        assert "a0->field_14 = 2;" in data["code"]
        assert data["applied"][0]["var"] == "a0"
        assert data["applied"][0]["struct"] == "command_s"

    def test_decompile_raw_without_named(self, tmp_path, monkeypatch) -> None:
        import json
        from types import SimpleNamespace

        from typer.testing import CliRunner

        import rebrew.main as main_mod

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True)
        (src / "f.c").write_text(
            "// FUNCTION: SERVER 0x401000\nint f(void) { return 0; }\n", encoding="utf-8"
        )
        (src / "functions.txt").write_text("0x00401000 8 f\n", encoding="utf-8")
        cfg = SimpleNamespace(
            target_name="SERVER",
            target_binary=tmp_path / "x.exe",
            reversed_dir=src,
            metadata_dir=tmp_path,
            function_list=src / "functions.txt",
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
        )
        monkeypatch.setattr("rebrew.name_decomp.require_config", lambda **kw: cfg)

        def _fake_fetch(backend, binary, va, root):
            return "int a0;\n*(char *)(a0 + 0x10) = 1;\n", backend

        monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", _fake_fetch)
        result = CliRunner().invoke(main_mod.app, ["decompile", "0x401000", "--json"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["named"] is False
        assert data["applied"] == []
        assert "*(char *)(a0 + 0x10) = 1;" in data["code"]
