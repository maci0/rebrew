"""Tests for name_decomp.py — applying known struct names to decompiler output."""

from rebrew.name_decomp import (
    apply_known_names,
    struct_definitions_to_layouts,
    struct_field_layout,
)


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

    def test_octal_and_suffixed_dimensions(self) -> None:
        lay = struct_field_layout("typedef struct o {\n\tchar oct[010];\n\tchar hx[0x10u];\n} o;\n")
        assert lay.complete
        assert lay.fields[0] == ("oct", 8)
        assert lay.fields[8] == ("hx", 16)
        assert lay.size == 24

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

    def test_unsized_array_marks_incomplete(self) -> None:
        lay = struct_field_layout("typedef struct u {\n\tint a;\n\tchar x[];\n} u;\n")
        assert not lay.complete

    def test_symbolic_dim_marks_incomplete(self) -> None:
        lay = struct_field_layout("typedef struct s {\n\tchar buf[N];\n} s;\n")
        assert not lay.complete

    def test_parenthesized_pointer_array_keeps_the_next_field(self) -> None:
        """``int (*table[4])`` is four pointers, and the next field stays.

        The name sits inside parentheses, so the line was not a field and
        the struct was incomplete. ``char (*row)[4]`` stays one pointer.
        """
        lay = struct_field_layout("typedef struct s {\n\tint (*table[4]);\n\tint tail;\n} s;\n")
        assert lay.complete
        assert lay.fields[0] == ("table", 16)
        assert lay.fields[16] == ("tail", 4)
        assert lay.size == 20

        row = struct_field_layout("typedef struct r {\n\tchar (*row)[4];\n\tint tail;\n} r;\n")
        assert row.complete
        assert row.fields[0] == ("row", 4)
        assert row.fields[4] == ("tail", 4)
        assert row.size == 8

        bare = struct_field_layout("typedef struct b {\n\tint *rows[4];\n} b;\n")
        assert bare.complete
        assert bare.fields[0] == ("rows", 16)

    def test_constant_expression_dimension(self) -> None:
        """``[2 + 2]`` is four bytes. The line parser used to mark the
        struct incomplete and drop the following field."""
        lay = struct_field_layout("typedef struct e {\n\tchar expr[2 + 2];\n\tint tail;\n} e;\n")
        assert lay.complete
        assert lay.fields[0] == ("expr", 4)
        assert lay.fields[4] == ("tail", 4)
        assert lay.size == 8

    def test_multiword_scalar_fields(self) -> None:
        """The line parser keeps ``long long`` and ``long double`` as one type.

        A single-word base treated ``long`` as the type and ``long`` as the
        field name, so the struct was incomplete and the real field was
        dropped.  The layout stays packed: no alignment padding.
        """
        lay = struct_field_layout(
            "typedef struct w {\n"
            "\tlong long *p;\n"
            "\tlong long x;\n"
            "\tunsigned long long y;\n"
            "\tlong double z;\n"
            "\tshort int s;\n"
            "\tlong int n;\n"
            "\tlong long int q;\n"
            "} w;\n"
        )
        assert lay.complete
        assert lay.fields[0] == ("p", 4)
        assert lay.fields[4] == ("x", 8)
        assert lay.fields[12] == ("y", 8)
        assert lay.fields[20] == ("z", 8)
        assert lay.fields[28] == ("s", 2)
        assert lay.fields[30] == ("n", 4)
        assert lay.fields[34] == ("q", 8)
        assert lay.size == 42

    def test_div_bound_keeps_packed_field(self) -> None:
        """``[7 / 2]`` is 3. A packed ``int field_3`` stays at offset 3.

        Natural alignment would move it to 4.  The bound is not a plain
        decimal, so the decompiler layout wins.
        """
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n\tchar gap_0000[7 / 2];\n\tint field_3;\n} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 3)
        assert lay.fields[3] == ("field_3", 4)

    def test_shift_bound_keeps_packed_field(self) -> None:
        """``[1 << 1]`` is 2. A packed ``int field_2`` stays at offset 2."""
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n\tchar gap_0000[1 << 1];\n\tint field_2;\n} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 2)
        assert lay.fields[2] == ("field_2", 4)

    def test_signed_intermediate_keeps_packed_field(self) -> None:
        """``[4 + -2]`` is 2. A packed ``int field_2`` stays at offset 2.

        Natural alignment would move it to 4.  The bound is not a plain
        decimal, so the decompiler layout wins.
        """
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n\tchar gap_0000[4 + -2];\n\tint field_2;\n} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 2)
        assert lay.fields[2] == ("field_2", 4)

    def test_bitwise_bound_keeps_packed_field(self) -> None:
        """``[15 & 7]`` is 7. A packed ``int field_7`` stays at offset 7.

        Natural alignment would move it to 8.  The bound is not a plain
        decimal, so the decompiler layout wins.
        """
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n\tchar gap_0000[15 & 7];\n\tint field_7;\n} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 7)
        assert lay.fields[7] == ("field_7", 4)

    def test_parenthesized_bound_keeps_packed_field(self) -> None:
        """``[(2)]`` is 2. A packed ``int field_2`` stays at offset 2.

        Natural alignment would move it to 4.  Parentheses are not a plain
        decimal, so the decompiler layout wins.
        """
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n\tchar gap_0000[(2)];\n\tint field_2;\n} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 2)
        assert lay.fields[2] == ("field_2", 4)

    def test_cast_bound_keeps_packed_field(self) -> None:
        """``[(int)2]`` is 2. A packed ``int field_2`` stays at offset 2."""
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n\tchar gap_0000[(int)2];\n\tint field_2;\n} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 2)
        assert lay.fields[2] == ("field_2", 4)

    def test_ternary_bound_keeps_packed_field(self) -> None:
        """``[0 ? 8 : 2]`` is 2. A packed ``int field_2`` stays at offset 2."""
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n\tchar gap_0000[0 ? 8 : 2];\n\tint field_2;\n} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 2)
        assert lay.fields[2] == ("field_2", 4)

    def test_comma_bound_keeps_packed_field(self) -> None:
        """``[(2, 3)]`` is 3. A packed ``int field_3`` stays at offset 3."""
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n\tchar gap_0000[(2, 3)];\n\tint field_3;\n} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 3)
        assert lay.fields[3] == ("field_3", 4)

    def test_sizeof_bound_keeps_packed_field(self) -> None:
        """``[sizeof(short)]`` is 2. A packed ``int field_2`` stays at offset 2."""
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n"
                "\tchar gap_0000[sizeof(short)];\n"
                "\tint field_2;\n"
                "} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 2)
        assert lay.fields[2] == ("field_2", 4)

    def test_comparison_bound_keeps_packed_field(self) -> None:
        """``[2 == 2]`` is 1. A packed ``int field_1`` stays at offset 1.

        Natural alignment would move it to 4.  ``==`` is not a plain decimal.
        """
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n\tchar gap_0000[2 == 2];\n\tint field_1;\n} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 1)
        assert lay.fields[1] == ("field_1", 4)

    def test_logical_bound_keeps_packed_field(self) -> None:
        """``[0 || 1]`` is 1. A packed ``int field_1`` stays at offset 1."""
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n\tchar gap_0000[0 || 1];\n\tint field_1;\n} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 1)
        assert lay.fields[1] == ("field_1", 4)

    def test_char_constant_keeps_packed_field(self) -> None:
        """``['\\n']`` is 10. A packed ``int field_A`` stays at offset 10."""
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n\tchar gap_0000['\\n'];\n\tint field_A;\n} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 10)
        assert lay.fields[10] == ("field_A", 4)

    def test_sizeof_string_keeps_packed_field(self) -> None:
        """``[sizeof("hi")]`` is 3. A packed ``int field_3`` stays at offset 3."""
        defs = {
            "pack_s": (
                'typedef struct pack_s {\n\tchar gap_0000[sizeof("hi")];\n\tint field_3;\n} pack_s;\n'
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 3)
        assert lay.fields[3] == ("field_3", 4)

    def test_sizeof_wchar_keeps_packed_field(self) -> None:
        """``[sizeof(wchar_t)]`` is 2. A packed ``int field_2`` stays at offset 2."""
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n"
                "\tchar gap_0000[sizeof(wchar_t)];\n"
                "\tint field_2;\n"
                "} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 2)
        assert lay.fields[2] == ("field_2", 4)

    def test_sizeof_wide_char_keeps_packed_field(self) -> None:
        """``[sizeof(L'A')]`` is 2. A packed ``int field_2`` stays at offset 2."""
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n"
                "\tchar gap_0000[sizeof(L'A')];\n"
                "\tint field_2;\n"
                "} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 2)
        assert lay.fields[2] == ("field_2", 4)

    def test_sizeof_bool_keeps_packed_field(self) -> None:
        """``[sizeof(bool)]`` is 1. A packed ``int field_1`` stays at offset 1."""
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n"
                "\tchar gap_0000[sizeof(bool)];\n"
                "\tint field_1;\n"
                "} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 1)
        assert lay.fields[1] == ("field_1", 4)

    def test_sizeof_wchar_array_keeps_packed_field(self) -> None:
        """``[sizeof(wchar_t[3])]`` is 6. A packed ``int field_6`` stays at offset 6."""
        defs = {
            "pack_s": (
                "typedef struct pack_s {\n"
                "\tchar gap_0000[sizeof(wchar_t[3])];\n"
                "\tint field_6;\n"
                "} pack_s;\n"
            ),
        }
        lay = struct_definitions_to_layouts(defs)["pack_s"]
        assert lay.complete
        assert lay.fields[0] == ("gap_0000", 6)
        assert lay.fields[6] == ("field_6", 4)


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

    def test_hex_array_index_rewritten(self) -> None:
        """``v2[0xA]`` is the same offset as ``v2[10]`` on a ``short *``."""
        text = (
            "unsigned int sub_1000d350(int a0)\n"
            "{\n"
            "  short *v2;\n"
            "  v2 = a0;\n"
            "  *(char *)(a0 + 0x10) = 1;\n"
            "  x = *(unsigned int *)&v2[0xA];\n"
            "  return 0;\n"
            "}\n"
        )
        out = apply_known_names(text, self._DEFS)
        assert "x = v2->field_14;" in out.code

    def test_bare_index_keeps_value_and_address(self) -> None:
        """``p[i]`` is a load and ``&p[i]`` is an address. The space before
        the variable stays. A matching element width drops the cast."""
        defs = {
            "slot_s": ("typedef struct slot_s {\n\tshort field_0;\n\tshort field_2;\n} slot_s;\n"),
        }
        text = "int a0;\nshort *p;\np = a0;\n*(short *)(a0 + 0) = 1;\ny = p[1];\nz = &p[0x1];\n"
        out = apply_known_names(text, defs)
        assert "y = p->field_2;" in out.code
        assert "z = &p->field_2;" in out.code

        wide = "int a0;\nshort *p;\np = a0;\n*(char *)(a0 + 0x10) = 1;\ny = p[0x8];\nz = &p[0x8];\n"
        out = apply_known_names(wide, self._DEFS)
        assert "y = *(short *)&p->field_10;" in out.code
        assert "z = (short *)&p->field_10;" in out.code

    def test_long_long_index_stride(self) -> None:
        """``long long *p`` indexes by 8, not by the trailing word ``long``."""
        defs = {
            "wide_s": (
                "typedef struct wide_s {\n\tchar gap_0000[0x8];\n\tdouble field_8;\n} wide_s;\n"
            ),
        }
        text = "int a0;\nlong long *p;\np = a0;\ny = p[1];\n"
        out = apply_known_names(text, defs)
        assert "y = p->field_8;" in out.code

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

    def test_bare_int_arithmetic_not_rewritten(self) -> None:
        """A bare ``var + N`` on a plain int (no deref/cast/index evidence)
        is integer arithmetic, not a member access."""
        text = "int a0;\nint i;\nfor (i = 0; i < 4; i++) { x = a0 + 0x10; }\n"
        out = apply_known_names(text, self._DEFS)
        assert out.code == text
        assert out.applied == []

    def test_pointer_width_from_arch(self) -> None:
        defs = {"p": "typedef struct p {\n\tint *next;\n} p;\n"}
        lay32 = struct_field_layout(defs["p"], pointer_width=4)
        assert lay32.fields[0] == ("next", 4)
        assert lay32.size == 4
        lay16 = struct_field_layout(defs["p"], pointer_width=2)
        assert lay16.fields[0] == ("next", 2)
        assert lay16.size == 2
        lay64 = struct_field_layout(defs["p"], pointer_width=8)
        assert lay64.fields[0] == ("next", 8)
        assert lay64.size == 8

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
        cfg = SimpleNamespace(
            target_name="SERVER",
            target_binary=tmp_path / "x.exe",
            reversed_dir=src,
            metadata_dir=tmp_path,
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
        cfg = SimpleNamespace(
            target_name="SERVER",
            target_binary=tmp_path / "x.exe",
            reversed_dir=src,
            metadata_dir=tmp_path,
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


class TestSharedModelLayouts:
    def test_aligned_offsets(self) -> None:
        from rebrew.name_decomp import struct_definitions_to_layouts

        layouts = struct_definitions_to_layouts(
            {"P": "typedef struct { char a; int b; short c; } P;"}
        )
        lay = layouts["P"]
        assert lay.complete is True
        assert lay.fields == {0: ("a", 1), 4: ("b", 4), 8: ("c", 2)}
        assert lay.size == 12

    def test_incomplete_struct_marks(self) -> None:
        from rebrew.name_decomp import struct_definitions_to_layouts

        layouts = struct_definitions_to_layouts(
            {"Q": "typedef struct { int a; unsigned b : 3; } Q;"}
        )
        assert layouts["Q"].complete is False
