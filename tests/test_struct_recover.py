"""Tests for struct_recover.py — struct recovery from decompiler output."""

from rebrew.struct_recover import (
    existing_structs,
    parse_decomp_for_structs,
    recover_structs,
    synthesize_struct,
)


class TestParseDecomp:
    def test_field_access_offsets(self) -> None:
        text = "PlayerInfo *this;\nthis->field_0 = 1;\nthis->field_10 = 2;\nthis->field_0x1c = 3;\n"
        ev = parse_decomp_for_structs(text)
        assert "PlayerInfo" in ev.named
        offsets = ev.named["PlayerInfo"].offsets
        assert set(offsets) == {0x0, 0x10, 0x1C}
        # default width for bare field accesses is 4
        assert offsets[0x0] == {4: 1}

    def test_cast_deref_widths(self) -> None:
        text = (
            "PlayerInfo *this;\n"
            "*(int *)(this + 0x8) = 1;\n"
            "*(short *)(this + 0x10) = 2;\n"
            "*(double *)(this + 0x20) = 3.0;\n"
        )
        ev = parse_decomp_for_structs(text)
        offsets = ev.named["PlayerInfo"].offsets
        assert offsets[0x8] == {4: 1}
        assert offsets[0x10] == {2: 1}
        assert offsets[0x20] == {8: 1}

    def test_cast_deref_decimal_offset(self) -> None:
        # Kuna emits decimal offsets without the 0x prefix.
        text = "int a0;\nif (*(char *)(a0 + 3) == 1) return 0;\n"
        ev = parse_decomp_for_structs(text)
        assert ev.named == {}
        assert ev.anonymous["a0"].offsets[3] == {1: 1}

    def test_array_index_scale(self) -> None:
        # Kuna types struct pointers as primitive arrays: ``&a0[10]`` on a
        # ``short *`` is byte offset 0x14; the cast supplies the access width.
        text = "short *a0;\nx = *(int *)&a0[10];\ny = a0[4];\n"
        ev = parse_decomp_for_structs(text)
        offsets = ev.anonymous["a0"].offsets
        assert offsets[0x14] == {4: 1}  # 10 * 2, int access
        assert offsets[0x8] == {2: 1}  # 4 * 2, short access
        # the same ``&a0[10]`` is not double-counted by the bare form
        assert offsets[0x14] == {4: 1}

    def test_cast_deref_ampersand_form(self) -> None:
        text = "PlayerInfo *p;\nx = *(int *)&p + 0x8;\n"
        ev = parse_decomp_for_structs(text)
        assert ev.named["PlayerInfo"].offsets[0x8] == {4: 1}

    def test_global_array_index_not_struct_evidence(self) -> None:
        # ``*(unsigned int *)(idx * 4 + 0x10025718)`` is a global array, not a
        # member access — no variable participates at a fixed offset.
        text = "unsigned int *v1;\nv1 = (unsigned int *)(idx * 4 + 0x10025718);\n*v1 = 1;\n"
        ev = parse_decomp_for_structs(text)
        assert ev.named == {}
        assert ev.anonymous == {}

    def test_pseudo_types_ignored_as_named_but_anonymous(self) -> None:
        # ``undefined4 *this`` gives no NAMED type, but the member accesses are
        # real evidence — surfaced as an anonymous candidate for the var.
        text = "undefined4 *this;\nthis->field_4 = 1;\n"
        ev = parse_decomp_for_structs(text)
        assert ev.named == {}
        assert ev.anonymous["this"].offsets[4] == {4: 1}

    def test_declaration_without_access_ignored(self) -> None:
        text = "SomeType *p;\nreturn 0;\n"
        ev = parse_decomp_for_structs(text)
        assert ev.named == {}
        assert ev.anonymous == {}

    def test_named_cast_establishes_base(self) -> None:
        text = "void *raw;\n((PlayerInfo *)raw)->field_8 = 1;\n"
        ev = parse_decomp_for_structs(text)
        assert "PlayerInfo" in ev.named

    def test_named_cast_types_later_accesses(self) -> None:
        text = "void *raw;\nraw = (PlayerInfo *)raw;\n*(int *)(raw + 0x8) = 1;\n"
        ev = parse_decomp_for_structs(text)
        assert ev.named["PlayerInfo"].offsets[0x8] == {4: 1}


class TestAnonymousCandidates:
    def test_unnamed_pointer_grouped_by_variable(self) -> None:
        # Real Kuna output for guild's sub_1000efb0: int a0, cast-derefs only.
        text = (
            "unsigned int sub_1000efb0(int a0) {\n"
            "  unsigned int *v1;\n"
            "  if (*(char *)(a0 + 0x10) == '\\x01') {\n"
            "    v1 = (unsigned int *)((unsigned int)*(unsigned char *)(a0 + 3) * 0x264264 + 0x101deb00);\n"
            "  }\n"
            "  dat_1002c3f4 = *(int *)(a0 + 0x11);\n"
            "  return 0;\n"
            "}\n"
        )
        ev = parse_decomp_for_structs(text)
        assert ev.named == {}
        assert "a0" in ev.anonymous
        offsets = ev.anonymous["a0"].offsets
        assert offsets[0x3] == {1: 1}  # *(unsigned char *)(a0 + 3) — decimal
        assert offsets[0x10] == {1: 1}  # *(char *)(a0 + 0x10)
        assert offsets[0x11] == {4: 1}  # *(int *)(a0 + 0x11)
        # the global-array deref produced no candidate
        assert "v1" not in ev.anonymous

    def test_compiler_temporaries_excluded(self) -> None:
        text = "local_8 = 0;\n*(int *)(local_8 + 4) = 1;\nuVar2 = *(short *)(uVar2 + 2);\n"
        ev = parse_decomp_for_structs(text)
        assert ev.anonymous == {}

    def test_param_names_are_candidates(self) -> None:
        text = "int param_1;\n*(char *)(param_1 + 0x10) = 1;\n"
        ev = parse_decomp_for_structs(text)
        assert "param_1" in ev.anonymous

    def test_named_type_beats_pseudo(self) -> None:
        # (PlayerInfo *)a0 names the base even though a0 is declared int.
        text = "int a0;\n*(char *)(a0 + 0x10) = 1;\na0 = (PlayerInfo *)a0;\n"
        ev = parse_decomp_for_structs(text)
        assert "PlayerInfo" in ev.named
        assert "a0" not in ev.anonymous

    def test_global_address_offsets_filtered(self) -> None:
        # ``a0 = idx * 0x21c; *(short *)(a0 + 0x100358A0)`` — Kuna folds a
        # global base + index into ``var + 0xADDR``; those are addresses, not
        # member offsets, and must not leak into the layout.
        text = "int a0;\na0 = idx * 0x21c;\nx = *(short *)(a0 + 0x100358A0);\ny = *(char *)(a0 + 0x10);\n"
        ev = parse_decomp_for_structs(text)
        offsets = ev.anonymous["a0"].offsets
        assert set(offsets) == {0x10}  # 0x100358A0 dropped
        assert offsets[0x10] == {1: 1}

    def test_max_offset_override(self) -> None:
        # A 4 MiB image base (0x400000) must filter globals at 0x401000 too.
        text = "int a0;\nx = *(char *)(a0 + 0x401000);\ny = *(char *)(a0 + 0x10);\n"
        ev = parse_decomp_for_structs(text, max_offset=0x400000)
        assert set(ev.anonymous["a0"].offsets) == {0x10}


class TestSynthesize:
    def test_gap_padding(self) -> None:
        out = synthesize_struct("player_slot", {0x0: {"4": 1}, 0x10: {"4": 1}})
        assert "typedef struct player_slot_s {" in out
        assert "int field_0;" in out
        assert "char gap_0004[0xc];" in out
        assert "int field_10;" in out
        assert "} player_slot;" in out

    def test_unknown_width_opaque_field(self) -> None:
        out = synthesize_struct("x", {0x0: {"12": 1}})
        assert "char field_0[0xc];" in out

    def test_unanchored_base_materializes_as_gap(self) -> None:
        # No evidence at 0: the base becomes a gap, never an invented field
        # (an invented int at 0 would overlap a byte at 0x3).
        out = synthesize_struct("hdr", {0x3: {"1": 1}, 0x10: {"4": 1}})
        assert "char gap_0000[0x3];" in out
        assert "char field_3;" in out
        assert "int field_10;" in out
        assert "field_0;" not in out


class TestRecover:
    def test_aggregates_and_merges(self) -> None:
        decomp = [
            (0x401000, "f1", "PlayerInfo *p;\np->field_0 = 1;\np->field_8 = 2;\n"),
            (0x401100, "f2", "PlayerInfo *q;\nq->field_0 = 1;\nq->field_10 = 2;\n"),
        ]
        results = recover_structs(decomp)
        by_name = {r["name"]: r for r in results}
        assert "PlayerInfo" in by_name
        assert by_name["PlayerInfo"]["new"] is True
        assert by_name["PlayerInfo"]["anonymous"] is False
        assert set(by_name["PlayerInfo"]["offsets"]) == {"0x0", "0x8", "0x10"}

    def test_existing_struct_not_new(self) -> None:
        decomp = [(0x401000, "f", "PlayerInfo *p;\np->field_0 = 1;\n")]
        existing = {"PlayerInfo": "typedef struct player_slot_s {...} PlayerInfo;"}
        results = recover_structs(decomp, existing=existing)
        assert results[0]["new"] is False

    def test_anonymous_aggregated_across_functions(self) -> None:
        decomp = [
            (0x401000, "f1", "int a0;\n*(char *)(a0 + 0x10) = 1;\n"),
            (0x401100, "f2", "int a0;\n*(int *)(a0 + 0x11) = 1;\n"),
        ]
        results = recover_structs(decomp)
        anon = [r for r in results if r["anonymous"]]
        assert len(anon) == 1
        (r,) = anon
        assert r["var"] == "a0"
        assert r["semantic"] is False
        assert r["functions"] == 2
        assert set(r["offsets"]) == {"0x10", "0x11"}
        # definition is offered so the user can see the layout
        assert "typedef struct a0_s {" in r["definition"]

    def test_anonymous_semantic_var_gets_type_name(self) -> None:
        decomp = [(0x401000, "f", "int pPlayer;\n*(char *)(pPlayer + 0x10) = 1;\n")]
        results = recover_structs(decomp)
        (r,) = results
        assert r["anonymous"] is True
        assert r["var"] == "pPlayer"
        assert r["semantic"] is True
        assert r["name"] == "Player"  # Hungarian prefix stripped
        assert "typedef struct Player_s {" in r["definition"]

    def test_anonymous_never_auto_applyable_marker(self) -> None:
        decomp = [(0x401000, "f", "int a0;\n*(char *)(a0 + 0x10) = 1;\n")]
        (r,) = recover_structs(decomp)
        assert r["new"] is True
        assert r["anonymous"] is True

    def test_no_evidence_empty(self) -> None:
        assert recover_structs([]) == []


class TestExistingStructs:
    def test_parses_named_structs(self, tmp_path) -> None:
        src = tmp_path / "s.c"
        src.write_text(
            "typedef struct player_slot {\n\tint flags;\n\tchar gap_4[0x10];\n} player_slot;\n",
            encoding="utf-8",
        )
        out = existing_structs([src])
        assert "player_slot" in out
        assert "typedef struct" in out["player_slot"]


class TestCli:
    def test_recover_via_mocked_decompiler(self, tmp_path, monkeypatch) -> None:
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
        monkeypatch.setattr("rebrew.struct_recover.require_config", lambda **kw: cfg)

        def _fake_fetch(backend, binary, va, root):
            return "PlayerInfo *p;\np->field_0 = 1;\np->field_8 = 2;\n", backend

        monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", _fake_fetch)
        result = CliRunner().invoke(
            main_mod.app, ["recover-structs", "--functions", "0x401000", "--json"]
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["decompiled"] == 1
        assert any(s["name"] == "PlayerInfo" and s["new"] for s in data["structs"])
        assert "typedef struct PlayerInfo_s {" in data["structs"][0]["definition"]

    def test_anonymous_in_json_output(self, tmp_path, monkeypatch) -> None:
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
        monkeypatch.setattr("rebrew.struct_recover.require_config", lambda **kw: cfg)

        def _fake_fetch(backend, binary, va, root):
            return "int a0;\n*(char *)(a0 + 0x10) = 1;\n", backend

        monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", _fake_fetch)
        result = CliRunner().invoke(
            main_mod.app, ["recover-structs", "--functions", "0x401000", "--json"]
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        anon = [s for s in data["structs"] if s["anonymous"]]
        assert len(anon) == 1
        assert anon[0]["var"] == "a0"
        assert anon[0]["semantic"] is False
        assert "typedef struct a0_s {" in anon[0]["definition"]
