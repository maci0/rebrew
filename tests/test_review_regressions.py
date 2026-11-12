"""Regressions for the cross-target source and data review."""

from pathlib import Path
from types import SimpleNamespace

import capstone
import pytest
from typer.testing import CliRunner

from rebrew.c_parser import prototype_type_key
from rebrew.cast_rewrite import declare_externs
from rebrew.cfg import app as cfg_app
from rebrew.data_pair import OperandPair, pair_data_operands, plan_pairs
from rebrew.source_binding import _is_call_target, _refuse_conflicting_prototype


class TestQuotedKeys:
    @pytest.mark.parametrize("json_args", [[], ["--json"]])
    def test_secret_show_is_redacted(self, tmp_path: Path, monkeypatch, json_args) -> None:
        (tmp_path / "rebrew-project.toml").write_text('[llm]\napi_key = "dummy-secret"\n')
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(cfg_app, ["show", 'llm."api_key"', *json_args])
        assert result.exit_code == 0, result.output
        assert "dummy-secret" not in result.output
        assert "***" in result.output

    @pytest.mark.parametrize("extra", [[], ["--json"], ["--dry-run", "--json"]])
    def test_secret_set_is_refused(self, tmp_path: Path, monkeypatch, extra) -> None:
        path = tmp_path / "rebrew-project.toml"
        path.write_text('[llm]\napi_key = ""\n')
        before = path.read_bytes()
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(cfg_app, ["set", 'llm."api_key"', "dummy-secret", *extra])
        assert result.exit_code != 0
        assert "dummy-secret" not in result.output
        assert path.read_bytes() == before

    def test_quoted_backend_is_validated(self, tmp_path: Path, monkeypatch) -> None:
        path = tmp_path / "rebrew-project.toml"
        path.write_text('[compiler]\nexecution_backend = "docker"\n')
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(cfg_app, ["set", 'compiler."execution_backend"', "bogus"])
        assert result.exit_code != 0
        assert "bogus" not in path.read_text()


class TestDataPlan:
    def test_relative_loop_keeps_its_body_offset(self) -> None:
        code = bytes.fromhex("e2fe")
        assert pair_data_operands(
            code,
            0x1000,
            code,
            0x2000,
            lambda va: False,
            lambda va: False,
            capstone.CS_ARCH_X86,
            capstone.CS_MODE_32,
        ) == ([], [])

    def test_repeated_compatible_proposals_write_one_row(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        import json

        from rebrew import data_pair
        from rebrew.metadata.data import load_data_metadata, record_data_rows
        from rebrew.metadata.functions import record_function_identity

        for module, va, name in (("A", 0x3000, "callee_a"), ("B", 0x5000, "callee_b")):
            record_function_identity(
                tmp_path, module=module, va=va, file="src/callee.c", name=name, kind="FUNCTION"
            )
        functions_before = (tmp_path / "rebrew-functions.toml").read_bytes()

        record_data_rows(
            tmp_path,
            [
                {
                    "module": "B",
                    "va": 0x600000,
                    "identity": {"name": "g_table", "kind": "GLOBAL"},
                    "fill": {"size": 8},
                }
            ],
        )
        configs = {
            name: SimpleNamespace(module=name, metadata_dir=tmp_path, target_binary=Path(name))
            for name in ("A", "B")
        }
        bodies = {
            "A": bytes.fromhex("a100005000a104005000e8f11f0000e9fc1f0000"),
            "B": bytes.fromhex("a100006000a104006000e8f12f0000e9fc2f0000"),
        }
        infos = {
            name: SimpleNamespace(
                arch="x86_32",
                sections={
                    ".data": SimpleNamespace(
                        name=".data",
                        va=start,
                        size=0x100,
                        is_code_section=False,
                    )
                },
                code=bodies[name],
            )
            for name, start in (("A", 0x500000), ("B", 0x600000))
        }
        monkeypatch.setattr(data_pair, "require_config", lambda **kw: configs[kw["target"]])
        monkeypatch.setattr(
            "rebrew.formats.binary_loader.load_binary", lambda path: infos[path.name]
        )
        monkeypatch.setattr(
            "rebrew.formats.binary_loader.extract_bytes_at_va", lambda info, *a, **kw: info.code
        )
        data_pair.pair(
            "0x1000",
            "0x2000",
            from_target="A",
            size=20,
            rewrite=None,
            dry_run=False,
            json_output=True,
            target="B",
        )
        report = json.loads(capsys.readouterr().out)
        assert report["created"] == 1
        assert report["calls"] == [
            {
                "offset": 10,
                "a": "0x00003000",
                "b": "0x00005000",
                "name_a": "callee_a",
                "name_b": "callee_b",
            },
            {"offset": 15, "a": "0x00003010", "b": "0x00005010", "name_a": None, "name_b": None},
        ]
        data = load_data_metadata(tmp_path)
        assert set(data) == {("A", 0x500000), ("B", 0x600000)}
        assert data[("A", 0x500000)]["name"] == "g_table"
        assert (tmp_path / "rebrew-functions.toml").read_bytes() == functions_before

    def test_proposed_extents_cannot_overlap(self) -> None:
        plan = plan_pairs(
            [OperandPair(0, 0x500000, 0x600000), OperandPair(6, 0x500008, 0x600010)],
            {},
            {0x600000: {"name": "g_one", "size": 16}, 0x600010: {"name": "g_two", "size": 16}},
            lambda va: ".data",
            lambda va: ".data",
        )
        assert [p["action"] for p in plan] == ["conflict", "conflict"]

    def test_two_names_for_one_address_are_both_conflicts(self) -> None:
        plan = plan_pairs(
            [OperandPair(0, 0x500000, 0x600000), OperandPair(6, 0x500000, 0x600010)],
            {},
            {0x600000: {"name": "g_one", "size": 4}, 0x600010: {"name": "g_two", "size": 4}},
            lambda va: ".data",
            lambda va: ".data",
        )
        assert [p["action"] for p in plan] == ["conflict", "conflict"]

    def test_new_extent_cannot_overlap_existing_row(self) -> None:
        plan = plan_pairs(
            [OperandPair(0, 0x500000, 0x600000)],
            {0x500004: {"name": "g_existing", "size": 4}},
            {0x600000: {"name": "g_table", "size": 16}},
            lambda va: ".data",
            lambda va: ".data",
        )
        assert plan[0]["action"] == "conflict"

    def test_new_extent_must_fit_one_section(self) -> None:
        plan = plan_pairs(
            [OperandPair(0, 0x500000, 0x600000)],
            {},
            {0x600000: {"name": "g_table", "size": 16}},
            lambda va: ".data",
            lambda va: ".data" if 0x500000 <= va < 0x500008 else None,
        )
        assert plan[0]["action"] == "conflict"

    @pytest.mark.parametrize(
        "a,b",
        [
            ("8b0500005000", "8b0d00006000"),
            ("a10000500083c001", "a10000600083c002"),
            ("8b4500a100005000", "8b4600a100006000"),
            ("7500a100005000", "7501a100006000"),
        ],
    )
    def test_non_address_operands_must_match(self, a: str, b: str) -> None:
        with pytest.raises(ValueError, match="differ"):
            pair_data_operands(
                bytes.fromhex(a),
                0x1000,
                bytes.fromhex(b),
                0x2000,
                lambda va: 0x500000 <= va < 0x700000,
                lambda va: 0x500000 <= va < 0x700000,
                capstone.CS_ARCH_X86,
                capstone.CS_MODE_32,
            )


class TestExternPlacement:
    def test_gap_after_comment_hosts_declaration(self) -> None:
        text = "/*\n\n*/\n\nint f(void) { return 0; }\n"
        new, declared = declare_externs(text, ["g_table"])
        assert declared == ["g_table"]
        assert new.splitlines()[3] == "extern char g_table[];"
        assert new.count("\n") == text.count("\n")

    def test_conditional_extern_is_not_an_anchor(self) -> None:
        text = "#if 0\nextern int other;\n#endif\nint f(void) { return 0; }\n"
        with pytest.raises(ValueError, match="extern|empty"):
            declare_externs(text, ["g_table"])

    @pytest.mark.parametrize("prefix", ["/*\n\n*/\n", "#if 0\n\n#endif\n"])
    def test_comment_or_conditional_blank_is_not_an_anchor(self, prefix: str) -> None:
        with pytest.raises(ValueError, match="extern|empty"):
            declare_externs(prefix + "int f(void) { return 0; }\n", ["g_table"])


class TestRebindGuards:
    @pytest.mark.parametrize("parameter", ["int", "double", "long", "float *", "char *"])
    def test_unprototyped_compatible_promoted_types(self, tmp_path: Path, parameter: str) -> None:
        key = prototype_type_key(f"int fcn_00405000({parameter})")
        assert key is not None
        _refuse_conflicting_prototype(
            "extern int fcn_00405000();\n",
            "fcn_00405000",
            key,
            tmp_path / "caller.c",
            SimpleNamespace(root=tmp_path),
        )

    @pytest.mark.parametrize(
        "replacement",
        [
            "void __cdecl fcn_00405000(int a)",
            "int __cdecl fcn_00405000(float a)",
            "int __stdcall fcn_00405000(int a)",
        ],
    )
    def test_unprototyped_declaration_still_checks_abi(
        self, tmp_path: Path, replacement: str
    ) -> None:
        key = prototype_type_key(replacement)
        assert key is not None
        with pytest.raises(ValueError, match="already declared"):
            _refuse_conflicting_prototype(
                "extern int fcn_00405000();\n",
                "fcn_00405000",
                key,
                tmp_path / "caller.c",
                SimpleNamespace(root=tmp_path),
            )

    def test_immediate_byte_is_not_a_call(self, monkeypatch) -> None:
        code = bytes.fromhex("b8e8fb1f0000c3")
        section = SimpleNamespace(
            name=".text",
            va=0x400FFF,
            size=len(code),
            file_offset=0,
            raw_size=len(code),
            is_code_section=True,
        )
        info = SimpleNamespace(arch="x86_32", sections={".text": section}, data=code)
        monkeypatch.setattr("rebrew.formats.binary_loader.load_binary", lambda path: info)
        assert not _is_call_target(Path("x.exe"), 0x403000)
