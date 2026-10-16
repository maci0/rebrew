"""Source contract contradictions are independent of matching object bytes."""

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from cli_json import cli_payload

from rebrew.config import ProjectConfig
from rebrew.metadata.functions import record_function_identity
from rebrew.rename_ops import RenameError
from rebrew.source_contracts import audit_contracts, reconcile_contract


def _project(tmp_path: Path) -> ProjectConfig:
    source = tmp_path / "src"
    source.mkdir()
    (source / "api.h").write_text("#ifndef API_H\n#define API_H\n#endif\n")
    (source / "owner.c").write_text("int queue(int id) { return id; }\n")
    (source / "user.c").write_text(
        "extern void queue(int value);\nint wrapper(void) { queue(1); return 0; }\n"
    )
    cfg = ProjectConfig(root=tmp_path, reversed_dir=source, module="GAME")
    for filename, name, va in [("owner.c", "queue", 0x401000), ("user.c", "wrapper", 0x401100)]:
        record_function_identity(
            cfg.metadata_dir,
            module="GAME",
            va=va,
            file=f"src/{filename}",
            name=name,
            symbol=f"_{name}",
            kind="FUNCTION",
            size=8,
        )
    return cfg


class TestContracts:
    def test_return_mismatch_and_return_use_are_independent(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "other.c").write_text(
            "int queue(int q); int consume(void) { return queue(3); }\n"
        )
        report = audit_contracts(cfg, name="queue")
        assert report["findings"][0]["differences"] == ["return_value_type"]
        assert {call["return_used"] for call in report["calls"]} == {False, True}
        assert not report["verdicts_changed"] and not report["preprocessed"]

    def test_unmarked_globals_do_not_hide_behind_marked_types(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "one.c").write_text("extern int g;\n")
        (cfg.reversed_dir / "two.c").write_text("extern char *g;\n")
        findings = audit_contracts(cfg, name="g")["findings"]
        assert findings[0]["differences"] == ["pointer_value"]
        assert len(findings[0]["sites"]) == 2

    def test_opaque_pointer_views_are_reported_separately(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "one.c").write_text("extern struct Opaque *g;\n")
        (cfg.reversed_dir / "two.c").write_text("extern void *g;\n")
        report = audit_contracts(cfg, name="g")
        assert report["findings"][0]["severity"] == "review"
        assert report["findings"][0]["differences"] == ["pointer_view"]

    def test_static_definitions_in_distinct_units_are_independent(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "one.c").write_text("static int f(void) { return 1; }\n")
        (cfg.reversed_dir / "two.c").write_text("static void f(int x) {}\n")
        assert not audit_contracts(cfg, name="f")["findings"]

    def test_foreign_target_providers_do_not_participate(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "foreign.c").write_text("void queue(char *x) {}\n")
        record_function_identity(
            cfg.metadata_dir,
            module="OTHER",
            va=0x501000,
            file="src/foreign.c",
            name="queue",
            symbol="_queue",
            kind="FUNCTION",
            size=8,
        )
        report = audit_contracts(cfg, name="queue")
        assert all(not site["file"].endswith("foreign.c") for site in report["sites"])

    def test_header_declaration_is_attributed_to_each_real_context(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "api.h").write_text("int queue(int id);\n")
        (cfg.reversed_dir / "user.c").write_text(
            '#include "api.h"\nint wrapper(void) { return queue(1); }\n'
        )
        assert any(
            site["file"].endswith("api.h") and site["context"].endswith("user.c")
            for site in audit_contracts(cfg, name="queue")["sites"]
        )


class TestContractReconciliation:
    def test_preview_no_write_apply_preserves_parameter_names_and_metadata(
        self, tmp_path: Path
    ) -> None:
        cfg = _project(tmp_path)
        before = {p: (p.read_bytes(), p.stat()) for p in tmp_path.rglob("*") if p.is_file()}
        preview = reconcile_contract(
            [cfg], "queue", Path("src/api.h"), "int queue(int value)", dry_run=True
        )
        assert before == {p: (p.read_bytes(), p.stat()) for p in tmp_path.rglob("*") if p.is_file()}
        assert preview["verification_required"] and len(preview["calls"]) == 1
        metadata = (tmp_path / "rebrew-functions.toml").read_bytes()
        reconcile_contract(
            [cfg],
            "queue",
            Path("src/api.h"),
            "int queue(int value)",
            expected_digest=preview["input_digest"],
        )
        owner = (cfg.reversed_dir / "owner.c").read_text()
        assert "queue(int id)" in owner and "return id;" in owner
        user = (cfg.reversed_dir / "user.c").read_text()
        assert '#include "api.h"' in user and "extern void queue" not in user
        assert "int queue(int value);\n#endif" in (cfg.reversed_dir / "api.h").read_text()
        assert (tmp_path / "rebrew-functions.toml").read_bytes() == metadata
        assert not audit_contracts(cfg, name="queue")["findings"]

    @pytest.mark.parametrize(
        "prototype",
        [
            "int queue(int x, int y)",
            "int other(int x)",
            "int queue(int x); int evil;",
            "static int queue(int x)",
            "int queue(...)",
        ],
    )
    def test_bad_replacement_writes_nothing(self, tmp_path: Path, prototype: str) -> None:
        cfg = _project(tmp_path)
        before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
        with pytest.raises(ValueError):
            reconcile_contract([cfg], "queue", Path("src/api.h"), prototype)
        assert before == {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}

    def test_stale_preview_rejected(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        preview = reconcile_contract(
            [cfg], "queue", Path("src/api.h"), "int queue(int value)", dry_run=True
        )
        (cfg.reversed_dir / "user.c").write_text("/* changed */\n")
        with pytest.raises(ValueError, match="changed"):
            reconcile_contract(
                [cfg],
                "queue",
                Path("src/api.h"),
                "int queue(int value)",
                expected_digest=preview["input_digest"],
            )

    @pytest.mark.parametrize(
        "source",
        [
            "#ifdef FLAG\nvoid queue(int x);\n#endif\n",
            '#include "missing.h"\nvoid queue(int x);\n',
            "int queue(int), other(void);\n",
        ],
    )
    def test_uncertain_context_requires_explicit_repair(self, tmp_path: Path, source: str) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "user.c").write_text(source)
        with pytest.raises(ValueError):
            reconcile_contract([cfg], "queue", Path("src/api.h"), "int queue(int value)")

    def test_failed_publication_restores_earlier_source(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        before = {p: p.read_bytes() for p in cfg.reversed_dir.iterdir()}
        from rebrew.utils import atomic_write_text

        def write(path: Path, text: str, **kwargs: Any) -> None:
            if path.name == "owner.c":
                raise OSError("cannot write")
            atomic_write_text(path, text, **kwargs)

        with (
            patch("rebrew.rename_ops.atomic_write_text", side_effect=write),
            pytest.raises(RenameError, match="failed"),
        ):
            reconcile_contract([cfg], "queue", Path("src/api.h"), "int queue(int value)")
        assert before == {p: p.read_bytes() for p in cfg.reversed_dir.iterdir()}


class TestAdversarialContracts:
    def test_external_sdk_header_is_never_rewritten(self, tmp_path: Path) -> None:
        project = tmp_path / "project"
        project.mkdir()
        cfg = _project(project)
        sdk = tmp_path / "sdk"
        sdk.mkdir()
        external = sdk / "api_sdk.h"
        external.write_text("void queue(int id);\n")
        (cfg.reversed_dir / "user.c").write_text(
            '#include "../../sdk/api_sdk.h"\nint wrapper(void) { queue(1); return 0; }\n'
        )
        before = external.read_bytes()
        with pytest.raises(ValueError, match="external"):
            reconcile_contract([cfg], "queue", Path("src/api.h"), "int queue(int value)")
        assert external.read_bytes() == before

    def test_calling_convention_conflict_is_an_error(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "user.c").write_text("int __stdcall queue(int value);\n")
        report = audit_contracts(cfg, name="queue")
        assert "calling_convention" in report["findings"][0]["differences"]
        assert report["findings"][0]["severity"] == "error"

    def test_c_file_ifndef_is_not_a_header_guard(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "user.c").write_text(
            "#ifndef FEATURE\n#define SOMETHING\nvoid queue(int x);\n#endif\n"
        )
        with pytest.raises(ValueError, match="conditional"):
            reconcile_contract([cfg], "queue", Path("src/api.h"), "int queue(int value)")

    def test_existing_unused_header_signature_is_replaced(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        header = cfg.reversed_dir / "api.h"
        header.write_text("#ifndef API_H\n#define API_H\nvoid queue(int id);\n#endif\n")
        reconcile_contract([cfg], "queue", Path("src/api.h"), "int queue(int value)")
        assert "void queue" not in header.read_text()
        assert header.read_text().count("queue(") == 1

    def test_fresh_snapshot_cannot_use_stale_decoded_source(self, tmp_path: Path) -> None:
        import os

        from rebrew.utils import read_source_text

        cfg = _project(tmp_path)
        owner = cfg.reversed_dir / "owner.c"
        read_source_text(owner)
        stat = owner.stat()
        owner.write_text(owner.read_text().replace("return id", "return 99"))
        os.utime(owner, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        reconcile_contract([cfg], "queue", Path("src/api.h"), "int queue(int value)")
        assert "return 99" in owner.read_text()

    def test_comment_cannot_suppress_include_insertion(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        user = cfg.reversed_dir / "user.c"
        user.write_text('// #include "api.h"\n' + user.read_text())
        reconcile_contract([cfg], "queue", Path("src/api.h"), "int queue(int value)")
        assert '\n#include "api.h"\n' in user.read_text()

    def test_conflicting_same_tu_linkage_is_reported(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "owner.c").write_text(
            "extern int queue(int x);\nstatic int queue(int x) { return x; }\n"
        )
        report = audit_contracts(cfg, name="queue")
        assert any(finding["differences"] == ["linkage"] for finding in report["findings"])

    def test_context_specific_typedef_meanings_cannot_look_equal(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "owner.c").write_text(
            "typedef int Handle;\nint queue(Handle id) { return id; }\n"
        )
        (cfg.reversed_dir / "user.c").write_text(
            'typedef char *Handle;\nextern int queue(Handle id);\nint wrapper(void) { return queue("x"); }\n'
        )
        report = audit_contracts(cfg, name="queue")
        assert report["findings"][0]["differences"] == ["argument_0_pointer_value"]

    def test_unresolved_equal_aliases_are_explicitly_unknown(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "owner.c").write_text("int queue(Handle id) { return 1; }\n")
        (cfg.reversed_dir / "user.c").write_text("int queue(Handle value);\n")
        assert any(
            row.get("types") == ["Handle"] for row in audit_contracts(cfg, name="queue")["unknown"]
        )

    def test_existing_variadic_definition_cannot_lose_ellipsis(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        owner = cfg.reversed_dir / "owner.c"
        owner.write_text("int queue(int id, ...) { __builtin_va_start(ap, id); return id; }\n")
        before = owner.read_bytes()
        with pytest.raises(ValueError):
            reconcile_contract([cfg], "queue", Path("src/api.h"), "int queue(int value)")
        assert owner.read_bytes() == before


class TestReleaseContractControls:
    @pytest.mark.parametrize("header", [False, True])
    def test_parse_recovery_is_unknown_and_blocks_writes(
        self, tmp_path: Path, header: bool
    ) -> None:
        cfg = _project(tmp_path)
        malformed = cfg.reversed_dir / ("api.h" if header else "owner.c")
        malformed.write_text("int queue(int x) { if (\n")
        if header:
            (cfg.reversed_dir / "user.c").write_text('#include "api.h"\n')
        before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
        report = audit_contracts(cfg, name="queue")
        assert any(
            row["file"] == str(malformed) and "parse errors" in row["reason"]
            for row in report["unknown"]
        )
        from typer.testing import CliRunner

        from rebrew.types_cli import app

        with patch("rebrew.types_cli.require_config", return_value=cfg):
            result = CliRunner().invoke(app, ["contracts", "--name", "queue", "--json"])
        assert result.exit_code == 1, result.output
        assert cli_payload(result)["unknown"]
        with pytest.raises(ValueError, match="incomplete"):
            reconcile_contract([cfg], "queue", Path("src/api.h"), "int queue(int value)")
        assert before == {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}

    def test_unused_canonical_header_parse_errors_block_writes(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "api.h").write_text("int queue(int value);\nint broken(\n")
        before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
        with pytest.raises(ValueError, match="canonical header.*parse errors"):
            reconcile_contract([cfg], "queue", Path("src/api.h"), "int queue(int value)")
        assert before == {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}

    @pytest.mark.parametrize("convention", ["", "__cdecl", "__stdcall", "__fastcall", "WINAPI"])
    @pytest.mark.parametrize("return_type", ["int", "void", "void *"])
    def test_void_return_validation_is_independent_of_calling_convention(
        self, tmp_path: Path, convention: str, return_type: str
    ) -> None:
        cfg = _project(tmp_path)
        body = "" if return_type == "void" else "return 0;"
        (cfg.reversed_dir / "owner.c").write_text(
            f"{return_type} {convention} queue(int id) {{ {body} }}\n"
        )
        proposed_return = "void *" if return_type == "void *" else "void"
        prototype = f"{proposed_return} {convention} queue(int value)"
        before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
        if return_type == "int":
            with pytest.raises(ValueError, match="return statements"):
                reconcile_contract([cfg], "queue", Path("src/api.h"), prototype, dry_run=True)
        else:
            preview = reconcile_contract([cfg], "queue", Path("src/api.h"), prototype, dry_run=True)
            assert preview["verification_required"]
        assert before == {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}


class TestCallbackTypedefContracts:
    @pytest.mark.parametrize("chained", [False, True])
    def test_callback_parameter_equals_inline_form(self, tmp_path: Path, chained: bool) -> None:
        cfg = _project(tmp_path)
        alias = "Chained" if chained else "Callback"
        header = "typedef\nint (__cdecl* Callback)(char* event);\n"
        if chained:
            header += "typedef Callback Chained;\n"
        (cfg.reversed_dir / "api.h").write_text(header)
        (cfg.reversed_dir / "owner.c").write_text(
            f'#include "api.h"\nint queue({alias} check) {{ return 1; }}\n'
        )
        (cfg.reversed_dir / "user.c").write_text(
            "int queue(int (__cdecl* handler)(char* value));\nint wrapper(void) { return 0; }\n"
        )
        report = audit_contracts(cfg, name="queue")
        assert not report["unknown"]
        assert not report["findings"]
        assert {site["key"] for site in report["sites"]} == {"int(int(*)(char*))"}

    @pytest.mark.parametrize(
        "other_callback",
        [
            "void (__cdecl* Callback)(char* value)",
            "int (__stdcall* Callback)(char* value)",
            "int (__cdecl* Callback)(int* value)",
            "int (__cdecl* Callback)(char* value, ...)",
        ],
    )
    def test_callback_contract_changes_stay_distinct(
        self, tmp_path: Path, other_callback: str
    ) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "owner.c").write_text(
            "typedef int (__cdecl* Callback)(char* event);\n"
            "int queue(Callback check) { return 1; }\n"
        )
        (cfg.reversed_dir / "user.c").write_text(
            f"typedef {other_callback};\nint queue(Callback handler);\n"
            "int wrapper(void) { return 0; }\n"
        )
        report = audit_contracts(cfg, name="queue")
        assert not report["unknown"]
        assert report["findings"][0]["severity"] == "error"
        assert report["findings"][0]["differences"] == ["signature"]

    def test_conditional_callback_remains_unknown(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "owner.c").write_text(
            "#if OTHER_ABI\ntypedef int (__stdcall* Callback)(char* event);\n"
            "#else\ntypedef int (__cdecl* Callback)(char* event);\n#endif\n"
            "int queue(Callback check) { return 1; }\n"
        )
        report = audit_contracts(cfg, name="queue")
        assert any(row.get("types") == ["Callback"] for row in report["unknown"])

    def test_qualified_callback_parameter_remains_unknown(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "owner.c").write_text(
            "typedef int (*Callback)(char* event);\nint queue(Callback const check) { return 1; }\n"
        )
        report = audit_contracts(cfg, name="queue")
        assert any(row.get("types") == ["Callback"] for row in report["unknown"])

    def test_callback_object_remains_unknown(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "owner.c").write_text(
            "typedef int (*Callback)(char* event);\nextern Callback check;\n"
            "int queue(int value) { return value; }\n"
        )
        report = audit_contracts(cfg, name="check")
        assert any(row.get("types") == ["Callback"] for row in report["unknown"])

    def test_nested_alias_is_resolved_after_callback_expansion(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "owner.c").write_text(
            "typedef int Value; typedef int (*Callback)(Value inner);\n"
            "int queue(Callback check, Value id) { return id; }\n"
        )
        (cfg.reversed_dir / "user.c").write_text(
            "int queue(int (*handler)(int value), int id);\nint wrapper(void) { return 0; }\n"
        )
        report = audit_contracts(cfg, name="queue")
        assert not report["unknown"] and not report["findings"]

    def test_alias_cycle_remains_unknown(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "owner.c").write_text(
            "typedef Second First; typedef First Second;\nint queue(First value) { return 1; }\n"
        )
        report = audit_contracts(cfg, name="queue")
        assert any("cyclic typedef" in row.get("types", []) for row in report["unknown"])

    def test_named_record_pointer_alias_keeps_its_declarator(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "owner.c").write_text(
            "typedef struct Event { int id; } *EventPtr;\nint queue(EventPtr event) { return 1; }\n"
        )
        (cfg.reversed_dir / "user.c").write_text(
            "struct Event; int queue(struct Event *value);\nint wrapper(void) { return 0; }\n"
        )
        report = audit_contracts(cfg, name="queue")
        assert not report["unknown"] and not report["findings"]
        assert {site["key"] for site in report["sites"]} == {"int(struct Event*)"}

    def test_record_returning_callback_keeps_its_declarator(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        (cfg.reversed_dir / "owner.c").write_text(
            "struct Event { int id; };\n"
            "typedef struct Event (*Callback)(int id);\n"
            "int queue(Callback check) { return 1; }\n"
        )
        (cfg.reversed_dir / "user.c").write_text(
            "struct Event; int queue(struct Event (*handler)(int value));\n"
            "int wrapper(void) { return 0; }\n"
        )
        report = audit_contracts(cfg, name="queue")
        assert not report["unknown"] and not report["findings"]
        assert {site["key"] for site in report["sites"]} == {"int(struct Event(*)(int))"}
