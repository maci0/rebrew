"""Read-only bound-donor replacement plans."""

lazy from pathlib import Path

import pytest

from rebrew.binding_replacement_plan import plan_binding_replacement
from rebrew.c_rename import ParsedSource, occurrences
from rebrew.config import ProjectConfig, load_config
from rebrew.metadata.functions import record_function_identity


def project(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    donor = src / "donor.c"
    donor.write_text("void old(char *p) {}\n")
    replacement = src / "destination.c"
    replacement.write_text("void canonical(char *p) {}\n")
    caller = src / "caller.c"
    caller.write_text("void old(char *);\nvoid caller(void) { old(0); }\n")
    cfg = ProjectConfig(root=tmp_path, reversed_dir=src, module="TL", target_name="TL")
    record_function_identity(
        tmp_path,
        module="TL",
        va=0x1000,
        file="src/donor.c",
        name="old",
        symbol="_old",
        kind="FUNCTION",
        size=4,
    )
    return cfg, donor, replacement, caller


def decisions(*paths: Path):
    result = {}
    for path in paths:
        for hit in occurrences(ParsedSource.parse(path.read_text()), "old"):
            result[f"src/{path.name}:{hit.start}:TL"] = (
                "preserve" if path.name == "donor.c" else "replace"
            )
    return result


def plan(cfg, donor, replacement, ownership, **kwargs):
    return plan_binding_replacement(
        [cfg], {"TL": 0x1000}, donor, replacement, "old", "canonical", ownership, **kwargs
    )


def test_config_changed_after_target_load_is_rejected(tmp_path: Path, monkeypatch):
    import rebrew.binding_replacement_plan as planner

    _cfg, donor, replacement, caller = project(tmp_path)
    config = tmp_path / "rebrew-project.toml"
    initial = '[targets.TL]\nbinary="game.exe"\nmodule="TL"\nreversed_dir="src"\n'
    config.write_text(initial)
    cfg = load_config(root=tmp_path, target="TL")
    load = planner.organization_configs

    def racing_load(configured):
        result = load(configured)
        config.write_text(
            initial + '[targets.GOLD]\nbinary="gold.exe"\nmodule="GOLD"\nreversed_dir="src"\n'
        )
        return result

    monkeypatch.setattr(planner, "organization_configs", racing_load)
    with pytest.raises(ValueError, match="config.*changed"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_config_created_during_discovery_is_rejected(tmp_path: Path, monkeypatch):
    import rebrew.binding_replacement_plan as planner

    cfg, donor, replacement, caller = project(tmp_path)
    collect = planner.collect_target_sources

    def racing_collect(*args, **kwargs):
        result = collect(*args, **kwargs)
        (tmp_path / "rebrew-project.toml").write_text("[targets.GOLD]\n")
        return result

    monkeypatch.setattr(planner, "collect_target_sources", racing_collect)
    with pytest.raises(ValueError, match="config.*changed"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_config_changed_after_snapshot_is_rejected(tmp_path: Path, monkeypatch):
    import rebrew.binding_replacement_plan as planner

    _cfg, donor, replacement, caller = project(tmp_path)
    config = tmp_path / "rebrew-project.toml"
    initial = '[targets.TL]\nbinary="game.exe"\nmodule="TL"\nreversed_dir="src"\n'
    config.write_text(initial)
    cfg = load_config(root=tmp_path, target="TL")
    contract = planner.contract_contexts
    calls = 0

    def racing_context(*args, **kwargs):
        nonlocal calls
        result = contract(*args, **kwargs)
        calls += 1
        if calls == 2:
            config.write_text(initial + '\n[targets.GOLD]\nbinary="gold.exe"\n')
        return result

    monkeypatch.setattr(planner, "contract_contexts", racing_context)
    with pytest.raises(ValueError, match="inputs changed while planning"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_review_is_read_only_and_proposes_only_reviewed_references(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    before = {p: p.read_bytes() for p in (donor, replacement, caller)}
    result = plan(cfg, donor, replacement, decisions(donor, caller))
    assert not result["apply_available"]
    assert len(result["references"]) == 3
    assert {p: p.read_bytes() for p in before} == before
    assert (
        plan(
            cfg,
            donor,
            replacement,
            decisions(donor, caller),
            expected_digest=result["input_digest"],
        )["input_digest"]
        == result["input_digest"]
    )


def test_missing_owner_or_stale_discovery_is_rejected(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    with pytest.raises(ValueError, match="ownership"):
        plan(cfg, donor, replacement, {})
    owners = decisions(donor, caller)
    original = plan(cfg, donor, replacement, owners)
    (tmp_path / "src" / "new.h").write_text("/* new discovery */\n")
    with pytest.raises(ValueError, match="changed"):
        plan(cfg, donor, replacement, owners, expected_digest=original["input_digest"])


def test_retargeted_include_symlink_to_same_file_changes_digest(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    src = caller.parent
    (src / "real.inc").write_text("/* header */\n")
    (src / "first.inc").symlink_to("real.inc")
    (src / "second.inc").symlink_to("real.inc")
    link = src / "api.h"
    link.symlink_to("first.inc")
    caller.write_text('#include "api.h"\nvoid old(char *);\nvoid caller(void) { old(0); }\n')
    owners = decisions(donor, caller)
    original = plan(cfg, donor, replacement, owners)
    link.unlink()
    link.symlink_to("second.inc")
    with pytest.raises(ValueError, match="changed"):
        plan(cfg, donor, replacement, owners, expected_digest=original["input_digest"])


def test_indirect_symlink_retarget_changes_digest(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    src = caller.parent
    (src / "real.inc").write_text("/* header */\n")
    link = src / "indirect.inc"
    link.symlink_to("real.inc")
    (src / "api.h").symlink_to("indirect.inc")
    caller.write_text('#include "api.h"\nvoid old(char *);\nvoid caller(void) { old(0); }\n')
    owners = decisions(donor, caller)
    original = plan(cfg, donor, replacement, owners)
    link.unlink()
    link.symlink_to("./real.inc")
    with pytest.raises(ValueError, match="changed"):
        plan(cfg, donor, replacement, owners, expected_digest=original["input_digest"])


def test_transitive_header_and_new_source_invalidate_review(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    (caller.parent / "api.h").write_text('#include "inner.inc"\n')
    inner = caller.parent / "inner.inc"
    inner.write_text("/* original */\n")
    caller.write_text('#include "api.h"\nvoid old(char *);\nvoid caller(void) { old(0); }\n')
    owners = decisions(donor, caller)
    original = plan(cfg, donor, replacement, owners)
    inner.write_text("/* changed */\n")
    with pytest.raises(ValueError, match="changed"):
        plan(cfg, donor, replacement, owners, expected_digest=original["input_digest"])
    inner.write_text("/* original */\n")
    (caller.parent / "extra.c").write_text("void unrelated(void) {}\n")
    with pytest.raises(ValueError, match="changed"):
        plan(cfg, donor, replacement, owners, expected_digest=original["input_digest"])


def test_header_changed_after_closure_read_is_rejected(tmp_path: Path, monkeypatch):
    import rebrew.source_contracts as contracts

    cfg, donor, replacement, caller = project(tmp_path)
    header = caller.parent / "api.h"
    header.write_text("/* original */\n")
    caller.write_text('#include "api.h"\nvoid old(char *);\nvoid caller(void) { old(0); }\n')
    scan = contracts.scan_include_closure
    changed = False

    def racing_scan(*args, **kwargs):
        nonlocal changed
        result = scan(*args, **kwargs)
        if not changed and str(header) in result[0]:
            header.write_text("/* changed */\n")
            changed = True
        return result

    monkeypatch.setattr(contracts, "scan_include_closure", racing_scan)
    with pytest.raises(ValueError, match="changed while"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_symlink_changed_after_closure_read_is_rejected(tmp_path: Path, monkeypatch):
    import rebrew.binding_replacement_plan as planner

    cfg, donor, replacement, caller = project(tmp_path)
    target = caller.parent / "real.inc"
    target.write_text("/* header */\n")
    link = caller.parent / "api.h"
    link.symlink_to("real.inc")
    caller.write_text('#include "api.h"\nvoid old(char *);\nvoid caller(void) { old(0); }\n')
    contract = planner.contract_contexts
    changed = False

    def racing_context(*args, **kwargs):
        nonlocal changed
        result = contract(*args, **kwargs)
        if not changed:
            link.unlink()
            link.symlink_to("./real.inc")
            changed = True
        return result

    monkeypatch.setattr(planner, "contract_contexts", racing_context)
    with pytest.raises(ValueError, match="include identity changed"):
        plan(cfg, donor, replacement, decisions(donor, caller))


@pytest.mark.parametrize("macro", [True, False])
def test_ambiguous_symlink_parent_refused_even_without_macro(tmp_path: Path, macro):
    cfg, donor, replacement, caller = project(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    (other / "real.h").write_text('#include "nested.h"\n')
    (other / "nested.h").write_text("/* other */\n")
    (caller.parent / "nested.h").write_text(
        "#define canonical(x) ((void)0)\n" if macro else "/* local */\n"
    )
    (caller.parent / "api.h").symlink_to("../other/real.h")
    caller.write_text('#include "api.h"\nvoid old(char *);\nvoid caller(void) { old(0); }\n')
    with pytest.raises(ValueError, match="ambiguous symlinked include parent"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_earlier_include_created_during_plan_is_rejected(tmp_path: Path, monkeypatch):
    import rebrew.binding_replacement_plan as planner

    cfg, donor, replacement, caller = project(tmp_path)
    early = tmp_path / "early"
    late = tmp_path / "late"
    early.mkdir()
    late.mkdir()
    (late / "api.h").write_text("/* same */\n")
    cfg.base_cflags = f'/I"{early}" /I"{late}"'
    caller.write_text("#include <api.h>\nvoid old(char *);\nvoid caller(void) { old(0); }\n")
    contract = planner.contract_contexts
    changed = False

    def racing_context(*args, **kwargs):
        nonlocal changed
        result = contract(*args, **kwargs)
        if not changed:
            (early / "api.h").write_text("/* same */\n")
            changed = True
        return result

    monkeypatch.setattr(planner, "contract_contexts", racing_context)
    with pytest.raises(ValueError, match="include closure changed while planning"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_source_added_during_review_is_rejected(tmp_path: Path, monkeypatch):
    import rebrew.binding_replacement_plan as planner

    cfg, donor, replacement, caller = project(tmp_path)
    header = caller.parent / "api.h"
    header.write_text("/* header */\n")
    contract = planner.contract_contexts
    changed = False

    def racing_context(*args, **kwargs):
        nonlocal changed
        result = contract(*args, **kwargs)
        if not changed:
            (caller.parent / "extra.c").write_text("void unrelated(void) {}\n")
            changed = True
        return result

    monkeypatch.setattr(planner, "contract_contexts", racing_context)
    with pytest.raises(ValueError, match="changed while planning"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_missing_or_retired_provider_is_rejected(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    replacement.write_text("void unrelated(void) {}\n")
    with pytest.raises(ValueError, match="external definition"):
        plan(cfg, donor, replacement, decisions(donor, caller))
    replacement.write_text("void canonical(char *p) {}\n")
    with pytest.raises(ValueError, match="missing or retired"):
        plan_binding_replacement(
            [cfg], {"TL": 0x2000}, donor, replacement, "old", "canonical", decisions(donor, caller)
        )


def test_macro_ownership_is_not_guessed(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    caller.write_text("#define old(x) (x)\nvoid caller(void) { old(0); }\n")
    with pytest.raises(ValueError, match="ambiguous macro"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_collision_and_readonly_dependency_changes_are_rejected(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    evidence = tmp_path / "native.bin"
    evidence.write_bytes(b"native")
    owners = decisions(donor, caller)
    first = plan(cfg, donor, replacement, owners, evidence=[evidence])
    evidence.write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed"):
        plan(
            cfg,
            donor,
            replacement,
            owners,
            evidence=[evidence],
            expected_digest=first["input_digest"],
        )
    (tmp_path / "src" / "duplicate.c").write_text("void canonical(char *p) {}\n")
    with pytest.raises(ValueError, match="already has a definition"):
        plan(cfg, donor, replacement, owners)


def test_actual_retired_identity_is_rejected(tmp_path: Path):
    from rebrew.metadata.binding_history import change_source_binding

    cfg, donor, replacement, caller = project(tmp_path)
    change_source_binding(tmp_path, "TL", 0x1000, reason="reviewed retirement")
    with pytest.raises(ValueError, match="missing or retired"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_cross_target_ownership_conflict_is_not_silently_rewritten(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    gold = ProjectConfig(
        root=tmp_path, reversed_dir=cfg.reversed_dir, module="GOLD", target_name="GOLD"
    )
    record_function_identity(
        tmp_path,
        module="GOLD",
        va=0x2000,
        file="src/donor.c",
        name="old",
        symbol="_old",
        kind="FUNCTION",
        size=4,
    )
    owners = decisions(donor, caller)
    for key, value in list(owners.items()):
        owners[key.removesuffix(":TL") + ":GOLD"] = value
    call_key = next(k for k in owners if k.startswith("src/caller.c:") and k.endswith(":GOLD"))
    owners[call_key] = "preserve"
    with pytest.raises(ValueError, match="conflicting target ownership"):
        plan_binding_replacement(
            [cfg, gold],
            {"TL": 0x1000, "GOLD": 0x2000},
            donor,
            replacement,
            "old",
            "canonical",
            owners,
        )


def test_discovery_exposes_ownership_keys_without_guessing(tmp_path: Path):
    cfg, donor, replacement, _caller = project(tmp_path)
    result = plan_binding_replacement([cfg], {"TL": 0x1000}, donor, replacement, "old", "canonical")
    assert not result["ownership_complete"]
    assert not result["apply_available"]
    assert {r["decision"] for r in result["references"]} == {"undecided"}


def test_new_name_macro_in_caller_is_rejected(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    caller.write_text(
        "#define canonical(x) ((void)0)\nvoid old(char *);\nvoid caller(void) { old(0); }\n"
    )
    with pytest.raises(ValueError, match="replacement name has a macro"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_new_name_macro_in_included_header_is_rejected(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    (caller.parent / "api.h").write_text("#define canonical(x) ((void)0)\n")
    caller.write_text('#include "api.h"\nvoid old(char *);\nvoid caller(void) { old(0); }\n')
    with pytest.raises(ValueError, match="replacement name has a macro"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_new_name_local_function_pointer_shadow_is_rejected(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    caller.write_text(
        "void old(char *);\nvoid caller(void) { void (*canonical)(char *) = 0; old(0); }\n"
    )
    with pytest.raises(ValueError, match="local shadow"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_new_name_parameter_shadow_is_rejected(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    caller.write_text("void old(char *);\nvoid caller(int canonical) { old(0); }\n")
    with pytest.raises(ValueError, match="local shadow"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_va_arg_pointer_type_is_not_a_syntax_error(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    caller.write_text(
        "void old(char *);\nvoid caller(void *ap) { char *p = va_arg(ap, char*); old(p); }\n"
    )
    assert plan(cfg, donor, replacement, decisions(donor, caller))["ownership_complete"]


def test_incomplete_include_closure_is_reported_not_asserted_safe(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    caller.write_text('#include "missing.h"\nvoid old(char *);\nvoid caller(void) { old(0); }\n')
    result = plan(cfg, donor, replacement, decisions(donor, caller))
    assert result["ownership_complete"] and not result["safety_review_complete"]
    assert result["macro_scope_unknown"]["include_contexts"]
    assert result["macro_scope_unknown"]["other"]


def test_existing_canonical_call_in_initializer_is_not_a_shadow(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    caller.write_text(
        "void old(char *);\nvoid canonical(char *);\nvoid caller(void) { int x = (canonical(0), 1); old(0); }\n"
    )
    assert plan(cfg, donor, replacement, decisions(donor, caller))["ownership_complete"]


@pytest.mark.parametrize("declaration", ["extern int canonical;", "typedef int canonical;"])
def test_new_name_file_scope_ordinary_collision_is_rejected(tmp_path: Path, declaration: str):
    cfg, donor, replacement, caller = project(tmp_path)
    caller.write_text(f"{declaration}\nvoid old(char *);\nvoid caller(void) {{ old(0); }}\n")
    with pytest.raises(ValueError, match="conflicting declaration"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_new_name_header_ordinary_collision_is_rejected(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    (caller.parent / "api.h").write_text("extern int canonical;\n")
    caller.write_text('#include "api.h"\nvoid old(char *);\nvoid caller(void) { old(0); }\n')
    with pytest.raises(ValueError, match="conflicting declaration"):
        plan(cfg, donor, replacement, decisions(donor, caller))


def test_split_guard_uses_explicit_target_states_and_preserves_offsets(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    gold = ProjectConfig(
        root=tmp_path,
        reversed_dir=cfg.reversed_dir,
        module="GOLD",
        target_name="GOLD",
        defines=["REBREW_GOLD"],
    )
    record_function_identity(
        tmp_path,
        module="GOLD",
        va=0x2000,
        file="src/donor.c",
        name="old",
        symbol="_old",
        kind="FUNCTION",
        size=4,
    )
    caller.write_text(
        "void old(char *);\nvoid caller(int n) {\n#ifdef REBREW_GOLD\n if (n == 1) {\n#else\n if (n == 2) {\n#endif\n old(0);\n }\n}\n"
    )
    owners = decisions(donor, caller)
    for key, value in list(owners.items()):
        owners[key.removesuffix(":TL") + ":GOLD"] = value
    args = (
        [cfg, gold],
        {"TL": 0x1000, "GOLD": 0x2000},
        donor,
        replacement,
        "old",
        "canonical",
        owners,
    )
    with pytest.raises(ValueError, match="unknown macro"):
        plan_binding_replacement(*args)
    result = plan_binding_replacement(
        *args, guard_states={"TL": {"REBREW_GOLD": False}, "GOLD": {"REBREW_GOLD": True}}
    )
    assert result["ownership_complete"] and not result["safety_review_complete"]
    expected = caller.read_bytes().index(b"old(0)")
    assert {
        r["offset"]
        for r in result["references"]
        if r["file"].endswith("caller.c") and r["line"] == 8
    } == {expected}
    with pytest.raises(ValueError, match="conflicts with target define"):
        plan_binding_replacement(
            *args, guard_states={"TL": {"REBREW_GOLD": False}, "GOLD": {"REBREW_GOLD": False}}
        )


def test_split_guard_refuses_unknown_header_closure(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    caller.write_text(
        '#include "missing.h"\nvoid old(char *);\nvoid caller(int n) {\n#ifdef FEATURE\n if (n == 1) {\n#else\n if (n == 2) {\n#endif\n old(0);\n }\n}\n'
    )
    with pytest.raises(ValueError, match="include closure is incomplete"):
        plan_binding_replacement(
            [cfg],
            {"TL": 0x1000},
            donor,
            replacement,
            "old",
            "canonical",
            decisions(donor, caller),
            guard_states={"TL": {"FEATURE": True}},
        )


def test_split_guard_refuses_conflicting_compiler_flag(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    cfg.base_cflags = "/UREBREW_GOLD"
    cfg.defines = ["REBREW_GOLD"]
    caller.write_text(
        "void old(char *);\nvoid caller(int n) {\n#ifdef REBREW_GOLD\n if (n == 1) {\n#else\n if (n == 2) {\n#endif\n old(0);\n }\n}\n"
    )
    with pytest.raises(ValueError, match="additional compiler flags"):
        plan_binding_replacement(
            [cfg],
            {"TL": 0x1000},
            donor,
            replacement,
            "old",
            "canonical",
            decisions(donor, caller),
            guard_states={"TL": {"REBREW_GOLD": True}},
        )


def test_split_guard_refuses_conditional_reference_change(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    gold = ProjectConfig(
        root=tmp_path,
        reversed_dir=cfg.reversed_dir,
        module="GOLD",
        target_name="GOLD",
        defines=["REBREW_GOLD"],
    )
    record_function_identity(
        tmp_path,
        module="GOLD",
        va=0x2000,
        file="src/donor.c",
        name="old",
        symbol="_old",
        kind="FUNCTION",
        size=4,
    )
    caller.write_text(
        "void old(char *);\nvoid caller(int n) {\n#ifdef REBREW_GOLD\n if (n == 1) { old(0);\n#else\n if (n == 2) {\n#endif\n }\n}\n"
    )
    owners = decisions(donor, caller)
    for key, value in list(owners.items()):
        owners[key.removesuffix(":TL") + ":GOLD"] = value
    with pytest.raises(ValueError, match="target guards change reference ownership"):
        plan_binding_replacement(
            [cfg, gold],
            {"TL": 0x1000, "GOLD": 0x2000},
            donor,
            replacement,
            "old",
            "canonical",
            owners,
            guard_states={"TL": {"REBREW_GOLD": False}, "GOLD": {"REBREW_GOLD": True}},
        )


def test_split_guard_checks_shadow_in_each_target_view(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    gold = ProjectConfig(
        root=tmp_path,
        reversed_dir=cfg.reversed_dir,
        module="GOLD",
        target_name="GOLD",
        defines=["REBREW_GOLD"],
    )
    record_function_identity(
        tmp_path,
        module="GOLD",
        va=0x2000,
        file="src/donor.c",
        name="old",
        symbol="_old",
        kind="FUNCTION",
        size=4,
    )
    caller.write_text(
        "void old(char *);\nvoid caller(int n) {\n#ifdef REBREW_GOLD\n if (n == 1) { int canonical = 0;\n#else\n if (n == 2) {\n#endif\n old(0);\n }\n}\n"
    )
    owners = decisions(donor, caller)
    for key, value in list(owners.items()):
        owners[key.removesuffix(":TL") + ":GOLD"] = value
    with pytest.raises(ValueError, match="local shadow"):
        plan_binding_replacement(
            [cfg, gold],
            {"TL": 0x1000, "GOLD": 0x2000},
            donor,
            replacement,
            "old",
            "canonical",
            owners,
            guard_states={"TL": {"REBREW_GOLD": False}, "GOLD": {"REBREW_GOLD": True}},
        )


def test_split_guard_refuses_unconfigured_positive_macro(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    caller.write_text(
        "void old(char *);\nvoid caller(int n) {\n#ifdef FEATURE\n if (n == 1) {\n#else\n if (n == 2) { old(0);\n#endif\n }\n}\n"
    )
    with pytest.raises(ValueError, match="no configured target definition"):
        plan_binding_replacement(
            [cfg],
            {"TL": 0x1000},
            donor,
            replacement,
            "old",
            "canonical",
            decisions(donor, caller),
            guard_states={"TL": {"FEATURE": True}},
        )


def test_target_preset_guard_override_is_not_ignored(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    cfg.cflags_presets = {"TL": "/DREBREW_GOLD"}
    gold = ProjectConfig(
        root=tmp_path,
        reversed_dir=cfg.reversed_dir,
        module="GOLD",
        target_name="GOLD",
        defines=["REBREW_GOLD"],
    )
    record_function_identity(
        tmp_path,
        module="GOLD",
        va=0x2000,
        file="src/donor.c",
        name="old",
        symbol="_old",
        kind="FUNCTION",
        size=4,
    )
    caller.write_text(
        "void old(char *);\nvoid caller(int n) {\n#ifdef REBREW_GOLD\n if (n == 1) {\n#else\n if (n == 2) {\n#endif\n old(0);\n }\n}\n"
    )
    owners = decisions(donor, caller)
    for key, value in list(owners.items()):
        owners[key.removesuffix(":TL") + ":GOLD"] = value
    with pytest.raises(ValueError, match="additional compiler flags"):
        plan_binding_replacement(
            [cfg, gold],
            {"TL": 0x1000, "GOLD": 0x2000},
            donor,
            replacement,
            "old",
            "canonical",
            owners,
            guard_states={"TL": {"REBREW_GOLD": False}, "GOLD": {"REBREW_GOLD": True}},
        )


def test_forced_include_must_not_be_silently_ignored(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    cfg.defines = ["REBREW_GOLD"]
    cfg.base_cflags = "/FIforced.h"
    caller.write_text(
        "void old(char *);\nvoid caller(int n) {\n#ifdef REBREW_GOLD\n if (n == 1) {\n#else\n if (n == 2) {\n#endif\n old(0);\n }\n}\n"
    )
    with pytest.raises(ValueError, match="forced compiler include"):
        plan_binding_replacement(
            [cfg],
            {"TL": 0x1000},
            donor,
            replacement,
            "old",
            "canonical",
            decisions(donor, caller),
            guard_states={"TL": {"REBREW_GOLD": True}},
        )


def test_split_guard_rejects_invalid_selected_target_view(tmp_path: Path):
    cfg, donor, replacement, caller = project(tmp_path)
    cfg.defines = ["REBREW_GOLD"]
    caller.write_text(
        "void old(char *);\nvoid caller(int n) {\n#ifdef REBREW_GOLD\n"
        " if (n == ) {\n#else\n if (n == 2) {\n#endif\n old(0);\n }\n}\n"
    )
    with pytest.raises(ValueError, match="structural view has syntax errors"):
        plan_binding_replacement(
            [cfg],
            {"TL": 0x1000},
            donor,
            replacement,
            "old",
            "canonical",
            decisions(donor, caller),
            guard_states={"TL": {"REBREW_GOLD": True}},
        )
