"""Bounded guarded interleaving previews and publishes only reviewed safe cases."""

import json
from typing import Any
lazy from pathlib import Path

import pytest
from source_util import SourceFixture, write_source
from typer.testing import CliRunner

from rebrew.config import ProjectConfig
from rebrew.merge import app
from rebrew.metadata.functions import load_metadata
from rebrew.metadata.storage import metadata_store
from rebrew.source_selection import collect_target_sources


def _project(
    root: Path, monkeypatch: pytest.MonkeyPatch, backend: str = "toml"
) -> tuple[list[Path], Path, ProjectConfig]:
    (root / "rebrew-project.toml").write_text(f'[metadata]\nbackend = "{backend}"\n')
    units = [
        (
            "script.c",
            "#ifndef REBREW_SERVER\n/* keep walk */\n/* ADDRESS: GOLDTL 0x0040cae0 */\nint walk(void) { return 1; }\n/* ADDRESS: GOLDTL 0x0040d980 */\nint camera(void) { return 4; }\n/* ADDRESS: GOLDTL 0x0040e1a0 */\nint register_scripts(void) { return walk() + camera(); }\n#endif\n",
            [(0x40CAE0, "walk"), (0x40D980, "camera"), (0x40E1A0, "register_scripts")],
        ),
        (
            "animation.c",
            "/* keep animation */\n/* ADDRESS: GOLDTL 0x0040cff0 */\nint animation(void) { return 2; }\n",
            [(0x40CFF0, "animation")],
        ),
        (
            "animation_int.c",
            "/* ADDRESS: GOLDTL 0x0040d130 */\nint animation_int(void) { return 3; }\n",
            [(0x40D130, "animation_int")],
        ),
    ]
    paths = []
    for filename, source, rows in units:
        path = root / filename
        write_source(
            path,
            SourceFixture(
                source,
                {
                    f"GOLDTL.0x{va:08x}": {"kind": "FUNCTION", "symbol": f"_{name}", "size": 8}
                    for va, name in rows
                },
            ),
        )
        paths.append(path)
    cfg = ProjectConfig(root=root, reversed_dir=root, module="GOLDTL", target_name="TL")
    server = ProjectConfig(root=root, reversed_dir=root, module="SERVER", target_name="SERVER")
    monkeypatch.setattr("rebrew.merge.require_config", lambda **kwargs: cfg)
    monkeypatch.setattr(
        "rebrew.source_organization.organization_configs", lambda cfg: [cfg, server]
    )
    return paths, root / "merged.c", cfg


def _invoke(paths: list[Path], output: Path, *flags: str) -> Any:
    return CliRunner().invoke(
        app,
        [
            "--output",
            str(output),
            "--force",
            "--delete",
            "--guarded-interleave",
            "--json",
            *flags,
            *map(str, paths),
        ],
    )


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_guarded_interleave_preview_apply_and_target_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
) -> None:
    paths, out, cfg = _project(tmp_path, monkeypatch, backend)
    metadata = load_metadata(tmp_path)
    original = {path: path.read_bytes() for path in paths}
    preview = _invoke(paths, out, "--dry-run")
    assert preview.exit_code == 0, preview.output
    result = json.loads(preview.output)
    output = result["merged_source"]
    order = [
        "walk(void)",
        "animation(void)",
        "animation_int(void)",
        "camera(void)",
        "register_scripts(void)",
    ]
    assert [output.index(name) for name in order] == sorted(output.index(name) for name in order)
    assert "/* keep walk */" in output and "/* keep animation */" in output
    assert output.count("#ifndef REBREW_SERVER") == output.count("#endif") == 2
    assert not out.exists() and {path: path.read_bytes() for path in paths} == original
    assert load_metadata(tmp_path) == metadata
    applied = _invoke(paths, out, "--expected-digest", result["input_digest"])
    assert applied.exit_code == 0, applied.output
    assert out.read_text() == output and all(not path.exists() for path in paths)
    assert all(row["file"] == "merged.c" for row in load_metadata(tmp_path).values())
    server = ProjectConfig(
        root=tmp_path, reversed_dir=tmp_path, module="SERVER", target_name="SERVER"
    )
    assert out not in collect_target_sources(server, "SERVER")[0]
    assert out in collect_target_sources(cfg, "GOLDTL")[0]


def test_guarded_interleave_accepts_simple_msx_scalar_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    source = paths[2]
    source.write_text(
        source.read_text().replace(
            "int animation_int(void) { return 3; }",
            "void __cdecl animation_int(float fade, int time) { (void)fade; (void)time; }",
        )
    )
    preview = _invoke(paths, out, "--dry-run")
    assert preview.exit_code == 0, preview.output
    digest = json.loads(preview.output)["input_digest"]
    result = _invoke(paths, out, "--expected-digest", digest)
    assert result.exit_code == 0, result.output
    assert "void __cdecl animation_int(float fade, int time)" in out.read_text()


@pytest.mark.parametrize("flag", ["/Dfade=__LINE__", "-Dfade=__LINE__", "-FIhidden.h", "-X"])
def test_guarded_interleave_refuses_parameter_capture_and_hidden_includes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str
) -> None:
    paths, out, cfg = _project(tmp_path, monkeypatch)
    source = paths[2]
    source.write_text(
        source.read_text().replace(
            "int animation_int(void) { return 3; }",
            "void animation_int(float fade, int time) { (void)fade; (void)time; }",
        )
    )
    cfg.base_cflags = flag
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0
    assert not out.exists()


def test_guarded_interleave_refuses_incompatible_internal_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    source = paths[0]
    source.write_text(
        source.read_text().replace(
            "int walk(void) { return 1; }", "int walk(int vol) { return vol; }"
        )
    )
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0 and "call contract" in result.output
    assert not out.exists()


@pytest.mark.parametrize("result_type", ["float", "void"])
def test_guarded_interleave_refuses_implicit_non_int_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, result_type: str
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    script = paths[0]
    replacement = (
        "float walk(void) { return 1; }"
        if result_type == "float"
        else "void walk(void) { return; }"
    )
    script.write_text(
        script.read_text()
        .replace("int walk(void) { return 1; }", replacement)
        .replace("return walk() + camera();", "return camera();")
    )
    animation = paths[1]
    animation.write_text(animation.read_text().replace("return 2;", "walk(); return 2;"))
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0 and "call contract" in result.output
    assert not out.exists()


def test_guarded_interleave_accepts_compatible_shared_float_declaration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    paths[0].write_text(
        paths[0]
        .read_text()
        .replace("int walk(void) { return 1; }", "float walk(void) { return 1; }")
    )
    for path in paths:
        path.write_text("float walk(void);\n" + path.read_text())
    preview = _invoke(paths, out, "--dry-run")
    assert preview.exit_code == 0, preview.output
    result = _invoke(paths, out, "--expected-digest", json.loads(preview.output)["input_digest"])
    assert result.exit_code == 0, result.output
    assert out.read_text().count("float walk(void);") == 1


@pytest.mark.parametrize("modifier,flag", [("__stdcall", "/Gd"), ("__cdecl", "/Gz")])
def test_guarded_interleave_refuses_implicit_call_convention_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, modifier: str, flag: str
) -> None:
    paths, out, cfg = _project(tmp_path, monkeypatch)
    script = paths[0]
    script.write_text(script.read_text().replace("int walk(void)", f"int {modifier} walk(void)"))
    cfg.base_cflags = flag
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0
    assert not out.exists()


@pytest.mark.parametrize("flag,allowed", [("/Gd", True), ("/Gz", False), ("-Gz", False)])
def test_guarded_interleave_respects_compiler_calling_convention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str, allowed: bool
) -> None:
    paths, out, cfg = _project(tmp_path, monkeypatch)
    cfg.base_cflags = flag
    result = _invoke(paths, out, "--dry-run")
    assert (result.exit_code == 0) is allowed, result.output
    assert not out.exists()


@pytest.mark.parametrize("flag,allowed", [("/Gd", True), ("", True), ("/Gz", False)])
def test_guarded_interleave_explicit_cdecl_requires_default_caller_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, flag: str, allowed: bool
) -> None:
    paths, out, cfg = _project(tmp_path, monkeypatch)
    script = paths[0]
    script.write_text(script.read_text().replace("int walk(void)", "int __cdecl walk(void)"))
    cfg.base_cflags = flag
    result = _invoke(paths, out, "--dry-run")
    assert (result.exit_code == 0) is allowed, result.output
    assert not out.exists()


def test_guarded_interleave_requires_reviewed_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    result = _invoke(paths, out)
    assert result.exit_code != 0 and "requires --expected-digest" in result.output
    assert all(path.exists() for path in paths) and not out.exists()


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_guarded_apply_failure_restores_all_inputs_and_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch, backend)
    preview = _invoke(paths, out, "--dry-run")
    assert preview.exit_code == 0, preview.output
    digest = json.loads(preview.output)["input_digest"]
    store = metadata_store(tmp_path / "rebrew-functions.toml")
    before = [p.read_bytes() for p in paths], store.snapshot()

    def fail(*args: Any, **kwargs: Any) -> None:
        raise ValueError("injected source evidence failure")

    monkeypatch.setattr("rebrew.metadata.source_provenance.replace_source_metadata", fail)
    result = _invoke(paths, out, "--expected-digest", digest)
    assert result.exit_code != 0 and "injected source evidence failure" in result.output
    assert ([p.read_bytes() for p in paths], store.snapshot()) == before
    assert not out.exists()


def test_guarded_interleave_rejects_conflicting_prototypes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    paths[0].write_text(
        paths[0]
        .read_text()
        .replace(
            "#ifndef REBREW_SERVER\n",
            "#ifndef REBREW_SERVER\nvoid f(char*, unsigned int, const char*);\n",
        )
    )
    paths[1].write_text("void f(char*, int, const char*);\n" + paths[1].read_text())
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0 and "declarations" in result.output
    assert all(p.exists() for p in paths) and not out.exists()


@pytest.mark.parametrize("preamble", ['#include "missing.h"\n', "#define VALUE 1\n"])
def test_guarded_interleave_refuses_unreviewed_preambles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, preamble: str
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    paths[1].write_text(preamble + paths[1].read_text())
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0 and not out.exists()


def test_guarded_interleave_refuses_function_name_macro(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, out, cfg = _project(tmp_path, monkeypatch)
    cfg.defines = ["walk=other"]
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0 and "compiler macro" in result.output
    assert all(path.exists() for path in paths) and not out.exists()


def test_guarded_interleave_refuses_line_sensitive_macro(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    paths[1].write_text(paths[1].read_text().replace("return 2;", "return __LINE__;"))
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0 and "line-sensitive" in result.output
    assert all(path.exists() for path in paths) and not out.exists()


def test_guarded_interleave_refuses_macro_mutation_inside_function(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    paths[1].write_text(
        paths[1].read_text().replace("{ return 2; }", "{\n#define REBREW_SERVER\nreturn 2;\n}")
    )
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0 and "directives inside functions" in result.output
    assert all(path.exists() for path in paths) and not out.exists()


def test_guarded_interleave_refuses_conflicting_native_orders(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rebrew.metadata.functions import record_function_identity

    paths, out, _ = _project(tmp_path, monkeypatch)
    for va, name in [(0x500200, "walk"), (0x500100, "camera"), (0x500300, "register_scripts")]:
        record_function_identity(
            tmp_path,
            module="GOLD",
            va=va,
            file="script.c",
            name=name,
            symbol=f"_{name}",
            kind="FUNCTION",
            size=8,
        )
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0 and "conflicting native orders" in result.output
    assert all(path.exists() for path in paths) and not out.exists()


def test_guarded_interleave_refuses_different_target_participation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rebrew.metadata.functions import record_function_identity

    paths, out, _ = _project(tmp_path, monkeypatch)
    record_function_identity(
        tmp_path,
        module="SERVER",
        va=0x10001000,
        file="script.c",
        name="walk",
        symbol="_walk",
        kind="FUNCTION",
        size=8,
    )
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0 and "conflict-free organization review" in result.output
    assert all(path.exists() for path in paths) and not out.exists()


def test_guarded_interleave_refuses_unproven_external_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    paths[1].write_text(paths[1].read_text().replace("return 2;", "return external();"))
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0 and "external call contract" in result.output
    assert all(path.exists() for path in paths) and not out.exists()


@pytest.mark.parametrize(
    "body",
    [
        'return "x" == "x";',
        "static int local; return local;",
        "return (int)1.25;",
    ],
)
def test_guarded_interleave_refuses_unreviewed_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    paths[1].write_text(paths[1].read_text().replace("return 2;", body))
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0 and "manual review" in result.output
    assert all(path.exists() for path in paths) and not out.exists()


def test_hex_integer_is_not_misidentified_as_float(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    paths[1].write_text(paths[1].read_text().replace("return 2;", "return 0xdead;"))
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code == 0, result.output
    assert "0xdead" in json.loads(result.output)["merged_source"]


def test_guarded_interleave_refuses_unimplemented_shared_copies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    result = _invoke(paths, out, "--dry-run", "--shared")
    assert result.exit_code != 0 and "no --consolidate or --shared" in result.output
    assert all(path.exists() for path in paths) and not out.exists()


@pytest.mark.parametrize("definitions", [["VALUE=__LINE__"], ["VALUE=ALIAS", "ALIAS=__LINE__"]])
def test_guarded_interleave_refuses_line_sensitive_macro_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, definitions: list[str]
) -> None:
    paths, out, cfg = _project(tmp_path, monkeypatch)
    cfg.defines = definitions
    paths[1].write_text(paths[1].read_text().replace("return 2;", "return VALUE;"))
    result = _invoke(paths, out, "--dry-run")
    assert result.exit_code != 0 and "macro or unresolved identifier" in result.output
    assert all(path.exists() for path in paths) and not out.exists()


def test_guarded_interleave_accept_unresolved_includes_passes_closure_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, out, _ = _project(tmp_path, monkeypatch)
    p = paths[1]
    p.write_text('#include "missing.h"\n' + p.read_text())
    refused = _invoke(paths, out, "--dry-run")
    assert refused.exit_code != 0 and "include closure is incomplete" in refused.output
    wrong = _invoke(paths, out, "--dry-run", "--accept-unresolved-includes", "other.h")
    assert wrong.exit_code != 0 and "include closure is incomplete" in wrong.output
    accepted = _invoke(paths, out, "--dry-run", "--accept-unresolved-includes", "missing.h")
    assert accepted.exit_code != 0 and "include closure is incomplete" not in accepted.output
    assert "include closure is incomplete" not in accepted.output
    assert "conflict-free organization review" in accepted.output
    assert all(path.exists() for path in paths) and not out.exists()
