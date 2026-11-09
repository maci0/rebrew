"""Compiler image header extraction and target include review."""

import io
import subprocess
import tarfile
lazy from pathlib import Path

import pytest

from rebrew.binding_replacement_plan import plan_binding_replacement
from rebrew.compiler.cache import include_specs, scan_include_closure
from rebrew.compiler.image_headers import ImageHeaders
from rebrew.config import ProjectConfig
from rebrew.metadata.functions import record_function_identity
from rebrew.source_contracts import contract_contexts

IMAGE = "sha256:" + "a" * 64


def archive(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return output.getvalue()


@pytest.fixture
def runtime(monkeypatch):
    state = {
        "id": IMAGE,
        "archive": archive({"api.h": b"#include <inner.h>\n", "inner.h": b"int sdk;\n"}),
    }
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        data = state["id"].encode() if args[1:3] == ["image", "inspect"] else state["archive"]
        return subprocess.CompletedProcess(args, 0, stdout=data, stderr=b"")

    monkeypatch.setattr("rebrew.compiler.image_headers.run_process_group", run)
    return state, calls


def test_image_headers_are_fresh_and_extracted_from_immutable_id(runtime):
    _, calls = runtime
    with ImageHeaders() as images:
        root = images.get("msvc-6.0-sp5-pp")
        assert (root / "inner.h").read_bytes() == b"int sdk;\n"
        command = next(cmd for cmd in calls if cmd[1] == "run")
        assert IMAGE in command and "--pull=never" in command and "--network=none" in command
        assert images.normalize(str(root / "inner.h")).endswith("/Include/inner.h")
    assert not root.exists()


def test_changed_extraction_and_image_identity_are_rejected(runtime):
    state, _ = runtime
    with ImageHeaders() as images:
        root = images.get("msvc-6.0-sp5-pp")
        (root / "inner.h").write_bytes(b"tampered")
        with pytest.raises(ValueError, match="extraction changed"):
            images.verify()
    with ImageHeaders() as images:
        images.get("msvc-6.0-sp5-pp")
        state["id"] = "sha256:" + "b" * 64
        with pytest.raises(ValueError, match="image changed"):
            images.verify()


def test_extra_directory_and_invalid_image_identity_are_rejected(runtime):
    state, _ = runtime
    with ImageHeaders() as images:
        root = images.get("msvc-6.0-sp5-pp")
        (root / "unexpected").mkdir()
        with pytest.raises(ValueError, match="extraction changed"):
            images.verify()
    state["id"] = "not-a-digest"
    with ImageHeaders() as images, pytest.raises(ValueError, match="no immutable id"):
        images.get("msvc-6.0-sp5-pp")


@pytest.mark.parametrize("name", ["../escape.h", "/escape.h"])
def test_unsafe_archive_paths_are_rejected(runtime, name):
    state, _ = runtime
    state["archive"] = archive({name: b"bad"})
    with ImageHeaders() as images, pytest.raises(ValueError, match="unsafe"):
        images.get("msvc-6.0-sp5-pp")


def test_archive_symlink_is_rejected(runtime):
    state, _ = runtime
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        info = tarfile.TarInfo("api.h")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tar.addfile(info)
    state["archive"] = output.getvalue()
    with ImageHeaders() as images, pytest.raises(ValueError, match="unsupported image header"):
        images.get("msvc-6.0-sp5-pp")


def test_project_include_precedes_sdk_and_transitive_bytes_are_observed(tmp_path: Path, runtime):
    src = tmp_path / "src"
    src.mkdir()
    source = src / "unit.c"
    source.write_text("#include <api.h>\n#include <inner.h>\n")
    (src / "api.h").write_text("int project;\n")
    cfg = ProjectConfig(root=tmp_path, reversed_dir=src, module="GAME")
    cfg.base_cflags = f'/I"{src}"'
    with ImageHeaders() as images:
        observed = {}
        lexical = []
        contexts, unknown = contract_contexts(
            cfg, observed_contents=observed, lexical_includes=lexical, image_headers=images
        )
        root = images.get(cfg.compiler_profile)
        assert not unknown
        assert (src / "api.h").resolve() in contexts
        assert (root / "api.h").resolve() not in contexts
        assert observed[(root / "inner.h").resolve()] == b"int sdk;\n"
        assert (root / "inner.h", (root / "inner.h").resolve()) in lexical


def test_msvc_quoted_include_searches_open_parent_before_sdk(tmp_path: Path, runtime):
    state, _ = runtime
    state["archive"] = archive({"mid.h": b'#include "target.h"\n'})
    src = tmp_path / "src"
    sub = src / "sub"
    sub.mkdir(parents=True)
    (src / "unit.c").write_text('#include "sub/top.h"\n')
    (src / "target.h").write_text("int wrong;\n")
    (sub / "top.h").write_text("#include <mid.h>\n")
    (sub / "target.h").write_text("int right;\n")
    cfg = ProjectConfig(root=tmp_path, reversed_dir=src, module="GAME")
    with ImageHeaders() as images:
        contexts, unknown = contract_contexts(cfg, image_headers=images)
        assert not unknown
        assert (sub / "target.h").resolve() in contexts
        assert (src / "target.h").resolve() not in contexts


def test_msvc_quoted_include_prefers_its_own_directory(tmp_path: Path, runtime):
    state, _ = runtime
    state["archive"] = archive({"mid.h": b'#include "target.h"\n', "target.h": b"int sdk;\n"})
    src = tmp_path / "src"
    src.mkdir()
    (src / "unit.c").write_text("#include <mid.h>\n")
    (src / "target.h").write_text("int parent;\n")
    cfg = ProjectConfig(root=tmp_path, reversed_dir=src, module="GAME")
    with ImageHeaders() as images:
        contexts, unknown = contract_contexts(cfg, image_headers=images)
        root = images.get(cfg.compiler_profile)
        assert not unknown
        assert (root / "target.h").resolve() in contexts
        assert (src / "target.h").resolve() not in contexts


@pytest.mark.parametrize("directive", ["#include <missing.h>\n", "#include SDK_HEADER\n"])
def test_unresolved_and_macro_includes_stay_unknown(tmp_path: Path, runtime, directive):
    src = tmp_path / "src"
    src.mkdir()
    (src / "unit.c").write_text(directive)
    cfg = ProjectConfig(root=tmp_path, reversed_dir=src, module="GAME")
    with ImageHeaders() as images:
        _contexts, unknown = contract_contexts(cfg, image_headers=images)
    assert unknown


@pytest.mark.parametrize(
    "flag", ["/FIhidden.h", "-FIhidden.h", "-FI hidden.h", "/X", "-X", "@flags.rsp"]
)
def test_include_affecting_compiler_flags_are_rejected(tmp_path: Path, runtime, flag):
    src = tmp_path / "src"
    src.mkdir()
    (src / "unit.c").write_text("void unit(void) {}\n")
    cfg = ProjectConfig(root=tmp_path, reversed_dir=src, module="GAME")
    cfg.base_cflags = flag
    with ImageHeaders() as images, pytest.raises(ValueError, match="include-affecting"):
        contract_contexts(cfg, image_headers=images)


def test_ordinary_compiler_flags_are_allowed(tmp_path: Path, runtime):
    src = tmp_path / "src"
    src.mkdir()
    (src / "unit.c").write_text("void unit(void) {}\n")
    cfg = ProjectConfig(root=tmp_path, reversed_dir=src, module="GAME")
    cfg.base_cflags = "/O2 /Gd -W3"
    with ImageHeaders() as images:
        _contexts, unknown = contract_contexts(cfg, image_headers=images)
    assert not unknown


def test_planner_pins_image_and_sdk_closure_with_stable_digest(tmp_path: Path, runtime):
    src = tmp_path / "src"
    src.mkdir()
    donor = src / "donor.c"
    donor.write_text("void old(void) {}\n")
    replacement = src / "replacement.c"
    replacement.write_text("void canonical(void) {}\n")
    (src / "caller.c").write_text(
        "#include <api.h>\nvoid old(void);\nvoid caller(void) { old(); }\n"
    )
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
    args = ([cfg], {"TL": 0x1000}, donor, replacement, "old", "canonical")
    first = plan_binding_replacement(*args, use_image_headers=True)
    second = plan_binding_replacement(
        *args, use_image_headers=True, expected_digest=first["input_digest"]
    )
    assert first["input_digest"] == second["input_digest"]
    assert first["compiler_images"][cfg.compiler_profile] == IMAGE
    assert any(
        key.startswith("image://") and key.endswith("/inner.h") for key in first["input_hashes"]
    )
    assert not first["include_unknown"] and not first["safety_review_complete"]
    state, _ = runtime
    state["archive"] = archive({"api.h": b"#include <inner.h>\n", "inner.h": b"int changed;\n"})
    with pytest.raises(ValueError, match="inputs changed"):
        plan_binding_replacement(
            *args, use_image_headers=True, expected_digest=first["input_digest"]
        )


@pytest.mark.parametrize(
    "directive",
    ["#include <missing.h>", "#include SDK_HEADER", "/* comment\n*/ #include <missing.h>"],
)
def test_planner_refuses_unknown_include_in_reference_context(tmp_path: Path, runtime, directive):
    src = tmp_path / "src"
    src.mkdir()
    donor = src / "donor.c"
    donor.write_text("void old(void) {}\n")
    replacement = src / "replacement.c"
    replacement.write_text("void canonical(void) {}\n")
    (src / "caller.c").write_text(f"{directive}\nvoid old(void);\nvoid caller(void) {{ old(); }}\n")
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
    with pytest.raises(ValueError, match="include closure is incomplete"):
        plan_binding_replacement(
            [cfg],
            {"TL": 0x1000},
            donor,
            replacement,
            "old",
            "canonical",
            use_image_headers=True,
        )


def test_multiline_comments_are_preprocessor_whitespace(tmp_path: Path, runtime):
    source = (
        'const char *s = "/* not a comment */";\n'
        "/* #include <ignored.h>\n*/ #include <missing.h>\n"
        "#include /* separator */ <api.h>\n"
        "char c = '/'; // #include <ignored2.h>\n"
        "#inc\\\nlude <inner.h>\n"
        "#include <dir//file.h>\n"
    )
    assert list(include_specs(source)) == [
        ("angle", "missing.h"),
        ("angle", "api.h"),
        ("angle", "inner.h"),
        ("angle", "dir//file.h"),
    ]
    src = tmp_path / "src"
    src.mkdir()
    (src / "unit.c").write_text(source)
    cfg = ProjectConfig(root=tmp_path, reversed_dir=src, module="GAME")
    with ImageHeaders() as images:
        _, unknown = contract_contexts(cfg, image_headers=images)
    assert "missing.h" in unknown[0]["missing"]


def test_symlink_retarget_during_header_read_is_rejected(tmp_path: Path, monkeypatch):
    target = tmp_path / "real.h"
    target.write_text("int value;\n")
    link = tmp_path / "api.h"
    link.symlink_to("real.h")
    identities = {}
    paths, fallback, _, consistent = scan_include_closure(
        '#include "api.h"\n', str(tmp_path), (), identities=identities
    )
    assert paths == (str(target),) and not fallback and consistent
    assert identities[link]["links"][-1][1] == "real.h"

    original = Path.read_bytes

    def racing_read(path):
        data = original(path)
        if path == target:
            link.unlink()
            link.symlink_to("./real.h")
        return data

    monkeypatch.setattr(Path, "read_bytes", racing_read)
    with pytest.raises(ValueError, match="identity changed while reading"):
        scan_include_closure('#include "api.h"\n', str(tmp_path), (), identities={})


def test_generic_closure_tracks_distinct_lexical_parents(tmp_path: Path):
    one = tmp_path / "one"
    two = tmp_path / "two"
    other = tmp_path / "other"
    for directory in (one, two, other):
        directory.mkdir()
    (other / "real.h").write_text('#include "nested.h"\n')
    (other / "nested.h").write_text("/* resolved parent */\n")
    (one / "nested.h").write_text("/* first lexical parent */\n")
    (two / "nested.h").write_text("/* second lexical parent */\n")
    (one / "api.h").symlink_to("../other/real.h")
    (two / "api.h").symlink_to("../other/real.h")
    paths, _, _, consistent = scan_include_closure(
        '#include "one/api.h"\n#include "two/api.h"\n', str(tmp_path), ()
    )
    assert consistent
    assert {str(other / "nested.h"), str(one / "nested.h"), str(two / "nested.h")} <= set(paths)
    with pytest.raises(ValueError, match="ambiguous symlinked include parent"):
        scan_include_closure('#include "one/api.h"\n', str(tmp_path), (), identities={})
