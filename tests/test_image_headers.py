"""Compiler image header extraction and target include review."""

import base64
import io
import subprocess
import sys
import tarfile
from typing import Any
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


class TestContractImageHeaders:
    def project(self, tmp_path):
        from test_source_contracts import _project

        cfg = _project(tmp_path)
        owner = cfg.reversed_dir / "owner.c"
        owner.write_text("#include <sdk.h>\n" + owner.read_text())
        return cfg

    def test_audit_opt_in_resolves_sdk_and_normalizes_report(self, tmp_path, runtime):
        from rebrew.source_contracts import audit_contracts

        state, _ = runtime
        state["archive"] = archive({"sdk.h": b"int sdk_value;\n"})
        cfg = self.project(tmp_path)
        assert audit_contracts(cfg, name="queue")["unknown"]
        first = audit_contracts(cfg, name="queue", use_image_headers=True)
        second = audit_contracts(cfg, name="queue", use_image_headers=True)
        assert not first["unknown"]
        assert first == second
        assert any(p.startswith("image://") for p in first["input_hashes"])
        assert "rebrew-image-headers-" not in str(first)

    def test_reconcile_stable_digest_and_changed_header_refusal(self, tmp_path, runtime):
        from rebrew.source_contracts import reconcile_contract

        state, _ = runtime
        state["archive"] = archive({"sdk.h": b"int sdk_value;\n"})
        cfg = self.project(tmp_path)
        args = ([cfg], "queue", Path("src/api.h"), "int queue(int value)")
        preview = reconcile_contract(*args, dry_run=True, use_image_headers=True)
        again = reconcile_contract(
            *args, dry_run=True, use_image_headers=True, expected_digest=preview["input_digest"]
        )
        assert preview == again
        assert any(p.startswith("image://") for p in preview["input_hashes"])
        state["archive"] = archive({"sdk.h": b"int changed;\n"})
        with pytest.raises(ValueError, match="inputs changed"):
            reconcile_contract(
                *args, use_image_headers=True, expected_digest=preview["input_digest"]
            )
        assert "extern void queue" in (cfg.reversed_dir / "user.c").read_text()

    def test_image_is_rechecked_under_publication_lock(self, tmp_path, runtime, monkeypatch):
        from contextlib import contextmanager

        import rebrew.source_contracts as contracts

        state, _ = runtime
        state["archive"] = archive({"sdk.h": b"int sdk_value;\n"})
        cfg = self.project(tmp_path)
        real = contracts.metadata_write_lock

        @contextmanager
        def changed(*args, **kwargs):
            with real(*args, **kwargs):
                state["id"] = "sha256:" + "b" * 64
                yield

        monkeypatch.setattr(contracts, "metadata_write_lock", changed)
        before = (cfg.reversed_dir / "owner.c").read_bytes()
        with pytest.raises(ValueError, match="image changed"):
            contracts.reconcile_contract(
                [cfg], "queue", Path("src/api.h"), "int queue(int value)", use_image_headers=True
            )
        assert (cfg.reversed_dir / "owner.c").read_bytes() == before

    @pytest.mark.parametrize("command", ["contracts", "reconcile"])
    def test_cli_flag_is_forwarded(self, tmp_path, runtime, command):
        from unittest.mock import patch

        from typer.testing import CliRunner

        from rebrew.types_cli import app

        state, _ = runtime
        state["archive"] = archive({"sdk.h": b"int sdk_value;\n"})
        cfg = self.project(tmp_path)
        args = (
            ["contracts", "--name", "queue"]
            if command == "contracts"
            else [
                "reconcile",
                "queue",
                "src/api.h",
                "--prototype",
                "int queue(int value)",
                "--dry-run",
            ]
        )
        with (
            patch("rebrew.types_cli.require_config", return_value=cfg),
            patch("rebrew.workspace.config.read_config", return_value={}),
        ):
            result = CliRunner().invoke(app, [*args, "--image-headers", "--json"])
        # contracts still reports the deliberately incompatible old return type.
        assert result.exit_code == (1 if command == "contracts" else 0), result.output
        assert "image://" in result.output

    def test_preview_and_apply_in_separate_processes(self, tmp_path):
        import json
        import sys

        cfg = self.project(tmp_path)
        script = """
import json, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, "tests")
from test_image_headers import archive, IMAGE
from rebrew.config import ProjectConfig
from rebrew.source_contracts import reconcile_contract
import subprocess
root = Path(sys.argv[1])
def run(args, **kwargs):
    data = IMAGE.encode() if args[1:3] == ["image", "inspect"] else archive({"sdk.h": b"int sdk_value;\\n"})
    return subprocess.CompletedProcess(args, 0, stdout=data, stderr=b"")
cfg = ProjectConfig(root=root, reversed_dir=root / "src", module="GAME")
with patch("rebrew.compiler.image_headers.run_process_group", run):
    report = reconcile_contract([cfg], "queue", Path("src/api.h"), "int queue(int value)",
                               dry_run=len(sys.argv) == 2, use_image_headers=True,
                               expected_digest=sys.argv[2] if len(sys.argv) > 2 else None)
print(json.dumps(report))
"""
        command = [sys.executable, "-c", script, str(cfg.root)]
        first = subprocess.run(command, capture_output=True, text=True, check=True)
        preview = json.loads(first.stdout)
        second = subprocess.run(
            [*command, preview["input_digest"]], capture_output=True, text=True, check=True
        )
        assert json.loads(second.stdout)["input_digest"] == preview["input_digest"]
        assert "extern void queue" not in (cfg.reversed_dir / "user.c").read_text()


def test_image_headers_use_the_real_process_helper(tmp_path, monkeypatch):
    import sys

    from rebrew.compiler import image_headers
    from rebrew.utils import run_process_group

    runtime = tmp_path / "runtime"
    runtime.write_text(
        f"#!{sys.executable}\nimport sys\n"
        f"sys.stdout.buffer.write({IMAGE.encode()!r} if sys.argv[1:3] == ['image', 'inspect'] "
        f"else {archive({'sdk.h': b'int sdk;\n'})!r})\n"
    )
    runtime.chmod(0o755)
    monkeypatch.setattr(image_headers, "run_process_group", run_process_group)
    with ImageHeaders(runtime=str(runtime)) as images:
        assert (images.get("msvc-6.0-sp5-pp") / "sdk.h").read_bytes() == b"int sdk;\n"


@pytest.mark.parametrize("failed", ["inspect", "extract"])
def test_image_runtime_failures_are_rejected(monkeypatch, failed):
    def run(args, **kwargs):
        inspect = args[1:3] == ["image", "inspect"]
        return subprocess.CompletedProcess(
            args,
            1 if inspect == (failed == "inspect") else 0,
            stdout=IMAGE.encode() if inspect else b"",
            stderr=b"failed",
        )

    monkeypatch.setattr("rebrew.compiler.image_headers.run_process_group", run)
    with ImageHeaders() as images, pytest.raises(ValueError, match="cannot inspect|cannot extract"):
        images.get("msvc-6.0-sp5-pp")


@pytest.mark.parametrize("failure", [None, "inspect", "extract"])
def test_image_headers_use_real_process_runner(
    monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    from rebrew.utils import run_process_group

    header_archive = archive({"api.h": b"int sdk;\n"})

    def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        stage = "inspect" if args[1:3] == ["image", "inspect"] else "extract"
        data = IMAGE.encode() if stage == "inspect" else header_archive
        return run_process_group(
            [
                sys.executable,
                "-c",
                "import base64, sys; sys.stdout.buffer.write(base64.b64decode(sys.argv[1])); "
                "sys.exit(int(sys.argv[2]))",
                base64.b64encode(data).decode("ascii"),
                "1" if stage == failure else "0",
            ],
            **kwargs,
        )

    monkeypatch.setattr("rebrew.compiler.image_headers.run_process_group", run)
    with ImageHeaders() as images:
        if failure is None:
            root = images.get("msvc-6.0-sp5-pp")
            assert (root / "api.h").read_bytes() == b"int sdk;\n"
        else:
            message = "cannot inspect" if failure == "inspect" else "cannot extract"
            with pytest.raises(ValueError, match=message):
                images.get("msvc-6.0-sp5-pp")
