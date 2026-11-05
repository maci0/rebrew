"""Pinned compiler preprocessing captures actual target output, without publishing state."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.compiler import preprocessed_context as capture


def _fixture(root: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, list]:
    root.chmod(0o755)
    src = root / "src"
    src.mkdir()
    (src / "common.h").write_text("#define VALUE 1\n")
    sdk = root / ".sdk"
    sdk.mkdir()
    (sdk / "windows.h").write_text("typedef int HWND;\n")
    source = src / "unit.c"
    source.write_text('#include "common.h"\nint f(void) { return VALUE; }\n')
    build = root / "build"
    build.mkdir()
    database = build / "compile_commands.json"
    entries = []
    for target in ("TL", "GOLD"):
        entries.append(
            {
                "directory": str(build),
                "file": str(source),
                "output": f"{target}.obj",
                "arguments": [
                    "rebrew",
                    "build",
                    "driver",
                    "cl",
                    "--",
                    "/REBREW_TOOLCHAIN:msvc-6.0-sp5-pp",
                    "/nologo",
                    "/D",
                    target,
                    f"/I{src}",
                    "/DVALUE=1",
                    "/UVALUE",
                    "/DVALUE=2",
                    "/MT",
                    "/Gd",
                    f"/Fo{target}.obj",
                    "-c",
                    str(source),
                ],
            }
        )
    database.write_text(json.dumps(entries))
    calls = []

    class Images:
        def __init__(self, runtime: str | None = None) -> None:
            self.trees = {}

        def __enter__(self) -> Images:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def get(self, profile: str) -> Path:
            self.trees[profile] = {
                "id": "sha256:" + "a" * 64,
                "manifest": {"windows.h": "123"},
                "include": "/opt/msvc6.0-sp5-pp/VC98/Include",
            }
            return sdk

        def verify(self) -> None:
            pass

        def normalize(self, value: object) -> object:
            return value

    def run(spec: object, flags: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append((flags, kwargs))
        marker = str(source).replace("/", "\\").replace("\\", "\\\\")
        target = "GOLD" if "GOLD" in flags else "TL"
        (Path(kwargs["workdir"]) / "unit.i").write_bytes(
            f'#line 1 "Z:{marker}"\nint {target}(void) {{return 2;}}\n'.encode()
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(capture, "ImageHeaders", Images)
    monkeypatch.setattr(capture, "run_toolchain", run)
    return source, database, calls


def test_capture_preserves_target_flag_order_and_expansion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, calls = _fixture(tmp_path, monkeypatch)
    a = capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
    b = capture.capture_msvc_context(tmp_path, db, source, output="GOLD.obj")
    assert b"int TL(" in a["expanded"] and b"int GOLD(" in b["expanded"]
    assert a["input_digest"] != b["input_digest"]
    flags, options = calls[0]
    assert flags.index("/DVALUE=1") < flags.index("/UVALUE") < flags.index("/DVALUE=2")
    assert flags[-2:] == ["/P", "Z:" + str(source).replace("/", "\\")]
    assert options["image_id"] == "sha256:" + "a" * 64
    assert not a["macro_table_complete"] and not a["provider_evidence"]
    assert not a["line_markers_authenticate_origin"]


def test_capture_expected_digest_detects_stale_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    previous = capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
    (source.parent / "common.h").write_text("#define VALUE 99\n")
    with pytest.raises(ValueError, match="preprocessed context changed"):
        capture.capture_msvc_context(
            tmp_path, db, source, output="TL.obj", expected_digest=previous["input_digest"]
        )


def test_unrelated_credentials_are_never_staged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("private\n")
    (tmp_path / ".env").write_text("private\n")
    original = capture.run_toolchain

    def inspect_staged(*args: object, **kwargs: object) -> object:
        staged = Path(kwargs["mounts"][0][0])
        assert not (staged / ".git").exists()
        assert not (staged / ".env").exists()
        assert (staged / "src" / "common.h").is_file()
        return original(*args, **kwargs)

    monkeypatch.setattr(capture, "run_toolchain", inspect_staged)
    report = capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
    assert not any(".env" in name or ".git" in name for name in report["files"])


def test_protected_include_refused_before_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, calls = _fixture(tmp_path, monkeypatch)
    (tmp_path / ".env").write_text("private\n")
    source.write_text('#include "../.env"\nint f(void) { return 1; }\n')
    with pytest.raises(ValueError, match="protected"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
    assert not calls


def test_restrictive_header_mode_refused_before_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, calls = _fixture(tmp_path, monkeypatch)
    (source.parent / "common.h").chmod(0o600)
    with pytest.raises(ValueError, match="permissions require review"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
    assert not calls


def test_new_earlier_header_invalidates_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    early, late = tmp_path / "early", tmp_path / "late"
    early.mkdir()
    late.mkdir()
    (late / "api.h").write_text("#define VALUE 2\n")
    source.write_text("#include <api.h>\nint f(void) { return VALUE; }\n")
    entries = json.loads(db.read_text())
    entries[0]["arguments"][7:7] = ["/I" + str(early), "/I" + str(late)]
    db.write_text(json.dumps(entries))
    original = capture.run_toolchain

    def add_shadow(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        (early / "api.h").write_text("#define VALUE 2\n")
        return result

    monkeypatch.setattr(capture, "run_toolchain", add_shadow)
    with pytest.raises(ValueError, match="inputs changed"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


def test_unreadable_earlier_include_directory_is_not_a_miss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    source, db, calls = _fixture(tmp_path, monkeypatch)
    early, late = tmp_path / "early", tmp_path / "late"
    early.mkdir()
    late.mkdir()
    (early / "api.h").write_text("#define VALUE 1\n")
    (late / "api.h").write_text("#define VALUE 2\n")
    source.write_text("#include <api.h>\nint f(void) { return VALUE; }\n")
    entries = json.loads(db.read_text())
    entries[0]["arguments"][7:7] = ["/I" + str(early), "/I" + str(late)]
    db.write_text(json.dumps(entries))
    scandir, is_file = os.scandir, Path.is_file

    def inaccessible(path: object) -> object:
        if not isinstance(path, int) and Path(path) == early:
            raise PermissionError("injected")
        return scandir(path)

    def inaccessible_file(path: Path) -> bool:
        return False if path == early / "api.h" else is_file(path)

    monkeypatch.setattr(os, "scandir", inaccessible)
    monkeypatch.setattr(Path, "is_file", inaccessible_file)
    with pytest.raises(ValueError, match="include search path|include closure"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
    assert not calls


@pytest.mark.parametrize("same_bytes", [True, False])
def test_winning_include_case_collision_refused_during_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, same_bytes: bool
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    header = source.parent / "Api.h"
    header.write_text("#define VALUE 1\n")
    source.write_text("#include <api.h>\nint f(void) { return VALUE; }\n")
    original = capture.run_toolchain

    def add_collision(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        (source.parent / "API.h").write_text(
            "#define VALUE 1\n" if same_bytes else "#define VALUE 2\n"
        )
        return result

    monkeypatch.setattr(capture, "run_toolchain", add_collision)
    with pytest.raises(ValueError, match="ambiguous"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


@pytest.mark.parametrize("mutation", ["source", "header", "database"])
def test_capture_refuses_changed_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    original = capture.run_toolchain

    def changed(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        target = {
            "source": source,
            "header": source.parent / "common.h",
            "database": db,
        }[mutation]
        target.write_text("changed\n")
        return result

    monkeypatch.setattr(capture, "run_toolchain", changed)
    with pytest.raises(ValueError, match="inputs changed"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


def test_capture_refuses_compiler_failure_and_ambiguous_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="select exactly one"):
        capture.capture_msvc_context(tmp_path, db, source, output="missing.obj")
    monkeypatch.setattr(
        capture,
        "run_toolchain",
        lambda *a, **kw: SimpleNamespace(returncode=1, stdout="", stderr="fatal error"),
    )
    with pytest.raises(ValueError, match="fatal error"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


def test_capture_rejects_image_change_after_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    original = capture.ImageHeaders

    class ChangedImages(original):
        def verify(self) -> None:
            raise ValueError("compiler image changed during review")

    monkeypatch.setattr(capture, "ImageHeaders", ChangedImages)
    with pytest.raises(ValueError, match="compiler image changed"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


def test_capture_stages_immutable_compiler_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    original = capture.run_toolchain
    expected = source.read_bytes()

    def edit_during_run(*args: object, **kwargs: object) -> object:
        staged = Path(kwargs["mounts"][0][0]) / source.relative_to(tmp_path)
        source.write_text("int changed;\n")
        assert staged.read_bytes() == expected
        return original(*args, **kwargs)

    monkeypatch.setattr(capture, "run_toolchain", edit_during_run)
    with pytest.raises(ValueError, match="inputs changed"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


def test_capture_stages_and_hashes_build_include_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    header = db.parent / "api.h"
    header.write_text("#define VALUE 9\n")
    source.write_text("#include <api.h>\nint f(void) { return VALUE; }\n")
    entries = json.loads(db.read_text())
    entries[0]["arguments"].insert(-1, "/I" + str(db.parent))
    db.write_text(json.dumps(entries))
    original = capture.run_toolchain

    def inspect_staged(*args: object, **kwargs: object) -> object:
        staged = Path(kwargs["mounts"][0][0]) / "build" / "api.h"
        assert staged.read_bytes() == header.read_bytes()
        return original(*args, **kwargs)

    monkeypatch.setattr(capture, "run_toolchain", inspect_staged)
    report = capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
    assert str(header) in report["files"]
    assert not report["complete_project_tree_snapshotted"]
    assert report["conservative_include_closure_complete"]


def test_capture_stages_hidden_relative_include_before_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    hidden = tmp_path / ".secret"
    hidden.mkdir()
    (hidden / "api.h").write_text("#define VALUE 11\n")
    fallback = tmp_path / "inc" / ".secret"
    fallback.mkdir(parents=True)
    (fallback / "api.h").write_text("#define VALUE 22\n")
    source.write_text('#include "../.secret/api.h"\nint f(void) { return VALUE; }\n')
    original = capture.run_toolchain

    def inspect_staged(*args: object, **kwargs: object) -> object:
        staged = Path(kwargs["mounts"][0][0])
        assert (staged / ".secret" / "api.h").read_text() == "#define VALUE 11\n"
        assert not (staged / "inc" / ".secret" / "api.h").exists()
        return original(*args, **kwargs)

    monkeypatch.setattr(capture, "run_toolchain", inspect_staged)
    report = capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
    assert str(hidden / "api.h") in report["files"]


@pytest.mark.parametrize(
    "directive", ['#line 1 "fake.h"', '%:line 1 "fake.h"', '??=line 1 "fake.h"', "__TIME__"]
)
def test_capture_refuses_spoofable_or_volatile_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, directive: str
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    source.write_text(directive + "\nint f(void) { return 1; }\n")
    with pytest.raises(ValueError, match="line directives.*volatile"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


def test_capture_ignores_line_directive_text_in_comments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    source.write_text('/* #line 1 "fake.h" */\n// #999\nint f(void) { return 1; }\n')
    assert capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")["expanded"]


def test_capture_refuses_symlinked_selected_include(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    alias = tmp_path / ".alias"
    alias.symlink_to("src", target_is_directory=True)
    source.write_text('#include "../.alias/common.h"\nint f(void) { return VALUE; }\n')
    with pytest.raises(ValueError, match="symlink"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


def test_capture_refuses_volatile_compiler_macro(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    entries = json.loads(db.read_text())
    entries[0]["arguments"].insert(-1, "/DVALUE=__TIME__")
    db.write_text(json.dumps(entries))
    with pytest.raises(ValueError, match="volatile.*compiler macro"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


def test_capture_refuses_pasted_volatile_macro(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, calls = _fixture(tmp_path, monkeypatch)
    source.write_text("#define CAT(a,b) a##b\nconst char *p = CAT(__TI,ME__);\n")
    with pytest.raises(ValueError, match="token pasting"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
    assert not calls


def test_token_paste_requires_epoch_and_preserves_source_timestamp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    source, db, _ = _fixture(tmp_path, monkeypatch)
    source.write_text("#define CAT(a,b) a##b\nconst char *p = CAT(__TI,ME__);\n")
    os.utime(source, ns=(978322000000000000, 978322000000000000))
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    with pytest.raises(ValueError, match="requires an explicit SOURCE_DATE_EPOCH"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj", allow_token_paste=True)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1073664562")
    original = capture.run_toolchain

    def inspect_timestamp(*args: object, **kwargs: object) -> object:
        staged = Path(kwargs["mounts"][0][0]) / source.relative_to(tmp_path)
        assert staged.stat().st_mtime_ns == source.stat().st_mtime_ns
        return original(*args, **kwargs)

    monkeypatch.setattr(capture, "run_toolchain", inspect_timestamp)
    result = capture.capture_msvc_context(
        tmp_path, db, source, output="TL.obj", allow_token_paste=True
    )
    assert result["environment"]["SOURCE_DATE_EPOCH"] == "1073664562"
    assert result["files"]["mtime:" + str(source)] == str(source.stat().st_mtime_ns)
    assert not result["macro_table_complete"] and not result["original_tu_equivalence_proven"]


def test_absent_conditional_include_is_pinned_and_rechecked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    source.write_text('#if 0\n#include "not_present.h"\n#endif\nint f(void) { return 1; }\n')
    original = capture.run_toolchain

    def create_missing(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        (source.parent / "not_present.h").write_text("int added;\n")
        return result

    monkeypatch.setattr(capture, "run_toolchain", create_missing)
    with pytest.raises(ValueError, match="inputs changed"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


def test_active_missing_include_remains_a_compiler_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    source.write_text('#include "not_present.h"\nint f(void) { return 1; }\n')
    monkeypatch.setattr(
        capture,
        "run_toolchain",
        lambda *a, **kw: SimpleNamespace(
            returncode=2, stdout="", stderr="fatal error C1083: cannot open include file"
        ),
    )
    with pytest.raises(ValueError, match="fatal error C1083"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


def test_backslash_include_is_refused_before_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, calls = _fixture(tmp_path, monkeypatch)
    sub = source.parent / "sub"
    sub.mkdir()
    (sub / "header.h").write_text("#define VALUE 11\n")
    source.write_text("#include <sub\\header.h>\nint f(void) { return VALUE; }\n")
    with pytest.raises(ValueError, match="backslash include"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
    assert not calls


@pytest.mark.parametrize("name", ["C:/secret.h", "/absolute/secret.h"])
def test_rooted_include_is_refused_before_compiler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    source, db, calls = _fixture(tmp_path, monkeypatch)
    source.write_text(f"#include <{name}>\nint f(void) {{ return 1; }}\n")
    with pytest.raises(ValueError, match="rooted include"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
    assert not calls


def test_capture_refuses_pasted_volatile_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, calls = _fixture(tmp_path, monkeypatch)
    entries = json.loads(db.read_text())
    entries[0]["arguments"].insert(-1, "/DA=__TI##ME__")
    db.write_text(json.dumps(entries))
    with pytest.raises(ValueError, match="token-pasting"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
    assert not calls


def test_dash_include_preserves_posix_line_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    entries = json.loads(db.read_text())
    entries[0]["arguments"].insert(-1, "-I" + str(source.parent))
    db.write_text(json.dumps(entries))
    original = capture.run_toolchain

    def with_marker(*args: object, **kwargs: object) -> object:
        flags = args[1]
        assert "-I" + str(source.parent) in flags
        result = original(*args, **kwargs)
        artifact = Path(kwargs["workdir"]) / "unit.i"
        marker = (str(source.parent) + r"\\common.h").encode()
        artifact.write_bytes(artifact.read_bytes() + b'#line 1 "' + marker + b'"\n')
        return result

    monkeypatch.setattr(capture, "run_toolchain", with_marker)
    assert capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")["line_markers"]


def test_capture_refuses_unknown_line_marker_and_option_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    original = capture.run_toolchain

    def marker(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        artifact = Path(kwargs["workdir"]) / "unit.i"
        artifact.write_bytes(artifact.read_bytes() + b'#line 1 "Z:\\\\outside\\\\secret.h"\n')
        return result

    monkeypatch.setattr(capture, "run_toolchain", marker)
    with pytest.raises(ValueError, match="unpinned file"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")

    def warning(*args: object, **kwargs: object) -> object:
        original(*args, **kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="warning D4002: ignored option")

    monkeypatch.setattr(capture, "run_toolchain", warning)
    with pytest.raises(ValueError, match="ignored or rejected"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


@pytest.mark.parametrize(
    "path,allowed",
    [
        (r"Z:\opt\msvc6.0-sp5-pp\VC98\InClUdE\WINDOWS.H", True),
        (r"Z:\opt\msvc6.0-sp5-pp\VC98\NOT_INCLUDE\untracked.h", False),
        (r"Z:\opt\msvc6.0-sp5-pp\VC98\Include\missing.h", False),
        (r"Z:\opt\msvc6.0-sp5-pp\VC98\Include\..\windows.h", False),
    ],
)
def test_sdk_markers_require_manifest_membership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str, allowed: bool
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    source.write_text("#include <windows.h>\nint f(void) { return 1; }\n")
    original = capture.run_toolchain

    def with_marker(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        artifact = Path(kwargs["workdir"]) / "unit.i"
        encoded = path.replace("\\", "\\\\").encode()
        artifact.write_bytes(artifact.read_bytes() + b'#line 1 "' + encoded + b'"\n')
        return result

    monkeypatch.setattr(capture, "run_toolchain", with_marker)
    if allowed:
        report = capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
        assert not report["line_markers_authenticate_origin"]
    else:
        with pytest.raises(ValueError):
            capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


@pytest.mark.parametrize("bad", ["@flags.rsp", "/FIhidden.h", "/I/outside"])
def test_capture_refuses_unpinned_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    entries = json.loads(db.read_text())
    entries[0]["arguments"].insert(-1, bad)
    db.write_text(json.dumps(entries))
    with pytest.raises(ValueError):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
