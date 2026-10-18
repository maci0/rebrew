"""Driver-cache regression controls without a compiler, image or runner setup."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew import cmake_cache
from rebrew.compiler.cache import get_project_cache
from rebrew.compiler.toolchain import TOOLCHAINS
from rebrew.config import load_compile_cache_config


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    (tmp_path / "rebrew-project.toml").write_text(
        '[project]\ndefault_target="game"\n'
        '[targets.game]\nbinary="original.exe"\nreversed_dir="src"\nmodule="GAME"\n'
        '[compiler]\nprofile="msvc-6.0-sp5-pp"\nexecution_backend="unshare"\n'
    )
    source = tmp_path / "source.c"
    header = tmp_path / "api.h"
    source.write_text('#include "api.h"\nint f(void) { return VALUE; }\n')
    header.write_text("#define VALUE 1\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "original.exe").write_bytes(b"fixture")
    output = tmp_path / "output.obj"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1071482016")
    state = SimpleNamespace(image="sha256:" + "a" * 64, environment={}, calls=[], rc=0, write=True)
    monkeypatch.setattr(cmake_cache.toolchain, "cached_image_digest", lambda *_: state.image)
    monkeypatch.setattr(cmake_cache.toolchain, "image_environment", lambda *_: state.environment)
    spec = TOOLCHAINS["msvc-6.0-sp5-pp"]
    args = ["/c", "/O2", "/ML", "/Fdunused/", "/Fo" + str(output), str(source)]
    cache = get_project_cache(load_compile_cache_config(tmp_path))

    def run(image):
        state.calls.append(image)
        if state.write:
            output.write_bytes(
                b"obj:" + hashlib.sha256(source.read_bytes() + header.read_bytes()).digest()
            )
        print("compiler output\r\nwarning fixture")
        print("compiler stderr\r\n", file=sys.stderr, end="")
        return state.rc

    def invoke(argv=None, runner=None):
        return cmake_cache.run_cached_cl(
            tmp_path, spec, args if argv is None else argv, run if runner is None else runner
        )

    return SimpleNamespace(
        root=tmp_path,
        source=source,
        header=header,
        output=output,
        args=args,
        state=state,
        cache=cache,
        invoke=invoke,
        run=run,
    )


def _replace_same_stat(path: Path, old: bytes, new: bytes) -> None:
    before = path.stat()
    content = path.read_bytes().replace(old, new)
    assert len(content) == before.st_size
    path.write_bytes(content)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert path.stat().st_ino == before.st_ino
    assert path.stat().st_mtime_ns == before.st_mtime_ns


@pytest.mark.parametrize("changed", ["source", "header"])
def test_preserved_mtime_content_change_misses(project: Any, changed: str) -> None:
    assert project.invoke() == 0
    original = project.output.read_bytes()
    if changed == "source":
        _replace_same_stat(project.source, b"int f", b"int g")
    else:
        _replace_same_stat(project.header, b"VALUE 1", b"VALUE 2")
    assert project.invoke() == 0
    assert len(project.state.calls) == 2
    assert project.output.read_bytes() != original
    assert project.invoke() == 0
    assert len(project.state.calls) == 2


def test_nested_dependencies_bypass_instead_of_guessing_msvc_search(project: Any) -> None:
    nested = project.root / "nested.h"
    nested.write_text("#define VALUE 1\n")
    project.header.write_text('#include "nested.h"\n')
    project.invoke()
    project.invoke()
    assert project.state.calls == [None, None]
    assert project.cache.count == 0


@pytest.mark.parametrize(
    "flag",
    [
        "/Zi",
        "/Z7",
        "/Gm",
        "/Ycapi.h",
        "/Yuapi.h",
        "/Fpfoo.pch",
        "/FAs",
        "/Fifoo.i",
        "/E",
        "/P",
        "/showIncludes",
        "/sourceDependencies:deps.json",
        "@args.rsp",
        "/FIapi.h",
        "/unknown",
    ],
)
def test_unsupported_side_effects_bypass(project: Any, flag: str) -> None:
    project.invoke([*project.args, flag])
    project.invoke([*project.args, flag])
    assert project.state.calls == [None, None]
    assert project.cache.count == 0


@pytest.mark.parametrize(
    "text",
    [
        '#include "missing.h"\n',
        '#define HEADER "api.h"\n#include HEADER\n',
        '#include_next "api.h"\n',
        '#import "types.dll"\n',
        '#pragma include_alias("a.h", "b.h")\n',
        '#/**/include "api.h"\n',
        '??=include "api.h"\n',
        '#inc\\\nlude "api.h"\n',
        "#define JOIN(a,b) a ## b\n",
        "#pragma pack(1)\n",
    ],
)
def test_unresolved_or_unsupported_preprocessing_bypasses(project: Any, text: str) -> None:
    project.source.write_text(text + "int f(void) { return 1; }\n")
    project.invoke()
    project.invoke()
    assert project.state.calls == [None, None]
    assert project.cache.count == 0


@pytest.mark.parametrize("token", ["__DATE__", "__TIME__", "__TIMESTAMP__"])
@pytest.mark.parametrize("where", ["source", "header"])
def test_time_builtins_bypass_even_frozen_clock(project: Any, where: str, token: str) -> None:
    path = getattr(project, where)
    path.write_text(path.read_text() + f"char *clock = {token};\n")
    project.invoke()
    project.invoke()
    assert project.state.calls == [None, None]


@pytest.mark.parametrize(
    "setting",
    ["CL", "_CL_", "cl", "missing-image", "invalid-image", "unknown-environment", "real-clock"],
)
def test_unadmitted_environment_bypasses(
    project: Any, monkeypatch: pytest.MonkeyPatch, setting: str
) -> None:
    if setting == "real-clock":
        monkeypatch.delenv("SOURCE_DATE_EPOCH")
    elif setting == "missing-image":
        project.state.image = ""
    elif setting == "invalid-image":
        project.state.image = "sha256:short"
    elif setting == "unknown-environment":
        project.state.environment = None
    else:
        project.state.environment = {setting: "/FIimplicit.h"}
    project.invoke()
    project.invoke()
    assert project.state.calls == [None, None]


@pytest.mark.parametrize(
    "change",
    [
        "flags",
        "image",
        "backend",
        "cwd",
        "clock",
        "source-spelling",
        "include-order",
        "output-path",
    ],
)
def test_invocation_identity_changes_miss(
    project: Any, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    argv = list(project.args)
    if change == "include-order":
        first, second = project.root / "one", project.root / "two"
        first.mkdir()
        second.mkdir()
        argv.extend(["/I" + str(first), "/I" + str(second)])
    project.invoke(argv)
    if change == "flags":
        argv.append("/DVALUE=2")
    elif change == "image":
        project.state.image = "sha256:" + "b" * 64
    elif change == "backend":
        monkeypatch.setattr(cmake_cache, "backend_identity", lambda: "different-helper")
    elif change == "cwd":
        other = project.root / "build"
        other.mkdir()
        monkeypatch.chdir(other)
    elif change == "clock":
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1071482017")
    elif change == "source-spelling":
        argv[-1] = "./source.c"
    elif change == "include-order":
        argv[-2:] = list(reversed(argv[-2:]))
    else:
        argv = [
            arg if not arg.startswith("/Fo") else "/Fo" + str(project.root / "other.obj")
            for arg in argv
        ]
    project.invoke(argv)
    assert len(project.state.calls) == 2
    assert project.state.calls[0] == "sha256:" + "a" * 64
    assert all(image is not None for image in project.state.calls)


@pytest.mark.parametrize("changed", ["source", "header"])
def test_inputs_changed_during_compile_are_not_published(project: Any, changed: str) -> None:
    def run(image):
        result = project.run(image)
        path = getattr(project, changed)
        _replace_same_stat(
            path,
            b"1" if changed == "header" else b"VALUE",
            b"2" if changed == "header" else b"OTHER",
        )
        return result

    project.invoke(runner=run)
    assert project.cache.count == 0
    project.invoke()
    assert len(project.state.calls) == 2


def test_replay_rechecks_inputs_after_restore(
    project: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    project.invoke()
    restore = cmake_cache._restore

    def changed(output, data):
        restore(output, data)
        _replace_same_stat(project.header, b"VALUE 1", b"VALUE 2")

    monkeypatch.setattr(cmake_cache, "_restore", changed)
    project.invoke()
    assert len(project.state.calls) == 2


@pytest.mark.parametrize(
    "failure", ["returncode", "missing-output", "unchanged-output", "exception"]
)
def test_failed_or_unproduced_objects_are_not_published(project: Any, failure: str) -> None:
    if failure == "returncode":
        project.state.rc = 2
    elif failure in {"missing-output", "unchanged-output"}:
        project.state.write = False
        if failure == "unchanged-output":
            project.output.write_bytes(b"old unrelated object")

    def run(image):
        result = project.run(image)
        if failure == "exception":
            raise ValueError("runner failed")
        return result

    for _ in range(2):
        if failure == "exception":
            with pytest.raises(ValueError, match="runner failed"):
                project.invoke(runner=run)
        else:
            assert project.invoke(runner=run) == project.state.rc
    assert len(project.state.calls) == 2
    assert project.cache.count == 0


def test_corrupted_record_degrades_to_compile(
    project: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    project.invoke()
    monkeypatch.setattr(project.cache, "get", lambda _: b'{"object":"bad"}')
    project.invoke()
    assert len(project.state.calls) == 2


def test_same_object_bytes_receive_fresh_mtime(project: Any) -> None:
    project.invoke()
    content = project.output.read_bytes()
    os.utime(project.output, ns=(100, 100))
    project.invoke()
    assert project.output.read_bytes() == content
    assert project.output.stat().st_mtime_ns > 100
    assert len(project.state.calls) == 1


@pytest.mark.parametrize(
    "payload,expected",
    [
        ('["PATH=/bin", "CL="]', {"PATH": "/bin", "CL": ""}),
        ("null", None),
        ("[5]", None),
        ('["missing-equals"]', None),
        ("invalid", None),
    ],
)
def test_image_environment_requires_inspectable_admitted_id(
    monkeypatch: pytest.MonkeyPatch, payload: str, expected: Any
) -> None:
    calls = []

    def inspect(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout=payload)

    monkeypatch.setattr(cmake_cache.toolchain.subprocess, "run", inspect)
    image = "sha256:" + "a" * 64
    assert cmake_cache.toolchain.image_environment(image) == expected
    assert calls[0][-1] == image
    calls.clear()
    assert cmake_cache.toolchain.image_environment("mutable:tag") is None
    assert calls == []


def test_cache_configuration_does_not_analyze_target_binary(project: Any) -> None:
    (project.root / "original.exe").unlink()
    config = project.root / "rebrew-project.toml"
    config.write_text(config.read_text() + "\n[cache]\nsize_limit_mib=2\n")
    cfg = load_compile_cache_config(project.root)
    assert cfg.cache_size_limit == 2 * 1024 * 1024
    assert cfg.cache_backend == "diskcache"
    project.invoke()
    project.invoke()
    assert len(project.state.calls) == 1


@pytest.mark.parametrize("split", [False, True])
def test_define_payload_cannot_inject_untracked_include_alias(project: Any, split: bool) -> None:
    project.source.write_text("int REDIRECT;\n" + project.source.read_text())
    (project.root / "other.h").write_text("#define VALUE 9\n")
    value = 'REDIRECT=__pragma(include_alias("api.h","other.h"))'
    argv = project.args + (["/D", value] if split else ["/D" + value])
    project.invoke(argv)
    project.invoke(argv)
    assert project.state.calls == [None, None]
    assert project.cache.count == 0


@pytest.mark.parametrize("split", [False, True])
@pytest.mark.parametrize("value", ["WIN32", "_WIN32_WINNT=0x0400", "NDEBUG", "VALUE=2"])
def test_simple_defines_still_reuse_objects(project: Any, split: bool, value: str) -> None:
    argv = project.args + (["/D", value] if split else ["/D" + value])
    project.invoke(argv)
    project.invoke(argv)
    assert project.state.calls == ["sha256:" + "a" * 64]


@pytest.mark.parametrize("split", [False, True])
@pytest.mark.parametrize(
    "value", ["CLOCK=__TIME__", "JOIN=a##b", 'IMPORT=_Pragma("pack(1)")', "BODY=(a+b)"]
)
def test_unsupported_define_bodies_bypass(project: Any, split: bool, value: str) -> None:
    argv = project.args + (["/D", value] if split else ["/D" + value])
    project.invoke(argv)
    project.invoke(argv)
    assert project.state.calls == [None, None]
    assert project.cache.count == 0


@pytest.mark.parametrize("keyword", ["_asm", "__asm"])
@pytest.mark.parametrize("where", ["source", "header", "joined-define", "split-define"])
def test_inline_assembly_aliases_bypass_before_ast_masking(
    project: Any, keyword: str, where: str
) -> None:
    argv = project.args
    if where in {"source", "header"}:
        path = getattr(project, where)
        path.write_text(
            path.read_text() + "int assembly(void) { " + keyword + " { nop } return 1; }\n"
        )
    else:
        value = "ASSEMBLER=" + keyword
        argv = project.args + (["/D", value] if where == "split-define" else ["/D" + value])
    project.invoke(argv)
    project.invoke(argv)
    assert project.state.calls == [None, None]
    assert project.cache.count == 0


def test_multicomponent_casefold_ambiguity_bypasses_driver_cache(project: Any) -> None:
    """Wine may choose the earlier DIR path that the host scanner skips."""
    earlier = project.root / "DIR"
    earlier.mkdir()
    (earlier / "api.h").write_text("#define VALUE 1\n")
    later = project.root / "includes"
    (later / "dir").mkdir(parents=True)
    (later / "dir" / "api.h").write_text("#define VALUE 2\n")
    project.source.write_text('#include "dir/api.h"\nint f(void) { return VALUE; }\n')
    argv = project.args + ["/I" + str(later)]
    project.invoke(argv)
    project.invoke(argv)
    assert project.state.calls == [None, None]
    assert project.cache.count == 0


@pytest.mark.parametrize(
    "name", ["dir/api.h", r"dir\api.h", "../api.h", "/api.h", r"C:\api.h", "C:api.h", ".", ".."]
)
@pytest.mark.parametrize("delimiters", ['"{}"', "<{}>"])
def test_nonleaf_literal_include_spellings_are_not_admitted(name: str, delimiters: str) -> None:
    from rebrew.cmake_cache import _ordinary_text

    assert not _ordinary_text(("#include " + delimiters.format(name) + "\n").encode())
