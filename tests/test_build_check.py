"""Tests for rebrew build-check.

``build/`` is gitignored in every rebrew project, so a hand-edited ``build.make``
is invisible to ``git status``, ``rebrew lint`` and ``rebrew verify`` -- while
silently redefining what every measurement taken from the tree means.  These
tests pin both directions: the checker must stay quiet on a tree CMake wrote and
must fire on one a human edited.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from rebrew import build_check
from rebrew.build_check import check, parse_compile_lines, parse_recorded


def test_objects_detect_header_changes_without_building(tmp_path):
    """A header alone can invalidate an object; the check must leave it untouched."""
    build = _tree(tmp_path, BUILD_MAKE)
    flags = build / "flags.make"
    flags.write_text("")
    os.utime(flags, (100, 100))
    bm = build / "CMakeFiles/server_dll.dir/build.make"
    objects = [obj for obj, _ in parse_compile_lines(BUILD_MAKE)]
    header = tmp_path / "shared.h"
    header.write_text("/* header */\n")
    os.utime(header, (100, 100))
    rules = []
    for obj in objects:
        path = build / obj
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"native object")
        os.utime(path, (200, 200))
        rules.append(f"{obj}: {header}\n\t@touch {obj}\n")
    bm.write_text(BUILD_MAKE + "\n" + "\n".join(rules))
    assert check(build, objects=True)["status"] == "ok"
    os.utime(header, (300, 300))
    assert check(build, objects=True)["status"] == "drift"
    assert all((build / obj).stat().st_mtime == 200 for obj in objects)


FLAGS_MAKE = """\
# Custom flags: CMakeFiles/server_dll.dir/src/a/one.c.obj_FLAGS = /O2 /Gd
# Custom options: CMakeFiles/server_dll.dir/src/a/one.c.obj_OPTIONS = /REBREW_TOOLCHAIN:msvc-6.0-sp5-pp
# Custom flags: CMakeFiles/server_dll.dir/src/b/two.c.obj_FLAGS = /Ox /Gd
"""

BUILD_MAKE = """\
CMakeFiles/server_dll.dir/src/a/one.c.obj: flags.make
\tcl /nologo /O2 /Gd /REBREW_TOOLCHAIN:msvc-6.0-sp5-pp /FoCMakeFiles/server_dll.dir/src/a/one.c.obj /FdCMakeFiles/server_dll.dir/ -c src/a/one.c
CMakeFiles/server_dll.dir/src/b/two.c.obj: flags.make
\tcl /nologo /Ox /Gd /FoCMakeFiles/server_dll.dir/src/b/two.c.obj /FdCMakeFiles/server_dll.dir/ -c src/b/two.c
CMakeFiles/server_dll.dir/src/c/three.c.obj: flags.make
\tcl /nologo /FoCMakeFiles/server_dll.dir/src/c/three.c.obj /FdCMakeFiles/server_dll.dir/ -c src/c/three.c
"""


def test_parse_recorded_reads_multiline_flags_make():
    """re.M is required -- without it the pattern matches nothing at all.

    Regression guard: an early version compiled the pattern without ``re.M``, so
    ``$`` anchored to end-of-string and a ``flags.make`` with hundreds of Custom
    comments yielded zero objects, making the checker report "clean" while
    comparing nothing.
    """
    recorded = parse_recorded(FLAGS_MAKE)
    assert len(recorded) == 2
    assert recorded["CMakeFiles/server_dll.dir/src/a/one.c.obj"] == {
        "/O2",
        "/Gd",
        "/REBREW_TOOLCHAIN:msvc-6.0-sp5-pp",
    }


def test_parse_recorded_strips_crlf_before_flag_split():
    """A CRLF flags.make must yield the same tokens as the LF one.

    ``re.M`` anchors ``$`` before the ``\\n``, so a bare ``$`` left the ``\\r``
    glued to the last flag token while ``parse_compile_lines`` reads build.make
    through ``splitlines()``, which strips it.  The two halves then disagreed on
    a token neither side held, and the check reported drift in a clean tree.
    """
    crlf = FLAGS_MAKE.replace("\n", "\r\n")
    assert parse_recorded(crlf) == parse_recorded(FLAGS_MAKE)


def test_parse_compile_lines_skips_listing_rules():
    text = BUILD_MAKE + (
        "CMakeFiles/server_dll.dir/src/a/one.c.s: flags.make\n"
        "\tcl /nologo /FAs /FaCMakeFiles/server_dll.dir/src/a/one.c.s /c src/a/one.c\n"
    )
    objs = [o for o, _ in parse_compile_lines(text)]
    assert "CMakeFiles/server_dll.dir/src/a/one.c.s" not in objs
    assert len(objs) == 3


def _tree(tmp_path: Path, build_make: str, *, sources: bool = True) -> Path:
    """A minimal build tree.  ``sources`` creates the .c files build.make names.

    The checker verifies those exist, so a fixture that omits them is not a
    clean tree -- it is a stale one, and `sources=False` is how the stale case is
    built.
    """
    d = tmp_path / "build" / "CMakeFiles" / "server_dll.dir"
    d.mkdir(parents=True)
    (d / "build.make").write_text(build_make, encoding="utf-8")
    (d / "flags.make").write_text(FLAGS_MAKE, encoding="utf-8")
    # Paths in build.make are relative to the project root, which is the
    # build dir's parent.
    if sources:
        for src in ("src/a/one.c", "src/b/two.c", "src/c/three.c"):
            path = tmp_path / src
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("int x;\n", encoding="utf-8")
    return tmp_path / "build"


def test_clean_tree_is_ok(tmp_path):
    result = check(_tree(tmp_path, BUILD_MAKE))
    assert result["status"] == "ok"
    # two of the three objects have a Custom comment; the third uses global flags
    assert result["checked"] == 2
    assert result["drift"] == []


def test_non_ascii_source_path_decodes_as_utf8(tmp_path: Path) -> None:
    """build.make may name a UTF-8 path; platform-default decode must not be used.

    Concrete input: ``src/a/café.c`` (U+00E9).  Without ``encoding="utf-8"``,
    a cp1252 locale would mis-decode the path bytes and report a false MISSING
    SOURCE drift.
    """
    cafe = "caf\u00e9"
    build = BUILD_MAKE.replace("src/a/one.c", f"src/a/{cafe}.c").replace(
        "one.c.obj", f"{cafe}.c.obj"
    )
    flags = FLAGS_MAKE.replace("one.c.obj", f"{cafe}.c.obj")
    d = tmp_path / "build" / "CMakeFiles" / "server_dll.dir"
    d.mkdir(parents=True)
    (d / "build.make").write_text(build, encoding="utf-8")
    (d / "flags.make").write_text(flags, encoding="utf-8")
    for src in (f"src/a/{cafe}.c", "src/b/two.c", "src/c/three.c"):
        path = tmp_path / src
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int x;\n", encoding="utf-8")
    result = check(tmp_path / "build", project_root=tmp_path)
    assert result["status"] == "ok"
    assert result["drift"] == []


def test_hand_edited_build_make_is_drift(tmp_path):
    """A flag in build.make that flags.make does not record was added by hand."""
    edited = BUILD_MAKE.replace("/Ox /Gd", "/Ox /Gd /Ob1")
    result = check(_tree(tmp_path, edited))
    assert result["status"] == "drift"
    assert [(d["flag"]) for d in result["drift"]] == ["/Ob1"]


def test_object_without_custom_comment_is_not_drift(tmp_path):
    """No Custom comment means no per-file flags -- the global C_FLAGS apply.

    Treating that as drift would flag most of a normal tree, because most files
    have no per-file entry.
    """
    result = check(_tree(tmp_path, BUILD_MAKE))
    assert result["status"] == "ok", result
    assert [d for d in result["drift"] if "three.c.obj" in d["obj"]] == [], (
        "an object with no recorded flags must not be reported"
    )


def test_missing_build_dir_is_not_configured(tmp_path):
    result = check(tmp_path / "build")
    assert result["status"] == "not-configured"
    assert result["drift"] == []


def test_not_configured_names_the_missing_file(tmp_path):
    """The message must say WHAT is absent, so a typo is diagnosable."""
    result = check(tmp_path / "typo-dir")
    assert "build.make" in result["message"]
    assert "typo-dir" in result["message"]


def test_not_configured_is_not_ok(tmp_path):
    """Regression guard: a mistyped --build-dir must not read as clean.

    ``check`` returning ``not-configured`` and the CLI exiting 0 on it would
    reproduce exactly the silent-pass failure this command exists to catch.
    Pin the distinction at the data level, because ``main`` calls
    ``typer.Exit`` and cannot be asserted on directly here.
    """
    assert check(tmp_path / "typo")["status"] != "ok"


def test_cli_exits_nonzero_when_not_configured(tmp_path, monkeypatch):
    """The CLI must fail when there is nothing to check, not report success."""
    from typer.testing import CliRunner

    from rebrew.build_check import app
    from rebrew.cli import EXIT_ERROR

    runner = CliRunner()
    result = runner.invoke(app, ["--build-dir", str(tmp_path / "nope")])
    assert result.exit_code == EXIT_ERROR, result.output


def test_cli_exits_zero_on_a_clean_tree(tmp_path):
    from typer.testing import CliRunner

    from rebrew.build_check import app

    runner = CliRunner()
    result = runner.invoke(app, ["--build-dir", str(_tree(tmp_path, BUILD_MAKE))])
    assert result.exit_code == 0, result.output


def test_cli_exits_nonzero_on_drift(tmp_path):
    from typer.testing import CliRunner

    from rebrew.build_check import app
    from rebrew.cli import EXIT_MISMATCH

    edited = BUILD_MAKE.replace("/Ox /Gd", "/Ox /Gd /Ob1")
    runner = CliRunner()
    result = runner.invoke(app, ["--build-dir", str(_tree(tmp_path, edited))])
    assert result.exit_code == EXIT_MISMATCH, result.output


@pytest.mark.parametrize("token", ["/O2", "/Gd", "/REBREW_TOOLCHAIN:msvc-6.0-sp5-pp"])
def test_recorded_tokens_are_not_drift(tmp_path, token):
    """A token flags.make records is never reported, whichever build.make has.

    Drift is one-directional: the checker reports build.make tokens missing from
    flags.make, so a recorded token stays quiet both while it is in the compile
    line and after a hand-edit drops it.
    """
    dropped = BUILD_MAKE.replace(f" {token}", "")
    assert token not in dropped, "the edit must actually remove the token"
    for i, build_make in enumerate((BUILD_MAKE, dropped)):
        result = check(_tree(tmp_path / f"case{i}", build_make))
        assert result["status"] == "ok", result["message"]
        assert all(d["flag"] != token for d in result["drift"])
        assert result["checked"] == 2


def test_missing_source_is_drift(tmp_path):
    """A rename leaves build.make naming an object that no longer exists.

    Regression for guild-rebrew round 1080: `rebrew rename` rewrote the source
    but not the gitignored build/, so split_link.sh died at exit 157 while this
    check reported clean.  Flags on the stale object all still agreed, and the
    object was skipped rather than flagged, because the flag loop only inspects
    objects carrying a Custom comment.
    """
    result = check(_tree(tmp_path, BUILD_MAKE, sources=False))
    assert result["status"] == "drift"
    assert "no longer exist" in result["message"]
    assert any(d["flag"] == "MISSING SOURCE" for d in result["drift"])


def test_missing_source_names_the_file(tmp_path):
    result = check(_tree(tmp_path, BUILD_MAKE, sources=False))
    named = " ".join(d["obj"] for d in result["drift"])
    assert "one.c" in named


def test_stale_source_reported_before_flags(tmp_path):
    """A stale tree makes every flag comparison meaningless, so it wins."""
    edited = BUILD_MAKE.replace("/Ox /Gd", "/Ox /Gd /Ob1")
    result = check(_tree(tmp_path, edited, sources=False))
    assert result["status"] == "drift"
    assert "no longer exist" in result["message"]
    assert result["checked"] == 0


def test_cli_exits_nonzero_on_missing_source(tmp_path):
    from typer.testing import CliRunner

    from rebrew.build_check import app
    from rebrew.cli import EXIT_MISMATCH

    runner = CliRunner()
    result = runner.invoke(app, ["--build-dir", str(_tree(tmp_path, BUILD_MAKE, sources=False))])
    assert result.exit_code == EXIT_MISMATCH, result.output


def test_cli_json_goes_to_stdout_status_to_stderr(tmp_path) -> None:
    """Human status stays on stderr so ``--json`` can be piped cleanly."""
    import json

    from typer.testing import CliRunner

    from rebrew.build_check import app

    runner = CliRunner()
    build = _tree(tmp_path, BUILD_MAKE)
    human = runner.invoke(app, ["--build-dir", str(build)])
    assert human.exit_code == 0, human.stdout + human.stderr
    assert human.stdout == ""
    assert "build-check:" in human.stderr

    coded = runner.invoke(app, ["--build-dir", str(build), "--json"])
    assert coded.exit_code == 0, coded.stdout + coded.stderr
    assert coded.stderr == ""
    payload = json.loads(coded.stdout)
    assert payload["status"] == "ok"


def test_per_file_pin_reads_toolchain_and_flags(tmp_path: Path) -> None:
    """A CMake-pinned file exposes its /REBREW_TOOLCHAIN + COMPILE_FLAGS so
    test/verify can match the linked compile."""
    from rebrew.build_check import per_file_pin

    build = _tree(tmp_path, BUILD_MAKE)
    tc, flags = per_file_pin(tmp_path / "src/a/one.c", build)
    assert tc == "msvc-6.0-sp5-pp"
    assert "O2" in flags and "Gd" in flags

    # Flags-only pin (no /REBREW_TOOLCHAIN).
    tc2, flags2 = per_file_pin(tmp_path / "src/b/two.c", build)
    assert tc2 is None
    assert "Ox" in flags2 and "Gd" in flags2


def test_per_file_pin_unpinned_file_returns_empty(tmp_path: Path) -> None:
    """A source with no Custom comment is not pinned -- caller keeps defaults."""
    from rebrew.build_check import per_file_pin

    build = _tree(tmp_path, BUILD_MAKE)
    tc, flags = per_file_pin(tmp_path / "src/c/three.c", build)
    assert tc is None and flags == ""


def test_per_file_pin_absent_build_returns_empty(tmp_path: Path) -> None:
    from rebrew.build_check import per_file_pin

    assert per_file_pin(tmp_path / "f.c", tmp_path / "no-build") == (None, "")


def test_cmake_pin_for_honours_cfg_build_dir(tmp_path: Path) -> None:
    """test._cmake_pin_for reads the configured build tree for one source."""
    from types import SimpleNamespace

    from rebrew.test import _cmake_pin_for

    build = _tree(tmp_path, BUILD_MAKE)
    cfg = SimpleNamespace(build_dir=str(build))
    tc, flags = _cmake_pin_for(tmp_path / "src/a/one.c", cfg)
    assert tc == "msvc-6.0-sp5-pp"
    assert "O2" in flags


def test_pin_generated_from_metadata_does_not_block_a_cflags_write() -> None:
    """The per-file flags CMake records come from the metadata (via
    `rebrew cmake-flags`), so matching flags are the metadata's own value and
    a new --cflags reaches the build on the next configure.  Only flags the
    metadata did not produce are a CMakeLists pin that --cflags cannot change.

    Regression: every function with a metadata cflags entry read as
    CMake-pinned, so its flags could never be changed through `rebrew test`.
    """
    from rebrew.test import _pin_overrides_metadata

    assert not _pin_overrides_metadata("/O2 /Gd /Ow", "/Ow /O2 /Gd")
    assert not _pin_overrides_metadata("", "/O2 /Gd")
    assert _pin_overrides_metadata("/O2 /Gd /Oa", "/O2 /Gd")
    # cmake-flags drops defines from the per-file flags it writes; a define in
    # the metadata is not a pin mismatch (guild-rebrew gv_ExAllocGraveyardWorker).
    assert not _pin_overrides_metadata("/O2 /Gd /Ow", "/DREBREW_ALLOW_NAKED /O2 /Gd /Ow")
    assert not _pin_overrides_metadata("/O2 /Gd /Ow", "-DX=1 /O2 /Gd /Ow")
    assert _pin_overrides_metadata("/O2 /Gd /Ow", "/DREBREW_ALLOW_NAKED /O2 /Gd")


def test_flags_make_without_custom_comments_is_not_configured(tmp_path):
    """No recorded Custom comment means nothing was compared.

    Reporting "ok" here is the silent pass this command exists to prevent: a
    CMake format change or a hand-edited flags.make would make every object
    unrecorded and the checker would compare nothing while claiming a clean tree.
    """
    build = _tree(tmp_path, BUILD_MAKE)
    (build / "CMakeFiles" / "server_dll.dir" / "flags.make").write_text(
        "# nothing recorded\n", encoding="utf-8"
    )
    result = check(build)
    assert result["status"] == "not-configured"
    assert result["checked"] == 0
    assert "one.c.obj" in result["message"]


def test_object_freshness_timeout_is_not_reported_as_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ``make -q`` that never returns lands in not-configured (exit 2), not ok."""
    build = _tree(tmp_path, BUILD_MAKE)

    def _hang(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd=["make", "-q"], timeout=1.0)

    monkeypatch.setattr(build_check, "run_process_group", _hang)
    result = check(build, objects=True)
    assert result["status"] == "not-configured"
    assert result["drift"] == []
    assert "timed out" in result["message"]


def test_object_freshness_make_missing_is_not_reported_as_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A make that cannot be spawned is the same non-pass, not a clean tree."""

    def _missing(*args: object, **kwargs: object) -> None:
        raise OSError(2, "No such file or directory")

    build = _tree(tmp_path, BUILD_MAKE)
    monkeypatch.setattr(build_check, "run_process_group", _missing)
    result = check(build, objects=True)
    assert result["status"] == "not-configured"
    assert "could not run make" in result["message"]
    assert "No such file" in result["message"]
