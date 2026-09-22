"""Tests for rebrew build-check.

``build/`` is gitignored in every rebrew project, so a hand-edited ``build.make``
is invisible to ``git status``, ``rebrew lint`` and ``rebrew verify`` -- while
silently redefining what every measurement taken from the tree means.  These
tests pin both directions: the checker must stay quiet on a tree CMake wrote and
must fire on one a human edited.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rebrew.build_check import check, parse_compile_lines, parse_recorded

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
    assert all("three.c.obj" not in d["obj"] for d in result["drift"]), (
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
    result = check(_tree(tmp_path, BUILD_MAKE))
    assert all(d["flag"] != token for d in result["drift"])


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
