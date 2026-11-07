"""checked_cflags: a person-supplied flag string reaches a compiler, so it is bounded plain tokens."""

from __future__ import annotations

lazy from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from rebrew.ops import CFLAGS_MAX_CHARS, OpsError, checked_cflags


@pytest.mark.parametrize(
    ("given_flags", "expected"),
    [
        ("", ""),
        ("/O1 /Gd", "/O1 /Gd"),
        ("  /O1   /Gd /MT ", "/O1 /Gd /MT"),
        ("/fp:precise /EHsc /D_X=1 /Zi", "/fp:precise /EHsc /D_X=1 /Zi"),
        ("-O1 -Wall -m32", "-O1 -Wall -m32"),
        ("/Ob2 /Oy- /Os /TC /Zp1", "/Ob2 /Oy- /Os /TC /Zp1"),
    ],
)
def test_plain_flags_are_kept(given_flags: str, expected: str) -> None:
    assert checked_cflags(given_flags) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "/Fo",
        "/Fdx.pdb",
        "/Fe",
        "/Fa",
        "/FI",
        "/I",
        "/Ifoo",
        "/Yu",
        "/Tc",
        "/Tp",
        "/link",
        "/LINK",
        "/LD",
        "/E",
        "/P",
        "/EP",
        "-o",
        "-I.",
        "-lm",
        "-include",
        "@resp.rsp",
        "/tmp/x",
        "/O1;rm",
        "O1",
        "/",
        "/O1\x00",
    ],
)
def test_file_naming_or_command_changing_tokens_are_refused(bad: str) -> None:
    with pytest.raises(OpsError, match="invalid-cflags") as err:
        checked_cflags(f"/O1 {bad}")
    assert err.value.status == 400


def test_over_the_bound_is_refused() -> None:
    with pytest.raises(OpsError, match="invalid-cflags"):
        checked_cflags("/O1 " * (CFLAGS_MAX_CHARS // 4 + 1))


@given(st.text(max_size=400))
def test_fuzz_an_accepted_string_is_stable_plain_tokens(text: str) -> None:
    try:
        out = checked_cflags(text)
    except OpsError:
        return
    assert checked_cflags(out) == out and len(out) <= CFLAGS_MAX_CHARS
    assert all(token[0] in "/-" and "/" not in token[1:] for token in out.split())


def test_a_remote_compile_reports_its_flags_and_execution_in_the_test_result() -> None:
    from rebrew.compiler import compile as compile_module
    from rebrew.test import _result_dict_body

    def result() -> dict[str, object]:
        return _result_dict_body(
            "a.c", "f", "0x1000", 1, "EXACT", True, 1, 1, [], b"\x90", [], None, None
        )

    compile_module._last_remote_compile = None
    assert result()["compile"] is None
    record = {"flags": ["/nologo", "/O1"], "execution": {"status": "admitted"}}
    compile_module._last_remote_compile = record
    try:
        assert result()["compile"] == record
    finally:
        compile_module._last_remote_compile = None


def test_project_cflags_go_into_the_snapshot_config_and_a_target_override(tmp_path: Path) -> None:
    import tomllib

    from rebrew.ops import apply_project_cflags

    config = tmp_path / "rebrew-project.toml"
    config.write_text(
        '[project]\nname = "p"\n[targets.mini]\nbinary = "b"\n[targets.mini.compiler]\ncflags = "/O2"\n'
        '[compiler]\nprofile = "msvc-6.0"\ncflags = "/O2 /Gd"  # the project default\n',
        encoding="utf-8",
    )
    rewritten = apply_project_cflags(tmp_path, "mini", "/O1   /Gd")
    data = tomllib.loads(config.read_text(encoding="utf-8"))
    assert data["compiler"]["cflags"] == "/O1 /Gd" and data["compiler"]["profile"] == "msvc-6.0"
    assert data["targets"]["mini"]["compiler"]["cflags"] == "/O1 /Gd"
    assert "# the project default" in config.read_text(encoding="utf-8")
    assert rewritten is not None and rewritten[0] == config.stat().st_size


def test_project_cflags_create_the_compiler_table_and_empty_flags_touch_nothing(
    tmp_path: Path,
) -> None:
    import tomllib

    from rebrew.ops import OpsError, apply_project_cflags

    config = tmp_path / "rebrew-project.toml"
    config.write_text('[project]\nname = "p"\n', encoding="utf-8")
    assert apply_project_cflags(tmp_path, "mini", "  ") is None
    assert config.read_text(encoding="utf-8") == '[project]\nname = "p"\n'
    apply_project_cflags(tmp_path, "mini", "/Os")
    assert tomllib.loads(config.read_text(encoding="utf-8"))["compiler"]["cflags"] == "/Os"
    with pytest.raises(OpsError, match="invalid-cflags"):
        apply_project_cflags(tmp_path, "mini", "/Fo")
