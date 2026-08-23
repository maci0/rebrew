"""Tests for rebrew config.py — parse-helper branches and warnings."""

from pathlib import Path

import pytest

from rebrew.config import (
    _as_str,
    _as_table,
    _parse_int_list,
    _parse_optional_int,
    _parse_source_ext,
    _resolve,
    _split_compiler_runner,
)


class TestParseHelpers:
    def test_as_str_none_and_valid(self) -> None:
        assert _as_str(None, "def", "x") == "def"
        assert _as_str("", "def", "x") == ""
        assert _as_str("ok", "def", "x") == "ok"

    def test_as_str_bad_type_warns(self) -> None:
        with pytest.warns(UserWarning, match="Expected string for x"):
            assert _as_str(99, "def", "x") == "def"

    def test_parse_int_list_invalid_string_warns(self) -> None:
        with pytest.warns(UserWarning, match="Invalid integer"):
            assert _parse_int_list(["0x10", "zzz"], "test") == [16]

    def test_parse_int_list_unexpected_type_warns(self) -> None:
        with pytest.warns(UserWarning, match="Unexpected type"):
            assert _parse_int_list([1.5], "test") == []

    def test_parse_source_ext_defaults(self) -> None:
        assert _parse_source_ext(None) == ".c"
        assert _parse_source_ext("") == ".c"
        assert _parse_source_ext(".") == ".c"
        assert _parse_source_ext("cpp") == ".cpp"
        assert _parse_source_ext(".c") == ".c"

    def test_parse_source_ext_invalid_warns(self) -> None:
        with pytest.warns(UserWarning, match="source_ext"):
            assert _parse_source_ext("a/b") == ".c"
        with pytest.warns(UserWarning, match="Expected string"):
            assert _parse_source_ext(5) == ".c"

    def test_parse_optional_int_invalid_warns(self) -> None:
        with pytest.warns(UserWarning, match="Invalid integer"):
            assert _parse_optional_int("abc", "test") is None

    def test_as_table_raises_on_non_dict(self) -> None:
        with pytest.raises(ValueError, match="must be a TOML table"):
            _as_table([1], "compiler")
        assert _as_table(None, "compiler") == {}

    def test_resolve_warns_on_bad_type(self) -> None:
        with pytest.warns(UserWarning, match="Expected path string"):
            assert _resolve(Path("/tmp"), 42) is None
        assert _resolve(Path("/tmp"), "rel") == Path("/tmp/rel")
        assert _resolve(Path("/tmp"), Path("/abs")) == Path("/abs")
        assert _resolve(Path("/tmp"), None) is None


class TestSplitCompilerRunner:
    def test_explicit_runner_wins(self) -> None:
        runner, command = _split_compiler_runner({"command": "wine CL.EXE", "runner": "wibo"})
        assert runner == "wibo"
        assert command == "wine CL.EXE"

    def test_wine_runner_detected(self) -> None:
        runner, command = _split_compiler_runner({"command": "wine /vc/CL.EXE"})
        assert runner == "wine"

    def test_wibo_runner_detected(self) -> None:
        runner, command = _split_compiler_runner({"command": "wibo /vc/CL.EXE"})
        assert runner == "wibo"

    def test_native_runner_empty(self) -> None:
        runner, command = _split_compiler_runner({"command": "cl"})
        assert runner == ""
        assert command == "cl"

    def test_default_command(self) -> None:
        runner, command = _split_compiler_runner({})
        assert runner == "wine"
        assert command == "wine CL.EXE"


class TestCapstoneProperties:
    def test_unknown_arch_defaults_to_x86_32(self) -> None:
        import capstone

        from rebrew.config import ProjectConfig

        cfg = ProjectConfig(root=Path("."), arch="weird_arch")
        assert cfg.capstone_arch == capstone.CS_ARCH_X86
        assert cfg.capstone_mode == capstone.CS_MODE_32

    def test_known_arch_properties(self) -> None:
        import capstone

        from rebrew.config import ProjectConfig

        cfg = ProjectConfig(root=Path("."), arch="x86_64")
        assert cfg.capstone_mode == capstone.CS_MODE_64
