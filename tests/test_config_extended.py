"""Tests for rebrew config.py — parse-helper branches and warnings."""

from pathlib import Path

import pytest

from rebrew.config import (
    ConfigWarning,
    as_str,
    as_table,
    parse_int_list,
    parse_optional_int,
    parse_source_ext,
    resolve_path,
    split_compiler_runner,
)


class TestParseHelpers:
    def test_as_str_none_and_valid(self) -> None:
        assert as_str(None, "def", "x") == "def"
        assert as_str("", "def", "x") == ""
        assert as_str("ok", "def", "x") == "ok"

    def test_as_str_bad_type_warns(self) -> None:
        with pytest.warns(UserWarning, match="Expected string for x"):
            assert as_str(99, "def", "x") == "def"

    def test_parse_int_list_invalid_string_warns(self) -> None:
        with pytest.warns(UserWarning, match="Invalid integer"):
            assert parse_int_list(["0x10", "zzz"], "test") == [16]

    def test_parse_int_list_unexpected_type_warns(self) -> None:
        with pytest.warns(UserWarning, match="Unexpected type"):
            assert parse_int_list([1.5], "test") == []

    def test_parse_int_list_integral_float_accepted(self) -> None:
        assert parse_int_list([2.0], "test") == [2]

    def test_parse_int_list_bool_rejected(self) -> None:
        with pytest.warns(UserWarning, match="Unexpected type"):
            assert parse_int_list([True], "test") == []

    def test_parse_source_ext_defaults(self) -> None:
        assert parse_source_ext(None) == ".c"
        with pytest.warns(ConfigWarning, match="Expected non-empty source_ext"):
            assert parse_source_ext("") == ".c"
        with pytest.warns(ConfigWarning, match="Expected non-empty source_ext"):
            assert parse_source_ext(".") == ".c"
        with pytest.warns(ConfigWarning, match="missing a leading dot"):
            assert parse_source_ext("cpp") == ".cpp"
        assert parse_source_ext(".c") == ".c"

    def test_parse_source_ext_invalid_warns(self) -> None:
        with pytest.warns(UserWarning, match="source_ext"):
            assert parse_source_ext("a/b") == ".c"
        with pytest.warns(UserWarning, match="Expected string"):
            assert parse_source_ext(5) == ".c"

    def test_parse_optional_int_invalid_warns(self) -> None:
        with pytest.warns(UserWarning, match="Invalid integer"):
            assert parse_optional_int("abc", "test") is None

    def test_as_table_raises_on_non_dict(self) -> None:
        with pytest.raises(ValueError, match="must be a TOML table"):
            as_table([1], "compiler")
        assert as_table(None, "compiler") == {}

    def test_resolve_warns_on_bad_type(self) -> None:
        with pytest.warns(UserWarning, match="Expected path string"):
            assert resolve_path(Path("/tmp"), 42) is None
        assert resolve_path(Path("/tmp"), "rel") == Path("/tmp/rel")
        assert resolve_path(Path("/tmp"), Path("/abs")) == Path("/abs")
        assert resolve_path(Path("/tmp"), None) is None


class TestSplitCompilerRunner:
    def test_explicit_runner_wins(self) -> None:
        runner, command = split_compiler_runner({"command": "wine CL.EXE", "runner": "wibo"})
        assert runner == "wibo"
        assert command == "wine CL.EXE"

    def test_wine_runner_detected(self) -> None:
        runner, command = split_compiler_runner({"command": "wine /vc/CL.EXE"})
        assert runner == "wine"

    def test_wibo_runner_detected(self) -> None:
        runner, command = split_compiler_runner({"command": "wibo /vc/CL.EXE"})
        assert runner == "wibo"

    def test_native_runner_empty(self) -> None:
        runner, command = split_compiler_runner({"command": "cl"})
        assert runner == ""
        assert command == "cl"

    def test_default_command(self) -> None:
        runner, command = split_compiler_runner({})
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
