"""Tests for rebrew-cfg (programmatic config editor)."""

from pathlib import Path

import pytest
import tomlkit
from click.exceptions import Exit as ClickExit

from rebrew.cfg import (
    _detect_format,
    _load_toml,
    _resolve_target,
    _save_toml,
)

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

SAMPLE_TOML = """\
# Project config
[targets."server.dll"]
binary = "original/Server/server.dll"
format = "pe"
arch = "x86_32"
reversed_dir = "src/server.dll"
function_list = "src/server.dll/r2_functions.txt"
bin_dir = "bin/server.dll"
origins = ["GAME", "ZLIB"]

# Per-target cflags
[targets."server.dll".cflags_presets]
ZLIB = "/O3"

[compiler]
profile = "msvc6"
command = "wine CL.EXE"
cflags = "/O2 /Gd"

[compiler.cflags_presets]
GAME = "/O2 /Gd"
MSVCRT = "/O1"
"""


def _make_project(tmp_path: Path, toml_content: str = SAMPLE_TOML) -> Path:
    (tmp_path / "rebrew.toml").write_text(toml_content, encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# _load_toml / _save_toml
# ---------------------------------------------------------------------------


class TestLoadSave:
    def test_round_trip_preserves_comments(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, path = _load_toml(root)
        _save_toml(doc, path)
        result = path.read_text(encoding="utf-8")
        assert "# Project config" in result
        assert "# Per-target cflags" in result

    def test_load_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ClickExit):
            _load_toml(tmp_path)


# ---------------------------------------------------------------------------
# _resolve_target
# ---------------------------------------------------------------------------


class TestResolveTarget:
    def test_default_first_target(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, _ = _load_toml(root)
        assert _resolve_target(doc, None) == "server.dll"

    def test_explicit_target(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, _ = _load_toml(root)
        assert _resolve_target(doc, "server.dll") == "server.dll"

    def test_missing_target_raises(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, _ = _load_toml(root)
        with pytest.raises(ClickExit):
            _resolve_target(doc, "nonexistent")


# ---------------------------------------------------------------------------
# Functional tests via direct function calls
# ---------------------------------------------------------------------------


class TestAddTarget:
    def test_adds_target_section(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, path = _load_toml(root)

        # Simulate add-target
        targets = doc["targets"]
        tgt = tomlkit.table()
        tgt.add("binary", "original/client.exe")
        tgt.add("format", "pe")
        tgt.add("arch", "x86_32")
        tgt.add("reversed_dir", "src/client.exe")
        tgt.add("function_list", "src/client.exe/functions.txt")
        tgt.add("bin_dir", "bin/client.exe")
        tgt.add("origins", ["GAME"])
        targets["client.exe"] = tgt
        _save_toml(doc, path)

        # Verify
        doc2, _ = _load_toml(root)
        assert "client.exe" in doc2["targets"]
        assert doc2["targets"]["client.exe"]["arch"] == "x86_32"

    def test_duplicate_target_detectable(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, _ = _load_toml(root)
        assert "server.dll" in doc["targets"]


class TestRemoveTarget:
    def test_removes_target(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, path = _load_toml(root)
        del doc["targets"]["server.dll"]
        _save_toml(doc, path)

        doc2, _ = _load_toml(root)
        assert "server.dll" not in doc2.get("targets", {})


class TestAddOrigin:
    def test_adds_origin(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, path = _load_toml(root)
        origins = doc["targets"]["server.dll"]["origins"]
        origins.append("MSVCRT")
        _save_toml(doc, path)

        doc2, _ = _load_toml(root)
        assert "MSVCRT" in doc2["targets"]["server.dll"]["origins"]

    def test_no_duplicate(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, _ = _load_toml(root)
        origins = doc["targets"]["server.dll"]["origins"]
        assert "GAME" in origins


class TestRemoveOrigin:
    def test_removes_origin(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, path = _load_toml(root)
        origins = doc["targets"]["server.dll"]["origins"]
        origins.remove("ZLIB")
        _save_toml(doc, path)

        doc2, _ = _load_toml(root)
        assert "ZLIB" not in doc2["targets"]["server.dll"]["origins"]
        assert "GAME" in doc2["targets"]["server.dll"]["origins"]


class TestSetCflags:
    def test_set_target_cflags(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, path = _load_toml(root)
        doc["targets"]["server.dll"]["cflags_presets"]["GAME"] = "/O1 /Gd"
        _save_toml(doc, path)

        doc2, _ = _load_toml(root)
        assert doc2["targets"]["server.dll"]["cflags_presets"]["GAME"] == "/O1 /Gd"

    def test_set_global_cflags(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, path = _load_toml(root)
        doc["compiler"]["cflags_presets"]["ZLIB"] = "/O3"
        _save_toml(doc, path)

        doc2, _ = _load_toml(root)
        assert doc2["compiler"]["cflags_presets"]["ZLIB"] == "/O3"


class TestSetScalar:
    def test_set_existing_key(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, path = _load_toml(root)
        doc["compiler"]["cflags"] = "/O1"
        _save_toml(doc, path)

        doc2, _ = _load_toml(root)
        assert doc2["compiler"]["cflags"] == "/O1"

    def test_set_nested_key(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, path = _load_toml(root)
        doc["targets"]["server.dll"]["arch"] = "x86_64"
        _save_toml(doc, path)

        doc2, _ = _load_toml(root)
        assert doc2["targets"]["server.dll"]["arch"] == "x86_64"


class TestCommentsPreserved:
    def test_comments_survive_all_operations(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, path = _load_toml(root)

        # Mutate
        doc["targets"]["server.dll"]["origins"].append("ENGINE")
        doc["compiler"]["cflags"] = "/O1"
        _save_toml(doc, path)

        text = path.read_text(encoding="utf-8")
        assert "# Project config" in text
        assert "# Per-target cflags" in text


class TestDetectFormat:
    def test_pe(self, tmp_path: Path) -> None:
        f = tmp_path / "test.dll"
        f.write_bytes(b"MZ" + b"\x00" * 100)
        assert _detect_format(f) == "pe"

    def test_elf(self, tmp_path: Path) -> None:
        f = tmp_path / "test.so"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        assert _detect_format(f) == "elf"

    def test_macho(self, tmp_path: Path) -> None:
        f = tmp_path / "test.dylib"
        f.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        assert _detect_format(f) == "macho"

    def test_unknown_defaults_pe(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 100)
        assert _detect_format(f) == "pe"

    def test_nonexistent_defaults_pe(self, tmp_path: Path) -> None:
        assert _detect_format(tmp_path / "nope") == "pe"

    def test_unrecognized_format_warns(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Unrecognized magic bytes should emit a warning to stderr and default to PE.

        Regression test for Phase 1 fix: previously returned 'pe' silently.
        """
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00\x00\x00\x00" + b"\x00" * 100)
        result = _detect_format(f)
        assert result == "pe"
        captured = capsys.readouterr()
        assert "Warning" in captured.err
        assert "unrecognized binary format" in captured.err

    def test_nonexistent_file_warns(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Non-existent file should emit a warning to stderr and default to PE.

        Regression test for Phase 1 fix: previously returned 'pe' silently.
        """
        result = _detect_format(tmp_path / "nonexistent.dll")
        assert result == "pe"
        captured = capsys.readouterr()
        assert "Warning" in captured.err
        assert "cannot read" in captured.err


# ---------------------------------------------------------------------------
# CLI-level tests (end-to-end via CliRunner)
# ---------------------------------------------------------------------------

from typer.testing import CliRunner  # noqa: E402

from rebrew.cfg import app as cfg_app  # noqa: E402

runner = CliRunner()


class TestCLIListTargets:
    def test_list_targets_output(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["list-targets"])
        assert result.exit_code == 0
        assert "server.dll" in result.output

    def test_list_targets_no_targets(self, tmp_path: Path, monkeypatch) -> None:
        (tmp_path / "rebrew.toml").write_text("[compiler]\nprofile = 'msvc6'\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["list-targets"])
        assert result.exit_code == 0
        assert "No targets defined" in result.output


class TestCLIShow:
    def test_show_all(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["show"])
        assert result.exit_code == 0
        assert "server.dll" in result.output
        assert "msvc6" in result.output

    def test_show_key(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["show", "compiler.cflags"])
        assert result.exit_code == 0
        assert "/O2 /Gd" in result.output

    def test_show_missing_key(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["show", "nonexistent.key"])
        assert result.exit_code == 1


class TestCLIAddRemoveTarget:
    def test_add_target_creates_dirs(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(
            cfg_app,
            [
                "add-target",
                "client.exe",
                "--binary",
                "original/client.exe",
                "--arch",
                "x86_32",
            ],
        )
        assert result.exit_code == 0
        assert "Added" in result.output
        assert (tmp_path / "src" / "client.exe").is_dir()
        assert (tmp_path / "bin" / "client.exe").is_dir()
        # Verify TOML was updated
        doc, _ = _load_toml(tmp_path)
        assert "client.exe" in doc["targets"]

    def test_add_target_idempotent(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        # server.dll already exists in SAMPLE_TOML
        result = runner.invoke(
            cfg_app,
            [
                "add-target",
                "server.dll",
                "--binary",
                "original/server.dll",
            ],
        )
        assert result.exit_code == 0
        assert "already exists" in result.output

    def test_remove_target(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["remove-target", "server.dll"])
        assert result.exit_code == 0
        assert "Removed" in result.output
        doc, _ = _load_toml(tmp_path)
        assert "server.dll" not in doc.get("targets", {})

    def test_remove_target_idempotent(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["remove-target", "nonexistent"])
        assert result.exit_code == 0
        assert "already removed" in result.output


class TestCLISet:
    def test_set_string(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["set", "compiler.cflags", "/O1"])
        assert result.exit_code == 0
        doc, _ = _load_toml(tmp_path)
        assert doc["compiler"]["cflags"] == "/O1"

    def test_set_int(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["set", "compiler.workers", "4"])
        assert result.exit_code == 0
        doc, _ = _load_toml(tmp_path)
        assert doc["compiler"]["workers"] == 4

    def test_set_hex(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["set", "compiler.image_base", "0x10000000"])
        assert result.exit_code == 0
        doc, _ = _load_toml(tmp_path)
        assert doc["compiler"]["image_base"] == 0x10000000


class TestCLIOrigins:
    def test_add_origin(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["add-origin", "ENGINE"])
        assert result.exit_code == 0
        assert "Added" in result.output
        doc, _ = _load_toml(tmp_path)
        assert "ENGINE" in doc["targets"]["server.dll"]["origins"]

    def test_add_origin_idempotent(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["add-origin", "GAME"])
        assert result.exit_code == 0
        assert "already exists" in result.output

    def test_remove_origin(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["remove-origin", "ZLIB"])
        assert result.exit_code == 0
        assert "Removed" in result.output
        doc, _ = _load_toml(tmp_path)
        assert "ZLIB" not in doc["targets"]["server.dll"]["origins"]

    def test_remove_origin_idempotent(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["remove-origin", "NONEXISTENT"])
        assert result.exit_code == 0
        assert "already removed" in result.output


class TestCLISetCflags:
    def test_set_target_cflags(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["set-cflags", "GAME", "/O1 /Gd", "--target", "server.dll"])
        assert result.exit_code == 0
        doc, _ = _load_toml(tmp_path)
        assert doc["targets"]["server.dll"]["cflags_presets"]["GAME"] == "/O1 /Gd"

    def test_set_global_cflags(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["set-cflags", "ZLIB", "/O3"])
        assert result.exit_code == 0
        doc, _ = _load_toml(tmp_path)
        assert doc["compiler"]["cflags_presets"]["ZLIB"] == "/O3"
