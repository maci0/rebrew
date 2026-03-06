"""Tests for rebrew-cfg (programmatic config editor)."""

from pathlib import Path

import pytest
import tomlkit
from click.exceptions import Exit as ClickExit

from rebrew.cfg import (
    _detect_format_and_arch,
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
function_list = "src/server.dll/functions.txt"
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
    (tmp_path / "rebrew-project.toml").write_text(toml_content, encoding="utf-8")
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


def _make_pe_stub(path: Path, machine: int = 0x14C) -> Path:
    """Build a minimal PE file that LIEF recognises (MZ + PE signature)."""
    import struct

    buf = bytearray(256)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 60, 128)  # e_lfanew
    buf[128:132] = b"PE\x00\x00"
    struct.pack_into("<H", buf, 132, machine)
    struct.pack_into("<H", buf, 148, 96)  # SizeOfOptionalHeader
    struct.pack_into("<H", buf, 152, 0x10B)  # PE32
    path.write_bytes(bytes(buf))
    return path


class TestDetectFormat:
    """Test format detection via _detect_format_and_arch (format component)."""

    def test_pe(self, tmp_path: Path) -> None:
        f = _make_pe_stub(tmp_path / "test.dll")
        fmt, _ = _detect_format_and_arch(f)
        assert fmt == "pe"

    def test_elf(self, tmp_path: Path) -> None:
        f = tmp_path / "test.so"
        f.write_bytes(b"\x7fELF" + b"\x00" * 100)
        fmt, _ = _detect_format_and_arch(f)
        assert fmt == "elf"

    def test_macho(self, tmp_path: Path) -> None:
        f = tmp_path / "test.dylib"
        f.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 100)
        fmt, _ = _detect_format_and_arch(f)
        assert fmt == "macho"

    def test_unknown_defaults_pe(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00" * 100)
        fmt, _ = _detect_format_and_arch(f)
        assert fmt == "pe"

    def test_nonexistent_defaults_pe(self, tmp_path: Path) -> None:
        fmt, _ = _detect_format_and_arch(tmp_path / "nope")
        assert fmt == "pe"

    def test_unrecognized_format_warns(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00\x00\x00\x00" + b"\x00" * 100)
        fmt, _ = _detect_format_and_arch(f)
        assert fmt == "pe"
        captured = capsys.readouterr()
        assert "Warning" in captured.err
        assert "unrecognized binary format" in captured.err

    def test_nonexistent_file_warns(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        fmt, _ = _detect_format_and_arch(tmp_path / "nonexistent.dll")
        assert fmt == "pe"
        captured = capsys.readouterr()
        assert "Warning" in captured.err
        assert "cannot read" in captured.err


class TestDetectFormatAndArch:
    def test_elf_little_endian_x86(self, tmp_path: Path) -> None:
        import struct

        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 1  # ei_class = 32-bit
        header[5] = 1  # ei_data = ELFDATA2LSB
        struct.pack_into("<H", header, 18, 3)  # EM_386
        f = tmp_path / "le32.elf"
        f.write_bytes(bytes(header))
        fmt, arch = _detect_format_and_arch(f)
        assert fmt == "elf"
        assert arch == "x86_32"

    def test_elf_little_endian_x86_64(self, tmp_path: Path) -> None:
        import struct

        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2  # ei_class = 64-bit
        header[5] = 1  # ei_data = ELFDATA2LSB
        struct.pack_into("<H", header, 18, 62)  # EM_X86_64
        f = tmp_path / "le64.elf"
        f.write_bytes(bytes(header))
        fmt, arch = _detect_format_and_arch(f)
        assert fmt == "elf"
        assert arch == "x86_64"

    def test_elf_big_endian_arm32(self, tmp_path: Path) -> None:
        import struct

        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 1  # ei_class = 32-bit
        header[5] = 2  # ei_data = ELFDATA2MSB
        struct.pack_into(">H", header, 18, 40)  # EM_ARM
        f = tmp_path / "be32.elf"
        f.write_bytes(bytes(header))
        fmt, arch = _detect_format_and_arch(f)
        assert fmt == "elf"
        assert arch == "arm32"

    def test_elf_big_endian_aarch64(self, tmp_path: Path) -> None:
        import struct

        header = bytearray(64)
        header[0:4] = b"\x7fELF"
        header[4] = 2  # ei_class = 64-bit
        header[5] = 2  # ei_data = ELFDATA2MSB
        struct.pack_into(">H", header, 18, 183)  # EM_AARCH64
        f = tmp_path / "be64.elf"
        f.write_bytes(bytes(header))
        fmt, arch = _detect_format_and_arch(f)
        assert fmt == "elf"
        assert arch == "arm64"

    def test_pe_x86(self, tmp_path: Path) -> None:
        f = _make_pe_stub(tmp_path / "test.exe", machine=0x14C)
        fmt, arch = _detect_format_and_arch(f)
        assert fmt == "pe"
        assert arch == "x86_32"

    def test_pe_amd64(self, tmp_path: Path) -> None:
        f = _make_pe_stub(tmp_path / "test.exe", machine=0x8664)
        fmt, arch = _detect_format_and_arch(f)
        assert fmt == "pe"
        assert arch == "x86_64"


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
        (tmp_path / "rebrew-project.toml").write_text(
            "[compiler]\nprofile = 'msvc6'\n", encoding="utf-8"
        )
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


# ---------------------------------------------------------------------------
# _resolve_dotted_key unit tests
# ---------------------------------------------------------------------------

from rebrew.cfg import _resolve_dotted_key  # noqa: E402


class TestResolveDottedKey:
    """Tests for greedy TOML-aware dotted key resolution."""

    def test_simple_key(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, _ = _load_toml(root)
        parent, final, parts = _resolve_dotted_key(doc, "compiler.cflags")
        assert final == "cflags"
        assert parent[final] == "/O2 /Gd"

    def test_dotted_target_name(self, tmp_path: Path) -> None:
        """Key like 'targets.server.dll.arch' must resolve through 'server.dll' key."""
        root = _make_project(tmp_path)
        doc, _ = _load_toml(root)
        parent, final, parts = _resolve_dotted_key(doc, "targets.server.dll.arch")
        assert final == "arch"
        assert parent[final] == "x86_32"
        assert parts == ["targets", "server.dll", "arch"]

    def test_dotted_target_nested(self, tmp_path: Path) -> None:
        """Deeply nested key through dotted target name."""
        root = _make_project(tmp_path)
        doc, _ = _load_toml(root)
        parent, final, parts = _resolve_dotted_key(doc, "targets.server.dll.cflags_presets.ZLIB")
        assert final == "ZLIB"
        assert parent[final] == "/O3"

    def test_missing_key_raises(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, _ = _load_toml(root)
        from click.exceptions import Exit as ClickExit

        with pytest.raises(ClickExit):
            _resolve_dotted_key(doc, "nonexistent.key.path")

    def test_create_missing(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path)
        doc, _ = _load_toml(root)
        parent, final, _ = _resolve_dotted_key(
            doc, "new_section.sub_key.value", create_missing=True
        )
        # Parent should have been created and final key should be accessible
        assert final == "value"
        assert isinstance(parent, dict)


# ---------------------------------------------------------------------------
# CLI tests for new commands
# ---------------------------------------------------------------------------


class TestCLIGet:
    def test_get_reads_value(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["get", "compiler.cflags"])
        assert result.exit_code == 0
        assert "/O2 /Gd" in result.output

    def test_get_dotted_target(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["get", "targets.server.dll.arch"])
        assert result.exit_code == 0
        assert "x86_32" in result.output


class TestCLIDump:
    def test_dump_json(self, tmp_path: Path, monkeypatch) -> None:
        import json

        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["dump"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "targets" in data
        assert "compiler" in data

    def test_dump_toml(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["dump", "--toml"])
        assert result.exit_code == 0
        assert "[compiler]" in result.output


class TestCLIPath:
    def test_path_output(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["path"])
        assert result.exit_code == 0
        assert "rebrew-project.toml" in result.output
        assert str(tmp_path) in result.output


class TestCLIShowDottedTarget:
    def test_show_dotted_target_arch(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["show", "targets.server.dll.arch"])
        assert result.exit_code == 0
        assert "x86_32" in result.output

    def test_show_dotted_target_binary(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["show", "targets.server.dll.binary"])
        assert result.exit_code == 0
        assert "original/Server/server.dll" in result.output


class TestCLISetDottedTarget:
    def test_set_through_dotted_target(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["set", "targets.server.dll.arch", "x86_64"])
        assert result.exit_code == 0
        doc, _ = _load_toml(tmp_path)
        assert doc["targets"]["server.dll"]["arch"] == "x86_64"


# ---------------------------------------------------------------------------
# CRT auto-detection tests
# ---------------------------------------------------------------------------

from rebrew.config import detect_crt_sources  # noqa: E402


class TestDetectCrtSources:
    def test_no_tools_dir(self, tmp_path: Path) -> None:
        """No tools/ directory → empty result."""
        assert detect_crt_sources(tmp_path) == {}

    def test_empty_tools_dir(self, tmp_path: Path) -> None:
        (tmp_path / "tools").mkdir()
        assert detect_crt_sources(tmp_path) == {}

    def test_msvc600_detected(self, tmp_path: Path) -> None:
        """Standard MSVC600 layout is detected."""
        crt_dir = tmp_path / "tools" / "MSVC600" / "VC98" / "CRT" / "SRC"
        crt_dir.mkdir(parents=True)
        result = detect_crt_sources(tmp_path)
        assert "MSVCRT" in result
        assert "MSVC600" in result["MSVCRT"]

    def test_case_insensitive(self, tmp_path: Path) -> None:
        """CRT path detection is case-insensitive."""
        crt_dir = tmp_path / "tools" / "msvc600" / "vc98" / "crt" / "src"
        crt_dir.mkdir(parents=True)
        result = detect_crt_sources(tmp_path)
        assert "MSVCRT" in result

    def test_msvc7_detected(self, tmp_path: Path) -> None:
        crt_dir = tmp_path / "tools" / "MSVC7" / "crt" / "src"
        crt_dir.mkdir(parents=True)
        result = detect_crt_sources(tmp_path)
        assert "MSVCRT" in result
        assert "MSVC7" in result["MSVCRT"]

    def test_first_match_wins(self, tmp_path: Path) -> None:
        """Only the first matching pattern per origin is returned."""
        crt1 = tmp_path / "tools" / "MSVC600" / "VC98" / "CRT" / "SRC"
        crt1.mkdir(parents=True)
        crt2 = tmp_path / "tools" / "MSVC7" / "crt" / "src"
        crt2.mkdir(parents=True)
        result = detect_crt_sources(tmp_path)
        # MSVC600 pattern appears first in _CRT_SOURCE_PATTERNS
        assert "MSVC600" in result["MSVCRT"]


class TestCLIDetectCrt:
    def test_detect_crt_no_tools(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["detect-crt"])
        assert result.exit_code == 0
        assert "No CRT source directories found" in result.output

    def test_detect_crt_found(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        crt_dir = tmp_path / "tools" / "MSVC600" / "VC98" / "CRT" / "SRC"
        crt_dir.mkdir(parents=True)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["detect-crt"])
        assert result.exit_code == 0
        assert "MSVCRT" in result.output

    def test_detect_crt_write(self, tmp_path: Path, monkeypatch) -> None:
        _make_project(tmp_path)
        crt_dir = tmp_path / "tools" / "MSVC600" / "VC98" / "CRT" / "SRC"
        crt_dir.mkdir(parents=True)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(cfg_app, ["detect-crt", "--write"])
        assert result.exit_code == 0
        assert "Wrote" in result.output
        doc, _ = _load_toml(tmp_path)
        assert "crt_sources" in doc["targets"]["server.dll"]
        assert doc["targets"]["server.dll"]["crt_sources"]["MSVCRT"] == "tools/MSVC600/VC98/CRT/SRC"
