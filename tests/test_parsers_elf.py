"""Integration tests for ELF .o parsing via a real gcc-compiled object file."""

import shutil
import subprocess
from pathlib import Path

import pytest

from rebrew.matcher.parsers import (
    list_obj_symbols,
    parse_obj_relocs_full,
    parse_obj_symbol_and_relocs,
    parse_obj_symbol_bytes,
)

_CC = shutil.which("cc") or shutil.which("gcc")

pytestmark = pytest.mark.skipif(_CC is None, reason="no C compiler available")


def _compile(tmp_path: Path) -> Path:
    src = tmp_path / "sample.c"
    src.write_text(
        "int helper(int x) { return x + 1; }\nint caller(int y) { return helper(y) + 2; }\n",
        encoding="utf-8",
    )
    obj = tmp_path / "sample.o"
    subprocess.run([_CC, "-c", "-O0", "-o", str(obj), str(src)], check=True, capture_output=True)
    return obj


class TestElfObjParsing:
    @pytest.mark.parametrize("machine", ["I386", "M68K"])
    def test_short_relocation_cannot_hide_adjacent_opcodes(self, monkeypatch, machine) -> None:
        import types

        import lief

        from rebrew.matcher.parsers import _parse_elf_symbol_bytes

        section = types.SimpleNamespace(name=".text", content=b"12345678")
        symbol = types.SimpleNamespace(name="helper", section=section, value=0, size=8)
        reloc = types.SimpleNamespace(address=2, size=16, section=section)
        elf = types.SimpleNamespace(
            header=types.SimpleNamespace(machine_type=getattr(lief.ELF.ARCH, machine)),
            symbols=[symbol],
            relocations=[reloc],
        )
        monkeypatch.setattr(lief.ELF, "parse", lambda _: elf)
        assert _parse_elf_symbol_bytes("unused.o", "helper") == (None, None)

    def test_untyped_assembly_function_ignores_local_labels(self, monkeypatch) -> None:
        import types

        import lief

        from rebrew.matcher.parsers import _parse_elf_symbol_bytes

        section = types.SimpleNamespace(name=".text", content=b"12345678")
        symbols = [
            types.SimpleNamespace(
                name=name,
                section=section,
                value=value,
                size=0,
                type=lief.ELF.Symbol.TYPE.NOTYPE,
                binding=binding,
            )
            for name, value, binding in [
                ("_helper", 0, lief.ELF.Symbol.BINDING.GLOBAL),
                ("Lpool", 2, lief.ELF.Symbol.BINDING.LOCAL),
                ("_next", 6, lief.ELF.Symbol.BINDING.GLOBAL),
            ]
        ]
        elf = types.SimpleNamespace(
            header=types.SimpleNamespace(machine_type=lief.ELF.ARCH.SH),
            symbols=symbols,
            relocations=[],
        )
        monkeypatch.setattr(lief.ELF, "parse", lambda _: elf)
        assert _parse_elf_symbol_bytes("unused.o", "helper") == (b"123456", {})

    def test_mos_objects_cannot_use_four_byte_relocation_masks(self, tmp_path: Path) -> None:
        from rebrew.gen_flirt_pat import parse_elf_obj

        obj = _compile(tmp_path)
        data = bytearray(obj.read_bytes())
        data[18:20] = (6502).to_bytes(2, "little")
        obj.write_bytes(data)
        with pytest.warns(RuntimeWarning, match="6502"):
            assert parse_obj_symbol_bytes(obj, "helper") == (None, None)
        assert list(parse_elf_obj(bytes(data))) == []

    @pytest.mark.parametrize("thumb", [False, True])
    def test_sized_arm_functions_preserve_tail_bytes(self, monkeypatch, thumb) -> None:
        import types

        import lief

        from rebrew.matcher.parsers import _parse_elf_symbol_bytes

        section = types.SimpleNamespace(name=".text", content=b"\x01\x02\x00\x00")
        symbol = types.SimpleNamespace(name="helper", section=section, value=int(thumb), size=4)
        elf = types.SimpleNamespace(
            header=types.SimpleNamespace(machine_type=lief.ELF.ARCH.ARM),
            symbols=[symbol],
            relocations=[],
        )
        monkeypatch.setattr(lief.ELF, "parse", lambda _: elf)
        assert _parse_elf_symbol_bytes("unused.o", "helper") == (bytes(section.content), {})

    def test_exact_symbol_wins_over_underscore_alias(self, tmp_path: Path) -> None:
        source = tmp_path / "aliases.c"
        source.write_text("int helper(void) { return 1; }\nint _helper(void) { return 2; }\n")
        obj = tmp_path / "aliases.o"
        subprocess.run([_CC, "-c", "-o", str(obj), str(source)], check=True, capture_output=True)
        bare, _ = parse_obj_symbol_bytes(obj, "helper")
        prefixed, _ = parse_obj_symbol_bytes(obj, "_helper")
        assert bare and prefixed and bare != prefixed

    def test_combined_parser_preserves_non_coff_objects(self, tmp_path: Path) -> None:
        obj = _compile(tmp_path)
        code, relocs = parse_obj_symbol_bytes(obj, "caller")
        full_code, full_relocs, typed = parse_obj_symbol_and_relocs(obj, "caller")
        assert full_code == code and full_relocs == relocs
        assert typed == []

    def test_symbol_bytes_extracted(self, tmp_path: Path) -> None:
        obj = _compile(tmp_path)
        code, relocs = parse_obj_symbol_bytes(str(obj), "helper")
        assert code is not None and len(code) > 0
        # helper makes no calls — no relocations expected.
        assert not relocs

    def test_caller_has_call_reloc(self, tmp_path: Path) -> None:
        obj = _compile(tmp_path)
        code, relocs = parse_obj_symbol_bytes(str(obj), "caller")
        assert code is not None and len(code) > 0
        # caller() calls helper() → at least one REL32 relocation.
        assert relocs and any("helper" in sym for sym in relocs.values())

    def test_missing_symbol_returns_none(self, tmp_path: Path) -> None:
        obj = _compile(tmp_path)
        code, relocs = parse_obj_symbol_bytes(str(obj), "no_such_fn")
        assert code is None
        assert relocs is None

    def test_list_symbols(self, tmp_path: Path) -> None:
        obj = _compile(tmp_path)
        syms = list_obj_symbols(str(obj))
        assert "helper" in syms
        assert "caller" in syms

    def test_relocs_full_is_coff_only(self, tmp_path: Path) -> None:
        # parse_obj_relocs_full is COFF-only; ELF call relocs surface via the
        # reloc_offsets dict from parse_obj_symbol_bytes (see caller test).
        obj = _compile(tmp_path)
        assert parse_obj_relocs_full(str(obj), "caller") == []


def test_parse_elf_obj_takes_static_functions_on_request(tmp_path: Path) -> None:
    from rebrew.gen_flirt_pat import parse_elf_obj

    src = tmp_path / "statics.c"
    src.write_text(
        "static int hidden(int x) { return x * 3 + 7; }\n"
        "int shown(int y) { return hidden(y) - hidden(y + 1); }\n",
        encoding="utf-8",
    )
    obj = tmp_path / "statics.o"
    subprocess.run([_CC, "-c", "-O0", "-o", str(obj), str(src)], check=True, capture_output=True)
    data = obj.read_bytes()
    assert [name for name, _c, _r in parse_elf_obj(data)] == ["shown"]
    assert sorted(name for name, _c, _r in parse_elf_obj(data, include_local=True)) == [
        "hidden",
        "shown",
    ]
