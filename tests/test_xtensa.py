"""Xtensa ELF detection and exact, bounded relocation regression checks."""

import struct
from pathlib import Path
from types import SimpleNamespace

import pytest
from bin_util import make_elf

from rebrew.coff_reloc import CoffRelocRecord, apply_coff_relocations, smart_reloc_compare
from rebrew.config import arch_pointer_size, load_config
from rebrew.formats.binary_loader import load_binary
from rebrew.formats.xtensa import apply_xtensa_relocation, xtensa_symbol_relocations


class TestXtensa:
    def test_architecture(self, tmp_path: Path) -> None:
        image = bytearray(make_elf(bytes.fromhex("3641001df0")))
        struct.pack_into("<H", image, 18, 94)
        binary = tmp_path / "dsp.elf"
        binary.write_bytes(image)
        assert load_binary(binary).arch == "xtensa"
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target="dsp"\n[targets.dsp]\nbinary="dsp.elf"\nformat="elf"\narch="xtensa"\n'
        )
        assert load_config(tmp_path).arch == "xtensa"
        assert arch_pointer_size("xtensa") == 4

    @pytest.mark.parametrize(
        ("raw", "destination", "expected", "pc"),
        [
            ("e50000a7", 0x320143A0, "e58308a7", 0x3200BB63),
            ("310000a7", 0x3200B01C, "3156fda7", 0x3200BAC3),
        ],
    )
    def test_native_encodings(self, raw: str, destination: int, expected: str, pc: int) -> None:
        buf = bytearray.fromhex(raw)
        apply_xtensa_relocation(buf, 0, 20, destination, pc)
        assert buf == bytes.fromhex(expected)

    def test_wrong_callee_register_and_adjacent_opcode(self) -> None:
        raw, target = bytes.fromhex("e50000a7"), bytes.fromhex("e58308a7")
        records = [CoffRelocRecord(0, 20, "callee", "elf-xtensa")]
        args = {"section_va": 0x3200BB63, "name_to_va": {"callee": 0x320143A0}}
        assert smart_reloc_compare(raw, target, records, **args)[0]
        for wrong in (bytes.fromhex("d58308a7"), bytes.fromhex("e58308a6")):
            assert not smart_reloc_compare(raw, wrong, records, **args)[0]
        assert not smart_reloc_compare(
            raw, target, records, section_va=0x3200BB63, name_to_va={"callee": 0x320143A4}
        )[0]
        assert not smart_reloc_compare(raw, raw, records, section_va=0x3200BB63)[0]

    def test_addend_and_zero_address(self) -> None:
        rec = CoffRelocRecord(0, 1, "global", "elf-xtensa", 7)
        assert apply_coff_relocations(b"\0" * 4, [rec], lambda _: 0, section_va=0) == b"\7\0\0\0"
        rec = CoffRelocRecord(0, 1, "", "elf-xtensa", 7, 0)
        assert apply_coff_relocations(b"\0" * 4, [rec], lambda _: None, section_va=0) == b"\7\0\0\0"

    @pytest.mark.parametrize(
        ("kind", "raw", "dest"),
        [
            (20, "e50000", 0x320143A1),
            (20, "e50000", 0x330143A0),
            (20, "310000", 0x3200BB64),
            (20, "310000", 0x31000000),
            (20, "1df000", 0x320143A0),
            (21, "e50000", 0x320143A0),
            (35, "e50000", 0x320143A0),
            (1, "000000", 0x320143A0),
            (1, "00000000", -1),
        ],
    )
    def test_invalid_fixups(self, kind: int, raw: str, dest: int) -> None:
        with pytest.raises((ValueError, NotImplementedError)):
            apply_xtensa_relocation(bytearray.fromhex(raw), 0, kind, dest, 0x3200BB63)

    def test_raw_rela_types_and_truncation(self) -> None:
        text = SimpleNamespace(name=".text.f", type=SimpleNamespace(name="PROGBITS"))
        target = SimpleNamespace(value=0, section=None, name="callee")
        rela = SimpleNamespace(
            type=SimpleNamespace(name="RELA"),
            information=0,
            link=2,
            entry_size=12,
            content=struct.pack("<IIi", 3, (1 << 8) | 20, -4),
            size=12,
        )
        elf = SimpleNamespace(
            header=SimpleNamespace(
                identity_class=SimpleNamespace(name="ELF32"),
                identity_data=SimpleNamespace(name="LSB"),
            ),
            sections=[text, rela, SimpleNamespace(type=SimpleNamespace(name="SYMTAB"))],
            symtab_symbols=[None, target],
        )
        function = SimpleNamespace(value=0, size=8, section=text, shndx=0)
        assert xtensa_symbol_relocations(elf, function) == [(3, 20, "callee", -4, None)]
        rela.content = rela.content[:-1]
        with pytest.raises(ValueError, match="truncated"):
            xtensa_symbol_relocations(elf, function)


class TestXtensaCompare:
    def test_compile_result_contains_resolved_bytes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.compiler.compile import _extract_and_compare

        raw, target = bytes.fromhex("e50000a7"), bytes.fromhex("e58308a7")
        records = [CoffRelocRecord(0, 20, "callee", "elf-xtensa")]
        monkeypatch.setattr(
            "rebrew.compiler.compile.parse_obj_symbol_and_relocs", lambda *_: (raw, {}, records)
        )
        result = _extract_and_compare(
            "unused.o", "probe", target, name_to_va={"callee": 0x320143A0}, section_va=0x3200BB63
        )
        assert result.matched and result.obj_bytes == target and result.delta == 0
        unresolved = _extract_and_compare("unused.o", "probe", raw, section_va=0x3200BB63)
        assert not unresolved.matched and unresolved.status == "EXTRACT_ERROR"
        from rebrew.compiler import xtensa

        calls = []

        def native(*args):
            calls.append(args)
            return target

        monkeypatch.setattr(xtensa, "link_xtensa_function", native)
        result = _extract_and_compare(
            "unused.o", "probe", target, section_va=0x3200BB63, cfg=SimpleNamespace(arch="xtensa")
        )
        assert result.matched and result.obj_bytes == target and calls

    @pytest.mark.parametrize("destination", [0x32001004 - 131072, 0x32001004 + 131071])
    def test_jump_range(self, destination: int) -> None:
        buf = bytearray.fromhex("060000a7")
        apply_xtensa_relocation(buf, 0, 20, destination, 0x32001000)
        encoded = int.from_bytes(buf[:3], "little") >> 6
        displacement = encoded - (1 << 18) if encoded & (1 << 17) else encoded
        assert 0x32001004 + displacement == destination and buf[3] == 0xA7

    def test_elf_symbol_decoration_matches_shared_parser(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import lief

        from rebrew.matcher.parsers import parse_obj_symbol_and_relocs, parse_obj_symbol_bytes

        code = bytes.fromhex("3641001df0")
        section = SimpleNamespace(content=code)
        symbol = SimpleNamespace(name="probe", section=section, value=0, size=len(code))
        elf = SimpleNamespace(
            header=SimpleNamespace(
                machine_type=lief.ELF.ARCH.XTENSA,
                identity_data=SimpleNamespace(name="LSB"),
                identity_class=SimpleNamespace(name="ELF32"),
            ),
            symtab_symbols=[symbol],
            sections=[],
        )
        path = tmp_path / "probe.o"
        path.write_bytes(b"\x7fELF")
        monkeypatch.setattr(lief.ELF, "parse", lambda *_: elf)
        assert parse_obj_symbol_and_relocs(path, "_probe") == (code, {}, [])
        assert parse_obj_symbol_bytes(path, "_probe") == (code, {})


class TestNativeCoreLinker:
    def test_core_link_uses_object_and_bindings_without_reference_bytes(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import lief

        from rebrew.compiler import xtensa
        from rebrew.compiler.toolchain_spec import ToolchainSpec

        code = bytes.fromhex("3641001df0")
        section = SimpleNamespace(name=".text.probe", size=7, flags=6)
        target = SimpleNamespace(name="probe", section=section, value=0, size=7)
        obj = SimpleNamespace(
            header=SimpleNamespace(machine_type=lief.ELF.ARCH.XTENSA),
            symtab_symbols=[target],
            sections=[section],
            relocations=[],
        )
        linked_section = SimpleNamespace(content=code, virtual_address=0x32001000)
        output = SimpleNamespace(name="probe", section=linked_section, value=0x32001000, size=5)
        linked = SimpleNamespace(symtab_symbols=[output])
        path = tmp_path / "input.o"
        path.write_bytes(b"operator object")
        monkeypatch.setattr(
            lief.ELF, "parse", lambda p: linked if str(p).endswith("linked.elf") else obj
        )
        spec = ToolchainSpec("xcc", "test/xcc:1", binary="xt-xcc")
        monkeypatch.setattr(xtensa.registry, "TOOLCHAINS", {"xcc": spec})
        monkeypatch.setattr(
            xtensa, "cached_image_digest", lambda _, **_kwargs: "sha256:" + "a" * 64
        )
        runs = []

        def run(spec, args, **kwargs):
            directory = kwargs["workdir"]
            assert (directory / "input.o").read_bytes() == b"operator object"
            assert '".text.probe" 0x32001000' in (directory / "layout.ld").read_text()
            assert spec.binary == "xt-ld" and spec.image_entrypoint == "xt-ld"
            assert kwargs["image_id"] == "sha256:" + "a" * 64
            assert not any("--defsym=probe=" in arg for arg in args)
            runs.append(directory)
            return SimpleNamespace(returncode=0)

        monkeypatch.setattr(xtensa, "run_toolchain", run)
        cfg = SimpleNamespace(
            compiler_profile="xcc", compile_timeout=60, execution_backend="docker"
        )
        assert (
            xtensa.link_xtensa_function(cfg, path, "_probe", 0x32001000, {"probe": 0x32001000})
            == code
        )
        assert not runs[0].exists()
        with pytest.raises(ValueError, match="contradicts"):
            xtensa.link_xtensa_function(cfg, path, "probe", 0x32001000, {"probe": 0x32001004})
        output.value += 4
        with pytest.raises(ValueError, match="requested function VA"):
            xtensa.link_xtensa_function(cfg, path, "probe", 0x32001000, {})
        output.value -= 4
        literal = SimpleNamespace(name=".literal.probe", flags=2, size=4)
        obj.relocations = [
            SimpleNamespace(
                section=section, symbol=SimpleNamespace(section=literal, name="", shndx=1)
            )
        ]
        obj.sections.append(literal)
        with pytest.raises(ValueError, match="section binding"):
            xtensa.link_xtensa_function(cfg, path, "probe", 0x32001000, {})


class TestNativeDisassembly:
    def test_decoding_is_checked_against_input(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.compiler import xtensa
        from rebrew.compiler.toolchain_spec import ToolchainSpec

        monkeypatch.setattr(
            xtensa.registry,
            "TOOLCHAINS",
            {"xcc": ToolchainSpec("xcc", "test/xcc:1", binary="xt-xcc")},
        )
        monkeypatch.setattr(
            xtensa, "cached_image_digest", lambda _, **_kwargs: "sha256:" + "a" * 64
        )
        response = SimpleNamespace(
            returncode=0, stdout="32001000:\t004136\tentry\ta1, 32\n32001003:\tf01d\tretw.n\n"
        )
        workdirs = []

        def run(spec, args, **kwargs):
            assert spec.binary == "xt-objdump"
            assert "-EL" in args and "-b" in args
            workdirs.append(kwargs["workdir"])
            return response

        monkeypatch.setattr(xtensa, "run_toolchain", run)
        cfg = SimpleNamespace(
            compiler_profile="xcc", compile_timeout=60, execution_backend="docker"
        )
        code = bytes.fromhex("3641001df0")
        insns = xtensa.disassemble_xtensa(cfg, code, 0x32001000)
        assert [(i.address, i.mnemonic, i.size) for i in insns] == [
            (0x32001000, "entry", 3),
            (0x32001003, "retw.n", 2),
        ]
        assert b"".join(i.bytes for i in insns) == code
        assert not workdirs[0].exists()
        response.stdout = response.stdout.replace("004136", "004137")
        with pytest.raises(ValueError, match="bytes disagree"):
            xtensa.disassemble_xtensa(cfg, code, 0x32001000)
        response.stdout = "32001000:\t004136\tentry\ta1, 32\n"
        with pytest.raises(ValueError, match="complete byte window"):
            xtensa.disassemble_xtensa(cfg, code, 0x32001000)


class TestNativeCallRelaxation:
    @pytest.mark.parametrize("backend", ["docker", "podman"])
    def test_link_preserves_section_affinity_and_external_addresses(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, backend: str
    ) -> None:
        import lief

        from rebrew.compiler import xtensa
        from rebrew.compiler.toolchain_spec import ToolchainSpec
        from rebrew.formats.binary_model import SectionInfo

        source_section = SimpleNamespace(name=".text.probe", size=8, flags=6)
        source_symbol = SimpleNamespace(name="probe", section=source_section, value=0, size=8)
        callee = SimpleNamespace(name="callee", section=None, shndx=0)
        obj = SimpleNamespace(
            header=SimpleNamespace(machine_type=lief.ELF.ARCH.XTENSA),
            symtab_symbols=[source_symbol],
            sections=[source_section],
            relocations=[SimpleNamespace(section=source_section, symbol=callee)],
        )
        output_section = SimpleNamespace(content=b"linked", virtual_address=0x32001000)
        output = SimpleNamespace(name="probe", section=output_section, value=0x32001000, size=6)
        bound = SimpleNamespace(name="callee", value=0x32002000)
        linked = SimpleNamespace(symtab_symbols=[output, bound])
        monkeypatch.setattr(
            lief.ELF, "parse", lambda p: linked if str(p).endswith("linked.elf") else obj
        )
        monkeypatch.setattr(
            xtensa, "xtensa_symbol_relocations", lambda *_: [(0, 11, "callee", 0, None)]
        )
        reference = SimpleNamespace(
            sections={".text": SectionInfo(".text", 0x32000000, 0x10000, 0, 0x10000, True)},
            data=b"\0" * 0x10000,
        )
        monkeypatch.setattr(xtensa, "load_binary", lambda _: reference)
        monkeypatch.setattr(
            xtensa.registry,
            "TOOLCHAINS",
            {"xcc": ToolchainSpec("xcc", "test/xcc:1", binary="xt-xcc")},
        )
        monkeypatch.setattr(
            xtensa, "cached_image_digest", lambda _, **_kwargs: "sha256:" + "a" * 64
        )
        tools = []

        def run(spec, args, **kwargs):
            directory = kwargs["workdir"]
            tools.append(spec.binary)
            if spec.binary == "xt-xcc":
                assembly = (directory / "anchors.S").read_text()
                assert ".type callee,@function" in assembly and ".byte 0" in assembly
            else:
                layout = (directory / "layout.ld").read_text()
                assert '".text" 0x32001000' in layout
                assert (
                    'input.o(".text.probe")' in layout
                    and 'anchors.o(".text.rebrew.bind.0")' in layout
                )
                assert ". = 0x1000;" in layout
                assert "--defsym=callee=0x32002000" not in args
                assert "anchors.o" in args
            return SimpleNamespace(returncode=0)

        monkeypatch.setattr(xtensa, "run_toolchain", run)
        path = tmp_path / "input.o"
        path.write_bytes(b"operator object")
        cfg = SimpleNamespace(
            compiler_profile="xcc",
            compile_timeout=60,
            execution_backend=backend,
            target_binary=tmp_path / "reference.elf",
        )
        assert (
            xtensa.link_xtensa_function(cfg, path, "probe", 0x32001000, {"callee": 0x32002000})
            == b"linked"
        )
        assert tools == ["xt-xcc", "xt-ld"]
        bound.value += 4
        with pytest.raises(ValueError, match="changed the binding for callee"):
            xtensa.link_xtensa_function(cfg, path, "probe", 0x32001000, {"callee": 0x32002000})

    def test_external_data_binding_uses_defsym(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        import lief

        from rebrew.compiler import xtensa
        from rebrew.compiler.toolchain_spec import ToolchainSpec

        section = SimpleNamespace(name=".text.probe", size=6, flags=6)
        target = SimpleNamespace(name="probe", section=section, value=0, size=6)
        external = SimpleNamespace(name="data", section=None, shndx=0)
        obj = SimpleNamespace(
            header=SimpleNamespace(machine_type=lief.ELF.ARCH.XTENSA),
            symtab_symbols=[target],
            sections=[section],
            relocations=[SimpleNamespace(section=section, symbol=external)],
        )
        output = SimpleNamespace(
            name="probe",
            section=SimpleNamespace(content=b"linked", virtual_address=0x32001000),
            value=0x32001000,
            size=6,
        )
        linked = SimpleNamespace(
            symtab_symbols=[output, SimpleNamespace(name="data", value=0x32002000)]
        )
        monkeypatch.setattr(
            lief.ELF, "parse", lambda path: linked if str(path).endswith("linked.elf") else obj
        )
        monkeypatch.setattr(
            xtensa, "xtensa_symbol_relocations", lambda *_: [(0, 1, "data", 0, None)]
        )
        monkeypatch.setattr(
            xtensa.registry,
            "TOOLCHAINS",
            {"xcc": ToolchainSpec("xcc", "test/xcc:1", binary="xt-xcc")},
        )
        monkeypatch.setattr(
            xtensa, "cached_image_digest", lambda _, **_kwargs: "sha256:" + "a" * 64
        )
        calls = []

        def run(spec, args, **_kwargs):
            assert spec.binary == "xt-ld" and "--defsym=data=0x32002000" in args
            calls.append(args)
            return SimpleNamespace(returncode=0)

        monkeypatch.setattr(xtensa, "run_toolchain", run)
        cfg = SimpleNamespace(
            compiler_profile="xcc", compile_timeout=60, execution_backend="docker"
        )
        path = tmp_path / "input.o"
        path.write_bytes(b"operator object")
        assert (
            xtensa.link_xtensa_function(cfg, path, "probe", 0x32001000, {"data": 0x32002000})
            == b"linked"
        )
        with pytest.raises(ValueError, match="symbol binding for data"):
            xtensa.link_xtensa_function(cfg, path, "probe", 0x32001000, {})
        assert len(calls) == 1


class TestXtensaReviewRegressions:
    def test_fallback_symbol_reaches_linker(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.compiler import compile as compiler
        from rebrew.compiler import xtensa

        raw = b"object"
        records = [CoffRelocRecord(0, 20, "callee", "elf-xtensa")]

        def parse(_path, symbol):
            return (raw, {}, records) if symbol == "probe" else (None, None, [])

        monkeypatch.setattr(compiler, "parse_obj_symbol_and_relocs", parse)
        received = []

        def link(_cfg, _path, symbol, *_args):
            received.append(symbol)
            return b"target"

        monkeypatch.setattr(xtensa, "link_xtensa_function", link)
        result = compiler._extract_and_compare(
            "unused.o",
            "_probe@4",
            b"target",
            section_va=0x32001000,
            cfg=SimpleNamespace(arch="xtensa"),
        )
        assert result.matched and received == ["probe"]

    def test_big_endian_elf_is_rejected_at_detection(self, tmp_path: Path) -> None:
        from rebrew.formats.binary_loader import detect_format_and_arch

        image = bytearray(make_elf(bytes.fromhex("3641001df0")))
        header = list(struct.unpack_from("<HHIIIIIHHHHHH", image, 16))
        header[1] = 94
        for index in range(header[9]):
            offset = header[4] + index * header[8]
            struct.pack_into(">8I", image, offset, *struct.unpack_from("<8I", image, offset))
        for index in range(header[11]):
            offset = header[5] + index * header[10]
            struct.pack_into(">10I", image, offset, *struct.unpack_from("<10I", image, offset))
        struct.pack_into(">HHIIIIIHHHHHH", image, 16, *header)
        image[5] = 2
        path = tmp_path / "big.elf"
        path.write_bytes(image)
        with pytest.raises(ValueError, match="little-endian ELF32"):
            detect_format_and_arch(path)
        with pytest.raises(ValueError, match="little-endian ELF32"):
            load_binary(path)

    def test_unsupported_inline_c_is_explicit(self) -> None:
        from rebrew.asm import generate_inline_c

        with pytest.raises(RuntimeError, match="XCC ignores the naked"):
            generate_inline_c(
                bytes.fromhex("3641001df0"), SimpleNamespace(arch="xtensa"), 0x32001000, "probe"
            )
