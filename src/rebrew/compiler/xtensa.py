"""Resolve core-specific Xtensa instructions with the admitted XCC linker."""

from __future__ import annotations

import re
lazy import shutil
lazy from dataclasses import replace
lazy from pathlib import Path
lazy from typing import Any

lazy import lief

lazy from rebrew.compiler import toolchain as registry
lazy from rebrew.compiler.temp_dirs import writable_temp_dir
lazy from rebrew.compiler.toolchain import ToolchainError, cached_image_digest, run_toolchain
lazy from rebrew.formats.binary_loader import decode_binary_name

_NAME = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$-]*\Z")


def link_xtensa_function(
    cfg: Any,
    obj_path: str | Path,
    symbol: str,
    section_va: int,
    bindings: dict[str, int] | None,
    toolchain: str | None = None,
) -> bytes:
    """Return native linked function bytes; require explicit referenced-section VAs.

    The core-aware linker owns bundled/TIE encodings and relaxation. No bytes
    from the reference image enter the link, and unresolved sections fail closed.
    """
    profile = toolchain or cfg.compiler_profile
    spec = registry.TOOLCHAINS.get(profile)
    if spec is None or not spec.image or spec.binary != "xt-xcc":
        raise ValueError("core-specific Xtensa relocation requires an image-backed xt-xcc profile")
    elf = lief.ELF.parse(str(obj_path))
    if elf is None or elf.header.machine_type != lief.ELF.ARCH.XTENSA:
        raise ValueError("native Xtensa link requires an Xtensa object")
    names = (symbol, symbol[1:] if symbol.startswith("_") else "_" + symbol)
    target = next(
        (
            s
            for name in names
            for s in elf.symtab_symbols
            if s.name == name and s.section is not None
        ),
        None,
    )
    if target is None or target.section is None:
        raise ValueError("native Xtensa link requires a function section")
    target_name = decode_binary_name(target.name)
    root_section = decode_binary_name(target.section.name)
    if not _NAME.fullmatch(target_name):
        raise ValueError("native Xtensa link requires a valid function symbol")
    addresses = dict(bindings or {})
    if target_name in addresses and addresses[target_name] != section_va:
        raise ValueError("Xtensa function binding contradicts its requested VA")
    addresses[root_section] = section_va - target.value
    reachable = {root_section}
    while True:
        added = {
            decode_binary_name(r.symbol.section.name)
            for r in elf.relocations
            if r.section is not None
            and decode_binary_name(r.section.name) in reachable
            and r.symbol is not None
            and r.symbol.section is not None
            and int(r.symbol.section.flags) & 2
        }
        if added <= reachable:
            break
        reachable |= added
    sections = {
        decode_binary_name(s.name): s
        for s in elf.sections
        if decode_binary_name(s.name) in reachable
    }
    statements = []
    for name in sorted(reachable):
        if not _NAME.fullmatch(name):
            raise ValueError("invalid Xtensa input section name")
        address = addresses.get(name)
        if address is None or not 0 <= address <= 0xFFFFFFFF:
            raise ValueError(f"native Xtensa link needs a section binding for {name}")
        if address + sections[name].size > 0x100000000:
            raise ValueError("Xtensa section binding overflows ELF32")
        statements.append(f'"{name}" 0x{address:x} : {{ KEEP(input.o("{name}")) }}')
    external = {
        decode_binary_name(r.symbol.name)
        for r in elf.relocations
        if r.section is not None
        and decode_binary_name(r.section.name) in reachable
        and r.symbol is not None
        and r.symbol.shndx == 0
        and r.symbol.name
    }
    definitions = []
    for name in sorted(external):
        address = addresses.get(name)
        if address is None or not _NAME.fullmatch(name) or not 0 <= address <= 0xFFFFFFFF:
            raise ValueError(f"native Xtensa link needs a symbol binding for {name}")
        definitions.append(f"--defsym={name}=0x{address:x}")
    directory = writable_temp_dir("rebrew_xtensa_link_")
    try:
        shutil.copyfile(obj_path, directory / "input.o")
        (directory / "layout.ld").write_text(
            "SECTIONS {\n"
            + "\n".join(statements)
            + "\n/DISCARD/ : { *(.debug*) *(.text*) *(.literal*) *(.rodata*) *(.data*) *(.bss*) }\n}\n"
        )
        linker = replace(spec, binary="xt-ld", image_entrypoint="xt-ld")
        result = run_toolchain(
            linker,
            [
                "--gc-sections",
                "--entry=" + target_name,
                "-T",
                "layout.ld",
                *definitions,
                "input.o",
                "-o",
                "linked.elf",
            ],
            workdir=directory,
            timeout=cfg.compile_timeout,
            image_id=cached_image_digest(spec.image),
            execution_backend=cfg.execution_backend,
        )
        if result.returncode:
            raise ValueError(f"native Xtensa linker failed: {result.stderr or result.stdout}")
        linked = lief.ELF.parse(str(directory / "linked.elf"))
        output = (
            next(
                (s for s in linked.symtab_symbols if decode_binary_name(s.name) == target_name),
                None,
            )
            if linked is not None
            else None
        )
        if (
            output is None
            or output.section is None
            or output.value != section_va
            or not output.size
        ):
            raise ValueError("native Xtensa linker did not preserve the requested function VA")
        offset = output.value - output.section.virtual_address
        code = bytes(output.section.content)[offset : offset + output.size]
        if len(code) != output.size:
            raise ValueError("native Xtensa function extends outside linked section")
        return code
    except ToolchainError as exc:
        raise ValueError(f"native Xtensa linker unavailable: {exc}") from exc
    finally:
        shutil.rmtree(directory)


class XtensaInstruction:
    """One core-decoded instruction, retaining the exact input bytes."""

    def __init__(self, address: int, raw: bytes, mnemonic: str, operands: str) -> None:
        self.address = address
        self.bytes = raw
        self.mnemonic = mnemonic
        self.op_str = operands
        self.size = len(raw)


def disassemble_xtensa(
    cfg: Any, code: bytes, va: int, *, binary: Path | None = None
) -> list[XtensaInstruction]:
    """Decode a byte window with the matching core's objdump rather than Capstone."""
    spec = registry.TOOLCHAINS.get(cfg.compiler_profile)
    if spec is None or not spec.image or spec.binary != "xt-xcc":
        raise ValueError("Xtensa disassembly requires an image-backed xt-xcc profile")
    if va < 0 or va + len(code) > 0x100000000:
        raise ValueError("Xtensa disassembly window overflows ELF32")
    if not code:
        return []
    directory = writable_temp_dir("rebrew_xtensa_asm_")
    try:
        if binary is None:
            (directory / "input.bin").write_bytes(code)
            arguments = [
                "-D",
                "-z",
                "-EL",
                "-b",
                "binary",
                "-m",
                "xtensa",
                f"--adjust-vma={va}",
                "input.bin",
            ]
        else:
            shutil.copyfile(binary, directory / "input.elf")
            arguments = [
                "-d",
                "-z",
                f"--start-address={va}",
                f"--stop-address={va + len(code)}",
                "input.elf",
            ]
        result = run_toolchain(
            replace(spec, binary="xt-objdump", image_entrypoint="xt-objdump"),
            arguments,
            workdir=directory,
            timeout=cfg.compile_timeout,
            image_id=cached_image_digest(spec.image),
            execution_backend=cfg.execution_backend,
        )
        if result.returncode:
            raise ValueError(f"native Xtensa disassembler failed: {result.stderr or result.stdout}")
        instructions = []
        consumed = 0
        for line in result.stdout.splitlines():
            match = re.match(r"^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]+)\s+(.+)", line)
            if match is None:
                continue
            address = int(match[1], 16)
            raw = bytes.fromhex(match[2])
            if code[consumed : consumed + len(raw)] != raw:
                raw = raw[::-1]
            if address != va + consumed or code[consumed : consumed + len(raw)] != raw:
                raise ValueError("Xtensa disassembly bytes disagree with the requested input")
            text = match[3].split(None, 1)
            instructions.append(
                XtensaInstruction(address, raw, text[0], text[1] if len(text) > 1 else "")
            )
            consumed += len(raw)
        if consumed != len(code):
            raise ValueError("Xtensa disassembly did not cover the complete byte window")
        return instructions
    except ToolchainError as exc:
        raise ValueError(f"native Xtensa disassembler unavailable: {exc}") from exc
    finally:
        shutil.rmtree(directory)
