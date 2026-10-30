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
lazy from rebrew.formats.binary_loader import decode_binary_name, load_binary, sniff_image_endian
lazy from rebrew.formats.xtensa import xtensa_symbol_relocations

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
    reference_path = getattr(cfg, "target_binary", None)
    reference = load_binary(Path(reference_path)) if reference_path is not None else None

    def native_section(address: int) -> Any:
        return (
            next(
                (s for s in reference.sections.values() if s.va <= address < s.va + s.raw_size),
                None,
            )
            if reference is not None
            else None
        )

    # Keep literal pools and callees in their native output section: XCC only
    # relaxes expanded calls when the callee has code-section affinity.
    groups: dict[str, list[tuple[int, str]]] = {}
    for name in sorted(reachable):
        if not _NAME.fullmatch(name):
            raise ValueError("invalid Xtensa input section name")
        address = addresses.get(name)
        if address is None or not 0 <= address <= 0xFFFFFFFF:
            raise ValueError(f"native Xtensa link needs a section binding for {name}")
        if address + sections[name].size > 0x100000000:
            raise ValueError("Xtensa section binding overflows ELF32")
        native = native_section(address)
        group = native.name if native is not None else name
        groups.setdefault(group, []).append((address, f'KEEP(input.o("{name}"))'))
    external = {
        decode_binary_name(r.symbol.name)
        for r in elf.relocations
        if r.section is not None
        and decode_binary_name(r.section.name) in reachable
        and r.symbol is not None
        and r.symbol.shndx == 0
        and r.symbol.name
    }
    call_names = (
        {name for _, kind, name, _, _ in xtensa_symbol_relocations(elf, target) if kind == 11}
        if external
        else set()
    )
    definitions = []
    anchors: dict[int, list[str]] = {}
    for name in sorted(external):
        address = addresses.get(name)
        if address is None or not _NAME.fullmatch(name) or not 0 <= address <= 0xFFFFFFFF:
            raise ValueError(f"native Xtensa link needs a symbol binding for {name}")
        native = native_section(address)
        if name in call_names and native is not None and native.is_code_section:
            anchors.setdefault(address, []).append(name)
        else:
            definitions.append(f"--defsym={name}=0x{address:x}")
    assembly = []
    for index, (address, names_at_address) in enumerate(sorted(anchors.items())):
        section_name = f".text.rebrew.bind.{index}"
        assembly.append(f'.section {section_name},"ax",@progbits')
        for name in names_at_address:
            assembly.extend([f".global {name}", f".type {name},@function", f"{name}:"])
        assembly.append(".byte 0")  # Address/type anchor only; never returned as recovered code.
        native = native_section(address)
        groups.setdefault(native.name, []).append((address, f'KEEP(anchors.o("{section_name}"))'))
    statements = []
    for name, entries in sorted(groups.items()):
        if not _NAME.fullmatch(name):
            raise ValueError("invalid Xtensa native section name")
        entries.sort()
        base = entries[0][0]
        if reference is not None and entries[-1][0] - base > len(reference.data):
            raise ValueError("Xtensa placement exceeds the file-backed native layout")
        contents = " ".join(
            f". = 0x{address - base:x}; {selector}" for address, selector in entries
        )
        statements.append(f'"{name}" 0x{base:x} : {{ {contents} }}')
    directory = writable_temp_dir("rebrew_xtensa_link_")
    try:
        shutil.copyfile(obj_path, directory / "input.o")
        (directory / "layout.ld").write_text(
            "SECTIONS {\n"
            + "\n".join(statements)
            + "\n/DISCARD/ : { *(.debug*) *(.text*) *(.literal*) *(.rodata*) *(.data*) *(.bss*) }\n}\n"
        )
        image_id = cached_image_digest(
            spec.image,
            runtime=cfg.execution_backend if cfg.execution_backend not in ("", "unshare") else None,
        )
        if assembly:
            (directory / "anchors.S").write_text("\n".join(assembly) + "\n")
            assembled = run_toolchain(
                spec,
                ["-c", "anchors.S", "-o", "anchors.o"],
                workdir=directory,
                timeout=cfg.compile_timeout,
                image_id=image_id,
                execution_backend=cfg.execution_backend,
            )
            if assembled.returncode:
                raise ValueError(
                    f"native Xtensa binding assembly failed: {assembled.stderr or assembled.stdout}"
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
                *(["anchors.o"] if assembly else []),
                "-o",
                "linked.elf",
            ],
            workdir=directory,
            timeout=cfg.compile_timeout,
            image_id=image_id,
            execution_backend=cfg.execution_backend,
        )
        if result.returncode:
            raise ValueError(f"native Xtensa linker failed: {result.stderr or result.stdout}")
        linked = lief.ELF.parse(str(directory / "linked.elf"))
        if linked is None:
            raise ValueError("native Xtensa linker did not produce an ELF image")
        linked_symbols = {decode_binary_name(s.name): s for s in linked.symtab_symbols}
        for name in external:
            bound = linked_symbols.get(name)
            if bound is None or bound.value != addresses[name]:
                raise ValueError(f"native Xtensa linker changed the binding for {name}")
        output = linked_symbols.get(target_name)
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
    if getattr(cfg, "endian", "") == "big" or (
        binary is not None and sniff_image_endian(binary) == "big"
    ):
        raise ValueError("big-endian Xtensa images are unsupported")
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
                "-D",
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
            image_id=cached_image_digest(
                spec.image,
                runtime=cfg.execution_backend
                if cfg.execution_backend not in ("", "unshare")
                else None,
            ),
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
