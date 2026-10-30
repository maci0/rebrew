# Xtensa ELF targets

Use `format = "elf"` and `arch = "xtensa"` for little-endian ELF32 Xtensa
firmware. Header detection recognizes `EM_XTENSA`; pointer width is four bytes.
The current implementation deliberately rejects big-endian objects.

Register the compiler with a TOML file in `REBREW_TOOLCHAIN_OVERLAY_DIR`:

```toml
["xtensa-xcc-14.04-aw_axi_cfg0"]
image = "reforge/xtensa-xcc:14.04-ri2020.4-aw_axi_cfg0"
binary = "xt-xcc"
image_entrypoint = "xt-xcc"
runtime = "native"
flags_style = "posix"
obj_ext = ".o"
bits = 32
```

This is an operator-supplied image, not a distributed Rebrew compiler image.
Set `[compiler].profile` to the profile name. Compilation uses the existing
Docker runner, immutable image admission, and compile cache.

## Relocations and verdicts

LIEF parses the ELF layout and symbols but does not currently preserve Xtensa
relocation types. Rebrew decodes standard ELF32 RELA entries from the section
contents LIEF exposes, retaining explicit addends and section-local references.

The typed compile/compare path applies `R_XTENSA_32` and `R_XTENSA_SLOT0_OP`
for standard 24-bit `CALL0/4/8/12`, `L32R`, and `J` instructions. It checks
bounds, alignment, address range, opcode/register bits, and neighboring bytes.
External symbols need catalog bindings; section-local references use the
function's native VA. None of these operands receives a four-byte mask.
A successful comparison returns the resolved bytes and earns `EXACT` only
when every function byte agrees. Literal-pool contents remain separate data
that must also be reconstructed and compared for whole-image equality.

## Core-aware XCC backend

With an image-backed `xt-xcc` profile, compile/compare invokes that image's
`xt-ld` at the requested function VA. The admitted compiler image ID is also
the linker image ID. The real core linker resolves bundled/TIE instruction
operands and performs its normal relaxation. Rebrew returns and compares the
linked bytes, including any changed function length; it never copies target
bytes into the object or masks instruction operands.

The function's input section is anchored automatically. Every other referenced
allocated section (including literal pools) needs its native section-base VA in
the symbol-binding map. Undefined symbols need their native symbol VAs. Missing,
contradictory, overflowing or overlapping placements fail rather than inventing
layout. Whole-image reconstruction still owns data contents and section order.

`rebrew binary asm show` and the shared byte-disassembly API use the image's
`xt-objdump`, covering core-specific bundled/TIE instructions without Capstone.
The image view preserves the original ELF instruction/property metadata. Raw
byte views cannot infer literal pools or padding boundaries. Decoder output is
checked for complete coverage and exact agreement with the supplied bytes.

The pure relocation API continues to handle standard 24-bit operands without a
compiler image. Unknown forms fail explicitly there. The legacy offset-only
parser refuses relocated Xtensa functions: clients that cannot supply native
placement/bindings must use the typed compile/compare path, not four-byte masks.
Big-endian Xtensa objects remain outside this little-endian firmware backend.

## Validation

`tests/test_xtensa.py` covers ELF/config detection, real stock CALL8/L32R
encodings, exact resolved output, wrong-callee and adjacent-byte controls,
zero-address bindings, explicit addends, jump-range endpoints, malformed RELA
entries, and unsupported forms. A real XCC 14.04 assembly/link probe also
reproduced CALL8 and L32R bytes through Rebrew's compile-and-compare API. The
recovered stock `fls` source matches all 95 bytes through the native linker,
including its bundled conditional branches; native disassembly covers every
byte of that same stock window.

Relocation numbering and hint semantics follow the
[Xtensa ELF relocation documentation](https://github.com/espressif/xtensa-isa-doc/blob/main/ELFRelocations.tex).
