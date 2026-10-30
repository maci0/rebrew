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

`NONE`, `ASM_EXPAND`, and `ASM_SIMPLIFY` carry no direct operand patch; the
last two are linker relaxation hints. Rebrew does not perform relaxation.
Unknown relocation types, bundled/TIE instruction forms, unsupported branches,
missing bindings, and out-of-range operands fail comparison. Linker-relaxed
long calls and final literal-pool placement still require the matching core's
linker. Architecture support is not a claim of complete Xtensa ISA coverage.

The legacy offset-only parser refuses relocated Xtensa functions so GA/diff
clients cannot silently apply pointer-width masks. Relocation-free functions
remain available there. Capstone 5 has no Xtensa decoder; disassembly requests
fail explicitly and should use IDA or the matching `xt-objdump` instead.

## Validation

`tests/test_xtensa.py` covers ELF/config detection, real stock CALL8/L32R
encodings, exact resolved output, wrong-callee and adjacent-byte controls,
zero-address bindings, explicit addends, jump-range endpoints, malformed RELA
entries, and unsupported forms. A real XCC 14.04 assembly/link probe also
reproduced CALL8 and L32R bytes through Rebrew's compile-and-compare API.

Relocation numbering and hint semantics follow the
[Xtensa ELF relocation documentation](https://github.com/espressif/xtensa-isa-doc/blob/main/ELFRelocations.tex).
