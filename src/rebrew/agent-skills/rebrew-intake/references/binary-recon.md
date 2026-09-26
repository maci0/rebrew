# Optional binary recon (fingerprint / PE / crypto / source security)

Run these after doctor when you need identity or threat surface before triage.
None of them are required for the core intake path.

## Binary dossier

```bash
rebrew analyze --json                      # one-shot intelligence dossier for the target binary
rebrew analyze original/<filename>         # analyze a specific binary
```

Combines binary layout (format/sections), toolchain detection, strings,
imports/IAT stubs, reference profile, reversed-function coverage, dispatch
tables, and FLIRT into one report.

## Fingerprints

```bash
rebrew fingerprints --json                 # fingerprint the target binary
rebrew fingerprints original/<filename>    # fingerprint a specific binary
```

Returns streamed digests (md5/sha1/sha256/sha512, SHA-3 family, crc32), imphash,
export hash, Rich-header hash, and per-section entropy. Cheap build-identity
checks: `imphash`, `export_hash`, `rich_header_hash`; `format` / `arch` confirm
the toolchain family intake assumes.

## PE metadata

```bash
rebrew pe-info --json                      # metadata for the target binary
rebrew pe-info original/<filename>         # metadata for a specific binary
```

Dumps headers/sections (entropy + `IMAGE_SCN_*`), exports, resources,
DllCharacteristics mitigations, Authenticode summary, debug directory
(CodeView PDB path/GUID/age), and Rich header. ELF/Mach-O get shared identity
fields plus a note that PE-only metadata is unavailable.

## Strings

```bash
rebrew strings --json                      # extract strings with sections and references
rebrew strings --xref                      # show referencing code addresses
rebrew strings --filter <regex>            # filter by string content
```

## Crypto constants / imports

```bash
rebrew crypto-scan --json                  # scan the target binary for crypto
rebrew crypto-scan original/<filename>     # scan a specific binary
```

AES/SHA/MD5 constant tables and crypto imports are `high` confidence;
crypto-named project functions are `medium`. Empty findings are valid.

## Source security scan

```bash
rebrew security-scan --json                       # project's reversed sources
rebrew security-scan src/<target>/                # explicit C tree
rebrew security-scan --min-severity high          # high only
```

Tree-sitter AST match for unbounded copies (CWE-120), non-literal format strings
(CWE-134), command execution (CWE-78), unchecked `memcpy` (CWE-787), weak
randomness (CWE-338), non-literal `alloca` (CWE-770). Findings are review
indicators, not exploit proof.
