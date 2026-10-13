# Choose Tools Before Adding Project Scripts

Read the relevant `--help` from the installed Rebrew version. Command names and
options in old notebooks may have changed; run the current command rather than
copying the old implementation. `rebrew skills list --json` identifies packaged
and user-overridden skills.

| Need | Use first |
| --- | --- |
| Progress, inventory, next action | `rebrew status --json`, `rebrew todo --json`, `rebrew coverage catalog --json`; regenerate served documents with `rebrew coverage build --json` |
| Disassembly or binary structure | `rebrew binary asm show`, `rebrew binary pe`; use the loaders for VA/raw-byte reads |
| Static-library attribution and ownership | `rebrew library match`, `rebrew library inspect`; distinguish a masked template hit from a uniquely supported provider in the raw map |
| Pristine source plus patches | `rebrew library vendor MANIFEST...`; check by default, explicit `--sync` to regenerate |
| Rename, bind or reorganize source identities | `rebrew source rename`, `rebrew source merge`, `rebrew source split`, `rebrew library bind-source`; CLI writers preserve identity and provenance |
| Data rows, canonical declarations and extents | `rebrew data list`, `rebrew data set`, `rebrew types bind`; read the data-analysis ownership reference before emitting storage |
| Bare address operands or missing fixups | `rebrew source symbolize --dry-run`, `rebrew binary relocs --json` |
| Source ordering, linked placement and TU data | `rebrew build order-sources`, `rebrew build link-order`, `rebrew build check-text-placement`, `rebrew build check-data-placement`, `rebrew build check-tu-data` |
| Matched source, bound operands, raw whole file | `rebrew test`, `rebrew verify`, `rebrew build round-trip --dry-run`, `rebrew verify --whole-binary --built PATH` |

Use `--target NAME` where supported for a non-default target; binary-independent
commands such as vendoring take explicit paths instead. Add `--json` where offered
and consume the documented result, rather than scraping Rich tables.

## When the CLI Is Not Enough

Search public APIs before writing another parser or comparer. Reuse the binary
loaders for reference bytes, `coff_reloc` for relocation application/comparison,
`matcher.parsers` for object symbols/relocations, and the locked `metadata.functions` /
`metadata.data` writers for managed rows. Load configuration and source discovery
through Rebrew so the selected target, archive providers and compiler overrides
remain consistent. Do not import another module's underscore-private helpers.

An object RELOC verdict masks operands and is not a full native byte proof. For a
binary-specific proof, bind every claimed operand from native evidence, compare
the complete body, and include a rejecting wrong-binding control. Existing strict
comparison and round-trip APIs provide the mechanics; the target addresses,
backing extents and provenance remain project evidence. Do not infer ownership
from an extern declaration, turn a prefix/template hit into a provider claim, or
paste reference bytes into objects to make a verification gate green.

## Keep Experiments Small and Retire Them

A one-off binary-specific experiment is legitimate. Put it in ignored scratch,
record its inputs and exact command/result, and use the existing APIs. Do not
promote its hardcoded VAs, copied bytes or compiler accident into generic policy.
Keep an intentionally independent acceptance check independent and label its
purpose; that is different from a duplicate day-to-day verifier.

If several callers need the same missing operation, make it an upstream feature
when authorized: configure inputs, preserve error handling, add regression tests,
update command discovery and documentation, migrate callers and delete the local
implementation. Otherwise record the precise gap for follow-up. Local work does
not authorize publishing or starting live sync/watch loops. Repair the packaged
AGENTS template/skill when the cause was poor discovery, then refresh generated
copies with `rebrew init --refresh-agents`; preserve project-specific rules.
## Masked library wrappers

Whole relocation-masked bodies can resemble unrelated code. Check known direct
native callees before choosing a wrapper's name:

```bash
rebrew library match --stock-lib LIBCMT.LIB --va 0x<VA> --resolve-callees --json
```

Use the target's actual runtime archive (for example LIBC instead of LIBCMT),
and `--compile-commands` for its compiled source libraries. Inspect
`callee_resolution`: complete callee bodies reject contradictions; aliases,
self-calls and unavailable evidence remain unresolved. This checks one level,
not data relocations, an entire call graph or the actual linked provider.
