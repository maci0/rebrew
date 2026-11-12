# Rebrew Metadata Format

All canonical source state lives in dedicated TOML stores (functions format 3; data format 2) at
`cfg.metadata_dir`. The only Rebrew syntax in C is an optional ADDRESS comment
immediately above the next declaration; see [source addresses](ANNOTATIONS.md).
Ordinary readers reject old inline blocks and older metadata formats. The explicit
`source consolidate` operation upgrades reviewed format-2 function/source stores;
preview with `--dry-run --json`, then apply with its `--expected-digest`.

Never hand-edit these files. Use the CLI or the owning metadata APIs, which
validate writes, lock the edit, and persist through the selected backend. TOML
files and SQLite databases use mode 0444 at rest; PostgreSQL uses database
permissions.
Examples below illustrate managed output.

## Functions

```toml
format = 3

["SERVER.0x10001000"]
file = "src/tick.c"
symbol = "_tick"
name = "tick"
kind = "FUNCTION"
size = 32
cflags = "/O2 /Gd"
status = "STUB"
blocker = "needs structure layout"
```

Keys are qualified `MODULE.0xVA` identities, unique after Unicode/module and
hex-address normalization. Missing modules, duplicate spellings, unknown fields
and the retired `marker_type` field are rejected. Tools emit zero-padded addresses;
an existing qualified spelling is updated in place. `file` is relative to the
metadata root, and must not escape it. A row can have no file until a source or
library provider is established.

Identity fields are `file`, `symbol`, `name`, `kind`. Classification is independent
of comparison state: library origin is `kind = "LIBRARY"`, while the linked
provider must be verified separately. Function state includes `size`, `cflags`,
`toolchain`, `status`, `blocker`, `blocker_delta`, `note`, `ghidra`, `analysis`,
`skip`, `source`, `struct`, `callers`, `globals`, `locals`, `comments`, and
`prove_constraints`. Evidence and provenance fields (`verification`,
`similarity`, `status_history`, `binding_history`, `native_identity`,
`origins`, `updated_by`, `updated_at`) have their own writers.
`source = "naked"` records an assembly reconstruction and
is never a source comment. The authoritative field shapes are
`METADATA_FIELD_TYPES` in `rebrew.metadata.functions`.

`rebrew source register` records current declaration-bound identities and leaves
existing fields and verdicts intact. `record_function_identity` and
`record_function_rows` are the Python identity writers. `update_field`,
`remove_field` and batch forms edit ordinary state. STATUS is written only by
`update_source_status` / `update_statuses_batch` after comparison. EXACT and RELOC
are byte matches; PROVEN is semantic evidence and is overwritten by the next byte
comparison. Parked SKIP and unfinished STUB retain their documented writer rules.

`similarity` is an optional numeric percentage in `[0, 100]`, including zero.
Only the locked test/verify verdict writer sets it, copying
`verification.similarity` when it accepts the comparison. Generic setters and
removers refuse this field. A subsequent accepted comparison without a score
clears it; retiring or replacing a source binding clears the current score while
retaining it in binding history. Source, header, compiler, size and flag changes
make the score stale; live readers omit stale measurements until reverified.

The supporting non-negative integer counts (`aligned_pairs`,
`target_instructions`, `candidate_instructions`, `hunks`) stay in `verification`.
Similarity is diagnostic: it never promotes STATUS or contributes matched bytes.
Status JSON exposes `similarity` keyed by status, with `count` and `mean` in
percent. Catalog and coverage use the existing `similarity` field on a `[0, 1]`
scale, including durable receipts when the delete-safe verify cache is absent.
BinSync exports neither STATUS nor similarity.

## Data

```toml
format = 2

["SERVER.0x10025000"]
file = "src/tables.c"
kind = "DATA"
name = "lookup"
type = "const unsigned char[256]"
size = 256
section = ".rdata"
status = "UNCHECKED"
storage_kind = "object"
```

The data store uses the same qualified key algebra. It owns `file`, `kind`,
`name`, `type`, `size`, `section`, `note`, `status`, `storage_kind`, `backing`,
`link_symbol`, and the evidence/stamp tables below. Classifications are DATA,
GLOBAL, STRING and VTABLE; an unspecified kind is an ordinary DATA row.
`storage_kind` distinguishes objects, views, literals, layout spans and imports.
An interior address names a view into its backing object; it is not another
allocation. Extern declarations are declarations or users, not storage owners.

`record_data_rows`, `set_data_field`, `set_data_fields_batch` and the `rebrew data`
commands own edits. Definition, identity, placement and classification changes
invalidate the current verdict while retaining historical comparison evidence;
no-op edits and notes preserve it. `rebrew data move` changes a row's
address and drops its verdict while retaining the previous comparison evidence.
Update or remove a conflicting ADDRESS anchor before moving the row.

Data verification has its own verdicts (EXACT, VERIFIED, DISPLACED, DRIFT,
UNCHECKED), independent of function matches. EXACT includes checked placement;
VERIFIED records byte agreement without placement proof. Count overlapping initialized spans once and exclude BSS from
file-byte verification. Coverage documents and dashboards never establish owners.

## Evidence and edit stamps

Function and data rows may carry `origins` (accepted external fields and their
source facts), `verification` (comparison inputs, status, writer, input hash and
measurement time), `updated_by`, and `updated_at`. These are independent facts.
An ordinary edit must not rewrite the origin of an imported field or pretend to
be a fresh comparison. Previews and failed integration syncs never advance the
binary-scoped baseline. See [BinSync reconciliation](BINSYNC_INTEGRATION.md).

## Source purposes and assembly evidence

```toml
format = 3

[source.definitions]

[source.files."src/link_shims.c".SERVER]
purpose = "retains the reviewed native link layout"
```

`rebrew-functions.toml` holds a reserved `source` table with `definitions` and
`files`. `source.files` stores
a non-empty target-scoped purpose for support code without a native VA. Use
`rebrew source register FILE --support "reason"` or `set_source_file`.

Assembly records live under `source.definitions.<file>.<symbol>.<module>`, with exactly
`source_hash` and `evidence`. They identify reviewed original assembly by file,
C definition, target and current body digest; they do not earn STATUS. Use
`rebrew source document-assembly` or the provenance owner API. Rename/move writers
retarget both kinds of source records.

The complete store map is in [metadata ownership](METADATA.md). The breaking
source/format decision is [ADR 033](adr/033-consolidated-source-evidence.md).
