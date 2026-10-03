# Global ownership and users

Read when consolidating headers, investigating multiple files per global, separating
CRT/game data, or repairing inventory gaps.

A definition allocates storage and is its owner. An `extern` declaration lets a
translation unit refer to it; the declaration site and functions that use the symbol
are separate facts. A DATA/GLOBAL annotation identifies an address, not an owner.
Many users are normal. Multiple definitions of the same externally linked symbol
are a defect unless a documented linker mechanism selects exactly one.

Use three questions per object:

1. Where are its bytes defined: one game translation unit or a stock library member?
2. Which header supplies the canonical type and address declaration?
3. Which translation units actually reference it, and which only redeclare it?

Keep game declarations in game/subsystem headers and CRT declarations in a single
CRT header, all with `extern`. Keep initialized game constants with their subsystem.
Address ranges and `.data`/`.rdata`/`.bss` describe physical placement; they do not
turn game floats or VFS strings into CRT data. Application allocator state is game
storage even when its names resemble the CRT heap.

When the CRT is fully linked, remove obsolete reconstructed CRT definitions after
checking that the build uses stock library storage. Retain declarations and
annotations for analysis. Do not add tentative definitions to make extern-only
inventory entries look owned. Do not copy runtime bytes into game source, patch a
`.lib`, or hide duplicates with `/FORCE:MULTIPLE`. A justified local displacement
needs the exact symbols/member and reference evidence recorded.

For an interior address, record the backing allocation and offset. A pointer field
at `table + 0x54` is a four-byte view, not a second full table. Historical symbol
spellings may be retained for a demonstrated compiler-order constraint, but they
must have no independent storage and must be documented as views. Complete extents
are needed for data verification; matching a prefix proves only the prefix.

Section-span annotations describe unknown bytes or alignment, not independently
owned objects. Keep these inventory facts separate from canonical game and CRT
headers. Check existing spans, complete array bounds, stock objects, and the PE
zero-filled virtual tail before emitting padding for a gap.

Consolidate redundant externs by including the canonical header. Preserve C types,
array bounds, constness, and calling conventions. On compilers such as VC6, even an
unused declaration can affect code generation: stage the header change and compare
known matches. Retain and document any required declaration-order exception rather
than allocating a fake symbol.

Header generators and data-label imports group by section and can overwrite a
curated split. Preview or generate to a temporary path, then reconcile declarations
with their logical owners. Update managed metadata through CLI/locked APIs. After
consolidation, inventory and lint again, reverify affected functions, and compare
the raw link/import table if definitions or link inputs changed. Distinguish an
unknown source owner from a library owner established by map/archive evidence.

`rebrew data` separates source `defined_in` from `library_owners`. Its default
library evidence is the MSVC map beside configured `raw_link`; select another with
`--link-map`. Library owners name the archive member and actual link symbol,
with map hash and linked VA. Resolve `<common>` only from a unique definition in
an already-cached configured archive member that the map independently selected.
An undefined zero-valued COFF reference, an unselected archive definition, or a
DLL import slot is not a static library storage owner. If several selected members
supply COMMON storage, leave its provider unresolved. Do not match descriptive
aliases to a library merely because their reference VA coincides with a map VA.
