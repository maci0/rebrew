"""ops_replies.py — the dispatch replies rebrew declares, one TypedDict per closed reply.

Each declared reply is both the code's contract and the published one:
``tools/gen_dispatch_schema.py`` writes its JSON schema into the dispatch schema
(:func:`json_schema`), and the op answers :func:`project` of what it built, the
members the declaration names and nothing else, so the two cannot drift.  A
member the code builds that the declaration does not name is dropped and logged.

A reply that carries the verdict of a remote compile that never ran names why with
:data:`NotRunReason`, a closed set, and its error's structured fields
(:class:`NotRunError`), never the compile client's message.
"""

import logging
import types
from typing import (
    Any,
    Literal,
    NotRequired,
    Required,
    TypedDict,
    Union,
    get_args,
    get_origin,
    get_type_hints,
    is_typeddict,
)

log = logging.getLogger(__name__)

#: Why a remote compile has no verdict (status ``NOT_RUN``): the kind of the
#: recompile client's failure (``rebrew.compiler.recompile_client.RecompileErrorKind``),
#: or the code of a compiler that is not offered (``CompilerNotOffered.error_code``).
NotRunReason = Literal[
    "network",
    "http",
    "validation",
    "protocol",
    "service",
    "deadline",
    "compiler_withdrawn",
    "compiler_not_installed",
]


class RemoteCompile(TypedDict):
    """What an op's recompile calls cost (``rebrew.compiler.compile.RemoteCompiles.totals``)."""

    count: int
    billed_undelivered: int
    unsettled: int
    wait_ms: int


class ByteMismatch(TypedDict):
    """One byte of the compiled object that differs from the target."""

    offset: int
    target: str
    got: str


class NotRunError(TypedDict, total=False):
    """A ``NOT_RUN`` verdict's error (``RebrewError.to_dict``) without its message."""

    type: str
    retryable: bool
    kind: str | None
    name: str | None
    status_code: int | None
    group: str | None
    error_code: str | None
    retry_after: float | None


class FileDigest(TypedDict):
    """A file named by its path relative to the project, and its SHA-256."""

    path: str
    sha256: str


class CompileRecord(TypedDict, total=False):
    """What a remote compile ran with (``CompareResult.remote_compile``)."""

    flags: Required[list[str]]
    #: The service's execution provenance, verbatim (recompile ``ExecutionProvenance``).
    execution: Required[dict[str, Any] | None]
    source_dir: str
    includes: list[FileDigest]


class LogicalDocument(TypedDict):
    """A metadata settings document by its path and its logical digest."""

    path: str
    logical_sha256: str


class CompileInputs(TypedDict):
    """The files and documents a candidate's verdict was compiled from."""

    files: list[FileDigest]
    documents: list[LogicalDocument]


class RelocationBinding(TypedDict, total=False):
    """One relocated operand and what binds it (``rebrew.coff_reloc.relocation_binding_evidence``).

    A row read back from the verify cache lacks the members the cache stores as null.
    """

    offset: Required[int]
    symbol: Required[str]
    kind: str
    typed: bool
    status: Literal[
        "IGNORED",
        "OUT_OF_EXTENT",
        "UNSUPPORTED",
        "IAT_POLICY",
        "UNRESOLVED",
        "AMBIGUOUS",
        "VALIDATED",
        "CONFLICT",
    ]
    addend: int
    bound_va: int | None
    byte_order: str
    expected_value: int
    native_value: int


class OperandSpan(TypedDict, total=False):
    start: Required[int]
    end: Required[int]
    kind: Required[Literal["register", "immediate"]]
    value: Required[int]
    # set when the paired instruction's operand differs
    changed: bool


class ListedInstruction(TypedDict, total=False):
    offset: Required[int]
    bytes: Required[str]
    mnemonic: Required[str]
    operands: Required[str]
    spans: Required[list[OperandSpan]]
    # the rebuilt side: the relocation symbols inside the instruction
    symbols: list[str]


class ComparisonRow(TypedDict, total=False):
    op: Required[Literal["equal", "replace", "insert", "delete"]]
    left: Required[int | None]
    right: Required[int | None]
    reloc: bool


class InstructionComparison(TypedDict):
    """``rebrew.instruction_diff.instruction_diff``: the original and rebuilt listings paired."""

    max_bytes: int
    truncated: bool
    original: list[ListedInstruction]
    rebuilt: list[ListedInstruction]
    rows: list[ComparisonRow]


class VerifyRow(TypedDict, total=False):
    """One function's row of ``rebrew verify --json`` (``verify_cache.RESULT_FIELDS`` and the
    report-only members)."""

    va: Required[str]
    name: Required[str]
    symbol: Required[str]
    module: Required[str]
    filepath: Required[str]
    size: Required[int]
    status: Required[str]
    message: str
    passed: bool
    match_percent: float
    delta: int
    match_count: int | None
    total: int | None
    obj_size: int | None
    reloc_count: int | None
    diff_lines: int | None
    similarity: float | None
    reg_delta: int | None
    effective_match: bool
    context_hash: str | None
    relocation_bindings: list[RelocationBinding]
    source: str | None
    compile: CompileRecord | None
    instructions: InstructionComparison
    error: NotRunError
    not_run_reason: NotRunReason


class LibraryProviders(TypedDict):
    """How many library functions each kind of provider supplies."""

    compiled: int
    prebuilt: int
    unresolved: int


class VerifySummary(TypedDict):
    """``rebrew verify``'s counts."""

    total: int
    passed: int
    failed: int
    exact: int
    reloc: int
    stub: int
    matching: int
    size_mismatch: int
    compile_error: int
    not_run: int
    missing_file: int
    byte_matched: int
    library_passed: int
    library_total: int
    library_providers: LibraryProviders
    library_excluded: int
    orphans_pruned: int
    inventory_count: int


class SizeFix(TypedDict, total=False):
    """An annotation size that differs from the binary's, or is missing."""

    va: Required[str]
    annotation_size: Required[int]
    binary_size: Required[int]
    name: Required[str]
    module: Required[str]
    status: str


class DuplicateVa(TypedDict):
    """A VA two sources claim: the one kept and the one dropped."""

    va: str
    kept: str
    dropped: str


class LibraryProvider(TypedDict, total=False):
    """Who supplies one library function (``function_providers.resolve_library_providers``)."""

    va: Required[str]
    name: Required[str]
    provider: Required[Literal["compiled", "prebuilt", "unresolved"]]
    file: str
    symbol: str
    library: str
    member: str


class SpliceMismatch(TypedDict):
    """A function ``rebrew build round-trip`` could not splice, and why."""

    symbol: str
    va: str
    status: str
    reason: str
    detail: str | None


class FencedNaked(TypedDict):
    """Naked functions the round trip fenced off, and their VAs."""

    count: int
    vas: list[str]


class HeaderParity(TypedDict):
    """One PE header field of the original and the rebuilt image."""

    field: str
    original: int | None
    reasm: int | None
    match: bool
    configured: int | None


class ByteCoverage(TypedDict):
    """How much of ``.text`` the rebuilt image splices, proves, or passes through."""

    text_size: int
    spliced_bytes: int
    proven_bytes: int
    passthrough_bytes: int
    spliced_pct: float
    passthrough_pct: float


class VerifyFunctionReply(TypedDict, total=False):
    """``rebrew.verify_function``: the ``rebrew test --json`` result of one source."""

    source: Required[str]
    symbol: Required[str]
    va: Required[str]
    size: Required[int]
    status: Required[str]
    match_count: Required[int]
    total: Required[int]
    reloc_count: Required[int]
    obj_size: Required[int]
    context_hash: Required[str | None]
    mismatches: Required[list[ByteMismatch]]
    compile: Required[CompileRecord | None]
    remote_compile: Required[RemoteCompile]
    not_run_reason: NotRunReason
    error: NotRunError
    relocation_bindings: list[RelocationBinding]
    aligned_pairs: int
    target_instructions: int
    candidate_instructions: int
    hunks: int
    similarity: float
    instructions: InstructionComparison
    compile_inputs: CompileInputs
    verdict_valid: bool


class TargetReportReply(TypedDict, total=False):
    """``rebrew.verify_target`` (``rebrew verify --json``) and ``rebrew.build``'s report members.

    ``results`` rows of status ``NOT_RUN`` carry ``not_run_reason`` in place of
    the compile client's message.  The commands' ``binary`` (the target's path)
    and ``out`` (where the rebuilt image was written) are not declared: a path of
    the engine's host never leaves it, and no consumer reads either.
    """

    remote_compile: Required[RemoteCompile]
    # rebrew verify --json
    schema_version: int
    provenance: str
    timestamp: str
    target: str
    context_hash: str | None
    dry_run: bool
    summary: VerifySummary
    size_divergences: list[SizeFix]
    missing_sizes: list[SizeFix]
    duplicate_vas: list[DuplicateVa]
    results: list[VerifyRow]
    libraries: list[LibraryProvider]
    functions_checked: bool
    raw_link_status_suppressed: bool
    sizes_fixed: int
    sizes_protected: list[SizeFix]
    skipped: bool
    reason: str
    arch: str
    # rebrew build round-trip --json
    sha256_original: str
    sha256_reasm: str
    match: bool
    strict_catalog: bool
    spliced: int
    skipped_proven: int
    skipped_other: int
    fenced_naked: FencedNaked
    skipped_catalog: list[SpliceMismatch]
    mismatches: list[SpliceMismatch]
    reason_counts: dict[str, int]
    header_parity: list[HeaderParity]
    byte_coverage: ByteCoverage


class LibraryCandidate(TypedDict):
    va: str
    name: str
    module: str
    kind: Literal["crt", "flirt", "import"]
    confidence: float


class IdentifyLibraryReply(TypedDict):
    sigs_written: int
    identified: int
    already_annotated: int
    to_write: int
    written: int
    candidates: list[LibraryCandidate]
    unreadable_signatures: list[str]


class CoverageSummary(TypedDict):
    total_functions: int
    matched_functions: int
    total_code: int
    matched_code: int
    fuzzy_match_percent: float
    units: int
    # trusted coverage only: the library account
    original_code: NotRequired[int]
    library_functions: NotRequired[int]
    library_code: NotRequired[int]
    library_verified_functions: NotRequired[int]
    library_verified_code: NotRequired[int]


class CoverageMeasures(TypedDict):
    fuzzy_match_percent: float
    total_code: int
    matched_code: int
    matched_code_percent: float
    total_data: int
    matched_data: int
    matched_data_percent: float
    total_functions: int
    matched_functions: int
    matched_functions_percent: float
    complete_code: int
    complete_code_percent: float
    complete_data: int
    complete_data_percent: float
    total_units: int
    complete_units: int
    original_code: NotRequired[int]
    library_functions: NotRequired[int]
    library_code: NotRequired[int]
    library_verified_functions: NotRequired[int]
    library_verified_code: NotRequired[int]


class CoverageUnitMeasures(TypedDict):
    total_code: int
    matched_code: int
    fuzzy_match_percent: float
    total_functions: int
    matched_functions: int


class CoverageFunction(TypedDict):
    name: str
    size: int
    fuzzy_match_percent: float
    address: int


class CoverageUnit(TypedDict):
    name: str
    measures: CoverageUnitMeasures
    functions: list[CoverageFunction]


class CoverageDocument(TypedDict):
    """objdiff's ``report.json``, version 2, as ``rebrew coverage report --decomp-dev`` writes it."""

    version: int
    measures: CoverageMeasures
    units: list[CoverageUnit]


class CoverageReportReply(TypedDict):
    summary: CoverageSummary
    report: CoverageDocument


class CfgBlock(TypedDict):
    va: str
    size: int
    instruction_count: int
    first: str
    last: str


CfgEdge = TypedDict(
    "CfgEdge",
    {
        "from": str,
        "to": str,
        "back_edge": bool,
        "kind": Literal["taken", "not_taken", "unconditional", "switch"],
    },
)


class ControlFlowGraphReply(TypedDict):
    va: str
    size: int
    block_count: int
    block_total: int
    block_cap: int
    truncated: bool
    note: str | None
    blocks: list[CfgBlock]
    edges: list[CfgEdge]


class Xref(TypedDict):
    kind: str
    from_va: int
    instruction: str | None


class XrefsReply(TypedDict):
    target: int
    import_name: str | None
    count: int
    refs: list[Xref]


class DescribeCaller(TypedDict):
    from_va: int
    name: str


class DescribeCallee(TypedDict):
    to_va: int
    name: str | None
    kind: str


class DescribeString(TypedDict):
    va: int
    text: str


class DescribeGlobal(TypedDict):
    va: int
    kind: str


class DescribeImport(TypedDict):
    slot: int
    name: str


class DescribeReply(TypedDict):
    va: int
    name: str
    status: str | None
    size: int | None
    cflags: str | None
    pattern: str | None
    convention: str | None
    callers: list[DescribeCaller]
    callees: list[DescribeCallee]
    strings: list[DescribeString]
    globals: list[DescribeGlobal]
    imports: list[DescribeImport]


class RecoveredStruct(TypedDict):
    name: str
    anonymous: bool
    new: bool
    definition: str
    offsets: list[str]
    evidence: int
    # anonymous structs only
    semantic: NotRequired[bool]
    var: NotRequired[str]
    va: NotRequired[int]
    functions: NotRequired[int]


class StructsReply(TypedDict, total=False):
    # 0 when no function was selected, which answers no other count
    functions: int
    decompiled: int
    skipped: int
    structs: Required[list[RecoveredStruct]]


class ImportEntry(TypedDict):
    dll: str
    name: str
    iat_va: str
    ordinal: int | None
    hint_name_rva: str | None


class ImportStub(TypedDict):
    va: str
    name: str


class ImportsReply(TypedDict):
    imports: list[ImportEntry]
    stubs: list[ImportStub]


class StringXref(TypedDict):
    kind: str
    from_va: int


class FoundString(TypedDict):
    va: int
    section: str
    kind: str
    size: int
    text: str
    xrefs: list[StringXref]


class StringsReply(TypedDict):
    count: int
    strings: list[FoundString]


class SectionEntropy(TypedDict):
    name: str
    va: int
    vsize: int
    raw_size: int
    entropy: float


class FingerprintReply(TypedDict):
    md5: str
    sha1: str
    sha256: str
    sha512: str
    sha3_224: str
    sha3_256: str
    sha3_384: str
    sha3_512: str
    crc32: str
    format: str | None
    arch: str | None
    size: int
    imphash: str | None
    export_hash: str | None
    rich_header_hash: str | None
    section_entropies: list[SectionEntropy]
    # only when the hash's backend is installed
    tlsh: NotRequired[str | None]
    ssdeep: NotRequired[str | None]


class Vtordisp(TypedDict):
    va: str
    target: str
    disp: int
    addend: int
    size: int


class FloatConst(TypedDict):
    va: str
    size: int
    value: str


class MetaSection(TypedDict):
    name: str
    va: str
    size: int
    file_offset: int
    raw_size: int


class BinaryMeta(TypedDict):
    format: str
    image_base: int
    text_va: int
    text_size: int
    sections: list[MetaSection]


class DossierToolchain(TypedDict):
    family: str
    version_hint: str
    confidence: str
    detected_by: str
    flags: list[str]
    opt_level: str | None
    evidence: list[str]


class TopString(TypedDict):
    va: str
    size: int
    kind: str
    section: str
    refs: int
    text: str


class StringCensus(TypedDict):
    count: int
    top: list[TopString]


class DllCount(TypedDict):
    dll: str
    count: int


class DossierImport(TypedDict):
    dll: str
    name: str
    iat_va: str


class ImportSummary(TypedDict):
    count: int
    dlls: list[DllCount]
    iat_stubs: int
    entries: list[DossierImport]


class ReferenceProfile(TypedDict):
    total: int
    by_kind: dict[str, int]


class FarCall(TypedDict):
    selector: str
    offset: str
    count: int
    segment: int | None


class FunctionCoverage(TypedDict):
    total: int
    covered: int
    total_bytes: int


class NearMatch(TypedDict):
    va: str
    blocker: str


class DispatchTable(TypedDict):
    va: str
    section: str
    entries: int
    resolved: int


class FlirtSignatureMatch(TypedDict):
    va: str
    size: int
    name: str


class FlirtSection(TypedDict):
    signature_count: int
    matches: list[FlirtSignatureMatch]


class AnalyzeReply(TypedDict):
    meta: BinaryMeta
    toolchain: DossierToolchain | None
    strings: StringCensus
    imports: ImportSummary
    references: ReferenceProfile
    far_calls: list[FarCall] | None
    functions: FunctionCoverage | None
    near_match: list[NearMatch] | None
    dispatch_tables: list[DispatchTable]
    vtordisp: list[Vtordisp]
    float_consts: list[FloatConst]
    flirt: FlirtSection | None
    library: list[LibraryCandidate]


class CryptoFinding(TypedDict):
    kind: Literal["constant", "import", "name"]
    name: str
    confidence: Literal["high", "medium"]
    # a constant's place
    va: NotRequired[int]
    section: NotRequired[str]
    # an import's or a name's match
    detail: NotRequired[str]


class CryptoConfidence(TypedDict):
    high: int
    medium: int


class CryptoScanReply(TypedDict):
    findings: list[CryptoFinding]
    count: int
    by_confidence: CryptoConfidence


class ImageSection(TypedDict):
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    entropy: float | None
    characteristics_value: int
    characteristics: list[str]
    read: bool
    write: bool
    execute: bool


class SecurityFlags(TypedDict):
    """The DllCharacteristics mitigations and the load configuration's GS and SafeSEH."""

    dll_characteristics: int
    aslr: bool
    nx: bool
    cfg: bool
    gs: bool
    safe_seh: bool
    seh: bool
    high_entropy_va: bool
    force_integrity: bool
    isolation: bool
    certificate_table: bool


class SecurityItem(TypedDict):
    """One mitigation; ``enabled`` and ``flag`` are null when the image does not state it."""

    enabled: bool | None
    flag: int | None
    flag_name: str


class SecurityChecklist(TypedDict):
    aslr: SecurityItem
    dep: SecurityItem
    cfg: SecurityItem
    driver_model: SecurityItem
    app_container: SecurityItem
    terminal_server_aware: SecurityItem
    image_isolation: SecurityItem
    code_integrity: SecurityItem
    high_entropy: SecurityItem
    seh: SecurityItem
    bound_image: SecurityItem


class SecurityScore(TypedDict):
    enabled: int
    total: int


class PeExport(TypedDict):
    name: str
    va: int | None
    ordinal: int | None
    forwarder: str | None


class Authenticode(TypedDict):
    present: bool
    signature_count: int
    signers: list[str]


class DebugEntry(TypedDict, total=False):
    type: Required[str]
    # CodeView, when the image carries them
    pdb_path: str
    guid: str
    age: int


class RichEntry(TypedDict):
    id: int
    build_id: int
    count: int


class RichHeader(TypedDict, total=False):
    present: Required[bool]
    # when the header was parsed
    key: int
    entries: list[RichEntry]


class Presence(TypedDict):
    tls_directory: bool
    load_config: bool
    resources: bool
    relocations: bool
    exports: bool
    imports: bool


class DirectoryCounts(TypedDict):
    exports: int
    imports: int
    import_dlls: int
    relocations: int


class DelayImport(TypedDict):
    dll: str
    name: str | None
    ordinal: int | None
    va: int


class VersionInfo(TypedDict, total=False):
    company_name: str
    product_name: str
    file_version: str
    original_filename: str


class NeSegment(TypedDict):
    index: int
    file_offset: int
    size: int
    min_allocation: int
    flags: int
    kind: Literal["code", "data"]
    iterated: bool


class PeInfoReply(TypedDict, total=False):
    """The header facts of one image; which members it carries depends on ``format``."""

    format: Required[Literal["pe", "ne", "mz", "elf", "macho"]]
    arch: Required[str]
    bits: Required[int | None]
    image_base: Required[int | None]
    entry_point: Required[int]
    size: Required[int]
    # PE, ELF and Mach-O
    entry_bytes: str | None
    note: str
    sections: list[ImageSection]
    # PE
    type: str
    subsystem: str
    timestamp: int
    timestamp_iso: str
    checksum: int
    export_timestamp: int | None
    security_flags: SecurityFlags
    security: SecurityChecklist
    security_score: SecurityScore
    flags_summary: list[str]
    exports: list[PeExport]
    export_count: int
    resource_count: int
    authenticode: Authenticode
    debug: list[DebugEntry]
    rich_header: RichHeader
    presence: Presence
    counts: DirectoryCounts
    delay_imports: list[DelayImport] | None
    tls_callbacks: list[int] | None
    safe_seh_handlers: list[int] | None
    cfg_targets: list[int] | None
    version_info: VersionInfo | None
    # MZ and NE
    dos_stub_size: int
    # MZ
    code_size: int
    # NE
    module_name: str | None
    description: str | None
    target_os: str
    entry_address: str | None
    entry_segment: int
    entry_offset: int
    segment_count: int
    segments: list[NeSegment]
    imported_modules: list[str]


class FlirtMatch(TypedDict):
    va: str
    size: int
    names: list[str]


class FlirtAmbiguousMatch(TypedDict):
    va: str
    size: int
    names: list[str]
    more: bool


class ReferenceFlirtReply(TypedDict):
    signature_count: int
    text_size: int
    min_size: int
    match_count: int
    skipped_ambiguous: int
    matches: list[FlirtMatch]
    ambiguous_matches: list[FlirtAmbiguousMatch]
    # code sections smaller than a match window
    warning: NotRequired[str]


#: A security finding's severity and confidence; the dispatch schema writes its values
#: from ``rebrew.security_scan.SEVERITY_ORDER`` (``tools/gen_dispatch_schema.py``).
Level = Literal["high", "medium", "low"]


class SecurityFinding(TypedDict):
    rule: str
    cwe: str
    severity: Level
    confidence: Level
    file: str
    line: int
    function: str
    snippet: str
    message: str


class SecuritySeverities(TypedDict):
    high: int
    medium: int
    low: int


class SecurityScanReply(TypedDict):
    #: the reversed sources' directory, relative to the project
    root: str
    files_scanned: int
    findings: list[SecurityFinding]
    count: int
    by_severity: SecuritySeverities


class StructuralSimilarity(TypedDict):
    """``rebrew.matcher.core.StructuralSimilarity`` of the best candidate against the target."""

    total_insns: int
    exact: int
    reloc_only: int
    register_only: int
    structural: int
    mnemonic_match_ratio: float
    structural_ratio: float
    flag_sensitive: bool


class FlagSearchRow(TypedDict, total=False):
    # flag sweep
    score: float
    flags: str
    exact: bool
    # toolchain sweep
    toolchain: str
    matched: bool
    bytes: str
    # toolchain and flag sweep: score, flags and exact as a flag sweep's
    best_score: float | None


class FlagSearchReply(TypedDict, total=False):
    """``rebrew match flags`` or ``match toolchains``: a count, a flag sweep or a toolchain sweep."""

    remote_compile: Required[RemoteCompile]
    # count_only
    candidates: int
    # flag sweep
    symbol: str
    mode: str
    tier: str
    best_score: float | None
    best_flags: str | None
    exact: bool
    structural_similarity: StructuralSimilarity
    # flag sweep and toolchain sweeps
    results: list[FlagSearchRow]
    # toolchain sweeps
    sweep: str
    best: str | None
    not_installed: list[str]


class LibraryOwner(TypedDict, total=False):
    """Which library a global belongs to, from the link map and its archives."""

    symbol: Required[str]
    library: Required[str]
    member: Required[str]
    map_hash: Required[str]
    evidence: Required[Literal["link-map", "link-map+archive-symbol"]]
    # link-map: where the map places it
    linked_va: str
    # link-map+archive-symbol: the archive the symbol was found in
    archive_hash: str


class GlobalVariable(TypedDict):
    name: str
    type: str
    va: NotRequired[str]
    section: NotRequired[str]
    declared_in: list[str]
    defined_in: list[str]
    referenced_in: list[str]
    library_owners: list[LibraryOwner]
    storage_kind: str
    size: int | None
    backing: str
    link_symbol: str
    generated_owners: list[str]
    annotated: bool
    conflict: NotRequired[bool]


class DataSummary(TypedDict):
    total: int
    annotated: int
    unannotated: int
    data_entries: int
    conflicts: int
    multiple_definitions: int
    library_owned: int


class DataSection(TypedDict):
    va: str
    size: int


class DataAnnotation(TypedDict):
    """A data binding (``rebrew.data_scan.scan_data_annotations``)."""

    va: str
    name: str
    size: int
    section: str
    note: str
    filepath: str


class TypeConflict(TypedDict):
    name: str
    #: each declared type and the files declaring it
    types: dict[str, list[str]]


class DataListReply(TypedDict):
    globals: dict[str, GlobalVariable]
    data_annotations: list[DataAnnotation]
    type_conflicts: list[TypeConflict]
    summary: DataSummary
    sections: dict[str, DataSection]


class DataSetRow(TypedDict, total=False):
    va: Required[str]
    module: Required[str]
    # the fields the call set
    name: str
    type: str
    section: str
    kind: str
    note: str
    storage_kind: str
    backing: str
    link_symbol: str
    file: str
    size: int


class DataSetReply(TypedDict):
    dry_run: bool
    input_digest: str
    changed: int
    set: list[DataSetRow]


class ReleaseReply(TypedDict):
    release: str
    schema_sha256: str


#: Members the command an op runs prints that its reply withholds, by op: each is a
#: path of the engine's host, which never leaves it, and no consumer reads it.  A
#: member of a list's items is ``<list>[].<member>`` (a library row's link ``map``), and
#: of an object's values ``<object>.*.<member>``.
WITHHELD: dict[str, tuple[str, ...]] = {
    # data, text and whole_binary are the --data, --text and --whole-binary checks, which
    # the op never asks for, so they are always null (and data's link_map is a host path)
    "rebrew.verify_target": ("binary", "libraries[].map", "data", "text", "whole_binary"),
    "rebrew.build": ("binary", "out"),
    "rebrew.analyze": ("binary",),
    "rebrew.crypto_scan": ("binary",),
    "rebrew.imports": ("binary",),
    "rebrew.pe_info": ("binary",),
    "rebrew.strings": ("binary",),
    "rebrew.reference_flirt": ("binary", "sig_dirs"),
    "rebrew.flag_search": ("source",),
    # the file new definitions went to; the op writes none, so it is always null
    "rebrew.structs": ("applied",),
    "rebrew.data_list": ("globals.*.library_owners[].map",),
}

#: The reply members that name a path in the engine's workspace, by op (``<list>[].<member>``
#: for a list's items): the project an analysis wrote, its coverage snapshots, each target's
#: document and binary, and a report's site.  The dispatch schema declares each as
#: a string of ``format`` ``workspace-path``; no other member of any reply names a path of
#: the engine's host.
WORKSPACE_PATHS: dict[str, tuple[str, ...]] = {
    "rebrew.analyse": ("project", "coverage_dir", "targets[].document", "targets[].path"),
    "rebrew.import-project": ("project", "coverage_dir", "targets[].document", "targets[].path"),
    "rebrew.import_archive": ("project", "coverage_dir", "targets[].document", "targets[].path"),
    "rebrew.report": ("out",),
}

#: The op each declared reply answers.
DECLARED: dict[str, Any] = {
    "rebrew.verify_function": VerifyFunctionReply,
    "rebrew.verify_target": TargetReportReply,
    "rebrew.build": TargetReportReply,
    "rebrew.identify_library": IdentifyLibraryReply,
    "rebrew.coverage_report": CoverageReportReply,
    "rebrew.analyze": AnalyzeReply,
    "rebrew.control_flow_graph": ControlFlowGraphReply,
    "rebrew.crypto_scan": CryptoScanReply,
    "rebrew.data_list": DataListReply,
    "rebrew.data_set": DataSetReply,
    "rebrew.describe": DescribeReply,
    "rebrew.fingerprint": FingerprintReply,
    "rebrew.flag_search": FlagSearchReply,
    "rebrew.imports": ImportsReply,
    "rebrew.pe_info": PeInfoReply,
    "rebrew.reference_flirt": ReferenceFlirtReply,
    "rebrew.security_scan": SecurityScanReply,
    "rebrew.strings": StringsReply,
    "rebrew.structs": StructsReply,
    "rebrew.xrefs": XrefsReply,
    "rebrew.release": ReleaseReply,
}


def _members(declared: Any) -> tuple[dict[str, Any], set[str]]:
    hints = get_type_hints(declared, include_extras=True)
    members: dict[str, Any] = {}
    for name, hint in hints.items():
        if get_origin(hint) in (Required, NotRequired):
            (hint,) = get_args(hint)
        members[name] = hint
    return members, set(declared.__required_keys__)


def _optional_inner(hint: Any) -> tuple[Any, bool]:
    if get_origin(hint) in (Union, types.UnionType):
        args = [arg for arg in get_args(hint) if arg is not type(None)]
        nullable = len(args) != len(get_args(hint))
        if len(args) == 1:
            return args[0], nullable
    return hint, False


_PRIMITIVES = {str: "string", int: "integer", float: "number", bool: "boolean"}


def json_schema(hint: Any) -> dict[str, Any]:
    """The JSON schema of the type *hint*: a TypedDict, a primitive, a list, a dict or a Literal."""
    inner, nullable = _optional_inner(hint)
    schema: dict[str, Any]
    if is_typeddict(inner):
        members, required = _members(inner)
        schema = {
            "additionalProperties": False,
            "properties": {name: json_schema(member) for name, member in members.items()},
            "type": "object",
        }
        # The backend's renderer omits an empty ``required``.
        if names := [name for name in members if name in required]:
            schema["required"] = names
    elif get_origin(inner) is Literal:
        schema = {"enum": list(get_args(inner)), "type": "string"}
    elif get_origin(inner) is list:
        (item,) = get_args(inner)
        schema = {"items": json_schema(item), "type": "array"}
    elif get_origin(inner) is dict and get_args(inner)[1] is not Any:
        schema = {"additionalProperties": json_schema(get_args(inner)[1]), "type": "object"}
    elif inner is dict or get_origin(inner) is dict:
        schema = {"type": "object"}
    elif inner in _PRIMITIVES:
        schema = {"type": _PRIMITIVES[inner]}
    else:
        raise TypeError(f"no JSON schema for {inner!r}")
    # The backend's renderer writes a nullable member this way and has no ``type`` array.
    return {"oneOf": [schema, {"type": "null"}]} if nullable else schema


def project(value: dict[str, Any], declared: Any, where: str) -> dict[str, Any]:
    """The members of *value* the TypedDict *declared* names, nested declared ones projected too.

    A member *value* holds that the declaration does not name is dropped and logged
    with *where*, so a reply carries exactly what the schema publishes; with
    :data:`rebrew.config.STRICT_REPLIES_ENV` set it raises :class:`ValueError`.
    """
    members, _required = _members(declared)
    dropped = sorted(set(value) - set(members))
    if dropped:
        import os

        from rebrew.config import STRICT_REPLIES_ENV, parse_env_bool

        strict = os.environ.get(STRICT_REPLIES_ENV, "")
        if parse_env_bool(STRICT_REPLIES_ENV, strict, default=False):
            raise ValueError(f"{where}: undeclared reply members {', '.join(dropped)}")
        log.warning("%s: dropped undeclared reply members %s", where, ", ".join(dropped))
    out: dict[str, Any] = {}
    for name, item in value.items():
        if name not in members:
            continue
        inner, _nullable = _optional_inner(members[name])
        if is_typeddict(inner) and isinstance(item, dict):
            item = project(item, inner, f"{where}.{name}")
        elif get_origin(inner) is list and isinstance(item, list):
            (element,) = get_args(inner)
            if is_typeddict(element):
                item = [
                    project(row, element, f"{where}.{name}") if isinstance(row, dict) else row
                    for row in item
                ]
        elif get_origin(inner) is dict and isinstance(item, dict):
            value_type = get_args(inner)[1]
            if is_typeddict(value_type):
                item = {
                    key: project(row, value_type, f"{where}.{name}")
                    if isinstance(row, dict)
                    else row
                    for key, row in item.items()
                }
        out[name] = item
    return out
