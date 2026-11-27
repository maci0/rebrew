"""Typed wire request dataclasses for ``rebrew.ops``."""

from __future__ import annotations

from dataclasses import dataclass, field

lazy from rebrew.compiler.recompile_client import Attribution

# ---------------------------------------------------------------------------
# Requests (field names and required fields follow the backend's Go types)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DisassembleRequest:
    project_dir: str
    va: int
    size: int
    format: str
    sha256: str = ""
    arch: str = ""


@dataclass(frozen=True)
class DisassembleBytesRequest:
    code: bytes
    va: int
    arch: str


@dataclass(frozen=True)
class AddressRequest:
    project_dir: str
    sha256: str
    va: int


@dataclass(frozen=True)
class SizedAddressRequest(AddressRequest):
    size: int = 0


@dataclass(frozen=True)
class XrefsRequest(AddressRequest):
    kinds: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DecompileRequest:
    project_dir: str
    sha256: str
    va: int
    backend: str
    named: bool


@dataclass(frozen=True)
class ProjectRequest:
    project_dir: str


@dataclass(frozen=True)
class BinaryFile:
    binary_id: int
    sha256: str
    name: str
    key: str = ""
    url: str = ""


@dataclass(frozen=True)
class CoverageInputEntry:
    path: str
    present: bool
    origin: str
    digest: str
    size: int


@dataclass(frozen=True)
class CoverageInput:
    """The retained coverage envelope; a request that sends one sends every field."""

    version: int
    source_revision: str
    generation: str
    binary_sha256: str
    target: str
    readset: list[CoverageInputEntry]
    analysis_manifest: str
    verification_digest: str


def _no_coverage_input() -> CoverageInput:
    """What a request without ``coverage_input`` carries: version 0, nothing else."""
    return CoverageInput(0, "", "", "", "", [], "", "")


@dataclass(frozen=True)
class CoverageVerification:
    verification_id: str
    source: str
    source_sha256: str
    va: int
    size: int
    status: str
    match_count: int
    total: int
    obj_size: int
    reloc_count: int
    result_digest: str


@dataclass(frozen=True)
class ReportRequest:
    binary_id: int
    project_dir: str
    output_dir: str
    sha256: str = ""
    files: list[RetainedFile] = field(default_factory=list)
    rebrew_target: str = ""
    binary_key: str = ""
    binary_url: str = ""
    coverage_input: CoverageInput = field(default_factory=_no_coverage_input)
    coverage_input_digest: str = ""
    verification_records: list[CoverageVerification] = field(default_factory=list)


@dataclass(frozen=True)
class SecurityScanRequest:
    binary_id: int
    project_dir: str
    min_severity: str


@dataclass(frozen=True)
class AnalyseRequest:
    binary_id: int
    sha256: str
    name: str
    file_key: str = ""
    url: str = ""
    project_id: str = ""


@dataclass(frozen=True)
class ImportArchiveRequest:
    binary_id: int
    sha256: str
    archive_sha256: str
    archive_key: str = ""
    archive_url: str = ""
    project_id: str = ""


@dataclass(frozen=True)
class ImportRequest:
    project_dir: str
    snapshots: str = ""
    build_db: bool = False


@dataclass(frozen=True)
class OperandFunction:
    va: int
    size: int
    locations: list[tuple[int, int]]


@dataclass(frozen=True)
class OperandLocationsRequest:
    sha256: str
    functions: list[OperandFunction]
    file: str = ""
    url: str = ""


@dataclass(frozen=True)
class StructsRequest:
    binary_id: int
    project_dir: str
    decompiler: str
    limit: int


@dataclass(frozen=True)
class Extent:
    va: int
    size: int


@dataclass(frozen=True)
class FunctionDigestsRequest:
    sha256: str
    functions: list[Extent]
    file: str = ""
    url: str = ""


@dataclass(frozen=True)
class StoredFile:
    sha256: str
    file: str = ""
    url: str = ""


@dataclass(frozen=True)
class SplatRequest:
    config: str


@dataclass(frozen=True)
class TargetRequest:
    project_dir: str
    sha256: str = ""


@dataclass(frozen=True)
class DataListRequest:
    project_dir: str
    sha256: str = ""
    files: list[RetainedFile] = field(default_factory=list)
    rebrew_target: str = ""
    binary_key: str = ""
    binary_url: str = ""
    coverage_input: CoverageInput = field(default_factory=_no_coverage_input)
    coverage_input_digest: str = ""
    verification_records: list[CoverageVerification] = field(default_factory=list)


@dataclass(frozen=True)
class CoverageReportRequest(TargetRequest):
    files: list[RetainedFile] = field(default_factory=list)
    rebrew_target: str = ""
    binary_key: str = ""
    binary_url: str = ""
    coverage_input: CoverageInput = field(default_factory=_no_coverage_input)
    coverage_input_digest: str = ""
    verification_records: list[CoverageVerification] = field(default_factory=list)


@dataclass(frozen=True)
class ReferenceFlirtRequest:
    project_dir: str
    format: str
    signatures: StoredFile
    min_size: int
    sha256: str = ""


@dataclass(frozen=True)
class VerifyRequest:
    project_dir: str
    source: str = ""
    sha256: str = ""
    no_promote: bool = False
    candidate: str = ""
    va: int = 0
    size: int = 0
    files: list[RetainedFile] = field(default_factory=list)
    rebrew_target: str = ""
    source_sha256: str = ""
    binary_key: str = ""
    binary_url: str = ""
    cflags: str = ""
    project_cflags: str = ""
    instructions: bool = False
    attribution: Attribution | None = None


@dataclass(frozen=True)
class ApplyCandidateRequest:
    """``verify_function`` in promote mode: the same retained inputs, and the files it changed come back."""

    project_dir: str
    source: str = ""
    sha256: str = ""
    candidate: str = ""
    va: int = 0
    size: int = 0
    files: list[RetainedFile] = field(default_factory=list)
    rebrew_target: str = ""
    source_sha256: str = ""
    binary_key: str = ""
    binary_url: str = ""
    cflags: str = ""
    project_cflags: str = ""
    attribution: Attribution | None = None


@dataclass(frozen=True)
class VerifyTargetRequest:
    project_dir: str
    sha256: str = ""
    no_promote: bool = False
    files: list[RetainedFile] = field(default_factory=list)
    rebrew_target: str = ""
    binary_key: str = ""
    binary_url: str = ""
    project_cflags: str = ""
    instructions: bool = False
    attribution: Attribution | None = None


@dataclass(frozen=True)
class BuildRequest:
    project_dir: str
    sha256: str = ""
    fix_headers: bool = False
    files: list[RetainedFile] = field(default_factory=list)
    rebrew_target: str = ""
    binary_key: str = ""
    binary_url: str = ""
    project_cflags: str = ""
    attribution: Attribution | None = None


@dataclass(frozen=True)
class SkeletonRequest:
    project_dir: str
    va: int
    sha256: str = ""
    name: str = ""


@dataclass(frozen=True)
class RetainedFile:
    """One file of a retained manifest: its snapshot-relative ``path``, SHA-256 and size.

    Exactly one of ``key`` (a filestore key) and ``url`` (a presigned HTTPS
    URL) names where its bytes are fetched from.
    """

    path: str
    digest: str
    size: int
    key: str = ""
    url: str = ""


@dataclass(frozen=True)
class VocabularyRequest:
    """No fields: the vocabulary is the worker's own."""


@dataclass(frozen=True)
class ReleaseRequest:
    """No fields: the release is the worker's own."""


@dataclass(frozen=True)
class CheckCflagsRequest:
    cflags: str


@dataclass(frozen=True)
class IdentifierRename:
    old: str
    new: str


@dataclass(frozen=True)
class RenameIdentifierRequest:
    source: str
    renames: list[IdentifierRename]


@dataclass(frozen=True)
class FileSetRequest:
    files: list[RetainedFile]


@dataclass(frozen=True)
class MetadataDiffRequest:
    before: list[RetainedFile]
    after: list[RetainedFile]


@dataclass(frozen=True)
class MetadataCarryRequest:
    capture: list[RetainedFile]
    target: list[RetainedFile]


@dataclass(frozen=True)
class DecompileSnapshotRequest:
    project_dir: str
    sha256: str
    va: int
    backend: str
    rebrew_target: str
    source_revision: str
    source_snapshot_sha256: str
    source_manifest: str
    files: list[RetainedFile]
    generation: str
    analysis_manifest_sha256: str
    analysis_manifest: str
    analysis_files: list[RetainedFile]
    binary_key: str = ""
    binary_url: str = ""
    attested_registry_digest: str = ""


@dataclass(frozen=True)
class SecuritySnapshotRequest:
    project_dir: str
    sha256: str
    rebrew_target: str
    source_revision: str
    source_snapshot_sha256: str
    source_manifest: str
    files: list[RetainedFile]
    generation: str
    analysis_manifest: str
    analysis_manifest_sha256: str
    analysis_files: list[RetainedFile]
    min_severity: str
    binary_key: str = ""
    binary_url: str = ""
    attested_registry_digest: str = ""


@dataclass(frozen=True)
class FlagSearchRequest:
    source: str
    source_sha256: str
    va: int
    files: list[RetainedFile]
    rebrew_target: str
    sha256: str = ""
    binary_key: str = ""
    binary_url: str = ""
    tier: str = "targeted"
    toolchains: str = ""
    exclude_toolchains: str = ""
    compare_toolchains: bool = False
    with_flags: bool = False
    #: Answer ``{"candidates": N}``, the compiles the search would make (a ceiling),
    #: and compile nothing.
    count_only: bool = False
    attribution: Attribution | None = None


@dataclass(frozen=True)
class DataSetRequest:
    project_dir: str
    va: int
    sha256: str = ""
    name: str = ""
    type: str = ""
    size: int = 0
    section: str = ""
    kind: str = ""
    note: str = ""
    storage_kind: str = ""
    backing: str = ""
    link_symbol: str = ""
    source_file: str = ""
    dry_run: bool = False


@dataclass(frozen=True)
class SnapshotMutationRequest:
    files: list[RetainedFile]
    rebrew_target: str
    sha256: str
    binary_key: str
    operation: str
    binary_url: str = ""
    source: str = ""
    candidate: str = ""
    candidate_sha256: str = ""
    generations: int = 1
    population: int = 1
    seed: int = 0
    va: int = 0
    name: str = ""
    type: str = ""
    size: int = 0
    section: str = ""
    kind: str = ""
    note: str = ""
    storage_kind: str = ""
    backing: str = ""
    link_symbol: str = ""
    source_file: str = ""
    old_name: str = ""
    new_name: str = ""
    sources: list[str] = field(default_factory=list)
    output: str = ""
    dry_run: bool = False
    #: ``variants`` only: answer ``{"result": {"candidates": N}}``, the compiles the
    #: search would make (a ceiling), and compile nothing.
    count_only: bool = False
    attribution: Attribution | None = None
