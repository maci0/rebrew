"""ops.py – The op worker the relumea backend dispatches rebrew calls to.

The backend names each call ``rebrew.<op>`` with a JSON request and reads a
JSON reply (contract: the backend's ``internal/engines/rebrew`` package and its
generated ``contracts/dispatch/rebrew.schema.json``).  One dispatcher serves two
transports:

``rebrew ops call <op>`` reads the request on stdin and writes the reply on
stdout.  A refusal writes ``{"error", "detail", "status"}`` on stdout and exits
``EXIT_ERROR``.

``rebrew ops serve --port N`` answers ``POST /<op>`` with the request as the
body, the same reply, and the refusal under its HTTP ``status``.  Every request
needs ``Authorization: Bearer $REBREW_OPS_TOKEN``; at most ``--concurrency``
calls run at once and the next one is answered 503 with ``Retry-After``.

Binaries are referenced, never carried in a request.  A stored binary is
either a filestore key resolved under ``--filestore`` (the backend's local
filestore directory) or a presigned HTTPS ``url`` downloaded into
``<workspace>/.scratch``; exactly one of the two is set, and the bytes must
hash to the request's ``sha256``.  An analysed binary is the ``project_dir`` of
its rebrew project; a request ``sha256`` selects the target whose binary has
that hash.  ``analyse`` creates a project-scoped directory under ``<workspace>/projects`` and
``report`` writes its relative ``output_dir`` under ``--workspace``.

Project paths (``project_dir``, ``snapshots``) must be absolute.  With a
workspace configured they must resolve, symlinks followed, inside it; ``serve``
always has one, so over HTTP no project path leaves the workspace.  Source and
output paths inside a project are project-relative and may not leave it.

Ops whose rebrew command prints its report instead of returning it run that
command as a child process in the project (:func:`run_rebrew`).  Ops that
compile refuse, while a remote compile backend is configured, a source whose
project headers cannot ship to it (:func:`remote_header_refusal`).

Engines that serve retained requests beside rebrew (recoverage) import three
names from here, documented in ``docs/PYTHON_API.md``: :class:`RetainedFile`,
:class:`WorkerConfig` and :func:`retained_target_snapshot`, whose refusals are
:class:`OpsError` (also exported by :mod:`rebrew.errors`).  The rest of this
module is the op worker's own.
"""

from __future__ import annotations

from dataclasses import dataclass
lazy import contextlib
lazy import json
lazy import logging
lazy import os
lazy import re
lazy import signal
lazy import sys
lazy import time as time
lazy from collections.abc import Callable, Mapping
lazy from pathlib import Path
lazy from typing import Any

import typer

from rebrew.call_progress import ProgressPipe as ProgressPipe
from rebrew.errors import RebrewError as RebrewError
from rebrew.metadata.bindings import BindingConflictError as BindingConflictError
from rebrew.ops.core import (
    ANALYSE_TIMEOUT_SECONDS as ANALYSE_TIMEOUT_SECONDS,
)
from rebrew.ops.core import (
    ANALYSIS_CAPTURE_FAILED as ANALYSIS_CAPTURE_FAILED,
)
from rebrew.ops.core import (
    ANALYSIS_REPORT_PATH as ANALYSIS_REPORT_PATH,
)
from rebrew.ops.core import (
    AUTO_DECOMPILER as AUTO_DECOMPILER,
)
from rebrew.ops.core import (
    BUSY_RETRY_AFTER_SECONDS as BUSY_RETRY_AFTER_SECONDS,
)
from rebrew.ops.core import (
    CALLER_GONE as CALLER_GONE,
)
from rebrew.ops.core import (
    CANCEL_POLL_SECONDS as CANCEL_POLL_SECONDS,
)
from rebrew.ops.core import (
    CANCELLATION_VAR as CANCELLATION_VAR,
)
from rebrew.ops.core import (
    CANDIDATE_ADDRESS_COMMENT as CANDIDATE_ADDRESS_COMMENT,
)
from rebrew.ops.core import (
    CANDIDATE_NAME_TAKEN as CANDIDATE_NAME_TAKEN,
)
from rebrew.ops.core import (
    CANDIDATE_NOT_ONE_FUNCTION as CANDIDATE_NOT_ONE_FUNCTION,
)
from rebrew.ops.core import (
    CFLAGS_MAX_CHARS as CFLAGS_MAX_CHARS,
)
from rebrew.ops.core import (
    CHILD_REPORT_SECONDS as CHILD_REPORT_SECONDS,
)
from rebrew.ops.core import (
    COMMAND_TIMEOUT_SECONDS as COMMAND_TIMEOUT_SECONDS,
)
from rebrew.ops.core import (
    COMPILE_NOT_RUN as COMPILE_NOT_RUN,
)
from rebrew.ops.core import (
    COMPILER_NOT_OFFERED as COMPILER_NOT_OFFERED,
)
from rebrew.ops.core import (
    COVERAGE_INPUT_UNVERIFIED as COVERAGE_INPUT_UNVERIFIED,
)
from rebrew.ops.core import (
    CROSS_ORIGIN as CROSS_ORIGIN,
)
from rebrew.ops.core import (
    DATA_FIELD_OPTIONS as DATA_FIELD_OPTIONS,
)
from rebrew.ops.core import (
    DATA_MARKERS as DATA_MARKERS,
)
from rebrew.ops.core import (
    DEADLINE_EXCEEDED as DEADLINE_EXCEEDED,
)
from rebrew.ops.core import (
    DECOMPILER_BACKENDS as DECOMPILER_BACKENDS,
)
from rebrew.ops.core import (
    DECOMPILER_NOT_OFFERED as DECOMPILER_NOT_OFFERED,
)
from rebrew.ops.core import (
    DECOMPILER_UNREACHABLE as DECOMPILER_UNREACHABLE,
)
from rebrew.ops.core import (
    DEFAULT_CONCURRENCY as DEFAULT_CONCURRENCY,
)
from rebrew.ops.core import (
    DEFAULT_MAX_DOWNLOAD_BYTES as DEFAULT_MAX_DOWNLOAD_BYTES,
)
from rebrew.ops.core import (
    DETAIL_MAX_CHARS as DETAIL_MAX_CHARS,
)
from rebrew.ops.core import (
    DIGEST_ALGORITHM as DIGEST_ALGORITHM,
)
from rebrew.ops.core import (
    DIGEST_MAX_FUNCTION_BYTES as DIGEST_MAX_FUNCTION_BYTES,
)
from rebrew.ops.core import (
    DIGEST_MAX_FUNCTIONS as DIGEST_MAX_FUNCTIONS,
)
from rebrew.ops.core import (
    DISASM_FORMATS as DISASM_FORMATS,
)
from rebrew.ops.core import (
    DISASSEMBLE_MAX_BYTES as DISASSEMBLE_MAX_BYTES,
)
from rebrew.ops.core import (
    DISPATCH_PROBLEMS as DISPATCH_PROBLEMS,
)
from rebrew.ops.core import (
    DISPATCH_PROGRESS_FD_ENV as DISPATCH_PROGRESS_FD_ENV,
)
from rebrew.ops.core import (
    DISPATCH_SCHEMA_SHA256 as DISPATCH_SCHEMA_SHA256,
)
from rebrew.ops.core import (
    DNS_RESOLUTION_LIMIT as DNS_RESOLUTION_LIMIT,
)
from rebrew.ops.core import (
    DNS_SLOTS as DNS_SLOTS,
)
from rebrew.ops.core import (
    DNS_TIMEOUT_SECONDS as DNS_TIMEOUT_SECONDS,
)
from rebrew.ops.core import (
    DOWNLOAD_CHUNK_BYTES as DOWNLOAD_CHUNK_BYTES,
)
from rebrew.ops.core import (
    DOWNLOAD_TIMEOUT_SECONDS as DOWNLOAD_TIMEOUT_SECONDS,
)
from rebrew.ops.core import (
    ENGINE_ERROR as ENGINE_ERROR,
)
from rebrew.ops.core import (
    EXITS as EXITS,
)
from rebrew.ops.core import (
    FAILED_STEP_VAR as FAILED_STEP_VAR,
)
from rebrew.ops.core import (
    FINAL_RECOMPILE_REFUSALS as FINAL_RECOMPILE_REFUSALS,
)
from rebrew.ops.core import (
    FLAG_SEARCH_TIERS as FLAG_SEARCH_TIERS,
)
from rebrew.ops.core import (
    FLIRT_FORMATS as FLIRT_FORMATS,
)
from rebrew.ops.core import (
    HOST_NOT_ALLOWED as HOST_NOT_ALLOWED,
)
from rebrew.ops.core import (
    IMPORT_TIMEOUT_SECONDS as IMPORT_TIMEOUT_SECONDS,
)
from rebrew.ops.core import (
    IN_PROCESS_TIMEOUT_SECONDS as IN_PROCESS_TIMEOUT_SECONDS,
)
from rebrew.ops.core import (
    INT64_MAX as INT64_MAX,
)
from rebrew.ops.core import (
    INT64_MIN as INT64_MIN,
)
from rebrew.ops.core import (
    INTAKE_TIMEOUT_SECONDS as INTAKE_TIMEOUT_SECONDS,
)
from rebrew.ops.core import (
    INVALID_PROJECT_CONFIG as INVALID_PROJECT_CONFIG,
)
from rebrew.ops.core import (
    INVALID_REQUEST as INVALID_REQUEST,
)
from rebrew.ops.core import (
    LATENCY_BUCKETS_MS as LATENCY_BUCKETS_MS,
)
from rebrew.ops.core import (
    MALFORMED_SIGNATURES as MALFORMED_SIGNATURES,
)
from rebrew.ops.core import (
    MAX_CONNECTIONS as MAX_CONNECTIONS,
)
from rebrew.ops.core import (
    MAX_READSET_BYTES as MAX_READSET_BYTES,
)
from rebrew.ops.core import (
    MAX_READSET_FILE_BYTES as MAX_READSET_FILE_BYTES,
)
from rebrew.ops.core import (
    MAX_READSET_FILES as MAX_READSET_FILES,
)
from rebrew.ops.core import (
    MAX_REPLY_BYTES as MAX_REPLY_BYTES,
)
from rebrew.ops.core import (
    MAX_REPORT_BYTES as MAX_REPORT_BYTES,
)
from rebrew.ops.core import (
    MAX_REPORT_FILES as MAX_REPORT_FILES,
)
from rebrew.ops.core import (
    MAX_REQUEST_BYTES as MAX_REQUEST_BYTES,
)
from rebrew.ops.core import (
    MAX_SKIPPED_RECORD_KEYS as MAX_SKIPPED_RECORD_KEYS,
)
from rebrew.ops.core import (
    METHOD_NOT_ALLOWED as METHOD_NOT_ALLOWED,
)
from rebrew.ops.core import (
    NASM_ARCH as NASM_ARCH,
)
from rebrew.ops.core import (
    NO_DECOMPILATION as NO_DECOMPILATION,
)
from rebrew.ops.core import (
    OP_PROBLEMS as OP_PROBLEMS,
)
from rebrew.ops.core import (
    OPERAND_MAX_FUNCTION_BYTES as OPERAND_MAX_FUNCTION_BYTES,
)
from rebrew.ops.core import (
    OPERAND_MAX_FUNCTIONS as OPERAND_MAX_FUNCTIONS,
)
from rebrew.ops.core import (
    OPERAND_MAX_INDEX as OPERAND_MAX_INDEX,
)
from rebrew.ops.core import (
    OPERAND_MAX_LOCATIONS as OPERAND_MAX_LOCATIONS,
)
from rebrew.ops.core import (
    PROBLEMS as PROBLEMS,
)
from rebrew.ops.core import (
    PROGRESS_MEDIA_TYPE as PROGRESS_MEDIA_TYPE,
)
from rebrew.ops.core import (
    PROGRESS_VAR as PROGRESS_VAR,
)
from rebrew.ops.core import (
    PROJECT_IMPORT_REFUSED as PROJECT_IMPORT_REFUSED,
)
from rebrew.ops.core import (
    READSET_TOO_LARGE as READSET_TOO_LARGE,
)
from rebrew.ops.core import (
    REMOTE_HEADERS as REMOTE_HEADERS,
)
from rebrew.ops.core import (
    RENAME_KINDS as RENAME_KINDS,
)
from rebrew.ops.core import (
    REPLY_HEADERS_VAR as REPLY_HEADERS_VAR,
)
from rebrew.ops.core import (
    REPORT_OUTPUT_INVALID as REPORT_OUTPUT_INVALID,
)
from rebrew.ops.core import (
    REQUEST_IDS as REQUEST_IDS,
)
from rebrew.ops.core import (
    REQUEST_LOCAL as REQUEST_LOCAL,
)
from rebrew.ops.core import (
    SCRATCH_DIR as SCRATCH_DIR,
)
from rebrew.ops.core import (
    SEARCH_TIMEOUT_SECONDS as SEARCH_TIMEOUT_SECONDS,
)
from rebrew.ops.core import (
    SHA256_RE as SHA256_RE,
)
from rebrew.ops.core import (
    SKIPPED_RECORD_OPS as SKIPPED_RECORD_OPS,
)
from rebrew.ops.core import (
    SOCKET_TIMEOUT_SECONDS as SOCKET_TIMEOUT_SECONDS,
)
from rebrew.ops.core import (
    SPLAT_ANCHOR as SPLAT_ANCHOR,
)
from rebrew.ops.core import (
    SPLAT_MAX_CONFIG_BYTES as SPLAT_MAX_CONFIG_BYTES,
)
from rebrew.ops.core import (
    TARGET_UNSAFE as TARGET_UNSAFE,
)
from rebrew.ops.core import (
    TIMEOUT_HEADER as TIMEOUT_HEADER,
)
from rebrew.ops.core import (
    TOKEN_ENV as TOKEN_ENV,
)
from rebrew.ops.core import (
    TOOLCHAIN_REJECTED as TOOLCHAIN_REJECTED,
)
from rebrew.ops.core import (
    UNAUTHORIZED as UNAUTHORIZED,
)
from rebrew.ops.core import (
    UNKNOWN_OP as UNKNOWN_OP,
)
from rebrew.ops.core import (
    UNSUPPORTED_BINARY_FORMAT as UNSUPPORTED_BINARY_FORMAT,
)
from rebrew.ops.core import (
    VARIANT_MAX_GENERATIONS as VARIANT_MAX_GENERATIONS,
)
from rebrew.ops.core import (
    VARIANT_MAX_POPULATION as VARIANT_MAX_POPULATION,
)
from rebrew.ops.core import (
    WORKER_BUSY as WORKER_BUSY,
)
from rebrew.ops.core import (
    XREFS_MAX_KINDS as XREFS_MAX_KINDS,
)
from rebrew.ops.core import (
    Cancellation as Cancellation,
)
from rebrew.ops.core import (
    CorrelatedFormatter as CorrelatedFormatter,
)
from rebrew.ops.core import (
    OpsError as OpsError,
)
from rebrew.ops.core import (
    WorkerConfig as WorkerConfig,
)
from rebrew.ops.core import (
    address_comment_refused as address_comment_refused,
)
from rebrew.ops.core import (
    apply_project_cflags as apply_project_cflags,
)
from rebrew.ops.core import (
    attach_server_log_handler as attach_server_log_handler,
)
from rebrew.ops.core import (
    attested_registry_digest as attested_registry_digest,
)
from rebrew.ops.core import (
    binding_conflict as binding_conflict,
)
from rebrew.ops.core import (
    bounded as bounded,
)
from rebrew.ops.core import (
    bounded_lines as bounded_lines,
)
from rebrew.ops.core import (
    capture_failed as capture_failed,
)
from rebrew.ops.core import (
    check_cancelled as check_cancelled,
)
from rebrew.ops.core import (
    check_manifest_size as check_manifest_size,
)
from rebrew.ops.core import (
    checked_cflags as checked_cflags,
)
from rebrew.ops.core import (
    declared_reply as declared_reply,
)
from rebrew.ops.core import (
    engine_decompilers as engine_decompilers,
)
from rebrew.ops.core import (
    error_body as error_body,
)
from rebrew.ops.core import (
    escape_log_text as escape_log_text,
)
from rebrew.ops.core import (
    existing_dir as existing_dir,
)
from rebrew.ops.core import (
    failure_detail as failure_detail,
)
from rebrew.ops.core import (
    final_recompile_refusal as final_recompile_refusal,
)
from rebrew.ops.core import (
    ghidra_outage as ghidra_outage,
)
from rebrew.ops.core import (
    has_lone_surrogate as has_lone_surrogate,
)
from rebrew.ops.core import (
    import_refused as import_refused,
)
from rebrew.ops.core import (
    invalid_project_config as invalid_project_config,
)
from rebrew.ops.core import (
    invalid_request as invalid_request,
)
from rebrew.ops.core import (
    not_run_detail as not_run_detail,
)
from rebrew.ops.core import (
    not_run_reason as not_run_reason,
)
from rebrew.ops.core import (
    ops_binding as ops_binding,
)
from rebrew.ops.core import (
    parse_request as parse_request,
)
from rebrew.ops.core import (
    progress_frame as progress_frame,
)
from rebrew.ops.core import (
    readset_limit as readset_limit,
)
from rebrew.ops.core import (
    refuse_compiler_not_offered as refuse_compiler_not_offered,
)
from rebrew.ops.core import (
    refuse_unoffered_decompiler as refuse_unoffered_decompiler,
)
from rebrew.ops.core import (
    refusing_disagreeing_records as refusing_disagreeing_records,
)
from rebrew.ops.core import (
    report_output_invalid as report_output_invalid,
)
from rebrew.ops.core import (
    request_id as request_id,
)
from rebrew.ops.core import (
    stamp_request as stamp_request,
)
from rebrew.ops.core import (
    step as step,
)
from rebrew.ops.core import (
    toolchain_rejected as toolchain_rejected,
)
from rebrew.ops.core import (
    trace_id as trace_id,
)
from rebrew.ops.core import (
    verified_coverage_inputs_required as verified_coverage_inputs_required,
)
from rebrew.ops.core import (
    withheld as withheld,
)
from rebrew.ops.core import (
    without_host_paths as without_host_paths,
)
from rebrew.ops.handlers_analysis import (
    CALL_SCAN_INFLIGHT as CALL_SCAN_INFLIGHT,
)
from rebrew.ops.handlers_analysis import (
    CALL_SCANS as CALL_SCANS,
)
from rebrew.ops.handlers_analysis import (
    CALL_SCANS_LOCK as CALL_SCANS_LOCK,
)
from rebrew.ops.handlers_analysis import (
    MAX_IDENTIFIER_RENAMES as MAX_IDENTIFIER_RENAMES,
)
from rebrew.ops.handlers_analysis import (
    analyse as analyse,
)
from rebrew.ops.handlers_analysis import (
    analyze as analyze,
)
from rebrew.ops.handlers_analysis import (
    binary_function_digests as binary_function_digests,
)
from rebrew.ops.handlers_analysis import (
    binary_operand_locations as binary_operand_locations,
)
from rebrew.ops.handlers_analysis import (
    call_references as call_references,
)
from rebrew.ops.handlers_analysis import (
    capstone_for as capstone_for,
)
from rebrew.ops.handlers_analysis import (
    capture_fresh_analysis as capture_fresh_analysis,
)
from rebrew.ops.handlers_analysis import (
    capture_project as capture_project,
)
from rebrew.ops.handlers_analysis import (
    check_cflags as check_cflags,
)
from rebrew.ops.handlers_analysis import (
    communicate as communicate,
)
from rebrew.ops.handlers_analysis import (
    control_flow_graph as control_flow_graph,
)
from rebrew.ops.handlers_analysis import (
    crypto_scan as crypto_scan,
)
from rebrew.ops.handlers_analysis import (
    decompile as decompile,
)
from rebrew.ops.handlers_analysis import (
    describe as describe,
)
from rebrew.ops.handlers_analysis import (
    disassemble as disassemble,
)
from rebrew.ops.handlers_analysis import (
    disassemble_bytes as disassemble_bytes,
)
from rebrew.ops.handlers_analysis import (
    fingerprint as fingerprint,
)
from rebrew.ops.handlers_analysis import (
    fresh_sqlite_metadata as fresh_sqlite_metadata,
)
from rebrew.ops.handlers_analysis import (
    identify_compiler as identify_compiler,
)
from rebrew.ops.handlers_analysis import (
    identify_library as identify_library,
)
from rebrew.ops.handlers_analysis import (
    import_archive as import_archive,
)
from rebrew.ops.handlers_analysis import (
    import_project as import_project,
)
from rebrew.ops.handlers_analysis import (
    imports as imports,
)
from rebrew.ops.handlers_analysis import (
    instruction_listing as instruction_listing,
)
from rebrew.ops.handlers_analysis import (
    library_functions as library_functions,
)
from rebrew.ops.handlers_analysis import (
    metadata_carry as metadata_carry,
)
from rebrew.ops.handlers_analysis import (
    metadata_describe as metadata_describe,
)
from rebrew.ops.handlers_analysis import (
    metadata_diff as metadata_diff,
)
from rebrew.ops.handlers_analysis import (
    pe_info as pe_info,
)
from rebrew.ops.handlers_analysis import (
    project_report as project_report,
)
from rebrew.ops.handlers_analysis import (
    project_targets as project_targets,
)
from rebrew.ops.handlers_analysis import (
    release as release,
)
from rebrew.ops.handlers_analysis import (
    rename_identifier as rename_identifier,
)
from rebrew.ops.handlers_analysis import (
    report as report,
)
from rebrew.ops.handlers_analysis import (
    run_intake as run_intake,
)
from rebrew.ops.handlers_analysis import (
    run_rebrew as run_rebrew,
)
from rebrew.ops.handlers_analysis import (
    run_rebrew_child as run_rebrew_child,
)
from rebrew.ops.handlers_analysis import (
    security_scan as security_scan,
)
from rebrew.ops.handlers_analysis import (
    splat_parse as splat_parse,
)
from rebrew.ops.handlers_analysis import (
    strings as strings,
)
from rebrew.ops.handlers_analysis import (
    structs as structs,
)
from rebrew.ops.handlers_analysis import (
    target_name as target_name,
)
from rebrew.ops.handlers_analysis import (
    vocabulary as vocabulary,
)
from rebrew.ops.handlers_analysis import (
    xrefs as xrefs,
)
from rebrew.ops.handlers_project import (
    CANDIDATE_MAX_BYTES as CANDIDATE_MAX_BYTES,
)
from rebrew.ops.handlers_project import (
    apply_candidate as apply_candidate,
)
from rebrew.ops.handlers_project import (
    build as build,
)
from rebrew.ops.handlers_project import (
    coverage_report as coverage_report,
)
from rebrew.ops.handlers_project import (
    data_list as data_list,
)
from rebrew.ops.handlers_project import (
    data_set as data_set,
)
from rebrew.ops.handlers_project import (
    decompile_snapshot as decompile_snapshot,
)
from rebrew.ops.handlers_project import (
    flag_search as flag_search,
)
from rebrew.ops.handlers_project import (
    follow_candidate_name as follow_candidate_name,
)
from rebrew.ops.handlers_project import (
    reference_flirt as reference_flirt,
)
from rebrew.ops.handlers_project import (
    remote_header_refusal as remote_header_refusal,
)
from rebrew.ops.handlers_project import (
    retained_compile_refusal as retained_compile_refusal,
)
from rebrew.ops.handlers_project import (
    retained_source_operation as retained_source_operation,
)
from rebrew.ops.handlers_project import (
    security_scan_snapshot as security_scan_snapshot,
)
from rebrew.ops.handlers_project import (
    skeleton as skeleton,
)
from rebrew.ops.handlers_project import (
    verify_candidate as verify_candidate,
)
from rebrew.ops.handlers_project import (
    verify_function as verify_function,
)
from rebrew.ops.handlers_project import (
    verify_target as verify_target,
)
from rebrew.ops.http import (
    OpsHandler as OpsHandler,
)
from rebrew.ops.http import (
    OpsServer as OpsServer,
)
from rebrew.ops.http import (
    ProgressStream as ProgressStream,
)
from rebrew.ops.http import (
    accepts_progress as accepts_progress,
)
from rebrew.ops.http import (
    allowed_hosts_for as allowed_hosts_for,
)
from rebrew.ops.requests import (
    AddressRequest as AddressRequest,
)
from rebrew.ops.requests import (
    AnalyseRequest as AnalyseRequest,
)
from rebrew.ops.requests import (
    ApplyCandidateRequest as ApplyCandidateRequest,
)
from rebrew.ops.requests import (
    BinaryFile as BinaryFile,
)
from rebrew.ops.requests import (
    BuildRequest as BuildRequest,
)
from rebrew.ops.requests import (
    CheckCflagsRequest as CheckCflagsRequest,
)
from rebrew.ops.requests import (
    CoverageInput as CoverageInput,
)
from rebrew.ops.requests import (
    CoverageInputEntry as CoverageInputEntry,
)
from rebrew.ops.requests import (
    CoverageReportRequest as CoverageReportRequest,
)
from rebrew.ops.requests import (
    CoverageVerification as CoverageVerification,
)
from rebrew.ops.requests import (
    DataListRequest as DataListRequest,
)
from rebrew.ops.requests import (
    DataSetRequest as DataSetRequest,
)
from rebrew.ops.requests import (
    DecompileRequest as DecompileRequest,
)
from rebrew.ops.requests import (
    DecompileSnapshotRequest as DecompileSnapshotRequest,
)
from rebrew.ops.requests import (
    DisassembleBytesRequest as DisassembleBytesRequest,
)
from rebrew.ops.requests import (
    DisassembleRequest as DisassembleRequest,
)
from rebrew.ops.requests import (
    Extent as Extent,
)
from rebrew.ops.requests import (
    FileSetRequest as FileSetRequest,
)
from rebrew.ops.requests import (
    FlagSearchRequest as FlagSearchRequest,
)
from rebrew.ops.requests import (
    FunctionDigestsRequest as FunctionDigestsRequest,
)
from rebrew.ops.requests import (
    IdentifierRename as IdentifierRename,
)
from rebrew.ops.requests import (
    ImportArchiveRequest as ImportArchiveRequest,
)
from rebrew.ops.requests import (
    ImportRequest as ImportRequest,
)
from rebrew.ops.requests import (
    MetadataCarryRequest as MetadataCarryRequest,
)
from rebrew.ops.requests import (
    MetadataDiffRequest as MetadataDiffRequest,
)
from rebrew.ops.requests import (
    OperandFunction as OperandFunction,
)
from rebrew.ops.requests import (
    OperandLocationsRequest as OperandLocationsRequest,
)
from rebrew.ops.requests import (
    ProjectRequest as ProjectRequest,
)
from rebrew.ops.requests import (
    ReferenceFlirtRequest as ReferenceFlirtRequest,
)
from rebrew.ops.requests import (
    ReleaseRequest as ReleaseRequest,
)
from rebrew.ops.requests import (
    RenameIdentifierRequest as RenameIdentifierRequest,
)
from rebrew.ops.requests import (
    ReportRequest as ReportRequest,
)
from rebrew.ops.requests import (
    RetainedFile as RetainedFile,
)
from rebrew.ops.requests import (
    SecurityScanRequest as SecurityScanRequest,
)
from rebrew.ops.requests import (
    SecuritySnapshotRequest as SecuritySnapshotRequest,
)
from rebrew.ops.requests import (
    SizedAddressRequest as SizedAddressRequest,
)
from rebrew.ops.requests import (
    SkeletonRequest as SkeletonRequest,
)
from rebrew.ops.requests import (
    SnapshotMutationRequest as SnapshotMutationRequest,
)
from rebrew.ops.requests import (
    SplatRequest as SplatRequest,
)
from rebrew.ops.requests import (
    StoredFile as StoredFile,
)
from rebrew.ops.requests import (
    StructsRequest as StructsRequest,
)
from rebrew.ops.requests import (
    TargetRequest as TargetRequest,
)
from rebrew.ops.requests import (
    VerifyRequest as VerifyRequest,
)
from rebrew.ops.requests import (
    VerifyTargetRequest as VerifyTargetRequest,
)
from rebrew.ops.requests import (
    VocabularyRequest as VocabularyRequest,
)
from rebrew.ops.requests import (
    XrefsRequest as XrefsRequest,
)
from rebrew.ops.staging import (
    address_va as address_va,
)
from rebrew.ops.staging import (
    binary_file as binary_file,
)
from rebrew.ops.staging import (
    check_download_host as check_download_host,
)
from rebrew.ops.staging import (
    checked_coverage_input as checked_coverage_input,
)
from rebrew.ops.staging import (
    confined_dir as confined_dir,
)
from rebrew.ops.staging import (
    confined_snapshot_config as confined_snapshot_config,
)
from rebrew.ops.staging import (
    download_file as download_file,
)
from rebrew.ops.staging import (
    inside_dir as inside_dir,
)
from rebrew.ops.staging import (
    project_file as project_file,
)
from rebrew.ops.staging import (
    project_root as project_root,
)
from rebrew.ops.staging import (
    retained_config as retained_config,
)
from rebrew.ops.staging import (
    retained_metadata_backend as retained_metadata_backend,
)
from rebrew.ops.staging import (
    retained_target_snapshot as retained_target_snapshot,
)
from rebrew.ops.staging import (
    sha256_hex as sha256_hex,
)
from rebrew.ops.staging import (
    stage_retained_binary as stage_retained_binary,
)
from rebrew.ops.staging import (
    stage_retained_files as stage_retained_files,
)
from rebrew.ops.staging import (
    stage_retained_snapshot as stage_retained_snapshot,
)
from rebrew.ops.staging import (
    stored_file as stored_file,
)
from rebrew.ops.staging import (
    target_config as target_config,
)
from rebrew.ops.staging import (
    target_options as target_options,
)
from rebrew.utils import fold_host
lazy from rebrew import __version__, telemetry
lazy from rebrew.cli import EXIT_ERROR, console, error_exit
lazy from rebrew.compiler.compile import RemoteCompiles, counting_remote_compiles
lazy from rebrew.formats.binary_loader import UnsupportedBinaryFormat

logger = logging.getLogger(__name__)

_CANCELLATION = CANCELLATION_VAR
_DNS_SLOTS = DNS_SLOTS
_FAILED_STEP = FAILED_STEP_VAR
_FINAL_RECOMPILE_REFUSALS = FINAL_RECOMPILE_REFUSALS
_LATENCY_BUCKETS_MS = LATENCY_BUCKETS_MS
_PROGRESS = PROGRESS_VAR
_Cancellation = Cancellation
_attach_server_log_handler = attach_server_log_handler
_bounded = bounded
_bounded_lines = bounded_lines
_declared_reply = declared_reply
_escape_log_text = escape_log_text
_existing_dir = existing_dir
_failure_detail = failure_detail
_final_recompile_refusal = final_recompile_refusal
_ghidra_outage = ghidra_outage
_invalid = invalid_request
_not_run_detail = not_run_detail
_refuse_compiler_not_offered = refuse_compiler_not_offered
_request_id = request_id
_step = step
_toolchain_rejected = toolchain_rejected
_trace_id = trace_id
_without_host_paths = without_host_paths
_call_scan_inflight = CALL_SCAN_INFLIGHT
_call_scans = CALL_SCANS
_call_scans_lock = CALL_SCANS_LOCK
_communicate = communicate
_run_rebrew_child = run_rebrew_child
_stage_retained_snapshot = stage_retained_snapshot
_stamp_request = stamp_request
_OpsHandler = OpsHandler
_allowed_hosts_for = allowed_hosts_for
_capstone_for = capstone_for
_check_manifest_size = check_manifest_size
_fresh_sqlite_metadata = fresh_sqlite_metadata
_run_intake = run_intake


@dataclass(frozen=True)
class Op:
    """One wire op: its request type, the function that answers it, and its deadline.

    ``timeout_seconds`` and ``interruptible`` are published per op in the
    dispatch schema.  Once ``timeout_seconds`` pass, the call answers 504
    ``deadline-exceeded`` at the next point rebrew can stop it: its child
    command is killed (checked every ``CANCEL_POLL_SECONDS``), and no further
    download chunk, retained file or checked step starts.  An
    ``interruptible`` op's long work is all such points, so it outlives its
    deadline only by the in-process step already running.  Any other op works
    in the worker process, which nothing stops: ``timeout_seconds`` is how
    long a caller waits for it.
    """

    request: type
    run: Callable[[WorkerConfig, Any], Mapping[str, Any]]
    timeout_seconds: int
    interruptible: bool = False


#: The ops that may compile through recompile: each request takes an ``attribution``
#: and each reply carries ``remote_compile`` (``{count, billed_undelivered, unsettled, wait_ms}``).
COMPILING_OPS = frozenset(
    {
        "rebrew.verify_function",
        "rebrew.apply_candidate",
        "rebrew.verify_target",
        "rebrew.build",
        "rebrew.flag_search",
        "rebrew.retained_source_operation",
    }
)


#: Every op of the backend's rebrew contract, by wire name.
OPS: dict[str, Op] = {
    "rebrew.disassemble": Op(DisassembleRequest, disassemble, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.disassemble_bytes": Op(
        DisassembleBytesRequest, disassemble_bytes, IN_PROCESS_TIMEOUT_SECONDS
    ),
    "rebrew.instruction_listing": Op(
        SizedAddressRequest, instruction_listing, IN_PROCESS_TIMEOUT_SECONDS
    ),
    "rebrew.control_flow_graph": Op(
        SizedAddressRequest, control_flow_graph, IN_PROCESS_TIMEOUT_SECONDS
    ),
    "rebrew.xrefs": Op(XrefsRequest, xrefs, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.call_references": Op(ProjectRequest, call_references, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.describe": Op(AddressRequest, describe, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.decompile": Op(DecompileRequest, decompile, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.decompile_snapshot": Op(
        DecompileSnapshotRequest, decompile_snapshot, IN_PROCESS_TIMEOUT_SECONDS
    ),
    "rebrew.identify_library": Op(ProjectRequest, identify_library, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.structs": Op(StructsRequest, structs, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.binary_operand_locations": Op(
        OperandLocationsRequest, binary_operand_locations, IN_PROCESS_TIMEOUT_SECONDS
    ),
    "rebrew.binary_function_digests": Op(
        FunctionDigestsRequest, binary_function_digests, IN_PROCESS_TIMEOUT_SECONDS
    ),
    "rebrew.imports": Op(BinaryFile, imports, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.strings": Op(BinaryFile, strings, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.fingerprint": Op(BinaryFile, fingerprint, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.analyze": Op(BinaryFile, analyze, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.crypto_scan": Op(BinaryFile, crypto_scan, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.pe_info": Op(BinaryFile, pe_info, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.identify_compiler": Op(BinaryFile, identify_compiler, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.library_functions": Op(StoredFile, library_functions, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.splat_parse": Op(SplatRequest, splat_parse, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.report": Op(ReportRequest, report, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.security_scan": Op(SecurityScanRequest, security_scan, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.security_scan_snapshot": Op(
        SecuritySnapshotRequest, security_scan_snapshot, IN_PROCESS_TIMEOUT_SECONDS
    ),
    "rebrew.analyse": Op(AnalyseRequest, analyse, ANALYSE_TIMEOUT_SECONDS, interruptible=True),
    "rebrew.import-project": Op(ImportRequest, import_project, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.import_archive": Op(
        ImportArchiveRequest, import_archive, IMPORT_TIMEOUT_SECONDS, interruptible=True
    ),
    "rebrew.project_targets": Op(FileSetRequest, project_targets, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.metadata_carry": Op(MetadataCarryRequest, metadata_carry, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.metadata_describe": Op(FileSetRequest, metadata_describe, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.metadata_diff": Op(MetadataDiffRequest, metadata_diff, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.reference_flirt": Op(
        ReferenceFlirtRequest, reference_flirt, COMMAND_TIMEOUT_SECONDS, interruptible=True
    ),
    "rebrew.verify_function": Op(VerifyRequest, verify_function, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.apply_candidate": Op(
        ApplyCandidateRequest, apply_candidate, COMMAND_TIMEOUT_SECONDS, interruptible=True
    ),
    "rebrew.verify_target": Op(
        VerifyTargetRequest, verify_target, SEARCH_TIMEOUT_SECONDS, interruptible=True
    ),
    "rebrew.build": Op(BuildRequest, build, SEARCH_TIMEOUT_SECONDS, interruptible=True),
    "rebrew.skeleton": Op(SkeletonRequest, skeleton, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.coverage_report": Op(
        CoverageReportRequest, coverage_report, IN_PROCESS_TIMEOUT_SECONDS
    ),
    "rebrew.flag_search": Op(
        FlagSearchRequest, flag_search, SEARCH_TIMEOUT_SECONDS, interruptible=True
    ),
    "rebrew.data_list": Op(DataListRequest, data_list, COMMAND_TIMEOUT_SECONDS, interruptible=True),
    "rebrew.data_set": Op(DataSetRequest, data_set, COMMAND_TIMEOUT_SECONDS, interruptible=True),
    "rebrew.vocabulary": Op(VocabularyRequest, vocabulary, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.release": Op(ReleaseRequest, release, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.check_cflags": Op(CheckCflagsRequest, check_cflags, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.rename_identifier": Op(
        RenameIdentifierRequest, rename_identifier, IN_PROCESS_TIMEOUT_SECONDS
    ),
    "rebrew.retained_source_operation": Op(
        SnapshotMutationRequest,
        retained_source_operation,
        SEARCH_TIMEOUT_SECONDS,
        interruptible=True,
    ),
}


def _answer(config: WorkerConfig, name: str, body: bytes) -> Mapping[str, Any]:
    op = OPS.get(name)
    if op is None:
        raise OpsError(f"unknown op: {bounded(name)}", code=UNKNOWN_OP, status=404)
    cancellation = CANCELLATION_VAR.get()
    token = None
    if cancellation is None:
        cancellation = Cancellation()
        token = CANCELLATION_VAR.set(cancellation)
    cancellation.limit(
        ops_binding("time", time).monotonic() + op.timeout_seconds,
        f"{name} outlived its {op.timeout_seconds} s deadline",
    )
    steps = FAILED_STEP_VAR.set([])
    try:
        return _run_op(config, name, op, body)
    finally:
        FAILED_STEP_VAR.reset(steps)
        if token is not None:
            CANCELLATION_VAR.reset(token)


def _counting_remote_compiles(
    config: WorkerConfig, name: str, op: Op, request: Any
) -> dict[str, Any]:
    """Run a compiling op and add its recompile calls: ``remote_compile {count, billed_undelivered, unsettled, wait_ms}``.

    ``count`` is the compiles recompile billed and gave the op a verdict on (an object
    or the compiler's rejection), ``billed_undelivered`` the compiles it billed whose
    verdict the op did not get (a failed object download, ``billed_not_delivered``,
    ``retained_output_unavailable``, ``artifact_expired``), ``unsettled`` the calls
    that may have been billed with no answer to settle it; a call is in at most one
    of the three.  ``wait_ms`` is the wall time spent waiting on recompile, refused
    and retried calls included.  All cover the op's child commands, which append to
    the same ledger.  A refusal after a recompile call carries them too
    (``OpsError.remote_compile``): a candidate the compiler rejected is refused, and
    recompile billed it.
    """
    from rebrew.compiler.temp_dirs import remove_temp_dir, writable_temp_dir

    directory = writable_temp_dir("rebrew-remote-compiles-")
    try:
        ledger = directory / "ledger"
        ledger.touch()
        with counting_remote_compiles(RemoteCompiles(ledger, request.attribution)) as remote:
            try:
                reply = dict(_run_parsed(config, name, op, request))
            except OpsError as exc:
                if remote.recorded():
                    exc.remote_compile = remote.totals()
                raise
            reply["remote_compile"] = remote.totals()
        return reply
    finally:
        remove_temp_dir(directory)


def _run_op(config: WorkerConfig, name: str, op: Op, body: bytes) -> Mapping[str, Any]:
    if len(body) > MAX_REQUEST_BYTES:
        detail = f"request exceeds {MAX_REQUEST_BYTES} bytes"
        raise OpsError(detail, code=INVALID_REQUEST, status=413)
    try:
        from rebrew.ops.named_snapshot import unique_json_object

        raw = json.loads(body, object_pairs_hook=unique_json_object)
    except ValueError:
        raise invalid_request("request is not JSON") from None
    request: Any = parse_request(op.request, raw)
    if name in COMPILING_OPS:
        return _counting_remote_compiles(config, name, op, request)
    return _run_parsed(config, name, op, request)


#: Exceptions an op never turns into a refusal: the process is ending.


#: The detail of a write refused for a function record and source that disagree; the
#: record's key goes to the worker log.
BINDING_CONFLICT_DETAIL = (
    "invalid project config: a function record names another function than its source's "
    "address anchor; rebrew doctor lists such records and a re-analysis repairs a generated stub"
)


def _undeclared_skipped_records(name: str, skipped: set[tuple[str, int]]) -> None:
    """Fail under strict replies, or warn, when an op outside :data:`SKIPPED_RECORD_OPS` skipped."""
    from rebrew.config import STRICT_REPLIES_ENV, parse_env_bool

    keys = _skipped_records(skipped)["keys"]
    strict = os.environ.get(STRICT_REPLIES_ENV, "")
    if parse_env_bool(STRICT_REPLIES_ENV, strict, default=False):
        raise ValueError(f"{name}: skipped records outside SKIPPED_RECORD_OPS: {', '.join(keys)}")
    logger.warning(
        "%s %s skipped records outside SKIPPED_RECORD_OPS (%s) trace_id=%s",
        request_id(),
        name,
        ", ".join(keys),
        trace_id(),
    )


def _run_parsed(config: WorkerConfig, name: str, op: Op, request: Any) -> Mapping[str, Any]:
    """*op*'s reply to *request*, as its declared reply when :mod:`rebrew.ops.replies` declares one."""
    from rebrew.metadata.bindings import binding_conflicts
    from rebrew.metadata.sqlite import reading
    from rebrew.ops.replies import DECLARED

    with binding_conflicts() as skipped, reading():
        try:
            reply = op.run(config, request)
        except OpsError:
            raise
        except typer.Exit as exc:
            from rebrew.cli import TOOLCHAIN_REJECTED_KIND, CommandExit

            if isinstance(exc, CommandExit) and exc.kind == TOOLCHAIN_REJECTED_KIND:
                roots = [path for path in (config.workspace, config.filestore) if path is not None]
                raise toolchain_rejected(exc.message, roots) from None
            raise OpsError(f"rebrew refused {name} (exit {exc.exit_code})") from None
        except UnsupportedBinaryFormat as exc:
            raise OpsError(str(exc), code=UNSUPPORTED_BINARY_FORMAT, status=422) from None
        except Exception as exc:  # the engine is a trust boundary: log it, answer it sanitized
            logger.exception("%s %s failed trace_id=%s", request_id(), name, trace_id())
            raise OpsError(failure_detail(config, name, exc)) from None
        except EXITS:
            raise
        except BaseException:  # a native panic (pyo3) escapes ``except Exception``
            logger.exception("%s %s failed trace_id=%s", request_id(), name, trace_id())
            raise OpsError(f"{name} failed: the engine raised an unexpected error") from None
        if skipped:
            if name in SKIPPED_RECORD_OPS:
                reply = {**reply, "skipped_records": _skipped_records(skipped)}
            else:
                _undeclared_skipped_records(name, skipped)
    return declared_reply(name, reply) if name in DECLARED else reply


def _skipped_records(skipped: set[tuple[str, int]]) -> dict[str, Any]:
    """The reply member naming the records a read skipped, by key, at most
    :data:`MAX_SKIPPED_RECORD_KEYS` of them."""
    keys = sorted(f"{module}.0x{va:08x}" for module, va in skipped)
    return {
        "count": len(keys),
        "keys": keys[:MAX_SKIPPED_RECORD_KEYS],
        "truncated": len(keys) > MAX_SKIPPED_RECORD_KEYS,
    }


#: Headers the HTTP transport adds to the reply of the call in flight
#: (``Retry-After`` of a refusal that names one); unset on the exec transport.


def dispatch(config: WorkerConfig, name: str, body: bytes) -> tuple[int, bytes]:
    """Answer one call: ``(200, reply)`` or ``(status, refusal)``."""
    try:
        reply = json.dumps(_answer(config, name, body), allow_nan=False).encode("utf-8")
    except OpsError as exc:
        headers = REPLY_HEADERS_VAR.get()
        if exc.retry_after is not None and headers is not None:
            headers["Retry-After"] = str(exc.retry_after)
        # A 5xx refusal is a server failure with no exception attached (a
        # download timing out, a child command dying): without one line the
        # operator holding the refusal has only the fixed detail to go on.
        # 4xx refusals are the caller's diagnosis, already in the wire body.
        if exc.status >= 500:
            logger.exception(
                "%s %s refused (%d) trace_id=%s", request_id(), name, exc.status, trace_id()
            )
        return exc.status, error_body(exc.code, str(exc), exc.status, exc.remote_compile)
    except TypeError, ValueError:
        logger.exception(
            "%s %s produced a reply that is not JSON trace_id=%s", request_id(), name, trace_id()
        )
        return 500, error_body(ENGINE_ERROR, f"{name} produced a reply that is not JSON", 500)
    if len(reply) > MAX_REPLY_BYTES:
        logger.error(
            "%s %s produced a reply over %d bytes trace_id=%s",
            request_id(),
            name,
            MAX_REPLY_BYTES,
            trace_id(),
        )
        return 500, error_body(ENGINE_ERROR, f"reply exceeds {MAX_REPLY_BYTES} bytes", 500)
    from rebrew.ops.replies import reply_schema_error

    if violation := reply_schema_error(name, reply):
        logger.error(
            "%s %s produced a reply outside its schema (%s) trace_id=%s",
            request_id(),
            name,
            violation,
            trace_id(),
        )
        return 500, error_body(ENGINE_ERROR, f"{name} produced a reply outside its schema", 500)
    return 200, reply


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Answer the relumea backend's rebrew ops over stdin/stdout or HTTP.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew ops call rebrew.fingerprint --filestore /srv/files\n\n"
        "  rebrew ops serve --port 8790 --workspace /srv/relumea\n\n"
        "serve needs REBREW_OPS_TOKEN. Backend setup: the rebrew repo's docs/CLI.md."
    ),
)


def _exit_on_signal(signum: int, _frame: Any) -> None:
    """Unwind the running call with the shell's exit status for *signum* (128 + signal)."""
    raise SystemExit(128 + signum)


_FILESTORE_HELP = "The backend's local filestore directory; request file keys resolve under it"
_WORKSPACE_HELP = (
    "Directory for analysis projects, report output_dir and url downloads;"
    " project paths must lie inside"
)
_MAX_DOWNLOAD_HELP = "Largest binary in bytes a request url may name"


@app.command(
    "call",
    epilog="[bold]Examples:[/bold]\n\n"
    "  rebrew ops call rebrew.pe_info --filestore /srv/files  # JSON on stdin",
)
def call_command(
    op: str = typer.Argument(..., help="Wire op name, such as rebrew.disassemble"),
    filestore: Path | None = typer.Option(
        None, "--filestore", envvar="REBREW_OPS_FILESTORE", help=_FILESTORE_HELP
    ),
    workspace: Path | None = typer.Option(
        None, "--workspace", envvar="REBREW_OPS_WORKSPACE", help=_WORKSPACE_HELP
    ),
    max_download_bytes: int = typer.Option(
        DEFAULT_MAX_DOWNLOAD_BYTES,
        "--max-download",
        envvar="REBREW_OPS_MAX_DOWNLOAD",
        min=1,
        help=_MAX_DOWNLOAD_HELP,
    ),
) -> None:
    """Answer one op: the JSON request on stdin, the reply on stdout.

    A refusal prints {"error","detail","status"} on stdout and exits 2.
    """
    config = WorkerConfig(
        existing_dir(filestore, "--filestore"),
        existing_dir(workspace, "--workspace"),
        max_download_bytes,
    )
    body = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    # read(MAX+1) lets dispatch answer over-limit input with 413; truncating
    # here would turn it into a 400 "not JSON" for the same client mistake
    # the HTTP transport answers 413.
    # A caller cancels with SIGTERM to this process's group. The child commands
    # run in their own sessions, so the call unwinds instead of dying: the
    # child's process tree is stopped and the retained snapshot removed.
    sigterm = getattr(signal, "SIGTERM", None)
    previous = signal.signal(sigterm, _exit_on_signal) if sigterm is not None else None
    progress = PROGRESS_VAR.set(_descriptor_progress())
    try:
        # stdout carries only the reply; anything rebrew prints goes to stderr.
        with contextlib.redirect_stdout(sys.stderr):
            status, reply = dispatch(config, op, body)
    finally:
        PROGRESS_VAR.reset(progress)
        if sigterm is not None:
            signal.signal(sigterm, previous)
    sys.stdout.buffer.write(reply + b"\n")
    sys.stdout.flush()
    if status != 200:
        raise typer.Exit(EXIT_ERROR)


def _descriptor_progress() -> Callable[[int, int], None] | None:
    """The progress sink :data:`DISPATCH_PROGRESS_FD_ENV` names for ``ops call``, or ``None`` when it is unset."""
    value = os.environ.get(DISPATCH_PROGRESS_FD_ENV)
    if value is None:
        return None
    try:
        fd = int(value)
        os.fstat(fd)
    except ValueError, OSError:
        error_exit(f"{DISPATCH_PROGRESS_FD_ENV} must name an open file descriptor, got {value!r}")
    writing = [True]

    def write(done: int, total: int) -> None:
        if not writing[0]:
            return
        try:
            os.write(fd, progress_frame(done, total))
        except OSError:
            # The caller stopped reading; its reply still goes to stdout.
            writing[0] = False

    return write


#: Seconds ``serve`` waits, once stopped, for the calls in flight to answer.
SERVE_DRAIN_SECONDS = 30.0


@app.command(
    "serve",
    epilog="[bold]Examples:[/bold]\n\n"
    "  rebrew ops serve --port 0 --workspace /srv/relumea --filestore /srv/files",
)
def serve_command(
    port: int = typer.Option(..., "--port", help="TCP port; 0 picks a free one"),
    host: str = typer.Option("127.0.0.1", "--host", help="Address to bind (loopback by default)"),
    filestore: Path | None = typer.Option(
        None, "--filestore", envvar="REBREW_OPS_FILESTORE", help=_FILESTORE_HELP
    ),
    workspace: Path | None = typer.Option(
        None, "--workspace", envvar="REBREW_OPS_WORKSPACE", help=_WORKSPACE_HELP + " (required)"
    ),
    max_download_bytes: int = typer.Option(
        DEFAULT_MAX_DOWNLOAD_BYTES,
        "--max-download",
        envvar="REBREW_OPS_MAX_DOWNLOAD",
        min=1,
        help=_MAX_DOWNLOAD_HELP,
    ),
    concurrency: int = typer.Option(
        DEFAULT_CONCURRENCY,
        "--concurrency",
        envvar="REBREW_OPS_CONCURRENCY",
        min=1,
        help="Calls answered at once; the next is refused 503 with Retry-After",
    ),
    allowed_hosts: str = typer.Option(
        "",
        "--allowed-hosts",
        envvar="REBREW_OPS_ALLOWED_HOSTS",
        help="Comma-separated exact additional HTTP Host authorities, including ports",
    ),
) -> None:
    """Serve POST /<op> over HTTP until interrupted.

    Every request needs Authorization: Bearer $REBREW_OPS_TOKEN.  --workspace
    is required: every project path a request names must lie inside it.
    """
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        error_exit(f"{TOKEN_ENV} is not set; serve answers only bearer-authenticated calls")
    if len(token.encode("utf-8")) < 32:
        error_exit(f"{TOKEN_ENV} must contain at least 32 bytes")
    if workspace is None:
        error_exit("serve needs --workspace (or REBREW_OPS_WORKSPACE) to confine project paths")
    config = WorkerConfig(
        existing_dir(filestore, "--filestore"),
        existing_dir(workspace, "--workspace"),
        max_download_bytes,
    )
    hosts = frozenset(fold_host(item.strip()) for item in allowed_hosts.split(",") if item.strip())
    if any(not re.fullmatch(r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?", item) for item in hosts):
        error_exit("--allowed-hosts must contain exact DNS names and optional ports")
    try:
        stop_telemetry = telemetry.configure_from_env("relumea-rebrew", __version__)
    except ValueError as exc:
        error_exit(str(exc))
    try:
        server = ops_binding("OpsServer", OpsServer)(
            (host, port), config, token, concurrency, hosts
        )
    except BaseException:
        # A failed bind must not leave the exporter thread running in a process
        # that continues serving some other caller.
        stop_telemetry()
        raise
    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            f"serving rebrew ops on http://{host}:{server.server_port} (non-loopback bind: bearer auth required)"
        )
    console.print(f"serving rebrew ops on http://{host}:{server.server_port}")

    def stop(_signum: int, _frame: Any) -> None:
        server.request_stop()

    # SIGTERM is never delivered on Windows; Ctrl+C raises KeyboardInterrupt
    # instead, which serve_forever propagates as the shutdown path. Mirror
    # climb.py's getattr guard so a platform without SIGTERM does not raise
    # AttributeError on startup.
    sigterm = getattr(signal, "SIGTERM", None)
    previous = signal.signal(sigterm, stop) if sigterm is not None else None
    restore_log = attach_server_log_handler()
    try:
        server.serve_forever()
    finally:
        server.server_close()
        server.drain(SERVE_DRAIN_SECONDS)
        restore_log()
        stop_telemetry()
        if sigterm is not None:
            signal.signal(sigterm, previous)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)


if __name__ == "__main__":
    main_entry()
