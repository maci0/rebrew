"""Stateless binary, analysis, disassembly, metadata, and project report ops."""

from __future__ import annotations

import contextlib
import threading
from pathlib import Path
lazy import base64
lazy import ctypes
lazy import dataclasses
lazy import errno
lazy import functools
lazy import hashlib
lazy import json
lazy import os
lazy import re
lazy import shutil
lazy import subprocess
lazy import sys
lazy import tempfile
lazy import time
lazy import typing
lazy import unicodedata
lazy from collections.abc import Callable, Iterator, Mapping
lazy from typing import TYPE_CHECKING, Any

from rebrew.errors import RebrewError
from rebrew.ops.core import (
    ANALYSIS_REPORT_PATH,
    APPLY_METADATA_FILE,
    CANCEL_POLL_SECONDS,
    CANCELLATION_VAR,
    CHILD_REPORT_SECONDS,
    COMPILER_NOT_OFFERED,
    COVERAGE_INPUT_UNVERIFIED,
    DATA_MARKERS,
    DECOMPILER_BACKENDS,
    DIGEST_ALGORITHM,
    DIGEST_MAX_FUNCTION_BYTES,
    DIGEST_MAX_FUNCTIONS,
    DISASM_FORMATS,
    DISASSEMBLE_MAX_BYTES,
    DISPATCH_SCHEMA_SHA256,
    INTAKE_TIMEOUT_SECONDS,
    MAX_READSET_BYTES,
    MAX_READSET_FILE_BYTES,
    MAX_READSET_FILES,
    MAX_REPORT_BYTES,
    MAX_REPORT_FILES,
    NASM_ARCH,
    NO_DECOMPILATION,
    OPERAND_MAX_FUNCTION_BYTES,
    OPERAND_MAX_FUNCTIONS,
    OPERAND_MAX_INDEX,
    OPERAND_MAX_LOCATIONS,
    PROGRESS_VAR,
    SCRATCH_DIR,
    SPLAT_ANCHOR,
    SPLAT_MAX_CONFIG_BYTES,
    TARGET_UNSAFE,
    XREFS_MAX_KINDS,
    Cancellation,
    OpsError,
    WorkerConfig,
    bounded,
    capture_failed,
    check_cancelled,
    check_manifest_size,
    checked_cflags,
    engine_decompilers,
    escape_log_text,
    final_recompile_refusal,
    ghidra_outage,
    import_refused,
    invalid_project_config,
    invalid_request,
    logger,
    no_decompilation,
    ops_binding,
    readset_limit,
    refuse_unoffered_decompiler,
    report_output_invalid,
    step,
    toolchain_rejected,
    verified_coverage_inputs_required,
    without_host_paths,
)
from rebrew.ops.requests import (
    AddressRequest,
    AnalyseRequest,
    BinaryFile,
    CheckCflagsRequest,
    DecompileRequest,
    DisassembleBytesRequest,
    DisassembleRequest,
    FileSetRequest,
    FunctionDigestsRequest,
    ImportArchiveRequest,
    ImportRequest,
    MetadataCarryRequest,
    MetadataDiffRequest,
    OperandLocationsRequest,
    ProjectRequest,
    ReleaseRequest,
    RenameIdentifierRequest,
    ReportRequest,
    RetainedFile,
    SecurityScanRequest,
    SizedAddressRequest,
    SplatRequest,
    StoredFile,
    StructsRequest,
    VocabularyRequest,
    XrefsRequest,
)
from rebrew.ops.staging import (
    address_va,
    binary_file,
    checked_coverage_input,
    confined_dir,
    confined_snapshot_config,
    inside_dir,
    project_root,
    retained_target_snapshot,
    sha256_hex,
    stage_retained_files,
    target_config,
)
lazy from rebrew import __version__, telemetry
lazy from rebrew.binary.cfg_ged import ImageReader
lazy from rebrew.call_progress import PROGRESS_FD_ENV, ProgressPipe
lazy from rebrew.cli import EXIT_ERROR
lazy from rebrew.compiler.compile import (
    current_remote_compiles,
)
lazy from rebrew.formats.binary_loader import load_binary
lazy from rebrew.metadata.bindings import BindingConflictError
lazy from rebrew.utils import sha256_file

if TYPE_CHECKING:
    from rebrew.ops.requests import (
        AddressRequest,
        AnalyseRequest,
        BinaryFile,
        CheckCflagsRequest,
        DecompileRequest,
        DisassembleBytesRequest,
        DisassembleRequest,
        FileSetRequest,
        FunctionDigestsRequest,
        ImportArchiveRequest,
        ImportRequest,
        MetadataCarryRequest,
        MetadataDiffRequest,
        OperandLocationsRequest,
        ProjectRequest,
        ReleaseRequest,
        RenameIdentifierRequest,
        ReportRequest,
        RetainedFile,
        SecurityScanRequest,
        SizedAddressRequest,
        SplatRequest,
        StoredFile,
        StructsRequest,
        VocabularyRequest,
        XrefsRequest,
    )


def capstone_for(arch: str) -> tuple[int, int]:
    from rebrew.config import ARCH_PRESETS
    from rebrew.formats.binary_loader import capstone_config_for
    from rebrew.formats.binary_model import BinaryInfo

    if arch not in ARCH_PRESETS:
        raise invalid_request(f"unsupported arch: {bounded(arch)}")
    try:
        return capstone_config_for(BinaryInfo(path=Path(), format="", arch=arch, endian=""))
    except NotImplementedError as exc:
        raise invalid_request(bounded(str(exc))) from None


def _listing_reply(text: str) -> dict[str, Any]:
    """A listing op's reply: the text and the renderer that wrote it
    (:func:`rebrew.binary.asm.listing_renderer`), under which the backend caches it."""
    from rebrew.binary.asm import listing_renderer

    return {"text": text, "renderer": listing_renderer()}


def _nasm_listing(code: bytes, va: int, read_image: ImageReader | None = None) -> str:
    from rebrew.binary.asm import disassemble_to_nasm

    source, _stats = disassemble_to_nasm(code, va, f"func_{va:08X}", read_image)
    return source + "\n"


def _asm_listing(
    code: bytes, va: int, cs_arch: int, cs_mode: int, read_image: ImageReader | None = None
) -> str:
    """One ``mnemonic operands`` line per instruction and jump-table entry.

    A table starts with its ``jump_table_<VA>:`` label; bytes that decode as
    no instruction are left out.
    """
    from rebrew.binary.cfg_ged import listing_items, table_label

    listing = listing_items(code, va, cs_arch, cs_mode, read_image)
    lines: list[str] = []
    for row in listing.rows:
        if row.va in listing.undecoded:
            continue
        if row.va in listing.table_starts:
            lines.append(f"{table_label(row.va)}:")
        lines.append(f"{row.mnemonic} {row.op_str}".rstrip())
    return "".join(line + "\n" for line in lines)


def disassemble(config: WorkerConfig, req: DisassembleRequest) -> dict[str, Any]:
    """Listing of ``[va, va+size)``: NASM source, ``asm`` lines, or the hex view.

    ``arch`` overrides the target's ISA for every format; it must be one of
    rebrew's arch presets, and NASM covers x86_32 only.
    """
    from rebrew.config import ARCH_PRESETS

    if req.format not in DISASM_FORMATS:
        raise invalid_request(f"format must be one of {', '.join(sorted(DISASM_FORMATS))}")
    if req.size <= 0:
        raise invalid_request(f"size must be positive, got {req.size}")
    if req.size > ops_binding("DISASSEMBLE_MAX_BYTES", DISASSEMBLE_MAX_BYTES):
        raise invalid_request(
            f"size must be at most {ops_binding('DISASSEMBLE_MAX_BYTES', DISASSEMBLE_MAX_BYTES)} bytes, got {req.size}"
        )
    va = address_va(req.va)
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    if req.arch and req.arch != cfg.arch:
        if req.arch not in ARCH_PRESETS:
            raise invalid_request(f"unsupported arch: {bounded(req.arch)}")
        cfg = dataclasses.replace(cfg, arch=req.arch)
    if req.format == "hex":
        from rebrew.binary.asm import hex_disassembly

        return _listing_reply(hex_disassembly(cfg, va, req.size))
    if req.format == "nasm" and cfg.arch != NASM_ARCH:
        raise invalid_request(f"NASM source covers {NASM_ARCH} only and this binary is {cfg.arch}")
    from rebrew.formats.binary_loader import extract_raw_bytes

    code = extract_raw_bytes(cfg.target_binary, va, req.size)
    if not code:
        raise invalid_request(f"no file bytes at 0x{va:x}")
    read_image = functools.partial(extract_raw_bytes, cfg.target_binary)
    if req.format == "nasm":
        return _listing_reply(_nasm_listing(code, va, read_image))
    return _listing_reply(_asm_listing(code, va, cfg.capstone_arch, cfg.capstone_mode, read_image))


def instruction_listing(config: WorkerConfig, req: SizedAddressRequest) -> dict[str, Any]:
    """The comparison of ``[va, va+size)`` with itself, in ``rebrew test --instructions``'s shape.

    It stands in for an ``EXACT`` rebuild, whose comparison no verification
    records: every row is ``equal``.
    """
    from rebrew.compare.instruction_diff import MAX_BYTES, instruction_diff
    from rebrew.formats.binary_loader import extract_raw_bytes

    if not 1 <= req.size <= MAX_BYTES:
        raise invalid_request(f"size must be 1 to {MAX_BYTES} bytes, got {req.size}")
    va = address_va(req.va)
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    code = extract_raw_bytes(cfg.target_binary, va, req.size)
    if not code:
        raise invalid_request(f"no file bytes at 0x{va:x}")
    return instruction_diff(
        code,
        code,
        va=va,
        cs_arch=cfg.capstone_arch,
        cs_mode=cfg.capstone_mode,
        read_image=functools.partial(extract_raw_bytes, cfg.target_binary),
    )


def disassemble_bytes(_config: WorkerConfig, req: DisassembleBytesRequest) -> dict[str, Any]:
    """Listing of raw code: NASM source for x86_32 (or no arch), ``asm`` lines otherwise."""
    if req.arch and req.arch != NASM_ARCH:
        from rebrew.config import ARCH_PRESETS

        if req.arch not in ARCH_PRESETS:
            raise invalid_request(f"unsupported arch: {bounded(req.arch)}")
    va = address_va(req.va)
    if req.arch in ("", NASM_ARCH):
        return _listing_reply(_nasm_listing(req.code, va))
    return _listing_reply(_asm_listing(req.code, va, *capstone_for(req.arch)))


# ---------------------------------------------------------------------------
# Function ops on an analysed binary
# ---------------------------------------------------------------------------


def control_flow_graph(config: WorkerConfig, req: SizedAddressRequest) -> dict[str, Any]:
    """Basic-block graph; ``size`` 0 lets rebrew resolve the extent."""
    from rebrew.binary.asm import build_cfg_payload

    if req.size < 0:
        raise invalid_request(f"size must not be negative, got {req.size}")
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    return build_cfg_payload(cfg, address_va(req.va), req.size)


def xrefs(config: WorkerConfig, req: XrefsRequest) -> dict[str, Any]:
    """References to ``va``, narrowed to ``kinds`` when given."""
    from rebrew.binary.analysis import is_xref_kind
    from rebrew.binary.xrefs import build_xrefs_payload

    if len(req.kinds) > ops_binding("XREFS_MAX_KINDS", XREFS_MAX_KINDS):
        raise invalid_request(
            f"kinds holds {len(req.kinds)} entries, over the limit of {ops_binding('XREFS_MAX_KINDS', XREFS_MAX_KINDS)}"
        )
    for kind in req.kinds:
        if not is_xref_kind(kind):
            raise invalid_request(f"kinds: {bounded(repr(kind))} is no reference kind")
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    return build_xrefs_payload(cfg.target_binary, address_va(req.va), req.kinds or None)


#: Call scans (``call_references`` answers) by the sha256 of the scanned binary's bytes, newest
#: use last. A function page reads its binary's scan on every view, and one worker serves a few
#: binaries at a time; the bound guards a long-lived worker walking many images.
_CALL_SCANS_MAX = 8
CALL_SCANS: dict[str, dict[str, Any]] = {}
CALL_SCANS_LOCK = threading.Lock()
#: One live scan per binary digest.  Concurrent cold requests otherwise each
#: repeat the full disassembly and import parse before any can publish a row.
#: Waiters stay with the leader until its ``finally`` publishes the outcome;
#: timing out and claiming the key would duplicate a slow scan.
CALL_SCAN_INFLIGHT: dict[str, threading.Event] = {}


def call_references(config: WorkerConfig, req: ProjectRequest) -> dict[str, Any]:
    """Scan one analysed binary for calls, jumps and import slots.

    The answer is a function of the binary's bytes alone, so it is kept by their sha256, read
    before the scan and again after it: a scan whose file changed meanwhile is answered but not
    kept. Callers serialize the answer and never change it.
    """
    from rebrew.binary.analysis import scan_references
    from rebrew.formats.binary_loader import load_binary
    from rebrew.formats.import_table import parse_import_table

    cfg = target_config(project_root(config, req.project_dir), "")
    binary = Path(cfg.target_binary)
    digest = sha256_file(binary)
    scans = typing.cast("dict[str, dict[str, Any]]", ops_binding("_call_scans", CALL_SCANS))
    scans_lock = ops_binding("_call_scans_lock", CALL_SCANS_LOCK)
    inflight = typing.cast(
        "dict[str, threading.Event]", ops_binding("_call_scan_inflight", CALL_SCAN_INFLIGHT)
    )
    while True:
        with scans_lock:
            kept = scans.pop(digest, None)
            if kept is not None:
                scans[digest] = kept
                return kept
            event = inflight.get(digest)
            if event is None:
                event = threading.Event()
                inflight[digest] = event
                break
        event.wait()
    try:
        references = scan_references(load_binary(binary))
        calls = sorted(
            (
                {"kind": ref.kind, "from_va": ref.from_va, "to_va": ref.to_va}
                for ref in references
                if ref.kind in {"call", "jmp", "iat_call", "iat_jmp"}
            ),
            key=lambda ref: (ref["from_va"], ref["to_va"], ref["kind"]),
        )
        imports = parse_import_table(binary)
        answer = {
            "references": calls,
            "import_slots": [{"va": va, "name": imports[va]} for va in sorted(imports)],
        }
        if sha256_file(binary) == digest:
            with CALL_SCANS_LOCK:
                scans[digest] = answer
                if len(CALL_SCANS) > _CALL_SCANS_MAX:
                    scans.pop(next(iter(scans)))
        return answer
    finally:
        with CALL_SCANS_LOCK:
            if CALL_SCAN_INFLIGHT.get(digest) is event:
                del CALL_SCAN_INFLIGHT[digest]
        event.set()


def describe(config: WorkerConfig, req: AddressRequest) -> dict[str, Any]:
    """The function dossier ``rebrew binary function --json`` prints."""
    from rebrew.binary.analysis import is_inside
    from rebrew.binary.describe import JSON_KEYS, build_dossier
    from rebrew.formats.binary_loader import load_binary

    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    va = address_va(req.va)
    info = load_binary(cfg.target_binary)
    if not is_inside(info, va):
        raise invalid_request(f"VA 0x{va:x} is outside the binary image")
    dossier = build_dossier(cfg, info, va)
    return {key: dossier[key] for key in JSON_KEYS}


def decompile(config: WorkerConfig, req: DecompileRequest) -> dict[str, Any]:
    """Decompiled source of ``va``; ``named`` applies the project's known struct names."""
    from rebrew.binary.analysis import is_inside
    from rebrew.decompiler import fetch_decompilation
    from rebrew.formats.binary_loader import load_binary
    from rebrew.ghidra import McpError

    if req.backend not in DECOMPILER_BACKENDS:
        raise invalid_request(f"unsupported decompiler backend: {req.backend}")
    refuse_unoffered_decompiler(req.backend)
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    va = address_va(req.va)
    if not is_inside(load_binary(cfg.target_binary), va):
        raise invalid_request(f"VA 0x{va:x} is outside the binary image")
    try:
        code, backend = fetch_decompilation(req.backend, cfg.target_binary, va, cfg.root)
    except McpError as exc:
        raise ghidra_outage(exc) from None
    if not code:
        raise no_decompilation(req.backend, va)
    if req.named:
        from rebrew.c_syntax.name_decomp import apply_known_names
        from rebrew.c_syntax.struct_recover import existing_structs
        from rebrew.source.discovery import iter_library_headers, iter_sources

        sources = [
            *iter_sources(cfg.reversed_dir, cfg),
            *iter_library_headers(cfg.reversed_dir, cfg),
        ]
        pointer_width = int(getattr(cfg, "pointer_size", 4) or 4)
        code = apply_known_names(code, existing_structs(sources), pointer_width=pointer_width).code
    return {"code": code, "backend": backend}


def identify_library(config: WorkerConfig, req: ProjectRequest) -> dict[str, Any]:
    """Library candidates of the default target, as a dry run that writes nothing."""
    from rebrew.config import load_config
    from rebrew.library.identify import collect_candidates
    from rebrew.naming import load_existing_vas

    cfg = load_config(project_root(config, req.project_dir))
    unreadable: list[str] = []
    candidates = collect_candidates(cfg, unreadable=unreadable)
    existing = set(load_existing_vas(cfg.reversed_dir, cfg))
    fresh = sum(1 for candidate in candidates if candidate.va not in existing)
    return {
        "sigs_written": 0,
        "identified": len(candidates),
        "already_annotated": len(candidates) - fresh,
        "to_write": fresh,
        "written": 0,
        "candidates": [
            {
                "va": f"0x{candidate.va:08x}",
                "name": candidate.name,
                "module": candidate.module,
                "kind": candidate.kind,
                "confidence": round(candidate.confidence, 2),
            }
            for candidate in candidates
        ],
        "unreadable_signatures": unreadable,
    }


def structs(config: WorkerConfig, req: StructsRequest) -> dict[str, Any]:
    """Structs recovered from the default target's annotated functions.

    ``limit`` caps how many functions are decompiled; 0 means no cap.  A
    project with no annotated functions answers ``{"functions": 0, "structs": []}``.
    """
    from rebrew.c_syntax.struct_recover import NoDecompilationError, recover_project_structs
    from rebrew.config import load_config
    from rebrew.ghidra import McpError

    if req.decompiler not in DECOMPILER_BACKENDS:
        raise invalid_request(f"unsupported decompiler backend: {req.decompiler}")
    if req.limit < 0:
        raise invalid_request(f"limit must not be negative, got {req.limit}")
    refuse_unoffered_decompiler(req.decompiler)
    cfg = load_config(project_root(config, req.project_dir))
    try:
        return recover_project_structs(
            cfg,
            decompiler=req.decompiler,
            all_funcs=True,
            limit=req.limit or None,
            json_output=True,
        )
    except NoDecompilationError:
        raise OpsError(
            f"decompiler '{req.decompiler}' produced no code for any selected function",
            code=NO_DECOMPILATION,
            status=422,
        ) from None
    except McpError as exc:
        raise ghidra_outage(exc) from None


def binary_operand_locations(config: WorkerConfig, req: OperandLocationsRequest) -> dict[str, Any]:
    """Per function, the requested (offset, operand index) pairs that decode as operands.

    Decoding starts at each function entry with the loader's ISA.
    """
    from rebrew.binary.analysis import capstone_handle
    from rebrew.formats.binary_loader import capstone_config_for, extract_bytes_at_va, load_binary

    if not 1 <= len(req.functions) <= ops_binding("OPERAND_MAX_FUNCTIONS", OPERAND_MAX_FUNCTIONS):
        raise invalid_request(
            f"functions must hold 1 to {ops_binding('OPERAND_MAX_FUNCTIONS', OPERAND_MAX_FUNCTIONS)} entries"
        )
    for function in req.functions:
        if function.va < 0 or not 1 <= function.size <= ops_binding(
            "OPERAND_MAX_FUNCTION_BYTES", OPERAND_MAX_FUNCTION_BYTES
        ):
            raise invalid_request("function extent is outside its bounds")
        if len(function.locations) > ops_binding(
            "OPERAND_MAX_LOCATIONS", OPERAND_MAX_LOCATIONS
        ) or any(
            not 0 <= offset < function.size
            or not 0 <= index <= ops_binding("OPERAND_MAX_INDEX", OPERAND_MAX_INDEX)
            for offset, index in function.locations
        ):
            raise invalid_request("operand locations are outside their bounds")
    with binary_file(config, req.file, req.url, req.sha256, "file") as path:
        info = load_binary(path)
        decoder = capstone_handle(*capstone_config_for(info), detail=True)
        results: list[list[list[int]]] = []
        for function in req.functions:
            code = extract_bytes_at_va(info, function.va, function.size, trim_padding=False)
            if code is None or len(code) != function.size:
                raise invalid_request("operand extent is not file backed")
            wanted = set(function.locations)
            valid: set[tuple[int, int]] = set()
            for instruction in decoder.disasm(code, function.va):
                offset = int(instruction.address) - function.va
                valid.update(
                    (offset, index)
                    for index in range(len(instruction.operands))
                    if (offset, index) in wanted
                )
                if valid == wanted:
                    break
            results.append([list(location) for location in sorted(valid)])
    return {"locations": results}


def binary_function_digests(config: WorkerConfig, req: FunctionDigestsRequest) -> dict[str, Any]:
    """The relocation-masked digest of each extent, parsing the image once.

    Every byte a typed fixup of the image covers is zeroed before hashing, so
    the same function linked at another base digests alike.  Only identities
    leave: no bytes, addresses or masks.  An extent that is not file backed,
    or one whose every byte is a fixup, fails the whole call.
    """
    from rebrew.formats.binary_loader import extract_bytes_at_va, load_binary
    from rebrew.formats.relocations import relocation_spans
    from rebrew.matcher.scoring import normalize_with_reloc_offsets

    if not 1 <= len(req.functions) <= ops_binding("DIGEST_MAX_FUNCTIONS", DIGEST_MAX_FUNCTIONS):
        raise invalid_request(
            f"functions must hold 1 to {ops_binding('DIGEST_MAX_FUNCTIONS', DIGEST_MAX_FUNCTIONS)} entries"
        )
    for extent in req.functions:
        if extent.va < 0 or not 1 <= extent.size <= ops_binding(
            "DIGEST_MAX_FUNCTION_BYTES", DIGEST_MAX_FUNCTION_BYTES
        ):
            raise invalid_request("function extent is outside its bounds")
    with binary_file(config, req.file, req.url, req.sha256, "file") as path:
        info = load_binary(path)
        try:
            spans = relocation_spans(info)
        except NotImplementedError as exc:
            raise invalid_request(bounded(str(exc))) from None
        identities = []
        for extent in req.functions:
            va, size = extent.va, extent.size
            code = extract_bytes_at_va(info, va, size, trim_padding=False)
            if code is None or len(code) != size:
                raise invalid_request("function digest extent is not file backed")
            masked = sorted(
                {
                    offset - va
                    for address, width in spans
                    for offset in range(max(va, address), min(va + size, address + width))
                }
            )
            if len(masked) == size:
                raise invalid_request("function has no unmasked bytes")
            normalized = normalize_with_reloc_offsets(code, masked, pointer_size=1)
            identities.append(
                {
                    "algorithm": DIGEST_ALGORITHM,
                    "arch": info.arch,
                    "size": size,
                    "digest": hashlib.sha256(normalized).hexdigest(),
                }
            )
    return {"identities": identities}


# ---------------------------------------------------------------------------
# Scan ops on a stored binary
# ---------------------------------------------------------------------------


def _scan_binary(config: WorkerConfig, req: BinaryFile) -> contextlib.AbstractContextManager[Path]:
    return binary_file(config, req.key, req.url, req.sha256, "key")


def imports(config: WorkerConfig, req: BinaryFile) -> dict[str, Any]:
    """Import table of the stored binary, as its JSON payload."""
    from rebrew.binary.imports import imports_payload

    with _scan_binary(config, req) as path:
        return imports_payload(path)


def strings(config: WorkerConfig, req: BinaryFile) -> dict[str, Any]:
    """Strings collected from the stored binary, as JSON."""
    from rebrew.binary.strings import collect_strings

    with _scan_binary(config, req) as path:
        return collect_strings(path, json_output=True)


def fingerprint(config: WorkerConfig, req: BinaryFile) -> dict[str, Any]:
    """Fingerprint bundle of the stored binary."""
    from rebrew.binary.fingerprints import fingerprint_bundle

    with _scan_binary(config, req) as path:
        return dict(fingerprint_bundle(path))


def analyze(config: WorkerConfig, req: BinaryFile) -> dict[str, Any]:
    """The standalone dossier: no project, so project-scoped sections stay empty."""
    from rebrew.binary.analyze import build_dossier, standalone_config

    with _scan_binary(config, req) as path:
        return build_dossier(standalone_config(path), path)


def crypto_scan(config: WorkerConfig, req: BinaryFile) -> dict[str, Any]:
    """Crypto constants (each finding named) and APIs.

    With no project there are no function names to match.
    """
    from rebrew.binary.crypto_scan import crypto_scan as scan

    with _scan_binary(config, req) as path:
        return scan(path, [])


def pe_info(config: WorkerConfig, req: BinaryFile) -> dict[str, Any]:
    """PE header fields of the stored binary."""
    from rebrew.binary.pe_info import pe_info as info

    with _scan_binary(config, req) as path:
        return dict(info(path))


def identify_compiler(config: WorkerConfig, req: BinaryFile) -> dict[str, Any]:
    """The toolchain ``rebrew intake`` and ``rebrew doctor`` detect, and the profile it suggests.

    The detection fields (family, version_hint, confidence, evidence, flags,
    detected_by, ...) are ``ToolchainInfo``'s; ``profile`` is the suggested
    rebrew compiler profile, null when no profile fits.  An unreadable or
    unrecognized binary answers family ``unknown``.
    """
    from rebrew.toolchain_detect import detect_toolchain, suggest_profile

    with _scan_binary(config, req) as path:
        info = detect_toolchain(path)
        return {**dataclasses.asdict(info), "profile": suggest_profile(info, path)}


def library_functions(config: WorkerConfig, req: StoredFile) -> dict[str, Any]:
    """The named functions of a static library (``.lib``/``.a``), each with its listing.

    Each member object's function symbols, file-static ones included, come
    with their code disassembled at offset 0 in the object's own ISA: NASM
    source for x86_32, ``asm`` lines otherwise, so a listing compares with a
    linked binary's.  Members of an unknown machine and functions that decode
    to nothing are left out; the rest keep archive order.  ``boundaries`` is
    :data:`rebrew.library.gen_flirt_pat.FUNCTION_BOUNDARIES`, the rule the functions
    were cut by: rows stored under another value describe other functions.
    """
    from rebrew.binary.asm import disassemble_to_nasm
    from rebrew.binary.cfg_ged import apply_self_relocations
    from rebrew.formats.archives import parse_archive
    from rebrew.formats.binary_loader import capstone_config_for, object_arch
    from rebrew.formats.binary_model import BinaryInfo
    from rebrew.library.gen_flirt_pat import FUNCTION_BOUNDARIES, parse_coff_obj, parse_elf_obj

    functions: list[dict[str, Any]] = []
    with binary_file(config, req.file, req.url, req.sha256, "file") as path:
        try:
            members = list(parse_archive(str(path)))
        except ValueError:
            raise invalid_request("the file is not an ar archive") from None
        for _member, obj in members:
            machine = object_arch(obj)
            if machine is None:
                continue
            arch, endian = machine
            cs_arch, cs_mode = capstone_config_for(
                BinaryInfo(path=path, format="", arch=arch, endian=endian)
            )
            symbols = (
                parse_elf_obj(obj, include_local=True)
                if obj.startswith(b"\x7fELF")
                else parse_coff_obj(obj)
            )
            for function in symbols:
                name = function.name
                # Linked at 0: its jump tables and their dispatch hold their
                # labels' offsets, so the tables list as data, as in a target.
                code = apply_self_relocations(function.code, 0, function.self_relocations)
                if arch == NASM_ARCH:
                    listing, _stats = disassemble_to_nasm(code, 0, None)
                else:
                    listing = _asm_listing(code, 0, cs_arch, cs_mode)
                if listing.strip():
                    functions.append(
                        {"name": name, "size": len(code), "arch": arch, "listing": listing}
                    )
    return {"functions": functions, "boundaries": FUNCTION_BOUNDARIES}


# ---------------------------------------------------------------------------
# Splat configs
# ---------------------------------------------------------------------------


def _anchored(path: Path | None) -> str | None:
    """*path* relative to the config's directory when it lies under it."""
    if path is None:
        return None
    return (
        str(path.relative_to(SPLAT_ANCHOR.parent))
        if path.is_relative_to(SPLAT_ANCHOR.parent)
        else str(path)
    )


def splat_parse(_config: WorkerConfig, req: SplatRequest) -> dict[str, Any]:
    """The splat config surface rebrew reads, parsed from the request text.

    Nothing the config names (target binary, symbol files) is opened, and
    nothing is written: ``rebrew source import-splat`` applies a config.
    Paths are as the config spells them, relative to its own directory.  A
    malformed config, an unsupported platform, or a construct outside the
    supported subset is refused with the parser's reason.
    """
    from rebrew.buildsys.splat_config import parse_splat_text

    if len(req.config.encode("utf-8", errors="surrogatepass")) > ops_binding(
        "SPLAT_MAX_CONFIG_BYTES", SPLAT_MAX_CONFIG_BYTES
    ):
        raise invalid_request(
            f"config exceeds {ops_binding('SPLAT_MAX_CONFIG_BYTES', SPLAT_MAX_CONFIG_BYTES)} bytes"
        )
    try:
        parsed = parse_splat_text(req.config, SPLAT_ANCHOR)
    except ValueError as exc:
        raise invalid_request(bounded(str(exc).replace(f"{SPLAT_ANCHOR}: ", ""))) from None
    except RecursionError:
        raise invalid_request("config nesting is too deep") from None
    return {
        "platform": parsed.platform,
        "compiler": parsed.compiler,
        "basename": parsed.basename,
        "target_path": _anchored(parsed.target_path),
        "elf_path": _anchored(parsed.elf_path),
        "rom_end": parsed.rom_end,
        "segments": [
            {
                "name": segment.name,
                "kind": segment.kind,
                "rom_start": segment.rom_start,
                "rom_end": segment.rom_end,
                "vram": segment.vram,
                "bss_size": segment.bss_size,
                "subsegments": [
                    {"rom_start": sub.rom_start, "kind": sub.kind, "name": sub.name}
                    for sub in segment.subsegments
                ],
            }
            for segment in parsed.segments
        ],
        "symbol_addrs_paths": [_anchored(path) for path in parsed.symbol_addrs_paths],
        "undefined_funcs_auto_path": _anchored(parsed.undefined_funcs_auto_path),
        "undefined_syms_auto_path": _anchored(parsed.undefined_syms_auto_path),
        "ignored": [{"key": item.key, "reason": item.reason} for item in parsed.ignored],
    }


# ---------------------------------------------------------------------------
# Project ops
# ---------------------------------------------------------------------------


def report(config: WorkerConfig, req: ReportRequest) -> dict[str, Any]:
    """Render the default target's report site into ``output_dir`` under the workspace.

    The inputs are the request's ``project_dir`` and ``output_dir``; the reply
    is the summary (``out``, ``pages``, ``summary``), not the site.  The
    backend serves ``/reports/<binary_id>/`` from ``reports/<binary_id>`` of
    its own workspace, so the pages reach users only when ``--workspace`` is
    that directory (one host or a shared volume).
    """
    from rebrew.config import load_config
    from rebrew.coverage.report import generate_report

    out = inside_dir(config.require_workspace(), req.output_dir, "output_dir")
    if req.files:
        if req.coverage_input.version != 1 or not req.coverage_input_digest:
            verified_coverage_inputs_required()
        if not re.fullmatch(r"reports/generated/[0-9a-f]{32}", req.output_dir):
            raise invalid_request("retained report output must have a unique generated path")
        if out != config.require_workspace() / req.output_dir:
            raise invalid_request("retained report output must not traverse symlinks")
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            out.mkdir()
        except FileExistsError:
            raise invalid_request("retained report output already exists") from None
        try:
            with retained_target_snapshot(
                config, req.files, req.rebrew_target, req.sha256, req.binary_key, req.binary_url
            ) as snapshot:
                trusted = checked_coverage_input(snapshot, req)
                try:
                    result = generate_report(
                        load_config(snapshot, target=req.rebrew_target), out, trusted=trusted
                    )
                except ValueError as exc:
                    raise OpsError(
                        bounded(str(exc)), code=COVERAGE_INPUT_UNVERIFIED, status=409
                    ) from None
                checked_coverage_input(snapshot, req)
                kinds: dict[str, list[str]] = result.pop("kinds")
                entries: list[dict[str, Any]] = []
                size = 0
                for path in sorted(out.rglob("*")):
                    if path.is_symlink():
                        raise report_output_invalid("the generated report holds a symlink")
                    if path.is_file():
                        size += path.stat().st_size
                        max_files = ops_binding("MAX_REPORT_FILES", MAX_REPORT_FILES)
                        max_bytes = ops_binding("MAX_REPORT_BYTES", MAX_REPORT_BYTES)
                        if len(entries) >= max_files or size > max_bytes:
                            raise report_output_invalid(
                                f"the generated report is over {max_files} files "
                                f"or {max_bytes} bytes"
                            )
                        relative = path.relative_to(out).as_posix()
                        if relative not in kinds:
                            # Every file states what it carries; one that does not
                            # would be served to a reader the data is withheld from.
                            raise OpsError(f"report file {relative} declares no kinds")
                        entries.append(
                            {
                                "path": relative,
                                "size": path.stat().st_size,
                                "digest": sha256_file(path),
                                "kinds": kinds[relative],
                            }
                        )
                if not entries:
                    raise report_output_invalid("the generated report holds no file")
                return {**result, "out": str(out), "manifest": entries}
        except BaseException:
            shutil.rmtree(out)
            raise
    if req.coverage_input.version or req.coverage_input_digest or req.verification_records:
        raise invalid_request("coverage input requires a retained snapshot")
    return generate_report(load_config(project_root(config, req.project_dir)), out)


def security_scan(config: WorkerConfig, req: SecurityScanRequest) -> dict[str, Any]:
    """Rule findings over the default target's reversed sources at ``min_severity`` or above."""
    from rebrew.config import load_config
    from rebrew.security_scan import SEVERITY_ORDER, filter_by_severity
    from rebrew.security_scan import security_scan as scan

    if req.min_severity not in SEVERITY_ORDER:
        raise invalid_request(f"min_severity must be one of {', '.join(SEVERITY_ORDER)}")
    cfg = load_config(project_root(config, req.project_dir))
    root, directory = cfg.root.resolve(), cfg.reversed_dir.resolve()
    if not directory.is_relative_to(root):
        raise invalid_request("the reversed sources lie outside the project")
    result = filter_by_severity(scan(directory), req.min_severity)
    # Paths relative to the project: the engine's own paths never leave it.
    result["root"] = directory.relative_to(root).as_posix()
    for finding in result["findings"]:
        finding["file"] = Path(finding["file"]).relative_to(root).as_posix()
    return result


def target_name(display_name: str) -> str:
    """The rebrew target name for an uploaded file: ``2k-calc.exe`` is ``t_2k_calc``."""
    # NFC first: the same name from a macOS volume arrives NFD, and the
    # combining mark would become ``_`` while an NFC accent becomes ``_``
    # mid-word, yielding two target names for one file (``Cafe\u0301``
    # -> ``Cafe`` vs ``Caf\u00e9`` -> ``Caf``).  ASCII-digit test: the stem
    # is ``[A-Za-z0-9_]`` only, so ``str.isdigit`` cannot see a non-ASCII digit.
    stem = TARGET_UNSAFE.sub("_", Path(unicodedata.normalize("NFC", display_name)).stem)
    stem = stem.strip("_") or "target"
    return f"t_{stem}" if "0" <= stem[0] <= "9" else stem


def run_intake(binary: Path, project: Path, target: str) -> dict[str, Any]:
    """Run ``rebrew intake --json`` in *project*.

    Intake onboards the project in its working directory and has no entry
    point that takes a root, so it runs through :func:`run_rebrew`.
    """
    return run_rebrew(
        ["intake", "--json", "--target", target, str(binary)], project, INTAKE_TIMEOUT_SECONDS
    )


def run_rebrew(
    arguments: list[str],
    project: Path,
    timeout: int,
    *,
    outcome_exit: bool = False,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run ``rebrew <arguments>`` in *project* and answer the JSON object it prints.

    *arguments* must select JSON output.  The commands an op runs this way
    work in their working directory, print their report rather than return
    it, or exit through ``error_exit``, while ``serve`` handles calls on
    threads sharing one cwd and one stdout, so each runs as a child process
    in its own session; a timeout kills the whole group.  With
    *outcome_exit*, exit 1 (rebrew's mismatch or failed-check outcome) also
    answers the printed report; any other non-zero exit is a refusal carrying
    the command's JSON error message.  *environment* adds child-only variables
    without mutating the worker process's environment (which concurrent calls
    share).  The child gets the call's deadline (or
    *timeout*, when sooner) less :data:`CHILD_REPORT_SECONDS` in
    ``REBREW_CALL_DEADLINE``, so its remote compiles stop retrying in time.
    The function records the child's reads skipped (their source's anchor names
    another function) join the call's ones (:func:`_skipped_records`).
    """
    override = ops_binding("run_rebrew", run_rebrew)
    if override is not run_rebrew:
        extra = {"environment": environment} if environment is not None else {}
        return typing.cast(
            "dict[str, Any]",
            override(arguments, project, timeout, outcome_exit=outcome_exit, **extra),
        )
    from rebrew.compiler.temp_dirs import remove_temp_dir, writable_temp_dir
    from rebrew.metadata.bindings import note_skipped_records

    directory = writable_temp_dir("rebrew-skipped-records-")
    skipped_file = directory / "skipped.json"
    try:
        return run_rebrew_child(
            arguments,
            project,
            timeout,
            outcome_exit=outcome_exit,
            skipped_file=skipped_file,
            environment=environment,
        )
    finally:
        if skipped_file.is_file():
            # A child killed while writing leaves an unreadable file: it skipped what it
            # logged, and the reply names none of it rather than failing the call.
            with contextlib.suppress(ValueError, TypeError):
                note_skipped_records(
                    (str(module), int(va))
                    for module, va in json.loads(skipped_file.read_text(encoding="utf-8"))
                )
        remove_temp_dir(directory)


def run_rebrew_child(
    arguments: list[str],
    project: Path,
    timeout: int,
    *,
    outcome_exit: bool,
    skipped_file: Path,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """:func:`run_rebrew` with the file the child writes its skipped records to."""
    override = ops_binding("_run_rebrew_child", run_rebrew_child)
    if override is not run_rebrew_child:
        return typing.cast(
            "dict[str, Any]",
            override(
                arguments,
                project,
                timeout,
                outcome_exit=outcome_exit,
                skipped_file=skipped_file,
                environment=environment,
            ),
        )
    from rebrew.compiler.compile import CALL_DEADLINE_ENV
    from rebrew.metadata.bindings import SKIPPED_RECORDS_ENV

    name = " ".join(word for word in arguments[:2] if not word.startswith("-"))
    cancellation = CANCELLATION_VAR.get()
    left = None
    if cancellation is not None:
        cancellation.check()
        left = cancellation.remaining()
    budget = timeout if left is None else min(timeout, left)
    child_deadline = time.time() + max(0.0, budget - CHILD_REPORT_SECONDS)
    # -P keeps the project cwd off sys.path so a rebrew/ tree inside the
    # project cannot shadow the installed rebrew.app.main (code exec).
    command = [sys.executable, "-P", "-m", "rebrew.app.main"]
    # A caller that takes progress gets the counts the child writes (verify
    # and build round-trip do) through a pipe; pass_fds is POSIX-only.
    sink = PROGRESS_VAR.get()
    remote = current_remote_compiles()
    pipe = ProgressPipe() if sink is not None and os.name == "posix" else None
    try:
        with step(f"starting rebrew {name}"):
            process = subprocess.Popen(
                [*command, *arguments],
                cwd=project,
                # The child exports its own spans (the remote compile's client span) under this one.
                env={
                    **os.environ,
                    **(environment or {}),
                    **telemetry.child_environment(),
                    CALL_DEADLINE_ENV: repr(child_deadline),
                    # The child counts its remote compiles into the op call's ledger.
                    **({} if remote is None else remote.environment()),
                    **({} if pipe is None else {PROGRESS_FD_ENV: str(pipe.write_fd)}),
                    # The child writes the records its reads skipped there (see _noted_skips).
                    SKIPPED_RECORDS_ENV: str(skipped_file),
                },
                pass_fds=() if pipe is None else (pipe.write_fd,),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                start_new_session=True,
            )
    except BaseException:
        if pipe is not None:
            pipe.close()
        raise
    relay = None
    if pipe is not None and sink is not None:
        pipe.close_write()
        relay = _relay(pipe, sink)
    try:
        stdout, stderr = communicate(process, timeout, cancellation, relay)
    except (subprocess.TimeoutExpired, OpsError) as stopped:
        from rebrew.utils import stop_process_tree

        # Snapshot descendants before signalling the group. A helper that called
        # setsid escapes the group; killing only the group first reparents it to
        # init, so the later process-tree walk can no longer find or stop it.
        stop_process_tree(process)
        # Do not call communicate() unbounded here: a grandchild that escaped
        # the process group can hold the pipe write end, and Python's
        # communicate() waits for EOF forever on it.  utils.run_process_group
        # handles the same wedged-writer case by killing descendants, waiting
        # with a timeout, then closing the read ends.
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            from rebrew.utils import release_captured_pipes, stop_process_tree

            stop_process_tree(process)
            release_captured_pipes(process)
        if isinstance(stopped, OpsError):  # the call was cancelled
            raise
        raise OpsError(f"rebrew {name} did not finish within {timeout} s") from None
    except BaseException:
        # KeyboardInterrupt / SystemExit during communicate(): without this
        # the child (and its whole process group) outlives the serve thread
        # that spawned it, accumulating one orphaned rebrew per interrupted
        # request.  Mirror utils.run_process_group's BaseException path.
        from rebrew.utils import stop_process_tree

        stop_process_tree(process)
        raise
    finally:
        if pipe is not None:
            pipe.close()
    refused = process.returncode != 0 and not (outcome_exit and process.returncode == 1)
    if refused and outcome_exit and process.returncode == EXIT_ERROR:
        # rebrew test prints a NOT_RUN result (the compile service never ran it) and exits 2.
        with contextlib.suppress(json.JSONDecodeError):
            printed = json.loads(stdout)
            if isinstance(printed, dict) and printed.get("status") == "NOT_RUN":
                return final_recompile_refusal(printed)
    if refused:
        kind, message = _command_refusal(stderr)
        if kind == "usage":
            # The command rejected its input (clispec ``usage``): the caller's request.
            raise invalid_request(
                bounded(f"rebrew {name} refused: {without_host_paths(message, [project])}")
            )
        from rebrew.cli import (
            BINDING_CONFLICT_KIND,
            COMPILER_NOT_OFFERED_KIND,
            TOOLCHAIN_REJECTED_KIND,
        )

        if kind == BINDING_CONFLICT_KIND:
            # The child names the record by its key; _refusing_disagreeing_records answers it.
            raise BindingConflictError(bounded(message))
        if kind == TOOLCHAIN_REJECTED_KIND:
            raise toolchain_rejected(message, [project])
        if kind == COMPILER_NOT_OFFERED_KIND:
            # The child's message is the refusal's own: a withdrawn compiler's reason.
            raise OpsError(bounded(message), code=COMPILER_NOT_OFFERED, status=400)
        logger.error(
            "rebrew %s exited %d: %s", name, process.returncode, escape_log_text(stderr.strip())
        )
        raise OpsError(bounded(f"rebrew {name} failed: {without_host_paths(message, [project])}"))
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError:
        logger.exception(
            "rebrew %s printed no JSON report: %s", name, escape_log_text(stderr.strip())
        )
        raise OpsError(f"rebrew {name} printed no JSON report") from None
    if not isinstance(report, dict):
        raise OpsError(f"rebrew {name} answered a report that is not an object")
    return report


def _relay(pipe: ProgressPipe, sink: Callable[[int, int], None]) -> Callable[[], None]:
    """Hand *sink* each new count the child wrote to *pipe*."""

    def forward() -> None:
        count = pipe.poll()
        if count is not None:
            sink(*count)

    return forward


def communicate(
    process: subprocess.Popen[str],
    timeout: float,
    cancellation: Cancellation | None,
    relay: Callable[[], None] | None = None,
) -> tuple[str, str]:
    """``process.communicate(timeout=timeout)`` that also ends when the call is cancelled.

    Raises ``subprocess.TimeoutExpired`` at *timeout*, and the call's
    :class:`OpsError` once *cancellation* is set; the caller stops the child
    either way.  *relay* forwards the child's progress at each check and once
    the child is done.
    """
    override = ops_binding("_communicate", communicate)
    if override is not communicate:
        return typing.cast("tuple[str, str]", override(process, timeout, cancellation, relay))
    deadline = ops_binding("time", time).monotonic() + timeout
    while True:
        try:
            stdout, stderr = process.communicate(
                timeout=timeout
                if cancellation is None
                else min(CANCEL_POLL_SECONDS, max(0.0, deadline - time.monotonic()))
            )
        except subprocess.TimeoutExpired:
            if cancellation is None:
                raise
            if relay is not None:
                relay()
            cancellation.check()
            if time.monotonic() >= deadline:
                raise
            continue
        if relay is not None:
            relay()
        return stdout, stderr


def _command_refusal(stderr: str) -> tuple[str, str]:
    """The kind and message of a command's JSON error line, or its exit being unexplained."""
    for line in reversed(stderr.splitlines()):
        with contextlib.suppress(json.JSONDecodeError):
            payload = json.loads(line)
            if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
                error = payload["error"]
                return str(error.get("kind", "")), str(error.get("message", ""))
    return "", "no error report"


def _binary_project(config: WorkerConfig, project_id: str, sha256: str) -> str:
    """The workspace-relative directory of a stored binary's project in *project_id*'s scope."""
    if len(project_id.encode("utf-8")) > 256 or "\x00" in project_id:
        raise invalid_request("project_id must be at most 256 UTF-8 bytes without NUL")
    workspace = config.require_workspace()
    if not project_id:
        relative = f"projects/{sha256_hex(sha256)}"
    else:
        scope = hashlib.sha256(project_id.encode("utf-8")).hexdigest()
        relative = f"projects/scopes/{scope}/{sha256_hex(sha256)}"
    if inside_dir(workspace, relative, "analysis project") != workspace / relative:
        raise invalid_request("analysis project must not traverse symlinks")
    return relative


def analyse(config: WorkerConfig, req: AnalyseRequest) -> dict[str, Any]:
    """Onboard a stored binary into its project-scoped workspace and report its coverage.

    A second run re-discovers into the same project.  ``intake`` is the onboarding report;
    ``discovery_rule`` is :data:`rebrew.binary.discover.DISCOVERY_RULE`, the rule the functions
    were discovered under.
    """
    workspace = config.require_workspace()
    relative = _binary_project(config, req.project_id, req.sha256)
    project = workspace / relative
    with binary_file(config, req.file_key, req.url, req.sha256, "file_key") as binary:
        project.mkdir(parents=True, exist_ok=True)
        if inside_dir(workspace, relative, "analysis project") != project:
            raise invalid_request("analysis project must not traverse symlinks")
        # A file rebrew cannot parse is the caller's (422), refused before the intake
        # child degrades to string evidence and finds no functions.  The capture
        # below reads the same parse from load_binary's cache.
        load_binary(binary)
        intake_fn = ops_binding("_run_intake", run_intake)
        target_id = target_name(req.name)
        intake = (
            run_intake(binary, project, target_id)
            if intake_fn is run_intake
            else intake_fn(binary, project, target_id)
        )
        capture, report = capture_fresh_analysis(config, binary, req.sha256, target_id)
        for item in report["targets"]:
            for field in ("document", "path"):
                if item[field]:
                    item[field] = str(project / item[field])
    from rebrew.binary.discover import DISCOVERY_RULE

    return {
        **report,
        "project": str(project),
        "intake": intake,
        "analysis_capture": capture,
        "discovery_rule": DISCOVERY_RULE,
    }


def fresh_sqlite_metadata(root: Path, target: str, scratch: Path) -> dict[str, Any]:
    """Import the independent intake before selecting SQLite and closing its readset."""
    from rebrew.config import load_config
    from rebrew.metadata.sqlite import (
        DATABASE_FILENAME,
        metadata_database_documents,
        snapshot_metadata_database,
    )
    from rebrew.metadata.storage import project_metadata_stores
    from rebrew.metadata_sets import describe_metadata
    from rebrew.metadata_transfer import migrate_metadata, migration_input_digest

    cfg = load_config(root, target=target)
    if cfg.metadata_read_backends != ("toml",) or cfg.metadata_write_backends != ("toml",):
        raise capture_failed("fresh analysis requires an independent TOML intake")
    confined_snapshot_config(cfg, root)
    logical = {
        store.path.relative_to(root).as_posix(): store.digest()
        for store in project_metadata_stores(root, recursive=True)
    }
    if "rebrew-functions.toml" not in logical:
        raise capture_failed("fresh analysis requires function metadata before import")
    # One migration pinned to its input digest: hashing the stores costs nothing beside the
    # format-preserving parse a preview would add, and a change in between still refuses.
    migrate_metadata(cfg, "sqlite", expected_digest=migration_input_digest(cfg, "sqlite"))
    cfg = load_config(root, target=target)
    if cfg.metadata_read_backends != ("sqlite",) or cfg.metadata_write_backends != ("sqlite",):
        raise capture_failed("fresh analysis metadata import did not select SQLite")
    with tempfile.TemporaryDirectory(prefix="metadata-snapshot-", dir=scratch) as temp:
        snapshot = snapshot_metadata_database(root, Path(temp) / DATABASE_FILENAME)
        documents = metadata_database_documents(snapshot)
        if documents != logical:
            raise capture_failed("fresh analysis metadata import changed logical documents")
        os.replace(snapshot, root / DATABASE_FILENAME)
    descriptor = describe_metadata(root, exclusive=False)
    if {item["path"]: item["logical_sha256"] for item in descriptor["documents"]} != logical:
        raise capture_failed("fresh analysis metadata changed after import")
    return descriptor


def capture_fresh_analysis(
    config: WorkerConfig, binary: Path, sha256: str, target: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Capture the complete baseline readset from a new, independent intake."""
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="analysis-capture-", dir=scratch) as temp:
        root = Path(temp).resolve()
        intake_fn = ops_binding("_run_intake", run_intake)
        if intake_fn is run_intake:
            run_intake(binary, root, target)
        else:
            intake_fn(binary, root, target)
        for path in root.rglob("*"):
            if path.is_symlink():
                raise capture_failed("fresh analysis capture contains a symlink")
        check_cancelled()
        try:
            metadata = ops_binding("_fresh_sqlite_metadata", fresh_sqlite_metadata)(
                root, target, scratch
            )
        except OpsError:
            raise
        except (OSError, ValueError, RebrewError) as exc:
            raise capture_failed(f"fresh analysis metadata migration failed: {exc}") from exc
        check_cancelled()
        return capture_project(root, sha256, target, metadata, "fresh analysis")


def capture_project(
    root: Path, sha256: str, target: str, metadata: dict[str, Any] | None, what: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Capture the complete readset of the project at *root* for *target* and report it.

    *metadata* is the SQLite metadata descriptor already selected in *root*;
    *what* names the project in refusals ("fresh analysis", "project import").
    """
    from rebrew.config import inventory_path_for, load_config
    from rebrew.coverage.project import coverage_inputs
    from rebrew.source.discovery import iter_headers, iter_sources

    cfg = load_config(root, target=target)
    confined_snapshot_config(cfg, root)
    if cfg.raw_link is not None:
        raise capture_failed(f"{what} capture cannot include an unverified raw link")
    if not cfg.target_binary.is_file() or sha256_file(cfg.target_binary) != sha256:
        raise invalid_request(f"{what} binary does not match the request")
    inventory = inventory_path_for(cfg.reversed_dir, cfg).resolve()
    source_paths = {p.resolve() for p in iter_sources(cfg.reversed_dir, cfg)}
    source_paths.update(p.resolve() for p in iter_headers(cfg.reversed_dir, cfg))
    paths = {Path(entry[0]) for entry in coverage_inputs(cfg)}
    entries: list[dict[str, Any]] = []
    total = 0
    max_files = ops_binding("MAX_READSET_FILES", MAX_READSET_FILES)
    max_bytes = ops_binding("MAX_READSET_BYTES", MAX_READSET_BYTES)
    max_file_bytes = ops_binding("MAX_READSET_FILE_BYTES", MAX_READSET_FILE_BYTES)
    captured_count = sum(1 for path in paths if path.resolve().is_relative_to(root))
    if captured_count > max_files:
        raise readset_limit(f"{what} capture", captured_count, max_files)
    for path in sorted(
        paths, key=lambda value: str(value).encode("utf-8", errors="surrogateescape")
    ):
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            if path.exists() or path.is_symlink():
                raise capture_failed(f"{what} reads an ambient input")
            continue
        relative = resolved.relative_to(root).as_posix()
        if path.is_symlink() or relative == ".":
            raise capture_failed(f"invalid {what} readset")
        if not path.exists():
            entries.append(
                {"path": relative, "kind": "absent", "size": 0, "digest": "", "data": ""}
            )
            continue
        if not path.is_file():
            raise capture_failed(f"{what} readset contains an unsupported directory")
        if "verify_cache" in path.name:
            raise capture_failed(f"{what} capture must not contain verification cache")
        if resolved == cfg.target_binary.resolve():
            entries.append(
                {
                    "path": relative,
                    "kind": "binary",
                    "size": path.stat().st_size,
                    "digest": sha256,
                    "data": "",
                }
            )
            continue
        size = path.stat().st_size
        total += size
        if size > max_file_bytes:
            raise readset_limit(f"{what} input {relative}", size, max_file_bytes, "bytes")
        if total > max_bytes:
            raise readset_limit(f"{what} capture", total, max_bytes, "bytes")
        data = path.read_bytes()
        if len(data) != size:
            raise capture_failed(f"{what} input changed during capture")
        entries.append(
            {
                "path": relative,
                "kind": "file",
                "role": "source" if resolved in source_paths else "analysis",
                "size": size,
                "digest": hashlib.sha256(data).hexdigest(),
                "data": base64.b64encode(data).decode("ascii"),
            }
        )
    report = ops_binding("project_report", project_report)(
        root, None, include_source=True, only=target
    )
    # The report is an assertion by this worker, so its complete captured
    # readset must still match after the report was constructed.
    current_paths = {Path(entry[0]) for entry in coverage_inputs(cfg)}
    current_sources = {p.resolve() for p in iter_sources(cfg.reversed_dir, cfg)}
    current_sources.update(p.resolve() for p in iter_headers(cfg.reversed_dir, cfg))
    if current_paths != paths or current_sources != source_paths:
        raise capture_failed(f"{what} input changed during reporting")
    # A row may bind a source outside the reversed directory (a library row's reference
    # source), which the coverage readset does not read: every source the report names is
    # captured as a source, so a reader of the capture finds each function's file.
    by_path = {entry["path"]: entry for entry in entries}
    for item in report["targets"]:
        for row in item["functions"]:
            relative = row.get("source_path", "")
            if not relative:
                continue
            captured = by_path.get(relative)
            if captured is not None and captured["kind"] == "file":
                captured["role"] = "source"
                continue
            path = root / relative
            if captured is not None or not path.is_file() or path.is_symlink():
                raise capture_failed(f"{what} report names a source it cannot capture")
            size = path.stat().st_size
            total += size
            if size > max_file_bytes:
                raise readset_limit(f"{what} input {relative}", size, max_file_bytes, "bytes")
            if total > max_bytes:
                raise readset_limit(f"{what} capture", total, max_bytes, "bytes")
            if len(by_path) >= max_files:
                raise readset_limit(f"{what} capture", len(by_path) + 1, max_files)
            data = path.read_bytes()
            by_path[relative] = {
                "path": relative,
                "kind": "file",
                "role": "source",
                "size": len(data),
                "digest": hashlib.sha256(data).hexdigest(),
                "data": base64.b64encode(data).decode("ascii"),
            }
    entries = sorted(
        by_path.values(), key=lambda entry: entry["path"].encode("utf-8", errors="surrogateescape")
    )
    for captured in entries:
        path = root / captured["path"]
        if any(
            part.is_symlink()
            for part in (path, *path.parents)
            if part != root and part.is_relative_to(root)
        ):
            raise capture_failed(f"{what} input changed during reporting")
        if captured["kind"] == "absent":
            if path.exists():
                raise capture_failed(f"{what} input changed during reporting")
        elif (
            not path.is_file()
            or path.stat().st_size != captured["size"]
            or sha256_file(path) != captured["digest"]
        ):
            raise capture_failed(f"{what} input changed during reporting")
    selected = None
    if inventory.is_relative_to(root):
        relative_inventory = inventory.relative_to(root).as_posix()
        selected = next((entry for entry in entries if entry["path"] == relative_inventory), None)
    if selected is not None and selected["kind"] == "file" and selected.get("role") == "analysis":
        project_config = next(
            (entry for entry in entries if entry["path"] == "rebrew-project.toml"), None
        )
        if project_config is None or project_config["kind"] != "file":
            raise capture_failed(f"{what} configuration is not captured")
        for captured in (project_config, selected):
            path = root / captured["path"]
            if (
                any(
                    part.is_symlink()
                    for part in (path, *path.parents)
                    if part != root and part.is_relative_to(root)
                )
                or not path.is_file()
                or path.stat().st_size != captured["size"]
                or sha256_file(path) != captured["digest"]
            ):
                raise capture_failed(f"{what} input changed during reporting")
        if not cfg.target_binary.is_file() or sha256_file(cfg.target_binary) != sha256:
            raise capture_failed(f"{what} input changed during reporting")
        current = load_config(root, target=target)
        if inventory_path_for(current.reversed_dir, current).resolve() != inventory:
            raise capture_failed(f"{what} inventory changed during reporting")
    for item in report["targets"]:
        for part in ("document", "path"):
            if item[part]:
                item[part] = str(Path(item[part]).relative_to(root))
    capture = {
        "version": 3,
        "binary_sha256": sha256,
        "target": target,
        "metadata": metadata,
        "entries": entries,
    }
    if selected is not None and selected["kind"] == "file" and selected.get("role") == "analysis":
        capture["inventory_path"] = selected["path"]
    if len(report["targets"]) == 1:
        item = report["targets"][0]
        if item["name"] != target or item["sha256"] != sha256:
            raise capture_failed(f"{what} report has a different target")
        functions: list[dict[str, Any]] = []
        stubs: list[dict[str, Any]] = []
        seen: set[int] = set()
        for raw, result, size_field in (
            (item["functions"], functions, True),
            (item["stubs"], stubs, False),
        ):
            for row in raw:
                va, name = row["va"], row["name"]
                if (
                    type(va) is not int
                    or not 0 <= va <= 2**63 - 1
                    or va in seen
                    or not isinstance(name, str)
                    or not name
                    or len(name.encode("utf-8")) > 4096
                ):
                    raise capture_failed(f"invalid {what} report identity")
                entry = {"va": va, "name": name}
                if size_field:
                    size = row["size"]
                    if type(size) is not int or not 0 <= size <= 2**63 - 1:
                        raise capture_failed(f"invalid {what} report extent")
                    entry["size"] = size
                seen.add(va)
                result.append(entry)
            result.sort(key=lambda row: row["va"])
        report_path = ANALYSIS_REPORT_PATH
        report_location = root / report_path
        if (
            report_location.exists()
            or any(
                part.is_symlink()
                for part in (report_location, *report_location.parents)
                if part != root and part.is_relative_to(root)
            )
            or any(e["path"] == report_path for e in entries)
        ):
            raise capture_failed(f"{what} report path already exists")
        normalized = json.dumps(
            {
                "version": 1,
                "binary_sha256": sha256,
                "target": target,
                "functions": functions,
                "stubs": stubs,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if (
            len(normalized) <= max_file_bytes
            and total + len(normalized) <= max_bytes
            and len(entries) < max_files
        ):
            entries.append(
                {
                    "path": report_path,
                    "kind": "file",
                    "role": "analysis",
                    "size": len(normalized),
                    "digest": hashlib.sha256(normalized).hexdigest(),
                    "data": base64.b64encode(normalized).decode("ascii"),
                }
            )
            entries.sort(key=lambda entry: entry["path"].encode("utf-8", errors="surrogateescape"))
            capture["report_path"] = report_path
    return capture, report


#: Compiler settings an imported project may not carry: each would run a program of the
#: project's choosing or reach a host of its choosing.  An empty value is the default.
_IMPORT_FORBIDDEN_COMPILER = ("command", "runner", "execution_backend", "recompile_url")


def _import_settings_refusal(raw: dict[str, Any]) -> None:
    """Refuse an imported configuration that would run or reach something, or keep metadata off TOML."""
    from rebrew.metadata.storage import backend_routes
    from rebrew.workspace import targets_table

    tables: list[tuple[str, Any]] = [("compiler", raw.get("compiler"))]
    tables += [
        (f"targets.{name}.compiler", entry.get("compiler"))
        for name, entry in targets_table(raw).items()
    ]
    for where, table in tables:
        if not isinstance(table, dict):
            continue
        for key in _IMPORT_FORBIDDEN_COMPILER:
            if table.get(key, "") != "":
                raise import_refused(
                    f"rebrew-project.toml sets [{where}] {key}; an imported project compiles"
                    " only through the hosted compile service, so remove it"
                )
    try:
        routes = backend_routes(raw.get("metadata", {}))
    except ValueError as exc:
        raise import_refused(f"rebrew-project.toml [metadata]: {exc}") from None
    if routes != (("toml",), ("toml",)):
        raise import_refused(
            "rebrew-project.toml selects a metadata backend other than TOML; export the project"
            " with `rebrew metadata migrate toml` first"
        )


def _import_target(root: Path, raw: dict[str, Any], sha256: str) -> str:
    """The one target whose binary inside the archive hashes to *sha256*."""
    from rebrew.workspace import target_binary, targets_table

    matches = []
    for name, entry in sorted(targets_table(raw).items()):
        binary = target_binary(root, entry)
        if binary is None or not binary.resolve().is_relative_to(root) or not binary.is_file():
            continue
        if sha256_file(binary) == sha256:
            matches.append(name)
    if not matches:
        raise import_refused(
            f"no target in rebrew-project.toml names a binary inside the archive with sha256 {sha256}"
            " (the project binary); include that exact file at the target's binary path"
        )
    if len(matches) > 1:
        raise import_refused(f"targets {', '.join(matches)} all name the project binary; keep one")
    entry = targets_table(raw)[matches[0]]
    if entry.get("raw_link"):
        raise import_refused(
            f"rebrew-project.toml sets raw_link for target {matches[0]}; an imported raw link is an"
            " unverified build output, so remove it"
        )
    return matches[0]


def _remove_replaced_project(path: Path) -> None:
    """Delete the project an import replaced, keeping what the worker may not remove.

    A file the worker cannot unlink (in production a ``PRINCIPLES.md`` an older
    rebrew copied with the SELinux category of an earlier pod) stays under
    *path* and is logged with its error for the operator; the import that
    replaced the project has already succeeded.
    """

    def keep(_function: Any, name: str, exc: BaseException) -> None:
        logger.warning("project import left %s of the replaced project at %s: %s", name, path, exc)

    shutil.rmtree(path, onexc=keep)


def _exchange_project_directories(staged: Path, project: Path) -> None:
    """Publish a replacement without exposing a gap at the canonical project path."""

    try:
        renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError:
        raise OSError(errno.ENOSYS, "atomic project directory exchange is unavailable") from None
    at_fdcwd = -100
    rename_exchange = 2
    if renameat2(at_fdcwd, os.fsencode(staged), at_fdcwd, os.fsencode(project), rename_exchange):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def import_archive(config: WorkerConfig, req: ImportArchiveRequest) -> dict[str, Any]:
    """Install an uploaded rebrew project archive as a stored binary's project and report it.

    The archive is unpacked under the bounds of :mod:`rebrew.project_archive` into
    scratch, its target whose binary hashes to ``sha256`` is selected, the
    metadata is scoped to that target's module and moved to SQLite, and the
    project is captured as an analysis is.  Only then does it replace the
    binary's project directory in ``project_id``'s scope.  Nothing from the
    archive runs: no intake, toolchain, execution backend or script.
    """
    from rebrew.config import load_config, target_module
    from rebrew.errors import ConfigError
    from rebrew.metadata.storage import metadata_store
    from rebrew.metadata_transfer import scope_metadata_to_module
    from rebrew.project_archive import ProjectArchiveError, unpack_project_archive
    from rebrew.workspace import read_config

    workspace = config.require_workspace()
    relative = _binary_project(config, req.project_id, req.sha256)
    scratch = workspace / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    with (
        binary_file(
            config, req.archive_key, req.archive_url, req.archive_sha256, "archive_key"
        ) as archive,
        tempfile.TemporaryDirectory(prefix="project-import-", dir=scratch) as temp,
    ):
        unpacked = Path(temp).resolve() / "project"
        unpacked.mkdir()
        try:
            root = unpack_project_archive(archive, unpacked)
        except ProjectArchiveError as exc:
            raise import_refused(str(exc)) from None
        check_cancelled()
        try:
            raw = read_config(root)
        except RebrewError as exc:
            raise invalid_project_config(root, exc) from None
        _import_settings_refusal(raw)
        target = _import_target(root, raw, req.sha256)
        try:
            cfg = load_config(root, target=target)
        except ConfigError as exc:
            raise invalid_project_config(root, exc) from None
        try:
            confined_snapshot_config(cfg, root)
        except OpsError as exc:
            raise import_refused(str(exc)) from None
        if not metadata_store(root / "rebrew-functions.toml").exists():
            raise import_refused("the archive has no rebrew-functions.toml function metadata")
        module = target_module(cfg)
        check_cancelled()
        try:
            dropped = scope_metadata_to_module(cfg, module)
            check_cancelled()
            metadata = ops_binding("_fresh_sqlite_metadata", fresh_sqlite_metadata)(
                root, target, scratch
            )
        except OpsError:
            raise
        except (OSError, ValueError, RebrewError) as exc:
            detail = str(exc).replace(f"{root}{os.sep}", "")
            raise import_refused(f"the archive's metadata cannot be imported: {detail}") from None
        check_cancelled()
        capture, report = capture_project(root, req.sha256, target, metadata, "project import")
        # The last check: past it the import replaces the binary's project.
        check_cancelled()
        project = workspace / relative
        project.parent.mkdir(parents=True, exist_ok=True)
        if inside_dir(workspace, relative, "analysis project") != project:
            raise invalid_request("analysis project must not traverse symlinks")
        try:
            root.rename(project)
        except OSError as exc:
            if exc.errno not in {errno.EEXIST, errno.ENOTEMPTY}:
                raise
            replaced = Path(tempfile.mkdtemp(prefix="replaced-", dir=scratch))
            try:
                # Keep the displaced tree outside the temporary directory's automatic cleanup.
                staged = root.rename(replaced / project.name)
                _exchange_project_directories(staged, project)
            finally:
                _remove_replaced_project(replaced)
    for item in report["targets"]:
        for part in ("document", "path"):
            if item[part]:
                item[part] = str(project / item[part])
    intake = {
        "source": "archive",
        "archive_sha256": req.archive_sha256,
        "target": target,
        "module": module,
        "dropped_records": dropped,
    }
    return {**report, "project": str(project), "intake": intake, "analysis_capture": capture}


@contextlib.contextmanager
def _staged_file_set(config: WorkerConfig, files: list[RetainedFile]) -> Iterator[Path]:
    """Stage a supplied project file set under the retained-snapshot rules."""
    from rebrew.utils import portable_path_parts

    check_manifest_size(files)
    paths = {entry.path for entry in files}
    if len(paths) != len(files) or any(not portable_path_parts(path) for path in paths):
        raise invalid_request("duplicate or invalid file set path")
    if "rebrew-project.toml" not in paths:
        raise invalid_request("a file set requires rebrew-project.toml")
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="file-set-", dir=scratch) as temp:
        root = Path(temp).resolve()
        stage_retained_files(config, root, files, exclusive=True)
        yield root


def _metadata_answer[T](read: Callable[[], T]) -> T:
    """Run a metadata read, answering 400 for a set rebrew cannot read."""
    try:
        return read()
    except (OSError, ValueError, RebrewError) as exc:
        raise invalid_request(f"invalid metadata set: {exc}") from exc


def release(_config: WorkerConfig, _req: ReleaseRequest) -> dict[str, Any]:
    """The engine's rebrew release and the SHA-256 of the dispatch schema it serves.

    A caller compares ``schema_sha256`` with the schema it was built against and
    refuses an engine that serves another before it relies on any other op.
    """

    return {"release": __version__, "schema_sha256": DISPATCH_SCHEMA_SHA256}


def vocabulary(_config: WorkerConfig, _req: VocabularyRequest) -> dict[str, Any]:
    """The names rebrew owns that a client must match rather than copy.

    ``statuses`` is the function STATUS table: every status a row may hold, the
    byte matches, the earned results a tool failure may not overwrite, the tool
    failures themselves, and the legacy spellings ``canonical_status`` folds
    (after trimming and upper-casing). ``cache_files`` are the file names of
    derived caches rebrew writes in a project, which a client never retains as input.
    ``placeholder_name`` is :data:`rebrew.workspace.names.PLACEHOLDER_NAME_PATTERN`:
    a name is a generated label when the whole name matches it.
    ``discovery_rule`` is :data:`rebrew.binary.discover.DISCOVERY_RULE`, the rule
    ``rebrew.analyse`` discovers functions under now.  ``decompilers`` is, for
    every decompiler the ops name but ``auto``, whether it can run on this engine
    (:func:`engine_decompilers`; checked again at most every 30 s): ``available``,
    ``not-installed`` or ``unreachable``, with a ``reason`` when it is not available.
    """
    from rebrew.binary.discover import DISCOVERY_RULE
    from rebrew.verify.cache import CACHE_FILENAMES
    from rebrew.workspace.names import PLACEHOLDER_NAME_PATTERN
    from rebrew.workspace.status import (
        EARNED_STATUSES,
        INFRASTRUCTURE_STATUSES,
        KNOWN_STATUSES,
        MATCHED_STATUSES,
        STATUS_ALIASES,
    )

    return {
        "statuses": {
            "known": sorted(KNOWN_STATUSES),
            "matched": list(MATCHED_STATUSES),
            "earned": list(EARNED_STATUSES),
            "infrastructure": list(INFRASTRUCTURE_STATUSES),
            "aliases": [
                {"alias": alias, "canonical": STATUS_ALIASES[alias]}
                for alias in sorted(STATUS_ALIASES)
            ],
        },
        "cache_files": list(CACHE_FILENAMES),
        "placeholder_name": PLACEHOLDER_NAME_PATTERN,
        "discovery_rule": DISCOVERY_RULE,
        "decompilers": [state.to_dict() for state in engine_decompilers()],
    }


def check_cflags(_config: WorkerConfig, req: CheckCflagsRequest) -> dict[str, Any]:
    """The flag string as every compiling op would use it, or the 400 they would answer."""
    return {"cflags": checked_cflags(req.cflags)}


#: Bound on the renames of one ``rebrew.rename_identifier`` call.
MAX_IDENTIFIER_RENAMES = 256


def rename_identifier(_config: WorkerConfig, req: RenameIdentifierRequest) -> dict[str, Any]:
    """Apply ordered identifier renames to one C text, each against the previous result.

    Every rename answers ``applied`` with the UTF-8 byte ``offsets`` of the
    replaced occurrences in the text it was applied to, or a ``reason`` it was
    skipped; a skipped rename leaves the text as it was.
    """
    from rebrew.source.c_rename import IdentifierRenameRefused, ParsedSource
    from rebrew.source.c_rename import rename_identifier as rename
    from rebrew.source.rename_ops import is_valid_new_name

    if not req.renames:
        raise invalid_request("renames must not be empty")
    if len(req.renames) > MAX_IDENTIFIER_RENAMES:
        raise invalid_request(f"more than {MAX_IDENTIFIER_RENAMES} renames")
    text = req.source
    parsed: ParsedSource | None = None
    results: list[dict[str, Any]] = []
    for entry in req.renames:
        offsets: list[int] = []
        reason = ""
        if not (is_valid_new_name(entry.old) and is_valid_new_name(entry.new)):
            reason = "not a C identifier"
        elif entry.old == entry.new:
            reason = "name unchanged"
        else:
            if parsed is None:
                parsed = ParsedSource.parse(text)
            try:
                text, offsets = rename(parsed, entry.old, entry.new)
            except IdentifierRenameRefused as exc:
                reason = str(exc)
            else:
                parsed = None
        results.append({"applied": not reason, "reason": reason, "offsets": offsets})
    return {"source": text, "renames": results}


def project_targets(config: WorkerConfig, req: FileSetRequest) -> dict[str, Any]:
    """The targets a supplied project config declares, as the config loader keys them."""
    from rebrew.workspace import read_config, targets_table

    with _staged_file_set(config, req.files) as root:
        try:
            table = targets_table(read_config(root))
        except (OSError, ValueError, RebrewError) as exc:
            raise invalid_project_config(root, exc) from exc
    return {"targets": sorted(table, key=lambda name: name.encode("utf-8"))}


def metadata_describe(config: WorkerConfig, req: FileSetRequest) -> dict[str, Any]:
    """The backend-neutral descriptor of the metadata a supplied file set reads."""
    from rebrew.metadata_sets import describe_metadata

    with _staged_file_set(config, req.files) as root:
        return _metadata_answer(lambda: describe_metadata(root))


def metadata_diff(config: WorkerConfig, req: MetadataDiffRequest) -> dict[str, Any]:
    """Every metadata record that differs between two supplied file sets, field by field."""
    from rebrew.metadata_sets import describe_metadata, diff_metadata

    with (
        _staged_file_set(config, req.before) as before,
        _staged_file_set(config, req.after) as after,
    ):
        return _metadata_answer(
            lambda: {
                "before": describe_metadata(before),
                "after": describe_metadata(after),
                "changes": diff_metadata(before, after),
            }
        )


def metadata_carry(config: WorkerConfig, req: MetadataCarryRequest) -> dict[str, Any]:
    """Carry a retained target's published function registry onto a fresh capture.

    The new metadata holds the capture's documents with every function registry
    document taken from the target's published metadata, imported through the
    reviewed migration into the capture's backend; its logical documents must equal
    those inputs. Without published metadata the target reads the capture's own.
    """
    from rebrew.metadata_sets import carry_metadata, describe_metadata, published_backend

    with (
        _staged_file_set(config, req.capture) as capture,
        _staged_file_set(config, req.target) as target,
    ):
        scratch = config.require_workspace() / SCRATCH_DIR
        with tempfile.TemporaryDirectory(prefix="metadata-carry-", dir=scratch) as temp:
            carried = Path(temp).resolve()
            published = _metadata_answer(
                lambda: describe_metadata(target, backend=published_backend(target))
            )
            _metadata_answer(lambda: carry_metadata(capture, target, carried))
            reads = carried if published["files"] else capture
            metadata = _metadata_answer(lambda: describe_metadata(reads))
            paths = ["rebrew-project.toml"]
            if published["files"]:
                paths.extend(item["path"] for item in metadata["files"])
            max_file_bytes = ops_binding("MAX_READSET_FILE_BYTES", MAX_READSET_FILE_BYTES)
            files = []
            for relative in paths:
                data = (carried / relative).read_bytes()
                if len(data) > max_file_bytes:
                    raise readset_limit(
                        f"carried metadata {relative}", len(data), max_file_bytes, "bytes"
                    )
                files.append(
                    {
                        "path": relative,
                        "size": len(data),
                        "digest": hashlib.sha256(data).hexdigest(),
                        "data": base64.b64encode(data).decode("ascii"),
                    }
                )
            kept = set(paths)
            return {
                "files": files,
                "remove": [item["path"] for item in published["files"] if item["path"] not in kept],
                "metadata": metadata,
                "attested_registry_digest": _attested_registry_digest(files),
            }


def _attested_registry_digest(published: list[dict[str, Any]]) -> str:
    """The digest a client attests for the registry among *published* files, else ``""``.

    The registry is the store under SQLite and ``rebrew-functions.toml`` under TOML;
    a later retained snapshot accepts a source copy of it only with this digest.
    """
    from rebrew.metadata.sqlite import DATABASE_FILENAME

    digests = {item["path"]: item["digest"] for item in published}
    return str(digests.get(DATABASE_FILENAME, digests.get(APPLY_METADATA_FILE, "")))


def import_project(config: WorkerConfig, req: ImportRequest) -> dict[str, Any]:
    """Coverage of an existing workspace: live, or the portable export in ``snapshots``.

    ``build_db`` asks for a refreshed live coverage view, the step the
    backend's ``--build-db`` ran before importing.  Live coverage is always
    read with ``refresh=True``, so the flag selects nothing beyond excluding
    ``snapshots``.
    """
    root = project_root(config, req.project_dir)
    scoped_projects = config.workspace / "projects" / "scopes" if config.workspace else None
    if scoped_projects is not None and root.is_relative_to(scoped_projects):
        raise invalid_request("scoped analysis projects cannot be imported by path")
    if req.snapshots and req.build_db:
        raise invalid_request("snapshots and build_db exclude each other")
    snapshots = None
    if req.snapshots:
        snapshots = confined_dir(config, req.snapshots, "snapshots")
        if scoped_projects is not None and snapshots.is_relative_to(scoped_projects):
            raise invalid_request("scoped analysis snapshots cannot be imported by path")
        if not snapshots.is_dir():
            raise invalid_request("snapshots must be a directory")
    return project_report(root, snapshots)


def project_report(
    root: Path, snapshots: Path | None, *, include_source: bool = False, only: str | None = None
) -> dict[str, Any]:
    """The backend's ``ProjectReport`` of *root*: targets, functions and import stubs.

    Live coverage is read unless *snapshots* names a portable export directory.
    *only*, when set, reports that one target; the other targets' coverage may fail.
    """
    from rebrew.binary.discover import elf_function_symbols
    from rebrew.config import load_config
    from rebrew.coverage.project import load_project_coverage
    from rebrew.coverage.toml import load_coverage_from
    from rebrew.formats.import_table import find_import_stubs
    from rebrew.workspace import read_config, target_binary, targets_table

    if snapshots is None:
        view = load_project_coverage(root, refresh=True)
        failures = {name for name in view.failures if only is None or name == only}
        if failures:
            raise OpsError(f"coverage failed for targets: {', '.join(sorted(failures))}")
        coverage = dict(view.snapshots)
    else:
        names = sorted(p.stem.removeprefix("coverage-") for p in snapshots.glob("coverage-*.toml"))
        coverage = {name: load_coverage_from(snapshots, name) for name in names}
    if only is not None:
        coverage = {name: value for name, value in coverage.items() if name == only}
    if not coverage:
        raise invalid_request("the project has no coverage targets")
    table = targets_table(read_config(root))
    targets = []
    for name in sorted(coverage):
        entry = table.get(name, {})
        cfg = load_config(root, target=name) if include_source else None
        resolved_root = root.resolve() if include_source else root

        def source_path(
            row: Any,
            source_dir: Path = cfg.reversed_dir if cfg else root,
            project_root: Path = resolved_root,
        ) -> str:
            paths: set[str] = set()
            for value in row.files:
                path = (source_dir / value).resolve()
                if path.is_relative_to(project_root) and path.is_file():
                    paths.add(path.relative_to(project_root).as_posix())
            return next(iter(paths)) if len(paths) == 1 else ""

        binary = target_binary(root, entry) if entry else None
        if binary is not None and not binary.is_file():
            binary = None
        symbol_names = (
            {va: (size, symbol) for va, size, symbol in elf_function_symbols(binary)}
            if binary is not None
            else {}
        )
        functions: list[dict[str, Any]] = []
        for row in sorted(coverage[name].functions, key=lambda row: row.va):
            if row.markerType in DATA_MARKERS:
                continue
            item = {
                "va": row.va,
                "name": symbol_names.get(row.va, (0, row.name.strip()))[1]
                if row.name.strip() == f"fcn_{row.va:08x}"
                else row.name.strip() or f"sub_{row.va:x}",
                "size": (symbol_names.get(row.va, (0, ""))[0] or max(0, row.size or 0))
                if row.name.strip() == f"fcn_{row.va:08x}"
                else max(0, row.size or 0),
                "status": row.status,
            }
            if include_source and (source := source_path(row)):
                item["source_path"] = source
            functions.append(item)
        import_stubs: dict[int, str] = find_import_stubs(binary) if binary is not None else {}
        # An import thunk that is also a function row is one identity.  A row
        # nobody worked on (generated name, STUB) is an import: older discovery
        # documented stubs as functions.  Any other row wins, taking the import
        # name when it only has the generated one.
        functions = [
            row
            for row in functions
            if row["va"] not in import_stubs
            or row["name"] != f"fcn_{row['va']:08x}"
            or row["status"] != "STUB"
        ]
        for function in functions:
            stub = import_stubs.pop(function["va"], None)
            if stub is not None and function["name"] == f"fcn_{function['va']:08x}":
                function["name"] = stub
        stubs = sorted(import_stubs.items())
        targets.append(
            {
                "name": name,
                "arch": str(entry.get("arch") or ""),
                "format": str(entry.get("format") or ""),
                "document": str(
                    root / "rebrew-project.toml"
                    if snapshots is None
                    else snapshots / f"coverage-{name}.toml"
                ),
                "functions": functions,
                "stubs": [{"va": va, "name": stub} for va, stub in stubs],
                "sha256": sha256_file(binary) if binary is not None else "",
                "path": str(binary) if binary is not None else "",
                "size": binary.stat().st_size if binary is not None else 0,
            }
        )
    return {
        "project": str(root),
        "coverage_dir": str(snapshots) if snapshots is not None else None,
        "targets": targets,
    }


# ---------------------------------------------------------------------------
