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
compile refuse, while a remote compile backend is configured, a source that
reads project headers (:func:`remote_header_refusal`).
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import MISSING, dataclass, field, fields
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import override  # decorator and base class: definition-time use
lazy import base64
lazy import binascii
lazy import dataclasses
lazy import hashlib
lazy import hmac
lazy import itertools
lazy import json
lazy import os
lazy import re
lazy import shutil
lazy import signal
lazy import subprocess
lazy import sys
lazy import tempfile
lazy import threading
lazy import time
lazy import traceback
lazy import typing
lazy import unicodedata
lazy from collections.abc import Callable, Iterable, Iterator, Mapping
lazy from typing import Any
lazy from urllib.parse import urlsplit

import typer
lazy import httpx

from rebrew.errors import RebrewError
lazy from rebrew import __version__, telemetry
lazy from rebrew.cli import EXIT_ERROR, console, error_exit
lazy from rebrew.formats.binary_loader import UnsupportedBinaryFormat
lazy from rebrew.utils import fold_host, split_source_lines

logger = logging.getLogger(__name__)

#: Level column width matching the dashboard's server log format.
_LOG_LEVEL_FORMAT = "%(levelname)-8s"
_LOG_TIME_FORMAT = "%H:%M:%S UTC"
_OPS_HANDLER_NAME = "rebrew-ops"
_PACKAGE_HANDLER_NAME = "rebrew-ops-package"
_PACKAGE_LOGGER_NAME = __name__.partition(".")[0]

#: Correlation id per ops request, mirroring the dashboard's ``r<N>``: the
#: ``X-Request-Id`` header, the access line, and every error line of one
#: request carry it, so an operator holding a refusal can pivot to the log
#: lines that explain it.
_REQUEST_IDS = itertools.count(1)
#: The request in flight on this thread, for the logger records a library
#: warning raises inside the request path (see ``dashboard._stamp_request``).
_REQUEST_LOCAL = threading.local()

#: Control characters escaped in request-derived log text, plus backslash.
_LOG_CONTROL_CHARS = {code: f"\\x{code:02x}" for code in (*range(0x20), *range(0x7F, 0xA0))}
_LOG_CONTROL_CHARS[ord("\\")] = "\\\\"


def _escape_log_text(text: str) -> str:
    """One-line, terminal-safe form of request-derived text for the log stream.

    Strips bidi-format characters and escapes control characters, exactly as
    the dashboard's access log does: a path or Host carrying a newline or
    bidi override must not forge a second log line or reorder the first.
    """
    from rebrew.utils import strip_bidi_format

    return strip_bidi_format(text).translate(_LOG_CONTROL_CHARS)


def _stamp_request(request_id: str) -> None:
    """Record the correlation id of the request in flight on this thread."""
    _REQUEST_LOCAL.request_id = request_id


def _request_id() -> str:
    """The stamped correlation id, or ``"-"`` off the HTTP transport."""
    return getattr(_REQUEST_LOCAL, "request_id", "-")


def _trace_id() -> str:
    """Trace id of the open span, so logs join the MELT investigative path."""
    opened = telemetry.current()
    return opened.trace_id if opened is not None else "-"


class _CorrelatedFormatter(logging.Formatter):
    """Stamp library records raised inside a request with its id and trace id.

    Mirrors the dashboard's formatter: a warning from engine code running
    inside an ops request names no request on its own, so the formatter
    supplies the stamped id and the open span's trace id, and escapes the
    rendered line so request-derived text cannot forge a second line.
    """

    @override
    def format(self, record: logging.LogRecord) -> str:
        request_id = _request_id()
        line = _escape_log_text(super().format(record))
        if request_id == "-":
            return line
        trace_id = _trace_id()
        return f"{request_id} {trace_id} {line}" if trace_id != "-" else f"{request_id} {line}"


def _attach_server_log_handler() -> Callable[[], None]:
    """Send this module's and the package's records to the console in one format.

    Without a handler, records fall back to ``lastResort`` or to the root
    handler ``configure_logging`` installed, in a different format with no
    request id, so library warnings raised inside a request cannot be
    pivoted to by id.  Mirrors the dashboard: the ops logger gets an INFO
    handler on the console, the package logger gets the correlated
    formatter, both stamped in UTC with a level column.  Returns a
    disposer restoring both loggers.
    """
    from rebrew.cli import console
    from rebrew.utils import remove_identity

    handler = logging.StreamHandler(console.file)
    formatter = logging.Formatter(f"%(asctime)s {_LOG_LEVEL_FORMAT} %(message)s", _LOG_TIME_FORMAT)
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    handler.set_name(_OPS_HANDLER_NAME)
    replaced = [h for h in logger.handlers if h.get_name() == handler.get_name()]
    previous_level = logger.level
    previous_propagate = logger.propagate

    package_log = logging.getLogger(_PACKAGE_LOGGER_NAME)
    package_handler = logging.StreamHandler(console.file)
    package_formatter = _CorrelatedFormatter(
        f"%(asctime)s {_LOG_LEVEL_FORMAT} %(message)s", _LOG_TIME_FORMAT
    )
    package_formatter.converter = time.gmtime
    package_handler.setFormatter(package_formatter)
    package_handler.set_name(_PACKAGE_HANDLER_NAME)
    package_replaced = [
        h for h in package_log.handlers if h.get_name() == package_handler.get_name()
    ]
    package_previous_propagate = package_log.propagate

    swapped = False
    package_swapped = False
    disposed = False

    def restore() -> None:
        nonlocal disposed, swapped, package_swapped
        if disposed:
            return
        disposed = True
        if swapped:
            remove_identity(logger.handlers, handler)
            for existing in replaced:
                logger.addHandler(existing)
            logger.setLevel(previous_level)
            logger.propagate = previous_propagate
            swapped = False
        if package_swapped:
            remove_identity(package_log.handlers, package_handler)
            for existing in package_replaced:
                package_log.addHandler(existing)
            package_log.propagate = package_previous_propagate
            package_swapped = False

    try:
        for existing in replaced:
            logger.removeHandler(existing)
        swapped = True
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        for existing in package_replaced:
            package_log.removeHandler(existing)
        package_swapped = True
        package_log.addHandler(package_handler)
        package_log.propagate = False
    except BaseException:
        restore()
        raise
    return restore


# ---------------------------------------------------------------------------
# Limits and wire constants
# ---------------------------------------------------------------------------

#: Environment variable holding the bearer token ``serve`` requires.
TOKEN_ENV = "REBREW_OPS_TOKEN"  # noqa: S105  # a variable name, not a credential

#: Largest request body accepted on either transport.  The biggest request is
#: ``disassemble_bytes`` carrying base64 code; 16 MiB leaves room for a 1 MiB
#: function many times over.
MAX_REQUEST_BYTES = 16 << 20

#: Largest reply written.  The backend reads at most this much (its
#: ``dispatch.MaxReply``), so a larger reply is refused here, with a reason.
MAX_REPLY_BYTES = 64 << 20

#: Seconds an HTTP connection may stall while its request is read or its reply
#: written.  Engine work is not bounded by it.
SOCKET_TIMEOUT_SECONDS = 60

#: Wall-clock bound on one ``rebrew intake`` run (``analyse``).
INTAKE_TIMEOUT_SECONDS = 600

#: Wall-clock bound on a rebrew command an op runs as a child process.
COMMAND_TIMEOUT_SECONDS = 600

#: Wall-clock bound on the child commands that compile every function or
#: search mutations: ``verify_target``, ``build`` and ``source_variants``.
SEARCH_TIMEOUT_SECONDS = 3600

#: Default of ``--concurrency``: calls ``serve`` runs at once.
DEFAULT_CONCURRENCY = 4

#: ``Retry-After`` seconds of the 503 ``serve`` answers when every slot is busy.
BUSY_RETRY_AFTER_SECONDS = 5

#: Default of ``--max-download``: the largest binary a ``url`` may name.
#: It matches the backend's default upload cap (``max_upload_bytes``).
DEFAULT_MAX_DOWNLOAD_BYTES = 256 << 20

#: Seconds a ``url`` download may stall connecting or between reads.
DOWNLOAD_TIMEOUT_SECONDS = 60

#: Seconds a DNS resolution for a ``url`` host may stall.  ``getaddrinfo``
#: has no timeout of its own, so without this a hung resolver pins a
#: worker slot for the kernel timeout and later requests queue behind it.
DNS_TIMEOUT_SECONDS = 10

#: Bytes read per chunk of a ``url`` download.
DOWNLOAD_CHUNK_BYTES = 1 << 20

#: Directory under the workspace that holds ``url`` downloads while a call runs.
SCRATCH_DIR = ".scratch"

#: Detail characters kept from a rebrew refusal.
DETAIL_MAX_CHARS = 400

#: Listing formats ``disassemble`` accepts.
DISASM_FORMATS = frozenset({"nasm", "asm", "hex"})

#: The one ISA rebrew's NASM source decodes.  ``disassemble_bytes`` lists every
#: other ISA in the ``asm`` format.
NASM_ARCH = "x86_32"

#: Backends ``decompile`` and ``structs`` accept (the backend's
#: ``DecompileRequest`` list).
DECOMPILER_BACKENDS = frozenset({"auto", "ghidra", "kuna", "r2dec", "r2ghidra"})

#: ``binary_operand_locations`` bounds: functions per call, bytes per function,
#: locations per function and the highest capstone operand index.
OPERAND_MAX_FUNCTIONS = 128
OPERAND_MAX_FUNCTION_BYTES = 1 << 20
OPERAND_MAX_LOCATIONS = 256
OPERAND_MAX_INDEX = 7

#: ``binary_function_digests`` bounds: functions per call and bytes per function.
DIGEST_MAX_FUNCTIONS = 128
DIGEST_MAX_FUNCTION_BYTES = 1 << 20

#: The relocation-masked digest ``binary_function_digests`` answers.
DIGEST_ALGORITHM = "sha256-relocations-v1"

#: Largest splat config text ``splat_parse`` reads.
SPLAT_MAX_CONFIG_BYTES = 256 << 10

#: Where ``splat_parse`` places the config text: its relative paths hang from
#: this directory, and nothing there is opened.
SPLAT_ANCHOR = Path("/splat/splat.yaml")

#: Signature formats ``reference_flirt`` reads, by request ``format``.
FLIRT_FORMATS = frozenset({"sig", "pat"})

#: ``rebrew source rename`` selectors by request ``kind``; a function takes none.
RENAME_KINDS = {"function": (), "data": ("--data",), "type": ("--type",), "field": ("--field",)}

#: ``data_set`` request fields and the ``rebrew data set`` option each sets.
DATA_FIELD_OPTIONS = {
    "name": "--name",
    "type": "--type",
    "section": "--section",
    "kind": "--kind",
    "note": "--note",
    "storage_kind": "--storage-kind",
    "backing": "--backing",
    "link_symbol": "--link-symbol",
    "source_file": "--file",
}

#: Coverage rows that are data, not functions.
_DATA_MARKERS = frozenset({"GLOBAL", "DATA"})

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TARGET_UNSAFE = re.compile(r"[^A-Za-z0-9_]")
_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1

# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------

INVALID_REQUEST = "invalid-request"
UNKNOWN_OP = "unknown-op"
ENGINE_ERROR = "engine-error"
WORKER_BUSY = "worker-busy"
#: A remote compile of a source that reads project headers (relumea ADR 0010, decision 4).
REMOTE_HEADERS = "remote-compile-headers"


class OpsError(RebrewError):
    """A refusal: a detail safe to show, a stable code, and an HTTP status."""

    code: str = ENGINE_ERROR
    status: int = 500

    STRUCTURED_FIELDS = (*RebrewError.STRUCTURED_FIELDS, "code", "status")

    def __init__(self, detail: str, *, code: str = ENGINE_ERROR, status: int = 500) -> None:
        super().__init__(detail)
        self.code = code
        self.status = status


def _invalid(detail: str) -> OpsError:
    return OpsError(detail, code=INVALID_REQUEST, status=400)


#: A person-supplied compiler flag string reaches a compiler, so it is a
#: bounded list of plain option tokens. Anything that names a file, a path or an
#: output, or changes the command, is refused (the backend applies the same rule).
CFLAGS_MAX_CHARS = 256
_CFLAGS_TOKEN = re.compile(r"[/-][A-Za-z0-9_:=.+-]+")
# Case-sensitive: /O1 and /MT are flags, /Fo names an output. MSVC-style options
# first, then the GCC-style options that take a path or run another program.
_CFLAGS_REFUSED = re.compile(
    r"/(?:F|I|Y|AI|Tc|Tp|LD)|/(?:E|EP|P)$|/[Ll][Ii][Nn][Kk]"
    r"|-(?:o|I|L|l|B|T|x|M|include|isystem|iquote|specs|wrapper|Xlinker|fplugin|dump)"
)


def apply_project_cflags(root: Path, target_name: str, flags: str) -> tuple[int, str] | None:
    """Set the validated *flags* as the project cflags of the private snapshot at *root*.

    ``[compiler] cflags`` takes the flags, and so does the target's own compiler override when it sets cflags,
    which would otherwise shadow them. A function's own cflags metadata still overrides the project cflags, which
    is why the target's flags go here and not through ``--cflags``. Returns the rewritten file's size and digest, or
    None when *flags* is empty and nothing was touched.
    """
    import tomlkit

    text = checked_cflags(flags)
    if not text:
        return None
    path = root / "rebrew-project.toml"
    doc = tomlkit.parse(path.read_text(encoding="utf-8-sig"))
    if "compiler" not in doc:
        doc["compiler"] = tomlkit.table()
    doc["compiler"]["cflags"] = text
    targets = doc.get("targets")
    override = (targets.get(target_name) or {}).get("compiler") if targets is not None else None
    if override is not None and "cflags" in override:
        override["cflags"] = text
    path.write_text(tomlkit.dumps(doc), encoding="utf-8")
    return path.stat().st_size, _file_sha256(path)


def checked_cflags(text: str) -> str:
    """The flag string, normalized to single spaces, or a 400 naming the bad token."""
    if len(text) > CFLAGS_MAX_CHARS:
        raise _invalid(f"invalid-cflags: longer than {CFLAGS_MAX_CHARS} characters")
    tokens = text.split()
    for token in tokens:
        if not _CFLAGS_TOKEN.fullmatch(token):
            raise _invalid(f"invalid-cflags: {token[:40]!r} is not a plain option token")
        if _CFLAGS_REFUSED.match(token):
            raise _invalid(f"invalid-cflags: {token!r} names a file or changes the command")
    return " ".join(tokens)


#: Bounds of one captured readset or retained source manifest, shared by every
#: site that reads or accepts one.  Intake writes one stub per discovered
#: function, so the file count is sized for binaries with tens of thousands of
#: functions; the byte bounds are the resource limit that matters.
MAX_READSET_FILES = 32768
#: Latency histogram upper bounds in ms for the ops request metric.
_LATENCY_BUCKETS_MS = (100.0, 1000.0, 10000.0, 60000.0, float("inf"))


MAX_READSET_BYTES = 32 * 1024 * 1024
MAX_READSET_FILE_BYTES = 8 * 1024 * 1024

READSET_TOO_LARGE = "readset-too-large"
ANALYSIS_CAPTURE_FAILED = "analysis-capture-failed"
UNSUPPORTED_BINARY_FORMAT = "unsupported-binary-format"


def _readset_limit(what: str, count: int, limit: int, unit: str = "files") -> OpsError:
    """The binary's own analysis is larger than the engine bounds: not the caller's fault."""
    return OpsError(
        f"{what} has {count} {unit}, over the limit of {limit}",
        code=READSET_TOO_LARGE,
        status=422,
    )


def _check_manifest_size(files: Any) -> None:
    """A retained source manifest is non-empty and within the shared readset bounds."""
    if not files:
        raise _invalid("invalid retained source manifest size")
    if len(files) > MAX_READSET_FILES:
        raise _readset_limit("retained source manifest", len(files), MAX_READSET_FILES)
    size = sum(f.size for f in files)
    if size > MAX_READSET_BYTES:
        raise _readset_limit("retained source manifest", size, MAX_READSET_BYTES, "bytes")


def _capture_failed(detail: str) -> OpsError:
    """A self-check of the fresh analysis capture failed: the engine's fault, not the caller's."""
    return OpsError(detail, code=ANALYSIS_CAPTURE_FAILED, status=500)


def _refused(detail: str) -> OpsError:
    return OpsError(detail)


def error_body(code: str, detail: str, status: int) -> bytes:
    """The refusal reply both transports write."""
    from rebrew.utils import strip_bidi_format

    return json.dumps(
        {"error": code, "detail": strip_bidi_format(detail), "status": status}
    ).encode("utf-8")


def _bounded(text: str) -> str:
    """*text* on one line, cut at :data:`DETAIL_MAX_CHARS`."""
    from rebrew.utils import strip_bidi_format, truncate_text

    return truncate_text(" ".join(strip_bidi_format(text).split()), DETAIL_MAX_CHARS)


# ---------------------------------------------------------------------------
# Worker configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WorkerConfig:
    """Where the worker reads stored binaries and writes projects and reports.

    ``max_download_bytes`` bounds a binary fetched from a request ``url``.
    """

    filestore: Path | None = None
    workspace: Path | None = None
    max_download_bytes: int = DEFAULT_MAX_DOWNLOAD_BYTES

    def require_filestore(self) -> Path:
        if self.filestore is None:
            raise _refused("the rebrew worker has no filestore configured (--filestore)")
        return self.filestore

    def require_workspace(self) -> Path:
        if self.workspace is None:
            raise _refused("the rebrew worker has no workspace configured (--workspace)")
        return self.workspace


def _existing_dir(value: Path | None, flag: str) -> Path | None:
    if value is None:
        return None
    if not value.is_absolute() or not value.is_dir():
        error_exit(f"{flag} must be an absolute path to an existing directory: {value}")
    return value.resolve()


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
    size: int = 0
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
    version: int = 0
    source_revision: str = ""
    generation: str = ""
    binary_sha256: str = ""
    target: str = ""
    readset: list[CoverageInputEntry] = field(default_factory=list)
    analysis_manifest: str = ""
    verification_digest: str = ""


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
    files: list[FlagSearchFile] = field(default_factory=list)
    rebrew_target: str = ""
    binary_key: str = ""
    binary_url: str = ""
    coverage_input: CoverageInput = field(default_factory=CoverageInput)
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
    files: list[FlagSearchFile] = field(default_factory=list)
    rebrew_target: str = ""
    binary_key: str = ""
    binary_url: str = ""
    coverage_input: CoverageInput = field(default_factory=CoverageInput)
    coverage_input_digest: str = ""
    verification_records: list[CoverageVerification] = field(default_factory=list)


@dataclass(frozen=True)
class CoverageReportRequest(TargetRequest):
    files: list[FlagSearchFile] = field(default_factory=list)
    rebrew_target: str = ""
    binary_key: str = ""
    binary_url: str = ""
    coverage_input: CoverageInput = field(default_factory=CoverageInput)
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
    files: list[FlagSearchFile] = field(default_factory=list)
    rebrew_target: str = ""
    source_sha256: str = ""
    binary_key: str = ""
    binary_url: str = ""
    cflags: str = ""
    project_cflags: str = ""


@dataclass(frozen=True)
class ApplyCandidateRequest:
    """``verify_function`` in promote mode: the same retained inputs, and the files it changed come back."""

    project_dir: str
    source: str = ""
    sha256: str = ""
    candidate: str = ""
    va: int = 0
    size: int = 0
    files: list[FlagSearchFile] = field(default_factory=list)
    rebrew_target: str = ""
    source_sha256: str = ""
    binary_key: str = ""
    binary_url: str = ""
    cflags: str = ""
    project_cflags: str = ""


@dataclass(frozen=True)
class VerifyTargetRequest:
    project_dir: str
    sha256: str = ""
    no_promote: bool = False
    files: list[FlagSearchFile] = field(default_factory=list)
    rebrew_target: str = ""
    binary_key: str = ""
    binary_url: str = ""
    project_cflags: str = ""


@dataclass(frozen=True)
class BuildRequest:
    project_dir: str
    sha256: str = ""
    fix_headers: bool = False
    files: list[FlagSearchFile] = field(default_factory=list)
    rebrew_target: str = ""
    binary_key: str = ""
    binary_url: str = ""
    project_cflags: str = ""


@dataclass(frozen=True)
class SkeletonRequest:
    project_dir: str
    va: int
    sha256: str = ""
    name: str = ""


@dataclass(frozen=True)
class CoverageExportRequest:
    project_dir: str
    output_dir: str
    sha256: str = ""


@dataclass(frozen=True)
class SourceVariantsRequest:
    project_dir: str
    source: str
    generations: int
    population: int
    seed: int
    sha256: str = ""


@dataclass(frozen=True)
class FlagSearchFile:
    path: str
    digest: str
    size: int
    key: str = ""
    url: str = ""


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
    files: list[FlagSearchFile]
    generation: str
    analysis_manifest_sha256: str
    analysis_manifest: str
    analysis_files: list[FlagSearchFile]
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
    files: list[FlagSearchFile]
    generation: str
    analysis_manifest: str
    analysis_manifest_sha256: str
    analysis_files: list[FlagSearchFile]
    min_severity: str
    binary_key: str = ""
    binary_url: str = ""
    attested_registry_digest: str = ""


@dataclass(frozen=True)
class FlagSearchRequest:
    source: str
    source_sha256: str
    va: int
    files: list[FlagSearchFile]
    rebrew_target: str
    sha256: str = ""
    binary_key: str = ""
    binary_url: str = ""
    tier: str = "targeted"
    toolchains: str = ""
    exclude_toolchains: str = ""
    compare_toolchains: bool = False
    with_flags: bool = False


@dataclass(frozen=True)
class DecompmeRequest:
    project_dir: str
    source: str
    sha256: str = ""
    dry_run: bool = False


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
class RenameRequest:
    project_dir: str
    kind: str
    old_name: str
    new_name: str
    sha256: str = ""
    dry_run: bool = False


@dataclass(frozen=True)
class SplitRequest:
    project_dir: str
    source: str
    sha256: str = ""
    va: int = 0
    dry_run: bool = False


@dataclass(frozen=True)
class MergeRequest:
    project_dir: str
    sources: list[str]
    output: str
    sha256: str = ""
    dry_run: bool = False


@dataclass(frozen=True)
class SnapshotMutationRequest:
    files: list[FlagSearchFile]
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


def _has_lone_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in value)


def _decode(value: Any, hint: Any, where: str) -> Any:
    """Check one JSON value against the field type *hint*; bytes arrive base64."""
    origin = typing.get_origin(hint)
    if hint is bool:
        if type(value) is not bool:
            raise _invalid(f"{where} must be a boolean")
        return value
    if hint is int:
        if type(value) is not int or not _INT64_MIN <= value <= _INT64_MAX:
            raise _invalid(f"{where} must be a 64-bit integer")
        return value
    if hint is str:
        if type(value) is not str:
            raise _invalid(f"{where} must be a string")
        # JSON accepts a lone surrogate as an escaped ``\\uXXXX``; every
        # downstream ``.encode("utf-8")`` (project_id bound, candidate byte
        # bound, sort keys, file writes) then raises UnicodeEncodeError and
        # surfaces as a 500 instead of a 400. Reject it at the boundary.
        # Paired surrogates never survive json.loads as separate code
        # points (they arrive combined), so any surrogate here is lone.
        if _has_lone_surrogate(value):
            raise _invalid(f"{where} contains an unpaired surrogate")
        return value
    if hint is bytes:
        if type(value) is not str:
            raise _invalid(f"{where} must be a base64 string")
        try:
            return base64.b64decode(value, validate=True)
        except binascii.Error, ValueError:
            raise _invalid(f"{where} is not valid base64") from None
    if origin is list:
        if type(value) is not list:
            raise _invalid(f"{where} must be an array")
        (item,) = typing.get_args(hint)
        return [_decode(entry, item, f"{where}[{index}]") for index, entry in enumerate(value)]
    if origin is tuple:
        items = typing.get_args(hint)
        if type(value) is not list or len(value) != len(items):
            raise _invalid(f"{where} must be an array of {len(items)} items")
        return tuple(
            _decode(entry, item, f"{where}[{index}]")
            for index, (entry, item) in enumerate(zip(value, items, strict=True))
        )
    return parse_request(hint, value, where)


def parse_request[T](cls: type[T], raw: Any, where: str = "request") -> T:
    """Build *cls* from a decoded JSON object, refusing unknown and missing fields."""
    if type(raw) is not dict:
        raise _invalid(f"{where} must be a JSON object")
    if (
        cls in {ReportRequest, CoverageReportRequest, DataListRequest}
        and not raw.get("files")
        and {"coverage_input", "coverage_input_digest", "verification_records"} & raw.keys()
    ):
        raise _invalid("coverage input requires a retained snapshot")
    if (
        cls in {ReportRequest, CoverageReportRequest, DataListRequest}
        and raw.get("coverage_input")
        and "verification_records" not in raw
    ):
        raise OpsError(
            "coverage verification records are required",
            code="coverage-input-unverified",
            status=409,
        )
    hints = typing.get_type_hints(cls)
    known = {spec.name: spec for spec in fields(cls)}  # type: ignore[arg-type]
    unknown = sorted(set(raw) - set(known))
    if unknown:
        raise _invalid(f"{where} has unknown fields: {', '.join(unknown)}")
    values: dict[str, Any] = {}
    for name, spec in known.items():
        if name in raw:
            if cls is AnalyseRequest and name == "project_id" and raw[name] == "":
                raise _invalid(f"{where}.project_id must not be empty")
            values[name] = _decode(raw[name], hints[name], f"{where}.{name}")
        elif spec.default is MISSING and spec.default_factory is MISSING:
            raise _invalid(f"{where} is missing {name}")
    return cls(**values)


# ---------------------------------------------------------------------------
# Binary and project references
# ---------------------------------------------------------------------------


def _file_sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _sha256(text: str) -> str:
    if _SHA256.match(text) is None:
        raise _invalid("sha256 must be 64 lowercase hex digits")
    return text


def _address(va: int) -> int:
    if va < 0:
        raise _invalid(f"va must not be negative, got {va}")
    return va


def stored_file(config: WorkerConfig, key: str, sha256: str) -> Path:
    """The filestore file at *key*, checked to lie under the root and hash to *sha256*.

    Keys follow the backend filestore's rule: relative, clean, ``/``-separated.
    """
    root = config.require_filestore()
    wanted = _sha256(sha256)
    parts = key.split("/")
    if not key or "\\" in key or "\0" in key or any(p in ("", ".", "..") for p in parts):
        raise _invalid("file key must be a clean relative filestore key")
    try:
        path = root.joinpath(*parts).resolve(strict=True)
    except FileNotFoundError:
        raise _invalid("no stored file for the key") from None
    if not path.is_relative_to(root) or not path.is_file():
        raise _invalid("the key does not name a stored file")
    if _file_sha256(path) != wanted:
        raise _invalid("the stored file does not match its sha256")
    return path


def _check_download_host(hostname: str) -> str:
    """Resolve *hostname* and return a public address to fetch from.

    A bearer holder must not turn the worker into an SSRF probe of the
    loopback/private network: an IP literal is checked directly, and a DNS
    name is resolved and every address refused when it is not globally
    routable.  A resolution failure (timeout, resolver error, no answer) is
    refused rather than attempted, as an engine error (500): retryable, as a
    failed connection is; only a non-public address is a bad request (400).

    The returned address is pinned by :func:`_download` so the fetch cannot
    re-resolve to a different (private) address between check and connect
    (DNS-rebinding TOCTOU): the check's answer is the fetch's destination.
    """
    import ipaddress
    import socket as _socket

    # getaddrinfo blocks with no timeout: a hung resolver would pin this
    # request thread (and its worker slot) for the kernel timeout.
    _result: list[Any] = []
    _error: list[BaseException] = []

    def _resolve() -> None:
        try:
            _result.append(_socket.getaddrinfo(hostname, 443, type=_socket.SOCK_STREAM))
        except BaseException as exc:  # propagated below; resolve runs on a thread
            _error.append(exc)

    _thread = threading.Thread(target=_resolve, daemon=True)
    _thread.start()
    _thread.join(DNS_TIMEOUT_SECONDS)
    if _thread.is_alive():
        raise _refused("url host cannot be resolved")
    if _error:
        if isinstance(_error[0], OSError):
            raise _refused("url host cannot be resolved") from None
        raise _error[0]
    infos = _result[0]
    if not infos:
        raise _refused("url host cannot be resolved")
    pinned = ""
    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            raise _refused("url host cannot be resolved") from None
        if not ip.is_global:
            raise _invalid("url host must be a public address")
        if not pinned:
            pinned = address
    return pinned


def _download(config: WorkerConfig, url: str, wanted: str, into: Path) -> None:
    """Write the body of a GET of the presigned HTTPS *url* to *into*.

    Redirects are not followed.  A body over ``max_download_bytes`` or one not
    hashing to *wanted* is refused.  Details never carry the URL: its query
    string is a credential.
    """
    from urllib.parse import urlunsplit

    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise _invalid("url must be an https URL")
    from rebrew.config import ALLOW_PRIVATE_DOWNLOAD_ENV, parse_env_bool

    fetch_url = url
    fetch_headers: dict[str, str] = {}
    fetch_extensions: dict[str, Any] = {}
    if not parse_env_bool(
        ALLOW_PRIVATE_DOWNLOAD_ENV,
        os.environ.get(ALLOW_PRIVATE_DOWNLOAD_ENV, ""),
        default=False,
    ):
        hostname = parts.hostname
        pinned = _check_download_host(hostname)
        # Pin the validated address: fetch the IP literal, keep the original
        # Host header and TLS SNI so the certificate still verifies against
        # the DNS name.  Without this the HTTP client would re-resolve the
        # name and could land on a private address the check never saw.
        if pinned != hostname:
            authority = f"[{pinned}]" if ":" in pinned else pinned
            if parts.port is not None:
                authority = f"{authority}:{parts.port}"
            fetch_url = urlunsplit(
                (parts.scheme, authority, parts.path, parts.query, parts.fragment)
            )
            fetch_headers["Host"] = parts.netloc
            fetch_extensions["sni_hostname"] = hostname
    limit = config.max_download_bytes
    digest = hashlib.sha256()
    received = 0
    # trust_env=False blocks ambient proxy redirection (a proxy could
    # resolve the name itself and bypass _check_download_host), but it also
    # makes httpx ignore SSL_CERT_FILE/SSL_CERT_DIR, so an operator-pinned
    # CA bundle would silently fall back to certifi. Re-apply the operator
    # CA explicitly when present so private-CA downloads keep working.
    import ssl as _ssl

    _cafile = os.environ.get("SSL_CERT_FILE")
    _capath = os.environ.get("SSL_CERT_DIR")
    _verify: Any = True
    if _cafile:
        _verify = _ssl.create_default_context(cafile=_cafile)
    elif _capath:
        _verify = _ssl.create_default_context(capath=_capath)
    try:
        with (
            httpx.Client(
                timeout=DOWNLOAD_TIMEOUT_SECONDS,
                follow_redirects=False,
                trust_env=False,
                verify=_verify,
            ) as _http,
            _http.stream(
                "GET",
                fetch_url,
                headers=fetch_headers or None,
                extensions=fetch_extensions or None,
            ) as response,
            into.open("wb") as out,
        ):
            if response.status_code != 200:
                # Upstream 5xx is a server failure the caller cannot fix by
                # changing the request (retry later), not a 400 client error.
                if response.status_code >= 500:
                    raise _refused(f"url answered HTTP {response.status_code}")
                raise _invalid(f"url answered HTTP {response.status_code}")
            declared = response.headers.get("Content-Length", "")
            if declared.isdigit() and int(declared) > limit:
                raise _invalid(f"url names more than {limit} bytes")
            for chunk in response.iter_bytes(DOWNLOAD_CHUNK_BYTES):
                received += len(chunk)
                if received > limit:
                    raise _invalid(f"url names more than {limit} bytes")
                digest.update(chunk)
                out.write(chunk)
    except (httpx.HTTPError, OSError) as exc:
        # A disk-full / permission failure on the write must surface as a
        # refusal with the cause, not escape as an unhandled OSError that
        # the caller reports as an internal error.  The partial file is
        # left for binary_file's finally to unlink.
        raise _refused(f"url download failed: {exc}") from exc
    if digest.hexdigest() != wanted:
        raise _invalid("the downloaded file does not match its sha256")


@contextlib.contextmanager
def binary_file(
    config: WorkerConfig, key: str, url: str, sha256: str, key_field: str
) -> Iterator[Path]:
    """The binary a request names by filestore *key* or by presigned *url*.

    Exactly one of the two is set.  A download lives under
    ``<workspace>/.scratch`` until the block ends.
    """
    if bool(key) == bool(url):
        raise _invalid(f"exactly one of {key_field} and url must be set")
    if key:
        yield stored_file(config, key, sha256)
        return
    wanted = _sha256(sha256)
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    handle, name = tempfile.mkstemp(prefix="download-", dir=scratch)
    os.close(handle)
    path = Path(name)
    try:
        _download(config, url, wanted, path)
        yield path
    finally:
        path.unlink(missing_ok=True)


def confined_dir(config: WorkerConfig, text: str, what: str) -> Path:
    """The absolute directory *text*, resolved; inside the workspace when one is set."""
    path = Path(text)
    if not path.is_absolute():
        raise _invalid(f"{what} must be an absolute path")
    resolved = path.resolve()
    if config.workspace is not None and not resolved.is_relative_to(config.workspace):
        raise _invalid(f"{what} must be inside the worker workspace")
    return resolved


def project_root(config: WorkerConfig, project_dir: str) -> Path:
    """The rebrew project at *project_dir* (see :func:`confined_dir`)."""
    root = confined_dir(config, project_dir, "project_dir")
    if not (root / "rebrew-project.toml").is_file():
        raise _invalid("project_dir is not a rebrew project (no rebrew-project.toml)")
    return root


def target_config(root: Path, sha256: str) -> Any:
    """The project config of the target whose binary hashes to *sha256*.

    An empty *sha256* selects the project's default target.
    """
    from rebrew.config import load_config
    from rebrew.workspace import read_config, target_binary, targets_table

    if not sha256:
        return load_config(root)
    wanted = _sha256(sha256)
    for name, entry in targets_table(read_config(root)).items():
        binary = target_binary(root, entry)
        if binary is not None and binary.is_file() and _file_sha256(binary) == wanted:
            return load_config(root, target=name)
    raise _invalid("no target of project_dir has a binary with that sha256")


def _inside(base: Path, relative: str, what: str, scope: str = "the worker workspace") -> Path:
    """*relative* resolved under *base*; an absolute path or an escape is refused."""
    if not relative or Path(relative).is_absolute():
        raise _invalid(f"{what} must be a relative path")
    path = (base / relative).resolve()
    if path == base or not path.is_relative_to(base):
        raise _invalid(f"{what} must stay inside {scope}")
    return path


def _project_file(root: Path, relative: str, what: str) -> Path:
    """The existing file *relative* names inside the project at *root*."""
    path = _inside(root, relative, what, "project_dir")
    if not path.is_file():
        raise _invalid(f"{what} is not a file of the project")
    return path


def _target_options(root: Path, sha256: str) -> list[str]:
    """``--target`` for the target whose binary hashes to *sha256*; none for the default."""
    if not sha256:
        return []
    return [f"--target={target_config(root, sha256).target_name}"]


# ---------------------------------------------------------------------------
# Listings
# ---------------------------------------------------------------------------


def _stage_retained_files(config: WorkerConfig, root: Path, files: Any, *, exclusive: bool) -> None:
    """Write a retained manifest into *root*, checking sizes and digests."""
    for entry in files:
        if (
            entry.size < 0
            or entry.size > 1024 * 1024
            or not re.fullmatch(r"[0-9a-f]{64}", entry.digest)
        ):
            raise _invalid("invalid retained source manifest entry")
        dest = _inside(root, entry.path, "source file", "snapshot")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if exclusive:
            with (
                binary_file(config, entry.key, entry.url, entry.digest, "key") as src,
                src.open("rb") as inp,
                dest.open("xb") as out,
            ):
                data = inp.read(entry.size + 1)
                if len(data) != entry.size or hashlib.sha256(data).hexdigest() != entry.digest:
                    raise _invalid("source does not match retained manifest")
                out.write(data)
        else:
            with (
                binary_file(config, entry.key, entry.url, entry.digest, "key") as src,
                src.open("rb") as inp,
            ):
                data = inp.read(entry.size + 1)
            if len(data) != entry.size or hashlib.sha256(data).hexdigest() != entry.digest:
                raise _invalid("source does not match retained manifest")
            dest.write_bytes(data)


def _stage_retained_binary(
    config: WorkerConfig, root: Path, target: Any, sha256: str, key: str, url: str
) -> Path:
    """Copy the target binary into *root*, refusing a snapshot conflict."""
    from rebrew.workspace import target_binary

    destination = _inside(root, target["binary"], "target binary", "snapshot")
    with binary_file(config, key, url, sha256, "binary_key") as binary:
        if destination.exists():
            if not destination.is_file() or _file_sha256(destination) != sha256:
                raise _invalid("retained target binary conflicts with snapshot")
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(binary, destination)
        resolved = target_binary(root, target)
        if (
            resolved is None
            or resolved.resolve() != destination
            or _file_sha256(destination) != sha256
        ):
            raise _invalid("snapshot target binary does not match")
    return destination


def _stage_retained_snapshot(
    config: WorkerConfig,
    root: Path,
    files: Any,
    target_name: str,
    sha256: str,
    binary_key: str,
    binary_url: str,
    *,
    exclusive: bool,
) -> Path:
    """Stage files and binary; return the destination."""
    from rebrew.workspace import read_config, targets_table

    _stage_retained_files(config, root, files, exclusive=exclusive)
    target = targets_table(read_config(root)).get(target_name)
    if not isinstance(target, dict) or not isinstance(target.get("binary"), str):
        raise _invalid("retained project has no selected target binary")
    return _stage_retained_binary(config, root, target, sha256, binary_key, binary_url)


def _capstone_for(arch: str) -> tuple[int, int]:
    from rebrew.config import ARCH_PRESETS
    from rebrew.formats.binary_loader import capstone_config_for
    from rebrew.formats.binary_model import BinaryInfo

    if arch not in ARCH_PRESETS:
        raise _invalid(f"unsupported arch: {_bounded(arch)}")
    try:
        return capstone_config_for(BinaryInfo(path=Path(), format="", arch=arch, endian=""))
    except NotImplementedError as exc:
        raise _invalid(_bounded(str(exc))) from None


def _nasm_listing(code: bytes, va: int) -> str:
    from rebrew.asm import disassemble_to_nasm

    source, _stats = disassemble_to_nasm(code, va, f"func_{va:08X}")
    return source + "\n"


def _asm_listing(code: bytes, va: int, cs_arch: int, cs_mode: int) -> str:
    """One ``mnemonic operands`` line per instruction."""
    from rebrew.analysis import disasm_insns

    return "".join(
        f"{insn.mnemonic} {insn.op_str}".rstrip() + "\n"
        for insn in disasm_insns(code, va, cs_arch, cs_mode)
    )


def disassemble(config: WorkerConfig, req: DisassembleRequest) -> dict[str, Any]:
    """Listing of ``[va, va+size)``: NASM source, ``asm`` lines, or the hex view.

    ``arch`` overrides the target's ISA for every format; it must be one of
    rebrew's arch presets, and NASM covers x86_32 only.
    """
    from rebrew.config import ARCH_PRESETS

    if req.format not in DISASM_FORMATS:
        raise _invalid(f"format must be one of {', '.join(sorted(DISASM_FORMATS))}")
    if req.size <= 0:
        raise _invalid(f"size must be positive, got {req.size}")
    va = _address(req.va)
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    if req.arch and req.arch != cfg.arch:
        if req.arch not in ARCH_PRESETS:
            raise _invalid(f"unsupported arch: {_bounded(req.arch)}")
        cfg = dataclasses.replace(cfg, arch=req.arch)
    if req.format == "hex":
        from rebrew.asm import hex_disassembly

        return {"text": hex_disassembly(cfg, va, req.size)}
    if req.format == "nasm" and cfg.arch != NASM_ARCH:
        raise _invalid(f"NASM source covers {NASM_ARCH} only and this binary is {cfg.arch}")
    from rebrew.formats.binary_loader import extract_raw_bytes

    code = extract_raw_bytes(cfg.target_binary, va, req.size)
    if not code:
        raise _invalid(f"no file bytes at 0x{va:x}")
    if req.format == "nasm":
        return {"text": _nasm_listing(code, va)}
    return {"text": _asm_listing(code, va, cfg.capstone_arch, cfg.capstone_mode)}


def disassemble_bytes(_config: WorkerConfig, req: DisassembleBytesRequest) -> dict[str, Any]:
    """Listing of raw code: NASM source for x86_32 (or no arch), ``asm`` lines otherwise."""
    if req.arch and req.arch != NASM_ARCH:
        from rebrew.config import ARCH_PRESETS

        if req.arch not in ARCH_PRESETS:
            raise _invalid(f"unsupported arch: {_bounded(req.arch)}")
    va = _address(req.va)
    if req.arch in ("", NASM_ARCH):
        return {"text": _nasm_listing(req.code, va)}
    return {"text": _asm_listing(req.code, va, *_capstone_for(req.arch))}


# ---------------------------------------------------------------------------
# Function ops on an analysed binary
# ---------------------------------------------------------------------------


def control_flow_graph(config: WorkerConfig, req: AddressRequest) -> dict[str, Any]:
    """Basic-block graph; ``size`` 0 lets rebrew resolve the extent."""
    from rebrew.asm import build_cfg_payload

    if req.size < 0:
        raise _invalid(f"size must not be negative, got {req.size}")
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    return build_cfg_payload(cfg, _address(req.va), req.size)


def xrefs(config: WorkerConfig, req: AddressRequest) -> dict[str, Any]:
    """References to ``va``, narrowed to ``kinds`` when given."""
    from rebrew.xrefs import build_xrefs_payload

    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    return build_xrefs_payload(cfg.target_binary, _address(req.va), req.kinds or None)


def call_references(config: WorkerConfig, req: ProjectRequest) -> dict[str, Any]:
    """Scan one analysed binary for calls, jumps and import slots."""
    from rebrew.analysis import scan_references
    from rebrew.formats.binary_loader import load_binary
    from rebrew.formats.import_table import parse_import_table

    cfg = target_config(project_root(config, req.project_dir), "")
    references = scan_references(load_binary(cfg.target_binary))
    calls = sorted(
        (
            {"kind": ref.kind, "from_va": ref.from_va, "to_va": ref.to_va}
            for ref in references
            if ref.kind in {"call", "jmp", "iat_call", "iat_jmp"}
        ),
        key=lambda ref: (ref["from_va"], ref["to_va"], ref["kind"]),
    )
    imports = parse_import_table(cfg.target_binary)
    return {
        "references": calls,
        "import_slots": [{"va": va, "name": imports[va]} for va in sorted(imports)],
    }


def describe(config: WorkerConfig, req: AddressRequest) -> dict[str, Any]:
    """The function dossier ``rebrew describe --json`` prints."""
    from rebrew.analysis import is_inside
    from rebrew.describe import JSON_KEYS, build_dossier
    from rebrew.formats.binary_loader import load_binary

    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    va = _address(req.va)
    info = load_binary(cfg.target_binary)
    if not is_inside(info, va):
        raise _invalid(f"VA 0x{va:x} is outside the binary image")
    dossier = build_dossier(cfg, info, va)
    return {key: dossier[key] for key in JSON_KEYS}


def decompile(config: WorkerConfig, req: DecompileRequest) -> dict[str, Any]:
    """Decompiled source of ``va``; ``named`` applies the project's known struct names."""
    from rebrew.analysis import is_inside
    from rebrew.decompiler import fetch_decompilation
    from rebrew.formats.binary_loader import load_binary

    if req.backend not in DECOMPILER_BACKENDS:
        raise _invalid(f"unsupported decompiler backend: {req.backend}")
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    va = _address(req.va)
    if not is_inside(load_binary(cfg.target_binary), va):
        raise _invalid(f"VA 0x{va:x} is outside the binary image")
    code, backend = fetch_decompilation(req.backend, cfg.target_binary, va, cfg.root)
    if not code:
        raise _refused(
            f"no decompilation via '{req.backend}' for 0x{va:x}"
            " (backend unavailable or unsupported address)"
        )
    if req.named:
        from rebrew.name_decomp import apply_known_names
        from rebrew.sources import iter_library_headers, iter_sources
        from rebrew.struct_recover import existing_structs

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
    from rebrew.identify_library import collect_candidates
    from rebrew.naming import load_existing_vas

    cfg = load_config(project_root(config, req.project_dir))
    candidates = collect_candidates(cfg)
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
    }


def structs(config: WorkerConfig, req: StructsRequest) -> dict[str, Any]:
    """Structs recovered from the default target's annotated functions.

    ``limit`` caps how many functions are decompiled; 0 means no cap.  A
    project with no annotated functions answers ``{"functions": 0, "structs": []}``.
    """
    from rebrew.config import load_config
    from rebrew.struct_recover import NoDecompilationError, recover_project_structs

    if req.decompiler not in DECOMPILER_BACKENDS:
        raise _invalid(f"unsupported decompiler backend: {req.decompiler}")
    if req.limit < 0:
        raise _invalid(f"limit must not be negative, got {req.limit}")
    cfg = load_config(project_root(config, req.project_dir))
    try:
        return recover_project_structs(
            cfg,
            decompiler=req.decompiler,
            all_funcs=True,
            limit=req.limit or None,
            json_output=True,
        )
    except NoDecompilationError as exc:
        raise _refused(_bounded(str(exc))) from None


def binary_operand_locations(config: WorkerConfig, req: OperandLocationsRequest) -> dict[str, Any]:
    """Per function, the requested (offset, operand index) pairs that decode as operands.

    Decoding starts at each function entry with the loader's ISA.
    """
    from rebrew.analysis import capstone_handle
    from rebrew.formats.binary_loader import capstone_config_for, extract_bytes_at_va, load_binary

    if not 1 <= len(req.functions) <= OPERAND_MAX_FUNCTIONS:
        raise _invalid(f"functions must hold 1 to {OPERAND_MAX_FUNCTIONS} entries")
    for function in req.functions:
        if function.va < 0 or not 1 <= function.size <= OPERAND_MAX_FUNCTION_BYTES:
            raise _invalid("function extent is outside its bounds")
        if len(function.locations) > OPERAND_MAX_LOCATIONS or any(
            not 0 <= offset < function.size or not 0 <= index <= OPERAND_MAX_INDEX
            for offset, index in function.locations
        ):
            raise _invalid("operand locations are outside their bounds")
    with binary_file(config, req.file, req.url, req.sha256, "file") as path:
        info = load_binary(path)
        decoder = capstone_handle(*capstone_config_for(info), detail=True)
        results: list[list[list[int]]] = []
        for function in req.functions:
            code = extract_bytes_at_va(info, function.va, function.size, trim_padding=False)
            if code is None or len(code) != function.size:
                raise _invalid("operand extent is not file backed")
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

    if not 1 <= len(req.functions) <= DIGEST_MAX_FUNCTIONS:
        raise _invalid(f"functions must hold 1 to {DIGEST_MAX_FUNCTIONS} entries")
    for extent in req.functions:
        if extent.va < 0 or not 1 <= extent.size <= DIGEST_MAX_FUNCTION_BYTES:
            raise _invalid("function extent is outside its bounds")
    with binary_file(config, req.file, req.url, req.sha256, "file") as path:
        info = load_binary(path)
        try:
            spans = relocation_spans(info)
        except NotImplementedError as exc:
            raise _invalid(_bounded(str(exc))) from None
        identities = []
        for extent in req.functions:
            va, size = extent.va, extent.size
            code = extract_bytes_at_va(info, va, size, trim_padding=False)
            if code is None or len(code) != size:
                raise _invalid("function digest extent is not file backed")
            masked = sorted(
                {
                    offset - va
                    for address, width in spans
                    for offset in range(max(va, address), min(va + size, address + width))
                }
            )
            if len(masked) == size:
                raise _invalid("function has no unmasked bytes")
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
    from rebrew.imports import imports_payload

    with _scan_binary(config, req) as path:
        return imports_payload(path)


def strings(config: WorkerConfig, req: BinaryFile) -> dict[str, Any]:
    """Strings collected from the stored binary, as JSON."""
    from rebrew.strings import collect_strings

    with _scan_binary(config, req) as path:
        return collect_strings(path, json_output=True)


def fingerprint(config: WorkerConfig, req: BinaryFile) -> dict[str, Any]:
    """Fingerprint bundle of the stored binary."""
    from rebrew.fingerprints import fingerprint_bundle

    with _scan_binary(config, req) as path:
        return dict(fingerprint_bundle(path))


def analyze(config: WorkerConfig, req: BinaryFile) -> dict[str, Any]:
    """The standalone dossier: no project, so project-scoped sections stay empty."""
    from rebrew.analyze import build_dossier, standalone_config

    with _scan_binary(config, req) as path:
        return build_dossier(standalone_config(path), path)


def crypto_scan(config: WorkerConfig, req: BinaryFile) -> dict[str, Any]:
    """Crypto constants (each finding named) and APIs.

    With no project there are no function names to match.
    """
    from rebrew.crypto_scan import crypto_scan as scan

    with _scan_binary(config, req) as path:
        return scan(path, [])


def pe_info(config: WorkerConfig, req: BinaryFile) -> dict[str, Any]:
    """PE header fields of the stored binary."""
    from rebrew.pe_info import pe_info as info

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
    to nothing are left out; the rest keep archive order.
    """
    from rebrew.asm import disassemble_to_nasm
    from rebrew.formats.archives import parse_archive
    from rebrew.formats.binary_loader import capstone_config_for, object_arch
    from rebrew.formats.binary_model import BinaryInfo
    from rebrew.gen_flirt_pat import parse_coff_obj, parse_elf_obj

    functions: list[dict[str, Any]] = []
    with binary_file(config, req.file, req.url, req.sha256, "file") as path:
        try:
            members = list(parse_archive(str(path)))
        except ValueError:
            raise _invalid("the file is not an ar archive") from None
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
            for name, code, _relocations in symbols:
                if arch == NASM_ARCH:
                    listing, _stats = disassemble_to_nasm(code, 0, None)
                else:
                    listing = _asm_listing(code, 0, cs_arch, cs_mode)
                if listing.strip():
                    functions.append(
                        {"name": name, "size": len(code), "arch": arch, "listing": listing}
                    )
    return {"functions": functions}


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
    from rebrew.splat_config import parse_splat_text

    if len(req.config.encode("utf-8", errors="surrogatepass")) > SPLAT_MAX_CONFIG_BYTES:
        raise _invalid(f"config exceeds {SPLAT_MAX_CONFIG_BYTES} bytes")
    try:
        parsed = parse_splat_text(req.config, SPLAT_ANCHOR)
    except ValueError as exc:
        raise _invalid(_bounded(str(exc).replace(f"{SPLAT_ANCHOR}: ", ""))) from None
    except RecursionError:
        raise _invalid("config nesting is too deep") from None
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
    from rebrew.report import generate_report

    root = project_root(config, req.project_dir)
    out = _inside(config.require_workspace(), req.output_dir, "output_dir")
    if req.files:
        if req.coverage_input.version != 1 or not req.coverage_input_digest:
            verified_coverage_inputs_required()
        if not re.fullmatch(r"reports/generated/[0-9a-f]{32}", req.output_dir):
            raise _invalid("retained report output must have a unique generated path")
        if out != config.require_workspace() / req.output_dir:
            raise _invalid("retained report output must not traverse symlinks")
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            out.mkdir()
        except FileExistsError:
            raise _invalid("retained report output already exists") from None
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
                        _bounded(str(exc)), code="coverage-input-unverified", status=409
                    ) from None
                checked_coverage_input(snapshot, req)
                entries: list[dict[str, Any]] = []
                size = 0
                for path in sorted(out.rglob("*")):
                    if path.is_symlink():
                        raise _invalid("report output must not contain symlinks")
                    if path.is_file():
                        size += path.stat().st_size
                        if len(entries) >= 4096 or size > 64 * 1024 * 1024:
                            raise _invalid("report output exceeds bounds")
                        entries.append(
                            {
                                "path": path.relative_to(out).as_posix(),
                                "size": path.stat().st_size,
                                "digest": _file_sha256(path),
                            }
                        )
                if not entries:
                    raise _invalid("report output is empty")
                return {**result, "out": str(out), "manifest": entries}
        except BaseException:
            shutil.rmtree(out)
            raise
    if req.coverage_input.version or req.coverage_input_digest or req.verification_records:
        raise _invalid("coverage input requires a retained snapshot")
    return generate_report(load_config(root), out)


def security_scan(config: WorkerConfig, req: SecurityScanRequest) -> dict[str, Any]:
    """Rule findings over the default target's reversed sources at ``min_severity`` or above."""
    from rebrew.config import load_config
    from rebrew.security_scan import SEVERITY_ORDER, filter_by_severity
    from rebrew.security_scan import security_scan as scan

    if req.min_severity not in SEVERITY_ORDER:
        raise _invalid(f"min_severity must be one of {', '.join(SEVERITY_ORDER)}")
    cfg = load_config(project_root(config, req.project_dir))
    return filter_by_severity(scan(cfg.reversed_dir), req.min_severity)


def target_name(display_name: str) -> str:
    """The rebrew target name for an uploaded file: ``2k-calc.exe`` is ``t_2k_calc``."""
    # NFC first: the same name from a macOS volume arrives NFD, and the
    # combining mark would become ``_`` while an NFC accent becomes ``_``
    # mid-word, yielding two target names for one file (``Cafe\u0301``
    # -> ``Cafe`` vs ``Caf\u00e9`` -> ``Caf``).  ASCII-digit test: the stem
    # is ``[A-Za-z0-9_]`` only, so ``str.isdigit`` cannot see a non-ASCII digit.
    stem = _TARGET_UNSAFE.sub("_", Path(unicodedata.normalize("NFC", display_name)).stem)
    stem = stem.strip("_") or "target"
    return f"t_{stem}" if "0" <= stem[0] <= "9" else stem


def _run_intake(binary: Path, project: Path, target: str) -> dict[str, Any]:
    """Run ``rebrew intake --json`` in *project*.

    Intake onboards the project in its working directory and has no entry
    point that takes a root, so it runs through :func:`run_rebrew`.
    """
    return run_rebrew(
        ["intake", "--json", "--target", target, str(binary)], project, INTAKE_TIMEOUT_SECONDS
    )


def run_rebrew(
    arguments: list[str], project: Path, timeout: int, *, outcome_exit: bool = False
) -> dict[str, Any]:
    """Run ``rebrew <arguments>`` in *project* and answer the JSON object it prints.

    *arguments* must select JSON output.  The commands an op runs this way
    work in their working directory, print their report rather than return
    it, or exit through ``error_exit``, while ``serve`` handles calls on
    threads sharing one cwd and one stdout, so each runs as a child process
    in its own session; a timeout kills the whole group.  With
    *outcome_exit*, exit 1 (rebrew's mismatch or failed-check outcome) also
    answers the printed report; any other non-zero exit is a refusal carrying
    the command's JSON error message.
    """
    name = " ".join(word for word in arguments[:2] if not word.startswith("-"))
    # -P keeps the project cwd off sys.path so a rebrew/ tree inside the
    # project cannot shadow the installed rebrew.app.main (code exec).
    command = [sys.executable, "-P", "-m", "rebrew.app.main"]
    process = subprocess.Popen(
        [*command, *arguments],
        cwd=project,
        # The child exports its own spans (the remote compile's client span) under this one.
        env={**os.environ, **telemetry.child_environment()},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        from rebrew.utils import kill_process_group

        kill_process_group(process)
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
        raise _refused(f"rebrew {name} did not finish within {timeout} s") from None
    except BaseException:
        # KeyboardInterrupt / SystemExit during communicate(): without this
        # the child (and its whole process group) outlives the serve thread
        # that spawned it, accumulating one orphaned rebrew per interrupted
        # request.  Mirror utils.run_process_group's BaseException path.
        from rebrew.utils import stop_process_tree

        stop_process_tree(process)
        raise
    if process.returncode != 0 and not (outcome_exit and process.returncode == 1):
        logger.error(
            "rebrew %s exited %d: %s", name, process.returncode, _escape_log_text(stderr.strip())
        )
        raise _refused(f"rebrew {name} failed: {_command_refusal(stderr)}")
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError:
        logger.exception(
            "rebrew %s printed no JSON report: %s", name, _escape_log_text(stderr.strip())
        )
        raise _refused(f"rebrew {name} printed no JSON report") from None
    if not isinstance(report, dict):
        raise _refused(f"rebrew {name} answered a report that is not an object")
    return report


def _command_refusal(stderr: str) -> str:
    """The message of a command's JSON error line, or its exit being unexplained."""
    for line in reversed(stderr.splitlines()):
        with contextlib.suppress(json.JSONDecodeError):
            payload = json.loads(line)
            if isinstance(payload, dict) and isinstance(payload.get("error"), dict):
                return _bounded(str(payload["error"].get("message", "")))
    return "no error report"


def analyse(config: WorkerConfig, req: AnalyseRequest) -> dict[str, Any]:
    """Onboard a stored binary into its project-scoped workspace and report its coverage.

    A second run re-discovers into the same project.  ``intake`` is the onboarding report.
    """
    project_id = req.project_id
    if len(project_id.encode("utf-8")) > 256 or "\x00" in project_id:
        raise _invalid("project_id must be at most 256 UTF-8 bytes without NUL")
    workspace = config.require_workspace()
    if not project_id:
        relative = f"projects/{_sha256(req.sha256)}"
    else:
        scope = hashlib.sha256(project_id.encode("utf-8")).hexdigest()
        relative = f"projects/scopes/{scope}/{_sha256(req.sha256)}"
    project = workspace / relative
    if _inside(workspace, relative, "analysis project") != project:
        raise _invalid("analysis project must not traverse symlinks")
    with binary_file(config, req.file_key, req.url, req.sha256, "file_key") as binary:
        project.mkdir(parents=True, exist_ok=True)
        if _inside(workspace, relative, "analysis project") != project:
            raise _invalid("analysis project must not traverse symlinks")
        intake = _run_intake(binary, project, target_name(req.name))
        capture, report = capture_fresh_analysis(config, binary, req.sha256, target_name(req.name))
        for item in report["targets"]:
            for field in ("document", "path"):
                if item[field]:
                    item[field] = str(project / item[field])
    return {**report, "project": str(project), "intake": intake, "analysis_capture": capture}


def capture_fresh_analysis(
    config: WorkerConfig, binary: Path, sha256: str, target: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Capture the complete baseline readset from a new, independent intake."""
    from rebrew.config import inventory_path_for, load_config
    from rebrew.coverage_project import coverage_inputs
    from rebrew.sources import iter_headers, iter_sources

    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="analysis-capture-", dir=scratch) as temp:
        root = Path(temp).resolve()
        _run_intake(binary, root, target)
        for path in root.rglob("*"):
            if path.is_symlink():
                raise _capture_failed("fresh analysis capture contains a symlink")
        cfg = load_config(root, target=target)
        confined_snapshot_config(cfg, root)
        if cfg.raw_link is not None:
            raise _capture_failed("fresh analysis capture cannot include an unverified raw link")
        if not cfg.target_binary.is_file() or _file_sha256(cfg.target_binary) != sha256:
            raise _invalid("fresh analysis binary does not match the request")
        inventory = inventory_path_for(cfg.reversed_dir, cfg).resolve()
        source_paths = {p.resolve() for p in iter_sources(cfg.reversed_dir, cfg)}
        source_paths.update(p.resolve() for p in iter_headers(cfg.reversed_dir, cfg))
        paths = {Path(entry[0]) for entry in coverage_inputs(cfg)}
        entries: list[dict[str, Any]] = []
        total = 0
        captured_count = sum(1 for path in paths if path.resolve().is_relative_to(root))
        if captured_count > MAX_READSET_FILES:
            raise _readset_limit("fresh analysis capture", captured_count, MAX_READSET_FILES)
        for path in sorted(
            paths, key=lambda value: str(value).encode("utf-8", errors="surrogateescape")
        ):
            resolved = path.resolve()
            if not resolved.is_relative_to(root):
                if path.exists() or path.is_symlink():
                    raise _capture_failed("fresh analysis reads an ambient input")
                continue
            relative = resolved.relative_to(root).as_posix()
            if path.is_symlink() or relative == ".":
                raise _capture_failed("invalid fresh analysis readset")
            if not path.exists():
                entries.append(
                    {"path": relative, "kind": "absent", "size": 0, "digest": "", "data": ""}
                )
                continue
            if not path.is_file():
                raise _capture_failed("fresh analysis readset contains an unsupported directory")
            if "verify_cache" in path.name:
                raise _capture_failed("fresh analysis capture must not contain verification cache")
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
            if size > MAX_READSET_FILE_BYTES:
                raise _readset_limit(
                    f"fresh analysis input {relative}", size, MAX_READSET_FILE_BYTES, "bytes"
                )
            if total > MAX_READSET_BYTES:
                raise _readset_limit("fresh analysis capture", total, MAX_READSET_BYTES, "bytes")
            data = path.read_bytes()
            if len(data) != size:
                raise _capture_failed("fresh analysis input changed during capture")
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
        report = project_report(root, None, include_source=True)
        # The report is an assertion by this worker, so its complete captured
        # readset must still match after the report was constructed.
        current_paths = {Path(entry[0]) for entry in coverage_inputs(cfg)}
        current_sources = {p.resolve() for p in iter_sources(cfg.reversed_dir, cfg)}
        current_sources.update(p.resolve() for p in iter_headers(cfg.reversed_dir, cfg))
        if current_paths != paths or current_sources != source_paths:
            raise _capture_failed("fresh analysis input changed during reporting")
        for captured in entries:
            path = root / captured["path"]
            if any(
                part.is_symlink()
                for part in (path, *path.parents)
                if part != root and part.is_relative_to(root)
            ):
                raise _capture_failed("fresh analysis input changed during reporting")
            if captured["kind"] == "absent":
                if path.exists():
                    raise _capture_failed("fresh analysis input changed during reporting")
            elif (
                not path.is_file()
                or path.stat().st_size != captured["size"]
                or _file_sha256(path) != captured["digest"]
            ):
                raise _capture_failed("fresh analysis input changed during reporting")
        selected = None
        if inventory.is_relative_to(root):
            relative_inventory = inventory.relative_to(root).as_posix()
            selected = next(
                (entry for entry in entries if entry["path"] == relative_inventory), None
            )
        if (
            selected is not None
            and selected["kind"] == "file"
            and selected.get("role") == "analysis"
        ):
            project_config = next(
                (entry for entry in entries if entry["path"] == "rebrew-project.toml"), None
            )
            if project_config is None or project_config["kind"] != "file":
                raise _capture_failed("fresh analysis configuration is not captured")
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
                    or _file_sha256(path) != captured["digest"]
                ):
                    raise _capture_failed("fresh analysis input changed during reporting")
            if not cfg.target_binary.is_file() or _file_sha256(cfg.target_binary) != sha256:
                raise _capture_failed("fresh analysis input changed during reporting")
            current = load_config(root, target=target)
            if inventory_path_for(current.reversed_dir, current).resolve() != inventory:
                raise _capture_failed("fresh analysis inventory changed during reporting")
        for item in report["targets"]:
            for field in ("document", "path"):
                if item[field]:
                    item[field] = str(Path(item[field]).relative_to(root))
        capture = {"version": 1, "binary_sha256": sha256, "target": target, "entries": entries}
        if (
            selected is not None
            and selected["kind"] == "file"
            and selected.get("role") == "analysis"
        ):
            capture["inventory_path"] = selected["path"]
        if len(report["targets"]) == 1:
            item = report["targets"][0]
            if item["name"] != target or item["sha256"] != sha256:
                raise _capture_failed("fresh analysis report has a different target")
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
                        raise _capture_failed("invalid fresh analysis report identity")
                    entry = {"va": va, "name": name}
                    if size_field:
                        size = row["size"]
                        if type(size) is not int or not 0 <= size <= 2**63 - 1:
                            raise _capture_failed("invalid fresh analysis report extent")
                        entry["size"] = size
                    seen.add(va)
                    result.append(entry)
                result.sort(key=lambda row: row["va"])
            report_path = ".relumea/analysis-report.json"
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
                raise _capture_failed("fresh analysis report path already exists")
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
                len(normalized) <= MAX_READSET_FILE_BYTES
                and total + len(normalized) <= MAX_READSET_BYTES
                and len(entries) < MAX_READSET_FILES
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
                entries.sort(
                    key=lambda entry: entry["path"].encode("utf-8", errors="surrogateescape")
                )
                capture["report_path"] = report_path
        return capture, report


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
        raise _invalid("scoped analysis projects cannot be imported by path")
    if req.snapshots and req.build_db:
        raise _invalid("snapshots and build_db exclude each other")
    snapshots = None
    if req.snapshots:
        snapshots = confined_dir(config, req.snapshots, "snapshots")
        if scoped_projects is not None and snapshots.is_relative_to(scoped_projects):
            raise _invalid("scoped analysis snapshots cannot be imported by path")
        if not snapshots.is_dir():
            raise _invalid("snapshots must be a directory")
    return project_report(root, snapshots)


def project_report(
    root: Path, snapshots: Path | None, *, include_source: bool = False
) -> dict[str, Any]:
    """The backend's ``ProjectReport`` of *root*: targets, functions and import stubs.

    Live coverage is read unless *snapshots* names a portable export directory.
    """
    from rebrew.config import load_config
    from rebrew.coverage_project import load_project_coverage
    from rebrew.coverage_toml import load_coverage_from
    from rebrew.discover import elf_function_symbols
    from rebrew.formats.import_table import find_import_stubs
    from rebrew.workspace import read_config, target_binary, targets_table

    if snapshots is None:
        view = load_project_coverage(root, refresh=True)
        if view.failures:
            raise _refused(f"coverage failed for targets: {', '.join(sorted(view.failures))}")
        coverage = dict(view.snapshots)
    else:
        names = sorted(p.stem.removeprefix("coverage-") for p in snapshots.glob("coverage-*.toml"))
        coverage = {name: load_coverage_from(snapshots, name) for name in names}
    if not coverage:
        raise _invalid("the project has no coverage targets")
    table = targets_table(read_config(root))
    targets = []
    for name in sorted(coverage):
        entry = table.get(name, {})
        cfg = load_config(root, target=name) if include_source else None

        def source_path(row: Any, source_dir: Path = cfg.reversed_dir if cfg else root) -> str:
            paths: set[str] = set()
            for value in row.files:
                path = (source_dir / value).resolve()
                if path.is_relative_to(root.resolve()) and path.is_file():
                    paths.add(path.relative_to(root.resolve()).as_posix())
            return next(iter(paths)) if len(paths) == 1 else ""

        binary = target_binary(root, entry) if entry else None
        if binary is not None and not binary.is_file():
            binary = None
        symbol_names = (
            {va: (size, symbol) for va, size, symbol in elf_function_symbols(binary)}
            if binary is not None
            else {}
        )
        functions: list[dict[str, Any]] = [
            {
                "va": row.va,
                "name": symbol_names.get(row.va, (0, row.name.strip()))[1]
                if row.name.strip() == f"fcn_{row.va:08x}"
                else row.name.strip() or f"sub_{row.va:x}",
                "size": (symbol_names.get(row.va, (0, ""))[0] or max(0, row.size or 0))
                if row.name.strip() == f"fcn_{row.va:08x}"
                else max(0, row.size or 0),
                "status": row.status,
                **(
                    {"source_path": source_path(row)} if include_source and source_path(row) else {}
                ),
            }
            for row in sorted(coverage[name].functions, key=lambda row: row.va)
            if row.markerType not in _DATA_MARKERS
        ]
        import_stubs: dict[int, str] = find_import_stubs(binary) if binary is not None else {}
        # An import thunk that is also a function row is one identity: the function
        # row wins, taking the import name when it only has the generated one.
        for row in functions:
            stub = import_stubs.pop(row["va"], None)
            if stub is not None and row["name"] == f"fcn_{row['va']:08x}":
                row["name"] = stub
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
                "sha256": _file_sha256(binary) if binary is not None else "",
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
# Reconstruction ops on a project
#
# Each names the target by its binary's sha256 (empty: the default target).
# Ops that run a rebrew command answer the JSON object it prints; the source
# and output paths they take are project-relative and must stay inside it.
# ---------------------------------------------------------------------------


def _flag(enabled: bool, option: str) -> list[str]:
    return [option] if enabled else []


def remote_header_refusal(cfg: Any, sources: Iterable[Path]) -> None:
    """Refuse a remote compile of a source that reads project headers.

    The recompile service compiles the source text against its image's own
    include tree; no project header travels with it, so such a source would
    not compile as it does locally (relumea ADR 0010, decision 4).  Until
    include bundles exist, a source whose include closure reaches a header
    under its directory or the project's ``/I`` directories, or that computes
    an include, is refused before anything compiles.  Local compiles pass.
    """
    from rebrew.compiler.compile import recompile_url

    if recompile_url(cfg) is None:
        return
    from rebrew.compiler.cache import scan_include_closure
    from rebrew.compiler.compile import effective_compile_flags, extract_include_dirs

    for source in sources:
        flags = effective_compile_flags(cfg, None, "", source.parent)
        headers, computed, _snapshots, _consistent = scan_include_closure(
            source.read_text(encoding="utf-8", errors="surrogateescape"),
            str(source.parent),
            tuple(extract_include_dirs(flags)),
        )
        if headers or computed:
            shown = source.relative_to(cfg.root) if source.is_relative_to(cfg.root) else source
            raise OpsError(
                f"{shown} reads project headers, which a remote compile cannot ship yet;"
                " compile it with a local backend",
                code=REMOTE_HEADERS,
                status=422,
            )


def retained_compile_refusal(cfg: Any, sources: Iterable[Path]) -> None:
    """Use only the operator-configured remote compiler and confined include flags."""
    from rebrew.compiler.compile import effective_compile_flags, extract_include_dirs

    approved = os.environ.get("REBREW_RECOMPILE_URL", "").strip()
    if not approved or cfg.recompile_url != approved:
        raise _refused("retained compilation requires the configured private recompile service")
    source_list = list(sources)
    for source in source_list:
        for flags in (cfg.cflags, *cfg.cflags_presets.values()):
            for item in extract_include_dirs(
                effective_compile_flags(cfg, None, flags, source.parent)
            ):
                if "\\" in item or not Path(item).resolve().is_relative_to(cfg.root):
                    raise _invalid("compiler include directory escapes the retained snapshot")
    remote_header_refusal(cfg, source_list)


def reference_flirt(config: WorkerConfig, req: ReferenceFlirtRequest) -> dict[str, Any]:
    """Match one FLIRT ``.sig``/``.pat`` file against the target's code sections.

    ``rebrew library scan-signatures`` with that file alone: unambiguous
    matches of at least ``min_size`` bytes, and the count of ambiguous ones
    skipped.  The signatures are a stored file like a binary.
    """
    if req.format not in FLIRT_FORMATS:
        raise _invalid(f"format must be one of {', '.join(sorted(FLIRT_FORMATS))}")
    if req.min_size < 0:
        raise _invalid(f"min_size must not be negative, got {req.min_size}")
    root = project_root(config, req.project_dir)
    target = _target_options(root, req.sha256)
    signatures = req.signatures
    scratch = config.require_workspace() / SCRATCH_DIR
    with binary_file(
        config, signatures.file, signatures.url, signatures.sha256, "signatures.file"
    ) as path:
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="flirt-", dir=scratch) as directory:
            shutil.copyfile(path, Path(directory) / f"reference.{req.format}")
            arguments = ["library", "scan-signatures", "--json", f"--min-size={req.min_size}"]
            return run_rebrew([*arguments, *target, "--", directory], root, COMMAND_TIMEOUT_SECONDS)


def verify_function(config: WorkerConfig, req: VerifyRequest) -> dict[str, Any]:
    """Compile one source and byte-compare it to the target (``rebrew test <source> --json``).

    A mismatch is a result.  Without ``no_promote`` the comparison writes the
    function's STATUS into the project metadata, as ``rebrew test`` does.
    """
    from rebrew.test import run_test

    if req.candidate:
        return verify_candidate(config, req)

    root = project_root(config, req.project_dir)
    cfg = target_config(root, req.sha256)
    source = _project_file(root, req.source, "source")
    remote_header_refusal(cfg, [source])
    return run_test(cfg, source, no_promote=req.no_promote, json_output=True)


def verify_candidate(config: WorkerConfig, req: VerifyRequest) -> dict[str, Any]:
    """Compare candidate text in a private snapshot of retained inputs."""
    return _run_candidate(config, req, apply=False)


#: Files an applied candidate may change; nothing else in the snapshot leaves the op.
APPLY_METADATA_FILE = "rebrew-functions.toml"


def apply_candidate(config: WorkerConfig, req: ApplyCandidateRequest) -> dict[str, Any]:
    """Promote an exact candidate in a private snapshot and return the files that changed.

    The candidate takes the function's address anchor, ``rebrew test`` runs in promote mode with the attempt's
    flags, so rebrew's own writers record STATUS, SIZE and CFLAGS, and the function's identity (symbol and
    name) follows the candidate through rebrew's identity writer. A result that is not EXACT or RELOC is
    refused: nothing is published from a candidate that no longer matches.
    """
    return _run_candidate(config, req, apply=True)


def _run_candidate(
    config: WorkerConfig, req: VerifyRequest | ApplyCandidateRequest, *, apply: bool
) -> dict[str, Any]:
    applying = req if isinstance(req, ApplyCandidateRequest) and apply else None
    from rebrew.c_parser import find_c_function_definitions
    from rebrew.config import load_config
    from rebrew.utils import portable_path_parts

    definitions = find_c_function_definitions(req.candidate)
    if len(definitions) != 1 or len(req.candidate.encode()) > 2_000_000:
        raise _invalid("candidate must contain one function and at most 2000000 bytes")
    if req.va < 0 or not 1 <= req.size <= 1048576:
        raise _invalid("invalid function extent")
    _check_manifest_size(req.files)
    paths = [f.path for f in req.files]
    if (
        len(set(paths)) != len(paths)
        or req.source not in paths
        or any(not portable_path_parts(path) for path in paths)
    ):
        raise _invalid("invalid retained source manifest paths")
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="verify-candidate-", dir=scratch) as temp:
        root = Path(temp).resolve()
        destination = _stage_retained_snapshot(
            config,
            root,
            req.files,
            req.rebrew_target,
            req.sha256,
            req.binary_key,
            req.binary_url,
            exclusive=False,
        )
        source = _project_file(root, req.source, "source")
        if source.suffix.lower() != ".c":
            raise _invalid("candidate source must be a C file")
        if _file_sha256(source) != req.source_sha256:
            raise _invalid("source does not match its retained digest")
        candidate = req.candidate
        module = ""
        if apply:
            from rebrew.metadata.anchors import address_comment
            from rebrew.metadata.bindings import module_for_va

            module = module_for_va(source, req.va)
            if not module:
                raise _invalid("the function has no address anchor in the retained source")
            if f"0x{req.va:08x}" not in candidate.lower():
                # rebrew wants the anchor directly above the one declaration it names, whatever
                # includes and types the candidate keeps above it.
                lines = split_source_lines(candidate, keepends=True)
                at = definitions[0][1] - 1
                lines.insert(at, address_comment(module, req.va) + "\n")
                candidate = "".join(lines)
        source.write_text(candidate, encoding="utf-8")
        rewritten = apply_project_cflags(root, req.rebrew_target, req.project_cflags)
        cfg = load_config(root, target=req.rebrew_target)
        confined_snapshot_config(cfg, root)
        retained_compile_refusal(cfg, [source])
        symbol = definitions[0][0]
        if applying is not None:
            if cfg.metadata_dir.resolve() != root:
                raise _invalid("the retained project keeps its function registry outside its root")
            symbol = _move_identity(cfg, applying, module, definitions[0][0])
        flags = checked_cflags(req.cflags)
        result = run_rebrew(
            [
                "test",
                "--json",
                *([] if apply else ["--no-promote"]),
                *([f"--cflags={flags}"] if flags else []),
                f"--target={req.rebrew_target}",
                f"--va=0x{req.va:x}",
                f"--size={req.size}",
                f"--symbol={symbol}",
                "--",
                str(source),
            ],
            root,
            COMMAND_TIMEOUT_SECONDS,
            outcome_exit=True,
        )
        if _file_sha256(destination) != req.sha256 or (
            not apply and source.read_text(encoding="utf-8") != req.candidate
        ):
            raise _invalid("snapshot candidate or binary changed during verification")
        for entry in req.files:
            if entry.path == req.source or (apply and entry.path == APPLY_METADATA_FILE):
                continue
            path = _project_file(root, entry.path, "source file")
            size, digest = (
                rewritten
                if rewritten and entry.path == "rebrew-project.toml"
                else (entry.size, entry.digest)
            )
            if path.stat().st_size != size or _file_sha256(path) != digest:
                raise _invalid("snapshot source changed during verification")
        result["source"] = req.source
        if applying is not None:
            return _applied(root, applying, result)
        return result


def _move_identity(cfg: Any, req: ApplyCandidateRequest, module: str, name: str) -> str:
    """Point the function's registry entry at the candidate's name through rebrew's identity writer.

    rebrew refuses to test a source whose address anchor names a function other than the registry's, so this
    runs before the comparison. The symbol is the one rebrew derives from the candidate's prototype
    (``_add@8`` for a stdcall ``add``): the comparison must name the same symbol to be allowed to record its
    STATUS, and it is returned for that.
    """
    from rebrew.c_parser import function_signatures
    from rebrew.metadata.bindings import derive_c_symbol
    from rebrew.metadata.functions import record_function_rows

    symbol = derive_c_symbol(name, function_signatures(req.candidate).get(name, ""))
    record_function_rows(
        cfg.metadata_dir,
        [
            {
                "module": module,
                "va": req.va,
                "identity": {"symbol": symbol, "name": name},
                "fields": {},
            }
        ],
        overwrite_name=True,
        updated_by="rename",
    )
    return symbol


def _applied(root: Path, req: ApplyCandidateRequest, result: dict[str, Any]) -> dict[str, Any]:
    """Finish an apply: refuse a result that is not a byte match, return the changed files."""
    if result.get("status") not in {"EXACT", "RELOC"}:
        raise _invalid(f"the candidate no longer matches: {result.get('status')}")
    changed = []
    for relative in (req.source, APPLY_METADATA_FILE):
        data = _project_file(root, relative, "applied file").read_bytes()
        if len(data) > 1024 * 1024:
            raise _invalid("an applied file exceeds the 1 MiB limit")
        changed.append(
            {
                "path": relative,
                "size": len(data),
                "digest": hashlib.sha256(data).hexdigest(),
                "data": base64.b64encode(data).decode("ascii"),
            }
        )
    return {"result": result, "files": changed}


def confined_snapshot_config(cfg: Any, root: Path) -> None:
    """Refuse project-config paths that could read or write outside a retained snapshot."""
    from rebrew.coverage_input_contract import CoverageInputError
    from rebrew.coverage_input_contract import confined_snapshot_config as check

    try:
        check(cfg, root)
    except CoverageInputError as exc:
        raise _invalid(str(exc)) from exc


@contextlib.contextmanager
def retained_target_snapshot(
    config: WorkerConfig,
    files: list[FlagSearchFile],
    target_name: str,
    sha256: str,
    binary_key: str,
    binary_url: str,
    project_cflags: str = "",
) -> Iterator[Path]:
    """Stage a bounded retained source manifest and binary without touching the live project.

    *project_cflags*, when set, become the project cflags of the private copy (``apply_project_cflags``).
    """
    from rebrew.config import inventory_path_for, load_config
    from rebrew.utils import portable_path_parts

    if not target_name or not files:
        raise _invalid("invalid retained source manifest")
    _check_manifest_size(files)
    if len({f.path for f in files}) != len(files) or any(
        not portable_path_parts(f.path) for f in files
    ):
        raise _invalid("duplicate retained source path")
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="retained-target-", dir=scratch) as temp:
        root = Path(temp).resolve()
        destination = _stage_retained_snapshot(
            config, root, files, target_name, sha256, binary_key, binary_url, exclusive=False
        )
        rewritten = apply_project_cflags(root, target_name, project_cflags)
        cfg = load_config(root, target=target_name)
        confined_snapshot_config(cfg, root)
        required = (
            inventory_path_for(cfg.reversed_dir, cfg),
            cfg.metadata_dir / "rebrew-functions.toml",
        )
        if cfg.metadata_backend != "toml" or any(
            not path.is_file()
            or path.relative_to(root).as_posix() not in {entry.path for entry in files}
            for path in required
        ):
            raise _invalid("retained target requires its inventory and TOML function metadata")
        yield root
        if _file_sha256(destination) != sha256:
            raise _invalid("snapshot target binary changed during operation")
        for entry in files:
            path = _project_file(root, entry.path, "source file")
            size, digest = (
                rewritten
                if rewritten and entry.path == "rebrew-project.toml"
                else (entry.size, entry.digest)
            )
            if path.stat().st_size != size or _file_sha256(path) != digest:
                raise _invalid("snapshot source changed during operation")


def _run_target_command(
    config: WorkerConfig,
    req: VerifyTargetRequest | BuildRequest,
    arguments: list[str],
) -> dict[str, Any]:
    """Run a whole-target rebrew command live or against a retained snapshot.

    Retained snapshots force the compile refusal; live runs refuse remote
    compilation of header-reading sources.  ``project_cflags`` requires the
    snapshot so the flags land on the private copy only.
    """
    from rebrew.config import load_config
    from rebrew.sources import iter_sources

    root = project_root(config, req.project_dir)
    if req.files:
        with retained_target_snapshot(
            config,
            req.files,
            req.rebrew_target,
            req.sha256,
            req.binary_key,
            req.binary_url,
            req.project_cflags,
        ) as snapshot:
            cfg = load_config(snapshot, target=req.rebrew_target)
            retained_compile_refusal(cfg, iter_sources(cfg.reversed_dir, cfg))
            return run_rebrew(
                [*arguments, f"--target={req.rebrew_target}"],
                snapshot,
                SEARCH_TIMEOUT_SECONDS,
                outcome_exit=True,
            )
    if req.project_cflags:
        raise _invalid("project_cflags needs a retained source snapshot")
    cfg = target_config(root, req.sha256)
    remote_header_refusal(cfg, iter_sources(cfg.reversed_dir, cfg))
    return run_rebrew(
        [*arguments, *_target_options(root, req.sha256)],
        root,
        SEARCH_TIMEOUT_SECONDS,
        outcome_exit=True,
    )


def verify_target(config: WorkerConfig, req: VerifyTargetRequest) -> dict[str, Any]:
    """Re-verify every source of the target (``rebrew verify --json``); a mismatch is a result."""
    if req.files and not req.no_promote:
        raise _invalid("retained target verification requires no_promote")
    arguments = ["verify", "--json", *_flag(req.no_promote, "--no-promote")]
    if req.files:
        arguments.append("--no-promote")
    return _run_target_command(config, req, arguments)


def build(config: WorkerConfig, req: BuildRequest) -> dict[str, Any]:
    """Splice every matched function back into the target and compare the image.

    ``rebrew build round-trip --json``; the rebuilt image is written beside the
    target's binary as ``<binary>.reasm``.  A byte difference is a result.
    """
    arguments = ["build", "round-trip", "--json", *_flag(req.fix_headers, "--fix-headers")]
    return _run_target_command(config, req, arguments)


def skeleton(config: WorkerConfig, req: SkeletonRequest) -> dict[str, Any]:
    """The C skeleton ``rebrew skeleton`` would write for ``va``, without writing it.

    ``name`` names the function; empty means ``FUN_<va>``.
    """
    from rebrew.analysis import is_inside
    from rebrew.config import target_module
    from rebrew.formats.binary_loader import load_binary
    from rebrew.skeleton import generate_skeleton

    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    va = _address(req.va)
    if not is_inside(load_binary(cfg.target_binary), va):
        raise _invalid(f"VA 0x{va:x} is outside the binary image")
    ghidra_name = req.name or f"FUN_{va:08x}"
    return {"source": generate_skeleton(cfg, va, ghidra_name, target_module(cfg), req.name or None)}


def coverage_export(config: WorkerConfig, req: CoverageExportRequest) -> dict[str, Any]:
    """Write portable coverage documents into ``output_dir`` under the workspace.

    ``rebrew coverage export``: one ``coverage-<target>.toml`` for the
    selected target, or for every target when ``sha256`` is empty.
    ``import-project`` reads the directory back as its ``snapshots``.
    """
    from rebrew.coverage_toml import write_coverage_toml

    root = project_root(config, req.project_dir)
    out = _inside(config.require_workspace(), req.output_dir, "output_dir")
    target = target_config(root, req.sha256).target_name if req.sha256 else None
    written = write_coverage_toml(root, out, target=target, json_output=True)
    return {"output_dir": str(out), "documents": [str(path) for path in written]}


def verified_coverage_inputs_required() -> None:
    """Coverage metadata needs producer custody, not merely a supplied manifest."""
    raise OpsError(
        "retained coverage requires verified inventory and result provenance",
        code="coverage-input-unverified",
        status=409,
    )


def checked_coverage_input(root: Path, req: Any) -> Any:
    """Validate the retained readset before and after each trusted calculation."""
    from rebrew.coverage_input_contract import CoverageInputError, validate_coverage_execution
    from rebrew.workspace.status import TrustedCoverage, TrustedVerification

    records = [dataclasses.asdict(record) for record in req.verification_records]
    try:
        validate_coverage_execution(
            root,
            req.rebrew_target,
            req.sha256,
            dataclasses.asdict(req.coverage_input),
            req.coverage_input_digest,
            records,
        )
        return TrustedCoverage(
            tuple(
                TrustedVerification(r.source, r.va, r.size, r.status, r.match_count)
                for r in req.verification_records
            )
        )
    except (CoverageInputError, ValueError) as exc:
        raise OpsError(_bounded(str(exc)), code="coverage-input-unverified", status=409) from None


def coverage_report(config: WorkerConfig, req: CoverageReportRequest) -> dict[str, Any]:
    """The target's decomp.dev progress report (objdiff ``report.json``, version 2).

    ``report`` is the document ``rebrew coverage report --decomp-dev``
    writes; ``summary`` its totals (functions, code bytes, fuzzy match).
    """
    from rebrew.config import load_config
    from rebrew.report import generate_decomp_dev_report

    if req.files:
        if req.coverage_input.version != 1 or not req.coverage_input_digest:
            verified_coverage_inputs_required()
        project_root(config, req.project_dir)
        with retained_target_snapshot(
            config,
            req.files,
            req.rebrew_target,
            req.sha256,
            req.binary_key,
            req.binary_url,
        ) as snapshot:
            cfg = load_config(snapshot, target=req.rebrew_target)
            trusted = checked_coverage_input(snapshot, req)
            scratch = config.require_workspace() / SCRATCH_DIR
            with tempfile.TemporaryDirectory(prefix="coverage-report-", dir=scratch) as directory:
                out = Path(directory) / "report.json"
                try:
                    summary = generate_decomp_dev_report(cfg, out, trusted=trusted)
                except ValueError as exc:
                    raise OpsError(
                        _bounded(str(exc)), code="coverage-input-unverified", status=409
                    ) from None
                checked_coverage_input(snapshot, req)
                report = json.loads(out.read_text(encoding="utf-8"))
                return {
                    "summary": {k: v for k, v in summary.items() if k != "out"},
                    "report": report,
                }
    if req.coverage_input.version or req.coverage_input_digest or req.verification_records:
        raise _invalid("coverage input requires a retained snapshot")
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="report-", dir=scratch) as directory:
        out = Path(directory) / "report.json"
        summary = generate_decomp_dev_report(cfg, out)
        report = json.loads(out.read_text(encoding="utf-8"))
    return {"summary": {k: v for k, v in summary.items() if k != "out"}, "report": report}


def source_variants(config: WorkerConfig, req: SourceVariantsRequest) -> dict[str, Any]:
    """Search source mutations of one function for a byte match (``rebrew match run --json``).

    A run that finds no match is a result.  ``seed`` makes the search
    reproducible.
    """
    if req.generations < 1 or req.population < 1 or req.seed < 0:
        raise _invalid("generations and population must be positive and seed not negative")
    root = project_root(config, req.project_dir)
    cfg = target_config(root, req.sha256)
    source = _project_file(root, req.source, "source")
    remote_header_refusal(cfg, [source])
    arguments = [
        "match",
        "run",
        "--json",
        f"--generations={req.generations}",
        f"--pop-size={req.population}",
        f"--seed={req.seed}",
    ]
    return run_rebrew(
        [*arguments, *_target_options(root, req.sha256), "--", str(source)],
        root,
        SEARCH_TIMEOUT_SECONDS,
        outcome_exit=True,
    )


def flag_search(config: WorkerConfig, req: FlagSearchRequest) -> dict[str, Any]:
    """Run a bounded flag or compiler profile sweep for one project source."""
    if req.va < 0 or req.tier not in {"quick", "targeted", "normal", "thorough", "full"}:
        raise _invalid("invalid address or flag search tier")
    if not req.compare_toolchains and (req.toolchains or req.exclude_toolchains or req.with_flags):
        raise _invalid("toolchain selection requires a toolchain comparison")
    if req.compare_toolchains and not req.with_flags and req.tier != "targeted":
        raise _invalid("tier requires flag search during toolchain comparison")
    if any(
        len(value) > 1024 or "\x00" in value for value in (req.toolchains, req.exclude_toolchains)
    ):
        raise _invalid("toolchain selectors must be at most 1024 characters")
    from rebrew.config import load_config

    _check_manifest_size(req.files)
    paths = [f.path for f in req.files]
    if len(set(paths)) != len(paths) or req.source not in paths:
        raise _invalid("invalid retained source manifest paths")
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="flag-search-", dir=scratch) as temp:
        root = Path(temp).resolve()
        destination = _stage_retained_snapshot(
            config,
            root,
            req.files,
            req.rebrew_target,
            req.sha256,
            req.binary_key,
            req.binary_url,
            exclusive=True,
        )
        source = _project_file(root, req.source, "source")
        if _file_sha256(source) != req.source_sha256:
            raise _invalid("source does not match its retained digest")
        cfg = load_config(root, target=req.rebrew_target)
        remote_header_refusal(cfg, [source])
        arguments = [
            "match",
            "toolchains" if req.compare_toolchains else "flags",
            "--json",
            "--jobs=2",
            f"--va=0x{req.va:x}",
        ]
        if not req.compare_toolchains or req.with_flags:
            arguments.append(f"--tier={req.tier}")
        if req.compare_toolchains:
            if not req.with_flags:
                arguments.remove("--jobs=2")
            arguments += _flag(req.with_flags, "--flags")
            if req.toolchains:
                arguments.append(f"--toolchains={req.toolchains}")
            if req.exclude_toolchains:
                arguments.append(f"--exclude-toolchains={req.exclude_toolchains}")
        result = run_rebrew(
            [*arguments, f"--target={req.rebrew_target}", "--", str(source)],
            root,
            SEARCH_TIMEOUT_SECONDS,
            outcome_exit=True,
        )
        if _file_sha256(source) != req.source_sha256 or _file_sha256(destination) != req.sha256:
            raise _invalid("snapshot source or binary changed during flag search")
        return result


def decompme_export(config: WorkerConfig, req: DecompmeRequest) -> dict[str, Any]:
    """Upload one function as a decomp.me scratch (``rebrew export decompme --json``).

    ``dry_run`` builds the payload and answers its summary without uploading.
    The worker reaches decomp.me (``REBREW_DECOMPME_API``) itself.
    """
    root = project_root(config, req.project_dir)
    source = _project_file(root, req.source, "source")
    arguments = ["export", "decompme", "--json", *_flag(req.dry_run, "--dry-run")]
    return run_rebrew(
        [*arguments, *_target_options(root, req.sha256), "--", str(source)],
        root,
        COMMAND_TIMEOUT_SECONDS,
    )


def data_list(config: WorkerConfig, req: DataListRequest) -> dict[str, Any]:
    """The target's global data inventory and section summary (``rebrew data list --json``)."""
    from rebrew.config import load_config

    root = project_root(config, req.project_dir)
    if req.files:
        # Same contract as ``report`` and ``coverage_report``: a retained
        # snapshot that names a coverage input must carry the verified one,
        # so a caller cannot list a target under an input the other two ops
        # would refuse.
        if req.coverage_input.version != 1 or not req.coverage_input_digest:
            verified_coverage_inputs_required()
        with retained_target_snapshot(
            config,
            req.files,
            req.rebrew_target,
            req.sha256,
            req.binary_key,
            req.binary_url,
        ) as snapshot:
            load_config(snapshot, target=req.rebrew_target)
            checked_coverage_input(snapshot, req)
            return run_rebrew(
                ["data", "list", "--json", f"--target={req.rebrew_target}"],
                snapshot,
                COMMAND_TIMEOUT_SECONDS,
            )
    return run_rebrew(
        ["data", "list", "--json", *_target_options(root, req.sha256)],
        root,
        COMMAND_TIMEOUT_SECONDS,
    )


def data_set(config: WorkerConfig, req: DataSetRequest) -> dict[str, Any]:
    """Set non-verdict fields of the data row at ``va`` (``rebrew data set --json``).

    Every non-empty field is set at once; ``size`` 0 leaves the size alone.
    """
    root = project_root(config, req.project_dir)
    va = _address(req.va)
    options = [
        f"{option}=0x{va:x}={value}"
        for field_name, option in DATA_FIELD_OPTIONS.items()
        if (value := getattr(req, field_name))
    ]
    if req.size < 0:
        raise _invalid(f"size must not be negative, got {req.size}")
    if req.size:
        options.append(f"--size=0x{va:x}={req.size}")
    if not options:
        raise _invalid("data_set needs at least one field to set")
    arguments = ["data", "set", "--json", *options, *_flag(req.dry_run, "--dry-run")]
    return run_rebrew(
        [*arguments, *_target_options(root, req.sha256)], root, COMMAND_TIMEOUT_SECONDS
    )


def source_rename(config: WorkerConfig, req: RenameRequest) -> dict[str, Any]:
    """Rename a function, global, type or struct member project-wide (``rebrew source rename``).

    ``kind`` is ``function`` (a name, symbol, file, VA or MODULE.0xVA),
    ``data`` (a global), ``type`` (a tag or typedef) or ``field``
    (``STRUCT.MEMBER``).
    """
    selector = RENAME_KINDS.get(req.kind)
    if selector is None:
        raise _invalid(f"kind must be one of {', '.join(RENAME_KINDS)}")
    root = project_root(config, req.project_dir)
    arguments = ["source", "rename", "--json", *selector, *_flag(req.dry_run, "--dry-run")]
    return run_rebrew(
        [*arguments, *_target_options(root, req.sha256), "--", req.old_name, req.new_name],
        root,
        COMMAND_TIMEOUT_SECONDS,
    )


def source_split(config: WorkerConfig, req: SplitRequest) -> dict[str, Any]:
    """Split a multi-function source into one file per function (``rebrew source split``).

    ``va``, when non-zero, extracts that one function instead.
    """
    root = project_root(config, req.project_dir)
    source = _project_file(root, req.source, "source")
    extract = [f"--va=0x{_address(req.va):x}"] if req.va else []
    arguments = ["source", "split", "--json", *extract, *_flag(req.dry_run, "--dry-run")]
    return run_rebrew(
        [*arguments, *_target_options(root, req.sha256), "--", str(source)],
        root,
        COMMAND_TIMEOUT_SECONDS,
    )


def source_merge(config: WorkerConfig, req: MergeRequest) -> dict[str, Any]:
    """Merge single-function sources into ``output``, a new project file (``rebrew source merge``)."""
    if len(req.sources) < 2:
        raise _invalid("sources must name at least two files")
    root = project_root(config, req.project_dir)
    sources = [str(_project_file(root, source, "source")) for source in req.sources]
    output = _inside(root, req.output, "output", "project_dir")
    if output.exists():
        raise _invalid("output must name a file that does not exist yet")
    arguments = ["source", "merge", "--json", f"--output={output}"]
    return run_rebrew(
        [
            *arguments,
            *_flag(req.dry_run, "--dry-run"),
            *_target_options(root, req.sha256),
            "--",
            *sources,
        ],
        root,
        COMMAND_TIMEOUT_SECONDS,
    )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Op:
    """One wire op: its request type and the function that answers it."""

    request: type
    run: Callable[[WorkerConfig, Any], Mapping[str, Any]]


def retained_source_operation(config: WorkerConfig, req: SnapshotMutationRequest) -> dict[str, Any]:
    """Run an operation against an isolated retained target."""
    from rebrew.snapshot_mutations import snapshot_mutation

    return snapshot_mutation(config, req)


def decompile_snapshot(config: WorkerConfig, req: DecompileSnapshotRequest) -> dict[str, Any]:
    """Run the operation over a verified retained snapshot."""
    from rebrew.analysis import is_inside
    from rebrew.decompiler import fetch_decompilation
    from rebrew.formats.binary_loader import load_binary
    from rebrew.name_decomp import apply_known_names
    from rebrew.named_snapshot import retained_snapshot
    from rebrew.sources import iter_library_headers, iter_sources
    from rebrew.struct_recover import existing_structs

    if req.backend not in DECOMPILER_BACKENDS:
        raise _invalid("invalid retained decompilation request")
    va = _address(req.va)
    with retained_snapshot(config, req) as (root, cfg, retained, verify_files):
        if not is_inside(load_binary(cfg.target_binary), va):
            raise _invalid(f"VA 0x{va:x} is outside the binary image")
        sources = [
            *iter_sources(cfg.reversed_dir, cfg),
            *iter_library_headers(cfg.reversed_dir, cfg),
        ]
        if any(path.is_symlink() or path.resolve() not in retained for path in sources):
            raise _invalid("source is not in the retained snapshot")
        definitions = existing_structs(sources)
        verify_files()
        code, backend = fetch_decompilation(req.backend, cfg.target_binary, va, root)
        if not code:
            raise _refused(f"no decompilation via '{req.backend}' for 0x{va:x}")
        verify_files()
        pointer_width = int(getattr(cfg, "pointer_size", 4) or 4)
        code = apply_known_names(code, definitions, pointer_width=pointer_width).code
        verify_files()
    return {
        "code": code,
        "backend": backend,
        "source_revision": req.source_revision,
        "source_snapshot_sha256": req.source_snapshot_sha256,
        "analysis_manifest_sha256": req.analysis_manifest_sha256,
        "generation": req.generation,
    }


def security_scan_snapshot(config: WorkerConfig, req: SecuritySnapshotRequest) -> dict[str, Any]:
    """Run the operation over a verified retained snapshot."""
    from rebrew.named_snapshot import retained_snapshot
    from rebrew.security_scan import SEVERITY_ORDER, filter_by_severity, scan_paths
    from rebrew.sources import EXCLUDE_DIRS, iter_sources

    if req.min_severity not in SEVERITY_ORDER:
        raise _invalid(f"min_severity must be one of {', '.join(SEVERITY_ORDER)}")
    with retained_snapshot(config, req) as (root, cfg, retained, verify_files):
        directory = cfg.reversed_dir.resolve()
        if not directory.is_relative_to(root):
            raise _invalid("security source directory escapes the snapshot")
        expected = {
            path
            for path in retained
            if path.is_relative_to(directory)
            and path.suffix.lower() == ".c"
            and not any(part in EXCLUDE_DIRS for part in path.relative_to(directory).parts[:-1])
        }
        published = {root / entry.path for entry in req.files}
        if not expected.issubset(published):
            raise _invalid("security source is not in the published snapshot")
        paths = iter_sources(directory) if directory.is_dir() else []
        if (
            any(path.is_symlink() or path.resolve() not in retained for path in paths)
            or set(paths) != expected
        ):
            raise _invalid("security sources differ from the retained snapshot")
        verify_files()
        try:
            findings = scan_paths(paths, strict=True)
        except OSError:
            raise _invalid("retained security source is unreadable") from None
        verify_files()
        for finding in findings:
            path = _project_file(root, finding["file"].removeprefix(str(root) + "/"), "source")
            if path not in expected:
                raise _invalid("security finding escapes the retained snapshot")
            finding["file"] = path.relative_to(root).as_posix()
        by_severity = dict.fromkeys(SEVERITY_ORDER, 0)
        for finding in findings:
            by_severity[str(finding["severity"])] += 1
        result = filter_by_severity(
            {
                "root": directory.relative_to(root).as_posix(),
                "files_scanned": len(paths),
                "findings": findings,
                "count": len(findings),
                "by_severity": by_severity,
            },
            req.min_severity,
        )
    return {
        "result": result,
        "source_revision": req.source_revision,
        "source_snapshot_sha256": req.source_snapshot_sha256,
        "generation": req.generation,
        "analysis_manifest_sha256": req.analysis_manifest_sha256,
    }


#: Every op of the backend's rebrew contract, by wire name.
OPS: dict[str, Op] = {
    "rebrew.disassemble": Op(DisassembleRequest, disassemble),
    "rebrew.disassemble_bytes": Op(DisassembleBytesRequest, disassemble_bytes),
    "rebrew.control_flow_graph": Op(AddressRequest, control_flow_graph),
    "rebrew.xrefs": Op(AddressRequest, xrefs),
    "rebrew.call_references": Op(ProjectRequest, call_references),
    "rebrew.describe": Op(AddressRequest, describe),
    "rebrew.decompile": Op(DecompileRequest, decompile),
    "rebrew.decompile_snapshot": Op(DecompileSnapshotRequest, decompile_snapshot),
    "rebrew.identify_library": Op(ProjectRequest, identify_library),
    "rebrew.structs": Op(StructsRequest, structs),
    "rebrew.binary_operand_locations": Op(OperandLocationsRequest, binary_operand_locations),
    "rebrew.binary_function_digests": Op(FunctionDigestsRequest, binary_function_digests),
    "rebrew.imports": Op(BinaryFile, imports),
    "rebrew.strings": Op(BinaryFile, strings),
    "rebrew.fingerprint": Op(BinaryFile, fingerprint),
    "rebrew.analyze": Op(BinaryFile, analyze),
    "rebrew.crypto_scan": Op(BinaryFile, crypto_scan),
    "rebrew.pe_info": Op(BinaryFile, pe_info),
    "rebrew.identify_compiler": Op(BinaryFile, identify_compiler),
    "rebrew.library_functions": Op(StoredFile, library_functions),
    "rebrew.splat_parse": Op(SplatRequest, splat_parse),
    "rebrew.report": Op(ReportRequest, report),
    "rebrew.security_scan": Op(SecurityScanRequest, security_scan),
    "rebrew.security_scan_snapshot": Op(SecuritySnapshotRequest, security_scan_snapshot),
    "rebrew.analyse": Op(AnalyseRequest, analyse),
    "rebrew.import-project": Op(ImportRequest, import_project),
    "rebrew.reference_flirt": Op(ReferenceFlirtRequest, reference_flirt),
    "rebrew.verify_function": Op(VerifyRequest, verify_function),
    "rebrew.apply_candidate": Op(ApplyCandidateRequest, apply_candidate),
    "rebrew.verify_target": Op(VerifyTargetRequest, verify_target),
    "rebrew.build": Op(BuildRequest, build),
    "rebrew.skeleton": Op(SkeletonRequest, skeleton),
    "rebrew.coverage_export": Op(CoverageExportRequest, coverage_export),
    "rebrew.coverage_report": Op(CoverageReportRequest, coverage_report),
    "rebrew.source_variants": Op(SourceVariantsRequest, source_variants),
    "rebrew.flag_search": Op(FlagSearchRequest, flag_search),
    "rebrew.decompme_export": Op(DecompmeRequest, decompme_export),
    "rebrew.data_list": Op(DataListRequest, data_list),
    "rebrew.data_set": Op(DataSetRequest, data_set),
    "rebrew.source_rename": Op(RenameRequest, source_rename),
    "rebrew.source_split": Op(SplitRequest, source_split),
    "rebrew.source_merge": Op(MergeRequest, source_merge),
    "rebrew.retained_source_operation": Op(SnapshotMutationRequest, retained_source_operation),
}


def _answer(config: WorkerConfig, name: str, body: bytes) -> Mapping[str, Any]:
    op = OPS.get(name)
    if op is None:
        raise OpsError(f"unknown op: {_bounded(name)}", code=UNKNOWN_OP, status=404)
    if len(body) > MAX_REQUEST_BYTES:
        detail = f"request exceeds {MAX_REQUEST_BYTES} bytes"
        raise OpsError(detail, code=INVALID_REQUEST, status=413)
    try:
        from rebrew.named_snapshot import unique_json_object

        raw = json.loads(body, object_pairs_hook=unique_json_object)
    except ValueError:
        raise _invalid("request is not JSON") from None
    request: Any = parse_request(op.request, raw)
    try:
        return op.run(config, request)
    except OpsError:
        raise
    except typer.Exit as exc:
        raise _refused(f"rebrew refused {name} (exit {exc.exit_code})") from None
    except UnsupportedBinaryFormat as exc:
        raise OpsError(str(exc), code=UNSUPPORTED_BINARY_FORMAT, status=422) from None
    except Exception:  # the engine is a trust boundary: log the cause, answer a fixed detail
        logger.exception("%s %s failed trace_id=%s", _request_id(), name, _trace_id())
        raise _refused(f"{name} failed; the worker log has the cause") from None


def dispatch(config: WorkerConfig, name: str, body: bytes) -> tuple[int, bytes]:
    """Answer one call: ``(200, reply)`` or ``(status, refusal)``."""
    try:
        reply = json.dumps(_answer(config, name, body), allow_nan=False).encode("utf-8")
    except OpsError as exc:
        # A 5xx refusal is a server failure with no exception attached (a
        # download timing out, a child command dying): without one line the
        # operator holding the refusal has only the fixed detail to go on.
        # 4xx refusals are the caller's diagnosis, already in the wire body.
        if exc.status >= 500:
            logger.exception(
                "%s %s refused (%d) trace_id=%s", _request_id(), name, exc.status, _trace_id()
            )
        return exc.status, error_body(exc.code, str(exc), exc.status)
    except TypeError, ValueError:
        logger.exception(
            "%s %s produced a reply that is not JSON trace_id=%s", _request_id(), name, _trace_id()
        )
        return 500, error_body(ENGINE_ERROR, f"{name} produced a reply that is not JSON", 500)
    if len(reply) > MAX_REPLY_BYTES:
        logger.error(
            "%s %s produced a reply over %d bytes trace_id=%s",
            _request_id(),
            name,
            MAX_REPLY_BYTES,
            _trace_id(),
        )
        return 500, error_body(ENGINE_ERROR, f"reply exceeds {MAX_REPLY_BYTES} bytes", 500)
    return 200, reply


# ---------------------------------------------------------------------------
# HTTP transport
# ---------------------------------------------------------------------------


_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
)
_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"


def _allowed_hosts_for(host: str, port: int) -> frozenset[str]:
    """Host-header values the ops server must answer (DNS-rebinding guard).

    Mirrors the dashboard's allow-list: loopback binds accept their numeric
    and localhost aliases; a wildcard bind also accepts the machine's own
    addresses. Anything else gets 403 before the bearer check.
    """
    wildcard = host in ("0.0.0.0", "::", "")
    loopback = wildcard or host in ("127.0.0.1", "localhost", "::1")
    names = {host} if host else set()
    if loopback:
        names |= {"127.0.0.1", "localhost", "::1"}
    if wildcard:
        # getaddrinfo blocks with no timeout: a hung resolver would pin server
        # startup for the kernel timeout, so resolve on a thread and fall back
        # to loopback aliases (see DNS_TIMEOUT_SECONDS).
        _result: list[Any] = []
        _error: list[BaseException] = []

        def _resolve() -> None:
            try:
                import socket as _socket

                _result.append(_socket.getaddrinfo(_socket.gethostname(), None))
            except BaseException as exc:
                _error.append(exc)

        _thread = threading.Thread(target=_resolve, daemon=True)
        _thread.start()
        _thread.join(DNS_TIMEOUT_SECONDS)
        if _thread.is_alive():
            logger.warning(
                "ops: local interface resolution timed out after %ss; "
                "host allow-list falls back to loopback aliases",
                DNS_TIMEOUT_SECONDS,
            )
        elif _error:
            logger.warning(
                "ops: local interface resolution failed (%s); "
                "host allow-list falls back to loopback aliases",
                _error[0],
            )
        else:
            names |= {str(info[4][0]) for info in _result[0] if info[4]}
    hosts: set[str] = set()
    for name in names:
        display = f"[{name}]" if ":" in name else name
        hosts.add(fold_host(f"{display}:{port}"))
        if port == 80:
            hosts.add(fold_host(display))
    return frozenset(hosts)


class OpsServer(ThreadingHTTPServer):
    """HTTP server answering ``POST /<op>`` for one worker configuration and token.

    At most *concurrency* calls hold a slot at once, from reading the body
    to writing the reply; a call finding none free is answered 503.

    Carries request metrics (see :meth:`record_request` and
    :meth:`metrics_snapshot`) behind ``/health`` and ``/metrics`` on the
    same port: counters plus latency, so an operator can pivot from a
    metric anomaly to the access lines that name the op and its id.
    """

    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        config: WorkerConfig,
        token: str,
        concurrency: int,
        allowed_hosts: frozenset[str] = frozenset(),
    ) -> None:
        super().__init__(address, _OpsHandler)
        self.config = config
        self.token = token
        self.slots = threading.BoundedSemaphore(concurrency)
        self.active = 0
        self.draining = False
        self.idle = threading.Condition()
        self.allowed_hosts = _allowed_hosts_for(address[0], self.server_address[1]) | allowed_hosts
        self._metrics_lock = threading.Lock()
        self._request_count = 0
        self._error_count = 0
        self._server_error_count = 0
        self._client_error_count = 0
        self._latency_ms_total = 0.0
        self._latency_ms_max = 0.0
        self._latency_ms_buckets = [0] * len(_LATENCY_BUCKETS_MS)
        self._started_at = time.monotonic()
        self._busy_refusals = 0
        # Faults that escaped a handler thread.  ``record_request`` never sees
        # them (``send_response`` did not run), so without this counter a
        # handler that crashes on every call leaves /health and /metrics at
        # zero errors while the process dumps tracebacks.
        self._unhandled_errors = 0
        self.concurrency = concurrency
        # Per-op breakdown, bounded by the op set: one entry per known op
        # plus "/unknown" for paths outside it.  Without it a metric anomaly
        # cannot say which op is slow or failing; the access line names the
        # op but no counter does.
        self._per_op: dict[str, dict[str, float]] = {}

    def record_request(self, code: int, elapsed_ms: float, op: str = "/unknown") -> None:
        with self._metrics_lock:
            self._request_count += 1
            entry = self._per_op.setdefault(
                op, {"count": 0.0, "server_errors": 0.0, "client_errors": 0.0, "latency_ms": 0.0}
            )
            entry["count"] += 1
            entry["latency_ms"] += elapsed_ms
            if code >= 500:
                entry["server_errors"] += 1
            elif code >= 400:
                entry["client_errors"] += 1
            self._latency_ms_total += elapsed_ms
            self._latency_ms_max = max(self._latency_ms_max, elapsed_ms)
            for index, bound in enumerate(_LATENCY_BUCKETS_MS):
                if elapsed_ms <= bound:
                    self._latency_ms_buckets[index] += 1
                    break
            else:
                self._latency_ms_buckets[-1] += 1
            if code >= 500:
                self._server_error_count += 1
                self._error_count += 1
            elif code >= 400:
                self._client_error_count += 1
                self._error_count += 1

    def record_unhandled(self) -> None:
        """Count a handler fault that escaped before a response was written."""
        with self._metrics_lock:
            self._unhandled_errors += 1

    @override
    def handle_error(self, request: Any, client_address: Any) -> None:
        """Log a handler fault with its request id instead of a bare traceback.

        ``socketserver.BaseServer.handle_error`` prints a rule-bracketed
        traceback straight to stderr: no stamp, no level, no correlation id,
        and no counter, so an operator cannot join it to the request that
        raised it and ``/health`` keeps reporting zero errors.  Mirrors the
        dashboard: a peer that went away is INFO with no count, a handler
        timeout is a WARNING with no count, and anything else is an ERROR
        with its traceback that counts as an unhandled fault.
        """
        exc = sys.exc_info()[1]
        request_id = _request_id()
        peer = _escape_log_text(str(client_address))
        if isinstance(exc, ConnectionError):
            logger.info(
                "%s client disconnected trace_id=%s: %s",
                request_id,
                _trace_id(),
                type(exc).__name__,
            )
            return
        if isinstance(exc, TimeoutError):
            logger.warning(
                "%s handler timed out serving %s trace_id=%s: %s",
                request_id,
                peer,
                _trace_id(),
                type(exc).__name__,
            )
            return
        self.record_unhandled()
        logger.error(
            "%s unhandled %s serving %s trace_id=%s\n%s",
            request_id,
            type(exc).__name__,
            peer,
            _trace_id(),
            _escape_log_text(traceback.format_exc().rstrip()),
        )

    def metrics_snapshot(
        self,
    ) -> tuple[dict[str, float | int], list[int], dict[str, dict[str, float]]]:
        with self._metrics_lock:
            return (
                {
                    "request_count": self._request_count,
                    "error_count": self._error_count,
                    "server_error_count": self._server_error_count,
                    "client_error_count": self._client_error_count,
                    "latency_ms_total": self._latency_ms_total,
                    "latency_ms_max": self._latency_ms_max,
                    "latency_ms_avg": (self._latency_ms_total / self._request_count)
                    if self._request_count
                    else 0.0,
                    "in_flight": self.active,
                    "busy_refusals": self._busy_refusals,
                    "unhandled_errors": self._unhandled_errors,
                    "uptime_seconds": time.monotonic() - self._started_at,
                },
                list(self._latency_ms_buckets),
                {op: dict(entry) for op, entry in self._per_op.items()},
            )


class _OpsHandler(BaseHTTPRequestHandler):
    timeout: typing.ClassVar[float | None] = SOCKET_TIMEOUT_SECONDS
    #: Correlation id of the request in flight; stamped per request in
    #: ``handle_one_request`` so a keep-alive connection never reuses one.
    _request_id: str = "-"
    #: Wall-clock start of the request in flight, for the access line.
    _request_started: float = 0.0

    @override
    def handle_one_request(self) -> None:  # (http.server API)
        self._request_started = time.perf_counter()
        self._request_id = f"r{next(_REQUEST_IDS)}"
        _stamp_request(self._request_id)
        super().handle_one_request()

    @override
    def log_request(
        self, code: int | str = "-", size: int | str = "-"
    ) -> None:  # (http.server API)
        """One INFO access line per answered request: id, op, status, and time.

        ``send_response`` calls this, so every refusal and reply logs exactly
        once.  The op comes from the request path (remote text, escaped);
        the elapsed time is the one number that says the engine, not the
        network, is what a slow call spent its time on.
        """
        elapsed_ms = (time.perf_counter() - self._request_started) * 1000.0
        op = (
            _escape_log_text(urlsplit(getattr(self, "path", "") or "").path.removeprefix("/"))
            or "-"
        )
        logger.info(
            "%s %s %s %s %.1fms trace_id=%s",
            self._request_id,
            op,
            code,
            size,
            elapsed_ms,
            _trace_id(),
        )

    @override
    def log_message(self, fmt: str, *args: Any) -> None:  # (http.server API)
        """Drop the stdlib's default access line: ``log_request`` already logs it.

        ``BaseHTTPRequestHandler.log_request`` delegates here, so without
        this the request would appear twice — once on the console in the
        stdlib format, once as the correlated ``logger`` record above.
        """

    @override
    def send_response(self, code: int, message: str | None = None) -> None:
        # No Server banner: BaseHTTPRequestHandler would emit the Python
        # patch level to any caller that can reach the worker.
        elapsed_ms = (time.perf_counter() - self._request_started) * 1000.0
        with contextlib.suppress(AttributeError):
            raw_path = urlsplit(getattr(self, "path", "") or "").path
            op_name = raw_path.removeprefix("/")
            route = f"/{op_name}" if op_name in OPS else "/unknown"
            typing.cast("OpsServer", self.server).record_request(code, elapsed_ms, route)
        self.log_request(code, getattr(self, "_response_size", "-"))
        opened = telemetry.current()
        if opened is not None and opened.kind == telemetry.KIND_SERVER:
            opened.set("http.response.status_code", int(code))
            if code >= 500:
                opened.fail(f"status {code}")
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())
        self.send_header("X-Request-Id", self._request_id)

    @override
    def send_error(  # (http.server API)
        self, code: int, message: str | None = None, explain: str | None = None
    ) -> None:
        # http.server's own errors (400/414/431/505) must not leak the
        # stdlib HTML page or the request line; answer with the JSON envelope.
        # 501 means a method with no do_* handler (e.g. TRACE): route it
        # through _not_post so a known op answers 405 with Allow and an
        # unknown path 404, matching the GET/HEAD path instead of a 501
        # that no client of an ops endpoint can act on.
        if code == 501 and self.command:  # NOT_IMPLEMENTED
            self._not_post()
            return
        logger.log(
            logging.ERROR if code >= 500 else logging.WARNING,
            "%s rejected %s: code %d trace_id=%s",
            self._request_id,
            _escape_log_text(getattr(self, "requestline", "") or "-"),
            code,
            _trace_id(),
        )
        status = int(code)
        body = error_body(INVALID_REQUEST, "invalid request", status)
        self._response_size = len(body)
        self.send_response(status)
        self.send_header("Connection", "close")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for _name, _value in _SECURITY_HEADERS:
            self.send_header(_name, _value)
        self.send_header("Content-Security-Policy", _CSP)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send(
        self,
        status: int,
        body: bytes,
        headers: Mapping[str, str] | None = None,
        *,
        content_type: str = "application/json",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in _SECURITY_HEADERS:
            self.send_header(name, value)
        self.send_header("Content-Security-Policy", _CSP)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _refuse(self, code: str, detail: str, status: int) -> None:
        headers = {"WWW-Authenticate": 'Bearer realm="rebrew-ops"'} if status == 401 else None
        self._send(status, error_body(code, detail, status), headers)

    def _check_host(self, server: OpsServer) -> bool:
        if fold_host(self.headers.get("Host", "").strip()) in server.allowed_hosts:
            return True
        peer = getattr(self, "client_address", None)
        logger.warning(
            "%s rejected request with Host %r from %s trace_id=%s",
            self._request_id,
            _escape_log_text(self.headers.get("Host", "")) or "-",
            _escape_log_text(str(peer[0]) if peer else "-"),
            _trace_id(),
        )
        self._refuse(
            "host-not-allowed", "request Host not allowed (wrong or missing Host header)", 403
        )
        return False

    def do_POST(self) -> None:  # (http.server API)
        name = urlsplit(self.path).path.removeprefix("/")
        route = f"/{name}" if name in OPS else "/unknown"  # the route is bounded by the op set
        with telemetry.span(
            f"POST {route}",
            kind=telemetry.KIND_SERVER,
            traceparent=self.headers.get("traceparent"),
        ) as opened:
            opened.set("http.request.method", "POST")
            opened.set("http.route", route)
            opened.set("rebrew.request_id", self._request_id)
            self._post()

    def _post(self) -> None:
        server = typing.cast("OpsServer", self.server)
        if not self._check_host(server):
            return
        # CSRF defense-in-depth: a browser sending a POST carries
        # Origin/Referer; a non-browser client (httpx, curl) does not. The
        # bearer check below is the real auth, but refusing a browser-origin
        # POST outright means a malicious page cannot probe the token with a
        # cross-origin form even if the token were somehow ambient.
        if self._cross_origin_browser_post():
            logger.warning("%s rejected cross-origin browser POST", self._request_id)
            self._refuse("cross-origin", "cross-origin browser POST is not allowed", 403)
            return
        # /health and /metrics are GET/HEAD on this server: a POST is a
        # wrong method for a served resource (405), not an unknown op (404).
        # Other paths fall through to dispatch, which answers 404 for a name
        # outside OPS.
        if urlsplit(self.path).path in ("/health", "/metrics"):
            self._send(
                405,
                error_body(
                    "method-not-allowed", "health and metrics are served with GET, HEAD", 405
                ),
                {"Allow": "GET, HEAD"},
            )
            return
        given = self.headers.get("Authorization", "").encode("utf-8")
        if not hmac.compare_digest(given, f"Bearer {server.token}".encode()):
            logger.warning(
                "%s rejected unauthenticated request trace_id=%s",
                self._request_id,
                _trace_id(),
            )
            self._refuse("unauthorized", "a valid bearer token is required", 401)
            return
        with server.idle:
            admitted = not server.draining and server.slots.acquire(blocking=False)
            if admitted:
                server.active += 1
        if not admitted:
            with server._metrics_lock:
                server._busy_refusals += 1
            logger.warning(
                "%s worker busy; returning 503 trace_id=%s", self._request_id, _trace_id()
            )
            body = error_body(WORKER_BUSY, "every worker slot is busy; retry later", 503)
            self._send(503, body, {"Retry-After": str(BUSY_RETRY_AFTER_SECONDS)})
            return
        try:
            self._answer(server)
        finally:
            with server.idle:
                server.active -= 1
                server.slots.release()
                server.idle.notify_all()

    def _cross_origin_browser_post(self) -> bool:
        """True when the request carries a browser Origin/Referer header.

        Browsers always send Origin on cross-origin POSTs and Referer on
        same-origin ones; a non-browser HTTP client sends neither.  Refusing
        the browser case costs nothing for legitimate callers (ops clients are
        httpx) and stops a malicious page from reaching the bearer check.
        """
        origin = self.headers.get("Origin")
        if origin is not None:
            # Any Origin value means a browser cross-origin (or same-origin
            # fetch) POST; server-to-server clients do not send it.
            return bool(origin.strip())
        referer = self.headers.get("Referer")
        return referer is not None and bool(referer.strip())

    def _answer(self, server: OpsServer) -> None:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        # CSRF defense-in-depth happens in _post before auth; this guard keeps
        # _answer safe if a future caller reaches it without _post's check.
        if self.headers.get("Origin") is not None or self.headers.get("Referer") is not None:
            self._refuse("cross-origin", "cross-origin browser POST is not allowed", 403)
            return
        if content_type != "application/json":
            self._refuse(INVALID_REQUEST, "Content-Type must be application/json", 415)
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._refuse(INVALID_REQUEST, "Content-Length is required", 411)
            return
        if not 0 <= length <= MAX_REQUEST_BYTES:
            self._refuse(INVALID_REQUEST, f"request exceeds {MAX_REQUEST_BYTES} bytes", 413)
            return
        # Read in chunks under the same bound so a stalled or truncated
        # stream cannot leave a half-read buffer queued behind the socket
        # timeout: each chunk is a fresh read, and the total never exceeds
        # the declared length that was already validated above.
        chunks: list[bytes] = []
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                self._refuse(INVALID_REQUEST, "request body truncated", 400)
                return
            chunks.append(chunk)
            remaining -= len(chunk)
        body = b"".join(chunks)
        self._send(*dispatch(server.config, urlsplit(self.path).path.removeprefix("/"), body))

    def _not_post(self) -> None:
        server = typing.cast("OpsServer", self.server)
        if not self._check_host(server):
            return
        path = urlsplit(self.path).path
        if path in ("/health", "/metrics") and self.command in ("GET", "HEAD"):
            if not hmac.compare_digest(
                self.headers.get("Authorization", "").encode("utf-8"),
                f"Bearer {server.token}".encode(),
            ):
                self._refuse("unauthorized", "a valid bearer token is required", 401)
                return
            snapshot, latency_buckets, per_op = server.metrics_snapshot()
            if path == "/health":
                payload = {
                    "status": "up",
                    "requests": snapshot["request_count"],
                    "errors": snapshot["error_count"],
                    "server_errors": snapshot["server_error_count"],
                    "client_errors": snapshot["client_error_count"],
                    "latency_ms_avg": round(snapshot["latency_ms_avg"], 3),
                    "latency_ms_max": round(snapshot["latency_ms_max"], 3),
                    "uptime_seconds": round(snapshot["uptime_seconds"], 3),
                    "concurrency": server.concurrency,
                    "busy_refusals": snapshot.get("busy_refusals", 0),
                    "unhandled_errors": snapshot.get("unhandled_errors", 0),
                    "trace_spans_dropped": telemetry.export_stats()["dropped"],
                    "trace_spans_failed": telemetry.export_stats()["failed"],
                }
                body = json.dumps(payload).encode("utf-8")
                self._send(200, body)
                return
            lines = [
                "# HELP rebrew_ops_requests_total Total ops requests answered.",
                "# TYPE rebrew_ops_requests_total counter",
                f"rebrew_ops_requests_total {snapshot['request_count']}",
                "# HELP rebrew_ops_errors_total Total ops requests answered with an error status.",
                "# TYPE rebrew_ops_errors_total counter",
                f"rebrew_ops_errors_total {snapshot['error_count']}",
                "# HELP rebrew_ops_server_errors_total Total ops requests answered with a 5xx status.",
                "# TYPE rebrew_ops_server_errors_total counter",
                f"rebrew_ops_server_errors_total {snapshot['server_error_count']}",
                "# HELP rebrew_ops_client_errors_total Total ops requests answered with a 4xx status.",
                "# TYPE rebrew_ops_client_errors_total counter",
                f"rebrew_ops_client_errors_total {snapshot['client_error_count']}",
                "# HELP rebrew_ops_latency_ms_total Total latency of answered ops requests, in milliseconds.",
                "# TYPE rebrew_ops_latency_ms_total counter",
                f"rebrew_ops_latency_ms_total {snapshot['latency_ms_total']:.3f}",
                "# HELP rebrew_ops_latency_ms_max Maximum latency of an answered ops request, in milliseconds.",
                "# TYPE rebrew_ops_latency_ms_max gauge",
                f"rebrew_ops_latency_ms_max {snapshot['latency_ms_max']:.3f}",
                "# HELP rebrew_ops_uptime_seconds Seconds since the server started.",
                "# TYPE rebrew_ops_uptime_seconds gauge",
                f"rebrew_ops_uptime_seconds {snapshot['uptime_seconds']:.3f}",
                "# HELP rebrew_ops_concurrency Configured number of calls answered at once.",
                "# TYPE rebrew_ops_concurrency gauge",
                f"rebrew_ops_concurrency {server.concurrency}",
                "# HELP rebrew_ops_in_flight Calls currently holding a worker slot.",
                "# TYPE rebrew_ops_in_flight gauge",
                f"rebrew_ops_in_flight {snapshot['in_flight']}",
                "# HELP rebrew_ops_busy_refusals_total Calls refused with 503 because no worker slot was free.",
                "# TYPE rebrew_ops_busy_refusals_total counter",
                f"rebrew_ops_busy_refusals_total {snapshot.get('busy_refusals', 0)}",
                "# HELP rebrew_ops_unhandled_errors_total Handler faults that escaped before a response was written.",
                "# TYPE rebrew_ops_unhandled_errors_total counter",
                f"rebrew_ops_unhandled_errors_total {snapshot.get('unhandled_errors', 0)}",
                "# HELP rebrew_ops_trace_spans_dropped_total Finished spans dropped because the export queue was full.",
                "# TYPE rebrew_ops_trace_spans_dropped_total counter",
                f"rebrew_ops_trace_spans_dropped_total {telemetry.export_stats()['dropped']}",
                "# HELP rebrew_ops_trace_spans_failed_total Finished spans lost to a failed export POST.",
                "# TYPE rebrew_ops_trace_spans_failed_total counter",
                f"rebrew_ops_trace_spans_failed_total {telemetry.export_stats()['failed']}",
                "# HELP rebrew_ops_latency Latency of answered ops requests, in milliseconds.",
                "# TYPE rebrew_ops_latency histogram",
                # The last bound is infinity, written +Inf as the exposition format spells it: one +Inf bucket.
                *(
                    f'rebrew_ops_latency_bucket{{le="{"+Inf" if bound == float("inf") else bound}"}} '
                    f"{sum(latency_buckets[: i + 1])}"
                    for i, bound in enumerate(_LATENCY_BUCKETS_MS)
                ),
                f"rebrew_ops_latency_count {snapshot['request_count']}",
                f"rebrew_ops_latency_sum {snapshot['latency_ms_total']:.3f}",
                "# HELP rebrew_ops_per_op_requests_total Requests per op (bounded by the op set).",
                "# TYPE rebrew_ops_per_op_requests_total counter",
                *(
                    f'rebrew_ops_per_op_requests_total{{op="{op}"}} {int(entry["count"])}'
                    for op, entry in sorted(per_op.items())
                ),
                "# HELP rebrew_ops_per_op_server_errors_total 5xx responses per op.",
                "# TYPE rebrew_ops_per_op_server_errors_total counter",
                *(
                    f'rebrew_ops_per_op_server_errors_total{{op="{op}"}} {int(entry["server_errors"])}'
                    for op, entry in sorted(per_op.items())
                ),
                "# HELP rebrew_ops_per_op_client_errors_total 4xx responses per op.",
                "# TYPE rebrew_ops_per_op_client_errors_total counter",
                *(
                    f'rebrew_ops_per_op_client_errors_total{{op="{op}"}} {int(entry["client_errors"])}'
                    for op, entry in sorted(per_op.items())
                ),
                "# HELP rebrew_ops_per_op_latency_ms_total Total latency per op, in milliseconds.",
                "# TYPE rebrew_ops_per_op_latency_ms_total counter",
                *(
                    f'rebrew_ops_per_op_latency_ms_total{{op="{op}"}} {entry["latency_ms"]:.3f}'
                    for op, entry in sorted(per_op.items())
                ),
            ]
            body = ("\n".join(lines) + "\n").encode("utf-8")
            self._send(
                200,
                body,
                content_type="text/plain; version=0.0.4; charset=utf-8",
            )
            return
        # 404 before 405, like the dashboard: a path that names no op has no
        # resource to list methods for.  POST on the same unknown name
        # already answers 404 unknown-op, so a non-POST must too.  The
        # /health and /metrics branches above already answered a non-GET/HEAD
        # on those served resources, so a POST there never reaches here, and
        # any other non-POST here is 405 only for a known op.
        if path in ("/health", "/metrics"):
            self._send(
                405,
                error_body(
                    "method-not-allowed", "health and metrics are served with GET, HEAD", 405
                ),
                {"Allow": "GET, HEAD"},
            )
            return
        name = path.removeprefix("/")
        if name not in OPS:
            self._refuse(UNKNOWN_OP, f"unknown op: {_bounded(name)}", 404)
            return
        self._send(
            405,
            error_body("method-not-allowed", "ops are called with POST", 405),
            {"Allow": "POST"},
        )

    do_GET = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _not_post


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

_FILESTORE_HELP = "The backend's local filestore directory; request file keys resolve under it"
_WORKSPACE_HELP = (
    "Directory for analysis projects, report output_dir and url downloads;"
    " project paths must lie inside"
)
_MAX_DOWNLOAD_HELP = "Largest binary in bytes a request url may name"


@app.command(
    "call",
    epilog="[bold]Examples:[/bold]\n\n"
    "  rebrew ops call rebrew.pe_info --filestore /srv/files · request on stdin",
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
        _existing_dir(filestore, "--filestore"),
        _existing_dir(workspace, "--workspace"),
        max_download_bytes,
    )
    body = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    # read(MAX+1) lets dispatch answer over-limit input with 413; truncating
    # here would turn it into a 400 "not JSON" for the same client mistake
    # the HTTP transport answers 413.
    # stdout carries only the reply; anything rebrew prints goes to stderr.
    with contextlib.redirect_stdout(sys.stderr):
        status, reply = dispatch(config, op, body)
    sys.stdout.buffer.write(reply + b"\n")
    sys.stdout.flush()
    if status != 200:
        raise typer.Exit(EXIT_ERROR)


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
        _existing_dir(filestore, "--filestore"),
        _existing_dir(workspace, "--workspace"),
        max_download_bytes,
    )
    hosts = frozenset(fold_host(item.strip()) for item in allowed_hosts.split(",") if item.strip())
    if any(not re.fullmatch(r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?", item) for item in hosts):
        error_exit("--allowed-hosts must contain exact DNS names and optional ports")
    server = OpsServer((host, port), config, token, concurrency, hosts)
    try:
        stop_telemetry = telemetry.configure_from_env("relumea-rebrew", __version__)
    except ValueError as exc:
        error_exit(str(exc))
    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            f"serving rebrew ops on http://{host}:{server.server_port} (non-loopback bind: bearer auth required)"
        )
    console.print(f"serving rebrew ops on http://{host}:{server.server_port}")

    def stop(_signum: int, _frame: Any) -> None:
        with server.idle:
            if server.draining:
                return
            server.draining = True
        threading.Thread(target=server.shutdown, daemon=True).start()

    # SIGTERM is never delivered on Windows; Ctrl+C raises KeyboardInterrupt
    # instead, which serve_forever propagates as the shutdown path. Mirror
    # climb.py's getattr guard so a platform without SIGTERM does not raise
    # AttributeError on startup.
    sigterm = getattr(signal, "SIGTERM", None)
    previous = signal.signal(sigterm, stop) if sigterm is not None else None
    restore_log = _attach_server_log_handler()
    try:
        server.serve_forever()
    finally:
        server.server_close()
        with server.idle:
            server.draining = True
            server.idle.wait_for(lambda: server.active == 0, timeout=30)
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
