"""Core worker primitives, limits, refusals, request validation, and logging correlation."""

from __future__ import annotations

import contextlib
import logging
import threading
from contextvars import ContextVar
from dataclasses import dataclass, fields
from pathlib import Path
from typing import override
lazy import dataclasses
lazy import itertools
lazy import math
lazy import os
lazy import re
lazy import sys
lazy import time
lazy import types
lazy import typing
lazy from collections.abc import Callable, Iterable, Iterator, Mapping
lazy from typing import Any

lazy import msgspec

from rebrew.errors import RebrewError
from rebrew.metadata.bindings import BindingConflictError
from rebrew.ops.requests import (
    AnalyseRequest,
    CoverageReportRequest,
    DataListRequest,
    ReportRequest,
)
lazy from rebrew import telemetry
lazy from rebrew.cli import console, error_exit
lazy from rebrew.metadata.bindings import DATA_KINDS
lazy from rebrew.utils import sha256_file


def ops_binding(name: str, default: Any) -> Any:
    """Resolve *name* from ``rebrew.ops`` when loaded so monkeypatches take effect."""
    ops_mod = sys.modules.get("rebrew.ops")
    return getattr(ops_mod, name, default) if ops_mod is not None else default


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
REQUEST_IDS = itertools.count(1)
#: The request in flight on this thread, for the logger records a library
#: warning raises inside the request path (see ``dashboard.stamp_request``).
REQUEST_LOCAL = threading.local()

#: Control characters escaped in request-derived log text, plus backslash.
_LOG_CONTROL_CHARS = {code: f"\\x{code:02x}" for code in (*range(0x20), *range(0x7F, 0xA0))}
_LOG_CONTROL_CHARS[ord("\\")] = "\\\\"


def escape_log_text(text: str) -> str:
    """One-line, terminal-safe form of request-derived text for the log stream.

    Strips bidi-format characters and escapes control characters, exactly as
    the dashboard's access log does: a path or Host carrying a newline or
    bidi override must not forge a second log line or reorder the first.
    """
    from rebrew.utils import strip_bidi_format

    return strip_bidi_format(text).translate(_LOG_CONTROL_CHARS)


def stamp_request(request_id: str) -> None:
    """Record the correlation id of the request in flight on this thread."""
    REQUEST_LOCAL.request_id = request_id


def request_id() -> str:
    """The stamped correlation id, or ``"-"`` off the HTTP transport."""
    return getattr(REQUEST_LOCAL, "request_id", "-")


def trace_id() -> str:
    """Trace id of the open span, so logs join the MELT investigative path."""
    opened = telemetry.current()
    return opened.trace_id if opened is not None else "-"


class CorrelatedFormatter(logging.Formatter):
    """Stamp library records raised inside a request with its id and trace id.

    Mirrors the dashboard's formatter: a warning from engine code running
    inside an ops request names no request on its own, so the formatter
    supplies the stamped id and the open span's trace id, and escapes the
    rendered line so request-derived text cannot forge a second line.
    """

    @override
    def format(self, record: logging.LogRecord) -> str:
        req_id = request_id()
        line = escape_log_text(super().format(record))
        if req_id == "-":
            return line
        tr_id = trace_id()
        return f"{req_id} {tr_id} {line}" if tr_id != "-" else f"{req_id} {line}"


def attach_server_log_handler() -> Callable[[], None]:
    """Send this module's and the package's records to the console in one format.

    Without a handler, records fall back to ``lastResort`` or to the root
    handler ``configure_logging`` installed, in a different format with no
    request id, so library warnings raised inside a request cannot be
    pivoted to by id.  Mirrors the dashboard: the ops logger gets an INFO
    handler on the console, the package logger gets the correlated
    formatter, both stamped in UTC with a level column.  Returns a
    disposer restoring both loggers.
    """
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
    package_formatter = CorrelatedFormatter(
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
#: search flags or mutations: ``verify_target``, ``build``, ``flag_search`` and
#: the retained variant search.
SEARCH_TIMEOUT_SECONDS = 3600

#: Caps on a retained variant search's ``generations`` and ``population``,
#: sized to its op's SEARCH_TIMEOUT_SECONDS deadline: the search compiles at
#: most 100 * 100 candidates, about 1,460 s at the measured 585 ms per compile
#: and compare (docs/PERFORMANCE.md) over the GA's default 4 parallel jobs.
VARIANT_MAX_GENERATIONS = 100
VARIANT_MAX_POPULATION = 100

#: Deadline of ``analyse``: its two intakes, the project's and the fresh capture's.
ANALYSE_TIMEOUT_SECONDS = 2 * INTAKE_TIMEOUT_SECONDS

#: Deadline of ``import_archive``, which runs in the worker and checks it
#: between steps.  The import of guild-rebrew's server project took 22-23 s
#: (CHANGELOG 6.40.0).
IMPORT_TIMEOUT_SECONDS = 600

#: Seconds a caller waits for an op the worker runs in process to its end;
#: nothing stops it at this bound.  It covers one decompilation: rizin's 300 s
#: analysis and its 120 s decompile command (``rebrew.decompiler``).
IN_PROCESS_TIMEOUT_SECONDS = 600

#: The ops whose project reads skip a function record whose source's anchor names another
#: function, and whose reply then names them in ``skipped_records``: each reads the
#: project's source bindings, in process or in the command it runs.
SKIPPED_RECORD_OPS = frozenset(
    {
        "rebrew.analyse",
        "rebrew.data_list",
        "rebrew.identify_library",
        "rebrew.coverage_report",
        "rebrew.report",
        "rebrew.describe",
        "rebrew.structs",
        "rebrew.import-project",
        "rebrew.import_archive",
        "rebrew.verify_function",
        "rebrew.build",
        "rebrew.apply_candidate",
        "rebrew.flag_search",
        "rebrew.retained_source_operation",
    }
)

#: Keys a reply's ``skipped_records`` lists; past it ``count`` stays exact and ``truncated`` is set.
MAX_SKIPPED_RECORD_KEYS = 256

#: SHA-256 of the dispatch schema this engine serves
#: (``tests/fixtures/dispatch/rebrew.schema.json``), answered by ``rebrew.release``;
#: a test holds it to the file, so a schema change updates it in the same commit.
DISPATCH_SCHEMA_SHA256 = "d14a7f3688a4234dc0d313f5e91c629a6ab2c8ffd4f875221552d603b3e41858"

#: Default of ``--concurrency``: calls ``serve`` runs at once.
DEFAULT_CONCURRENCY = 4

#: Accepted HTTP connections allowed to hold a handler thread at once. The call
#: semaphore bounds engine work, but without a separate admission cap idle or
#: partial requests could still create one thread and descriptor per connection.
MAX_CONNECTIONS = 64

#: ``Retry-After`` seconds of the 503 ``serve`` answers when every slot is busy.
BUSY_RETRY_AFTER_SECONDS = 5

#: Request header naming the seconds the caller waits for the call; ``serve``
#: cancels the call once they pass.
TIMEOUT_HEADER = "X-Rebrew-Timeout"

#: Seconds of its deadline a child command keeps to finish and print its
#: report: the call deadline it gets in ``REBREW_CALL_DEADLINE``
#: (``rebrew.compiler.compile.CALL_DEADLINE_ENV``) ends this long before the
#: worker stops it, so its remote compiles stop retrying in time.
CHILD_REPORT_SECONDS = 30

#: Seconds between checks for a running call's caller having given up, and
#: for its child command's call being cancelled or past its deadline.
CANCEL_POLL_SECONDS = 0.5

#: Media type of a progress stream: one JSON object per line, each
#: ``{"progress": {"done": N, "total": M}}`` the call's child command counted,
#: then ``{"status": S, "reply": R}`` (with ``retry_after`` when the refusal
#: names one) last.  ``serve`` answers with it a caller whose ``Accept`` names it,
#: once the call has a count to report.
PROGRESS_MEDIA_TYPE = "application/x-ndjson"

#: Names the file descriptor ``ops call`` writes the progress lines of its call
#: to, ``{"progress": {"done": N, "total": M}}`` each (the backend's exec transport).
DISPATCH_PROGRESS_FD_ENV = "RELUMEA_DISPATCH_PROGRESS_FD"

#: Default of ``--max-download``: the largest binary a ``url`` may name.
#: It matches the backend's default upload cap (``max_upload_bytes``).
DEFAULT_MAX_DOWNLOAD_BYTES = 256 << 20

#: Seconds a ``url`` download may stall connecting or between reads.
DOWNLOAD_TIMEOUT_SECONDS = 60

#: Seconds a DNS resolution for a ``url`` host may stall.  ``getaddrinfo``
#: has no timeout of its own, so without this a hung resolver pins a
#: worker slot for the kernel timeout and later requests queue behind it.
DNS_TIMEOUT_SECONDS = 10

#: Resolver threads that may remain blocked after their request timed out.
#: Python cannot cancel ``getaddrinfo``; the cap keeps repeated hung lookups
#: from retaining one daemon thread per URL request.
DNS_RESOLUTION_LIMIT = 32
DNS_SLOTS = threading.BoundedSemaphore(DNS_RESOLUTION_LIMIT)

#: Bytes read per chunk of a ``url`` download.
DOWNLOAD_CHUNK_BYTES = 1 << 20

#: Directory under the workspace that holds ``url`` downloads while a call runs.
SCRATCH_DIR = ".scratch"

#: Detail characters kept from a rebrew refusal.
DETAIL_MAX_CHARS = 400

#: Listing formats ``disassemble`` accepts.
DISASM_FORMATS = frozenset({"nasm", "asm", "hex"})

#: Largest extent ``disassemble`` lists, the bound of the other extent ops.
DISASSEMBLE_MAX_BYTES = 1 << 20

#: Most reference kinds one ``xrefs`` call may narrow to.
XREFS_MAX_KINDS = 64

#: The one ISA rebrew's NASM source decodes.  ``disassemble_bytes`` lists every
#: other ISA in the ``asm`` format.
NASM_ARCH = "x86_32"

#: Backends ``decompile`` and ``structs`` accept (the backend's
#: ``DecompileRequest`` list).
DECOMPILER_BACKENDS = frozenset({"auto", "ghidra", "kuna", "r2dec", "r2ghidra"})

#: The :data:`DECOMPILER_BACKENDS` entry that picks among the available backends.
AUTO_DECOMPILER = "auto"

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

#: Flag-sweep tiers ``flag_search`` takes, by request ``tier``.
FLAG_SEARCH_TIERS = frozenset({"quick", "targeted", "normal", "thorough", "full"})

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
DATA_MARKERS = DATA_KINDS

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
TARGET_UNSAFE = re.compile(r"[^A-Za-z0-9_]")
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1

# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------

INVALID_REQUEST = "invalid-request"
UNKNOWN_OP = "unknown-op"
ENGINE_ERROR = "engine-error"
WORKER_BUSY = "worker-busy"
#: The caller closed the connection before the reply (499, after nginx).
CALLER_GONE = "caller-gone"
#: The call outlived its op's deadline (``Op.timeout_seconds``) or the seconds
#: its caller named in :data:`TIMEOUT_HEADER`.
DEADLINE_EXCEEDED = "deadline-exceeded"
#: A remote compile of a source whose project headers cannot ship (relumea ADR 0010, decision 4).
REMOTE_HEADERS = "remote-compile-headers"
#: A supplied ``rebrew-project.toml`` rebrew cannot read (400); the detail
#: starts ``invalid project config:``.
INVALID_PROJECT_CONFIG = "invalid-project-config"
#: The remote compile service never ran an applied candidate's compile (503,
#: with ``Retry-After`` when the service named one): nothing was applied.
COMPILE_NOT_RUN = "compile-not-run"
#: The compiler a compile names is not offered (400): the registry withdrew it (the
#: detail says why), or the remote compile service's deployment has not installed it.
#: Nothing was compiled or billed; a retry is refused the same, so choose another compiler.
COMPILER_NOT_OFFERED = "compiler-not-offered"
#: The decompiler a request names is not offered here (400): this engine has not
#: installed it, or no Ghidra endpoint is configured; ``auto`` when none of the backends
#: it probes is.  The detail is a fixed sentence naming what is missing; a retry is
#: refused the same, so choose another decompiler (``rebrew.vocabulary``'s ``decompilers``).
DECOMPILER_NOT_OFFERED = "decompiler-not-offered"
#: The configured Ghidra endpoint the ``ghidra`` decompiler uses did not answer (503,
#: ``Retry-After``): an outage, retried later.
DECOMPILER_UNREACHABLE = "decompiler-unreachable"
#: An offered decompiler ran and produced no code for the requested address (or, for
#: ``rebrew.structs``, for any selected function): a fixed sentence naming the backend
#: and the address; the same request is answered the same.
NO_DECOMPILATION = "no-decompilation"
#: The toolchain ran and rejected the source (422): no verdict, and the detail
#: carries the compiler's diagnostics.  A toolchain that could not run stays
#: 500 ``engine-error``.
TOOLCHAIN_REJECTED = "toolchain-rejected"
#: A candidate that defines no C function or more than one (400): the detail says which.
CANDIDATE_NOT_ONE_FUNCTION = "candidate-not-one-function"
#: A candidate whose own ``ADDRESS`` comment is malformed, not on a line of its own, or
#: names another address (400).
CANDIDATE_ADDRESS_COMMENT = "candidate-address-comment"
#: A candidate naming its function as another function of the target is named (409):
#: the detail names both functions.
CANDIDATE_NAME_TAKEN = "candidate-name-taken"


class OpsError(RebrewError):
    """A refusal: a detail safe to show, a stable code, and an HTTP status."""

    code: str = ENGINE_ERROR
    status: int = 500
    retry_after: int | None = None
    #: ``{count, wait_ms}`` of a compiling op's recompile calls, which its refusal carries.
    remote_compile: dict[str, int] | None = None

    STRUCTURED_FIELDS = (*RebrewError.STRUCTURED_FIELDS, "code", "status", "retry_after")

    def __init__(
        self,
        detail: str,
        *,
        code: str = ENGINE_ERROR,
        status: int = 500,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.status = status
        self.retry_after = retry_after


def invalid_request(detail: str) -> OpsError:
    return OpsError(detail, code=INVALID_REQUEST, status=400)


def engine_decompilers() -> list[Any]:
    """The :class:`~rebrew.decompiler.BackendState` of every decompiler the ops name.

    ``ghidra`` uses the endpoint :data:`rebrew.config.GHIDRA_MCP_ENDPOINT_ENV` names;
    without one it is not offered.
    """
    from rebrew.decompiler import backend_state, configured_ghidra_endpoint

    endpoint = configured_ghidra_endpoint()
    return [
        backend_state(name, endpoint=endpoint)
        for name in sorted(DECOMPILER_BACKENDS - {AUTO_DECOMPILER})
    ]


def refuse_unoffered_decompiler(name: str) -> None:
    """Refuse *name* when it cannot run here, before any work.

    ``auto`` is refused when none of the backends it probes can run.  A backend
    not installed is :data:`DECOMPILER_NOT_OFFERED` (400); a configured Ghidra
    endpoint that does not answer is :data:`DECOMPILER_UNREACHABLE` (503).
    """
    from rebrew.decompiler import (
        BACKENDS,
        REASON_TEXT,
        STATE_WINDOW_SECONDS,
        backend_state,
        configured_ghidra_endpoint,
    )

    endpoint = configured_ghidra_endpoint()
    if name == AUTO_DECOMPILER:
        probed = [backend for backend in BACKENDS if backend in DECOMPILER_BACKENDS]
        if not any(backend_state(b, endpoint=endpoint).state == "available" for b in probed):
            raise OpsError(
                "no decompiler 'auto' probes is offered here",
                code=DECOMPILER_NOT_OFFERED,
                status=400,
            )
        return
    state = backend_state(name, endpoint=endpoint)
    if state.reason is None:
        return
    missing = REASON_TEXT[state.reason]
    if state.state == "unreachable":
        raise OpsError(
            f"decompiler '{name}' is unavailable: {missing}",
            code=DECOMPILER_UNREACHABLE,
            status=503,
            retry_after=math.ceil(STATE_WINDOW_SECONDS),
        )
    raise OpsError(
        f"decompiler '{name}' is not offered here: {missing}",
        code=DECOMPILER_NOT_OFFERED,
        status=400,
    )


def ghidra_outage(exc: Exception) -> OpsError:
    """A Ghidra endpoint that stopped answering mid-call; its text goes to the log, bounded."""
    from rebrew.decompiler import STATE_WINDOW_SECONDS

    logger.warning("Ghidra MCP endpoint failed: %s", escape_log_text(str(exc))[:200])
    return OpsError(
        "decompiler 'ghidra' is unavailable: the configured Ghidra endpoint did not answer",
        code=DECOMPILER_UNREACHABLE,
        status=503,
        retry_after=math.ceil(STATE_WINDOW_SECONDS),
    )


def address_comment_refused(detail: str) -> OpsError:
    return OpsError(detail, code=CANDIDATE_ADDRESS_COMMENT, status=400)


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
    return path.stat().st_size, sha256_file(path)


def checked_cflags(text: str) -> str:
    """The flag string, normalized to single spaces, or a 400 naming the bad token."""
    if len(text) > CFLAGS_MAX_CHARS:
        raise invalid_request(f"invalid-cflags: longer than {CFLAGS_MAX_CHARS} characters")
    tokens = text.split()
    for token in tokens:
        if not _CFLAGS_TOKEN.fullmatch(token):
            raise invalid_request(f"invalid-cflags: {token[:40]!r} is not a plain option token")
        if _CFLAGS_REFUSED.match(token):
            raise invalid_request(f"invalid-cflags: {token!r} names a file or changes the command")
    return " ".join(tokens)


#: Bounds of one captured readset or retained source manifest, shared by every
#: site that reads or accepts one.  Intake writes one stub per discovered
#: function, so the file count is sized for binaries with tens of thousands of
#: functions; the byte bounds are the resource limit that matters.
MAX_READSET_FILES = 32768
#: Latency histogram upper bounds in ms for the ops request metric.
LATENCY_BUCKETS_MS = (100.0, 1000.0, 10000.0, 60000.0, float("inf"))


MAX_READSET_BYTES = 32 * 1024 * 1024
MAX_READSET_FILE_BYTES = 8 * 1024 * 1024

#: Where a fresh analysis capture holds the analysis report (the discovered
#: functions and stubs).  Its shape is published in the dispatch schema under
#: ``documents``.
ANALYSIS_REPORT_PATH = ".relumea/analysis-report.json"

READSET_TOO_LARGE = "readset-too-large"
ANALYSIS_CAPTURE_FAILED = "analysis-capture-failed"
#: A retained report site rebrew generated that it will not retain: over
#: :data:`MAX_REPORT_FILES` or :data:`MAX_REPORT_BYTES`, empty, or holding a
#: symlink.  The site is rebrew's own output from a verified snapshot, so the
#: engine's failure (500), not the caller's.
REPORT_OUTPUT_INVALID = "report-output-invalid"

#: The most files and bytes a retained report site holds.
MAX_REPORT_FILES = 4096
MAX_REPORT_BYTES = 64 * 1024 * 1024
UNSUPPORTED_BINARY_FORMAT = "unsupported-binary-format"
#: A ``.sig`` or ``.pat`` file the caller supplied that python-flirt cannot parse (422).
MALFORMED_SIGNATURES = "malformed-signatures"
#: A project archive the worker will not import: an unsafe or oversized entry, no matching
#: target binary, or a setting that would run something.  The caller's to fix.
PROJECT_IMPORT_REFUSED = "project-import-refused"
#: A retained coverage input whose files or records do not match what it names (409).
COVERAGE_INPUT_UNVERIFIED = "coverage-input-unverified"
#: The HTTP transport's own refusals: no or a wrong bearer token, a Host the
#: server does not answer, a browser's cross-origin POST, a method other than POST.
UNAUTHORIZED = "unauthorized"
HOST_NOT_ALLOWED = "host-not-allowed"
CROSS_ORIGIN = "cross-origin"
METHOD_NOT_ALLOWED = "method-not-allowed"

#: Every refusal code an op or the HTTP transport answers, and the statuses it is
#: answered with.  The dispatch schema publishes it as ``errors``
#: (``tools/gen_dispatch_schema.py``); a test holds every refusal the code raises to it.
#: ``invalid-request`` takes the statuses the HTTP server answers a malformed
#: request with (``BaseHTTPRequestHandler.send_error``) besides 400.
PROBLEMS: dict[str, tuple[int, ...]] = {
    INVALID_REQUEST: (400, 411, 413, 414, 415, 431, 501, 505),
    UNKNOWN_OP: (404,),
    METHOD_NOT_ALLOWED: (405,),
    UNAUTHORIZED: (401,),
    HOST_NOT_ALLOWED: (403,),
    CROSS_ORIGIN: (403,),
    ENGINE_ERROR: (500,),
    WORKER_BUSY: (503,),
    CALLER_GONE: (499,),
    DEADLINE_EXCEEDED: (504,),
    REMOTE_HEADERS: (422,),
    INVALID_PROJECT_CONFIG: (400,),
    COMPILE_NOT_RUN: (503,),
    COMPILER_NOT_OFFERED: (400,),
    DECOMPILER_NOT_OFFERED: (400,),
    DECOMPILER_UNREACHABLE: (503,),
    NO_DECOMPILATION: (422,),
    TOOLCHAIN_REJECTED: (422,),
    CANDIDATE_NOT_ONE_FUNCTION: (400,),
    CANDIDATE_ADDRESS_COMMENT: (400,),
    CANDIDATE_NAME_TAKEN: (409,),
    READSET_TOO_LARGE: (422,),
    ANALYSIS_CAPTURE_FAILED: (500,),
    REPORT_OUTPUT_INVALID: (500,),
    UNSUPPORTED_BINARY_FORMAT: (422,),
    MALFORMED_SIGNATURES: (422,),
    PROJECT_IMPORT_REFUSED: (422,),
    COVERAGE_INPUT_UNVERIFIED: (409,),
}

#: The codes every op can answer: the HTTP transport's, the dispatcher's (a call
#: cut short, a worker that is busy, an exception it translates), and an
#: invalid request or engine failure.
DISPATCH_PROBLEMS = frozenset(
    {
        INVALID_REQUEST,
        METHOD_NOT_ALLOWED,
        UNAUTHORIZED,
        HOST_NOT_ALLOWED,
        CROSS_ORIGIN,
        ENGINE_ERROR,
        WORKER_BUSY,
        CALLER_GONE,
        DEADLINE_EXCEEDED,
        UNSUPPORTED_BINARY_FORMAT,
        TOOLCHAIN_REJECTED,
    }
)

_RETAINED_PROBLEMS = frozenset({INVALID_PROJECT_CONFIG, READSET_TOO_LARGE})
_COMPILE_PROBLEMS = frozenset({COMPILER_NOT_OFFERED, READSET_TOO_LARGE, REMOTE_HEADERS})
_CANDIDATE_PROBLEMS = _COMPILE_PROBLEMS | {
    CANDIDATE_ADDRESS_COMMENT,
    CANDIDATE_NAME_TAKEN,
    CANDIDATE_NOT_ONE_FUNCTION,
    COMPILE_NOT_RUN,
}
_DECOMPILE_PROBLEMS = frozenset({DECOMPILER_NOT_OFFERED, DECOMPILER_UNREACHABLE, NO_DECOMPILATION})
_COVERAGE_PROBLEMS = _RETAINED_PROBLEMS | {COVERAGE_INPUT_UNVERIFIED}

#: The codes an op answers besides :data:`DISPATCH_PROBLEMS`, by op; an op not
#: named answers no other.  The dispatch schema publishes each op's codes as its
#: ``errors``; a test holds every refusal an op's code reaches to its entry.
OP_PROBLEMS: dict[str, frozenset[str]] = {
    "rebrew.analyse": frozenset({ANALYSIS_CAPTURE_FAILED, COMPILER_NOT_OFFERED, READSET_TOO_LARGE}),
    "rebrew.apply_candidate": _CANDIDATE_PROBLEMS,
    "rebrew.verify_function": _CANDIDATE_PROBLEMS,
    "rebrew.build": _COMPILE_PROBLEMS | {INVALID_PROJECT_CONFIG},
    "rebrew.verify_target": _COMPILE_PROBLEMS | {INVALID_PROJECT_CONFIG},
    "rebrew.retained_source_operation": _COMPILE_PROBLEMS
    | {INVALID_PROJECT_CONFIG, CANDIDATE_NAME_TAKEN},
    "rebrew.flag_search": _COMPILE_PROBLEMS,
    "rebrew.coverage_report": _COVERAGE_PROBLEMS,
    "rebrew.report": _COVERAGE_PROBLEMS | {REPORT_OUTPUT_INVALID},
    "rebrew.data_list": _COVERAGE_PROBLEMS | {COMPILER_NOT_OFFERED},
    "rebrew.data_set": frozenset({COMPILER_NOT_OFFERED}),
    "rebrew.reference_flirt": frozenset({COMPILER_NOT_OFFERED, MALFORMED_SIGNATURES}),
    "rebrew.decompile": _DECOMPILE_PROBLEMS,
    "rebrew.decompile_snapshot": _DECOMPILE_PROBLEMS,
    "rebrew.structs": _DECOMPILE_PROBLEMS,
    "rebrew.import_archive": _RETAINED_PROBLEMS | {ANALYSIS_CAPTURE_FAILED, PROJECT_IMPORT_REFUSED},
    "rebrew.project_targets": _RETAINED_PROBLEMS,
    "rebrew.metadata_carry": frozenset({READSET_TOO_LARGE}),
    "rebrew.metadata_describe": frozenset({READSET_TOO_LARGE}),
    "rebrew.metadata_diff": frozenset({READSET_TOO_LARGE}),
}


def readset_limit(what: str, count: int, limit: int, unit: str = "files") -> OpsError:
    """The binary's own analysis is larger than the engine bounds: not the caller's fault."""
    return OpsError(
        f"{what} has {count} {unit}, over the limit of {limit}",
        code=READSET_TOO_LARGE,
        status=422,
    )


def check_manifest_size(files: Any) -> None:
    """A retained source manifest is non-empty and within the shared readset bounds."""
    if not files:
        raise invalid_request("invalid retained source manifest size")
    max_files = ops_binding("MAX_READSET_FILES", MAX_READSET_FILES)
    max_bytes = ops_binding("MAX_READSET_BYTES", MAX_READSET_BYTES)
    if len(files) > max_files:
        raise readset_limit("retained source manifest", len(files), max_files)
    size = sum(f.size for f in files)
    if size > max_bytes:
        raise readset_limit("retained source manifest", size, max_bytes, "bytes")


def invalid_project_config(root: Path, exc: Exception) -> OpsError:
    """A supplied ``rebrew-project.toml`` rebrew cannot read: 400 :data:`INVALID_PROJECT_CONFIG`.

    The detail is the caller's own file, named within *root* and never by the
    worker's scratch path.
    """
    detail = str(exc).replace(f"{root}{os.sep}", "").replace(str(root), ".")
    if not detail.startswith("rebrew-project.toml"):
        detail = f"rebrew-project.toml: {detail}"
    return OpsError(
        bounded(f"invalid project config: {detail}"), code=INVALID_PROJECT_CONFIG, status=400
    )


def import_refused(detail: str) -> OpsError:
    """A project archive refused for what it holds; *detail* names the entry or setting."""
    return OpsError(bounded(detail), code=PROJECT_IMPORT_REFUSED, status=422)


def report_output_invalid(detail: str) -> OpsError:
    """rebrew's own report site cannot be retained: the engine's failure."""
    return OpsError(detail, code=REPORT_OUTPUT_INVALID, status=500)


def capture_failed(detail: str) -> OpsError:
    """A self-check of the fresh analysis capture failed: the engine's fault, not the caller's."""
    return OpsError(detail, code=ANALYSIS_CAPTURE_FAILED, status=500)


#: The detail of a :data:`COMPILER_NOT_OFFERED` refusal for a compiler not installed.
_NOT_INSTALLED_DETAIL = (
    "the recompile service has not installed the compiler this compile names: "
    "nothing was compiled or billed"
)

#: The detail of a :data:`COMPILER_NOT_OFFERED` refusal the recompile service itself
#: answered ``compiler_withdrawn`` (its registry withdrew a compiler rebrew's still offers).
_SERVICE_WITHDRAWN_DETAIL = (
    "the recompile service has withdrawn the compiler this compile names: "
    "nothing was compiled or billed"
)

#: The refusal an op answers a compile with whose ``error_code`` is final for every
#: retry: (problem code, detail); a ``None`` detail is the refusal's own message, which
#: only rebrew's registry writes (a withdrawn compiler's names its reason).  Nothing
#: was compiled or billed.
FINAL_RECOMPILE_REFUSALS: dict[str, tuple[str, str | None]] = {
    "compiler_not_installed": (COMPILER_NOT_OFFERED, _NOT_INSTALLED_DETAIL),
    "compiler_withdrawn": (COMPILER_NOT_OFFERED, None),
    # recompile 13 checks the bound rebrew checks first (recompile_client.Attribution).
    "invalid_attribution": (INVALID_REQUEST, "the recompile service refused the attribution"),
}

#: ``RecompileError.kind`` values and how a :data:`COMPILE_NOT_RUN` detail names them.
_NOT_RUN_KINDS = {
    "network": "no readable reply",
    "http": "a refusal",
    "validation": "a request rebrew refused to send",
    "protocol": "a reply rebrew could not read",
    "service": "a failure of the service",
    "deadline": "the call's deadline",
}


def not_run_detail(error: Any) -> str:
    """The fixed :data:`COMPILE_NOT_RUN` sentence for a NOT_RUN result's *error*.

    It names the answer by its kind, HTTP status and ``code`` only: the error's
    message carries the service URL and the service's own text, which the client
    logged where it received them (``recompile_client.compile_source``).
    """
    fields = error if isinstance(error, dict) else {}
    if fields.get("type") == "ToolchainError":
        # The runtime's own words (hosts, paths) go to the worker log, never here.
        return "the toolchain did not run the compile: nothing was applied"
    status = fields.get("status_code")
    code = fields.get("error_code")
    named = [
        _NOT_RUN_KINDS.get(str(fields.get("kind")), "an error"),
        *([f"HTTP {status}"] if isinstance(status, int) and not isinstance(status, bool) else []),
        *([code] if isinstance(code, str) and re.fullmatch(r"[a-z][a-z_]{0,63}", code) else []),
    ]
    return (
        f"the recompile service did not run the compile ({', '.join(named)}): nothing was applied"
    )


def refuse_compiler_not_offered(cfg: Any) -> None:
    """Refuse a compile of the project's compiler when it is not offered, before any work.

    The registry withdrew it, or the remote compile service has not installed it
    (``compiler.compile.compiler_not_offered``).  A source whose own toolchain
    override names such a compiler reads ``NOT_RUN`` with the reason instead.
    """
    from rebrew.compiler.compile import compiler_not_offered
    from rebrew.compiler.toolchain import CompilerNotOffered

    refusal = compiler_not_offered(cfg, str(getattr(cfg, "compiler_profile", "") or ""))
    if refusal is not None:
        assert isinstance(refusal, CompilerNotOffered)
        problem, detail = FINAL_RECOMPILE_REFUSALS[refusal.error_code]
        raise OpsError(detail or bounded(str(refusal)), code=problem, status=400)


def not_run_reason(verdict: dict[str, Any]) -> None:
    """Replace a ``NOT_RUN`` verdict's message with its closed-set ``not_run_reason``.

    The message and the error's text carry the compile client's words (a service
    URL, the service's body); the reason is the client's outcome kind
    (:data:`rebrew.ops.replies.NotRunReason`).
    """
    from typing import get_args

    from rebrew.ops.replies import NotRunReason

    if verdict.get("status") != "NOT_RUN":
        return
    verdict.pop("message", None)
    error = verdict.get("error")
    fields = error if isinstance(error, dict) else {}
    # The error keeps its structured fields; its message carries the client's words.
    fields.pop("message", None)
    kind = fields.get("type")
    reason = (
        fields.get("error_code")
        if kind == "CompilerNotOffered"
        else "toolchain_not_run"
        if kind == "ToolchainError"
        else fields.get("kind")
    )
    if reason not in get_args(NotRunReason):
        raise ValueError(f"a NOT_RUN verdict without a known reason: {reason!r}")
    verdict["not_run_reason"] = reason


def withheld(value: Any, steps: list[str]) -> Any:
    """*value* without the member *steps* lead to: a member name, ``[]`` for each item
    of a list, ``*`` for each value of an object.  Copies what it changes."""
    step, rest = steps[0], steps[1:]
    if step == "[]":
        return [withheld(item, rest) for item in value] if isinstance(value, list) else value
    if not isinstance(value, dict):
        return value
    if step == "*":
        return {key: withheld(item, rest) for key, item in value.items()}
    if not rest:
        return {key: item for key, item in value.items() if key != step}
    if step not in value:
        return value
    return {**value, step: withheld(value[step], rest)}


def declared_reply(name: str, reply: Mapping[str, Any]) -> dict[str, Any]:
    """*reply* as the op's declared reply (:mod:`rebrew.ops.replies`), not-run text closed."""
    from rebrew.ops.replies import DECLARED, WITHHELD, project

    closed = dict(reply)
    for path in WITHHELD.get(name, ()):
        closed = withheld(closed, path.replace("[]", ".[]").split("."))
    not_run_reason(closed)
    rows = closed.get("results")
    if isinstance(rows, list):
        closed["results"] = [dict(row) if isinstance(row, dict) else row for row in rows]
        for row in closed["results"]:
            if isinstance(row, dict):
                not_run_reason(row)
    return project(closed, DECLARED[name], name)


def final_recompile_refusal(result: dict[str, Any]) -> dict[str, Any]:
    """*result*, unless it is a NOT_RUN whose refusal no retry changes."""
    error = result.get("error")
    code = error.get("error_code") if isinstance(error, dict) else None
    if result.get("status") == "NOT_RUN" and code in FINAL_RECOMPILE_REFUSALS:
        assert isinstance(error, dict)
        problem, detail = FINAL_RECOMPILE_REFUSALS[code]
        if detail is None and error.get("type") != "CompilerNotOffered":
            # The service's own answer: its message holds the service's text.
            detail = _SERVICE_WITHDRAWN_DETAIL
        raise OpsError(detail or bounded(str(error.get("message", ""))), code=problem, status=400)
    return result


def toolchain_rejected(diagnostics: str, roots: Iterable[Path] = ()) -> OpsError:
    """The toolchain ran and rejected the source: 422 with its diagnostics, no verdict.

    The diagnostics keep their lines; a path under one of *roots* is named
    relative to it (:func:`without_host_paths`).
    """
    detail = bounded_lines(without_host_paths(diagnostics, roots))
    return OpsError(detail, code=TOOLCHAIN_REJECTED, status=422)


class Cancellation:
    """The refusal the running call gets once its caller has given up or its deadline passed."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._refusal: tuple[str, str, int] | None = None
        self._deadline: tuple[float, str] | None = None

    def cancel(self, detail: str, code: str, status: int) -> None:
        """Record the first reason; later ones change nothing."""
        with self._lock:
            if self._refusal is None:
                self._refusal = (detail, code, status)

    def limit(self, deadline: float, detail: str) -> None:
        """End the call at ``time.monotonic()`` *deadline* unless an earlier one is set."""
        with self._lock:
            if self._deadline is None or deadline < self._deadline[0]:
                self._deadline = (deadline, detail)

    def remaining(self) -> float | None:
        """Seconds left before the call's deadline, or ``None`` without one."""
        with self._lock:
            deadline = self._deadline
        return None if deadline is None else deadline[0] - time.monotonic()

    def check(self) -> None:
        """Raise the refusal once the call is cancelled or past its deadline."""
        if self._refusal is not None:
            detail, code, status = self._refusal
            raise OpsError(detail, code=code, status=status)
        if self._deadline is not None and time.monotonic() >= self._deadline[0]:
            raise OpsError(self._deadline[1], code=DEADLINE_EXCEEDED, status=504)


#: The running call's cancellation, set around every op by the dispatcher (with
#: the op's deadline) and by the HTTP transport (with its caller's).
#: ``run_rebrew`` checks it while its child command runs, and a download, a
#: staged retained file and an op's own steps check it before they start;
#: other in-process work runs to its own end.
CANCELLATION_VAR: ContextVar[Cancellation | None] = ContextVar(
    "rebrew_ops_cancellation", default=None
)

#: Where the running call's progress goes, ``(done, total)`` per new count:
#: set by a transport that carries it (``serve`` to a caller accepting
#: :data:`PROGRESS_MEDIA_TYPE`, ``ops call`` with :data:`DISPATCH_PROGRESS_FD_ENV`).
#: ``run_rebrew`` relays its child command's counts there.
PROGRESS_VAR: ContextVar[Callable[[int, int], None] | None] = ContextVar(
    "rebrew_ops_progress", default=None
)


def progress_frame(done: int, total: int) -> bytes:
    """One progress line of a stream or of ``ops call``'s progress descriptor."""
    return msgspec.json.encode({"progress": {"done": done, "total": total}}) + b"\n"


def check_cancelled() -> None:
    """Raise the running call's refusal once it is cancelled or past its deadline."""
    cancellation = CANCELLATION_VAR.get()
    if cancellation is not None:
        cancellation.check()


def error_body(
    code: str, detail: str, status: int, remote_compile: dict[str, int] | None = None
) -> bytes:
    """The refusal reply both transports write; a compiling op's carries its ``remote_compile``."""
    from rebrew.utils import strip_bidi_format

    return msgspec.json.encode(
        {
            "error": code,
            "detail": strip_bidi_format(detail),
            "status": status,
            **({} if remote_compile is None else {"remote_compile": remote_compile}),
        }
    )


def bounded(text: str) -> str:
    """*text* on one line, cut at :data:`DETAIL_MAX_CHARS`."""
    from rebrew.utils import strip_bidi_format, truncate_text

    return truncate_text(" ".join(strip_bidi_format(text).split()), DETAIL_MAX_CHARS)


def bounded_lines(text: str) -> str:
    """*text* line by line, each line's whitespace collapsed and blank lines dropped, cut at
    :data:`DETAIL_MAX_CHARS`: a compiler's diagnostics stay one per line."""
    from rebrew.utils import strip_bidi_format, truncate_text

    lines = (" ".join(line.split()) for line in strip_bidi_format(text).splitlines())
    return truncate_text("\n".join(line for line in lines if line), DETAIL_MAX_CHARS)


#: A URL in failure text; its query string can be a presigned credential.
_URL_TEXT = re.compile(r"https?://[^\s'\"<>]+")
#: An absolute POSIX path in failure text, not the tail of a relative one.
_ABSOLUTE_PATH_TEXT = re.compile(r"(?<![\w.~/-])/(?:[\w.@+~-]+/)*[\w.@+~-]+")


def without_host_paths(text: str, roots: Iterable[Path] = ()) -> str:
    """*text* with every URL as ``<url>`` and every absolute path cut to what a user can place.

    A path under one of *roots* (a project, the workspace, the filestore) is
    named relative to it, a scratch directory under ``.scratch`` dropped (it
    is the private copy of a snapshot); any other absolute path is its file
    name.
    """
    known = sorted({str(root) for root in roots}, key=len, reverse=True)

    def placed(match: re.Match[str]) -> str:
        path = match.group(0)
        for root in known:
            if path.startswith(f"{root}/"):
                relative = path[len(root) + 1 :]
                if relative.startswith(f"{SCRATCH_DIR}/"):
                    relative = relative.split("/", 2)[2] if relative.count("/") >= 2 else ""
                return relative or "."
            if path == root:
                return "."
        return Path(path).name

    return _ABSOLUTE_PATH_TEXT.sub(placed, _URL_TEXT.sub("<url>", text))


#: The step an unexplained failure of the running call escaped from, as
#: ``(step, exception)``: set by :func:`step`, read by the dispatcher.
FAILED_STEP_VAR: ContextVar[list[tuple[str, BaseException]] | None] = ContextVar(
    "rebrew_ops_failed_step", default=None
)


@contextlib.contextmanager
def step(what: str) -> Iterator[None]:
    """Name what the running op is doing, for the refusal of a failure nothing else explains.

    The innermost step an exception leaves is the one recorded; *what* reads
    after "failed while" (``"staging the retained snapshot"``).
    """
    try:
        yield
    except Exception as exc:
        failed = FAILED_STEP_VAR.get()
        if failed is not None and (not failed or failed[0][1] is not exc):
            failed[:] = [(what, exc)]
        raise


def failure_detail(config: WorkerConfig, name: str, exc: BaseException) -> str:
    """The refusal of a failure nothing else explained: its step and its message, no host path."""
    failed = FAILED_STEP_VAR.get() or []
    chain: list[BaseException] = []
    link: BaseException | None = exc
    while link is not None and link not in chain:
        chain.append(link)
        link = link.__cause__ or link.__context__
    step = next((what for what, raised in failed if raised in chain), "")
    if isinstance(exc, OSError) and exc.strerror:
        message = f"{exc.strerror}: {exc.filename}" if exc.filename else exc.strerror
    else:
        message = str(exc) or type(exc).__name__
    roots = [path for path in (config.workspace, config.filestore) if path is not None]
    where = f" while {step}" if step else ""
    return bounded(f"{name} failed{where}: {without_host_paths(message, roots)}")


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
            raise OpsError("the rebrew worker has no filestore configured (--filestore)")
        return self.filestore

    def require_workspace(self) -> Path:
        if self.workspace is None:
            raise OpsError("the rebrew worker has no workspace configured (--workspace)")
        return self.workspace


def existing_dir(value: Path | None, flag: str) -> Path | None:
    if value is None:
        return None
    if not value.is_absolute() or not value.is_dir():
        error_exit(f"{flag} must be an absolute path to an existing directory: {value}")
    return value.resolve()


def has_lone_surrogate(value: str) -> bool:
    """Whether *value* holds a surrogate code point (U+D800 to U+DFFF).

    Strict UTF-8 refuses exactly those, so the codec scans the string in C
    instead of one Python comparison per character.
    """
    if value.isascii():
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return False


_MSGSPEC_MISSING_RE = re.compile(r"^Object missing required field `([^`]+)`(?: - at `\$([^`]*)`)?$")

#: Per-request-dataclass known field names and nested dataclass fields.
_REQUEST_SCHEMA: dict[type, tuple[frozenset[str], dict[str, tuple[type, bool]]]] = {}


def _request_schema(cls: type) -> tuple[frozenset[str], dict[str, tuple[type, bool]]]:
    """Cached ``(known_field_names, nested_dataclass_fields)`` for *cls*.

    Each nested entry maps a field name to ``(dataclass_type, is_list)`` so
    unknown-field rejection recurses into nested dataclasses without re-walking
    primitive hints. Two threads racing a first parse store equal entries.
    """
    found = _REQUEST_SCHEMA.get(cls)
    if found is not None:
        return found
    hints = typing.get_type_hints(cls)
    known = frozenset(spec.name for spec in fields(cls))
    nested: dict[str, tuple[type, bool]] = {}
    for name, hint in hints.items():
        if typing.get_origin(hint) is types.UnionType:
            args = [arg for arg in typing.get_args(hint) if arg is not type(None)]
            if len(args) == 1:
                hint = args[0]
        if typing.get_origin(hint) is list:
            (item,) = typing.get_args(hint)
            if dataclasses.is_dataclass(item) and isinstance(item, type):
                nested[name] = (item, True)
        elif dataclasses.is_dataclass(hint) and isinstance(hint, type):
            nested[name] = (hint, False)
    return _REQUEST_SCHEMA.setdefault(cls, (known, nested))


def _check_json_value(value: Any, where: str) -> None:
    """Enforce JSON wire bounds msgspec does not check on Python primitives.

    * 64-bit signed integer range (``INT64_MIN .. INT64_MAX``);
    * no unpaired UTF-16 surrogates in strings or object keys (JSON accepts
      ``\\uD800`` escapes that would fail downstream ``.encode("utf-8")``);
    * no raw ``bytes`` values (``bytes`` fields must arrive as base64 strings).
    """
    t = type(value)
    if t is int:
        if not INT64_MIN <= value <= INT64_MAX:
            raise invalid_request(f"{where} must be a 64-bit integer")
    elif t is str:
        if has_lone_surrogate(value):
            raise invalid_request(f"{where} contains an unpaired surrogate")
    elif t is bytes:
        raise invalid_request(f"{where} must be a base64 string")
    elif t is list:
        for index, entry in enumerate(value):
            _check_json_value(entry, f"{where}[{index}]")
    elif t is dict:
        for key, entry in value.items():
            if type(key) is str and has_lone_surrogate(key):
                raise invalid_request(f"{where} contains an unpaired surrogate")
            _check_json_value(entry, f"{where}.{key}")


def _check_unknown_fields(cls: type, raw: dict[Any, Any], where: str) -> None:
    """Refuse keys *cls* (or any nested dataclass inside *cls*) does not declare."""
    known, nested = _request_schema(cls)
    unknown = sorted(str(k) for k in raw if k not in known)
    if unknown:
        raise invalid_request(f"{where} has unknown fields: {', '.join(unknown)}")
    for name, (sub_cls, is_list) in nested.items():
        if name not in raw:
            continue
        val = raw[name]
        if is_list:
            if type(val) is list:
                for index, entry in enumerate(val):
                    if type(entry) is dict:
                        _check_unknown_fields(sub_cls, entry, f"{where}.{name}[{index}]")
        elif type(val) is dict:
            _check_unknown_fields(sub_cls, val, f"{where}.{name}")


def parse_request[T](cls: type[T], raw: Any, where: str = "request") -> T:
    """Build *cls* from a decoded JSON object, refusing unknown and missing fields."""
    if type(raw) is not dict:
        raise invalid_request(f"{where} must be a JSON object")
    if (
        cls in {ReportRequest, CoverageReportRequest, DataListRequest}
        and not raw.get("files")
        and {"coverage_input", "coverage_input_digest", "verification_records"} & raw.keys()
    ):
        raise invalid_request("coverage input requires a retained snapshot")
    if (
        cls in {ReportRequest, CoverageReportRequest, DataListRequest}
        and raw.get("coverage_input")
        and "verification_records" not in raw
    ):
        raise OpsError(
            "coverage verification records are required",
            code=COVERAGE_INPUT_UNVERIFIED,
            status=409,
        )
    _check_unknown_fields(cls, raw, where)
    if cls is AnalyseRequest and raw.get("project_id") == "":
        raise invalid_request(f"{where}.project_id must not be empty")
    _check_json_value(raw, where)
    try:
        return msgspec.convert(raw, cls, strict=True)
    except msgspec.ValidationError as exc:
        msg = str(exc)
        match = _MSGSPEC_MISSING_RE.match(msg)
        if match is not None:
            field_name, path = match.group(1), match.group(2) or ""
            raise invalid_request(f"{where}{path} is missing {field_name}") from None
        raise invalid_request(f"{where}: {msg}") from None
    except ValueError as exc:  # a type that checks its own values (Attribution)
        raise invalid_request(f"{where}: {exc}") from None


APPLY_METADATA_FILE = "rebrew-functions.toml"
EXITS = (KeyboardInterrupt, SystemExit, GeneratorExit)
REPLY_HEADERS_VAR: ContextVar[dict[str, str] | None] = ContextVar(
    "rebrew_ops_reply_headers", default=None
)


def no_decompilation(backend: str, va: int) -> OpsError:
    """The decompiler *backend* (or every one ``auto`` tried) gave no code for *va*."""
    return OpsError(
        f"decompiler '{backend}' produced no code for 0x{va:x}",
        code=NO_DECOMPILATION,
        status=422,
    )


def attested_registry_digest(published: list[dict[str, Any]]) -> str:
    """Digest of the published metadata database or TOML registry in *published*."""
    from rebrew.metadata.sqlite import DATABASE_FILENAME

    digests = {item["path"]: item["digest"] for item in published}
    return str(digests.get(DATABASE_FILENAME, digests.get(APPLY_METADATA_FILE, "")))


def verified_coverage_inputs_required() -> None:
    """Coverage metadata needs producer custody, not merely a supplied manifest."""
    raise OpsError(
        "retained coverage requires verified inventory and result provenance",
        code=COVERAGE_INPUT_UNVERIFIED,
        status=409,
    )


#: The detail of a write refused for a function record and source that disagree; the
#: record's key goes to the worker log.
BINDING_CONFLICT_DETAIL = (
    "invalid project config: a function record names another function than its source's "
    "address anchor; rebrew doctor lists such records and a re-analysis repairs a generated stub"
)


def binding_conflict() -> OpsError:
    """The project's own function record and source disagree: 400, a fixed sentence."""
    return OpsError(BINDING_CONFLICT_DETAIL, code=INVALID_PROJECT_CONFIG, status=400)


@contextlib.contextmanager
def refusing_disagreeing_records() -> Iterator[None]:
    """Refuse a record-writing op over a record whose source's anchor names another function.

    Every other op skips such a record and answers for the rest of the project; a write
    the caller aimed at the project answers 400 :data:`INVALID_PROJECT_CONFIG` on purpose.
    """
    from rebrew.cli import BINDING_CONFLICT_KIND, CommandExit
    from rebrew.metadata.bindings import strict_bindings

    operation = "rebrew.retained_source_operation"
    try:
        with strict_bindings():
            yield
    except BindingConflictError as exc:
        # The key, never the names: an in-process refusal carries it, a child's message is it.
        record = f"{exc.module}.0x{exc.va:08x}" if exc.module else escape_log_text(str(exc))
        logger.warning(
            "%s %s refused a function record whose source's anchor names another function: "
            "%s trace_id=%s",
            request_id(),
            operation,
            record,
            trace_id(),
        )
        raise binding_conflict() from None
    except CommandExit as exc:
        if exc.kind != BINDING_CONFLICT_KIND:
            raise
        logger.warning("%s %s refused a function record: %s", request_id(), operation, exc.message)
        raise binding_conflict() from None


def _undeclared_skipped_records(name: str, skipped: set[tuple[str, int]]) -> None:
    """Fail under strict replies, or warn, when an op outside :data:`SKIPPED_RECORD_OPS` skipped."""
