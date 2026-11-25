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

import contextlib
import logging
import threading  # module statement: the call scan lock is made at load
from contextvars import ContextVar  # module statement: definition-time use
from dataclasses import MISSING, dataclass, field, fields
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import override  # decorator and base class: definition-time use
lazy import base64
lazy import binascii
lazy import dataclasses
lazy import functools
lazy import hashlib
lazy import hmac
lazy import itertools
lazy import json
lazy import math
lazy import os
lazy import re
lazy import select
lazy import shutil
lazy import signal
lazy import socket
lazy import subprocess
lazy import sys
lazy import tempfile
lazy import time
lazy import traceback
lazy import types
lazy import typing
lazy import unicodedata
lazy from collections.abc import Callable, Collection, Iterable, Iterator, Mapping
lazy from email.utils import formatdate
lazy from typing import Any
lazy from urllib.parse import urlsplit

import typer
lazy import httpx

from rebrew.errors import RebrewError
lazy from rebrew import __version__, telemetry
lazy from rebrew.call_progress import PROGRESS_FD_ENV, ProgressPipe
lazy from rebrew.cfg_ged import ImageReader
lazy from rebrew.cli import EXIT_ERROR, console, error_exit
lazy from rebrew.compiler.compile import (
    RemoteCompiles,
    counting_remote_compiles,
    current_remote_compiles,
)
lazy from rebrew.compiler.recompile_client import Attribution
lazy from rebrew.formats.binary_loader import UnsupportedBinaryFormat, load_binary
lazy from rebrew.metadata.bindings import DATA_KINDS, BindingConflictError
lazy from rebrew.utils import fold_host, path_is_relative_to, sha256_file, split_source_lines

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
DISPATCH_SCHEMA_SHA256 = "0a0ae03ccbef17e0fca0babab877d6ee7dd466ba96c112f6b9a4891a320cd264"

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
_DNS_SLOTS = threading.BoundedSemaphore(DNS_RESOLUTION_LIMIT)

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
_DATA_MARKERS = DATA_KINDS

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


def _invalid(detail: str) -> OpsError:
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


def _refuse_unoffered_decompiler(name: str) -> None:
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


def _ghidra_outage(exc: Exception) -> OpsError:
    """A Ghidra endpoint that stopped answering mid-call; its text goes to the log, bounded."""
    from rebrew.decompiler import STATE_WINDOW_SECONDS

    logger.warning("Ghidra MCP endpoint failed: %s", _escape_log_text(str(exc))[:200])
    return OpsError(
        "decompiler 'ghidra' is unavailable: the configured Ghidra endpoint did not answer",
        code=DECOMPILER_UNREACHABLE,
        status=503,
        retry_after=math.ceil(STATE_WINDOW_SECONDS),
    )


def _address_comment_refused(detail: str) -> OpsError:
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


def _invalid_project_config(root: Path, exc: Exception) -> OpsError:
    """A supplied ``rebrew-project.toml`` rebrew cannot read: 400 :data:`INVALID_PROJECT_CONFIG`.

    The detail is the caller's own file, named within *root* and never by the
    worker's scratch path.
    """
    detail = str(exc).replace(f"{root}{os.sep}", "").replace(str(root), ".")
    if not detail.startswith("rebrew-project.toml"):
        detail = f"rebrew-project.toml: {detail}"
    return OpsError(
        _bounded(f"invalid project config: {detail}"), code=INVALID_PROJECT_CONFIG, status=400
    )


def _import_refused(detail: str) -> OpsError:
    """A project archive refused for what it holds; *detail* names the entry or setting."""
    return OpsError(_bounded(detail), code=PROJECT_IMPORT_REFUSED, status=422)


def _report_output_invalid(detail: str) -> OpsError:
    """rebrew's own report site cannot be retained: the engine's failure."""
    return OpsError(detail, code=REPORT_OUTPUT_INVALID, status=500)


def _capture_failed(detail: str) -> OpsError:
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
_FINAL_RECOMPILE_REFUSALS: dict[str, tuple[str, str | None]] = {
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


def _not_run_detail(error: Any) -> str:
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


def _refuse_compiler_not_offered(cfg: Any) -> None:
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
        problem, detail = _FINAL_RECOMPILE_REFUSALS[refusal.error_code]
        raise OpsError(detail or _bounded(str(refusal)), code=problem, status=400)


def _not_run_reason(verdict: dict[str, Any]) -> None:
    """Replace a ``NOT_RUN`` verdict's message with its closed-set ``not_run_reason``.

    The message and the error's text carry the compile client's words (a service
    URL, the service's body); the reason is the client's outcome kind
    (:data:`rebrew.ops_replies.NotRunReason`).
    """
    from typing import get_args

    from rebrew.ops_replies import NotRunReason

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


def _withheld(value: Any, steps: list[str]) -> Any:
    """*value* without the member *steps* lead to: a member name, ``[]`` for each item
    of a list, ``*`` for each value of an object.  Copies what it changes."""
    step, rest = steps[0], steps[1:]
    if step == "[]":
        return [_withheld(item, rest) for item in value] if isinstance(value, list) else value
    if not isinstance(value, dict):
        return value
    if step == "*":
        return {key: _withheld(item, rest) for key, item in value.items()}
    if not rest:
        return {key: item for key, item in value.items() if key != step}
    if step not in value:
        return value
    return {**value, step: _withheld(value[step], rest)}


def _declared_reply(name: str, reply: Mapping[str, Any]) -> dict[str, Any]:
    """*reply* as the op's declared reply (:mod:`rebrew.ops_replies`), not-run text closed."""
    from rebrew.ops_replies import DECLARED, WITHHELD, project

    closed = dict(reply)
    for path in WITHHELD.get(name, ()):
        closed = _withheld(closed, path.replace("[]", ".[]").split("."))
    _not_run_reason(closed)
    rows = closed.get("results")
    if isinstance(rows, list):
        closed["results"] = [dict(row) if isinstance(row, dict) else row for row in rows]
        for row in closed["results"]:
            if isinstance(row, dict):
                _not_run_reason(row)
    return project(closed, DECLARED[name], name)


def _final_recompile_refusal(result: dict[str, Any]) -> dict[str, Any]:
    """*result*, unless it is a NOT_RUN whose refusal no retry changes."""
    error = result.get("error")
    code = error.get("error_code") if isinstance(error, dict) else None
    if result.get("status") == "NOT_RUN" and code in _FINAL_RECOMPILE_REFUSALS:
        assert isinstance(error, dict)
        problem, detail = _FINAL_RECOMPILE_REFUSALS[code]
        if detail is None and error.get("type") != "CompilerNotOffered":
            # The service's own answer: its message holds the service's text.
            detail = _SERVICE_WITHDRAWN_DETAIL
        raise OpsError(detail or _bounded(str(error.get("message", ""))), code=problem, status=400)
    return result


def _toolchain_rejected(diagnostics: str, roots: Iterable[Path] = ()) -> OpsError:
    """The toolchain ran and rejected the source: 422 with its diagnostics, no verdict.

    The diagnostics keep their lines; a path under one of *roots* is named
    relative to it (:func:`_without_host_paths`).
    """
    detail = _bounded_lines(_without_host_paths(diagnostics, roots))
    return OpsError(detail, code=TOOLCHAIN_REJECTED, status=422)


class _Cancellation:
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
_CANCELLATION: ContextVar[_Cancellation | None] = ContextVar(
    "rebrew_ops_cancellation", default=None
)

#: Where the running call's progress goes, ``(done, total)`` per new count:
#: set by a transport that carries it (``serve`` to a caller accepting
#: :data:`PROGRESS_MEDIA_TYPE`, ``ops call`` with :data:`DISPATCH_PROGRESS_FD_ENV`).
#: ``run_rebrew`` relays its child command's counts there.
_PROGRESS: ContextVar[Callable[[int, int], None] | None] = ContextVar(
    "rebrew_ops_progress", default=None
)


def progress_frame(done: int, total: int) -> bytes:
    """One progress line of a stream or of ``ops call``'s progress descriptor."""
    return json.dumps({"progress": {"done": done, "total": total}}).encode("utf-8") + b"\n"


def _check_cancelled() -> None:
    """Raise the running call's refusal once it is cancelled or past its deadline."""
    cancellation = _CANCELLATION.get()
    if cancellation is not None:
        cancellation.check()


def error_body(
    code: str, detail: str, status: int, remote_compile: dict[str, int] | None = None
) -> bytes:
    """The refusal reply both transports write; a compiling op's carries its ``remote_compile``."""
    from rebrew.utils import strip_bidi_format

    return json.dumps(
        {
            "error": code,
            "detail": strip_bidi_format(detail),
            "status": status,
            **({} if remote_compile is None else {"remote_compile": remote_compile}),
        }
    ).encode("utf-8")


def _bounded(text: str) -> str:
    """*text* on one line, cut at :data:`DETAIL_MAX_CHARS`."""
    from rebrew.utils import strip_bidi_format, truncate_text

    return truncate_text(" ".join(strip_bidi_format(text).split()), DETAIL_MAX_CHARS)


def _bounded_lines(text: str) -> str:
    """*text* line by line, each line's whitespace collapsed and blank lines dropped, cut at
    :data:`DETAIL_MAX_CHARS`: a compiler's diagnostics stay one per line."""
    from rebrew.utils import strip_bidi_format, truncate_text

    lines = (" ".join(line.split()) for line in strip_bidi_format(text).splitlines())
    return truncate_text("\n".join(line for line in lines if line), DETAIL_MAX_CHARS)


#: A URL in failure text; its query string can be a presigned credential.
_URL_TEXT = re.compile(r"https?://[^\s'\"<>]+")
#: An absolute POSIX path in failure text, not the tail of a relative one.
_ABSOLUTE_PATH_TEXT = re.compile(r"(?<![\w.~/-])/(?:[\w.@+~-]+/)*[\w.@+~-]+")


def _without_host_paths(text: str, roots: Iterable[Path] = ()) -> str:
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
#: ``(step, exception)``: set by :func:`_step`, read by the dispatcher.
_FAILED_STEP: ContextVar[list[tuple[str, BaseException]] | None] = ContextVar(
    "rebrew_ops_failed_step", default=None
)


@contextlib.contextmanager
def _step(what: str) -> Iterator[None]:
    """Name what the running op is doing, for the refusal of a failure nothing else explains.

    The innermost step an exception leaves is the one recorded; *what* reads
    after "failed while" (``"staging the retained snapshot"``).
    """
    try:
        yield
    except Exception as exc:
        failed = _FAILED_STEP.get()
        if failed is not None and (not failed or failed[0][1] is not exc):
            failed[:] = [(what, exc)]
        raise


def _failure_detail(config: WorkerConfig, name: str, exc: BaseException) -> str:
    """The refusal of a failure nothing else explained: its step and its message, no host path."""
    failed = _FAILED_STEP.get() or []
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
    return _bounded(f"{name} failed{where}: {_without_host_paths(message, roots)}")


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
        if has_lone_surrogate(value):
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
    if origin is types.UnionType:
        # ``T | None``: JSON null is None, anything else is a T.
        (inner,) = [arg for arg in typing.get_args(hint) if arg is not type(None)]
        return None if value is None else _decode(value, inner, where)
    if origin is tuple:
        items = typing.get_args(hint)
        if type(value) is not list or len(value) != len(items):
            raise _invalid(f"{where} must be an array of {len(items)} items")
        return tuple(
            _decode(entry, item, f"{where}[{index}]")
            for index, (entry, item) in enumerate(zip(value, items, strict=True))
        )
    return parse_request(hint, value, where)


#: Field type hints and fields per request dataclass, one entry per class.
_REQUEST_FIELDS: dict[type, tuple[dict[str, object], dict[str, dataclasses.Field[object]]]] = {}


def _request_fields(
    cls: type,
) -> tuple[dict[str, object], dict[str, dataclasses.Field[object]]]:
    """The field type hints and the fields of the request dataclass *cls*.

    Both are fixed when the class is defined, so they are resolved on its first
    parse: a nested request type (one per retained file or readset row)
    resolved its hints once per value. Two threads racing a first parse store
    equal entries.
    """
    found = _REQUEST_FIELDS.get(cls)
    if found is None:
        found = _REQUEST_FIELDS.setdefault(
            cls,
            (typing.get_type_hints(cls), {spec.name: spec for spec in fields(cls)}),
        )
    return found


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
            code=COVERAGE_INPUT_UNVERIFIED,
            status=409,
        )
    hints, known = _request_fields(cls)
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
    try:
        return cls(**values)
    except ValueError as exc:  # a type that checks its own values (Attribution)
        raise _invalid(f"{where}: {exc}") from None


# ---------------------------------------------------------------------------
# Binary and project references
# ---------------------------------------------------------------------------


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
    # A well-formed key the filestore cannot serve is this worker's storage (a
    # missing mount, a corrupt or substituted object), not the request: 500.
    try:
        path = root.joinpath(*parts).resolve(strict=True)
    except FileNotFoundError:
        raise OpsError("no stored file for the key") from None
    if not path_is_relative_to(path, root) or not path.is_file():
        raise OpsError("the key does not name a stored file")
    if sha256_file(path) != wanted:
        raise OpsError("the stored file does not match its sha256")
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
    # request thread (and its worker slot) for the kernel timeout. A timed-out
    # resolver cannot be cancelled, so retain at most DNS_RESOLUTION_LIMIT of
    # them and refuse further URL lookups until one finishes.
    slots = _DNS_SLOTS
    if not slots.acquire(blocking=False):
        raise OpsError("url host cannot be resolved")
    _result: list[Any] = []
    _error: list[BaseException] = []

    def _resolve() -> None:
        try:
            _result.append(_socket.getaddrinfo(hostname, 443, type=_socket.SOCK_STREAM))
        except BaseException as exc:  # propagated below; resolve runs on a thread
            _error.append(exc)
        finally:
            slots.release()

    _thread = threading.Thread(target=_resolve, daemon=True)
    try:
        _thread.start()
    except BaseException:
        slots.release()
        raise
    _thread.join(DNS_TIMEOUT_SECONDS)
    if _thread.is_alive():
        raise OpsError("url host cannot be resolved")
    if _error:
        if isinstance(_error[0], OSError):
            raise OpsError("url host cannot be resolved") from None
        raise _error[0]
    infos = _result[0]
    if not infos:
        raise OpsError("url host cannot be resolved")
    pinned = ""
    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            raise OpsError("url host cannot be resolved") from None
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
                    raise OpsError(f"url answered HTTP {response.status_code}")
                raise _invalid(f"url answered HTTP {response.status_code}")
            declared = response.headers.get("Content-Length", "")
            if declared.isdigit() and int(declared) > limit:
                raise _invalid(f"url names more than {limit} bytes")
            for chunk in response.iter_bytes(DOWNLOAD_CHUNK_BYTES):
                _check_cancelled()
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
        raise OpsError(f"url download failed: {exc}") from exc
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
    _check_cancelled()
    if key:
        with _step("reading a stored file"):
            path = stored_file(config, key, sha256)
        yield path
        return
    wanted = _sha256(sha256)
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    handle, name = tempfile.mkstemp(prefix="download-", dir=scratch)
    os.close(handle)
    path = Path(name)
    try:
        with _step("downloading a stored file"):
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
        if binary is not None and binary.is_file() and sha256_file(binary) == wanted:
            return load_config(root, target=name)
    raise _invalid("no target of project_dir has a binary with that sha256")


def _inside(base: Path, relative: str, what: str, scope: str = "the worker workspace") -> Path:
    """*relative* resolved under *base*; an absolute path or an escape is refused."""
    if not relative or Path(relative).is_absolute():
        raise _invalid(f"{what} must be a relative path")
    path = (base / relative).resolve()
    if path == base or not path_is_relative_to(path, base):
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
            or entry.size > MAX_READSET_FILE_BYTES
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
            if not destination.is_file() or sha256_file(destination) != sha256:
                raise _invalid("retained target binary conflicts with snapshot")
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(binary, destination)
        resolved = target_binary(root, target)
        if (
            resolved is None
            or resolved.resolve() != destination
            or sha256_file(destination) != sha256
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


def _listing_reply(text: str) -> dict[str, Any]:
    """A listing op's reply: the text and the renderer that wrote it
    (:func:`rebrew.asm.listing_renderer`), under which the backend caches it."""
    from rebrew.asm import listing_renderer

    return {"text": text, "renderer": listing_renderer()}


def _nasm_listing(code: bytes, va: int, read_image: ImageReader | None = None) -> str:
    from rebrew.asm import disassemble_to_nasm

    source, _stats = disassemble_to_nasm(code, va, f"func_{va:08X}", read_image)
    return source + "\n"


def _asm_listing(
    code: bytes, va: int, cs_arch: int, cs_mode: int, read_image: ImageReader | None = None
) -> str:
    """One ``mnemonic operands`` line per instruction and jump-table entry.

    A table starts with its ``jump_table_<VA>:`` label; bytes that decode as
    no instruction are left out.
    """
    from rebrew.cfg_ged import listing_items, table_label

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
        raise _invalid(f"format must be one of {', '.join(sorted(DISASM_FORMATS))}")
    if req.size <= 0:
        raise _invalid(f"size must be positive, got {req.size}")
    if req.size > DISASSEMBLE_MAX_BYTES:
        raise _invalid(f"size must be at most {DISASSEMBLE_MAX_BYTES} bytes, got {req.size}")
    va = _address(req.va)
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    if req.arch and req.arch != cfg.arch:
        if req.arch not in ARCH_PRESETS:
            raise _invalid(f"unsupported arch: {_bounded(req.arch)}")
        cfg = dataclasses.replace(cfg, arch=req.arch)
    if req.format == "hex":
        from rebrew.asm import hex_disassembly

        return _listing_reply(hex_disassembly(cfg, va, req.size))
    if req.format == "nasm" and cfg.arch != NASM_ARCH:
        raise _invalid(f"NASM source covers {NASM_ARCH} only and this binary is {cfg.arch}")
    from rebrew.formats.binary_loader import extract_raw_bytes

    code = extract_raw_bytes(cfg.target_binary, va, req.size)
    if not code:
        raise _invalid(f"no file bytes at 0x{va:x}")
    read_image = functools.partial(extract_raw_bytes, cfg.target_binary)
    if req.format == "nasm":
        return _listing_reply(_nasm_listing(code, va, read_image))
    return _listing_reply(_asm_listing(code, va, cfg.capstone_arch, cfg.capstone_mode, read_image))


def instruction_listing(config: WorkerConfig, req: AddressRequest) -> dict[str, Any]:
    """The comparison of ``[va, va+size)`` with itself, in ``rebrew test --instructions``'s shape.

    It stands in for an ``EXACT`` rebuild, whose comparison no verification
    records: every row is ``equal``.
    """
    from rebrew.formats.binary_loader import extract_raw_bytes
    from rebrew.instruction_diff import MAX_BYTES, instruction_diff

    if not 1 <= req.size <= MAX_BYTES:
        raise _invalid(f"size must be 1 to {MAX_BYTES} bytes, got {req.size}")
    va = _address(req.va)
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    code = extract_raw_bytes(cfg.target_binary, va, req.size)
    if not code:
        raise _invalid(f"no file bytes at 0x{va:x}")
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
            raise _invalid(f"unsupported arch: {_bounded(req.arch)}")
    va = _address(req.va)
    if req.arch in ("", NASM_ARCH):
        return _listing_reply(_nasm_listing(req.code, va))
    return _listing_reply(_asm_listing(req.code, va, *_capstone_for(req.arch)))


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
    from rebrew.analysis import is_xref_kind
    from rebrew.xrefs import build_xrefs_payload

    if len(req.kinds) > XREFS_MAX_KINDS:
        raise _invalid(f"kinds holds {len(req.kinds)} entries, over the limit of {XREFS_MAX_KINDS}")
    for kind in req.kinds:
        if not is_xref_kind(kind):
            raise _invalid(f"kinds: {_bounded(repr(kind))} is no reference kind")
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    return build_xrefs_payload(cfg.target_binary, _address(req.va), req.kinds or None)


#: Call scans (``call_references`` answers) by the sha256 of the scanned binary's bytes, newest
#: use last. A function page reads its binary's scan on every view, and one worker serves a few
#: binaries at a time; the bound guards a long-lived worker walking many images.
_CALL_SCANS_MAX = 8
_call_scans: dict[str, dict[str, Any]] = {}
_call_scans_lock = threading.Lock()
#: One live scan per binary digest.  Concurrent cold requests otherwise each
#: repeat the full disassembly and import parse before any can publish a row.
#: Waiters stay with the leader until its ``finally`` publishes the outcome;
#: timing out and claiming the key would duplicate a slow scan.
_call_scan_inflight: dict[str, threading.Event] = {}


def call_references(config: WorkerConfig, req: ProjectRequest) -> dict[str, Any]:
    """Scan one analysed binary for calls, jumps and import slots.

    The answer is a function of the binary's bytes alone, so it is kept by their sha256, read
    before the scan and again after it: a scan whose file changed meanwhile is answered but not
    kept. Callers serialize the answer and never change it.
    """
    from rebrew.analysis import scan_references
    from rebrew.formats.binary_loader import load_binary
    from rebrew.formats.import_table import parse_import_table

    cfg = target_config(project_root(config, req.project_dir), "")
    binary = Path(cfg.target_binary)
    digest = sha256_file(binary)
    while True:
        with _call_scans_lock:
            kept = _call_scans.pop(digest, None)
            if kept is not None:
                _call_scans[digest] = kept
                return kept
            event = _call_scan_inflight.get(digest)
            if event is None:
                event = threading.Event()
                _call_scan_inflight[digest] = event
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
            with _call_scans_lock:
                _call_scans[digest] = answer
                if len(_call_scans) > _CALL_SCANS_MAX:
                    _call_scans.pop(next(iter(_call_scans)))
        return answer
    finally:
        with _call_scans_lock:
            if _call_scan_inflight.get(digest) is event:
                del _call_scan_inflight[digest]
        event.set()


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


def _no_decompilation(backend: str, va: int) -> OpsError:
    """The decompiler *backend* (or every one ``auto`` tried) gave no code for *va*."""
    return OpsError(
        f"decompiler '{backend}' produced no code for 0x{va:x}", code=NO_DECOMPILATION, status=422
    )


def decompile(config: WorkerConfig, req: DecompileRequest) -> dict[str, Any]:
    """Decompiled source of ``va``; ``named`` applies the project's known struct names."""
    from rebrew.analysis import is_inside
    from rebrew.decompiler import fetch_decompilation
    from rebrew.formats.binary_loader import load_binary
    from rebrew.ghidra import McpError

    if req.backend not in DECOMPILER_BACKENDS:
        raise _invalid(f"unsupported decompiler backend: {req.backend}")
    _refuse_unoffered_decompiler(req.backend)
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    va = _address(req.va)
    if not is_inside(load_binary(cfg.target_binary), va):
        raise _invalid(f"VA 0x{va:x} is outside the binary image")
    try:
        code, backend = fetch_decompilation(req.backend, cfg.target_binary, va, cfg.root)
    except McpError as exc:
        raise _ghidra_outage(exc) from None
    if not code:
        raise _no_decompilation(req.backend, va)
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
    from rebrew.config import load_config
    from rebrew.ghidra import McpError
    from rebrew.struct_recover import NoDecompilationError, recover_project_structs

    if req.decompiler not in DECOMPILER_BACKENDS:
        raise _invalid(f"unsupported decompiler backend: {req.decompiler}")
    if req.limit < 0:
        raise _invalid(f"limit must not be negative, got {req.limit}")
    _refuse_unoffered_decompiler(req.decompiler)
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
        raise _ghidra_outage(exc) from None


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
    to nothing are left out; the rest keep archive order.  ``boundaries`` is
    :data:`rebrew.gen_flirt_pat.FUNCTION_BOUNDARIES`, the rule the functions
    were cut by: rows stored under another value describe other functions.
    """
    from rebrew.asm import disassemble_to_nasm
    from rebrew.cfg_ged import apply_self_relocations
    from rebrew.formats.archives import parse_archive
    from rebrew.formats.binary_loader import capstone_config_for, object_arch
    from rebrew.formats.binary_model import BinaryInfo
    from rebrew.gen_flirt_pat import FUNCTION_BOUNDARIES, parse_coff_obj, parse_elf_obj

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
                        _bounded(str(exc)), code=COVERAGE_INPUT_UNVERIFIED, status=409
                    ) from None
                checked_coverage_input(snapshot, req)
                kinds: dict[str, list[str]] = result.pop("kinds")
                entries: list[dict[str, Any]] = []
                size = 0
                for path in sorted(out.rglob("*")):
                    if path.is_symlink():
                        raise _report_output_invalid("the generated report holds a symlink")
                    if path.is_file():
                        size += path.stat().st_size
                        if len(entries) >= MAX_REPORT_FILES or size > MAX_REPORT_BYTES:
                            raise _report_output_invalid(
                                f"the generated report is over {MAX_REPORT_FILES} files "
                                f"or {MAX_REPORT_BYTES} bytes"
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
                    raise _report_output_invalid("the generated report holds no file")
                return {**result, "out": str(out), "manifest": entries}
        except BaseException:
            shutil.rmtree(out)
            raise
    if req.coverage_input.version or req.coverage_input_digest or req.verification_records:
        raise _invalid("coverage input requires a retained snapshot")
    return generate_report(load_config(project_root(config, req.project_dir)), out)


def security_scan(config: WorkerConfig, req: SecurityScanRequest) -> dict[str, Any]:
    """Rule findings over the default target's reversed sources at ``min_severity`` or above."""
    from rebrew.config import load_config
    from rebrew.security_scan import SEVERITY_ORDER, filter_by_severity
    from rebrew.security_scan import security_scan as scan

    if req.min_severity not in SEVERITY_ORDER:
        raise _invalid(f"min_severity must be one of {', '.join(SEVERITY_ORDER)}")
    cfg = load_config(project_root(config, req.project_dir))
    root, directory = cfg.root.resolve(), cfg.reversed_dir.resolve()
    if not directory.is_relative_to(root):
        raise _invalid("the reversed sources lie outside the project")
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
    from rebrew.compiler.temp_dirs import remove_temp_dir, writable_temp_dir
    from rebrew.metadata.bindings import note_skipped_records

    directory = writable_temp_dir("rebrew-skipped-records-")
    skipped_file = directory / "skipped.json"
    try:
        return _run_rebrew_child(
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


def _run_rebrew_child(
    arguments: list[str],
    project: Path,
    timeout: int,
    *,
    outcome_exit: bool,
    skipped_file: Path,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """:func:`run_rebrew` with the file the child writes its skipped records to."""
    from rebrew.compiler.compile import CALL_DEADLINE_ENV
    from rebrew.metadata.bindings import SKIPPED_RECORDS_ENV

    name = " ".join(word for word in arguments[:2] if not word.startswith("-"))
    cancellation = _CANCELLATION.get()
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
    sink = _PROGRESS.get()
    remote = current_remote_compiles()
    pipe = ProgressPipe() if sink is not None and os.name == "posix" else None
    try:
        with _step(f"starting rebrew {name}"):
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
        stdout, stderr = _communicate(process, timeout, cancellation, relay)
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
                return _final_recompile_refusal(printed)
    if refused:
        kind, message = _command_refusal(stderr)
        if kind == "usage":
            # The command rejected its input (clispec ``usage``): the caller's request.
            raise _invalid(
                _bounded(f"rebrew {name} refused: {_without_host_paths(message, [project])}")
            )
        from rebrew.cli import (
            BINDING_CONFLICT_KIND,
            COMPILER_NOT_OFFERED_KIND,
            TOOLCHAIN_REJECTED_KIND,
        )

        if kind == BINDING_CONFLICT_KIND:
            # The child names the record by its key; _refusing_disagreeing_records answers it.
            raise BindingConflictError(_bounded(message))
        if kind == TOOLCHAIN_REJECTED_KIND:
            raise _toolchain_rejected(message, [project])
        if kind == COMPILER_NOT_OFFERED_KIND:
            # The child's message is the refusal's own: a withdrawn compiler's reason.
            raise OpsError(_bounded(message), code=COMPILER_NOT_OFFERED, status=400)
        logger.error(
            "rebrew %s exited %d: %s", name, process.returncode, _escape_log_text(stderr.strip())
        )
        raise OpsError(_bounded(f"rebrew {name} failed: {_without_host_paths(message, [project])}"))
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError:
        logger.exception(
            "rebrew %s printed no JSON report: %s", name, _escape_log_text(stderr.strip())
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


def _communicate(
    process: subprocess.Popen[str],
    timeout: float,
    cancellation: _Cancellation | None,
    relay: Callable[[], None] | None = None,
) -> tuple[str, str]:
    """``process.communicate(timeout=timeout)`` that also ends when the call is cancelled.

    Raises ``subprocess.TimeoutExpired`` at *timeout*, and the call's
    :class:`OpsError` once *cancellation* is set; the caller stops the child
    either way.  *relay* forwards the child's progress at each check and once
    the child is done.
    """
    deadline = time.monotonic() + timeout
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
        raise _invalid("project_id must be at most 256 UTF-8 bytes without NUL")
    workspace = config.require_workspace()
    if not project_id:
        relative = f"projects/{_sha256(sha256)}"
    else:
        scope = hashlib.sha256(project_id.encode("utf-8")).hexdigest()
        relative = f"projects/scopes/{scope}/{_sha256(sha256)}"
    if _inside(workspace, relative, "analysis project") != workspace / relative:
        raise _invalid("analysis project must not traverse symlinks")
    return relative


def analyse(config: WorkerConfig, req: AnalyseRequest) -> dict[str, Any]:
    """Onboard a stored binary into its project-scoped workspace and report its coverage.

    A second run re-discovers into the same project.  ``intake`` is the onboarding report;
    ``discovery_rule`` is :data:`rebrew.discover.DISCOVERY_RULE`, the rule the functions
    were discovered under.
    """
    workspace = config.require_workspace()
    relative = _binary_project(config, req.project_id, req.sha256)
    project = workspace / relative
    with binary_file(config, req.file_key, req.url, req.sha256, "file_key") as binary:
        project.mkdir(parents=True, exist_ok=True)
        if _inside(workspace, relative, "analysis project") != project:
            raise _invalid("analysis project must not traverse symlinks")
        # A file rebrew cannot parse is the caller's (422), refused before the intake
        # child degrades to string evidence and finds no functions.  The capture
        # below reads the same parse from load_binary's cache.
        load_binary(binary)
        intake = _run_intake(binary, project, target_name(req.name))
        capture, report = capture_fresh_analysis(config, binary, req.sha256, target_name(req.name))
        for item in report["targets"]:
            for field in ("document", "path"):
                if item[field]:
                    item[field] = str(project / item[field])
    from rebrew.discover import DISCOVERY_RULE

    return {
        **report,
        "project": str(project),
        "intake": intake,
        "analysis_capture": capture,
        "discovery_rule": DISCOVERY_RULE,
    }


def _fresh_sqlite_metadata(root: Path, target: str, scratch: Path) -> dict[str, Any]:
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
        raise _capture_failed("fresh analysis requires an independent TOML intake")
    confined_snapshot_config(cfg, root)
    logical = {
        store.path.relative_to(root).as_posix(): store.digest()
        for store in project_metadata_stores(root, recursive=True)
    }
    if "rebrew-functions.toml" not in logical:
        raise _capture_failed("fresh analysis requires function metadata before import")
    # One migration pinned to its input digest: hashing the stores costs nothing beside the
    # format-preserving parse a preview would add, and a change in between still refuses.
    migrate_metadata(cfg, "sqlite", expected_digest=migration_input_digest(cfg, "sqlite"))
    cfg = load_config(root, target=target)
    if cfg.metadata_read_backends != ("sqlite",) or cfg.metadata_write_backends != ("sqlite",):
        raise _capture_failed("fresh analysis metadata import did not select SQLite")
    with tempfile.TemporaryDirectory(prefix="metadata-snapshot-", dir=scratch) as temp:
        snapshot = snapshot_metadata_database(root, Path(temp) / DATABASE_FILENAME)
        documents = metadata_database_documents(snapshot)
        if documents != logical:
            raise _capture_failed("fresh analysis metadata import changed logical documents")
        os.replace(snapshot, root / DATABASE_FILENAME)
    descriptor = describe_metadata(root, exclusive=False)
    if {item["path"]: item["logical_sha256"] for item in descriptor["documents"]} != logical:
        raise _capture_failed("fresh analysis metadata changed after import")
    return descriptor


def capture_fresh_analysis(
    config: WorkerConfig, binary: Path, sha256: str, target: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Capture the complete baseline readset from a new, independent intake."""
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="analysis-capture-", dir=scratch) as temp:
        root = Path(temp).resolve()
        _run_intake(binary, root, target)
        for path in root.rglob("*"):
            if path.is_symlink():
                raise _capture_failed("fresh analysis capture contains a symlink")
        _check_cancelled()
        try:
            metadata = _fresh_sqlite_metadata(root, target, scratch)
        except OpsError:
            raise
        except (OSError, ValueError, RebrewError) as exc:
            raise _capture_failed(f"fresh analysis metadata migration failed: {exc}") from exc
        _check_cancelled()
        return capture_project(root, sha256, target, metadata, "fresh analysis")


def capture_project(
    root: Path, sha256: str, target: str, metadata: dict[str, Any] | None, what: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Capture the complete readset of the project at *root* for *target* and report it.

    *metadata* is the SQLite metadata descriptor already selected in *root*;
    *what* names the project in refusals ("fresh analysis", "project import").
    """
    from rebrew.config import inventory_path_for, load_config
    from rebrew.coverage_project import coverage_inputs
    from rebrew.sources import iter_headers, iter_sources

    cfg = load_config(root, target=target)
    confined_snapshot_config(cfg, root)
    if cfg.raw_link is not None:
        raise _capture_failed(f"{what} capture cannot include an unverified raw link")
    if not cfg.target_binary.is_file() or sha256_file(cfg.target_binary) != sha256:
        raise _invalid(f"{what} binary does not match the request")
    inventory = inventory_path_for(cfg.reversed_dir, cfg).resolve()
    source_paths = {p.resolve() for p in iter_sources(cfg.reversed_dir, cfg)}
    source_paths.update(p.resolve() for p in iter_headers(cfg.reversed_dir, cfg))
    paths = {Path(entry[0]) for entry in coverage_inputs(cfg)}
    entries: list[dict[str, Any]] = []
    total = 0
    captured_count = sum(1 for path in paths if path.resolve().is_relative_to(root))
    if captured_count > MAX_READSET_FILES:
        raise _readset_limit(f"{what} capture", captured_count, MAX_READSET_FILES)
    for path in sorted(
        paths, key=lambda value: str(value).encode("utf-8", errors="surrogateescape")
    ):
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            if path.exists() or path.is_symlink():
                raise _capture_failed(f"{what} reads an ambient input")
            continue
        relative = resolved.relative_to(root).as_posix()
        if path.is_symlink() or relative == ".":
            raise _capture_failed(f"invalid {what} readset")
        if not path.exists():
            entries.append(
                {"path": relative, "kind": "absent", "size": 0, "digest": "", "data": ""}
            )
            continue
        if not path.is_file():
            raise _capture_failed(f"{what} readset contains an unsupported directory")
        if "verify_cache" in path.name:
            raise _capture_failed(f"{what} capture must not contain verification cache")
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
            raise _readset_limit(f"{what} input {relative}", size, MAX_READSET_FILE_BYTES, "bytes")
        if total > MAX_READSET_BYTES:
            raise _readset_limit(f"{what} capture", total, MAX_READSET_BYTES, "bytes")
        data = path.read_bytes()
        if len(data) != size:
            raise _capture_failed(f"{what} input changed during capture")
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
    report = project_report(root, None, include_source=True, only=target)
    # The report is an assertion by this worker, so its complete captured
    # readset must still match after the report was constructed.
    current_paths = {Path(entry[0]) for entry in coverage_inputs(cfg)}
    current_sources = {p.resolve() for p in iter_sources(cfg.reversed_dir, cfg)}
    current_sources.update(p.resolve() for p in iter_headers(cfg.reversed_dir, cfg))
    if current_paths != paths or current_sources != source_paths:
        raise _capture_failed(f"{what} input changed during reporting")
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
                raise _capture_failed(f"{what} report names a source it cannot capture")
            size = path.stat().st_size
            total += size
            if size > MAX_READSET_FILE_BYTES:
                raise _readset_limit(
                    f"{what} input {relative}", size, MAX_READSET_FILE_BYTES, "bytes"
                )
            if total > MAX_READSET_BYTES:
                raise _readset_limit(f"{what} capture", total, MAX_READSET_BYTES, "bytes")
            if len(by_path) >= MAX_READSET_FILES:
                raise _readset_limit(f"{what} capture", len(by_path) + 1, MAX_READSET_FILES)
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
            raise _capture_failed(f"{what} input changed during reporting")
        if captured["kind"] == "absent":
            if path.exists():
                raise _capture_failed(f"{what} input changed during reporting")
        elif (
            not path.is_file()
            or path.stat().st_size != captured["size"]
            or sha256_file(path) != captured["digest"]
        ):
            raise _capture_failed(f"{what} input changed during reporting")
    selected = None
    if inventory.is_relative_to(root):
        relative_inventory = inventory.relative_to(root).as_posix()
        selected = next((entry for entry in entries if entry["path"] == relative_inventory), None)
    if selected is not None and selected["kind"] == "file" and selected.get("role") == "analysis":
        project_config = next(
            (entry for entry in entries if entry["path"] == "rebrew-project.toml"), None
        )
        if project_config is None or project_config["kind"] != "file":
            raise _capture_failed(f"{what} configuration is not captured")
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
                raise _capture_failed(f"{what} input changed during reporting")
        if not cfg.target_binary.is_file() or sha256_file(cfg.target_binary) != sha256:
            raise _capture_failed(f"{what} input changed during reporting")
        current = load_config(root, target=target)
        if inventory_path_for(current.reversed_dir, current).resolve() != inventory:
            raise _capture_failed(f"{what} inventory changed during reporting")
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
            raise _capture_failed(f"{what} report has a different target")
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
                    raise _capture_failed(f"invalid {what} report identity")
                entry = {"va": va, "name": name}
                if size_field:
                    size = row["size"]
                    if type(size) is not int or not 0 <= size <= 2**63 - 1:
                        raise _capture_failed(f"invalid {what} report extent")
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
            raise _capture_failed(f"{what} report path already exists")
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
                raise _import_refused(
                    f"rebrew-project.toml sets [{where}] {key}; an imported project compiles"
                    " only through the hosted compile service, so remove it"
                )
    try:
        routes = backend_routes(raw.get("metadata", {}))
    except ValueError as exc:
        raise _import_refused(f"rebrew-project.toml [metadata]: {exc}") from None
    if routes != (("toml",), ("toml",)):
        raise _import_refused(
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
        raise _import_refused(
            f"no target in rebrew-project.toml names a binary inside the archive with sha256 {sha256}"
            " (the project binary); include that exact file at the target's binary path"
        )
    if len(matches) > 1:
        raise _import_refused(f"targets {', '.join(matches)} all name the project binary; keep one")
    entry = targets_table(raw)[matches[0]]
    if entry.get("raw_link"):
        raise _import_refused(
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
            raise _import_refused(str(exc)) from None
        _check_cancelled()
        try:
            raw = read_config(root)
        except RebrewError as exc:
            raise _invalid_project_config(root, exc) from None
        _import_settings_refusal(raw)
        target = _import_target(root, raw, req.sha256)
        try:
            cfg = load_config(root, target=target)
        except ConfigError as exc:
            raise _invalid_project_config(root, exc) from None
        try:
            confined_snapshot_config(cfg, root)
        except OpsError as exc:
            raise _import_refused(str(exc)) from None
        if not metadata_store(root / "rebrew-functions.toml").exists():
            raise _import_refused("the archive has no rebrew-functions.toml function metadata")
        module = target_module(cfg)
        _check_cancelled()
        try:
            dropped = scope_metadata_to_module(cfg, module)
            _check_cancelled()
            metadata = _fresh_sqlite_metadata(root, target, scratch)
        except OpsError:
            raise
        except (OSError, ValueError, RebrewError) as exc:
            detail = str(exc).replace(f"{root}{os.sep}", "")
            raise _import_refused(f"the archive's metadata cannot be imported: {detail}") from None
        _check_cancelled()
        capture, report = capture_project(root, req.sha256, target, metadata, "project import")
        # The last check: past it the import replaces the binary's project.
        _check_cancelled()
        project = workspace / relative
        project.parent.mkdir(parents=True, exist_ok=True)
        if _inside(workspace, relative, "analysis project") != project:
            raise _invalid("analysis project must not traverse symlinks")
        # The earlier project leaves the scoped path before the new one takes it, and outside the
        # temporary directory: a file the worker may not unlink must not fail the finished import.
        replaced = None
        if project.exists():
            replaced = Path(tempfile.mkdtemp(prefix="replaced-", dir=scratch))
            project.rename(replaced / project.name)
        root.rename(project)
    if replaced is not None:
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

    _check_manifest_size(files)
    paths = {entry.path for entry in files}
    if len(paths) != len(files) or any(not portable_path_parts(path) for path in paths):
        raise _invalid("duplicate or invalid file set path")
    if "rebrew-project.toml" not in paths:
        raise _invalid("a file set requires rebrew-project.toml")
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="file-set-", dir=scratch) as temp:
        root = Path(temp).resolve()
        _stage_retained_files(config, root, files, exclusive=True)
        yield root


def _metadata_answer[T](read: Callable[[], T]) -> T:
    """Run a metadata read, answering 400 for a set rebrew cannot read."""
    try:
        return read()
    except (OSError, ValueError, RebrewError) as exc:
        raise _invalid(f"invalid metadata set: {exc}") from exc


def release(_config: WorkerConfig, _req: ReleaseRequest) -> dict[str, Any]:
    """The engine's rebrew release and the SHA-256 of the dispatch schema it serves.

    A caller compares ``schema_sha256`` with the schema it was built against and
    refuses an engine that serves another before it relies on any other op.
    """
    from rebrew import __version__

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
    ``discovery_rule`` is :data:`rebrew.discover.DISCOVERY_RULE`, the rule
    ``rebrew.analyse`` discovers functions under now.  ``decompilers`` is, for
    every decompiler the ops name but ``auto``, whether it can run on this engine
    (:func:`engine_decompilers`; checked again at most every 30 s): ``available``,
    ``not-installed`` or ``unreachable``, with a ``reason`` when it is not available.
    """
    from rebrew.discover import DISCOVERY_RULE
    from rebrew.verify_cache import CACHE_FILENAMES
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
    from rebrew.c_rename import IdentifierRenameRefused, ParsedSource
    from rebrew.c_rename import rename_identifier as rename
    from rebrew.rename_ops import is_valid_new_name

    if not req.renames:
        raise _invalid("renames must not be empty")
    if len(req.renames) > MAX_IDENTIFIER_RENAMES:
        raise _invalid(f"more than {MAX_IDENTIFIER_RENAMES} renames")
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
            raise _invalid_project_config(root, exc) from exc
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
            files = []
            for relative in paths:
                data = (carried / relative).read_bytes()
                if len(data) > MAX_READSET_FILE_BYTES:
                    raise _readset_limit(
                        f"carried metadata {relative}", len(data), MAX_READSET_FILE_BYTES, "bytes"
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
    root: Path, snapshots: Path | None, *, include_source: bool = False, only: str | None = None
) -> dict[str, Any]:
    """The backend's ``ProjectReport`` of *root*: targets, functions and import stubs.

    Live coverage is read unless *snapshots* names a portable export directory.
    *only*, when set, reports that one target; the other targets' coverage may fail.
    """
    from rebrew.config import load_config
    from rebrew.coverage_project import load_project_coverage
    from rebrew.coverage_toml import load_coverage_from
    from rebrew.discover import elf_function_symbols
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
        raise _invalid("the project has no coverage targets")
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
            if row.markerType in _DATA_MARKERS:
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
# Reconstruction ops on a project
#
# Each names the target by its binary's sha256 (empty: the default target).
# Ops that run a rebrew command answer the JSON object it prints; the source
# and output paths they take are project-relative and must stay inside it.
# ---------------------------------------------------------------------------


def _flag(enabled: bool, option: str) -> list[str]:
    return [option] if enabled else []


def remote_header_refusal(cfg: Any, sources: Iterable[Path]) -> None:
    """Refuse a remote compile of a source whose project headers cannot ship.

    A remote compile ships the project headers a source reads as an include
    bundle (``compiler.compile.remote_include_bundle``; relumea ADR 0010,
    decision 4).  A source is refused before anything compiles when its
    bundle cannot be built (an ``#include`` a macro computes, a header outside
    the project root or not UTF-8, a DOS toolchain), or when sources need one
    and the configured recompile service does not accept bundles; that
    refusal names the first such source and the header it includes, and for
    several sources how many need one.  A service that cannot be asked is not
    a refusal: the compile reports that failure.  Local compiles pass.
    """
    from rebrew.compiler.compile import recompile_url

    url = recompile_url(cfg)
    if url is None:
        return
    from rebrew.compiler import toolchain as toolchain_registry
    from rebrew.compiler.compile import (
        effective_compile_flags,
        remote_bundles_supported,
        remote_include_bundle,
    )
    from rebrew.compiler.recompile_client import RecompileError

    def shown(path: Path) -> str:
        return path.relative_to(cfg.root).as_posix() if path.is_relative_to(cfg.root) else path.name

    spec = toolchain_registry.TOOLCHAINS.get(getattr(cfg, "compiler_profile", "") or "")
    first = ""
    affected = total = 0
    for source in sources:
        total += 1
        parent = source.resolve().parent
        try:
            bundle = remote_include_bundle(
                cfg,
                spec,
                source.read_text(encoding="utf-8", errors="surrogateescape"),
                effective_compile_flags(cfg, spec, "", parent),
                parent,
            )
        except RecompileError as exc:
            raise OpsError(
                _bounded(f"{shown(source)} {exc}; compile it with a local backend"),
                code=REMOTE_HEADERS,
                status=422,
            ) from None
        if bundle is None:
            continue
        affected += 1
        if not first:
            header = min(bundle.includes)
            more = len(bundle.includes) - 1
            first = f"{shown(source)} includes the project header {header}" + (
                f" and {more} more" if more else ""
            )
    if not affected or remote_bundles_supported(cfg) is not False:
        return
    extent = f"; {affected} of {total} sources read project headers" if total > 1 else ""
    raise OpsError(
        _bounded(
            f"{first}{extent}. The recompile service at {url} does not accept include bundles:"
            " upgrade it, or compile with a local backend"
        ),
        code=REMOTE_HEADERS,
        status=422,
    )


def retained_compile_refusal(cfg: Any, sources: Iterable[Path]) -> None:
    """Use only the operator-configured remote compiler and confined include flags."""
    from rebrew.compiler.compile import effective_compile_flags, extract_include_dirs

    approved = os.environ.get("REBREW_RECOMPILE_URL", "").strip()
    if not approved or cfg.recompile_url != approved:
        raise OpsError("retained compilation requires the configured private recompile service")
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
    from rebrew.flirt import SignatureFileError, parse_signature_file

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
            reference = Path(directory) / f"reference.{req.format}"
            shutil.copyfile(path, reference)
            try:
                parse_signature_file(reference)
            except SignatureFileError:
                raise OpsError(
                    f"the signatures are not a {req.format} file python-flirt reads",
                    code=MALFORMED_SIGNATURES,
                    status=422,
                ) from None
            arguments = ["library", "scan-signatures", "--json", f"--min-size={req.min_size}"]
            return run_rebrew([*arguments, *target, "--", directory], root, COMMAND_TIMEOUT_SECONDS)


def verify_function(config: WorkerConfig, req: VerifyRequest) -> dict[str, Any]:
    """Compile one source and byte-compare it to the target (``rebrew test <source> --json``).

    A mismatch is a result.  Without ``no_promote`` the comparison writes the
    function's STATUS into the project metadata, as ``rebrew test`` does.
    ``instructions`` (a candidate only) adds ``rebrew test --instructions``'s
    comparison.
    """
    from rebrew.test import run_test

    if req.candidate:
        return verify_candidate(config, req)
    if req.instructions:
        raise _invalid("instructions needs a candidate")

    root = project_root(config, req.project_dir)
    cfg = target_config(root, req.sha256)
    source = _project_file(root, req.source, "source")
    remote_header_refusal(cfg, [source])
    result = run_test(cfg, source, no_promote=req.no_promote, json_output=True)
    if "source" in result:
        # The project's path for it, as a candidate's report names it: the host's never leaves.
        result["source"] = req.source
    return _final_recompile_refusal(result)


def verify_candidate(config: WorkerConfig, req: VerifyRequest) -> dict[str, Any]:
    """Compare candidate text in a private snapshot of retained inputs.

    The candidate is judged by the bytes it compiles to, whatever it names its function: when the
    name differs from the registry's, the snapshot's registry follows it for the run, as an apply's
    does, and nothing leaves the op but the report.
    """
    return _run_candidate(config, req, apply=False)


#: The largest candidate text, in UTF-8 bytes, a verification or an apply compiles.
CANDIDATE_MAX_BYTES = 2_000_000


#: The function registry of a TOML project. A SQLite project's registry is its
#: ``rebrew-metadata.sqlite3`` store; an applied candidate returns its source and
#: the registry its config reads, and nothing else leaves the op.
APPLY_METADATA_FILE = "rebrew-functions.toml"


def apply_candidate(config: WorkerConfig, req: ApplyCandidateRequest) -> dict[str, Any]:
    """Promote an exact candidate in a private snapshot and return the files that changed.

    The candidate takes the function's address anchor, ``rebrew test`` runs in promote mode with the attempt's
    flags, so rebrew's own writers record STATUS, SIZE and CFLAGS, and the function's identity (symbol and
    name) follows the candidate through rebrew's identity writer. A result that is not EXACT or RELOC is
    refused: nothing is published from a candidate that no longer matches. A SQLite project returns a
    closed, verified copy of its store in place of ``rebrew-functions.toml``.
    """
    return _run_candidate(config, req, apply=True)


def _candidate_with_anchor(candidate: str, module: str, va: int) -> str:
    """Keep the retained identity immediately above the candidate's definition."""
    from rebrew.c_parser import comment_nodes, find_c_function_definitions, parse_c_source
    from rebrew.config import DEFAULT_ADDRESS_COMMENT_REGEX
    from rebrew.metadata.anchors import address_comment, comment_body

    tree, raw = parse_c_source(candidate)
    removals = []
    for node in comment_nodes(tree):
        comment = raw[node.start_byte : node.end_byte].decode("utf-8")
        body = comment_body(comment)
        if not body.startswith("ADDRESS:"):
            continue
        match = re.fullmatch(DEFAULT_ADDRESS_COMMENT_REGEX, body)
        if match is None:
            raise _address_comment_refused("invalid candidate ADDRESS comment")
        if int(match["va"], 16) != va:
            raise _address_comment_refused("candidate ADDRESS comment names a different VA")
        start = raw.rfind(b"\n", 0, node.start_byte) + 1
        end = raw.find(b"\n", node.end_byte)
        end = len(raw) if end < 0 else end + 1
        if (
            "\n" in comment
            or raw[start : node.start_byte].strip()
            or raw[node.end_byte : end].strip()
        ):
            raise _address_comment_refused("candidate ADDRESS comment must occupy one full line")
        if module:
            removals.append((start, end))
    if not module:
        return candidate
    for start, end in reversed(removals):
        raw = raw[:start] + raw[end:]
    candidate = raw.decode("utf-8")
    ((_, line),) = find_c_function_definitions(candidate)
    newline = "\r\n" if "\r\n" in candidate else "\n"
    lines = split_source_lines(candidate, keepends=True)
    lines.insert(line - 1, address_comment(module, va) + newline)
    return "".join(lines)


def _run_candidate(
    config: WorkerConfig, req: VerifyRequest | ApplyCandidateRequest, *, apply: bool
) -> dict[str, Any]:
    applying = req if isinstance(req, ApplyCandidateRequest) and apply else None
    from rebrew.c_parser import find_c_function_definitions
    from rebrew.config import load_config
    from rebrew.utils import portable_path_parts

    if len(req.candidate.encode()) > CANDIDATE_MAX_BYTES:
        raise _invalid(f"the candidate is over {CANDIDATE_MAX_BYTES} bytes")
    definitions = find_c_function_definitions(req.candidate)
    if len(definitions) != 1:
        names = ", ".join(name for name, _ in definitions)
        raise OpsError(
            f"the candidate defines {len(definitions)} functions ({names}); it must define exactly one"
            if definitions
            else "the candidate defines no C function; it must define exactly one",
            code=CANDIDATE_NOT_ONE_FUNCTION,
            status=400,
        )
    name = definitions[0][0]
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
        if sha256_file(source) != req.source_sha256:
            raise _invalid("source does not match its retained digest")
        from rebrew.metadata.bindings import module_for_va

        module = module_for_va(source, req.va)
        if apply and not module:
            raise _invalid("the function has no address anchor in the retained source")
        candidate = _candidate_with_anchor(req.candidate, module, req.va)
        source.write_text(candidate, encoding="utf-8")
        rewritten = apply_project_cflags(root, req.rebrew_target, req.project_cflags)
        cfg = load_config(root, target=req.rebrew_target)
        confined_snapshot_config(cfg, root)
        retained_compile_refusal(cfg, [source])
        from rebrew.c_parser import function_signatures
        from rebrew.metadata.bindings import derive_c_symbol

        symbol = derive_c_symbol(name, function_signatures(req.candidate).get(name, ""))
        # The registry is the snapshot's: an apply returns it, a verification compares it
        # with the renamed copy after the run.
        registry, renamed = follow_candidate_name(
            cfg, root, paths, module, req.va, name, symbol, always=apply
        )
        flags = checked_cflags(req.cflags)
        result = run_rebrew(
            [
                "test",
                "--json",
                *([] if apply else ["--no-promote"]),
                *_flag(isinstance(req, VerifyRequest) and req.instructions, "--instructions"),
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
        if sha256_file(destination) != req.sha256 or (
            not apply and source.read_bytes() != candidate.encode("utf-8")
        ):
            raise _invalid("snapshot candidate or binary changed during verification")
        if (
            not apply
            and renamed is not None
            and _project_file(root, registry, "function registry").read_bytes() != renamed
        ):
            raise _invalid("snapshot source changed during verification")
        for entry in req.files:
            if entry.path in {req.source, registry}:
                continue
            path = _project_file(root, entry.path, "source file")
            size, digest = (
                rewritten
                if rewritten and entry.path == "rebrew-project.toml"
                else (entry.size, entry.digest)
            )
            if path.stat().st_size != size or sha256_file(path) != digest:
                raise _invalid("snapshot source changed during verification")
        from rebrew.workspace.status import comparison_verdict_valid

        result["source"] = req.source
        result["compile_inputs"] = _compile_inputs(
            root, source, candidate.encode("utf-8"), result.get("compile")
        )
        result["verdict_valid"] = comparison_verdict_valid(result, req.source, req.va, req.size)
        if applying is not None:
            return _applied(root, applying, result, registry)
        return result


def _compile_inputs(
    root: Path, source: Path, compiled: bytes, remote: Any = None
) -> dict[str, Any]:
    """The project inputs a retained candidate compile read, in the descriptor shape.

    ``files`` are the compiled source, the project config (flags, toolchain)
    and each project header the remote compile shipped in its include bundle
    (*remote*, the ``compile`` block ``rebrew test --json`` reports); a header
    whose bytes are not the snapshot's is refused.  ``documents`` is the
    library settings document that overrides the flags, if any.
    """
    from rebrew.metadata.functions import nearest_library_metadata_path
    from rebrew.metadata.storage import metadata_store

    config = root / "rebrew-project.toml"
    files = [
        {
            "path": source.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(compiled).hexdigest(),
        },
        {"path": config.name, "sha256": sha256_file(config)},
    ]
    shipped = remote.get("includes", []) if isinstance(remote, dict) else []
    if not isinstance(shipped, list):
        raise OpsError("the compile reported a malformed include bundle")
    for header in shipped:
        if not isinstance(header, dict) or not all(
            isinstance(header.get(key), str) for key in ("path", "sha256")
        ):
            raise OpsError("the compile reported a malformed include bundle")
        path = _project_file(root, header["path"], "include")
        if sha256_file(path) != header["sha256"]:
            raise _invalid("snapshot source changed during verification")
        files.append({"path": header["path"], "sha256": header["sha256"]})
    documents = []
    library = nearest_library_metadata_path(source.parent, root)
    if library is not None:
        digest = metadata_store(library).digest()
        if digest is None:
            raise _invalid("the library settings changed during verification")
        documents.append({"path": library.relative_to(root).as_posix(), "logical_sha256": digest})
    return {
        "files": sorted(files, key=lambda item: item["path"].encode("utf-8")),
        "documents": documents,
    }


def follow_candidate_name(
    cfg: Any,
    root: Path,
    staged: Iterable[str],
    module: str,
    va: int,
    name: str,
    symbol: str,
    *,
    always: bool = False,
) -> tuple[str, bytes | None]:
    """Point a staged snapshot's registry entry for *va* at a candidate's *name* and *symbol*.

    rebrew refuses to scan a source whose address anchor names a function other than the
    registry does, so a candidate compiled in a private snapshot (*root*) takes its function's
    registry entry with it. Nothing happens without an anchor *module*, or when the registry
    already holds *name* unless *always* (an apply, which records the derived symbol). A name or
    symbol another function of *module* holds is refused, 409 ``candidate-name-taken``.

    Answers the registry's snapshot-relative path and its bytes after the rename, which the
    caller checks again after the run, or ``("", None)`` when nothing changed.
    """
    if not module or (not always and _registry_name(cfg, module, va) == name):
        return "", None
    _refuse_taken_name(cfg, module, va, name, symbol)
    if cfg.metadata_dir.resolve() != root:
        raise _invalid("the retained project keeps its function registry outside its root")
    registry = _applied_registry(root, list(staged))
    _move_identity(cfg, module, va, name, symbol)
    return registry, _project_file(root, registry, "function registry").read_bytes()


def _registry_name(cfg: Any, module: str, va: int) -> str:
    """The name the snapshot's registry holds for the function at *va*; empty for none."""
    from rebrew.metadata.functions import get_entry

    return str(get_entry(cfg.metadata_dir, va, module).get("name", ""))


def _refuse_taken_name(cfg: Any, module: str, va: int, name: str, symbol: str) -> None:
    """Refuse a candidate naming its function as another function of *module* is named, or by its symbol."""
    from rebrew.metadata.functions import load_metadata

    entries = load_metadata(cfg.metadata_dir, deepcopy=False)
    for (other_module, other_va), entry in sorted(entries.items()):
        if other_module != module or other_va == va:
            continue
        if name == entry.get("name") or symbol == entry.get("symbol"):
            current = entries.get((module, va), {}).get("name", "")
            raise OpsError(
                f"the candidate names the function at 0x{va:08x}"
                f"{f' ({current})' if current else ''} {name!r}, "
                f"the name of the function at 0x{other_va:08x}; give it another name",
                code=CANDIDATE_NAME_TAKEN,
                status=409,
            )


def _move_identity(cfg: Any, module: str, va: int, name: str, symbol: str) -> None:
    """Point the function's registry entry at the candidate's name and symbol through rebrew's identity writer.

    rebrew refuses to test a source whose address anchor names a function other than the registry's, so this
    runs before the comparison, on the snapshot's registry only. *symbol* is the one rebrew derives from the
    candidate's prototype (``_add@8`` for a stdcall ``add``): the comparison names the same symbol, which an
    apply needs to record its STATUS.
    """
    from rebrew.metadata.functions import record_function_rows

    record_function_rows(
        cfg.metadata_dir,
        [{"module": module, "va": va, "identity": {"symbol": symbol, "name": name}, "fields": {}}],
        overwrite_name=True,
        updated_by="rename",
    )


def _applied_registry(root: Path, staged: list[str]) -> str:
    """The staged registry an apply writes: the one the config reads, never beside the other."""
    from rebrew.metadata.sqlite import DATABASE_FILENAME

    backend = retained_metadata_backend(root)
    registry, ignored = (
        (APPLY_METADATA_FILE, DATABASE_FILENAME)
        if backend == "toml"
        else (DATABASE_FILENAME, APPLY_METADATA_FILE)
    )
    if ignored in staged:
        raise _invalid(
            f"the retained project carries {ignored}, which its {backend} metadata ignores"
        )
    if registry not in staged:
        raise _invalid(f"the retained project carries no {registry}")
    return registry


def _applied(
    root: Path, req: ApplyCandidateRequest, result: dict[str, Any], registry: str
) -> dict[str, Any]:
    """Finish an apply: refuse a result that is not a byte match, return the changed files."""
    from rebrew.metadata.sqlite import (
        DATABASE_FILENAME,
        metadata_database_documents,
        snapshot_metadata_database,
    )

    if result.get("status") == "NOT_RUN":
        error = result.get("error")
        logger.warning(
            "%s apply_candidate: the compile did not run: %s trace_id=%s",
            _request_id(),
            _escape_log_text(str(result.get("message", ""))),
            _trace_id(),
        )
        wait = error.get("retry_after") if isinstance(error, dict) else None
        raise OpsError(
            _not_run_detail(error),
            code=COMPILE_NOT_RUN,
            status=503,
            retry_after=math.ceil(wait) if isinstance(wait, (int, float)) else None,
        )
    if result.get("status") not in {"EXACT", "RELOC"}:
        raise _invalid(f"the candidate no longer matches: {result.get('status')}")
    changed = []
    for relative in (req.source, registry):
        if relative == DATABASE_FILENAME:
            # The live store may hold a rollback journal; publish a closed backup.
            with tempfile.TemporaryDirectory(prefix="applied-metadata-", dir=root.parent) as temp:
                try:
                    copy = snapshot_metadata_database(root, Path(temp) / DATABASE_FILENAME)
                    metadata_database_documents(copy)
                except (ValueError, OSError, RebrewError) as exc:
                    raise _invalid(f"the applied metadata store is invalid: {exc}") from exc
                data = copy.read_bytes()
        else:
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
    return {
        "result": result,
        "files": changed,
        "metadata": _published_metadata(root, changed),
        "attested_registry_digest": _attested_registry_digest(changed),
    }


def _published_metadata(root: Path, published: list[dict[str, Any]]) -> dict[str, Any]:
    """Describe *root*'s metadata as published: a returned file's digest replaces the live one's.

    A SQLite store is published as a closed copy, whose bytes differ from the live database.
    """
    from rebrew.metadata_sets import describe_metadata

    digests = {item["path"]: item["digest"] for item in published}
    try:
        descriptor = describe_metadata(root, exclusive=False)
    except (OSError, ValueError, RebrewError) as exc:
        raise _invalid(f"the applied metadata is invalid: {exc}") from exc
    for item in descriptor["files"]:
        item["sha256"] = digests.get(item["path"], item["sha256"])
    return descriptor


def retained_metadata_backend(root: Path) -> str:
    """The one local metadata backend a staged retained root reads, its SQLite store checked."""
    from rebrew.metadata.sqlite import DATABASE_FILENAME, metadata_database_documents
    from rebrew.metadata.storage import backend_routes
    from rebrew.workspace import read_config

    try:
        reads, writes = backend_routes(read_config(root).get("metadata", {}))
    except ValueError as exc:
        raise _invalid(str(exc)) from exc
    if reads not in {("toml",), ("sqlite",)} or writes != reads:
        raise _invalid("retained target requires one local metadata backend")
    if reads == ("sqlite",):
        try:
            documents = metadata_database_documents(root / DATABASE_FILENAME)
        except (ValueError, OSError, RebrewError) as exc:
            raise _invalid(str(exc)) from exc
        if APPLY_METADATA_FILE not in documents:
            raise _invalid("retained target requires SQLite function metadata")
    return reads[0]


def confined_snapshot_config(cfg: Any, root: Path) -> None:
    """Refuse project-config paths that could read or write outside a retained snapshot."""
    from rebrew.coverage_input_contract import CoverageInputError
    from rebrew.coverage_input_contract import confined_snapshot_config as check

    try:
        check(cfg, root)
    except CoverageInputError as exc:
        raise _invalid(str(exc)) from exc


def retained_config(root: Path, target_name: str) -> Any:
    """The staged snapshot's project config; a config rebrew refuses is the caller's to fix: 400 invalid-project-config."""
    from rebrew.config import load_config
    from rebrew.errors import ConfigError

    try:
        return load_config(root, target=target_name)
    except ConfigError as exc:
        raise _invalid_project_config(root, exc) from None


@contextlib.contextmanager
def retained_target_snapshot(
    config: WorkerConfig,
    files: list[RetainedFile],
    target_name: str,
    sha256: str,
    binary_key: str,
    binary_url: str,
    project_cflags: str = "",
) -> Iterator[Path]:
    """Stage a retained snapshot (manifest *files* and the target binary) and yield its root.

    The root is a fresh directory under ``<workspace>/.scratch``, removed when
    the block ends; the live project is never read.  Staging refuses a manifest
    over the readset bounds, a repeated or non-portable path, bytes that do not
    match, a ``rebrew-project.toml`` rebrew cannot load, config paths that leave
    the snapshot (``confined_snapshot_config``), metadata that is not one local
    backend, and a snapshot without its inventory and function metadata.  A
    block that ends without an exception is refused when it changed the binary
    or a staged file.  Every refusal is :class:`OpsError`.  *project_cflags*,
    when set, become the project cflags of the private copy
    (``apply_project_cflags``).
    """
    from rebrew.config import inventory_path_for
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
        with _step("staging the retained snapshot"):
            destination = _stage_retained_snapshot(
                config, root, files, target_name, sha256, binary_key, binary_url, exclusive=False
            )
            from rebrew.metadata.sqlite import DATABASE_FILENAME

            backend = retained_metadata_backend(root)
            rewritten = apply_project_cflags(root, target_name, project_cflags)
            cfg = retained_config(root, target_name)
            confined_snapshot_config(cfg, root)
            registry, ignored = (
                root / DATABASE_FILENAME,
                cfg.metadata_dir / "rebrew-functions.toml",
            )
            if backend == "toml":
                registry, ignored = ignored, registry
            staged = {entry.path for entry in files}
            required = (inventory_path_for(cfg.reversed_dir, cfg), registry)
            if any(
                not path.is_file() or path.relative_to(root).as_posix() not in staged
                for path in required
            ):
                raise _invalid("retained target requires its inventory and function metadata")
            # The other backend's registry would be staged and never read.
            if ignored.relative_to(root).as_posix() in staged:
                raise _invalid(
                    f"retained target carries {ignored.name}, which its {backend} metadata ignores"
                )
        yield root
        with _step("checking the retained snapshot after the run"):
            if sha256_file(destination) != sha256:
                raise _invalid("snapshot target binary changed during operation")
            for entry in files:
                path = _project_file(root, entry.path, "source file")
                size, digest = (
                    rewritten
                    if rewritten and entry.path == "rebrew-project.toml"
                    else (entry.size, entry.digest)
                )
                if path.stat().st_size != size or sha256_file(path) != digest:
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
            with _step("loading the project config"):
                cfg = load_config(snapshot, target=req.rebrew_target)
            with _step("checking the compiler is offered"):
                _refuse_compiler_not_offered(cfg)
            with _step("checking the sources for a remote compile"):
                retained_compile_refusal(cfg, iter_sources(cfg.reversed_dir, cfg))
            return run_rebrew(
                [*arguments, f"--target={req.rebrew_target}"],
                snapshot,
                SEARCH_TIMEOUT_SECONDS,
                outcome_exit=True,
            )
    if req.project_cflags:
        raise _invalid("project_cflags needs a retained source snapshot")
    root = project_root(config, req.project_dir)
    with _step("loading the project config"):
        cfg = target_config(root, req.sha256)
    with _step("checking the compiler is offered"):
        _refuse_compiler_not_offered(cfg)
    with _step("checking the sources for a remote compile"):
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
    arguments = [
        "verify",
        "--json",
        *_flag(req.no_promote, "--no-promote"),
        *_flag(req.instructions, "--instructions"),
    ]
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


def verified_coverage_inputs_required() -> None:
    """Coverage metadata needs producer custody, not merely a supplied manifest."""
    raise OpsError(
        "retained coverage requires verified inventory and result provenance",
        code=COVERAGE_INPUT_UNVERIFIED,
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
        raise OpsError(_bounded(str(exc)), code=COVERAGE_INPUT_UNVERIFIED, status=409) from None


def coverage_report(config: WorkerConfig, req: CoverageReportRequest) -> dict[str, Any]:
    """The target's decomp.dev progress report (objdiff ``report.json``, version 2).

    ``report`` is the document ``rebrew coverage report --decomp-dev``
    writes; ``summary`` its totals (functions, code bytes, fuzzy match).
    """
    from rebrew.config import load_config
    from rebrew.report import decomp_dev_report

    if req.files:
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
            cfg = load_config(snapshot, target=req.rebrew_target)
            trusted = checked_coverage_input(snapshot, req)
            try:
                report, summary = decomp_dev_report(cfg, trusted=trusted)
            except ValueError as exc:
                raise OpsError(
                    _bounded(str(exc)), code=COVERAGE_INPUT_UNVERIFIED, status=409
                ) from None
            checked_coverage_input(snapshot, req)
            return {"summary": summary, "report": report}
    if req.coverage_input.version or req.coverage_input_digest or req.verification_records:
        raise _invalid("coverage input requires a retained snapshot")
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    report, summary = decomp_dev_report(cfg)
    return {"summary": summary, "report": report}


def flag_search(config: WorkerConfig, req: FlagSearchRequest) -> dict[str, Any]:
    """Run a bounded flag or compiler profile sweep for one project source.

    ``count_only`` stages the same snapshot and answers ``{"candidates": N}``, the
    compiles the search would make, so a caller can price it before it runs.
    """
    if req.va < 0 or req.tier not in FLAG_SEARCH_TIERS:
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
        if sha256_file(source) != req.source_sha256:
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
        if req.count_only:
            arguments.append("--count")
        result = run_rebrew(
            [*arguments, f"--target={req.rebrew_target}", "--", str(source)],
            root,
            SEARCH_TIMEOUT_SECONDS,
            outcome_exit=True,
        )
        if sha256_file(source) != req.source_sha256 or sha256_file(destination) != req.sha256:
            raise _invalid("snapshot source or binary changed during flag search")
        return result


def data_list(config: WorkerConfig, req: DataListRequest) -> dict[str, Any]:
    """The target's global data inventory and section summary (``rebrew data list --json``)."""
    from rebrew.config import load_config

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
    root = project_root(config, req.project_dir)
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


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


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


def retained_source_operation(config: WorkerConfig, req: SnapshotMutationRequest) -> dict[str, Any]:
    """Run an operation against an isolated retained target."""
    from rebrew.snapshot_mutations import snapshot_mutation

    with _refusing_disagreeing_records():
        return snapshot_mutation(config, req)


def decompile_snapshot(config: WorkerConfig, req: DecompileSnapshotRequest) -> dict[str, Any]:
    """Run the operation over a verified retained snapshot."""
    from rebrew.analysis import is_inside
    from rebrew.decompiler import fetch_decompilation
    from rebrew.formats.binary_loader import load_binary
    from rebrew.ghidra import McpError
    from rebrew.name_decomp import apply_known_names
    from rebrew.named_snapshot import retained_snapshot
    from rebrew.sources import iter_library_headers, iter_sources
    from rebrew.struct_recover import existing_structs

    if req.backend not in DECOMPILER_BACKENDS:
        raise _invalid("invalid retained decompilation request")
    _refuse_unoffered_decompiler(req.backend)
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
        try:
            code, backend = fetch_decompilation(req.backend, cfg.target_binary, va, root)
        except McpError as exc:
            raise _ghidra_outage(exc) from None
        if not code:
            raise _no_decompilation(req.backend, va)
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
        AddressRequest, instruction_listing, IN_PROCESS_TIMEOUT_SECONDS
    ),
    "rebrew.control_flow_graph": Op(AddressRequest, control_flow_graph, IN_PROCESS_TIMEOUT_SECONDS),
    "rebrew.xrefs": Op(AddressRequest, xrefs, IN_PROCESS_TIMEOUT_SECONDS),
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
        raise OpsError(f"unknown op: {_bounded(name)}", code=UNKNOWN_OP, status=404)
    cancellation = _CANCELLATION.get()
    token = None
    if cancellation is None:
        cancellation = _Cancellation()
        token = _CANCELLATION.set(cancellation)
    cancellation.limit(
        time.monotonic() + op.timeout_seconds,
        f"{name} outlived its {op.timeout_seconds} s deadline",
    )
    steps = _FAILED_STEP.set([])
    try:
        return _run_op(config, name, op, body)
    finally:
        _FAILED_STEP.reset(steps)
        if token is not None:
            _CANCELLATION.reset(token)


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
        from rebrew.named_snapshot import unique_json_object

        raw = json.loads(body, object_pairs_hook=unique_json_object)
    except ValueError:
        raise _invalid("request is not JSON") from None
    request: Any = parse_request(op.request, raw)
    if name in COMPILING_OPS:
        return _counting_remote_compiles(config, name, op, request)
    return _run_parsed(config, name, op, request)


#: Exceptions an op never turns into a refusal: the process is ending.
_EXITS = (KeyboardInterrupt, SystemExit, GeneratorExit)


#: The detail of a write refused for a function record and source that disagree; the
#: record's key goes to the worker log.
BINDING_CONFLICT_DETAIL = (
    "invalid project config: a function record names another function than its source's "
    "address anchor; rebrew doctor lists such records and a re-analysis repairs a generated stub"
)


def _binding_conflict() -> OpsError:
    """The project's own function record and source disagree: 400, a fixed sentence."""
    return OpsError(BINDING_CONFLICT_DETAIL, code=INVALID_PROJECT_CONFIG, status=400)


@contextlib.contextmanager
def _refusing_disagreeing_records() -> Iterator[None]:
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
        record = f"{exc.module}.0x{exc.va:08x}" if exc.module else _escape_log_text(str(exc))
        logger.warning(
            "%s %s refused a function record whose source's anchor names another function: "
            "%s trace_id=%s",
            _request_id(),
            operation,
            record,
            _trace_id(),
        )
        raise _binding_conflict() from None
    except CommandExit as exc:
        if exc.kind != BINDING_CONFLICT_KIND:
            raise
        logger.warning("%s %s refused a function record: %s", _request_id(), operation, exc.message)
        raise _binding_conflict() from None


def _undeclared_skipped_records(name: str, skipped: set[tuple[str, int]]) -> None:
    """Fail under strict replies, or warn, when an op outside :data:`SKIPPED_RECORD_OPS` skipped."""
    from rebrew.config import STRICT_REPLIES_ENV, parse_env_bool

    keys = _skipped_records(skipped)["keys"]
    strict = os.environ.get(STRICT_REPLIES_ENV, "")
    if parse_env_bool(STRICT_REPLIES_ENV, strict, default=False):
        raise ValueError(f"{name}: skipped records outside SKIPPED_RECORD_OPS: {', '.join(keys)}")
    logger.warning(
        "%s %s skipped records outside SKIPPED_RECORD_OPS (%s) trace_id=%s",
        _request_id(),
        name,
        ", ".join(keys),
        _trace_id(),
    )


def _run_parsed(config: WorkerConfig, name: str, op: Op, request: Any) -> Mapping[str, Any]:
    """*op*'s reply to *request*, as its declared reply when :mod:`rebrew.ops_replies` declares one."""
    from rebrew.metadata.bindings import binding_conflicts
    from rebrew.metadata.sqlite import reading
    from rebrew.ops_replies import DECLARED

    with binding_conflicts() as skipped, reading():
        try:
            reply = op.run(config, request)
        except OpsError:
            raise
        except typer.Exit as exc:
            from rebrew.cli import TOOLCHAIN_REJECTED_KIND, CommandExit

            if isinstance(exc, CommandExit) and exc.kind == TOOLCHAIN_REJECTED_KIND:
                roots = [path for path in (config.workspace, config.filestore) if path is not None]
                raise _toolchain_rejected(exc.message, roots) from None
            raise OpsError(f"rebrew refused {name} (exit {exc.exit_code})") from None
        except UnsupportedBinaryFormat as exc:
            raise OpsError(str(exc), code=UNSUPPORTED_BINARY_FORMAT, status=422) from None
        except Exception as exc:  # the engine is a trust boundary: log it, answer it sanitized
            logger.exception("%s %s failed trace_id=%s", _request_id(), name, _trace_id())
            raise OpsError(_failure_detail(config, name, exc)) from None
        except _EXITS:
            raise
        except BaseException:  # a native panic (pyo3) escapes ``except Exception``
            logger.exception("%s %s failed trace_id=%s", _request_id(), name, _trace_id())
            raise OpsError(f"{name} failed: the engine raised an unexpected error") from None
        if skipped:
            if name in SKIPPED_RECORD_OPS:
                reply = {**reply, "skipped_records": _skipped_records(skipped)}
            else:
                _undeclared_skipped_records(name, skipped)
    return _declared_reply(name, reply) if name in DECLARED else reply


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
_REPLY_HEADERS: ContextVar[dict[str, str] | None] = ContextVar(
    "rebrew_ops_reply_headers", default=None
)


def dispatch(config: WorkerConfig, name: str, body: bytes) -> tuple[int, bytes]:
    """Answer one call: ``(200, reply)`` or ``(status, refusal)``."""
    try:
        reply = json.dumps(_answer(config, name, body), allow_nan=False).encode("utf-8")
    except OpsError as exc:
        headers = _REPLY_HEADERS.get()
        if exc.retry_after is not None and headers is not None:
            headers["Retry-After"] = str(exc.retry_after)
        # A 5xx refusal is a server failure with no exception attached (a
        # download timing out, a child command dying): without one line the
        # operator holding the refusal has only the fixed detail to go on.
        # 4xx refusals are the caller's diagnosis, already in the wire body.
        if exc.status >= 500:
            logger.exception(
                "%s %s refused (%d) trace_id=%s", _request_id(), name, exc.status, _trace_id()
            )
        return exc.status, error_body(exc.code, str(exc), exc.status, exc.remote_compile)
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

    *answer* answers every ``POST /<name>`` with ``(status, reply)`` from the
    worker configuration, the name and the body; *ops* is the op names it
    serves, which bound the per-op metrics and the span names (any other name
    is ``/unknown``) and decide a non-POST answer: 405 ``Allow: POST`` for a
    served op, 404 otherwise.  Both default to rebrew's own (:data:`OPS`,
    :func:`dispatch`); another engine passes its op table and dispatcher.

    Carries request metrics (see :meth:`record_request` and
    :meth:`metrics_snapshot`) behind ``/health`` and ``/metrics`` on the
    same port: counters plus latency, so an operator can pivot from a
    metric anomaly to the access lines that name the op and its id.

    A graceful stop is :meth:`request_stop` (from a signal handler: refuse new
    calls and end :meth:`serve_forever`), then :meth:`drain` (wait for the calls
    in flight).
    """

    daemon_threads = True
    #: Instance-level so tests and embedded engines can lower the admission cap.
    _max_connections = MAX_CONNECTIONS

    def __init__(
        self,
        address: tuple[str, int],
        config: WorkerConfig,
        token: str,
        concurrency: int,
        allowed_hosts: frozenset[str] = frozenset(),
        *,
        ops: Collection[str] = OPS.keys(),
        answer: Callable[[WorkerConfig, str, bytes], tuple[int, bytes]] = dispatch,
    ) -> None:
        super().__init__(address, _OpsHandler)
        try:
            self.config = config
            self.ops = frozenset(ops)
            self.answer = answer
            self.token = token
            self.slots = threading.BoundedSemaphore(concurrency)
            self._active = 0
            self._connections = 0
            self._connections_lock = threading.Lock()
            self._draining = False
            self._idle = threading.Condition()
            self.allowed_hosts = (
                _allowed_hosts_for(address[0], self.server_address[1]) | allowed_hosts
            )
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
        except BaseException:
            # TCPServer has already bound and activated its socket. A failure in
            # post-bind setup must not leave that descriptor behind for a caller
            # that never received a server object to close.
            self.server_close()
            raise

    @override
    def process_request(self, request: Any, client_address: Any) -> None:
        """Bound accepted sockets before ``ThreadingHTTPServer`` spawns a thread."""
        with self._connections_lock:
            active = self._connections
            if active < self._max_connections:
                self._connections += 1
                refused = None
            else:
                refused = active
        if refused is not None:
            self._refuse_connection(request, client_address, refused)
            self.shutdown_request(request)
            return
        # The handler releases the slot. If its thread never starts, this accept
        # path must return the slot instead of permanently reducing the cap.
        handed_off = False
        try:
            super().process_request(request, client_address)
            handed_off = True
        finally:
            if not handed_off:
                with self._connections_lock:
                    self._connections -= 1

    @override
    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._connections_lock:
                self._connections -= 1

    def _refuse_connection(self, request: Any, client_address: Any, active: int) -> None:
        """Answer one over-cap connection without creating a handler thread."""
        request_id = f"r{next(_REQUEST_IDS)}"
        detail = (
            f"too many connections in flight ({active} of {self._max_connections}); retry shortly"
        )
        body = error_body(WORKER_BUSY, detail, 503)
        with self._metrics_lock:
            self._busy_refusals += 1
        self.record_request(503, 0.0, "/unknown")
        logger.warning(
            "%s refusing connection from %s trace_id=%s: %d already in flight (cap %d)",
            request_id,
            _escape_log_text(str(client_address)),
            _trace_id(),
            active,
            self._max_connections,
        )
        if not isinstance(request, socket.socket):
            return
        lines = [
            "HTTP/1.1 503 Service Unavailable",
            f"Date: {formatdate(usegmt=True)}",
            f"Retry-After: {BUSY_RETRY_AFTER_SECONDS}",
            "Content-Type: application/json; charset=utf-8",
            f"Content-Length: {len(body)}",
            "Connection: close",
            f"X-Request-Id: {request_id}",
            *[f"{name}: {value}" for name, value in _SECURITY_HEADERS],
            f"Content-Security-Policy: {_CSP}",
        ]
        try:
            request.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
        except OSError as exc:
            logger.info(
                "%s client vanished before the refusal reached it trace_id=%s: %s",
                request_id,
                _trace_id(),
                exc,
            )

    def request_stop(self) -> None:
        """Refuse every new call 503 and end :meth:`serve_forever`; later calls change nothing.

        Safe from a signal handler: the shutdown runs on its own thread.
        """
        with self._idle:
            if self._draining:
                return
            self._draining = True
        threading.Thread(target=self.shutdown, daemon=True).start()

    def drain(self, timeout: float) -> int:
        """Refuse every new call and wait up to *timeout* seconds for those in flight.

        Returns how many are still in flight, 0 once all have answered.
        """
        with self._idle:
            self._draining = True
            self._idle.wait_for(lambda: self._active == 0, timeout=timeout)
            return self._active

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
                    "in_flight": self._active,
                    "busy_refusals": self._busy_refusals,
                    "unhandled_errors": self._unhandled_errors,
                    "uptime_seconds": time.monotonic() - self._started_at,
                },
                list(self._latency_ms_buckets),
                {op: dict(entry) for op, entry in self._per_op.items()},
            )


def _accepts_progress(accept: str) -> bool:
    """Whether an ``Accept`` header names :data:`PROGRESS_MEDIA_TYPE`."""
    return any(
        part.split(";", 1)[0].strip().lower() == PROGRESS_MEDIA_TYPE for part in accept.split(",")
    )


class _ProgressStream:
    """A ``serve`` answer as :data:`PROGRESS_MEDIA_TYPE`, started by the call's first count.

    A call that reports no count is answered as plain JSON, as to any other caller.
    """

    def __init__(self, handler: _OpsHandler, cancellation: _Cancellation) -> None:
        self._handler = handler
        self._cancellation = cancellation
        self.started = False

    def send(self, done: int, total: int) -> None:
        """Write one count, starting the answer on the first; a caller gone cancels the call."""
        try:
            if not self.started:
                self.started = True
                self._handler._start_stream()
            self._handler.wfile.write(progress_frame(done, total))
        except OSError:
            self._cancellation.cancel("the caller closed the connection", CALLER_GONE, 499)

    def finish(self, status: int, reply: bytes, headers: Mapping[str, str]) -> None:
        """Write the last line: the call's status, its ``Retry-After`` seconds when named, and its reply."""
        head: dict[str, Any] = {"status": status}
        if (retry := headers.get("Retry-After")) is not None:
            head["retry_after"] = int(retry)
        last = json.dumps(head)[:-1].encode("utf-8") + b', "reply": ' + reply + b"}\n"
        self._handler.wfile.write(last)
        self._handler._record_answer(status)


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
        self._record_answer(code)
        self._send_status_line(code, message)

    def _record_answer(self, code: int) -> None:
        """Count, log and trace the answer's status; a progress stream does it when it ends."""
        elapsed_ms = (time.perf_counter() - self._request_started) * 1000.0
        with contextlib.suppress(AttributeError):
            raw_path = urlsplit(getattr(self, "path", "") or "").path
            op_name = raw_path.removeprefix("/")
            server = typing.cast("OpsServer", self.server)
            route = f"/{op_name}" if op_name in server.ops else "/unknown"
            server.record_request(code, elapsed_ms, route)
        self.log_request(code, getattr(self, "_response_size", "-"))
        opened = telemetry.current()
        if opened is not None and opened.kind == telemetry.KIND_SERVER:
            opened.set("http.response.status_code", int(code))
            if code >= 500:
                opened.fail(f"status {code}")

    def _send_status_line(self, code: int, message: str | None = None) -> None:
        # No Server banner: BaseHTTPRequestHandler would emit the Python
        # patch level to any caller that can reach the worker.
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())
        self.send_header("X-Request-Id", self._request_id)

    def _start_stream(self) -> None:
        """Send the head of a 200 :data:`PROGRESS_MEDIA_TYPE` answer, which ends when the connection closes."""
        self._send_status_line(200)
        self.send_header("Content-Type", PROGRESS_MEDIA_TYPE)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        for name, value in _SECURITY_HEADERS:
            self.send_header(name, value)
        self.send_header("Content-Security-Policy", _CSP)
        self.end_headers()
        self.close_connection = True

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
            HOST_NOT_ALLOWED, "request Host not allowed (wrong or missing Host header)", 403
        )
        return False

    def do_POST(self) -> None:  # (http.server API)
        name = urlsplit(self.path).path.removeprefix("/")
        served = typing.cast("OpsServer", self.server).ops
        route = f"/{name}" if name in served else "/unknown"  # the route is bounded by the op set
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
            self._refuse(CROSS_ORIGIN, "cross-origin browser POST is not allowed", 403)
            return
        # /health and /metrics are GET/HEAD on this server: a POST is a
        # wrong method for a served resource (405), not an unknown op (404).
        # Other paths fall through to the server's answer, which refuses a name
        # outside its ops (dispatch: 404).
        if urlsplit(self.path).path in ("/health", "/metrics"):
            self._send(
                405,
                error_body(METHOD_NOT_ALLOWED, "health and metrics are served with GET, HEAD", 405),
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
            self._refuse(UNAUTHORIZED, "a valid bearer token is required", 401)
            return
        with server._idle:
            admitted = not server._draining and server.slots.acquire(blocking=False)
            if admitted:
                server._active += 1
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
            with server._idle:
                server._active -= 1
                server.slots.release()
                server._idle.notify_all()

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
            self._refuse(CROSS_ORIGIN, "cross-origin browser POST is not allowed", 403)
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
        cancellation = _Cancellation()
        if (seconds := self.headers.get(TIMEOUT_HEADER)) is not None:
            try:
                budget = float(seconds)
            except ValueError:
                budget = 0.0
            if not 0 < budget < float("inf"):
                self._refuse(INVALID_REQUEST, f"{TIMEOUT_HEADER} must be positive seconds", 400)
                return
            cancellation.limit(time.monotonic() + budget, f"the call outlived its {TIMEOUT_HEADER}")
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
        answered = threading.Event()
        watcher = threading.Thread(
            target=self._watch_caller, args=(cancellation, answered), daemon=True
        )
        token = _CANCELLATION.set(cancellation)
        stream = (
            _ProgressStream(self, cancellation)
            if _accepts_progress(self.headers.get("Accept", ""))
            else None
        )
        progress = _PROGRESS.set(None if stream is None else stream.send)
        headers: dict[str, str] = {}
        replied = _REPLY_HEADERS.set(headers)
        watcher.start()
        try:
            status, reply = server.answer(
                server.config, urlsplit(self.path).path.removeprefix("/"), body
            )
        except _EXITS:
            raise
        except BaseException:  # no call ends without a reply
            logger.exception("%s answer failed trace_id=%s", self._request_id, _trace_id())
            server.record_unhandled()
            status = 500
            reply = error_body(ENGINE_ERROR, "the engine failed while answering this call", 500)
        finally:
            answered.set()
            _REPLY_HEADERS.reset(replied)
            _PROGRESS.reset(progress)
            _CANCELLATION.reset(token)
            watcher.join()
        if stream is not None and stream.started:
            stream.finish(status, reply, headers)
        else:
            self._send(status, reply, headers or None)

    def _watch_caller(self, cancellation: _Cancellation, answered: threading.Event) -> None:
        """Cancel the call once its caller closes the connection."""
        while not answered.wait(CANCEL_POLL_SECONDS):
            if self._caller_gone():
                cancellation.cancel("the caller closed the connection", CALLER_GONE, 499)
                return

    def _caller_gone(self) -> bool:
        """True when the caller closed (or reset) the connection, read without consuming.

        A caller only waits for the reply, so a readable socket at end of stream
        is a close; pipelined bytes are left for the next request.
        """
        try:
            readable, _, _ = select.select([self.connection], [], [], 0)
            return bool(readable) and self.connection.recv(1, socket.MSG_PEEK) == b""
        except OSError:
            return True

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
                self._refuse(UNAUTHORIZED, "a valid bearer token is required", 401)
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
                error_body(METHOD_NOT_ALLOWED, "health and metrics are served with GET, HEAD", 405),
                {"Allow": "GET, HEAD"},
            )
            return
        name = path.removeprefix("/")
        if name not in typing.cast("OpsServer", self.server).ops:
            self._refuse(UNKNOWN_OP, f"unknown op: {_bounded(name)}", 404)
            return
        self._send(
            405,
            error_body(METHOD_NOT_ALLOWED, "ops are called with POST", 405),
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
    # A caller cancels with SIGTERM to this process's group. The child commands
    # run in their own sessions, so the call unwinds instead of dying: the
    # child's process tree is stopped and the retained snapshot removed.
    sigterm = getattr(signal, "SIGTERM", None)
    previous = signal.signal(sigterm, _exit_on_signal) if sigterm is not None else None
    progress = _PROGRESS.set(_descriptor_progress())
    try:
        # stdout carries only the reply; anything rebrew prints goes to stderr.
        with contextlib.redirect_stdout(sys.stderr):
            status, reply = dispatch(config, op, body)
    finally:
        _PROGRESS.reset(progress)
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
        _existing_dir(filestore, "--filestore"),
        _existing_dir(workspace, "--workspace"),
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
        server = OpsServer((host, port), config, token, concurrency, hosts)
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
    restore_log = _attach_server_log_handler()
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
