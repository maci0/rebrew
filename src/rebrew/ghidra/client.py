"""ghidra/client.py — Low-level HTTP client for ReVa MCP endpoint communication.

Handles MCP session initialization, JSON-RPC tool invocation, and bulk function
and data fetching via ReVa HTTP endpoints.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import time
from collections.abc import Mapping
from typing import Any, Literal, NamedTuple, Protocol, runtime_checkable

from rebrew.errors import RebrewError
from rebrew.ghidra.models import JsonRpcResponse, McpToolResult
from rebrew.utils import RETRYABLE_HTTP_STATUS, close_response, console, untrusted_text

logger = logging.getLogger(__name__)

#: How a :class:`McpError` arose — callers branch on this instead of
#: matching message substrings.
McpErrorKind = Literal["network", "http", "protocol", "validation"]


class McpError(RebrewError, RuntimeError):
    """ReVa MCP transport or protocol failure before/outside an apply loop.

    Structured fields let callers recover without string-matching ``str(exc)``:

    - ``kind`` — ``"network"`` / ``"http"`` / ``"protocol"`` / ``"validation"``
    - ``status_code`` — HTTP status when known, else ``None``
    - ``retryable`` — ``True`` for transport blips and transient HTTP codes
    """

    def __init__(
        self,
        message: str,
        *,
        kind: McpErrorKind = "protocol",
        status_code: int | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.status_code = status_code
        self.retryable = retryable


class McpApplyResult(NamedTuple):
    """Per-op outcome counts from :func:`apply_commands_via_mcp`.

    A named pair rather than a bare ``tuple[int, int]``: both fields are
    ``int``, so positional destructuring cannot catch a transposition.  It is
    still a 2-tuple, so existing ``success, errors = apply(...)`` code keeps
    working unchanged.
    """

    success: int
    errors: int


class McpApplyAborted(RebrewError, RuntimeError):
    """MCP apply died mid-loop after partially applying *ops*.

    Carries the (applied, errors) counts so the caller can decide whether a
    fallback re-apply is safe: re-running the full op list after partial
    application would duplicate the ops that already landed.
    """

    _STRUCTURED_FIELDS = (*RebrewError._STRUCTURED_FIELDS, "applied", "errors")

    def __init__(self, msg: str, *, applied: int, errors: int) -> None:
        super().__init__(msg)
        self.applied = applied
        self.errors = errors


class McpResponse(Protocol):
    """The response fields rebrew reads off an :class:`McpHttpClient` reply.

    An ``httpx.Response`` satisfies this structurally, and so does a plain
    stand-in with those five members.  ``close()`` is absent on purpose:
    :func:`rebrew.utils.close_response` probes for it, so a stand-in that has
    no connection to release is still a valid reply.
    """

    @property
    def status_code(self) -> int: ...

    @property
    def headers(self) -> Mapping[str, str]: ...

    @property
    def text(self) -> str: ...

    def json(self) -> Any: ...

    def raise_for_status(self) -> Any: ...


@runtime_checkable
class McpHttpClient(Protocol):
    """The HTTP surface the MCP functions below actually call.

    ``httpx.Client`` satisfies this, and so does any stand-in with ``post``
    and ``delete`` taking ``**kwargs``.  The keywords below are the ones
    these functions pass (the JSON-RPC ``json=`` body, the ``headers``
    session id, the per-call ``timeout``), so a stand-in is type-checked
    against the calls the implementation really makes.  Every ``client=``
    parameter in this package is typed against it.
    """

    def post(
        self,
        url: str,
        *,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> McpResponse: ...

    def delete(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> McpResponse: ...


MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
#: ReVa MCP server the structural ops default to, and the default every
#: ``--endpoint`` option across the tree offers.
DEFAULT_MCP_ENDPOINT = "http://localhost:8080/mcp/message"
MCP_REQUEST_TIMEOUT_S = 30
#: Budget for the session-termination ``DELETE``; it runs on every exit path,
#: so a stalled server must not hold up the caller for a full request timeout.
MCP_SESSION_END_TIMEOUT_S = 5

#: Op failures printed inline before the console stream stops; every failure
#: past this one is counted and reported once in the run summary instead, so a
#: bulk failure leaves a record an operator can act on rather than hundreds of
#: near-identical lines.
MCP_ERROR_PRINT_LIMIT = 30
#: Retry passes for ``parse-c-structure`` ops, whose ordering is a dependency
#: graph the server resolves across pushes.
MCP_STRUCT_RETRY_PASSES = 3
#: Longest failure text kept in the run summary; a Ghidra stack trace is
#: multi-line and would break the one-record-per-line log format.
MCP_SUMMARY_REASON_CHARS = 200

#: Hard cap on MCP list pages.  ``totalCount`` / ``nextStartIndex`` already
#: stop a well-behaved server; this bounds a server that keeps advancing
#: without ever satisfying ``start >= total``.
MAX_MCP_PAGES = 100_000

#: Hard cap on items one paginated MCP list may retain.  A page cap is a
#: loop counter, not a memory bound: a page whose metadata row omits
#: ``totalCount`` parses to ``0``, which disables the ``start >= total``
#: check, so the page cap alone lets the list grow to
#: ``MAX_MCP_PAGES * batch_size`` entries before it trips.
MAX_MCP_ITEMS = 500_000

#: Hard ceiling on one MCP tool response body, in bytes.  A tool result is
#: untrusted text that rebrew parses, writes into generated C, and later feeds
#: to the LLM seeder, so a server (or a stalled proxy in front of it) that
#: answers with an unbounded body must not be able to grow the process or a
#: source file without limit.  Generous next to real decompilation and
#: cross-reference payloads, which land far below it.
MAX_MCP_RESPONSE_BYTES = 1_000_000


def _parse_sse_response(text: str) -> JsonRpcResponse | None:
    """Extract JSON-RPC result from an SSE (text/event-stream) response body.

    A ``data:`` line that is not valid JSON, or that decodes to something
    other than a JSON object (an array, a bare string, a number, ``null``),
    is skipped like a keep-alive or comment line: scanning continues so a
    later line can still carry the response, and the caller reports the one
    answer every unusable body gets, "no parseable JSON-RPC response".
    """
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("data:"):
            try:
                decoded = json.loads(stripped[5:].lstrip())
            except json.JSONDecodeError:
                continue
            if not isinstance(decoded, dict):
                continue
            return JsonRpcResponse.from_dict(decoded)
    return None


def _response_within_limit(resp: McpResponse, tool_name: str, request_id: int | str) -> bool:
    """True when the body is small enough to parse and embed.

    The declared ``Content-Length`` is checked first so an oversized body is
    refused before ``json.loads`` allocates for it; the encoded text is
    measured too, because a server that declares nothing (or a chunked reply)
    still gets a real ceiling.
    """
    declared_raw = resp.headers.get("content-length") or resp.headers.get("Content-Length")
    if declared_raw is not None:
        try:
            declared = int(declared_raw)
        except (TypeError, ValueError):
            declared = None
        if declared is not None and declared > MAX_MCP_RESPONSE_BYTES:
            logger.warning(
                "MCP tool %s request %s returned Content-Length %s, over the %d byte limit",
                tool_name,
                request_id,
                declared_raw,
                MAX_MCP_RESPONSE_BYTES,
            )
            return False
    try:
        actual = len(resp.text.encode("utf-8", errors="replace"))
    except (AttributeError, TypeError, ValueError):
        return True
    if actual > MAX_MCP_RESPONSE_BYTES:
        logger.warning(
            "MCP tool %s request %s returned %d bytes, over the %d byte limit",
            tool_name,
            request_id,
            actual,
            MAX_MCP_RESPONSE_BYTES,
        )
        return False
    return True


def _call_mcp_tool(
    client: McpHttpClient,
    endpoint: str,
    tool_name: str,
    arguments: dict[str, Any],
    request_id: int,
    session_id: str,
) -> McpToolResult | None:
    """POST a ``tools/call`` request and return the tool result, or None on failure."""
    import httpx  # deferred: ~46 ms of startup for non-Ghidra commands

    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    headers = dict(MCP_HEADERS)
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    try:
        resp = client.post(endpoint, json=payload, headers=headers, timeout=MCP_REQUEST_TIMEOUT_S)
    except httpx.HTTPError as exc:
        logger.warning(
            "MCP tool %s request %s failed with HTTP error %s from %s",
            tool_name,
            request_id,
            exc,
            endpoint,
        )
        return None
    try:
        if resp.status_code != 200:
            logger.warning(
                "MCP tool %s request %s failed with HTTP %s from %s",
                tool_name,
                request_id,
                resp.status_code,
                endpoint,
            )
            return None
        if not _response_within_limit(resp, tool_name, request_id):
            return None
        ct = resp.headers.get("content-type", "").lower()
        if "text/event-stream" in ct:
            data = _parse_sse_response(resp.text)
        else:
            text = resp.text.strip()
            if not text:
                logger.warning(
                    "MCP tool %s request %s returned empty body from %s",
                    tool_name,
                    request_id,
                    endpoint,
                )
                return None
            try:
                data = JsonRpcResponse.from_dict(resp.json())
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
                logger.warning(
                    "MCP tool %s request %s returned invalid JSON from %s",
                    tool_name,
                    request_id,
                    endpoint,
                )
                return None
        if not data:
            logger.warning(
                "MCP tool %s request %s returned no parseable JSON-RPC response from %s",
                tool_name,
                request_id,
                endpoint,
            )
            return None
        if data.error is not None:
            logger.warning(
                "MCP tool %s request %s returned JSON-RPC error: %s",
                tool_name,
                request_id,
                data.error.message,
            )
            return None
        if not (data.result and "content" in data.result):
            logger.warning(
                "MCP tool %s request %s returned result without content from %s",
                tool_name,
                request_id,
                endpoint,
            )
            return None
        res = McpToolResult.from_dict(data.result)
        if res.isError:
            error_text = res.content[0].text if res.content else str(data.result)
            logger.warning(
                "MCP tool %s request %s returned tool error: %s",
                tool_name,
                request_id,
                error_text,
            )
            return None
        return res
    finally:
        close_response(resp)


def fetch_mcp_tool(
    client: McpHttpClient,
    endpoint: str,
    tool_name: str,
    arguments: dict[str, Any],
    request_id: int,
    session_id: str = "",
) -> list[Any]:
    """Call a ReVa MCP tool and return parsed JSON list from text content.

    Returns an empty list on HTTP errors or JSON parse failures.
    """
    res = _call_mcp_tool(client, endpoint, tool_name, arguments, request_id, session_id)
    if res is None:
        return []
    text_items = [it for it in res.content if it.type == "text"]
    if not text_items:
        logger.warning(
            "MCP tool %s request %s returned no text content items",
            tool_name,
            request_id,
        )
        return []
    # Multiple text items: each is a separate JSON object
    if len(text_items) > 1:
        objects = []
        for it in text_items:
            with contextlib.suppress(json.JSONDecodeError):
                objects.append(json.loads(it.text))
        if not objects:
            logger.warning(
                "MCP tool %s request %s returned only invalid JSON text items",
                tool_name,
                request_id,
            )
        return objects
    # Single text item
    raw = text_items[0].text
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return parsed
        return [parsed]
    except json.JSONDecodeError:
        logger.warning(
            "MCP tool %s request %s returned invalid JSON text content",
            tool_name,
            request_id,
        )
    return []


def fetch_mcp_tool_raw(
    client: McpHttpClient,
    endpoint: str,
    tool_name: str,
    arguments: dict[str, Any],
    request_id: int,
    session_id: str = "",
) -> Any:
    """Call a ReVa MCP tool and return parsed JSON result (raw, not list-wrapped).

    Unlike ``fetch_mcp_tool`` which always returns ``list[Any]``, this returns
    the parsed value directly — dict, list, str, or None on failure.  Used by
    the extended pull operations (prototypes, structs, comments).
    """
    res = _call_mcp_tool(client, endpoint, tool_name, arguments, request_id, session_id)
    if res is None:
        return None
    text_items = [it for it in res.content if it.type == "text"]
    if not text_items:
        logger.warning(
            "MCP tool %s request %s returned no text content items",
            tool_name,
            request_id,
        )
        return None
    # Single text item: return parsed JSON directly
    if len(text_items) == 1:
        raw = text_items[0].text
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    # Multiple text items: parse each as JSON, collect into list
    objects = []
    for it in text_items:
        with contextlib.suppress(json.JSONDecodeError):
            objects.append(json.loads(it.text))
    if not objects:
        logger.warning(
            "MCP tool %s request %s returned only invalid JSON text items",
            tool_name,
            request_id,
        )
    return objects if objects else None


def init_mcp_session(client: McpHttpClient, endpoint: str) -> str:
    """Initialize an MCP session and return the session ID.

    Transport failures and non-2xx replies raise :class:`McpError`
    (``kind="network"`` or ``kind="http"``, with ``status_code`` and
    ``retryable``) instead of an ``httpx`` exception.
    """
    import httpx  # deferred: ~46 ms of startup for non-Ghidra commands

    init_payload = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "rebrew sync", "version": "1.0.0"},
        },
    }
    try:
        resp = client.post(
            endpoint, json=init_payload, headers=MCP_HEADERS, timeout=MCP_REQUEST_TIMEOUT_S
        )
    except httpx.HTTPError as exc:
        raise McpError(
            f"Failed to initialize MCP session: {exc}",
            kind="network",
            retryable=True,
        ) from exc
    try:
        resp.raise_for_status()
        return str(resp.headers.get("Mcp-Session-Id", ""))
    except httpx.HTTPStatusError as exc:
        response = exc.response
        code = response.status_code if response is not None else None
        raise McpError(
            f"Failed to initialize MCP session: HTTP {code}",
            kind="http",
            status_code=code,
            retryable=code in RETRYABLE_HTTP_STATUS if code is not None else False,
        ) from exc
    finally:
        close_response(resp)


def end_mcp_session(client: McpHttpClient, endpoint: str, session_id: str) -> None:
    """Terminate *session_id* with an MCP ``DELETE`` so the server frees it.

    Every :func:`init_mcp_session` caller pairs it with this call on all exit
    paths: the server keeps per-session state until told otherwise, so one
    unterminated session per command (or per function in batch decompiles)
    accumulates for the server's lifetime.  Best-effort: a server may answer
    405 (termination unsupported) and a transport failure here must not mask
    the caller's result or exception.  An empty id (no session) is a no-op.
    """
    import httpx  # deferred: ~46 ms of startup for non-Ghidra commands

    if not session_id:
        return
    try:
        resp = client.delete(
            endpoint,
            headers={**MCP_HEADERS, "Mcp-Session-Id": session_id},
            timeout=MCP_SESSION_END_TIMEOUT_S,
        )
    except httpx.HTTPError as exc:
        # WARNING, not DEBUG: Python drops a DEBUG record without a
        # DEBUG-configured handler, so at DEBUG this failure left no trace at
        # all.  It is the one fault on this path with no other symptom — the
        # caller's result is unaffected by design — while the server keeps the
        # session's state until told otherwise, so the sessions accumulate
        # until the server refuses new ones, with nothing in the log to say
        # why.  The call still must not raise: this runs on the cleanup path.
        logger.warning("MCP session %s termination failed at %s: %s", session_id, endpoint, exc)
        return
    close_response(resp)


def _paginate_mcp_list(
    client: McpHttpClient,
    endpoint: str,
    tool_name: str,
    program_path: str,
    session_id: str,
    *,
    batch_size: int,
    request_id_start: int,
    filter_default_names: bool,
) -> list[dict[str, Any]]:
    """Page through a ReVa list tool until exhausted, ``MAX_MCP_ITEMS``, or ``MAX_MCP_PAGES``.

    Shared by ``fetch_all_symbols`` / ``fetch_all_functions`` so the
    nextStartIndex / totalCount advance guards cannot drift apart.
    Returns the raw per-item dicts (metadata rows excluded).

    Every exit path logs one record naming the tool, the program, how many
    pages and items came back, how long the walk took, and whether it ran to
    the end.  A pull that stops early (a cap, a page the server would not
    advance past, a transport failure ending the walk) returns a list that is
    indistinguishable from a complete one, so without this record a truncated
    program reads as a full sync until someone counts rows against Ghidra.
    ``apply_commands_via_mcp`` already closes its run this way; the pull path
    had no equivalent.  Complete walks log at INFO, incomplete ones at
    WARNING, so a grep separates them without parsing the message.
    """
    if batch_size <= 0:
        raise McpError("batch_size must be positive", kind="validation")
    started = time.perf_counter()
    items: list[dict[str, Any]] = []
    start = 0
    request_id = request_id_start
    pages = 0

    def finish(outcome: str) -> list[dict[str, Any]]:
        """Log the one record this walk produces, then hand back its items."""
        record = logger.warning if outcome != "complete" else logger.info
        record(
            "MCP %s pull of %s: %s (%d page(s), %d item(s), %.1fs)",
            tool_name,
            program_path,
            outcome,
            pages,
            len(items),
            time.perf_counter() - started,
        )
        return items

    for _ in range(MAX_MCP_PAGES):
        raw = fetch_mcp_tool(
            client,
            endpoint,
            tool_name,
            {
                "programPath": program_path,
                "filterDefaultNames": filter_default_names,
                "maxCount": batch_size,
                "startIndex": start,
            },
            request_id,
            session_id=session_id,
        )
        request_id += 1

        metadata = None
        page: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            # ``nextStartIndex`` marks the metadata row too: a page whose
            # metadata carries only that key is not a symbol, and treating it
            # as one would end the walk after the first page.
            if "totalCount" in item or "nextStartIndex" in item:
                metadata = item
            elif "address" in item or "name" in item:
                page.append(item)

        items.extend(page)
        pages += 1

        if metadata is None or len(page) == 0:
            # ``fetch_mcp_tool`` answers an empty list for a failure it logged
            # (transport, HTTP, oversized body, unparseable reply) as well as
            # for a page the server finished on, and this layer cannot tell
            # those two apart from the list alone.  The metadata row can: a
            # server that answers with one has reported its state, so a short
            # or empty page is the walk ending as designed — a program with no
            # symbols reports ``totalCount: 0`` and is complete, not a fault.
            # No metadata row on the first page means no usable answer arrived
            # at all, which is the unreachable-endpoint case, so it reports at
            # WARNING rather than as a clean pull of nothing.
            if metadata is None and not items:
                return finish("ended on the first page with no rows")
            return finish("complete")
        if len(items) >= MAX_MCP_ITEMS:
            return finish(f"stopped at the {MAX_MCP_ITEMS}-item cap")
        # A metadata row without a usable ``totalCount`` reports no total, so
        # the count check below cannot stop the walk; the page runs until the
        # server sends a short or empty page, bounded by MAX_MCP_ITEMS.
        try:
            total = int(metadata["totalCount"])
        except (KeyError, ValueError, TypeError):
            total = -1
        try:
            next_start = int(metadata.get("nextStartIndex", start + batch_size))
        except (ValueError, TypeError):
            next_start = start + batch_size
        # Stop on a server that echoes nextStartIndex without advancing,
        # which would otherwise loop forever.
        if next_start <= start:
            return finish("stopped: server did not advance nextStartIndex")
        start = next_start
        if total >= 0 and start >= total:
            return finish("complete")

    return finish(f"stopped at the {MAX_MCP_PAGES}-page cap")


def fetch_all_symbols(
    client: McpHttpClient,
    endpoint: str,
    program_path: str,
    session_id: str,
    batch_size: int = 200,
) -> list[dict[str, Any]]:
    """Fetch all non-default symbols from ReVa MCP with pagination.

    Similar to ``fetch_all_functions`` but uses ``get-symbols``.
    Returns dicts with ``address`` and ``name`` keys.

    A transport, HTTP, body-size, or protocol failure is logged at warning
    level by :func:`_call_mcp_tool`, not raised: it ends the walk, so the
    result is empty or holds only the pages read before it.
    :func:`init_mcp_session` raises ``McpError`` on the same failures.
    """
    return _paginate_mcp_list(
        client,
        endpoint,
        "get-symbols",
        program_path,
        session_id,
        batch_size=batch_size,
        request_id_start=200,
        filter_default_names=True,
    )


def fetch_all_functions(
    client: McpHttpClient,
    endpoint: str,
    program_path: str,
    session_id: str,
    batch_size: int = 200,
) -> list[dict[str, Any]]:
    """Fetch all functions from ReVa MCP with pagination.

    ReVa's ``get-functions`` returns at most *maxCount* entries per call.
    This helper pages through the full list and normalises the field names
    to the format expected by the data-pull path (``va``, ``tool_name``, ``size``).

    A transport, HTTP, body-size, or protocol failure is logged at warning
    level by :func:`_call_mcp_tool`, not raised: it ends the walk, so the
    result is empty or holds only the pages read before it.
    :func:`init_mcp_session` raises ``McpError`` on the same failures.
    """
    page = _paginate_mcp_list(
        client,
        endpoint,
        "get-functions",
        program_path,
        session_id,
        batch_size=batch_size,
        request_id_start=100,
        filter_default_names=False,
    )
    return [
        {
            "va": f.get("address", f.get("va")),
            "tool_name": f.get("name", f.get("ghidra_name") or f.get("tool_name", "")),
            "size": f.get("sizeInBytes", f.get("size", 0)),
        }
        for f in page
    ]


_ALREADY_EXISTS_PATTERNS: tuple[re.Pattern[str], ...] = (
    # ReVa/Ghidra "already exists" failures name the operation and the
    # address: never substring-match unrelated errors (e.g. a log line that
    # mentions an existing file).  JSON-RPC numeric codes only describe the
    # transport (-32700..-32603); the create/modify tools report success this
    # way only via their text payload, so the payload must pin both.
    re.compile(r"\bcreate-(?:function|label)\b.*\b0x[0-9a-fA-F]+\b.*\balready exists\b"),
    re.compile(r"\balready exists\b.*\bcreate-(?:function|label)\b.*\b0x[0-9a-fA-F]+\b"),
)

#: Ops whose re-application is idempotent (the CLI backend counts their
#: "already exists" failures as success, same as the MCP path).  Includes
#: the structural push/retry set: a second ``rebrew sync`` (or a
#: ``parse-c-structure`` dependency retry after the type already landed)
#: must not treat Ghidra's duplicate-name reply as a hard failure.
_IDEMPOTENT_OPS = frozenset(
    {
        "create-function",
        "create-label",
        "parse-c-structure",
        "set-comment",
        "set-bookmark",
        "set-function-prototype",
    }
)

#: Verb prefixes stripped when deriving a bare noun from an op slug
#: (``set-comment`` → ``comment``, ``parse-c-structure`` → ``c-structure``).
_OP_VERB_PREFIXES = ("create-", "set-", "parse-")


def is_idempotent_success(op: dict[str, Any] | None, error_msg: str) -> bool:
    """True when *error_msg* is an idempotent re-apply of *op*, not a failure.

    The error arrived as the result of this op's own ``tools/call`` request,
    so the request context is known — but the text must still pin THIS op:
    an "already exists"-style marker plus the op's noun or address, and no
    mention of a different operation or a different address.  Unrelated
    errors that merely contain the substring are failures.  The caller
    dispatches on the structured result first (JSON-RPC ``error`` vs tool
    ``isError``); this only classifies the text payload.
    """
    text = str(error_msg).lower()
    if "already exists" not in text and "duplicate" not in text and "already has" not in text:
        return False
    if op is None:
        return False
    tool = str(op.get("tool", "")).lower()
    if not tool:
        return False
    args = op.get("args")
    op_addrs: set[int] = set()
    if isinstance(args, dict):
        for v in args.values():
            if isinstance(v, str) and re.fullmatch(r"0x[0-9a-fA-F]+", v.strip()):
                op_addrs.add(int(v.strip(), 16))
    # Compare addresses numerically: the server may echo ``0x1000`` for an op
    # that carries ``0x00001000`` (and vice versa).
    text_addrs = {int(a, 16) for a in re.findall(r"0x[0-9a-fA-F]+", text)}
    # A different address named → the error is about something else.
    if not text_addrs <= op_addrs:
        return False

    def _op_spellings(name: str) -> set[str]:
        return {name, name.replace("-", " "), name.replace("-", "_")}

    def _op_nouns(name: str, *, segments: bool = False) -> set[str]:
        """Every way a server may name this op: the slug, its spaced/underscored
        spellings, and the bare noun after a verb prefix
        (``create-label`` → ``label``, ``set-comment`` → ``comment``).

        With *segments*, also add each hyphen/underscore piece of the bare
        noun (``parse-c-structure`` → ``structure``) so THIS op can match
        short server wordings.  Cross-op rejection must leave *segments*
        off — otherwise ``function`` shared by ``create-function`` and
        ``set-function-prototype`` would false-reject a valid re-apply.
        """
        bare = name
        for prefix in _OP_VERB_PREFIXES:
            if name.startswith(prefix):
                bare = name[len(prefix) :]
                break
        nouns = {
            name,
            bare,
            name.replace("-", " "),
            name.replace("-", "_"),
            bare.replace("-", " "),
            bare.replace("-", "_"),
        }
        if segments:
            for part in re.split(r"[-_]", bare):
                if len(part) > 2:
                    nouns.add(part)
        return nouns

    # A different create-op named → the error is about something else.  Check
    # every spelling: a "create function ..." payload must not be accepted for
    # a create-label op just because only the hyphenated slug was matched.
    other_spellings = set().union(*(_op_spellings(o) for o in _IDEMPOTENT_OPS - {tool}))
    if any(s in text for s in other_spellings):
        return False
    # ...and the bare noun: the server may echo "function 0x1000 already
    # exists" for a create-label op, naming the other op without its slug.
    other_nouns = set().union(*(_op_nouns(o) for o in _IDEMPOTENT_OPS - {tool}))
    if any(n in text for n in other_nouns if n):
        return False

    nouns = _op_nouns(tool, segments=True)
    named_op = any(noun in text for noun in nouns if noun)
    named_addr = bool(text_addrs)
    if tool in _IDEMPOTENT_OPS and (named_op or named_addr):
        return True
    # Ghidra's typed DuplicateNameException pins a name collision without
    # always echoing the op slug — the tools/call context already names
    # which op, and this exception is not a generic "file exists" log line.
    if tool in _IDEMPOTENT_OPS and "duplicatenameexception" in text:
        return True
    # Generic patterns (op + address in either order) cover server wordings
    # that echo both without the exact tool slug.
    return any(p.search(text) for p in _ALREADY_EXISTS_PATTERNS)


def apply_commands_via_mcp(
    commands: list[dict[str, Any]],
    endpoint: str = DEFAULT_MCP_ENDPOINT,
    *,
    client: McpHttpClient | None = None,
    timeout: float = MCP_REQUEST_TIMEOUT_S,
) -> McpApplyResult:
    """Apply sync commands to Ghidra via ReVa MCP Streamable HTTP.

    Returns :class:`McpApplyResult` with ``success`` and ``errors`` counts
    (a 2-tuple, so ``success, errors = ...`` still works).

    *client*, when given, must satisfy :class:`McpHttpClient` — an
    ``httpx.Client`` or a stand-in with ``post`` / ``delete``.  The caller owns
    its lifetime; the function does not close it.
    """
    import httpx  # deferred: ~46 ms of startup for non-Ghidra commands

    success = 0
    errors = 0
    total = len(commands)
    started = time.perf_counter()
    # Every failure, keyed by op tool and reason: the console stream stops
    # printing partway through a bulk failure, so this is the only place that
    # still says which op class broke and how often.
    unreported: dict[str, int] = {}

    def _report_op_failure(tool: str, va: object, reason: object) -> None:
        """Print the first failures inline, count the rest for the run summary."""
        if errors <= MCP_ERROR_PRINT_LIMIT:
            console.print(f"  ERROR at {va} ({tool}): {untrusted_text(reason)}")
        elif errors == MCP_ERROR_PRINT_LIMIT + 1:
            console.print("  ... suppressing further errors")
        key = f"{tool}: {str(reason).splitlines()[0] if str(reason).strip() else reason}"
        key = key[:MCP_SUMMARY_REASON_CHARS]
        unreported[key] = unreported.get(key, 0) + 1

    cm: Any = (
        contextlib.nullcontext(client) if client is not None else httpx.Client(timeout=timeout)
    )
    with (
        cm as http,
        contextlib.ExitStack() as session_cleanup,
    ):
        try:
            session_id = init_mcp_session(http, endpoint)
            session_cleanup.callback(end_mcp_session, http, endpoint, session_id)
        except httpx.HTTPError as exc:
            raise McpError(
                f"Failed to initialize MCP session: {exc}",
                kind="network",
                retryable=True,
            ) from exc

        if not session_id:
            console.print(
                "[yellow]warning:[/yellow] No session ID received, proceeding without one"
            )

        headers = dict(MCP_HEADERS)
        if session_id:
            headers["Mcp-Session-Id"] = session_id

        # Best-effort: ReVa does not require this notification to succeed.
        try:
            notify = http.post(
                endpoint,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers=headers,
                timeout=timeout,
            )
            try:
                notify.raise_for_status()
            finally:
                close_response(notify)
        except httpx.HTTPError as exc:
            logger.warning("Failed to send initialized notification to %s: %s", endpoint, exc)

        def _send_cmd(
            cmd: dict[str, Any],
            cmd_id: int,
        ) -> tuple[bool, str]:
            """Send a single MCP command. Returns (ok, error_msg)."""
            payload = {
                "jsonrpc": "2.0",
                "id": cmd_id,
                "method": "tools/call",
                "params": {"name": cmd["tool"], "arguments": cmd["args"]},
            }
            resp = http.post(endpoint, json=payload, headers=headers, timeout=timeout)
            try:
                resp.raise_for_status()
                if not _response_within_limit(resp, str(cmd["tool"]), f"cmd-{cmd_id}"):
                    return False, "MCP response exceeded the size limit"
                # Read body once to avoid double-decode on non-UTF8 responses.
                body = resp.text.strip()
                if not body:
                    return False, "empty MCP response body"
                ct = resp.headers.get("content-type", "").lower()
                if "text/event-stream" in ct:
                    data = _parse_sse_response(body)
                else:
                    try:
                        data = JsonRpcResponse.from_dict(resp.json())
                    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
                        return False, "invalid MCP JSON-RPC response"
                if not data:
                    return False, "missing MCP JSON-RPC response"
                is_error = data.error is not None
                error_msg = data.error.message if data.error else ""
                if not is_error:
                    # A JSON-RPC success must carry a tool result with ``content``
                    # to confirm the mutation landed (the ``_call_mcp_tool``
                    # contract).  Counting a content-less result as applied silently
                    # drops the op.
                    if not (isinstance(data.result, dict) and "content" in data.result):
                        return False, "MCP response carried no tool-result content"
                    res = McpToolResult.from_dict(data.result)
                    if res.isError:
                        is_error = True
                        content = res.content
                        error_msg = content[0].text if content else str(data.result)
                if is_error:
                    if is_idempotent_success(cmd, error_msg):
                        return True, ""
                    return False, str(error_msg)
                return True, ""
            finally:
                close_response(resp)

        current_phase = ""
        struct_failures: list[dict[str, Any]] = []
        for i, cmd in enumerate(commands):
            tool = cmd["tool"]
            if tool != current_phase:
                if current_phase:
                    console.print()  # newline after previous phase progress
                phase_labels = {
                    "create-function": "Creating functions",
                    "create-label": "Setting labels",
                    "set-comment": "Adding comments",
                    "set-bookmark": "Adding bookmarks",
                    "parse-c-structure": "Pushing struct definitions",
                    "set-function-prototype": "Setting function prototypes",
                }
                console.print(f"  {phase_labels.get(tool, tool)}...")
                current_phase = tool

            va = cmd["args"].get("addressOrSymbol", cmd["args"].get("address", "?"))
            try:
                ok, error_msg = _send_cmd(cmd, i + 1)
                if ok:
                    success += 1
                else:
                    if tool == "parse-c-structure":
                        struct_failures.append(cmd)
                    errors += 1
                    _report_op_failure(cmd["tool"], va, error_msg)
            except httpx.HTTPError as exc:
                if tool == "parse-c-structure":
                    struct_failures.append(cmd)
                errors += 1
                if success > 0:
                    # Earlier ops verifiably landed (and this one may have
                    # landed server-side before the transport died):
                    # re-running the full list via a fallback would duplicate
                    # them.  Report progress and let the caller decide.
                    logger.exception(
                        "MCP apply to %s aborted at op %d/%d after %.1fs: %d applied, %d error(s)",
                        endpoint,
                        i + 1,
                        total,
                        time.perf_counter() - started,
                        success,
                        errors,
                    )
                    raise McpApplyAborted(
                        f"MCP transport failed at op {i + 1}/{total} "
                        f"({success} applied, {errors} error(s)): {exc}",
                        applied=success + errors,
                        errors=errors,
                    ) from exc
                _report_op_failure(cmd["tool"], va, exc)

            if (i + 1) % 50 == 0 or i == total - 1:
                pct = (i + 1) * 100 // total
                console.print(f"  [{pct:3d}%] {i + 1}/{total} operations applied", end="\r")

            # Rate limiting — don't overwhelm the server
            if (i + 1) % 100 == 0:
                time.sleep(0.1)

        # Retry failed parse-c-structure ops (dependency ordering)
        for retry in range(MCP_STRUCT_RETRY_PASSES):
            if not struct_failures:
                break
            console.print(
                f"\n  Retrying {len(struct_failures)} struct definitions (pass {retry + 2})..."
            )
            still_failing: list[dict[str, Any]] = []
            for retry_idx, cmd in enumerate(struct_failures):
                try:
                    ok, error_msg = _send_cmd(cmd, total + retry * 1000 + retry_idx + 1)
                    if ok:
                        success += 1
                        errors -= 1
                    else:
                        still_failing.append(cmd)
                        if retry == MCP_STRUCT_RETRY_PASSES - 1:
                            defn = cmd["args"].get("cDefinition", "")[:80]
                            console.print(f"  PERMANENT FAIL: {untrusted_text(error_msg)} | {defn}")
                except httpx.HTTPError as exc:
                    still_failing.append(cmd)
                    if retry == MCP_STRUCT_RETRY_PASSES - 1:
                        defn = cmd["args"].get("cDefinition", "")[:80]
                        console.print(f"  PERMANENT FAIL (HTTP): {exc} | {defn}")
            resolved = len(struct_failures) - len(still_failing)
            if resolved > 0:
                console.print(f"  Resolved {resolved} definitions on retry pass {retry + 2}")
            struct_failures = still_failing
            if struct_failures and not resolved:
                break

    console.print()  # newline after progress
    # One record per run, on the logging stream the caller can grep and keep:
    # how long the apply took, how many ops failed, and which op class and
    # reason the console stream stopped printing.
    elapsed_s = time.perf_counter() - started
    if errors:
        logger.error(
            "MCP apply to %s: %d of %d op(s) failed, %d applied, %.1fs",
            endpoint,
            errors,
            total,
            success,
            elapsed_s,
        )
        if struct_failures:
            logger.error(
                "MCP apply to %s: %d parse-c-structure op(s) still failing after %d retry pass(es)",
                endpoint,
                len(struct_failures),
                MCP_STRUCT_RETRY_PASSES,
            )
        for key, count in sorted(unreported.items(), key=lambda kv: -kv[1]):
            logger.error("MCP apply to %s: %d op(s) failed: %s", endpoint, count, key)
    else:
        logger.info("MCP apply to %s: %d op(s) applied in %.1fs", endpoint, success, elapsed_s)
    return McpApplyResult(success, errors)


__all__ = [
    "MAX_MCP_PAGES",
    "MAX_MCP_RESPONSE_BYTES",
    "MCP_HEADERS",
    "MCP_REQUEST_TIMEOUT_S",
    "McpApplyAborted",
    "McpApplyResult",
    "McpError",
    "McpErrorKind",
    "McpHttpClient",
    "McpResponse",
    "apply_commands_via_mcp",
    "end_mcp_session",
    "fetch_all_functions",
    "fetch_all_symbols",
    "fetch_mcp_tool",
    "fetch_mcp_tool_raw",
    "init_mcp_session",
    "is_idempotent_success",
]
