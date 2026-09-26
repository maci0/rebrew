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
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    import httpx

from rich.console import Console

from rebrew.errors import RebrewError
from rebrew.ghidra.models import JsonRpcResponse, McpToolResult
from rebrew.utils import close_response

# Local console: rebrew.ghidra must stay importable without rebrew.cli
# (library layering test).
console = Console(stderr=True)
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


class McpApplyAborted(RebrewError, RuntimeError):
    """MCP apply died mid-loop after partially applying *ops*.

    Carries the (applied, errors) counts so the caller can decide whether a
    fallback re-apply is safe: re-running the full op list after partial
    application would duplicate the ops that already landed.
    """

    def __init__(self, msg: str, *, applied: int, errors: int) -> None:
        super().__init__(msg)
        self.applied = applied
        self.errors = errors


#: Transient HTTP statuses that are safe to retry after a backoff.
_RETRYABLE_HTTP = frozenset({408, 425, 429, 500, 502, 503, 504})

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
MCP_REQUEST_TIMEOUT_S = 30
#: Budget for the session-termination ``DELETE``; it runs on every exit path,
#: so a stalled server must not hold up the caller for a full request timeout.
MCP_SESSION_END_TIMEOUT_S = 5

#: Hard cap on MCP list pages.  ``totalCount`` / ``nextStartIndex`` already
#: stop a well-behaved server; this bounds a server that keeps advancing
#: without ever satisfying ``start >= total``.
MAX_MCP_PAGES = 100_000


def _parse_sse_response(text: str) -> JsonRpcResponse | None:
    """Extract JSON-RPC result from an SSE (text/event-stream) response body."""
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("data:"):
            try:
                return JsonRpcResponse.from_dict(json.loads(stripped[5:].lstrip()))
            except json.JSONDecodeError:
                continue
    return None


def _call_mcp_tool(
    client: httpx.Client,
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
    client: httpx.Client,
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
    client: httpx.Client,
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


def init_mcp_session(client: httpx.Client, endpoint: str) -> str:
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
            retryable=code in _RETRYABLE_HTTP if code is not None else False,
        ) from exc
    finally:
        close_response(resp)


def end_mcp_session(client: httpx.Client, endpoint: str, session_id: str) -> None:
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
        logger.debug("MCP session %s termination failed at %s: %s", session_id, endpoint, exc)
        return
    close_response(resp)


def _paginate_mcp_list(
    client: httpx.Client,
    endpoint: str,
    tool_name: str,
    program_path: str,
    session_id: str,
    *,
    batch_size: int,
    request_id_start: int,
    filter_default_names: bool,
) -> list[dict[str, Any]]:
    """Page through a ReVa list tool until exhausted or ``MAX_MCP_PAGES``.

    Shared by ``fetch_all_symbols`` / ``fetch_all_functions`` so the
    nextStartIndex / totalCount advance guards cannot drift apart.
    Returns the raw per-item dicts (metadata rows excluded).
    """
    if batch_size <= 0:
        raise McpError("batch_size must be positive", kind="validation")
    items: list[dict[str, Any]] = []
    start = 0
    request_id = request_id_start

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
            if "totalCount" in item:
                metadata = item
            elif "address" in item or "name" in item:
                page.append(item)

        items.extend(page)

        if metadata is None or len(page) == 0:
            return items
        try:
            total = int(metadata.get("totalCount", 0))
        except (ValueError, TypeError):
            total = 0
        try:
            next_start = int(metadata.get("nextStartIndex", start + batch_size))
        except (ValueError, TypeError):
            next_start = start + batch_size
        # Stop on a server that echoes nextStartIndex without advancing,
        # which would otherwise loop forever.
        if next_start <= start:
            return items
        start = next_start
        if start >= total:
            return items

    logger.warning(
        "MCP %s pagination hit %s-page cap for %s; returning partial list",
        tool_name,
        MAX_MCP_PAGES,
        program_path,
    )
    return items


def fetch_all_symbols(
    client: httpx.Client,
    endpoint: str,
    program_path: str,
    session_id: str,
    batch_size: int = 200,
) -> list[dict[str, Any]]:
    """Fetch all non-default symbols from ReVa MCP with pagination.

    Similar to ``fetch_all_functions`` but uses ``get-symbols``.
    Returns dicts with ``address`` and ``name`` keys.
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
    client: httpx.Client,
    endpoint: str,
    program_path: str,
    session_id: str,
    batch_size: int = 200,
) -> list[dict[str, Any]]:
    """Fetch all functions from ReVa MCP with pagination.

    ReVa's ``get-functions`` returns at most *maxCount* entries per call.
    This helper pages through the full list and normalises the field names
    to the format expected by the data-pull path (``va``, ``tool_name``, ``size``).
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


def _is_idempotent_success(op: dict[str, Any] | None, error_msg: str) -> bool:
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
    endpoint: str = "http://localhost:8080/mcp/message",
    *,
    client: httpx.Client | None = None,
    timeout: float = MCP_REQUEST_TIMEOUT_S,
) -> tuple[int, int]:
    """Apply sync commands to Ghidra via ReVa MCP Streamable HTTP.

    Returns (success_count, error_count).

    *client*, when given, must be an ``httpx.Client`` (or compatible stand-in).
    The caller owns its lifetime; the function does not close it.
    """
    import httpx  # deferred: ~46 ms of startup for non-Ghidra commands

    success = 0
    errors = 0
    total = len(commands)

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
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            raise McpError(
                f"Failed to initialize MCP session: HTTP {code}",
                kind="http",
                status_code=code,
                retryable=code in _RETRYABLE_HTTP,
            ) from exc
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
                    if _is_idempotent_success(cmd, error_msg):
                        return True, ""
                    return False, str(error_msg)
                return True, ""
            finally:
                close_response(resp)

        # Apply each command
        current_phase = ""
        struct_failures: list[dict[str, Any]] = []
        for i, cmd in enumerate(commands):
            # Show phase transitions
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

            try:
                ok, error_msg = _send_cmd(cmd, i + 1)
                if ok:
                    success += 1
                else:
                    if tool == "parse-c-structure":
                        struct_failures.append(cmd)
                    errors += 1
                    va = cmd["args"].get("addressOrSymbol", cmd["args"].get("address", "?"))
                    if errors <= 30:
                        console.print(f"  ERROR at {va} ({cmd['tool']}): {error_msg}")
                    elif errors == 31:
                        console.print("  ... suppressing further errors")
            except httpx.HTTPError as exc:
                if tool == "parse-c-structure":
                    struct_failures.append(cmd)
                errors += 1
                if success > 0:
                    # Earlier ops verifiably landed (and this one may have
                    # landed server-side before the transport died):
                    # re-running the full list via a fallback would duplicate
                    # them.  Report progress and let the caller decide.
                    raise McpApplyAborted(
                        f"MCP transport failed at op {i + 1}/{total} "
                        f"({success} applied, {errors} error(s)): {exc}",
                        applied=success + errors,
                        errors=errors,
                    ) from exc
                va = cmd["args"].get("addressOrSymbol", cmd["args"].get("address", "?"))
                if errors <= 30:
                    console.print(f"  ERROR at {va} ({cmd['tool']}): {exc}")
                elif errors == 31:
                    console.print("  ... suppressing further errors")

            # Progress indicator
            if (i + 1) % 50 == 0 or i == total - 1:
                pct = (i + 1) * 100 // total
                console.print(f"  [{pct:3d}%] {i + 1}/{total} operations applied", end="\r")

            # Rate limiting — don't overwhelm the server
            if (i + 1) % 100 == 0:
                time.sleep(0.1)

        # Retry failed parse-c-structure ops (dependency ordering)
        max_retries = 3
        for retry in range(max_retries):
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
                        if retry == max_retries - 1:
                            defn = cmd["args"].get("cDefinition", "")[:80]
                            console.print(f"  PERMANENT FAIL: {error_msg} | {defn}")
                except httpx.HTTPError as exc:
                    still_failing.append(cmd)
                    if retry == max_retries - 1:
                        defn = cmd["args"].get("cDefinition", "")[:80]
                        console.print(f"  PERMANENT FAIL (HTTP): {exc} | {defn}")
            resolved = len(struct_failures) - len(still_failing)
            if resolved > 0:
                console.print(f"  Resolved {resolved} definitions on retry pass {retry + 2}")
            struct_failures = still_failing
            if struct_failures and not resolved:
                break

    console.print()  # newline after progress
    return success, errors


__all__ = [
    "MAX_MCP_PAGES",
    "MCP_HEADERS",
    "MCP_REQUEST_TIMEOUT_S",
    "McpApplyAborted",
    "McpError",
    "McpErrorKind",
    "apply_commands_via_mcp",
    "end_mcp_session",
    "fetch_all_functions",
    "fetch_all_symbols",
    "fetch_mcp_tool",
    "fetch_mcp_tool_raw",
    "init_mcp_session",
]
