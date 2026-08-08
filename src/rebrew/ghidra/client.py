"""ghidra/client.py — Low-level HTTP client for ReVa MCP endpoint communication.

Handles MCP session initialization, JSON-RPC tool invocation, and bulk function
and data fetching via ReVa HTTP endpoints.
"""

import contextlib
import json
import logging
import time
from typing import Any

import httpx
from rich.console import Console

from rebrew.ghidra.models import JsonRpcResponse, McpToolResult

console = Console(stderr=True)
logger = logging.getLogger(__name__)

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
MCP_REQUEST_TIMEOUT_S = 30


def _parse_sse_response(text: str) -> JsonRpcResponse | None:
    """Extract JSON-RPC result from an SSE (text/event-stream) response body."""
    for line in text.splitlines():
        if line.startswith("data:"):
            try:
                return JsonRpcResponse.from_dict(json.loads(line[5:].lstrip()))
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
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    headers = dict(MCP_HEADERS)
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = client.post(endpoint, json=payload, headers=headers, timeout=MCP_REQUEST_TIMEOUT_S)
    if resp.status_code != 200:
        logger.warning(
            "MCP tool %s request %s failed with HTTP %s from %s",
            tool_name,
            request_id,
            resp.status_code,
            endpoint,
        )
        return None
    ct = resp.headers.get("content-type", "")
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
        except (ValueError, UnicodeDecodeError):
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
    """Initialize an MCP session and return the session ID."""
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
    resp = client.post(
        endpoint, json=init_payload, headers=MCP_HEADERS, timeout=MCP_REQUEST_TIMEOUT_S
    )
    resp.raise_for_status()
    return str(resp.headers.get("Mcp-Session-Id", ""))


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
    all_syms: list[dict[str, Any]] = []
    start = 0
    request_id = 200

    while True:
        raw = fetch_mcp_tool(
            client,
            endpoint,
            "get-symbols",
            {
                "programPath": program_path,
                "filterDefaultNames": True,
                "maxCount": batch_size,
                "startIndex": start,
            },
            request_id,
            session_id=session_id,
        )
        request_id += 1

        metadata = None
        page_syms: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            if "totalCount" in item:
                metadata = item
            elif "address" in item or "name" in item:
                page_syms.append(item)

        all_syms.extend(page_syms)

        if metadata is None or len(page_syms) == 0:
            break
        total = metadata.get("totalCount", 0)
        next_start = metadata.get("nextStartIndex", start + batch_size)
        # Guard against a server that echoes nextStartIndex without advancing
        # (previously looped forever, one 30s HTTP call per iteration).
        if next_start <= start:
            break
        start = next_start
        if start >= total:
            break

    return all_syms


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
    to the format expected by ``pull_ghidra_renames`` (``va``, ``tool_name``, ``size``).
    """
    all_funcs: list[dict[str, Any]] = []
    start = 0
    request_id = 100

    while True:
        raw = fetch_mcp_tool(
            client,
            endpoint,
            "get-functions",
            {
                "programPath": program_path,
                "filterDefaultNames": False,
                "maxCount": batch_size,
                "startIndex": start,
            },
            request_id,
            session_id=session_id,
        )
        request_id += 1

        metadata = None
        page_funcs: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            if "totalCount" in item:
                metadata = item
            elif "address" in item or "name" in item:
                page_funcs.append(item)

        all_funcs.extend(
            {
                "va": f.get("address", f.get("va")),
                "tool_name": f.get("name", f.get("ghidra_name") or f.get("tool_name", "")),
                "size": f.get("sizeInBytes", f.get("size", 0)),
            }
            for f in page_funcs
        )

        if metadata is None or len(page_funcs) == 0:
            break
        total = metadata.get("totalCount", 0)
        start = metadata.get("nextStartIndex", start + batch_size)
        if start >= total:
            break

    return all_funcs


def apply_commands_via_mcp(
    commands: list[dict[str, Any]],
    endpoint: str = "http://localhost:8080/mcp/message",
) -> tuple[int, int]:
    """Apply sync commands to Ghidra via ReVa MCP Streamable HTTP.

    Returns (success_count, error_count).
    """
    success = 0
    errors = 0
    total = len(commands)

    with httpx.Client(timeout=MCP_REQUEST_TIMEOUT_S) as client:
        # Initialize MCP session (reuse shared helper)
        try:
            session_id = init_mcp_session(client, endpoint)
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Failed to initialize MCP session: {exc}") from exc

        if not session_id:
            console.print(
                "[yellow]warning:[/yellow] No session ID received, proceeding without one"
            )

        headers = dict(MCP_HEADERS)
        if session_id:
            headers["Mcp-Session-Id"] = session_id

        # Send initialized notification
        client.post(
            endpoint,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=headers,
            timeout=MCP_REQUEST_TIMEOUT_S,
        ).raise_for_status()

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
            resp = client.post(
                endpoint, json=payload, headers=headers, timeout=MCP_REQUEST_TIMEOUT_S
            )
            resp.raise_for_status()
            body = resp.text.strip()
            if not body:
                return False, "empty MCP response body"
            ct = resp.headers.get("content-type", "")
            if "text/event-stream" in ct:
                data = _parse_sse_response(body)
            else:
                try:
                    data = JsonRpcResponse.from_dict(resp.json())
                except (ValueError, UnicodeDecodeError):
                    return False, "invalid MCP JSON-RPC response"
            if not data:
                return False, "missing MCP JSON-RPC response"
            is_error = data.error is not None
            error_msg = data.error.message if data.error else ""
            if not is_error and data.result:
                res = McpToolResult.from_dict(data.result)
                if res.isError:
                    is_error = True
                    content = res.content
                    if content and len(content) > 0:
                        error_msg = content[0].text
                    else:
                        error_msg = str(data.result)
            if is_error:
                if "already exists" in str(error_msg).lower():
                    return True, ""
                return False, str(error_msg)
            return True, ""

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
                except httpx.HTTPError:
                    still_failing.append(cmd)
            resolved = len(struct_failures) - len(still_failing)
            if resolved > 0:
                console.print(f"  Resolved {resolved} definitions on retry pass {retry + 2}")
            struct_failures = still_failing
            if struct_failures and not resolved:
                break

    console.print()  # newline after progress
    return success, errors
