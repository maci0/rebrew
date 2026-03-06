"""Module docstring."""

import contextlib
import json
import time
from typing import Any

import httpx
import typer

from rebrew.cli import error_exit
from rebrew.ghidra.models import JsonRpcResponse, McpToolResult

_MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}
_MCP_REQUEST_TIMEOUT_S = 30


def _parse_sse_response(text: str) -> JsonRpcResponse | None:
    """Extract JSON-RPC result from an SSE (text/event-stream) response body."""
    for line in text.splitlines():
        if line.startswith("data: "):
            try:
                return JsonRpcResponse.from_dict(json.loads(line[6:]))
            except json.JSONDecodeError:
                continue
        elif line.startswith("data:"):
            try:
                return JsonRpcResponse.from_dict(json.loads(line[5:]))
            except json.JSONDecodeError:
                continue
    return None


def _fetch_mcp_tool(
    client: httpx.Client,
    endpoint: str,
    tool_name: str,
    arguments: dict[str, Any],
    request_id: int,
    session_id: str = "",
) -> list[Any]:
    """Call a ReVa MCP tool and return parsed JSON list from text content."""
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    headers = dict(_MCP_HEADERS)
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = client.post(endpoint, json=payload, headers=headers, timeout=_MCP_REQUEST_TIMEOUT_S)
    if resp.status_code != 200:
        return []
    ct = resp.headers.get("content-type", "")
    if "text/event-stream" in ct:
        data = _parse_sse_response(resp.text)
    else:
        text = resp.text.strip()
        if not text:
            return []
        try:
            data = JsonRpcResponse.from_dict(resp.json())
        except (ValueError, UnicodeDecodeError):
            return []
    if not data:
        return []
    if data.result and "content" in data.result:
        res = McpToolResult.from_dict(data.result)
        text_items = [it for it in res.content if it.type == "text"]
        if not text_items:
            return []
        # Multiple text items: each is a separate JSON object
        if len(text_items) > 1:
            objects = []
            for it in text_items:
                with contextlib.suppress(json.JSONDecodeError):
                    objects.append(json.loads(it.text))
            return objects
        # Single text item
        raw = text_items[0].text
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return parsed
            return [parsed]
        except json.JSONDecodeError:
            pass
    return []


def _fetch_mcp_tool_raw(
    client: httpx.Client,
    endpoint: str,
    tool_name: str,
    arguments: dict[str, Any],
    request_id: int,
    session_id: str = "",
) -> Any:
    """Call a ReVa MCP tool and return parsed JSON result (raw, not list-wrapped).

    Unlike ``_fetch_mcp_tool`` which always returns ``list[Any]``, this returns
    the parsed value directly — dict, list, str, or None on failure.  Used by
    the extended pull operations (prototypes, structs, comments).
    """
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    headers = dict(_MCP_HEADERS)
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = client.post(endpoint, json=payload, headers=headers, timeout=_MCP_REQUEST_TIMEOUT_S)
    if resp.status_code != 200:
        return None
    ct = resp.headers.get("content-type", "")
    if "text/event-stream" in ct:
        data = _parse_sse_response(resp.text)
    else:
        text = resp.text.strip()
        if not text:
            return None
        try:
            data = JsonRpcResponse.from_dict(resp.json())
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return None
    if not data:
        return None
    if data.result and "content" in data.result:
        res = McpToolResult.from_dict(data.result)
        text_items = [it for it in res.content if it.type == "text"]
        if not text_items:
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
        return objects if objects else None
    return None


def _init_mcp_session(client: Any, endpoint: str) -> str:
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
        endpoint, json=init_payload, headers=_MCP_HEADERS, timeout=_MCP_REQUEST_TIMEOUT_S
    )
    return str(resp.headers.get("Mcp-Session-Id", ""))


def _fetch_all_symbols(
    client: httpx.Client,
    endpoint: str,
    program_path: str,
    session_id: str,
    batch_size: int = 200,
) -> list[dict[str, Any]]:
    """Fetch all non-default symbols from ReVa MCP with pagination.

    Similar to ``_fetch_all_functions`` but uses ``get-symbols``.
    Returns dicts with ``address`` and ``name`` keys.
    """
    all_syms: list[dict[str, Any]] = []
    start = 0
    request_id = 200

    while True:
        raw = _fetch_mcp_tool(
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
        start = metadata.get("nextStartIndex", start + batch_size)
        if start >= total:
            break

    return all_syms


def _fetch_all_functions(
    client: httpx.Client,
    endpoint: str,
    program_path: str,
    session_id: str,
    batch_size: int = 200,
) -> list[dict[str, Any]]:
    """Fetch all functions from ReVa MCP with pagination.

    ReVa's ``get-functions`` returns at most *maxCount* entries per call.
    This helper pages through the full list and normalises the field names
    to the format expected by ``pull_ghidra_renames`` (``va``, ``ghidra_name``).
    """
    all_funcs: list[dict[str, Any]] = []
    start = 0
    request_id = 100

    while True:
        raw = _fetch_mcp_tool(
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

        for f in page_funcs:
            all_funcs.append(
                {
                    "va": f.get("address", f.get("va")),
                    "tool_name": f.get("name", f.get("ghidra_name") or f.get("tool_name", "")),
                    "size": f.get("sizeInBytes", f.get("size", 0)),
                }
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

    with httpx.Client(timeout=30.0) as client:
        # Initialize MCP session
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
                endpoint,
                json=init_payload,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
                timeout=_MCP_REQUEST_TIMEOUT_S,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            error_exit(f"Failed to initialize MCP session: {exc}")

        # Extract session ID from response header
        session_id = resp.headers.get("mcp-session-id", "")
        if not session_id:
            # Try to parse from SSE response body
            body = resp.text
            # Some servers return session ID in the JSON response
            try:
                data = json.loads(body)
                session_id = data.get("sessionId", "")
            except ValueError:
                pass

        if not session_id:
            typer.echo("WARNING: No session ID received, proceeding without one", err=True)

        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if session_id:
            headers["mcp-session-id"] = session_id

        # Send initialized notification
        client.post(
            endpoint,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"},
            headers=headers,
            timeout=_MCP_REQUEST_TIMEOUT_S,
        )

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
                endpoint, json=payload, headers=headers, timeout=_MCP_REQUEST_TIMEOUT_S
            )
            resp.raise_for_status()
            body = resp.text.strip()
            if not body:
                return True, ""
            ct = resp.headers.get("content-type", "")
            if "text/event-stream" in ct:
                data = _parse_sse_response(body)
            else:
                try:
                    data = JsonRpcResponse.from_dict(resp.json())
                except (ValueError, UnicodeDecodeError):
                    return True, ""
            if not data:
                return True, ""
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
                    print()  # newline after previous phase progress
                phase_labels = {
                    "create-function": "Creating functions",
                    "create-label": "Setting labels",
                    "set-comment": "Adding comments",
                    "set-bookmark": "Adding bookmarks",
                    "parse-c-structure": "Pushing struct definitions",
                    "set-function-prototype": "Setting function prototypes",
                }
                print(f"  {phase_labels.get(tool, tool)}...")
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
                        print(f"  ERROR at {va} ({cmd['tool']}): {error_msg}")
                    elif errors == 31:
                        print("  ... suppressing further errors")
            except httpx.HTTPError as exc:
                if tool == "parse-c-structure":
                    struct_failures.append(cmd)
                errors += 1
                va = cmd["args"].get("addressOrSymbol", cmd["args"].get("address", "?"))
                if errors <= 30:
                    print(f"  ERROR at {va} ({cmd['tool']}): {exc}")
                elif errors == 31:
                    print("  ... suppressing further errors")

            # Progress indicator
            if (i + 1) % 50 == 0 or i == total - 1:
                pct = (i + 1) * 100 // total
                print(f"  [{pct:3d}%] {i + 1}/{total} operations applied", end="\r")

            # Rate limiting — don't overwhelm the server
            if (i + 1) % 100 == 0:
                time.sleep(0.1)

        # Retry failed parse-c-structure ops (dependency ordering)
        max_retries = 3
        for retry in range(max_retries):
            if not struct_failures:
                break
            print(f"\n  Retrying {len(struct_failures)} struct definitions (pass {retry + 2})...")
            still_failing: list[dict[str, Any]] = []
            for cmd in struct_failures:
                try:
                    ok, error_msg = _send_cmd(cmd, total + retry * 1000)
                    if ok:
                        success += 1
                        errors -= 1
                    else:
                        still_failing.append(cmd)
                        if retry == max_retries - 1:
                            defn = cmd["args"].get("cDefinition", "")[:80]
                            print(f"  PERMANENT FAIL: {error_msg} | {defn}")
                except httpx.HTTPError:
                    still_failing.append(cmd)
            resolved = len(struct_failures) - len(still_failing)
            if resolved > 0:
                print(f"  Resolved {resolved} definitions on retry pass {retry + 2}")
            struct_failures = still_failing
            if struct_failures and not resolved:
                break

    print()  # newline after progress
    return success, errors
