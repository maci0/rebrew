"""Read a CliRunner result that may carry the clispec error envelope on stderr.

Success JSON stays on stdout. A JSON-mode failure leaves stdout empty and puts
``{"error":{"kind","message","hint"}}`` on the last stderr line. Tests written
against the previous ``{"error": "<string>", "code": N}`` stdout document keep
that view through :func:`cli_payload`.
"""

from __future__ import annotations

import json
from typing import Any


def cli_payload(result: Any) -> Any:
    """The command's JSON document, or the legacy error object for an envelope."""
    stdout = (getattr(result, "stdout", None) or "").strip()
    if stdout:
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            data = None
        else:
            legacy = _legacy_error(data, result)
            return data if legacy is None else legacy
    stderr = getattr(result, "stderr", None) or ""
    for line in reversed([item.strip() for item in stderr.splitlines() if item.strip()]):
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        legacy = _legacy_error(data, result)
        if legacy is not None:
            return legacy
        if not stdout:
            return data
        break
    return json.loads(stdout)


def _legacy_error(data: Any, result: Any) -> dict[str, Any] | None:
    if not isinstance(data, dict):
        return None
    error = data.get("error")
    if not isinstance(error, dict):
        return None
    if not {"kind", "message", "hint"} <= set(error):
        return None
    return {"error": error["message"], "code": getattr(result, "exit_code", None)}
