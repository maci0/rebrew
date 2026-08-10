"""llm_seed.py — optional LLM-assisted GA seed generation.

``rebrew match --llm-seed`` asks a configured LLM endpoint for alternative C
implementations of a NEAR_MATCHING function, validates each returned snippet
with tree-sitter (it must parse and define a function), and injects the
survivors into the GA's initial population as extra seeds.

Strictly optional and off by default: with no endpoint configured the flag
degrades to a warning and the GA runs unchanged.  The endpoint is taken from
``[llm] endpoint``/``api_key`` in ``rebrew-project.toml`` or the
``REBREW_LLM_ENDPOINT`` / ``REBREW_LLM_API_KEY`` environment variables.
"""

from __future__ import annotations

import logging
import os
from typing import Any

_PROMPT_TEMPLATE = """\
You are helping byte-match a C function in an old MSVC binary.  The current
C implementation almost matches the target assembly but the bytes differ.
Return exactly {count} alternative C implementations of the same function.
Constraints:
- Same signature and calling convention as the given source.
- C89 only (no // comments, no declarations after statements).
- Each implementation in a ```c fenced code block, nothing else.
- Prefer forms that change codegen: different expression shapes, loop forms,
  temp variables, pointer vs array access.

Current source:
```c
{source}
```
"""


def build_prompt(source: str, count: int = 3) -> str:
    """The exact prompt sent to the endpoint (exposed for --llm-seed --dry-run)."""
    return _PROMPT_TEMPLATE.format(source=source, count=count)


def llm_config(cfg: Any) -> dict[str, str] | None:
    """Return ``{"endpoint": ..., "api_key": ...}`` or None when not configured.

    Config ``[llm]`` keys win over environment variables.
    """
    endpoint = str(getattr(cfg, "llm_endpoint", "") or "").strip()
    api_key = str(getattr(cfg, "llm_api_key", "") or "").strip()
    if not endpoint:
        endpoint = os.environ.get("REBREW_LLM_ENDPOINT", "").strip()
    if not api_key:
        api_key = os.environ.get("REBREW_LLM_API_KEY", "").strip()
    if not endpoint:
        return None
    return {"endpoint": endpoint, "api_key": api_key}


def extract_seeds(text: str) -> list[str]:
    """Extract ```c fenced code blocks from an LLM response."""
    import re

    blocks = re.findall(r"```(?:c|C)?\s*\n(.*?)```", text, re.DOTALL)
    return [b.strip() for b in blocks if b.strip()]


def _valid_c_source(src: str) -> bool:
    """True when *src* parses and defines a function (tree-sitter)."""
    from rebrew.c_parser import extract_function_name_and_proto

    try:
        return extract_function_name_and_proto(src) is not None
    except Exception:  # noqa: BLE001 — garbage must never break seeding
        return False


def _parse_response(data: Any) -> str:
    """Best-effort text extraction from common chat-completion shapes."""
    if isinstance(data, dict):
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                msg = first.get("message") or first.get("delta") or {}
                content = msg.get("content") if isinstance(msg, dict) else None
                if isinstance(content, str):
                    return content
                if isinstance(content, list):  # OpenAI-style content parts
                    return "".join(str(p.get("text", "")) for p in content if isinstance(p, dict))
        return str(data)
    return str(data)


def _request(
    client: Any,
    conf: dict[str, str],
    source: str,
    count: int,
) -> list[str]:
    """POST the prompt and return validated C seeds.

    Raises on HTTP/parse failure — the no-raise guarantee for the GA is
    enforced by the caller :func:`request_seeds`.
    """
    headers = {"Content-Type": "application/json"}
    if conf.get("api_key"):
        headers["Authorization"] = f"Bearer {conf['api_key']}"
    payload = {
        "model": "gpt-4o-mini",  # many endpoints ignore this field
        "messages": [
            {
                "role": "user",
                "content": _PROMPT_TEMPLATE.format(source=source, count=count),
            }
        ],
        "temperature": 0.8,
    }
    resp = client.post(conf["endpoint"], json=payload, headers=headers, timeout=90)
    resp.raise_for_status()
    text = _parse_response(resp.json())
    return [s for s in extract_seeds(text) if _valid_c_source(s)]


def request_seeds(
    cfg: Any,
    source: str,
    count: int = 3,
    *,
    client: Any | None = None,
) -> list[str]:
    """Ask the configured LLM for alternative C implementations of *source*.

    Returns only tree-sitter-valid snippets.  Empty list when no endpoint is
    configured, the request fails, or the response carries no valid C.
    Never raises (the GA must run unchanged when the LLM is unavailable).
    """
    conf = llm_config(cfg)
    if conf is None:
        return []
    try:
        if client is not None:
            return _request(client, conf, source, count)
        import httpx

        with httpx.Client(timeout=90) as http:
            return _request(http, conf, source, count)
    except Exception as exc:  # noqa: BLE001 — LLM availability must never break the GA
        # --llm-seed was explicitly requested; a silent empty result hides a
        # misconfigured endpoint/key.  Warn so the user knows seeds were asked
        # for but never arrived (still return [] — the GA must run unchanged).
        logging.warning("LLM seeding requested but failed: %s", exc)
        return []
