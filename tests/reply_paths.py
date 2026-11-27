"""Fail a test whose op reply names a path of the engine's host outside a workspace path handle.

Every reply ``rebrew.ops`` answers in the suite is walked beside its op's response
schema in ``tests/fixtures/dispatch/rebrew.schema.json``: a string naming a path
under the run's temporary directory (where every test's workspace, filestore and
project live) fails the test unless the schema declares that member
``format: workspace-path`` (``rebrew.ops.replies.WORKSPACE_PATHS``).  Strings in open
members and child-command output count like any other.  A refusal's ``detail`` is
not a reply and is not walked.  Loaded through ``addopts`` like ``pytest_ansi_env``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
lazy from collections.abc import Iterator, Mapping

import pytest

import rebrew.ops as ops

_SCHEMA = json.loads(
    (Path(__file__).parent / "fixtures" / "dispatch" / "rebrew.schema.json").read_text()
)
_HANDLE = {"format": "workspace-path", "type": "string"}
_ROOTS: list[str] = []
_FOUND: list[str] = []
_run_parsed = ops._run_parsed


def _is_handle(schema: Any) -> bool:
    return isinstance(schema, dict) and (schema == _HANDLE or _HANDLE in schema.get("oneOf", ()))


def _member(schema: Any, name: str) -> Any:
    if not isinstance(schema, dict):
        return None
    if name in schema.get("properties", {}):
        return schema["properties"][name]
    additional = schema.get("additionalProperties")
    return additional if isinstance(additional, dict) else None


def _host_paths(value: Any, schema: Any, where: str) -> Iterator[str]:
    if isinstance(value, dict):
        for name, item in value.items():
            yield from _host_paths(item, _member(schema, name), f"{where}.{name}")
    elif isinstance(value, list):
        items = schema.get("items") if isinstance(schema, dict) else None
        for index, item in enumerate(value):
            yield from _host_paths(item, items, f"{where}[{index}]")
    elif (
        isinstance(value, str) and not _is_handle(schema) and any(root in value for root in _ROOTS)
    ):
        yield where


def _checked(config: Any, name: str, op: Any, request: Any) -> Mapping[str, Any]:
    reply = _run_parsed(config, name, op, request)
    response = _SCHEMA["ops"].get(name, {}).get("response")
    _FOUND.extend(f"{name} {where}" for where in _host_paths(reply, response, "$"))
    return reply


ops._run_parsed = _checked


@pytest.fixture(autouse=True)
def _no_host_path_in_replies(tmp_path_factory: pytest.TempPathFactory) -> Iterator[None]:
    base = tmp_path_factory.getbasetemp()
    _ROOTS[:] = sorted({str(base), str(base.resolve())})
    _FOUND.clear()
    yield
    found, _FOUND[:] = list(_FOUND), []
    assert not found, f"replies name a path of the engine's host: {found}"
