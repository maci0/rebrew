"""Work counted per dispatch op at a fixed fixture size: the engines' ratchet.

Each op below runs on the two-function ``mini_pe.exe`` analysis, and the
test counts what its second call (the first pays one-time process reads)
does that costs more than computing: fsyncs, subprocess
spawns, SQL statements, retained snapshot builds, binary parses, source tree
scans, files opened and SQLite connections.  :data:`FLOOR` is the least each
of the first six can be for one call; :data:`OVER_FLOOR` lists the counts
still above it, so a regression fails here and so does an improvement left off
the list, which can only shrink.  Files opened have no floor: :data:`OPENS`
holds each op's ceiling at this fixture, and :data:`CONNECTIONS` the SQLite
connections each op may open (``rebrew.analyse`` keeps a project's metadata in
SQLite).  Instructions are measured by a script outside the gate, never
asserted.
"""

from __future__ import annotations

import base64
import builtins
import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any
lazy from collections.abc import Callable

import pytest
from session_cache import build_once

import rebrew.catalog.loaders
import rebrew.formats.binary_loader
import rebrew.metadata.bindings
import rebrew.ops
from rebrew.ops import WorkerConfig, dispatch

FIXTURES = Path(__file__).parent / "fixtures"
BINARY = FIXTURES / "mini_pe.exe"
SHA256 = hashlib.sha256(BINARY.read_bytes()).hexdigest()
KEY = f"binaries/{SHA256}"
ENTRY_VA = 0x401000
ENTRY_SIZE = 11

#: The least one call can do of each counted kind.
FLOOR = {
    "fsync": 0,
    "spawn": 0,
    "sql": 0,
    "snapshot": 1,
    "parse": 1,
    "scan": 1,
}

#: ``(case, counter)`` still over :data:`FLOOR`, with the count this fixture
#: answers.  Empty is the goal; an entry leaves when its count reaches the floor.
OVER_FLOOR: dict[tuple[str, str], int] = {
    # The retained snapshot's SQLite store: its validation (schema, integrity
    # check, every document), one reader's schema check, and the document reads.
    ("coverage_report retained", "sql"): 81,
}

#: SQLite connections per call: the retained snapshot's validation and one reader.
CONNECTIONS = {
    "coverage_report retained": 2,
    "coverage_report project": 0,
    "instruction_listing": 0,
    "pe_info": 0,
    "strings": 0,
    "imports": 0,
}

#: Source binding reads per call (the fixture has two sources): one per source the op reads.
BINDINGS = {
    "coverage_report retained": 2,
    "coverage_report project": 2,
    "instruction_listing": 0,
    "pe_info": 0,
    "strings": 0,
    "imports": 0,
}

#: Files opened per call at this fixture: a ceiling, not a floor.
OPENS = {
    "coverage_report retained": 74,
    "coverage_report project": 9,
    "instruction_listing": 10,
    "pe_info": 8,
    "strings": 4,
    "imports": 5,
}


def _analysed(root: Path) -> dict[str, Any]:
    root = root.resolve()
    filestore, workspace = root / "files", root / "workspace"
    (filestore / "binaries").mkdir(parents=True)
    shutil.copyfile(BINARY, filestore / KEY)
    workspace.mkdir()
    request = {"binary_id": 1, "sha256": SHA256, "name": "mini.exe", "file_key": KEY}
    status, body = dispatch(
        WorkerConfig(filestore, workspace), "rebrew.analyse", json.dumps(request).encode()
    )
    assert status == 200, body
    reply: dict[str, Any] = json.loads(body)
    return reply


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> tuple[WorkerConfig, dict[str, Any]]:
    """A worker over a copy of one analysis, and the cases' requests."""
    from rebrew.coverage_input_contract import coverage_input_digest, plan_coverage_readset
    from rebrew.ops import RetainedFile, retained_target_snapshot

    built, reply = build_once(tmp_path_factory, "op-budget-analysis", _analysed)
    root = tmp_path_factory.mktemp("op-budget")
    shutil.copytree(built, root, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".rebrew"))
    root = root.resolve()
    config = WorkerConfig(root / "files", root / "workspace")
    project = root / Path(reply["project"]).relative_to(built.resolve())
    capture = reply["analysis_capture"]
    sources = {e["path"] for e in capture["entries"] if e.get("role") == "source"}
    files = []
    for entry in capture["entries"]:
        if entry["kind"] != "file":
            continue
        data = base64.b64decode(entry["data"])
        digest = hashlib.sha256(data).hexdigest()
        (root / "files" / "binaries" / digest).write_bytes(data)
        files.append(
            {
                "path": entry["path"],
                "size": len(data),
                "digest": digest,
                "key": f"binaries/{digest}",
            }
        )
    target = capture["target"]
    with retained_target_snapshot(
        config, [RetainedFile(**item) for item in files], target, SHA256, KEY, ""
    ) as staged:
        plan = plan_coverage_readset(staged, target)
    envelope = {
        "version": 1,
        "source_revision": "a" * 64,
        "generation": "b" * 32,
        "binary_sha256": SHA256,
        "target": target,
        "analysis_manifest": "c" * 64,
        "verification_digest": hashlib.sha256(b"[]").hexdigest(),
        "readset": [
            {
                **row,
                "origin": "source"
                if row["path"] in sources or row["path"] == "rebrew-project.toml"
                else "analysis",
            }
            for row in plan
        ],
    }
    binary = {"binary_id": 1, "sha256": SHA256, "key": KEY, "name": "mini.exe"}
    address = {"project_dir": str(project), "sha256": SHA256, "va": ENTRY_VA, "size": ENTRY_SIZE}
    cases = {
        "coverage_report retained": (
            "rebrew.coverage_report",
            {
                "project_dir": str(project),
                "sha256": SHA256,
                "files": files,
                "rebrew_target": target,
                "binary_key": KEY,
                "coverage_input": envelope,
                "coverage_input_digest": coverage_input_digest(envelope),
                "verification_records": [],
            },
        ),
        "coverage_report project": (
            "rebrew.coverage_report",
            {"project_dir": str(project), "sha256": SHA256},
        ),
        "instruction_listing": ("rebrew.instruction_listing", address),
        "pe_info": ("rebrew.pe_info", binary),
        "strings": ("rebrew.strings", binary),
        "imports": ("rebrew.imports", binary),
    }
    return config, cases


def _counting(
    monkeypatch: pytest.MonkeyPatch, counts: Counter[str], name: str, owner: Any, attr: str
) -> None:
    original: Callable[..., Any] = getattr(owner, attr)

    def counted(*args: Any, **kwargs: Any) -> Any:
        counts[name] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, attr, counted)


def _traced_connect(counts: Counter[str], connect: Callable[..., Any]) -> Callable[..., Any]:
    def traced(*args: Any, **kwargs: Any) -> Any:
        connection = connect(*args, **kwargs)
        counts["connect"] += 1
        connection.set_trace_callback(lambda _statement: counts.update(("sql",)))
        return connection

    return traced


@pytest.fixture
def counted(monkeypatch: pytest.MonkeyPatch) -> Counter[str]:
    counts: Counter[str] = Counter()
    _counting(monkeypatch, counts, "fsync", os, "fsync")
    _counting(monkeypatch, counts, "fsync", os, "fdatasync")
    _counting(monkeypatch, counts, "spawn", subprocess.Popen, "__init__")
    _counting(monkeypatch, counts, "snapshot", rebrew.ops, "_stage_retained_snapshot")
    _counting(monkeypatch, counts, "parse", rebrew.formats.binary_loader, "_parse_regular")
    _counting(monkeypatch, counts, "scan", rebrew.catalog.loaders, "scan_reversed_dir")
    _counting(monkeypatch, counts, "bind", rebrew.metadata.bindings, "source_bindings")
    _counting(monkeypatch, counts, "open", io, "open")
    monkeypatch.setattr(builtins, "open", io.open)
    monkeypatch.setattr(sqlite3, "connect", _traced_connect(counts, sqlite3.connect))
    # Every counted call parses from a cold binary cache, so the counts do not depend on order.
    monkeypatch.setattr(rebrew.formats.binary_loader, "_load_binary_cache", {})
    return counts


def _run(
    config: WorkerConfig, op: str, request: dict[str, Any], counts: Counter[str], cache: Any
) -> None:
    """One warm call counted: the first call of the process pays its one-time reads."""
    for _ in range(2):
        counts.clear()
        cache.clear()
        status, body = dispatch(config, op, json.dumps(request).encode())
        assert status == 200, body[:300]


@pytest.mark.parametrize("case", sorted(OPENS))
def test_an_op_does_no_more_work_than_its_budget(
    world: tuple[WorkerConfig, dict[str, Any]], counted: Counter[str], case: str
) -> None:
    config, cases = world
    op, request = cases[case]
    _run(config, op, request, counted, rebrew.formats.binary_loader._load_binary_cache)
    over = []
    for counter, floor in FLOOR.items():
        count = counted[counter]
        listed = OVER_FLOOR.get((case, counter))
        if listed is None and count > floor:
            over.append(f"{counter}: {count} > floor {floor}")
        elif listed is not None and not floor < count <= listed:
            over.append(
                f"{counter}: {count}, listed at {listed} over floor {floor}: update the list"
            )
    if counted["open"] > OPENS[case]:
        over.append(f"open: {counted['open']} > ceiling {OPENS[case]}")
    if counted["connect"] > CONNECTIONS[case]:
        over.append(f"connect: {counted['connect']} > ceiling {CONNECTIONS[case]}")
    if counted["bind"] > BINDINGS[case]:
        over.append(f"bind: {counted['bind']} > ceiling {BINDINGS[case]}")
    assert not over, f"{case}: {'; '.join(over)}"
