"""End-to-end round trip through BinSync's own Client (the acceptance test of the sync).

rebrew pushes a migrated project; BinSync loads it; a second BinSync user
("ghidra") commits a function rename, a global rename, a struct member
rename, a prototype and a comment on its own branch; rebrew pulls them once,
a second pull changes nothing, and the next push leaves that user's branch
untouched.

BinSync (with PySide6) is too heavy for a test dependency, so the BinSync
side runs ``tests/binsync_peer.py`` under the interpreter named by
``REBREW_BINSYNC_PYTHON``; the module skips when that is unset or cannot
import ``binsync``.  Run it with::

    REBREW_BINSYNC_PYTHON=/path/to/venv/bin/python make test-one T=tests/test_binsync_roundtrip.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from rebrew.app.main import app
from rebrew.utils import md5_file

pytest.importorskip("declib")

#: Interpreter with ``binsync`` installed (BinSync is not a rebrew dependency).
_PEER_PYTHON = os.environ.get("REBREW_BINSYNC_PYTHON", "")

#: Seconds one BinSync Client invocation may take before the test fails.
_PEER_TIMEOUT = 120


def _peer_python_works() -> bool:
    if not _PEER_PYTHON or shutil.which("git") is None:
        return False
    try:
        probe = subprocess.run(
            [_PEER_PYTHON, "-I", "-c", "import binsync.core.client"],
            capture_output=True,
            timeout=_PEER_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


pytestmark = pytest.mark.skipif(
    not _peer_python_works(), reason="REBREW_BINSYNC_PYTHON does not name a Python with binsync"
)

runner = CliRunner()

_BINARY = b"MZ\x90\x00" + bytes(range(64))

_LONG_NOTE = (
    "Starts the server thread and the session table; the argument is the listener "
    "context handed over by DllMain and is never dereferenced before the lock is taken."
)

_TYPES_H = (
    "typedef void *LPVOID;\n"
    "typedef struct TOWN_REC {\n    short id;\n    short pad02;\n    int a04;\n} TOWN_REC;\n"
    "typedef struct { int id; char tag; } PADDED;\n"
)

_SERVER_C = (
    '#include "types.h"\n'
    "// GLOBAL: SERVER 0x10003000\nint g_count;\n"
    "// FUNCTION: SERVER 0x10001000\n// SIZE: 32\n"
    f"// NOTE: {_LONG_NOTE}\n"
    "int __cdecl Init(LPVOID param)\n{\n    return g_count;\n}\n"
    "// FUNCTION: SERVER 0x10001020\n// SIZE: 32\n"
    "int __cdecl CountTowns(TOWN_REC *town)\n{\n    return town->a04 + g_count;\n}\n"
)

_EDITS = {
    "functions": {
        "0x10001020": {"name": "TownCensus"},
        "0x10001000": {"type": "int __cdecl Init(char * param)"},
    },
    "globals": {"0x10003000": "g_town_count"},
    "struct_members": {"TOWN_REC": {"offset": 4, "name": "census"}},
    "comments": {"0x10001005": {"comment": "lock taken here", "func_addr": "0x10001000"}},
}


def _git(state: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(state), *args], capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


def _peer(*args: str) -> dict[str, Any]:
    script = Path(__file__).with_name("binsync_peer.py")
    done = subprocess.run(
        [_PEER_PYTHON, "-I", str(script), *args],
        capture_output=True,
        text=True,
        timeout=_PEER_TIMEOUT,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    return dict(json.loads(done.stdout))


def _rebrew(*args: str) -> dict[str, Any]:
    result = runner.invoke(app, [*args, "--json"], catch_exceptions=False)
    assert result.exit_code == 0, result.output
    return dict(json.loads(result.output))


def _tree(root: Path) -> dict[str, bytes]:
    """Every project file rebrew owns: sources and the two metadata stores."""
    paths = [*(root / "src").rglob("*"), root / "rebrew-functions.toml", root / "rebrew-data.toml"]
    return {str(p.relative_to(root)): p.read_bytes() for p in paths if p.is_file()}


def _project(root: Path) -> None:
    (root / "rebrew-project.toml").write_text(
        "[project]\nname = 'rt'\ndefault_target = 'server'\n"
        "[compiler]\nprofile = 'msvc-6.0'\ncommand = 'CL.EXE'\n"
        "[targets.server]\nbinary = 'server.dll'\nreversed_dir = 'src'\nmarker = 'SERVER'\n",
        encoding="utf-8",
    )
    (root / "server.dll").write_bytes(_BINARY)
    src = root / "src"
    src.mkdir()
    (src / "types.h").write_text(_TYPES_H, encoding="utf-8")
    (src / "server.c").write_text(_SERVER_C, encoding="utf-8")
    _rebrew("source", "migrate-markers")
    _rebrew("data", "set", "--link-symbol", "0x10003000=_g_count")
    _rebrew("data", "set", "--type", "0x10003000=int")


def test_round_trip_through_binsync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _project(tmp_path)
    state = tmp_path / "state"
    md5 = md5_file(tmp_path / "server.dll")

    _rebrew("binsync", "init", str(state), "--user", "rebrew")
    _rebrew("binsync", "push", str(state))

    loaded = _peer("load", str(state), md5, "ghidra")
    assert "rebrew" in loaded["users"]
    rebrew_state = loaded["states"]["rebrew"]
    assert rebrew_state["functions"]["0x10001000"]["type"] == "int __cdecl Init(LPVOID param)"
    assert rebrew_state["global_vars"]["0x10003000"] == "g_count"
    assert rebrew_state["structs"]["TOWN_REC"]["4"] == "a04"
    assert rebrew_state["struct_sizes"]["PADDED"] == 8

    edits = tmp_path / "edits.json"
    edits.write_text(json.dumps(_EDITS), encoding="utf-8")
    peer_head = _peer("edit", str(state), md5, "ghidra", "rebrew", str(edits))["head"]

    first = _rebrew("binsync", "pull", str(state))
    assert first["peers"] == ["ghidra"]
    assert first["conflicts"] == 0
    assert first["applied_names"] == 1
    assert first["applied_prototypes"] == 1
    assert first["applied_globals"] == 1
    assert first["applied_structs"] == 1
    assert first["applied_comments"] == 1
    assert first["applied_notes"] == 0  # the long note came back re-wrapped, not edited

    source = (tmp_path / "src" / "server.c").read_text(encoding="utf-8")
    header = (tmp_path / "src" / "types.h").read_text(encoding="utf-8")
    assert "int __cdecl Init(char * param)\n{\n    return g_town_count;\n}" in source
    assert "int __cdecl TownCensus(TOWN_REC *town)\n{\n    return town->census + g_town_count;" in (
        source
    )
    assert "int g_town_count;" in source
    assert "/* ANALYSIS @ 0x10001005: lock taken here */" in source
    assert "    int census;\n" in header
    data = (tmp_path / "rebrew-data.toml").read_text(encoding="utf-8")
    assert 'link_symbol = "_g_town_count"' in data

    settled = _tree(tmp_path)
    second = _rebrew("binsync", "pull", str(state))
    assert {k: v for k, v in second.items() if k.startswith("applied_") and v} == {}
    assert second["conflicts"] == 0
    assert _tree(tmp_path) == settled

    _rebrew("binsync", "push", str(state))
    assert _git(state, "rev-parse", "binsync/ghidra") == peer_head
    assert _git(state, "rev-parse", "--abbrev-ref", "HEAD") == "binsync/rebrew"

    reloaded = _peer("load", str(state), md5, "ghidra")
    assert reloaded["users"] == ["ghidra", "rebrew"]
    pushed = reloaded["states"]["rebrew"]
    assert pushed["functions"]["0x10001020"]["name"] == "TownCensus"
    assert pushed["global_vars"]["0x10003000"] == "g_town_count"
    assert pushed["structs"]["TOWN_REC"]["4"] == "census"
    assert pushed["struct_sizes"]["PADDED"] == 8

    third = _rebrew("binsync", "pull", str(state))
    assert {k: v for k, v in third.items() if k.startswith("applied_") and v} == {}
    assert _tree(tmp_path) == settled
