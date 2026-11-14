"""Candidate comparisons report the inputs their compile read and whether the verdict is complete."""

from __future__ import annotations

import hashlib
import http.server
import json
import threading
from typing import Any, override
lazy from pathlib import Path

import pytest
from test_apply_candidate import PROJECT, _request, _stage, promote_in_process
from test_metadata_sets import _ref

from rebrew.ops import dispatch
from rebrew.workspace.status import comparison_verdict_valid

__all__ = ["promote_in_process"]  # the fixture is used by name

LIBRARY = b'cflags = "/O1 /Gd"\n'
SOURCE = "src/stub.c"
VA = 0x401000
SIZE = 11


def _comparison(**changes: Any) -> dict[str, Any]:
    exact = {
        "source": SOURCE,
        "va": f"0x{VA:08x}",
        "size": SIZE,
        "status": "EXACT",
        "match_count": SIZE,
        "total": SIZE,
        "obj_size": SIZE,
        "reloc_count": 0,
        "mismatches": [],
    }
    return {**exact, **changes}


@pytest.mark.parametrize(
    ("changes", "valid"),
    [
        ({}, True),
        ({"status": "RELOC", "reloc_count": 2}, True),
        ({"status": "RELOC"}, False),
        ({"reloc_count": 1}, False),
        ({"mismatches": [{"offset": 0}]}, False),
        ({"status": "NEAR_MATCHING", "match_count": 9, "mismatches": [{}, {}]}, True),
        ({"status": "NEAR_MATCHING"}, False),
        ({"status": "SIZE_MISMATCH", "obj_size": 12, "total": 12, "match_count": 3}, True),
        ({"status": "SIZE_MISMATCH", "match_count": 3}, False),
        ({"status": "STUB", "obj_size": 1, "match_count": 0}, True),
        ({"status": "STUB", "obj_size": 1, "total": 11, "match_count": 2}, False),
        ({"status": "COMPILE_ERROR"}, False),
        ({"status": "PROVEN"}, False),
        ({"va": "0x401001"}, False),
        ({"source": "src/other.c"}, False),
        ({"size": 10}, False),
        ({"match_count": True}, False),
        ({"total": None}, False),
        ({"match_count": 12, "total": 11}, False),
    ],
)
def test_a_verdict_is_valid_only_when_its_counts_agree_with_its_status(
    changes: dict[str, Any], valid: bool
) -> None:
    assert comparison_verdict_valid(_comparison(**changes), SOURCE, VA, SIZE) is valid


@pytest.mark.parametrize("library", [False, True])
def test_verify_function_reports_its_compile_inputs_and_verdict(
    tmp_path: Path,
    promote_in_process: list[list[str]],
    monkeypatch: pytest.MonkeyPatch,
    library: bool,
) -> None:
    from rebrew import ops

    config, entries = _stage(tmp_path)
    if library:
        entries.append(_ref(config, "src/rebrew-libraries.toml", LIBRARY))
    run = ops.run_rebrew
    compiled: list[str] = []

    def record(args: Any, root: Path, *rest: Any, **kwargs: Any) -> dict[str, Any]:
        compiled.append(hashlib.sha256((root / SOURCE).read_bytes()).hexdigest())
        return run(args, root, *rest, **kwargs)

    monkeypatch.setattr(ops, "run_rebrew", record)
    candidate = "void fcn_00401000(void)\n{\n}\n"
    status, raw = dispatch(config, "rebrew.verify_function", _request(entries, candidate=candidate))
    assert status == 200, raw
    reply = json.loads(raw)
    assert "--no-promote" in promote_in_process[0]
    assert reply["compile_inputs"]["files"] == [
        {"path": "rebrew-project.toml", "sha256": hashlib.sha256(PROJECT).hexdigest()},
        {"path": SOURCE, "sha256": compiled[0]},
    ]
    inputs = reply["compile_inputs"]
    assert inputs["documents"] == (
        [
            {
                "path": "src/rebrew-libraries.toml",
                "logical_sha256": hashlib.sha256(LIBRARY).hexdigest(),
            }
        ]
        if library
        else []
    )
    assert reply["verdict_valid"] is True


def test_compile_inputs_name_the_headers_a_remote_compile_shipped(
    tmp_path: Path,
    promote_in_process: list[list[str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A verdict earned with an include bundle depends on its headers too."""
    from rebrew import ops

    header = b"#define ONE 1\n"
    config, entries = _stage(tmp_path)
    entries.append(_ref(config, "src/stub.h", header))
    run = ops.run_rebrew
    shipped = [{"path": "src/stub.h", "sha256": hashlib.sha256(header).hexdigest()}]

    def remote(args: Any, root: Path, *rest: Any, **kwargs: Any) -> dict[str, Any]:
        result = run(args, root, *rest, **kwargs)
        result["compile"] = {
            "flags": [],
            "execution": None,
            "source_dir": "src",
            "includes": shipped,
        }
        return result

    monkeypatch.setattr(ops, "run_rebrew", remote)
    candidate = "void fcn_00401000(void)\n{\n}\n"
    status, raw = dispatch(config, "rebrew.verify_function", _request(entries, candidate=candidate))
    assert status == 200, raw
    files = json.loads(raw)["compile_inputs"]["files"]
    assert {"path": "src/stub.h", "sha256": shipped[0]["sha256"]} in files

    shipped[0]["sha256"] = "0" * 64
    status, raw = dispatch(config, "rebrew.verify_function", _request(entries, candidate=candidate))
    assert status == 400, raw


class _RejectingRecompile(http.server.BaseHTTPRequestHandler):
    """A recompile whose toolchain rejects every source, over real HTTP for a child process."""

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers["Content-Length"]))
        body = json.dumps(
            {
                "status": "error",
                "error_code": "toolchain_failure",
                "log": "stub.c(4) : error C2065: 'nope' : undeclared identifier\n",
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @override
    def log_message(self, format: str, *args: Any) -> None:
        del format, args


def test_a_retained_toolchain_rejection_is_a_verdictless_422(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The retained comparison runs ``rebrew test`` as a child; its rejection keeps its kind."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RejectingRecompile)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("REBREW_RECOMPILE_URL", f"http://127.0.0.1:{server.server_port}")
        config, entries = _stage(tmp_path)
        candidate = "void fcn_00401000(void)\n{\n    nope;\n}\n"
        answers = [
            dispatch(config, op, _request(entries, candidate=candidate))
            for op in ("rebrew.verify_function", "rebrew.apply_candidate")
        ]
    finally:
        server.shutdown()
        server.server_close()
    for status, raw in answers:
        refusal = json.loads(raw)
        assert (status, refusal["error"]) == (422, "toolchain-rejected"), raw
        assert "error C2065" in refusal["detail"]
