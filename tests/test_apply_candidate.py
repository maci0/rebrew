"""apply_candidate: an exact candidate is promoted in a private snapshot and the changed files come back."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import tomllib
from pathlib import Path
from typing import Any

import pytest

from rebrew.ops import WorkerConfig, dispatch

FIXTURES = Path(__file__).parent / "fixtures"
BINARY = FIXTURES / "mini_pe.exe"
SHA256 = hashlib.sha256(BINARY.read_bytes()).hexdigest()
VA = 0x401000
PROJECT = (
    b'[project]\ndefault_target = "mini"\n'
    b'[targets.mini]\nbinary = "original/mini"\nformat = "pe"\narch = "x86_32"\nreversed_dir = "src"\n'
    b'[compiler]\nprofile = "msvc-6.0"\ncflags = "/O2 /Gd"\n'
)
STUB = b"/* ADDRESS: MINI 0x00401000 */\n\nvoid fcn_00401000(void)\n{\n}\n"
FUNCTIONS = (
    b"format = 3\n\n"
    b'["MINI.0x00401000"]\nfile = "src/stub.c"\nsymbol = "_fcn_00401000"\nname = "fcn_00401000"\n'
    b'kind = "STUB"\nsize = 11\nstatus = "STUB"\n\n'
    b'["MINI.0x00401020"]\nfile = "src/other.c"\nsymbol = "_other"\nname = "other"\nkind = "STUB"\nsize = 4\nstatus = "STUB"\n'
)
CANDIDATE = "int __stdcall add(int a, int b) { return a + b; }\n"


def _stage(root: Path) -> tuple[WorkerConfig, list[dict[str, Any]]]:
    filestore = root / "files"
    (filestore / "binaries").mkdir(parents=True)
    shutil.copyfile(BINARY, filestore / f"binaries/{SHA256}")
    workspace = root / "workspace"
    workspace.mkdir()
    entries = []
    for name, data in (
        ("rebrew-project.toml", PROJECT),
        ("src/stub.c", STUB),
        ("rebrew-functions.toml", FUNCTIONS),
    ):
        digest = hashlib.sha256(data).hexdigest()
        (filestore / "binaries" / digest).write_bytes(data)
        entries.append(
            {"path": name, "digest": digest, "size": len(data), "key": f"binaries/{digest}"}
        )
    return WorkerConfig(filestore.resolve(), workspace.resolve()), entries


@pytest.fixture
def promote_in_process(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Run `rebrew test` for real, in this process, with the compile step answering EXACT."""
    from typer.testing import CliRunner

    from rebrew import ops
    from rebrew.app.main import app as umbrella
    from rebrew.compiler.compile import CompareResult

    seen: list[list[str]] = []
    monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")

    def run(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
        seen.append(list(args))
        # monkeypatch.chdir restores the cwd even if CliRunner.invoke raises
        # (a bare os.chdir/finally pair only restores when the block is
        # entered; an exception before the try would leak the chdir into
        # every later test in the worker).
        monkeypatch.chdir(root)
        result = CliRunner().invoke(umbrella, [str(a) for a in args])
        print("CLIOUT", result.output[:800], result.exception)
        return json.loads(result.stdout)  # type: ignore[no-any-return]

    monkeypatch.setattr(ops, "run_rebrew", run)
    monkeypatch.setattr(
        "rebrew.test.compile_and_compare",
        lambda *a, **k: CompareResult(
            matched=True,
            status="EXACT",
            match_percent=100.0,
            delta=0,
            obj_bytes=b"\xc3" * 11,
            reloc_offsets=[],
        ),
    )
    return seen


def _request(entries: list[dict[str, Any]], **extra: Any) -> bytes:
    body = {
        "project_dir": "/unused",
        "source": "src/stub.c",
        "candidate": CANDIDATE,
        "sha256": SHA256,
        "va": VA,
        "size": 11,
        "files": entries,
        "source_sha256": hashlib.sha256(STUB).hexdigest(),
        "rebrew_target": "mini",
        "binary_key": f"binaries/{SHA256}",
        **extra,
    }
    return json.dumps(body).encode()


def test_an_exact_candidate_returns_its_source_and_registry(
    tmp_path: Path, promote_in_process: list[list[str]]
) -> None:
    config, entries = _stage(tmp_path)
    status, reply = dispatch(config, "rebrew.apply_candidate", _request(entries, cflags="/O1 /Gd"))
    assert status == 200, reply
    body = json.loads(reply)
    assert body["result"]["status"] == "EXACT"
    assert (
        "--cflags=/O1 /Gd" in promote_in_process[0] and "--no-promote" not in promote_in_process[0]
    )
    files = {f["path"]: base64.b64decode(f["data"]) for f in body["files"]}
    assert set(files) == {"src/stub.c", "rebrew-functions.toml"}
    source = files["src/stub.c"].decode()
    assert source.startswith("/* ADDRESS: MINI 0x00401000 */") and "__stdcall add" in source
    registry = tomllib.loads(files["rebrew-functions.toml"].decode())
    entry = registry["MINI.0x00401000"]
    assert entry["status"] == "EXACT" and entry["cflags"] == "/O1 /Gd"
    assert entry["kind"] == "FUNCTION"  # the promoted stub is no longer a stub (lint E017)
    assert entry["symbol"] == "_add@8" and entry["name"] == "add" and entry["file"] == "src/stub.c"
    other = registry["MINI.0x00401020"]
    assert other["symbol"] == "_other" and other["status"] == "STUB" and "cflags" not in other
    assert other["kind"] == "STUB"
    for f in body["files"]:
        assert (
            f["size"] == len(base64.b64decode(f["data"]))
            and f["digest"] == hashlib.sha256(base64.b64decode(f["data"])).hexdigest()
        )
    assert not any(p.name == "applied" for p in tmp_path.rglob("*"))


def test_the_anchor_goes_directly_above_the_function_not_above_the_includes(
    tmp_path: Path, promote_in_process: list[list[str]]
) -> None:
    candidate = (
        "#include <windows.h>\n\ntypedef int BOOL;\n\n"
        "BOOL __stdcall add(int a, int b)\n{\n    return a + b;\n}\n"
    )
    config, entries = _stage(tmp_path)
    status, reply = dispatch(
        config, "rebrew.apply_candidate", _request(entries, candidate=candidate)
    )
    assert status == 200, reply
    files = {f["path"]: base64.b64decode(f["data"]).decode() for f in json.loads(reply)["files"]}
    lines = files["src/stub.c"].splitlines()
    anchor = lines.index("/* ADDRESS: MINI 0x00401000 */")
    assert lines[anchor - 1] == "" and lines[anchor + 1].startswith("BOOL __stdcall add")
    assert lines[0] == "#include <windows.h>"


def test_a_candidate_that_no_longer_matches_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, promote_in_process: list[list[str]]
) -> None:
    from rebrew.compiler.compile import CompareResult

    monkeypatch.setattr(
        "rebrew.test.compile_and_compare",
        lambda *a, **k: CompareResult(
            matched=False,
            status="NEAR_MATCHING",
            match_percent=90.0,
            delta=1,
            obj_bytes=b"\xc3" * 11,
            reloc_offsets=[],
        ),
    )
    config, entries = _stage(tmp_path)
    status, reply = dispatch(config, "rebrew.apply_candidate", _request(entries))
    assert status == 400 and b"no longer matches" in reply
    # The rename happened in the private snapshot only: it is gone, and no registry or source was left anywhere.
    workspace = tmp_path / "workspace"
    assert not list(workspace.rglob("rebrew-functions.toml")) and not list(
        workspace.rglob("stub.c")
    )
    stored = (tmp_path / "files" / "binaries" / hashlib.sha256(FUNCTIONS).hexdigest()).read_bytes()
    assert stored == FUNCTIONS and b"_add" not in stored
