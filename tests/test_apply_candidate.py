"""apply_candidate: an exact candidate is promoted in a private snapshot and the changed files come back."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import http.client
import http.server
import json
import secrets
import shutil
import threading
import tomllib
from pathlib import Path
from typing import Any, override
lazy from collections.abc import Iterator

import pytest

from rebrew.config import DEFAULT_COMPILE_TIMEOUT
from rebrew.ops import CHILD_REPORT_SECONDS, WorkerConfig, dispatch

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


def _stage(
    root: Path, source: str = "src/stub.c", extra: tuple[tuple[str, bytes], ...] = ()
) -> tuple[WorkerConfig, list[dict[str, Any]]]:
    filestore = root / "files"
    (filestore / "binaries").mkdir(parents=True)
    shutil.copyfile(BINARY, filestore / f"binaries/{SHA256}")
    workspace = root / "workspace"
    workspace.mkdir()
    entries = []
    for name, data in (
        ("rebrew-project.toml", PROJECT),
        (source, STUB),
        ("rebrew-functions.toml", FUNCTIONS.replace(b'"src/stub.c"', f'"{source}"'.encode())),
        *extra,
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


@pytest.mark.parametrize("op", ["rebrew.verify_function", "rebrew.apply_candidate"])
@pytest.mark.parametrize("shape", ["misplaced", "correct", "absent", "string", "duplicate", "line"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_candidate_anchor_is_canonical_for_verify_and_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str, shape: str, newline: str
) -> None:
    from rebrew import ops
    from rebrew.coff_reloc import build_name_to_va
    from rebrew.config import load_config
    from rebrew.metadata.anchors import parse_address_anchors
    from rebrew.metadata.functions import update_source_status

    # Same module, VA and line layout as the reported candidate; only the binary is a fixture.
    va = 0x01004116
    anchor = "/* ADDRESS: NOTEPAD 0x01004116 */"
    original = STUB.replace(b"MINI 0x00401000", b"NOTEPAD 0x01004116")
    project = PROJECT.replace(
        b'reversed_dir = "src"\n', b'reversed_dir = "src"\nmodule = "NOTEPAD"\n'
    )
    metadata = FUNCTIONS.replace(b"MINI.", b"NOTEPAD.").replace(b"0x00401000", b"0x01004116")
    monkeypatch.setitem(globals(), "STUB", original)
    monkeypatch.setitem(globals(), "PROJECT", project)
    monkeypatch.setitem(globals(), "FUNCTIONS", metadata)
    config, entries = _stage(tmp_path)
    prefix = "/* recovered candidate */\n#include <windows.h>\n\n"
    definition = "void fcn_00401000(void) {}\n"
    candidate = (
        anchor + "\n" + prefix + definition
        if shape == "misplaced"
        else prefix + (anchor + "\n" if shape == "correct" else "") + definition
    )
    if shape == "duplicate":
        candidate = anchor + "\n" + prefix + anchor + "\n" + definition
    if shape == "line":
        candidate = "// ADDRESS: NOTEPAD 0x01004116\n" + prefix + definition
    if shape == "string":
        candidate = 'const char *label = "/* ADDRESS: OTHER 0x99999999 */";\n' + candidate
    candidate = candidate.replace("\n", newline)
    seen = []
    monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")

    def run(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
        source = root / "src/stub.c"
        text = source.read_bytes().decode()
        build_name_to_va(load_config(root))
        (bound,) = parse_address_anchors(text)
        assert bound.va == va and bound.module == "NOTEPAD"
        assert text.splitlines()[bound.definition_line - 2] == anchor
        assert "#include <windows.h>" in text
        if shape == "string":
            assert '"/* ADDRESS: OTHER 0x99999999 */"' in text
        assert text.count(anchor) == 1
        if newline == "\r\n":
            assert "\n" not in text.replace("\r\n", "")
        seen.append(text)
        if op == "rebrew.apply_candidate":
            update_source_status(root, "EXACT", "NOTEPAD", va, force=True)
        return {"status": "EXACT"}

    monkeypatch.setattr(ops, "run_rebrew", run)
    status, reply = dispatch(
        config,
        op,
        _request(
            entries, candidate=candidate, va=va, source_sha256=hashlib.sha256(original).hexdigest()
        ),
    )
    assert status == 200, reply
    assert len(seen) == 1
    assert (config.filestore / entries[1]["key"]).read_bytes() == original


@pytest.mark.parametrize("op", ["rebrew.verify_function", "rebrew.apply_candidate"])
def test_candidate_cannot_claim_a_different_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str
) -> None:
    from rebrew import ops

    config, entries = _stage(tmp_path)
    monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("a conflicting candidate anchor reached the compiler")

    monkeypatch.setattr(ops, "run_rebrew", forbidden)
    status, reply = dispatch(
        config,
        op,
        _request(entries, candidate="/* ADDRESS: MINI 0x00401020 */\n" + CANDIDATE),
    )
    assert status == 400 and b"different VA" in reply


@pytest.mark.parametrize("op", ["rebrew.verify_function", "rebrew.apply_candidate"])
def test_misplaced_anchor_reaches_real_test_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    promote_in_process: list[list[str]],
    op: str,
) -> None:
    from rebrew import ops
    from rebrew.coff_reloc import build_name_to_va
    from rebrew.config import load_config

    config, entries = _stage(tmp_path)
    candidate = (
        "/* ADDRESS: MINI 0x00401000 */\n/* recovered candidate */\n"
        "#include <windows.h>\n\nvoid fcn_00401000(void) {}\n"
    )
    run_cli = ops.run_rebrew

    def scan_and_run(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
        build_name_to_va(load_config(root))
        return run_cli(args, root, *unused, **kwargs)

    monkeypatch.setattr(ops, "run_rebrew", scan_and_run)
    status, reply = dispatch(config, op, _request(entries, candidate=candidate))
    assert status == 200, reply
    result = json.loads(reply)
    assert (result["result"] if op.endswith("apply_candidate") else result)["status"] == "EXACT"
    assert bool("--no-promote" in promote_in_process[0]) == (op == "rebrew.verify_function")


def _sqlite_entries(root: Path, config: WorkerConfig) -> list[dict[str, Any]]:
    """The staged entries of the fixture project after the reviewed import into SQLite."""
    from rebrew.config import load_config
    from rebrew.metadata.sqlite import DATABASE_FILENAME
    from rebrew.metadata_transfer import migrate_metadata

    project = root / "producer"
    (project / "src").mkdir(parents=True)
    (project / "rebrew-project.toml").write_bytes(PROJECT)
    (project / "rebrew-functions.toml").write_bytes(FUNCTIONS)
    (project / "rebrew-data.toml").write_bytes(DATA)
    (project / "src/stub.c").write_bytes(STUB)
    cfg = load_config(project, target="mini")
    preview = migrate_metadata(cfg, "sqlite", dry_run=True)
    migrate_metadata(cfg, "sqlite", expected_digest=preview["input_digest"])
    assert config.filestore is not None
    entries = []
    for name in ("rebrew-project.toml", "src/stub.c", DATABASE_FILENAME):
        data = (project / name).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        (config.filestore / "binaries" / digest).write_bytes(data)
        entries.append(
            {"path": name, "digest": digest, "size": len(data), "key": f"binaries/{digest}"}
        )
    return entries


DATA = b'format = 2\n\n["MINI.0x00402000"]\nname = "g_counter"\nsize = 4\n'


def test_a_sqlite_project_returns_its_closed_store_as_the_registry(
    tmp_path: Path, promote_in_process: list[list[str]]
) -> None:
    from rebrew.metadata.sqlite import DATABASE_FILENAME, metadata_database_documents

    config, _ = _stage(tmp_path)
    entries = _sqlite_entries(tmp_path, config)
    before = (config.filestore / entries[2]["key"]).read_bytes()
    status, reply = dispatch(config, "rebrew.apply_candidate", _request(entries, cflags="/O1 /Gd"))
    assert status == 200, reply
    body = json.loads(reply)
    assert body["result"]["status"] == "EXACT" and "--no-promote" not in promote_in_process[0]
    files = {f["path"]: base64.b64decode(f["data"]) for f in body["files"]}
    assert set(files) == {"src/stub.c", DATABASE_FILENAME}
    for f in body["files"]:
        data = base64.b64decode(f["data"])
        assert f["size"] == len(data) and f["digest"] == hashlib.sha256(data).hexdigest()
    store = tmp_path / "published" / DATABASE_FILENAME
    store.parent.mkdir()
    store.write_bytes(files[DATABASE_FILENAME])
    documents = metadata_database_documents(store)
    assert set(documents) == {"rebrew-functions.toml", "rebrew-data.toml"}
    assert documents["rebrew-data.toml"] == hashlib.sha256(DATA).hexdigest()
    import sqlite3

    with sqlite3.connect(store.as_uri() + "?mode=ro", uri=True) as connection:
        (content,) = connection.execute(
            "SELECT content FROM metadata_documents WHERE path = 'rebrew-functions.toml'"
        ).fetchone()
    registry = tomllib.loads(content)
    entry = registry["MINI.0x00401000"]
    assert entry["status"] == "EXACT" and entry["cflags"] == "/O1 /Gd"
    assert entry["kind"] == "FUNCTION" and entry["symbol"] == "_add@8" and entry["name"] == "add"
    assert registry["MINI.0x00401020"]["status"] == "STUB"
    # The retained store the request named is unchanged.
    assert (config.filestore / entries[2]["key"]).read_bytes() == before


@pytest.mark.parametrize("backend", ["sqlite", "toml"])
def test_apply_refuses_the_registry_its_config_ignores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
) -> None:
    from rebrew import ops

    config, toml_entries = _stage(tmp_path)
    entries = _sqlite_entries(tmp_path, config)
    if backend == "sqlite":
        entries.append(toml_entries[2])
        ignored = "rebrew-functions.toml"
    else:
        entries[0] = toml_entries[0]
        ignored = "rebrew-metadata.sqlite3"

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("an ignored registry reached the compiler")

    monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")
    monkeypatch.setattr(ops, "run_rebrew", forbidden)
    status, reply = dispatch(config, "rebrew.apply_candidate", _request(entries))
    assert status == 400, reply
    assert json.loads(reply)["detail"] == (
        f"the retained project carries {ignored}, which its {backend} metadata ignores"
    )


#: Bound on a wait for the worker or the stand-in service, so a wedged one fails the test.
_WAIT_SECONDS = 120


@contextlib.contextmanager
def _throttling_recompile(retry_after: str) -> Iterator[str]:
    """A recompile stand-in on a local port answering every compile 429 with *retry_after*.

    The candidate ops compile in a ``rebrew test`` child process, which an
    in-process transport cannot reach.
    """

    class _Throttle(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = b"throttled"
            self.send_response(429)
            self.send_header("Retry-After", retry_after)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        @override
        def log_message(self, *_args: Any) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Throttle)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(_WAIT_SECONDS)
        server.server_close()


#: ``Retry-After`` of the throttling stand-in: longer than the child's compiles may wait.
_THROTTLE_SECONDS = 60

#: Seconds the candidate's ``rebrew test`` child gets: its report margin, one whole
#: compile request (the default ``compile_timeout`` plus the 120 s the remote backend
#: adds), and 20 s to start attempts in, so it waits out no throttle.
_CHILD_SECONDS = CHILD_REPORT_SECONDS + DEFAULT_COMPILE_TIMEOUT + 120 + 20


def _unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, url: str
) -> tuple[WorkerConfig, list[dict[str, Any]]]:
    """A retained project compiling at *url*: the service throttles past the child's deadline."""
    project = PROJECT + f'recompile_url = "{url}"\n'.encode()
    monkeypatch.setitem(globals(), "PROJECT", project)
    monkeypatch.setenv("REBREW_RECOMPILE_URL", url)
    monkeypatch.setattr("rebrew.ops.COMMAND_TIMEOUT_SECONDS", _CHILD_SECONDS)
    return _stage(tmp_path)


def test_verify_answers_a_compile_the_service_never_ran_as_a_not_run_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It answered 500 "rebrew test failed: not run (service unavailable): ...", which the
    backend stored as a failed verdict."""
    with _throttling_recompile(str(_THROTTLE_SECONDS)) as url:
        config, entries = _unavailable(tmp_path, monkeypatch, url)
        candidate = "int fcn_00401000(void) { return 0; }\n"
        status, raw = dispatch(
            config, "rebrew.verify_function", _request(entries, candidate=candidate)
        )
    reply = json.loads(raw)
    assert status == 200, reply
    assert reply["status"] == "NOT_RUN" and reply["verdict_valid"] is False
    assert reply["message"].startswith("not run (service unavailable): ")
    assert (reply["error"]["status_code"], reply["error"]["retry_after"]) == (
        429,
        float(_THROTTLE_SECONDS),
    )
    assert (config.filestore / entries[0]["key"]).read_bytes() == PROJECT


def test_apply_answers_a_compile_the_service_never_ran_as_503_with_retry_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing is applied from a candidate the service never compiled, and the caller may retry."""
    from rebrew.ops import OpsServer

    token = secrets.token_hex(16)
    with _throttling_recompile(str(_THROTTLE_SECONDS)) as url:
        config, entries = _unavailable(tmp_path, monkeypatch, url)
        with OpsServer(("127.0.0.1", 0), config, token, 1) as server:
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
            )
            thread.start()
            try:
                connection = http.client.HTTPConnection(
                    "127.0.0.1", server.server_address[1], timeout=_WAIT_SECONDS
                )
                connection.request(
                    "POST",
                    "/rebrew.apply_candidate",
                    body=_request(entries),
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    },
                )
                response = connection.getresponse()
                refusal = json.loads(response.read())
                connection.close()
            finally:
                server.shutdown()
                thread.join(_WAIT_SECONDS)
    assert (response.status, refusal["error"]) == (503, "compile-not-run"), refusal
    assert response.getheader("Retry-After") == str(_THROTTLE_SECONDS)
    assert refusal["detail"].startswith("not run (service unavailable): ")


#: A source in a subdirectory, as the backend's projects lay them out.
NESTED = "src/notepad/fcn_00401000.c"


def test_a_renamed_candidate_gets_a_verdict_and_leaves_the_retained_registry_alone(
    tmp_path: Path, promote_in_process: list[list[str]]
) -> None:
    """A candidate naming its function `add` over the registry's `fcn_00401000` failed the reloc scan.

    It answered 500 "rebrew test failed: global/function scan failed, ...: address anchor names
    'add', but the metadata names 'fcn_00401000'".
    """
    config, entries = _stage(tmp_path, NESTED)
    stored = {e["key"]: (config.filestore / e["key"]).read_bytes() for e in entries}
    status, reply = dispatch(config, "rebrew.verify_function", _request(entries, source=NESTED))
    assert status == 200, reply
    result = json.loads(reply)
    assert result["status"] == "EXACT" and result["verdict_valid"] is True
    assert result["source"] == NESTED and result["symbol"] == "_add@8"
    assert "--no-promote" in promote_in_process[0] and "--symbol=_add@8" in promote_in_process[0]
    assert "files" not in result
    assert {e["key"]: (config.filestore / e["key"]).read_bytes() for e in entries} == stored
    assert not list((tmp_path / "workspace").rglob("rebrew-functions.toml"))


def test_an_unrenamed_candidate_compares_under_its_registry_symbol(
    tmp_path: Path, promote_in_process: list[list[str]]
) -> None:
    """Verification passed the bare C name as the symbol, which rebrew test reads as an override
    differing from the function's own symbol."""
    config, entries = _stage(tmp_path)
    candidate = "void fcn_00401000(void) {}\n"
    status, reply = dispatch(
        config, "rebrew.verify_function", _request(entries, candidate=candidate)
    )
    assert status == 200, reply
    assert json.loads(reply)["symbol"] == "_fcn_00401000"
    assert "--symbol=_fcn_00401000" in promote_in_process[0]


@pytest.mark.parametrize("op", ["rebrew.verify_function", "rebrew.apply_candidate"])
def test_a_candidate_taking_another_functions_name_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str
) -> None:
    from rebrew import ops

    config, entries = _stage(tmp_path)
    monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("a candidate taking another function's name reached the compiler")

    monkeypatch.setattr(ops, "run_rebrew", forbidden)
    status, reply = dispatch(
        config, op, _request(entries, candidate="int other(void) { return 0; }\n")
    )
    assert status == 409, reply
    refusal = json.loads(reply)
    assert refusal["error"] == "candidate-name-taken"
    assert refusal["detail"] == (
        "the candidate names the function at 0x00401000 (fcn_00401000) 'other', "
        "the name of the function at 0x00401020; give it another name"
    )


def test_a_verification_that_changes_the_renamed_registry_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rebrew import ops

    config, entries = _stage(tmp_path)
    monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")

    def promoting(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
        from rebrew.metadata.functions import update_source_status

        update_source_status(root, "EXACT", "MINI", VA, force=True)
        return {"status": "EXACT"}

    monkeypatch.setattr(ops, "run_rebrew", promoting)
    status, reply = dispatch(config, "rebrew.verify_function", _request(entries))
    assert status == 400 and b"snapshot source changed during verification" in reply


@pytest.mark.parametrize("op", ["rebrew.verify_function", "rebrew.apply_candidate"])
@pytest.mark.parametrize(
    ("candidate", "code", "detail"),
    [
        (
            "int add(int a) { return a; }\nint sub(int a) { return -a; }\n",
            "candidate-not-one-function",
            "the candidate defines 2 functions (add, sub); it must define exactly one",
        ),
        (
            "this is not C at all\n",
            "candidate-not-one-function",
            "the candidate defines no C function; it must define exactly one",
        ),
        (
            "/* ADDRESS: MINI 0x00401020 */\n" + CANDIDATE,
            "candidate-address-comment",
            "candidate ADDRESS comment names a different VA",
        ),
        (
            "/* ADDRESS: MINI 0x00401000 */ " + CANDIDATE,
            "candidate-address-comment",
            "candidate ADDRESS comment must occupy one full line",
        ),
    ],
)
def test_a_candidate_a_person_can_correct_is_refused_under_its_own_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str, candidate: str, code: str, detail: str
) -> None:
    """These answered 400 invalid-request, which a caller cannot tell from its own malformed request."""
    from rebrew import ops

    config, entries = _stage(tmp_path)
    monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("a refused candidate reached the compiler")

    monkeypatch.setattr(ops, "run_rebrew", forbidden)
    status, reply = dispatch(config, op, _request(entries, candidate=candidate))
    assert (status, json.loads(reply)) == (
        400,
        {"error": code, "detail": detail, "status": 400},
    )


#: The attribution a Workbench job sends with an op that compiles.
ATTRIBUTION = {"org": "acct-org-1", "project": "prj-1", "user": "user-1", "job": "job-1"}


@contextlib.contextmanager
def _recompile(
    seen: list[dict[str, str]], *, failure: str | None = None, artifact: str = "served"
) -> Iterator[str]:
    """A recompile stand-in: every compile fails with the ``error_code`` *failure*, or is a ``ret`` object.

    An object and a ``toolchain_failure`` (the compiler's rejection) are verdicts
    recompile bills.  Each compile request's headers go to *seen*.
    *artifact* says how the object download answers: ``served``, ``refused``
    (503), ``truncated`` (the connection closes short of its Content-Length) or
    ``lost`` (the connection closes before any reply).
    """
    from bin_util import make_coff_obj

    # The helper writes a long name only for an extra symbol; the registry symbol is one.
    obj = make_coff_obj(b"\xc3", func_symbol="_x", extra_funcs=[("_fcn_00401000", 0)])

    class _Service(http.server.BaseHTTPRequestHandler):
        def _reply(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append(dict(self.headers.items()))
            verdict = (
                {"status": "ok", "artifact_url": "/api/v1/artifacts/000000000000.obj"}
                if failure is None
                else {"status": "error", "error_code": failure, "log": "error C2143"}
            )
            body = {"id": "0" * 12, "compiler": "msvc-6.0", "log": "", **verdict}
            self._reply(200, json.dumps(body).encode(), "application/json")

        def do_GET(self) -> None:
            if artifact == "served":
                self._reply(200, obj, "application/octet-stream")
                return
            self.close_connection = True
            if artifact == "refused":
                self._reply(503, b"artifact store unavailable", "text/plain")
            elif artifact == "truncated":
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(obj) + 64))
                self.end_headers()
                self.wfile.write(obj)

        @override
        def log_message(self, *_args: Any) -> None:
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Service)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(_WAIT_SECONDS)
        server.server_close()


def _compiling_at(
    url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *extra: tuple[str, bytes]
) -> Any:
    monkeypatch.setitem(globals(), "PROJECT", PROJECT + f'recompile_url = "{url}"\n'.encode())
    monkeypatch.setenv("REBREW_RECOMPILE_URL", url)
    return _stage(tmp_path, extra=extra)


def test_a_candidate_reports_its_remote_compiles_and_forwards_the_attribution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backend charges a verification by the compiles it made and meters the time it waited."""
    seen: list[dict[str, str]] = []
    with _recompile(seen) as url:
        config, entries = _compiling_at(url, tmp_path, monkeypatch)
        status, raw = dispatch(
            config,
            "rebrew.verify_function",
            _request(entries, candidate="void fcn_00401000(void) {}\n", attribution=ATTRIBUTION),
        )
    reply = json.loads(raw)
    assert status == 200, reply
    assert reply["verdict_valid"] is True
    assert set(reply["remote_compile"]) == {"count", "wait_ms"}
    assert reply["remote_compile"]["count"] == 1 == len(seen)
    assert isinstance(reply["remote_compile"]["wait_ms"], int)
    assert reply["remote_compile"]["wait_ms"] >= 0
    assert json.loads(seen[0]["X-Relumea-Attribution"]) == ATTRIBUTION


@pytest.mark.parametrize("artifact", ["refused", "truncated", "lost"])
def test_a_compile_whose_download_fails_is_still_counted_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, artifact: str
) -> None:
    """recompile settles the compile inside its POST, before the artifact is fetched."""
    seen: list[dict[str, str]] = []
    with _recompile(seen, artifact=artifact) as url:
        config, entries = _compiling_at(url, tmp_path, monkeypatch)
        status, raw = dispatch(
            config,
            "rebrew.verify_function",
            _request(entries, candidate="void fcn_00401000(void) {}\n", attribution=ATTRIBUTION),
        )
    reply = json.loads(raw)
    assert (status, reply["status"]) == (200, "NOT_RUN"), reply
    # One POST: a failed download is fetched again, never compiled again.
    assert len(seen) == 1
    assert reply["remote_compile"]["count"] == 1, reply


def test_a_compile_the_service_failed_is_not_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """recompile bills no unit for its own failure (here an exit 0 that wrote no object)."""
    seen: list[dict[str, str]] = []
    with _recompile(seen, failure="missing_artifact") as url:
        config, entries = _compiling_at(url, tmp_path, monkeypatch)
        status, raw = dispatch(
            config,
            "rebrew.verify_function",
            _request(entries, candidate="void fcn_00401000(void) {}\n"),
        )
    reply = json.loads(raw)
    assert (status, reply["status"]) == (200, "NOT_RUN"), reply
    assert len(seen) == 1
    assert reply["remote_compile"]["count"] == 0, reply


def test_a_rejected_candidate_is_refused_with_its_billed_compile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """recompile bills the compiler's rejection, so the refusal still says a compile was made."""
    seen: list[dict[str, str]] = []
    with _recompile(seen, failure="toolchain_failure") as url:
        config, entries = _compiling_at(url, tmp_path, monkeypatch)
        status, raw = dispatch(
            config,
            "rebrew.verify_function",
            _request(entries, candidate="int fcn_00401000(void) { return 0; }\n"),
        )
    refusal = json.loads(raw)
    assert (status, refusal["error"]) == (422, "toolchain-rejected"), refusal
    assert refusal["remote_compile"]["count"] == 1 == len(seen)
    # Without an attribution in the request, none goes to recompile.
    assert "X-Relumea-Attribution" not in seen[0]


#: Attributions recompile would refuse: an empty, long, or multi-line member, a missing or
#: extra member, a member that is not a string, and a value that is not an object.
MALFORMED_ATTRIBUTIONS: list[object] = [
    {**ATTRIBUTION, "org": ""},
    {**ATTRIBUTION, "job": "x" * 129},
    {**ATTRIBUTION, "user": "line\nbreak"},
    {key: value for key, value in ATTRIBUTION.items() if key != "project"},
    {**ATTRIBUTION, "extra": "x"},
    {**ATTRIBUTION, "org": 7},
    "acct-org-1",
]


@pytest.mark.parametrize("attribution", MALFORMED_ATTRIBUTIONS)
def test_a_malformed_attribution_is_refused_before_anything_compiles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attribution: object
) -> None:
    from rebrew import ops

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("a malformed attribution reached the compiler")

    monkeypatch.setattr(ops, "run_rebrew", forbidden)
    config, entries = _stage(tmp_path)
    status, raw = dispatch(
        config, "rebrew.apply_candidate", _request(entries, attribution=attribution)
    )
    assert status == 400, raw
    assert json.loads(raw)["error"] == "invalid-request"


def test_a_flag_search_states_its_compiles_before_it_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The backend prices a flag search at its ceiling before it dispatches the search."""
    from rebrew.matcher.compiler import generate_flag_combinations

    seen: list[dict[str, str]] = []
    with _recompile(seen) as url:
        config, entries = _compiling_at(url, tmp_path, monkeypatch)
        request = {
            "source": "src/stub.c",
            "source_sha256": hashlib.sha256(STUB).hexdigest(),
            "va": VA,
            "files": entries,
            "rebrew_target": "mini",
            "sha256": SHA256,
            "binary_key": f"binaries/{SHA256}",
            "tier": "quick",
            "count_only": True,
        }
        status, raw = dispatch(config, "rebrew.flag_search", json.dumps(request).encode())
    reply = json.loads(raw)
    assert status == 200, reply
    # Every combination of the tier, then the seed once.
    assert reply["candidates"] == len(generate_flag_combinations("quick", "msvc-6.0")) + 1
    assert reply["remote_compile"] == {"count": 0, "wait_ms": 0}
    assert not seen


#: The function inventory a retained target snapshot must carry.
INVENTORY = ("src/function_structure.json", b'{"functions": []}')


def _variants(entries: list[dict[str, Any]], **extra: Any) -> bytes:
    candidate = "void fcn_00401000(void) {}\n"
    body = {
        "files": entries,
        "rebrew_target": "mini",
        "sha256": SHA256,
        "binary_key": f"binaries/{SHA256}",
        "operation": "variants",
        "source": "src/stub.c",
        "candidate": candidate,
        "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
        "va": VA,
        "size": 11,
        "generations": 2,
        "population": 2,
        "seed": 7,
        **extra,
    }
    return json.dumps(body).encode()


def test_a_variant_search_reports_its_remote_compiles_and_forwards_the_attribution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every candidate of the search compiles through recompile, for the job that asked."""
    seen: list[dict[str, str]] = []
    with _recompile(seen) as url:
        config, entries = _compiling_at(url, tmp_path, monkeypatch, INVENTORY)
        status, raw = dispatch(
            config,
            "rebrew.retained_source_operation",
            _variants(entries, attribution=ATTRIBUTION),
        )
    reply = json.loads(raw)
    assert status == 200, reply
    # At most the ceiling a count_only call states.
    assert 0 < len(seen) <= 2 * 2 + 1
    assert reply["remote_compile"]["count"] == len(seen)
    assert all(json.loads(h["X-Relumea-Attribution"]) == ATTRIBUTION for h in seen)


def test_a_variant_search_states_its_compiles_before_it_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every member of every generation, then the champion's ceiling check."""
    seen: list[dict[str, str]] = []
    with _recompile(seen) as url:
        config, entries = _compiling_at(url, tmp_path, monkeypatch, INVENTORY)
        status, raw = dispatch(
            config, "rebrew.retained_source_operation", _variants(entries, count_only=True)
        )
    reply = json.loads(raw)
    assert status == 200, reply
    assert reply == {
        "result": {"candidates": 2 * 2 + 1},
        "remote_compile": {"count": 0, "wait_ms": 0},
    }
    assert not seen


@pytest.mark.parametrize("operation", ["data-set", "rename", "split", "merge", "decompme"])
def test_only_a_variant_search_can_be_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    from rebrew import ops

    def forbidden(*args: Any, **kwargs: Any) -> None:
        pytest.fail("a count reached a command")

    monkeypatch.setattr(ops, "run_rebrew", forbidden)
    config, entries = _stage(tmp_path)
    status, raw = dispatch(
        config,
        "rebrew.retained_source_operation",
        _variants(entries, operation=operation, count_only=True),
    )
    assert (status, json.loads(raw)["detail"]) == (
        400,
        "count_only applies only to the variants operation",
    ), raw
