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
