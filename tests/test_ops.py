"""Tests for ops.py: the relumea backend's rebrew op worker.

Every request and reply is checked against the backend's generated contract
(``tests/fixtures/dispatch/rebrew.schema.json``, provenance in ``NOTE.txt``
beside it).  The project the function and project ops read is the one
``rebrew.analyse`` generates from ``tests/fixtures/mini_pe.exe``.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
import http.client
import http.server
import json
import logging
import os
import secrets
import select
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, override

import pytest
from bin_util import append_pe_section, le32, make_import_call_pe
from recompile_stub import serve_recompile
from session_cache import build_once

from rebrew.discover import DISCOVERY_RULE
from rebrew.ops import COMPILING_OPS, OPS, WorkerConfig, dispatch, target_name
from rebrew.report import SITE_DATA_KINDS

FIXTURES = Path(__file__).parent / "fixtures"
BINARY = FIXTURES / "mini_pe.exe"
SHA256 = hashlib.sha256(BINARY.read_bytes()).hexdigest()
KEY = f"binaries/{SHA256}"
ENTRY_VA = 0x401000
ENTRY_SIZE = 11
TOKEN = secrets.token_hex(16)
#: Bound on any child process or HTTP wait, so a wedged worker fails the test.
WAIT_SECONDS = 120
#: The `remote_compile` of a compiling op that called no recompile service.
NO_REMOTE_COMPILES = {"count": 0, "billed_undelivered": 0, "unsettled": 0, "wait_ms": 0}

_CONTRACT = json.loads((FIXTURES / "dispatch" / "rebrew.schema.json").read_text())

#: What ``rebrew data list --json`` prints for a target with no data.
_EMPTY_DATA_LIST = {
    "globals": {},
    "data_annotations": [],
    "type_conflicts": [],
    "summary": dict.fromkeys(
        (
            "total",
            "annotated",
            "unannotated",
            "data_entries",
            "conflicts",
            "multiple_definitions",
            "library_owned",
        ),
        0,
    ),
    "sections": {},
}

# ---------------------------------------------------------------------------
# A strict JSON Schema subset: exactly the keywords the contract uses.  An
# unknown keyword fails, so a contract that grows one is noticed here.
# ---------------------------------------------------------------------------

_KEYWORDS = {
    "$schema",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "contentEncoding",
    "oneOf",
    "enum",
    "format",
}
_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def _validate(schema: Any, value: Any, where: str = "$") -> None:
    if schema is True:
        return
    unknown = set(schema) - _KEYWORDS
    assert not unknown, f"{where}: validator does not implement {sorted(unknown)}"
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        assert any(_TYPES[t](value) for t in types), f"{where}: {value!r} is not {types}"
    if "enum" in schema:
        assert value in schema["enum"], f"{where}: {value!r} is not one of {schema['enum']}"
    if "oneOf" in schema:
        matched = 0
        for option in schema["oneOf"]:
            try:
                _validate(option, value, where)
            except AssertionError:
                continue
            matched += 1
        assert matched == 1, f"{where}: {value!r} matches {matched} oneOf options"
    if schema.get("contentEncoding") is not None:
        assert schema["contentEncoding"] == "base64"
        base64.b64decode(value, validate=True)
    if isinstance(value, dict):
        missing = set(schema.get("required", ())) - set(value)
        assert not missing, f"{where}: missing {sorted(missing)}"
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            assert not extra, f"{where}: unexpected {sorted(extra)}"
        additional = schema.get("additionalProperties")
        for name, item in value.items():
            if name in properties:
                _validate(properties[name], item, f"{where}.{name}")
            elif isinstance(additional, dict):
                _validate(additional, item, f"{where}.{name}")
    if isinstance(value, list):
        assert len(value) >= schema.get("minItems", 0), where
        assert len(value) <= schema.get("maxItems", len(value)), where
        if "items" in schema:
            for index, item in enumerate(value):
                _validate(schema["items"], item, f"{where}[{index}]")


@dataclasses.dataclass(frozen=True)
class _Definition:
    """One top-level function or class of the engine's dispatch code, as the refusal tests read it."""

    #: ``(file:line, code, status)`` of each refusal call; None where a variable gives it.
    refusals: list[tuple[str, str | None, int | None]]
    #: The functions it calls by name.
    calls: set[str]
    #: Every name it reads.
    names: set[str]


#: Calls whose code and status arguments :func:`_refusal_sites` records, besides ``OpsError``.
_POSITIONAL_REFUSALS = ("_refuse", "error_body", "cancel")
_REFUSAL_CALLS = ("OpsError", *_POSITIONAL_REFUSALS)


def _refusal_sites(*modules: str) -> dict[str, _Definition]:
    """Each top-level definition of rebrew's *modules* (every module when none is named), by
    name: its ``OpsError``, ``_refuse``, ``error_body`` and ``cancel`` calls, and what it calls."""
    import ast

    from rebrew import ops

    constants = {name: value for name, value in vars(ops).items() if isinstance(value, str)}
    src = Path(ops.__file__).parent
    sites: dict[str, _Definition] = {}
    paths = [src / f"{module}.py" for module in modules] or sorted(src.rglob("*.py"))
    for path in paths:
        text = path.read_text(encoding="utf-8")
        # A whole-tree scan is read for its refusals only, and a file that names
        # none of the refusal calls has none; parsing all of src dominated it.
        if not modules and not any(call in text for call in _REFUSAL_CALLS):
            continue
        tree = ast.parse(text)
        for top in tree.body:
            if not isinstance(top, ast.FunctionDef | ast.ClassDef):
                continue
            definition = sites.setdefault(top.name, _Definition([], set(), set()))
            for node in ast.walk(top):
                if isinstance(node, ast.Name):
                    definition.names.add(node.id)
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if isinstance(func, ast.Name):
                    definition.calls.add(func.id)
                elif isinstance(func, ast.Attribute) and getattr(func.value, "id", "") in (
                    "ops",
                    "snapshot_mutations",
                ):
                    definition.calls.add(func.attr)
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                keywords = {k.arg: k.value for k in node.keywords}
                if name == "OpsError":
                    code_node, status_node = keywords.get("code"), keywords.get("status")
                elif name in _POSITIONAL_REFUSALS and len(node.args) >= 3:
                    code_node = node.args[1] if name == "cancel" else node.args[0]
                    status_node = node.args[2]
                else:
                    continue
                if isinstance(code_node, ast.Attribute):
                    code = constants.get(code_node.attr)
                elif isinstance(code_node, ast.Name):
                    code = constants.get(code_node.id)
                elif isinstance(code_node, ast.Constant):
                    code = code_node.value
                else:
                    code = None
                if code is None and code_node is None and name == "OpsError":
                    code = ops.ENGINE_ERROR
                status = status_node.value if isinstance(status_node, ast.Constant) else None
                if status is None and status_node is None and name == "OpsError":
                    status = 500
                definition.refusals.append((f"{path.name}:{node.lineno}", code, status))
    return sites


def _op_schema(op: str, part: str) -> Any:
    return _CONTRACT["ops"][op][part]


def _call(config: WorkerConfig, op: str, request: dict[str, Any]) -> Any:
    """Validate *request*, dispatch it in process, validate and return the reply."""
    _validate(_op_schema(op, "request"), request)
    status, body = dispatch(config, op, json.dumps(request).encode())
    reply = json.loads(body)
    assert status == 200, reply
    _validate(_op_schema(op, "response"), reply)
    return reply


def _refusal(config: WorkerConfig, op: str, body: bytes) -> dict[str, Any]:
    status, reply = dispatch(config, op, body)
    refusal = json.loads(reply)
    # A compiling op's refusal after a recompile call also says what that call cost.
    remote = {"remote_compile"} if op in COMPILING_OPS and "remote_compile" in refusal else set()
    assert set(refusal) == {"error", "detail", "status"} | remote
    assert refusal["status"] == status != 200
    return refusal


def _worker_dirs(root: Path) -> tuple[Path, Path]:
    """A filestore holding the fixture under its content key, and an empty workspace."""
    filestore = root / "files"
    (filestore / "binaries").mkdir(parents=True)
    shutil.copyfile(BINARY, filestore / KEY)
    workspace = root / "workspace"
    workspace.mkdir()
    return filestore, workspace


def _analyse_request() -> dict[str, Any]:
    return {"binary_id": 1, "sha256": SHA256, "name": "mini.exe", "file_key": KEY}


def _binary_file() -> dict[str, Any]:
    return {"binary_id": 1, "sha256": SHA256, "key": KEY, "name": "mini.exe"}


def _check_analysed(reply: dict[str, Any], workspace: Path) -> Path:
    project = workspace / "projects" / SHA256
    assert reply["project"] == str(project)
    assert reply["coverage_dir"] is None
    (target,) = reply["targets"]
    assert (target["name"], target["arch"], target["format"]) == ("mini", "x86_32", "pe")
    assert [(f["va"], f["size"], f["status"]) for f in target["functions"]] == [
        (0x401000, 11, "STUB"),
        (0x401010, 10, "STUB"),
    ]
    assert target["sha256"] == SHA256
    assert reply["intake"]["functions"] == 2
    assert reply["discovery_rule"] == DISCOVERY_RULE
    return project


def _analyse_fresh(root: Path) -> dict[str, Any]:
    """One ``analyse`` into the empty workspace of a worker root at *root*, and its reply."""
    root = root.resolve()
    filestore, workspace = _worker_dirs(root)
    reply = _call(WorkerConfig(filestore, workspace), "rebrew.analyse", _analyse_request())
    _check_analysed(reply, workspace)
    return reply


@pytest.fixture(scope="module")
def fresh_analysis(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    """A worker root with one ``analyse`` into its empty workspace, and the reply.

    Built once per session for every xdist worker. Tests never change it: one
    that writes works on :func:`_copy_analysed`.
    """
    root, reply = build_once(tmp_path_factory, "ops-fresh-analysis", _analyse_fresh)
    return root.resolve(), reply


def _copy_analysed(
    analysed: tuple[Path, dict[str, Any]], destination: Path
) -> tuple[WorkerConfig, Path]:
    """A worker over a copy of the analysed root at *destination*, and the copy's project.

    The ``.rebrew`` caches are left behind; they name the original paths and
    are rebuilt on demand.
    """
    root, reply = analysed
    shutil.copytree(root, destination, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".rebrew"))
    destination = destination.resolve()
    config = WorkerConfig(destination / "files", destination / "workspace")
    return config, destination / Path(reply["project"]).relative_to(root)


def _analyse_binary(root: Path, pe: bytes, name: str) -> dict[str, Any]:
    """One ``analyse`` of *pe*, stored under its content key, into a new worker root at *root*."""
    root = root.resolve()
    digest = hashlib.sha256(pe).hexdigest()
    filestore, workspace = root / "files", root / "workspace"
    (filestore / "binaries").mkdir(parents=True)
    (filestore / "binaries" / digest).write_bytes(pe)
    workspace.mkdir()
    request = {"binary_id": 1, "sha256": digest, "name": name, "file_key": f"binaries/{digest}"}
    reply: dict[str, Any] = _call(WorkerConfig(filestore, workspace), "rebrew.analyse", request)
    return reply


@pytest.fixture(scope="module")
def world(
    tmp_path_factory: pytest.TempPathFactory, fresh_analysis: tuple[Path, dict[str, Any]]
) -> tuple[WorkerConfig, Path]:
    """A worker configuration and its copy of the analysed project."""
    return _copy_analysed(fresh_analysis, tmp_path_factory.mktemp("ops"))


class TestTargetName:
    def test_nfd_and_nfc_spellings_share_one_name(self) -> None:
        # A macOS volume hands back NFD; the backend NFC spelling must
        # not mint a second target.
        assert target_name("Café.exe") == target_name("Café.exe")

    def test_ascii_names_are_unchanged(self) -> None:
        assert target_name("2k-calc.exe") == "t_2k_calc"
        assert target_name("mini.exe") == "mini"


class TestContract:
    def test_every_contract_op_is_served(self) -> None:
        assert set(OPS) == set(_CONTRACT["ops"])

    def test_request_fields_match_contract(self) -> None:
        import dataclasses

        for name, op in OPS.items():
            code = {f.name for f in dataclasses.fields(op.request)}
            contract = set(_CONTRACT["ops"][name]["request"].get("properties", {}))
            assert code == contract, name

    def test_request_enums_are_the_sets_the_ops_enforce(self) -> None:
        """A caller validating against the schema sees exactly what the op refuses others of."""
        from rebrew import ops
        from rebrew.metadata.bindings import DATA_KINDS
        from rebrew.security_scan import SEVERITY_ORDER
        from rebrew.snapshot_mutations import OPERATIONS

        enforced = {
            ("rebrew.retained_source_operation", "operation"): OPERATIONS,
            # A rename's kinds and a data-set's: each operation refuses the other's.
            ("rebrew.retained_source_operation", "kind"): {*ops.RENAME_KINDS, *DATA_KINDS},
            ("rebrew.flag_search", "tier"): ops.FLAG_SEARCH_TIERS,
            ("rebrew.disassemble", "format"): ops.DISASM_FORMATS,
            ("rebrew.reference_flirt", "format"): ops.FLIRT_FORMATS,
            ("rebrew.decompile", "backend"): ops.DECOMPILER_BACKENDS,
            ("rebrew.decompile_snapshot", "backend"): ops.DECOMPILER_BACKENDS,
            ("rebrew.structs", "decompiler"): ops.DECOMPILER_BACKENDS,
            ("rebrew.security_scan", "min_severity"): SEVERITY_ORDER,
            ("rebrew.security_scan_snapshot", "min_severity"): SEVERITY_ORDER,
        }
        published = {
            (name, field): set(schema["enum"])
            for name, entry in _CONTRACT["ops"].items()
            for field, schema in entry["request"].get("properties", {}).items()
            if "enum" in schema
        }
        assert published == {key: set(values) for key, values in enforced.items()}

    def test_the_report_manifest_publishes_its_kinds(self) -> None:
        """A consumer withholds a site file by its kinds; the schema names the set."""
        from rebrew.report import SITE_DATA_KINDS

        entry = _CONTRACT["ops"]["rebrew.report"]["response"]["properties"]["manifest"]["items"]
        assert entry["required"] == ["path", "size", "digest", "kinds"]
        assert entry["properties"]["kinds"]["items"]["enum"] == list(SITE_DATA_KINDS)

    def test_every_refusal_the_code_raises_is_a_declared_code_and_status(self) -> None:
        """``errors`` (``rebrew.ops.PROBLEMS``) holds every code and status an op or the
        HTTP transport answers: each ``OpsError``, ``_refuse``, ``error_body`` and
        ``cancel`` call that names a code constant and a literal status is in it."""
        from rebrew import ops

        undeclared = []
        checked = 0
        for definition in _refusal_sites().values():
            for where, code, status in definition.refusals:
                if code is None or status is None:
                    continue  # a code or status the call takes from a variable
                checked += 1
                if status not in ops.PROBLEMS.get(code, ()):
                    undeclared.append(f"{where} {code} {status}")
        assert checked > 30
        assert undeclared == []
        assert _CONTRACT["errors"] == {
            code: {"status": list(statuses)} for code, statuses in ops.PROBLEMS.items()
        }

    def test_a_nullable_member_is_written_as_one_of_its_type_or_null(self) -> None:
        """The backend renders a nullable as ``oneOf``; it has no ``type`` array."""
        from typing import TypedDict

        from rebrew.ops_replies import json_schema

        class Reply(TypedDict):
            hash: str | None
            record: dict[str, Any] | None

        assert json_schema(Reply)["properties"] == {
            "hash": {"oneOf": [{"type": "string"}, {"type": "null"}]},
            "record": {"oneOf": [{"type": "object"}, {"type": "null"}]},
        }

    def test_an_object_with_no_required_member_has_no_required(self) -> None:
        """The backend omits an empty ``required``."""
        from typing import TypedDict

        from rebrew.ops_replies import json_schema

        class Reply(TypedDict, total=False):
            code: str

        assert json_schema(Reply) == {
            "additionalProperties": False,
            "properties": {"code": {"type": "string"}},
            "type": "object",
        }

    def test_the_schema_holds_no_form_the_backend_cannot_render(self) -> None:
        """The schema must equal the backend's rendering byte for byte, which inlines every
        definition (no ``$ref``, no ``$defs``) and has no ``type`` array and no empty
        ``required`` (``tools.gen_dispatch_schema.UNRENDERABLE``)."""
        from tools.gen_dispatch_schema import SCHEMA, UNRENDERABLE

        text = SCHEMA.read_text(encoding="utf-8")
        assert set(UNRENDERABLE) == {'"$ref"', '"$defs"', '"type": [', '"required": []'}
        assert [form for form in UNRENDERABLE if form in text] == []

    def test_each_op_declares_the_refusals_its_code_reaches(self) -> None:
        """An op's ``errors`` are :data:`rebrew.ops.DISPATCH_PROBLEMS` and its
        ``OP_PROBLEMS``, which are exactly the other codes its handler reaches: every
        refusal call in a function the handler calls, transitively.  A code taken from
        :data:`rebrew.ops._FINAL_RECOMPILE_REFUSALS` counts each code that table holds."""
        from rebrew import ops

        sites = _refusal_sites("ops", "snapshot_mutations")
        table = {code for code, _detail in ops._FINAL_RECOMPILE_REFUSALS.values()}

        def reached(name: str) -> set[str]:
            seen: set[str] = set()
            todo = [name]
            codes: set[str] = set()
            while todo:
                function = todo.pop()
                if function in seen or function not in sites:
                    continue
                seen.add(function)
                definition = sites[function]
                codes |= {code for _where, code, _status in definition.refusals if code}
                if "_FINAL_RECOMPILE_REFUSALS" in definition.names:
                    codes |= table
                todo.extend(definition.calls)
            return codes

        wrong = {}
        for name, op in ops.OPS.items():
            other = reached(op.run.__name__) - ops.DISPATCH_PROBLEMS
            if other != ops.OP_PROBLEMS.get(name, frozenset()):
                wrong[name] = sorted(other)
        assert wrong == {}
        assert set(ops.OP_PROBLEMS) <= set(ops.OPS)
        assert not ops.DISPATCH_PROBLEMS - set(ops.PROBLEMS)
        for name in ops.OPS:
            codes = ops.DISPATCH_PROBLEMS | ops.OP_PROBLEMS.get(name, frozenset())
            assert _CONTRACT["ops"][name]["errors"] == {
                code: {"status": list(ops.PROBLEMS[code])} for code in sorted(codes)
            }

    def test_a_workspace_path_member_is_marked_by_its_format(self) -> None:
        """Each member :data:`rebrew.ops_replies.WORKSPACE_PATHS` names, and no other, is a
        string of ``format`` ``workspace-path``."""
        from rebrew.ops_replies import WORKSPACE_PATHS

        handle = {"format": "workspace-path", "type": "string"}

        def marked(node: Any, where: str) -> list[str]:
            if not isinstance(node, dict):
                return []
            found = [where] if node == handle else []
            for name, child in node.get("properties", {}).items():
                found += marked(child, f"{where}.{name}")
            found += marked(node.get("items"), f"{where}[]")
            for option in node.get("oneOf", ()):
                found += marked(option, where)
            return found

        published = {
            op: sorted(marked(entry["response"], "")) for op, entry in _CONTRACT["ops"].items()
        }
        declared = {
            op: sorted(f".{path}" for path in paths) for op, paths in WORKSPACE_PATHS.items()
        }
        assert {op: found for op, found in published.items() if found} == declared

    def test_the_engine_states_its_release_and_the_schema_it_serves(self) -> None:
        """``rebrew.release`` answers this rebrew's version and the SHA-256 of the
        checked-in dispatch schema, so a caller can refuse an engine serving another."""
        from rebrew import __version__
        from tools.gen_dispatch_schema import SCHEMA

        reply = _call(WorkerConfig(), "rebrew.release", {})
        assert reply == {
            "release": __version__,
            "schema_sha256": hashlib.sha256(SCHEMA.read_bytes()).hexdigest(),
        }

    def test_the_schema_is_what_the_generator_writes(self) -> None:
        """Each enum is written from the set the code enforces (tools/gen_dispatch_schema.py)."""
        from tools.gen_dispatch_schema import SCHEMA, render

        current = SCHEMA.read_text(encoding="utf-8")
        assert render(current) == current


def _lstrlen_calls(lstrlen: int, _local_alloc: int) -> str:
    """Win2k notepad 0x1002cf5: ``mov esi, [lstrlenW]`` once, then ``call esi`` on one arm of an
    if and again after the arms merge."""
    return (
        f"55 8bec 837d1400 56 8b35{le32(lstrlen)} 57 7409"
        "ff7514 ffd6 8bf8 eb02 33ff ff7510 ffd6 5f 5e 5d c3"
    )


def _lstrlen_call_once(lstrlen: int, _local_alloc: int) -> str:
    """The same code with the second ``call esi`` replaced by two ``nop``."""
    return (
        f"55 8bec 837d1400 56 8b35{le32(lstrlen)} 57 7409"
        "ff7514 ffd6 8bf8 eb02 33ff ff7510 9090 5f 5e 5d c3"
    )


def _analyse_import_calls(root: Path) -> dict[str, Any]:
    """The ``_lstrlen_calls`` PE analysed into a new worker root at *root*: the reply and the
    lstrlenW slot."""
    binary, slot, _ = make_import_call_pe(root, _lstrlen_calls)
    return {"reply": _analyse_binary(root, binary.read_bytes(), "calls.exe"), "slot": slot}


@pytest.fixture(scope="module")
def import_call_analysis(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, dict[str, Any], int]:
    """A worker root with the ``_lstrlen_calls`` PE analysed, the reply and the lstrlenW slot.

    Built once per session for every xdist worker; tests work on
    :func:`_import_call_project` copies.
    """
    root, built = build_once(tmp_path_factory, "ops-import-call-analysis", _analyse_import_calls)
    return root.resolve(), built["reply"], built["slot"]


def _import_call_project(
    analysis: tuple[Path, dict[str, Any], int], tmp_path: Path
) -> tuple[WorkerConfig, str, int, bytes]:
    """A copy at *tmp_path* of the ``_lstrlen_calls`` analysis: its worker, project dir, lstrlenW
    slot and bytes."""
    root, reply, slot = analysis
    config, project = _copy_analysed((root, reply), tmp_path)
    assert config.filestore is not None
    pe = (config.filestore / "binaries" / reply["targets"][0]["sha256"]).read_bytes()
    return config, str(project), slot, pe


def _slot_calls(reply: dict[str, Any], slot: int) -> list[tuple[str, int]]:
    return [
        (row["kind"], row["from_va"])
        for row in reply["references"]
        if row["to_va"] == slot and row["from_va"] < ENTRY_VA + 0x25
    ]


class TestCallReferences:
    def test_binary_call_scan(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.call_references", {"project_dir": str(project)})
        assert isinstance(reply["references"], list)
        assert all(
            row["kind"] in {"call", "jmp", "iat_call", "iat_jmp"} for row in reply["references"]
        )
        assert reply["references"] == sorted(
            reply["references"], key=lambda row: (row["from_va"], row["to_va"], row["kind"])
        )
        assert reply["import_slots"] == sorted(reply["import_slots"], key=lambda row: row["va"])

    def test_calls_through_a_register_holding_an_import(
        self, import_call_analysis: tuple[Path, dict[str, Any], int], tmp_path: Path
    ) -> None:
        config, project, slot, _ = _import_call_project(import_call_analysis, tmp_path)
        reply = _call(config, "rebrew.call_references", {"project_dir": project})
        assert _slot_calls(reply, slot) == [
            ("iat_call", ENTRY_VA + 0x14),
            ("iat_call", ENTRY_VA + 0x1F),
        ]
        assert {"va": slot, "name": "lstrlenW"} in reply["import_slots"]

    def test_a_binary_is_scanned_again_only_once_its_bytes_change(
        self,
        import_call_analysis: tuple[Path, dict[str, Any], int],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import rebrew.analysis
        import rebrew.ops

        config, project, slot, pe = _import_call_project(import_call_analysis, tmp_path)
        scanned: list[Path] = []
        scan = rebrew.analysis.scan_references

        def counted(info: Any) -> Any:
            scanned.append(info.path)
            return scan(info)

        monkeypatch.setattr(rebrew.ops, "_call_scans", {})
        monkeypatch.setattr(rebrew.analysis, "scan_references", counted)
        request = {"project_dir": project}
        first = _call(config, "rebrew.call_references", request)
        assert _call(config, "rebrew.call_references", request) == first
        assert len(scanned) == 1
        (target,) = [p for p in Path(project).rglob("*") if p.is_file() and p.read_bytes() == pe]
        (tmp_path / "changed").mkdir()
        changed, changed_slot, _ = make_import_call_pe(tmp_path / "changed", _lstrlen_call_once)
        assert changed_slot == slot
        target.write_bytes(changed.read_bytes())
        reply = _call(config, "rebrew.call_references", request)
        assert len(scanned) == 2
        assert _slot_calls(reply, slot) == [("iat_call", ENTRY_VA + 0x14)]


class TestListingOps:
    @pytest.mark.parametrize(
        ("fmt", "first"),
        [
            ("asm", "push ebp\nmov ebp, esp\n"),
            ("nasm", "bits 32\norg 0x00401000\n"),
            ("hex", "  0x00401000:  55"),
        ],
    )
    def test_disassemble(self, world: tuple[WorkerConfig, Path], fmt: str, first: str) -> None:
        config, project = world
        request = {"project_dir": str(project), "va": ENTRY_VA, "size": ENTRY_SIZE, "format": fmt}
        assert _call(config, "rebrew.disassemble", request)["text"].startswith(first)

    def test_instruction_listing_is_the_original_against_itself(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        config, project = world
        request = {"project_dir": str(project), "sha256": SHA256, "va": ENTRY_VA, "size": 3}
        reply = _call(config, "rebrew.instruction_listing", request)
        assert reply["max_bytes"] == 8192 and reply["truncated"] is False
        assert reply["original"] == reply["rebuilt"]
        assert [(i["offset"], i["mnemonic"], i["operands"]) for i in reply["original"]] == [
            (0, "push", "ebp"),
            (1, "mov", "ebp, esp"),
        ]
        assert reply["original"][1]["spans"] == [
            {"start": 0, "end": 3, "kind": "register", "value": 0},
            {"start": 5, "end": 8, "kind": "register", "value": 1},
        ]
        assert reply["rows"] == [
            {"op": "equal", "left": 0, "right": 0},
            {"op": "equal", "left": 1, "right": 1},
        ]
        for size in (0, 8193):
            refusal = _refusal(
                config, "rebrew.instruction_listing", json.dumps({**request, "size": size}).encode()
            )
            assert refusal["error"] == "invalid-request"

    def test_disassemble_selects_the_target_by_sha256(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        config, project = world
        request = {
            "project_dir": str(project),
            "sha256": SHA256,
            "arch": "x86_32",
            "va": ENTRY_VA,
            "size": 1,
            "format": "asm",
        }
        assert _call(config, "rebrew.disassemble", request)["text"] == "push ebp\n"
        request["sha256"] = "0" * 64
        refusal = _refusal(config, "rebrew.disassemble", json.dumps(request).encode())
        assert refusal["detail"] == "no target of project_dir has a binary with that sha256"

    def test_nasm_refuses_another_arch(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {
            "project_dir": str(project),
            "arch": "x86_64",
            "va": ENTRY_VA,
            "size": ENTRY_SIZE,
            "format": "nasm",
        }
        refusal = _refusal(config, "rebrew.disassemble", json.dumps(request).encode())
        assert refusal["status"] == 400

    @pytest.mark.parametrize("fmt", ["hex", "asm"])
    def test_arch_override_applies_to_every_format(
        self, world: tuple[WorkerConfig, Path], fmt: str
    ) -> None:
        config, project = world
        request = {
            "project_dir": str(project),
            "arch": "x86_16",
            "va": ENTRY_VA,
            "size": 1,
            "format": fmt,
        }
        first = _call(config, "rebrew.disassemble", request)["text"].splitlines()[0]
        assert first.split()[-2:] == ["push", "bp"]

    def test_unknown_arch_is_refused(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {
            "project_dir": str(project),
            "arch": "vax",
            "va": ENTRY_VA,
            "size": 1,
            "format": "hex",
        }
        refusal = _refusal(config, "rebrew.disassemble", json.dumps(request).encode())
        assert (refusal["status"], refusal["detail"]) == (400, "unsupported arch: vax")

    @pytest.mark.parametrize("fmt", ["asm", "hex"])
    def test_disassemble_extent_is_bounded_like_the_other_extent_ops(
        self, world: tuple[WorkerConfig, Path], fmt: str
    ) -> None:
        """The size was unchecked: the listing read to the end of the file."""
        config, project = world
        request = {"project_dir": str(project), "va": ENTRY_VA, "size": 2**40, "format": fmt}
        refusal = _refusal(config, "rebrew.disassemble", json.dumps(request).encode())
        assert (refusal["status"], refusal["detail"]) == (
            400,
            f"size must be at most {1 << 20} bytes, got {2**40}",
        )

    def test_disassemble_bytes(self) -> None:
        code = base64.b64encode(b"\x55\x48\x89\xe5\xc3").decode()
        reply = _call(
            WorkerConfig(), "rebrew.disassemble_bytes", {"code": code, "va": 0, "arch": "x86_64"}
        )
        assert reply["text"] == "push rbp\nmov rbp, rsp\nret\n"


#: MSVC 6's two-level switch at 0x401000 (tests/test_cfg_ged.py TWO_LEVEL,
#: rebased): cases at 0x401014 and 0x40101a, default at 0x401020, a nop, the
#: 3-entry address table at 0x401024 and the 6-byte index table at 0x401030.
SWITCH = bytes.fromhex(
    "83f805 771b 33c9 8a8830104000 ff248d24104000"
    "b801000000c3 b802000000c3 33c0c3 90"
    "14104000 1a104000 20104000 000101020002"
)
SWITCH_ASM = """\
cmp eax, 5
ja 0x401020
xor ecx, ecx
mov cl, byte ptr [eax + 0x401030]
jmp dword ptr [ecx*4 + 0x401024]
mov eax, 1
ret
mov eax, 2
ret
xor eax, eax
ret
nop
jump_table_00401024:
dd 0x401014
dd 0x40101a
dd 0x401020
jump_table_00401030:
db 0x0
db 0x1
db 0x1
db 0x2
db 0x0
db 0x2
"""


def _analyse_switch(root: Path) -> dict[str, Any]:
    """A PE holding SWITCH at 0x401000 analysed into a new worker root at *root*, and the reply."""
    from bin_util import make_pe

    return _analyse_binary(root, make_pe(SWITCH + b"\xc3"), "switch.exe")


@pytest.fixture(scope="module")
def switch_analysis(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    """A worker root with SWITCH's PE analysed, and the reply.

    Built once per session for every xdist worker; tests work on
    :func:`_switch_project` copies.
    """
    root, reply = build_once(tmp_path_factory, "ops-switch-analysis", _analyse_switch)
    return root.resolve(), reply


@pytest.fixture
def switch_project(
    switch_analysis: tuple[Path, dict[str, Any]], tmp_path: Path
) -> tuple[WorkerConfig, str, str]:
    """A copy of the SWITCH analysis of the test's own: worker, project dir, sha256."""
    config, project = _copy_analysed(switch_analysis, tmp_path)
    return config, str(project), switch_analysis[1]["targets"][0]["sha256"]


class TestJumpTableListings:
    """A jump table inside the function is data in every listing, as it is in the CFG."""

    def test_asm_lists_the_tables_as_labelled_data(
        self, switch_project: tuple[WorkerConfig, str, str]
    ) -> None:
        config, project, _ = switch_project
        request = {"project_dir": project, "va": ENTRY_VA, "size": len(SWITCH), "format": "asm"}
        assert _call(config, "rebrew.disassemble", request)["text"] == SWITCH_ASM

    @pytest.mark.skipif(shutil.which("nasm") is None, reason="nasm not installed")
    def test_nasm_lists_the_tables_as_labelled_data(
        self, switch_project: tuple[WorkerConfig, str, str]
    ) -> None:
        config, project, _ = switch_project
        request = {"project_dir": project, "va": ENTRY_VA, "size": len(SWITCH), "format": "nasm"}
        lines = _call(config, "rebrew.disassemble", request)["text"].splitlines()
        assert lines[lines.index("jump_table_00401024:") + 1 :][:3] == [
            f"    {'dd 0x401014':40s} ; 00401024  14104000",
            f"    {'dd 0x40101a':40s} ; 00401028  1a104000",
            f"    {'dd 0x401020':40s} ; 0040102C  20104000",
        ]
        assert (
            lines[lines.index("jump_table_00401030:") + 1] == f"    {'db 0x0':40s} ; 00401030  00"
        )
        assert not any(line.startswith("    db 0x") and "trailing" in line for line in lines)
        code = base64.b64encode(SWITCH).decode()
        request = {"code": code, "va": ENTRY_VA, "arch": "x86_32"}
        bytes_reply = _call(config, "rebrew.disassemble_bytes", request)
        assert bytes_reply["text"].splitlines()[4:] == lines[4:]

    def test_hex_lists_the_tables_as_data(
        self, switch_project: tuple[WorkerConfig, str, str]
    ) -> None:
        config, project, _ = switch_project
        request = {"project_dir": project, "va": ENTRY_VA, "size": len(SWITCH), "format": "hex"}
        lines = _call(config, "rebrew.disassemble", request)["text"].splitlines()
        assert lines[12:15] == [
            f"  0x00401024:  {'14104000':<20s}  {'dd':<8s} 0x401014  ; jump table",
            f"  0x00401028:  {'1a104000':<20s}  {'dd':<8s} 0x40101a",
            f"  0x0040102c:  {'20104000':<20s}  {'dd':<8s} 0x401020",
        ]
        assert len(lines) == 12 + 3 + 6

    def test_instruction_listing_decodes_the_tables_as_data(
        self, switch_project: tuple[WorkerConfig, str, str]
    ) -> None:
        config, project, digest = switch_project
        request = {"project_dir": project, "sha256": digest, "va": ENTRY_VA, "size": len(SWITCH)}
        reply = _call(config, "rebrew.instruction_listing", request)
        rows = [(i["offset"], i["mnemonic"], i["operands"]) for i in reply["original"]]
        assert rows[12:] == [
            (0x24, "dd", "0x401014"),
            (0x28, "dd", "0x40101a"),
            (0x2C, "dd", "0x401020"),
            *[(0x30 + k, "db", f"0x{slot:x}") for k, slot in enumerate([0, 1, 1, 2, 0, 2])],
        ]


#: ``asm.LISTING_RENDERER`` and the SHA-256 of the listing text
#: :func:`TestListingRenderer.test_the_renderer_names_the_listing_text` hashes.
RECORDED_RENDERER = "1"
RECORDED_DIGEST = "3901883ff9502133f09b5ce6b36ee8c24a2b4d1d8a2f2d78d9a53afd8e5a1fe9"
#: Code past SWITCH's: a frame, an indirect call and an undecodable tail (32-bit),
#: a 64-bit and a 16-bit function, at ENTRY_VA.
LISTING_CODE = (
    ("x86_32", "558bec8b450883e4f0ffd06affc9c30f"),
    ("x86_64", "554889e5488b0548000000ffd05dc3"),
    ("x86_16", "5589e58b46048b5e06cd215dc3"),
)


class TestListingRenderer:
    """The backend keeps a listing while the renderer the op reports is unchanged."""

    @pytest.mark.skipif(shutil.which("nasm") is None, reason="nasm not installed")
    def test_the_renderer_names_the_listing_text(
        self, switch_project: tuple[WorkerConfig, str, str]
    ) -> None:
        """A change to the text of these listings needs a new ``LISTING_RENDERER``,
        recorded here with the new digest."""
        from rebrew import asm

        config, project, _ = switch_project
        digest = hashlib.sha256()
        replies = []
        for arch in ("", "x86_64", "x86_16"):
            for fmt in ("nasm", "asm", "hex"):
                if arch and fmt == "nasm":
                    continue
                request = {"project_dir": project, "va": ENTRY_VA, "size": len(SWITCH)}
                replies.append(
                    _call(config, "rebrew.disassemble", {**request, "format": fmt, "arch": arch})
                )
        for arch, code in LISTING_CODE:
            request = {"code": base64.b64encode(bytes.fromhex(code)).decode(), "va": ENTRY_VA}
            replies.append(_call(config, "rebrew.disassemble_bytes", {**request, "arch": arch}))
        for reply in replies:
            digest.update(reply["text"].encode())
        assert {reply["renderer"] for reply in replies} == {asm.listing_renderer()}
        assert asm.listing_renderer().startswith(asm.LISTING_RENDERER + "+capstone-")
        assert (asm.LISTING_RENDERER, digest.hexdigest()) == (RECORDED_RENDERER, RECORDED_DIGEST)


class TestFunctionOps:
    def _address(self, project: Path, **extra: Any) -> dict[str, Any]:
        return {"project_dir": str(project), "sha256": SHA256, "va": ENTRY_VA, **extra}

    def test_control_flow_graph(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.control_flow_graph", self._address(project, size=11))
        assert (reply["block_count"], reply["blocks"][0]["last"]) == (1, "ret")

    def test_xrefs(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.xrefs", self._address(project, kinds=["call"]))
        assert (reply["target"], reply["count"]) == (ENTRY_VA, 0)
        reply = _call(config, "rebrew.xrefs", self._address(project, kinds=["iat_call", "and_mem"]))
        assert reply["count"] == 0

    @pytest.mark.parametrize("kinds", [["bogus"], ["call", ""], ["_mem"], ["call"] * 65])
    def test_xrefs_refuses_a_kind_no_reference_can_have(
        self, world: tuple[WorkerConfig, Path], kinds: list[str]
    ) -> None:
        """An unknown kind matched nothing and answered an empty list as a result."""
        config, project = world
        body = json.dumps(self._address(project, kinds=kinds)).encode()
        assert _refusal(config, "rebrew.xrefs", body)["status"] == 400

    def test_describe(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.describe", self._address(project))
        assert (reply["name"], reply["size"], reply["status"]) == ("fcn_00401000", 11, "STUB")

    def test_describe_refuses_an_address_outside_the_image(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        config, project = world
        body = json.dumps({**self._address(project), "va": 0x10}).encode()
        assert _refusal(config, "rebrew.describe", body)["detail"] == (
            "VA 0x10 is outside the binary image"
        )

    def test_decompile_refuses_an_address_outside_the_image(
        self, world: tuple[WorkerConfig, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Same 400 the describe op gives for the same client mistake; the
        # engine error (500) is reserved for a valid address the backend
        # cannot decompile, not for an address outside the image.
        TestDecompilersOffered._engine(monkeypatch, kuna=True)
        config, project = world
        request = {**self._address(project), "va": 0x10, "backend": "auto", "named": False}
        refusal = _refusal(config, "rebrew.decompile", json.dumps(request).encode())
        assert (refusal["error"], refusal["status"], refusal["detail"]) == (
            "invalid-request",
            400,
            "VA 0x10 is outside the binary image",
        )

    def test_decompile(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {**self._address(project), "backend": "auto", "named": True}
        status, body = dispatch(config, "rebrew.decompile", json.dumps(request).encode())
        reply = json.loads(body)
        if status != 200 and reply["error"] == "decompiler-not-offered":
            pytest.skip("no decompiler backend is installed")
        assert status == 200, reply
        _validate(_op_schema("rebrew.decompile", "response"), reply)
        assert reply["code"]

    def test_identify_library(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.identify_library", {"project_dir": str(project)})
        assert (reply["identified"], reply["written"]) == (0, 0)

    @pytest.mark.parametrize(("limit", "decompiled"), [(0, 2), (1, 1), (5, 2)])
    def test_structs_limit_zero_means_no_cap(
        self,
        world: tuple[WorkerConfig, Path],
        monkeypatch: pytest.MonkeyPatch,
        limit: int,
        decompiled: int,
    ) -> None:
        # The decompiler is an external engine; a fake one records the calls.
        calls: list[int] = []

        def fake_decompiler(_backend: str, _binary: Path, va: int, _root: Path) -> tuple[str, str]:
            calls.append(va)
            return "int f(int *p) { return p[1]; }", "kuna"

        monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", fake_decompiler)
        TestDecompilersOffered._engine(monkeypatch, kuna=True)
        config, project = world
        request = {
            "binary_id": 1,
            "project_dir": str(project),
            "decompiler": "kuna",
            "limit": limit,
        }
        reply = _call(config, "rebrew.structs", request)
        assert (reply["decompiled"], len(calls)) == (decompiled, decompiled)

    def test_structs_without_a_decompilation_is_refused(
        self, world: tuple[WorkerConfig, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", lambda *_args: ("", "kuna"))
        TestDecompilersOffered._engine(monkeypatch, kuna=True)
        config, project = world
        request = {"binary_id": 1, "project_dir": str(project), "decompiler": "kuna", "limit": 0}
        refusal = _refusal(config, "rebrew.structs", json.dumps(request).encode())
        assert (refusal["error"], refusal["status"], refusal["detail"]) == (
            "no-decompilation",
            422,
            "decompiler 'kuna' produced no code for any selected function",
        )

    def test_operand_locations(self, world: tuple[WorkerConfig, Path]) -> None:
        config, _project = world
        # push ebp (offset 0, one operand), mov ebp, esp (offset 1, two operands);
        # offset 2 is inside the mov.
        function = {"va": ENTRY_VA, "size": ENTRY_SIZE, "locations": [[0, 0], [1, 1], [2, 0]]}
        request = {"sha256": SHA256, "file": KEY, "functions": [function]}
        reply = _call(config, "rebrew.binary_operand_locations", request)
        assert reply == {"locations": [[[0, 0], [1, 1]]]}


class TestScanOps:
    @pytest.mark.parametrize(
        ("op", "field", "expected"),
        [
            ("rebrew.fingerprint", "sha256", SHA256),
            ("rebrew.strings", "count", 0),
            ("rebrew.crypto_scan", "count", 0),
            ("rebrew.pe_info", "format", "pe"),
        ],
    )
    def test_scan(
        self, world: tuple[WorkerConfig, Path], op: str, field: str, expected: Any
    ) -> None:
        config, _project = world
        assert _call(config, op, _binary_file())[field] == expected

    def test_imports(self, world: tuple[WorkerConfig, Path]) -> None:
        config, _project = world
        reply = _call(config, "rebrew.imports", _binary_file())
        assert [(i["dll"], i["name"]) for i in reply["imports"]] == [
            ("KERNEL32.dll", "GetTickCount")
        ]

    def test_analyze(self, world: tuple[WorkerConfig, Path]) -> None:
        config, _project = world
        assert _call(config, "rebrew.analyze", _binary_file())["meta"]["format"] == "pe"

    def test_crypto_scan_names_each_constant(self, tmp_path: Path) -> None:
        sha1_h = struct.pack("<5I", 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
        pe = append_pe_section(BINARY.read_bytes(), ".rdata", sha1_h)
        filestore, workspace = _worker_dirs(tmp_path)
        digest = hashlib.sha256(pe).hexdigest()
        (filestore / "binaries" / digest).write_bytes(pe)
        request = {**_binary_file(), "sha256": digest, "key": f"binaries/{digest}"}
        reply = _call(WorkerConfig(filestore, workspace), "rebrew.crypto_scan", request)
        assert [(f["kind"], f["name"], f["section"]) for f in reply["findings"]] == [
            ("constant", "SHA-1 initial hash H", ".rdata")
        ]


class TestProjectOps:
    def test_report_writes_under_the_workspace(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {"binary_id": 1, "project_dir": str(project), "output_dir": "reports/1"}
        reply = _call(config, "rebrew.report", request)
        assert config.workspace is not None
        assert reply["out"] == str(config.workspace / "reports" / "1")
        assert (config.workspace / "reports" / "1" / "index.html").is_file()

    @pytest.mark.parametrize("output_dir", ["/tmp/out", "../out", "reports/../.."])
    def test_report_refuses_an_output_outside_the_workspace(
        self, world: tuple[WorkerConfig, Path], output_dir: str
    ) -> None:
        config, project = world
        body = {"binary_id": 1, "project_dir": str(project), "output_dir": output_dir}
        assert _refusal(config, "rebrew.report", json.dumps(body).encode())["status"] == 400

    def test_security_scan(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {"binary_id": 1, "project_dir": str(project), "min_severity": "low"}
        reply = _call(config, "rebrew.security_scan", request)
        assert (reply["files_scanned"], reply["count"]) == (2, 0)

    def test_import_project_live(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.import-project", {"project_dir": str(project)})
        assert (reply["project"], reply["coverage_dir"]) == (str(project), None)
        assert [f["name"] for f in reply["targets"][0]["functions"]] == [
            "fcn_00401000",
            "fcn_00401010",
        ]

    def test_import_project_build_db_reads_live_coverage(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        config, project = world
        request = {"project_dir": str(project), "build_db": True}
        reply = _call(config, "rebrew.import-project", request)
        assert (reply["coverage_dir"], len(reply["targets"][0]["functions"])) == (None, 2)

    def test_import_project_from_snapshots(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path
    ) -> None:
        from rebrew.coverage_db import write_coverage

        config, project = world
        assert config.workspace is not None
        exports = config.workspace / "exports" / tmp_path.name
        exports.mkdir(parents=True)
        write_coverage(project, exports, target=None, json_output=True)
        request = {"project_dir": str(project), "snapshots": str(exports)}
        reply = _call(config, "rebrew.import-project", request)
        assert reply["coverage_dir"] == str(exports)
        assert reply["targets"][0]["document"] == str(exports / "coverage-mini.toml")
        assert len(reply["targets"][0]["functions"]) == 2
        request["build_db"] = True
        assert _refusal(config, "rebrew.import-project", json.dumps(request).encode())[
            "detail"
        ] == ("snapshots and build_db exclude each other")

        write_coverage(project, tmp_path, target=None, json_output=True)
        outside = {"project_dir": str(project), "snapshots": str(tmp_path)}
        assert _refusal(config, "rebrew.import-project", json.dumps(outside).encode())[
            "detail"
        ] == ("snapshots must be inside the worker workspace")


class TestProjectPaths:
    """project_dir is absolute and, with a workspace, resolves inside it."""

    def test_relative_project_dir_is_refused(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        relative = os.path.relpath(project)
        body = json.dumps({"project_dir": relative}).encode()
        assert _refusal(config, "rebrew.identify_library", body)["detail"] == (
            "project_dir must be an absolute path"
        )

    def test_dotdot_inside_the_workspace_is_resolved(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        config, project = world
        dotted = project / ".." / project.name
        reply = _call(config, "rebrew.import-project", {"project_dir": str(dotted)})
        assert reply["project"] == str(project)

    def test_project_outside_the_workspace_is_refused(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path
    ) -> None:
        config, project = world
        outside = tmp_path / "copy"
        shutil.copytree(project, outside, symlinks=True)
        assert config.workspace is not None
        link = config.workspace / f"link-{tmp_path.name}"
        link.symlink_to(outside)
        for path in (outside, link, config.workspace / ".." / tmp_path.name / "copy"):
            body = json.dumps({"project_dir": str(path)}).encode()
            assert _refusal(config, "rebrew.import-project", body)["detail"] == (
                "project_dir must be inside the worker workspace"
            )
        # Without a workspace (a local `ops call` worker) the copy is readable.
        reply = _call(WorkerConfig(), "rebrew.import-project", {"project_dir": str(outside)})
        assert reply["project"] == str(outside.resolve())


# ---------------------------------------------------------------------------
# Binaries named by a presigned HTTPS url
# ---------------------------------------------------------------------------


class _OriginHandler(http.server.BaseHTTPRequestHandler):
    """Serves the fixture at /mini.exe, without a length at /unsized.exe."""

    def do_GET(self) -> None:
        body = BINARY.read_bytes()
        if self.path not in ("/mini.exe?X-Signature=s3cret", "/unsized.exe"):
            self.send_error(404)
            return
        self.send_response(200)
        if self.path != "/unsized.exe":
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    @override
    def log_message(self, format: str, *args: Any) -> None:
        pass


def _self_signed_certificate(directory: Path) -> None:
    """Write a self-signed certificate for 127.0.0.1 and its key to *directory*."""
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", str(key), "-out", str(cert),
        ],
        check=True,
        capture_output=True,
        timeout=WAIT_SECONDS,
    )  # fmt: skip


@pytest.fixture
def https_origin(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Any:
    """An HTTPS server with a self-signed certificate the worker trusts.

    The certificate is made once per session for every xdist worker; servers
    only read it.
    """
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    directory, _ = build_once(tmp_path_factory, "ops-https-certificate", _self_signed_certificate)
    cert, key = directory / "cert.pem", directory / "key.pem"
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert, key)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    monkeypatch.setenv("REBREW_OPS_ALLOW_PRIVATE_DOWNLOAD", "1")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


class TestUrlBinaries:
    def _config(self, tmp_path: Path, **extra: Any) -> WorkerConfig:
        filestore, workspace = _worker_dirs(tmp_path)
        return WorkerConfig(filestore.resolve(), workspace.resolve(), **extra)

    def _url_file(self, origin: str, path: str = "/mini.exe?X-Signature=s3cret") -> dict[str, Any]:
        request = {**_binary_file(), "url": origin + path}
        del request["key"]
        return request

    def _scratch_is_empty(self, config: WorkerConfig) -> bool:
        assert config.workspace is not None
        return not any((config.workspace / ".scratch").iterdir())

    def test_scan_ops_read_a_url(self, tmp_path: Path, https_origin: str) -> None:
        config = self._config(tmp_path)
        for path in ("/mini.exe?X-Signature=s3cret", "/unsized.exe"):
            request = self._url_file(https_origin, path)
            assert _call(config, "rebrew.fingerprint", request)["sha256"] == SHA256
        assert self._scratch_is_empty(config)

    def test_operand_locations_read_a_url(self, tmp_path: Path, https_origin: str) -> None:
        config = self._config(tmp_path)
        function = {"va": ENTRY_VA, "size": ENTRY_SIZE, "locations": [[0, 0]]}
        request = {
            "sha256": SHA256,
            "url": https_origin + "/mini.exe?X-Signature=s3cret",
            "functions": [function],
        }
        assert _call(config, "rebrew.binary_operand_locations", request) == {
            "locations": [[[0, 0]]]
        }

    def test_analyse_reads_a_url(self, tmp_path: Path, https_origin: str) -> None:
        config = self._config(tmp_path)
        request = {**_analyse_request(), "url": https_origin + "/mini.exe?X-Signature=s3cret"}
        del request["file_key"]
        assert config.workspace is not None
        _check_analysed(_call(config, "rebrew.analyse", request), config.workspace)
        assert self._scratch_is_empty(config)

    @pytest.mark.parametrize(
        ("change", "limit", "detail"),
        [
            ({"key": KEY}, None, "exactly one of key and url must be set"),
            ({"url": ""}, None, "exactly one of key and url must be set"),
            ({"url": "http://127.0.0.1/mini.exe"}, None, "url must be an https URL"),
            ({"url": "file:///etc/passwd"}, None, "url must be an https URL"),
            ({"path": "/missing.exe"}, None, "url answered HTTP 404"),
            ({}, 64, "url names more than 64 bytes"),
            ({"path": "/unsized.exe"}, 64, "url names more than 64 bytes"),
            ({"sha256": "0" * 64}, None, "the downloaded file does not match its sha256"),
        ],
    )
    def test_refusals(
        self,
        tmp_path: Path,
        https_origin: str,
        change: dict[str, Any],
        limit: int | None,
        detail: str,
    ) -> None:
        config = self._config(tmp_path, **({} if limit is None else {"max_download_bytes": limit}))
        request = self._url_file(https_origin, change.pop("path", "/mini.exe?X-Signature=s3cret"))
        request.update(change)
        refusal = _refusal(config, "rebrew.fingerprint", json.dumps(request).encode())
        assert (refusal["status"], refusal["detail"]) == (400, detail)
        assert "s3cret" not in refusal["detail"]
        scratch = tmp_path / "workspace" / ".scratch"
        assert not scratch.exists() or not any(scratch.iterdir())

    def test_a_url_needs_a_workspace(self, https_origin: str) -> None:
        request = self._url_file(https_origin)
        refusal = _refusal(WorkerConfig(), "rebrew.fingerprint", json.dumps(request).encode())
        assert refusal["detail"] == "the rebrew worker has no workspace configured (--workspace)"

    def test_hung_dns_does_not_pin_the_worker(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest import mock

        import rebrew.ops as ops

        monkeypatch.setattr(ops, "DNS_TIMEOUT_SECONDS", 0.2)

        # Block until the test ends, so the resolver is hung on any machine.
        release = threading.Event()

        def _hung(*args: Any, **kwargs: Any) -> Any:
            release.wait()
            return []

        try:
            with mock.patch.object(socket, "getaddrinfo", _hung):
                started = time.monotonic()
                refusal = _refusal(
                    self._config(tmp_path),
                    "rebrew.fingerprint",
                    json.dumps(self._url_file("https://example.com")).encode(),
                )
                assert refusal["detail"] == "url host cannot be resolved"
                assert time.monotonic() - started < 1.0
                assert (refusal["status"], refusal["error"]) == (500, "engine-error")
        finally:
            release.set()

    def test_private_dns_answer_is_refused(self, tmp_path: Path) -> None:
        from unittest import mock

        def _private(*args: Any, **kwargs: Any) -> Any:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

        with mock.patch.object(socket, "getaddrinfo", _private):
            refusal = _refusal(
                self._config(tmp_path),
                "rebrew.fingerprint",
                json.dumps(self._url_file("https://evil.example.com/mini.exe")).encode(),
            )
            assert refusal["detail"] == "url host must be a public address"

    def test_download_fetches_the_validated_address_not_a_second_lookup(
        self, tmp_path: Path
    ) -> None:
        from unittest import mock

        import httpx

        seen: dict[str, Any] = {}
        mini = BINARY.read_bytes()

        class _PinnedResponse:
            status_code: int = 200
            headers: dict[str, str]

            def __init__(self) -> None:
                self.headers = {"Content-Length": str(len(mini))}

            def iter_bytes(self, size: int) -> Any:
                yield mini

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *args: Any) -> None:
                return None

        def _fake_client(*args: Any, **kwargs: Any) -> Any:
            class _Client:
                def __init__(self, **kw: Any) -> None:
                    pass

                def __enter__(self) -> Any:
                    return self

                def __exit__(self, *args: Any) -> None:
                    return None

                def stream(self, method: str, url: str, **kw: Any) -> Any:
                    seen["url"] = url
                    seen["headers"] = kw.get("headers") or {}
                    seen["extensions"] = kw.get("extensions") or {}
                    return _PinnedResponse()

            return _Client()

        def _public(*args: Any, **kwargs: Any) -> Any:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

        with (
            mock.patch.object(socket, "getaddrinfo", _public),
            mock.patch.object(httpx, "Client", _fake_client),
            mock.patch.dict("os.environ", {"REBREW_OPS_ALLOW_PRIVATE_DOWNLOAD": "0"}),
        ):
            result = _call(
                self._config(tmp_path),
                "rebrew.fingerprint",
                self._url_file("https://example.com/mini.exe"),
            )
            assert result["sha256"] == SHA256
            assert seen["url"].startswith("https://93.184.216.34/")
            assert seen["headers"]["Host"] == "example.com"
            assert seen["extensions"]["sni_hostname"] == "example.com"

    def test_a_failed_lookup_is_retryable(self, tmp_path: Path) -> None:
        from unittest import mock

        def _down(*args: Any, **kwargs: Any) -> Any:
            raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")

        with mock.patch.object(socket, "getaddrinfo", _down):
            refusal = _refusal(
                self._config(tmp_path),
                "rebrew.fingerprint",
                json.dumps(self._url_file("https://example.com")).encode(),
            )
        assert (refusal["status"], refusal["error"], refusal["detail"]) == (
            500,
            "engine-error",
            "url host cannot be resolved",
        )


class TestRefusals:
    @pytest.mark.parametrize(
        ("op", "body", "code", "status"),
        [
            ("rebrew.nope", b"{}", "unknown-op", 404),
            ("rebrew.fingerprint", b"not json", "invalid-request", 400),
            ("rebrew.fingerprint", b"[]", "invalid-request", 400),
            ("rebrew.import-project", b'{"project_dir": "/x", "extra": 1}', "invalid-request", 400),
            ("rebrew.import-project", b"{}", "invalid-request", 400),
            ("rebrew.import-project", b'{"project_dir": "relative"}', "invalid-request", 400),
            (
                "rebrew.import-project",
                b'{"project_dir": "/x", "build_db": 1}',
                "invalid-request",
                400,
            ),
            (
                "rebrew.disassemble_bytes",
                b'{"code": "@@", "va": 0, "arch": ""}',
                "invalid-request",
                400,
            ),
            # A JSON string may carry an unpaired surrogate as an escape;
            # every downstream .encode("utf-8") would raise and surface as
            # a 500, so the boundary rejects it with a 400.
            (
                "rebrew.import-project",
                b'{"project_dir": "x\\ud800y"}',
                "invalid-request",
                400,
            ),
        ],
    )
    def test_malformed_requests(self, op: str, body: bytes, code: str, status: int) -> None:
        refusal = _refusal(WorkerConfig(), op, body)
        assert (refusal["error"], refusal["status"]) == (code, status)

    def test_oversized_request(self) -> None:
        from rebrew.ops import MAX_REQUEST_BYTES

        refusal = _refusal(WorkerConfig(), "rebrew.fingerprint", b" " * (MAX_REQUEST_BYTES + 1))
        assert refusal["status"] == 413

    def test_unconfigured_filestore(self) -> None:
        refusal = _refusal(
            WorkerConfig(), "rebrew.fingerprint", json.dumps(_binary_file()).encode()
        )
        assert (refusal["error"], refusal["detail"]) == (
            "engine-error",
            "the rebrew worker has no filestore configured (--filestore)",
        )

    @pytest.mark.parametrize(
        ("key", "sha256", "detail", "status"),
        [
            ("../escape", SHA256, "file key must be a clean relative filestore key", 400),
            ("/abs", SHA256, "file key must be a clean relative filestore key", 400),
            (KEY, "ABC", "sha256 must be 64 lowercase hex digits", 400),
            # A well-formed key the filestore cannot serve is the worker's
            # storage (a missing mount, a corrupt object), not the request.
            ("binaries/missing", SHA256, "no stored file for the key", 500),
            (KEY, "0" * 64, "the stored file does not match its sha256", 500),
        ],
    )
    def test_stored_file_references(
        self, world: tuple[WorkerConfig, Path], key: str, sha256: str, detail: str, status: int
    ) -> None:
        config, _project = world
        body = json.dumps({**_binary_file(), "key": key, "sha256": sha256}).encode()
        refusal = _refusal(config, "rebrew.fingerprint", body)
        assert (refusal["detail"], refusal["status"]) == (detail, status)

    def test_symlink_out_of_the_filestore(self, tmp_path: Path) -> None:
        filestore, _workspace = _worker_dirs(tmp_path)
        (filestore / "binaries" / "link").symlink_to(BINARY.resolve())
        body = json.dumps({**_binary_file(), "key": "binaries/link"}).encode()
        refusal = _refusal(WorkerConfig(filestore.resolve()), "rebrew.fingerprint", body)
        assert (refusal["detail"], refusal["status"]) == (
            "the key does not name a stored file",
            500,
        )


# ---------------------------------------------------------------------------
# Function digests, library functions, compiler identification, splat configs
# ---------------------------------------------------------------------------

#: The fixture's first function: ``push ebp; mov ebp, esp; mov eax, [0]; pop ebp; ret``.
ENTRY_CODE = bytes.fromhex("55 8b ec 8b 05 00 00 00 00 5d c3")

SPLAT_YAML = """\
options:
  basename: fixture.exe
  target_path: "fixture.exe"
  platform: win32
  compiler: MSVC6
  symbol_addrs_path: symbol_addrs.txt
segments:
  - name: text
    type: code
    start: 0x200
    vram: 0x00401000
    subsegments:
      - [0x200, text, main_text]
  - [0x400]
"""


def _store(filestore: Path, data: bytes) -> tuple[str, str]:
    """Store *data* under its content key; return ``(sha256, key)``."""
    digest = hashlib.sha256(data).hexdigest()
    (filestore / "binaries" / digest).write_bytes(data)
    return digest, f"binaries/{digest}"


def _relocated_fixture(directory: Path) -> bytes:
    """The fixture with one HIGHLOW fixup on the entry function's ``[0]`` operand."""
    import lief

    binary = lief.PE.parse(BINARY)
    assert binary is not None
    block = lief.PE.Relocation()
    block.virtual_address = 0x1000
    block.add_entry(lief.PE.RelocationEntry(5, lief.PE.RelocationEntry.BASE_TYPES.HIGHLOW))
    binary.add_relocation(block)
    path = directory / "relocated.exe"
    binary.write(str(path))
    return path.read_bytes()


class TestFunctionDigests:
    def _request(self, sha256: str, key: str, *extents: tuple[int, int]) -> dict[str, Any]:
        functions = [{"va": va, "size": size} for va, size in extents]
        return {"sha256": sha256, "file": key, "functions": functions}

    def test_unrelocated_bytes_hash_whole(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        request = self._request(SHA256, KEY, (ENTRY_VA, ENTRY_SIZE))
        reply = _call(config, "rebrew.binary_function_digests", request)
        assert reply == {
            "identities": [
                {
                    "algorithm": "sha256-relocations-v1",
                    "arch": "x86_32",
                    "size": ENTRY_SIZE,
                    "digest": hashlib.sha256(ENTRY_CODE).hexdigest(),
                }
            ]
        }

    def test_fixups_are_masked(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        digest, key = _store(filestore, _relocated_fixture(tmp_path))
        reply = _call(
            config,
            "rebrew.binary_function_digests",
            self._request(digest, key, (ENTRY_VA, ENTRY_SIZE)),
        )
        masked = ENTRY_CODE[:5] + b"\0\0\0\0" + ENTRY_CODE[9:]
        assert reply["identities"][0]["digest"] == hashlib.sha256(masked).hexdigest()

    @pytest.mark.parametrize(
        ("extents", "detail"),
        [
            ((), "functions must hold 1 to 128 entries"),
            (((ENTRY_VA, 0),), "function extent is outside its bounds"),
            (((-1, 4),), "function extent is outside its bounds"),
            (((0x10, 4),), "function digest extent is not file backed"),
        ],
    )
    def test_refusals(
        self, tmp_path: Path, extents: tuple[tuple[int, int], ...], detail: str
    ) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        body = json.dumps(self._request(SHA256, KEY, *extents)).encode()
        refusal = _refusal(config, "rebrew.binary_function_digests", body)
        assert (refusal["status"], refusal["detail"]) == (400, detail)


@pytest.fixture(scope="module")
def identified_compiler(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """The ``identify_compiler`` reply for the fixture. Tests only read it."""
    filestore, workspace = _worker_dirs(tmp_path_factory.mktemp("identify"))
    config = WorkerConfig(filestore.resolve(), workspace.resolve())
    reply: dict[str, Any] = _call(config, "rebrew.identify_compiler", _binary_file())
    return reply


class TestStoredFileOps:
    def test_library_functions(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        digest, key = _store(filestore, (FIXTURES / "mini.lib").read_bytes())
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        reply = _call(config, "rebrew.library_functions", {"sha256": digest, "file": key})
        functions = {f["name"]: f for f in reply["functions"]}
        # Rows listed under an earlier boundary rule (1: every COFF symbol a
        # function) describe fragments; a store compares this stamp.
        assert reply["boundaries"] == 2
        assert set(functions) == {"_func1", "_func2"}
        assert (functions["_func1"]["arch"], functions["_func1"]["size"]) == ("x86_32", 16)
        assert "push ebp" in functions["_func1"]["listing"]

    @pytest.mark.skipif(shutil.which("nasm") is None, reason="nasm not installed")
    def test_library_functions_lists_jump_tables_as_data(self, tmp_path: Path) -> None:
        """A switch in a library object lists its tables as data, as the linked
        target's listing does: the object's table and dispatch fields are zero
        or an addend, and its relocations to its own labels place them."""
        from bin_util import make_coff_obj, make_lib_archive

        # SWITCH at offset 0; the address table reference is $L(0x20) + 4.
        labels = [(9, 0x30, 0), (16, 0x20, 4), (0x24, 0x14, 0), (0x28, 0x1A, 0), (0x2C, 0x20, 0)]
        unlinked = bytearray(SWITCH)
        for at, _label, addend in labels:
            unlinked[at : at + 4] = addend.to_bytes(4, "little")
        obj = make_coff_obj(
            bytes(unlinked),
            func_symbol="_f",
            label_relocs=[(at, 0x6, label) for at, label, _ in labels],
        )
        filestore, workspace = _worker_dirs(tmp_path)
        digest, key = _store(filestore, make_lib_archive([("f.obj", obj)]))
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        reply = _call(config, "rebrew.library_functions", {"sha256": digest, "file": key})
        lines = [
            line.split(";")[0].strip() for line in reply["functions"][0]["listing"].splitlines()
        ]
        assert lines[lines.index("jmp dword [ecx*4 + 0x24]") :] == [
            "jmp dword [ecx*4 + 0x24]",
            "mov eax, 1",
            "ret",
            "mov eax, 2",
            "ret",
            "db 0x33, 0xC0",  # nasm encodes xor eax, eax as 31 c0
            "ret",
            "nop",
            "jump_table_00000024:",
            "dd 0x14",
            "dd 0x1a",
            "dd 0x20",
            "jump_table_00000030:",
            *[f"db 0x{slot:x}" for slot in (0, 1, 1, 2, 0, 2)],
            "add byte [eax], al",  # the section padding
        ]

    def test_library_functions_refuses_a_non_archive(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        body = json.dumps({"sha256": SHA256, "file": KEY}).encode()
        refusal = _refusal(config, "rebrew.library_functions", body)
        assert refusal["detail"] == "the file is not an ar archive"

    def test_identify_compiler(self, identified_compiler: dict[str, Any]) -> None:
        reply = identified_compiler
        assert {"family", "confidence", "evidence", "detected_by", "profile"} <= set(reply)
        assert isinstance(reply["evidence"], list)

    def test_identify_compiler_fills_what_the_pe_tells_and_nulls_the_rest(
        self, identified_compiler: dict[str, Any]
    ) -> None:
        """An x86_32 PE answered arch, opt_level, codegen and packed as empty strings.

        The arch is the PE header's, packed is the packer scan's answer (false:
        none found), and what the detector cannot tell is null (not determined).
        """
        reply = identified_compiler
        assert reply["arch"] == "x86_32"
        assert (reply["packed"], reply["packer"]) == (False, None)
        assert (reply["opt_level"], reply["codegen"]) == (None, None)

    @pytest.mark.parametrize("diec", [True, False])
    def test_identify_compiler_text_is_plain_facts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, diec: bool
    ) -> None:
        """The evidence users read has no em dash, no install hint and no worker path.

        It said "DIE: diec not found (PATH or tools/diec) — install for stronger
        detection" and "2 frame-pointer prologues (push ebp; mov ebp,esp) — /Oy-
        or unoptimized", and named the worker's diec path when DIE ran.
        """
        import rebrew.toolchain_detect as detect

        if not diec:
            monkeypatch.setattr(detect, "_find_diec", lambda: None)
        filestore, workspace = _worker_dirs(tmp_path)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        reply = _call(config, "rebrew.identify_compiler", _binary_file())
        text = json.dumps(reply, ensure_ascii=False)
        assert "—" not in text
        assert "install" not in text
        assert "/usr/" not in text and "tools/diec" not in text
        if not diec:
            assert "Detect It Easy not available" in reply["evidence"]
        assert (
            "2 frame-pointer prologues (push ebp; mov ebp,esp): /Oy- or unoptimized"
            in (reply["evidence"])
        )

    def test_splat_parse(self) -> None:
        reply = _call(WorkerConfig(), "rebrew.splat_parse", {"config": SPLAT_YAML})
        assert (reply["platform"], reply["compiler"], reply["target_path"]) == (
            "win32",
            "MSVC6",
            "fixture.exe",
        )
        assert reply["symbol_addrs_paths"] == ["symbol_addrs.txt"]
        (segment,) = reply["segments"]
        assert (segment["rom_start"], segment["rom_end"], segment["vram"]) == (
            0x200,
            0x400,
            0x401000,
        )
        assert segment["subsegments"] == [{"rom_start": 0x200, "kind": "text", "name": "main_text"}]

    def test_splat_parse_refuses_unreadable_text(self) -> None:
        body = json.dumps({"config": "segments: [unclosed"}).encode()
        refusal = _refusal(WorkerConfig(), "rebrew.splat_parse", body)
        assert refusal["status"] == 400
        assert "/splat" not in refusal["detail"]


# ---------------------------------------------------------------------------
# Reconstruction ops on a project
# ---------------------------------------------------------------------------


def _project_copy(world: tuple[WorkerConfig, Path], name: str) -> tuple[WorkerConfig, Path]:
    """A copy of the analysed project inside the workspace, for ops that write."""
    config, project = world
    assert config.workspace is not None
    copy = config.workspace / "copies" / name
    shutil.copytree(project, copy)
    return config, copy


def _with_project_header(project: Path) -> str:
    """Add a source that includes a project header; return its project-relative path."""
    (project / "src" / "mini" / "local.h").write_text("#define ONE 1\n")
    source = project / "src" / "mini" / "uses_header.c"
    source.write_text('#include "local.h"\nint uses_header(void) { return ONE; }\n')
    return "src/mini/uses_header.c"


def _retained_coverage_request(
    fresh_analysis: tuple[Path, dict[str, Any]], tmp_path: Path
) -> tuple[WorkerConfig, dict[str, Any], dict[str, Any], dict[str, Any]]:
    """A retained ``coverage_report`` request over a copy of a fresh analysis, no records.

    Returns the worker configuration over *tmp_path*, the request, the analyse
    reply (its ``project`` names the copy) and the coverage envelope.
    """
    from rebrew.coverage_input_contract import coverage_input_digest, plan_coverage_readset
    from rebrew.ops import RetainedFile, retained_target_snapshot

    config, project = _copy_analysed(fresh_analysis, tmp_path)
    assert config.filestore is not None
    filestore = config.filestore
    analysed = {**fresh_analysis[1], "project": str(project)}
    capture = analysed["analysis_capture"]
    files = []
    source_paths = {entry["path"] for entry in capture["entries"] if entry.get("role") == "source"}
    for entry in capture["entries"]:
        if entry["kind"] != "file":
            continue
        data = base64.b64decode(entry["data"])
        digest, key = _store(filestore, data)
        files.append({"path": entry["path"], "size": len(data), "digest": digest, "key": key})
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
                if row["path"] in source_paths or row["path"] == "rebrew-project.toml"
                else "analysis",
            }
            for row in plan
        ],
    }
    request = {
        "project_dir": analysed["project"],
        "sha256": SHA256,
        "files": files,
        "rebrew_target": target,
        "binary_key": KEY,
        "coverage_input": envelope,
        "coverage_input_digest": coverage_input_digest(envelope),
        "verification_records": [],
    }
    return config, request, analysed, envelope


def _thunk_calls(slot_a: int, slot_b: int) -> str:
    """Win2k notepad's tail: two functions calling ``jmp dword [iat]`` thunks, the first thunk
    followed by int3 padding, the last by two int3 and then the import directory."""
    return (
        "55 8b ec e8 08000000 5d c3"
        + " cc" * 6  # 0x00 calls thunk a
        + f"ff25{le32(slot_a)}"
        + " cc" * 10  # 0x10 thunk a, int3 padding
        + "55 8b ec e8 6b000000 5d c3"
        + " cc" * 0x69  # 0x20 calls thunk b
        + f"ff25{le32(slot_b)} cc cc"  # 0x93 thunk b, then the import directory
    )


def _analyse_thunk_calls(root: Path) -> dict[str, Any]:
    """The ``_thunk_calls`` PE analysed into a new worker root at *root*, and the reply."""
    binary, _slot_a, _slot_b = make_import_call_pe(root, _thunk_calls)
    return _analyse_binary(root, binary.read_bytes(), "calls.exe")


@pytest.fixture(scope="module")
def thunk_analysis(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict[str, Any]]:
    """A worker root with the ``_thunk_calls`` PE analysed, and the reply.

    Built once per session for every xdist worker. Tests never change it: one
    that writes works on :func:`_copy_analysed`.
    """
    root, reply = build_once(tmp_path_factory, "ops-thunk-analysis", _analyse_thunk_calls)
    return root.resolve(), reply


class TestReconstructionOps:
    def test_retained_reports_require_and_use_verified_readset(
        self,
        fresh_analysis: tuple[Path, dict[str, Any]],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from rebrew.coverage_input_contract import (
            coverage_input_digest,
            verification_records_digest,
        )

        config, request, analysed, envelope = _retained_coverage_request(fresh_analysis, tmp_path)
        status, body = dispatch(config, "rebrew.coverage_report", json.dumps(request).encode())
        assert status == 200, body
        assert json.loads(body)["report"]["measures"]["matched_functions"] == 0
        missing_records = {
            key: value for key, value in request.items() if key != "verification_records"
        }
        status, _ = dispatch(config, "rebrew.coverage_report", json.dumps(missing_records).encode())
        assert status == 409
        status, _ = dispatch(
            config,
            "rebrew.coverage_report",
            json.dumps({"project_dir": analysed["project"], "coverage_input": {}}).encode(),
        )
        assert status == 400
        site = {**request, "binary_id": 1, "output_dir": "reports/generated/" + "a" * 32}
        status, body = dispatch(config, "rebrew.report", json.dumps(site).encode())
        assert status == 200, body
        manifest = json.loads(body)["manifest"]
        assert manifest and "kinds" not in json.loads(body)
        # Every file states what it carries, read from its generator: the
        # backend withholds by these, not by file names.
        kinds = {entry["path"]: entry["kinds"] for entry in manifest}
        assert all(value and set(value) <= set(SITE_DATA_KINDS) for value in kinds.values())
        for path, value in kinds.items():
            base = path.removesuffix(".gz").removesuffix(".zst")
            expected = (
                ["call_graph"]
                if base in {"graph.html", "adjacency.txt", "callgraph.mmd"}
                else ["cross_references"]
                if base.startswith("strings")
                else ["none"]
            )
            assert value == expected, path
        assert {"index.html", "strings.html", "graph.html", "favicon.svg"} <= set(kinds)
        function = analysed["targets"][0]["functions"][0]
        source = next(row for row in envelope["readset"] if row["path"] == function["source_path"])
        record = {
            "verification_id": "modeled",
            "source": source["path"],
            "source_sha256": source["digest"],
            "va": function["va"],
            "size": function["size"],
            "status": "EXACT",
            "match_count": function["size"],
            "total": function["size"],
            "obj_size": function["size"],
            "reloc_count": 0,
            "result_digest": "e" * 64,
        }
        envelope["verification_digest"] = verification_records_digest([record])
        request["coverage_input_digest"] = coverage_input_digest(envelope)
        request["verification_records"] = [record]
        # The report is answered, never written: a durable write of a discarded copy is waste.
        syncs: list[int] = []
        real_fsync = os.fsync
        monkeypatch.setattr(os, "fsync", lambda fd: (syncs.append(fd), real_fsync(fd))[1])
        status, body = dispatch(config, "rebrew.coverage_report", json.dumps(request).encode())
        monkeypatch.setattr(os, "fsync", real_fsync)
        assert status == 200, body
        assert json.loads(body)["report"]["measures"]["matched_functions"] == 1
        assert syncs == []
        record.update(
            status="SIZE_MISMATCH",
            match_count=0,
            obj_size=function["size"] + 1,
            total=function["size"] + 1,
        )
        envelope["verification_digest"] = verification_records_digest([record])
        request["coverage_input_digest"] = coverage_input_digest(envelope)
        status, body = dispatch(config, "rebrew.coverage_report", json.dumps(request).encode())
        assert status == 200, body
        assert json.loads(body)["report"]["measures"]["matched_functions"] == 0
        request["coverage_input_digest"] = "d" * 64
        status, body = dispatch(config, "rebrew.coverage_report", json.dumps(request).encode())
        assert status == 409, body

    def test_retained_build_names_an_invalid_project_config(
        self,
        fresh_analysis: tuple[Path, dict[str, Any]],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A staged rebrew-project.toml rebrew refuses is the caller's to fix: say what, not "see the log"."""
        config, project = _copy_analysed(fresh_analysis, tmp_path)
        assert config.filestore is not None
        filestore = config.filestore
        capture = fresh_analysis[1]["analysis_capture"]
        files = []
        for entry in capture["entries"]:
            if entry["kind"] != "file":
                continue
            data = base64.b64decode(entry["data"])
            if entry["path"] == "rebrew-project.toml":
                assert b"\n[compiler]\n" in data, "the generated config has a compiler table"
                data = data.replace(
                    b"\n[compiler]\n", b'\n[compiler]\nexecution_backend = "unshare"\n', 1
                )
            digest, key = _store(filestore, data)
            files.append({"path": entry["path"], "size": len(data), "digest": digest, "key": key})
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:9")
        request = {
            "project_dir": str(project),
            "sha256": SHA256,
            "files": files,
            "rebrew_target": capture["target"],
            "binary_key": KEY,
        }
        refusal = _refusal(config, "rebrew.build", json.dumps(request).encode())
        assert (refusal["error"], refusal["status"]) == ("invalid-project-config", 400)
        assert refusal["detail"] == (
            "invalid project config: rebrew-project.toml: compiler.execution_backend = unshare conflicts with remote recompile"
        )

    def test_analyse_same_binary_has_isolated_project_workspaces(self, tmp_path: Path) -> None:
        from rebrew.config import load_config
        from rebrew.metadata.sqlite import DATABASE_FILENAME

        filestore, workspace = _worker_dirs(tmp_path)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())

        def analyse(project_id: str) -> Path:
            request = {**_analyse_request(), "project_id": project_id}
            status, body = dispatch(config, "rebrew.analyse", json.dumps(request).encode())
            assert status == 200, body
            report = json.loads(body)
            capture = report["analysis_capture"]
            assert capture["version"] == 3
            assert capture["binary_sha256"] == SHA256
            assert capture["target"] == report["targets"][0]["name"]
            assert report["targets"][0]["sha256"] == SHA256
            assert sum(entry["kind"] == "binary" for entry in capture["entries"]) == 1
            assert any(entry["kind"] == "file" for entry in capture["entries"])
            source_paths = {
                entry["path"] for entry in capture["entries"] if entry.get("role") == "source"
            }
            for function in report["targets"][0]["functions"]:
                if "source_path" in function:
                    assert function["source_path"] in source_paths
            project = Path(report["project"])
            assert load_config(project).metadata_backend == "toml"
            assert not (project / DATABASE_FILENAME).exists()
            return project

        first = analyse("tenant-a")
        second = analyse("tenant-b")
        assert first != second
        (first / "isolation-marker").write_text("tenant-a")
        assert not (second / "isolation-marker").exists()
        assert analyse("tenant-b") == second
        assert (first / "isolation-marker").read_text() == "tenant-a"
        default = analyse("default")
        assert (
            default
            == workspace.resolve()
            / "projects"
            / "scopes"
            / hashlib.sha256(b"default").hexdigest()
            / SHA256
        )
        assert default not in (first, second)
        status, _ = dispatch(
            config, "rebrew.analyse", json.dumps({**_analyse_request(), "project_id": ""}).encode()
        )
        assert status == 400

    def test_analyse_rejects_scope_symlink_to_another_project(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        target = workspace / "other"
        target.mkdir()
        scope = hashlib.sha256(b"project-a").hexdigest()
        parent = workspace / "projects" / "scopes"
        parent.mkdir(parents=True)
        (parent / scope).symlink_to(target, target_is_directory=True)
        request = {**_analyse_request(), "project_id": "project-a"}
        status, _body = dispatch(
            WorkerConfig(filestore.resolve(), workspace.resolve()),
            "rebrew.analyse",
            json.dumps(request).encode(),
        )
        assert status == 400
        assert not list(target.iterdir())

    def test_import_refuses_scoped_analysis_path(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        project = workspace / "projects" / "scopes" / "scope-a" / SHA256
        project.mkdir(parents=True)
        (project / "rebrew-project.toml").write_text("")
        status, _ = dispatch(
            WorkerConfig(filestore.resolve(), workspace.resolve()),
            "rebrew.import-project",
            json.dumps({"project_dir": str(project)}).encode(),
        )
        assert status == 400

    @pytest.mark.parametrize("bound", ["MAX_REPORT_FILES", "MAX_REPORT_BYTES"])
    def test_a_retained_report_over_the_bounds_is_the_engines_failure(
        self,
        fresh_analysis: tuple[Path, dict[str, Any]],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        bound: str,
    ) -> None:
        """The site is rebrew's own output from a verified snapshot: no request of the
        caller's is malformed, so the refusal is a 5xx of its own, not invalid-request."""
        config, request, _analysed, _envelope = _retained_coverage_request(fresh_analysis, tmp_path)
        monkeypatch.setattr(f"rebrew.ops.{bound}", 1)
        site = {**request, "binary_id": 1, "output_dir": "reports/generated/" + "b" * 32}
        status, body = dispatch(config, "rebrew.report", json.dumps(site).encode())
        refusal = json.loads(body)
        assert (status, refusal["error"]) == (500, "report-output-invalid"), refusal
        assert not (config.workspace / site["output_dir"]).exists()

    def test_a_retained_report_that_wrote_nothing_is_the_engines_failure(
        self,
        fresh_analysis: tuple[Path, dict[str, Any]],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config, request, _analysed, _envelope = _retained_coverage_request(fresh_analysis, tmp_path)
        monkeypatch.setattr(
            "rebrew.report.generate_report",
            lambda _cfg, out, **_k: {"out": str(out), "pages": [], "summary": {}, "kinds": {}},
        )
        site = {**request, "binary_id": 1, "output_dir": "reports/generated/" + "c" * 32}
        status, body = dispatch(config, "rebrew.report", json.dumps(site).encode())
        refusal = json.loads(body)
        assert (status, refusal["error"]) == (500, "report-output-invalid"), refusal

    def test_retained_ops_do_not_read_project_dir(
        self,
        fresh_analysis: tuple[Path, dict[str, Any]],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A retained request reads only its snapshot, as recoverage's do.

        Each op first required ``project_dir`` to be a live rebrew project in
        the worker's workspace, so a replica without that directory (or a
        project the isolated runner recorded elsewhere) answered 400.
        """
        config, request, _analysed, _envelope = _retained_coverage_request(fresh_analysis, tmp_path)
        gone = str(tmp_path / "elsewhere" / "project")
        retained = {**request, "project_dir": gone}
        _call(config, "rebrew.coverage_report", retained)
        site = {**retained, "binary_id": 1, "output_dir": "reports/generated/" + "f" * 32}
        assert _call(config, "rebrew.report", site)["manifest"]
        commands: list[list[str]] = []

        def run_rebrew(arguments: list[str], project: Path, *_a: Any, **_k: Any) -> Any:
            assert project.is_relative_to(config.workspace) and project.name.startswith(
                "retained-target-"
            )
            commands.append(arguments)
            return _EMPTY_DATA_LIST if arguments[0] == "data" else {"dry_run": False}

        monkeypatch.setattr("rebrew.ops.run_rebrew", run_rebrew)
        # Retained target commands compile only through the operator's service.
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://recompile.test")
        status, body = dispatch(config, "rebrew.data_list", json.dumps(retained).encode())
        assert status == 200, body
        target_request = {
            key: retained[key]
            for key in ("project_dir", "sha256", "files", "rebrew_target", "binary_key")
        }
        for op, extra in (("rebrew.verify_target", {"no_promote": True}), ("rebrew.build", {})):
            body = json.dumps({**target_request, **extra}).encode()
            status, reply = dispatch(config, op, body)
            assert status == 200, reply
        assert [arguments[:2] for arguments in commands] == [
            ["data", "list"],
            ["verify", "--json"],
            ["build", "round-trip"],
        ]

    def test_analysed_elf_reports_defined_symbol_names_and_sizes(self, tmp_path: Path) -> None:
        import lief

        compiler = shutil.which("cc")
        if compiler is None:
            pytest.skip("needs a C compiler")
        source = tmp_path / "fixture.c"
        source.write_text(
            "__attribute__((noinline)) int checksum(int x) { return x*17+3; }\nint main(void) { return checksum(2); }\n"
        )
        binary = tmp_path / "fixture.elf"
        subprocess.run([compiler, "-O0", "-no-pie", "-o", str(binary), str(source)], check=True)
        filestore, workspace = _worker_dirs(tmp_path)
        digest, key = _store(filestore, binary.read_bytes())
        status, body = dispatch(
            WorkerConfig(filestore.resolve(), workspace.resolve()),
            "rebrew.analyse",
            json.dumps(
                {"binary_id": 1, "sha256": digest, "name": "fixture", "file_key": key}
            ).encode(),
        )
        assert status == 200, body
        elf = lief.ELF.parse(str(binary))
        assert elf is not None
        expected = {
            s.name: (s.value, s.size)
            for s in elf.symbols
            if s.name in {"checksum", "main", "_start"}
        }
        found = {
            f["name"]: (f["va"], f["size"]) for f in json.loads(body)["targets"][0]["functions"]
        }
        assert {name: found.get(name) for name in expected} == expected

    def test_analysed_import_thunks_are_stubs_whatever_follows_them(
        self, thunk_analysis: tuple[Path, dict[str, Any]]
    ) -> None:
        """Win2k notepad ends its code with ``jmp dword [iat]`` thunks: the one
        followed by int3 padding was a 20-byte function (``_initterm``) and the
        last one, two int3 before the import directory, a 259-byte function
        (``OpenPrinterW``) running to a ``ret`` byte in that directory."""
        from bin_util import IMPORT_CALL_NAMES

        root, reply = thunk_analysis
        target = reply["targets"][0]
        pe = (root / "files" / "binaries" / target["sha256"]).read_bytes()
        # The import directory's first dword (its name table's RVA) opens with a ``ret`` byte.
        assert pe[0x200 + 0x9B] == 0xC3
        assert [(f["va"], f["size"], f["name"]) for f in target["functions"]] == [
            (0x401000, 10, "fcn_00401000"),
            (0x401020, 10, "fcn_00401020"),
        ]
        assert target["stubs"] == [
            {"va": 0x401010, "name": IMPORT_CALL_NAMES[0]},
            {"va": 0x401093, "name": IMPORT_CALL_NAMES[1]},
        ]

    def test_imported_project_reports_an_old_stub_row_as_its_import(
        self, thunk_analysis: tuple[Path, dict[str, Any]], tmp_path: Path
    ) -> None:
        """A project onboarded by the old rule holds a STUB row at an import stub
        (Win2k notepad's ``OpenPrinterW``, 259 bytes): the report named the row
        after the import and kept it a function, so the backend stored a
        function the decompiler wrote as ``OpenPrinterW() { return OpenPrinterW(); }``."""
        from bin_util import IMPORT_CALL_NAMES

        from rebrew.intake import classify_all

        config, project = _copy_analysed(thunk_analysis, tmp_path)
        classify_all(project, project / "src" / "calls", "CALLS", [(0x401093, 9, "")], "msvc", "")
        target = _call(config, "rebrew.import-project", {"project_dir": str(project)})["targets"][0]
        assert [f["va"] for f in target["functions"]] == [0x401000, 0x401020]
        assert target["stubs"] == [
            {"va": 0x401010, "name": IMPORT_CALL_NAMES[0]},
            {"va": 0x401093, "name": IMPORT_CALL_NAMES[1]},
        ]

    def test_analysed_function_does_not_absorb_code_after_its_padding(self, tmp_path: Path) -> None:
        """Win2k notepad's fcn_010065f0 (19 bytes, ``ret``, nop padding) grew to
        49 once the thunk after it bounded the gap: the coverage grid's small-gap
        absorption took the padding and two functions too short for discovery
        (``xor eax, eax; ret`` and ``ret``)."""

        def assemble(slot_a: int, _slot_b: int) -> str:
            return (
                "55 8b ec b8 01000000 5d c3"  # 0x00 mov eax, 1 in a frame; ret
                + " cc" * 6
                + " 33 c0 c3"  # 0x10 xor eax, eax; ret
                + " cc" * 13
                + " c3"  # 0x20 ret
                + " cc" * 15
                + f" ff25{le32(slot_a)}"  # 0x30 thunk
            )

        binary, _slot_a, _slot_b = make_import_call_pe(tmp_path, assemble)
        filestore, workspace = _worker_dirs(tmp_path)
        digest, key = _store(filestore, binary.read_bytes())
        target = _call(
            WorkerConfig(filestore.resolve(), workspace.resolve()),
            "rebrew.analyse",
            {"binary_id": 1, "sha256": digest, "name": "calls.exe", "file_key": key},
        )["targets"][0]
        assert [(f["va"], f["size"]) for f in target["functions"]] == [(0x401000, 10)]

    def test_candidate_uses_private_retained_snapshot(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from rebrew import ops

        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")
        filestore, workspace = _worker_dirs(tmp_path)
        original = b"int add(int a, int b) { return a - b; }\n"
        project = b'[project]\ndefault_target="mini"\n[targets.mini]\nbinary="original/mini"\nformat="pe"\narch="x86_32"\nreversed_dir="src"\n'
        entries = []
        for name, data in (("rebrew-project.toml", project), ("src/add.c", original)):
            digest, key = _store(filestore, data)
            entries.append({"path": name, "digest": digest, "size": len(data), "key": key})
        seen: list[Path] = []

        def run(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            assert (root / "src/add.c").read_text() == "int add(int a, int b) { return a+b; }\n"
            assert "--va=0x401000" in args and "--size=11" in args and "--no-promote" in args
            seen.append(root)
            return {"status": "EXACT"}

        monkeypatch.setattr(ops, "run_rebrew", run)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        request = {
            "project_dir": "/unused",
            "source": "src/add.c",
            "candidate": "int add(int a, int b) { return a+b; }\n",
            "sha256": SHA256,
            "va": ENTRY_VA,
            "size": ENTRY_SIZE,
            "files": entries,
            "source_sha256": hashlib.sha256(original).hexdigest(),
            "rebrew_target": "mini",
            "binary_key": KEY,
        }
        status, body = dispatch(config, "rebrew.verify_function", json.dumps(request).encode())
        assert status == 200, body
        assert json.loads(body)["status"] == "EXACT" and len(seen) == 1 and not seen[0].exists()
        assert (filestore / entries[1]["key"]).read_bytes() == original
        request["source_sha256"] = "0" * 64
        status, _body = dispatch(config, "rebrew.verify_function", json.dumps(request).encode())
        assert status == 400
        request["source_sha256"] = hashlib.sha256(original).hexdigest()

        # cflags reach `rebrew test` as one --cflags argument; none means the project's.
        argv: list[list[str]] = []

        def record(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            argv.append(list(args))
            return {"status": "EXACT"}

        monkeypatch.setattr(ops, "run_rebrew", record)
        status, _ = dispatch(config, "rebrew.verify_function", json.dumps(request).encode())
        assert status == 200 and not any(a.startswith("--cflags") for a in argv[-1])
        assert "--instructions" not in argv[-1]
        flagged = {**request, "cflags": "/O1   /Gd"}
        status, _ = dispatch(config, "rebrew.verify_function", json.dumps(flagged).encode())
        assert status == 200 and "--cflags=/O1 /Gd" in argv[-1]
        # instructions asks `rebrew test` for the instruction-level comparison.
        status, _ = dispatch(
            config, "rebrew.verify_function", json.dumps({**request, "instructions": True}).encode()
        )
        assert status == 200 and "--instructions" in argv[-1]
        assert argv[-1].index("--instructions") < argv[-1].index("--")
        # The target's flags become the snapshot's project cflags: no --cflags, and the check that the
        # retained config is unchanged accepts the rewrite it made itself.
        seen_project: list[str] = []

        def project_run(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            seen_project.append((root / "rebrew-project.toml").read_text())
            assert not any(a.startswith("--cflags") for a in args)
            return {"status": "EXACT"}

        monkeypatch.setattr(ops, "run_rebrew", project_run)
        status, body = dispatch(
            config,
            "rebrew.verify_function",
            json.dumps({**request, "project_cflags": "/O1 /Gd"}).encode(),
        )
        assert status == 200, body
        assert 'cflags = "/O1 /Gd"' in seen_project[0]
        monkeypatch.setattr(ops, "run_rebrew", record)
        for bad in ("/Fo", "/O1 /Fdx.pdb", "-o", "@rsp", "/tmp/x", "/link"):
            status, body = dispatch(
                config, "rebrew.verify_function", json.dumps({**request, "cflags": bad}).encode()
            )
            assert status == 400 and "invalid-cflags" in body.decode(), (bad, body)
        monkeypatch.setattr(ops, "run_rebrew", run)

        def mutate(_args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            (root / "rebrew-project.toml").write_text("changed")
            return {"status": "EXACT"}

        monkeypatch.setattr(ops, "run_rebrew", mutate)
        status, _ = dispatch(config, "rebrew.verify_function", json.dumps(request).encode())
        assert status == 400

    def test_target_flags_become_the_snapshots_project_cflags(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        import tomllib

        from rebrew import ops

        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")
        filestore, workspace = _worker_dirs(tmp_path)
        live = workspace / "live"
        live.mkdir()
        project = b'[project]\ndefault_target="mini"\n[targets.mini]\nbinary="original/mini"\nformat="pe"\narch="x86_32"\nreversed_dir="src"\n[compiler]\ncflags="/O2 /Gd"\n'
        (live / "rebrew-project.toml").write_bytes(project)
        source = b"int add(int a, int b) { return a-b; }\n"
        entries = []
        for name, data in (
            ("rebrew-project.toml", project),
            ("src/add.c", source),
            ("src/function_structure.json", b'{"functions": []}'),
            ("rebrew-functions.toml", b""),
        ):
            digest, key = _store(filestore, data)
            entries.append({"path": name, "digest": digest, "size": len(data), "key": key})
        configs: list[str] = []

        def run(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            configs.append(
                tomllib.loads((root / "rebrew-project.toml").read_text())["compiler"]["cflags"]
            )
            assert not any(a.startswith("--cflags") for a in args)
            return {"dry_run": False}

        monkeypatch.setattr(ops, "run_rebrew", run)
        monkeypatch.setattr(ops, "remote_header_refusal", lambda *args: None)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        request = {
            "project_dir": str(live),
            "sha256": SHA256,
            "files": entries,
            "rebrew_target": "mini",
            "binary_key": KEY,
            "no_promote": True,
        }
        for op in ("rebrew.build", "rebrew.verify_target"):
            body = {**request, "project_cflags": "/O1   /Gd"}
            if op == "rebrew.build":
                body.pop("no_promote")
            status, reply = dispatch(config, op, json.dumps(body).encode())
            assert status == 200, reply
            status, reply = dispatch(
                config, op, json.dumps({**body, "project_cflags": ""}).encode()
            )
            assert status == 200, reply
        assert configs == ["/O1 /Gd", "/O2 /Gd", "/O1 /Gd", "/O2 /Gd"]
        for bad in ("/Fo", "-o", "/tmp/x"):
            refused = {k: v for k, v in request.items() if k != "no_promote"}
            status, reply = dispatch(
                config, "rebrew.build", json.dumps({**refused, "project_cflags": bad}).encode()
            )
            assert status == 400 and "invalid-cflags" in reply.decode(), (bad, reply)
        live_only = {k: v for k, v in request.items() if k not in {"files", "binary_key"}}
        status, reply = dispatch(
            config,
            "rebrew.verify_target",
            json.dumps({**live_only, "project_cflags": "/O1"}).encode(),
        )
        assert status == 400 and "retained" in reply.decode()

    def test_target_operations_use_retained_snapshot(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from rebrew import ops

        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")
        filestore, workspace = _worker_dirs(tmp_path)
        live = workspace / "live"
        live.mkdir()
        project = b'[project]\ndefault_target="mini"\n[targets.mini]\nbinary="original/mini"\nformat="pe"\narch="x86_32"\nreversed_dir="src"\n'
        (live / "rebrew-project.toml").write_bytes(project)
        source = b"int add(int a, int b) { return a-b; }\n"
        entries = []
        for name, data in (
            ("rebrew-project.toml", project),
            ("src/add.c", source),
            ("src/function_structure.json", b'{"functions": []}'),
            ("rebrew-functions.toml", b""),
        ):
            digest, key = _store(filestore, data)
            entries.append({"path": name, "digest": digest, "size": len(data), "key": key})
        seen: list[Path] = []

        def run(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            assert root != live and (root / "src/add.c").read_bytes() == source
            assert "--target=mini" in args
            seen.append(root)
            return {"dry_run": False}

        monkeypatch.setattr(ops, "run_rebrew", run)
        monkeypatch.setattr(ops, "remote_header_refusal", lambda *args: None)
        config = WorkerConfig(filestore.resolve(), workspace.resolve())
        request = {
            "project_dir": str(live),
            "sha256": SHA256,
            "files": entries,
            "rebrew_target": "mini",
            "binary_key": KEY,
        }
        for op in ("rebrew.build", "rebrew.verify_target"):
            body = {**request, **({"no_promote": True} if op.endswith("verify_target") else {})}
            status, reply = dispatch(config, op, json.dumps(body).encode())
            assert status == 200, reply
        assert len(seen) == 2 and all(not path.exists() for path in seen)
        argv: list[list[str]] = []

        def record(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            argv.append(list(args))
            return {"dry_run": False}

        monkeypatch.setattr(ops, "run_rebrew", record)
        for extra in ({}, {"instructions": True}):
            body = json.dumps({**request, "no_promote": True, **extra}).encode()
            status, reply = dispatch(config, "rebrew.verify_target", body)
            assert status == 200, reply
        assert "--instructions" not in argv[0] and "--instructions" in argv[1]
        monkeypatch.setattr(ops, "run_rebrew", run)
        bad = {**request, "files": [*entries, entries[0]]}
        status, _ = dispatch(config, "rebrew.build", json.dumps(bad).encode())
        assert status == 400
        alias = {**entries[1], "path": "src/../src/add.c"}
        bad = {**request, "files": [*entries, alias]}
        status, _ = dispatch(config, "rebrew.build", json.dumps(bad).encode())
        assert status == 400
        escape = project.replace(b'reversed_dir="src"', b'reversed_dir="/etc"')
        digest, key = _store(filestore, escape)
        bad_config = {
            "path": "rebrew-project.toml",
            "digest": digest,
            "size": len(escape),
            "key": key,
        }
        status, _ = dispatch(
            config,
            "rebrew.build",
            json.dumps({**request, "files": [bad_config, *entries[1:]]}).encode(),
        )
        assert status == 400
        outside_library = workspace / "rebrew-libraries.toml"
        outside_library.write_text('library = "foreign"\n')
        status, _ = dispatch(config, "rebrew.build", json.dumps(request).encode())
        assert status == 400
        outside_library.unlink()
        status, _ = dispatch(config, "rebrew.verify_target", json.dumps(request).encode())
        assert status == 400

        def mutate(args: Any, root: Path, *unused: Any, **kwargs: Any) -> dict[str, Any]:
            (root / "src/add.c").write_text("changed")
            return {"dry_run": False}

        monkeypatch.setattr(ops, "run_rebrew", mutate)
        status, _ = dispatch(config, "rebrew.build", json.dumps(request).encode())
        assert status == 400

        from rebrew import report

        def render(_cfg: Any, out: Path) -> dict[str, Any]:
            (out / "index.html").write_text("safe report")
            return {"out": str(out), "pages": 1, "summary": {}}

        monkeypatch.setattr(report, "generate_report", render)
        report_request = {**request, "binary_id": 1, "output_dir": "reports/generated/" + "a" * 32}
        status, reply = dispatch(config, "rebrew.report", json.dumps(report_request).encode())
        assert status == 409, reply
        status, _ = dispatch(config, "rebrew.coverage_report", json.dumps(request).encode())
        assert status == 409

    def test_skeleton(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        request = {"project_dir": str(project), "va": 0x401010, "name": "second"}
        source = _call(config, "rebrew.skeleton", request)["source"]
        assert "second" in source and "0x00401010" in source.lower()
        request["va"] = 0x10
        assert _refusal(config, "rebrew.skeleton", json.dumps(request).encode())["status"] == 400

    def test_reference_flirt(self, world: tuple[WorkerConfig, Path]) -> None:
        from rebrew.gen_flirt_pat import bytes_to_pat_line

        config, project = world
        assert config.filestore is not None
        pat = (bytes_to_pat_line("_func1", ENTRY_CODE, {5, 6, 7, 8}) + "\n---\n").encode()
        digest, key = _store(config.filestore, pat)
        request = {
            "project_dir": str(project),
            "sha256": SHA256,
            "format": "pat",
            "signatures": {"sha256": digest, "file": key},
            "min_size": 0,
        }
        reply = _call(config, "rebrew.reference_flirt", request)
        assert [(m["va"], m["names"]) for m in reply["matches"]] == [("0x00401000", ["_func1"])]
        request["format"] = "idb"
        assert _refusal(config, "rebrew.reference_flirt", json.dumps(request).encode())[
            "status"
        ] == (400)

    def test_the_analysis_report_follows_its_published_shape(
        self, fresh_analysis: tuple[Path, dict[str, Any]]
    ) -> None:
        """The backend parses ``.relumea/analysis-report.json`` from the capture, so
        its path and shape are rebrew's contract, published beside the ops (R4-022).
        They lived only in code on both sides."""
        capture = fresh_analysis[1]["analysis_capture"]
        documents = _CONTRACT["documents"]
        assert list(documents) == [capture["report_path"]]
        entry = next(e for e in capture["entries"] if e["path"] == capture["report_path"])
        report = json.loads(base64.b64decode(entry["data"]))
        _validate(documents[capture["report_path"]], report)
        assert [(f["va"], f["size"]) for f in report["functions"]] == [
            (0x401000, 11),
            (0x401010, 10),
        ]
        # A report the schema refuses is caught by the same validator.
        with pytest.raises(AssertionError):
            _validate(documents[capture["report_path"]], {**report, "extra": 1})

    @pytest.mark.parametrize(
        "op",
        [
            "rebrew.coverage_export",
            "rebrew.source_variants",
            "rebrew.decompme_export",
            "rebrew.source_rename",
            "rebrew.source_split",
            "rebrew.source_merge",
        ],
    )
    def test_ops_without_a_caller_are_not_served(self, op: str) -> None:
        """No backend code, client or engine calls these (R4-017), yet they wrote
        project files, the workspace or a decomp.me scratch against a live project.
        ``rebrew.retained_source_operation`` does the source work on snapshots."""
        assert op not in _CONTRACT["ops"]
        refusal = _refusal(WorkerConfig(), op, b"{}")
        assert (refusal["status"], refusal["error"]) == (404, "unknown-op")

    def test_import_project_reads_portable_coverage_documents(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        from rebrew.coverage_toml import write_coverage_toml

        config, project = world
        assert config.workspace is not None
        out = config.workspace / "exports" / "cov"
        assert write_coverage_toml(project, out, target="mini", json_output=True) == [
            out / "coverage-mini.toml"
        ]
        imported = _call(
            config, "rebrew.import-project", {"project_dir": str(project), "snapshots": str(out)}
        )
        assert len(imported["targets"][0]["functions"]) == 2

    def test_coverage_report(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        reply = _call(config, "rebrew.coverage_report", {"project_dir": str(project)})
        assert reply["report"]["version"] == 2
        assert (reply["summary"]["total_functions"], reply["summary"]["matched_functions"]) == (
            2,
            0,
        )
        assert "out" not in reply["summary"]

    def test_data_list_refuses_coverage_input_like_the_other_coverage_ops(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        """``data_list`` takes the same coverage fields as ``report``.

        A coverage input without the retained snapshot is a 400, and one
        without its verification records is a 409, the same two answers the
        other coverage ops give.  Answering 200 would list a target under an
        input those ops refuse.
        """
        config, project = world
        bare = {"project_dir": str(project), "coverage_input": {}}
        assert _refusal(config, "rebrew.data_list", json.dumps(bare).encode())["status"] == 400
        # A file is present, so this is a retained snapshot rather than the
        # no-snapshot case above; what it lacks is the verification records.
        unverified = {
            "project_dir": str(project),
            "files": [{"path": "src/a.c", "digest": "a" * 64, "size": 1}],
            "coverage_input": {"version": 1},
        }
        refusal = _refusal(config, "rebrew.data_list", json.dumps(unverified).encode())
        assert (refusal["status"], refusal["error"]) == (409, "coverage-input-unverified")

    @pytest.mark.parametrize("op", ["rebrew.report", "rebrew.coverage_report", "rebrew.data_list"])
    def test_a_partial_coverage_input_is_an_invalid_request(
        self, world: tuple[WorkerConfig, Path], op: str
    ) -> None:
        """The schema requires all eight fields; the missing ones were defaulted and
        the request was refused later as 409 coverage-input-unverified."""
        config, project = world
        request = {
            "binary_id": 1,
            "project_dir": str(project),
            "output_dir": "reports/generated/" + "b" * 32,
            "files": [{"path": "src/a.c", "digest": "a" * 64, "size": 1}],
            "rebrew_target": "mini",
            "coverage_input": {"version": 1},
            "coverage_input_digest": "c" * 64,
            "verification_records": [],
        }
        if op != "rebrew.report":
            del request["binary_id"], request["output_dir"]
        refusal = _refusal(config, op, json.dumps(request).encode())
        assert (refusal["status"], refusal["error"]) == (400, "invalid-request")
        assert refusal["detail"] == "request.coverage_input is missing source_revision"

    def test_data_list_and_set(self, world: tuple[WorkerConfig, Path]) -> None:
        config, project = world
        listing = _call(config, "rebrew.data_list", {"project_dir": str(project)})
        assert listing["sections"][".text"]["va"] == "0x00401000"
        request = {"project_dir": str(project), "va": 0x401050, "note": "seen", "dry_run": True}
        reply = _call(config, "rebrew.data_set", request)
        assert (reply["dry_run"], reply["changed"], reply["set"][0]["note"]) == (True, 1, "seen")
        empty = {"project_dir": str(project), "va": 0x401050}
        assert _refusal(config, "rebrew.data_set", json.dumps(empty).encode())["detail"] == (
            "data_set needs at least one field to set"
        )

    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("storage_kind", "bogus", "invalid storage_kind 'bogus'"),
            ("name", "not an identifier", "--name wants a C identifier"),
        ],
    )
    def test_data_set_value_the_command_rejects_is_an_invalid_request(
        self, world: tuple[WorkerConfig, Path], field: str, value: str, message: str
    ) -> None:
        """The command's usage refusal answered 500 engine-error, its kind dropped."""
        config, project = world
        request = {"project_dir": str(project), "va": 0x401050, field: value, "dry_run": True}
        refusal = _refusal(config, "rebrew.data_set", json.dumps(request).encode())
        assert (refusal["status"], refusal["error"]) == (400, "invalid-request")
        assert message in refusal["detail"]

    @pytest.mark.parametrize("source", ["../escape.c", "/etc/passwd", "src/mini/missing.c"])
    def test_source_paths_stay_in_the_project(
        self, world: tuple[WorkerConfig, Path], source: str
    ) -> None:
        config, project = world
        body = json.dumps({"project_dir": str(project), "source": source}).encode()
        assert _refusal(config, "rebrew.verify_function", body)["status"] == 400

    @pytest.mark.parametrize(
        ("op", "extra"),
        [
            ("rebrew.verify_function", {"source": "src/mini/uses_header.c"}),
            ("rebrew.verify_target", {}),
            ("rebrew.build", {}),
        ],
    )
    def test_remote_compile_refuses_headers_a_service_cannot_take(
        self,
        world: tuple[WorkerConfig, Path],
        monkeypatch: pytest.MonkeyPatch,
        op: str,
        extra: dict[str, Any],
    ) -> None:
        """A recompile older than include bundles is refused before anything compiles."""
        config, project = _project_copy(world, op.removeprefix("rebrew."))
        _with_project_header(project)
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://recompile.test")
        posted = serve_recompile(monkeypatch, features=None)
        body = json.dumps({"project_dir": str(project), **extra}).encode()
        refusal = _refusal(config, op, body)
        assert (refusal["error"], refusal["status"]) == ("remote-compile-headers", 422)
        assert refusal["detail"].startswith(
            "src/mini/uses_header.c includes the project header src/mini/local.h"
        )
        assert (
            "The recompile service at http://recompile.test does not accept include bundles"
            in (refusal["detail"])
        )
        assert "compile with a local backend" in refusal["detail"]
        assert str(project) not in refusal["detail"]
        if op in {"rebrew.verify_target", "rebrew.build"}:
            assert "1 of " in refusal["detail"], "a whole-target refusal says how many sources"
        assert posted == []

    @pytest.mark.parametrize(
        ("op", "extra"),
        [
            ("rebrew.verify_function", {"source": "src/mini/computed.c"}),
            ("rebrew.verify_target", {}),
            ("rebrew.build", {}),
        ],
    )
    def test_remote_compile_refuses_headers_that_cannot_ship(
        self,
        world: tuple[WorkerConfig, Path],
        monkeypatch: pytest.MonkeyPatch,
        op: str,
        extra: dict[str, Any],
    ) -> None:
        config, project = _project_copy(world, "unshippable_" + op.removeprefix("rebrew."))
        (project / "src" / "mini" / "computed.c").write_text(
            "#define HEADER <local.h>\n#include HEADER\nint computed(void) { return 1; }\n"
        )
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://recompile.test")
        posted = serve_recompile(monkeypatch, features=["include-bundles"])
        body = json.dumps({"project_dir": str(project), **extra}).encode()
        refusal = _refusal(config, op, body)
        assert (refusal["error"], refusal["status"]) == ("remote-compile-headers", 422)
        assert refusal["detail"].startswith("src/mini/computed.c computes an #include")
        assert posted == []

    def test_remote_compile_ships_project_headers(
        self, world: tuple[WorkerConfig, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A source that reads a project header compiles remotely with its bundle."""
        config, project = _project_copy(world, "verify_function_bundle")
        bound = min((project / "src" / "mini").glob("*.c"))
        bound.write_text('#include "local.h"\n' + bound.read_text())
        (project / "src" / "mini" / "local.h").write_text("#define ONE 1\n")
        source = bound.relative_to(project).as_posix()
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://recompile.test")
        posted = serve_recompile(monkeypatch, features=["include-bundles"])
        body = json.dumps({"project_dir": str(project), "source": source, "no_promote": True})
        _status, reply = dispatch(config, "rebrew.verify_function", body.encode())
        # The stand-in rejects every compile; the op reaches it, it is not refused.
        assert json.loads(reply).get("error") != "remote-compile-headers", reply
        (sent,) = posted
        assert sent["source_dir"] == "src/mini"
        assert sent["includes"] == [{"path": "src/mini/local.h", "content": "#define ONE 1\n"}]

    def test_a_toolchain_rejection_is_a_verdictless_422(
        self, world: tuple[WorkerConfig, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The compiler said no to the source: the caller's input, with its diagnostics."""
        config, project = _project_copy(world, "verify_function_rejected")
        source = min((project / "src" / "mini").glob("*.c")).relative_to(project).as_posix()
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://recompile.test")
        serve_recompile(monkeypatch, features=["include-bundles"])
        body = json.dumps({"project_dir": str(project), "source": source, "no_promote": True})
        refusal = _refusal(config, "rebrew.verify_function", body.encode())
        assert (refusal["status"], refusal["error"]) == (422, "toolchain-rejected"), refusal
        assert "error C2065" in refusal["detail"]
        # The rejection is a verdict recompile bills: the in-process compile counted it.
        assert refusal["remote_compile"]["count"] == 1

    def test_a_toolchain_rejection_has_one_prefix_and_keeps_its_lines(
        self, world: tuple[WorkerConfig, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It read "COMPILE ERROR: COMPILE_ERROR: ..." with the diagnostics run into one line."""
        config, project = _project_copy(world, "verify_function_two_errors")
        source = min((project / "src" / "mini").glob("*.c")).relative_to(project).as_posix()
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://recompile.test")
        diagnostics = [
            "fcn.c(3) : error C2065: 'nope' : undeclared identifier",
            "fcn.c(4) : error C2143: syntax error : missing ';' before '}'",
        ]
        serve_recompile(monkeypatch, features=["include-bundles"], log="\n".join(diagnostics))
        body = json.dumps({"project_dir": str(project), "source": source, "no_promote": True})
        refusal = _refusal(config, "rebrew.verify_function", body.encode())
        assert (refusal["status"], refusal["error"]) == (422, "toolchain-rejected"), refusal
        assert refusal["detail"].splitlines() == [
            f"COMPILE_ERROR: {diagnostics[0]}",
            diagnostics[1],
        ]

    def test_a_child_command_rejection_keeps_its_lines_without_host_paths(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A retained compile runs ``rebrew test`` as a child; its JSON error crosses intact."""
        config, project = world
        child = tmp_path / "rejecting-python"
        child.write_text(
            "#!/bin/sh\n"
            'printf \'{"error":{"kind":"toolchain_rejected","message":"COMPILE_ERROR: '
            '%s/src/a.c(1) : error C2065\\\\nsrc/a.c(2) : error C2143"}}\\n\' "$PWD" >&2\n'
            "exit 2\n"
        )
        child.chmod(0o755)
        monkeypatch.setattr(sys, "executable", str(child))
        body = json.dumps({"project_dir": str(project)}).encode()
        refusal = _refusal(config, "rebrew.data_list", body)
        assert (refusal["status"], refusal["error"]) == (422, "toolchain-rejected"), refusal
        assert refusal["detail"].splitlines() == [
            "COMPILE_ERROR: src/a.c(1) : error C2065",
            "src/a.c(2) : error C2143",
        ]

    def test_a_service_that_cannot_compile_answers_a_not_run_report(
        self, world: tuple[WorkerConfig, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The compile never ran: a report with no verdict, not a 500 the backend stores as one."""
        config, project = _project_copy(world, "verify_function_unavailable")
        source = min((project / "src" / "mini").glob("*.c")).relative_to(project).as_posix()
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://recompile.test")
        monkeypatch.setattr("rebrew.compiler.recompile_client.time.sleep", lambda _s: None)
        serve_recompile(monkeypatch, features=["include-bundles"], error_code="runner_unavailable")
        body = json.dumps({"project_dir": str(project), "source": source, "no_promote": True})
        status, raw = dispatch(config, "rebrew.verify_function", body.encode())
        reply = json.loads(raw)
        assert status == 200, reply
        assert reply["status"] == "NOT_RUN"
        # The reason is a closed set; the compile client's message stays out of the reply.
        assert reply["not_run_reason"] == "service" and "message" not in reply
        assert reply["error"]["error_code"] == "runner_unavailable"
        assert "message" not in reply["error"]


# ---------------------------------------------------------------------------
# Transports, end to end through the installed command
# ---------------------------------------------------------------------------


def _rebrew(*args: str) -> list[str]:
    return [sys.executable, "-m", "rebrew.app.main", *args]


class TestExecTransport:
    def _exec(self, argv: list[str], op: str, request: dict[str, Any]) -> tuple[int, Any]:
        """Run the worker the way the backend's exec transport does: argv, then the op."""
        _validate(_op_schema(op, "request"), request)
        done = subprocess.run(
            [*argv, op],
            input=json.dumps(request).encode(),
            capture_output=True,
            timeout=WAIT_SECONDS,
            check=False,
        )
        return done.returncode, json.loads(done.stdout)

    def test_analyse_then_disassemble(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        argv = _rebrew("ops", "call", "--filestore", str(filestore), "--workspace", str(workspace))
        code, reply = self._exec(argv, "rebrew.analyse", _analyse_request())
        assert code == 0, reply
        _validate(_op_schema("rebrew.analyse", "response"), reply)
        project = _check_analysed(reply, workspace.resolve())

        request = {"project_dir": str(project), "va": ENTRY_VA, "size": 1, "format": "asm"}
        code, reply = self._exec(argv, "rebrew.disassemble", request)
        assert (code, reply["text"]) == (0, "push ebp\n")
        _validate(_op_schema("rebrew.disassemble", "response"), reply)

    def test_sigterm_stops_the_child_command_and_removes_the_snapshot(
        self, fresh_analysis: tuple[Path, dict[str, Any]], tmp_path: Path
    ) -> None:
        """The backend cancels an exec call with SIGTERM to the worker's process group.

        The child command runs in its own session, outside that group, and the
        worker died without stopping it: it kept running and the retained
        snapshot under ``.scratch`` stayed on disk.
        """
        config, request, _analysed, _envelope = _retained_coverage_request(fresh_analysis, tmp_path)
        assert config.filestore is not None and config.workspace is not None
        pid_file = tmp_path / "child.pid"
        launcher = tmp_path / "launch.py"
        # The worker's own interpreter, with the sleeping stand-in as the
        # sys.executable its child commands start.
        launcher.write_text(
            "import runpy\nimport sys\n\n"
            "sys.executable = sys.argv[1]\n"
            'sys.argv = ["rebrew", *sys.argv[2:]]\n'
            'runpy.run_module("rebrew.app.main", run_name="__main__")\n'
        )
        argv = [
            sys.executable,
            str(launcher),
            str(_sleeping_python(tmp_path)),
            "ops",
            "call",
            "--filestore",
            str(config.filestore),
            "--workspace",
            str(config.workspace),
            "rebrew.data_list",
        ]
        with (tmp_path / "worker.log").open("wb") as log:
            worker = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=log,
                env={**os.environ, _CHILD_PID_ENV: str(pid_file)},
                start_new_session=True,
            )
        assert worker.stdin is not None
        worker.stdin.write(json.dumps(request).encode())
        worker.stdin.close()
        child = _child_pid(pid_file)
        try:
            os.killpg(worker.pid, signal.SIGTERM)
            assert worker.wait(timeout=WAIT_SECONDS) == 128 + signal.SIGTERM
            assert _stopped(child, _STOP_SECONDS)
            assert not list((config.workspace / ".scratch").glob("retained-target-*"))
        finally:
            _kill_leftover(child)
            if worker.poll() is None:
                worker.kill()
                worker.wait(timeout=WAIT_SECONDS)

    def test_refusal_exits_2_with_the_error_on_stdout(self, tmp_path: Path) -> None:
        request = {"project_dir": str(tmp_path), "va": 0, "size": 1, "format": "asm"}
        code, reply = self._exec(_rebrew("ops", "call"), "rebrew.disassemble", request)
        assert code == 2
        assert reply == {
            "error": "invalid-request",
            "detail": "project_dir is not a rebrew project (no rebrew-project.toml)",
            "status": 400,
        }


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


#: Environment variable naming the file the sleeping child writes its pid to.
_CHILD_PID_ENV = "REBREW_TEST_CHILD_PID"


def _sleeping_python(directory: Path) -> Path:
    """A stand-in for the interpreter a child command runs under: it records its pid and sleeps.

    ``run_rebrew`` starts ``sys.executable -P -m rebrew.app.main ...``; with this
    as ``sys.executable`` the child never finishes on its own.
    """
    script = directory / "sleeping-python"
    script.write_text(f'#!/bin/sh\necho $$ > "${_CHILD_PID_ENV}"\nexec sleep {WAIT_SECONDS}\n')
    script.chmod(0o755)
    return script


def _child_pid(path: Path) -> int:
    deadline = time.monotonic() + WAIT_SECONDS
    while not path.is_file() or not path.read_text().strip():
        assert time.monotonic() < deadline, "the child command never started"
        time.sleep(0.05)
    return int(path.read_text())


def _deadline_once_the_child_runs(monkeypatch: pytest.MonkeyPatch, pid_file: Path) -> None:
    """Let the op's deadline end the call only once its child command has written *pid_file*.

    A 1 s deadline could otherwise pass before the op spawned the child (a loaded
    host stages the snapshot slowly): the call answered 504 with no child to stop,
    and the test waited for a pid that never came.  A caller's own cancellation
    is not held.
    """
    import rebrew.ops as ops

    real_check = ops._Cancellation.check

    def check(self: Any) -> None:
        if self._refusal is not None or (pid_file.is_file() and pid_file.read_text().strip()):
            real_check(self)

    monkeypatch.setattr(ops._Cancellation, "check", check)


def _stopped(pid: int, within: float) -> bool:
    """Whether process *pid* is gone (killed and reaped) within *within* seconds."""
    deadline = time.monotonic() + within
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def _kill_leftover(pid: int) -> None:
    """Stop a child an unfixed worker left running, by its exact pid."""
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)


#: Seconds a cancelled call may take to stop its child command.
_STOP_SECONDS = 20


class TestHttpCancellation:
    """A call stops when its caller gives up, and its slot serves the next call."""

    @contextlib.contextmanager
    def _serving(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> Any:
        """A one-slot worker whose child commands sleep; yields (port, pid file, request)."""
        from rebrew.ops import OpsServer

        config, project = world
        pid_file = tmp_path / "child.pid"
        monkeypatch.setattr(sys, "executable", str(_sleeping_python(tmp_path)))
        monkeypatch.setenv(_CHILD_PID_ENV, str(pid_file))
        body = json.dumps({"project_dir": str(project)}).encode()
        with OpsServer(("127.0.0.1", 0), config, TOKEN, 1) as server:
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
            )
            thread.start()
            try:
                yield server.server_address[1], pid_file, body
            finally:
                if pid_file.is_file():
                    _kill_leftover(int(pid_file.read_text()))
                server.shutdown()
                thread.join(timeout=WAIT_SECONDS)

    @staticmethod
    def _request(port: int, body: bytes, extra: str = "") -> bytes:
        return (
            f"POST /rebrew.data_list HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
            f"Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n{extra}\r\n"
        ).encode() + body

    def test_a_caller_that_closes_the_connection_stops_the_call(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The backend gives up at its dispatch timeout and closes the connection.

        Nothing watched the socket, so the child command ran on to its own
        bound (up to an hour) holding one of the worker's slots.
        """
        with self._serving(world, tmp_path, monkeypatch) as (port, pid_file, body):
            caller = socket.create_connection(("127.0.0.1", port), timeout=WAIT_SECONDS)
            caller.sendall(self._request(port, body))
            child = _child_pid(pid_file)
            caller.close()
            assert _stopped(child, _STOP_SECONDS)
            status, _reply = TestHttpTransport()._wait_for_a_free_slot(
                port, time.monotonic() + _STOP_SECONDS
            )
            assert status == 404

    def test_a_call_past_its_deadline_answers_504_and_stops(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with self._serving(world, tmp_path, monkeypatch) as (port, pid_file, body):
            caller = socket.create_connection(("127.0.0.1", port), timeout=WAIT_SECONDS)
            try:
                caller.sendall(self._request(port, body, "X-Rebrew-Timeout: 1\r\n"))
                child = _child_pid(pid_file)
                reply = b"".join(iter(lambda: caller.recv(4096), b""))
            finally:
                caller.close()
            head, _, payload = reply.partition(b"\r\n\r\n")
            assert head.split(b"\r\n", 1)[0].split(b" ", 2)[1] == b"504"
            assert json.loads(payload)["error"] == "deadline-exceeded"
            assert _stopped(child, _STOP_SECONDS)

    @pytest.mark.parametrize("value", ["0", "-1", "soon", "nan", "inf"])
    def test_a_malformed_deadline_is_refused(
        self,
        world: tuple[WorkerConfig, Path],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        value: str,
    ) -> None:
        with self._serving(world, tmp_path, monkeypatch) as (port, pid_file, body):
            status, reply = TestHttpTransport()._post(
                port,
                "/rebrew.data_list",
                body,
                {"Authorization": f"Bearer {TOKEN}", "X-Rebrew-Timeout": value},
            )
            assert (status, reply["error"]) == (400, "invalid-request")
            assert not pid_file.exists()


#: Names the file the counting child waits for before it finishes.
_BARRIER_ENV = "REBREW_TEST_BARRIER"


def _counting_python(directory: Path) -> Path:
    """A stand-in for a child command's interpreter that counts like ``rebrew verify``.

    It writes 1 of 3 to the progress descriptor the worker hands it, waits for
    the test's barrier file, writes 3 of 3 and prints its report.
    """
    script = directory / "counting-python"
    # /dev/fd: dash (CI's /bin/sh) refuses `>&N` for a descriptor above 9.
    script.write_text(
        "#!/bin/sh\n"
        'printf \'{"done": 1, "total": 3}\\n\' > "/dev/fd/$REBREW_PROGRESS_FD"\n'
        f'while [ ! -e "${_BARRIER_ENV}" ]; do sleep 0.05; done\n'
        'printf \'{"done": 3, "total": 3}\\n\' > "/dev/fd/$REBREW_PROGRESS_FD"\n'
        "printf '{\"spliced\": 3}\\n'\n"
    )
    script.chmod(0o755)
    return script


class TestProgress:
    """A long call's child counts reach its caller while it runs, on both transports.

    A verification of all 316 functions of a target ran 18 minutes with no
    count anyone could read; the job showed 0% and looked hung.
    """

    @staticmethod
    def _frames(lines: list[bytes]) -> list[Any]:
        return [json.loads(line) for line in lines]

    def test_serve_streams_counts_then_the_reply_to_a_caller_that_accepts_them(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.ops import PROGRESS_MEDIA_TYPE, OpsServer

        config, project = world
        barrier = tmp_path / "go"
        monkeypatch.setattr(sys, "executable", str(_counting_python(tmp_path)))
        monkeypatch.setenv(_BARRIER_ENV, str(barrier))
        body = json.dumps({"project_dir": str(project), "no_promote": True}).encode()
        with OpsServer(("127.0.0.1", 0), config, TOKEN, 1) as server:
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
            )
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
                connection.request(
                    "POST",
                    "/rebrew.verify_target",
                    body,
                    {
                        "Authorization": f"Bearer {TOKEN}",
                        "Content-Type": "application/json",
                        "Accept": f"application/json, {PROGRESS_MEDIA_TYPE}",
                    },
                )
                response = connection.getresponse()
                assert response.status == 200
                assert response.getheader("Content-Type") == PROGRESS_MEDIA_TYPE
                first = response.readline()
                barrier.touch()
                rest = response.read().splitlines()
                connection.close()
            finally:
                # The child waits for it: a failed assertion must not leave it running.
                barrier.touch()
                server.shutdown()
                thread.join(timeout=WAIT_SECONDS)
        assert self._frames([first, *rest]) == [
            {"progress": {"done": 1, "total": 3}},
            {"progress": {"done": 3, "total": 3}},
            {"status": 200, "reply": {"spliced": 3, "remote_compile": NO_REMOTE_COMPILES}},
        ]

    def test_serve_answers_plain_json_to_a_caller_that_does_not_accept_counts(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.ops import OpsServer

        config, project = world
        barrier = tmp_path / "go"
        barrier.touch()
        monkeypatch.setattr(sys, "executable", str(_counting_python(tmp_path)))
        monkeypatch.setenv(_BARRIER_ENV, str(barrier))
        body = json.dumps({"project_dir": str(project), "no_promote": True}).encode()
        with OpsServer(("127.0.0.1", 0), config, TOKEN, 1) as server:
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
            )
            thread.start()
            try:
                status, reply = TestHttpTransport()._post(
                    server.server_address[1],
                    "/rebrew.verify_target",
                    body,
                    {"Authorization": f"Bearer {TOKEN}"},
                )
            finally:
                server.shutdown()
                thread.join(timeout=WAIT_SECONDS)
        assert (status, reply) == (200, {"spliced": 3, "remote_compile": NO_REMOTE_COMPILES})

    def test_ops_call_writes_counts_to_the_descriptor_the_caller_names(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path
    ) -> None:
        from rebrew.ops import DISPATCH_PROGRESS_FD_ENV

        config, project = world
        assert config.workspace is not None
        barrier = tmp_path / "go"
        launcher = tmp_path / "launch.py"
        launcher.write_text(
            "import runpy\nimport sys\n\n"
            "sys.executable = sys.argv[1]\n"
            'sys.argv = ["rebrew", *sys.argv[2:]]\n'
            'runpy.run_module("rebrew.app.main", run_name="__main__")\n'
        )
        read, write = os.pipe()
        argv = [
            sys.executable,
            str(launcher),
            str(_counting_python(tmp_path)),
            "ops",
            "call",
            "--workspace",
            str(config.workspace),
            "rebrew.verify_target",
        ]
        try:
            worker = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={
                    **os.environ,
                    _BARRIER_ENV: str(barrier),
                    DISPATCH_PROGRESS_FD_ENV: str(write),
                },
                pass_fds=(write,),
            )
        finally:
            os.close(write)
        with os.fdopen(read, "rb") as progress:
            try:
                assert worker.stdin is not None
                worker.stdin.write(
                    json.dumps({"project_dir": str(project), "no_promote": True}).encode()
                )
                worker.stdin.close()
                assert select.select([progress], [], [], WAIT_SECONDS)[0], "no count arrived"
                first = progress.readline()
                barrier.touch()
                rest = progress.read().splitlines()
                assert worker.stdout is not None
                stdout = worker.stdout.read()
                assert worker.wait(timeout=WAIT_SECONDS) == 0
            finally:
                # The child waits for it: a failed assertion must not leave it running.
                barrier.touch()
                if worker.poll() is None:
                    worker.kill()
                    worker.wait(timeout=WAIT_SECONDS)
        assert self._frames([first, *rest]) == [
            {"progress": {"done": 1, "total": 3}},
            {"progress": {"done": 3, "total": 3}},
        ]
        assert json.loads(stdout) == {"spliced": 3, "remote_compile": NO_REMOTE_COMPILES}


class TestFailureDetails:
    """A failure nothing else explained answers its step and its message, never a log pointer.

    Users read "rebrew.build failed; the worker log has the cause" through the
    backend, about a log they cannot see.
    """

    def test_a_build_failure_names_its_step_and_cause_without_host_paths(
        self,
        fresh_analysis: tuple[Path, dict[str, Any]],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import rebrew.ops as ops

        config, retained, _analysed, _envelope = _retained_coverage_request(
            fresh_analysis, tmp_path
        )
        request = {
            key: retained[key]
            for key in ("project_dir", "sha256", "files", "rebrew_target", "binary_key")
        }

        def missing_source(cfg: Any, _sources: Any) -> None:
            raise FileNotFoundError(2, "No such file or directory", str(cfg.root / "src/a.c"))

        monkeypatch.setattr(ops, "retained_compile_refusal", missing_source)
        refusal = _refusal(config, "rebrew.build", json.dumps(request).encode())
        assert (refusal["status"], refusal["error"]) == (500, "engine-error")
        assert refusal["detail"] == (
            "rebrew.build failed while checking the sources for a remote compile: "
            "No such file or directory: src/a.c"
        )

    def test_vocabulary_names_the_discovery_rule(self) -> None:
        """A client compares a stored analysis's rule with the engine's without analysing."""
        reply = _call(WorkerConfig(), "rebrew.vocabulary", {})
        assert reply["discovery_rule"] == DISCOVERY_RULE

    def test_any_op_failure_answers_its_cause_without_paths_or_urls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken(_config: Any, _req: Any) -> dict[str, Any]:
            raise ValueError(
                "cannot read /home/worker/.cache/rebrew/table.json from "
                "https://bucket.example/obj?X-Amz-Signature=s3cret"
            )

        op = OPS["rebrew.vocabulary"]
        monkeypatch.setitem(OPS, "rebrew.vocabulary", dataclasses.replace(op, run=broken))
        refusal = _refusal(WorkerConfig(), "rebrew.vocabulary", b"{}")
        assert (refusal["status"], refusal["error"]) == (500, "engine-error")
        assert refusal["detail"] == "rebrew.vocabulary failed: cannot read table.json from <url>"


class TestOpDeadlines:
    """Every op runs under the deadline the dispatch schema publishes for it (R4-001).

    The backend bounded every call with one 5-minute dispatch timeout while
    rebrew bounded its child commands at 10 minutes to an hour and its own
    work not at all, so neither side knew how long an op may run.
    """

    def test_every_op_publishes_the_deadline_it_runs_under(self) -> None:
        published = {
            name: (entry["timeout_seconds"], entry["interruptible"])
            for name, entry in _CONTRACT["ops"].items()
        }
        assert published == {
            name: (op.timeout_seconds, op.interruptible) for name, op in OPS.items()
        }

    def test_exactly_the_compiling_ops_take_an_attribution_and_report_remote_compiles(
        self,
    ) -> None:
        """The backend charges these ops by the reply's count; the schema must say which they are."""

        attributed = {
            name
            for name, entry in _CONTRACT["ops"].items()
            if "attribution" in entry["request"].get("properties", {})
        }
        reported = {
            name
            for name, entry in _CONTRACT["ops"].items()
            if "remote_compile" in entry["response"].get("required", [])
        }
        assert attributed == reported == COMPILING_OPS

    def test_a_child_command_past_its_op_deadline_answers_504_and_stops(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With no caller deadline (the exec transport has none) the op's own one stops the child."""
        config, project = world
        pid_file = tmp_path / "child.pid"
        monkeypatch.setattr(sys, "executable", str(_sleeping_python(tmp_path)))
        monkeypatch.setenv(_CHILD_PID_ENV, str(pid_file))
        op = OPS["rebrew.data_list"]
        monkeypatch.setitem(OPS, "rebrew.data_list", dataclasses.replace(op, timeout_seconds=1))
        _deadline_once_the_child_runs(monkeypatch, pid_file)
        body = json.dumps({"project_dir": str(project)}).encode()
        replies: list[tuple[int, bytes]] = []
        call = threading.Thread(
            target=lambda: replies.append(dispatch(config, "rebrew.data_list", body)), daemon=True
        )
        call.start()
        child = _child_pid(pid_file)
        try:
            call.join(_STOP_SECONDS)
            assert replies, "the call ran past its op deadline"
            status, reply = replies[0]
            assert (status, json.loads(reply)["error"]) == (504, "deadline-exceeded")
            assert _stopped(child, _STOP_SECONDS)
        finally:
            _kill_leftover(child)
            call.join(WAIT_SECONDS)

    @pytest.mark.parametrize("op", ["rebrew.verify_function", "rebrew.apply_candidate"])
    def test_a_candidate_past_its_op_deadline_answers_504_and_stops_its_child(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, op: str
    ) -> None:
        """Both candidate ops compile in a ``rebrew test`` child, which the op's deadline kills."""
        from test_apply_candidate import _request, _stage

        config, entries = _stage(tmp_path)
        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://127.0.0.1:18953")
        pid_file = tmp_path / "child.pid"
        monkeypatch.setattr(sys, "executable", str(_sleeping_python(tmp_path)))
        monkeypatch.setenv(_CHILD_PID_ENV, str(pid_file))
        monkeypatch.setitem(OPS, op, dataclasses.replace(OPS[op], timeout_seconds=1))
        _deadline_once_the_child_runs(monkeypatch, pid_file)
        replies: list[tuple[int, bytes]] = []
        call = threading.Thread(
            target=lambda: replies.append(dispatch(config, op, _request(entries))), daemon=True
        )
        call.start()
        child = _child_pid(pid_file)
        try:
            call.join(_STOP_SECONDS)
            assert replies, "the call ran past its op deadline"
            status, reply = replies[0]
            assert (status, json.loads(reply)["error"]) == (504, "deadline-exceeded")
            assert _stopped(child, _STOP_SECONDS)
        finally:
            _kill_leftover(child)
            call.join(WAIT_SECONDS)

    def test_verify_function_without_a_candidate_runs_in_process_past_its_deadline(
        self, world: tuple[WorkerConfig, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``rebrew test`` runs in the worker for a project source: nothing stops it at the deadline.

        With a candidate the op's work is a child command the deadline kills
        (above), so the op is interruptible in that mode only and is published
        ``interruptible`` false.
        """
        config, project = world
        op = OPS["rebrew.verify_function"]
        monkeypatch.setitem(
            OPS, "rebrew.verify_function", dataclasses.replace(op, timeout_seconds=1)
        )
        ran: list[float] = []

        def outlives_the_deadline(*args: Any, **kwargs: Any) -> dict[str, Any]:
            time.sleep(1.5)
            ran.append(time.monotonic())
            return {"status": "EXACT"}

        monkeypatch.setattr("rebrew.test.run_test", outlives_the_deadline)
        source = min((project / "src" / "mini").glob("*.c")).relative_to(project).as_posix()
        body = json.dumps({"project_dir": str(project), "source": source, "no_promote": True})
        status, reply = dispatch(config, "rebrew.verify_function", body.encode())
        assert (status, json.loads(reply)) == (
            200,
            {"status": "EXACT", "remote_compile": NO_REMOTE_COMPILES},
        )
        assert len(ran) == 1

    def test_a_child_command_gets_its_deadline_less_the_report_reserve(
        self, world: tuple[WorkerConfig, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The child's remote compiles retry within the op's deadline, so they must know it."""
        import rebrew.ops as ops

        config, project = world
        seen = tmp_path / "deadline"
        child = tmp_path / "reporting-python"
        child.write_text(f'#!/bin/sh\necho "$REBREW_CALL_DEADLINE" > "{seen}"\necho "{{}}"\n')
        child.chmod(0o755)
        monkeypatch.setattr(sys, "executable", str(child))
        body = json.dumps({"project_dir": str(project)}).encode()
        before = time.time()
        status, reply = dispatch(config, "rebrew.data_list", body)
        assert status == 200, reply
        deadline = float(seen.read_text())
        bound = OPS["rebrew.data_list"].timeout_seconds - ops.CHILD_REPORT_SECONDS
        assert before + bound - 5 <= deadline <= time.time() + bound

    def test_an_import_past_its_deadline_installs_nothing(
        self, analysed_project: tuple[WorkerConfig, Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``import_archive`` runs in the worker and checks its deadline between steps."""
        import rebrew.metadata_transfer

        config, filestore, project = analysed_project
        op = OPS["rebrew.import_archive"]
        monkeypatch.setitem(
            OPS, "rebrew.import_archive", dataclasses.replace(op, timeout_seconds=1)
        )
        scope = rebrew.metadata_transfer.scope_metadata_to_module

        def outlives_the_deadline(*args: Any, **kwargs: Any) -> Any:
            time.sleep(1.5)
            return scope(*args, **kwargs)

        monkeypatch.setattr(
            rebrew.metadata_transfer, "scope_metadata_to_module", outlives_the_deadline
        )
        status, reply = _import(config, filestore, _tar_bytes(_project_members(project)))
        assert (status, reply["error"]) == (504, "deadline-exceeded"), reply
        assert config.workspace is not None
        scope_dir = (
            config.workspace / "projects" / "scopes" / hashlib.sha256(b"imported").hexdigest()
        )
        assert not scope_dir.exists()
        assert not list((config.workspace / ".scratch").glob("project-import-*"))


#: One compile and byte-compare in a GA run, measured on smygb's real MSVC6
#: toolchain (docs/PERFORMANCE.md, "GA bottleneck: compilation, not scoring").
_MEASURED_COMPILE_SECONDS = 0.585


class TestVariantSearchBounds:
    """A retained variant search is capped to what fits its op's deadline (R4-001).

    ``generations`` and ``population`` had only a lower bound, so a request
    for 10**6 generations was accepted and ran until the deadline killed it.
    """

    @staticmethod
    def _request(
        fresh_analysis: tuple[Path, dict[str, Any]], tmp_path: Path
    ) -> tuple[WorkerConfig, dict[str, Any]]:
        import rebrew.ops as ops

        config, retained, _analysed, _envelope = _retained_coverage_request(
            fresh_analysis, tmp_path
        )
        source = next(entry["path"] for entry in retained["files"] if entry["path"].endswith(".c"))
        candidate = "int candidate(void) { return 0; }\n"
        return config, {
            "files": retained["files"],
            "rebrew_target": retained["rebrew_target"],
            "sha256": SHA256,
            "binary_key": KEY,
            "operation": "variants",
            "source": source,
            "candidate": candidate,
            "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
            "va": ENTRY_VA,
            "size": ENTRY_SIZE,
            "generations": ops.VARIANT_MAX_GENERATIONS,
            "population": ops.VARIANT_MAX_POPULATION,
        }

    @staticmethod
    def _searches(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
        """Record the search commands the op runs, answering each with an empty result."""
        import rebrew.ops as ops

        searches: list[list[str]] = []

        def search(arguments: list[str], *_args: Any, **_kwargs: Any) -> dict[str, Any]:
            searches.append(arguments)
            return {}

        monkeypatch.setattr(ops, "run_rebrew", search)
        return searches

    @pytest.mark.parametrize(
        ("field", "cap"),
        [("generations", "VARIANT_MAX_GENERATIONS"), ("population", "VARIANT_MAX_POPULATION")],
    )
    def test_a_bound_over_its_cap_is_refused_naming_the_cap(
        self,
        fresh_analysis: tuple[Path, dict[str, Any]],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        field: str,
        cap: str,
    ) -> None:
        import rebrew.ops as ops

        config, request = self._request(fresh_analysis, tmp_path)
        searches = self._searches(monkeypatch)
        limit = getattr(ops, cap)
        body = json.dumps({**request, field: limit + 1}).encode()
        refusal = _refusal(config, "rebrew.retained_source_operation", body)
        assert (refusal["status"], refusal["error"]) == (400, "invalid-request")
        assert refusal["detail"] == f"{field} must be at most {cap} ({limit}), got {limit + 1}"
        assert searches == []

    def test_a_search_at_both_caps_runs(
        self,
        fresh_analysis: tuple[Path, dict[str, Any]],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import rebrew.ops as ops

        config, request = self._request(fresh_analysis, tmp_path)
        searches = self._searches(monkeypatch)
        assert _call(config, "rebrew.retained_source_operation", request) == {
            "result": {},
            "remote_compile": NO_REMOTE_COMPILES,
        }
        [search] = searches
        assert f"--generations={ops.VARIANT_MAX_GENERATIONS}" in search
        assert f"--pop-size={ops.VARIANT_MAX_POPULATION}" in search

    def test_a_search_at_both_caps_fits_the_op_deadline(self) -> None:
        """Every candidate of every generation and the champion compiled, over the GA's default jobs."""
        import rebrew.ops as ops
        from rebrew.config import DEFAULT_PROJECT_JOBS

        candidates = ops.VARIANT_MAX_GENERATIONS * ops.VARIANT_MAX_POPULATION + 1
        seconds = candidates * _MEASURED_COMPILE_SECONDS / DEFAULT_PROJECT_JOBS
        assert seconds <= OPS["rebrew.retained_source_operation"].timeout_seconds


class TestRetainedSnapshotApi:
    """The retained-snapshot staging engines beside rebrew import (docs/PYTHON_API.md).

    recoverage staged retained snapshots with ``FlagSearchFile``,
    ``retained_target_snapshot``, ``confined_snapshot_config``, ``WorkerConfig``
    and ``OpsError`` from ``rebrew.ops`` while no document published them (R7-005).
    """

    def test_documented_names_snapshot(self) -> None:
        """Gating: the documented names keep their import path and shape."""
        import inspect

        import rebrew.ops as ops
        from rebrew.errors import OpsError

        assert [f.name for f in dataclasses.fields(ops.RetainedFile)] == [
            "path",
            "digest",
            "size",
            "key",
            "url",
        ]
        assert [f.name for f in dataclasses.fields(ops.WorkerConfig)] == [
            "filestore",
            "workspace",
            "max_download_bytes",
        ]
        assert list(inspect.signature(ops.retained_target_snapshot).parameters) == [
            "config",
            "files",
            "target_name",
            "sha256",
            "binary_key",
            "binary_url",
            "project_cflags",
        ]
        assert list(inspect.signature(ops.OpsServer).parameters) == [
            "address",
            "config",
            "token",
            "concurrency",
            "allowed_hosts",
            "ops",
            "answer",
        ]
        assert list(inspect.signature(ops.OpsServer.request_stop).parameters) == ["self"]
        assert list(inspect.signature(ops.OpsServer.drain).parameters) == ["self", "timeout"]
        from rebrew import telemetry

        assert list(inspect.signature(telemetry.configure).parameters) == [
            "endpoint",
            "service",
            "version",
        ]
        assert ops.OpsError is OpsError

    def test_stages_the_manifest_and_removes_it_after(
        self, fresh_analysis: tuple[Path, dict[str, Any]], tmp_path: Path
    ) -> None:
        from rebrew.config import load_config
        from rebrew.ops import RetainedFile, retained_target_snapshot

        config, request, _analysed, _envelope = _retained_coverage_request(fresh_analysis, tmp_path)
        assert config.workspace is not None
        target = request["rebrew_target"]
        files = [RetainedFile(**entry) for entry in request["files"]]
        with retained_target_snapshot(config, files, target, SHA256, KEY, "") as root:
            assert root.is_relative_to(config.workspace / ".scratch")
            for entry in request["files"]:
                staged = (root / entry["path"]).read_bytes()
                assert hashlib.sha256(staged).hexdigest() == entry["digest"]
            binary = load_config(root, target=target).target_binary
            assert hashlib.sha256(binary.read_bytes()).hexdigest() == SHA256
        assert not root.exists()

    def test_a_stored_file_that_does_not_match_is_an_ops_error(
        self, fresh_analysis: tuple[Path, dict[str, Any]], tmp_path: Path
    ) -> None:
        from rebrew.errors import OpsError
        from rebrew.ops import RetainedFile, retained_target_snapshot

        config, request, _analysed, _envelope = _retained_coverage_request(fresh_analysis, tmp_path)
        assert config.filestore is not None and config.workspace is not None
        (config.filestore / request["files"][0]["key"]).write_bytes(b"changed")
        files = [RetainedFile(**entry) for entry in request["files"]]
        with (
            pytest.raises(OpsError) as refused,
            retained_target_snapshot(config, files, request["rebrew_target"], SHA256, KEY, ""),
        ):
            pytest.fail("a snapshot with a changed file was staged")
        assert (refused.value.code, refused.value.status) == ("engine-error", 500)
        assert str(refused.value) == "the stored file does not match its sha256"
        assert not list((config.workspace / ".scratch").glob("retained-target-*"))

    def test_a_config_whose_paths_leave_the_snapshot_is_refused_while_staging(
        self, fresh_analysis: tuple[Path, dict[str, Any]], tmp_path: Path
    ) -> None:
        """Staging confines the project config itself: a caller need not check it again."""
        import tomlkit

        from rebrew.errors import OpsError
        from rebrew.ops import RetainedFile, retained_target_snapshot

        config, request, _analysed, _envelope = _retained_coverage_request(fresh_analysis, tmp_path)
        assert config.filestore is not None
        entries = []
        for entry in request["files"]:
            if entry["path"] == "rebrew-project.toml":
                document = tomlkit.parse((config.filestore / entry["key"]).read_text())
                document.setdefault("project", tomlkit.table())["output_dir"] = "../outside"
                data = tomlkit.dumps(document).encode()
                digest, key = _store(config.filestore, data)
                entry = {**entry, "digest": digest, "key": key, "size": len(data)}
            entries.append(RetainedFile(**entry))
        with (
            pytest.raises(OpsError) as refused,
            retained_target_snapshot(config, entries, request["rebrew_target"], SHA256, KEY, ""),
        ):
            pytest.fail("a snapshot whose config leaves it was staged")
        assert (refused.value.code, refused.value.status) == ("invalid-request", 400)
        assert str(refused.value) == "retained project configuration escapes the snapshot"


class TestHttpTransport:
    def test_ephemeral_port_uses_bound_port_for_host_checks(self) -> None:
        from rebrew.ops import OpsServer

        with OpsServer(("127.0.0.1", 0), WorkerConfig(), TOKEN, 1) as server:
            port = server.server_address[1]
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
            )
            thread.start()
            try:
                for host, expected in (
                    (f"127.0.0.1:{port}", 200),
                    (f"foreign.invalid:{port}", 403),
                    ("127.0.0.1:0", 403),
                ):
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    try:
                        connection.request(
                            "GET",
                            "/health",
                            headers={"Host": host, "Authorization": f"Bearer {TOKEN}"},
                        )
                        response = connection.getresponse()
                        response.read()
                        assert response.status == expected, host
                    finally:
                        connection.close()
            finally:
                server.shutdown()
                thread.join(timeout=5)
            assert not thread.is_alive()

    def test_sigterm_drains_active_request(self, tmp_path: Path) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        port = _free_port()
        process = subprocess.Popen(
            _rebrew(
                "ops",
                "serve",
                "--port",
                str(port),
                "--filestore",
                str(filestore),
                "--workspace",
                str(workspace),
                "--concurrency",
                "1",
            ),
            env={**os.environ, "REBREW_OPS_TOKEN": TOKEN},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        connection = None
        try:
            deadline = time.monotonic() + WAIT_SECONDS
            while True:
                assert process.poll() is None and time.monotonic() < deadline
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=1).close()
                    break
                except OSError:
                    time.sleep(0.1)
            # A stalled call sent once can lose the slot to the first probe and be refused,
            # leaving every later probe a 404: the helper sends it again until it holds the slot.
            connection = self._hold_the_only_slot(port)
            process.terminate()
            time.sleep(0.2)
            assert process.poll() is None
            connection.sendall(b'{"xx": 12}')
            reply = b"".join(iter(lambda: connection.recv(4096), b""))
            head, _, body = reply.partition(b"\r\n\r\n")
            assert (head.split(b"\r\n", 1)[0], json.loads(body)["error"]) == (
                b"HTTP/1.0 400 Bad Request",
                "invalid-request",
            )
            assert process.wait(timeout=5) == 0
        finally:
            if connection is not None:
                connection.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=WAIT_SECONDS)

    @pytest.fixture
    def server(self, tmp_path: Path) -> Any:
        """A one-slot ``rebrew ops serve`` of its own, for a test that holds the slot or writes."""
        with self._serve(tmp_path) as served:
            yield served

    @pytest.fixture(scope="class")
    @classmethod
    def slot_free_server(cls, tmp_path_factory: pytest.TempPathFactory) -> Any:
        """One server shared by tests whose requests never take the slot or write the workspace."""
        with cls._serve(tmp_path_factory.mktemp("serve")) as served:
            yield served

    @staticmethod
    @contextlib.contextmanager
    def _serve(root: Path) -> Any:
        """Run ``rebrew ops serve`` with one slot over a worker root; yields (port, workspace)."""
        filestore, workspace = _worker_dirs(root)
        port = _free_port()
        process = subprocess.Popen(
            _rebrew(
                "ops",
                "serve",
                "--port",
                str(port),
                "--filestore",
                str(filestore),
                "--workspace",
                str(workspace),
                "--concurrency",
                "1",
                "--allowed-hosts",
                f"relumea-rebrew:{port}",
            ),
            env={**os.environ, "REBREW_OPS_TOKEN": TOKEN, "PYTHONUNBUFFERED": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + WAIT_SECONDS
        try:
            while True:
                assert process.poll() is None, "rebrew ops serve exited"
                assert time.monotonic() < deadline, "rebrew ops serve did not start"
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=1).close()
                    break
                except OSError:
                    time.sleep(0.1)
            yield port, workspace
        finally:
            process.terminate()
            process.wait(timeout=WAIT_SECONDS)

    def _post(self, port: int, path: str, body: bytes, headers: dict[str, str]) -> tuple[int, Any]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            req_headers = {"Content-Type": "application/json", **headers}
            connection.request("POST", path, body=body, headers=req_headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def _op(self, port: int, op: str, request: dict[str, Any]) -> Any:
        _validate(_op_schema(op, "request"), request)
        status, reply = self._post(
            port,
            f"/{op}",
            json.dumps(request).encode(),
            {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        )
        assert status == 200, reply
        _validate(_op_schema(op, "response"), reply)
        return reply

    def test_configured_host_is_exact(self, server: tuple[int, Path]) -> None:
        port, _ = server
        for host, expected in ((f"relumea-rebrew:{port}", 200), (f"attacker:{port}", 403)):
            status, _ = self._post(
                port,
                "/rebrew.disassemble_bytes",
                b'{"code":"ww==","va":4096,"arch":"x86_64"}',
                {"Host": host, "Authorization": f"Bearer {TOKEN}"},
            )
            assert status == expected

    def test_analyse_then_function_ops(self, server: tuple[int, Path]) -> None:
        port, workspace = server
        project = _check_analysed(
            self._op(port, "rebrew.analyse", _analyse_request()), workspace.resolve()
        )
        assert self._op(port, "rebrew.fingerprint", _binary_file())["sha256"] == SHA256
        reply = self._op(
            port, "rebrew.describe", {"project_dir": str(project), "sha256": SHA256, "va": ENTRY_VA}
        )
        assert reply["name"] == "fcn_00401000"

    @pytest.mark.parametrize(
        ("path", "headers", "status", "code"),
        [
            ("/rebrew.fingerprint", {}, 401, "unauthorized"),
            ("/rebrew.fingerprint", {"Authorization": "Bearer wrong"}, 401, "unauthorized"),
            ("/rebrew.nope", {"Authorization": f"Bearer {TOKEN}"}, 404, "unknown-op"),
            (
                "/rebrew.fingerprint",
                {"Authorization": f"Bearer {TOKEN}", "Content-Length": str(64 << 20)},
                413,
                "invalid-request",
            ),
        ],
    )
    def test_refusals(
        self, server: tuple[int, Path], path: str, headers: dict[str, str], status: int, code: str
    ) -> None:
        port, _workspace = server
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            connection.putrequest("POST", path)
            sent = {"Content-Length": "2", "Content-Type": "application/json", **headers}
            for name, value in sent.items():
                connection.putheader(name, value)
            connection.endheaders(b"{}" if sent["Content-Length"] == "2" else b"")
            response = connection.getresponse()
            reply = json.loads(response.read())
        finally:
            connection.close()
        assert (response.status, reply["error"], reply["status"]) == (status, code, status)

    def test_get_is_refused(self, slot_free_server: tuple[int, Path]) -> None:
        port, _workspace = slot_free_server
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            connection.request("GET", "/rebrew.fingerprint")
            response = connection.getresponse()
            assert (response.status, json.loads(response.read())["error"]) == (
                405,
                "method-not-allowed",
            )
            assert response.getheader("Allow") == "POST"
        finally:
            connection.close()

    def test_unknown_method_is_refused_like_get(self, slot_free_server: tuple[int, Path]) -> None:
        """A method with no do_* handler (TRACE/FOO) is 405/404, not 501."""
        port, _workspace = slot_free_server
        for method, path, status, allow in (
            ("TRACE", "/rebrew.fingerprint", 405, "POST"),
            ("FOO", "/rebrew.fingerprint", 405, "POST"),
            ("TRACE", "/nope", 404, None),
        ):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
            try:
                connection.request(method, path)
                response = connection.getresponse()
                response.read()
                assert (response.status, response.getheader("Allow")) == (status, allow), (
                    method,
                    path,
                )
            finally:
                connection.close()

    def test_post_to_health_and_metrics_is_refused(
        self, slot_free_server: tuple[int, Path]
    ) -> None:
        port, _workspace = slot_free_server
        auth = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
        for path in ("/health", "/metrics"):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
            try:
                connection.request("POST", path, body=b"{}", headers=auth)
                response = connection.getresponse()
                body = json.loads(response.read())
                assert (response.status, body["error"], response.getheader("Allow")) == (
                    405,
                    "method-not-allowed",
                    "GET, HEAD",
                )
            finally:
                connection.close()

    def test_health_and_metrics(self, slot_free_server: tuple[int, Path]) -> None:
        port, _workspace = slot_free_server
        auth = {"Authorization": f"Bearer {TOKEN}"}
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            conn.request("GET", "/health", headers=auth)
            resp = conn.getresponse()
            body = resp.read()
            assert resp.status == 200
            payload = json.loads(body)
            assert payload["status"] == "up"
            assert payload["requests"] >= 0
            assert "latency_ms_avg" in payload
            assert "uptime_seconds" in payload
        finally:
            conn.close()

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            conn.request("GET", "/metrics", headers=auth)
            resp = conn.getresponse()
            text = resp.read().decode()
            assert resp.status == 200
            assert resp.getheader("Content-Type") == "text/plain; version=0.0.4; charset=utf-8"
            assert "rebrew_ops_requests_total" in text
            assert "rebrew_ops_errors_total" in text
            assert "rebrew_ops_latency_ms_total" in text
            # One Prometheus histogram family: its TYPE names the family, the buckets are cumulative, and exactly
            # one bucket is +Inf, equal to _count.
            assert "# TYPE rebrew_ops_latency histogram" in text
            buckets = [
                line.split(" ")
                for line in text.splitlines()
                if line.startswith("rebrew_ops_latency_bucket{")
            ]
            bounds = [
                name.removeprefix('rebrew_ops_latency_bucket{le="').removesuffix('"}')
                for name, _ in buckets
            ]
            counts = [int(value) for _, value in buckets]
            assert bounds.count("+Inf") == 1 and bounds[-1] == "+Inf" and "inf" not in bounds
            assert counts == sorted(counts)
            count_line = next(
                line for line in text.splitlines() if line.startswith("rebrew_ops_latency_count ")
            )
            assert counts[-1] == int(count_line.split(" ")[1])
        finally:
            conn.close()

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            conn.request("GET", "/health")
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 401
        finally:
            conn.close()

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            conn.request("GET", "/metrics")
            resp = conn.getresponse()
            resp.read()
            assert resp.status == 401
        finally:
            conn.close()

        # HEAD must carry headers only, never a body (RFC 9110 §9.3.2).
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            conn.request("HEAD", "/health", headers=auth)
            resp = conn.getresponse()
            assert resp.status == 200
            assert resp.getheader("Content-Length") is not None
            assert resp.read() == b""
        finally:
            conn.close()

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            conn.request("HEAD", "/metrics", headers=auth)
            resp = conn.getresponse()
            assert resp.status == 200
            assert resp.getheader("Content-Length") is not None
            assert resp.read() == b""
        finally:
            conn.close()

    def test_serve_requires_a_token(self) -> None:
        done = subprocess.run(
            _rebrew("ops", "serve", "--port", "0"),
            env={k: v for k, v in os.environ.items() if k != "REBREW_OPS_TOKEN"},
            capture_output=True,
            text=True,
            timeout=WAIT_SECONDS,
            check=False,
        )
        assert done.returncode == 2
        assert "REBREW_OPS_TOKEN is not set" in done.stderr

    def test_serve_requires_a_workspace(self) -> None:
        done = subprocess.run(
            _rebrew("ops", "serve", "--port", "0"),
            env={
                **{k: v for k, v in os.environ.items() if k != "REBREW_OPS_WORKSPACE"},
                "REBREW_OPS_TOKEN": TOKEN,
            },
            capture_output=True,
            text=True,
            timeout=WAIT_SECONDS,
            check=False,
        )
        assert done.returncode == 2
        assert "serve needs --workspace" in done.stderr

    def test_project_outside_the_workspace_is_refused(self, server: tuple[int, Path]) -> None:
        port, _workspace = server
        status, reply = self._post(
            port,
            "/rebrew.import-project",
            json.dumps({"project_dir": str(FIXTURES)}).encode(),
            {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
        )
        assert (status, reply["detail"]) == (400, "project_dir must be inside the worker workspace")

    def _hold_the_only_slot(self, port: int) -> socket.socket:
        """A connection whose call holds the worker's only slot while it waits for a body that never comes.

        The worker refuses at once a call that finds the slot taken, even by a request in flight for a
        millisecond, so the stalled call can itself be refused (503 on its own socket). It is sent again
        until a probe finds the slot held and the stalled call was not the one refused.

        Each attempt starts from a free slot. A call whose socket was just closed holds the slot
        until the worker reads the close, and a probe answered 503 for that call would pass off
        a stalled call that was itself refused as the holder.
        """
        deadline = time.monotonic() + WAIT_SECONDS
        while time.monotonic() < deadline:
            self._wait_for_a_free_slot(port, deadline)
            stalled = socket.create_connection(("127.0.0.1", port), timeout=WAIT_SECONDS)
            stalled.sendall(
                f"POST /rebrew.fingerprint HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n".encode()
                + f"Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n".encode()
            )
            while time.monotonic() < deadline:
                refused, _, _ = select.select([stalled], [], [], 0)
                if refused:  # answered before its body: it lost the slot to another request
                    break
                status, reply = self._post(
                    port,
                    "/rebrew.nope",
                    b"{}",
                    {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
                )
                if status == 503:
                    assert reply["error"] == "worker-busy"
                    return stalled
                time.sleep(0.05)
            stalled.close()
        raise AssertionError("no stalled call ever held the slot")

    def _wait_for_a_free_slot(self, port: int, deadline: float) -> tuple[int, Any]:
        """The dispatcher's answer to a probe once no call holds the worker's only slot."""
        headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
        while True:
            status, reply = self._post(port, "/rebrew.nope", b"{}", headers)
            if status != 503:
                return status, reply
            assert time.monotonic() < deadline, "the slot was not released"
            time.sleep(0.05)

    def test_a_full_worker_answers_503_and_a_refused_stalled_call_is_sent_again(
        self, server: tuple[int, Path]
    ) -> None:
        port, _workspace = server
        headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
        first = self._hold_the_only_slot(port)
        try:
            # A second stalled call finds the slot taken and is refused at once: wait for
            # that refusal on its own socket instead of for a fixed time.
            second = socket.create_connection(("127.0.0.1", port), timeout=WAIT_SECONDS)
            try:
                second.sendall(
                    f"POST /rebrew.fingerprint HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n".encode()
                    + f"Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n".encode()
                )
                refused, _, _ = select.select([second], [], [], WAIT_SECONDS)
                assert refused, "the second stalled call was not refused while the slot was held"
                assert b" 503 " in second.recv(4096).split(b"\r\n", 1)[0]
            finally:
                second.close()
        finally:
            first.close()
        # The refused call is sent again once the slot is free: it must genuinely hold the
        # slot, so a probe is the one refused with 503.
        resent = self._hold_the_only_slot(port)
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
            try:
                connection.request("POST", "/rebrew.nope", body=b"{}", headers=headers)
                response = connection.getresponse()
                reply = json.loads(response.read())
            finally:
                connection.close()
            assert (response.status, reply["error"], response.getheader("Retry-After")) == (
                503,
                "worker-busy",
                "5",
            )
        finally:
            resent.close()
        # Once every stalled socket closes, the slot must be free again: a leaked slot
        # would leave this at 503 instead of the dispatcher's 404.
        status, reply = self._wait_for_a_free_slot(port, time.monotonic() + WAIT_SECONDS)
        assert (status, reply["error"]) == (404, "unknown-op")

    def test_access_line_and_header_share_a_request_id(self, server: tuple[int, Path]) -> None:
        port, _workspace = server
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        try:
            connection.request(
                "POST",
                "/rebrew.nope",
                body=b"{}",
                headers={
                    "Authorization": f"Bearer {TOKEN}",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            response.read()
        finally:
            connection.close()
        assert response.status == 404
        request_id = response.getheader("X-Request-Id")
        assert request_id is not None and request_id.startswith("r")


def test_dispatch_5xx_is_logged_and_4xx_is_not(caplog: Any) -> None:
    cfg = WorkerConfig()
    with caplog.at_level(logging.ERROR, logger="rebrew.ops"):
        status5, _ = dispatch(
            cfg,
            "rebrew.fingerprint",
            json.dumps({"binary_id": 1, "sha256": "0" * 64, "name": "x", "key": "k"}).encode(),
        )
    assert status5 == 500
    assert [record.levelno for record in caplog.records] == [logging.ERROR]
    assert "refused" in caplog.records[0].getMessage()
    caplog.clear()
    with caplog.at_level(logging.ERROR, logger="rebrew.ops"):
        status4, _ = dispatch(cfg, "rebrew.nope", b"{}")
    assert status4 == 404
    assert caplog.records == []


def test_handler_fault_is_logged_with_its_request_id_and_counted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A fault that escapes a handler thread must not vanish into stderr.

    ``socketserver`` reports it through ``handle_error`` with no handler in
    hand, so the record has to carry the stamped request id, and the fault has
    to reach the counter ``/health`` and ``/metrics`` read.  A peer that simply
    went away is not a fault and must not move that counter.
    """
    from rebrew.ops import OpsServer, _stamp_request

    server = OpsServer.__new__(OpsServer)
    server._metrics_lock = threading.Lock()
    server._unhandled_errors = 0

    def raise_fault() -> None:
        _stamp_request("r7")
        try:
            raise RuntimeError("handler exploded")
        except RuntimeError:
            server.handle_error(None, ("127.0.0.1", 9))

    with caplog.at_level(logging.INFO, logger="rebrew.ops"):
        raise_fault()
    assert server._unhandled_errors == 1
    assert logging.ERROR in (entry.levelno for entry in caplog.records)
    blob = "\n".join(caplog.text.splitlines())
    assert "r7" in blob
    assert "RuntimeError" in blob
    assert "handler exploded" in blob

    caplog.clear()
    _stamp_request("r8")
    try:
        raise ConnectionResetError("peer reset")
    except ConnectionResetError:
        with caplog.at_level(logging.DEBUG, logger="rebrew.ops"):
            server.handle_error(None, ("127.0.0.1", 9))
    assert server._unhandled_errors == 1
    assert [entry.levelno for entry in caplog.records] == [logging.INFO]


def test_export_stats_are_zero_without_an_exporter() -> None:
    from rebrew import telemetry

    assert telemetry.export_stats() == {"dropped": 0, "failed": 0}


# ---------------------------------------------------------------------------
# Project archive import
# ---------------------------------------------------------------------------


@pytest.fixture
def analysed_project(
    tmp_path: Path, fresh_analysis: tuple[Path, dict[str, Any]]
) -> tuple[WorkerConfig, Path, Path]:
    """A worker, its filestore, and an analysed project directory to archive.

    A copy of the module's one analysis: each test may change its own.
    """
    config, project = _copy_analysed(fresh_analysis, tmp_path)
    assert config.filestore is not None
    return config, config.filestore, project


def _tar_bytes(
    members: list[tuple[str, bytes | None, str]], *, file_mode: int = 0o644, dir_mode: int = 0o755
) -> bytes:
    """A tar.gz of (name, data, kind) members; kind is file, dir, symlink, hardlink or fifo."""
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size, info.mode = len(data or b""), file_mode
                archive.addfile(info, io.BytesIO(data or b""))
                continue
            info.type = {
                "dir": tarfile.DIRTYPE,
                "symlink": tarfile.SYMTYPE,
                "hardlink": tarfile.LNKTYPE,
                "fifo": tarfile.FIFOTYPE,
            }[kind]
            info.mode = dir_mode
            info.linkname = (data or b"").decode()
            archive.addfile(info)
    return buffer.getvalue()


def _project_members(project: Path, prefix: str = "") -> list[tuple[str, bytes | None, str]]:
    """Every regular file of *project* as tar members, skipping rebrew's lock and cache files."""
    members: list[tuple[str, bytes | None, str]] = []
    for path in sorted(project.rglob("*")):
        relative = path.relative_to(project).as_posix()
        if path.is_file() and not path.name.endswith(".lock") and "/.rebrew/" not in f"/{relative}":
            members.append((prefix + relative, path.read_bytes(), "file"))
    return members


def _import(config: WorkerConfig, filestore: Path, archive: bytes) -> tuple[int, dict[str, Any]]:
    digest, key = _store(filestore, archive)
    request = {
        "binary_id": 1,
        "project_id": "imported",
        "sha256": SHA256,
        "archive_sha256": digest,
        "archive_key": key,
    }
    _validate(_op_schema("rebrew.import_archive", "request"), request)
    status, body = dispatch(config, "rebrew.import_archive", json.dumps(request).encode())
    return status, json.loads(body)


class TestImportArchive:
    def test_imports_the_matching_target_with_its_statuses_and_capture(
        self, analysed_project: tuple[WorkerConfig, Path, Path]
    ) -> None:
        from rebrew.config import load_config, target_module
        from rebrew.metadata.functions import update_field, update_source_status

        config, filestore, project = analysed_project
        module = target_module(load_config(project))
        assert update_source_status(project, "EXACT", module, ENTRY_VA, force=True)
        update_field(project, 0x500000, "NOTE", "a record of another module", "OTHERMOD")
        status, reply = _import(config, filestore, _tar_bytes(_project_members(project, "export/")))
        assert status == 200, reply
        _validate(_op_schema("rebrew.import_archive", "response"), reply)
        installed = Path(reply["project"])
        scope = hashlib.sha256(b"imported").hexdigest()
        assert installed == config.workspace / "projects" / "scopes" / scope / SHA256
        [target] = reply["targets"]
        assert target["sha256"] == SHA256
        assert {row["va"]: row["status"] for row in target["functions"]}[ENTRY_VA] == "EXACT"
        capture = reply["analysis_capture"]
        assert (capture["binary_sha256"], capture["target"]) == (SHA256, target["name"])
        assert sum(entry["kind"] == "binary" for entry in capture["entries"]) == 1
        assert reply["intake"]["module"] == module
        assert reply["intake"]["dropped_records"] == 1
        assert "OTHERMOD." not in (installed / "rebrew-functions.toml").read_text()

    def test_refuses_an_archive_whose_binary_is_not_the_project_binary(
        self, analysed_project: tuple[WorkerConfig, Path, Path]
    ) -> None:
        config, filestore, project = analysed_project
        members = [
            (name, b"MZ not the stored binary" if data == BINARY.read_bytes() else data, kind)
            for name, data, kind in _project_members(project)
        ]
        status, reply = _import(config, filestore, _tar_bytes(members))
        assert (status, reply["error"]) == (422, "project-import-refused"), reply
        assert SHA256 in reply["detail"]

    @pytest.mark.parametrize(
        ("member", "why"),
        [
            (("../escape.txt", b"x", "file"), "../escape.txt"),
            (("/etc/evil", b"x", "file"), "/etc/evil"),
            (("link", b"/etc/passwd", "symlink"), "link"),
            (("hard", b"rebrew-project.toml", "hardlink"), "hard"),
            (("pipe", None, "fifo"), "pipe"),
        ],
    )
    def test_refuses_unsafe_entries_before_writing_them(
        self,
        tmp_path: Path,
        analysed_project: tuple[WorkerConfig, Path, Path],
        member: tuple[str, bytes | None, str],
        why: str,
    ) -> None:
        config, filestore, project = analysed_project
        status, reply = _import(config, filestore, _tar_bytes([*_project_members(project), member]))
        assert (status, reply["error"]) == (422, "project-import-refused"), reply
        assert why in reply["detail"]
        assert not (tmp_path / "escape.txt").exists()
        assert not (
            config.workspace / "projects" / "scopes" / hashlib.sha256(b"imported").hexdigest()
        ).exists()

    def test_refuses_more_entries_than_the_bound(
        self, analysed_project: tuple[WorkerConfig, Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.project_archive

        config, filestore, project = analysed_project
        members = _project_members(project)
        monkeypatch.setattr(rebrew.project_archive, "ARCHIVE_MAX_ENTRIES", len(members) - 1)
        status, reply = _import(config, filestore, _tar_bytes(members))
        assert (status, reply["error"]) == (422, "project-import-refused"), reply
        assert "entries" in reply["detail"]

    @pytest.mark.parametrize(
        ("setting", "named"),
        [
            ('execution_backend = "unshare"', "execution_backend"),
            ('command = "sh -c true"', "command"),
            ('recompile_url = "http://127.0.0.1:9"', "recompile_url"),
        ],
    )
    def test_refuses_settings_that_run_or_reach_something(
        self, analysed_project: tuple[WorkerConfig, Path, Path], setting: str, named: str
    ) -> None:
        config, filestore, project = analysed_project
        members = []
        for name, data, kind in _project_members(project):
            if name == "rebrew-project.toml":
                assert data is not None
                table = f'[targets."{target_name("mini.exe")}".compiler]'
                data += f"\n{table}\n{setting}\n".encode()
            members.append((name, data, kind))
        status, reply = _import(config, filestore, _tar_bytes(members))
        assert (status, reply["error"]) == (422, "project-import-refused"), reply
        assert named in reply["detail"]

    def test_an_unreadable_config_is_invalid_project_config(
        self, analysed_project: tuple[WorkerConfig, Path, Path]
    ) -> None:
        """An archive config rebrew cannot read answers the code every supplied config refusal shares."""
        config, filestore, project = analysed_project
        members = [
            (name, b"[targets\n" if name == "rebrew-project.toml" else data, kind)
            for name, data, kind in _project_members(project)
        ]
        status, reply = _import(config, filestore, _tar_bytes(members))
        assert (status, reply["error"]) == (400, "invalid-project-config"), reply
        assert reply["detail"].startswith("invalid project config: rebrew-project.toml")
        assert str(config.workspace) not in reply["detail"]

    def test_archive_modes_never_reach_the_installed_project(
        self, analysed_project: tuple[WorkerConfig, Path, Path]
    ) -> None:
        """Read-only, setuid and sticky modes in the archive are not kept: directories stay writable."""
        config, filestore, project = analysed_project
        members = _project_members(project)
        directories = sorted({str(Path(name).parent) for name, _data, _kind in members} - {"."})
        archive = _tar_bytes(
            [(name, None, "dir") for name in directories] + members,
            file_mode=0o4444,
            dir_mode=0o1555,
        )
        status, reply = _import(config, filestore, archive)
        assert status == 200, reply
        installed = Path(reply["project"])
        for path in (installed, *installed.rglob("*")):
            mode = stat.S_IMODE(path.lstat().st_mode)
            assert not mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX), path
            assert mode & stat.S_IWUSR or path.is_file(), path
        sources = [path for path in installed.rglob("*.c") if path.is_file()]
        assert sources and all(stat.S_IMODE(path.stat().st_mode) == 0o644 for path in sources)

    def test_a_replaced_project_the_worker_cannot_delete_does_not_fail_the_import(
        self,
        analysed_project: tuple[WorkerConfig, Path, Path],
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A file of the binary's earlier project the worker may not unlink (production: a foreign
        SELinux category on PRINCIPLES.md) is left behind and logged; the import itself succeeds."""
        config, filestore, project = analysed_project
        assert config.workspace is not None
        scope = hashlib.sha256(b"imported").hexdigest()
        shutil.copytree(project, config.workspace / "projects" / "scopes" / scope / SHA256)
        unlink = os.unlink

        def denied(path: Any, *args: Any, **kwargs: Any) -> None:
            if Path(path).name == "PRINCIPLES.md":
                raise PermissionError(13, "Permission denied", str(path))
            unlink(path, *args, **kwargs)

        monkeypatch.setattr(os, "unlink", denied)
        status, reply = _import(config, filestore, _tar_bytes(_project_members(project)))
        monkeypatch.undo()
        assert status == 200, reply
        assert Path(reply["project"]).joinpath("rebrew-project.toml").is_file()
        [left] = (config.workspace / ".scratch").glob("replaced-*")
        assert [path.name for path in left.rglob("PRINCIPLES.md")] == ["PRINCIPLES.md"]
        assert any(str(left) in record.getMessage() for record in caplog.records)

    def test_an_import_parses_the_function_store_once_with_its_formatting(
        self, analysed_project: tuple[WorkerConfig, Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A format-preserving parse is the import's dearest step on a whole-game store: the
        private copy is migrated with one, not a preview and a migration."""
        import rebrew.metadata.files as files

        config, filestore, project = analysed_project
        reads: list[str] = []
        load = files.load_toml_for_write_strict
        load_single = files._load_roundtrip

        def counted(path: Path, description: str) -> Any:
            reads.append(Path(path).name)
            return load(path, description)

        def counted_single(path: Path, description: str, validate: Any) -> Any:
            reads.append(Path(path).name)
            return load_single(path, description, validate)

        # Fragmented stores load each member strictly; a single-file store goes
        # through the lazy round-trip loader.
        monkeypatch.setattr(files, "load_toml_for_write_strict", counted)
        monkeypatch.setattr(files, "_load_roundtrip", counted_single)
        status, reply = _import(config, filestore, _tar_bytes(_project_members(project)))
        assert status == 200, reply
        assert reads.count("rebrew-functions.toml") == 1

    def test_a_source_outside_the_reversed_directory_is_captured_as_a_source(
        self, analysed_project: tuple[WorkerConfig, Path, Path]
    ) -> None:
        """A library row may bind a reference source outside the reversed directory (guild's
        references/zlib/*.c): every source the report names is a captured source, or the backend
        refuses the import (YC job 1589)."""
        config, filestore, project = analysed_project
        moved = "references/lib/fcn_00401000.c"
        members = []
        for name, data, kind in _project_members(project):
            if name == "src/mini/fcn_00401000.c":
                name = moved
            elif name == "rebrew-functions.toml":
                row = b'file = "src/mini/fcn_00401000.c"\nsymbol = "_fcn_00401000"\nname = "fcn_00401000"\nkind = "STUB"'
                assert data is not None and row in data
                library = row.replace(b"src/mini", moved.rsplit("/", 1)[0].encode()).replace(
                    b'"STUB"', b'"LIBRARY"'
                )
                data = data.replace(row, library)
            members.append((name, data, kind))
        status, reply = _import(config, filestore, _tar_bytes(members))
        assert status == 200, reply
        [target] = reply["targets"]
        named = {row["source_path"] for row in target["functions"] if row.get("source_path")}
        assert moved in named
        captured = {
            entry["path"]
            for entry in reply["analysis_capture"]["entries"]
            if entry["kind"] == "file" and entry.get("role") == "source"
        }
        assert named <= captured, sorted(named - captured)
        paths = [entry["path"] for entry in reply["analysis_capture"]["entries"]]
        assert paths == sorted(paths, key=lambda path: path.encode("utf-8"))

    def test_a_zip_archive_imports_like_a_tar(
        self, analysed_project: tuple[WorkerConfig, Path, Path]
    ) -> None:
        import io
        import zipfile

        config, filestore, project = analysed_project
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data, _kind in _project_members(project):
                archive.writestr(name, data or b"")
        status, reply = _import(config, filestore, buffer.getvalue())
        assert status == 200, reply
        assert reply["targets"][0]["sha256"] == SHA256


class TestCallerOpTable:
    """An engine serves its own ops through ``OpsServer(..., ops=..., answer=...)``."""

    @staticmethod
    def _call(port: int, method: str, path: str, body: bytes = b"") -> tuple[int, str, bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=WAIT_SECONDS)
        headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
        connection.request(method, path, body=body or None, headers=headers)
        response = connection.getresponse()
        answer = (response.status, response.getheader("Allow") or "", response.read())
        connection.close()
        return answer

    def test_the_server_routes_meters_and_refuses_by_the_callers_table(self) -> None:
        from rebrew.ops import OpsServer, WorkerConfig

        called: list[str] = []

        def answer(config: WorkerConfig, name: str, body: bytes) -> tuple[int, bytes]:
            called.append(name)
            return 200, json.dumps({"op": name, "body": json.loads(body)}).encode()

        with OpsServer(
            ("127.0.0.1", 0), WorkerConfig(), TOKEN, 1, ops={"engine.echo"}, answer=answer
        ) as server:
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
            )
            thread.start()
            port = server.server_address[1]
            try:
                posted = self._call(port, "POST", "/engine.echo", b'{"x": 1}')
                got = self._call(port, "GET", "/engine.echo")
                rebrew_op = self._call(port, "GET", "/rebrew.verify_function")
                metrics = self._call(port, "GET", "/metrics")[2].decode()
            finally:
                server.shutdown()
                thread.join(timeout=WAIT_SECONDS)
        assert posted[0] == 200 and json.loads(posted[2]) == {"op": "engine.echo", "body": {"x": 1}}
        assert called == ["engine.echo"]
        assert got[:2] == (405, "POST")
        assert rebrew_op[0] == 404
        assert 'rebrew_ops_per_op_requests_total{op="/engine.echo"}' in metrics
        assert 'op="/rebrew.verify_function"' not in metrics

    def test_a_stop_drains_the_call_in_flight_through_the_documented_names(self) -> None:
        """``request_stop`` ends ``serve_forever`` and refuses new calls; ``drain`` waits
        for the call in flight (docs/PYTHON_API.md), so an engine needs no server state."""
        from rebrew.ops import OpsServer, WorkerConfig

        entered = threading.Event()
        release = threading.Event()

        def answer(config: WorkerConfig, name: str, body: bytes) -> tuple[int, bytes]:
            entered.set()
            assert release.wait(WAIT_SECONDS)
            return 200, b'{"done": true}'

        with OpsServer(
            ("127.0.0.1", 0), WorkerConfig(), TOKEN, 2, ops={"engine.slow"}, answer=answer
        ) as server:
            serving = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
            )
            serving.start()
            port = server.server_address[1]
            replies: list[tuple[int, str, bytes]] = []
            caller = threading.Thread(
                target=lambda: replies.append(self._call(port, "POST", "/engine.slow", b"{}"))
            )
            caller.start()
            assert entered.wait(WAIT_SECONDS)
            server.request_stop()
            server.request_stop()  # a second signal changes nothing
            serving.join(WAIT_SECONDS)
            assert not serving.is_alive()
            assert server.drain(0) == 1
            release.set()
            assert server.drain(WAIT_SECONDS) == 0
            caller.join(WAIT_SECONDS)
        assert replies == [(200, "", b'{"done": true}')]


class TestDecompilersOffered:
    """The engine offers only the decompilers that can run here, says so in
    ``rebrew.vocabulary``, and refuses another before any work."""

    @staticmethod
    def _engine(
        monkeypatch: pytest.MonkeyPatch,
        *,
        rizin: bool = False,
        plugins: tuple[str, ...] = (),
        kuna: bool = False,
        ghidra: str | None = None,
        answers: bool = False,
    ) -> None:
        """An engine whose tools are the ones named, and nothing else."""
        import shutil

        from rebrew import decompiler

        monkeypatch.setattr(decompiler, "_states", {})
        monkeypatch.setattr(decompiler, "_find_re_tool", lambda: "rizin" if rizin else None)
        monkeypatch.setattr(decompiler, "_plugin_loaded", lambda _tool, command: command in plugins)
        real_which = shutil.which
        monkeypatch.setattr(
            decompiler.shutil,
            "which",
            lambda name, *a, **k: (
                ("/usr/bin/kuna" if kuna else None) if name == "kuna" else real_which(name, *a, **k)
            ),
        )
        if ghidra is None:
            monkeypatch.delenv("REBREW_GHIDRA_MCP_ENDPOINT", raising=False)
        else:
            monkeypatch.setenv("REBREW_GHIDRA_MCP_ENDPOINT", ghidra)
        monkeypatch.setattr(decompiler, "_ghidra_answers", lambda _endpoint: answers)

    @staticmethod
    def _no_work(monkeypatch: pytest.MonkeyPatch) -> None:
        def worked(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("a decompiler ran")

        monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", worked)
        monkeypatch.setattr("rebrew.struct_recover.fetch_decompilation", worked, raising=False)

    def test_the_production_request_is_refused_before_any_work(
        self, world: tuple[WorkerConfig, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No Ghidra endpoint is configured: nothing opens an MCP session, and the
        refusal is the caller's choice (400), not a transport error (500)."""
        import httpx

        def no_ghidra(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("an MCP session was opened")

        monkeypatch.delenv("REBREW_GHIDRA_MCP_ENDPOINT", raising=False)
        monkeypatch.setattr("rebrew.decompiler._states", {})
        monkeypatch.setattr(httpx.Client, "post", no_ghidra)
        config, project = world
        request = {"project_dir": str(project), "sha256": SHA256, "va": ENTRY_VA}
        body = json.dumps({**request, "backend": "ghidra", "named": False}).encode()
        refusal = _refusal(config, "rebrew.decompile", body)
        assert (refusal["error"], refusal["status"], refusal["detail"]) == (
            "decompiler-not-offered",
            400,
            "decompiler 'ghidra' is not offered here: no Ghidra endpoint is configured",
        )

    @pytest.mark.parametrize(
        ("backend", "engine", "detail"),
        [
            ("kuna", {}, "decompiler 'kuna' is not offered here: kuna is not installed"),
            (
                "r2ghidra",
                {},
                "decompiler 'r2ghidra' is not offered here: neither rizin nor radare2 is installed",
            ),
            (
                "r2dec",
                {"rizin": True, "plugins": ("pdg",)},
                "decompiler 'r2dec' is not offered here: rizin loads no plugin for it",
            ),
            ("auto", {"rizin": True}, "no decompiler 'auto' probes is offered here"),
        ],
    )
    @pytest.mark.parametrize("op", ["rebrew.decompile", "rebrew.structs"])
    def test_a_decompiler_not_installed_is_refused_before_any_work(
        self,
        world: tuple[WorkerConfig, Path],
        monkeypatch: pytest.MonkeyPatch,
        op: str,
        backend: str,
        engine: dict[str, Any],
        detail: str,
    ) -> None:
        self._engine(monkeypatch, **engine)
        self._no_work(monkeypatch)
        config, project = world
        if op == "rebrew.decompile":
            request = {"project_dir": str(project), "sha256": SHA256, "va": ENTRY_VA}
            body = {**request, "backend": backend, "named": False}
        else:
            body = {"binary_id": 1, "project_dir": str(project), "decompiler": backend, "limit": 0}
        refusal = _refusal(config, op, json.dumps(body).encode())
        assert (refusal["error"], refusal["status"], refusal["detail"]) == (
            "decompiler-not-offered",
            400,
            detail,
        )

    def test_an_offered_decompiler_that_yields_nothing_is_the_callers_refusal(
        self, world: tuple[WorkerConfig, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``auto`` offered (kuna is installed) and every backend it tries gives no code:
        a declared 422 ``no-decompilation`` naming the address, not an engine fault."""
        self._engine(monkeypatch, kuna=True)

        def nothing(*_args: Any, **_kwargs: Any) -> tuple[str, str]:
            return "", "auto"

        monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", nothing)
        config, project = world
        request = {"project_dir": str(project), "sha256": SHA256, "va": ENTRY_VA}
        body = {**request, "backend": "auto", "named": False}
        refusal = _refusal(config, "rebrew.decompile", json.dumps(body).encode())
        assert (refusal["error"], refusal["status"], refusal["detail"]) == (
            "no-decompilation",
            422,
            f"decompiler 'auto' produced no code for 0x{ENTRY_VA:x}",
        )

    def test_a_configured_ghidra_that_does_not_answer_is_an_outage(
        self, world: tuple[WorkerConfig, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._engine(monkeypatch, ghidra="http://ghidra.internal:8080/mcp/message")
        self._no_work(monkeypatch)
        config, project = world
        request = {"project_dir": str(project), "sha256": SHA256, "va": ENTRY_VA}
        status, raw = dispatch(
            config,
            "rebrew.decompile",
            json.dumps({**request, "backend": "ghidra", "named": False}).encode(),
        )
        refusal = json.loads(raw)
        assert (status, refusal["error"], refusal["detail"]) == (
            503,
            "decompiler-unreachable",
            "decompiler 'ghidra' is unavailable: the configured Ghidra endpoint did not answer",
        )

    def test_a_ghidra_that_stops_answering_mid_call_is_an_outage_without_its_text(
        self, world: tuple[WorkerConfig, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.ghidra import McpError

        self._engine(monkeypatch, ghidra="http://ghidra.internal:8080/mcp/message", answers=True)

        def refused(*_args: Any, **_kwargs: Any) -> Any:
            raise McpError(
                "Failed to initialize MCP session: [Errno 111] Connection refused", kind="network"
            )

        monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", refused)
        config, project = world
        request = {"project_dir": str(project), "sha256": SHA256, "va": ENTRY_VA}
        status, raw = dispatch(
            config,
            "rebrew.decompile",
            json.dumps({**request, "backend": "ghidra", "named": False}).encode(),
        )
        refusal = json.loads(raw)
        assert (status, refusal["error"]) == (503, "decompiler-unreachable")
        assert "Errno" not in refusal["detail"] and "ghidra.internal" not in refusal["detail"]

    def test_an_available_decompiler_runs_and_auto_picks_among_the_available(
        self, world: tuple[WorkerConfig, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Production: rizin without plugins and kuna; only kuna runs."""
        self._engine(monkeypatch, rizin=True, kuna=True)
        asked: list[str] = []

        def decompiled(backend: str, *_args: Any, **_kwargs: Any) -> tuple[str, str]:
            asked.append(backend)
            return "int f(void) { return 0; }", "kuna"

        monkeypatch.setattr("rebrew.decompiler.fetch_decompilation", decompiled)
        config, project = world
        request = {"project_dir": str(project), "sha256": SHA256, "va": ENTRY_VA}
        for backend in ("kuna", "auto"):
            reply = _call(
                config, "rebrew.decompile", {**request, "backend": backend, "named": False}
            )
            assert reply == {"code": "int f(void) { return 0; }", "backend": "kuna"}
        assert asked == ["kuna", "auto"]
        for backend, missing in (("r2ghidra", "no plugin"), ("ghidra", "no Ghidra endpoint")):
            refusal = _refusal(
                config,
                "rebrew.decompile",
                json.dumps({**request, "backend": backend, "named": False}).encode(),
            )
            assert refusal["error"] == "decompiler-not-offered" and missing in refusal["detail"]
        assert asked == ["kuna", "auto"]

    @pytest.mark.parametrize(
        ("engine", "expected"),
        [
            (
                {},
                [
                    {"name": "ghidra", "state": "not-installed", "reason": "no-endpoint"},
                    {"name": "kuna", "state": "not-installed", "reason": "no-kuna"},
                    {"name": "r2dec", "state": "not-installed", "reason": "no-rizin"},
                    {"name": "r2ghidra", "state": "not-installed", "reason": "no-rizin"},
                ],
            ),
            (
                {
                    "rizin": True,
                    "plugins": ("pdg",),
                    "kuna": True,
                    "ghidra": "http://ghidra.internal:8080/mcp/message",
                },
                [
                    {"name": "ghidra", "state": "unreachable", "reason": "endpoint-unreachable"},
                    {"name": "kuna", "state": "available"},
                    {"name": "r2dec", "state": "not-installed", "reason": "no-plugin"},
                    {"name": "r2ghidra", "state": "available"},
                ],
            ),
            (
                # The production image: a static rizin without plugins, kuna, no Ghidra.
                {"rizin": True, "kuna": True},
                [
                    {"name": "ghidra", "state": "not-installed", "reason": "no-endpoint"},
                    {"name": "kuna", "state": "available"},
                    {"name": "r2dec", "state": "not-installed", "reason": "no-plugin"},
                    {"name": "r2ghidra", "state": "not-installed", "reason": "no-plugin"},
                ],
            ),
            (
                {"ghidra": "http://ghidra.internal:8080/mcp/message", "answers": True},
                [
                    {"name": "ghidra", "state": "available"},
                    {"name": "kuna", "state": "not-installed", "reason": "no-kuna"},
                    {"name": "r2dec", "state": "not-installed", "reason": "no-rizin"},
                    {"name": "r2ghidra", "state": "not-installed", "reason": "no-rizin"},
                ],
            ),
        ],
        ids=["bare", "rizin-with-ghidra-plugin", "production", "ghidra"],
    )
    def test_vocabulary_lists_each_decompiler_and_whether_it_runs_here(
        self, monkeypatch: pytest.MonkeyPatch, engine: dict[str, Any], expected: list[Any]
    ) -> None:
        self._engine(monkeypatch, **engine)
        assert _call(WorkerConfig(), "rebrew.vocabulary", {})["decompilers"] == expected

    def test_the_vocabulary_sets_are_the_ones_the_code_names(self) -> None:
        from typing import get_args

        from rebrew import ops
        from rebrew.decompiler import DecompilerReason, DecompilerState

        entry = _CONTRACT["ops"]["rebrew.vocabulary"]["response"]["properties"]["decompilers"]
        fields = entry["items"]["properties"]
        assert set(fields["name"]["enum"]) == ops.DECOMPILER_BACKENDS - {"auto"}
        assert fields["state"]["enum"] == list(get_args(DecompilerState))
        assert fields["reason"]["enum"] == list(get_args(DecompilerReason))


#: Inputs that crashed a parser (sixth review's fuzzing): a ``.sig`` whose library
#: name is not UTF-8, on which python-flirt panics; a PE and an MZ cut short.
MALFORMED = FIXTURES / "malformed"


class TestMalformedInput:
    """A caller's malformed file is answered, never an engine fault or no answer."""

    def test_a_project_signature_python_flirt_panics_on_is_skipped_and_named(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        config, project = world
        sigs = project / "flirt_sigs"
        sigs.mkdir(exist_ok=True)
        bad = sigs / "bad.sig"
        shutil.copyfile(MALFORMED / "flirt-panic.sig", bad)
        try:
            reply = _call(config, "rebrew.identify_library", {"project_dir": str(project)})
        finally:
            bad.unlink()
        assert reply["unreadable_signatures"] == ["bad.sig"]

    def test_an_uploaded_signature_python_flirt_panics_on_is_the_callers_422(
        self, world: tuple[WorkerConfig, Path]
    ) -> None:
        config, project = world
        digest, key = _store(config.filestore, (MALFORMED / "flirt-panic.sig").read_bytes())
        request = {
            "project_dir": str(project),
            "sha256": SHA256,
            "format": "sig",
            "signatures": {"sha256": digest, "file": key},
            "min_size": 0,
        }
        refusal = _refusal(config, "rebrew.reference_flirt", json.dumps(request).encode())
        assert (refusal["error"], refusal["status"], refusal["detail"]) == (
            "malformed-signatures",
            422,
            "the signatures are not a sig file python-flirt reads",
        )

    @pytest.mark.parametrize("name", ["truncated-pe.exe", "truncated-mz.exe"])
    def test_a_truncated_binary_is_the_callers_422(self, tmp_path: Path, name: str) -> None:
        filestore, workspace = _worker_dirs(tmp_path)
        data = (MALFORMED / name).read_bytes()
        digest, key = _store(filestore, data)
        request = {"binary_id": 1, "sha256": digest, "name": name, "file_key": key}
        refusal = _refusal(
            WorkerConfig(filestore.resolve(), workspace.resolve()),
            "rebrew.analyse",
            json.dumps(request).encode(),
        )
        assert (refusal["error"], refusal["status"]) == ("unsupported-binary-format", 422)
        assert refusal["detail"].endswith("it is truncated or malformed")
        assert str(filestore) not in refusal["detail"]

    def test_no_exception_ends_an_http_call_without_a_reply(self) -> None:
        """A native panic is a BaseException; the server answers 500 and keeps serving."""
        from rebrew.ops import OpsServer

        class Panic(BaseException):
            pass

        calls: list[str] = []

        def answer(_config: WorkerConfig, name: str, _body: bytes) -> tuple[int, bytes]:
            calls.append(name)
            if len(calls) == 1:
                raise Panic("invalid string: FromUtf8Error")
            return 200, b"{}"

        with OpsServer(
            ("127.0.0.1", 0), WorkerConfig(), TOKEN, 1, ops={"x.y"}, answer=answer
        ) as server:
            thread = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
            )
            thread.start()
            try:
                port = server.server_address[1]
                first = TestCallerOpTable._call(port, "POST", "/x.y", b"{}")
                second = TestCallerOpTable._call(port, "POST", "/x.y", b"{}")
            finally:
                server.shutdown()
                thread.join(timeout=WAIT_SECONDS)
        assert first[0] == 500
        assert json.loads(first[2]) == {
            "error": "engine-error",
            "detail": "the engine failed while answering this call",
            "status": 500,
        }
        assert second[0] == 200
