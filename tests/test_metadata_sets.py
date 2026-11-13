"""rebrew.metadata_describe and rebrew.metadata_diff over real TOML and SQLite file sets."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any
lazy from pathlib import Path

import pytest
from test_apply_candidate import (
    DATA,
    FUNCTIONS,
    PROJECT,
    _request,
    _sqlite_entries,
    _stage,
    promote_in_process,
)
from test_ops import _op_schema, _validate

from rebrew.metadata.sqlite import DATABASE_FILENAME
from rebrew.ops import WorkerConfig, dispatch

__all__ = ["promote_in_process"]  # the fixture is used by name

DROP_IN = b'["MINI.0x00401040"]\nfile = "src/third.c"\nsymbol = "_third"\nname = "third"\nkind = "STUB"\nsize = 4\nstatus = "STUB"\n'


def _call(config: WorkerConfig, op: str, request: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    _validate(_op_schema(op, "request"), request)
    status, raw = dispatch(config, op, json.dumps(request).encode())
    reply: dict[str, Any] = json.loads(raw)
    if status == 200:
        _validate(_op_schema(op, "response"), reply)
    return status, reply


def _ref(config: WorkerConfig, path: str, data: bytes) -> dict[str, Any]:
    assert config.filestore is not None
    digest = hashlib.sha256(data).hexdigest()
    (config.filestore / "binaries" / digest).write_bytes(data)
    return {"path": path, "digest": digest, "size": len(data), "key": f"binaries/{digest}"}


def _toml_set(config: WorkerConfig) -> list[dict[str, Any]]:
    return [
        _ref(config, path, data)
        for path, data in (
            ("rebrew-project.toml", PROJECT),
            ("rebrew-functions.toml", FUNCTIONS),
            ("rebrew-functions.d/third.toml", DROP_IN),
            ("rebrew-data.toml", DATA),
            ("src/stub.c", b"int stub;\n"),
        )
    ]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestDescribe:
    def test_a_toml_set_lists_its_store_files_and_logical_documents(self, tmp_path: Path) -> None:
        from rebrew.metadata.files import metadata_digest

        config, _ = _stage(tmp_path)
        status, reply = _call(config, "rebrew.metadata_describe", {"files": _toml_set(config)})
        assert status == 200, reply
        assert reply["files"] == [
            {"path": "rebrew-data.toml", "sha256": _sha(DATA)},
            {"path": "rebrew-functions.d/third.toml", "sha256": _sha(DROP_IN)},
            {"path": "rebrew-functions.toml", "sha256": _sha(FUNCTIONS)},
        ]
        staged = tmp_path / "copy"
        (staged / "rebrew-functions.d").mkdir(parents=True)
        (staged / "rebrew-functions.toml").write_bytes(FUNCTIONS)
        (staged / "rebrew-functions.d/third.toml").write_bytes(DROP_IN)
        assert reply["documents"] == [
            {"path": "rebrew-data.toml", "logical_sha256": _sha(DATA)},
            {
                "path": "rebrew-functions.toml",
                "logical_sha256": metadata_digest(staged / "rebrew-functions.toml"),
            },
        ]

    def test_a_sqlite_set_names_its_store_and_the_same_documents(self, tmp_path: Path) -> None:
        config, _ = _stage(tmp_path)
        entries = _sqlite_entries(tmp_path, config)
        status, reply = _call(config, "rebrew.metadata_describe", {"files": entries})
        assert status == 200, reply
        (store,) = [entry for entry in entries if entry["path"] == DATABASE_FILENAME]
        assert reply == {
            "files": [{"path": DATABASE_FILENAME, "sha256": store["digest"]}],
            "documents": [
                {"path": "rebrew-data.toml", "logical_sha256": _sha(DATA)},
                {"path": "rebrew-functions.toml", "logical_sha256": _sha(FUNCTIONS)},
            ],
        }

    @pytest.mark.parametrize(
        ("change", "detail"),
        [
            ("no-config", "a metadata set requires rebrew-project.toml"),
            (
                "foreign-toml",
                "invalid metadata set: rebrew-functions.toml is not read by this project's"
                " sqlite metadata",
            ),
            (
                "two-backends",
                "invalid metadata set: metadata requires one local backend, toml or sqlite",
            ),
            ("corrupt-store", "invalid metadata set: "),
        ],
    )
    def test_a_set_rebrew_cannot_read_is_refused(
        self, tmp_path: Path, change: str, detail: str
    ) -> None:
        config, toml_entries = _stage(tmp_path)
        entries = _sqlite_entries(tmp_path, config)
        if change == "no-config":
            entries = entries[1:]
        elif change == "foreign-toml":
            entries.append(toml_entries[2])
        elif change == "two-backends":
            project = PROJECT + b'[metadata]\nread_backends = ["sqlite", "toml"]\n'
            entries[0] = _ref(config, "rebrew-project.toml", project)
        else:
            entries[2] = _ref(config, DATABASE_FILENAME, b"not a database")
        status, reply = _call(config, "rebrew.metadata_describe", {"files": entries})
        assert status == 400, reply
        assert reply["detail"].startswith(detail)


class TestDiff:
    @pytest.mark.parametrize("backend", ["toml", "sqlite"])
    def test_an_applied_candidate_changes_only_its_own_function(
        self, tmp_path: Path, promote_in_process: list[list[str]], backend: str
    ) -> None:
        config, entries = _stage(tmp_path)
        if backend == "sqlite":
            entries = _sqlite_entries(tmp_path, config)
        status, raw = dispatch(config, "rebrew.apply_candidate", _request(entries))
        assert status == 200, raw
        applied = json.loads(raw)
        _validate(_op_schema("rebrew.apply_candidate", "response"), applied)
        published = {item["path"]: base64.b64decode(item["data"]) for item in applied["files"]}
        after = [
            _ref(config, entry["path"], published[entry["path"]])
            if entry["path"] in published
            else entry
            for entry in entries
        ]
        status, reply = _call(config, "rebrew.metadata_diff", {"before": entries, "after": after})
        assert status == 200, reply
        registry = "rebrew-functions.toml" if backend == "toml" else DATABASE_FILENAME
        assert reply["after"] == applied["metadata"]
        assert [item["path"] for item in reply["after"]["files"]] == (
            [registry] if backend == "toml" else [DATABASE_FILENAME]
        )
        assert reply["after"]["files"] == [{"path": registry, "sha256": _sha(published[registry])}]
        (change,) = reply["changes"]
        assert {key: change[key] for key in ("document", "store", "key", "module", "va")} == {
            "document": "rebrew-functions.toml",
            "store": "functions",
            "key": ["MINI.0x00401000"],
            "module": "MINI",
            "va": 0x401000,
        }
        assert change["change"] == "changed"
        fields = {item["field"]: (item["before"], item["after"]) for item in change["fields"]}
        assert fields["name"] == ("fcn_00401000", "add")
        assert fields["symbol"] == ("_fcn_00401000", "_add@8")
        assert fields["kind"] == ("STUB", "FUNCTION")
        assert fields["status"] == ("STUB", "EXACT")
        assert "file" not in fields and "size" not in fields
        assert fields["updated_at"][0] is None and isinstance(fields["updated_at"][1], str)

    def test_the_same_documents_in_two_backends_do_not_differ(self, tmp_path: Path) -> None:
        config, toml_entries = _stage(tmp_path)
        sqlite_entries = _sqlite_entries(tmp_path, config)
        toml_entries.append(_ref(config, "rebrew-data.toml", DATA))
        status, reply = _call(
            config, "rebrew.metadata_diff", {"before": toml_entries, "after": sqlite_entries}
        )
        assert status == 200, reply
        assert reply["changes"] == []
        assert reply["before"]["documents"] == reply["after"]["documents"]
        assert reply["before"]["files"] != reply["after"]["files"]

    def test_added_and_removed_records_and_documents_list_every_field(self, tmp_path: Path) -> None:
        config, _ = _stage(tmp_path)
        before = _toml_set(config)
        changed_functions = FUNCTIONS.replace(b'status = "STUB"\n', b"", 1) + (
            b'\n["MINI.0x00401060"]\nfile = "src/new.c"\nsymbol = "_new"\nname = "new"\n'
            b'kind = "STUB"\nsize = 2\nstatus = "STUB"\nupdated_at = 2026-11-13T10:00:00Z\n'
        )
        after = [
            _ref(config, "rebrew-project.toml", PROJECT),
            _ref(config, "rebrew-functions.toml", changed_functions),
        ]
        status, reply = _call(config, "rebrew.metadata_diff", {"before": before, "after": after})
        assert status == 200, reply
        summary = [(c["document"], c["key"], c["change"]) for c in reply["changes"]]
        assert summary == [
            ("rebrew-data.toml", [], "removed"),
            ("rebrew-data.toml", ["MINI.0x00402000"], "removed"),
            ("rebrew-functions.toml", ["MINI.0x00401000"], "changed"),
            ("rebrew-functions.toml", ["MINI.0x00401040"], "removed"),
            ("rebrew-functions.toml", ["MINI.0x00401060"], "added"),
        ]
        changes = {(c["document"], tuple(c["key"])): c for c in reply["changes"]}
        assert changes["rebrew-data.toml", ()]["fields"] == [
            {"field": "format", "before": 2, "after": None}
        ]
        assert changes["rebrew-data.toml", ()]["va"] is None
        assert changes["rebrew-functions.toml", ("MINI.0x00401000",)]["fields"] == [
            {"field": "status", "before": "STUB", "after": None}
        ]
        added = changes["rebrew-functions.toml", ("MINI.0x00401060",)]
        assert {f["field"]: f["after"] for f in added["fields"]}["updated_at"] == (
            "2026-11-13T10:00:00+00:00"
        )
        assert all(f["before"] is None for f in added["fields"])
        assert added["va"] == 0x401060
