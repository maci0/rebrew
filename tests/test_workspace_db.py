"""Tests for rebrew.workspace.db."""

from __future__ import annotations

import contextlib
import json
import sqlite3
from pathlib import Path

import pytest

from rebrew.workspace.db import (
    SCHEMA_TARGET,
    coverage_db_lock,
    db_version_matches,
    open_sqlite_ro,
    read_db_version,
    sqlite_ro_uri,
)


def make_db(path: Path, rows: list[tuple[str, str, str]]) -> Path:
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE metadata (target TEXT, key TEXT, value TEXT)")
        conn.executemany("INSERT INTO metadata (target, key, value) VALUES (?, ?, ?)", rows)
    return path


def test_sqlite_ro_uri_is_percent_encoded(tmp_path: Path) -> None:
    db = tmp_path / "cov erage?#.db"
    uri = sqlite_ro_uri(db)
    assert uri.endswith("?mode=ro")
    assert "%20" in uri
    assert "%3F" in uri
    assert "%23" in uri
    assert "#" not in uri
    assert "?" not in uri[: -len("?mode=ro")]


def test_sqlite_ro_uri_relative_uses_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert sqlite_ro_uri(Path("db/coverage.db")) == (
        (tmp_path / "db" / "coverage.db").as_uri() + "?mode=ro"
    )


def test_shared_coverage_lock_blocks_exclusive(tmp_path: Path) -> None:
    """A shared holder must reject a non-blocking exclusive lock, then release it.

    A short sleep after the writer thread starts does not prove the writer
    reached ``flock``: on a slow scheduler both a working lock and a no-op
    lock still look unacquired.
    """
    import fcntl

    db = tmp_path / "coverage.db"
    db.write_bytes(b"")
    lock_path = db.with_name(db.name + ".lock")

    def _exclusive_is_blocked() -> None:
        probe = lock_path.open("a", encoding="utf-8")
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            probe.close()

    with coverage_db_lock(db, shared=True):
        assert lock_path.is_file()
        _exclusive_is_blocked()

    with coverage_db_lock(db):
        _exclusive_is_blocked()


def test_sqlite_ro_uri_opens_reserved_name(tmp_path: Path) -> None:
    db = make_db(tmp_path / "cov erage?#.db", [(SCHEMA_TARGET, "db_version", json.dumps(6))])
    assert read_db_version(db) == 6


def test_open_sqlite_ro_rejects_writes(tmp_path: Path) -> None:
    """mode=ro + query_only must both reject DDL/DML."""
    db = make_db(tmp_path / "ro.db", [("t", "k", '"v"')])
    with contextlib.closing(open_sqlite_ro(db)) as conn:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("CREATE TABLE evil (x)")
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO metadata VALUES ('a', 'b', 'c')")


def test_open_sqlite_ro_closes_handle_when_pragma_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed setup PRAGMA must close the connection the caller never gets."""
    closed: list[bool] = []

    class _FailingConn:
        def execute(self, sql: str) -> None:
            raise sqlite3.DatabaseError(f"boom: {sql}")

        def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(sqlite3, "connect", lambda *_a, **_k: _FailingConn())
    with pytest.raises(sqlite3.DatabaseError, match="query_only"):
        open_sqlite_ro(tmp_path / "x.db")
    assert closed == [True]


def test_read_db_version_schema_row(tmp_path: Path) -> None:
    db = make_db(
        tmp_path / "coverage.db",
        [
            ("NP", "db_version", json.dumps(5)),
            (SCHEMA_TARGET, "db_version", json.dumps(6)),
        ],
    )
    assert read_db_version(db) == 6


def test_read_db_version_string_stamp(tmp_path: Path) -> None:
    db = make_db(tmp_path / "coverage.db", [(SCHEMA_TARGET, "db_version", json.dumps("6"))])
    assert read_db_version(db) == "6"


def test_read_db_version_falls_back_to_target_row(tmp_path: Path) -> None:
    db = make_db(tmp_path / "coverage.db", [("NP", "db_version", json.dumps(5))])
    assert read_db_version(db) == 5


def test_read_db_version_missing_file(tmp_path: Path) -> None:
    assert read_db_version(tmp_path / "coverage.db") is None


def test_read_db_version_missing_table(tmp_path: Path) -> None:
    db = tmp_path / "coverage.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE functions (va INTEGER)")
    assert read_db_version(db) is None


def test_read_db_version_missing_row(tmp_path: Path) -> None:
    db = make_db(tmp_path / "coverage.db", [("NP", "status", "EXACT")])
    assert read_db_version(db) is None


def test_read_db_version_non_json_value(tmp_path: Path) -> None:
    db = make_db(tmp_path / "coverage.db", [(SCHEMA_TARGET, "db_version", "v6")])
    assert read_db_version(db) == "v6"


def test_read_db_version_non_int_json_value(tmp_path: Path) -> None:
    db = make_db(tmp_path / "coverage.db", [(SCHEMA_TARGET, "db_version", "6.5")])
    assert read_db_version(db) == "6.5"


def test_read_db_version_integer_column(tmp_path: Path) -> None:
    db = tmp_path / "coverage.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE metadata (target TEXT, key TEXT, value INTEGER)")
        conn.execute(
            "INSERT INTO metadata (target, key, value) VALUES (?, ?, ?)",
            (SCHEMA_TARGET, "db_version", 6),
        )
    assert read_db_version(db) == "6"


def test_read_db_version_opens_read_only(tmp_path: Path) -> None:
    db = make_db(tmp_path / "coverage.db", [(SCHEMA_TARGET, "db_version", json.dumps(6))])
    read_db_version(db)
    assert db.exists()


@pytest.mark.parametrize(
    ("stored", "current", "expected"),
    [
        (None, 6, True),
        (6, 6, True),
        ("6", 6, True),
        (6, "6", True),
        (5, 6, False),
        ("5", 6, False),
    ],
)
def test_db_version_matches(stored: int | str | None, current: int | str, expected: bool) -> None:
    assert db_version_matches(stored, current) is expected
