"""Rebinding checks other rows' claims without tomlkit-parsing every record."""

lazy from pathlib import Path

import pytest

from rebrew.metadata import lazydoc
from rebrew.metadata.binding_history import change_source_binding
from rebrew.metadata.functions import load_metadata, save_metadata

#: Enough rows that the store is segmented lazily under the patched threshold.
_ROWS = 80
_TARGET_VA = 0x1000
_OWNER_VA = 0x1010
_LAZY_MIN_CHARS = 4 * 1024


def _row(index: int) -> dict[str, object]:
    return {
        "file": f"f{index}.c",
        "name": f"fn{index}",
        "symbol": f"_fn{index}",
        "kind": "FUNCTION",
        "status": "RELOC",
        "size": 8,
    }


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(lazydoc, "LAZY_MIN_CHARS", _LAZY_MIN_CHARS)
    rows = {("S", _TARGET_VA + index * 0x10): _row(index) for index in range(_ROWS)}
    save_metadata(tmp_path, rows, expected_hash=None)
    assert (tmp_path / "rebrew-functions.toml").stat().st_size >= _LAZY_MIN_CHARS
    return tmp_path


def _identity(index: int) -> dict[str, str]:
    row = _row(index)
    return {key: str(row[key]) for key in ("file", "name", "symbol", "kind")}


def _count_parsed_records(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    parsed: list[int] = []
    original = lazydoc._Chunk.parsed

    def counting(self: lazydoc._Chunk) -> object:
        if self.doc is None:
            parsed.append(1)
        return original(self)

    monkeypatch.setattr(lazydoc._Chunk, "parsed", counting)
    return parsed


def test_rebind_parses_only_the_rows_it_edits(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _count_parsed_records(monkeypatch)
    report = change_source_binding(
        project,
        "S",
        _TARGET_VA,
        reason="reviewed",
        identity={"file": "new.c", "name": "renamed", "symbol": "_renamed", "kind": "FUNCTION"},
        project_root=project,
    )
    assert report["action"] == "rebind"
    assert len(parsed) == 1
    row = load_metadata(project)[("S", _TARGET_VA)]
    assert (row["file"], row["name"]) == ("new.c", "renamed")


@pytest.mark.parametrize(
    "stolen", [{"name": "fn1"}, {"symbol": "_fn1"}], ids=["same-name", "same-symbol"]
)
def test_rebind_refuses_a_definition_another_row_owns(
    project: Path, monkeypatch: pytest.MonkeyPatch, stolen: dict[str, str]
) -> None:
    identity = {**_identity(1), "name": "other", "symbol": "_other", **stolen}
    parsed = _count_parsed_records(monkeypatch)
    with pytest.raises(ValueError, match=rf"already belongs to S\.0x{_OWNER_VA:x}"):
        change_source_binding(
            project, "S", _TARGET_VA, reason="reviewed", identity=identity, project_root=project
        )
    assert len(parsed) == 1


def test_rebind_may_reuse_the_definition_of_a_retired_row(project: Path) -> None:
    change_source_binding(project, "S", _OWNER_VA, reason="wrong claim", project_root=project)
    change_source_binding(
        project,
        "S",
        _TARGET_VA,
        reason="reviewed",
        identity=_identity(1),
        project_root=project,
    )
    row = load_metadata(project)[("S", _TARGET_VA)]
    assert (row["file"], row["name"]) == ("f1.c", "fn1")
