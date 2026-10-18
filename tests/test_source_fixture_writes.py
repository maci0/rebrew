"""Fixture metadata lands in one store write and keeps an earned STATUS."""

from __future__ import annotations

from pathlib import Path

import pytest
from source_util import write_source

from rebrew.metadata.anchors import parse_address_anchors
from rebrew.metadata.bindings import derive_c_symbol
from rebrew.metadata.functions import atomic_write_locked, load_metadata, update_source_status

_TEXT = "/* ADDRESS: SERVER 0x10003000 */\n\nint extra(void) { return 0; }\n"
_KEY = ("SERVER", 0x10003000)


def _store_writes(paths: list[Path]) -> list[Path]:
    return [path for path in paths if path.name == "rebrew-functions.toml"]


class TestWriteSourceOneEdit:
    def test_identity_size_and_status_share_one_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        writes: list[Path] = []
        real = atomic_write_locked

        def spy(filepath: Path | str, text: str, encoding: str = "utf-8") -> None:
            writes.append(Path(filepath))
            real(filepath, text, encoding=encoding)

        monkeypatch.setattr("rebrew.metadata.functions.atomic_write_locked", spy)
        source = tmp_path / "extra.c"
        write_source(
            source,
            _TEXT,
            metadata_fields={"SERVER.0x10003000": {"kind": "FUNCTION", "size": 16}},
        )
        assert len(_store_writes(writes)) == 1
        entry = load_metadata(tmp_path)[_KEY]
        anchor = parse_address_anchors(_TEXT)[0]
        assert entry["name"] == "extra"
        assert entry["kind"] == "FUNCTION"
        assert entry["size"] == 16
        assert entry["status"] == "STUB"
        assert str(entry["file"]).endswith("extra.c")
        assert entry["symbol"] == derive_c_symbol(entry["name"], anchor.prototype)

        update_source_status(tmp_path, "EXACT", "SERVER", _KEY[1], force=True)
        writes.clear()
        write_source(
            source,
            _TEXT,
            metadata_fields={"SERVER.0x10003000": {"kind": "FUNCTION", "size": 32}},
        )
        assert len(_store_writes(writes)) == 1
        kept = load_metadata(tmp_path)[_KEY]
        assert kept["status"] == "EXACT"
        assert kept["size"] == 32
        assert kept["name"] == "extra"
        assert kept["symbol"] == entry["symbol"]
        assert kept["file"] == entry["file"]


@pytest.mark.parametrize("custom_basetemp", [False, True])
def test_fixture_metadata_cannot_escape_into_an_ancestor_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, custom_basetemp: bool
) -> None:
    import source_util

    ancestor = tmp_path / "real-project"
    ancestor.mkdir()
    (ancestor / "rebrew-project.toml").write_text("[project]\nname = 'parent'\n")
    write_source(
        ancestor / "native.c",
        _TEXT,
        metadata_dir=ancestor,
        metadata_fields={"SERVER.0x10003000": {"kind": "FUNCTION", "size": 16}},
    )
    update_source_status(ancestor, "EXACT", _KEY[0], _KEY[1], force=True)
    store = ancestor / "rebrew-functions.toml"
    before = store.read_bytes()
    basetemp = ancestor / ("custom-temp" if custom_basetemp else "pytest-0")
    fixture = basetemp / "test_sample0"
    fixture.mkdir(parents=True)
    monkeypatch.setattr(source_util, "_pytest_basetemp", basetemp)

    write_source(
        fixture / "extra.c",
        _TEXT,
        metadata_fields={"SERVER.0x10003000": {"kind": "FUNCTION", "size": 32}},
    )

    assert store.read_bytes() == before
    assert load_metadata(fixture)[_KEY]["status"] == "STUB"
    assert load_metadata(fixture)[_KEY]["size"] == 32


@pytest.mark.parametrize("project_name", ["project", "pytest-7"])
def test_project_inside_fixture_boundary_keeps_its_own_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, project_name: str
) -> None:
    import source_util

    basetemp = tmp_path / "custom-temp"
    project = basetemp / "test_sample0" / project_name
    source = project / "src" / "extra.c"
    source.parent.mkdir(parents=True)
    (project / "rebrew-project.toml").write_text("[project]\nname = 'fixture'\n")
    monkeypatch.setattr(source_util, "_pytest_basetemp", basetemp, raising=False)

    write_source(source, _TEXT, metadata_fields={"SERVER.0x10003000": {"size": 16}})

    assert load_metadata(project)[_KEY]["file"] == "src/extra.c"
    assert not (source.parent / "rebrew-functions.toml").exists()
