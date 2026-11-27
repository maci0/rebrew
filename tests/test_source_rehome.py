"""Reviewed source evidence survives moves without validating stale evidence."""

from typing import Any
lazy from pathlib import Path

import pytest

from rebrew.metadata.coordinated import coordinated_inputs, coordinated_transaction
from rebrew.metadata.source_provenance import (
    document_assembly,
    function_definition_hashes,
    load_source_files,
    load_source_provenance,
    move_source_provenance,
    plan_source_rehome,
    rename_source_provenance,
    replace_source_metadata,
    set_source_file,
)
from rebrew.metadata.storage import metadata_store


def _fixture(root: Path, backend: str = "toml") -> tuple[Path, Path, str]:
    (root / "rebrew-project.toml").write_text(f'[metadata]\nbackend = "{backend}"\n')
    a, out = root / "a.c", root / "merged.c"
    a.write_text("int f(void) { return 1; }\n")
    for module in ("A", "B"):
        document_assembly(root, a, "f", module, "Reviewed original assembly")
    a.write_text("int f(void) { return 2; }\n")
    document_assembly(root, a, "f", "A", "Reviewed original assembly")
    set_source_file(root, "a.c", "A", "native support")
    return a, out, "int f(void) { /* moved */ return 2; }\n"


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_current_and_stale_evidence_move_under_transaction(tmp_path: Path, backend: str) -> None:
    a, out, merged = _fixture(tmp_path, backend)
    before = {r.module: r.source_hash for r in load_source_provenance(tmp_path)}
    defs, files = plan_source_rehome(tmp_path, {"a.c": a.read_text()}, "merged.c", merged)
    assert {r.file for r in defs} == {"merged.c"} and files[0].file == "merged.c"
    hashes = {r.module: r.source_hash for r in defs}
    assert hashes["A"] == function_definition_hashes(merged)["f"]
    assert hashes["B"] == before["B"] and hashes["B"] != hashes["A"]
    expected = coordinated_inputs(tmp_path, [a, out])
    with coordinated_transaction(tmp_path, [a, out], expected_inputs=expected) as staged:
        staged.publish(out, merged.encode())
        store = metadata_store(tmp_path / "rebrew-functions.toml")
        replace_source_metadata(tmp_path, defs, files, expected_hash=store.digest())
    assert not a.exists() and load_source_provenance(tmp_path) == defs
    assert load_source_files(tmp_path) == files


def test_purpose_collision_is_refused_before_changes(tmp_path: Path) -> None:
    a, out, merged = _fixture(tmp_path)
    b = tmp_path / "b.c"
    b.write_text("int g(void) { return 0; }\n")
    set_source_file(tmp_path, "b.c", "A", "different reason")
    metadata = metadata_store(tmp_path / "rebrew-functions.toml").snapshot()
    with pytest.raises(ValueError, match="conflicting source purposes"):
        plan_source_rehome(
            tmp_path, {"a.c": a.read_text(), "b.c": b.read_text()}, "merged.c", merged
        )
    assert metadata_store(tmp_path / "rebrew-functions.toml").snapshot() == metadata
    assert a.exists() and b.exists() and not out.exists()


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_rehome_failure_rolls_back_source_and_provenance(tmp_path: Path, backend: str) -> None:
    a, out, merged = _fixture(tmp_path, backend)
    defs, files = plan_source_rehome(tmp_path, {"a.c": a.read_text()}, "merged.c", merged)
    metadata = metadata_store(tmp_path / "rebrew-functions.toml").snapshot()
    expected = coordinated_inputs(tmp_path, [a, out])
    with (
        pytest.raises(RuntimeError, match="injected"),
        coordinated_transaction(tmp_path, [a, out], expected_inputs=expected) as staged,
    ):
        staged.publish(out, merged.encode())
        store = metadata_store(tmp_path / "rebrew-functions.toml")
        replace_source_metadata(tmp_path, defs, files, expected_hash=store.digest())
        raise RuntimeError("injected")
    assert a.read_text() == "int f(void) { return 2; }\n" and not out.exists()
    assert metadata_store(tmp_path / "rebrew-functions.toml").snapshot() == metadata


def _documented(root: Path, backend: str) -> None:
    """Evidence and purposes on a.c, evidence on b.c and c.c, nothing on x.c."""
    (root / "rebrew-project.toml").write_text(f'[metadata]\nbackend = "{backend}"\n')
    for name, function in (("a.c", "f"), ("b.c", "g"), ("c.c", "h"), ("x.c", "k")):
        (root / name).write_text(f"int {function}(void) {{ return 1; }}\n")
    for name, function in (("a.c", "f"), ("b.c", "g"), ("c.c", "h")):
        document_assembly(root, root / name, function, "A", "Reviewed original assembly")
    set_source_file(root, "a.c", "A", "native support")


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_several_moves_follow_like_one_move_at_a_time(
    tmp_path: Path, backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One locked write; a refused move in the middle leaves the others applied."""
    from rebrew.metadata import source_provenance

    separate, together = tmp_path / "separate", tmp_path / "together"
    for root in (separate, together):
        root.mkdir()
        _documented(root, backend)
    # a.c moves twice; b.c onto c.c is refused (c.c holds records); x.c has none.
    names = [("a.c", "a2.c"), ("b.c", "c.c"), ("a2.c", "a3.c"), ("x.c", "y.c")]
    for old, new in names:
        try:
            rename_source_provenance(separate, {}, move=(separate / old, separate / new))
        except ValueError:
            continue
    real = source_provenance.metadata_write_lock
    locks: list[str] = []

    def counted(directory: Path, name: str) -> Any:
        locks.append(name)
        return real(directory, name)

    monkeypatch.setattr(source_provenance, "metadata_write_lock", counted)
    move_source_provenance(together, [(together / old, together / new) for old, new in names])
    assert locks == ["rebrew-functions.toml"]
    assert {(r.file, r.symbol) for r in load_source_provenance(together)} == {
        ("a3.c", "f"),
        ("b.c", "g"),
        ("c.c", "h"),
    }
    assert [f.file for f in load_source_files(together)] == ["a3.c"]
    assert load_source_provenance(together) == load_source_provenance(separate)
    assert load_source_files(together) == load_source_files(separate)
    stored = metadata_store(together / "rebrew-functions.toml").snapshot()
    assert stored == metadata_store(separate / "rebrew-functions.toml").snapshot()
