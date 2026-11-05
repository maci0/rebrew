"""Coordinated source and metadata edits restore both backends on failure."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
lazy from pathlib import Path

import pytest
import tomlkit

from rebrew.metadata.coordinated import coordinated_inputs, coordinated_transaction
from rebrew.metadata.storage import metadata_store


def _setup(root: Path, backend: str) -> tuple[Path, Path, list]:
    (root / "rebrew-project.toml").write_text(f'[metadata]\nbackend = "{backend}"\n')
    a, out = root / "a.c", root / "merged.c"
    a.write_text("int a(void) { return 1; }\n")
    stores = [metadata_store(root / n) for n in ("rebrew-data.toml", "rebrew-functions.toml")]
    stores[0].write(tomlkit.parse('format = 2\n["A.0x1000"]\nname = "x"\n'), "test")
    stores[1].write(tomlkit.parse('format = 3\n["A.0x2000"]\nname = "a"\n'), "test")
    return a, out, stores


def test_pinned_store_scope_restores_backend_selection_on_error(tmp_path: Path) -> None:
    from rebrew.metadata.storage import pin_metadata_stores

    path = tmp_path / "rebrew-functions.toml"
    selected = metadata_store(path)
    with pytest.raises(RuntimeError, match="injected"), pin_metadata_stores([selected]):
        (tmp_path / "rebrew-project.toml").write_text('[metadata]\nbackend = "sqlite"\n')
        assert metadata_store(path).name == "toml"
        raise RuntimeError("injected")
    assert metadata_store(path).name == "sqlite"


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_failed_publication_preserves_concurrent_replacement(tmp_path: Path, backend: str) -> None:
    a, _, stores = _setup(tmp_path, backend)
    snapshots = [store.snapshot() for store in stores]
    expected = coordinated_inputs(tmp_path, [a])
    with (
        pytest.raises(BaseExceptionGroup, match="rollback failed"),
        coordinated_transaction(tmp_path, [a], expected_inputs=expected) as staged,
    ):
        staged.publish(a, b"published\n")
        a.unlink()
        a.write_bytes(b"concurrent edit\n")
        raise RuntimeError("injected")
    assert a.read_bytes() == b"concurrent edit\n"
    assert [p.read_bytes() for p in tmp_path.glob(".rebrew-stage-*")] == [
        b"int a(void) { return 1; }\n"
    ]
    assert [store.snapshot() for store in stores] == snapshots


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_rollback_quarantines_concurrent_edit_at_removal(
    tmp_path: Path, backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import rebrew.metadata.coordinated as coordinated

    a, _, _ = _setup(tmp_path, backend)
    expected = coordinated_inputs(tmp_path, [a])
    replace = coordinated.os.replace

    def concurrent(src: Path, dst: Path) -> None:
        if src == a and Path(dst).name.startswith(".rebrew-rollback-"):
            a.unlink()
            a.write_bytes(b"concurrent edit\n")
        replace(src, dst)

    monkeypatch.setattr(coordinated.os, "replace", concurrent)
    with (
        pytest.raises(BaseExceptionGroup, match="rollback failed"),
        coordinated_transaction(tmp_path, [a], expected_inputs=expected) as staged,
    ):
        staged.publish(a, b"published\n")
        raise RuntimeError("injected")
    assert a.read_bytes() == b"concurrent edit\n"
    assert [p.read_bytes() for p in tmp_path.glob(".rebrew-stage-*")] == [
        b"int a(void) { return 1; }\n"
    ]


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_rollback_restores_both_stores_and_source(tmp_path: Path, backend: str) -> None:
    a, out, stores = _setup(tmp_path, backend)
    if backend == "toml":
        fragments = tmp_path / "rebrew-functions.d"
        fragments.mkdir()
        (fragments / "part.toml").write_text('# retain evidence\n["B.0x3000"]\nname = "b"\n')
    snapshots = [store.snapshot() for store in stores]
    expected = coordinated_inputs(tmp_path, [a, out])
    with (
        pytest.raises(RuntimeError, match="injected"),
        coordinated_transaction(tmp_path, [a, out], expected_inputs=expected) as staged,
    ):
        assert staged[a].read_text() == "int a(void) { return 1; }\n"
        staged.publish(out, b"int changed;\n")
        for store in stores:
            doc = store.read("test", roundtrip=True)
            doc["note"] = "changed"
            store.write(doc, "test")
        raise RuntimeError("injected")
    assert a.read_text() == "int a(void) { return 1; }\n" and not out.exists()
    assert [store.snapshot() for store in stores] == snapshots
    assert not list(tmp_path.glob(".rebrew-stage-*"))


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_stale_digest_and_commit(tmp_path: Path, backend: str) -> None:
    a, out, stores = _setup(tmp_path, backend)
    expected = coordinated_inputs(tmp_path, [a, out])
    a.write_text("int a(void) { return 2; }\n")
    with (
        pytest.raises(ValueError, match="inputs changed"),
        coordinated_transaction(tmp_path, [a, out], expected_inputs=expected),
    ):
        pytest.fail("stale inputs entered")
    expected = coordinated_inputs(tmp_path, [a, out])
    with coordinated_transaction(tmp_path, [a, out], expected_inputs=expected) as staged:
        staged.publish(out, b"int merged;\n")
        doc = stores[1].read("test", roundtrip=True)
        doc["note"] = "applied"
        stores[1].write(doc, "test")
    assert not a.exists() and out.read_text() == "int merged;\n"
    assert stores[1].read("test")["note"] == "applied"


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_competing_owner_writer_waits_for_transaction(tmp_path: Path, backend: str) -> None:
    a, out, stores = _setup(tmp_path, backend)
    expected = coordinated_inputs(tmp_path, [a, out])
    started, finished = Event(), Event()

    def writer() -> None:
        started.set()
        doc = stores[1].read("test", roundtrip=True)
        doc["note"] = "other"
        stores[1].write(doc, "test")
        finished.set()

    with ThreadPoolExecutor(max_workers=1) as pool:
        with coordinated_transaction(tmp_path, [a, out], expected_inputs=expected) as staged:
            future = pool.submit(writer)
            assert started.wait(2) and not finished.wait(0.2)
            staged.publish(out, b"int merged;\n")
        future.result(timeout=5)
    assert finished.is_set()


def test_failed_second_stage_does_not_delete_unstaged_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import rebrew.metadata.coordinated as coordinated

    a, out, _stores = _setup(tmp_path, "toml")
    b = tmp_path / "b.c"
    b.write_text("int b;\n")
    expected = coordinated_inputs(tmp_path, [a, b, out])
    replace = coordinated.os.replace

    def fail(src: Path, dst: Path) -> None:
        if src == b:
            raise OSError("injected stage failure")
        replace(src, dst)

    monkeypatch.setattr(coordinated.os, "replace", fail)
    with (
        pytest.raises(OSError, match="injected"),
        coordinated_transaction(tmp_path, [a, b, out], expected_inputs=expected),
    ):
        pytest.fail("stage should fail")
    assert a.exists() and b.read_text() == "int b;\n" and not out.exists()


def test_rollback_removes_new_metadata_documents(tmp_path: Path) -> None:
    (tmp_path / "rebrew-project.toml").write_text('[metadata]\nbackend = "toml"\n')
    source = tmp_path / "a.c"
    source.write_text("int x;\n")
    expected = coordinated_inputs(tmp_path, [source])
    store = metadata_store(tmp_path / "rebrew-functions.toml")
    with (
        pytest.raises(RuntimeError, match="injected"),
        coordinated_transaction(tmp_path, [source], expected_inputs=expected),
    ):
        store.write(tomlkit.parse("format = 3\n"), "test")
        raise RuntimeError("injected")
    assert source.read_text() == "int x;\n" and not store.exists()


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_waiting_edit_rechecks_digest_after_competing_writer(tmp_path: Path, backend: str) -> None:
    a, out, stores = _setup(tmp_path, backend)
    expected = coordinated_inputs(tmp_path, [a, out])
    started = Event()

    def editor() -> None:
        started.set()
        with coordinated_transaction(tmp_path, [a, out], expected_inputs=expected):
            pytest.fail("stale review was accepted")

    with ThreadPoolExecutor(max_workers=1) as pool:
        with stores[1].transaction():
            future = pool.submit(editor)
            assert started.wait(2)
            doc = stores[1].read("test", roundtrip=True)
            doc["note"] = "changed during review"
            stores[1].write(doc, "test")
        with pytest.raises(ValueError, match="inputs changed"):
            future.result(timeout=5)
    assert a.exists() and not out.exists()


def test_project_configuration_is_in_digest(tmp_path: Path) -> None:
    a, out, _stores = _setup(tmp_path, "toml")
    expected = coordinated_inputs(tmp_path, [a, out])
    (tmp_path / "rebrew-project.toml").write_text(
        '[metadata]\nbackend = "toml"\n# changed context\n'
    )
    with (
        pytest.raises(ValueError, match="inputs changed"),
        coordinated_transaction(tmp_path, [a, out], expected_inputs=expected),
    ):
        pytest.fail("changed configuration was accepted")
    assert a.exists() and not out.exists()


def test_selective_staging_preserves_read_only_sources(tmp_path: Path) -> None:
    a, out, _ = _setup(tmp_path, "toml")
    other = tmp_path / "other.c"
    other.write_text("int other;\n")
    expected = coordinated_inputs(tmp_path, [a, other, out])
    with coordinated_transaction(
        tmp_path, [a, other, out], stage=[a, out], expected_inputs=expected
    ) as staged:
        assert other.read_text() == "int other;\n"
        staged.publish(out, b"int merged;\n")
    assert not a.exists() and other.read_text() == "int other;\n" and out.exists()


@pytest.mark.parametrize("change", ["dependency", "discovery"])
def test_read_only_dependencies_and_discovery_changes_reject_stale_plan(
    tmp_path: Path, change: str
) -> None:
    a, out, _ = _setup(tmp_path, "toml")
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    header = inputs / "base.h"
    header.write_text("int f(void);\n")
    expected = coordinated_inputs(tmp_path, [a, out], watched=[header], discovery_roots=[inputs])
    if change == "dependency":
        header.write_text("int f(int);\n")
    else:
        (inputs / "new.c").write_text("int added;\n")
    with (
        pytest.raises(ValueError, match="inputs changed"),
        coordinated_transaction(
            tmp_path, [a, out], expected_inputs=expected, watched=[header], discovery_roots=[inputs]
        ),
    ):
        pytest.fail("stale dependency plan was accepted")
    assert a.exists() and not out.exists()


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_owner_writer_waits_until_failed_edit_is_fully_restored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
) -> None:
    import rebrew.metadata.coordinated as coordinated
    from rebrew.metadata.source_provenance import load_source_files, set_source_file

    a, out, stores = _setup(tmp_path, backend)
    expected = coordinated_inputs(tmp_path, [a, out])
    restoring, release, started, finished = Event(), Event(), Event(), Event()
    link = coordinated.os.link

    def pause_restore(src: Path, dst: Path, **kwargs: object) -> None:
        if Path(src).name.startswith(".rebrew-stage-") and Path(dst) == a:
            restoring.set()
            if not release.wait(5):
                raise TimeoutError("restore was not released")
        link(src, dst, **kwargs)

    monkeypatch.setattr(coordinated.os, "link", pause_restore)

    def failed_edit() -> None:
        with coordinated_transaction(tmp_path, [a, out], expected_inputs=expected) as staged:
            staged.publish(out, b"int replacement;\n")
            doc = stores[1].read("test", roundtrip=True)
            doc["note"] = "uncommitted"
            stores[1].write(doc, "test")
            raise RuntimeError("injected")

    def owner_write() -> None:
        started.set()
        set_source_file(tmp_path, "support.c", "A", "concurrent reviewed purpose")
        finished.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        failed = pool.submit(failed_edit)
        assert restoring.wait(5)
        concurrent = pool.submit(owner_write)
        assert started.wait(2) and not finished.wait(0.2)
        release.set()
        with pytest.raises(RuntimeError, match="injected"):
            failed.result(timeout=5)
        concurrent.result(timeout=5)
    assert a.read_text() == "int a(void) { return 1; }\n" and not out.exists()
    assert "note" not in stores[1].read("test")
    assert load_source_files(tmp_path)[0].purpose == "concurrent reviewed purpose"


def test_unknown_backend_refused_before_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    import rebrew.metadata.coordinated as coordinated

    (tmp_path / "rebrew-project.toml").write_text("# test\n")
    source = tmp_path / "a.c"
    source.write_text("int x;\n")
    monkeypatch.setattr(
        coordinated, "metadata_store", lambda path: SimpleNamespace(name="unknown", root=tmp_path)
    )
    with (
        pytest.raises(ValueError, match="one supported metadata backend"),
        coordinated_transaction(tmp_path, [source], expected_inputs={}),
    ):
        pytest.fail("unknown backend was accepted")
    assert source.exists()


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_watched_nested_metadata_rolls_back_with_project_stores(
    tmp_path: Path, backend: str
) -> None:
    a, out, _ = _setup(tmp_path, backend)
    nested = tmp_path / "src"
    nested.mkdir()
    nested_store = metadata_store(nested / "rebrew-libraries.toml")
    nested_store.write(tomlkit.parse('cflags = "/Od"\n'), "test")
    before = nested_store.snapshot()
    expected = coordinated_inputs(tmp_path, [a, out], watched=[nested_store.path])
    with (
        pytest.raises(RuntimeError, match="injected"),
        coordinated_transaction(
            tmp_path, [a, out], watched=[nested_store.path], expected_inputs=expected
        ),
    ):
        nested_store.write(tomlkit.parse('cflags = "/O2"\n'), "test")
        raise RuntimeError("injected")
    assert nested_store.snapshot() == before and a.exists() and not out.exists()


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
@pytest.mark.parametrize("change", ["bytes", "mode"])
def test_editor_change_during_stage_is_restored_and_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str, change: str
) -> None:
    import rebrew.metadata.coordinated as coordinated

    a, out, stores = _setup(tmp_path, backend)
    before = [store.snapshot() for store in stores]
    expected = coordinated_inputs(tmp_path, [a, out])
    original_replace = coordinated.os.replace

    def racing_replace(src: Path, dst: Path) -> None:
        if Path(src) == a and Path(dst).name.startswith(".rebrew-stage-"):
            if change == "bytes":
                a.write_text("/* concurrent edit */\n")
            else:
                a.chmod(0o600)
        original_replace(src, dst)

    monkeypatch.setattr(coordinated.os, "replace", racing_replace)
    with (
        pytest.raises(ValueError, match="changed during staging"),
        coordinated_transaction(tmp_path, [a, out], expected_inputs=expected),
    ):
        pytest.fail("concurrent edit was not rejected")
    if change == "bytes":
        assert a.read_text() == "/* concurrent edit */\n"
    else:
        assert a.stat().st_mode & 0o777 == 0o600
    assert not out.exists() and [store.snapshot() for store in stores] == before


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_exclusive_publication_preserves_concurrent_output(tmp_path: Path, backend: str) -> None:
    a, out, stores = _setup(tmp_path, backend)
    before = [store.snapshot() for store in stores]
    expected = coordinated_inputs(tmp_path, [a, out])
    with (
        pytest.raises(FileExistsError),
        coordinated_transaction(tmp_path, [a, out], expected_inputs=expected) as staged,
    ):
        out.write_text("/* other editor */\n")
        staged.publish(out, b"int our_output;\n")
    assert a.read_text() == "int a(void) { return 1; }\n"
    assert out.read_text() == "/* other editor */\n"
    assert [store.snapshot() for store in stores] == before


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_recreated_source_and_staged_original_are_both_preserved(
    tmp_path: Path, backend: str
) -> None:
    a, out, stores = _setup(tmp_path, backend)
    before = [store.snapshot() for store in stores]
    expected = coordinated_inputs(tmp_path, [a, out])
    with (
        pytest.raises(ExceptionGroup, match="rollback failed") as excinfo,
        coordinated_transaction(tmp_path, [a, out], expected_inputs=expected) as staged,
    ):
        a.write_text("/* recreated by editor */\n")
        staged.publish(out, b"int our_output;\n")
    assert a.read_text() == "/* recreated by editor */\n" and not out.exists()
    backups = list(tmp_path.glob(".rebrew-stage-*"))
    assert len(backups) == 1 and backups[0].read_text() == "int a(void) { return 1; }\n"
    assert str(backups[0]) in str(excinfo.value.exceptions[1])
    assert [store.snapshot() for store in stores] == before


@pytest.mark.parametrize("backend", ["toml", "sqlite"])
def test_open_editor_modification_to_staged_inode_is_restored(tmp_path: Path, backend: str) -> None:
    a, out, stores = _setup(tmp_path, backend)
    before = [store.snapshot() for store in stores]
    expected = coordinated_inputs(tmp_path, [a, out])
    with (
        a.open("r+b") as editor,
        pytest.raises(ValueError, match="staged original changed"),
        coordinated_transaction(tmp_path, [a, out], expected_inputs=expected) as staged,
    ):
        editor.seek(0)
        editor.write(b"/* edited open inode */\n")
        editor.truncate()
        editor.flush()
        staged.publish(out, b"int our_output;\n")
    assert a.read_text() == "/* edited open inode */\n" and not out.exists()
    assert [store.snapshot() for store in stores] == before
