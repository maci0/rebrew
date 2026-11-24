"""Live backend selection for cached library overrides."""

import os
from concurrent.futures import ProcessPoolExecutor
lazy from pathlib import Path
lazy from typing import Any

import pytest

import rebrew.metadata.storage as storage
from rebrew.compiler.overrides import resolve_compile_overrides_cached
from rebrew.config import ProjectConfig, load_config
from rebrew.metadata.files import TomlStore
from rebrew.metadata.functions import LIBRARY_METADATA_FILE
from rebrew.metadata.replication import JOURNAL_PATH
from rebrew.metadata.sqlite import reading
from rebrew.metadata.storage import MetadataStore, metadata_store


def _write_sqlite_flags(library: Path, flags: str) -> None:
    store = metadata_store(library, backend="sqlite", root=library.parent)
    store.write({"cflags": flags}, "test")


class TestLibraryOverrideRouting:
    def test_reuses_selection_and_reads_live_routes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = tmp_path / "rebrew-project.toml"
        config_text = (
            '[project]\ndefault_target = "game"\nshared_dir = ""\n'
            '[targets.game]\nbinary = "game.exe"\nreversed_dir = "src"\nmodule = "GAME"\n'
            '[metadata]\nread_backends = ["sqlite", "toml"]\nwrite_backends = ["sqlite", "toml"]\n'
        )
        config.write_text(config_text)
        cfg = load_config(tmp_path)
        source_dir = tmp_path / "src"
        source_dir.mkdir()
        library = tmp_path / LIBRARY_METADATA_FILE
        _write_sqlite_flags(library, "/O1")
        toml = metadata_store(library, backend="toml", root=tmp_path)
        fragment = library.with_suffix(".d") / "flags.toml"
        fragment.parent.mkdir()
        fragment.write_text('cflags = "/O2"\n')
        root_selections: list[Path] = []

        def selected(
            path: Path, *, backend: str | None = None, root: Path | None = None
        ) -> MetadataStore:
            if path == library:
                root_selections.append(path)
            return metadata_store(path, backend=backend, root=root)

        def flags() -> str:
            return resolve_compile_overrides_cached(cfg, source_dir, None, None, "GAME")[1]

        with reading():
            assert flags() == "/O1"
            monkeypatch.setattr(storage, "metadata_store", selected)
            assert flags() == "/O1"
            assert not root_selections

            with storage.pin_metadata_stores([toml]):
                assert flags() == "/O2"
            assert flags() == "/O1"

            _write_sqlite_flags(library, "/O3")
            assert flags() == "/O3"
            with ProcessPoolExecutor(max_workers=1) as writer:
                writer.submit(_write_sqlite_flags, library, "/O4").result()
            assert flags() == "/O4"

            journal = TomlStore(tmp_path / JOURNAL_PATH, tmp_path)
            journal.write_text("# one\n", "test")
            journal.path.chmod(0o644)
            before = storage.named_documents_token(tmp_path, LIBRARY_METADATA_FILE)
            stat = journal.path.stat()
            journal.path.write_text("# two\n")
            os.utime(journal.path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            assert storage.named_documents_token(tmp_path, LIBRARY_METADATA_FILE) != before

            stat = config.stat()
            config.write_text(config_text.replace('["sqlite", "toml"]', '["toml", "sqlite"]', 1))
            os.utime(config, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            assert flags() == "/O2"
            stat = fragment.stat()
            fragment.write_text('cflags = "/Od"\n')
            os.utime(fragment, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            assert flags() == "/Od"

    def test_cached_project_selection_stats_config_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = tmp_path / "rebrew-project.toml"
        config.write_text('[metadata]\nbackend = "sqlite"\n')
        source_dir = tmp_path / "src"
        source_dir.mkdir()
        library = source_dir / LIBRARY_METADATA_FILE
        assert metadata_store(library).name == "sqlite"
        stat = os.stat
        checks = 0

        def counted(path: str | Path, *args: Any, **kwargs: Any) -> os.stat_result:
            nonlocal checks
            if os.fspath(path) == str(config):
                checks += 1
            return stat(path, *args, **kwargs)

        with monkeypatch.context() as cached:
            cached.setattr(os, "stat", counted)
            assert metadata_store(library).name == "sqlite"
            assert checks == 1

        config.write_text('[metadata]\nbackend = "toml"\n')
        assert metadata_store(library).name == "toml"

    def test_pin_at_an_intermediate_directory_changes_the_next_lookup(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text('[metadata]\nbackend = "sqlite"\n')
        directory = tmp_path / "src"
        source_dir = directory / "unit"
        source_dir.mkdir(parents=True)
        _write_sqlite_flags(tmp_path / LIBRARY_METADATA_FILE, "/O1")
        library = directory / LIBRARY_METADATA_FILE
        pinned = metadata_store(library, backend="toml", root=tmp_path)
        pinned.write({"cflags": "/O2"}, "test")
        cfg = ProjectConfig(root=tmp_path, reversed_dir=source_dir)

        with reading():
            assert resolve_compile_overrides_cached(cfg, source_dir, None, None)[1] == "/O1"
            with storage.pin_metadata_stores([pinned]):
                assert resolve_compile_overrides_cached(cfg, source_dir, None, None)[1] == "/O2"
            assert resolve_compile_overrides_cached(cfg, source_dir, None, None)[1] == "/O1"

    def test_new_dropin_is_seen_when_its_directory_mtime_is_restored(self, tmp_path: Path) -> None:
        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path)
        dropins = (tmp_path / LIBRARY_METADATA_FILE).with_suffix(".d")
        dropins.mkdir()
        assert resolve_compile_overrides_cached(cfg, tmp_path, None, None)[1] != "/Od"
        stat = dropins.stat()
        (dropins / "flags.toml").write_text('cflags = "/Od"\n')
        os.utime(dropins, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        assert resolve_compile_overrides_cached(cfg, tmp_path, None, None)[1] == "/Od"

    def test_nested_project_is_seen_through_a_source_directory_symlink(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "rebrew-project.toml").write_text('[metadata]\nbackend = "sqlite"\n')
        project = tmp_path / "nested"
        source_dir = project / "src"
        source_dir.mkdir(parents=True)
        link = tmp_path / "link"
        link.symlink_to(source_dir, target_is_directory=True)
        library = link / LIBRARY_METADATA_FILE
        assert metadata_store(library).name == "sqlite"

        (project / "rebrew-project.toml").write_text('[metadata]\nbackend = "toml"\n')
        assert metadata_store(library).root == project
        assert metadata_store(library).name == "toml"

    def test_nested_sqlite_project_changes_the_next_override_lookup(self, tmp_path: Path) -> None:
        config_text = '[metadata]\nbackend = "sqlite"\n'
        (tmp_path / "rebrew-project.toml").write_text(config_text)
        project = tmp_path / "nested"
        source_dir = project / "src"
        source_dir.mkdir(parents=True)
        cfg = ProjectConfig(root=tmp_path, reversed_dir=source_dir)
        _write_sqlite_flags(tmp_path / LIBRARY_METADATA_FILE, "/O1")

        with reading():
            assert resolve_compile_overrides_cached(cfg, source_dir, None, None)[1] == "/O1"
            (project / "rebrew-project.toml").write_text(config_text)
            _write_sqlite_flags(project / LIBRARY_METADATA_FILE, "/O2")
            assert resolve_compile_overrides_cached(cfg, source_dir, None, None)[1] == "/O2"
