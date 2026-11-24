"""Live backend selection for cached library overrides."""

import os
from concurrent.futures import ProcessPoolExecutor
lazy from pathlib import Path

import pytest

import rebrew.metadata.storage as storage
from rebrew.compiler.overrides import resolve_compile_overrides_cached
from rebrew.config import load_config
from rebrew.metadata.functions import LIBRARY_METADATA_FILE
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

            stat = config.stat()
            config.write_text(config_text.replace('["sqlite", "toml"]', '["toml", "sqlite"]', 1))
            os.utime(config, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            assert flags() == "/O2"
            fragment.write_text('cflags = "/Od"\n')
            assert flags() == "/Od"
