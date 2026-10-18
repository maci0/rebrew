"""Metadata drop-ins remain live, validated and editable in their owning files."""

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from rebrew.config import ProjectConfig
from rebrew.metadata.data import (
    data_file_index,
    delete_data_entries_batch,
    get_data_entry,
    load_data_metadata,
    patch_data_fields_batch,
    save_data_metadata,
    set_data_field,
)
from rebrew.metadata.files import metadata_digest, metadata_fingerprint, metadata_paths
from rebrew.metadata.functions import (
    delete_entries_batch,
    get_entry,
    load_metadata,
    record_function_identity,
    save_metadata,
    update_field,
    update_source_status,
)
from rebrew.metadata.source_provenance import (
    document_assembly,
    function_definition_hashes,
    load_source_files,
    load_source_provenance,
    rename_source_provenance,
    set_source_file,
)
from rebrew.utils import load_tomllib


def _dropin(root: Path, store: str, name: str = "game.toml") -> Path:
    path = root / f"rebrew-{store}.d" / name
    path.parent.mkdir(exist_ok=True)
    (root / f"rebrew-{store}.toml").rename(path)
    return path


class TestQualifiedDropins:
    @pytest.mark.parametrize("store", ["functions", "data"])
    def test_directory_only_updates_deletes_and_new_rows(self, tmp_path: Path, store: str) -> None:
        if store == "functions":
            save_metadata(tmp_path, {("S", 0x1000): {"file": "a.c", "size": 4}})
            load, get = load_metadata, get_entry
        else:
            save_data_metadata(
                tmp_path, {("S", 0x1000): {"file": "a.c", "size": 4}}, expected_hash=None
            )
            load, get = load_data_metadata, get_data_entry
        shard = _dropin(tmp_path, store)
        main = tmp_path / f"rebrew-{store}.toml"
        assert get(tmp_path, 0x1000, "S")["size"] == 4
        if store == "functions":
            update_field(tmp_path, 0x1000, "NOTE", "reviewed", "S")
            update_source_status(tmp_path, "EXACT", "S", 0x1000, force=True)
            assert get(tmp_path, 0x1000, "S")["status"] == "EXACT"
        else:
            assert data_file_index(tmp_path)["a.c"][0][:2] == ("S", 0x1000)
            set_data_field(tmp_path, 0x1000, "note", "reviewed", "S")
        assert not main.exists()
        assert load_tomllib(shard)["S.0x00001000"]["note"] == "reviewed"
        assert shard.stat().st_mode & 0o777 == 0o444
        before = shard.read_bytes()
        if store == "functions":
            record_function_identity(
                tmp_path, module="S", va=0x2000, file="b.c", name="b", kind="FUNCTION"
            )
            delete = delete_entries_batch
        else:
            set_data_field(tmp_path, 0x2000, "name", "b", "S")
            delete = delete_data_entries_batch
        assert shard.read_bytes() == before
        assert set(load(tmp_path)) == {("S", 0x1000), ("S", 0x2000)}
        assert delete(tmp_path, [("S", 0x1000)]) == 1
        assert load_tomllib(shard) == {"format": 3 if store == "functions" else 2}
        assert set(load(tmp_path)) == {("S", 0x2000)}

    def test_cache_tracks_edits_additions_removals_and_ignores_other_files(
        self, tmp_path: Path
    ) -> None:
        save_metadata(tmp_path, {("S", 1): {"size": 4}})
        first = _dropin(tmp_path, "functions", "20-game.toml")
        assert load_metadata(tmp_path)[("S", 1)]["size"] == 4
        save_metadata(tmp_path, {("S", 1): {"size": 8}})
        assert load_metadata(tmp_path)[("S", 1)]["size"] == 8
        extra = first.with_name("10-runtime.toml")
        extra.write_text('format = 3\n["CRT.0x02"]\nsize = 16\n')
        first.with_name("backup.toml.bak").write_text("invalid")
        nested = first.parent / "nested"
        nested.mkdir()
        (nested / "ignored.toml").write_text("invalid")
        assert set(load_metadata(tmp_path)) == {("S", 1), ("CRT", 2)}
        assert [p.name for p in metadata_paths(tmp_path / "rebrew-functions.toml")] == [
            "10-runtime.toml",
            "20-game.toml",
        ]
        extra.unlink()
        assert set(load_metadata(tmp_path)) == {("S", 1)}
        first.unlink()
        assert load_metadata(tmp_path) == {}

    @pytest.mark.parametrize("alias", ["S.0x00001000", "S.0x1000"])
    def test_duplicate_identity_refuses_reads_and_writes(self, tmp_path: Path, alias: str) -> None:
        save_metadata(tmp_path, {("S", 0x1000): {"size": 4}})
        main = tmp_path / "rebrew-functions.toml"
        before = main.read_bytes()
        directory = main.with_suffix(".d")
        directory.mkdir()
        shard = directory / "duplicate.toml"
        shard.write_text(f'format = 3\n["{alias}"]\nnote = "duplicate"\n')
        for action in (
            lambda: load_metadata(tmp_path),
            lambda: update_field(tmp_path, 0x1000, "NOTE", "changed", "S"),
        ):
            with pytest.raises(ValueError, match="duplicate metadata"):
                action()
        assert main.read_bytes() == before
        assert "changed" not in shard.read_text()

    def test_malformed_fragment_prevents_all_writes(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("S", 1): {"size": 4}})
        shard = _dropin(tmp_path, "functions")
        before = shard.read_bytes()
        shard.with_name("broken.toml").write_text("format = 1\n")
        with pytest.raises(ValueError, match="format = 3"):
            update_field(tmp_path, 1, "NOTE", "changed", "S")
        assert shard.read_bytes() == before
        assert not (tmp_path / "rebrew-functions.toml").exists()

    def test_review_guard_notices_a_fragment_change(self, tmp_path: Path) -> None:
        save_data_metadata(tmp_path, {("S", 1): {"size": 4}}, expected_hash=None)
        shard = _dropin(tmp_path, "data")
        updates = [{"module": "S", "va": 1, "fields": {"name": "g"}}]
        preview = patch_data_fields_batch(tmp_path, updates, dry_run=True)
        assert not (shard.parent / "game.toml.lock").exists()
        set_data_field(tmp_path, 1, "size", 8, "S")
        with pytest.raises(ValueError, match="changed since preview"):
            patch_data_fields_batch(tmp_path, updates, expected_digest=preview["input_digest"])
        assert get_data_entry(tmp_path, 1, "S")["size"] == 8
        assert "name" not in get_data_entry(tmp_path, 1, "S")

    def test_writers_share_one_lock_across_fragments(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("S", 1): {"size": 4}})
        one = _dropin(tmp_path, "functions", "one.toml")
        save_metadata(tmp_path / "other", {("S", 2): {"size": 8}})
        (tmp_path / "other/rebrew-functions.toml").rename(one.with_name("two.toml"))
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(update_field, tmp_path, va, "NOTE", str(va), "S") for va in (1, 2)
            ]
            for future in futures:
                future.result()
        assert [load_metadata(tmp_path)[("S", va)]["note"] for va in (1, 2)] == ["1", "2"]
        assert not (tmp_path / "rebrew-functions.toml").exists()

    def test_directory_only_metadata_root_and_doctor(self, tmp_path: Path) -> None:
        from rebrew.doctor import check_metadata_files

        directory = tmp_path / "src"
        directory.mkdir()
        save_metadata(directory, {})
        _dropin(directory, "functions")
        save_data_metadata(directory, {}, expected_hash=None)
        _dropin(directory, "data")
        cfg = ProjectConfig(root=tmp_path, reversed_dir=directory)
        assert cfg.metadata_dir == directory
        assert check_metadata_files(cfg).status == "pass"


class TestSourceDropins:
    def test_definition_and_file_purpose_edits_keep_their_fragment(self, tmp_path: Path) -> None:
        file = tmp_path / "a.c"
        file.write_text("int f(void) { return 0; }\n")
        document_assembly(tmp_path, file, "f", "S", "reviewed")
        set_source_file(tmp_path, "helper.c", "S", "support")
        shard = _dropin(tmp_path, "functions")
        document_assembly(tmp_path, file, "f", "S", "rechecked")
        set_source_file(tmp_path, "helper.c", "S", "new purpose")
        assert not (tmp_path / "rebrew-functions.toml").exists()
        assert load_source_provenance(tmp_path)[0].evidence == "rechecked"
        assert load_source_files(tmp_path)[0].purpose == "new purpose"
        document_assembly(tmp_path, file, "f", "T", "other target")
        assert len(load_source_provenance(tmp_path)) == 2
        document_assembly(tmp_path, file, "f", "S", None)
        assert [r.module for r in load_source_provenance(tmp_path)] == ["T"]
        assert load_tomllib(shard)["source"]["definitions"] == {}
        before = file.read_text()
        after = before.replace("return 0", "return 1")
        rename_source_provenance(tmp_path, {file: (before, after)})
        assert (
            load_source_provenance(tmp_path)[0].source_hash
            == function_definition_hashes(after)["f"]
        )

    def test_duplicate_nested_record_is_rejected(self, tmp_path: Path) -> None:
        set_source_file(tmp_path, "helper.c", "S", "support")
        shard = _dropin(tmp_path, "functions")
        (tmp_path / "rebrew-functions.toml").write_bytes(shard.read_bytes())
        with pytest.raises(ValueError, match="duplicate metadata"):
            load_source_files(tmp_path)
        with pytest.raises(ValueError, match="duplicate metadata"):
            set_source_file(tmp_path, "helper.c", "S", "changed")


class TestTypeDropins:
    def test_bind_refreshes_shard_and_combines_targets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type, load_types

        file = tmp_path / "types.h"
        file.write_text("typedef struct ITEM { int value; } ITEM;\n")
        cfg: Any = SimpleNamespace(metadata_dir=tmp_path, module="S", cflags="")
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        monkeypatch.setattr(
            "rebrew.type_metadata._inputs",
            lambda *args: dict.fromkeys(
                ("source_hash", "headers_hash", "context_hash", "binary_hash"), "a" * 64
            ),
        )
        bind_type(cfg, "item", file, "ITEM", 4, 4, "allocation", "reviewed", {})
        shard = _dropin(tmp_path, "types")
        bind_type(cfg, "item", file, "ITEM", 4, 4, "allocation", "rechecked", {})
        assert load_types(tmp_path)[0]["evidence"] == "rechecked"
        assert not (tmp_path / "rebrew-types.toml").exists()
        cfg.module = "T"
        bind_type(cfg, "item", file, "ITEM", 4, 4, "allocation", "other target", {})
        assert {row["module"] for row in load_types(tmp_path)} == {"S", "T"}
        assert load_tomllib(shard)["types"]["item"]["S"]["evidence"] == "rechecked"


class TestLibraryDropins:
    def test_cli_updates_lists_and_removes_directory_only_settings(self, tmp_path: Path) -> None:
        from rebrew.library import app
        from rebrew.metadata.functions import find_library_override, library_override_fingerprint

        runner = CliRunner()
        assert runner.invoke(app, ["set", str(tmp_path), "--cflags=/O1"]).exit_code == 0
        shard = _dropin(tmp_path, "libraries")
        before = library_override_fingerprint(tmp_path, tmp_path)
        override = find_library_override(tmp_path, tmp_path)
        assert override is not None and override.cflags == "/O1"
        result = runner.invoke(app, ["set", str(tmp_path), "--cflags=/O2"])
        assert result.exit_code == 0, result.output
        assert load_tomllib(shard)["cflags"] == "/O2"
        assert library_override_fingerprint(tmp_path, tmp_path) != before
        assert not (tmp_path / "rebrew-libraries.toml").exists()
        assert runner.invoke(app, ["list", str(tmp_path), "--json"]).exit_code == 0
        assert runner.invoke(app, ["remove", str(tmp_path)]).exit_code == 0
        assert not shard.exists()
        assert find_library_override(tmp_path, tmp_path) is None

    def test_new_fragment_invalidates_cached_library_settings(self, tmp_path: Path) -> None:
        from rebrew.compiler.overrides import resolve_compile_overrides_cached

        cfg = ProjectConfig(root=tmp_path, reversed_dir=tmp_path)
        directory = tmp_path / "rebrew-libraries.d"
        directory.mkdir()
        assert resolve_compile_overrides_cached(cfg, tmp_path, "", "", "")[1] != "/Od"
        (directory / "flags.toml").write_text('cflags = "/Od"\n')
        assert resolve_compile_overrides_cached(cfg, tmp_path, "", "", "")[1] == "/Od"


class TestDropinIntegration:
    def test_store_digest_tracks_fragment_names_and_contents(self, tmp_path: Path) -> None:
        save_metadata(tmp_path, {("S", 1): {"size": 4}})
        path = tmp_path / "rebrew-functions.toml"
        original = metadata_digest(path)
        shard = _dropin(tmp_path, "functions")
        sharded = metadata_digest(path)
        assert sharded != original
        shard.rename(shard.with_name("renamed.toml"))
        assert metadata_digest(path) != sharded

    @pytest.mark.parametrize("store", ["functions", "data"])
    def test_bulk_save_preserves_short_key_ownership(self, tmp_path: Path, store: str) -> None:
        directory = tmp_path / f"rebrew-{store}.d"
        directory.mkdir()
        shard = directory / "short.toml"
        version = 3 if store == "functions" else 2
        shard.write_text(f'format = {version}\n["S.0x1"]\nsize = 4\n')
        if store == "functions":
            save_metadata(tmp_path, {("S", 1): {"size": 8}})
        else:
            save_data_metadata(
                tmp_path,
                {("S", 1): {"size": 8}},
                expected_hash=metadata_digest(tmp_path / "rebrew-data.toml"),
            )
        assert load_tomllib(shard)["S.0x1"]["size"] == 8
        assert not (tmp_path / f"rebrew-{store}.toml").exists()

    def test_failed_multi_fragment_edit_restores_exact_bytes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata import files
        from rebrew.metadata.functions import set_fields_batch

        directory = tmp_path / "rebrew-functions.d"
        directory.mkdir()
        one, two = (directory / name for name in ("one.toml", "two.toml"))
        one.write_bytes(
            b'format = 3\r\n# Keep comment and line endings\r\n["S.0x1"]\r\nsize = 4\r\n'
        )
        two.write_text('format = 3\n["S.0x2"]\nsize = 8\n')
        original = {path: path.read_bytes() for path in (one, two)}
        real = files.atomic_write_locked

        def fail_second(path: Path, text: str) -> None:
            if path == two:
                raise OSError("disk full")
            real(path, text)

        monkeypatch.setattr(files, "atomic_write_locked", fail_second)
        with pytest.raises(OSError, match="disk full"):
            set_fields_batch(
                tmp_path,
                [{"module": "S", "va": va, "fields": {"note": "checked"}} for va in (1, 2)],
            )
        assert {path: path.read_bytes() for path in (one, two)} == original
        assert all(path.stat().st_mode & 0o777 == 0o444 for path in (one, two))

    def test_data_layout_and_verification_read_directory_only_store(self, tmp_path: Path) -> None:
        from rebrew.data_layout import data_symbols
        from rebrew.data_verify import verify_data_bytes
        from rebrew.gen_link_stubs import load_data_symbols

        save_data_metadata(
            tmp_path,
            {("S", 0x4000): {"name": "global_value", "size": 4, "section": ".data", "type": "int"}},
            expected_hash=None,
        )
        _dropin(tmp_path, "data")
        path = tmp_path / "rebrew-data.toml"
        assert data_symbols(path) == {"global_value": 0x4000}
        assert load_data_symbols(path) == [(0x4000, "global_value", "int")]
        report = verify_data_bytes(
            metadata_path=path,
            expected={0x4000: b"data"},
            actual={0x4000: b"data"},
            sizes={0x4000: 4},
        )
        assert report["matched"] == 1 and report["compared"] == 1

    def test_fingerprint_stats_each_input_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cache-hit store read stats each file and lists the drop-in directory once.

        The fingerprint runs on every cached metadata read, so discovery must
        not add another stat per fragment just to answer ``is_file``.
        """

        save_metadata(tmp_path, {("S", 1): {"size": 4}})
        directory = tmp_path / "rebrew-functions.d"
        directory.mkdir()
        (directory / "10-a.toml").write_text('format = 3\n["S.0x2"]\nsize = 8\n')
        (directory / "20-b.toml").write_text('format = 3\n["S.0x3"]\nsize = 12\n')

        real_stat = Path.stat
        stat_paths: list[Path] = []

        def counting_stat(self: Path, *args: Any, **kwargs: Any) -> Any:
            stat_paths.append(self)
            return real_stat(self, *args, **kwargs)

        real_scandir = os.scandir
        scandir_args: list[Any] = []

        def counting_scandir(path: Any) -> Any:
            scandir_args.append(path)
            return real_scandir(path)

        monkeypatch.setattr(Path, "stat", counting_stat)
        monkeypatch.setattr(os, "scandir", counting_scandir)
        token = metadata_fingerprint(tmp_path / "rebrew-functions.toml")
        assert [Path(part[0]).name for part in token] == [
            "rebrew-functions.toml",
            "10-a.toml",
            "20-b.toml",
        ]
        assert [path.name for path in stat_paths] == ["rebrew-functions.toml"]
        assert [Path(path).name for path in scandir_args] == ["rebrew-functions.d"]

    def test_edit_parses_and_dumps_only_the_owning_fragment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One edit in a sharded store loads each fragment once and dumps only its file.

        The write path previously parsed every fragment a second time to check
        duplicates and rendered all of them, so a store split into many
        fragments paid the whole collection twice per record edit.
        """
        from rebrew.metadata import files

        save_metadata(tmp_path, {("S", 1): {"size": 4}})
        directory = tmp_path / "rebrew-functions.d"
        directory.mkdir()
        (directory / "10-a.toml").write_text('format = 3\n["S.0x2"]\nsize = 8\n')
        (directory / "20-b.toml").write_text('format = 3\n["S.0x3"]\nsize = 12\n')

        calls = {"loads": 0, "dumps": 0}
        real_load = files.load_toml_for_write_strict
        real_dumps = files.tomlkit.dumps

        def counting_load(*args: Any, **kwargs: Any) -> Any:
            calls["loads"] += 1
            return real_load(*args, **kwargs)

        def counting_dumps(*args: Any, **kwargs: Any) -> Any:
            calls["dumps"] += 1
            return real_dumps(*args, **kwargs)

        monkeypatch.setattr(files, "load_toml_for_write_strict", counting_load)
        monkeypatch.setattr(files.tomlkit, "dumps", counting_dumps)
        update_field(tmp_path, 1, "note", "reviewed", "S")
        assert calls["loads"] == 6
        assert calls["dumps"] == 2
