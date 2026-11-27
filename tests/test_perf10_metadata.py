"""Cold metadata reads keep isolation, and the perf10 metadata benchmarks measure real work."""

import json
from types import SimpleNamespace
from typing import Any, override
lazy from pathlib import Path

import pytest

from rebrew.metadata import bindings
from rebrew.metadata.bindings import iter_source_bindings
from rebrew.metadata.document import parse_metadata_doc
from rebrew.metadata.functions import clear_metadata_cache, load_metadata, save_metadata
from tools import bench_perf10_metadata as bench


def _project(root: Path, backend: str) -> None:
    route = (
        'read_backends = ["sqlite", "toml"]\nwrite_backends = ["sqlite", "toml"]\n'
        if backend == "routed"
        else f'backend = "{backend}"\n'
    )
    (root / "rebrew-project.toml").write_text(
        '[project]\ndefault_target = "game"\nshared_dir = ""\n'
        '[targets.game]\nbinary = "game.exe"\nreversed_dir = "src"\nmodule = "GAME"\n'
        f"[metadata]\n{route}",
        encoding="utf-8",
    )


def _rows() -> dict[tuple[str, int], dict[str, Any]]:
    return {
        ("GAME", 0x1000 + 0x10 * i): {
            "file": "a.c",
            "name": f"f{i}",
            "size": 8,
            "origins": {"size": "binsync"},
            "globals": ["g"],
        }
        for i in range(4)
    }


def _cold(root: Path) -> dict[tuple[str, int], dict[str, Any]]:
    clear_metadata_cache()
    return load_metadata(root, deepcopy=False)


class TestColdLoadIsolation:
    """A cold read hands rows to the cache uncopied; no store may keep a reference to them."""

    @pytest.mark.parametrize("backend", ["toml", "sqlite", "routed"])
    def test_mutating_loaded_rows_never_reaches_the_next_cold_read(
        self, tmp_path: Path, backend: str
    ) -> None:
        _project(tmp_path, backend)
        save_metadata(tmp_path, _rows())
        first = _cold(tmp_path)
        key = ("GAME", 0x1000)
        first[key]["origins"]["size"] = "tampered"
        first[key]["globals"].append("tampered")
        first[key]["size"] = 99
        (tmp_path / ".rebrew" / "metadata-doc" / "rebrew-functions.toml.json").unlink()
        second = _cold(tmp_path)
        assert second[key]["origins"] == {"size": "binsync"}
        assert second[key]["globals"] == ["g"]
        assert second[key]["size"] == 8
        assert second[key] is not first[key]

    def test_dropin_rows_are_isolated_from_the_main_file_read(self, tmp_path: Path) -> None:
        _project(tmp_path, "toml")
        rows = _rows()
        main = {k: v for k, v in rows.items() if k[1] < 0x1020}
        save_metadata(tmp_path, main)
        extra = tmp_path / "rebrew-functions.d"
        extra.mkdir()
        (extra / "part.toml").write_text(
            "format = 3\n"
            '["GAME.0x00001020"]\nfile = "a.c"\nname = "f2"\nsize = 8\nglobals = ["g"]\n'
            '["GAME.0x00001020".origins]\nsize = "binsync"\n'
            '["GAME.0x00001030"]\nfile = "a.c"\nname = "f3"\nsize = 8\nglobals = ["g"]\n'
            '["GAME.0x00001030".origins]\nsize = "binsync"\n',
            encoding="utf-8",
        )
        first = _cold(tmp_path)
        assert len(first) == 4
        for entry in first.values():
            entry["origins"]["size"] = "tampered"
            entry["globals"].clear()
        again = _cold(tmp_path)
        assert all(e["origins"] == {"size": "binsync"} for e in again.values())
        assert all(e["globals"] == ["g"] for e in again.values())

    def test_backend_retaining_its_documents_is_not_reached_by_caller_mutation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.metadata.storage as storage
        from rebrew.metadata.files import TomlStore

        retained: list[Any] = []

        class RetainingStore(TomlStore):
            name = "retaining"

            @override
            def read(self, description: str, **kwargs: Any) -> dict[str, Any]:
                validate = kwargs.get("validate")

                def keep(doc: Any) -> Any:
                    retained.append(doc)
                    return validate(doc) if validate else None

                doc = super().read(description, **{**kwargs, "validate": keep})
                retained.append(doc)
                return doc

        monkeypatch.setattr(storage, "_BACKENDS", None)
        monkeypatch.setattr(
            storage,
            "iter_optional_provider_dicts",
            lambda *args, **kwargs: iter(
                [(SimpleNamespace(origin="test"), {"retaining": RetainingStore})]
            ),
        )
        storage.refresh_metadata_backends()
        _project(tmp_path, "retaining")
        save_metadata(tmp_path, _rows())
        retained.clear()
        rows = _cold(tmp_path)
        assert retained
        before = json.dumps(retained[-1], sort_keys=True, default=str)
        for entry in rows.values():
            entry["origins"]["size"] = "tampered"
            entry["globals"].append("tampered")
        assert json.dumps(retained[-1], sort_keys=True, default=str) == before
        assert "tampered" not in before

    @pytest.mark.parametrize("backend", ["toml", "sqlite", "routed"])
    def test_deepcopy_load_stays_isolated_from_the_cache(
        self, tmp_path: Path, backend: str
    ) -> None:
        _project(tmp_path, backend)
        save_metadata(tmp_path, _rows())
        clear_metadata_cache()
        owned = load_metadata(tmp_path)
        owned[("GAME", 0x1000)]["origins"]["size"] = "tampered"
        assert load_metadata(tmp_path)[("GAME", 0x1000)]["origins"] == {"size": "binsync"}


class TestUnknownFieldFastPath:
    KNOWN = frozenset({"SIZE", "CFLAGS"})

    @pytest.mark.parametrize("field", ["Size", "SIZE", "sizes", "cflagss", ""])
    def test_only_the_lowercase_spelling_of_a_known_field_is_accepted(self, field: str) -> None:
        with pytest.raises(ValueError, match="unknown metadata fields"):
            parse_metadata_doc(
                {"format": 2, "S.0x1000": {"size": 1, field: 2}}, known_fields=self.KNOWN
            )

    def test_spelling_the_original_check_accepts_still_passes(self) -> None:
        # "ſize".upper() is "SIZE" and it is already lowercase: accepted before the fast path.
        doc = {"format": 2, "S.0x1000": {"ſize": 1}}
        assert parse_metadata_doc(doc, known_fields=self.KNOWN) == {("S", 0x1000): {"ſize": 1}}

    def test_known_lowercase_fields_pass(self) -> None:
        doc = {"format": 2, "S.0x1000": {"size": 1, "cflags": "/O2"}}
        assert parse_metadata_doc(doc, known_fields=self.KNOWN) == {
            ("S", 0x1000): {"size": 1, "cflags": "/O2"}
        }


class TestBindingDisplayPath:
    def test_inventory_bindings_use_base_dir_relative_paths_for_both_stores(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path.resolve()
        _project(root, "toml")
        (root / "game").mkdir()
        (root / "other").mkdir()
        src = root / "game" / "u.c"
        src.write_text("/* u */\n", encoding="utf-8")
        save_metadata(root, {("GAME", 0x1000): {"file": "game/u.c", "name": "f", "size": 4}})
        (root / "rebrew-data.toml").write_text(
            'format = 2\n["GAME.0x00002000"]\nfile = "game/u.c"\nname = "g"\nsize = 4\n',
            encoding="utf-8",
        )
        for base, expected in ((root, "game/u.c"), (root / "other", "../game/u.c")):
            clear_metadata_cache()
            ((_, annos),) = iter_source_bindings(
                [src], metadata_dir=root, base_dir=base, inventory_only=True
            )
            assert [a.name for a in annos] == ["f", "g"]
            assert {a.filepath for a in annos} == {expected}


class TestBenchmarkWorkloads:
    def test_load_fixture_spans_main_file_dropins_and_provenance(self, tmp_path: Path) -> None:
        fixture = bench.build_load_fixture(tmp_path)
        assert fixture.expected["rows"] == bench.LOAD_MAIN_ROWS + (
            bench.LOAD_DROPINS * bench.LOAD_DROPIN_ROWS
        )
        assert len(list((tmp_path / "rebrew-functions.d").glob("*.toml"))) == bench.LOAD_DROPINS
        assert "[source.definitions" in (tmp_path / "rebrew-functions.toml").read_text()

    def test_binding_fixture_covers_every_source_with_both_stores(self, tmp_path: Path) -> None:
        fixture, sources = bench.build_binding_fixture(tmp_path)
        assert len(sources) == bench.BIND_SOURCES
        assert fixture.expected["bindings"] == bench.BIND_SOURCES * (
            bench.BIND_ROWS_PER_SOURCE + bench.BIND_DATA_ROWS_PER_SOURCE
        )
        clear_metadata_cache()
        with bindings._METADATA_FILE_INDEX_LOCK:
            bindings._METADATA_FILE_INDEX.clear()
        pairs = iter_source_bindings(
            sources, metadata_dir=tmp_path, base_dir=tmp_path, inventory_only=True
        )
        assert len(pairs) == bench.BIND_SOURCES
        assert sum(len(a) for _, a in pairs) == fixture.expected["bindings"]

    def test_cli_emits_one_document_with_both_workloads(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(bench, "SAMPLES", 2)
        monkeypatch.setattr(bench, "LOAD_MAIN_ROWS", 60)
        monkeypatch.setattr(bench, "LOAD_DROPIN_ROWS", 10)
        monkeypatch.setattr(bench, "LOAD_SOURCE_DEFINITIONS", 5)
        monkeypatch.setattr(bench, "BIND_SOURCES", 12)
        monkeypatch.setattr("sys.argv", ["bench", "--json"])
        assert bench.main() == 0
        report = json.loads(capsys.readouterr().out)
        assert set(report["workloads"]) == {
            "metadata_cold_load_validate",
            "binding_resolution_inventory",
        }
        for row in report["workloads"].values():
            assert len(row["cpu_samples"]) == len(row["wall_samples"]) == 2
            assert row["cache_state"] and row["dimensions"]


class TestColdLoadCopyBudget:
    """Work gates ensuring cold TOML metadata loads clone each record once, never via deepcopy."""

    def test_dropin_cold_load_avoids_deepcopy_and_double_clone(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import copy
        import shutil

        from rebrew.metadata import document
        from rebrew.metadata.functions import clear_metadata_cache, load_metadata

        root = tmp_path.resolve()
        _project(root, "toml")
        (root / "rebrew-functions.toml").write_text(
            'format = 3\n["GAME.0x00401000"]\nfile = "a.c"\nname = "f0"\nsize = 16\n'
            'globals = ["g0"]\n',
            encoding="utf-8",
        )
        dropins = root / "rebrew-functions.d"
        dropins.mkdir()
        (dropins / "part0.toml").write_text(
            'format = 3\n["GAME.0x00401020"]\nfile = "b.c"\nname = "f1"\nsize = 32\n'
            'globals = ["g1"]\n',
            encoding="utf-8",
        )
        clear_metadata_cache()
        shutil.rmtree(root / ".rebrew", ignore_errors=True)

        deepcopies = 0
        doc_clones = 0
        orig_deepcopy = copy.deepcopy
        orig_doc_clone = document.clone_plain

        def count_deepcopy(x: Any, *args: Any, **kwargs: Any) -> Any:
            nonlocal deepcopies
            deepcopies += 1
            return orig_deepcopy(x, *args, **kwargs)

        def count_doc_clone(x: Any) -> Any:
            nonlocal doc_clones
            doc_clones += 1
            return orig_doc_clone(x)

        monkeypatch.setattr(copy, "deepcopy", count_deepcopy)
        monkeypatch.setattr(document, "clone_plain", count_doc_clone)

        rows = load_metadata(root, deepcopy=False)
        assert len(rows) == 2
        assert deepcopies == 0
        assert doc_clones == 0

        # Mutating returned rows must not corrupt _PARSED_MEMBERS.
        rows[("GAME", 0x401000)]["globals"].append("mutated")
        clear_metadata_cache()
        shutil.rmtree(root / ".rebrew", ignore_errors=True)
        fresh = load_metadata(root, deepcopy=False)
        assert fresh[("GAME", 0x401000)]["globals"] == ["g0"]

    def test_single_file_cold_load_clones_once_and_isolates_parsed_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import shutil

        from rebrew.metadata import document, files
        from rebrew.metadata.functions import clear_metadata_cache, load_metadata

        root = tmp_path.resolve()
        _project(root, "toml")
        (root / "rebrew-functions.toml").write_text(
            'format = 3\n["GAME.0x00401000"]\nfile = "a.c"\nname = "f0"\nsize = 16\n'
            'globals = ["g0"]\n',
            encoding="utf-8",
        )
        clear_metadata_cache()
        shutil.rmtree(root / ".rebrew", ignore_errors=True)

        file_clones = 0
        doc_clones = 0
        orig_file_clone = files.clone_plain
        orig_doc_clone = document.clone_plain

        def count_file_clone(x: Any) -> Any:
            nonlocal file_clones
            file_clones += 1
            return orig_file_clone(x)

        def count_doc_clone(x: Any) -> Any:
            nonlocal doc_clones
            doc_clones += 1
            return orig_doc_clone(x)

        monkeypatch.setattr(files, "clone_plain", count_file_clone)
        monkeypatch.setattr(document, "clone_plain", count_doc_clone)

        rows = load_metadata(root, deepcopy=False)
        assert len(rows) == 1
        assert file_clones == 1
        assert doc_clones == 0

        rows[("GAME", 0x401000)]["globals"].append("mutated")
        clear_metadata_cache()
        shutil.rmtree(root / ".rebrew", ignore_errors=True)
        fresh = load_metadata(root, deepcopy=False)
        assert fresh[("GAME", 0x401000)]["globals"] == ["g0"]
