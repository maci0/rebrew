"""Durable, target-scoped type identity and layout evidence."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cli_json import cli_payload

from rebrew.types import parse_structs


def _project(root: Path) -> Any:
    (root / "types.h").write_text("typedef struct ITEM { int value; } ITEM;\n")
    (root / "a.exe").write_bytes(b"native")
    return SimpleNamespace(
        root=root,
        metadata_dir=root,
        module="A",
        target_modules=["A", "B"],
        target_binary=root / "a.exe",
        compiler_profile="test",
        cflags="",
        base_cflags="",
        compiler_includes=None,
        shared_dir=None,
    )


def _move_type(root: Path, digest: str) -> None:
    from rebrew.metadata.coordinated import coordinated_inputs, coordinated_transaction
    from rebrew.type_metadata import rehome_type_bindings

    old, new = root / "types.h", root / "moved.h"
    raw = old.read_bytes()
    inputs = coordinated_inputs(root, [old, new])
    with coordinated_transaction(root, [old, new], expected_inputs=inputs) as stage:
        stage.publish(new, raw)
        rehome_type_bindings(root, "types.h", "moved.h", expected_digest=digest)


class TestTypeMetadata:
    @pytest.mark.parametrize("backend", ["toml", "sqlite"])
    def test_type_rehome_preserves_an_existing_unbound_destination(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
    ) -> None:
        from rebrew.type_metadata import bind_type, load_types, rehome_type_bindings

        cfg = _project(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text(f'[metadata]\nbackend = "{backend}"\n')
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        old, new = tmp_path / "types.h", tmp_path / "moved.h"
        original = old.read_bytes()
        new.write_bytes(b"/* unrelated destination */\n")
        before = load_types(tmp_path)
        preview = rehome_type_bindings(tmp_path, "types.h", "moved.h", dry_run=True)
        with pytest.raises(ValueError, match="selected byte-preserving"):
            _move_type(tmp_path, preview["input_digest"])
        assert old.read_bytes() == original
        assert new.read_bytes() == b"/* unrelated destination */\n"
        assert load_types(tmp_path) == before

    def test_type_rehome_requires_the_selected_staged_byte_preserving_move(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.coordinated import coordinated_inputs, coordinated_transaction
        from rebrew.metadata.storage import metadata_store, pin_metadata_stores
        from rebrew.type_metadata import bind_type, rehome_type_bindings

        cfg = _project(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text('[metadata]\nbackend = "toml"\n')
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        preview = rehome_type_bindings(tmp_path, "types.h", "moved.h", dry_run=True)
        args = (tmp_path, "types.h", "moved.h")
        with (
            pin_metadata_stores([metadata_store(tmp_path / "rebrew-types.toml")]),
            pytest.raises(ValueError, match="active coordinated"),
        ):
            rehome_type_bindings(*args, expected_digest=preview["input_digest"])
        with (
            coordinated_transaction(tmp_path, [], expected_inputs=coordinated_inputs(tmp_path, [])),
            pytest.raises(ValueError, match="selected byte-preserving"),
        ):
            rehome_type_bindings(*args, expected_digest=preview["input_digest"])
        old, new = tmp_path / "types.h", tmp_path / "moved.h"
        with (
            pytest.raises(ValueError, match="selected byte-preserving"),
            coordinated_transaction(
                tmp_path, [old, new], expected_inputs=coordinated_inputs(tmp_path, [old, new])
            ) as stage,
        ):
            stage.publish(new, b"different\n")
            rehome_type_bindings(*args, expected_digest=preview["input_digest"])
        assert old.exists() and not new.exists()

    def test_type_rehome_rejects_destination_binding_collision(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type, load_types, rehome_type_bindings

        cfg = _project(tmp_path)
        (tmp_path / "moved.h").write_bytes((tmp_path / "types.h").read_bytes())
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.one", Path("types.h"), "ITEM", 4, 4, "allocation", "one", {})
        bind_type(cfg, "engine.two", Path("moved.h"), "ITEM", 4, 4, "allocation", "two", {})
        before = load_types(tmp_path)
        with pytest.raises(ValueError, match="already bound"):
            rehome_type_bindings(tmp_path, "types.h", "moved.h", dry_run=True)
        assert load_types(tmp_path) == before

    def test_type_rehome_preserves_fragment_owner(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type, load_types, rehome_type_bindings

        cfg = _project(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text('[metadata]\nbackend = "toml"\n')
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        fragment_dir = tmp_path / "rebrew-types.d"
        fragment_dir.mkdir()
        (tmp_path / "rebrew-types.toml").rename(fragment_dir / "owner.toml")
        preview = rehome_type_bindings(tmp_path, "types.h", "moved.h", dry_run=True)
        _move_type(tmp_path, preview["input_digest"])
        assert not (tmp_path / "rebrew-types.toml").exists()
        assert (fragment_dir / "owner.toml").exists()
        assert load_types(tmp_path)[0]["path_revalidation_required"] is True

    @pytest.mark.parametrize("backend", ["toml", "sqlite"])
    def test_rebind_backend_change_during_owner_write_rolls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
    ) -> None:
        import rebrew.type_metadata as types
        from rebrew.metadata.storage import metadata_store

        cfg = _project(tmp_path)
        config = tmp_path / "rebrew-project.toml"
        config.write_text(f'[metadata]\nbackend = "{backend}"\n')
        monkeypatch.setattr(types, "compile_type", lambda *args: None)
        types.bind_type(
            cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {}
        )
        preview = types.rehome_type_bindings(tmp_path, "types.h", "moved.h", dry_run=True)
        _move_type(tmp_path, preview["input_digest"])
        store = metadata_store(tmp_path / "rebrew-types.toml", backend=backend, root=tmp_path)
        before = store.snapshot()
        inputs = types._inputs
        calls = 0

        def change_backend(*args: Any, **kwargs: Any) -> Any:
            nonlocal calls
            result = inputs(*args, **kwargs)
            calls += 1
            if calls == 2:
                other = "sqlite" if backend == "toml" else "toml"
                config.write_text(f'[metadata]\nbackend = "{other}"\n')
            return result

        monkeypatch.setattr(types, "_inputs", change_backend)
        with pytest.raises(ValueError, match="configuration changed"):
            types.bind_type(
                cfg, "engine.item", Path("moved.h"), "ITEM", 4, 4, "allocation", "native", {}
            )
        assert store.snapshot() == before
        other = "sqlite" if backend == "toml" else "toml"
        assert not metadata_store(
            tmp_path / "rebrew-types.toml", backend=other, root=tmp_path
        ).exists()

    def test_rebind_keeps_invalidation_when_config_changes_during_compile(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type, load_types, rehome_type_bindings

        cfg = _project(tmp_path)
        config = tmp_path / "rebrew-project.toml"
        config.write_text('[metadata]\nbackend = "toml"\n')
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        preview = rehome_type_bindings(tmp_path, "types.h", "moved.h", dry_run=True)
        _move_type(tmp_path, preview["input_digest"])
        before = load_types(tmp_path)

        def change_config(*args: Any) -> None:
            config.write_text('[metadata]\nbackend = "toml"\n# changed flags\n')

        monkeypatch.setattr("rebrew.type_metadata.compile_type", change_config)
        with pytest.raises(ValueError, match="configuration changed"):
            bind_type(cfg, "engine.item", Path("moved.h"), "ITEM", 4, 4, "allocation", "native", {})
        assert load_types(tmp_path) == before
        assert before[0]["path_revalidation_required"] is True

    @pytest.mark.parametrize("backend", ["toml", "sqlite"])
    def test_type_rehome_rolls_back_with_other_owner_failure(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
    ) -> None:
        from rebrew.metadata.coordinated import coordinated_inputs, coordinated_transaction
        from rebrew.metadata.data import set_data_fields_batch
        from rebrew.metadata.functions import record_function_identity
        from rebrew.metadata.storage import metadata_store
        from rebrew.type_metadata import bind_type, rehome_type_bindings

        cfg = _project(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text(f'[metadata]\nbackend = "{backend}"\n')
        old, new = tmp_path / "types.h", tmp_path / "moved.h"
        original = old.read_bytes()
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        record_function_identity(
            tmp_path,
            module="A",
            va=0x1000,
            file="types.h",
            name="f",
            symbol="_f",
            kind="FUNCTION",
            size=4,
        )
        stores = [
            metadata_store(tmp_path / name)
            for name in ("rebrew-functions.toml", "rebrew-data.toml", "rebrew-types.toml")
        ]
        before = [store.snapshot() for store in stores]
        preview = rehome_type_bindings(tmp_path, "types.h", "moved.h", dry_run=True)
        inputs = coordinated_inputs(tmp_path, [old, new])
        with (
            pytest.raises(RuntimeError, match="injected"),
            coordinated_transaction(tmp_path, [old, new], expected_inputs=inputs) as stage,
        ):
            stage.publish(new, original)
            rehome_type_bindings(
                tmp_path, "types.h", "moved.h", expected_digest=preview["input_digest"]
            )
            set_data_fields_batch(
                tmp_path, [{"module": "A", "va": 0x2000, "fields": {"name": "g", "size": 4}}]
            )
            raise RuntimeError("injected")
        assert old.read_bytes() == original and not new.exists()
        assert [store.snapshot() for store in stores] == before

    @pytest.mark.parametrize("backend", ["toml", "sqlite"])
    def test_rehome_keeps_history_and_requires_reviewed_rebind(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
    ) -> None:
        from rebrew.type_metadata import bind_type, check_types, load_types, rehome_type_bindings

        cfg = _project(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text(f'[metadata]\nbackend = "{backend}"\n')
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        original = load_types(tmp_path)[0]
        preview = rehome_type_bindings(tmp_path, "types.h", "moved.h", dry_run=True)
        with pytest.raises(ValueError, match="coordinated"):
            rehome_type_bindings(
                tmp_path, "types.h", "moved.h", expected_digest=preview["input_digest"]
            )
        with pytest.raises(ValueError, match="digest"):
            _move_type(tmp_path, "stale")
        _move_type(tmp_path, preview["input_digest"])
        moved = load_types(tmp_path)[0]
        assert moved["file"] == "moved.h" and moved["path_revalidation_required"] is True
        assert all(
            moved[k] == original[k]
            for k in ("source_hash", "headers_hash", "context_hash", "binary_hash")
        )
        assert moved["path_history"][0]["file"] == "types.h"
        assert moved["path_history"][0]["freshness"] == "unassessed"
        assert moved["path_history"][0]["evidence"] == "native"
        monkeypatch.setattr(
            "rebrew.type_metadata.compile_type", lambda *args: pytest.fail("stale type compiled")
        )
        assert "stale type evidence" in check_types(cfg, compile_layouts=True)[0]["issue"]
        with pytest.raises(ValueError, match="rebind invalidated"):
            rehome_type_bindings(tmp_path, "moved.h", "later.h", dry_run=True)
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("moved.h"), "ITEM", 4, 4, "allocation", "new review", {})
        rebound = load_types(tmp_path)[0]
        assert not rebound.get("path_revalidation_required")
        assert rebound["path_history"] == moved["path_history"]
        assert check_types(cfg) == []

    def test_tag_and_typedef_spelling_both_identify_the_definition(self) -> None:
        from rebrew.type_metadata import struct_definition_names

        assert struct_definition_names("typedef struct ITEM { int x; } Item;") == {"ITEM", "Item"}
        assert struct_definition_names("typedef struct ITEM { int x; } ITEM;") == {"ITEM"}

    @pytest.mark.parametrize("change", ["header", "flags", "binary", "defines"])
    def test_input_changes_stale_evidence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
    ) -> None:
        from rebrew.type_metadata import bind_type, check_types

        cfg = _project(tmp_path)
        (tmp_path / "types.h").write_text(
            '#include "dep.h"\ntypedef struct ITEM { int value; } ITEM;\n'
        )
        (tmp_path / "dep.h").write_text("/* initial */\n")
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        if change == "header":
            (tmp_path / "dep.h").write_text("/* changed */\n")
        elif change == "flags":
            cfg.base_cflags = "/Zp1"
        elif change == "defines":
            cfg.defines = ["GOLD"]
        else:
            (tmp_path / "a.exe").write_bytes(b"different native")
        assert "stale" in check_types(cfg)[0]["issue"]

    def test_target_binary_is_read_once_for_all_records(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type, check_types

        cfg = _project(tmp_path)
        (tmp_path / "types.h").write_text(
            "typedef struct ITEM { int value; } ITEM;\n"
            "typedef struct PAIR { int a; int b; } PAIR;\n"
        )
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        bind_type(cfg, "engine.pair", Path("types.h"), "PAIR", 8, 8, "allocation", "native", {})

        reads = 0
        original = Path.open

        def counting(self: Path, *args: Any, **kwargs: Any) -> Any:
            nonlocal reads
            if self == cfg.target_binary:
                reads += 1
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", counting)
        assert check_types(cfg) == []
        assert reads == 1

    @pytest.mark.parametrize(
        "field,value",
        [
            pytest.param("size", True),
            pytest.param("size", -1),
            pytest.param("native_size", 1),
            pytest.param("extent", []),
            pytest.param("offsets", {"value": 4}),
            pytest.param("symbol", "ITEM; bad()"),
            pytest.param("evidence", ""),
        ],
    )
    def test_invalid_record_never_replaces_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
    ) -> None:
        from rebrew.type_metadata import bind_type

        cfg = _project(tmp_path)
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        args: dict[str, Any] = {
            "size": 4,
            "native_size": 4,
            "extent": "allocation",
            "evidence": "native",
            "offsets": {},
            "symbol": "ITEM",
        }
        bind_type(cfg, "engine.item", Path("types.h"), **args)
        before = (tmp_path / "rebrew-types.toml").read_bytes()
        args[field] = value
        with pytest.raises(ValueError):
            bind_type(cfg, "engine.item", Path("types.h"), **args)
        assert (tmp_path / "rebrew-types.toml").read_bytes() == before

    def test_compile_race_and_symlink_escape(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type

        cfg = _project(tmp_path)

        def changed(*args: Any) -> None:
            (tmp_path / "types.h").write_text(
                "typedef struct ITEM { int value; int other; } ITEM;\n"
            )

        monkeypatch.setattr("rebrew.type_metadata.compile_type", changed)
        with pytest.raises(ValueError, match="changed during"):
            bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        assert not (tmp_path / "rebrew-types.toml").exists()
        (tmp_path / "outside.h").symlink_to(tmp_path.parent / "other.h")
        with pytest.raises(ValueError):
            bind_type(
                cfg, "engine.item", Path("outside.h"), "ITEM", 4, 4, "allocation", "native", {}
            )

    def test_lint_reports_stale_bindings(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.lint import _check_W031_type_metadata
        from rebrew.type_metadata import bind_type

        cfg = _project(tmp_path)
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        assert _check_W031_type_metadata(cfg) == []
        cfg.base_cflags = "/Zp1"
        assert _check_W031_type_metadata(cfg)[0].warnings

    def test_conditional_fields_are_not_a_complete_layout(self) -> None:
        types = parse_structs(
            "typedef struct ITEM { int x;\n#ifdef GOLD\nint y;\n#endif\nint z; } ITEM;"
        )
        assert not types["ITEM"].complete
        assert types["ITEM"].fields == [("x", "int", 0)]

    def test_bind_then_stale_and_rebind_keeps_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type, check_types, load_types

        cfg = _project(tmp_path)
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(
            cfg,
            "engine.item",
            Path("types.h"),
            "ITEM",
            4,
            4,
            "allocation",
            "A:0x401000 allocation",
            {"value": 0},
        )
        assert check_types(cfg) == []
        assert len(load_types(tmp_path)) == 1
        assert (tmp_path / "rebrew-types.toml").stat().st_mode & 0o777 == 0o444
        (tmp_path / "types.h").write_text("typedef struct ITEM { int value; int other; } ITEM;\n")
        assert "stale" in check_types(cfg)[0]["issue"]
        bind_type(
            cfg,
            "engine.item",
            Path("types.h"),
            "ITEM",
            8,
            8,
            "allocation",
            "reviewed new extent",
            {"value": 0},
        )
        assert load_types(tmp_path)[0]["id"] == "engine.item"
        assert check_types(cfg) == []

    def test_compiler_failure_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type

        cfg = _project(tmp_path)

        def fail(*args: Any) -> None:
            raise ValueError("layout compile failed")

        monkeypatch.setattr("rebrew.type_metadata.compile_type", fail)
        with pytest.raises(ValueError, match="layout compile"):
            bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})
        assert not (tmp_path / "rebrew-types.toml").exists()

    def test_target_variants_and_duplicate_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type, check_types, load_types

        cfg = _project(tmp_path)
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "stride", "native stride", {})
        cfg.module = "B"
        cfg.base_cflags = "/DGOLD"
        bind_type(
            cfg, "engine.item", Path("types.h"), "ITEM", 4, 8, "allocation", "partial view", {}
        )
        assert len(load_types(tmp_path)) == 2
        assert check_types(cfg) == []
        with pytest.raises(ValueError, match="already bound"):
            bind_type(cfg, "other", Path("types.h"), "ITEM", 4, 8, "allocation", "native", {})
        with pytest.raises(ValueError, match="already bound"):
            bind_type(
                cfg,
                "other",
                Path("types.h"),
                "ITEM",
                4,
                8,
                "allocation",
                "native",
                {},
                dry_run=True,
            )

    def test_dry_run_no_compile_and_corrupt_store_preserved(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type

        cfg = _project(tmp_path)

        def fail(*args: Any) -> None:
            pytest.fail("dry run compiled")

        monkeypatch.setattr("rebrew.type_metadata.compile_type", fail)
        bind_type(
            cfg,
            "engine.item",
            Path("types.h"),
            "ITEM",
            4,
            4,
            "allocation",
            "native",
            {},
            dry_run=True,
        )
        assert not (tmp_path / "rebrew-types.toml").exists()
        store = tmp_path / "rebrew-types.toml"
        store.write_text("not valid [")
        with pytest.raises(ValueError):
            bind_type(
                cfg,
                "engine.item",
                Path("types.h"),
                "ITEM",
                4,
                4,
                "allocation",
                "native",
                {},
                dry_run=True,
            )
        assert store.read_text() == "not valid ["

    def test_ambiguous_definition_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.type_metadata import bind_type

        cfg = _project(tmp_path)
        (tmp_path / "types.h").write_text(
            "#ifdef GOLD\ntypedef struct ITEM { int a; } ITEM;\n#else\ntypedef struct ITEM { int b; } ITEM;\n#endif\n"
        )
        with pytest.raises(ValueError, match="unique"):
            bind_type(cfg, "engine.item", Path("types.h"), "ITEM", 4, 4, "allocation", "native", {})


class TestTypeCLI:
    def test_bind_and_check_json_and_stale_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        from typer.testing import CliRunner

        from rebrew.types_cli import app

        cfg = _project(tmp_path)
        cfg.reversed_dir = tmp_path
        monkeypatch.setattr("rebrew.types_cli.require_config", lambda **kwargs: cfg)
        monkeypatch.setattr("rebrew.type_metadata.compile_type", lambda *args: None)
        monkeypatch.setattr("rebrew.sources.iter_sources", lambda *args: [])
        runner = CliRunner()
        args = [
            "bind",
            "engine.item",
            "types.h",
            "ITEM",
            "--size",
            "4",
            "--native-size",
            "4",
            "--evidence",
            "native",
            "--field",
            "value=0",
            "--json",
        ]
        bound = runner.invoke(app, args)
        assert bound.exit_code == 0, bound.output
        assert cli_payload(bound)["id"] == "engine.item"
        current = runner.invoke(app, ["check", "--compile", "--json"])
        assert current.exit_code == 0, current.output
        assert cli_payload(current)["type_findings"] == []
        cfg.base_cflags = "/Zp1"
        stale = runner.invoke(app, ["check", "--json"])
        assert stale.exit_code == 1, stale.output
        assert "stale" in cli_payload(stale)["type_findings"][0]["issue"]
        assert runner.invoke(app, ["check"]).exit_code == 1

    def test_generated_probe_uses_type_and_target_flags(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.config import ProjectConfig
        from rebrew.type_metadata import compile_type

        (tmp_path / "types.h").write_text("struct ITEM { int value; };\n")
        (tmp_path / "includes").mkdir()
        cfg = ProjectConfig(
            root=tmp_path,
            reversed_dir=tmp_path,
            base_cflags="/Iincludes",
            defines=["GOLD"],
            shared_dir=tmp_path / "includes",
        )

        def fake_compile(
            config: Any, source: Path, flags: list[str], workdir: Path, **kwargs: Any
        ) -> tuple[str, str]:
            # unshare cannot same-path mount a temporary source beneath private /tmp.
            assert source.parent != workdir
            assert workdir.is_dir()
            text = source.read_text()
            assert "sizeof(struct ITEM) == 4" in text
            assert "offsetof(struct ITEM, value) == 0" in text
            assert config.defines == ["GOLD"]
            assert str(tmp_path / "includes") in config.base_cflags
            assert flags == ["/O2"]
            assert kwargs["use_cache"] is False
            assert kwargs["extra_include_dirs"] == [str(tmp_path)]
            return "checked.obj", ""

        monkeypatch.setattr("rebrew.compiler.compile.compile_to_obj", fake_compile)
        compile_type(
            cfg,
            {
                "file": "types.h",
                "symbol": "ITEM",
                "size": 4,
                "offsets": {"value": 0},
                "cflags": "/O2",
            },
        )
