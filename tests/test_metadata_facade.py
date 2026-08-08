"""Tests for the typed metadata facade (rebrew.metadata typed layer)."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.metadata import (
    FILE_ONLY_KEYS,
    KNOWN_STATUSES,
    LEGACY_KEYS,
    METADATA_FIELDS,
    FunctionMetadata,
    coerce_metadata_value,
    field_kind,
    load_entry,
    save_entry,
    set_field,
)


def _entry(tmp_path: Path, va: int = 0x10001000, module: str = "SERVER", **fields: object) -> Path:
    for key, value in fields.items():
        set_field(tmp_path, va, key, value, module=module)
    return tmp_path


class TestFieldKind:
    def test_metadata_owned(self) -> None:
        for key in METADATA_FIELDS:
            assert field_kind(key) == "metadata"

    def test_file_only(self) -> None:
        for key in FILE_ONLY_KEYS:
            assert field_kind(key) == "file"
        assert field_kind("symbol") == "file"  # case-insensitive

    def test_legacy(self) -> None:
        assert field_kind("ORIGIN") == "legacy"
        assert field_kind("SECTION") == "legacy"

    def test_unknown(self) -> None:
        assert field_kind("NOPE") == "unknown"
        assert field_kind("") == "unknown"

    def test_routing_consistent_with_annotation_keys(self) -> None:
        """Every annotation key classifies, and METADATA_KEYS is never unknown."""
        from rebrew.annotation import ALL_KNOWN_KEYS, METADATA_KEYS

        for key in METADATA_KEYS:
            assert field_kind(key) in ("metadata", "legacy"), key
        # ORIGIN/SECTION are exactly the legacy keys — metadata does not own them.
        assert {k for k in METADATA_KEYS if field_kind(k) == "legacy"} == set(LEGACY_KEYS)
        for key in ALL_KNOWN_KEYS:
            assert field_kind(key) != "unknown"


class TestCoerceMetadataValue:
    def test_size_string_to_int(self) -> None:
        assert coerce_metadata_value("size", "64") == 64
        assert coerce_metadata_value("size", 64) == 64
        assert coerce_metadata_value("blocker_delta", "12") == 12

    def test_size_unparseable_passes_through(self) -> None:
        assert coerce_metadata_value("size", "big") == "big"

    def test_other_fields_untouched(self) -> None:
        assert coerce_metadata_value("cflags", "/O2") == "/O2"
        assert coerce_metadata_value("note", "12") == "12"


class TestFunctionMetadata:
    def test_round_trip_all_fields(self, tmp_path: Path) -> None:
        meta = FunctionMetadata(
            module="SERVER",
            va=0x10001000,
            status="EXACT",
            size=128,
            cflags="/O2",
            blocker="tail call",
            blocker_delta=4,
            note="n",
            ghidra="g",
            analysis="a",
            skip=False,
            globals_list=["g_foo", "g_bar"],
            source="crt",
            prove_constraints={"mem": 1},
        )
        assert meta.validate() == []
        save_entry(tmp_path, meta)

        loaded = load_entry(tmp_path, meta.va, meta.module)
        assert loaded is not None
        assert loaded == meta
        assert loaded.blocker_delta == 4
        assert loaded.globals_list == ["g_foo", "g_bar"]

    def test_from_entry_coerces_size(self, tmp_path: Path) -> None:
        _entry(tmp_path, size="64")
        loaded = load_entry(tmp_path, 0x10001000, "SERVER")
        assert loaded is not None
        assert loaded.size == 64

    def test_load_entry_missing_returns_none(self, tmp_path: Path) -> None:
        assert load_entry(tmp_path, 0x10001000, "SERVER") is None

    def test_to_entry_drops_none(self) -> None:
        meta = FunctionMetadata(module="SERVER", va=0x1000)
        assert meta.to_entry() == {}

    def test_validate_errors(self) -> None:
        bad = FunctionMetadata(module="", va=0, status="BOGUS", size=-1, blocker_delta="x")
        errors = bad.validate()
        assert any("module" in e for e in errors)
        assert any("va" in e for e in errors)
        assert any("BOGUS" in e for e in errors)
        assert any("size" in e for e in errors)
        assert any("blocker_delta" in e for e in errors)

    def test_validate_accepts_operational_status(self) -> None:
        # Operational statuses written by test/verify are not annotation
        # statuses; the typed facade flags them so callers decide.
        assert "COMPILE_ERROR" not in KNOWN_STATUSES
        meta = FunctionMetadata(module="SERVER", va=0x1000, status="COMPILE_ERROR")
        assert any("status" in e for e in meta.validate())

    def test_save_entry_rejects_invalid(self, tmp_path: Path) -> None:
        bad = FunctionMetadata(module="SERVER", va=0x1000, size=-5)
        with pytest.raises(ValueError, match="size"):
            save_entry(tmp_path, bad)
        assert load_entry(tmp_path, 0x1000, "SERVER") is None

    def test_save_entry_routes_status(self, tmp_path: Path) -> None:
        """save_entry with a status goes through update_source_status (no raise)."""
        meta = FunctionMetadata(module="SERVER", va=0x1000, status="RELOC", size=10)
        save_entry(tmp_path, meta)
        loaded = load_entry(tmp_path, 0x1000, "SERVER")
        assert loaded is not None
        assert loaded.status == "RELOC"


class TestFacadeLintIntegration:
    def test_lint_fix_coerces_size_via_facade(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """lint --fix persists inline SIZE as an int (not the raw string)."""
        from typer.testing import CliRunner

        from rebrew.lint import app

        toml = (
            "[project]\n"
            'default_target = "server_dll"\n'
            "\n"
            "[targets.server_dll]\n"
            'binary = "original/Server/server.dll"\n'
            'format = "pe"\n'
            'arch = "x86_32"\n'
            'reversed_dir = "src/server_dll"\n'
            'marker = "SERVER"\n'
        )
        (tmp_path / "rebrew-project.toml").write_text(toml, encoding="utf-8")
        src = tmp_path / "src/server_dll"
        src.mkdir(parents=True)
        (src / "foo.c").write_text(
            "// STUB: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2\n"
            "\n"
            "int func_a(void) { return 0; }\n",
            encoding="utf-8",
        )
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["--fix", "src/server_dll/foo.c"])
        assert result.exit_code == 0
        from rebrew.metadata import get_entry

        entry = get_entry(tmp_path / "src", 0x10001000, "SERVER")
        assert entry.get("size") == 64
        assert isinstance(entry.get("size"), int)
        # Source no longer carries the inline SIZE.
        text = (src / "foo.c").read_text(encoding="utf-8")
        assert "SIZE:" not in text


class TestFacadeSimpleNamespaceCfg:
    def test_load_entry_from_namespace_cfg(self, tmp_path: Path) -> None:
        """Typed facade works with the SimpleNamespace config used by tools."""
        cfg = SimpleNamespace(metadata_dir=tmp_path)
        set_field(cfg.metadata_dir, 0x1000, "cflags", "/O2", module="SERVER")
        entry = load_entry(cfg.metadata_dir, 0x1000, "SERVER")
        assert entry is not None
        assert entry.cflags == "/O2"
