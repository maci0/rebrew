import json
import os
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.config import ProjectConfig
from rebrew.verify import (
    _compiler_config_hash,
    _load_verify_cache,
    _save_verify_cache,
    _source_hash,
    app,
)

runner = CliRunner()


def _make_cfg(tmp_path: Path) -> ProjectConfig:
    reversed_dir = tmp_path / "src"
    reversed_dir.mkdir(parents=True, exist_ok=True)
    target_binary = tmp_path / "target.dll"
    target_binary.write_bytes(b"MZ")
    return ProjectConfig(
        root=tmp_path,
        target_name="SERVER",
        target_binary=target_binary,
        reversed_dir=reversed_dir,
        function_list=tmp_path / "functions.txt",
        compiler_command="wine CL.EXE",
        base_cflags="/nologo /c /MT",
        compiler_includes=tmp_path / "include",
        compiler_libs=tmp_path / "lib",
        origin_compiler={"GAME": {"cflags": "/O2 /Gd"}},
    )


class TestCompilerConfigHash:
    def test_changes_when_compiler_settings_change(self, tmp_path: Path) -> None:
        cfg_a = _make_cfg(tmp_path)
        cfg_b = _make_cfg(tmp_path)
        cfg_b.base_cflags = "/O1"

        assert _compiler_config_hash(cfg_a) != _compiler_config_hash(cfg_b)


class TestSourceHash:
    def test_hash_changes_with_file_content(self, tmp_path: Path) -> None:
        path = tmp_path / "func.c"
        path.write_text("int foo(void) { return 1; }\n", encoding="utf-8")
        hash_a = _source_hash(path)

        path.write_text("int foo(void) { return 2; }\n", encoding="utf-8")
        hash_b = _source_hash(path)

        assert hash_a != hash_b


class TestLoadVerifyCache:
    def test_load_valid_cache(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        cache_path = tmp_path / ".rebrew" / "verify_cache.json"
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 1,
            "compiler_hash": _compiler_config_hash(cfg),
            "target": cfg.target_name,
            "entries": {},
        }
        cache_path.write_text(json.dumps(data), encoding="utf-8")

        loaded = _load_verify_cache(cache_path, cfg)
        assert isinstance(loaded, dict)
        assert loaded["version"] == 1

    def test_reject_invalid_json(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        cache_path = tmp_path / ".rebrew" / "verify_cache.json"
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text("{", encoding="utf-8")

        assert _load_verify_cache(cache_path, cfg) is None

    def test_reject_wrong_version(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        cache_path = tmp_path / ".rebrew" / "verify_cache.json"
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 99,
            "compiler_hash": _compiler_config_hash(cfg),
            "target": cfg.target_name,
            "entries": {},
        }
        cache_path.write_text(json.dumps(data), encoding="utf-8")

        assert _load_verify_cache(cache_path, cfg) is None

    def test_reject_wrong_target(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        cache_path = tmp_path / ".rebrew" / "verify_cache.json"
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 1,
            "compiler_hash": _compiler_config_hash(cfg),
            "target": "OTHER",
            "entries": {},
        }
        cache_path.write_text(json.dumps(data), encoding="utf-8")

        assert _load_verify_cache(cache_path, cfg) is None

    def test_reject_wrong_compiler_hash(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        cache_path = tmp_path / ".rebrew" / "verify_cache.json"
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "version": 1,
            "compiler_hash": "deadbeef",
            "target": cfg.target_name,
            "entries": {},
        }
        cache_path.write_text(json.dumps(data), encoding="utf-8")

        assert _load_verify_cache(cache_path, cfg) is None


class TestSaveVerifyCache:
    def test_save_and_round_trip(self, tmp_path: Path) -> None:
        cfg = _make_cfg(tmp_path)
        source_path = cfg.reversed_dir / "func_a.c"
        source_path.write_text("int func_a(void) { return 1; }\n", encoding="utf-8")

        results = [
            {
                "va": "0x10001000",
                "name": "func_a",
                "filepath": "func_a.c",
                "size": 16,
                "status": "EXACT",
                "message": "EXACT MATCH",
                "passed": True,
                "match_percent": 100.0,
                "delta": 0,
            }
        ]
        entries = [
            {
                "va": 0x10001000,
                "name": "func_a",
                "filepath": "func_a.c",
                "size": 16,
                "origin": "GAME",
                "cflags": "",
                "symbol": "",
            }
        ]
        cache_path = tmp_path / ".rebrew" / "verify_cache.json"

        _save_verify_cache(cache_path, cfg, results, entries)
        loaded = _load_verify_cache(cache_path, cfg)

        assert isinstance(loaded, dict)
        cache_entries = loaded.get("entries", {})
        assert "0x10001000" in cache_entries
        assert cache_entries["0x10001000"]["filepath"] == "func_a.c"
        assert cache_entries["0x10001000"]["result"]["status"] == "EXACT"


class TestIncrementalVerify:
    def test_only_changed_files_are_recompiled(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _make_cfg(tmp_path)
        file_a = cfg.reversed_dir / "func_a.c"
        file_b = cfg.reversed_dir / "func_b.c"
        file_a.write_text("int func_a(void) { return 1; }\n", encoding="utf-8")
        file_b.write_text("int func_b(void) { return 2; }\n", encoding="utf-8")

        entries = [
            {
                "va": 0x10001000,
                "name": "func_a",
                "filepath": "func_a.c",
                "size": 16,
                "origin": "GAME",
                "cflags": "",
                "symbol": "",
            },
            {
                "va": 0x10002000,
                "name": "func_b",
                "filepath": "func_b.c",
                "size": 16,
                "origin": "GAME",
                "cflags": "",
                "symbol": "",
            },
        ]

        calls: list[int] = []

        def fake_get_config(*args: object, **kwargs: object) -> ProjectConfig:
            return cfg

        def fake_scan_reversed_dir(*args: object, **kwargs: object) -> list[dict[str, object]]:
            return entries

        def fake_parse_function_list(*args: object, **kwargs: object) -> list[dict[str, object]]:
            return []

        def fake_build_registry(*args: object, **kwargs: object) -> dict[int, dict[str, object]]:
            return {}

        def fake_verify_entry(
            entry: dict[str, object],
            _cfg: ProjectConfig,
        ) -> tuple[bool, str, bytes | None, bytes | None, list[int] | dict[int, str] | None]:
            calls.append(int(entry["va"]))
            return True, "EXACT MATCH", b"\x90", b"\x90", None

        monkeypatch.setattr("rebrew.verify.get_config", fake_get_config)
        monkeypatch.setattr("rebrew.verify.scan_reversed_dir", fake_scan_reversed_dir)
        monkeypatch.setattr("rebrew.verify.parse_function_list", fake_parse_function_list)
        monkeypatch.setattr("rebrew.verify.build_function_registry", fake_build_registry)
        monkeypatch.setattr("rebrew.verify.verify_entry", fake_verify_entry)

        first = runner.invoke(app, ["--json"])
        assert first.exit_code == 0, first.output
        assert len(calls) == 2

        cache_path = cfg.root / ".rebrew" / "verify_cache.json"
        assert cache_path.exists()

        calls.clear()
        second = runner.invoke(app, ["--json"])
        assert second.exit_code == 0, second.output
        assert calls == []

        same_content = file_a.read_text(encoding="utf-8")
        file_a.write_text(same_content, encoding="utf-8")
        timestamp = time.time() + 3.0
        os.utime(file_a, (timestamp, timestamp))

        calls.clear()
        third = runner.invoke(app, ["--json"])
        assert third.exit_code == 0, third.output
        assert calls == []

        file_a.write_text("int func_a(void) { return 7; }\n", encoding="utf-8")
        calls.clear()
        fourth = runner.invoke(app, ["--json"])
        assert fourth.exit_code == 0, fourth.output
        assert calls == [0x10001000]

        calls.clear()
        full_run = runner.invoke(app, ["--json", "--full"])
        assert full_run.exit_code == 0, full_run.output
        assert sorted(calls) == [0x10001000, 0x10002000]

    def test_fix_status_not_applied_to_cached_results(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _make_cfg(tmp_path)
        file_a = cfg.reversed_dir / "func_a.c"
        file_a.write_text("int func_a(void) { return 1; }\n", encoding="utf-8")

        entries = [
            {
                "va": 0x10001000,
                "name": "func_a",
                "filepath": "func_a.c",
                "size": 16,
                "origin": "GAME",
                "cflags": "",
                "symbol": "",
                "status": "MATCHING",
            }
        ]

        def fake_get_config(*args: object, **kwargs: object) -> ProjectConfig:
            return cfg

        def fake_scan_reversed_dir(*args: object, **kwargs: object) -> list[dict[str, object]]:
            return entries

        def fake_parse_function_list(*args: object, **kwargs: object) -> list[dict[str, object]]:
            return []

        def fake_build_registry(*args: object, **kwargs: object) -> dict[int, dict[str, object]]:
            return {}

        def fake_verify_entry(
            entry: dict[str, object],
            _cfg: ProjectConfig,
        ) -> tuple[bool, str, bytes | None, bytes | None, list[int] | dict[int, str] | None]:
            return True, "EXACT MATCH", b"\x90", b"\x90", None

        monkeypatch.setattr("rebrew.verify.get_config", fake_get_config)
        monkeypatch.setattr("rebrew.verify.scan_reversed_dir", fake_scan_reversed_dir)
        monkeypatch.setattr("rebrew.verify.parse_function_list", fake_parse_function_list)
        monkeypatch.setattr("rebrew.verify.build_function_registry", fake_build_registry)
        monkeypatch.setattr("rebrew.verify.verify_entry", fake_verify_entry)

        first = runner.invoke(app, ["--json", "--fix-status"])
        assert first.exit_code == 0, first.output

        def _should_not_be_called(*args: object, **kwargs: object) -> None:
            raise AssertionError("fix-status update should not run for cached entries")

        monkeypatch.setattr("rebrew.annotation.update_annotation_key", _should_not_be_called)
        monkeypatch.setattr("rebrew.annotation.remove_annotation_key", _should_not_be_called)

        second = runner.invoke(app, ["--json", "--fix-status"])
        assert second.exit_code == 0, second.output
