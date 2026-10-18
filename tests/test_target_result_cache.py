"""Target-isolated verification receipts and last-good compare baselines."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew.config import ProjectConfig
from rebrew.verify_cache import (
    baseline_path,
    cache_path_for,
    load_baseline,
    load_verify_cache,
    save_baseline,
    save_verify_cache,
)


def _cfg(root: Path, target: str) -> ProjectConfig:
    source = root / "src"
    source.mkdir(exist_ok=True)
    return ProjectConfig(
        root=root,
        target_name=target,
        reversed_dir=source,
        all_targets=["Gold", "TL"],
        target_binary=root / (target + ".exe"),
    )


def _rows(
    cfg: ProjectConfig, va: int, status: str = "EXACT"
) -> tuple[list[Any], list[dict[str, Any]]]:
    name = f"function_{va:x}"
    (cfg.reversed_dir / (name + ".c")).write_text("int " + name + "(void) { return 1; }\n")
    entries = [
        SimpleNamespace(
            va=va, name=name, filepath=name + ".c", size=8, kind="GAME", cflags="", symbol=""
        )
    ]
    rows = [
        {
            "va": f"0x{va:08x}",
            "name": name,
            "filepath": name + ".c",
            "size": 8,
            "status": status,
            "passed": status == "EXACT",
            "match_percent": 100.0,
            "delta": 0,
        }
    ]
    return entries, rows


def test_gold_tl_gold_scoped_refresh_preserves_each_targets_results(tmp_path: Path) -> None:
    gold, tl = _cfg(tmp_path, "Gold"), _cfg(tmp_path, "TL")
    first, first_rows = _rows(gold, 0x1000)
    second, second_rows = _rows(gold, 0x2000)
    save_verify_cache(cache_path_for(gold), gold, first_rows + second_rows, first + second)
    tl_entries, tl_rows = _rows(tl, 0x1000, "STUB")
    save_verify_cache(cache_path_for(tl), tl, tl_rows, tl_entries)
    save_verify_cache(cache_path_for(gold), gold, first_rows, first, preserve_keys={"0x00002000"})
    gold_cache = load_verify_cache(cache_path_for(gold), gold)
    tl_cache = load_verify_cache(cache_path_for(tl), tl)
    assert gold_cache is not None and tl_cache is not None
    assert set(gold_cache.entries) == {"0x00001000", "0x00002000"}
    assert gold_cache.entries["0x00001000"].status == "EXACT"
    assert tl_cache.entries["0x00001000"].status == "STUB"


def test_alternating_targets_keeps_compare_baseline_gate_available(tmp_path: Path) -> None:
    gold, tl = _cfg(tmp_path, "Gold"), _cfg(tmp_path, "TL")
    for cfg in (gold, tl):
        save_baseline(
            cfg, {"target": cfg.target_name, "results": [{"va": "0x1000", "status": "EXACT"}]}
        )
    for cfg in (gold, tl, gold):
        baseline, warning = load_baseline(cfg)
        assert warning is None
        assert baseline is not None and baseline["target"] == cfg.target_name


@pytest.mark.parametrize(
    "target", ["../Gold", "Gold/TL", r"Gold\TL", "Gold_TL", "gold", "Gold", "Γκολντ"]
)
def test_target_names_are_not_interpreted_or_lossily_sanitized(tmp_path: Path, target: str) -> None:
    cfg = _cfg(tmp_path, target)
    path = cache_path_for(cfg)
    assert path.is_relative_to(tmp_path / ".rebrew" / "targets")
    assert len(path.parent.name) == 64
    assert path != cache_path_for(replace(cfg, target_name=target + "_"))


def test_single_target_paths_are_unchanged(tmp_path: Path) -> None:
    cfg = replace(_cfg(tmp_path, "Gold"), all_targets=["Gold"])
    assert cache_path_for(cfg) == tmp_path / ".rebrew" / "verify_cache.toml"
    assert baseline_path(cfg) == tmp_path / ".rebrew" / "verify_baseline.toml"


def test_matching_legacy_cache_migrates_preserved_rows_without_modifying_legacy(
    tmp_path: Path,
) -> None:
    gold = _cfg(tmp_path, "Gold")
    legacy = replace(gold, all_targets=["Gold"])
    first, rows = _rows(gold, 0x1000)
    second, more = _rows(gold, 0x2000)
    save_verify_cache(cache_path_for(legacy), legacy, rows + more, first + second)
    legacy_path = cache_path_for(legacy)
    old_bytes = legacy_path.read_bytes()
    assert load_verify_cache(cache_path_for(gold), gold) is not None
    assert cache_path_for(gold, for_read=True) == cache_path_for(legacy)
    assert not cache_path_for(gold).exists()
    save_verify_cache(cache_path_for(gold), gold, rows, first, preserve_keys={"0x00002000"})
    loaded = load_verify_cache(cache_path_for(gold), gold)
    assert loaded is not None and len(loaded.entries) == 2
    assert cache_path_for(gold, for_read=True) == cache_path_for(gold)
    assert legacy_path.read_bytes() == old_bytes
    assert load_verify_cache(cache_path_for(_cfg(tmp_path, "TL")), _cfg(tmp_path, "TL")) is None


@pytest.mark.parametrize("change", ["target", "compiler", "binary", "schema"])
def test_foreign_legacy_cache_is_never_adopted(tmp_path: Path, change: str) -> None:
    import tomllib

    from cache_util import cache_text

    gold = _cfg(tmp_path, "Gold")
    legacy = replace(gold, all_targets=["Gold"])
    entries, rows = _rows(gold, 0x1000)
    save_verify_cache(cache_path_for(legacy), legacy, rows, entries)
    path = cache_path_for(legacy)
    raw = tomllib.loads(path.read_text())
    key = {
        "target": "target",
        "compiler": "compiler_hash",
        "binary": "binary_id",
        "schema": "version",
    }[change]
    raw[key] = 999 if change == "schema" else "foreign"
    path.write_text(cache_text(raw))
    assert cache_path_for(gold, for_read=True) == cache_path_for(gold)
    assert load_verify_cache(cache_path_for(gold), gold) is None
    assert not cache_path_for(gold).exists()


@pytest.mark.parametrize("content", ["broken = [", 'version=2\ntarget="TL"\n'])
def test_selected_cache_is_authoritative_over_matching_legacy(tmp_path: Path, content: str) -> None:
    gold = _cfg(tmp_path, "Gold")
    legacy = replace(gold, all_targets=["Gold"])
    entries, rows = _rows(gold, 0x1000)
    save_verify_cache(cache_path_for(legacy), legacy, rows, entries)
    path = cache_path_for(gold)
    path.parent.mkdir(parents=True)
    path.write_text(content)
    assert cache_path_for(gold, for_read=True) == path
    assert load_verify_cache(path, gold) is None


def test_matching_legacy_baseline_is_read_then_isolated_without_deleting_legacy(
    tmp_path: Path,
) -> None:
    gold = _cfg(tmp_path, "Gold")
    legacy = replace(gold, all_targets=["Gold"])
    save_baseline(legacy, {"target": "Gold", "results": []})
    legacy_path = baseline_path(legacy)
    before = legacy_path.read_bytes()
    baseline, warning = load_baseline(gold)
    assert baseline is not None and warning is None
    assert not baseline_path(gold).exists()
    save_baseline(gold, {"target": "Gold", "results": [{"va": "0x1000"}]})
    assert legacy_path.read_bytes() == before
    assert load_baseline(_cfg(tmp_path, "TL"))[0] is None
    baseline_path(gold).write_text("broken = [")
    assert load_baseline(gold)[0] is None


def test_promotion_patches_are_target_local_and_migrate_matching_legacy(tmp_path: Path) -> None:
    from rebrew.status import _load_cache_raw
    from rebrew.todo import load_verify_entries
    from rebrew.verify_cache import patch_verify_cache_entries

    gold, tl = _cfg(tmp_path, "Gold"), _cfg(tmp_path, "TL")
    legacy = replace(gold, all_targets=["Gold"])
    entries, rows = _rows(gold, 0x1000)
    save_verify_cache(cache_path_for(legacy), legacy, rows, entries)
    legacy_path = cache_path_for(legacy)
    patch_verify_cache_entries(gold, [{"va": 0x1000, "status": "RELOC"}])
    save_verify_cache(cache_path_for(tl), tl, rows, entries)
    patch_verify_cache_entries(tl, [{"va": 0x1000, "status": "STUB"}])
    for cfg, expected in ((gold, "RELOC"), (tl, "STUB")):
        raw = _load_cache_raw(cfg)
        assert raw is not None and raw["entries"]["0x00001000"]["status"] == expected
        assert load_verify_entries(cfg)["0x00001000"].status == expected
    unchanged = load_verify_cache(legacy_path, legacy)
    assert unchanged is not None and unchanged.entries["0x00001000"].status == "EXACT"


def test_coverage_import_and_invalidation_select_target_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rebrew.coverage_db import import_verify_rows
    from rebrew.coverage_project import _inputs

    cfgs = {target: _cfg(tmp_path, target) for target in ("Gold", "TL")}
    (tmp_path / "rebrew-project.toml").write_text("")
    monkeypatch.setattr("rebrew.coverage_db.load_config", lambda root, target: cfgs[target])
    for target, cfg in cfgs.items():
        entries, rows = _rows(cfg, 0x1000)
        save_verify_cache(cache_path_for(cfg), cfg, rows, entries)
        imported = import_verify_rows(tmp_path, target, {}, "now")
        assert imported is not None and imported[0][0] == target
        paths = {row[0] for row in _inputs(cfg)}
        assert str(cache_path_for(cfg)) in paths
        assert str(tmp_path / ".rebrew" / "verify_cache.toml") in paths


def test_compare_cli_does_not_skip_gold_gate_after_tl_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cli_json import cli_payload
    from typer.testing import CliRunner

    from rebrew.verify import app

    gold, tl = _cfg(tmp_path, "Gold"), _cfg(tmp_path, "TL")
    entries, rows = _rows(gold, 0x1000)
    for cfg in (gold, tl):
        save_baseline(cfg, {"target": cfg.target_name, "results": rows})
    original = baseline_path(gold).read_bytes()
    monkeypatch.setattr("rebrew.verify.require_config", lambda **kwargs: gold)
    monkeypatch.setattr(
        "rebrew.verify.prepare_entries",
        lambda *args, **kwargs: (entries, 0, 0, [], [], 0, [], [], [], {}, 0),
    )
    current = [{**rows[0], "status": "NEAR_MATCHING", "passed": False, "delta": 1}]
    monkeypatch.setattr(
        "rebrew.verify.run_verification", lambda *args, **kwargs: (0, 1, [], current, [])
    )
    monkeypatch.setattr("rebrew.verify._apply_or_preview_status", lambda *args, **kwargs: None)
    result = CliRunner().invoke(app, ["--compare", "--json"])
    assert result.exit_code == 1, result.output
    data = cli_payload(result)
    assert data["diff"]["regressions"]
    assert baseline_path(gold).read_bytes() == original
    assert not cache_path_for(gold).exists()


@pytest.mark.parametrize("changed_input", ["compiler", "binary"])
def test_same_target_identity_changes_do_not_evict_sibling(
    tmp_path: Path, changed_input: str
) -> None:
    gold, tl = _cfg(tmp_path, "Gold"), _cfg(tmp_path, "TL")
    for cfg in (gold, tl):
        cfg.target_binary.write_bytes(b"old")
        entries, rows = _rows(cfg, 0x1000)
        save_verify_cache(cache_path_for(cfg), cfg, rows, entries)
    if changed_input == "compiler":
        gold.base_cflags += " /Od"
    else:
        gold.target_binary.write_bytes(b"different")
    assert load_verify_cache(cache_path_for(gold), gold) is None
    assert load_verify_cache(cache_path_for(tl), tl) is not None


def test_one_target_cache_refresh_invalidates_only_its_coverage_inputs(tmp_path: Path) -> None:
    from rebrew.coverage_project import _inputs

    gold, tl = _cfg(tmp_path, "Gold"), _cfg(tmp_path, "TL")
    entries, rows = _rows(gold, 0x1000)
    for cfg in (gold, tl):
        save_verify_cache(cache_path_for(cfg), cfg, rows, entries)
    before_gold, before_tl = _inputs(gold), _inputs(tl)
    save_verify_cache(cache_path_for(gold), gold, [{**rows[0], "delta": 1}], entries)
    assert _inputs(gold) != before_gold
    assert _inputs(tl) == before_tl


@pytest.mark.parametrize("kind", ["cache", "baseline"])
def test_dangling_selected_file_never_falls_back_to_legacy(tmp_path: Path, kind: str) -> None:
    gold = _cfg(tmp_path, "Gold")
    legacy = replace(gold, all_targets=["Gold"])
    if kind == "cache":
        entries, rows = _rows(gold, 0x1000)
        save_verify_cache(cache_path_for(legacy), legacy, rows, entries)
        selected = cache_path_for(gold)
    else:
        save_baseline(legacy, {"target": "Gold", "results": []})
        selected = baseline_path(gold)
    selected.parent.mkdir(parents=True, exist_ok=True)
    selected.symlink_to(selected.parent / "missing")
    if kind == "cache":
        assert cache_path_for(gold, for_read=True) == selected
        assert load_verify_cache(selected, gold) is None
    else:
        assert baseline_path(gold, for_read=True) == selected
        assert load_baseline(gold)[0] is None


@pytest.mark.parametrize("legacy_owner", ["Gold", "TL"])
def test_removing_sibling_targets_keeps_newer_isolated_results(
    tmp_path: Path, legacy_owner: str
) -> None:
    gold = _cfg(tmp_path, "Gold")
    legacy = replace(gold, target_name=legacy_owner, all_targets=[legacy_owner])
    entries, rows = _rows(gold, 0x1000)
    save_verify_cache(cache_path_for(legacy), legacy, [{**rows[0], "status": "STUB"}], entries)
    save_baseline(legacy, {"target": legacy_owner, "generation": "old", "results": []})
    save_verify_cache(cache_path_for(gold), gold, rows, entries)
    save_baseline(gold, {"target": "Gold", "generation": "new", "results": []})
    remaining = replace(gold, all_targets=["Gold"])
    assert cache_path_for(remaining) == cache_path_for(gold)
    cache = load_verify_cache(cache_path_for(remaining), remaining)
    assert cache is not None and cache.entries["0x00001000"].status == "EXACT"
    baseline, warning = load_baseline(remaining)
    assert warning is None and baseline is not None and baseline["generation"] == "new"
