"""Tests for verify.py prepare_entries filtering and dedup."""

from pathlib import Path
from types import SimpleNamespace

import pytest

import rebrew.verify as verify_mod
from rebrew.annotation import Annotation


def _ann(va: int, marker: str = "FUNCTION", filepath: str = "f.c") -> Annotation:
    return Annotation(
        va=va, name=f"f{va:x}", status="STUB", size=64, filepath=filepath, marker_type=marker
    )


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        reversed_dir=tmp_path / "src",
        function_list=tmp_path / "functions.txt",
        target_binary=tmp_path / "x.dll",
        root=tmp_path,
        metadata_dir=tmp_path,
    )


def _patch(monkeypatch: pytest.MonkeyPatch, entries: list[Annotation]) -> None:
    monkeypatch.setattr(verify_mod, "scan_reversed_dir", lambda _d, cfg=None: entries)
    monkeypatch.setattr(verify_mod, "parse_function_list", lambda _p: [])
    monkeypatch.setattr(verify_mod, "build_function_registry", lambda *a, **k: {})
    monkeypatch.setattr(verify_mod, "count_detection_sources", lambda r: (0, 0, 0, 0))
    monkeypatch.setattr(verify_mod, "_load_verify_cache", lambda *a, **k: None)


class TestPrepareEntries:
    def test_filters_and_dedups(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _cfg(tmp_path)
        cfg.src_dir = cfg.reversed_dir
        (tmp_path / "x.dll").write_bytes(b"MZ")
        _patch(
            monkeypatch,
            [
                _ann(0x1000),
                _ann(0x1000),  # duplicate VA
                _ann(0x2000, marker="DATA"),
                _ann(0x3000, marker="GLOBAL"),
                _ann(0x4000, filepath="lib.h"),
            ],
        )
        entries, passed, failed, fail_details, results, cached, size_div = (
            verify_mod.prepare_entries(cfg, full=True, json_output=False)
        )
        vas = [e.va for e in entries]
        assert vas == [0x1000]  # DATA/GLOBAL/.h filtered, dup removed

    def test_missing_binary_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import typer

        _patch(monkeypatch, [])
        with pytest.raises(typer.Exit):
            verify_mod.prepare_entries(_cfg(tmp_path), full=True, json_output=False)


def cfg_reversed_dir() -> Path:
    return Path("/tmp")  # replaced per-test below via global


class TestPrepareEntriesCache:
    """prepare_entries incremental-cache branches (769-795)."""

    def _setup(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: Annotation
    ) -> SimpleNamespace:
        global cfg_reversed_dir
        cfg_reversed_dir = lambda: tmp_path / "src"  # noqa: E731
        cfg = _cfg(tmp_path)
        (tmp_path / "x.dll").write_bytes(b"MZ")
        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        f = src / entry.filepath
        f.write_text("int f(void) { return 0; }\n", encoding="utf-8")
        monkeypatch.setattr(verify_mod, "scan_reversed_dir", lambda _d, cfg=None: [entry])
        monkeypatch.setattr(verify_mod, "parse_function_list", lambda _p: [])
        monkeypatch.setattr(verify_mod, "build_function_registry", lambda *a, **k: {})
        monkeypatch.setattr(verify_mod, "count_detection_sources", lambda r: (0, 0, 0, 0))
        return cfg

    def _cache_entry(
        self, filepath: str, *, passed: bool = True, mtime: int = 0, source_hash: str = ""
    ) -> dict:
        if not source_hash:
            p = Path(cfg_reversed_dir()) / filepath
            source_hash = verify_mod._source_hash(p) if p.exists() else "no-file"
        return {
            "source_hash": source_hash,
            "filepath": filepath,
            "mtime_ns": mtime,
            "result": {
                "status": "EXACT" if passed else "STUB",
                "va": "0x1000",
                "size": 64,
                "filepath": filepath,
                "name": "f",
                "symbol": "_f",
                "delta": 0 if passed else 4,
                "match_percent": 100.0 if passed else 90.0,
                "passed": passed,
                "message": "" if passed else "9B diff",
            },
        }

    def test_cached_pass_reused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {"0x00001000": verify_mod.VerifyCacheEntry.from_dict(self._cache_entry("f.c"))}
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_mod.VerifyCache(
                version=1, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        entries, passed, failed, fail_details, results, cached, size_div = (
            verify_mod.prepare_entries(cfg, full=False, json_output=False)
        )
        assert cached == 1
        assert passed == 1
        assert results[0]["status"] == "EXACT"

    def test_cached_fail_recorded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {
            "0x00001000": verify_mod.VerifyCacheEntry.from_dict(
                self._cache_entry("f.c", passed=False)
            )
        }
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_mod.VerifyCache(
                version=1, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        entries, passed, failed, fail_details, results, cached, size_div = (
            verify_mod.prepare_entries(cfg, full=False, json_output=False)
        )
        assert cached == 1
        assert failed == 1
        assert len(fail_details) == 1

    def test_cached_filepath_mismatch_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {"0x00001000": verify_mod.VerifyCacheEntry.from_dict(self._cache_entry("other.c"))}
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_mod.VerifyCache(
                version=1, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        _entries, passed, _failed, _fd, results, cached, size_div = verify_mod.prepare_entries(
            cfg, full=False, json_output=False
        )
        assert cached == 0
        assert passed == 0
        assert results == []

    def test_cached_stale_hash_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        # mtime 0 always differs from the file's real mtime; source_hash is stale.
        cache = {
            "0x00001000": verify_mod.VerifyCacheEntry.from_dict(
                self._cache_entry("f.c", mtime=0, source_hash="stale-hash")
            )
        }
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_mod.VerifyCache(
                version=1, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        _entries, passed, _failed, _fd, results, cached, size_div = verify_mod.prepare_entries(
            cfg, full=False, json_output=False
        )
        assert cached == 0
        assert passed == 0

    def test_size_divergence_detected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _cfg(tmp_path)
        cfg.src_dir = cfg.reversed_dir
        (tmp_path / "x.dll").write_bytes(b"MZ")
        _patch(monkeypatch, [_ann(0x1000)])  # annotation size 64
        monkeypatch.setattr(
            verify_mod,
            "build_function_registry",
            lambda *a, **k: {0x1000: {"canonical_size": 80, "size_reason": "list"}},
        )
        _e, _p, _f, _fd, _r, _c, size_div = verify_mod.prepare_entries(
            cfg, full=True, json_output=False
        )
        assert len(size_div) == 1
        assert size_div[0]["va"] == "0x00001000"
        assert size_div[0]["annotation_size"] == 64
        assert size_div[0]["binary_size"] == 80

    def test_no_divergence_when_sizes_agree(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _cfg(tmp_path)
        cfg.src_dir = cfg.reversed_dir
        (tmp_path / "x.dll").write_bytes(b"MZ")
        _patch(monkeypatch, [_ann(0x1000)])  # annotation size 64
        monkeypatch.setattr(
            verify_mod,
            "build_function_registry",
            lambda *a, **k: {0x1000: {"canonical_size": 64, "size_reason": "list"}},
        )
        _e, _p, _f, _fd, _r, _c, size_div = verify_mod.prepare_entries(
            cfg, full=True, json_output=False
        )
        assert size_div == []
