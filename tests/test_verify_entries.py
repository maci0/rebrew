"""Tests for verify.py prepare_entries filtering and dedup."""

from pathlib import Path
from types import SimpleNamespace

import pytest

import rebrew.verify as verify_mod
import rebrew.verify_cache as verify_cache_mod
import rebrew.verify_hash as verify_hash_mod
from rebrew.annotation import Annotation


def _ann(va: int, marker: str = "FUNCTION", filepath: str = "f.c", size: int = 64) -> Annotation:
    return Annotation(
        va=va, name=f"f{va:x}", status="STUB", size=size, filepath=filepath, marker_type=marker
    )


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        reversed_dir=tmp_path / "src",
        target_binary=tmp_path / "x.dll",
        root=tmp_path,
        metadata_dir=tmp_path,
    )


def _patch(monkeypatch: pytest.MonkeyPatch, entries: list[Annotation]) -> None:
    monkeypatch.setattr(verify_mod, "scan_reversed_dir", lambda _d, cfg=None: entries)
    monkeypatch.setattr(verify_mod, "cached_function_list", lambda _cfg: [])
    monkeypatch.setattr(verify_mod, "build_function_registry", lambda *a, **k: {})
    monkeypatch.setattr(verify_mod, "count_detection_sources", lambda r: (0, 0, 0, 0))
    monkeypatch.setattr(verify_mod, "_load_verify_cache", lambda *a, **k: None)
    monkeypatch.setattr(
        "rebrew.coff_reloc.build_name_to_va",
        lambda cfg, annotations=None: {e.name: e.va for e in entries if e.name},
    )


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
        (
            entries,
            passed,
            failed,
            fail_details,
            results,
            cached,
            size_div,
            _miss,
            _dup,
            _n2v,
            _inv,
        ) = verify_mod.prepare_entries(cfg, full=True, json_output=False)
        vas = [e.va for e in entries]
        assert vas == [0x1000]  # DATA/GLOBAL/.h filtered, dup removed

    def test_missing_binary_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import typer

        _patch(monkeypatch, [])
        with pytest.raises(typer.Exit):
            verify_mod.prepare_entries(_cfg(tmp_path), full=True, json_output=False)

    def test_duplicate_va_warns_and_names_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        """A duplicate VA keeps the first source and warns loudly naming the
        dropped file — on stderr and in the returned duplicate rows."""
        cfg = _cfg(tmp_path)
        cfg.src_dir = cfg.reversed_dir
        (tmp_path / "x.dll").write_bytes(b"MZ")
        _patch(
            monkeypatch,
            [
                _ann(0x1000, filepath="kept.c"),
                _ann(0x1000, filepath="dropped.c"),
            ],
        )
        entries, *_rest, duplicates, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=True, json_output=False
        )
        assert [e.va for e in entries] == [0x1000]
        assert duplicates == [{"va": "0x00001000", "kept": "kept.c", "dropped": "dropped.c"}]
        err = capsys.readouterr().err
        assert "duplicate VA 0x00001000" in err
        assert "dropped.c" in err


def cfg_reversed_dir() -> Path:
    return Path("/tmp")  # replaced per-test below via global


class TestPrepareEntriesCache:
    """prepare_entries incremental-cache branches (769-795)."""

    def _setup(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: Annotation
    ) -> SimpleNamespace:
        global cfg_reversed_dir

        def _reversed() -> Path:
            return tmp_path / "src"

        cfg_reversed_dir = _reversed
        cfg = _cfg(tmp_path)
        (tmp_path / "x.dll").write_bytes(b"MZ")
        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        f = src / entry.filepath
        f.write_text("int f(void) { return 0; }\n", encoding="utf-8")
        monkeypatch.setattr(verify_mod, "scan_reversed_dir", lambda _d, cfg=None: [entry])
        monkeypatch.setattr(verify_mod, "cached_function_list", lambda _cfg: [])
        monkeypatch.setattr(verify_mod, "build_function_registry", lambda *a, **k: {})
        monkeypatch.setattr(verify_mod, "count_detection_sources", lambda r: (0, 0, 0, 0))
        monkeypatch.setattr(
            "rebrew.coff_reloc.build_name_to_va",
            lambda cfg, annotations=None: {entry.name: entry.va} if entry.name else {},
        )
        return cfg

    def _cache_entry(
        self,
        filepath: str,
        *,
        passed: bool = True,
        mtime: int = 0,
        source_hash: str = "",
        size: int = 64,
        cflags: str | None = None,
    ) -> dict:
        if cflags is None:
            # Mirror the new writer: the cache stores the RESOLVED effective
            # flags (config fallback chain applied), not the raw metadata
            # value — a hit requires the freshly-resolved value to match.
            from rebrew.compile_overrides import resolve_cflags

            cflags = resolve_cflags(_cfg(Path("/tmp")), None, "")
        if not source_hash:
            p = Path(cfg_reversed_dir()) / filepath
            source_hash = verify_hash_mod._source_hash(p) if p.exists() else "no-file"
        # Mirror the new writer: the entry stores the reached-header
        # dependency fingerprint, so a hit requires the freshly-computed
        # value to match (a header the source reaches must invalidate it).
        p = Path(cfg_reversed_dir()) / filepath
        headers_fp = (
            verify_hash_mod._entry_headers_fp(_cfg(Path(cfg_reversed_dir())), p, cflags)
            if p.exists()
            else ""
        )
        # Mirror the new writer: the resolved toolchain override
        # (per-function → per-library → project default), so a TOOLCHAIN edit
        # invalidates the entry.
        from rebrew.compile_overrides import resolve_compile_overrides

        _tc, _cf2 = resolve_compile_overrides(
            _cfg(Path(cfg_reversed_dir())), Path(cfg_reversed_dir()), "", "", ""
        )
        toolchain = _tc or verify_mod._DEFAULT_TOOLCHAIN
        return {
            "source_hash": source_hash,
            "filepath": filepath,
            "mtime_ns": mtime,
            # Flat v2 row: one `size` (annotation SIZE at cache time — the
            # invalidation guard AND the verdict size are both entry.size).
            "size": size,  # 64 matches _ann's default annotation size
            "cflags": cflags,
            "headers_fp": headers_fp,
            "toolchain": toolchain,
            "defines": "(none)",
            "status": "EXACT" if passed else "STUB",
            "va": "0x1000",
            "name": "f",
            "symbol": "_f",
            "delta": 0 if passed else 4,
            "match_percent": 100.0 if passed else 90.0,
            "passed": passed,
            "message": "" if passed else "9B diff",
        }

    def test_cached_pass_reused(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(self._cache_entry("f.c"))
        }
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        (
            entries,
            passed,
            failed,
            fail_details,
            results,
            cached,
            size_div,
            _miss,
            _dup,
            _n2v,
            _inv,
        ) = verify_mod.prepare_entries(cfg, full=False, json_output=False)
        assert cached == 1
        assert passed == 1
        assert results[0]["status"] == "EXACT"

    def test_context_scoped_cache_hit_requires_matching_digest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cached verdict is served only under the same context digest.

        Entries carry the ``context_hash`` they were earned under; a run
        pinned to a different (or no) context must re-verify, and a bare
        run must not serve a context-earned row.
        """
        from rebrew.compile_context import CompileContext

        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(self._cache_entry("f.c"))
        }
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        ctx = CompileContext(path=tmp_path / "ctx.c", text="typedef int myint;\n", sha256="abc123")

        _e, _p, _f, _fd, _r, cached_no_ctx, _sd, _ms, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False
        )
        assert cached_no_ctx == 1, "a bare-source entry hits a bare run"

        _e, _p, _f, _fd, _r, cached_ctx, _sd, _ms, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False, context=ctx
        )
        assert cached_ctx == 0, "a context-earned row must not serve a bare run"

        # Rewind: the same digest must hit.
        cache["0x00001000"] = verify_cache_mod.VerifyCacheEntry.from_dict(
            {**self._cache_entry("f.c"), "context_hash": "abc123"}
        )
        _e, _p, _f, _fd, _r, cached_same, _sd, _ms, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False, context=ctx
        )
        assert cached_same == 1, "the same digest must hit"

        other = CompileContext(
            path=tmp_path / "ctx2.c", text="struct S {int a;};\n", sha256="def456"
        )
        _e, _p, _f, _fd, _r, cached_other, _sd, _ms, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False, context=other
        )
        assert cached_other == 0, "a different digest must re-verify"

    def test_cached_entry_invalidated_by_size_change(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cached result with a different annotation SIZE must be re-verified.

        SIZE is metadata-only (catalog --fix-sizes never touches the .c), so
        the source hash cannot detect it — the cache entry's size field is
        the only guard against serving a stale EXACT after a size fix.
        """
        entry = _ann(0x1000)  # annotation size 64
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(
                self._cache_entry("f.c", size=32)  # cached with a different size
            )
        }
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        _, _, _, _, _, cached, _, _, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False
        )
        assert cached == 0

    def test_cached_proven_invalidated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cached PROVEN result must be re-verified.

        The current cache writer stores raw byte results only — the PROVEN
        overlay is applied at report time from CURRENT metadata.  A cached
        PROVEN therefore comes from pre-fix code that baked the overlay in,
        and would mask a later metadata STATUS demotion with a stale pass.
        """
        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(
                self._cache_entry("f.c", passed=True)
            )
        }
        cache["0x00001000"].status = "PROVEN"  # stale pre-fix baked value
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        _, _, _, _, _, cached, _, _, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False
        )
        assert cached == 0

    def test_cached_entry_invalidated_by_cflags_change(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cached result with different CFLAGS must be re-verified."""
        entry = _ann(0x1000)  # annotation cflags ""
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(
                self._cache_entry("f.c", cflags="/O1")
            )
        }
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        _, _, _, _, _, cached, _, _, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False
        )
        assert cached == 0

    def test_config_cflags_change_invalidates_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cached result must be re-verified after [compiler].cflags or a
        module preset changes — the entry stores the RESOLVED effective flags
        (config fallback chain applied), so a config edit that changes what a
        function compiles with invalidates it (the old code
        compared only metadata CFLAGS, leaving stale EXACT/RELOC served)."""
        entry = _ann(0x1000)  # annotation cflags "" → resolves from config
        cfg = self._setup(tmp_path, monkeypatch, entry)
        # Cache was written when the config resolved to the default.
        cache = {
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(
                self._cache_entry("f.c", cflags="/O2 /Gd")
            )
        }
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        # First pass: cache hit (resolved flags match the cached entry).
        _, _, _, _, _, cached, _, _, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False
        )
        assert cached == 1
        # Config-level cflags change: the same source now compiles differently
        # → the cached result is stale and must be re-verified.
        cfg.cflags = "/O1"
        _, _, _, _, _, cached, _, _, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False
        )
        assert cached == 0
        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(
                self._cache_entry("f.c", passed=False)
            )
        }
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        (
            entries,
            passed,
            failed,
            fail_details,
            results,
            cached,
            size_div,
            _miss,
            _dup,
            _n2v,
            _inv,
        ) = verify_mod.prepare_entries(cfg, full=False, json_output=False)
        assert cached == 1
        assert failed == 1
        assert len(fail_details) == 1

    def test_cached_toolchain_change_invalidates_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A library/function TOOLCHAIN override edit must invalidate the
        entry — only the resolved cflags were stored before, so a toolchain
        swap served stale EXACT/RELOC for every function under the library
        (paper: the resolved-config change is classified against the entry's
        (toolchain, cflags) specification)."""
        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(
                self._cache_entry("f.c", cflags="/O2 /Gd")
            )
        }
        cache["0x00001000"].toolchain = "watcom-2.0-win32"  # cached under a library override
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        _, _, _, _, _, cached, _, _, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False
        )
        assert cached == 0

    def test_cached_toolchain_match_served(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The entry's stored toolchain matches the freshly-resolved value."""
        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(self._cache_entry("f.c"))
        }
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        _, _, _, _, _, cached, _, _, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False
        )
        assert cached == 1

    def test_cflags_order_only_change_keeps_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rebrew-libraries.toml edit that only reorders flags compiles
        identically — the canonicalized equivalence class matches, so the
        entry is served (observational equivalence: material-change
        classification rather than raw-string comparison)."""
        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        # Resolved flags are "/O2 /Gd"; the cached entry holds the same flags
        # in a different order — no material change.
        cache = {
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(
                self._cache_entry("f.c", cflags="/Gd /O2")
            )
        }
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        _, _, _, _, _, cached, _, _, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False
        )
        assert cached == 1

    def test_defines_change_invalidates_cache(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A per-target defines edit (a version switch in a shared
        multi-version source) must re-verify the entry — defines are compile
        inputs invisible to the source hash and cflags string."""
        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(
                self._cache_entry("f.c", cflags="/O2 /Gd")
            )
        }
        cache["0x00001000"].defines = "V1"  # cached under an older version switch
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        _, _, _, _, _, cached, _, _, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False
        )
        assert cached == 0

    def test_defines_match_served(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The entry's stored defines match the freshly-resolved ones."""
        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(
                self._cache_entry("f.c", cflags="/O2 /Gd")
            )
        }
        cache["0x00001000"].defines = "(none)"
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        _, _, _, _, _, cached, _, _, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=False, json_output=False
        )
        assert cached == 1

    def test_cached_filepath_mismatch_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        entry = _ann(0x1000)
        cfg = self._setup(tmp_path, monkeypatch, entry)
        cache = {
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(self._cache_entry("other.c"))
        }
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        _entries, passed, _failed, _fd, results, cached, size_div, _miss, _dup, _n2v, _inv = (
            verify_mod.prepare_entries(cfg, full=False, json_output=False)
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
            "0x00001000": verify_cache_mod.VerifyCacheEntry.from_dict(
                self._cache_entry("f.c", mtime=0, source_hash="stale-hash")
            )
        }
        monkeypatch.setattr(
            verify_mod,
            "_load_verify_cache",
            lambda *a, **k: verify_cache_mod.VerifyCache(
                version=2, compiler_hash="", headers_hash="", target="", entries=cache
            ),
        )
        _entries, passed, _failed, _fd, results, cached, size_div, _miss, _dup, _n2v, _inv = (
            verify_mod.prepare_entries(cfg, full=False, json_output=False)
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
        _e, _p, _f, _fd, _r, _c, size_div, _miss, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=True, json_output=False
        )
        assert len(size_div) == 1
        assert size_div[0]["va"] == "0x00001000"
        assert size_div[0]["annotation_size"] == 64
        assert size_div[0]["binary_size"] == 80

    def test_padding_to_alignment_not_a_divergence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A canonical size that is just the annotation rounded up to the next
        16-byte function-alignment boundary is the aligned slot, not stale."""
        cfg = _cfg(tmp_path)
        cfg.src_dir = cfg.reversed_dir
        (tmp_path / "x.dll").write_bytes(b"MZ")
        _patch(monkeypatch, [_ann(0x1000, size=66)])  # 66 % 16 == 2 -> pad 14
        monkeypatch.setattr(
            verify_mod,
            "build_function_registry",
            lambda *a, **k: {0x1000: {"canonical_size": 80, "size_reason": "list"}},
        )
        _e, _p, _f, _fd, _r, _c, size_div, _miss, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=True, json_output=False
        )
        assert size_div == []

    def test_validated_overcount_not_a_divergence(self) -> None:
        """EXACT/RELOC/PROVEN at the annotation size proves that many real
        bytes; a smaller canonical (Ghidra fragment) is the unreliable side.
        PROVEN matches ``_partition_size_fixes`` protection."""
        from rebrew.verify import _size_divergence_action

        assert _size_divergence_action(752, 340, "RELOC") == "skip"
        assert _size_divergence_action(304, 24, "EXACT") == "skip"
        assert _size_divergence_action(667, 704, "PROVEN") == "warn"  # under-count
        assert _size_divergence_action(704, 667, "PROVEN") == "skip"  # over-count

    def test_truncation_hazard_still_warns(self) -> None:
        """ann < canonical can false-EXACT on a prefix: never skip it, even
        when matched."""
        from rebrew.verify import _size_divergence_action

        assert _size_divergence_action(51, 239, "RELOC") == "warn"
        assert _size_divergence_action(396, 400, "EXACT") == "skip"  # pad, ann%16==12

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
        _e, _p, _f, _fd, _r, _c, size_div, _miss, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=True, json_output=False
        )
        assert size_div == []

    def test_missing_size_collected_for_backfill(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A documented stub with NO annotation size (intake's STUB files) has
        an empty 0-byte annotation — the binary-derived canonical size must be
        collected as a backfill candidate so --fix-sizes can make it testable.
        Regression: smygb's 151 intake stubs reported MISSING_SIZE forever."""
        cfg = _cfg(tmp_path)
        cfg.src_dir = cfg.reversed_dir
        (tmp_path / "x.dll").write_bytes(b"MZ")
        from dataclasses import replace

        _patch(monkeypatch, [replace(_ann(0x1000), size=0)])  # no SIZE anywhere
        monkeypatch.setattr(
            verify_mod,
            "build_function_registry",
            lambda *a, **k: {0x1000: {"canonical_size": 235, "size_reason": "list"}},
        )
        _e, _p, _f, _fd, _r, _c, size_div, missing, _dup, _n2v, _inv = verify_mod.prepare_entries(
            cfg, full=True, json_output=False
        )
        assert size_div == []  # not a divergence — it's absent, not stale
        assert len(missing) == 1
        assert missing[0]["va"] == "0x00001000"
        assert missing[0]["binary_size"] == 235


class TestBinaryIdCacheGuard:
    """A rebuilt binary of the same target name must invalidate the verify
    cache (round-4: the cache previously checked only the target NAME)."""

    def test_binary_change_invalidates_cache(self, tmp_path: Path) -> None:
        import json as _json

        bin_path = tmp_path / "x.dll"
        bin_path.write_bytes(b"MZ1")
        (tmp_path / "src").mkdir(exist_ok=True)
        cfg = SimpleNamespace(
            reversed_dir=tmp_path / "src",
            target_binary=bin_path,
            target_name="T",
            compiler_command="cl",
            base_cflags="/nologo /c /MT",
            compiler_includes=tmp_path / "inc",
            compiler_libs=tmp_path / "lib",
        )
        cache_path = tmp_path / "verify_cache.json"
        cache = verify_cache_mod.VerifyCache(
            version=2,
            compiler_hash=verify_hash_mod._compiler_config_hash(cfg),
            headers_hash=verify_hash_mod._headers_hash(cfg),
            target="T",
            binary_id=verify_cache_mod._binary_id(cfg),
            entries={},
        )
        cache_path.write_text(_json.dumps(cache.to_dict()))
        assert verify_cache_mod._load_verify_cache(cache_path, cfg) is not None

        # Same target name, different binary bytes → cache must be rejected.
        bin_path.write_bytes(b"MZ2")
        assert verify_cache_mod._load_verify_cache(cache_path, cfg) is None

        # Legacy caches (no binary_id) stay accepted.
        cache.binary_id = ""
        cache_path.write_text(_json.dumps(cache.to_dict()))
        assert verify_cache_mod._load_verify_cache(cache_path, cfg) is not None


def test_verify_entry_survives_a_raising_logger(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A failing log call inside a best-effort block must not fail the entry.

    Regression: the diff_lines/similarity handlers logged ``result.va``, an
    attribute ``CompareResult`` does not have, so every function that reached
    those blocks raised out of a guard whose entire purpose is to swallow
    failures.  ``rebrew verify --full`` reported 31/283 instead of 281/283 on
    a tree with no source change.  Best-effort has to include its own
    diagnostics.
    """
    from rebrew.compile import CompareResult

    result = CompareResult(
        matched=False,
        status="NEAR_MATCHING",
        match_percent=50.0,
        delta=4,
        obj_bytes=b"\x90\x90\x90\x90",
        reloc_offsets=[],
    )

    import rebrew.binary_loader as bl_mod
    import rebrew.compile as compile_mod

    monkeypatch.setattr(compile_mod, "compile_and_compare", lambda *a, **k: result)
    monkeypatch.setattr(bl_mod, "extract_raw_bytes", lambda *a, **k: b"\x90\x90\x90\x91")

    def _raising_debug(*_a: object, **_k: object) -> None:
        raise AttributeError("'CompareResult' object has no attribute 'va'")

    monkeypatch.setattr(verify_mod.log, "debug", _raising_debug)

    # Force both best-effort blocks to enter their handlers.
    import rebrew.matcher as matcher_mod

    def _boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("disassembly unavailable")

    monkeypatch.setattr(matcher_mod, "diff_functions", _boom, raising=False)
    monkeypatch.setattr(matcher_mod, "code_similarity", _boom, raising=False)

    cfg = _cfg(tmp_path)
    cfg.arch = "x86_32"
    cfg.cflags = ""
    cfg.toolchain = None
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "src" / "f.c").write_text("void f1000(void) {}\n")

    out = verify_mod.verify_entry(_ann(0x1000), cfg)  # must not raise
    assert out.diff_lines is None
    assert out.similarity is None


def test_byte_match_counts_excludes_proven() -> None:
    """PROVEN must never be counted as a byte match.

    Regression: the verify summary printed only `passed/total`, and `passed`
    folds PROVEN in with EXACT/RELOC.  For a byte-identical goal that number is
    wrong twice over -- it overstates progress, and a RELOC -> PROVEN
    regression leaves it unchanged while the deliverable loses bytes.  The JSON
    always exposed `summary.byte_matched`; the human line now does too, via
    this helper.
    """
    from rebrew.verify import byte_match_counts

    results = [
        {"status": "EXACT"},
        {"status": "RELOC"},
        {"status": "RELOC"},
        {"status": "PROVEN"},
        {"status": "PROVEN"},
        {"status": "STUB"},
        {"status": "NEAR_MATCHING"},
    ]
    assert byte_match_counts(results) == (3, 2)

    # A RELOC -> PROVEN regression must move the byte-match count down even
    # though `passed` would not change.
    regressed = [dict(r) for r in results]
    regressed[1]["status"] = "PROVEN"
    assert byte_match_counts(regressed) == (2, 3)

    assert byte_match_counts([]) == (0, 0)


def test_scope_entries_batch_file_filters_to_file(tmp_path: Path) -> None:
    """Single-file scope keeps only that file's annotations."""
    from types import SimpleNamespace

    from rebrew.annotation import Annotation
    from rebrew.verify import _scope_entries

    rev = tmp_path / "src"
    rev.mkdir()
    (rev / "a.c").write_text("x", encoding="utf-8")
    (rev / "b.c").write_text("x", encoding="utf-8")

    def _ann(path: str, va: int) -> Annotation:
        return Annotation(va=va, name="f", filepath=path, module="T")

    cfg = SimpleNamespace(reversed_dir=rev, root=tmp_path)
    entries = [_ann("a.c", 0x1000), _ann("b.c", 0x2000)]
    scoped, total, *_rest = _scope_entries(
        entries, (0, 0, [], [], 0), ([], []), batch_file="a.c", cfg=cfg
    )
    assert total == 1
    assert [e.va for e in scoped] == [0x1000]


def test_scope_entries_batch_file_empty_errors(tmp_path: Path) -> None:
    """An empty file scope is an error, never a silent green gate."""
    from types import SimpleNamespace

    import typer

    from rebrew.annotation import Annotation
    from rebrew.verify import _scope_entries

    rev = tmp_path / "src"
    rev.mkdir()
    cfg = SimpleNamespace(reversed_dir=rev, root=tmp_path)
    with pytest.raises(typer.Exit):
        _scope_entries(
            [Annotation(va=0x1000, name="f", filepath="a.c", module="T")],
            (0, 0, [], [], 0),
            ([], []),
            batch_file="missing.c",
            cfg=cfg,
        )


def test_fix_sizes_never_rewrites_a_byte_matched_size() -> None:
    """A size that already produces a match is evidence, not a defect.

    Regression: --fix-sizes applied every size divergence, taking heuristic
    discovery as authority.  But discovery merges adjacent functions when the
    only boundary is `ret` plus padding, and counts trailing jump tables the
    body excludes -- so it under-counts and over-counts byte-matched entries
    alike.  One run on guild-rebrew rewrote 13 sizes and dropped byte-matched
    functions from 264 to 252.

    _skip_validated_overcount already covered over-counts; the under-count
    direction (the jump-table case, e.g. vfs_OpenStream body 667 against a
    canonical 704) was applied automatically and is what did the damage.
    """
    from rebrew.verify import _partition_size_fixes

    fixes = [
        {"va": "0x1000cfe0", "annotation_size": 64, "binary_size": 96, "status": "RELOC"},
        {"va": "0x10009020", "annotation_size": 667, "binary_size": 704, "status": "PROVEN"},
        {"va": "0x10001000", "annotation_size": 10, "binary_size": 40, "status": "EXACT"},
        {"va": "0x10002000", "annotation_size": 0, "binary_size": 110, "status": "MISSING_SIZE"},
        {"va": "0x10003000", "annotation_size": 20, "binary_size": 80, "status": "STUB"},
    ]
    appliable, protected = _partition_size_fixes(fixes)

    # The three matched/proven entries are kept; only genuinely unverified
    # sizes may be rewritten.
    assert {f["va"] for f in protected} == {"0x1000cfe0", "0x10009020", "0x10001000"}
    assert {f["va"] for f in appliable} == {"0x10002000", "0x10003000"}

    # No protected entries means the list passes through untouched.
    plain = [{"va": "0x10004000", "annotation_size": 0, "binary_size": 8, "status": "STUB"}]
    assert _partition_size_fixes(plain) == (plain, [])
