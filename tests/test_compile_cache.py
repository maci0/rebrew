"""Tests for rebrew.compile_cache — CompileCache, key builder, module-level registry."""

import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from rebrew.compile_cache import (
    CACHE_SCHEMA_VERSION,
    DEFAULT_CACHE_BACKEND,
    CompileCache,
    close_all_caches,
    compile_cache_key,
    dir_fingerprint_hash,
    get_compile_cache,
    get_project_cache,
    header_dependency_hash,
    include_fingerprint,
)
from rebrew.config import ProjectConfig


class TestCompileCache:
    def test_put_get(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        cache.put("k1", b"\x55\x8b\xec")
        assert cache.get("k1") == b"\x55\x8b\xec"
        cache.close()

    def test_get_missing(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        assert cache.get("nonexistent") is None
        cache.close()

    def test_overwrite(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        cache.put("k", b"\x01")
        cache.put("k", b"\x02")
        assert cache.get("k") == b"\x02"
        cache.close()

    def test_clear(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        cache.put("a", b"\x01")
        cache.put("b", b"\x02")
        assert cache.count == 2
        cache.clear()
        assert cache.count == 0
        assert cache.get("a") is None
        cache.close()

    def test_stats(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        cache.put("k", b"\x55" * 100)
        info = cache.stats()
        assert info["entries"] == 1
        assert info["volume_bytes"] > 0
        # Binary, not decimal: a 1 MiB footprint reports 1.0, not 0.95.
        assert info["volume_mib"] == round(info["volume_bytes"] / (1024 * 1024), 2)
        assert "size_limit_mib" in info
        cache.close()

    def test_type_safety_returns_none_for_non_bytes(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        cache._cache.set("bad", "not bytes")
        assert cache.get("bad") is None
        cache.close()

    def test_close_resets_cache_and_degrades(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        cache.close()
        assert cache._cache is None
        assert cache.get("k") is None
        cache.put("k", b"val")
        assert cache.count == 0

    def test_get_compile_cache_reopens_after_close(self, tmp_path: Path) -> None:
        c1 = get_compile_cache(tmp_path)
        c1.close()
        c2 = get_compile_cache(tmp_path)
        assert c2 is not c1
        assert c2._cache is not None
        c2.close()

    def test_close_waits_for_inflight_lookup(self, tmp_path: Path) -> None:
        """close() must not tear the SQLite handle down under a live get().

        One CompileCache is shared by every GA and sweep worker for the length
        of a run, and the LRU eviction in get_compile_cache closes the oldest
        backend once _CACHES_MAX project roots are open. With one root per
        target (``match --all-targets``) that eviction lands inside another
        target's lookup. Without the store lock the worker reads a closed
        connection, and a failed lookup degrades to a miss by design, so the
        hit is silently lost.
        """
        import threading

        cache = CompileCache(tmp_path / "cc")
        cache.put("k", b"\x55\x8b\xec")
        store = cache._cache
        assert store is not None

        in_get = threading.Event()
        release = threading.Event()
        real_get = store.get

        def _blocking_get(key: str, default: object = None) -> object:
            in_get.set()
            assert release.wait(10.0), "test thread never released the lookup"
            return real_get(key, default=default)

        store.get = _blocking_get  # type: ignore[method-assign]
        got: list[bytes | None] = []
        reader = threading.Thread(target=lambda: got.append(cache.get("k")), daemon=True)
        reader.start()
        assert in_get.wait(10.0), "get() never entered the store"

        closed = threading.Event()

        def _close() -> None:
            cache.close()
            closed.set()

        closer = threading.Thread(target=_close, daemon=True)
        closer.start()
        # close() must block until the in-flight lookup is done.
        assert not closed.wait(0.2), "close() tore down the store under a live get()"

        release.set()
        reader.join(10.0)
        closer.join(10.0)
        assert not reader.is_alive()
        assert not closer.is_alive()
        # The lookup still saw its entry, and the close still took effect.
        assert got == [b"\x55\x8b\xec"]
        assert closed.is_set()
        assert cache._cache is None


class TestCompileCacheKey:
    def test_source_digest_memo_evicts_by_retained_bytes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The digest memo is bounded by source bytes, not entry count.

        One entry pins a whole source body, so a full-tree run would keep
        every source it ever keyed resident.
        """
        import rebrew.compile_cache as cc

        monkeypatch.setattr(cc, "_SOURCE_DIGEST_MAX_BYTES", 4096)
        cc.clear_source_digest_memo()
        for i in range(6):
            assert len(cc.source_digest(f"int f{i}(void){{return {i};}}" + "/* x */" * 200)) == 64
        assert cc._SOURCE_DIGEST_BYTES <= 4096
        # The newest source is still memoized (one repeat read is free).
        assert len(cc._source_digest_memo) < 6
        cc.clear_source_digest_memo()
        assert cc._source_digest_memo == {}

    @pytest.mark.parametrize(
        "field", ["source_filename", "source_ext", "cflags", "include_dirs", "toolchain_id"]
    )
    def test_surrogateescaped_inputs_remain_distinct(self, field: str) -> None:
        inputs: dict[str, Any] = {
            "source_content": "int f(void){return 1;}",
            "source_filename": "f.c",
            "cflags": [],
            "include_dirs": [],
            "toolchain_id": "cc",
        }
        keys = []
        for name in ["legacy_\udce9", "legacy_\udcea", "legacy_é", "legacy_�"]:
            inputs[field] = [name] if field in {"cflags", "include_dirs"} else name
            key = compile_cache_key(**inputs)
            assert compile_cache_key(**inputs) == key
            keys.append(key)
        assert len(set(keys)) == len(keys)

    def test_deterministic(self) -> None:
        k1 = compile_cache_key("int f(){return 1;}", "f.c", ["/O2"], ["/inc"], "wine CL")
        k2 = compile_cache_key("int f(){return 1;}", "f.c", ["/O2"], ["/inc"], "wine CL")
        assert k1 == k2

    def test_different_source_different_key(self) -> None:
        k1 = compile_cache_key("int f(){return 1;}", "f.c", ["/O2"], ["/inc"], "wine CL")
        k2 = compile_cache_key("int f(){return 2;}", "f.c", ["/O2"], ["/inc"], "wine CL")
        assert k1 != k2

    def test_different_flags_different_key(self) -> None:
        k1 = compile_cache_key("int f(){return 1;}", "f.c", ["/O2"], ["/inc"], "wine CL")
        k2 = compile_cache_key("int f(){return 1;}", "f.c", ["/O1"], ["/inc"], "wine CL")
        assert k1 != k2

    def test_different_filename_different_key(self) -> None:
        k1 = compile_cache_key("int f(){return 1;}", "a.c", ["/O2"], ["/inc"], "wine CL")
        k2 = compile_cache_key("int f(){return 1;}", "b.c", ["/O2"], ["/inc"], "wine CL")
        assert k1 != k2

    def test_different_toolchain_different_key(self) -> None:
        k1 = compile_cache_key("int f(){return 1;}", "f.c", ["/O2"], ["/inc"], "wine CL")
        k2 = compile_cache_key("int f(){return 1;}", "f.c", ["/O2"], ["/inc"], "wibo CL")
        assert k1 != k2

    def test_different_include_dirs_different_key(self) -> None:
        k1 = compile_cache_key("int f(){return 1;}", "f.c", ["/O2"], ["/inc1"], "wine CL")
        k2 = compile_cache_key("int f(){return 1;}", "f.c", ["/O2"], ["/inc2"], "wine CL")
        assert k1 != k2

    def test_legacy_encoded_source_does_not_crash(self) -> None:
        """A cp1252/shift_jis source (decoded with surrogateescape, as
        read_compile_source does) must hash losslessly — the strict utf-8
        encode previously raised UnicodeEncodeError, which compile_and_compare
        mislabeled as COMPILE_ERROR, making legacy-encoded sources
        permanently untestable."""
        src = b"void f(void){int x=\x93;}\n".decode("utf-8", "surrogateescape")
        k1 = compile_cache_key(src, "f.c", ["/O2"], ["/inc"], "wine CL")
        k2 = compile_cache_key(src, "f.c", ["/O2"], ["/inc"], "wine CL")
        assert k1 == k2  # deterministic
        # Round-trip: the same bytes decoded the same way produce the same key
        again = b"void f(void){int x=\x93;}\n".decode("utf-8", "surrogateescape")
        assert compile_cache_key(again, "f.c", ["/O2"], ["/inc"], "wine CL") == k1

    def test_different_source_ext_different_key(self) -> None:
        k1 = compile_cache_key("int f(){return 1;}", "f.c", ["/O2"], ["/inc"], "wine CL", ".c")
        k2 = compile_cache_key("int f(){return 1;}", "f.c", ["/O2"], ["/inc"], "wine CL", ".cpp")
        assert k1 != k2

    def test_flag_order_insensitive_classes_same_key(self) -> None:
        """Flags setting distinct compiler options commute — /O2 and /Gd are
        different options, so their order cannot change the object."""
        k1 = compile_cache_key("src", "f.c", ["/O2", "/Gd"], ["/inc"], "wine CL")
        k2 = compile_cache_key("src", "f.c", ["/Gd", "/O2"], ["/inc"], "wine CL")
        assert k1 == k2

    def test_last_wins_flags_keep_order(self) -> None:
        """/O1 /O2 and /O2 /O1 compile differently (the last wins) — order
        within an option group must still separate the keys."""
        k1 = compile_cache_key("src", "f.c", ["/O1", "/O2"], ["/inc"], "wine CL")
        k2 = compile_cache_key("src", "f.c", ["/O2", "/O1"], ["/inc"], "wine CL")
        assert k1 != k2

    def test_duplicate_flags_same_key(self) -> None:
        k1 = compile_cache_key("src", "f.c", ["/O2", "/O2"], ["/inc"], "wine CL")
        k2 = compile_cache_key("src", "f.c", ["/O2"], ["/inc"], "wine CL")
        assert k1 == k2

    def test_group_collapses_to_last_occurrence(self) -> None:
        """Within one option group only the last occurrence matters."""
        k1 = compile_cache_key("src", "f.c", ["/O1", "/O2"], ["/inc"], "wine CL")
        k2 = compile_cache_key("src", "f.c", ["/O2"], ["/inc"], "wine CL")
        assert k1 == k2

    def test_repeated_group_flag_keeps_last_occurrence(self) -> None:
        """/O1 /O2 /O1 compiles as /O1: a keep-first dedupe would key it as /O2."""
        k1 = compile_cache_key("src", "f.c", ["/O1", "/O2", "/O1"], ["/inc"], "wine CL")
        k2 = compile_cache_key("src", "f.c", ["/O1"], ["/inc"], "wine CL")
        k3 = compile_cache_key("src", "f.c", ["/O2"], ["/inc"], "wine CL")
        assert k1 == k2
        assert k1 != k3

    def test_repeated_unknown_flag_not_deduped(self) -> None:
        """Unknown tokens are not idempotent: -O2 -O0 -O2 builds at -O2, and
        /D A /D B defines B where /D A B does not."""
        k1 = compile_cache_key("src", "f.c", ["-O2", "-O0", "-O2"], ["/inc"], "gcc")
        k2 = compile_cache_key("src", "f.c", ["-O2", "-O0"], ["/inc"], "gcc")
        assert k1 != k2
        k3 = compile_cache_key("src", "f.c", ["/D", "A", "/D", "B"], ["/inc"], "wine CL")
        k4 = compile_cache_key("src", "f.c", ["/D", "A", "B"], ["/inc"], "wine CL")
        assert k3 != k4

    def test_unknown_flag_order_preserved(self) -> None:
        """A flag outside the synced definitions is an anchor: reordering it
        against a known flag could change compilation, so it must not."""
        k1 = compile_cache_key("src", "f.c", ["/O2", "/custom"], ["/inc"], "wine CL")
        k2 = compile_cache_key("src", "f.c", ["/custom", "/O2"], ["/inc"], "wine CL")
        assert k1 != k2

    def test_include_dir_flag_order_preserved(self) -> None:
        """/I flags set the include search order — never canonicalized."""
        k1 = compile_cache_key("src", "f.c", ["/Iinc1", "/Iinc2"], ["/inc"], "wine CL")
        k2 = compile_cache_key("src", "f.c", ["/Iinc2", "/Iinc1"], ["/inc"], "wine CL")
        assert k1 != k2

    def test_default_rebrew_flags_canonicalize(self) -> None:
        """The everyday flag set (/O2 /Gd /MT) canonicalizes to one key
        regardless of input order — flag sweeps and repeated compiles share
        entries."""
        flags_a = ["/O2", "/Gd", "/MT"]
        flags_b = ["/MT", "/Gd", "/O2"]
        k1 = compile_cache_key("src", "f.c", flags_a, ["/inc"], "wine CL")
        k2 = compile_cache_key("src", "f.c", flags_b, ["/inc"], "wine CL")
        assert k1 == k2

    def test_returns_hex_string(self) -> None:
        key = compile_cache_key("src", "f.c", ["/O2"], ["/inc"], "wine CL")
        assert len(key) == 64
        int(key, 16)  # validates hex

    def test_schema_version_in_key(self, monkeypatch) -> None:
        k1 = compile_cache_key("src", "f.c", ["/O2"], ["/inc"], "wine CL")
        assert isinstance(k1, str)
        # Changing the schema version must produce a different cache key,
        # proving the version is incorporated into the hash.
        import rebrew.compile_cache as cc_mod

        monkeypatch.setattr(cc_mod, "CACHE_SCHEMA_VERSION", CACHE_SCHEMA_VERSION + 1)
        k2 = compile_cache_key("src", "f.c", ["/O2"], ["/inc"], "wine CL")
        assert k1 != k2


class TestIncludeFingerprint:
    @pytest.mark.parametrize("name", ["café.h", "cafe\u0301.h", "legacy_\udce9.h"])
    def test_non_ascii_filename_is_stable(self, tmp_path: Path, name: str) -> None:
        if os.name != "posix" and "\udce9" in name:
            pytest.skip("Byte filenames require a POSIX filesystem")
        header = tmp_path / name
        header.write_bytes(b"#define N 1\n")
        first = include_fingerprint(str(tmp_path))
        include_fingerprint.cache_clear()
        assert len(first) == 64
        assert include_fingerprint(str(tmp_path)) == first
        header.rename(tmp_path / "other.h")
        include_fingerprint.cache_clear()
        assert include_fingerprint(str(tmp_path)) != first

    def test_header_edit_visible_without_cache_clear(self, tmp_path: Path) -> None:
        """Content edits must change the digest mid-process without cache_clear.

        The path list is memoized, but each call re-stats listed headers — a
        size/mtime change on an existing header must invalidate compile keys
        that fall back to whole-directory fingerprints.
        """
        inc = tmp_path / "inc"
        inc.mkdir()
        header = inc / "library_foo.h"
        header.write_text("#define N 1\n")
        include_fingerprint.cache_clear()
        first = include_fingerprint(str(inc))
        header.write_text("#define N 22222\n")
        assert include_fingerprint(str(inc)) != first

    def test_new_header_visible_without_cache_clear(self, tmp_path: Path) -> None:
        """Creating a header mid-run must change the digest (dir mtime bump)."""
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("x\n")
        include_fingerprint.cache_clear()
        first = include_fingerprint(str(inc))
        (inc / "b.h").write_text("y\n")
        assert include_fingerprint(str(inc)) != first

    def test_new_header_in_subdir_tracked_without_cache_clear(self, tmp_path: Path) -> None:
        """A header created under a subdirectory leaves the root mtime alone.

        It must still join the memoized path list, so later edits to it change
        the digest instead of serving objects compiled against the old header.
        """
        inc = tmp_path / "inc"
        (inc / "sys").mkdir(parents=True)
        (inc / "a.h").write_text("x\n")
        include_fingerprint.cache_clear()
        include_fingerprint(str(inc))
        new = inc / "sys" / "types.h"
        new.write_text("y\n")
        second = include_fingerprint(str(inc))
        new.write_text("yyyy\n")
        assert include_fingerprint(str(inc)) != second

    def test_missing_dir_is_empty(self, tmp_path: Path) -> None:
        assert include_fingerprint(str(tmp_path / "nope")) == ""

    def test_unstatable_header_is_not_a_missing_header(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A header that cannot be stat'd must not hash like one that is absent.

        The path list is memoized while directory mtimes hold.  Skipping the
        failed stat made that digest identical to the tree from before the
        header existed, so the compile cache could reuse that object.
        """
        inc = tmp_path / "inc"
        only = tmp_path / "only"
        inc.mkdir()
        only.mkdir()
        (inc / "a.h").write_text("a\n")
        (inc / "b.h").write_text("b\n")
        (only / "a.h").write_text("a\n")
        include_fingerprint.cache_clear()
        both = include_fingerprint(str(inc))
        missing = include_fingerprint(str(only))
        assert both != missing
        real_stat = Path.stat

        def _stat(self: Path, *args: object, **kwargs: object) -> Any:
            if self.name == "b.h":
                raise OSError(13, "Permission denied")
            return real_stat(self, *args, **kwargs)

        monkeypatch.setattr(Path, "stat", _stat)
        unreadable = include_fingerprint(str(inc))
        assert unreadable != both
        assert unreadable != missing

    def test_unreadable_dir_is_not_empty_fingerprint(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """An OSError mid-walk must not collapse to ``""`` (missing-dir).

        That collision dropped header deps from the cache key and could serve
        a stale object after the tree became readable again.
        """
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("x\n")
        include_fingerprint.cache_clear()

        def _boom(*_a: object, **_kw: object) -> list[Path]:
            raise OSError(13, "Permission denied")

        monkeypatch.setattr(Path, "rglob", _boom)
        fp = include_fingerprint(str(inc))
        assert fp != ""
        assert len(fp) == 64  # sha256 hex

    def test_unstattable_dir_is_not_empty_fingerprint(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A dir that exists but cannot be stat'd must not read as missing."""
        inc = tmp_path / "inc"
        inc.mkdir()
        include_fingerprint.cache_clear()

        def _boom(*_a: object, **_kw: object) -> Any:
            raise OSError(13, "Permission denied")

        monkeypatch.setattr(Path, "is_dir", lambda _self: True)
        monkeypatch.setattr(Path, "stat", _boom)
        fp = include_fingerprint(str(inc))
        assert fp != ""
        assert len(fp) == 64  # sha256 hex

    def test_header_edit_changes_key(self, tmp_path: Path) -> None:
        inc = tmp_path / "inc"
        inc.mkdir()
        header = inc / "library_foo.h"
        header.write_text("#define N 1\n")
        src = "#include <library_foo.h>\nint f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        header.write_text("#define N 22222\n")  # different size => different stat
        k2 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")
        assert k1 != k2

    def test_non_header_files_ignored(self, tmp_path: Path) -> None:
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("x")
        include_fingerprint.cache_clear()
        k1 = compile_cache_key("src", "f.c", ["/O2"], [str(inc)], "wine CL")

        (inc / "unrelated.c").write_text("int main(void){return 0;}")
        include_fingerprint.cache_clear()
        k2 = compile_cache_key("src", "f.c", ["/O2"], [str(inc)], "wine CL")
        assert k1 == k2

    def test_unstable_walk_is_not_memoized(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A walk that races a directory change must not be published.

        Publishing it would pin a path list under mtimes that no longer
        describe it, and the next lookup would trust the stale list.
        """
        import rebrew.compile_cache as cc

        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("x\n")
        include_fingerprint.cache_clear()
        monkeypatch.setattr(cc, "_dir_mtimes_match", lambda _mtimes: False)
        assert include_fingerprint(str(inc))
        assert cc._INCLUDE_FP_PATHS == {}

    def test_concurrent_fingerprint_agrees(self, tmp_path: Path) -> None:
        """Parallel fills share the path memo and must not raise or diverge."""
        import threading

        from thread_util import join_all

        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("x\n")
        (inc / "sys").mkdir()
        (inc / "sys" / "types.h").write_text("y\n")
        include_fingerprint.cache_clear()
        errors: list[BaseException] = []
        digests: list[str] = []
        lock = threading.Lock()

        def _worker() -> None:
            try:
                local = [include_fingerprint(str(inc)) for _ in range(16)]
                with lock:
                    digests.extend(local)
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker, daemon=True) for _ in range(8)]
        for thread in threads:
            thread.start()
        join_all(threads)
        assert errors == []
        assert digests
        assert all(digest == digests[0] for digest in digests)


class TestHeaderDependencyHash:
    """Per-source #include-closure fingerprints (paper-driven precision).

    The v4 key tracks each translation unit's *reached* headers instead of a
    whole-directory fingerprint: editing a header invalidates exactly the
    entries that include it, and an edit to an unreached header is a hit.
    """

    @pytest.mark.skipif(os.name != "posix", reason="Byte filenames require a POSIX filesystem")
    @pytest.mark.parametrize("directive", ['#include "legacy_\udce9.h"', "#include LIB_H"])
    def test_byte_filename_dependency_changes_key(self, tmp_path: Path, directive: str) -> None:
        header = tmp_path / "legacy_\udce9.h"
        header.write_bytes(b"#define N 1\n")
        source = directive + "\nint f(void){return N;}\n"
        first = compile_cache_key(source, "f.c", [], [str(tmp_path)], "cc")
        assert compile_cache_key(source, "f.c", [], [str(tmp_path)], "cc") == first
        header.write_bytes(b"#define N 22222\n")
        include_fingerprint.cache_clear()
        assert compile_cache_key(source, "f.c", [], [str(tmp_path)], "cc") != first

    def test_parent_relative_include_changes_key(self, tmp_path: Path) -> None:
        """`#include "../shared/types.h"` reaches outside the /I dirs.  The
        compiler resolves it, so an edit to it must invalidate the entry."""
        (tmp_path / "shared").mkdir()
        (tmp_path / "shared" / "types.h").write_text("#define N 1\n", encoding="utf-8")
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        source = '#include "../shared/types.h"\nint f(void){return N;}\n'
        first = header_dependency_hash(source, str(src_dir), [str(src_dir)])
        (tmp_path / "shared" / "types.h").write_text("#define N 22222\n", encoding="utf-8")
        assert header_dependency_hash(source, str(src_dir), [str(src_dir)]) != first

    def test_unresolvable_parent_include_falls_back(self, tmp_path: Path) -> None:
        """A traversal include that resolves nowhere cannot be pinned, so the
        key falls back to the conservative directory fingerprint."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        source = '#include "../nowhere/types.h"\nint f(void){return 1;}\n'
        include_dirs = [str(src_dir)]
        assert header_dependency_hash(source, str(src_dir), include_dirs) == (
            dir_fingerprint_hash(str(src_dir), include_dirs)
        )

    def test_no_includes_is_fixed_digest(self) -> None:
        """A unit with no header deps gets a stable, non-empty digest ("" is
        reserved by the verify cache for legacy entries)."""
        d = header_dependency_hash("int f(void){return 1;}", None, ["/inc"])
        assert len(d) == 64
        int(d, 16)  # hex
        assert header_dependency_hash("int g(void){return 2;}", None, ["/inc"]) == d

    def test_unreadable_reached_header_changes_key(self, tmp_path: Path) -> None:
        """A reached header that cannot be stat'ed must still move the key.

        Dropping it made the closure identical to one without that header, so
        the cached .obj was served against a different include set.
        """
        from rebrew.compile_cache import _header_key_entries

        inc = tmp_path / "inc"
        inc.mkdir()
        header = inc / "a.h"
        header.write_text("typedef int A;\n")
        good = _header_key_entries((str(header),), None, [str(inc)])
        st = header.stat()
        assert good == [(0, "a.h", st.st_size, st.st_mtime_ns, st.st_ino)]

        real_stat = Path.stat

        def _fail(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
            if self.name == "a.h":
                raise OSError("simulated stat failure")
            return real_stat(self, follow_symlinks=follow_symlinks)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(Path, "stat", _fail)
            unreadable = _header_key_entries((str(header),), None, [str(inc)])
        assert unreadable == [(0, "a.h", -1, -1, -1)]
        assert unreadable != good

    def test_unreached_header_edit_keeps_key(self, tmp_path: Path) -> None:
        """THE precision win: only reached headers shape the key."""
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("typedef int A;\n")
        (inc / "b.h").write_text("typedef int B;\n")
        src = "#include <a.h>\nint f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        (inc / "b.h").write_text("typedef long B;\n")
        k2 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")
        assert k1 == k2

    def test_shared_header_digest_is_built_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Two sources that reach one header build the digest once, until it changes."""
        import rebrew.compile_cache as compile_cache

        inc = tmp_path / "inc"
        inc.mkdir()
        header = inc / "a.h"
        header.write_text("typedef int A;\n", encoding="utf-8")
        calls = {"n": 0}
        real = compile_cache._header_key_entries

        def _counting(
            paths: tuple[str, ...], source_dir: str | None, include_dirs: list[str]
        ) -> list[tuple[int, str, int, int, int]]:
            calls["n"] += 1
            return real(paths, source_dir, include_dirs)

        monkeypatch.setattr(compile_cache, "_header_key_entries", _counting)
        dirs = [str(inc)]
        src_a = "#include <a.h>\nint fa(void){return 1;}\n"
        src_b = "#include <a.h>\nint fb(void){return 2;}\n"
        first = header_dependency_hash(src_a, None, dirs)
        assert calls["n"] == 1
        assert header_dependency_hash(src_b, None, dirs) == first
        assert calls["n"] == 1

        stat = header.stat()
        os.utime(header, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
        assert header_dependency_hash(src_a, None, dirs) != first
        assert calls["n"] == 2

        real_b = tmp_path / "b"
        real_b.mkdir()
        (real_b / "a.h").write_text("typedef int B;\n", encoding="utf-8")
        link = tmp_path / "link"
        link.symlink_to(inc, target_is_directory=True)
        linked = header_dependency_hash(src_a, None, [str(link)])
        held = calls["n"]
        assert header_dependency_hash(src_b, None, [str(link)]) == linked
        assert calls["n"] == held
        link.unlink()
        link.symlink_to(real_b, target_is_directory=True)
        assert header_dependency_hash(src_a, None, [str(link)]) != linked
        assert calls["n"] == held + 1

    def test_repeated_search_dir_is_stat_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The source directory is also an include dir. One stat fills both slots."""
        from rebrew.compile_cache import _search_dir_mtimes

        directory = str(tmp_path)
        other = tmp_path / "inc"
        other.mkdir()
        missing = str(tmp_path / "nope")
        calls: list[str] = []
        real = os.stat

        def counting(
            path: str | os.PathLike[str], *args: object, **kwargs: object
        ) -> os.stat_result:
            calls.append(os.fspath(path))
            return real(path, *args, **kwargs)  # type: ignore[arg-type]

        def refuse(self: Path, *_args: object, **_kwargs: object) -> os.stat_result:
            raise AssertionError("Path.stat")

        monkeypatch.setattr(os, "stat", counting)
        monkeypatch.setattr(Path, "stat", refuse)
        mtime = real(directory).st_mtime_ns
        assert _search_dir_mtimes(directory, (directory,)) == (mtime, mtime)
        assert calls == [directory]

        calls.clear()
        other_mtime = real(other).st_mtime_ns
        assert _search_dir_mtimes(directory, (str(other),)) == (mtime, other_mtime)
        assert calls == [directory, str(other)]

        calls.clear()
        assert _search_dir_mtimes(missing, (missing,)) == (0, 0)
        assert calls == [missing]

    def test_reached_header_edit_changes_key(self, tmp_path: Path) -> None:
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("typedef int A;\n")
        src = "#include <a.h>\nint f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        (inc / "a.h").write_text("typedef long A;\n")
        k2 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")
        assert k1 != k2

    def test_same_size_rename_over_header_changes_key(self, tmp_path: Path) -> None:
        """A header replaced by an equal-length rename-over must invalidate.

        An editor's atomic save, a ``cp -p``, and a coarse-timestamp
        filesystem all swap a header without moving mtime_ns or its size;
        the inode is the only part of the fingerprint that moves.
        """
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("typedef int A;\n")
        src = "#include <a.h>\nint f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        # A true rename-over (what atomic_write_text and an editor's save
        # do): same byte length, restored mtime, new inode.
        st = (inc / "a.h").stat()
        tmp = inc / "a.h.tmp"
        tmp.write_text("typedef long A\n")
        os.utime(tmp, ns=(st.st_atime_ns, st.st_mtime_ns))
        os.replace(tmp, inc / "a.h")
        assert (inc / "a.h").stat().st_size == st.st_size
        k2 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")
        assert k1 != k2

    def test_nested_header_dependency(self, tmp_path: Path) -> None:
        """An edit to a header included transitively must invalidate."""
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("#include <b.h>\n#define A 1\n")
        (inc / "b.h").write_text("#define B 1\n")
        src = "#include <a.h>\nint f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        (inc / "b.h").write_text("#define B 2\n")
        k2 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")
        assert k1 != k2

    def test_in_place_header_edit_adding_include_tracks_new_dep(self, tmp_path: Path) -> None:
        """An in-place edit that adds an ``#include`` extends the closure.

        Rewriting ``a.h`` in place leaves the directory mtime unchanged, so
        the resolution memo must still notice the new ``b.h`` dependency;
        otherwise a later ``b.h`` edit keeps the old key (stale ``.obj`` hit).
        """
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("#define A 1\n")
        (inc / "b.h").write_text("#define B 1\n")
        dir_mtime = inc.stat().st_mtime_ns
        src = "#include <a.h>\nint f(void){return 1;}\n"
        compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        with (inc / "a.h").open("w") as f:
            f.write("#include <b.h>\n#define A 1\n")
        os.utime(inc, ns=(dir_mtime, dir_mtime))
        k1 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        (inc / "b.h").write_text("#define B 2 /* longer */\n")
        os.utime(inc, ns=(dir_mtime, dir_mtime))
        k2 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")
        assert k1 != k2

    def test_quote_include_from_source_dir(self, tmp_path: Path) -> None:
        """A quote include next to the source is tracked via source_dir."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "local.h").write_text("#define L 1\n")
        src = '#include "local.h"\nint f(void){return 1;}\n'
        k1 = compile_cache_key(src, "f.c", ["/O2"], [], "wine CL", source_dir=str(src_dir))

        (src_dir / "local.h").write_text("#define L 2\n")
        k2 = compile_cache_key(src, "f.c", ["/O2"], [], "wine CL", source_dir=str(src_dir))
        assert k1 != k2

    def test_created_header_changes_key_for_reacher(self, tmp_path: Path) -> None:
        """A header created later in a searched dir changes the resolved set.

        Directory mtimes participate in the resolution memo key, so membership
        changes are visible mid-process without an explicit ``cache_clear``.
        """
        inc = tmp_path / "inc"
        inc.mkdir()
        src = "#include <new.h>\nint f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        (inc / "new.h").write_text("#define N 1\n")
        k2 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")
        assert k1 != k2

    def test_unreadable_reached_header_falls_back(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A reached header that cannot be read must not drop its includes.

        Hashing only that header's stat (the closure stops at the failed
        read) stays stable when an included header changes, and the cache
        then serves an object compiled against the old text.
        """
        import rebrew.compile_cache as cc

        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text('#include "b.h"\n', encoding="utf-8")
        (inc / "b.h").write_text("typedef int B;\n", encoding="utf-8")
        src = '#include "a.h"\nint f(void){return 1;}\n'
        real_read = Path.read_bytes

        def _read(self: Path) -> bytes:
            if self.name == "a.h":
                raise OSError(13, "Permission denied")
            return real_read(self)

        monkeypatch.setattr(Path, "read_bytes", _read)
        cc._INCLUDE_CLOSURE_MEMO.clear()
        include_fingerprint.cache_clear()
        first = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "cc")
        (inc / "b.h").write_text("typedef long B;\n", encoding="utf-8")
        include_fingerprint.cache_clear()
        second = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "cc")
        assert first != second

    def test_missing_include_no_crash(self) -> None:
        """An include that resolves nowhere (CRT headers live inside the
        immutable toolchain image) is left untracked — no crash, stable key."""
        src = "#include <nonexistent.h>\nint f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2"], ["/nope"], "wine CL")
        k2 = compile_cache_key(src, "f.c", ["/O2"], ["/nope"], "wine CL")
        assert k1 == k2

    def test_case_and_nfd_header_resolution(self, tmp_path: Path) -> None:
        """NFD on disk vs NFC in #include matches under case-insensitive resolution."""
        inc = tmp_path / "inc"
        inc.mkdir()
        # On disk: NFD spelling ("e" + combining acute)
        nfd_name = "caf\u0065\u0301.h"
        (inc / nfd_name).write_text("#define VAL 1\n", encoding="utf-8")

        # In source: NFC spelling ("é")
        src = '#include "caf\u00e9.h"\nint f(void){return VAL;}\n'
        k1 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        (inc / nfd_name).write_text("#define VAL 2\n", encoding="utf-8")
        k2 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")
        assert k1 != k2

    def test_nonliteral_include_falls_back_to_dir_fingerprint(self, tmp_path: Path) -> None:
        """#include MACRO cannot be resolved statically — fall back to the
        conservative whole-directory fingerprint (any header edit invalidates)."""
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("typedef int A;\n")
        src = "#include LIB_H\nint f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        (inc / "a.h").write_text("typedef long A;\n")
        include_fingerprint.cache_clear()
        k2 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")
        assert k1 != k2

    @pytest.mark.parametrize("depth", [0, 1, 3])
    def test_nonliteral_include_stops_header_reads(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, depth: int
    ) -> None:
        for i in range(depth):
            next_include = f'#include "level{i + 1}.h"' if i + 1 < depth else "#include LIB_H"
            (tmp_path / f"level{i}.h").write_text(
                next_include + '\n#include "unused.h"\n', encoding="utf-8"
            )
        (tmp_path / "unused.h").write_text("typedef int Unused;\n", encoding="utf-8")
        first_include = '#include "level0.h"' if depth else "#include LIB_H"
        source = first_include + '\n#include "unused.h"\n'
        include_dirs = [str(tmp_path)]
        expected = header_dependency_hash("#include OTHER_MACRO\n", str(tmp_path), include_dirs)
        reads: list[str] = []
        read_bytes = Path.read_bytes

        def counted_read(path: Path) -> bytes:
            reads.append(path.name)
            return read_bytes(path)

        monkeypatch.setattr(Path, "read_bytes", counted_read)
        assert header_dependency_hash(source, str(tmp_path), include_dirs) == expected
        assert reads == [f"level{i}.h" for i in range(depth)]

    def test_include_in_block_comment_not_tracked(self, tmp_path: Path) -> None:
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("typedef int A;\n")
        src = "/* #include <a.h> */\nint f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        (inc / "a.h").write_text("typedef long A;\n")
        k2 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")
        assert k1 == k2

    def test_comment_prefixed_include_tracked(self, tmp_path: Path) -> None:
        """/* c */ #include <a.h> must still be resolved (an under-approximation
        would risk a stale hit)."""
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("typedef int A;\n")
        src = "/* c */ #include <a.h>\nint f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        (inc / "a.h").write_text("typedef long A;\n")
        k2 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")
        assert k1 != k2

    @pytest.mark.parametrize("prefix", ["/FI", "-FI", "-include", "--include=", "-imacros", "-fi="])
    def test_force_include_flag_falls_back(self, tmp_path: Path, prefix: str) -> None:
        """A force-include pulls a header into every compile invisibly —
        conservative whole-directory fingerprints are used instead."""
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("typedef int A;\n")
        src = "int f(void){return 1;}\n"
        flags = ["/O2", f"{prefix}{inc}/a.h"]
        k1 = compile_cache_key(src, "f.c", flags, [str(inc)], "wine CL")

        (inc / "a.h").write_text("typedef long A;\n")
        include_fingerprint.cache_clear()
        k2 = compile_cache_key(src, "f.c", flags, [str(inc)], "wine CL")
        assert k1 != k2

    @pytest.mark.parametrize(
        ("src", "flags"),
        [
            ('#include "local.h"\n#include LIB_H\nint f(void){return 1;}\n', ["/O2"]),
            ('#include "local.h"\nint f(void){return 1;}\n', ["/O2", "/FIforced.h"]),
        ],
    )
    def test_fallback_fingerprints_source_dir(
        self, tmp_path: Path, src: str, flags: list[str]
    ) -> None:
        """Quote includes search the source dir first, so the conservative
        fallback must fingerprint it too, not only the ``/I`` dirs."""
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "local.h").write_text("#define L 1\n")
        k1 = compile_cache_key(src, "f.c", flags, [], "wine CL", source_dir=str(src_dir))

        (src_dir / "local.h").write_text("#define L 22\n")
        include_fingerprint.cache_clear()
        k2 = compile_cache_key(src, "f.c", flags, [], "wine CL", source_dir=str(src_dir))
        assert k1 != k2

    def test_raced_scan_is_not_memoized(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A scan whose header changed mid-read must not be published.

        Storing the post-edit stat next to the pre-edit closure makes the
        next lookup treat that closure as fresh.
        """
        import rebrew.compile_cache as cc

        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("int a;\n")
        src = '#include "a.h"\nint f(void){return a;}\n'
        real = cc._scan_include_closure

        def _raced(*args: object, **kwargs: object) -> tuple[object, ...]:
            paths, fallback, stats, _consistent = real(*args, **kwargs)
            return paths, fallback, tuple((-1, -1) for _ in stats), False

        monkeypatch.setattr(cc, "_scan_include_closure", _raced)
        cc._INCLUDE_CLOSURE_MEMO.clear()
        paths, fallback = cc._resolve_include_paths(src, str(inc), ())
        assert paths
        assert fallback is False
        assert cc._INCLUDE_CLOSURE_MEMO == {}

    def test_publish_keeps_valid_peer_closure(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A slower scan must not replace a closure whose stats still match."""
        import rebrew.compile_cache as cc

        inc = tmp_path / "inc"
        inc.mkdir()
        header = inc / "a.h"
        header.write_text("int a;\n")
        src = '#include "a.h"\nint f(void){return a;}\n'
        cc._INCLUDE_CLOSURE_MEMO.clear()
        first_paths, _fallback = cc._resolve_include_paths(src, str(inc), ())
        assert first_paths

        def _stale(*_args: object, **_kwargs: object) -> tuple[object, ...]:
            return (), False, (), True

        monkeypatch.setattr(cc, "_scan_include_closure", _stale)
        # Force the fast path to miss so publish runs, while the peer entry
        # is still valid when re-checked under the lock.
        real_stats = cc._header_stats
        calls = {"n": 0}

        def _miss_once(paths: tuple[str, ...]) -> tuple[tuple[int, int], ...]:
            calls["n"] += 1
            if calls["n"] == 1 and paths == first_paths:
                return tuple((-1, -1) for _ in paths)
            return real_stats(paths)

        monkeypatch.setattr(cc, "_header_stats", _miss_once)
        paths, _fallback = cc._resolve_include_paths(src, str(inc), ())
        assert paths == first_paths
        cached = next(iter(cc._INCLUDE_CLOSURE_MEMO.values()))
        assert cached[0] == first_paths


class TestGetCompileCache:
    def test_factory_and_eviction_close_run_outside_pool_lock(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.compile_cache as cc

        def _factory(path: Path, cap: int) -> CompileCache:
            assert cc._caches_lock.acquire(blocking=False)
            cc._caches_lock.release()
            cache = CompileCache(path, cap)
            original_close = cache.close

            def _close() -> None:
                assert cc._caches_lock.acquire(blocking=False)
                cc._caches_lock.release()
                original_close()

            monkeypatch.setattr(cache, "close", _close)
            return cache

        close_all_caches()
        monkeypatch.setattr(cc, "_CACHE_BACKENDS", {"plugin": _factory})
        monkeypatch.setattr(cc, "_CACHES_MAX", 1)
        try:
            first = get_compile_cache(tmp_path / "first", "plugin")
            second = get_compile_cache(tmp_path / "second", "plugin")
            assert not first.is_open() and second.is_open()
            assert len(cc._caches) == 1
        finally:
            close_all_caches()

    @pytest.mark.parametrize("shared", [False, True])
    def test_racing_factories_publish_once_and_close_the_loser(
        self, shared: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import threading
        from concurrent.futures import ThreadPoolExecutor

        import rebrew.compile_cache as cc

        ready = threading.Barrier(2)
        candidates: list[CompileCache] = []
        candidates_lock = threading.Lock()

        def _factory(path: Path, cap: int) -> CompileCache:
            with candidates_lock:
                cache = candidates[0] if shared and candidates else CompileCache(path, cap)
                candidates.append(cache)
            ready.wait(timeout=5)
            return cache

        close_all_caches()
        monkeypatch.setattr(cc, "_CACHE_BACKENDS", {"plugin": _factory})
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(get_compile_cache, tmp_path, "plugin") for _ in range(2)]
                results = [future.result(timeout=10) for future in futures]
            assert results[0] is results[1]
            assert len(candidates) == 2 and len(cc._caches) == 1
            unique_candidates = {id(cache): cache for cache in candidates}
            assert sum(cache.is_open() for cache in unique_candidates.values()) == 1
        finally:
            close_all_caches()
        assert all(not cache.is_open() for cache in candidates)

    def test_replaced_factory_gets_a_new_instance(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.compile_cache as cc

        monkeypatch.setattr(cc, "_CACHE_BACKENDS", dict(cc._CACHE_BACKENDS))

        def _first(path: Path, cap: int) -> CompileCache:
            return CompileCache(path, cap)

        def _second(path: Path, cap: int) -> CompileCache:
            return CompileCache(path, cap)

        monkeypatch.setattr(cc, "_discover_cache_backends", lambda: {"plugin": _first})
        close_all_caches()
        try:
            cc.refresh_cache_backends()
            old = get_compile_cache(tmp_path, "plugin")
            monkeypatch.setattr(cc, "_discover_cache_backends", lambda: {"plugin": _second})
            cc.refresh_cache_backends()
            new = get_compile_cache(tmp_path, "plugin")
            assert new is not old
            assert get_compile_cache(tmp_path, "plugin") is new
            # Outstanding users keep their committed instance until cleanup.
            assert old.is_open()
            monkeypatch.setattr(cc, "_discover_cache_backends", lambda: {})
            cc.refresh_cache_backends()
            with pytest.raises(ValueError, match="unknown cache backend"):
                get_compile_cache(tmp_path, "plugin")
        finally:
            close_all_caches()
        assert not old.is_open() and not new.is_open()

    def test_close_failure_does_not_strand_other_instances(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.compile_cache as cc

        close_all_caches()
        first = get_compile_cache(tmp_path / "first")
        second = get_compile_cache(tmp_path / "second")
        assert isinstance(second, CompileCache)
        original_close = second.close

        def _close_then_fail() -> None:
            original_close()
            raise RuntimeError("close failed")

        monkeypatch.setattr(second, "close", _close_then_fail)
        with pytest.raises(RuntimeError, match="close failed"):
            close_all_caches()
        assert not first.is_open() and not second.is_open()
        assert cc._caches == {}
        close_all_caches()

    def test_returns_same_instance(self, tmp_path: Path) -> None:
        close_all_caches()
        c1 = get_compile_cache(tmp_path)
        c2 = get_compile_cache(tmp_path)
        assert c1 is c2
        close_all_caches()

    def test_size_limit_is_part_of_the_instance_identity(self, tmp_path: Path) -> None:
        """Two caps in one process must not share one store.

        The cap is fixed when the store opens, so handing a second caller the
        first caller's handle would silently apply the wrong eviction
        threshold.
        """
        close_all_caches()
        c1 = get_compile_cache(tmp_path, size_limit=1 * 1024 * 1024)
        c2 = get_compile_cache(tmp_path, size_limit=2 * 1024 * 1024)
        assert c1 is not c2
        assert c1 is get_compile_cache(tmp_path, size_limit=1 * 1024 * 1024)
        close_all_caches()

    def test_project_cache_uses_configured_backend_and_cap(self, tmp_path: Path) -> None:
        close_all_caches()
        cfg = SimpleNamespace(
            root=tmp_path,
            cache_backend=DEFAULT_CACHE_BACKEND,
            cache_size_limit=3 * 1024 * 1024,
        )
        cache = get_project_cache(cfg)
        assert cache is get_compile_cache(tmp_path, DEFAULT_CACHE_BACKEND, 3 * 1024 * 1024)
        close_all_caches()

    def test_different_roots_different_instances(self, tmp_path: Path) -> None:
        close_all_caches()
        r1 = tmp_path / "proj1"
        r2 = tmp_path / "proj2"
        r1.mkdir()
        r2.mkdir()
        c1 = get_compile_cache(r1)
        c2 = get_compile_cache(r2)
        assert c1 is not c2
        close_all_caches()

    def test_cache_dir_location(self, tmp_path: Path) -> None:
        close_all_caches()
        cache = get_compile_cache(tmp_path)
        cache.put("test", b"\x00")
        assert (tmp_path / ".rebrew" / "compile_cache").exists()
        # The dir holds the live store, so a round trip must survive it.
        assert cache.get("test") == b"\x00"
        close_all_caches()

    def test_evicts_oldest_when_over_cap(self, tmp_path: Path, monkeypatch) -> None:
        """Touching many project roots must close the oldest backend, not retain
        every SQLite handle until process exit."""
        import rebrew.compile_cache as cc

        close_all_caches()
        monkeypatch.setattr(cc, "_CACHES_MAX", 2)
        roots = []
        for i in range(3):
            r = tmp_path / f"proj{i}"
            r.mkdir()
            roots.append(r)
            get_compile_cache(r)
        assert len(cc._caches) == 2
        # Oldest (proj0) evicted; proj1 and proj2 remain.
        assert any(str(roots[0] / ".rebrew" / "compile_cache") in k[1] for k in cc._caches) is False
        assert any(str(roots[1] / ".rebrew" / "compile_cache") in k[1] for k in cc._caches) is True
        assert any(str(roots[2] / ".rebrew" / "compile_cache") in k[1] for k in cc._caches) is True
        close_all_caches()


class TestCompileToObjCacheIntegration:
    def test_cache_hit_skips_subprocess(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj

        subprocess_called = {"count": 0}

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            subprocess_called["count"] += 1
            (workdir / "f.obj").write_bytes(b"\x00COFF_OBJ")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)

        cfg: Any = SimpleNamespace(
            compiler_includes=tmp_path,
            base_cflags="/nologo /c",
            compile_timeout=3,
            msvc_env=lambda: {},
            compiler_command="CL.EXE",
            compiler_libs=tmp_path,
            compiler_runner="",
            root=tmp_path,
            compiler_profile="msvc-6.0",
            posix_style=False,
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        source = src_dir / "f.c"
        source.write_text("int f(void){return 1;}\n", encoding="utf-8")

        cache = CompileCache(tmp_path / "test_cache")

        workdir1 = tmp_path / "w1"
        workdir1.mkdir()
        obj1, err1 = compile_to_obj(
            cast(ProjectConfig, cfg),
            source,
            ["/O2"],
            workdir1,
            cache=cache,
        )
        assert err1 == ""
        assert obj1 is not None
        assert subprocess_called["count"] == 1

        workdir2 = tmp_path / "w2"
        workdir2.mkdir()
        obj2, err2 = compile_to_obj(
            cast(ProjectConfig, cfg),
            source,
            ["/O2"],
            workdir2,
            cache=cache,
        )
        assert err2 == ""
        assert obj2 is not None
        assert subprocess_called["count"] == 1  # no second subprocess call
        assert Path(obj2).read_bytes() == b"\x00COFF_OBJ"

        # The workdir source copy is only needed for the compiler subprocess
        # (perf-review: cache hit skips the copy + read-back entirely).
        assert (workdir1 / "f.c").exists()  # miss path copied the source
        assert not (workdir2 / "f.c").exists()  # hit path must not copy

        cache.close()

    def test_use_cache_false_bypasses(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj

        call_count = {"n": 0}

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            call_count["n"] += 1
            (workdir / "f.obj").write_bytes(b"\x00OBJ")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)

        cfg: Any = SimpleNamespace(
            compiler_includes=tmp_path,
            base_cflags="/nologo /c",
            compile_timeout=3,
            msvc_env=lambda: {},
            compiler_command="CL.EXE",
            compiler_libs=tmp_path,
            compiler_runner="",
            root=tmp_path,
            compiler_profile="msvc-6.0",
            posix_style=False,
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        source = src_dir / "f.c"
        source.write_text("int f(void){return 1;}\n", encoding="utf-8")

        for i in range(2):
            wd = tmp_path / f"w{i}"
            wd.mkdir()
            compile_to_obj(
                cast(ProjectConfig, cfg),
                source,
                ["/O2"],
                wd,
                use_cache=False,
            )
        assert call_count["n"] == 2

    def test_different_flags_cache_miss(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj

        call_count = {"n": 0}

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            call_count["n"] += 1
            (workdir / "f.obj").write_bytes(b"\x00OBJ")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)

        cfg: Any = SimpleNamespace(
            compiler_includes=tmp_path,
            base_cflags="/nologo /c",
            compile_timeout=3,
            msvc_env=lambda: {},
            compiler_command="CL.EXE",
            compiler_libs=tmp_path,
            compiler_runner="",
            root=tmp_path,
            compiler_profile="msvc-6.0",
            posix_style=False,
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        source = src_dir / "f.c"
        source.write_text("int f(void){return 1;}\n", encoding="utf-8")

        cache = CompileCache(tmp_path / "test_cache")

        for i, flags in enumerate([["/O2"], ["/O1"]]):
            wd = tmp_path / f"w{i}"
            wd.mkdir()
            compile_to_obj(
                cast(ProjectConfig, cfg),
                source,
                flags,
                wd,
                cache=cache,
            )
        assert call_count["n"] == 2  # different flags = two compiles

        cache.close()

    def test_unreadable_source_returns_error_tuple(self, tmp_path: Path) -> None:
        """An unreadable source is a compile failure, not an exception.

        compile_to_obj documents `(obj_path, error_msg)` with obj_path None on
        failure, and every other failure on the path returns that tuple. The
        source read sat outside any try, so a missing or unreadable file
        raised OSError out of the ~14 direct callers instead."""
        from rebrew.compile import compile_to_obj

        cfg: Any = SimpleNamespace(
            compiler_includes=tmp_path,
            base_cflags="/nologo /c",
            compile_timeout=3,
            msvc_env=lambda: {},
            compiler_command="CL.EXE",
            compiler_libs=tmp_path,
            compiler_runner="",
            root=tmp_path,
            compiler_profile="msvc-6.0",
            posix_style=False,
        )
        workdir = tmp_path / "w"
        workdir.mkdir()
        obj, err = compile_to_obj(
            cast(ProjectConfig, cfg),
            tmp_path / "does_not_exist.c",
            ["/O2"],
            workdir,
            cache=CompileCache(tmp_path / "test_cache"),
        )
        assert obj is None
        assert "Failed to read source" in err

    def test_failed_compile_not_cached(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj

        call_count = {"n": 0}

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            call_count["n"] += 1
            return SimpleNamespace(returncode=1, stdout="error", stderr="")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)

        cfg: Any = SimpleNamespace(
            compiler_includes=tmp_path,
            base_cflags="/nologo /c",
            compile_timeout=3,
            msvc_env=lambda: {},
            compiler_command="CL.EXE",
            compiler_libs=tmp_path,
            compiler_runner="",
            root=tmp_path,
            compiler_profile="msvc-6.0",
            posix_style=False,
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        source = src_dir / "f.c"
        source.write_text("int f(void){return 1;}\n", encoding="utf-8")

        cache = CompileCache(tmp_path / "test_cache")

        for i in range(2):
            wd = tmp_path / f"w{i}"
            wd.mkdir()
            obj, err = compile_to_obj(
                cast(ProjectConfig, cfg),
                source,
                ["/O2"],
                wd,
                cache=cache,
            )
            assert obj is None
        assert call_count["n"] == 2  # failures not cached, so both hit subprocess

        cache.close()


class TestHitMissCounters:
    def test_initial_counters_zero(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        assert cache.hits == 0
        assert cache.misses == 0
        cache.close()

    def test_miss_increments_misses(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        cache.get("nonexistent")
        assert cache.hits == 0
        assert cache.misses == 1
        cache.close()

    def test_hit_increments_hits(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        cache.put("k", b"\x55\x8b\xec")
        result = cache.get("k")
        assert result == b"\x55\x8b\xec"
        assert cache.hits == 1
        assert cache.misses == 0
        cache.close()

    def test_mixed_hits_and_misses(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        cache.put("a", b"\x01")
        cache.put("b", b"\x02")
        cache.get("a")  # hit
        cache.get("b")  # hit
        cache.get("c")  # miss
        cache.get("d")  # miss
        cache.get("e")  # miss
        assert cache.hits == 2
        assert cache.misses == 3
        cache.close()

    def test_stats_includes_session_data(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        cache.put("k", b"\x00" * 50)
        cache.get("k")  # hit
        cache.get("missing")  # miss
        info = cache.stats()
        assert info["session_hits"] == 1
        assert info["session_misses"] == 1
        assert info["session_hit_rate_pct"] == 50.0
        cache.close()

    def test_stats_hit_rate_zero_when_no_lookups(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        info = cache.stats()
        assert info["session_hits"] == 0
        assert info["session_misses"] == 0
        assert info["session_hit_rate_pct"] == 0.0
        cache.close()

    def test_stats_hit_rate_100_percent(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        cache.put("x", b"\xff")
        cache.get("x")
        info = cache.stats()
        assert info["session_hit_rate_pct"] == 100.0
        cache.close()

    def test_stats_concurrent_atomic_counters(self, tmp_path: Path) -> None:
        """Concurrent lookups and stats() reads must never observe torn counters."""
        import threading

        from thread_util import join_all

        cache = CompileCache(tmp_path / "cc")
        cache.put("hit", b"\x01")
        stop = threading.Event()

        def _worker() -> None:
            while not stop.is_set():
                cache.get("hit")
                cache.get("miss")

        threads = [threading.Thread(target=_worker, daemon=True) for _ in range(4)]
        for t in threads:
            t.start()
        try:
            for _ in range(50):
                info = cache.stats()
                hits = info["session_hits"]
                misses = info["session_misses"]
                total = hits + misses
                expected_rate = round(100.0 * hits / total, 1) if total > 0 else 0.0
                assert info["session_hit_rate_pct"] == expected_rate
                assert info["session_hit_rate_pct"] <= 100.0
        finally:
            stop.set()
            join_all(threads)
            cache.close()


class TestCacheDegradation:
    """A corrupt or contended store must degrade to miss/skip, never raise.

    The cache is an accelerator for the GA hot loop and verify batch: an
    unhandled diskcache/sqlite error there kills hours-long runs with an
    obscure traceback (error-handling review).
    """

    @pytest.fixture(autouse=True)
    def _reset_degraded_flag(self, monkeypatch) -> None:
        """Each test sees its own warn-once budget (the flag is module-global)."""
        import rebrew.compile_cache as cc_mod

        monkeypatch.setattr(cc_mod, "_degraded_logged", set())

    def test_corrupt_store_disables_cache(self, tmp_path: Path) -> None:
        cache_dir = tmp_path / "cc"
        cache_dir.mkdir()
        # A non-SQLite file where diskcache expects its DB header.
        (cache_dir / "cache.db").write_bytes(b"this is not sqlite\x00\x01\x02")
        cache = CompileCache(cache_dir)  # must not raise
        assert cache._cache is None
        assert cache.get("k") is None  # miss, not raise
        assert cache.misses == 1
        cache.put("k", b"\x01")  # skip, not raise
        assert cache.count == 0
        assert cache.volume == 0
        cache.clear()  # no-op, not raise
        stats = cache.stats()
        assert stats["entries"] == 0
        cache.close()  # no-op, not raise

    def test_corrupt_entry_degrades_to_miss(self, tmp_path: Path) -> None:
        """An entry whose stored value fails validation is a plain miss."""
        cache = CompileCache(tmp_path / "cc")
        cache._cache.set("bad", 3.14)  # non-bytes payload → type-guarded miss
        assert cache.get("bad") is None
        cache.close()

    def test_get_failure_counts_as_miss(self, tmp_path: Path, monkeypatch) -> None:
        cache = CompileCache(tmp_path / "cc")
        calls = {"n": 0}

        def _boom(*a: object, **kw: object) -> bytes:
            calls["n"] += 1
            raise sqlite3.DatabaseError("database disk image is malformed")

        monkeypatch.setattr(cache._cache, "get", _boom)
        assert cache.get("k") is None
        assert calls["n"] == 1
        assert cache.misses == 1 and cache.hits == 0
        cache.close()

    def test_put_failure_is_swallowed_with_warning(
        self, tmp_path: Path, monkeypatch, caplog
    ) -> None:
        import logging

        cache = CompileCache(tmp_path / "cc")

        def _full(key: object, value: object) -> None:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(cache._cache, "set", _full)
        with caplog.at_level(logging.WARNING, logger="rebrew.compile_cache"):
            cache.put("k", b"\x01")  # must not raise
        assert any("Compile cache store failed" in r.message for r in caplog.records)
        cache.close()

    def test_repeat_failure_of_one_op_warns_once(self, tmp_path: Path, monkeypatch, caplog) -> None:
        """Repeat suppression is per operation, so a GA batch does not flood."""
        import logging

        cache = CompileCache(tmp_path / "cc")

        def _boom(*a: object, **kw: object) -> bytes:
            raise sqlite3.DatabaseError("database disk image is malformed")

        monkeypatch.setattr(cache._cache, "get", _boom)
        with caplog.at_level(logging.WARNING, logger="rebrew.compile_cache"):
            cache.get("a")
            cache.get("b")
        assert sum("Compile cache lookup failed" in r.message for r in caplog.records) == 1
        cache.close()

    def test_a_new_failure_op_is_reported_after_the_first(
        self, tmp_path: Path, monkeypatch, caplog
    ) -> None:
        """A failure mode the process has not reported yet still gets a line."""
        import logging

        cache = CompileCache(tmp_path / "cc")

        def _boom_get(*a: object, **kw: object) -> bytes:
            raise sqlite3.DatabaseError("database disk image is malformed")

        def _boom_set(*a: object, **kw: object) -> None:
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(cache._cache, "get", _boom_get)
        monkeypatch.setattr(cache._cache, "set", _boom_set)
        with caplog.at_level(logging.WARNING, logger="rebrew.compile_cache"):
            cache.get("k")
            cache.put("k", b"\x01")
        assert any("Compile cache lookup failed" in r.message for r in caplog.records)
        assert any("Compile cache store failed" in r.message for r in caplog.records)
        cache.close()


class TestNoPickleDisk:
    """GHSA-w8v5-vhqr-4h9v: planted pickle entries must not execute on read."""

    def test_poisoned_pickle_entry_is_a_miss(self, tmp_path: Path) -> None:
        import diskcache

        cache_dir = tmp_path / "cc"

        # Plant a MODE_PICKLE value with the vulnerable default Disk.
        class _Boom:
            def __reduce__(self) -> tuple[object, ...]:
                return (exec, ("raise RuntimeError('pwned')",))

        with diskcache.Cache(str(cache_dir)) as raw:
            raw.set("evil", _Boom())

        cache = CompileCache(cache_dir)
        # Must not raise RuntimeError('pwned') — NoPickleDisk refuses MODE_PICKLE.
        assert cache.get("evil") is None
        assert cache.misses == 1
        # Honest bytes entries still work in the same store.
        cache.put("ok", b"\x90\x90")
        assert cache.get("ok") == b"\x90\x90"
        cache.close()

    def test_rejects_object_values_on_write(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        assert cache._cache is not None
        with pytest.raises(TypeError, match="NoPickleDisk"):
            cache._cache.set("x", {"not": "bytes"})
        cache.close()


class TestAtexitClose:
    def test_hook_armed_once_and_closes_caches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The atexit close arms with the first opened cache (not at import),
        at most once, and disposing empties the registry idempotently."""
        import rebrew.compile_cache as cc

        registered: list[tuple] = []
        monkeypatch.setattr(cc.atexit, "register", lambda fn, *a: registered.append((fn, a)))
        monkeypatch.setattr(cc, "_CACHES_ATEXIT_REGISTERED", False)
        monkeypatch.setattr(cc, "_caches", {})
        get_compile_cache(tmp_path / "a")
        get_compile_cache(tmp_path / "b")
        assert len(registered) == 1, "one atexit hook for every cache"
        fn, args = registered[0]
        assert fn is cc.close_all_caches
        fn(*args)
        assert cc._caches == {}
        fn(*args)  # inverse is idempotent


class TestSourceDateEpochCacheIdentity:
    def test_epoch_separates_objects_and_verdicts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.verify_hash import compiler_config_hash

        cfg = ProjectConfig(root=tmp_path)
        monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
        keys = []
        for epoch in (None, "1071482016", "1771046057"):
            if epoch is not None:
                monkeypatch.setenv("SOURCE_DATE_EPOCH", epoch)
            keys.append(
                (
                    compile_cache_key("char date[] = __DATE__;", "date.c", [], [], "clock-test"),
                    compiler_config_hash(cfg),
                )
            )
        assert len({key[0] for key in keys}) == 3
        assert len({key[1] for key in keys}) == 3
