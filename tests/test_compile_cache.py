"""Tests for rebrew.compile_cache — CompileCache, key builder, module-level registry."""

import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from rebrew.compile_cache import (
    CACHE_SCHEMA_VERSION,
    CompileCache,
    _resolve_include_paths,
    close_all_caches,
    compile_cache_key,
    get_compile_cache,
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
        assert info["volume_mb"] >= 0
        assert "size_limit_mb" in info
        cache.close()

    def test_type_safety_returns_none_for_non_bytes(self, tmp_path: Path) -> None:
        cache = CompileCache(tmp_path / "cc")
        cache._cache.set("bad", "not bytes")
        assert cache.get("bad") is None
        cache.close()


class TestCompileCacheKey:
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
        read_source_text does) must hash losslessly — the strict utf-8
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
    def test_missing_dir_is_empty(self, tmp_path: Path) -> None:
        assert include_fingerprint(str(tmp_path / "nope")) == ""

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


class TestHeaderDependencyHash:
    """Per-source #include-closure fingerprints (paper-driven precision).

    The v4 key tracks each translation unit's *reached* headers instead of a
    whole-directory fingerprint: editing a header invalidates exactly the
    entries that include it, and an edit to an unreached header is a hit.
    """

    def test_no_includes_is_fixed_digest(self) -> None:
        """A unit with no header deps gets a stable, non-empty digest ("" is
        reserved by the verify cache for legacy entries)."""
        d = header_dependency_hash("int f(void){return 1;}", None, ["/inc"])
        assert len(d) == 64
        int(d, 16)  # hex
        assert header_dependency_hash("int g(void){return 2;}", None, ["/inc"]) == d

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

    def test_reached_header_edit_changes_key(self, tmp_path: Path) -> None:
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("typedef int A;\n")
        src = "#include <a.h>\nint f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        (inc / "a.h").write_text("typedef long A;\n")
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
        """A header created later in a searched dir changes the resolved set
        on the next key computation (resolution is re-run per process)."""
        inc = tmp_path / "inc"
        inc.mkdir()
        src = "#include <new.h>\nint f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")

        (inc / "new.h").write_text("#define N 1\n")
        _resolve_include_paths.cache_clear()  # structure change needs a fresh resolution
        k2 = compile_cache_key(src, "f.c", ["/O2"], [str(inc)], "wine CL")
        assert k1 != k2

    def test_missing_include_no_crash(self) -> None:
        """An include that resolves nowhere (CRT headers live inside the
        immutable toolchain image) is left untracked — no crash, stable key."""
        src = "#include <nonexistent.h>\nint f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2"], ["/nope"], "wine CL")
        k2 = compile_cache_key(src, "f.c", ["/O2"], ["/nope"], "wine CL")
        assert k1 == k2

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

    def test_force_include_flag_falls_back(self, tmp_path: Path) -> None:
        """/FI pulls a header into every compile invisibly — conservative
        whole-directory fingerprints are used instead."""
        inc = tmp_path / "inc"
        inc.mkdir()
        (inc / "a.h").write_text("typedef int A;\n")
        src = "int f(void){return 1;}\n"
        k1 = compile_cache_key(src, "f.c", ["/O2", f"/FI{inc}/a.h"], [str(inc)], "wine CL")

        (inc / "a.h").write_text("typedef long A;\n")
        include_fingerprint.cache_clear()
        k2 = compile_cache_key(src, "f.c", ["/O2", f"/FI{inc}/a.h"], [str(inc)], "wine CL")
        assert k1 != k2


class TestGetCompileCache:
    def test_returns_same_instance(self, tmp_path: Path) -> None:
        close_all_caches()
        c1 = get_compile_cache(tmp_path)
        c2 = get_compile_cache(tmp_path)
        assert c1 is c2
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
            compiler_profile="msvc6",
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
            compiler_profile="msvc6",
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
            compiler_profile="msvc6",
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
            compiler_profile="msvc6",
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

        monkeypatch.setattr(cc_mod, "_degraded_logged", False)

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
