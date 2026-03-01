"""Tests for rebrew.compile_cache — CompileCache, key builder, module-level registry."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from rebrew.compile_cache import (
    CACHE_SCHEMA_VERSION,
    CompileCache,
    close_all_caches,
    compile_cache_key,
    get_compile_cache,
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

    def test_different_source_ext_different_key(self) -> None:
        k1 = compile_cache_key("int f(){return 1;}", "f.c", ["/O2"], ["/inc"], "wine CL", ".c")
        k2 = compile_cache_key("int f(){return 1;}", "f.c", ["/O2"], ["/inc"], "wine CL", ".cpp")
        assert k1 != k2

    def test_flag_order_matters(self) -> None:
        k1 = compile_cache_key("src", "f.c", ["/O2", "/Gd"], ["/inc"], "wine CL")
        k2 = compile_cache_key("src", "f.c", ["/Gd", "/O2"], ["/inc"], "wine CL")
        assert k1 != k2

    def test_returns_hex_string(self) -> None:
        key = compile_cache_key("src", "f.c", ["/O2"], ["/inc"], "wine CL")
        assert len(key) == 64
        int(key, 16)  # validates hex

    def test_schema_version_in_key(self) -> None:
        k = compile_cache_key("src", "f.c", ["/O2"], ["/inc"], "wine CL")
        assert isinstance(k, str)
        assert CACHE_SCHEMA_VERSION == 1


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

        def _fake_run(cmd: list[str], **_kwargs: object) -> SimpleNamespace:
            subprocess_called["count"] += 1
            cwd = Path(str(_kwargs.get("cwd", tmp_path)))
            fo_flag = [c for c in cmd if c.startswith("/Fo")][0]
            (cwd / fo_flag[3:]).write_bytes(b"\x00COFF_OBJ")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("rebrew.compile.subprocess.run", _fake_run)
        monkeypatch.setattr("rebrew.compile.resolve_cl_command", lambda _cfg: ["CL.EXE"])

        cfg: Any = SimpleNamespace(
            compiler_includes=tmp_path,
            base_cflags="/nologo /c",
            compile_timeout=3,
            msvc_env=lambda: {},
            root=tmp_path,
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

        cache.close()

    def test_use_cache_false_bypasses(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj

        call_count = {"n": 0}

        def _fake_run(cmd, **_kwargs: object) -> SimpleNamespace:
            call_count["n"] += 1
            obj_name = [c for c in cmd if c.endswith(".obj")][0]
            obj_path = Path(_kwargs.get("cwd", tmp_path)) / obj_name.split("/")[-1]
            obj_path.write_bytes(b"\x00OBJ")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("rebrew.compile.subprocess.run", _fake_run)
        monkeypatch.setattr("rebrew.compile.resolve_cl_command", lambda _cfg: ["CL.EXE"])

        cfg: Any = SimpleNamespace(
            compiler_includes=tmp_path,
            base_cflags="/nologo /c",
            compile_timeout=3,
            msvc_env=lambda: {},
            root=tmp_path,
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

        def _fake_run(cmd, **_kwargs: object) -> SimpleNamespace:
            call_count["n"] += 1
            obj_name = [c for c in cmd if c.endswith(".obj")][0]
            obj_path = Path(_kwargs.get("cwd", tmp_path)) / obj_name.split("/")[-1]
            obj_path.write_bytes(b"\x00OBJ")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        monkeypatch.setattr("rebrew.compile.subprocess.run", _fake_run)
        monkeypatch.setattr("rebrew.compile.resolve_cl_command", lambda _cfg: ["CL.EXE"])

        cfg: Any = SimpleNamespace(
            compiler_includes=tmp_path,
            base_cflags="/nologo /c",
            compile_timeout=3,
            msvc_env=lambda: {},
            root=tmp_path,
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

        def _fake_run(cmd, **_kwargs: object) -> SimpleNamespace:
            call_count["n"] += 1
            return SimpleNamespace(returncode=1, stdout=b"error", stderr=b"")

        monkeypatch.setattr("rebrew.compile.subprocess.run", _fake_run)
        monkeypatch.setattr("rebrew.compile.resolve_cl_command", lambda _cfg: ["CL.EXE"])

        cfg: Any = SimpleNamespace(
            compiler_includes=tmp_path,
            base_cflags="/nologo /c",
            compile_timeout=3,
            msvc_env=lambda: {},
            root=tmp_path,
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
