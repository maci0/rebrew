"""Tests for compile.py pure helpers — CL command resolution and include flags."""

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.compile import resolve_cl_command, resolve_include_flags


def _cfg(root: Path, **overrides: object) -> SimpleNamespace:
    defaults: dict = {
        "root": root,
        "compiler_command": "wine tools/CL.EXE",
        "compiler_runner": "",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestResolveClCommand:
    def test_wine_detected_and_stripped(self, tmp_path: Path) -> None:
        cmd = resolve_cl_command(_cfg(tmp_path))
        # The runner is stripped from the CL path and re-prepended.
        assert cmd == ["wine", str(tmp_path / "tools" / "CL.EXE")]

    def test_explicit_runner_stripped(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path, compiler_command="wibo /vc/CL.EXE", compiler_runner="wibo")
        cmd = resolve_cl_command(cfg)
        assert cmd == ["wibo", "/vc/CL.EXE"]

    def test_absolute_cl_path(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path, compiler_command="wine /abs/CL.EXE")
        cmd = resolve_cl_command(cfg)
        assert cmd == ["wine", "/abs/CL.EXE"]

    def test_no_runner_flags_preserved(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path, compiler_command="wine tools/CL.EXE /nologo /c")
        cmd = resolve_cl_command(cfg)
        assert cmd == ["wine", str(tmp_path / "tools" / "CL.EXE"), "/nologo", "/c"]


class TestResolveIncludeFlags:
    def test_relative_from_src(self, tmp_path: Path) -> None:
        src_parent = tmp_path / "src"
        inc = src_parent / "inc"
        inc.mkdir(parents=True)
        out = resolve_include_flags(["/Iinc"], src_parent, tmp_path)
        assert out == [f"/I{inc.resolve()}"]

    def test_relative_from_root(self, tmp_path: Path) -> None:
        src_parent = tmp_path / "src"
        src_parent.mkdir()
        inc = tmp_path / "inc"
        inc.mkdir()
        out = resolve_include_flags(["/Iinc"], src_parent, tmp_path)
        assert out == [f"/I{inc.resolve()}"]

    def test_missing_dir_keeps_flag(self, tmp_path: Path) -> None:
        out = resolve_include_flags(["/Imissing"], tmp_path, tmp_path)
        assert out == ["/Imissing"]

    def test_absolute_and_non_include_passthrough(self, tmp_path: Path) -> None:
        out = resolve_include_flags(["/I/abs/inc", "/O2", "/c"], tmp_path, tmp_path)
        assert out == ["/I/abs/inc", "/O2", "/c"]

    def test_dash_i_form(self, tmp_path: Path) -> None:
        src_parent = tmp_path / "src"
        inc = src_parent / "inc"
        inc.mkdir(parents=True)
        out = resolve_include_flags(["-Iinc"], src_parent, tmp_path)
        assert out == [f"-I{inc.resolve()}"]

    def test_two_token_space_separated(self, tmp_path: Path) -> None:
        """Split "/I ../Units" (two shlex tokens) merges into
        one resolved include flag instead of corrupting the bare /I.
        The next token may carry a trailing comma separator (/I,<dir>)."""
        src_parent = tmp_path / "src"
        inc = tmp_path / "Units"
        inc.mkdir(parents=True)
        out = resolve_include_flags(["/I", "../Units"], src_parent, tmp_path)
        assert out == [f"/I{inc.resolve()}"]

    def test_two_token_dash_i(self, tmp_path: Path) -> None:
        src_parent = tmp_path / "src"
        inc = src_parent / "inc"
        inc.mkdir(parents=True)
        out = resolve_include_flags(["-I", "inc"], src_parent, tmp_path)
        assert out == [f"-I{inc.resolve()}"]

    def test_trailing_bare_i_left_alone(self, tmp_path: Path) -> None:
        """A lone trailing /I with no following token stays untouched."""
        out = resolve_include_flags(["/O2", "/I"], tmp_path, tmp_path)
        assert out == ["/O2", "/I"]

    def test_bare_i_takes_the_next_token(self, tmp_path: Path) -> None:
        """A bare `/I` always consumes the following token.

        The old `len(nxt) <= 4` heuristic read `/opt`, `/usr`, `/tmp` as flags
        and dropped them from header tracking, so a header reached only through
        `/I /opt` was never fingerprinted.  `/I` without a value is malformed
        anyway, so the next token is its value.
        """
        out = resolve_include_flags(["/I", "/O2"], tmp_path, tmp_path)
        assert out == ["/I/O2"]


class TestResolveCompilerEnv:
    def test_resolves_paths(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import resolve_compiler_env

        tools = tmp_path / "tools"
        tools.mkdir()
        cl = tools / "CL.EXE"
        cl.touch()
        cfg = SimpleNamespace(
            root=tmp_path,
            compiler_command="wine tools/CL.EXE",
            compiler_runner="",
            compiler_includes="inc",
            metadata_dir=tmp_path,
        )
        (tmp_path / "inc").mkdir()
        monkeypatch.setattr("rebrew.compile.msvc_env_from_config", lambda cfg: {"X": "1"})
        monkeypatch.setattr("rebrew.compile.get_project_cache", lambda *a, **k: None)
        cl_cmd, inc_dir, env, cc = resolve_compiler_env(cfg)
        assert str(cl) in cl_cmd  # existing relative path root-prefixed
        assert "wine" in cl_cmd
        assert inc_dir == str(tmp_path / "inc")  # existing include dir resolved
        assert env == {"X": "1"}
        assert cc is None

    def test_missing_paths_fallback(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import resolve_compiler_env

        cfg = SimpleNamespace(
            root=tmp_path,
            compiler_command="",
            compiler_runner="",
            compiler_includes="missing_inc",
            metadata_dir=tmp_path,
        )
        monkeypatch.setattr("rebrew.compile.resolve_cl_command", lambda cfg: ["cl"])
        monkeypatch.setattr("rebrew.compile.msvc_env_from_config", lambda cfg: {})
        monkeypatch.setattr("rebrew.compile.get_project_cache", lambda *a, **k: None)
        cl_cmd, inc_dir, env, cc = resolve_compiler_env(cfg)
        assert cl_cmd == "cl"  # empty command falls back to resolve_cl_command
        assert inc_dir == "missing_inc"  # non-existent include stays as-is
        assert cc is None


class TestNativeToolchainId:
    """The native compile-cache toolchain id tracks the resolved binary.

    Image specs key on the docker content digest; a host compiler has no
    image, so its resolved path's (mtime, size) must stand in for identity —
    a compiler upgrade must never serve objects cached from the old binary.
    """

    def _spec(self, binary: str) -> SimpleNamespace:
        # `host_path=None` mirrors a spec with no vendored tree, so the resolver
        # falls through to PATH exactly as it does for a PATH-resolved compiler.
        return SimpleNamespace(binary=binary, host_path=None, host_bin="bin", name=binary)

    def test_vendored_binary_wins_over_path(self, tmp_path: Path, monkeypatch) -> None:
        """The id must track the binary the runner EXECUTES: for an image-less
        spec, `toolchain._resolve_binary` prefers the vendored tree over PATH,
        so hashing only `shutil.which` left watcom-2.0-win16's `wcc` (not on PATH)
        with a digest-free id — replacing the vendored tree kept serving the
        old compiler's objects."""
        from rebrew.compile import _native_binary_cache, _native_toolchain_id

        vendored = tmp_path / "watcom-2.0-win32" / "source" / "binl"
        vendored.mkdir(parents=True)
        wcc = vendored / "WCC.EXE"
        wcc.write_bytes(b"vendored compiler")
        on_path = tmp_path / "wcc"
        on_path.write_bytes(b"different compiler on PATH")
        monkeypatch.setattr("rebrew.compile.shutil.which", lambda name: str(on_path))
        _native_binary_cache.clear()
        spec = SimpleNamespace(
            binary="wcc",
            host_path=tmp_path / "watcom-2.0-win32",
            host_bin="binl",
            name="watcom-2.0-win16",
        )
        tid = _native_toolchain_id(spec)
        assert tid.startswith("native:wcc@")
        # Content digest of the VENDORED binary, not the PATH one.
        from rebrew.compile import _native_binary_digest

        assert tid == f"native:wcc@{_native_binary_digest(wcc.resolve())}"

    def test_real_binary_gets_stat_suffix(self) -> None:
        from rebrew.compile import _native_binary_cache, _native_toolchain_id

        _native_binary_cache.clear()
        tid = _native_toolchain_id(self._spec("sh"))
        assert tid.startswith("native:sh@")
        assert len(tid.split("@", 1)[1]) == 64

    def test_missing_binary_has_no_identity(self, monkeypatch) -> None:
        from rebrew.compile import _native_binary_cache, _native_toolchain_id

        _native_binary_cache.clear()
        monkeypatch.setattr("rebrew.compile.shutil.which", lambda name: None)
        assert _native_toolchain_id(self._spec("no-such-compiler")) is None
        assert "no-such-compiler" not in _native_binary_cache

    def test_short_digest_is_not_an_identity(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import _native_binary_cache, _native_toolchain_id

        binary = tmp_path / "cc"
        binary.write_bytes(b"compiler")
        monkeypatch.setattr("rebrew.compile.shutil.which", lambda name: str(binary))
        monkeypatch.setattr("rebrew.compile._native_binary_digest", lambda path: "ab" * 8)
        _native_binary_cache.clear()
        assert _native_toolchain_id(self._spec("cc")) is None
        assert "cc" not in _native_binary_cache

    def test_digests_sharing_a_16_hex_prefix_do_not_collide(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        from rebrew.compile import _native_binary_cache, _native_toolchain_id

        prefix = "ab" * 8
        bodies = {
            "one": prefix + "a" * 48,
            "two": prefix + "b" * 48,
        }
        for name, body in bodies.items():
            path = tmp_path / name
            path.write_bytes(body.encode())

        def _digest(path: Path) -> str:
            return bodies[path.name]

        monkeypatch.setattr("rebrew.compile._native_binary_digest", _digest)
        _native_binary_cache.clear()
        ids = []
        for name in ("one", "two"):
            monkeypatch.setattr(
                "rebrew.compile.shutil.which", lambda _name, name=name: str(tmp_path / name)
            )
            ids.append(_native_toolchain_id(self._spec(name)))
        assert ids[0] is not None and ids[1] is not None
        assert ids[0] != ids[1]
        assert ids[0].split("@", 1)[1][:16] == ids[1].split("@", 1)[1][:16]
        assert len(ids[0].split("@", 1)[1]) == 64

    def test_match_binary_nfd_nfc(self, tmp_path: Path) -> None:
        from rebrew.toolchain import _match_binary

        # NFD on disk vs NFC searched
        nfd_name = "cl_\u0065\u0301.exe"
        bin_path = tmp_path / nfd_name
        bin_path.write_bytes(b"MZ...")
        # Search with NFC
        hit = _match_binary(tmp_path, "cl_\u00e9")
        assert hit == bin_path

    def test_binary_upgrade_changes_id(self, tmp_path: Path, monkeypatch) -> None:
        """Two different binaries under the same name must not share an id.

        The memo is keyed on (path, mtime, size, inode): an in-process upgrade
        that changes those must invalidate without an explicit cache clear.
        """
        import os

        from rebrew.compile import _native_binary_cache, _native_toolchain_id

        gcc = tmp_path / "gcc"
        gcc.write_bytes(b"#!/bin/sh\nexit 0\n")
        gcc.chmod(0o755)
        os.utime(gcc, (1767225600, 1767225600))  # fixed old mtime
        monkeypatch.setattr("rebrew.compile.shutil.which", lambda name: str(gcc))
        _native_binary_cache.clear()
        id_old = _native_toolchain_id(self._spec("mingw-16.2.0"))
        # "Upgrade": same path, new content + a later mtime — no clear.
        gcc.write_bytes(b"#!/bin/sh\nexit 0\n# newer compiler\n")
        os.utime(gcc, (1767226000, 1767226000))
        id_new = _native_toolchain_id(self._spec("mingw-16.2.0"))
        assert id_old != id_new
        assert _native_binary_cache["mingw-16.2.0"][4] == id_new

    def test_same_stat_different_bytes_changes_id(self, tmp_path: Path, monkeypatch) -> None:
        """A swapped compiler that preserves (mtime, size) still invalidates
        the cache — the key hashes content, not stat."""
        import os

        from rebrew.compile import _native_binary_cache, _native_toolchain_id

        gcc = tmp_path / "gcc"
        gcc.write_bytes(b"AAAA")
        gcc.chmod(0o755)
        mtime = 1767225600
        os.utime(gcc, (mtime, mtime))
        monkeypatch.setattr("rebrew.compile.shutil.which", lambda name: str(gcc))
        _native_binary_cache.clear()
        id_old = _native_toolchain_id(self._spec("mingw-16.2.0"))
        # Same size, same mtime, different bytes.
        gcc.write_bytes(b"BBBB")
        os.utime(gcc, (mtime, mtime))
        _native_binary_cache.clear()
        id_new = _native_toolchain_id(self._spec("mingw-16.2.0"))
        assert id_old != id_new

    def test_same_size_rename_over_same_mtime_changes_id(self, tmp_path: Path, monkeypatch) -> None:
        """A same-size rename-over in one mtime tick must not keep the old digest.

        In-place ``write_bytes`` keeps the inode, so the content rehash in
        ``test_same_stat_different_bytes_changes_id`` clears the memo first.
        Replacing the binary (``os.replace``) changes only the inode when
        mtime and size are preserved; the memo must rehash without a clear.
        """
        import os

        from rebrew.compile import _native_toolchain_id

        gcc = tmp_path / "gcc"
        gcc.write_bytes(b"AAAA")
        gcc.chmod(0o755)
        mtime = 1767225600
        os.utime(gcc, (mtime, mtime))
        monkeypatch.setattr("rebrew.compile.shutil.which", lambda name: str(gcc))
        id_old = _native_toolchain_id(self._spec("mingw-16.2.0"))
        swapped = tmp_path / "gcc.new"
        swapped.write_bytes(b"BBBB")
        swapped.chmod(0o755)
        os.utime(swapped, ns=(mtime * 1_000_000_000, mtime * 1_000_000_000))
        os.replace(swapped, gcc)
        st = gcc.stat()
        assert st.st_size == 4
        assert st.st_mtime_ns == mtime * 1_000_000_000
        id_new = _native_toolchain_id(self._spec("mingw-16.2.0"))
        assert id_old != id_new

    def test_native_binary_cache_is_thread_safe(self, tmp_path: Path, monkeypatch) -> None:
        """Concurrent cache-key builds must not race the eviction mutation."""
        import threading

        from thread_util import join_all

        from rebrew.compile import (
            _NATIVE_BINARY_CACHE_MAX,
            _native_binary_cache,
            _native_toolchain_id,
        )

        bins = tmp_path / "bins"
        bins.mkdir()
        paths: list[Path] = []
        for i in range(_NATIVE_BINARY_CACHE_MAX + 16):
            p = bins / f"cc{i}"
            p.write_bytes(b"compiler-" + bytes([i % 256]))
            paths.append(p)

        def _which(name: str) -> str | None:
            # name is the binary field (cc0, cc1, ...); map to the fixture path.
            candidate = bins / name
            return str(candidate) if candidate.is_file() else None

        monkeypatch.setattr("rebrew.compile.shutil.which", _which)
        _native_binary_cache.clear()
        errors: list[BaseException] = []

        def _worker(i: int) -> None:
            try:
                tid = _native_toolchain_id(self._spec(f"cc{i % len(paths)}"))
                assert tid.startswith("native:cc")
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker, args=(i,), daemon=True) for i in range(64)]
        for t in threads:
            t.start()
        join_all(threads)
        assert errors == []
        assert len(_native_binary_cache) <= _NATIVE_BINARY_CACHE_MAX


class TestInvalidateToolchainDigest:
    def test_pops_one_or_clears_all(self) -> None:
        from rebrew.toolchain import (
            _toolchain_digest_cache,
            invalidate_toolchain_digest,
        )

        _toolchain_digest_cache.clear()
        _toolchain_digest_cache["rebrew/msvc:6.0-win32"] = "aaaaaaaaaaaa"
        _toolchain_digest_cache["rebrew/gcc:14.2.0-linux-x64"] = "bbbbbbbbbbbb"
        invalidate_toolchain_digest("rebrew/msvc:6.0-win32")
        assert "rebrew/msvc:6.0-win32" not in _toolchain_digest_cache
        assert _toolchain_digest_cache["rebrew/gcc:14.2.0-linux-x64"] == "bbbbbbbbbbbb"
        invalidate_toolchain_digest()
        assert _toolchain_digest_cache == {}

    def test_cached_image_digest_skips_empty_failures(self, monkeypatch) -> None:
        """A failed inspect must not be memoized as an identity."""
        import rebrew.toolchain as toolchain_mod
        from rebrew.toolchain import cached_image_digest

        toolchain_mod._toolchain_digest_cache.clear()
        calls = {"n": 0}

        def _fail(*_a, **_k):
            calls["n"] += 1
            return SimpleNamespace(returncode=1, stdout="", stderr="missing")

        monkeypatch.setattr(toolchain_mod.subprocess, "run", _fail)
        assert cached_image_digest("rebrew/msvc:6.0-win32") == ""
        assert "rebrew/msvc:6.0-win32" not in toolchain_mod._toolchain_digest_cache
        assert cached_image_digest("rebrew/msvc:6.0-win32") == ""
        assert calls["n"] == 2  # retried — not memoized

    def test_cached_image_digest_stores_success(self, monkeypatch) -> None:
        import rebrew.toolchain as toolchain_mod
        from rebrew.toolchain import cached_image_digest

        toolchain_mod._toolchain_digest_cache.clear()
        calls = {"n": 0}

        image_id = "sha256:" + "ab" * 32

        def _ok(*_a, **_k):
            calls["n"] += 1
            return SimpleNamespace(returncode=0, stdout=image_id + "\n", stderr="")

        monkeypatch.setattr(toolchain_mod.subprocess, "run", _ok)
        assert cached_image_digest("rebrew/msvc:6.0-win32") == image_id
        assert cached_image_digest("rebrew/msvc:6.0-win32") == image_id
        assert calls["n"] == 1

    def test_invalidate_during_inspect_does_not_store_old_digest(self, monkeypatch) -> None:
        """A swap landing mid-inspect must not let the pre-swap id be used.

        Serving the pre-swap id would file a post-swap compile under the old
        image, which is the stale-key case ``invalidate_toolchain_digest``
        exists to prevent.  The result is empty and nothing is cached.
        """
        import rebrew.toolchain as toolchain_mod
        from rebrew.toolchain import cached_image_digest, invalidate_toolchain_digest

        toolchain_mod._toolchain_digest_cache.clear()

        def _swap_mid_inspect(*_a, **_k):
            invalidate_toolchain_digest("rebrew/msvc:6.0-win32")
            return SimpleNamespace(returncode=0, stdout="sha256:0ld0ld0ld0ld99\n", stderr="")

        monkeypatch.setattr(toolchain_mod.subprocess, "run", _swap_mid_inspect)
        assert cached_image_digest("rebrew/msvc:6.0-win32") == ""
        assert "rebrew/msvc:6.0-win32" not in toolchain_mod._toolchain_digest_cache

    def test_invalidate_during_inspect_prefers_post_swap_refill(self, monkeypatch) -> None:
        """A worker that already re-inspected wins over returning empty."""
        import rebrew.toolchain as toolchain_mod
        from rebrew.toolchain import cached_image_digest, invalidate_toolchain_digest

        toolchain_mod._toolchain_digest_cache.clear()
        refilled = "sha256:" + "cd" * 32

        def _swap_then_refill(*_a, **_k):
            invalidate_toolchain_digest("rebrew/msvc:6.0-win32")
            # Another worker post-swap refilled the memo.
            toolchain_mod._toolchain_digest_cache["rebrew/msvc:6.0-win32"] = refilled
            return SimpleNamespace(returncode=0, stdout="sha256:" + "ab" * 32 + "\n", stderr="")

        monkeypatch.setattr(toolchain_mod.subprocess, "run", _swap_then_refill)
        assert cached_image_digest("rebrew/msvc:6.0-win32") == refilled

    def test_short_refill_after_invalidate_is_rejected(self, monkeypatch) -> None:
        import rebrew.toolchain as toolchain_mod
        from rebrew.toolchain import cached_image_digest, invalidate_toolchain_digest

        toolchain_mod._toolchain_digest_cache.clear()

        def _swap_then_refill(*_a, **_k):
            invalidate_toolchain_digest("rebrew/msvc:6.0-win32")
            toolchain_mod._toolchain_digest_cache["rebrew/msvc:6.0-win32"] = "newnewnewnew"
            return SimpleNamespace(returncode=0, stdout="sha256:" + "ab" * 32 + "\n", stderr="")

        monkeypatch.setattr(toolchain_mod.subprocess, "run", _swap_then_refill)
        assert cached_image_digest("rebrew/msvc:6.0-win32") == ""
        assert "rebrew/msvc:6.0-win32" not in toolchain_mod._toolchain_digest_cache

    @pytest.mark.parametrize(
        "stdout",
        [
            "",
            "abcdef0123456789deadbeef",
            "sha256:abcdef012345",
            "sha256:" + "AB" * 32,
            "sha256:" + "ab" * 32 + "ff",
            "sha256:" + "ab" * 32 + "\nsha256:" + "cd" * 32,
            "not-an-id",
        ],
    )
    def test_malformed_inspect_is_not_an_identity(self, monkeypatch, stdout: str) -> None:
        import rebrew.toolchain as toolchain_mod
        from rebrew.toolchain import cached_image_digest

        toolchain_mod._toolchain_digest_cache.clear()
        calls = {"n": 0}

        def _ok(*_a, **_k):
            calls["n"] += 1
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

        monkeypatch.setattr(toolchain_mod.subprocess, "run", _ok)
        tag = "rebrew/msvc:6.0-win32"
        assert cached_image_digest(tag) == ""
        assert tag not in toolchain_mod._toolchain_digest_cache
        assert cached_image_digest(tag) == ""
        assert calls["n"] == 2

    def test_nonzero_inspect_and_timeout_are_not_memoized(self, monkeypatch) -> None:
        import rebrew.toolchain as toolchain_mod
        from rebrew.toolchain import cached_image_digest

        toolchain_mod._toolchain_digest_cache.clear()
        calls = {"n": 0}

        def _bad(*_a, **_k):
            calls["n"] += 1
            if calls["n"] == 1:
                return SimpleNamespace(
                    returncode=1, stdout="sha256:" + "ab" * 32 + "\n", stderr="missing"
                )
            raise subprocess.TimeoutExpired(cmd=["docker"], timeout=15)

        monkeypatch.setattr(toolchain_mod.subprocess, "run", _bad)
        tag = "rebrew/msvc:6.0-win32"
        assert cached_image_digest(tag) == ""
        assert cached_image_digest(tag) == ""
        assert calls["n"] == 2
        assert tag not in toolchain_mod._toolchain_digest_cache

    def test_short_memo_is_dropped_and_reinspected(self, monkeypatch) -> None:
        import rebrew.toolchain as toolchain_mod
        from rebrew.toolchain import cached_image_digest

        tag = "rebrew/msvc:6.0-win32"
        image_id = "sha256:" + "ef" * 32
        toolchain_mod._toolchain_digest_cache.clear()
        toolchain_mod._toolchain_digest_cache[tag] = "abcdef012345"
        calls = {"n": 0}

        def _ok(*_a, **_k):
            calls["n"] += 1
            return SimpleNamespace(returncode=0, stdout=image_id + "\n", stderr="")

        monkeypatch.setattr(toolchain_mod.subprocess, "run", _ok)
        assert cached_image_digest(tag) == image_id
        assert calls["n"] == 1
        assert toolchain_mod._toolchain_digest_cache[tag] == image_id

    def test_full_ids_sharing_a_12_hex_prefix_do_not_collide(self, monkeypatch) -> None:
        import rebrew.toolchain as toolchain_mod
        from rebrew.compile import _toolchain_cache_id
        from rebrew.compile_cache import compile_cache_key
        from rebrew.toolchain import cached_image_digest

        prefix = "abcdef012345"
        id_a = "sha256:" + prefix + "a" * 52
        id_b = "sha256:" + prefix + "b" * 52
        assert id_a[7:19] == id_b[7:19]
        assert id_a != id_b
        stdout = {"rebrew/one:tag": id_a + "\n", "rebrew/two:tag": id_b + "\n"}
        toolchain_mod._toolchain_digest_cache.clear()

        def _ok(cmd, **_k):
            return SimpleNamespace(returncode=0, stdout=stdout[cmd[-1]], stderr="")

        monkeypatch.setattr(toolchain_mod.subprocess, "run", _ok)
        assert cached_image_digest("rebrew/one:tag") == id_a
        assert cached_image_digest("rebrew/two:tag") == id_b
        spec = SimpleNamespace(image="rebrew/one:tag")
        tid_a = _toolchain_cache_id(spec, id_a)
        tid_b = _toolchain_cache_id(spec, id_b)
        assert tid_a is not None and tid_b is not None
        assert tid_a != tid_b
        assert _toolchain_cache_id(spec, "sha256:abcdef012345") is None
        assert _toolchain_cache_id(spec, None) is None

        def _key(toolchain_id: str) -> str:
            return compile_cache_key("int f(void){return 1;}", "f.c", ["/O2"], [], toolchain_id)

        assert _key(tid_a) != _key(tid_b)

    def test_image_present_does_not_cache_misses(self, monkeypatch) -> None:
        """A miss must re-inspect so an external pull is visible mid-process."""
        import rebrew.toolchain as toolchain_mod
        from rebrew.toolchain import image_present

        toolchain_mod._image_presence.clear()
        monkeypatch.setattr(toolchain_mod, "docker_available", lambda: True)
        results = [1, 0]  # miss then hit
        calls = {"n": 0}

        def _inspect(*_a, **_k):
            calls["n"] += 1
            code = results.pop(0)
            return SimpleNamespace(returncode=code, stdout="", stderr="")

        monkeypatch.setattr(toolchain_mod.subprocess, "run", _inspect)
        assert image_present("rebrew/msvc:6.0-win32") is False
        assert "rebrew/msvc:6.0-win32" not in toolchain_mod._image_presence
        assert image_present("rebrew/msvc:6.0-win32") is True
        assert toolchain_mod._image_presence["rebrew/msvc:6.0-win32"] is True
        assert calls["n"] == 2

    def test_image_present_inspect_timeout_is_retryable(self, monkeypatch) -> None:
        """A hung daemon is a retryable docker error, not a permanent invocation failure."""
        import rebrew.toolchain as toolchain_mod
        from rebrew.toolchain import ToolchainError, image_present

        toolchain_mod._image_presence.clear()
        monkeypatch.setattr(toolchain_mod, "docker_available", lambda: True)

        def _timeout(*_a: object, **_k: object) -> object:
            raise subprocess.TimeoutExpired(cmd=["docker"], timeout=30)

        monkeypatch.setattr(toolchain_mod.subprocess, "run", _timeout)
        with pytest.raises(ToolchainError, match="docker image inspect") as ei:
            image_present("rebrew/msvc:6.0-win32")
        assert ei.value.kind == "docker"
        assert ei.value.retryable is True
        assert isinstance(ei.value.__cause__, subprocess.TimeoutExpired)

    def test_retag_timeout_is_toolchain_error(self, monkeypatch) -> None:
        """Rollback suppresses ToolchainError; a raw timeout would hide the swap error."""
        import rebrew.toolchain as toolchain_mod
        from rebrew.toolchain import ToolchainError, _retag_image

        def _timeout(*_a: object, **_k: object) -> object:
            raise subprocess.TimeoutExpired(cmd=["docker"], timeout=60)

        monkeypatch.setattr(toolchain_mod.subprocess, "run", _timeout)
        with pytest.raises(ToolchainError, match="docker tag") as ei:
            _retag_image("sha256:abc", "rebrew/msvc:6.0-win32")
        assert ei.value.kind == "docker"
        assert ei.value.retryable is True

    def test_digest_and_presence_memos_are_thread_safe(self, monkeypatch) -> None:
        """Concurrent fill/evict must not raise or corrupt the memo dicts.

        ``rebrew verify -j N`` and GA workers hit these memos on every cache-key
        build; an unlocked check-then-evict used to race under load.
        """
        import threading

        from thread_util import join_all

        import rebrew.toolchain as toolchain_mod
        from rebrew.toolchain import cached_image_digest, image_present

        toolchain_mod._toolchain_digest_cache.clear()
        toolchain_mod._image_presence.clear()
        monkeypatch.setattr(toolchain_mod, "docker_available", lambda: True)

        image_id = "sha256:" + "ab" * 32

        def _ok(*_a, **_k):
            return SimpleNamespace(returncode=0, stdout=image_id + "\n", stderr="")

        monkeypatch.setattr(toolchain_mod.subprocess, "run", _ok)
        errors: list[BaseException] = []

        def _worker(i: int) -> None:
            try:
                tag = f"rebrew/msvc:6.0-win32-{i % 80}"
                assert cached_image_digest(tag) == image_id
                assert image_present(tag) is True
            except BaseException as exc:  # collect; fail outside threads
                errors.append(exc)

        threads = [threading.Thread(target=_worker, args=(i,), daemon=True) for i in range(64)]
        for t in threads:
            t.start()
        join_all(threads)
        assert errors == []
        # Bounded eviction must leave at most the configured caps.
        assert (
            len(toolchain_mod._toolchain_digest_cache) <= toolchain_mod._TOOLCHAIN_DIGEST_CACHE_MAX
        )
        assert len(toolchain_mod._image_presence) <= toolchain_mod._IMAGE_PRESENCE_MAX


class TestCompilerCmdRoundTrip:
    def test_spaced_compiler_path_round_trips(self, tmp_path: Path, monkeypatch) -> None:
        """`cl_cmd` is re-split with shlex by the GA / flag sweep; `" ".join`
        lost the quoting `resolve_cl_command` keeps, so a compiler path with a
        space became two argv elements and the compile failed with
        "Compiler not found"."""
        from rebrew.compile import resolve_compiler_env
        from rebrew.utils import safe_shlex_split

        cfg = SimpleNamespace(
            root=tmp_path,
            compiler_command="",
            compiler_runner="",
            compiler_includes="inc",
            metadata_dir=tmp_path,
        )
        (tmp_path / "inc").mkdir()
        monkeypatch.setattr(
            "rebrew.compile.resolve_cl_command", lambda cfg: ["/opt/My Tools/gcc", "-c"]
        )
        monkeypatch.setattr("rebrew.compile.msvc_env_from_config", lambda cfg: {})
        monkeypatch.setattr("rebrew.compile.get_project_cache", lambda *a, **k: None)
        cl_cmd, _inc, _env, _cc = resolve_compiler_env(cfg)
        assert safe_shlex_split(cl_cmd) == ["/opt/My Tools/gcc", "-c"]


class TestDockerIncludeRewriteMounts:
    """Absolute /I outside the project must not become a docker bind mount."""

    def test_mounts_under_allowed_root(self, tmp_path: Path) -> None:
        from rebrew.compile import _docker_include_rewrite

        work = tmp_path / "work"
        work.mkdir()
        inc = tmp_path / "inc"
        inc.mkdir()
        flags, mounts = _docker_include_rewrite([f"/I{inc}"], work, allowed_roots=[tmp_path, work])
        assert flags == [f"/I{inc.resolve()}"]
        assert mounts == [(str(inc.resolve()), str(inc.resolve()))]

    def test_refuses_mount_outside_allowed_roots(self, tmp_path: Path) -> None:
        from rebrew.compile import _docker_include_rewrite

        work = tmp_path / "work"
        work.mkdir()
        outside = tmp_path.parent / f"rebrew-outside-{tmp_path.name}"
        outside.mkdir(exist_ok=True)
        try:
            flags, mounts = _docker_include_rewrite(
                [f"/I{outside}"], work, allowed_roots=[tmp_path, work]
            )
            assert mounts == []
            assert flags == [f"/I{outside.resolve()}"]
        finally:
            outside.rmdir()
