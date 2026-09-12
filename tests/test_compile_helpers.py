"""Tests for compile.py pure helpers — CL command resolution and include flags."""

from pathlib import Path
from types import SimpleNamespace

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
        """ "/I ../Units" (split by shlex into two tokens) must merge into
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
        monkeypatch.setattr(
            "rebrew.compile.get_compile_cache", lambda root, backend="diskcache": None
        )
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
        monkeypatch.setattr(
            "rebrew.compile.get_compile_cache", lambda root, backend="diskcache": None
        )
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
        so hashing only `shutil.which` left watcom16's `wcc` (not on PATH)
        with a digest-free id — replacing the vendored tree kept serving the
        old compiler's objects."""
        from rebrew.compile import _native_binary_cache, _native_toolchain_id

        vendored = tmp_path / "watcom" / "source" / "binl"
        vendored.mkdir(parents=True)
        wcc = vendored / "WCC.EXE"
        wcc.write_bytes(b"vendored compiler")
        on_path = tmp_path / "wcc"
        on_path.write_bytes(b"different compiler on PATH")
        monkeypatch.setattr("rebrew.compile.shutil.which", lambda name: str(on_path))
        _native_binary_cache.clear()
        spec = SimpleNamespace(
            binary="wcc", host_path=tmp_path / "watcom", host_bin="binl", name="watcom16"
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
        assert len(tid.split("@")[1]) == 16  # short sha256 content digest

    def test_missing_binary_falls_back(self, monkeypatch) -> None:
        from rebrew.compile import _native_binary_cache, _native_toolchain_id

        _native_binary_cache.clear()
        monkeypatch.setattr("rebrew.compile.shutil.which", lambda name: None)
        assert _native_toolchain_id(self._spec("no-such-compiler")) == "native:no-such-compiler"

    def test_binary_upgrade_changes_id(self, tmp_path: Path, monkeypatch) -> None:
        """Two different binaries under the same name must not share an id."""
        import os

        from rebrew.compile import _native_binary_cache, _native_toolchain_id

        gcc = tmp_path / "gcc"
        gcc.write_bytes(b"#!/bin/sh\nexit 0\n")
        gcc.chmod(0o755)
        os.utime(gcc, (1767225600, 1767225600))  # fixed old mtime
        monkeypatch.setattr("rebrew.compile.shutil.which", lambda name: str(gcc))
        _native_binary_cache.clear()
        id_old = _native_toolchain_id(self._spec("gcc-pe"))
        # "Upgrade": same path, new content + a later mtime.
        gcc.write_bytes(b"#!/bin/sh\nexit 0\n# newer compiler\n")
        os.utime(gcc, (1767226000, 1767226000))
        _native_binary_cache.clear()
        id_new = _native_toolchain_id(self._spec("gcc-pe"))
        assert id_old != id_new

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
        id_old = _native_toolchain_id(self._spec("gcc-pe"))
        # Same size, same mtime, different bytes.
        gcc.write_bytes(b"BBBB")
        os.utime(gcc, (mtime, mtime))
        _native_binary_cache.clear()
        id_new = _native_toolchain_id(self._spec("gcc-pe"))
        assert id_old != id_new


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
        monkeypatch.setattr(
            "rebrew.compile.get_compile_cache", lambda root, backend="diskcache": None
        )
        cl_cmd, _inc, _env, _cc = resolve_compiler_env(cfg)
        assert safe_shlex_split(cl_cmd) == ["/opt/My Tools/gcc", "-c"]
