"""Tests for compile.py pure helpers — backend selection and include flags."""

from pathlib import Path
from types import SimpleNamespace

from rebrew.compile import recompile_url, resolve_include_flags


def _cfg(root: Path, **overrides: object) -> SimpleNamespace:
    defaults: dict = {
        "root": root,
        "compiler_command": "wine tools/CL.EXE",
        "compiler_runner": "",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


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
        """/I ../Units (split by shlex into two tokens) must merge into
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

    def test_bare_i_before_flag_does_not_merge(self, tmp_path: Path) -> None:
        """/I followed by another flag (/I /O2) is not a path merge."""
        out = resolve_include_flags(["/I", "/O2"], tmp_path, tmp_path)
        assert out == ["/I", "/O2"]


class TestResolveCompilerEnv:
    def test_resolves_paths(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import resolve_compiler_env

        tools = tmp_path / "tools"
        tools.mkdir()
        cl = tools / "CL.EXE"
        cl.touch()
        cfg = SimpleNamespace(
            root=tmp_path,
            compiler_includes="inc",
            metadata_dir=tmp_path,
        )
        (tmp_path / "inc").mkdir()
        monkeypatch.setattr("rebrew.compile.msvc_env_from_config", lambda cfg: {"X": "1"})
        monkeypatch.setattr(
            "rebrew.compile.get_compile_cache", lambda root, backend="diskcache": None
        )
        inc_dir, env, cc = resolve_compiler_env(cfg)
        assert inc_dir == str(tmp_path / "inc")  # existing include dir resolved
        assert env == {"X": "1"}
        assert cc is None

    def test_missing_paths_fallback(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import resolve_compiler_env

        cfg = SimpleNamespace(
            root=tmp_path,
            compiler_includes="missing_inc",
            metadata_dir=tmp_path,
        )
        monkeypatch.setattr("rebrew.compile.msvc_env_from_config", lambda cfg: {})
        monkeypatch.setattr(
            "rebrew.compile.get_compile_cache", lambda root, backend="diskcache": None
        )
        inc_dir, env, cc = resolve_compiler_env(cfg)
        assert inc_dir == "missing_inc"  # non-existent include stays as-is
        assert cc is None


class TestRemoteToolchainId:
    """A remote compile never shares a cache entry with a local compile.

    The recompile service may run a different image build than local
    docker, so the cache id pins the backend (URL + toolchain name), not
    just the image tag.
    """

    def _cfg(self, tmp_path: Path, url: str) -> SimpleNamespace:
        return SimpleNamespace(
            root=tmp_path,
            compiler_profile="msvc6",
            compiler_command="",
            compiler_runner="",
            compiler_includes=tmp_path,
            base_cflags="",
            compile_timeout=3,
            defines=[],
            recompile_url=url,
            recompile_emit_assembly=False,
            cache_backend="diskcache",
        )

    def _source(self, tmp_path: Path) -> Path:
        src_dir = tmp_path / "src"
        src_dir.mkdir(exist_ok=True)
        source = src_dir / "f.c"
        source.write_text("int f(void){return 1;}\n", encoding="utf-8")
        return source

    def test_backend_switch_changes_key(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_cache_key

        url = "http://localhost:8000"
        assert recompile_url(self._cfg(tmp_path, url)) == url
        assert recompile_url(self._cfg(tmp_path, "")) is None
        local_id = "rebrew/msvc:6.0-win32"
        remote_id = f"recompile:{url}/msvc6"
        assert local_id != remote_id
        key_local = compile_cache_key(
            source_content="int f(void){return 1;}\n",
            source_filename="f.c",
            cflags=["/c"],
            include_dirs=[str(tmp_path)],
            toolchain_id=local_id,
            source_ext=".c",
            source_dir=str(tmp_path),
        )
        key_remote = compile_cache_key(
            source_content="int f(void){return 1;}\n",
            source_filename="f.c",
            cflags=["/c"],
            include_dirs=[str(tmp_path)],
            toolchain_id=remote_id,
            source_ext=".c",
            source_dir=str(tmp_path),
        )
        assert key_local != key_remote

    def test_remote_compile_posts_source(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj
        from rebrew.recompile_client import RecompileResult

        seen: dict = {}

        def _fake_compile(base_url, compiler, source, flags, **kwargs):
            seen["url"] = base_url
            seen["compiler"] = compiler
            seen["source"] = source
            seen["flags"] = flags
            return RecompileResult(ok=True, obj_bytes=b"\x00obj")

        monkeypatch.setattr("rebrew.recompile_client.compile_source", _fake_compile)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)
        source = self._source(tmp_path)
        workdir = tmp_path / "work"
        workdir.mkdir()
        obj_path, err = compile_to_obj(
            self._cfg(tmp_path, "http://localhost:8000"), source, ["/O2"], workdir
        )
        assert err == ""
        assert obj_path is not None
        assert Path(obj_path).read_bytes() == b"\x00obj"
        assert seen["compiler"] == "msvc6"
        assert "return 1" in seen["source"]
        assert "/O2" in seen["flags"]

    def test_remote_failure_surfaces_log(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj
        from rebrew.recompile_client import RecompileResult

        def _fake_compile(base_url, compiler, source, flags, **kwargs):
            return RecompileResult(ok=False, log="C1083: cannot open source")

        monkeypatch.setattr("rebrew.recompile_client.compile_source", _fake_compile)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)
        source = self._source(tmp_path)
        workdir = tmp_path / "work"
        workdir.mkdir()
        obj_path, err = compile_to_obj(
            self._cfg(tmp_path, "http://localhost:8000"), source, ["/O2"], workdir
        )
        assert obj_path is None
        assert "C1083" in err

    def test_remote_error_maps_to_message(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import compile_to_obj
        from rebrew.recompile_client import RecompileError

        def _fake_compile(base_url, compiler, source, flags, **kwargs):
            raise RecompileError("connection refused")

        monkeypatch.setattr("rebrew.recompile_client.compile_source", _fake_compile)
        monkeypatch.setattr("rebrew.compile.get_compile_cache", lambda *a, **k: None)
        source = self._source(tmp_path)
        workdir = tmp_path / "work"
        workdir.mkdir()
        obj_path, err = compile_to_obj(
            self._cfg(tmp_path, "http://localhost:8000"), source, ["/O2"], workdir
        )
        assert obj_path is None
        assert "recompile service error" in err

    def test_env_url_selects_remote(self, tmp_path: Path, monkeypatch) -> None:

        monkeypatch.setenv("REBREW_RECOMPILE_URL", "http://remote:9000")
        assert recompile_url(self._cfg(tmp_path, "")) == "http://remote:9000"
