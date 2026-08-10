"""Tests for rebrew match.py CLI entry point — --watch mode and guards."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner


def _params() -> SimpleNamespace:
    return SimpleNamespace(
        seed_c=Path("/tmp/f.c"),
        cl="cl.exe",
        inc=[],
        cflags="/O2",
        symbol="_f",
        msvc_env={},
        cc=None,
        timeout=30,
        cfg=SimpleNamespace(metadata_dir=Path("/tmp/meta"), compile_timeout=30),
        va_int=0x1000,
        target_bytes=b"\x55\x8b\xec\x5d\xc3",
    )


class TestMatchCliWatch:
    def test_watch_with_all_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.match import app

        cfg = SimpleNamespace(
            metadata_dir=tmp_path,
            reversed_dir=tmp_path / "src",
            marker="SERVER",
            source_ext=".c",
            default_jobs=2,
        )
        monkeypatch.setattr("rebrew.match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--watch", "--all"])
        assert result.exit_code == 1
        assert "--watch cannot be combined with --all" in result.output

    def test_watch_enters_watch_mode_and_retests(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.match import app

        cfg = SimpleNamespace(
            metadata_dir=tmp_path,
            reversed_dir=tmp_path / "src",
            marker="SERVER",
            source_ext=".c",
            default_jobs=2,
        )
        monkeypatch.setattr("rebrew.match.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.match.resolve_build_params", lambda *a, **k: _params())

        seen: dict = {}
        monkeypatch.setattr(
            "rebrew.match._run_single_ga",
            lambda *a, **k: seen.update(called=True),
        )
        captured: dict = {}
        monkeypatch.setattr(
            "rebrew.utils.watch_files",
            lambda paths, retest: captured.update(paths=paths, retest=retest),
        )
        result = CliRunner().invoke(app, ["--watch", "f.c"])
        assert result.exit_code == 0
        # First invocation must enter watch mode, not run the GA itself.
        assert seen == {}
        (watched,) = captured["paths"]
        assert watched == Path("f.c").resolve()
        # Re-invoking the retest re-enters main() with watch=False → runs the GA.
        captured["retest"]()
        assert seen["called"] is True


class TestMatchAllTargets:
    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            metadata_dir=tmp_path,
            reversed_dir=tmp_path / "src",
            marker="SERVER",
            source_ext=".c",
            ignored_symbols=[],
            default_jobs=2,
            root=tmp_path,
            target_name="server_dll",
            all_targets=["server_dll", "client_exe"],
        )

    def test_runs_each_target(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.match import app

        cfg = self._cfg(tmp_path)
        monkeypatch.setattr("rebrew.match.require_config", lambda **kw: cfg)

        def _fake_load_config(root: Path, target: str | None = None) -> SimpleNamespace:
            return SimpleNamespace(
                metadata_dir=tmp_path,
                reversed_dir=tmp_path / "src",
                marker="SERVER",
                source_ext=".c",
                ignored_symbols=[],
                default_jobs=2,
                root=root,
                target_name=target or "server_dll",
                all_targets=cfg.all_targets,
            )

        monkeypatch.setattr("rebrew.config.load_config", _fake_load_config)
        seen: dict = {}
        calls: list[str] = []

        def _fake_run_all(cfg=None, **kwargs: object) -> tuple[int, int]:
            calls.append(getattr(cfg, "target_name", "?"))
            seen.setdefault("n", 0)
            seen["n"] += 1
            return (1, 0) if seen["n"] == 1 else (0, 1)

        monkeypatch.setattr("rebrew.match._run_all", _fake_run_all)
        result = CliRunner().invoke(app, ["--all-targets", "--json"])
        assert result.exit_code == 0
        assert calls == ["server_dll", "client_exe"]
        import json

        payload = json.loads(result.output)
        assert payload["mode"] == "all-targets"
        assert payload["matched"] == 1
        assert payload["failed"] == 1

    def test_all_targets_with_all_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.match import app

        cfg = self._cfg(tmp_path)
        monkeypatch.setattr("rebrew.match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--all-targets", "--all"])
        assert result.exit_code == 1
        assert "--all-targets cannot be combined with --all" in result.output

    def test_all_targets_watch_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.match import app

        cfg = self._cfg(tmp_path)
        monkeypatch.setattr("rebrew.match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--all-targets", "--watch"])
        assert result.exit_code == 1
        assert "--watch cannot be combined with --all-targets" in result.output


class TestResolveBuildParamsSymbol:
    """--symbol must select the matching annotation in a multi-function file
    (VA/SIZE derive from it, not from the first annotation)."""

    def _make_multi(self, tmp_path: Path) -> Path:
        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True)
        f = src / "multi.c"
        f.write_text(
            "// FUNCTION: SERVER 0x401000\n"
            "// SIZE: 64\n"
            "int first_fn(void) { return 0; }\n"
            "\n"
            "// FUNCTION: SERVER 0x401100\n"
            "// SIZE: 128\n"
            "int second_fn(void) { return 1; }\n",
            encoding="utf-8",
        )
        return f

    def test_selects_matching_annotation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.config import load_config
        from rebrew.match import resolve_build_params

        toml = tmp_path / "rebrew-project.toml"
        toml.write_text(
            '[project]\ndefault_target = "server"\n\n'
            "[targets.server]\n"
            'binary = "x.dll"\nformat = "pe"\narch = "x86_32"\n'
            'reversed_dir = "src/SERVER"\nmarker = "SERVER"\n'
            'function_list = "src/SERVER/functions.txt"\n',
            encoding="utf-8",
        )
        cfg = load_config(tmp_path)
        import sys

        sys.path.insert(0, str(Path(__file__).parent))
        from bin_util import make_pe

        (tmp_path / "x.dll").write_bytes(
            make_pe(b"\x55\x8b\xec\x5d\xc3" * 120, image_base=0x400000)
        )
        f = self._make_multi(tmp_path)
        monkeypatch.chdir(tmp_path)

        params = resolve_build_params(
            cfg, str(f), None, None, None, "_second_fn", None, None, False, True
        )
        assert params.symbol == "_second_fn"
        assert params.va_int == 0x401100
        assert params.target_size == 128

    def test_no_symbol_falls_back_to_first(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.config import load_config
        from rebrew.match import resolve_build_params

        toml = tmp_path / "rebrew-project.toml"
        toml.write_text(
            '[project]\ndefault_target = "server"\n\n'
            "[targets.server]\n"
            'binary = "x.dll"\nformat = "pe"\narch = "x86_32"\n'
            'reversed_dir = "src/SERVER"\nmarker = "SERVER"\n'
            'function_list = "src/SERVER/functions.txt"\n',
            encoding="utf-8",
        )
        cfg = load_config(tmp_path)
        import sys

        sys.path.insert(0, str(Path(__file__).parent))
        from bin_util import make_pe

        (tmp_path / "x.dll").write_bytes(
            make_pe(b"\x55\x8b\xec\x5d\xc3" * 120, image_base=0x400000)
        )
        f = self._make_multi(tmp_path)
        monkeypatch.chdir(tmp_path)

        params = resolve_build_params(cfg, str(f), None, None, None, None, None, None, False, True)
        assert params.symbol == "_first_fn"
        assert params.va_int == 0x401000
        assert params.target_size == 64

    def test_va_selects_matching_annotation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """resolve_build_params with target_va set must select THAT annotation
        in a multi-function file, not the first one (workflow: `rebrew
        diff/match/prove 0x<va>` was diffing the wrong function)."""
        from rebrew.config import load_config
        from rebrew.match import resolve_build_params

        toml = tmp_path / "rebrew-project.toml"
        toml.write_text(
            '[project]\ndefault_target = "server"\n\n'
            "[targets.server]\n"
            'binary = "x.dll"\nformat = "pe"\narch = "x86_32"\n'
            'reversed_dir = "src/SERVER"\nmarker = "SERVER"\n'
            'function_list = "src/SERVER/functions.txt"\n',
            encoding="utf-8",
        )
        cfg = load_config(tmp_path)
        import sys

        sys.path.insert(0, str(Path(__file__).parent))
        from bin_util import make_pe

        (tmp_path / "x.dll").write_bytes(
            make_pe(b"\x55\x8b\xec\x5d\xc3" * 120, image_base=0x400000)
        )
        f = self._make_multi(tmp_path)
        monkeypatch.chdir(tmp_path)

        params = resolve_build_params(
            cfg, str(f), None, None, None, None, "0x401100", None, False, True
        )
        assert params.symbol == "_second_fn"
        assert params.va_int == 0x401100
        assert params.target_size == 128


class TestFindFunctionRange:
    """_find_function_range — GA mutation scoping helper."""

    def test_finds_matching_function(self) -> None:
        from rebrew.match import _find_function_range

        src = """int helper(void) { return 0; }

int target_fn(int x) {
    return x + 1;
}

int other(void) { return 2; }
"""
        r = _find_function_range(src, "_target_fn")
        assert r is not None
        assert "target_fn" in src[r[0] : r[1]]
        assert "helper" not in src[r[0] : r[1]]

    def test_underscore_prefix_optional(self) -> None:
        from rebrew.match import _find_function_range

        src = "int foo(void) { return 1; }"
        r = _find_function_range(src, "foo")
        assert r is not None
        assert "foo" in src[r[0] : r[1]]

    def test_missing_symbol_returns_none(self) -> None:
        from rebrew.match import _find_function_range

        src = "int foo(void) { return 1; }"
        assert _find_function_range(src, "_nonexistent") is None

    def test_non_c_garbage_returns_none(self) -> None:
        from rebrew.match import _find_function_range

        assert _find_function_range("not c at all", "_foo") is None

    def test_set_target_range_scopes_cursor(self) -> None:
        """set_target_range must restrict mutation queries to the byte window."""
        from rebrew.matcher import ast_engine
        from rebrew.matcher.mutator import _cursor, _LazyQuery, set_target_range

        src = b"int a(void) { return 1; } int b(void) { return 2; }"
        set_target_range(0, len(b"int a(void) { return 1; } "))  # only function a
        try:
            q = _LazyQuery(
                ast_engine._C_LANGUAGE,
                "(function_definition declarator: (function_declarator declarator: (identifier) @name)) @fn",
            )
            tree = ast_engine.parse_c_ast(src)
            cursor = _cursor(q)
            names = []
            for m in cursor.matches(tree.root_node):
                captures = m[1] if isinstance(m, tuple) else m.captures
                if "name" in captures:
                    names.append(captures["name"][0].text.decode())
            assert names == ["a"]  # function b is outside the range
        finally:
            set_target_range(None, None)


class TestMatchCliDryRun:
    """rebrew match --dry-run is batch-only; single-function must reject it."""

    def test_single_function_dry_run_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.match import app

        cfg = SimpleNamespace(
            metadata_dir=tmp_path,
            reversed_dir=tmp_path / "src",
            marker="SERVER",
            source_ext=".c",
            default_jobs=2,
        )
        monkeypatch.setattr("rebrew.match.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--dry-run", "f.c"])
        assert result.exit_code == 2
        assert "batch mode only" in result.output
        # The GA must not run for a single function under --dry-run.
        assert "_run_single_ga" not in result.output


class TestAllTargetsParallel:
    """J5: --all-targets splits --jobs across targets when it can."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            metadata_dir=tmp_path,
            reversed_dir=tmp_path / "src",
            marker="SERVER",
            source_ext=".c",
            ignored_symbols=[],
            default_jobs=4,
            root=tmp_path,
            target_name="server_dll",
            all_targets=["server_dll", "client_exe"],
        )

    def test_jobs_split_across_targets(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.match import app

        cfg = self._cfg(tmp_path)
        monkeypatch.setattr("rebrew.match.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.config.load_config",
            lambda root, target=None: SimpleNamespace(
                metadata_dir=tmp_path,
                reversed_dir=tmp_path / "src",
                marker="SERVER",
                source_ext=".c",
                ignored_symbols=[],
                default_jobs=4,
                root=root,
                target_name=target or "server_dll",
                all_targets=cfg.all_targets,
            ),
        )
        job_args: list[int] = []

        def _fake_run_all(cfg=None, **kwargs: object) -> tuple[int, int]:
            job_args.append(int(kwargs.get("jobs", 0)))
            return (1, 0)

        monkeypatch.setattr("rebrew.match._run_all", _fake_run_all)
        result = CliRunner().invoke(app, ["--all-targets", "--json"])
        assert result.exit_code == 0
        # 4 jobs over 2 targets → 2 each; total wine concurrency stays ~4.
        assert job_args == [2, 2]

    def test_single_target_keeps_full_jobs(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.match import app

        cfg = self._cfg(tmp_path)
        cfg.all_targets = ["server_dll"]
        monkeypatch.setattr("rebrew.match.require_config", lambda **kw: cfg)
        job_args: list[int] = []

        def _fake_run_all(cfg=None, **kwargs: object) -> tuple[int, int]:
            job_args.append(int(kwargs.get("jobs", 0)))
            return (1, 0)

        monkeypatch.setattr("rebrew.match._run_all", _fake_run_all)
        result = CliRunner().invoke(app, ["--all-targets", "--json"])
        assert result.exit_code == 0
        assert job_args == [4]  # no split needed
