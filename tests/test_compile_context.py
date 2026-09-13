"""Tests for context-pinned compilation (compile.py + context.py).

Covers the merged compile unit (`#line` directives), the compile-cache
behaviour under a changing context, and the context digest recorded on a
CompareResult / its JSON body.  No docker: the compile runs through a
monkeypatched native toolchain and a real on-disk cache in ``tmp_path``.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew.compile import (
    CompareResult,
    compile_to_obj,
    contextualized_source,
)
from rebrew.compile_cache import CompileCache
from rebrew.context import CompileContext, context_sha256, load_compile_context
from rebrew.toolchain_spec import ToolchainSpec

SOURCE = "int f(int a) { return a + 1; }\n"


def _spec() -> ToolchainSpec:
    """A host-only spec: compile_to_obj runs it through the native backend.

    ``run_toolchain`` is monkeypatched in every test, so the spec only has to
    select the native branch and produce a stable cache identity.
    """
    return ToolchainSpec(name="fake-1.0", image=None, binary="fake-cc", runtime="native")


def _cfg(root: Path, profile: str = "fake-1.0") -> SimpleNamespace:
    return SimpleNamespace(
        root=root,
        compiler_profile=profile,
        compiler_command="",
        compiler_includes=str(root),
        base_cflags="/nologo /c",
        compile_timeout=60,
        defines=[],
        target_name="T",
    )


class _FakeCompiler:
    """Records every compile unit it is asked to build."""

    def __init__(self, obj_name: str) -> None:
        self.obj_name = obj_name
        self.units: list[str] = []

    def __call__(self, spec: Any, args: list[str], *, workdir: Path, **kwargs: Any) -> Any:
        src = next((a for a in args if a.endswith(".c")), "f.c")
        unit_path = Path(workdir) / Path(src).name
        self.units.append(unit_path.read_text(encoding="utf-8"))
        (Path(workdir) / self.obj_name).write_bytes(b"\x55\xc3")
        return SimpleNamespace(returncode=0, stdout="", stderr="")


class TestContextUnit:
    def test_directives_delimit_context_and_source(self) -> None:
        """The merged unit names each part, so a diagnostic points at the file
        the offending line came from."""
        ctx = CompileContext(path=Path("ctx.c"), text="typedef int myint;", sha256="x")
        unit = contextualized_source(ctx, SOURCE, "f.c")
        assert unit == '#line 1 "ctx.c"\ntypedef int myint;\n#line 1 "f.c"\n' + SOURCE
        assert unit.index('#line 1 "ctx.c"') < unit.index('#line 1 "f.c"')

    def test_no_context_returns_source_unchanged(self) -> None:
        assert contextualized_source(None, SOURCE, "f.c") == SOURCE

    def test_empty_context_returns_source_unchanged(self) -> None:
        """A context carrying no declarations must not alter the compile unit
        (an empty one would otherwise prepend two stray directives)."""
        ctx = CompileContext(path=Path("ctx.c"), text="", sha256=context_sha256(""))
        assert contextualized_source(ctx, SOURCE, "f.c") == SOURCE


class TestCompileContextFile:
    def test_none_path_is_no_context(self) -> None:
        assert load_compile_context(None) is None

    def test_missing_file_fails_loud(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            load_compile_context(tmp_path / "absent.c")

    def test_hash_is_stable_and_content_addressed(self, tmp_path: Path) -> None:
        path = tmp_path / "ctx.c"
        path.write_text("typedef int myint;\n", encoding="utf-8")
        first = load_compile_context(path)
        second = load_compile_context(path)
        assert first is not None and second is not None
        assert first.sha256 == second.sha256
        assert first.sha256 == context_sha256("typedef int myint;\n")

        path.write_text("typedef long myint;\n", encoding="utf-8")
        changed = load_compile_context(path)
        assert changed is not None
        assert changed.sha256 != first.sha256


class TestContextPinnedCompileCache:
    def _ctx(self, path: Path, text: str) -> CompileContext:
        path.write_text(text, encoding="utf-8")
        ctx = load_compile_context(path)
        assert ctx is not None
        return ctx

    def test_cache_hit_per_context_and_miss_on_change(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cached object built under one context must not satisfy a build
        under another; the same context still hits."""
        src = tmp_path / "f.c"
        src.write_text(SOURCE, encoding="utf-8")
        cfg = _cfg(tmp_path)
        cache = CompileCache(tmp_path / "cache")
        ctx_a = self._ctx(tmp_path / "a.c", "typedef int myint;\n")
        ctx_b = self._ctx(tmp_path / "b.c", "typedef long myint;\n")

        fake = _FakeCompiler("f.obj")
        monkeypatch.setattr("rebrew.compile.TOOLCHAINS", {"fake-1.0": _spec()})
        monkeypatch.setattr("rebrew.compile.run_toolchain", fake)

        def _compile(ctx: CompileContext | None, workdir_name: str) -> tuple[str | None, str]:
            workdir = tmp_path / workdir_name
            workdir.mkdir()
            return compile_to_obj(cfg, src, [], workdir, cache=cache, obj_name="f.obj", context=ctx)

        obj_a, err = _compile(ctx_a, "w1")
        assert err == "" and obj_a is not None
        assert len(fake.units) == 1
        assert fake.units[0].startswith('#line 1 "ctx.c"')

        # Same context: served from the cache, the compiler is not re-run.
        obj_hit, err = _compile(ctx_a, "w2")
        assert err == "" and obj_hit is not None
        assert len(fake.units) == 1, "a build under the same context must hit the cache"

        # Changed context: a different compile input, so a miss.
        obj_b, err = _compile(ctx_b, "w3")
        assert err == "" and obj_b is not None
        assert len(fake.units) == 2, "a build under a changed context must not reuse the object"
        assert fake.units[1] != fake.units[0]
        assert "typedef long myint;" in fake.units[1]

        # No context is a third, distinct input.
        obj_none, err = _compile(None, "w4")
        assert err == "" and obj_none is not None
        assert len(fake.units) == 3
        assert fake.units[2] == SOURCE


class TestContextNeverTouchesTheResultCache:
    """A context-scoped verdict is not written to the shared verify cache.

    The cache entry records no context digest, so a verdict earned under a
    context and written there would later be served to a context-free run
    that never compiled it.
    """

    def _project(self, tmp_path: Path) -> None:
        import shutil

        fixture = Path(__file__).parent / "fixtures" / "mini_pe.exe"
        (tmp_path / "original").mkdir()
        shutil.copy(fixture, tmp_path / "original" / "x.exe")
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "x"\n'
            '[targets.x]\nbinary = "original/x.exe"\n'
            '[compiler]\nprofile = "msvc-6.0"\n',
            encoding="utf-8",
        )
        src = tmp_path / "src" / "x"
        src.mkdir(parents=True)
        (src / "f.c").write_text("// FUNCTION: X 0x1000\nint f(void) { return 1; }\n")

    def _run(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]
    ) -> tuple[Any, list]:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        seen: list = []

        def _fake_compile(*a: Any, **k: Any) -> CompareResult:
            seen.append(k.get("context"))
            return CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"\xc3",
                reloc_offsets=[],
                context_hash="deadbeef" if k.get("context") is not None else None,
            )

        monkeypatch.setattr("rebrew.test.compile_and_compare", _fake_compile)
        monkeypatch.setattr(
            "rebrew.test._patch_verify_cache", lambda *a, **k: seen.append("patched")
        )
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(
            umbrella,
            ["test", "src/x/f.c", "--va", "0x1000", "--size", "4", "--symbol", "_f", *args],
        )
        return result, seen

    def test_context_is_passed_and_cache_untouched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._project(tmp_path)
        ctx = tmp_path / "ctx.c"
        ctx.write_text("typedef int myint;\n", encoding="utf-8")
        result, seen = self._run(tmp_path, monkeypatch, ["--context", str(ctx)])
        assert result.exit_code == 0, result.output
        passed_context = [s for s in seen if s != "patched"]
        assert len(passed_context) == 1
        assert passed_context[0] is not None
        assert passed_context[0].sha256 == context_sha256("typedef int myint;\n")
        assert "patched" not in seen

    def test_without_context_the_cache_is_patched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._project(tmp_path)
        result, seen = self._run(tmp_path, monkeypatch, [])
        assert result.exit_code == 0, result.output
        assert [s for s in seen if s != "patched"] == [None]
        assert "patched" in seen


class TestContextHashReporting:
    def test_compare_result_records_the_digest(self) -> None:
        """compile_and_compare stamps the digest onto every result, including
        a compile failure, whose verdict is just as context-scoped."""
        result = CompareResult(
            matched=True,
            status="EXACT",
            match_percent=100.0,
            delta=0,
            obj_bytes=b"\x90",
            reloc_offsets=[],
            context_hash="deadbeef",
        )
        from rebrew.test import build_result_dict_from_compare

        body = build_result_dict_from_compare("f.c", "_f", "0x1000", 1, result, b"\x90")
        assert body["context_hash"] == "deadbeef"

    def test_json_carries_null_without_a_context(self) -> None:
        from rebrew.test import build_result_dict_from_compare

        result = CompareResult(
            matched=True,
            status="EXACT",
            match_percent=100.0,
            delta=0,
            obj_bytes=b"\x90",
            reloc_offsets=[],
        )
        body = build_result_dict_from_compare("f.c", "_f", "0x1000", 1, result, b"\x90")
        assert body["context_hash"] is None
