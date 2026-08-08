"""Tests for batch GA and flag sweep logic in rebrew.match."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew.match import (
    find_all_matching,
    find_all_stubs,
    parse_matching_all,
    parse_stub_info,
    update_cflags_annotation,
)

# -------------------------------------------------------------------------
# parse_stub_info
# -------------------------------------------------------------------------


class TestParseStubInfo:
    def _make_stub_file(
        self,
        tmp_path,
        va=0x10001000,
        status="STUB",
        size=64,
        symbol="_my_func",
    ) -> Path:
        # Derive clean function name from symbol for the C definition
        func_name = symbol.lstrip("_")
        f = tmp_path / f"func_{va:08x}.c"
        f.write_text(
            f"// FUNCTION: SERVER 0x{va:08X}\n"
            f"// STATUS: {status}\n"
            f"// CFLAGS: /O2 /Gd\n"
            f"void __cdecl {func_name}(void) {{\n"
            f"    // stub\n"
            f"}}\n",
            encoding="utf-8",
        )
        # SIZE lives in metadata, not inline
        metadata_toml = tmp_path / "rebrew-function.toml"
        existing = metadata_toml.read_text(encoding="utf-8") if metadata_toml.exists() else ""
        metadata_toml.write_text(
            existing + f'["SERVER.0x{va:08X}"]\nsize = {size}\n',
            encoding="utf-8",
        )
        return f

    def test_parses_stub(self, tmp_path: Path) -> None:
        f = self._make_stub_file(tmp_path)
        result = parse_stub_info(f)
        assert len(result) == 1
        assert result[0].va == "0x10001000"
        assert result[0].symbol == "_my_func"

    def test_skips_non_stub(self, tmp_path: Path) -> None:
        f = self._make_stub_file(tmp_path, status="EXACT")
        result = parse_stub_info(f)
        assert result == []

    def test_skips_skip_status(self, tmp_path: Path) -> None:
        f = self._make_stub_file(tmp_path, status="SKIP")
        result = parse_stub_info(f)
        assert result == []

    def test_skips_ignored_symbols(self, tmp_path: Path) -> None:
        f = self._make_stub_file(tmp_path, symbol="_asm_func")
        result = parse_stub_info(f, ignored={"_asm_func"})
        assert result == []

    def test_skips_tiny_functions(self, tmp_path: Path) -> None:
        f = self._make_stub_file(tmp_path, size=2)
        result = parse_stub_info(f)
        assert result == []

    def test_no_annotations(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.c"
        f.write_text("int main() { return 0; }\n", encoding="utf-8")
        result = parse_stub_info(f)
        assert result == []


# -------------------------------------------------------------------------
# find_all_stubs
# -------------------------------------------------------------------------


class TestFindAllStubs:
    def _make_stub(self, d, va, symbol, size=64) -> None:
        func_name = symbol.lstrip("_")
        f = d / f"func_{va:08x}.c"
        f.write_text(
            f"// FUNCTION: SERVER 0x{va:08X}\n"
            f"// STATUS: STUB\n"
            f"// ORIGIN: GAME\n"
            f"// CFLAGS: /O2 /Gd\n"
            f"void __cdecl {func_name}(void) {{}}\n",
            encoding="utf-8",
        )
        # SIZE in metadata
        metadata_toml = d / "rebrew-function.toml"
        existing = metadata_toml.read_text(encoding="utf-8") if metadata_toml.exists() else ""
        metadata_toml.write_text(
            existing + f'["SERVER.0x{va:08X}"]\nsize = {size}\n',
            encoding="utf-8",
        )

    def test_finds_stubs(self, tmp_path: Path) -> None:
        self._make_stub(tmp_path, 0x10001000, "_func_a", size=64)
        self._make_stub(tmp_path, 0x10002000, "_func_b", size=128)
        stubs = find_all_stubs(tmp_path)
        assert len(stubs) == 2

    def test_sorted_by_size(self, tmp_path: Path) -> None:
        self._make_stub(tmp_path, 0x10002000, "_big", size=200)
        self._make_stub(tmp_path, 0x10001000, "_small", size=32)
        stubs = find_all_stubs(tmp_path)
        assert stubs[0].size <= stubs[1].size

    def test_empty_dir(self, tmp_path: Path) -> None:
        stubs = find_all_stubs(tmp_path)
        assert stubs == []

    def test_ignores_exact(self, tmp_path: Path) -> None:
        f = tmp_path / "exact.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: EXACT\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _exact\n"
            "void __cdecl _exact(void) {}\n",
            encoding="utf-8",
        )
        stubs = find_all_stubs(tmp_path)
        assert stubs == []

    def test_duplicate_va_warning(self, tmp_path: Path) -> None:
        """Duplicate VAs should be detected — only first kept."""
        self._make_stub(tmp_path, 0x10001000, "_dup_a")
        # Create second file with same VA
        f2 = tmp_path / "dup_file.c"
        f2.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: STUB\n"
            "// SIZE: 64\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _dup_b\n"
            "void __cdecl _dup_b(void) {}\n",
            encoding="utf-8",
        )
        stubs = find_all_stubs(tmp_path)
        assert len(stubs) == 1

    def test_filters_ignored(self, tmp_path: Path) -> None:
        self._make_stub(tmp_path, 0x10001000, "_asm_builtin")
        stubs = find_all_stubs(tmp_path, ignored={"_asm_builtin"})
        assert stubs == []


# -------------------------------------------------------------------------
# parse_matching_all (batch flag sweep discovery)
# -------------------------------------------------------------------------


class TestParseMatchingAll:
    def _make_c(
        self,
        d: Path,
        name: str,
        va: int,
        status: str,
        blocker: str = "",
        skip: bool = False,
        cflags: str = "/O2 /Gd",
    ) -> Path:
        lines = [
            f"// FUNCTION: SERVER 0x{va:08x}",
            f"// SYMBOL: _{name}",
        ]
        if skip:
            lines.append("// SKIP: reason")
        lines.append(f"int __cdecl {name}(void) {{ return 0; }}")
        path = d / f"{name}.c"
        path.write_text("\n".join(lines), encoding="utf-8")
        # Write metadata-owned fields to rebrew-function.toml
        import re

        metadata_toml = d / "rebrew-function.toml"
        existing = metadata_toml.read_text(encoding="utf-8") if metadata_toml.exists() else ""
        entry = f'["SERVER.0x{va:08x}"]\nstatus = "{status}"\nsize = 100\ncflags = "{cflags}"\n'
        if blocker:
            entry += f'blocker = "{blocker}"\n'
            m = re.match(r"(\d+)B", blocker)
            if m:
                entry += f"blocker_delta = {m.group(1)}\n"
        if skip:
            entry += 'skip = "reason"\n'
        metadata_toml.write_text(existing + entry, encoding="utf-8")
        return path

    def test_accepts_matching_without_blocker(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncA", 0x10001000, "NEAR_MATCHING")
        result = parse_matching_all(tmp_path / "FuncA.c")
        assert len(result) == 1
        assert result[0].va == "0x10001000"
        assert result[0].delta == 9999

    def test_accepts_matching_with_blocker(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncB", 0x10002000, "NEAR_MATCHING", "3B diff")
        result = parse_matching_all(tmp_path / "FuncB.c")
        assert len(result) == 1
        assert result[0].delta == 3

    def test_rejects_stub(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncC", 0x10003000, "STUB")
        result = parse_matching_all(tmp_path / "FuncC.c")
        assert result == []

    def test_rejects_exact(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncD", 0x10004000, "EXACT")
        result = parse_matching_all(tmp_path / "FuncD.c")
        assert result == []

    def test_rejects_skip(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncE", 0x10005000, "NEAR_MATCHING", skip=True)
        result = parse_matching_all(tmp_path / "FuncE.c")
        assert result == []

    def test_rejects_ignored(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncF", 0x10006000, "NEAR_MATCHING")
        result = parse_matching_all(tmp_path / "FuncF.c", ignored={"_FuncF"})
        assert result == []

    def test_preserves_cflags(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "FuncG", 0x10007000, "NEAR_MATCHING", cflags="/O1 /Gz")
        result = parse_matching_all(tmp_path / "FuncG.c")
        assert len(result) == 1
        assert result[0].cflags == "/O1 /Gz"


# -------------------------------------------------------------------------
# find_all_matching
# -------------------------------------------------------------------------


class TestFindAllMatching:
    def _make_c(
        self,
        d: Path,
        name: str,
        va: int,
        status: str,
        blocker: str = "",
        size: int = 100,
    ) -> None:
        lines = [
            f"// FUNCTION: SERVER 0x{va:08x}",
            f"// SYMBOL: _{name}",
            f"int __cdecl {name}(void) {{ return 0; }}",
        ]
        (d / f"{name}.c").write_text("\n".join(lines), encoding="utf-8")
        # Write metadata-owned fields to rebrew-function.toml
        import re

        metadata_toml = d / "rebrew-function.toml"
        existing = metadata_toml.read_text(encoding="utf-8") if metadata_toml.exists() else ""
        entry = f'["SERVER.0x{va:08x}"]\nstatus = "{status}"\nsize = {size}\ncflags = "/O2 /Gd"\n'
        if blocker:
            entry += f'blocker = "{blocker}"\n'
            m = re.match(r"(\d+)B", blocker)
            if m:
                entry += f"blocker_delta = {m.group(1)}\n"
        metadata_toml.write_text(existing + entry, encoding="utf-8")

    def test_finds_all_matching(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "Match1", 0x10001000, "NEAR_MATCHING", "2B diff")
        self._make_c(tmp_path, "Match2", 0x10002000, "NEAR_MATCHING")
        self._make_c(tmp_path, "Stub1", 0x10003000, "STUB")
        self._make_c(tmp_path, "Exact1", 0x10004000, "EXACT")

        results = find_all_matching(tmp_path)
        names = [r.filepath.stem for r in results]
        assert "Match1" in names
        assert "Match2" in names
        assert "Stub1" not in names
        assert "Exact1" not in names

    def test_sorted_by_delta_then_size(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "NoDelta", 0x10003000, "NEAR_MATCHING", size=50)
        self._make_c(tmp_path, "BigDelta", 0x10001000, "NEAR_MATCHING", "8B diff", size=100)
        self._make_c(tmp_path, "SmallDelta", 0x10002000, "NEAR_MATCHING", "1B diff", size=200)

        results = find_all_matching(tmp_path)
        names = [r.filepath.stem for r in results]
        assert names[0] == "SmallDelta"
        assert names[1] == "BigDelta"
        assert names[2] == "NoDelta"

    def test_empty_dir(self, tmp_path: Path) -> None:
        results = find_all_matching(tmp_path)
        assert results == []

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        results = find_all_matching(tmp_path / "nonexistent")
        assert results == []

    def test_duplicate_va_keeps_first(self, tmp_path: Path) -> None:
        self._make_c(tmp_path, "Dup1", 0x10001000, "NEAR_MATCHING")
        f2 = tmp_path / "dup2.c"
        f2.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: NEAR_MATCHING\n"
            "// SIZE: 100\n"
            "// CFLAGS: /O2 /Gd\n"
            "// SYMBOL: _Dup2\n"
            "int __cdecl Dup2(void) { return 0; }\n",
            encoding="utf-8",
        )
        results = find_all_matching(tmp_path, warn_duplicates=False)
        assert len(results) == 1


# -------------------------------------------------------------------------
# update_cflags_annotation
# -------------------------------------------------------------------------


class TestUpdateCflagsAnnotation:
    """update_cflags_annotation now writes CFLAGS to the metadata (not inline)."""

    def _make_source(self, tmp_path: Path) -> Path:
        f = tmp_path / "func.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "// STATUS: NEAR_MATCHING\n"
            "int __cdecl func(void) { return 0; }\n",
            encoding="utf-8",
        )
        return f

    def test_updates_cflags_to_metadata(self, tmp_path: Path) -> None:
        """update_cflags_annotation writes CFLAGS to the metadata, not inline."""
        f = self._make_source(tmp_path)
        changed = update_cflags_annotation(f, "/O1 /Gz")
        assert changed is True
        # Verify metadata was written
        metadata_toml = tmp_path / "rebrew-function.toml"
        assert metadata_toml.exists()
        content = metadata_toml.read_text(encoding="utf-8")
        assert "/O1 /Gz" in content
        # Source file itself should be unchanged (no inline CFLAGS written)
        source = f.read_text(encoding="utf-8")
        assert "CFLAGS" not in source

    def test_no_change_when_same(self, tmp_path: Path) -> None:
        """update_cflags_annotation returns False when metadata already has same value."""
        f = self._make_source(tmp_path)
        # Write initial value
        update_cflags_annotation(f, "/O2 /Gd")
        # Now write same value again
        changed = update_cflags_annotation(f, "/O2 /Gd")
        assert changed is False

    def test_no_change_when_no_marker(self, tmp_path: Path) -> None:
        """Returns False when no FUNCTION/STUB marker can be found in the file."""
        f = tmp_path / "no_cflags.c"
        f.write_text(
            "int main() { return 0; }\n",
            encoding="utf-8",
        )
        changed = update_cflags_annotation(f, "/O1 /Gz")
        assert changed is False

    def test_preserves_source_file(self, tmp_path: Path) -> None:
        """The source .c file must not be modified when updating via metadata."""
        f = self._make_source(tmp_path)
        original = f.read_text(encoding="utf-8")
        update_cflags_annotation(f, "/O1 /Gz")
        assert f.read_text(encoding="utf-8") == original


class TestStubMetadataDir:
    """Stub discovery must read SIZE/STATUS from cfg.metadata_dir, which is
    the reversed_dir PARENT in the standard layout (rebrew-function.toml at
    src/, not next to each .c file)."""

    def _make(self, tmp_path: Path) -> tuple[Path, Path, Any]:
        reversed_dir = tmp_path / "src" / "game"
        reversed_dir.mkdir(parents=True)
        f = reversed_dir / "func.c"
        f.write_text(
            "// STUB: SERVER 0x10001000\nvoid __cdecl func(void) {}\n",
            encoding="utf-8",
        )
        meta = tmp_path / "src" / "rebrew-function.toml"
        meta.write_text('["SERVER.0x10001000"]\nsize = 64\nstatus = "STUB"\n', encoding="utf-8")
        cfg = SimpleNamespace(
            reversed_dir=reversed_dir,
            metadata_dir=tmp_path / "src",
            source_ext=".c",
            marker="SERVER",
            ignored_symbols=[],
        )
        return reversed_dir, f, cfg

    def test_parse_with_explicit_metadata_dir(self, tmp_path: Path) -> None:
        _, f, cfg = self._make(tmp_path)
        # Legacy default (filepath.parent) misses the size -> no stub.
        assert parse_stub_info(f) == []
        # Correct metadata dir finds it.
        stubs = parse_stub_info(f, metadata_dir=cfg.metadata_dir)
        assert len(stubs) == 1
        assert stubs[0].size == 64

    def test_find_all_stubs_uses_cfg_metadata_dir(self, tmp_path: Path) -> None:
        reversed_dir, _, cfg = self._make(tmp_path)
        stubs = find_all_stubs(reversed_dir, cfg=cfg)
        assert len(stubs) == 1
        assert stubs[0].size == 64
        assert stubs[0].va == "0x10001000"


class TestGADeadline:
    """BinaryMatchingGA.run(deadline=...) cooperatively stops between
    generations — the thread-safe replacement for SIGALRM."""

    def test_past_deadline_returns_immediately(self, tmp_path: Path) -> None:
        import time

        from rebrew.match import BinaryMatchingGA

        ga = BinaryMatchingGA(
            seed_source="int f(void) { return 0; }",
            target_bytes=b"\xc3",
            cl_cmd="cl",
            inc_dir="",
            cflags="/O2",
            symbol="_f",
            out_dir=tmp_path,
            num_generations=100,
            pop_size=4,
            num_jobs=1,
        )
        t0 = time.monotonic()
        src, score = ga.run(deadline=time.monotonic() - 1)
        assert time.monotonic() - t0 < 5  # no compile happened
        assert src is None
        assert score == float("inf")

    def test_future_deadline_runs_at_least_one_gen(self, tmp_path: Path) -> None:
        import time

        from rebrew.match import BinaryMatchingGA

        ga = BinaryMatchingGA(
            seed_source="int f(void) { return 0; }",
            target_bytes=b"\xc3",
            cl_cmd="cl",
            inc_dir="",
            cflags="/O2",
            symbol="_f",
            out_dir=tmp_path,
            num_generations=1,
            pop_size=4,
            num_jobs=1,
        )
        ga.run(deadline=time.monotonic() + 60)
        # best_score starts as inf; the previous `or best_score == inf` branch
        # passed even when no generation ran. Require elapsed time from a gen.
        assert ga.elapsed_sec > 0


class TestRunAllParallel:
    """Batch --all processes stubs in parallel with deterministic order."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            reversed_dir=tmp_path,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            ignored_symbols=[],
            target_name="SERVER",
            root=tmp_path,
            target_binary=tmp_path / "x.dll",
        )

    def test_parallel_batch_processes_all_in_order(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        from rebrew.match import StubInfo, _run_all

        stubs = [
            StubInfo(
                filepath=tmp_path / f"s{i}.c",
                va=f"0x1000{i}000",
                size=64,
                symbol=f"_s{i}",
                cflags="/O2",
                status="STUB",
                module="SERVER",
            )
            for i in range(3)
        ]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        seen: list[tuple[str, int]] = []

        def _fake_run(stub, cfg, generations, pop, jobs, timeout, seeds=None, cflags_override=None):
            seen.append((stub.symbol, jobs))
            return False, "best_score=5.00"

        monkeypatch.setattr("rebrew.match._run_one_stub_ga", _fake_run)
        cfg = self._cfg(tmp_path)
        _run_all(
            cfg,
            jobs=2,
            generations=1,
            pop_size=1,
            timeout_min=1,
            dry_run=False,
            min_size=0,
            max_size=9999,
            filter_str="",
            near_miss=False,
            improve=False,
            threshold=10,
            flag_sweep=False,
            fix_cflags=False,
            max_stubs=0,
            seed_from_solved=False,
            json_output=True,
            tier="targeted",
        )
        # All three stubs processed; intra-GA jobs serialized to keep total
        # concurrency at ~jobs in the parallel path.
        assert sorted(s for s, _j in seen) == ["_s0", "_s1", "_s2"]
        assert all(j == 1 for _, j in seen)

    def test_serial_batch_keeps_intra_jobs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.match import StubInfo, _run_all

        stubs = [
            StubInfo(
                filepath=tmp_path / "s.c",
                va="0x10001000",
                size=64,
                symbol="_s",
                cflags="/O2",
                status="STUB",
                module="SERVER",
            )
        ]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        seen: list[int] = []

        def _fake_run(stub, cfg, generations, pop, jobs, timeout, seeds=None, cflags_override=None):
            seen.append(jobs)
            return False, "best_score=5.00"

        monkeypatch.setattr("rebrew.match._run_one_stub_ga", _fake_run)
        _run_all(
            self._cfg(tmp_path),
            jobs=1,
            generations=1,
            pop_size=1,
            timeout_min=1,
            dry_run=False,
            min_size=0,
            max_size=9999,
            filter_str="",
            near_miss=False,
            improve=False,
            threshold=10,
            flag_sweep=False,
            fix_cflags=False,
            max_stubs=0,
            seed_from_solved=False,
            json_output=True,
            tier="targeted",
        )
        assert seen == [1]  # serial path passes jobs through


class TestFlagSweepIncludeDirs:
    """flag_sweep must pass the source directory through so relative
    includes (e.g. `#include "../../Units/Error/error.h"`) resolve."""

    def test_extra_include_dirs_forwarded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.matcher.compiler import flag_sweep

        seen: dict = {}

        def _fake_build(*a: Any, **k: Any) -> Any:
            seen["extra_include_dirs"] = k.get("extra_include_dirs")
            return SimpleNamespace(ok=True, obj_bytes=b"\x55\x8b\xec\x5d\xc3", reloc_offsets=None)

        monkeypatch.setattr("rebrew.matcher.compiler.build_candidate_obj_only", _fake_build)
        flag_sweep(
            "int f(void){return 0;}",
            b"\x55\x8b\xec\x5d\xc3",
            "cl",
            "",
            "/O2",
            "_f",
            n_jobs=1,
            tier="quick",
            extra_include_dirs=["/src/fn_dir"],
        )
        assert seen.get("extra_include_dirs") == ["/src/fn_dir"]

    def test_single_sweep_passes_seed_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The single-function CLI path resolves the seed file's directory."""
        from rebrew.match import _run_single_flag_sweep

        seen: dict = {}

        def _fake_flag_sweep(*a: Any, **k: Any) -> list[tuple[float, str]]:
            seen["extra_include_dirs"] = k.get("extra_include_dirs")
            return [(0.0, "/O2")]

        monkeypatch.setattr("rebrew.match.flag_sweep", _fake_flag_sweep)
        monkeypatch.setattr(
            "rebrew.match.build_candidate_obj_only",
            lambda *a, **k: SimpleNamespace(ok=True, obj_bytes=b"\xc3", reloc_offsets=None),
        )
        p = SimpleNamespace(
            seed_src="int f(void){return 0;}",
            target_bytes=b"\xc3",
            cl="cl",
            inc="",
            cflags="/O2",
            symbol="_f",
            seed_c=tmp_path / "src" / "fn.c",
            msvc_env={},
            cc=None,
            cfg=SimpleNamespace(compile_timeout=60),
        )
        _run_single_flag_sweep(p, "quick", 1, False)
        assert seen.get("extra_include_dirs") == [str((tmp_path / "src").resolve())]


class TestSweepThenGa:
    """--sweep-then-ga: flag-sweep each stub, then GA with the best flags."""

    def test_uses_sweep_flags(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.match import StubInfo, _run_all

        stubs = [
            StubInfo(
                filepath=tmp_path / "s.c",
                va="0x10001000",
                size=64,
                symbol="_s",
                cflags="/O2 /Gd",
                status="STUB",
                module="SERVER",
            )
        ]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        monkeypatch.setattr(
            "rebrew.match.run_flag_sweep",
            lambda stub, cfg, tier="targeted", jobs=4: (100.0, "/O2 /G3", []),
        )
        seen: dict = {}

        def _fake_run(stub, cfg, generations, pop, jobs, timeout, seeds=None, cflags_override=None):
            seen["override"] = cflags_override
            return False, "best_score=5.00"

        monkeypatch.setattr("rebrew.match._run_one_stub_ga", _fake_run)
        cfg = SimpleNamespace(
            reversed_dir=tmp_path,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            ignored_symbols=[],
            target_name="SERVER",
            root=tmp_path,
            target_binary=tmp_path / "x.dll",
        )
        _run_all(
            cfg,
            jobs=1,
            generations=1,
            pop_size=1,
            timeout_min=1,
            dry_run=False,
            min_size=0,
            max_size=9999,
            filter_str="",
            near_miss=False,
            improve=False,
            threshold=10,
            flag_sweep=False,
            fix_cflags=False,
            max_stubs=0,
            seed_from_solved=False,
            json_output=True,
            tier="targeted",
            sweep_then_ga=True,
        )
        assert seen.get("override") == "/O2 /G3"

    def test_sweep_failure_falls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.match import StubInfo, _run_all

        stubs = [
            StubInfo(
                filepath=tmp_path / "s.c",
                va="0x10001000",
                size=64,
                symbol="_s",
                cflags="/O2 /Gd",
                status="STUB",
                module="SERVER",
            )
        ]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        monkeypatch.setattr(
            "rebrew.match.run_flag_sweep",
            lambda stub, cfg, tier="targeted", jobs=4: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        seen: dict = {}

        def _fake_run(stub, cfg, generations, pop, jobs, timeout, seeds=None, cflags_override=None):
            seen["override"] = cflags_override
            return False, "best_score=5.00"

        monkeypatch.setattr("rebrew.match._run_one_stub_ga", _fake_run)
        cfg = SimpleNamespace(
            reversed_dir=tmp_path,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            ignored_symbols=[],
            target_name="SERVER",
            root=tmp_path,
            target_binary=tmp_path / "x.dll",
        )
        _run_all(
            cfg,
            jobs=1,
            generations=1,
            pop_size=1,
            timeout_min=1,
            dry_run=False,
            min_size=0,
            max_size=9999,
            filter_str="",
            near_miss=False,
            improve=False,
            threshold=10,
            flag_sweep=False,
            fix_cflags=False,
            max_stubs=0,
            seed_from_solved=False,
            json_output=True,
            tier="targeted",
            sweep_then_ga=True,
        )
        assert seen.get("override") is None  # fell back to stub.cflags


class TestSkipRecent:
    """--skip-recent: stubs with a recent ga_runs record are skipped."""

    def test_skips_recently_run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from datetime import UTC, datetime, timedelta

        from rebrew.match import StubInfo, _filter_recently_run

        cfg = SimpleNamespace(root=tmp_path, target_name="SERVER", reversed_dir=tmp_path)
        stubs = [
            StubInfo(
                filepath=tmp_path / f"s{i}.c",
                va=f"0x1000{i}000",
                size=64,
                symbol=f"_s{i}",
                cflags="/O2",
                status="STUB",
                module="SERVER",
            )
            for i in range(3)
        ]
        runs = tmp_path / ".rebrew"
        runs.mkdir(parents=True)
        now = datetime.now(UTC).isoformat()
        old = (datetime.now(UTC) - timedelta(hours=5)).isoformat()
        (runs / "ga_runs.jsonl").write_text(
            f'{{"ts": "{now}", "target": "SERVER", "va": "0x10000000", "symbol": "_s0", "matched": false}}\n'
            f'{{"ts": "{old}", "target": "SERVER", "va": "0x10001000", "symbol": "_s1", "matched": false}}\n',
            encoding="utf-8",
        )
        kept = _filter_recently_run(stubs, cfg, hours=2, json_output=True)
        vas = [s.va for s in kept]
        assert "0x10000000" not in vas  # recent -> skipped
        assert "0x10001000" in vas  # old -> kept

    def test_no_records_keeps_all(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.match import StubInfo, _filter_recently_run

        cfg = SimpleNamespace(root=tmp_path, target_name="SERVER")
        stubs = [
            StubInfo(
                filepath=tmp_path / "s.c",
                va="0x10001000",
                size=64,
                symbol="_s",
                cflags="/O2",
                status="STUB",
                module="SERVER",
            )
        ]
        assert _filter_recently_run(stubs, cfg, hours=2, json_output=True) == stubs


class TestOutDirRejection:
    """--out-dir is single-function only; batch mode must reject it, not
    silently drop it."""

    def test_all_rejects_out_dir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from types import SimpleNamespace

        from typer.testing import CliRunner

        from rebrew.match import app

        monkeypatch.setattr(
            "rebrew.match.require_config",
            lambda target=None, json_mode=False: SimpleNamespace(
                root=tmp_path,
                default_jobs=2,
                reversed_dir=tmp_path / "src",
                metadata_dir=tmp_path,
                marker="SERVER",
                target_binary=tmp_path / "x.dll",
            ),
        )
        result = CliRunner().invoke(app, ["--all", "--out-dir", "custom/out"])
        assert result.exit_code != 0
        assert "--out-dir only applies to single-function mode" in result.output

    def test_all_with_default_out_dir_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        from typer.testing import CliRunner

        from rebrew.match import app

        monkeypatch.setattr(
            "rebrew.match.require_config",
            lambda target=None, json_mode=False: SimpleNamespace(
                root=tmp_path,
                default_jobs=2,
                reversed_dir=tmp_path / "src",
                metadata_dir=tmp_path,
                marker="SERVER",
                target_binary=tmp_path / "x.dll",
            ),
        )
        monkeypatch.setattr("rebrew.match._run_all", lambda **kw: None)
        result = CliRunner().invoke(app, ["--all"])
        assert result.exit_code == 0


class TestGaHistory:
    """match --ga-history summarizes .rebrew/ga_runs.jsonl."""

    def _setup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from types import SimpleNamespace

        cfg = SimpleNamespace(root=tmp_path, target_name="SERVER")
        monkeypatch.setattr("rebrew.match.require_config", lambda target=None, json_mode=False: cfg)

    def test_history_summary_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.match import app

        self._setup(tmp_path, monkeypatch)
        runs_dir = tmp_path / ".rebrew"
        runs_dir.mkdir()
        lines = [
            {
                "ts": "2026-08-07T10:00:00+00:00",
                "target": "SERVER",
                "va": "0x1",
                "symbol": "_a",
                "matched": True,
                "score": 0.0,
            },
            {
                "ts": "2026-08-07T10:01:00+00:00",
                "target": "SERVER",
                "va": "0x2",
                "symbol": "_b",
                "matched": False,
                "score": 5000.0,
            },
            {
                "ts": "2026-08-07T10:02:00+00:00",
                "target": "SERVER",
                "va": "0x3",
                "symbol": "_c",
                "matched": False,
            },
            {
                "this is not json",
            },
        ]
        (runs_dir / "ga_runs.jsonl").write_text(
            "".join(json.dumps(item) + "\n" for item in lines if isinstance(item, dict))
            + "{broken\n",
            encoding="utf-8",
        )
        result = CliRunner().invoke(app, ["--ga-history", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["total"] == 3  # broken line skipped
        assert data["matched"] == 1
        assert data["matched_pct"] == round(100.0 / 3, 1)
        assert data["avg_score"] == 2500.0
        assert data["best_score"] == 0.0
        assert len(data["recent"]) == 3
        assert data["recent"][0]["symbol"] == "_c"  # newest first

    def test_history_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.match import app

        self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, ["--ga-history", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["total"] == 0
        assert data["matched"] == 0
        assert data["avg_score"] is None


class TestFlagSweepJsonShape:
    """flag-sweep JSON entries carry the same fields as GA entries (incl.
    exact) for shape-consistent consumers."""

    def test_sweep_items_include_exact(self, tmp_path: Path, monkeypatch, capsys) -> None:
        import json

        from rebrew.match import _run_single_flag_sweep

        monkeypatch.setattr(
            "rebrew.match.flag_sweep",
            lambda *a, **k: [(0.05, "/O2"), (5000.0, "/O1")],
        )
        monkeypatch.setattr(
            "rebrew.match.build_candidate_obj_only",
            lambda *a, **k: SimpleNamespace(ok=True, obj_bytes=b"\xc3", reloc_offsets=None),
        )
        p = SimpleNamespace(
            seed_src="int f(void){return 0;}",
            target_bytes=b"\xc3",
            cl="cl",
            inc="",
            cflags="/O2",
            symbol="_f",
            seed_c=tmp_path / "src" / "fn.c",
            msvc_env={},
            cc=None,
            cfg=SimpleNamespace(compile_timeout=60),
        )
        _run_single_flag_sweep(p, "quick", 1, True)  # json_output=True
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["mode"] == "flag_sweep"
        assert data["exact"] is True  # best 0.05 < 0.1 → exact
        assert data["results"][0]["exact"] is True
        assert data["results"][1]["exact"] is False
        assert "exact" in data["results"][0]
