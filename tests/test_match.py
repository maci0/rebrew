"""Tests for rebrew.match — BinaryMatchingGA initialization and population logic."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew.match import BinaryMatchingGA, StubInfo

# ---------------------------------------------------------------------------
# BinaryMatchingGA — init and population
# ---------------------------------------------------------------------------


def _make_ga(tmp_path: Path, **kwargs) -> BinaryMatchingGA:
    """Create a GA instance with minimal valid parameters."""
    defaults = {
        "seed_source": "int f(void) { return 0; }",
        "target_bytes": b"\x55\x8b\xec\xc3",
        "cl_cmd": "wine CL.EXE",
        "inc_dir": "/fake/include",
        "cflags": "/O2 /Gd",
        "symbol": "_f",
        "out_dir": tmp_path / "ga_out",
        "pop_size": 8,
        "num_generations": 2,
        "num_jobs": 1,
        "rng_seed": 42,
    }
    defaults.update(kwargs)
    return BinaryMatchingGA(**defaults)


class TestCompileCflags:
    """_compile_cflags is the ONE shared flag-glue definition for the
    single-function, flag-sweep, and batch-GA paths — a divergent copy in the
    sweep path silently dropped base_cflags (e.g. /MT), so a sweep-reported
    exact demoted on the next test/verify.  Every branch needs a test
    (config-review F8)."""

    def test_posix_style_prepends_base(self) -> None:
        from rebrew.match import _compile_cflags

        assert _compile_cflags("/O2", "-O2", posix_style=True) == "-O2 /O2"

    def test_posix_style_no_base(self) -> None:
        from rebrew.match import _compile_cflags

        assert _compile_cflags("/O2", "", posix_style=True) == "/O2"

    def test_msvc_base_with_c_glue(self) -> None:
        """base_cf carries /c → base first, no /nologo /c insertion."""
        from rebrew.match import _compile_cflags

        assert _compile_cflags("/O2 /Gd", "/nologo /c /MT") == "/nologo /c /MT /O2 /Gd"

    def test_msvc_base_without_c_inserts_glue(self) -> None:
        """base_cf lacks /c and cflags lacks it → the /nologo /c glue is
        inserted (the watcom E1139 regression class)."""
        from rebrew.match import _compile_cflags

        assert _compile_cflags("/O2", "/MT") == "/nologo /c /MT /O2"

    def test_cflags_already_has_c(self) -> None:
        """cflags already carries /c → passed through verbatim."""
        from rebrew.match import _compile_cflags

        assert _compile_cflags("/nologo /c /O1", "") == "/nologo /c /O1"


class TestBinaryMatchingGAInit:
    """Tests for BinaryMatchingGA constructor and _init_population."""

    def test_population_size(self, tmp_path: Path) -> None:
        """Population is initialized to pop_size."""
        ga = _make_ga(tmp_path, pop_size=16)
        assert len(ga.population) == 16

    def test_seed_source_in_population(self, tmp_path: Path) -> None:
        """Seed source is always the first member of the population."""
        seed = "int original(void) { return 42; }"
        ga = _make_ga(tmp_path, seed_source=seed)
        assert ga.population[0] == seed

    def test_best_score_starts_infinite(self, tmp_path: Path) -> None:
        """Best score starts at infinity before any evaluation."""
        ga = _make_ga(tmp_path)
        assert ga.best_score == float("inf")

    def test_best_source_starts_none(self, tmp_path: Path) -> None:
        """Best source starts as None before any evaluation."""
        ga = _make_ga(tmp_path)
        assert ga.best_source is None

    def test_stagnant_gens_starts_zero(self, tmp_path: Path) -> None:
        """Stagnation counter starts at zero."""
        ga = _make_ga(tmp_path)
        assert ga.stagnant_gens == 0

    def test_deterministic_with_seed(self, tmp_path: Path) -> None:
        """Same RNG seed produces same initial population."""
        ga1 = _make_ga(tmp_path / "run1", rng_seed=123, pop_size=8)
        ga2 = _make_ga(tmp_path / "run2", rng_seed=123, pop_size=8)
        assert ga1.population == ga2.population

    def test_different_seeds_differ(self, tmp_path: Path) -> None:
        """Different RNG seeds produce different populations."""
        ga1 = _make_ga(tmp_path / "run1", rng_seed=1, pop_size=8)
        ga2 = _make_ga(tmp_path / "run2", rng_seed=2, pop_size=8)
        # Count how many non-seed members differ between the two populations
        differ_count = sum(
            1 for a, b in zip(ga1.population[1:], ga2.population[1:], strict=True) if a != b
        )
        # At least half the non-seed members should differ
        assert differ_count >= len(ga1.population[1:]) // 2, (
            f"Only {differ_count}/{len(ga1.population) - 1} members differ between seeds"
        )

    def test_cache_created(self, tmp_path: Path) -> None:
        """Build cache is initialized."""
        ga = _make_ga(tmp_path)
        assert ga.cache is not None

    def test_mutation_weights_default_empty(self, tmp_path: Path) -> None:
        """Default mutation weights are empty dict."""
        ga = _make_ga(tmp_path)
        assert ga.mutation_weights == {}

    def test_custom_mutation_weights(self, tmp_path: Path) -> None:
        """Custom mutation weights are preserved."""
        weights = {"commute_add": 2.0, "flip_comparison": 0.5}
        ga = _make_ga(tmp_path, mutation_weights=weights)
        assert ga.mutation_weights == weights

    def test_compare_obj_default_true(self, tmp_path: Path) -> None:
        """compare_obj defaults to True (OBJ-only mode)."""
        ga = _make_ga(tmp_path)
        assert ga.compare_obj is True

    def test_elitism_default(self, tmp_path: Path) -> None:
        """Default elitism is 4."""
        ga = _make_ga(tmp_path)
        assert ga.elitism == 4

    def test_stagnation_limit_default(self, tmp_path: Path) -> None:
        """Default stagnation limit is 40."""
        ga = _make_ga(tmp_path)
        assert ga.stagnation_limit == 40

    def test_env_stored(self, tmp_path: Path) -> None:
        """Custom env dict is stored."""
        env = {"WINEDEBUG": "-all", "LIB": "/fake/lib"}
        ga = _make_ga(tmp_path, env=env)
        assert ga.env == env

    def test_output_dir_created(self, tmp_path: Path) -> None:
        """Output directory path is stored as Path."""
        ga = _make_ga(tmp_path)
        assert isinstance(ga.out_dir, Path)


# ---------------------------------------------------------------------------
# _compute_fitness edge cases
# ---------------------------------------------------------------------------


class TestComputeFitness:
    """Tests for _compute_fitness logic without actually compiling."""

    def test_failed_build_returns_high_score(self, tmp_path: Path) -> None:
        """Failed build result should return a very high penalty score."""
        from rebrew.matcher import BuildResult

        ga = _make_ga(tmp_path)
        res = BuildResult(ok=False, error_msg="compiler not found")
        score = ga._compute_fitness(res, "test_hash", "int f() { return 0; }")
        assert score == 10000000.0

    def test_none_obj_bytes_returns_high_score(self, tmp_path: Path) -> None:
        """Build result with ok=True but no obj_bytes returns high score."""
        from rebrew.matcher import BuildResult

        ga = _make_ga(tmp_path)
        res = BuildResult(ok=True, obj_bytes=None)
        score = ga._compute_fitness(res, "test_hash", "int f() { return 0; }")
        assert score == 10000000.0

    def test_cached_fitness_skips_rescore(self, tmp_path: Path) -> None:
        """A BuildResult already carrying a fitness returns it without
        re-scoring (perf-review F6 — the warm-cache fast path)."""
        from rebrew.matcher import BuildResult

        ga = _make_ga(tmp_path)
        res = BuildResult(ok=True, obj_bytes=b"\x55\x8b\xec\xc3", fitness=42.5)
        score = ga._compute_fitness(res, "test_hash", "int f() { return 0; }")
        assert score == 42.5

    def test_scored_result_memoizes_fitness(self, tmp_path: Path) -> None:
        """After a real score computation, the fitness is stored on the
        BuildResult so a later cache hit skips the numpy work."""
        from rebrew.matcher import BuildResult

        ga = _make_ga(tmp_path)
        res = BuildResult(ok=True, obj_bytes=b"\x55\x8b\xec\xc3")
        assert res.fitness is None
        score = ga._compute_fitness(res, "test_hash", "int f() { return 0; }")
        assert res.fitness == score
        assert score == ga._compute_fitness(res, "test_hash", "int f() { return 0; }")

    def test_fresh_pickle_result_skips_rescore_via_memo(self, tmp_path: Path) -> None:
        """A BuildResult freshly unpickled from the disk cache carries
        fitness=None (the field is populated after put), so the warm path
        must consult the process-local memo — the disk-backed BuildCache
        alone could never trigger the old getattr fast path (perf-review
        F6: elites persist across generations, so this is the real win)."""
        from rebrew.matcher import BuildResult

        ga = _make_ga(tmp_path)
        first = BuildResult(ok=True, obj_bytes=b"\x55\x8b\xec\xc3")
        score = ga._compute_fitness(first, "same_src_hash", "int f() { return 0; }")
        # Simulate a cache.get(): a fresh object with the same key but no
        # fitness field populated.
        second = BuildResult(ok=True, obj_bytes=b"\x55\x8b\xec\xc3")
        assert second.fitness is None
        assert ga._compute_fitness(second, "same_src_hash", "int f() { return 0; }") == score

    def test_memo_hit_skips_compile_pool(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A generation whose whole population is already in the process-local
        fitness memo must NOT submit _compile_source (perf-review F5) — the
        old code always ran the disk BuildCache round-trip first and only then
        found the memo.  Prefill the memo for every member and make any
        compile call explode."""
        from rebrew.compile_cache import _source_digest

        ga = _make_ga(tmp_path, num_generations=1, pop_size=4)
        for src in ga.population:
            ga._fitness_memo[_source_digest(src)] = 5.0
        calls: list[str] = []

        def boom(src: str) -> Any:
            calls.append(src)
            raise AssertionError("memoized source must not reach the compile pool")

        monkeypatch.setattr(ga, "_compile_source", boom)
        best_src, best_score = ga._run_inner()
        assert calls == []
        assert best_score == 5.0
        assert best_src in ga.population


# ---------------------------------------------------------------------------
# Batch orchestration (_run_all): discovery, filtering, dry-run, execution
# ---------------------------------------------------------------------------


class TestRunAllBatch:
    """The batch driver: discovery filtering, dry-run JSON, GA execution with
    per-run persistence, and error isolation (one bad stub must not abort)."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            reversed_dir=tmp_path / "src" / "T",
            root=tmp_path,
            target_name="T",
            ignored_symbols=[],
            metadata_dir=tmp_path,
            image_base=0x10000000,
            dll_exports={},
            target_binary=tmp_path / "test.dll",
            function_list="",
            all_targets=["T"],
        )

    def _stub(self, name: str, va: str = "0x10001000", size: int = 100) -> StubInfo:
        return StubInfo(
            filepath=Path(name),
            va=va,
            size=size,
            symbol=name,
            cflags="/O2",
            status="STUB",
            module="T",
        )

    def _run(
        self,
        cfg: SimpleNamespace,
        *,
        dry_run: bool = False,
        json_output: bool = False,
        min_size: int = 0,
        max_size: int = 9999,
        filter_str: str = "",
        max_stubs: int = 0,
        skip_recent_hours: int = 0,
        jobs: int = 1,
        seed_from_solved: bool = False,
        sweep_then_ga: bool = False,
        flag_sweep: bool = False,
    ) -> tuple[int, int]:
        from rebrew.match import _run_all

        return _run_all(
            cfg,
            jobs=jobs,
            generations=5,
            pop_size=4,
            timeout_min=1,
            dry_run=dry_run,
            min_size=min_size,
            max_size=max_size,
            filter_str=filter_str,
            near_miss=False,
            improve=False,
            threshold=10,
            flag_sweep=flag_sweep,
            fix_cflags=False,
            max_stubs=max_stubs,
            seed_from_solved=seed_from_solved,
            json_output=json_output,
            tier="targeted",
            sweep_then_ga=sweep_then_ga,
            skip_recent_hours=skip_recent_hours,
        )

    def test_dry_run_json_lists_stubs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        stubs = [self._stub("a.c"), self._stub("b.c", "0x10001010", 200)]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        out = self._run(self._cfg(tmp_path), dry_run=True, json_output=True)
        assert out == (0, 0)

    def test_size_and_string_filters(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        import json

        stubs = [
            self._stub("a.c", "0x10001000", 50),
            self._stub("b.c", "0x10001010", 200),
            self._stub("c.c", "0x10001020", 300),
        ]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        cfg = self._cfg(tmp_path)
        # min_size + filter_str + max_stubs compose.
        self._run(cfg, dry_run=True, json_output=True, min_size=100, filter_str="b.c")
        data = json.loads(capsys.readouterr().out)
        # Only b.c (200B) survives both filters.
        assert data["count"] == 1
        assert data["items"][0]["symbol"] == "b.c"

    def test_skip_recent_filters(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:

        stubs = [self._stub("a.c"), self._stub("b.c")]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        monkeypatch.setattr("rebrew.match._filter_recently_run", lambda s, cfg, hours, j: [s[1]])
        out = self._run(self._cfg(tmp_path), dry_run=True, json_output=True, skip_recent_hours=24)
        assert out == (0, 0)

    def test_ga_run_persists_result(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:

        stubs = [self._stub("a.c")]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        calls: list[tuple] = []

        def _fake_ga(
            stub,
            cfg,
            gens,
            pop,
            jobs,
            timeout,
            seeds,
            cflags_override=None,
            rng_seed=None,
            resume_from=None,
            mutation_weights=None,
            solutions_out=None,
        ):
            return True, "MATCHED"

        def _fake_record(root, *, target, va, symbol, matched):
            calls.append((str(root), target, va, symbol, matched))

        monkeypatch.setattr("rebrew.match._run_one_stub_ga", _fake_ga)
        monkeypatch.setattr("rebrew.matcher.solutions.record_ga_run", _fake_record)
        matched, failed = self._run(self._cfg(tmp_path), json_output=True)
        assert (matched, failed) == (1, 0)
        assert calls == [(str(tmp_path), "T", "0x10001000", "a.c", True)]

    def test_failed_stub_does_not_abort_batch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        stubs = [self._stub("bad.c"), self._stub("good.c", "0x10001010")]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)

        def _fake_ga(
            stub,
            cfg,
            gens,
            pop,
            jobs,
            timeout,
            seeds,
            cflags_override=None,
            rng_seed=None,
            resume_from=None,
            mutation_weights=None,
            solutions_out=None,
        ):
            if "bad" in stub.symbol:
                raise RuntimeError("boom")
            return True, "MATCHED"

        monkeypatch.setattr("rebrew.match._run_one_stub_ga", _fake_ga)
        matched, failed = self._run(self._cfg(tmp_path), json_output=True)
        assert (matched, failed) == (1, 1)

    def test_parallel_path_matches_serial(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        stubs = [self._stub(f"f{i}.c", f"0x1000{i:04x}") for i in range(1, 4)]
        monkeypatch.setattr("rebrew.match.find_all_stubs", lambda *a, **k: stubs)
        monkeypatch.setattr(
            "rebrew.match._run_one_stub_ga",
            lambda stub, cfg, gens, pop, jobs, timeout, seeds, cflags_override=None, rng_seed=None, resume_from=None, mutation_weights=None, solutions_out=None: (
                True,
                "MATCHED",
            ),
        )
        matched, failed = self._run(self._cfg(tmp_path), jobs=2, json_output=True)
        assert (matched, failed) == (3, 0)


class TestUpdateStubToMatched:
    """The GA's stub→matched source splice must target the stub's OWN block."""

    def _stub(self, va: str) -> StubInfo:
        return StubInfo(
            filepath=Path("unused.c"),
            va=va,
            size=10,
            symbol="f",
            cflags="/O2",
            status="STUB",
            module="T",
        )

    def test_splices_second_function_not_first(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.match import update_stub_to_matched

        f = tmp_path / "multi.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "int first(void) { return 1; }\n\n"
            "// FUNCTION: SERVER 0x10002000\n"
            "int second(void) { return 2; }\n",
            encoding="utf-8",
        )
        best = "int second(void) { return 42; }\n"
        update_stub_to_matched(f, best, self._stub("0x10002000"), metadata_dir=tmp_path)
        text = f.read_text(encoding="utf-8")
        assert "return 1;" in text  # first function untouched
        assert "return 42;" in text  # second function spliced
        assert "return 2;" not in text
        # STATUS is metadata-owned — no inline STATUS line is written.
        assert "// STATUS" not in text
        from rebrew.metadata import get_entry

        entry = get_entry(tmp_path, 0x10002000, module="SERVER")
        assert entry.get("status") == "RELOC"

    def test_siblings_after_target_preserved(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The splice must not drop functions that FOLLOW the stub's block
        (round-3: header + best_src truncated everything after the stub)."""
        from rebrew.match import update_stub_to_matched

        f = tmp_path / "multi.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "int first(void) { return 1; }\n\n"
            "// FUNCTION: SERVER 0x10002000\n"
            "int second(void) { return 2; }\n\n"
            "// FUNCTION: SERVER 0x10003000\n"
            "int third(void) { return 3; }\n",
            encoding="utf-8",
        )
        best = "int second(void) { return 42; }\n"
        update_stub_to_matched(f, best, self._stub("0x10002000"), metadata_dir=tmp_path)
        text = f.read_text(encoding="utf-8")
        assert "return 1;" in text
        assert "return 42;" in text
        assert "return 2;" not in text
        assert "return 3;" in text  # sibling AFTER the target survives
        assert "0x10003000" in text


class TestFlagSweepMatchValidation:
    """A flag-sweep "exact" is reloc-masked only — the batch driver must
    confirm it against the symbol catalog (compile_and_compare) before
    promoting EXACT/RELOC (functionality-review F3)."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            root=tmp_path,
            reversed_dir=tmp_path / "src" / "T",
            target_name="T",
            ignored_symbols=[],
            metadata_dir=tmp_path,
            image_base=0x10000000,
            dll_exports={},
            target_binary=tmp_path / "test.dll",
            function_list="",
            all_targets=["T"],
            source_ext=".c",
            base_cflags="",
        )

    def test_unconfirmed_sweep_exact_not_promoted(self, tmp_path, monkeypatch) -> None:
        """The sweep reports score 0 (reloc-masked) but the authoritative
        compile-and-compare rejects it (wrong callee) — STATUS must NOT be
        promoted and no solution saved."""
        from rebrew.match import _run_batch_flag_sweep

        cfg = self._cfg(tmp_path)
        src_dir = tmp_path / "src" / "T"
        src_dir.mkdir(parents=True, exist_ok=True)
        f = src_dir / "near.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n// STATUS: NEAR_MATCHING\n"
            "int near(void) { return 0; }\n",
            encoding="utf-8",
        )
        stub = StubInfo(
            filepath=f,
            va="0x10001000",
            size=64,
            symbol="near",
            cflags="/O2",
            status="NEAR_MATCHING",
            module="SERVER",
        )

        def _fake_sweep(stub, cfg, tier="targeted", jobs=1):
            return 0.0, "/O1", [(0.0, "/O1")]  # reloc-masked exact

        def _fake_compare(cfg, source, symbol, target_bytes, cflags, **kw):
            from rebrew.compile import CompareResult

            return CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=60.0,
                delta=4,
                obj_bytes=b"\x90" * 64,
                reloc_offsets=[],
                message="NEAR_MATCHING: wrong callee (reloc target mismatch)",
            )

        monkeypatch.setattr("rebrew.match.run_flag_sweep", _fake_sweep)
        monkeypatch.setattr("rebrew.compile.compile_and_compare", _fake_compare)
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda *a, **k: b"\x90" * 64)
        calls: list[str] = []
        monkeypatch.setattr(
            "rebrew.metadata.update_source_status", lambda *a, **k: calls.append("status")
        )
        monkeypatch.setattr("rebrew.verify.patch_verify_cache_entries", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.matcher.solutions.save_solutions", lambda *a, **k: None)
        # update_cflags_annotation is a module-level function in match.py —
        # bypass it so the test asserts promotion behavior, not the cflags write.
        monkeypatch.setattr("rebrew.match.update_cflags_annotation", lambda *a, **k: True)

        exact, not_exact = _run_batch_flag_sweep(
            [stub],
            cfg,
            "targeted",
            1,
            fix_cflags=True,
            json_output=True,
            mode_label="sweep",
            name_to_va={"near": 0x10001000},
        )
        assert exact == 0
        assert calls == []  # never promoted

    def test_confirmed_sweep_exact_promoted(self, tmp_path, monkeypatch) -> None:
        """The authoritative compare confirms the reloc-masked exact — the
        promotion proceeds as before."""
        from rebrew.match import _run_batch_flag_sweep

        cfg = self._cfg(tmp_path)
        src_dir = tmp_path / "src" / "T"
        src_dir.mkdir(parents=True, exist_ok=True)
        f = src_dir / "near.c"
        f.write_text(
            "// FUNCTION: SERVER 0x10001000\n// STATUS: NEAR_MATCHING\n"
            "int near(void) { return 0; }\n",
            encoding="utf-8",
        )
        stub = StubInfo(
            filepath=f,
            va="0x10001000",
            size=64,
            symbol="near",
            cflags="/O2",
            status="NEAR_MATCHING",
            module="SERVER",
        )

        def _fake_sweep(stub, cfg, tier="targeted", jobs=1):
            return 0.0, "/O1", [(0.0, "/O1")]

        def _fake_compare(cfg, source, symbol, target_bytes, cflags, **kw):
            from rebrew.compile import CompareResult

            return CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"\x90" * 64,
                reloc_offsets=[],
                message="EXACT MATCH",
            )

        monkeypatch.setattr("rebrew.match.run_flag_sweep", _fake_sweep)
        monkeypatch.setattr("rebrew.compile.compile_and_compare", _fake_compare)
        monkeypatch.setattr("rebrew.binary_loader.extract_raw_bytes", lambda *a, **k: b"\x90" * 64)
        calls: list[str] = []
        monkeypatch.setattr(
            "rebrew.metadata.update_source_status", lambda *a, **k: calls.append("status")
        )
        monkeypatch.setattr("rebrew.verify.patch_verify_cache_entries", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.matcher.solutions.save_solutions", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.match.update_cflags_annotation", lambda *a, **k: True)

        exact, not_exact = _run_batch_flag_sweep(
            [stub],
            cfg,
            "targeted",
            1,
            fix_cflags=True,
            json_output=True,
            mode_label="sweep",
            name_to_va={"near": 0x10001000},
        )
        assert exact == 1
        assert calls == ["status"]  # promoted


class TestFindSizeMismatch:
    """SIZE_MISMATCH functions were unreachable by any batch mode — the GA
    could only target STUBs (--all), NEAR_MATCHING (--improve/--near-miss).
    --size-mismatch closes that gap (np-rebrew TOOLCHAIN_BUGS)."""

    def _write(self, tmp_path: Path, name: str, va: str, status: str) -> Path:
        f = tmp_path / name
        f.write_text(
            f"// FUNCTION: SERVER {va}\n// STATUS: {status}\n// SIZE: 64\n"
            f"int f(void) {{ return 0; }}\n",
            encoding="utf-8",
        )
        return f

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            root=tmp_path,
            reversed_dir=tmp_path,
            metadata_dir=tmp_path,
            marker="SERVER",
            ignored_symbols=[],
            target_name="T",
            source_ext=".c",
        )

    def test_finds_only_size_mismatch(self, tmp_path: Path) -> None:
        from rebrew.match import find_size_mismatch

        self._write(tmp_path, "sm.c", "0x10001000", "SIZE_MISMATCH")
        self._write(tmp_path, "stub.c", "0x10002000", "STUB")
        self._write(tmp_path, "near.c", "0x10003000", "NEAR_MATCHING")
        stubs = find_size_mismatch(tmp_path, cfg=self._cfg(tmp_path))
        assert [s.va for s in stubs] == ["0x10001000"]

    def test_run_all_size_mismatch_mode(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.match import _run_all, find_size_mismatch

        real_find = find_size_mismatch
        self._write(tmp_path, "sm.c", "0x10001000", "SIZE_MISMATCH")
        seen: list[str] = []

        def _fake_find(*a: Any, **k: Any) -> list[Any]:
            stubs = real_find(tmp_path, cfg=self._cfg(tmp_path))
            seen.extend(s.va for s in stubs)
            return stubs

        monkeypatch.setattr("rebrew.match.find_size_mismatch", _fake_find)

        def _fake_ga(*a: Any, **k: Any) -> tuple[bool, str]:
            return False, "best_score=5.00"

        monkeypatch.setattr("rebrew.match._run_one_stub_ga", _fake_ga)
        monkeypatch.setattr("rebrew.matcher.solutions.record_ga_run", lambda *a, **k: None)

        cfg = self._cfg(tmp_path)
        _run_all(
            cfg,
            jobs=1,
            generations=1,
            pop_size=4,
            timeout_min=5,
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
            size_mismatch=True,
        )
        assert seen == ["0x10001000"]


# ---------------------------------------------------------------------------
# resolve_build_params — VA-targeted annotation selection in multi-function
# files (workflow: `rebrew diff 0x<va>` must diff THAT function, not the
# first one in the file)
# ---------------------------------------------------------------------------


class TestResolveBuildParamsVATargeting:
    """Regression: diff/match/prove invoked by VA on a multi-function file
    selected the FIRST annotation (wrong function) when --symbol was absent,
    producing a false 'perfect match' for the wrong bytes."""

    def _cfg(self, tmp_path: Path, src_dir: Path) -> SimpleNamespace:
        return SimpleNamespace(
            reversed_dir=src_dir,
            root=tmp_path,
            target_name="T",
            marker="T",
            metadata_dir=tmp_path,
            image_base=0x10000000,
            compiler_command="wine CL.EXE",
            base_cflags="/O2",
            compiler_includes="inc",
            compiler_libs="lib",
            target_binary=tmp_path / "t.dll",
            cflags="/O2 /Gd",
            default_jobs=1,
        )

    def test_va_selects_matching_annotation(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.annotation import parse_c_file_multi
        from rebrew.match import resolve_build_params

        src_dir = tmp_path / "src" / "T"
        src_dir.mkdir(parents=True)
        multi = src_dir / "multi.c"
        multi.write_text(
            "// FUNCTION: T 0x10001000\n"
            "// SIZE: 8\n"
            "void exit_handler(void) { return; }\n"
            "\n"
            "// FUNCTION: T 0x1000a010\n"
            "// SIZE: 112\n"
            "void cleanup(void) { return; }\n",
            encoding="utf-8",
        )
        cfg = self._cfg(tmp_path, src_dir)
        # extract_raw_bytes reads the target binary — stub it with 112 bytes.
        monkeypatch.setattr("rebrew.match.extract_raw_bytes", lambda *a, **k: b"\x90" * 112)
        # read_source_text + parse must run; compiler env resolution can be stubbed.
        monkeypatch.setattr(
            "rebrew.match.resolve_compiler_env",
            lambda cfg: ("wine CL.EXE", "inc", {"WINEDEBUG": "-all"}, None),
        )

        params = resolve_build_params(
            cfg,
            str(multi),
            None,
            None,
            None,
            None,
            "0x1000a010",
            None,  # target_va = 0x1000a010, target_size=None
            False,
            False,
        )
        assert params.symbol == "_cleanup"
        assert params.target_size == 112  # from the VA-matched annotation, not 8

        # Sanity: without the VA, the fallback would pick the first annotation.
        annos = parse_c_file_multi(multi, target_name="T", metadata_dir=tmp_path)
        assert annos[0].va == 0x10001000
        assert annos[1].va == 0x1000A010

    def test_va_no_match_errors(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A requested VA the resolved file does not annotate must error, not
        silently fall back to the first annotation (wrong-function diff)."""
        import typer

        from rebrew.match import resolve_build_params

        src_dir = tmp_path / "src" / "T"
        src_dir.mkdir(parents=True)
        multi = src_dir / "multi.c"
        multi.write_text(
            "// FUNCTION: T 0x10001000\n// SIZE: 8\nvoid exit_handler(void) { return; }\n",
            encoding="utf-8",
        )
        cfg = self._cfg(tmp_path, src_dir)
        with pytest.raises(typer.Exit) as exc:
            resolve_build_params(
                cfg,
                str(multi),
                None,
                None,
                None,
                None,
                "0x1000a010",  # not annotated in multi.c
                None,
                False,
                False,
            )
        assert exc.value.exit_code == 1

    def test_va_no_match_allowed_with_symbol(self, tmp_path: Path, monkeypatch: Any) -> None:
        """An explicit --symbol is a deliberate override — VA mismatch is allowed."""
        from rebrew.match import resolve_build_params

        src_dir = tmp_path / "src" / "T"
        src_dir.mkdir(parents=True)
        multi = src_dir / "multi.c"
        multi.write_text(
            "// FUNCTION: T 0x10001000\n// SIZE: 8\nvoid exit_handler(void) { return; }\n",
            encoding="utf-8",
        )
        cfg = self._cfg(tmp_path, src_dir)
        monkeypatch.setattr("rebrew.match.extract_raw_bytes", lambda *a, **k: b"\x90" * 8)
        monkeypatch.setattr(
            "rebrew.match.resolve_compiler_env",
            lambda cfg: ("wine CL.EXE", "inc", {"WINEDEBUG": "-all"}, None),
        )
        params = resolve_build_params(
            cfg,
            str(multi),
            None,
            None,
            None,
            "_exit_handler",
            "0x1000a010",  # mismatch, but symbol is explicit
            None,
            False,
            False,
        )
        assert params.symbol == "_exit_handler"


class TestMutationFocusWeights:
    """--mutation-focus biases GA mutation selection toward a near-diag
    category (register / equivalent / structural), or auto via the blocker."""

    def test_explicit_category_weights_its_operators(self) -> None:
        from rebrew.match import _mutation_focus_weights

        weights = _mutation_focus_weights("register")
        assert weights
        # All register-category suggestions get the focus weight.
        assert all(w == 6.0 for w in weights.values())
        assert len(weights) >= 5

    def test_reloc_returns_none(self) -> None:
        from rebrew.match import _mutation_focus_weights

        assert _mutation_focus_weights("reloc") is None

    def test_none_focus_returns_none(self) -> None:
        from rebrew.match import _mutation_focus_weights

        assert _mutation_focus_weights(None) is None

    def test_auto_with_blocker(self) -> None:
        from rebrew.match import _mutation_focus_weights

        weights = _mutation_focus_weights(
            "auto", "NEAR_MATCHING — STRUCTURAL (100% of delta) — try: mut_swap_if_else"
        )
        assert weights
        assert "mut_swap_if_else" in weights

    def test_auto_without_blocker(self) -> None:
        from rebrew.match import _mutation_focus_weights

        assert _mutation_focus_weights("auto", None) is None
        assert _mutation_focus_weights("auto", "plain blocker text") is None

    def test_weights_match_mutator_names(self) -> None:
        """Every weighted operator must exist in mutator.ALL_MUTATIONS."""
        import re
        from pathlib import Path

        from rebrew.match import _mutation_focus_weights
        from rebrew.matcher import mutator

        weights = _mutation_focus_weights("equivalent")
        source = Path(mutator.__file__).read_text(encoding="utf-8")
        defined = set(re.findall(r"^def (mut_\w+)\(", source, re.M))
        for op in weights:
            assert op in defined, f"{op} not in mutator.py"
