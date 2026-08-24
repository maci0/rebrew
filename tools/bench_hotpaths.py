"""bench_hotpaths.py — repeatable benchmark of rebrew's pure-Python hot paths.

Measures the Python-bound workloads that dominate real usage (and the test
suite's pure-Python tail), so optimizations are driven by numbers instead of
guesswork:

1. annotation parsing   — ``parse_c_file_multi`` over a synthetic multi-function .c
2. metadata loading     — ``load_metadata`` over a generated rebrew-function.toml
3. catalog grid build   — the real ``catalog --data-json`` pipeline on the fixture binary
4. verify-cache I/O     — save + load of a large VerifyCache
5. near-diag classify   — ``analyze()`` on synthetic byte pairs
6. binary-similarity    — ``score_matrix`` over synthetic signature sets
7. GA candidate scoring — ``score_candidate`` on a real fixture function vs N candidates

Run twice (before/after an optimization) and compare rows:

    uv run python tools/bench_hotpaths.py            # timing table
    uv run python tools/bench_hotpaths.py --json     # machine-readable

The script is deterministic (fixed seeds, synthetic-but-realistic inputs) so
row-to-row deltas reflect code changes, not input noise.
"""

from __future__ import annotations

import argparse
import json
import random
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_FIXTURE = _REPO_ROOT / "tests" / "fixtures" / "mini_pe.exe"

#: Pre-optimization baselines (recorded 2026-08-21, before the profiled
#: optimizations: capstone handle caching, toml reads, _zero_reloc_fields
#: size prefilter, per-call import hoisting).  `--compare` prints the delta
#: against these so an optimization's claim is reproducible.
BASELINES: dict[str, float] = {
    "annotation_parsing": 0.002,
    "metadata_load": 0.087,
    "catalog_grid": 0.016,
    "verify_cache": 0.002,
    "near_diag": 0.031,
    "binary_similarity": 0.020,
    "ga_scoring": 0.361,
    # Follow-on pass baselines (recorded before the follow-on optimizations:
    # metadata-once merge in parse_c_file_multi, diff summary_only fast path,
    # inline register mask, non-detail no-reloc diff normalization).
    "parse_tree": 0.022,
    "diff_structural": 0.409,
    "registry_build": 0.002,
    "status_aggregation": 0.030,
    "compile_cache": 0.003,
    "verify_cached": 0.006,
}


def _timeit(fn: Callable[[], Any], repeat: int = 5) -> float:
    """Best-of-*repeat* wall time for *fn* (seconds)."""
    best = float("inf")
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def bench_annotation_parsing() -> dict[str, float]:
    """parse_c_file_multi over a synthetic 200-function .c."""
    from rebrew.annotation import _PARSE_MEMO, parse_c_file_multi

    blocks = []
    for i in range(200):
        va = 0x10001000 + i * 0x100
        blocks.append(
            f"// FUNCTION: SERVER 0x{va:x}\n"
            f"// NOTE: function {i}\n"
            f"int func_{i}(int a, int b) {{ return a + b; }}\n\n"
        )
    text = "".join(blocks)
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "multi.c"
        src.write_text(text, encoding="utf-8")

        def run() -> None:
            _PARSE_MEMO.clear()  # the parser memo would hide real parse time
            annos = parse_c_file_multi(src, metadata_dir=None)
            assert len(annos) == 200

        return {"ops": 200, "seconds": _timeit(run, repeat=10)}


def bench_metadata_load() -> dict[str, float]:
    """load_metadata over a generated 500-entry rebrew-function.toml."""
    from rebrew.metadata import clear_metadata_cache, load_metadata

    lines: list[str] = []
    for i in range(500):
        va = 0x10001000 + i * 0x100
        lines.append(f'["SERVER.0x{va:x}"]')
        lines.append('status = "EXACT"')
        lines.append(f"size = {64 + i % 8}")
        lines.append('cflags = "/O2"')
    with tempfile.TemporaryDirectory() as d:
        toml = Path(d) / "rebrew-function.toml"
        toml.write_text("\n".join(lines), encoding="utf-8")
        meta_dir = Path(d)

        def run() -> None:
            clear_metadata_cache()
            entries = load_metadata(meta_dir)
            assert len(entries) == 500

        return {"ops": 500, "seconds": _timeit(run, repeat=10)}


def bench_catalog_grid() -> dict[str, float]:
    """The real catalog --data-json pipeline on the fixture binary (once)."""
    from typer.testing import CliRunner

    from rebrew.main import app

    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / "proj"
        (root / "original").mkdir(parents=True)
        (root / "src" / "SERVER").mkdir(parents=True)
        (root / "bin" / "SERVER").mkdir(parents=True)
        import shutil

        shutil.copy(_FIXTURE, root / "original" / "mini_pe.exe")
        (root / "rebrew-project.toml").write_text(
            "[project]\n"
            'name = "bench"\n'
            'default_target = "SERVER"\n\n'
            '[targets."SERVER"]\n'
            'binary = "original/mini_pe.exe"\n'
            'format = "pe"\n'
            'arch = "x86_32"\n'
            'reversed_dir = "src/SERVER"\n'
            'function_list = "src/SERVER/functions.txt"\n'
            'bin_dir = "bin/SERVER"\n'
            'marker = "SERVER"\n\n'
            "[compiler]\n"
            'profile = "gcc-pe"\n'
            'command = "i686-w64-mingw32-gcc"\n'
            'includes = ""\nlibs = ""\ncflags = "-O2"\n',
            encoding="utf-8",
        )
        (root / "src" / "SERVER" / "functions.txt").write_text(
            "0x00401000 11 _func1\n0x00401018 2 _func2\n", encoding="utf-8"
        )
        runner = CliRunner()
        import os

        os.chdir(root)
        # Warm once (writes db/data_*.json); measure a second invocation.
        assert (
            runner.invoke(
                app, ["catalog", "--data-json", "--json"], catch_exceptions=False
            ).exit_code
            == 0
        )

        def run() -> None:
            r = runner.invoke(app, ["catalog", "--data-json", "--json"], catch_exceptions=False)
            assert r.exit_code == 0

        result = {"ops": 1, "seconds": _timeit(run, repeat=5)}
        os.chdir(_REPO_ROOT)
        return result


def bench_verify_cache() -> dict[str, float]:
    """VerifyCache save + load round-trip with 500 entries."""
    from rebrew.verify import VerifyCache, VerifyCacheEntry, VerifyResult

    entries: dict[str, VerifyCacheEntry] = {}
    for i in range(500):
        va = 0x10001000 + i * 0x100
        entries[f"0x{va:08x}"] = VerifyCacheEntry(
            source_hash=f"hash{i}",
            filepath=f"src/f{i}.c",
            mtime_ns=12345 + i,
            result=VerifyResult(
                status="EXACT",
                va=va,
                size=64,
                passed=True,
                message="",
            ),
            cflags="/O2",
        )
    cache = VerifyCache(version=1, target="SERVER", compiler_hash="bench", entries=entries)

    def run() -> None:
        data = cache.to_dict()
        assert VerifyCache.from_dict(data).entries is not None

    return {"ops": 500, "seconds": _timeit(run, repeat=10)}


def bench_near_diag() -> dict[str, float]:
    """near_diag.analyze() over 200 synthetic byte pairs."""
    from rebrew.near_diag import analyze

    mov_ebx = bytes.fromhex("89 d8 c3")
    mov_ecx = bytes.fromhex("89 c8 c3")
    pairs = [(mov_ebx, mov_ecx)] * 200

    def run() -> None:
        for t, c in pairs:
            analyze(t, c, None, 0x1000)

    return {"ops": len(pairs), "seconds": _timeit(run, repeat=5)}


def bench_binary_similarity() -> dict[str, float]:
    """score_matrix over a 600x600 synthetic signature set."""
    import numpy as np

    from rebrew.binary_similarity import score_matrix

    rng = np.random.default_rng(7)
    vocab = [f"op{i}" for i in range(120)]
    sigs_a: list[dict[str, Any]] = []
    sigs_b: list[dict[str, Any]] = []
    for _ in range(600):
        for bucket in (sigs_a, sigs_b):
            hist = {m: int(rng.integers(0, 4)) for m in rng.choice(vocab, size=20, replace=False)}
            bucket.append(
                {
                    "histogram": hist,
                    "calls": int(rng.integers(0, 10)),
                    "branches": int(rng.integers(0, 10)),
                }
            )

    def run() -> None:
        m = score_matrix(sigs_a, sigs_b)
        assert m.shape == (600, 600)

    return {"ops": 600 * 600, "seconds": _timeit(run, repeat=5)}


def bench_ga_scoring() -> dict[str, float]:
    """score_candidate on a realistic ~100-byte function vs 400 mutated candidates.

    The candidate bytes are single-byte-flipped copies of the target so the
    scorer does real disassembly + normalization work (the identical-bytes
    fast path would measure nothing).
    """
    from rebrew.matcher.scoring import score_candidate

    # Hand-assembled x86-32: ebp frame, 0x20 locals, a counting loop with a
    # memory operand, and a call-like structure — representative of GA targets.
    body = bytes.fromhex(
        "55 8b ec 83 ec 20 56 57 "  # push ebp; mov ebp,esp; sub esp,0x20; push esi; push edi
        "b9 10 00 00 00 "  # mov ecx, 0x10
        "01 4d fc 49 75 fa "  # loop: add [ebp-4],ecx; dec ecx; jnz loop
        "8b 45 fc 03 45 08 89 45 f8 "  # mov eax,[ebp-4]; add eax,[ebp+8]; mov [ebp-8],eax
        "c1 e0 02 89 45 f4 "  # shl eax,2; mov [ebp-0xc],eax
        "5f 5e c9 c3"  # pop edi; pop esi; leave; ret
    )
    target = body * 4  # ~120 bytes, realistic size
    import random

    rng = random.Random(7)
    candidates: list[bytes] = []
    for _ in range(400):
        c = bytearray(target)
        for _ in range(3):
            c[rng.randrange(len(c))] = rng.randrange(256)
        candidates.append(bytes(c))

    def run() -> None:
        for c in candidates:
            score_candidate(target, c)

    return {"ops": len(candidates), "seconds": _timeit(run, repeat=5)}


# ---------------------------------------------------------------------------
# Follow-on pass workloads (project scale)
# ---------------------------------------------------------------------------

_REAL_BODY = bytes.fromhex(
    "55 8b ec 83 ec 20 56 57 "
    "b9 10 00 00 00 "
    "01 4d fc 49 75 fa "
    "8b 45 fc 03 45 08 89 45 f8 "
    "c1 e0 02 89 45 f4 "
    "5f 5e c9 c3"
)


def bench_parse_tree() -> dict[str, float]:
    """parse_c_file_multi + metadata merge over a 1000-function tree."""
    from rebrew.annotation import _PARSE_MEMO, parse_c_file_multi

    blocks = []
    for i in range(1000):
        va = 0x10001000 + i * 0x100
        blocks.append(
            f"// FUNCTION: SERVER 0x{va:x}\n// NOTE: fn {i}\nint f_{i}(int a) {{ return a; }}\n\n"
        )
    with tempfile.TemporaryDirectory() as d:
        meta_dir = Path(d)
        src = meta_dir / "tree.c"
        src.write_text("".join(blocks), encoding="utf-8")
        meta_lines: list[str] = []
        for i in range(1000):
            va = 0x10001000 + i * 0x100
            meta_lines += [f'["SERVER.0x{va:x}"]', 'status = "STUB"', "size = 64"]
        (meta_dir / "rebrew-function.toml").write_text("\n".join(meta_lines), encoding="utf-8")

        def run() -> None:
            _PARSE_MEMO.clear()
            anns = parse_c_file_multi(src, metadata_dir=meta_dir)
            assert len(anns) == 1000

        return {"ops": 1000, "seconds": _timeit(run, repeat=5)}


def bench_diff_structural() -> dict[str, float]:
    """diff_functions + structural_similarity over 200 realistic pairs."""
    from rebrew.matcher.scoring import diff_functions, structural_similarity

    target = _REAL_BODY * 4
    rng = random.Random(11)
    candidates: list[bytes] = []
    for _ in range(200):
        c = bytearray(target)
        for _ in range(3):
            c[rng.randrange(len(c))] = rng.randrange(256)
        candidates.append(bytes(c))

    def run() -> None:
        for c in candidates:
            diff_functions(target, c, None, as_dict=True)
            structural_similarity(target, c)

    return {"ops": len(candidates), "seconds": _timeit(run, repeat=5)}


def bench_registry_build() -> dict[str, float]:
    """parse_function_list + build_function_registry over 2000 entries."""
    from rebrew.catalog.loaders import parse_function_list
    from rebrew.catalog.registry import build_function_registry

    lines = "".join(f"0x{0x401000 + i * 16:08x} {32 + i % 16} f_{i}\n" for i in range(2000))
    with tempfile.TemporaryDirectory() as d:
        fl = Path(d) / "functions.txt"
        fl.write_text(lines, encoding="utf-8")

        def run() -> None:
            funcs = parse_function_list(fl)
            reg = build_function_registry(funcs, None)
            assert len(reg) >= 2000

        return {"ops": 2000, "seconds": _timeit(run, repeat=5)}


def bench_status_aggregation() -> dict[str, float]:
    """collect_status over a synthetic 500-function project (no verify cache)."""
    from rebrew.config import ProjectConfig
    from rebrew.status import collect_status

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        src_dir = root / "src" / "SERVER"
        src_dir.mkdir(parents=True)
        flines: list[str] = []
        for i in range(500):
            va = 0x10001000 + i * 0x100
            flines.append(f"0x{va:08x} 64 f_{i}")
            (src_dir / f"f_{i}.c").write_text(
                f"// STUB: SERVER 0x{va:x}\nvoid f_{i}(void) {{}}\n", encoding="utf-8"
            )
        (src_dir / "functions.txt").write_text("\n".join(flines), encoding="utf-8")
        meta_lines: list[str] = []
        for i in range(500):
            va = 0x10001000 + i * 0x100
            meta_lines += [f'["SERVER.0x{va:x}"]', 'status = "STUB"', "size = 64"]
        (root / "rebrew-function.toml").write_text("\n".join(meta_lines), encoding="utf-8")
        cfg = ProjectConfig(
            target_name="SERVER",
            target_binary=root / "nope.exe",
            arch="x86_32",
            root=root,
            reversed_dir=src_dir,
            function_list=src_dir / "functions.txt",
            marker="SERVER",
            source_ext=".c",
            db_dir=root / "db",
        )

        def run() -> None:
            report = collect_status(cfg)
            assert report.total_functions >= 500

        return {"ops": 500, "seconds": _timeit(run, repeat=5)}


def bench_compile_cache() -> dict[str, float]:
    """CompileCache put + get round-trip over 1000 entries."""
    from rebrew.compile_cache import CompileCache

    with tempfile.TemporaryDirectory() as d:
        cc = CompileCache(Path(d) / "cache")
        keys = [f"k{i}" for i in range(1000)]
        blobs = [f"obj{i}".encode() * 32 for i in range(1000)]
        for k, b in zip(keys, blobs, strict=True):
            cc.put(k, b)

        def run() -> None:
            for k in keys:
                assert cc.get(k) is not None

        result = {"ops": len(keys), "seconds": _timeit(run, repeat=5)}
        cc.close()
        return result


def bench_verify_cached() -> dict[str, float]:
    """The incremental verify cache-hit check over 500 sources (source hash +
    header fingerprint — the per-entry cost of an incremental `rebrew verify`)."""
    from rebrew.config import ProjectConfig
    from rebrew.verify import _entry_headers_fp, _source_hash

    with tempfile.TemporaryDirectory() as d:
        src_dir = Path(d) / "src"
        src_dir.mkdir()
        paths: list[Path] = []
        for i in range(500):
            p = src_dir / f"f_{i}.c"
            p.write_text(
                f"// STUB: SERVER 0x{0x10001000 + i * 0x100:x}\nint f_{i}(void) {{ return 0; }}\n"
            )
            paths.append(p)
        cfg = ProjectConfig(root=Path(d), compiler_includes=src_dir)

        def run() -> None:
            for p in paths:
                _source_hash(p)
                _entry_headers_fp(cfg, p, "/O2")

        return {"ops": len(paths), "seconds": _timeit(run, repeat=5)}


_BENCHES: dict[str, Callable[[], dict[str, float]]] = {
    "annotation_parsing": bench_annotation_parsing,
    "metadata_load": bench_metadata_load,
    "catalog_grid": bench_catalog_grid,
    "verify_cache": bench_verify_cache,
    "near_diag": bench_near_diag,
    "binary_similarity": bench_binary_similarity,
    "ga_scoring": bench_ga_scoring,
    # Follow-on pass workloads (project scale).
    "parse_tree": bench_parse_tree,
    "diff_structural": bench_diff_structural,
    "registry_build": bench_registry_build,
    "status_aggregation": bench_status_aggregation,
    "compile_cache": bench_compile_cache,
    "verify_cached": bench_verify_cached,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Print speedup vs the recorded BASELINES (reproducible proof)",
    )
    parser.add_argument(
        "--bench",
        action="append",
        help="Only run these benches (repeatable); default: all",
    )
    args = parser.parse_args()

    names = args.bench or list(_BENCHES)
    results: dict[str, dict[str, Any]] = {}
    for name in names:
        fn = _BENCHES[name]
        row = fn()
        rate = row["ops"] / row["seconds"] if row["seconds"] else float("inf")
        results[name] = {**row, "ops_per_sec": round(rate, 1)}
        if args.compare:
            base = BASELINES.get(name)
            if base and base > 0:
                speedup = base / row["seconds"]
                marker = "OK " if speedup >= 1.3 else "   "
                print(
                    f"{name:20} {row['seconds']:.3f}s  ({rate:,.0f} ops/s)  "
                    f"{marker}{speedup:.2f}x vs baseline"
                )
            else:
                print(f"{name:20} {row['seconds']:.3f}s  ({rate:,.0f} ops/s)  (no baseline)")
        else:
            print(f"{name:20} {row['seconds']:.3f}s  ({rate:,.0f} ops/s)")

    if args.json:
        print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
