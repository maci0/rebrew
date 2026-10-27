"""bench_hotpaths.py — CPU-time microbenchmarks of Rebrew hot paths.

Measures the Python-bound workloads that dominate real usage (and the test
suite's pure-Python tail), so optimizations are driven by numbers instead of
guesswork:

1. annotation parsing   — ``read_source_bindings`` over a synthetic multi-function .c
2. metadata loading     — ``load_metadata`` over a generated rebrew-functions.toml
3. catalog grid build   — the real ``catalog --json`` pipeline on the fixture binary
4. verify-cache I/O     — save + load of a large VerifyCache
5. near-diag classify   — ``analyze()`` on synthetic byte pairs
6. binary-similarity    — ``score_matrix`` over synthetic signature sets
7. GA candidate scoring — ``score_candidate`` on a real fixture function vs N candidates

Run twice (before/after an optimization) and compare rows:

    uv run --frozen python tools/bench_hotpaths.py            # timing table
    uv run --frozen python tools/bench_hotpaths.py --json     # machine-readable

The script is deterministic (fixed seeds, synthetic-but-realistic inputs) so
input selection is repeatable. CPU time excludes descheduling; wall samples
remain visible. Cache states are described by each workload.
"""

from __future__ import annotations

from pathlib import Path
lazy import argparse
lazy import hashlib
lazy import json
lazy import math
lazy import os
lazy import platform
lazy import random
lazy import statistics
lazy import subprocess
lazy import sys
lazy import tempfile
lazy import time
lazy from collections.abc import Callable
lazy from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_FIXTURE = _REPO_ROOT / "tests" / "fixtures" / "mini_pe.exe"


def measure(fn: Callable[[], Any], repeat: int = 7) -> dict[str, Any]:
    """Warm once and retain CPU/wall samples; descheduling is excluded from CPU time."""
    fn()
    cpu: list[float] = []
    wall: list[float] = []
    for _ in range(repeat):
        w0 = time.perf_counter_ns()
        c0 = time.process_time_ns()
        fn()
        cpu.append((time.process_time_ns() - c0) / 1e9)
        wall.append((time.perf_counter_ns() - w0) / 1e9)
    return {
        "cpu_seconds": statistics.median(cpu),
        "wall_seconds": statistics.median(wall),
        "cpu_samples": cpu,
        "wall_samples": wall,
    }


def _write_project_config(root: Path) -> None:
    """Give a synthetic project the config every real project has.

    Metadata backend selection walks ancestors for this file; without it each
    read pays the walk, which no real project does.
    """
    (root / "rebrew-project.toml").write_text(
        '[project]\nname = "bench"\ndefault_target = "SERVER"\n[compiler]\nprofile = "msvc-6.0"\n',
        encoding="utf-8",
    )


def bench_annotation_parsing() -> dict[str, Any]:
    """read_source_bindings over a synthetic 200-function .c."""
    from rebrew.metadata.bindings import read_source_bindings

    blocks = []
    for i in range(200):
        va = 0x10001000 + i * 0x100
        blocks.append(
            f"/* ADDRESS: SERVER 0x{va:x} */\nint func_{i}(int a, int b) {{ return a + b; }}\n\n"
        )
    text = "".join(blocks)
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "multi.c"
        src.write_text(text, encoding="utf-8")

        def run() -> None:
            # C syntax caches are shared by normal scans.
            annos = read_source_bindings(src, metadata_dir=None)
            assert len(annos) == 200

        return {"ops": 200, **measure(run, repeat=10)}


def bench_metadata_load() -> dict[str, Any]:
    """load_metadata over a generated 500-entry rebrew-functions.toml."""
    from rebrew.metadata.functions import clear_metadata_cache, load_metadata, save_metadata

    rows = {
        ("SERVER", 0x10001000 + i * 0x100): {"status": "STUB", "size": 64 + i % 8, "cflags": "/O2"}
        for i in range(500)
    }
    with tempfile.TemporaryDirectory() as d:
        meta_dir = Path(d)
        save_metadata(meta_dir, rows)

        def run() -> None:
            clear_metadata_cache()
            entries = load_metadata(meta_dir)
            assert len(entries) == 500

        return {"ops": 500, **measure(run, repeat=10)}


def bench_catalog_grid() -> dict[str, Any]:
    """The real catalog --data-json pipeline on the fixture binary (once)."""
    from typer.testing import CliRunner

    from rebrew.app.main import app

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
            'bin_dir = "bin/SERVER"\n'
            'module = "SERVER"\n\n'
            "[compiler]\n"
            'profile = "mingw-16.2.0"\n'
            'command = "i686-w64-mingw32-gcc"\n'
            'includes = ""\nlibs = ""\ncflags = "-O2"\n',
            encoding="utf-8",
        )
        import json as _json

        (root / "src" / "SERVER" / "function_structure.json").write_text(
            _json.dumps(
                [
                    {"va": 0x00401000, "size": 11, "name": "_func1"},
                    {"va": 0x00401018, "size": 2, "name": "_func2"},
                ]
            ),
            encoding="utf-8",
        )
        runner = CliRunner()
        import os

        os.chdir(root)
        try:
            # Import and configure the CLI before measuring repeated catalog reads.
            assert (
                runner.invoke(
                    app, ["coverage", "catalog", "--json"], catch_exceptions=False
                ).exit_code
                == 0
            )

            def run() -> None:
                r = runner.invoke(app, ["coverage", "catalog", "--json"], catch_exceptions=False)
                assert r.exit_code == 0

            return {"ops": 1, **measure(run, repeat=5)}
        finally:
            # Restore on every path: a failed assert would leave the process
            # standing in a directory the enclosing TemporaryDirectory removes.
            os.chdir(_REPO_ROOT)


def bench_verify_cache() -> dict[str, Any]:
    """VerifyCache save + load round-trip with 500 entries."""
    from rebrew.verify_cache import VerifyCache, VerifyCacheEntry

    entries: dict[str, VerifyCacheEntry] = {}
    for i in range(500):
        va = 0x10001000 + i * 0x100
        entries[f"0x{va:08x}"] = VerifyCacheEntry(
            source_hash=f"hash{i}",
            filepath=f"src/f{i}.c",
            mtime_ns=12345 + i,
            status="EXACT",
            va=va,
            size=64,
            passed=True,
            message="",
            cflags="/O2",
        )
    cache = VerifyCache(version=2, target="SERVER", compiler_hash="bench", entries=entries)

    def run() -> None:
        data = cache.to_dict()
        assert VerifyCache.from_dict(data).entries is not None

    return {"ops": 500, **measure(run, repeat=10)}


def bench_near_diag() -> dict[str, Any]:
    """near_analysis.analyze() over 200 synthetic byte pairs.

    Fixed byte pairs exercise the register-mismatch classifier.
    """
    from rebrew.near_analysis import analyze

    mov_ebx = bytes.fromhex("89 d8 c3")
    mov_ecx = bytes.fromhex("89 c8 c3")
    pairs = [(mov_ebx, mov_ecx)] * 200

    def run() -> None:
        for t, c in pairs:
            analyze(t, c, None, 0x1000)

    return {"ops": len(pairs), **measure(run, repeat=5)}


def bench_binary_similarity() -> dict[str, Any]:
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

    return {"ops": 600 * 600, **measure(run, repeat=5)}


def bench_ga_scoring() -> dict[str, Any]:
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

    return {"ops": len(candidates), **measure(run, repeat=5)}


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


def bench_parse_tree() -> dict[str, Any]:
    """read_source_bindings + metadata merge over a 1000-function tree."""
    from rebrew.metadata.bindings import read_source_bindings

    blocks = []
    for i in range(1000):
        va = 0x10001000 + i * 0x100
        blocks.append(f"/* ADDRESS: SERVER 0x{va:x} */\nint f_{i}(int a) {{ return a; }}\n\n")
    with tempfile.TemporaryDirectory() as d:
        meta_dir = Path(d)
        src = meta_dir / "tree.c"
        src.write_text("".join(blocks), encoding="utf-8")
        from rebrew.metadata.functions import save_metadata

        save_metadata(
            meta_dir,
            {
                ("SERVER", 0x10001000 + i * 0x100): {"status": "STUB", "size": 64}
                for i in range(1000)
            },
        )

        def run() -> None:
            # C syntax caches are shared by normal scans.
            anns = read_source_bindings(src, metadata_dir=meta_dir)
            assert len(anns) == 1000

        return {"ops": 1000, **measure(run, repeat=5)}


def bench_diff_structural() -> dict[str, Any]:
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

    return {"ops": len(candidates), **measure(run, repeat=5)}


def bench_registry_build() -> dict[str, Any]:
    """load_function_structure + build_function_registry over 2000 entries."""
    import json as _json

    from rebrew.catalog.loaders import load_function_structure
    from rebrew.catalog.registry import build_function_registry

    rows = [{"va": 0x401000 + i * 16, "size": 32 + i % 16, "name": f"f_{i}"} for i in range(2000)]
    with tempfile.TemporaryDirectory() as d:
        fl = Path(d) / "function_structure.json"
        fl.write_text(_json.dumps(rows), encoding="utf-8")

        def run() -> None:
            funcs = [
                {"va": e.va, "size": e.size, "name": e.name} for e in load_function_structure(fl)
            ]
            reg = build_function_registry(funcs, None)
            assert len(reg) >= 2000

        return {"ops": 2000, **measure(run, repeat=5)}


def bench_status_aggregation() -> dict[str, Any]:
    """collect_status over a synthetic 500-function project (no verify cache)."""
    from rebrew.config import ProjectConfig
    from rebrew.status import collect_status

    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write_project_config(root)
        src_dir = root / "src" / "SERVER"
        src_dir.mkdir(parents=True)
        rows: list[dict[str, object]] = []
        for i in range(500):
            va = 0x10001000 + i * 0x100
            rows.append({"va": va, "size": 64, "name": f"f_{i}"})
            (src_dir / f"f_{i}.c").write_text(
                f"/* ADDRESS: SERVER 0x{va:x} */\nvoid f_{i}(void) {{}}\n", encoding="utf-8"
            )
        import json as _json2

        (src_dir / "function_structure.json").write_text(_json2.dumps(rows), encoding="utf-8")
        from rebrew.metadata.functions import save_metadata

        save_metadata(
            root,
            {
                ("SERVER", 0x10001000 + i * 0x100): {"status": "STUB", "size": 64}
                for i in range(500)
            },
        )
        cfg = ProjectConfig(
            target_name="SERVER",
            target_binary=root / "nope.exe",
            arch="x86_32",
            root=root,
            reversed_dir=src_dir,
            module="SERVER",
            source_ext=".c",
        )

        def run() -> None:
            report = collect_status(cfg)
            assert report.total_functions >= 500

        return {"ops": 500, **measure(run, repeat=5)}


def bench_compile_cache() -> dict[str, Any]:
    """CompileCache put + get round-trip over 1000 entries."""
    from rebrew.compiler.cache import CompileCache

    with tempfile.TemporaryDirectory() as d:
        cc = CompileCache(Path(d) / "cache")
        try:
            keys = [f"k{i}" for i in range(1000)]
            blobs = [f"obj{i}".encode() * 32 for i in range(1000)]
            for k, b in zip(keys, blobs, strict=True):
                cc.put(k, b)

            def run() -> None:
                for k in keys:
                    assert cc.get(k) is not None

            return {"ops": len(keys), **measure(run, repeat=5)}
        finally:
            cc.close()


def bench_verify_cached() -> dict[str, Any]:
    """The incremental verify cache-hit check over 500 sources (source hash +
    header fingerprint — the per-entry cost of an incremental `rebrew verify`)."""
    from rebrew.config import ProjectConfig
    from rebrew.verify_hash import entry_headers_fp, source_hash

    with tempfile.TemporaryDirectory() as d:
        src_dir = Path(d) / "src"
        src_dir.mkdir()
        paths: list[Path] = []
        for i in range(500):
            p = src_dir / f"f_{i}.c"
            p.write_text(
                f"/* ADDRESS: SERVER 0x{0x10001000 + i * 0x100:x} */\nint f_{i}(void) {{ return 0; }}\n",
                encoding="utf-8",
            )
            paths.append(p)
        cfg = ProjectConfig(root=Path(d), compiler_includes=src_dir)

        def run() -> None:
            for p in paths:
                source_hash(p)
                entry_headers_fp(cfg, p, "/O2")

        return {"ops": len(paths), **measure(run, repeat=5)}


def bench_mutation_apply() -> dict[str, Any]:
    """mutate_code over a realistic function (the GA's per-candidate cost)."""
    import random

    from rebrew.matcher.mutator import mutate_code

    src = (
        "int add(int a, int b) {\n"
        "    int s = 0;\n"
        "    for (int i = 0; i < 10; i++) {\n"
        "        s += a * i + b;\n"
        "    }\n"
        "    return s;\n"
        "}\n"
    )

    def run() -> None:
        rng = random.Random(42)
        for _ in range(200):
            mutate_code(src, rng)

    return {"ops": 200, **measure(run, repeat=5)}


def _binding_tree(data_count: int, anchors: bool) -> dict[str, Any]:
    """Scan 100 sources against small or large unrelated metadata inventories."""
    from rebrew.metadata.bindings import read_source_bindings
    from rebrew.metadata.data import save_data_metadata
    from rebrew.metadata.functions import save_metadata

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _write_project_config(root)
        paths = []
        functions = {}
        data = {}
        for i in range(100):
            path = root / f"f{i}.c"
            prefix = f"/* ADDRESS: SERVER 0x{0x10001000 + i * 64:x} */\n" if anchors else ""
            global_prefix = f"/* ADDRESS: SERVER 0x{0x10080000 + i * 4:x} */\n" if anchors else ""
            path.write_text(
                prefix
                + f"int f{i}(int x) {{ return x + {i}; }}\n"
                + global_prefix
                + f"int g{i} = {i};\n"
            )
            paths.append(path)
            functions["SERVER", 0x10001000 + i * 64] = {
                "file": path.name,
                "name": f"f{i}",
                "symbol": f"_f{i}",
                "kind": "FUNCTION",
                "size": 16,
                "status": "STUB",
            }
        for i in range(data_count):
            data["SERVER", 0x10080000 + i * 4] = {
                "file": f"f{i}.c" if i < 100 else "pool.c",
                "name": f"g{i}",
                "kind": "DATA",
                "size": 4,
                "type": "int",
                "section": ".data",
            }
        save_metadata(root, functions)
        save_data_metadata(root, data, expected_hash=None)

        def scan() -> None:
            for path in paths:
                bindings = read_source_bindings(path, metadata_dir=root)
                assert len(bindings) == 2
                assert bindings[0].name == path.stem
                assert {b.kind for b in bindings} == {"FUNCTION", "DATA"}

        return {"ops": len(paths), **measure(scan)}


def bench_bindings_small() -> dict[str, Any]:
    """Warm source scan with anchors, 100 functions and 200 data rows."""
    return _binding_tree(200, True)


def bench_bindings_large() -> dict[str, Any]:
    """Warm source scan with anchors, 100 functions and 2000 data rows."""
    return _binding_tree(2000, True)


def bench_bindings_metadata_only() -> dict[str, Any]:
    """Warm source scan without anchors, 100 functions and 2000 data rows."""
    return _binding_tree(2000, False)


def bench_source_purposes() -> dict[str, Any]:
    """Repeated immutable source-purpose reads from a 200-definition document."""
    from rebrew.metadata.source_provenance import (
        AssemblyProvenance,
        SourceFilePurpose,
        load_source_files,
        replace_source_metadata,
    )

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        _write_project_config(root)
        definitions = [
            AssemblyProvenance(f"f{i}.c", f"f{i}", "SERVER", "a" * 64, "Reviewed original assembly")
            for i in range(200)
        ]
        purposes = [SourceFilePurpose(f"support{i}.c", "SERVER", "link support") for i in range(20)]
        replace_source_metadata(root, definitions, purposes, expected_hash=None)

        def read() -> None:
            for _ in range(100):
                records = load_source_files(root)
                assert len(records) == 20

        return {"ops": 100, **measure(read)}


_BENCHES: dict[str, Callable[[], dict[str, Any]]] = {
    "source_purposes": bench_source_purposes,
    "bindings_small": bench_bindings_small,
    "bindings_large": bench_bindings_large,
    "bindings_metadata_only": bench_bindings_metadata_only,
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
    "mutation_apply": bench_mutation_apply,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    parser.add_argument("--output", type=Path, help="Save the complete measurement report")
    parser.add_argument("--compare", type=Path, help="Compare CPU medians with a saved report")
    parser.add_argument("--bench", action="append", choices=sorted(_BENCHES))
    args = parser.parse_args()
    for variable in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
        os.environ[variable] = "1"
    fingerprint = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    before = None
    if args.compare:
        before = json.loads(args.compare.read_text())
        if (
            before.get("schema") != 1
            or before.get("clock") != "process_time_ns"
            or before.get("benchmark_sha256") != fingerprint
        ):
            parser.error("comparison requires the same benchmark workloads and measurement schema")
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=_REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    diff = subprocess.run(
        ["git", "diff", "HEAD", "--", "src", "tools"],
        cwd=_REPO_ROOT,
        capture_output=True,
        check=True,
    ).stdout
    results: dict[str, Any] = {}
    for name in args.bench or list(_BENCHES):
        row = _BENCHES[name]()
        cpu = row["cpu_seconds"]
        rate = row["ops"] / cpu if cpu else float("inf")
        row["ops_per_cpu_second"] = round(rate, 1) if math.isfinite(rate) else None
        if before is not None:
            old = before["benchmarks"][name]
            if old["ops"] != row["ops"]:
                parser.error(f"{name}: workload operation count changed")
            row["speedup"] = old["cpu_seconds"] / cpu if cpu else None
        results[name] = row
        if not args.json:
            suffix = f"  {row['speedup']:.2f}x" if row.get("speedup") else ""
            print(f"{name:24} CPU {cpu:.6f}s  wall {row['wall_seconds']:.6f}s{suffix}")
    report = {
        "schema": 1,
        "clock": "process_time_ns",
        "benchmark_sha256": fingerprint,
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "revision": revision,
            "diff_sha256": hashlib.sha256(diff).hexdigest(),
            "native_threads": 1,
        },
        "benchmarks": results,
    }
    rendered = json.dumps(report, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.write_text(rendered)
    if args.json:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
