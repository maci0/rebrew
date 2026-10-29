"""bench_perf10_metadata.py: load-independent microbenchmarks of the metadata package.

Two synthetic, seeded workloads, each with an exact-result assertion:

1. ``metadata_cold_load_validate``: ``load_metadata`` of a function store
   (main TOML plus ``.d`` drop-ins) with every cache cold: in-memory
   document cache cleared and the persisted parsed-document cache removed, so
   each sample parses and validates the TOML.
2. ``binding_resolution_inventory``: ``iter_source_bindings(inventory_only=True)``
   over many sources against already-loaded function and data stores. The
   parsed-document caches are warm; the per-store file index is cleared before
   each sample, so each sample rebuilds it and resolves every source.

Run:

    python tools/bench_perf10_metadata.py            # table
    python tools/bench_perf10_metadata.py --json     # one JSON document

CPU time (``process_time_ns``) is the primary clock; ``perf_counter_ns`` wall
samples are kept beside it. Imports and fixture generation are outside the
timed region.
"""

from __future__ import annotations

from pathlib import Path
lazy import argparse
lazy import hashlib
lazy import json
lazy import platform
lazy import random
lazy import shutil
lazy import statistics
lazy import sys
lazy import tempfile
lazy import time
lazy from collections.abc import Callable
lazy from typing import Any

SEED = 20260610
SAMPLES = 9
MODULES = ("SERVER", "CLIENT", "TOOLS")
STATUSES = ("EXACT", "RELOC", "NEAR_MATCHING", "STUB", "MATCHING")
CFLAGS = ("/O2 /Gd", "/O1 /Gr", "/Ox /Gz /MT")
HEX = "0123456789abcdef"

# Workload 1 dimensions.
LOAD_MAIN_ROWS = 6000
LOAD_DROPINS = 3
LOAD_DROPIN_ROWS = 400
LOAD_SOURCE_DEFINITIONS = 300

# Workload 2 dimensions.
BIND_SOURCES = 500
BIND_ROWS_PER_SOURCE = 8
BIND_DATA_ROWS_PER_SOURCE = 2


def measure(fn: Callable[[], Any], *, before: Callable[[], None]) -> dict[str, Any]:
    """Run ``before`` then ``fn`` per sample; time only ``fn``.

    One untimed warm-up call runs first so lazy imports are not in a sample.
    """
    before()
    fn()
    cpu: list[float] = []
    wall: list[float] = []
    for _ in range(SAMPLES):
        before()
        w0 = time.perf_counter_ns()
        c0 = time.process_time_ns()
        fn()
        cpu.append((time.process_time_ns() - c0) / 1e9)
        wall.append((time.perf_counter_ns() - w0) / 1e9)
    return {
        "cpu_seconds_median": statistics.median(cpu),
        "wall_seconds_median": statistics.median(wall),
        "cpu_samples": cpu,
        "wall_samples": wall,
    }


def _digest(parts: list[str]) -> str:
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def _write_project_config(root: Path) -> None:
    (root / "rebrew-project.toml").write_text(
        '[project]\nname = "bench"\ndefault_target = "SERVER"\n[compiler]\nprofile = "msvc-6.0"\n',
        encoding="utf-8",
    )


def _function_text(rng: random.Random, rows: list[tuple[str, int, str, int]]) -> str:
    out: list[str] = []
    for module, va, file, n in rows:
        status = rng.choice(STATUSES)
        key = f"{module}.0x{va:08x}"
        out.append(
            f'["{key}"]\n'
            f"file = {json.dumps(file)}\n"
            f'symbol = "_fn_{n}"\n'
            f'name = "fn_{n}"\n'
            'kind = "FUNCTION"\n'
            f"size = {rng.randrange(8, 4096)}\n"
            f'status = "{status}"\n'
            f'cflags = "{rng.choice(CFLAGS)}"\n'
            f'note = "synthetic row {n} with a moderately long free-text note"\n'
            'updated_by = "bench"\n'
            f'updated_at = "2026-01-{1 + n % 28:02d}T00:00:00Z"\n'
            f'globals = ["g_{n}", "g_{n + 1}"]\n'
            f'["{key}".origins]\n'
            'size = "binsync"\n'
            'status = "verify"\n'
            f'["{key}".verification]\n'
            f'status = "{status}"\n'
            'time = "2026-01-01T00:00:00Z"\n'
        )
    return "".join(out)


def _source_section(rng: random.Random) -> str:
    out = ["[source.definitions]\n"]
    for i in range(LOAD_SOURCE_DEFINITIONS):
        digest = "".join(rng.choice(HEX) for _ in range(64))
        out.append(
            f'[source.definitions."game/mod_{i // 10}.c".fn_{i}.SERVER]\n'
            f'source_hash = "{digest}"\n'
            f'evidence = "original assembly receipt {i}"\n'
        )
    out.append("[source.files]\n")
    for i in range(40):
        out.append(f'[source.files."game/support_{i}.c".SERVER]\npurpose = "support unit {i}"\n')
    return "".join(out)


class _Fixture:
    def __init__(self, root: Path, *, expected: dict[str, Any], dims: dict[str, Any]) -> None:
        self.root = root
        self.expected = expected
        self.dims = dims


def build_load_fixture(root: Path) -> _Fixture:
    """Function store: one main TOML, several drop-ins, a source provenance section."""
    rng = random.Random(SEED)
    _write_project_config(root)
    total = LOAD_MAIN_ROWS + LOAD_DROPINS * LOAD_DROPIN_ROWS
    vas = sorted(rng.sample(range(0x401000, 0x401000 + total * 0x100, 0x10), total))
    rows = [(MODULES[i % len(MODULES)], va, f"game/mod_{i // 10}.c", i) for i, va in enumerate(vas)]
    rng.shuffle(rows)
    main_rows, dropin_rows = rows[:LOAD_MAIN_ROWS], rows[LOAD_MAIN_ROWS:]
    (root / "rebrew-functions.toml").write_text(
        "format = 3\n" + _source_section(rng) + _function_text(rng, main_rows), encoding="utf-8"
    )
    dropins = root / "rebrew-functions.d"
    dropins.mkdir()
    for d in range(LOAD_DROPINS):
        chunk = dropin_rows[d * LOAD_DROPIN_ROWS : (d + 1) * LOAD_DROPIN_ROWS]
        (dropins / f"part{d}.toml").write_text(
            "format = 3\n[source.definitions]\n[source.files]\n" + _function_text(rng, chunk),
            encoding="utf-8",
        )
    sums = [f"{m}:{va}:{n}" for m, va, _file, n in sorted(rows)]
    return _Fixture(
        root,
        expected={"rows": total, "digest": _digest(sums)},
        dims={
            "function_rows": total,
            "main_rows": LOAD_MAIN_ROWS,
            "dropin_files": LOAD_DROPINS,
            "rows_per_dropin": LOAD_DROPIN_ROWS,
            "source_definitions": LOAD_SOURCE_DEFINITIONS,
            "modules": len(MODULES),
        },
    )


def build_binding_fixture(root: Path) -> tuple[_Fixture, list[Path]]:
    """Function and data stores plus source files each owning a fixed row count."""
    rng = random.Random(SEED + 1)
    _write_project_config(root)
    src_dir = root / "game"
    src_dir.mkdir()
    sources: list[Path] = []
    func_rows: list[tuple[str, int, str, int]] = []
    data_text: list[str] = []
    va = 0x401000
    n = 0
    expected_parts: list[str] = []
    for i in range(BIND_SOURCES):
        path = src_dir / f"unit_{i}.c"
        path.write_text(f"/* synthetic unit {i} */\n", encoding="utf-8")
        sources.append(path)
        # Mixed spellings of the stored path, as hand-converted stores have.
        rel = f"game/unit_{i}.c"
        stored = rel.replace("/", "\\") if i % 7 == 0 else rel
        for _ in range(BIND_ROWS_PER_SOURCE):
            module = MODULES[n % len(MODULES)]
            func_rows.append((module, va, stored, n))
            expected_parts.append(f"F:{module}:{va}:fn_{n}:{rel}")
            va += 0x40
            n += 1
        for _ in range(BIND_DATA_ROWS_PER_SOURCE):
            module = MODULES[n % len(MODULES)]
            data_text.append(
                f'["{module}.0x{va:08x}"]\n'
                f'file = "{rel}"\n'
                f'name = "g_{n}"\n'
                'kind = "DATA"\n'
                f"size = {4 * (1 + n % 8)}\n"
                'section = ".data"\n'
            )
            expected_parts.append(f"D:{module}:{va}:g_{n}:{rel}")
            va += 0x10
            n += 1
    rng.shuffle(func_rows)
    (root / "rebrew-functions.toml").write_text(
        "format = 3\n[source.definitions]\n[source.files]\n" + _function_text(rng, func_rows),
        encoding="utf-8",
    )
    (root / "rebrew-data.toml").write_text("format = 2\n" + "".join(data_text), encoding="utf-8")
    return (
        _Fixture(
            root,
            expected={
                "sources": BIND_SOURCES,
                "bindings": BIND_SOURCES * (BIND_ROWS_PER_SOURCE + BIND_DATA_ROWS_PER_SOURCE),
                "digest": _digest(sorted(expected_parts)),
            },
            dims={
                "sources": BIND_SOURCES,
                "function_rows": BIND_SOURCES * BIND_ROWS_PER_SOURCE,
                "data_rows": BIND_SOURCES * BIND_DATA_ROWS_PER_SOURCE,
                "modules": len(MODULES),
            },
        ),
        sources,
    )


def bench_cold_load_validate() -> dict[str, Any]:
    from rebrew.metadata.functions import clear_metadata_cache, load_metadata

    with tempfile.TemporaryDirectory(prefix="bench-meta-load-", dir=_scratch_dir()) as tmp:
        root = Path(tmp)
        fixture = build_load_fixture(root)
        disk_cache = root / ".rebrew"
        result: dict[str, Any] = {}

        def before() -> None:
            clear_metadata_cache()
            shutil.rmtree(disk_cache, ignore_errors=True)

        def run() -> None:
            result["entries"] = load_metadata(root, deepcopy=False)

        timing = measure(run, before=before)
        entries = result["entries"]
        assert len(entries) == fixture.expected["rows"], len(entries)
        got = _digest(
            [f"{m}:{va}:{e['name'].removeprefix('fn_')}" for (m, va), e in sorted(entries.items())]
        )
        assert got == fixture.expected["digest"], "loaded rows differ from the generated store"
        return {
            "cache_state": "cold: in-memory document cache cleared and persisted parsed-document "
            "cache removed before each sample; every sample parses and validates the TOML",
            "dimensions": fixture.dims,
            **timing,
        }


def bench_binding_resolution() -> dict[str, Any]:
    from rebrew.metadata import bindings
    from rebrew.metadata.bindings import iter_source_bindings
    from rebrew.metadata.data import data_file_index
    from rebrew.metadata.functions import clear_metadata_cache, load_metadata

    with tempfile.TemporaryDirectory(prefix="bench-meta-bind-", dir=_scratch_dir()) as tmp:
        root = Path(tmp).resolve()
        fixture, sources = build_binding_fixture(root)
        clear_metadata_cache()
        function_entries = load_metadata(root, deepcopy=False)
        data_file_index(root)
        result: dict[str, Any] = {}

        def before() -> None:
            with bindings._METADATA_FILE_INDEX_LOCK:
                bindings._METADATA_FILE_INDEX.clear()
                bindings._METADATA_FILE_INDEX_OWNER.clear()

        def run() -> None:
            result["pairs"] = iter_source_bindings(
                sources,
                metadata_dir=root,
                base_dir=root,
                inventory_only=True,
                function_entries=function_entries,
            )

        timing = measure(run, before=before)
        pairs = result["pairs"]
        assert len(pairs) == fixture.expected["sources"], len(pairs)
        parts: list[str] = []
        for _path, annos in pairs:
            assert annos == sorted(annos, key=lambda a: a.va)
            for a in annos:
                tag = "F" if a.kind == "FUNCTION" else "D"
                parts.append(f"{tag}:{a.module}:{a.va}:{a.name}:{a.filepath}")
        assert len(parts) == fixture.expected["bindings"], len(parts)
        assert _digest(sorted(parts)) == fixture.expected["digest"], (
            "bindings differ from the store"
        )
        return {
            "cache_state": "warm document caches (function and data stores already loaded); "
            "per-store file index cleared before each sample, so each sample rebuilds it",
            "dimensions": fixture.dims,
            **timing,
        }


def _scratch_dir() -> str | None:
    """A disk-backed directory for fixtures; never a tmpfs."""
    scratch = Path(__file__).resolve().parent.parent / ".scratch"
    scratch.mkdir(exist_ok=True)
    return str(scratch)


_BENCHES: dict[str, Callable[[], dict[str, Any]]] = {
    "metadata_cold_load_validate": bench_cold_load_validate,
    "binding_resolution_inventory": bench_binding_resolution,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()
    report: dict[str, Any] = {
        "clock": "process_time_ns",
        "wall_clock": "perf_counter_ns",
        "seed": SEED,
        "samples": SAMPLES,
        "python": platform.python_version(),
        "workloads": {name: bench() for name, bench in _BENCHES.items()},
    }
    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        for name, row in report["workloads"].items():
            print(
                f"{name:34s} cpu {row['cpu_seconds_median'] * 1000:9.2f} ms"
                f"  wall {row['wall_seconds_median'] * 1000:9.2f} ms"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
