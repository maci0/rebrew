"""bench_perf10_formats.py: CPU-time microbenchmarks of two formats/ kernels.

1. ``archive_members``: ``parse_archive`` over a synthetic ``!<arch>`` file
   (symbol index, GNU ``/\\n`` and COFF NUL long names, short names, odd body
   sizes that need the pad byte).
2. ``omf16_relocs``: ``parse_obj_omf16`` (record walk + capstone reloc
   location) over synthetic unoptimized (0xA0/0x90) and optimized (0xC2/0x96)
   16-bit MSVC objects.

Inputs come from a fixed seed. Fixture setup and imports sit outside the
timed region; every run asserts the exact decoded result, so a no-op cannot
pass. CPU time (``process_time_ns``) is primary, wall time is reported beside
it. Cache state: the archive/object files are read once before timing (OS page
cache warm), capstone is imported and primed, and ``formats/`` keeps no
result cache, so every timed run parses from bytes.

    python tools/bench_perf10_formats.py --json
"""

from __future__ import annotations

from pathlib import Path
lazy import argparse
lazy import json
lazy import platform
lazy import random
lazy import statistics
lazy import struct
lazy import sys
lazy import tempfile
lazy import time
lazy from collections.abc import Callable
lazy from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SEED = 20261029
_SAMPLES = 9
_CACHE_STATE = (
    "warm: file in OS page cache, capstone imported and primed, no in-process result cache"
)

# archive workload dimensions
_AR_MEMBERS = 6000
_AR_MIN_BODY = 200
_AR_MAX_BODY = 3000
_AR_LONG_EVERY = 3
_AR_COFF_LONG_EVERY = 7
_AR_HEADER = 60
_AR_INNER = 3

# omf16 workload dimensions
_OMF_FUNCS = 500
_OMF_LOOKUPS = 24
_OMF_INNER = 2
_OMF_NEAR_C2_HEADER = 9
_OMF_PROLOGUE = b"\x55\x8b\xec"  # push bp; mov bp,sp
_OMF_EPILOGUE = b"\x5d\xc3"  # pop bp; ret
_OMF_FILLER_OPS = (b"\x33\xc0", b"\x40", b"\x50", b"\x58", b"\x03\xc1", b"\x8b\xd8")
_OMF_BAD_BYTES = frozenset((0xE8, 0xE9))  # byte-scanned as rel16, so kept out of operands


# --- archive fixture ------------------------------------------------------


def _ar_header(name: bytes, size: int) -> bytes:
    field = name.ljust(16, b" ")
    return (
        field
        + b"0".ljust(12)
        + b"0".ljust(6)
        + b"0".ljust(6)
        + b"100644".ljust(8)
        + (str(size).encode().ljust(10))
        + b"`\n"
    )


def _build_archive(rng: random.Random) -> tuple[bytes, list[tuple[str, bytes]]]:
    """Return archive bytes and the exact ``(name, body)`` list parse_archive must yield."""
    expected: list[tuple[str, bytes]] = []
    headers: list[bytes] = []
    long_table = bytearray()
    bodies: list[bytes] = []
    for i in range(_AR_MEMBERS):
        body = rng.randbytes(rng.randint(_AR_MIN_BODY, _AR_MAX_BODY))
        if i % _AR_LONG_EVERY == 0:
            name = f"long_member_name_{i:06d}.o"
            terminator = b"\0" if i % _AR_COFF_LONG_EVERY == 0 else b"/\n"
            headers.append(b"/" + str(len(long_table)).encode())
            long_table += name.encode() + terminator
        else:
            name = f"m{i:05d}.o"
            headers.append(name.encode() + b"/")
        bodies.append(body)
        expected.append((name, body))
    index = rng.randbytes(4 * _AR_MEMBERS)
    out = bytearray(b"!<arch>\n")

    def add(raw_name: bytes, body: bytes) -> None:
        if len(out) % 2:
            out.append(0x0A)
        out.extend(_ar_header(raw_name, len(body)))
        out.extend(body)

    add(b"/", index)
    add(b"//", bytes(long_table))
    for header, body in zip(headers, bodies, strict=True):
        add(header, body)
    return bytes(out), expected


# --- omf16 fixture --------------------------------------------------------


def _record(rtype: int, body: bytes) -> bytes:
    raw = bytes([rtype]) + struct.pack("<H", len(body) + 1) + body
    return raw + bytes([-sum(raw) & 0xFF])


def _operand(rng: random.Random) -> bytes:
    while True:
        raw = rng.randbytes(2)
        if not _OMF_BAD_BYTES & set(raw):
            return raw


def _function(rng: random.Random) -> tuple[bytes, dict[int, str]]:
    """Code bytes plus the exact reloc map the parser must report."""
    code = bytearray(_OMF_PROLOGUE)
    relocs: dict[int, str] = {}
    for _ in range(rng.randint(12, 30)):
        kind = rng.randrange(4)
        if kind == 0:  # call rel16
            code.append(0xE8)
            relocs[len(code)] = "rel16"
            code += _operand(rng)
        elif kind == 1:  # mov ax,[g]
            code.append(0xA1)
            relocs[len(code)] = "disp16"
            code += _operand(rng)
        elif kind == 2:  # push [g]
            code += b"\xff\x36"
            relocs[len(code)] = "disp16"
            code += _operand(rng)
        else:
            code += rng.choice(_OMF_FILLER_OPS)
    code += _OMF_EPILOGUE
    return bytes(code), relocs


def _name_list(names: list[str]) -> bytes:
    return b"".join(bytes([len(n)]) + n.encode() for n in names)


def _build_unoptimized(
    funcs: list[tuple[bytes, dict[int, str]]],
) -> tuple[bytes, dict[str, tuple[bytes, dict[int, str]]]]:
    """0xA0 LEDATA chunks (3 per function) + 0x90 MODEND publics."""
    out = bytearray()
    publics = bytearray()
    expected: dict[str, tuple[bytes, dict[int, str]]] = {}
    offset = 0
    for i, (code, relocs) in enumerate(funcs):
        name = f"_u{i:04d}"
        third = len(code) // 3
        for start, stop in ((0, third), (third, 2 * third), (2 * third, len(code))):
            out += _record(0xA0, b"\x01" + struct.pack("<H", offset + start) + code[start:stop])
        publics += bytes([len(name)]) + name.encode() + struct.pack("<H", offset)
        expected[name] = (code, relocs)
        offset += len(code)
    out += _record(0x90, bytes(publics))
    return bytes(out), expected


def _build_optimized(
    funcs: list[tuple[bytes, dict[int, str]]],
) -> tuple[bytes, dict[str, tuple[bytes, dict[int, str]]]]:
    """0x96 GRPDEF (near code), 0xCA statics, 0x96 publics, one 0xC2 per function."""
    names = [f"_o{i:04d}" for i in range(len(funcs))]
    half = len(names) // 2
    out = bytearray(_record(0x96, b"\x00" + _name_list(["_TEXT"])))
    out += _record(0xCA, _name_list(names[:half]))
    out += _record(0x96, _name_list(names[half:]))
    expected: dict[str, tuple[bytes, dict[int, str]]] = {}
    for name, (code, relocs) in zip(names, funcs, strict=True):
        out += _record(0xC2, b"\x00" * _OMF_NEAR_C2_HEADER + code)
        expected[name] = (code, relocs)
    return bytes(out), expected


# --- harness --------------------------------------------------------------


def _measure(fn: Callable[[], Any], inner: int) -> dict[str, Any]:
    """Prime once, then take ``_SAMPLES`` samples of ``inner`` runs each."""
    fn()
    cpu: list[float] = []
    wall: list[float] = []
    for _ in range(_SAMPLES):
        w0 = time.perf_counter_ns()
        c0 = time.process_time_ns()
        for _ in range(inner):
            fn()
        cpu.append((time.process_time_ns() - c0) / 1e9)
        wall.append((time.perf_counter_ns() - w0) / 1e9)
    return {
        "cpu_median_seconds": statistics.median(cpu),
        "wall_median_seconds": statistics.median(wall),
        "cpu_samples_seconds": cpu,
        "wall_samples_seconds": wall,
        "runs_per_sample": inner,
    }


def _bench_archive(work: Path) -> dict[str, Any]:
    from rebrew.formats.archives import parse_archive

    data, expected = _build_archive(random.Random(_SEED))
    path = work / "bench.lib"
    path.write_bytes(data)
    path.read_bytes()
    assert len(expected) == _AR_MEMBERS and len({n for n, _ in expected}) == _AR_MEMBERS

    def run() -> None:
        got = list(parse_archive(str(path)))
        assert got == expected

    return {
        "workload": "archive_members",
        "cache_state": _CACHE_STATE,
        "inputs": {
            "seed": _SEED,
            "members": _AR_MEMBERS,
            "archive_bytes": len(data),
            "long_name_members": sum(1 for n, _ in expected if n.startswith("long_")),
            "body_bytes_min_max": [_AR_MIN_BODY, _AR_MAX_BODY],
        },
        **_measure(run, _AR_INNER),
    }


def _bench_omf16(work: Path) -> dict[str, Any]:
    from rebrew.formats.omf16 import parse_obj_omf16

    rng = random.Random(_SEED)
    funcs = [_function(rng) for _ in range(_OMF_FUNCS)]
    unopt, unopt_expected = _build_unoptimized(funcs)
    opt, opt_expected = _build_optimized(funcs)
    unopt_path = work / "unopt.obj"
    opt_path = work / "opt.obj"
    unopt_path.write_bytes(unopt)
    opt_path.write_bytes(opt)
    lookups: list[tuple[Path, str, tuple[bytes, dict[int, str]]]] = []
    step = _OMF_FUNCS // _OMF_LOOKUPS
    for i in range(0, _OMF_FUNCS, step):
        for path, expected, tag in (
            (unopt_path, unopt_expected, "u"),
            (opt_path, opt_expected, "o"),
        ):
            name = f"_{tag}{i:04d}"
            lookups.append((path, name, expected[name]))
    total_relocs = sum(len(r) for _, _, (_, r) in lookups)
    assert total_relocs > len(lookups)
    # An unmatched symbol must stay (None, {}).
    miss: tuple[bytes | None, dict[int, str]] = (None, {})

    def run() -> None:
        for path, name, want in lookups:
            assert parse_obj_omf16(path, name) == want
        assert parse_obj_omf16(unopt_path, "_absent") == miss

    return {
        "workload": "omf16_relocs",
        "cache_state": _CACHE_STATE,
        "inputs": {
            "seed": _SEED,
            "functions_per_object": _OMF_FUNCS,
            "unoptimized_bytes": len(unopt),
            "optimized_bytes": len(opt),
            "symbol_lookups": len(lookups) + 1,
            "relocs_checked": total_relocs,
        },
        **_measure(run, _OMF_INNER),
    }


def main() -> int:
    import rebrew

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Machine-readable output")
    args = parser.parse_args()
    scratch = _REPO_ROOT / ".scratch"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch, prefix="bench-perf10-formats-") as tmp:
        work = Path(tmp)
        results = {w["workload"]: w for w in (_bench_archive(work), _bench_omf16(work))}
    report = {
        "benchmark": "bench_perf10_formats",
        "python": sys.version.split()[0],
        "rebrew_source": str(Path(rebrew.__file__).parent),
        "platform": platform.platform(),
        "clock": "process_time_ns (cpu, primary), perf_counter_ns (wall)",
        "workloads": results,
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for name, w in results.items():
            print(
                f"{name:18s} cpu {w['cpu_median_seconds'] * 1e3:9.2f} ms/sample"
                f"  wall {w['wall_median_seconds'] * 1e3:9.2f} ms/sample"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
