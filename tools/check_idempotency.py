"""check_idempotency.py — verify CLI outputs are deterministic across runs.

Runs a set of read-only ``rebrew`` commands twice and byte-compares their
JSON output.  A difference means the tool has run-to-run nondeterminism
(unstable dict ordering, timestamps in results, RNG leakage, ...) which breaks
scripting and CI diffs.

By default it checks every offline ``--json`` / ``--dry-run`` command (the
full surface pinned by ``tests/test_json_purity.py``).  Additional commands
can be appended as arguments::

    python tools/check_idempotency.py                     # defaults
    python tools/check_idempotency.py "diff --json 0x1000" "test --dry-run --json 0x1000"

The ``verify`` report's ``timestamp`` field is by-design wall-clock metadata
and is normalized away before comparison.

Run from a rebrew project root (where ``rebrew-project.toml`` lives), or pass
``--cwd <dir>``.  ``--fixture-dir <dir>`` assembles the checked-in fixture
project (tests/fixtures/mini_pe.exe) at *dir* and runs the sweep there — the
CI entry point, no real project needed.  Also importable for tests::

    from tools.check_idempotency import outputs_identical
    assert outputs_identical("rebrew status --json", cwd=project_root)
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

_PROJECT_TOML = """\
[project]
name = "idemprobe"
default_target = "SERVER"
jobs = 1

[targets."SERVER"]
binary = "original/mini_pe.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src/SERVER"
function_list = "src/SERVER/functions.txt"
bin_dir = "bin/SERVER"
source_ext = ".c"
marker = "SERVER"

[compiler]
profile = "gcc-pe"
runner = ""
command = "i686-w64-mingw32-gcc"
includes = ""
libs = ""
cflags = "-O2"
base_cflags = ""
timeout = 60
"""


def write_fixture_project(project_dir: Path) -> Path:
    """Assemble the minimal fixture project at *project_dir*; return it.

    Copies the checked-in fixture PE (tests/fixtures/mini_pe.exe) and writes
    a rebrew-project.toml plus one STUB source — enough for every offline
    ``--json`` command to run against real files.
    """
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "original").mkdir(exist_ok=True)
    (project_dir / "src" / "SERVER").mkdir(parents=True, exist_ok=True)
    (project_dir / "bin" / "SERVER").mkdir(parents=True, exist_ok=True)
    fixture = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "mini_pe.exe"
    shutil.copy(fixture, project_dir / "original" / "mini_pe.exe")
    (project_dir / "rebrew-project.toml").write_text(_PROJECT_TOML, encoding="utf-8")
    (project_dir / "src" / "SERVER" / "functions.txt").write_text(
        "0x00401000 11 _func1\n0x00401010 10 _func2\n", encoding="utf-8"
    )
    (project_dir / "src" / "SERVER" / "fcn.c").write_text(
        "// FUNCTION: SERVER 0x00401000\nint __cdecl _func1(void) { return 0; }\n",
        encoding="utf-8",
    )
    return project_dir


def _normalize(obj: Any) -> Any:
    """Recursively drop by-design volatile keys (e.g. report timestamps)."""
    if isinstance(obj, dict):
        return {k: _normalize(v) for k, v in obj.items() if k != "timestamp"}
    if isinstance(obj, list):
        return [_normalize(v) for v in obj]
    return obj


def _run(cmd: str, cwd: Path) -> tuple[int, str]:
    """Run *cmd* via `rebrew` in *cwd*; return (exit_code, stdout).

    A timed-out or crashed invocation is reported as a non-zero exit so the
    checker marks it FAIL rather than aborting with a traceback.
    """
    full = ["rebrew", *cmd.split()]
    try:
        proc = subprocess.run(full, cwd=str(cwd), capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return 2, ""
    except OSError as e:
        return 2, f"<cannot run: {e}>"
    return proc.returncode, proc.stdout


def outputs_identical(cmd: str, cwd: Path) -> bool:
    """Run *cmd* twice and return True when the JSON outputs match.

    The ``verify`` report's timestamp is normalized away.  Exit codes are
    compared too, so a command that fails the same way both times is still
    deterministic.
    """
    code1, out1 = _run(cmd, cwd)
    code2, out2 = _run(cmd, cwd)
    if code1 != code2:
        return False
    try:
        return _normalize(json.loads(out1)) == _normalize(json.loads(out2))
    except json.JSONDecodeError:
        # Non-JSON output: compare bytes verbatim.
        return out1 == out2


DEFAULT_COMMANDS = [
    "status --json",
    "todo --json",
    "verify --json --dry-run",
    # The full offline --json surface (mirrors tests/test_json_purity.py).
    "strings --json",
    "imports --json",
    "asm --json 0x401000",
    "describe --json 0x401000",
    "xrefs original/mini_pe.exe 0x401000 --json",
    "analyze --json",
    "identify-library --json",
    "lint --json",
    "data --json",
    "doctor --json",
    "cache stats --json",
    "cfg show --json",
    "flirt --exe original/mini_pe.exe --json",
]


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cwd = Path.cwd()
    if "--cwd" in argv:
        idx = argv.index("--cwd")
        if idx + 1 >= len(argv):
            print("--cwd requires a directory argument")
            return 2
        cwd = Path(argv[idx + 1])
        del argv[idx : idx + 2]
    if "--fixture-dir" in argv:
        idx = argv.index("--fixture-dir")
        if idx + 1 >= len(argv):
            print("--fixture-dir requires a directory argument")
            return 2
        cwd = write_fixture_project(Path(argv[idx + 1]))
        del argv[idx : idx + 2]
    commands = DEFAULT_COMMANDS + argv

    failed = 0
    for cmd in commands:
        ok = outputs_identical(cmd, cwd)
        marker = "PASS" if ok else "FAIL"
        print(f"[{marker}] {cmd}")
        if not ok:
            failed += 1

    if failed:
        print(f"\n{failed} command(s) produced non-identical output across two runs.")
        return 1
    print(f"\nAll {len(commands)} command(s) deterministic.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
