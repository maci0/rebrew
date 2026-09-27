"""check_idempotency.py — verify re-execution safety across runs.

Phase 1 (read-only sweep): runs a set of read-only ``rebrew`` commands twice
and byte-compares their JSON output.  A difference means the tool has run-to-run
nondeterminism (unstable dict ordering, timestamps in results, RNG leakage,
...) which breaks scripting and CI diffs.

Phase 2 (write sweep): runs each *mutating* command twice against its own
fresh fixture project and compares the project tree after run 1 with the tree
after run 2.  Output determinism says nothing about re-execution safety: a
command that appends a marker, a stub, a metadata row or a history entry on
every run produces identical output and still corrupts the project the second
time.  The tree is compared by content digest, so a repeated write that lands
the same bytes passes and one that grows or drifts fails.

By default it checks every offline ``--json`` / ``--dry-run`` command (the
full surface pinned by ``tests/test_json_purity.py``).  Additional commands
can be appended as arguments::

    python tools/check_idempotency.py                     # defaults
    python tools/check_idempotency.py "diff --json 0x1000" "test --dry-run --json 0x1000"

The write sweep needs a scratch project (it mutates one), so it runs only when
``--fixture-dir`` is given; each command gets its own freshly assembled copy.

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

import contextlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from rebrew.utils import run_process_group

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
profile = "mingw-16.2.0"
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
    if project_dir.exists():
        for p in project_dir.rglob("*"):
            if not p.is_symlink() and p.is_file():
                with contextlib.suppress(OSError):
                    p.chmod(0o600)
        shutil.rmtree(project_dir, ignore_errors=True)
    project_dir.mkdir(parents=True, exist_ok=True)
    (project_dir / "original").mkdir(exist_ok=True)
    (project_dir / "src" / "SERVER").mkdir(parents=True, exist_ok=True)
    (project_dir / "bin" / "SERVER").mkdir(parents=True, exist_ok=True)
    fixture = (
        Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "mini_pe.exe"
    )
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


def tree_digest(root: Path) -> dict[str, str]:
    """``relative path -> sha256`` for every regular file under *root*.

    Content only, not mode or mtime: a command that rewrites a file with the
    same bytes is as safe as one that skips it, and a re-run that only touches
    mtimes must not read as a change.
    """
    import hashlib

    out: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        out[path.relative_to(root).as_posix()] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
    return out


def _tree_diff(before: dict[str, str], after: dict[str, str]) -> str:
    """Human-readable summary of the paths whose content differs."""
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(p for p in set(before) & set(after) if before[p] != after[p])
    parts: list[str] = []
    for label, paths in (("added", added), ("removed", removed), ("changed", changed)):
        if paths:
            parts.append(
                f"{label}: "
                + ", ".join(paths[:10])
                + (" ..." if len(paths) > 10 else "")
            )
    return "; ".join(parts) or "(no path differs)"


def _run(cmd: str, cwd: Path) -> tuple[int, str]:
    """Run *cmd* via `rebrew` in *cwd*; return (exit_code, stdout).

    A timed-out or crashed invocation is reported as a non-zero exit so the
    checker marks it FAIL rather than aborting with a traceback.
    """
    full = ["rebrew", *cmd.split()]
    try:
        # run_process_group, not subprocess.run: the 600s timeout must take
        # the child's whole process group with it, or a `rebrew` that spawned
        # a compiler leaves that compiler orphaned.
        proc = run_process_group(
            full,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return 2, ""
    except OSError as e:
        return 2, f"<cannot run: {e}>"
    return proc.returncode, proc.stdout


def check_command_idempotency(cmd: str, cwd: Path) -> tuple[bool, str]:
    """Run *cmd* twice and return (identical, diff_explanation)."""
    code1, out1 = _run(cmd, cwd)
    code2, out2 = _run(cmd, cwd)
    if code1 != code2:
        return (
            False,
            f"exit code mismatch: first run exited {code1}, second run exited {code2}",
        )
    try:
        norm1 = _normalize(json.loads(out1))
        norm2 = _normalize(json.loads(out2))
        if norm1 != norm2:
            import difflib

            dump1 = json.dumps(norm1, indent=2, sort_keys=True).splitlines()
            dump2 = json.dumps(norm2, indent=2, sort_keys=True).splitlines()
            diff = list(
                difflib.unified_diff(
                    dump1, dump2, fromfile="run1", tofile="run2", lineterm=""
                )
            )
            diff_text = "\n".join(diff[:20])
            if len(diff) > 20:
                diff_text += f"\n... ({len(diff) - 20} more diff lines)"
            return False, f"JSON output mismatch:\n{diff_text}"
        return True, ""
    except json.JSONDecodeError:
        if out1 != out2:
            import difflib

            diff = list(
                difflib.unified_diff(
                    out1.splitlines(),
                    out2.splitlines(),
                    fromfile="run1",
                    tofile="run2",
                    lineterm="",
                )
            )
            diff_text = "\n".join(diff[:20])
            return False, f"output mismatch:\n{diff_text}"
        return True, ""


def outputs_identical(cmd: str, cwd: Path) -> bool:
    """Run *cmd* twice and return True when the JSON outputs match.

    The ``verify`` report's timestamp is normalized away.  Exit codes are
    compared too, so a command that fails the same way both times is still
    deterministic.
    """
    ok, _ = check_command_idempotency(cmd, cwd)
    return ok


def check_write_idempotency(cmd: str, project_dir: Path) -> tuple[bool, str]:
    """Run the mutating *cmd* twice on one project; return (same_state, why).

    The project is assembled fresh, so the first run starts from a known
    state.  Both runs execute the same command: an exit-code difference means
    the command is not even repeatable, and a content difference in the tree
    means the second execution left something behind.
    """
    code1, _ = _run(cmd, project_dir)
    after_first = tree_digest(project_dir)
    code2, _ = _run(cmd, project_dir)
    after_second = tree_digest(project_dir)
    if code1 != code2:
        return (
            False,
            f"exit code mismatch: first run exited {code1}, second run exited {code2}",
        )
    if after_first != after_second:
        return (
            False,
            f"second run changed the project ({_tree_diff(after_first, after_second)})",
        )
    return True, ""


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
    "pdb-info original/mini_pe.exe --json",  # deterministic error path (no sibling .pdb)
    "lint --json",
    "data --json",
    "doctor --json",
    "cache stats --json",
    "cfg show --json",
    "flirt --exe original/mini_pe.exe --json",
]


#: Commands that mutate the project.  Each is run twice against its own fresh
#: fixture; the tree must be identical after both runs.  Offline only — no
#: command here compiles anything or needs a toolchain image.
WRITE_COMMANDS = [
    # Strips inline markers into rebrew-functions.toml (ADR 023).
    "migrate-markers",
    # Writes a STUB .c + BLOCKER + STATUS for every undocumented function.
    "document-unmatched",
    # Regenerates the link_stubs.c BSS placeholder TU from rebrew-data.toml.
    "gen-link-stubs",
]

#: One ``.data`` symbol, so the gen-link-stubs sweep has metadata to generate
#: from (the read-only fixture ships no data markers).
_DATA_TOML = (
    "[SYMBOLS.SERVER.g_player]\n"
    "section = '.data'\n"
    "name = 'g_player'\n"
    "size = 0x40\n"
)

#: Commands in :data:`WRITE_COMMANDS` that take ``--data-metadata``.
_DATA_METADATA_COMMANDS = ("gen-link-stubs",)


def _write_sweep_dir(base: Path, index: int, cmd: str) -> Path:
    """Assemble the fixture project the *index*-th write command runs against.

    One directory per command: they mutate, so a shared project would let the
    first command's leftovers mask the second one's second-run damage.
    """
    project_dir = write_fixture_project(base / f"write{index}")
    if any(cmd.startswith(c) for c in _DATA_METADATA_COMMANDS):
        (project_dir / "src" / "rebrew-data.toml").write_text(
            _DATA_TOML, encoding="utf-8"
        )
    return project_dir


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cwd = Path.cwd()
    sweep_base: Path | None = None
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
        base = Path(argv[idx + 1])
        cwd = write_fixture_project(base)
        # A sibling of the read-only fixture, not a subdirectory of it: the
        # write projects must not show up inside the project under test.
        sweep_base = base.with_name(base.name + "-write")
        del argv[idx : idx + 2]
    commands = DEFAULT_COMMANDS + argv

    # Every command is read-only (the module contract) and independent —
    # run them in parallel: 36 serial `rebrew` subprocess spawns made the
    # idempotency check (and the suite test driving it) take ~19s; eight
    # workers cut that to a few seconds while preserving output order.
    from concurrent.futures import ThreadPoolExecutor

    failed = 0
    failures: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(
            pool.map(lambda cmd: (cmd, *check_command_idempotency(cmd, cwd)), commands)
        )
    for cmd, ok, reason in outcomes:
        marker = "PASS" if ok else "FAIL"
        print(f"[{marker}] {cmd}")
        if not ok:
            failed += 1
            failures.append((cmd, reason))

    # Phase 2 needs a scratch project of its own (each command mutates one),
    # so it only runs when the caller supplied --fixture-dir.
    write_outcomes: list[tuple[str, bool, str]] = []
    if sweep_base is not None:
        for index, cmd in enumerate(WRITE_COMMANDS):
            write_outcomes.append(
                (
                    cmd,
                    *check_write_idempotency(
                        cmd, _write_sweep_dir(sweep_base, index, cmd)
                    ),
                )
            )
        for cmd, ok, reason in write_outcomes:
            marker = "PASS" if ok else "FAIL"
            print(f"[{marker}] (write) {cmd}")
            if not ok:
                failed += 1
                failures.append((cmd, reason))

    if failed:
        print(f"\n{failed} command(s) were not safe to run twice:")
        for cmd, reason in failures:
            print(f"\n--- {cmd} ---")
            print(reason)
        return 1
    suffix = f" (+{len(write_outcomes)} write)" if write_outcomes else ""
    print(f"\nAll {len(commands)} read-only command(s) deterministic{suffix}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
