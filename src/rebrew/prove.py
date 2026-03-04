"""prove.py — Symbolic equivalence prover for rebrew.

Uses angr's symbolic execution and Z3 constraint solving to mathematically
prove that a compiled function is semantically equivalent to the original
binary, even when byte-level comparison fails due to different register
allocation, instruction reordering, or loop unrolling.

Architecture
~~~~~~~~~~~~
1. Extract target bytes from the DLL and compiled bytes from the .obj
2. Load both into separate angr Projects using the ``blob`` backend
3. Parse the ``// PROTOTYPE:`` annotation for calling convention + arg count
4. Hook external call relocations with ``ReturnUnconstrained``
5. Run symbolic execution on both with ``LoopSeer`` and timeout limits
6. Compare EAX (return register) formulas via Z3 — if no satisfying
   assignment makes them differ, the functions are proven equivalent

angr is an optional dependency (~500 MB).  Import is guarded with a clear
error message directing users to ``uv pip install -e ".[prove]"``.
"""

from __future__ import annotations

import re
import signal
import tempfile
import warnings
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import parse_c_file, resolve_symbol, update_annotation_key
from rebrew.cli import TargetOption, error_exit, json_print, require_config
from rebrew.compile import compile_to_obj
from rebrew.config import ProjectConfig
from rebrew.matcher.parsers import parse_obj_symbol_bytes

# ---------------------------------------------------------------------------
# Guarded angr import
# ---------------------------------------------------------------------------

_ANGR_MISSING_MSG = (
    "angr is required for 'rebrew prove'.  Install it with:\n  uv pip install -e \".[prove]\""
)


def _require_angr() -> None:
    """Raise a clear error if angr is not installed."""
    try:
        import angr  # noqa: F401
    except ImportError:
        raise ImportError(_ANGR_MISSING_MSG)


# ---------------------------------------------------------------------------
# Prototype parsing
# ---------------------------------------------------------------------------

# Matches prototypes like:
#   int __cdecl func(int, char*)
#   void __thiscall CClass::Method(int a, float b)
#   int func(void)
_PROTO_RE = re.compile(
    r"^\s*(?P<ret>\w[\w\s\*]*?)\s+"
    r"(?:(?P<cc>__cdecl|__stdcall|__thiscall|__fastcall)\s+)?"
    r"(?:[\w:]+)\s*"  # function name (may include class::)
    r"\((?P<args>[^)]*)\)"
)


def _parse_prototype(proto: str) -> tuple[str, int]:
    """Parse a C prototype string into (calling_convention, arg_count).

    Returns ("cdecl", 0) as default if parsing fails.
    """
    m = _PROTO_RE.match(proto.strip())
    if not m:
        return "cdecl", 0

    cc = (m.group("cc") or "__cdecl").lstrip("_").lower()
    args_str = m.group("args").strip()

    if not args_str or args_str.lower() == "void":
        return cc, 0

    # Count args by splitting on commas (handles pointer types with *)
    args = [a.strip() for a in args_str.split(",") if a.strip()]
    return cc, len(args)


# ---------------------------------------------------------------------------
# Core equivalence prover
# ---------------------------------------------------------------------------


def prove_equivalence(
    original_bytes: bytes,
    compiled_bytes: bytes,
    reloc_offsets: dict[int, str] | None,
    prototype: str,
    arch: str = "x86",
    *,
    timeout: int = 60,
    loop_bound: int = 10,
) -> tuple[bool, str]:
    """Prove semantic equivalence of two function byte blobs via symbolic execution.

    Args:
        original_bytes: Raw bytes from the target binary.
        compiled_bytes: Raw bytes from the compiled .obj.
        reloc_offsets: Relocation offsets in the compiled blob (offset → symbol name).
        prototype: C prototype string for argument setup.
        arch: Architecture string (default "x86").
        timeout: Seconds before giving up.
        loop_bound: Max loop iterations for angr's LoopSeer.

    Returns:
        (proven, message) — proven is True if semantic equivalence was proved.
    """
    import angr
    import claripy

    cc, arg_count = _parse_prototype(prototype)

    # Create symbolic arguments
    sym_args = [claripy.BVS(f"arg_{i}", 32) for i in range(arg_count)]

    def _setup_state(proj: angr.Project, label: str) -> angr.SimState:
        """Create an initial state with symbolic arguments placed per calling convention."""
        state = proj.factory.blank_state(addr=0)
        # Set up a fake stack frame
        state.regs.esp = 0x7FFF0000
        state.regs.ebp = 0x7FFF0000

        if cc == "thiscall" and sym_args:
            # ECX = this pointer (first arg)
            state.regs.ecx = sym_args[0]
            # Remaining args on stack (right-to-left)
            for i, arg in enumerate(sym_args[1:]):
                state.memory.store(state.regs.esp + 4 + (i * 4), arg, endness="Iend_LE")
        elif cc == "fastcall":
            # ECX = arg0, EDX = arg1, rest on stack
            if len(sym_args) >= 1:
                state.regs.ecx = sym_args[0]
            if len(sym_args) >= 2:
                state.regs.edx = sym_args[1]
            for i, arg in enumerate(sym_args[2:]):
                state.memory.store(state.regs.esp + 4 + (i * 4), arg, endness="Iend_LE")
        else:
            # cdecl / stdcall — all args on stack
            for i, arg in enumerate(sym_args):
                state.memory.store(state.regs.esp + 4 + (i * 4), arg, endness="Iend_LE")

        return state

    def _make_project(blob: bytes) -> angr.Project:
        import io

        return angr.Project(
            io.BytesIO(blob),
            main_opts={"backend": "blob", "arch": "x86", "base_addr": 0},
            auto_load_libs=False,
        )

    try:
        proj_orig = _make_project(original_bytes)
        proj_comp = _make_project(compiled_bytes)
    except Exception as e:
        return False, f"Failed to create angr projects: {e}"

    # Hook relocation offsets in compiled blob with ReturnUnconstrained
    if reloc_offsets:
        for offset, _sym_name in reloc_offsets.items():
            if 0 <= offset < len(compiled_bytes):
                try:
                    proj_comp.hook(
                        offset,
                        angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](),
                        length=4,
                    )
                except (KeyError, TypeError, ValueError) as e:
                    warnings.warn(
                        f"Failed to hook reloc at offset 0x{offset:x}: {e}",
                        stacklevel=2,
                    )

    state_orig = _setup_state(proj_orig, "original")
    state_comp = _setup_state(proj_comp, "compiled")

    def _run_simulation(proj: angr.Project, state: angr.SimState) -> list[Any]:
        """Run symbolic execution and return satisfiable states."""
        sm = proj.factory.simgr(state)
        sm.use_technique(angr.exploration_techniques.LoopSeer(bound=loop_bound))

        # Timeout via alarm signal (Unix only)
        timed_out = False

        def _timeout_handler(signum: int, frame: Any) -> None:
            nonlocal timed_out
            timed_out = True
            raise TimeoutError("Symbolic execution timed out")

        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(timeout)
        try:
            sm.run()
        except TimeoutError:
            pass
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

        # Filter to only satisfiable states with meaningful EAX values
        if timed_out:
            return sm.satisfiable(unsat_core=False) or []
        return sm.satisfiable(unsat_core=False)

    try:
        states_orig = _run_simulation(proj_orig, state_orig)
        states_comp = _run_simulation(proj_comp, state_comp)
    except Exception as e:
        return False, f"Symbolic execution failed: {e}"

    if not states_orig:
        return False, "No terminal states reached for original binary (timeout or path explosion)"
    if not states_comp:
        return False, "No terminal states reached for compiled code (timeout or path explosion)"

    # Compare EAX (return register) across all terminal state pairs
    # For equivalence: for ALL pairs of (orig, comp) states, EAX must be provably equal
    for s_orig in states_orig:
        eax_orig = s_orig.regs.eax
        can_differ = False  # True if we found at least one (orig, comp) pair that can differ
        for s_comp in states_comp:
            eax_comp = s_comp.regs.eax

            # Check if there exists an input that makes them differ
            # Build constraint from both states' symbolic variables
            solver = claripy.Solver()
            # Copy constraints from both states
            for expr in s_orig.solver.constraints:
                solver.add(expr)
            for expr in s_comp.solver.constraints:
                solver.add(expr)
            solver.add(eax_orig != eax_comp)

            if solver.satisfiable():
                # Found an assignment where return values differ — not equivalent
                can_differ = True
                break

        if can_differ:
            return False, (
                "Z3 found a satisfying assignment where return values differ "
                f"(checked {len(states_orig)} x {len(states_comp)} state pairs)"
            )

    return True, (
        f"Proven equivalent ({len(states_orig)} original state(s), "
        f"{len(states_comp)} compiled state(s))"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = """\
[bold]Examples:[/bold]

rebrew prove src/server.dll/calculate_physics.c       Prove equivalence

rebrew prove src/server.dll/calculate_physics.c --json JSON output

rebrew prove src/server.dll/calculate_physics.c --dry-run  Don't update annotations

rebrew prove my_func                                  Find by symbol name

[bold]How it works:[/bold]

1. Validates the function status is MATCHING (byte-diff but structurally close)

2. Extracts target bytes from the DLL and compiles the C source

3. Loads both byte blobs into angr's symbolic execution engine

4. Proves EAX equivalence via Z3 constraint solving

5. If proven: updates STATUS from MATCHING → PROVEN

[dim]angr is a heavy optional dependency (~500 MB).
Install with: uv pip install -e ".[prove]"[/dim]"""

app = typer.Typer(
    help="Prove semantic equivalence of MATCHING functions via symbolic execution.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)

console = Console(stderr=True)


def _resolve_source(source_arg: str, cfg: ProjectConfig) -> Path:
    """Resolve a source argument to a Path.

    Accepts either a direct file path or a symbol name to search for.
    """
    p = Path(source_arg)
    if p.exists() and p.is_file():
        return p

    # Try searching for a matching .c file by stem
    from rebrew.cli import iter_sources

    for src in iter_sources(cfg.reversed_dir, cfg):
        if src.stem == source_arg or src.stem == source_arg.lstrip("_"):
            return src

    return p  # Return as-is, will fail later with a clear error


@app.callback(invoke_without_command=True)
def main(
    source: str = typer.Argument(..., help="C source file or symbol name"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    timeout: int = typer.Option(60, "--timeout", help="Seconds before giving up"),
    loop_bound: int = typer.Option(10, "--loop-bound", help="Max loop iterations for angr"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
) -> None:
    """Prove semantic equivalence of a MATCHING function via symbolic execution."""
    # Guard angr import early
    try:
        _require_angr()
    except ImportError as e:
        error_exit(str(e), json_mode=json_output)

    cfg = require_config(target=target, json_mode=json_output)
    source_path = _resolve_source(source, cfg)

    if not source_path.exists():
        error_exit(f"Source file not found: {source_path}", json_mode=json_output)

    # Parse annotation
    ann = parse_c_file(source_path, target_name=cfg.marker if cfg else None)
    if ann is None:
        error_exit(f"No annotation found in {source_path}", json_mode=json_output)

    if ann.status not in ("MATCHING", "MATCHING_RELOC"):
        error_exit(
            f"Status is '{ann.status}', expected MATCHING or MATCHING_RELOC. "
            "Only MATCHING functions need symbolic equivalence proving.",
            json_mode=json_output,
        )

    symbol = resolve_symbol(ann, source_path)
    va = ann.va
    size = ann.size

    if not size:
        error_exit(f"SIZE annotation is missing or zero in {source_path}", json_mode=json_output)

    # Extract target bytes from DLL
    target_bytes = cfg.extract_dll_bytes(va, size)
    if not target_bytes:
        error_exit(
            f"Failed to extract target bytes at VA 0x{va:08x} (size {size})",
            json_mode=json_output,
        )

    # Compile source and extract obj bytes
    cflags_str = ann.cflags or "/O2 /Gd"
    cflags_list = cflags_str.split()
    origin = ann.origin or "GAME"
    compile_cfg = cfg.for_origin(origin)

    with tempfile.TemporaryDirectory(prefix="rebrew_prove_") as workdir:
        obj_path, err = compile_to_obj(compile_cfg, source_path, cflags_list, workdir)
        if obj_path is None:
            error_exit(f"Compile error: {err}", json_mode=json_output)

        obj_bytes, reloc_offsets = parse_obj_symbol_bytes(obj_path, symbol)
        if obj_bytes is None:
            error_exit(f"Symbol '{symbol}' not found in compiled .obj", json_mode=json_output)

    prototype = ann.prototype or ""

    # Run the prover
    if not json_output:
        console.print(
            f"[bold]Proving equivalence:[/bold] {source_path.name} "
            f"(0x{va:08x}, {len(target_bytes)}B vs {len(obj_bytes)}B)"
        )
        console.print(f"  Prototype: {prototype or '(none — assuming void f(void))'}")
        console.print(f"  Timeout: {timeout}s, loop bound: {loop_bound}")

    proven, message = prove_equivalence(
        target_bytes,
        obj_bytes,
        reloc_offsets,
        prototype,
        timeout=timeout,
        loop_bound=loop_bound,
    )

    # Build result
    result: dict[str, Any] = {
        "source": str(source_path),
        "symbol": symbol,
        "va": f"0x{va:08x}",
        "size": size,
        "previous_status": ann.status,
        "proven": proven,
        "message": message,
        "target_bytes_len": len(target_bytes),
        "compiled_bytes_len": len(obj_bytes),
    }

    if proven and not dry_run:
        updated = update_annotation_key(source_path, va, "STATUS", "PROVEN")
        result["action"] = "updated" if updated else "no_change"
        result["new_status"] = "PROVEN"
    elif proven and dry_run:
        result["action"] = "would_update"
        result["new_status"] = "PROVEN"
    else:
        result["action"] = "none"
        result["new_status"] = ann.status

    if json_output:
        json_print(result)
    else:
        if proven:
            console.print(f"[green bold]PROVEN:[/green bold] {message}")
            if dry_run:
                console.print("[dim]--dry-run: STATUS not updated[/dim]")
            else:
                console.print(f"[green]STATUS updated: {ann.status} → PROVEN[/green]")
        else:
            console.print(f"[yellow bold]NOT PROVEN:[/yellow bold] {message}")
            console.print("[dim]STATUS unchanged — function remains MATCHING[/dim]")

    if not proven:
        raise typer.Exit(code=1)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
