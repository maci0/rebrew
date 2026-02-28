# Proposal: Surgical Semantic Equivalence with `angr`

## Problem Statement
The `rebrew` project currently relies on byte-for-byte matching (or relocation-masked matching) to prove that decompiled C code is functionally equivalent to the original binary.
While this works for the vast majority of the codebase, compilers often generate assembly that is functionally identical but structurally different (e.g., swapping independent instructions, allocating different registers, or unrolling loops differently).

Currently, these functions are permanently stuck in the `MATCHING` state. To reach 100% provable equivalence without resorting to inline assembly hacks or fragile compiler flag permutations, we need a mathematical proof of equivalence for these stubbornly divergent functions.

## Proposed Solution: `rebrew prove`
We propose introducing a new CLI tool, `rebrew prove`, powered by the `angr` binary analysis framework and its Z3 constraint solver.

Because whole-program symbolic execution suffers from state explosion, `angr` will **never** analyze the entire binary. Instead, `rebrew` will use its existing lightning-fast byte diffing to verify 99% of the functions, and invoke `angr` **surgically** only on the specific `MATCHING` functions that require semantic proof.

---

## Tooling Architecture

### 1. `rebrew prove <target_ident>`
A new Typer command that targets a specific `.c` file or `// SYMBOL:` annotation marked as `MATCHING`.

#### Execution Flow
1. **Compile**: `rebrew` compiles the local `.c` file to a COFF `.obj` file using the standard `compile.py` pipeline.
2. **Extract**: `rebrew` extracts the raw bytes for the target function from the original PE binary and the newly compiled `.obj` file.
3. **Load via CLE**: Both byte blobs are loaded into two isolated `angr.Project` instances using the `blob` backend.
4. **Symbolic Scaffolding**:
   - `angr` requires a valid machine state. `rebrew` will automatically inspect the function prototype (via the `// PROTOTYPE:` annotation) to initialize symbolic variables (e.g., `BVS('arg1', 32)`) in the correct calling convention registers (`ECX`, `EDX`, or stack).
   - Any external function calls (`extern`) within the blobs will be hooked with generic `angr.SIM_PROCEDURES` that return unconstrained symbolic values.
5. **Symbolic Execution**: Both `angr` simulation managers step through their respective execution paths.
6. **Constraint Solving (Z3)**: At the function exit points, Z3 evaluates the final symbolic state of the return register (`EAX`) and any modified memory. If the algebraic formulas for both states are logically equivalent (i.e., `solver.satisfiable(state_A.regs.eax != state_B.regs.eax)` returns `False`), the functions are mathematically identical.

### 2. New Annotation Status: `PROVEN`
If Z3 successfully proves semantic equivalence, `rebrew prove` will automatically update the file's header:
```c
// FUNCTION: SERVER 0x10008880
// STATUS: PROVEN
// ORIGIN: GAME
// SIZE: 142
// CFLAGS: /O2 /Gd
// SYMBOL: _calculate_physics
```
A `PROVEN` status holds the same weight as `EXACT` or `RELOC` in the project completion metrics.

---

## User Workflow

1. **Standard Reversing**: A reverse engineer writes C code for `calculate_physics.c`.
2. **Testing**: They run `rebrew test src/server.dll/calculate_physics.c`. The output shows `STATUS: MATCHING`. The bytes differ because the modern compiler chose `EBX` instead of `EDI` for a loop counter.
3. **GA Attempt**: They run `rebrew match src/server.dll/calculate_physics.c` to see if a specific `/O` flag fixes it. The GA fails to find a byte-identical match.
4. **Surgical Proof**: Instead of rewriting the C code to force the compiler's hand, they run:
   ```bash
   rebrew prove calculate_physics
   ```
5. **Validation**: `angr` spins up in the background. After 15 seconds, it outputs:
   ```
   [angr] Analyzing paths for _calculate_physics (0x10008880)
   [angr] Paths explored: 14 (Original), 14 (Obj)
   [Z3] Solving constraints...
   ✅ SEMANTIC EQUIVALENCE PROVEN
   Updated status to PROVEN in calculate_physics.c
   ```

## Technical Challenges & Mitigations

1. **Relocations in `.obj` files**: Unlinked COFF files contain `0x00000000` placeholders for globals and external calls.
   * *Mitigation*: `rebrew prove` will parse the COFF relocation table (`.reloc`) before passing the blob to `angr` and hook those specific offsets to return symbolic pointers.
2. **Loops and Path Explosion**: A function with complex loops might take `angr` hours to traverse.
   * *Mitigation*: `rebrew prove` will enforce a strict timeout (e.g., 60 seconds) and a loop bound limit (`angr.exploration_techniques.LoopSeer`). If it cannot prove equivalence within the budget, it fails gracefully and leaves the status as `MATCHING`.
3. **Floating Point Operations**: Z3 struggles significantly with FPU (`x87` or SSE) math.
   * *Mitigation*: Functions heavily reliant on floats may need to be skipped or handled with unconstrained approximation.

## Conclusion
By treating `angr` as a heavy, specialized hammer rather than a general-purpose tool, `rebrew` can definitively close the gap on the hardest 1% of functions without sacrificing the speed and simplicity of its compiler-in-the-loop workflow.
