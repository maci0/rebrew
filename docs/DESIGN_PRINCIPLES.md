# Rebrew Design Principles

This document outlines the core architectural and operational philosophies that guide the development of the Rebrew ecosystem. These principles ensure the tooling remains robust, safe for autonomous AI usage, and conducive to a reproducible reverse-engineering workflow.

## 1. Idempotency First
Every tool in the Rebrew suite (`rebrew catalog`, `rebrew verify`, `rebrew init`, etc.) must be safely repeatable. Running a command twice should not yield a different outcome than running it once. There must be no destructive side-effects when re-running workflows, ensuring that humans and AI agents can safely retry operations.

## 2. Config-Driven Execution
Global and project-specific settings live in `rebrew.toml`. Tools must rely on this central configuration rather than requiring complex, manual CLI path arguments. This creates a unified entry point and guarantees that any agent or contributor is working with the exact same context (paths, compiler flags, target binaries).

## 3. Composability and Modularity
Rebrew is built as a collection of small, single-purpose CLI utilities following the Unix philosophy. Complex workflows—like autonomous batch reversing—are achieved by chaining these tools together. This makes the system extremely friendly to AI orchestration and custom batch scripting.

## 4. Score Monotonicity (Strict Non-Regression)
Whether driven by a human or an AI agent, the system must **never** make a function's decompiled state worse. Every proposed change is evaluated against a strict byte-comparison score. Updates to existing functions are only promoted if their status improves (e.g., `MATCHING` -> `RELOC`) or the mismatched byte count strictly decreases.

## 5. Byte-Identical Ground Truth
"Close enough" is not the goal. The ultimate source of truth is the compiler output. Cosmetic changes (renaming variables, adding comments) are only accepted if `rebrew test` verifies that the resulting `.obj` bytes remain completely identical to the existing matched baseline.

## 6. Safe by Default (Shadow Workspaces)
To prevent corruption of known-good decompilation (`EXACT` / `RELOC` states), experimental generation and compilation must occur in isolated staging areas. Changes are promoted to the main source tree only after passing the byte-matching gates and regression suites.

## 7. The Snowball Effect (Iterative Enrichment)
Success breeds success. Every reversed function immediately enriches the context available to the ecosystem. Tools and agents process the easiest functions first (smallest functions, library matches, single-block leaves), continuously expanding the semantic database. This makes subsequent, harder functions easier to reverse.

## 8. Bi-Directional Synchronization
Local decompilation workflows and reverse-engineering platforms (like Ghidra) must complement each other. Discoveries made in the local repository (struct definitions, variable renames, compilation flags) should seamlessly flow back into the disassembler's project database, and vice-versa, avoiding silos of knowledge.

## 9. RAG over Hallucination
AI models are powerful semantics engines, but they cannot guess absolute Virtual Addresses (VAs), structure offsets, or proprietary calling conventions. Therefore, all AI code generation must be grounded by a Retrieval-Augmented Generation (RAG) system. Deterministic facts (e.g., jump targets, global pointer types) must be retrieved from the known `rebrew.db` and explicitly injected into the LLM prompt.

## 10. AI as a Baseline, Not a Finisher
The LLM's role is to generate a semantically correct structural baseline. It shouldn't be relied upon to perfectly guess register allocation optimizations or minute instruction jitter. Once the LLM achieves a `MATCHING` state with a small byte delta, deterministic programmatic tools (like the Genetic Algorithm) take over to brute-force the remaining permutations.

## 11. Tiered Context Budgets
Context windows are finite and expensive. When injecting RAG context for a target function, a strict priority budget must be enforced. Critical definitions (directly referenced struct types and called function signatures) take precedence over "nice-to-have" context (like the raw assembly of distant caller algorithms).

## 12. Explicit Typing and Code Clarity
Relying on implicit language features introduces hidden codegen discrepancies. Code implementation should favor maximum explicitness to ensure reliable, deterministic output:
- Explicit precision: Always use `__cdecl`, `__stdcall`, and exact variable sizes (`unsigned char` over `char`) matching the original binary.
- Avoid expression tricks: Prefer clear, explicit control flow (`if/return`) over size-optimized but complex expressions (like `(x != -1) - 1`).

## 13. Predictable C89 Structural Conformity
When dealing with older compilers (like MSVC6), code must map directly to compiler idiosyncrasies:
- Variable declarations must stay grouped at the top of a block.
- Logic structure (`if/else` flow, loop choice) dictates the machine code generation directly, requiring rigid adherence over modern "clean code" stylistic preferences.

## 14. Continuous Linting and Validation
Metadata integrity is critical for a smooth reverse-engineering pipeline. Every decompiled `.c` file must undergo strict, continuous linting (`rebrew lint`) at every step of the generation, compilation, and modification process. This guarantees that all header annotations (`STATUS`, `ORIGIN`, `SIZE`, `CFLAGS`) remain structurally compliant, enabling seamless downstream parsing by the dashboard and matching engines without manual intervention.

## 15. Full-Binary Scope (Beyond `.text`)
A faithful decompilation requires coverage of the *entire* binary, not just executable code. The `.data`, `.rdata`, and `.bss` sections contain globals, dispatch tables, vtables, string tables, and const arrays that are equally critical for correctness. Tools must inventory and cross-reference data-section artifacts (`rebrew data`), detect dispatch tables / vtables by scanning for contiguous function-pointer arrays, and flag type conflicts across files. Code coverage and data coverage are tracked together.

## 16. Automated Near-Miss Promotion
Many `MATCHING` functions differ from the target by only a handful of bytes — an operand swap, branch inversion, or register allocation jitter. The system must be able to batch-process these near-miss cases unattended (`rebrew ga --near-miss --threshold N`), sorted by byte delta so the easiest wins come first. This ensures that trivial MATCHING→RELOC promotions are never left on the table, and that human attention is reserved for functions that genuinely require it.
