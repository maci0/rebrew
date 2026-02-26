---
name: rebrew-status-tracking
description: Monitor and analyze project reverse engineering progress using verification, catalogging, and function dependency graphs.
license: MIT
---

# Rebrew Status Tracking

Use these commands to visualize progress, track match statuses, and discover blocking dependencies.

## 1. Fast Overall Status
To get a quick count of EXACT, RELOC, MATCHING, and STUB functions:
- Run `uv run rebrew status`
- For machine-readable output, use `uv run rebrew status --json`.

## 2. Full Verification Run
If you need to validate compilation and diffing strictly across all functions:
- Run `uv run rebrew-verify`
- For a structured JSON report: `uv run rebrew-verify --json` (writes to stdout)
- To save the report: `uv run rebrew-verify -o db/verify_results.json`
This compiles every annotated function and diffs them against the original binary using `rich` progress bars.

## 3. Annotation Validation
To check annotation correctness across all reversed files:
- Run `uv run rebrew-lint` for human-readable lint results.
- Run `uv run rebrew-lint --json` for machine-readable lint results (error counts, per-file details).
- Run `uv run rebrew-lint --fix` to auto-migrate old annotation formats.

## 4. Library Function Identification
To identify known library functions (MSVCRT, zlib, DirectX, etc.) in the binary:
- Run `uv run rebrew-flirt --json` for machine-readable FLIRT signature matches.
- This helps distinguish library code from game code and prioritize reversing efforts.

## 5. Function Dependency Graph
If you are trying to understand call relationships or find out what functions are blocking progress:
- Run `uv run rebrew graph` to generate a mermaid call graph from `extern` declarations in source files.
- Run `uv run rebrew graph --format summary` to get statistics on graph components, leaf functions, and the top unreversed blocker functions.
- Run `uv run rebrew graph --focus <FuncName> --depth 2` to isolate the neighbourhood for a specific function.
- Add `--origin <TYPE>` (e.g. GAME or MSVCRT) to filter.

## 6. Generating the Coverage Database
The full pipeline to build the coverage database and inspect it:

```bash
# Step 1: Generate data JSON from annotations + binary analysis
uv run rebrew-catalog

# Step 2: Build the SQLite coverage database from the JSON
uv run rebrew-build-db

# Step 3 (optional): Launch the recoverage web dashboard
uv run recoverage serve
```

The database stores per-function metadata (`detected_by`, `size_by_tool`, `textOffset`), per-global metadata (`origin`, `size`), section cell states, and coverage statistics. See `docs/DB_FORMAT.md` for the full schema (v2).

## 7. Cold-Start Triage
For a quick, combined overview at session start:
- Run `uv run rebrew triage` for coverage stats, near-miss functions, and recommendations in one command.
- Run `uv run rebrew triage --json` for machine-readable output.
- Combines `rebrew-next --stats`, `rebrew-next --improving`, and FLIRT scan into a single report.

## 8. Atomic Promotion
To test and atomically update STATUS annotations:
- Run `uv run rebrew promote src/<target>/<file>.c` to compile, compare, and update STATUS in one step.
- Use `--dry-run` to preview changes without writing.
- For JSON output: `uv run rebrew promote --json src/<target>/<file>.c`

## 9. CLI Coverage Stats
To inspect coverage stats without starting the web dashboard:
- Run `uv run recoverage stats` for a Rich table of per-section coverage.
- Run `uv run recoverage export --format json` for machine-readable export.
- Run `uv run recoverage check --min-coverage 60` as a CI gate.
