# Rebrew Development Notes

Practical knowledge for contributing to rebrew.  For conventions and layout
see [`AGENTS.md`](../AGENTS.md); for the CLI surface see [`CLI.md`](CLI.md).

## Test conventions

- No `conftest.py` — every test file is self-contained (inline helpers, `tmp_path`).
- Class-based grouping (`class TestFeature:`), helpers prefixed `_`, tests
  annotated `-> None`.
- `tests/bin_util.py` provides hand-rolled COFF/PE builders (`make_coff_obj`,
  `make_lib_archive`, `make_pe`) for tests that need real binaries — LIEF has
  no builders in the pinned version.  Import it as `from bin_util import ...`
  (pytest puts the test directory on `sys.path`).

## Typer quirks (learned the hard way)

1. **Options after positionals are fine.**  Interspersed args parse normally
   in the `@app.callback(invoke_without_command=True)` commands: both
   `runner.invoke(app, ["0x1000", "--json"])` (`tests/test_asm_extended.py`) and
   `["show", "0x1000", "--json"]` (`tests/test_extract_cli.py`) exit 0.  Do not
   contort an argv list to hoist options ahead of positionals.
2. **`main()` direct calls misbind partial kwargs.**  Prefer
   `CliRunner().invoke(app, [...])` over calling `main(...)` directly.  Worse,
   typer's wrapper **leaks `typer.models.OptionInfo` as the value of omitted
   params** on direct Python calls — an `OptionInfo` is truthy and not a
   `Path`, so `if x is not None:` and `Path(x)` misbehave.  This caused two
   real bugs (a truthy `--flag-sweep-toolchains` leaking into `match`'s watch
   re-test; `rebrew init` crashing on a leaked `--link-tools-from`).
   **Convention:**
   - Callbacks that unit tests invoke directly must guard every new option
     with `option_default(x, None)` from `rebrew.cli` (see `init.py`).
   - Closures that re-enter a callback (e.g. `match._retest` in watch mode)
     must forward **every** CLI param explicitly — a missing one leaks as a
     truthy `OptionInfo` instead of its default.
3. **Module-level `Console(stderr=True)`** captures stderr at import — output
   is not capturable via `capsys` or `CliRunner` for modules that build their
   console at module scope.  Assert JSON stdout or logic side effects instead,
   and use `result.stdout` (not `result.output`) when the JSON is on stdout.
4. **`typer.Exit` carries no message** — `error_exit` prints it, so
   `pytest.raises(match=...)` cannot match it.  Assert on `result.output`
   instead.

## Metadata / tomlkit gotchas

- `rebrew-functions.toml` keys are quoted strings: `["SERVER.0x01006364"]`.
- **tomlkit copies plain lists on assignment** — mutating a list after
  `tbl[key] = my_list` is invisible to the document.  Re-assign after
  mutation (this caused a real `cfg add-module` persistence bug).
- **STATUS writes/deletes are gated.**  `update_field`/`remove_field` refuse
  STATUS; use `update_source_status`.  Inline-STATUS stripping from a `.c`
  file must go through `remove_inline_annotation_key` (file-only) — routing
  it through `remove_annotation_key` raises.
- VA formatting is `0x%08x` (8 digits) everywhere in output; test
  expectations must match.
- **`update_annotation_key`/metadata writes default `metadata_dir` to
  `filepath.parent`** — for library headers that lives next to the .c/.h,
  NOT the real metadata root (`cfg.metadata_dir`).  Always pass
  `metadata_dir=cfg.metadata_dir` explicitly (this bit `crt-match
  --fix-source`, which created a stray rebrew-functions.toml next to the
  header).  Same trap in `match_batch._parse_annotations` — pass cfg.metadata_dir
  through.
- **Compile paths need the source directory as an extra include dir.**  A
  `.c` using relative includes (`#include "../../Units/..."`) fails to
  compile from a temp dir unless `extra_include_dirs=[source.parent]` is
  passed.  The GA path does this; `flag_sweep` had to learn it too
  (single-function `--flag-sweep-only` silently returned 0 results).

## Import patterns

- Modules use **local imports inside functions** to break import cycles
  (`from rebrew.compile import compile_and_compare` inside `verify_entry`).
  Monkeypatch the **source module** (`rebrew.compile.compile_and_compare`),
  not the importer — `monkeypatch.setattr("rebrew.verify.compile_and_compare",
  ...)` fails because the attribute doesn't exist on `rebrew.verify`.
- `tools/detect_cycles.py` enforces no module-level import cycles (pre-commit
  hook).  `if TYPE_CHECKING:` guards are skipped by the detector.
- `tools/public_surface.py` reads the public import surface out of the AST
  (no import of the package, so no optional extra is needed) and diffs it
  against a ref: `uv run --frozen python tools/public_surface.py --diff v2.14.0` prints
  what a consumer's `from rebrew.x import y` loses.  A removed or reshaped name
  there needs a `**Breaking:**` entry naming it; see "Versioning and releases"
  in [`CONTRIBUTING.md`](../CONTRIBUTING.md) and
  `tests/test_public_surface.py`.

## Registry snapshots

Every component registry (the `rebrew.registry` entry-point groups: toolchains,
decompiler backends, GA mutations, flag sets, library presets, detection tables,
binary loaders, cache backends, discoverers) is discovered at import and
republished **as a whole** by its `refresh_*` function.  A reader that needs two
tables from one refresh must take them from the same generation:

- `rebrew.toolchain.registry_snapshot()` — the registry and its origins
- `rebrew.toolchain_detect.detection_tables()` — the four detection tables
- `rebrew.decompiler.fetch_decompilation` — reads both under `_BACKEND_REFRESH_LOCK`

`from rebrew.toolchain import TOOLCHAINS` at module level pins one generation
for the life of the importer, and a function-local import pins it for the call.
That is fine for a single-registry read and wrong when the result is paired with
another table: `cmake-toolchain` used to read the linker-era and Rich-build
tables separately, so a refresh landing between them wrote `12.00` for a profile
whose build number was in the generation it did not read.  A registry module
that publishes more than one table from one refresh owns a snapshot accessor;
adding a second bare global reopens the same bug.  Refresh functions must also
build every value **before** rebinding, then publish under the module's lock —
never mutate a published map in place, or a concurrent reader straddles two
generations.

`registry.refresh_all()` re-runs every group under one lock and returns
`{group: count}`, keyed without the `rebrew.` prefix.  The CLI command groups
(`rebrew.commands`, `rebrew.multicommands`) are not refreshed: the umbrella app
mounts them once, and a second mount could not restore that generation.

A test that installs a fake entry point must let the refresh be the inverse:
re-register with the entry point gone and assert the contribution left
(`TestDetectionTablesSnapshot`).  The autouse
`_isolate_registry_state` fixture in `tests/test_registry.py` restores the
published globals around every test in that module.

## Toolchain-dependent tests

- `match.py`/`test.py`/`matcher/compiler.py` need the MSVC toolchain docker
  image — covered with stubs at the pure-helper level only.
- `prove.py` needs `angr` (the `prove` extra).  `uv sync --all-extras` (the
  documented dev install) enables the full prove test classes for real
  (the angr-gated tests in `tests/test_prove.py` are skipped when angr is
  absent).  The
  module-level `_run_simulation` is patchable so tests can inject crafted
  states and still exercise the real `_compare_state_pairs` logic.
- The FLIRT pipeline (`flirt.py`, `gen_flirt_pat.py`) needs real `.sig`/`.pat`
  files and COFF `.lib` archives; `tests/bin_util.py` now covers the COFF
  parsing side without MSVC, and `tests/test_property_parsers.py` fuzzes the
  round-trip `.obj` extraction helpers (`_extract_string_symbols`,
  `_extract_local_labels`) against valid and malformed objects.

## Validation commands

System deps for a green local suite: **nasm** on `PATH` (asm round-trip tests;
CI installs it) and **node** on `PATH` (the `tests/dashboard_*.mjs` interaction
tests, which `tests/test_dashboard.py` skips without it).  Bootstrap also needs
sibling `../resembl` at tag `v3.1.0`
whose `HEAD` is the `RESEMBL_SHA` commit (CI `resembl-sha`) — `make setup`
checks both and prints the clone or checkout line when either is wrong.  `make help`
lists every contributor target.

```bash
make doctor                             # report every missing prerequisite (uv, ../resembl, bash, nasm,
                                        # node, shellcheck, yamllint, venv extras) with the fix for each; read-only
make setup                              # --locked sync (extras + similarity) + pre-commit/pre-push hooks (push runs
                                        # make test, needs nasm; SKIP=pytest git push to skip)
make test-one T=tests/test_annotation.py  # single file / pytest nodeid
make test-one T=tests/test_annotation.py FLAGS="-k test_stdcall"   # narrow further
make test-one T=tests/test_dashboard.py::TestSummaryRequests        # one class
make test                               # full suite (ANSI-safe; same as CI)
make lint                             # ruff check . (same scope as the pre-commit hook)
make format-check                     # ruff format --check
make mypy                             # type check (0 issues expected; strict,
                                        # covers src/rebrew + tools + every tests/ module
                                        # that has come clean; the rest is not yet clean)
make check                            # 15 of 17 pre-commit hooks — pytest (pre-push) and
                                        # validate-skill-commands (manual) are stage-gated.
                                        # Exports NO_COLOR / TERM=dumb /
                                        # _TYPER_FORCE_DISABLE_TERMINAL first, so a
                                        # FORCE_COLOR or GITHUB_ACTIONS export in the
                                        # shell cannot split the option names the
                                        # skills and help-text hooks assert on. The
                                        # raw pre-commit call below does not, which is
                                        # why the make target is the documented one.
NO_COLOR=1 TERM=dumb _TYPER_FORCE_DISABLE_TERMINAL=1 \
  uv run --frozen pre-commit run --all-files   # same 15 hooks, ANSI-safe by hand
make all                                # local gates: format-check, lint, mypy, audit, coverage, gen-fixtures-check, cycles-check, idempotency-check, cli-contract
make cli-contract                       # high-value --help greps (CI cli-contract job)
make gen-fixtures                       # regenerate tests/fixtures/ (then commit)
make build                              # sdist+wheel (CI package job; run before a PR)
make coverage                           # full suite under slipcover, fails below COV_FLOOR
# Bare pytest is also ANSI-safe (pytest_ansi_env plugin); prefer make test-one.
```

## Performance notes (GA scoring hot loop)

Profiled `score_candidate` (512-byte functions, 40 reloc offsets, 5000 iters):

- **capstone disasm ≈ 40 %** of per-call time — C library, not vectorizable.
- **difflib.SequenceMatcher ≈ 27 %** — mnemonic-sequence diff; scoring
  weights are calibrated to it, so swapping it changes behavior.
- Remaining ≈ 30 %: numpy byte compare (already vectorized), prologue
  checks, the reloc-mask slice loop (µs-scale at realistic reloc counts).

The GA hot path already precomputes the target side once per function
(`precompute_target` → `_pre_norm_target` / `_pre_target_mnems`, wired in
`match_ga.py` and `matcher/compiler.py`); per-candidate cost is dominated by
the unavoidable candidate disassembly.  A numpy fancy-indexing prototype
for `_normalize_with_reloc_offsets` measured **slower** (0.7×) than the
existing slice-assignment loop — do not "vectorize" it.  The `_pre_*`
contract is locked by `TestPrecomputedTarget` in tests/test_scoring.py.
