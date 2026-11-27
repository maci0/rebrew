# Rebrew Development Notes

Practical knowledge for contributing to rebrew.  For conventions and layout
see [`AGENTS.md`](../AGENTS.md); for the CLI surface see [`CLI.md`](CLI.md).

## Python and dependency baseline

Use Python 3.15.2 (`.python-version`); the package requires Python 3.15+.
Ruff targets Python 3.15, including deferred annotations and unparenthesized
exception lists. Byte comparisons intentionally use `map(strict=False)` when
only the shared prefix contributes matches.

`uv lock --upgrade` selects the latest stable versions permitted by upstream
requirements. The remaining older transitive versions are intentional:
`cle` pins `arpy==1.1.1`; `pyvex` requires `bitstring<5`, whose 4.4.0 release
requires `tibs<0.6`; `angr` requires `pycparser~=3.11.0`; and the pinned m2c
Git HEAD requires `graphviz<0.21.0`. Update those owners before changing their
transitives. The PyPI package named `m2c` is unrelated to the decompiler and
must never replace the Git dependency.

## Test conventions

- Follow the [test patterns](../AGENTS.md#test-patterns) for fixtures, shared
  helpers, and naming.
- `tests/bin_util.py` provides hand-rolled COFF/PE builders (`make_coff_obj`,
  `make_lib_archive`, `make_pe`) for tests that need controlled binary
  fixtures. Import it as `from bin_util import ...` (pytest puts the test
  directory on `sys.path`).

## Typer behavior in tests

1. **Options after positionals are fine.**  Interspersed args parse normally
   in the CLI. For example, the composed app accepts
   `["binary", "asm", "show", "0x401000", "--json"]`
   (`tests/test_asm_extended.py`).
2. **Use `CliRunner().invoke(app, [...])` to test CLI parsing.** A direct
   Python call uses the function defaults verbatim. An omitted parameter
   declared with `typer.Option(...)` receives a truthy `OptionInfo`, which
   can break presence checks and path conversion.
   - Callbacks that unit tests invoke directly must guard every new option
     with `option_default(x, None)` from `rebrew.cli` (see `init.py`).
   - Closures that re-enter a callback (e.g. `match._retest` in watch mode)
     must forward **every** CLI param explicitly: a missing one leaks as a
     truthy `OptionInfo` instead of its default.
3. **Console capture follows the selected stream.** The shared console from
   `rebrew.utils` resolves the current stderr when writing, so `capsys` and
   `CliRunner` can capture it. An explicitly supplied `file=` fixes a different
   destination. Inspect `result.stdout` for normal JSON results and
   `result.stderr` for structured errors; `result.output` combines streams.
4. **`typer.Exit` carries no message.** Assert on the emitted diagnostic in
   `result.stderr` or `result.output` when testing `error_exit`.

## Metadata / tomlkit gotchas

- `rebrew-functions.toml` keys are quoted strings: `["SERVER.0x01006364"]`.
- **tomlkit copies plain lists on assignment**: mutating a list after
  `tbl[key] = my_list` is invisible to the document.  Re-assign after
  mutation.
- **STATUS writes/deletes are gated.**  `update_field`/`remove_field` refuse
  STATUS; use `update_source_status`.  Inline state in a `.c` file is not a
  source: lint reports the tag (E024), and every writer goes to the store.
- Canonical metadata and report VA keys use `0x%08x` (8 digits). Diagnostics
  and some JSON outputs use minimal-width `0x%x`; assert the format each
  command actually emits.
- **`set_binding_field` / `remove_binding_field` default `metadata_dir` to
  `filepath.parent`**: for library headers that lives next to the .c/.h,
  NOT the real metadata root (`cfg.metadata_dir`).  Always pass
  `metadata_dir=cfg.metadata_dir` explicitly (this bit `library crt-match
  --fix-source`, which created a stray rebrew-functions.toml next to the
  header).  Same trap in `match_batch._parse_annotations`: pass cfg.metadata_dir
  through.
- **Compile paths search the actual source file's directory first.**
  `compile_to_obj` adds `source.parent` automatically, so relative includes
  such as `#include "../../Units/..."` resolve when compiling the real file.
  When compiling a staged or temporary copy, pass
  `extra_include_dirs=[original_source_parent]` explicitly.

## Import patterns

Follow the lazy-import and layering rules in [AGENTS.md](../AGENTS.md).

- Keep a dependency out of the static module graph with a function-local
  import (`from rebrew.compiler.compile import compile_and_compare` inside
  `verify_entry`); the cycle detector reads module-scope imports, so it cannot
  see a local one.
  Monkeypatch the **source module** (`rebrew.compiler.compile.compile_and_compare`),
  not the importer: `monkeypatch.setattr("rebrew.verify.compile_and_compare",
  ...)` fails because the attribute doesn't exist on `rebrew.verify`.
- `tools/detect_cycles.py` enforces no module-scope import cycles (pre-commit
  hook); a PEP 810 `lazy import` still counts.  Function bodies and
  `if TYPE_CHECKING:` guards are skipped by the detector.
- `tools/check_layering.py` enforces import direction. For example, `errors`
  re-exports `ComponentError` under `TYPE_CHECKING` to avoid a runtime dependency.
- `tools/public_surface.py` reads the public import surface out of the AST
  (no import of the package, so no optional extra is needed) and diffs it
  against a ref: `uv run --frozen python tools/public_surface.py --diff <last-release-tag>` prints
  what a consumer's `from rebrew.x import y` loses.  A removed or reshaped name
  there needs a `**Breaking:**` entry naming it; see "Versioning and releases"
  in [`CONTRIBUTING.md`](../CONTRIBUTING.md) and
  `tests/test_public_surface.py`.

## Registry snapshots

Every component registry (the `rebrew.registry` entry-point groups: toolchains,
decompiler backends, GA mutations, flag sets, library presets, metadata backends,
detection tables, MSVC version tables, binary loaders, cache backends, discoverers) is discovered at import
(metadata backends at first use) and republished **as a whole** by its `refresh_*` function.  A reader that needs two
tables from one refresh must take them from the same generation:

- `rebrew.compiler.toolchain.registry_snapshot()`: the registry and its origins
- `rebrew.toolchain_detect.detection_tables()`: the four detection tables
- `rebrew.decompiler.fetch_decompilation`: reads both under `_BACKEND_REFRESH_LOCK`

`from rebrew.compiler.toolchain import TOOLCHAINS` at module level pins one generation
for the life of the importer, and a function-local import pins it for the call.
That is fine for a single-registry read and wrong when the result is paired with
another table: `cmake-toolchain` must read the linker-era and Rich-build tables
from one generation, because a refresh landing between them would write `12.00`
for a profile whose build number was in the generation it did not read.  A
registry module that publishes more than one table from one refresh owns a
snapshot accessor; adding a second bare global reopens the same bug.  Refresh
functions must also build every value **before** rebinding, then publish under
the module's lock: never mutate a published map in place, or a concurrent
reader straddles two generations.

Refresh builds from packaged definitions, never from the previous merged table:
removing a plugin must remove its contributions and restore any overridden
defaults. Public refresh results and snapshots copy mutable containers, including
nested tuning data. Provider-owned dictionaries and returned snapshots must not
be able to mutate a published generation. Discovery captures its provider map
once for the whole strategy run, so a refresh cannot swap providers mid-run.

`registry.refresh_all()` re-runs every group under one lock and returns
`{group: count}`, keyed without the `rebrew.` prefix.  The CLI command groups
(`rebrew.commands`, `rebrew.multicommands`) are not refreshed: the umbrella app
mounts them once, and a second mount could not restore that generation.
The composite lock serializes refresh calls. Reads across different registry
groups can observe different generations. Group snapshots guarantee
consistency within their owning group.

A test that installs a fake entry point must let the refresh be the inverse:
re-register with the entry point gone and assert the contribution left
(`TestDetectionTablesSnapshot`).  The autouse
`_isolate_registry_state` fixture in `tests/test_registry.py` restores the
published globals around every test in that module.

## Toolchain-dependent tests

- Matching helper and CLI tests can stub compile dependencies. Toolchain
  round-trip tests exercise the real compile and comparison when the required
  image is available and skip otherwise.
- `prove.py` needs `angr` (the `prove` extra).  `make setup` (the documented
  dev install: `uv sync --locked --all-extras --group similarity`) enables the
  full prove test classes for real (the angr-gated tests in
  `tests/test_prove.py` are skipped when angr is absent).  The
  module-level `_run_simulation` is patchable so tests can inject crafted
  states and still exercise the real `_compare_state_pairs` logic.
- The FLIRT pipeline (`flirt.py`, `gen_flirt_pat.py`) needs real `.sig`/`.pat`
  files and COFF `.lib` archives; `tests/bin_util.py` now covers the COFF
  parsing side without MSVC, and `tests/test_property_parsers.py` fuzzes the
  round-trip `.obj` extraction helpers (`_extract_string_symbols`,
  `_extract_local_labels`) against valid and malformed objects.

## Validation commands

Prerequisites (nasm, bun, cc/pkg-config/json-c, the sibling `../resembl` at
tag `v5.4.0` and the rest) and what each gate does without them are in
[CONTRIBUTING.md](../CONTRIBUTING.md#bootstrap-clean-clone); `make doctor`
reports them, and `make help` lists the contributor targets. Notes that live
only here:

```bash
make setup  # installs pre-push hooks for make test and make idempotency-check
make mypy   # checks the modules listed in pyproject.toml
make check  # pre-commit hooks with consistent terminal settings
```

## Performance notes (GA scoring hot loop)

The `score_candidate` profile, the target precomputation contract
(`TestPrecomputedTarget`) and the rejected vectorization experiment are in
[PERFORMANCE.md](PERFORMANCE.md#ga-scoring-hot-loop-score_candidate).
