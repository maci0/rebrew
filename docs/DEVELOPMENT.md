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

1. **Options after positionals break the callback.**  In this codebase's
   `@app.callback(invoke_without_command=True)` pattern, `runner.invoke(app,
   ["0x1000", "--json"])` fails with a typer parse error, while
   `["--json", "0x1000"]` works.  Always pass options **before** positional
   arguments in CLI tests.
2. **`main()` direct calls misbind partial kwargs.**  Prefer
   `CliRunner().invoke(app, [...])` over calling `main(...)` directly.  Worse,
   typer's wrapper **leaks `typer.models.OptionInfo` as the value of omitted
   params** on direct Python calls — an `OptionInfo` is truthy and not a
   `Path`, so `if x is not None:` and `Path(x)` misbehave.  This caused two
   real bugs (a truthy `--sweep-toolchain` leaking into `match`'s watch
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

- `rebrew-function.toml` keys are quoted strings: `["SERVER.0x01006364"]`.
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
  --fix-source`, which created a stray rebrew-function.toml next to the
  header).  Same trap in `match._parse_annotations` — pass cfg.metadata_dir
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

## Toolchain-dependent tests

- `match.py`/`test.py`/`matcher/compiler.py` need the MSVC toolchain docker
  image — covered with stubs at the pure-helper level only.
- `prove.py` needs `angr` (the `prove` extra).  `uv sync --all-extras` (the
  documented dev install) enables the full prove test classes for real
  (62 tests, previously skipped when angr was absent).  The module-level
  `_run_simulation` is patchable so tests can inject crafted states and still
  exercise the real `_compare_state_pairs` logic.
- The FLIRT pipeline (`flirt.py`, `gen_flirt_pat.py`) needs real `.sig`/`.pat`
  files and COFF `.lib` archives; `tests/bin_util.py` now covers the COFF
  parsing side without MSVC, and `tests/test_property_parsers.py` fuzzes the
  round-trip `.obj` extraction helpers (`_extract_string_symbols`,
  `_extract_local_labels`) against valid and malformed objects.

## Validation commands

```bash
make setup                              # frozen lock + pre-commit install
uv run pytest tests/ -q                 # full suite
uv run ruff check src/ tests/ tools/    # lint
uv run ruff format --check src/ tests/ tools/
uv run mypy src/rebrew/                 # type check (0 issues expected)
uv run pre-commit run --all-files       # all 15 hooks
make build                              # sdist+wheel (deterministic wheels)
uv run python -m slipcover -m pytest tests/ -q   # coverage (summary line)
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
`match.py` and `matcher/compiler.py`); per-candidate cost is dominated by
the unavoidable candidate disassembly.  A numpy fancy-indexing prototype
for `_normalize_with_reloc_offsets` measured **slower** (0.7×) than the
existing slice-assignment loop — do not "vectorize" it.  The `_pre_*`
contract is locked by `TestPrecomputedTarget` in tests/test_scoring.py.
