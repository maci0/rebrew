# GA Matcher Improvements for Model Training

This document outlines improvements to the GA matcher for training a machine learning model to guide mutations.

## Current State

We have a unified GA matcher powered by the modular `matcher` package:

1. **`src/rebrew/match.py`** - Unified entry point (delegates to PyGAD-based engine)
2. **`src/rebrew/matcher/`** - Modular package containing core, compiler, scoring, parsers, and mutator logic.

Mutation logic is now fully modularized in `rebrew.matcher.mutator`, supporting both regex-based and AST-aware (via `pycparser`) transformations.

The engine supports:
- Training data collection (`--training-output` flag)
- Mutation tracking with success rates
- Checkpoint/resume
- Stagnation detection and adaptive mutation
- Multiple target modes (--target-bin, --target-obj, --target-lib, --target-exe)
- Flag sweep (--flag-sweep, --flag-sweep-only)
- Diff output (--diff, --diff-only)
- Verbosity control (-v, --quiet)
- RNG seed for reproducibility
- SQLite-backed persistent caching of compilation results

## Completed Improvements

### 1. Training Data Collection (DONE)

**Status**: Fixed in the unified matcher engine.

The `TrainingDataLogger` tracks all mutations with:
- Generation number
- Mutation type
- Parent/child source hashes
- Parent/child scores
- Score delta
- Improved flag (bool)
- Timestamp

**Usage**:
```bash
rebrew-match \
  --cl "wine /path/to/CL.EXE" \
  --inc "/path/to/Include" \
  --cflags "/nologo /c /O2 /MT /Gd" \
  --target-exe original/Server/server.dll \
  --target-va 0x10003da0 --target-size 160 \
  --symbol "_alloc_game_object" \
  --seed-c src/server_dll/alloc_game_object.c \
  --training-output output/run/training.jsonl
```

### 2. Model Training Script (DONE)

**Status**: Created `tools/train_mutation_model.py`

Analyzes training data and generates:
- Mutation success rates per type
- Weighted mutation selection probabilities
- Summary statistics

**Usage**:
```bash
uv run python tools/train_mutation_model.py output/run/training.jsonl --output model.pkl
```

### 3. Model Inference (DONE)

**Status**: The unified matcher supports the `--load-model` flag.

The trained model pickle file contains `mutation_weights` dict mapping mutation names to success probabilities. The GA uses these weights to bias mutation selection in `matcher.mutator`.

**Usage**:
```bash
rebrew-match \
  --load-model model.pkl \
  ...other args...
```

### 4. Training Data Format

JSONL format with fields:
- `generation`: int
- `mutation_type`: str (e.g., "commute_simple_add")
- `parent_hash`: str (SHA256[:16])
- `child_hash`: str (SHA256[:16])
- `parent_score`: float
- `child_score`: float
- `score_delta`: float (child - parent, negative = improvement)
- `improved`: bool
- `parent_source`: str
- `child_source`: str
- `timestamp`: float

## Matcher Features

The unified engine provides:

| Feature | Flag | Description |
|---------|------|-------------|
| Stagnation limit | `--stagnation-limit N` | Early stop after N gens without improvement |
| Adaptive mutation | `--adaptive-mutation` | Increase mutation rate when stagnant |
| Checkpoint | `--checkpoint PATH` | Save/load GA state |
| Resume | `--resume` | Continue from checkpoint |
| Flag sweep | `--flag-sweep` | Find optimal compiler flags |
| Diff only | `--diff-only FILE` | Compare single file, no GA |
| Verbosity | `-v` / `--quiet` | Control output level |
| RNG seed | `--rng-seed N` | Reproducible runs |
| SQLite Cache | (automatic) | Persistent caching in `build_cache.db` |

## Remaining Work

### Phase 4: Continuous Learning (NOT STARTED)

1. Add online learning during GA runs
2. Periodically retrain model with new data
3. Create feedback loop
