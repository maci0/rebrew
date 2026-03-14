# ML Training: Binary-Source Pair Collection & Model Training

This guide covers generating a large-scale dataset of (C source, compiled binary) pairs
using the rebrew GA engine, then training an ML model to predict source transformations
that produce target binaries.

---

## Part 1: Generating a Dataset

### Prerequisites

- One or more rebrew projects configured with `rebrew-project.toml`
- MSVC6 toolchain accessible via Wine/wibo
- Sufficient disk space (a 100k-pair dataset ≈ 2-5 GB of JSONL)

### Collecting Pairs from a Single Function

```bash
rebrew match func.c --collect-pairs training_data.jsonl
```

Every successful compile during the GA run appends a JSONL record:

```json
{
  "source": "void func() { ... }",
  "compiled_bytes": "558bec...",
  "target_bytes": "558bec...",
  "score": 1234.5,
  "cflags": "/O1 /Gs",
  "symbol": "_FuncName@8"
}
```

### Batch Collection Across All Functions

Use `--all` with `--collect-pairs` to sweep every function in a project:

```bash
rebrew match --all --collect-pairs project_pairs.jsonl \
    --generations 50 --pop-size 64
```

### Sourcing Code for Large-Scale Datasets

To train a highly capable model, you need hundreds of thousands or millions of functions. Relying solely on manual decompilation projects is too slow. Here are strategies to source that volume of C code:

#### 1. Scraping decomp.me
Decomp.me hosts thousands of community-matched functions, many specifically targeting MSVC6, GCC, and MWCC for old games.
- **API Access**: Use the decomp.me APIs to fetch completed or near-completed scratches.
- **Filtering**: Filter by compiler (e.g., `msvc6.0`, `msvc6.0sp5`).
- **Data format**: Extract the C source code, target assembly, and exact compiler flags.
- **Integration**: Create an automated script that feeds the scraped C source into your local rebrew pipeline. Compile the source locally with the scraped flags to verify the target binary, then use this as ground truth for GA collection.

#### 2. Historical Open-Source Repositories
Since rebrew focuses on MSVC6/Win32, modern C11/C99 code might not compile or represent the target distribution well.
- **Search Criteria**: Search GitHub for C/C++ repositories created or last significantly updated between 1998–2005.
- **Notable Targets**: Open-sourced game engines (Quake, Doom, Half-Life SDKs), old Windows utilities, and libraries (zlib, early SQLite).
- **Process**: Auto-generate a dummy `rebrew-project.toml` that attempts to compile every `.c` function in the repo with standard MSVC6 flags (`/O1`, `/O2`, `/Gz`). Any function that compiles successfully becomes a ground-truth target.

#### 3. Synthetic Code Generation
Use a modern LLM (like Claude 3.5 Sonnet or GPT-4o) to generate massive amounts of synthetic, MSVC6-compatible C code.
- **Prompting**: "Write a random C function that performs [math operations / array sorting / state machine logic]. Use only C89 features compatible with MSVC6. Do not use standard library includes; use only pointers, structs, and basic types."
- **Verification**: If the generated code compiles with MSVC6, it enters the dataset.

#### 4. Existing Decompilation Datasets
Leverage large datasets from other decompilation research:
- **AnghaBench**: ~1 million compilable C functions mined from GitHub.
- **LLM4Decompile Dataset**: Millions of compiled C functions.
- **Recompilation**: You must recompile these datasets using your specific MSVC6 toolchain via wibo/Wine to get the exact bytes and AST patterns expected by your model.

### Bootstrapping the GA Dataset from Sourced Code

Once you have raw C source code from the above methods, how do you turn it into a dataset of *mutations* and *binary pairs*?

1. **Compile Ground Truth**: Compile the sourced C function with MSVC6 to generate the `target_bytes`. This is your perfect match.
2. **Create a Starting Point**: You need an imperfect starting point for the GA to optimize. You can either:
   - Pass the compiled binary through Ghidra/IDA to generate raw pseudo-code (highly realistic).
   - Or apply random "destructive" mutations to the original source (e.g., change `for` to `while`, alter types, flatten structs).
3. **Run the GA**: Feed the imperfect source and the `target_bytes` into the rebrew GA engine with `--collect-pairs`.
   - The GA will explore the mutation space, attempting to reconstruct the binary.
   - Every compile attempt (both good and bad) is recorded, creating a rich dataset of how specific source transformations affect the compiled output and match score.

### Multi-Project Aggregation

To build a truly large dataset, run collection across multiple rebrew projects
and concatenate the results:

```bash
#!/bin/bash
# collect_all.sh — run from a directory containing multiple rebrew project dirs

OUTDIR="$(pwd)/ml_dataset"
mkdir -p "$OUTDIR"

for project_dir in project-a/ project-b/ project-c/; do
    name=$(basename "$project_dir")
    echo "=== Collecting from $name ==="
    cd "$project_dir"
    rebrew match --all \
        --collect-pairs "$OUTDIR/${name}_pairs.jsonl" \
        --generations 50 \
        --pop-size 64 \
        --timeout-min 10
    cd ..
done

# Merge all JSONL files
cat "$OUTDIR"/*_pairs.jsonl > "$OUTDIR/all_pairs.jsonl"

echo "Total records: $(wc -l < "$OUTDIR/all_pairs.jsonl")"
```

### Dataset Statistics

After collection, inspect the dataset:

```python
import json
from collections import Counter

scores = []
sizes = []
with open("all_pairs.jsonl") as f:
    for line in f:
        rec = json.loads(line)
        scores.append(rec["score"])
        sizes.append(len(rec["compiled_bytes"]) // 2)  # hex -> bytes

print(f"Total pairs:    {len(scores):,}")
print(f"Score range:    {min(scores):.1f} – {max(scores):.1f}")
print(f"Exact matches:  {sum(1 for s in scores if s < 0.1):,}")
print(f"Avg code size:  {sum(sizes)/len(sizes):.0f} bytes")
```

### Recommended Dataset Scale

| Target | Pairs | Projects | Estimated Time |
|---|---|---|---|
| Proof of concept | 10k | 1 | ~2 hours |
| Useful model | 100k–500k | 3–5 | ~1–3 days |
| Production-grade | 1M+ | 10+ | ~1 week |

---

## Part 2: Data Preprocessing

### Tokenizing Source Code

C source needs tokenization. Use a simple byte-pair encoding or character-level
tokenizer. For decompilation tasks, character-level often works well since MSVC6
codegen is sensitive to individual characters (`short` vs `int`).

```python
# preprocess.py — Load JSONL and prepare tensors

import json
import numpy as np

MAX_SRC_LEN = 4096   # characters
MAX_BIN_LEN = 2048   # bytes

def load_pairs(path: str, max_records: int = 0):
    """Load JSONL pairs, returning (sources, binaries, scores)."""
    sources, binaries, scores = [], [], []
    with open(path) as f:
        for i, line in enumerate(f):
            if max_records and i >= max_records:
                break
            rec = json.loads(line)
            sources.append(rec["source"])
            binaries.append(bytes.fromhex(rec["compiled_bytes"]))
            scores.append(rec["score"])
    return sources, binaries, scores

def encode_source(src: str, max_len: int = MAX_SRC_LEN) -> np.ndarray:
    """Character-level encoding, zero-padded."""
    encoded = [ord(c) for c in src[:max_len]]
    padded = encoded + [0] * (max_len - len(encoded))
    return np.array(padded, dtype=np.uint16)

def encode_binary(data: bytes, max_len: int = MAX_BIN_LEN) -> np.ndarray:
    """Raw byte encoding, zero-padded."""
    trimmed = data[:max_len]
    padded = list(trimmed) + [0] * (max_len - len(trimmed))
    return np.array(padded, dtype=np.uint8)

def prepare_dataset(jsonl_path: str, max_records: int = 0):
    """Return (src_array, bin_array, score_array) ready for training."""
    sources, binaries, scores = load_pairs(jsonl_path, max_records)

    src_arr = np.stack([encode_source(s) for s in sources])
    bin_arr = np.stack([encode_binary(b) for b in binaries])
    score_arr = np.array(scores, dtype=np.float32)

    return src_arr, bin_arr, score_arr
```

---

## Part 3: Training the Model

### Stack Choice

| Component | Tool | Why |
|---|---|---|
| Framework | **Keras 3** (with JAX backend) | Backend-agnostic, runs on CUDA + ROCm |
| GPU (NVIDIA) | `pip install jax[cuda12]` | CUDA 12 support via JAX |
| GPU (AMD) | `pip install jax[rocm]` | ROCm 6.x support via JAX |
| Serialization | HDF5 / SafeTensors | Model checkpointing |

> **Why Keras 3 + JAX?** Keras 3 is backend-agnostic — the same code runs on
> TensorFlow, JAX, or PyTorch backends. JAX has first-class ROCm support,
> making it the cleanest path to AMD GPU training without code changes.

### Environment Setup

```bash
# Create a fresh venv for training
python -m venv ml-env
source ml-env/bin/activate

# Core dependencies
pip install keras jax numpy h5py

# GPU backend — pick ONE:
pip install jax[cuda12]   # NVIDIA (CUDA 12)
pip install jax[rocm]     # AMD (ROCm 6.x)

# Verify GPU is visible
python -c "import jax; print(jax.devices())"
```

Set the Keras backend before importing:

```bash
export KERAS_BACKEND=jax
```

### Model Architecture

Two practical architectures for this task:

#### Architecture A: Score Predictor

Predicts how well a source variant will match a target binary — used to
guide the GA or prioritize mutations.

```python
# train_score_predictor.py

import os
os.environ["KERAS_BACKEND"] = "jax"

import keras
from keras import layers
import numpy as np
from preprocess import prepare_dataset

# --- Load data ---
src_data, bin_data, scores = prepare_dataset("all_pairs.jsonl")

# Normalize scores to [0, 1] range for regression
max_score = scores.max()
norm_scores = scores / max_score

# Train/val split (90/10)
n = len(scores)
idx = np.random.permutation(n)
split = int(n * 0.9)
train_idx, val_idx = idx[:split], idx[split:]

# --- Source encoder ---
src_input = keras.Input(shape=(4096,), dtype="int32", name="source")
src_emb = layers.Embedding(input_dim=256, output_dim=64)(src_input)
src_enc = layers.Conv1D(128, 5, activation="relu", padding="same")(src_emb)
src_enc = layers.Conv1D(128, 5, activation="relu", padding="same")(src_enc)
src_enc = layers.GlobalAveragePooling1D()(src_enc)

# --- Binary encoder ---
bin_input = keras.Input(shape=(2048,), dtype="int32", name="binary")
bin_emb = layers.Embedding(input_dim=256, output_dim=64)(bin_input)
bin_enc = layers.Conv1D(128, 5, activation="relu", padding="same")(bin_emb)
bin_enc = layers.Conv1D(128, 5, activation="relu", padding="same")(bin_enc)
bin_enc = layers.GlobalAveragePooling1D()(bin_enc)

# --- Merge and predict ---
merged = layers.Concatenate()([src_enc, bin_enc])
x = layers.Dense(256, activation="relu")(merged)
x = layers.Dropout(0.3)(x)
x = layers.Dense(128, activation="relu")(x)
x = layers.Dropout(0.2)(x)
output = layers.Dense(1, activation="sigmoid", name="score")(x)

model = keras.Model(inputs=[src_input, bin_input], outputs=output)
model.compile(
    optimizer=keras.optimizers.Adam(learning_rate=1e-3),
    loss="mse",
    metrics=["mae"],
)
model.summary()

# --- Train ---
model.fit(
    [src_data[train_idx].astype("int32"), bin_data[train_idx].astype("int32")],
    norm_scores[train_idx],
    validation_data=(
        [src_data[val_idx], bin_data[val_idx].astype("int32")],
        norm_scores[val_idx],
    ),
    epochs=50,
    batch_size=64,
    callbacks=[
        keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True),
        keras.callbacks.ModelCheckpoint("score_model.keras", save_best_only=True),
    ],
)

# --- Evaluate ---
val_loss, val_mae = model.evaluate(
    [src_data[val_idx], bin_data[val_idx].astype("int32")],
    norm_scores[val_idx],
)
print(f"Validation MAE: {val_mae:.4f} (in normalized score units)")
```

#### Architecture B: Mutation Classifier

Given a (source, target_binary) pair, predict which mutation category is most
likely to improve the match. This turns GA exploration into guided search.

```python
# train_mutation_classifier.py
# Requires augmented JSONL with a "mutation" field (added by a modified GA)

import os
os.environ["KERAS_BACKEND"] = "jax"

import keras
from keras import layers

NUM_MUTATIONS = 121  # len(ALL_MUTATIONS)

src_input = keras.Input(shape=(4096,), dtype="int32", name="source")
bin_input = keras.Input(shape=(2048,), dtype="int32", name="target")

# Shared encoder
src_emb = layers.Embedding(256, 64)(src_input)
src_enc = layers.Bidirectional(layers.LSTM(128))(src_emb)

bin_emb = layers.Embedding(256, 64)(bin_input)
bin_enc = layers.Bidirectional(layers.LSTM(128))(bin_emb)

merged = layers.Concatenate()([src_enc, bin_enc])
x = layers.Dense(256, activation="relu")(merged)
x = layers.Dropout(0.3)(x)
output = layers.Dense(NUM_MUTATIONS, activation="softmax", name="mutation")(x)

model = keras.Model(inputs=[src_input, bin_input], outputs=output)
model.compile(
    optimizer="adam",
    loss="sparse_categorical_crossentropy",
    metrics=["accuracy"],
)
```

### Training Tips

1. **Start small**: Train on 10k pairs first to validate the pipeline works
2. **Filter by score**: For the score predictor, include the full range; for
   the mutation classifier, focus on pairs where score improved
3. **Batch size**: Start with 64, increase to 256+ on GPUs with >8GB VRAM
4. **Mixed precision**: Enable for faster training on modern GPUs:
   ```python
   keras.mixed_precision.set_global_policy("mixed_float16")
   ```
5. **Multi-GPU**: JAX automatically shards across multiple GPUs if available

### ROCm-Specific Notes

```bash
# Verify ROCm installation
rocm-smi

# Set the visible GPU(s)
export HIP_VISIBLE_DEVICES=0

# JAX ROCm requires amdgpu driver + ROCm 6.x
# Install: https://rocm.docs.amd.com/projects/install-on-linux/
pip install jax[rocm]

# Verify
python -c "import jax; print(jax.devices())"
# Should show: [RocmDevice(id=0)]
```

### CUDA-Specific Notes

```bash
# Verify CUDA installation
nvidia-smi

# Set the visible GPU(s)
export CUDA_VISIBLE_DEVICES=0

pip install jax[cuda12]

# Verify
python -c "import jax; print(jax.devices())"
# Should show: [CudaDevice(id=0)]
```

---

## Part 4: Using the Trained Model

### Score Predictor → GA Integration

The score predictor can pre-filter mutations before expensive compilation:

```python
# In the GA loop, before compiling a candidate:
predicted_score = model.predict([encode_source(candidate), encode_binary(target)])
if predicted_score > THRESHOLD:
    # Skip this candidate — predicted to be poor
    continue
# Otherwise, compile and evaluate normally
```

### Mutation Classifier → Guided GA

Replace random mutation selection with model-guided selection:

```python
# Instead of: mutation = rng.choice(ALL_MUTATIONS)
probs = model.predict([encode_source(current_src), encode_binary(target)])
top_k_indices = np.argsort(probs[0])[-5:]  # top 5 predicted mutations
mutation = ALL_MUTATIONS[rng.choice(top_k_indices)]
```

---

## Part 5: Data Quality & Iteration

### Enriching the Dataset

For better mutation classifier training, extend the JSONL format to include
which mutation was applied. This requires a small change to `match.py` to
log the mutation name alongside each pair.

### Enriched JSONL Format

Capture richer metadata per pair for advanced training strategies:

```json
{
  "source": "void func() { ... }",
  "compiled_bytes": "558bec...",
  "target_bytes": "558bec...",
  "score": 1234.5,
  "cflags": "/O1 /Gs",
  "symbol": "_FuncName@8",
  "mutation": "mut_swap_int_short",
  "parent_source": "void func() { ... original ... }",
  "parent_score": 2500.0,
  "improvement": 1265.5,
  "generation": 17
}
```

The `mutation`, `parent_source`, and `improvement` fields enable training models
that predict _which mutation to apply_ given the current state, not just the
final source-binary relationship.

### Curriculum Learning

1. **Phase 1**: Train on all pairs (learn general source-binary relationships)
2. **Phase 2**: Fine-tune on near-miss pairs (score < 5000) to learn the
   subtle transformations that matter for exact matching
3. **Phase 3**: Fine-tune specifically on exact matches (score ≈ 0) to learn
   what "correct" looks like

### Monitoring & Metrics

| Metric | Target | Meaning |
|---|---|---|
| Score predictor MAE | < 0.05 | Can reliably rank candidates |
| Mutation classifier top-5 accuracy | > 50% | Model suggests useful mutations |
| GA convergence speed improvement | > 2× | Model-guided GA finds matches faster |

---

## Part 6: LLM-Based Approach (Skeleton-to-Skin)

_Inspired by [SK²Decompile](https://github.com/albertan017/LLM4Decompile/tree/main/sk2decompile)
(arXiv:2509.22114). Adapted for MSVC6/Win32 binary matching._

Instead of small CNN/LSTM models (Parts 3-4), fine-tune a pretrained LLM to
directly generate source code from decompiler output.

### One Model vs Two?

SK²Decompile uses two separate models: Skeleton (pseudo → normalized IR with
placeholders) and Skin (normalized IR → readable source with real names).
Rebrew has two goals that map to these phases:

1. **Byte-exact match** — structure, types, calling conventions (Skeleton)
2. **Readable source** — meaningful names, clear intent (Skin)

Variable names don't affect MSVC6 codegen, so naming is irrelevant for byte
matching. But the reversed source still needs to be maintainable by humans —
nobody wants to ship matched code full of `var1` and `func2`.

**Recommended: single model to start, consider adding Phase 2 for readability.**

#### Option A: Single Model (simpler, faster iteration)

One model that produces readable, byte-matching source end-to-end. Works
well when symbol names are already known from Ghidra/IDA — the model sees
real names in the pseudo-code input and learns to preserve them.

```
Ghidra pseudo-code → [normalize_pseudo()] → [Single LLM] → Readable MSVC6 C source
```

Pros:
- Half the inference cost in the GA loop (one model call, not two)
- End-to-end RL with `compile_and_compare` as reward — no proxy metrics
- Simpler training pipeline (one dataset, one model, one fine-tune)
- Works well when names are available from symbols/Ghidra

Cons:
- The model must learn structure AND naming simultaneously — harder task
- RL reward (byte matching) doesn't incentivize good naming, only structure
- May produce structurally correct but poorly named output

#### Option B: Two Models (SK²Decompile approach, better readability)

Phase 1 focuses purely on structure (with placeholder names), Phase 2
focuses on identifier naming and readability. Each is independently
optimized with tailored rewards.

```
Ghidra pseudo → [Model 1: Skeleton] → Normalized IR → [Model 2: Skin] → Readable C source
                 (structure-focused)                    (naming-focused)
```

Pros:
- Each model has a simpler, more focused task
- Phase 1 uses byte-match RL reward; Phase 2 uses embedding similarity
- Better naming quality — Phase 2 is specifically optimized for readability
- Useful when symbols are stripped and names must be inferred from context

Cons:
- 2× inference cost per candidate in the GA loop
- Phase 1 can't directly optimize for byte matching (placeholder names
  compile differently than real typed names)
- More complex training pipeline (two datasets, two models, two fine-tunes)

#### When to Use Which

| Scenario | Choice | Rationale |
|---|---|---|
| Symbols available from Ghidra/IDA | Single model | Names are known, just need structure |
| Stripped binary, names unknown | Two models | Phase 2 infers meaningful names |
| GA loop integration (speed matters) | Single model | Half the inference cost |
| Standalone decompilation tool | Two models | Readability is the primary output |
| Limited VRAM / compute | Single model | Only one model to train and serve |

For most rebrew projects — where you have Ghidra exports with function names
and the GA engine needs fast inference — **start with a single model**. Add
Phase 2 later if naming quality becomes a bottleneck.

### Source Normalization via tree-sitter

Source normalization to placeholders is valuable as **training-time data
augmentation** — it forces the model to learn structural patterns (`short`
vs `int`, loop structure, cast placement) rather than memorizing identifier
correlations. Include both normalized and real-named variants in the training
set.

Rebrew already uses tree-sitter (`c_parser.py`). Leverage it to normalize
source code into placeholder form for training data:

```python
# normalize_source.py — Generate normalized IR from C source using tree-sitter

from tree_sitter import Language, Parser
import tree_sitter_c as tsc

C_LANG = Language(tsc.language())
parser = Parser(C_LANG)

def normalize_source(source: str) -> tuple[str, dict[str, str]]:
    """Replace identifiers with generic placeholders.

    Returns (normalized_source, mapping) where mapping can reverse
    the transformation.
    """
    tree = parser.parse(source.encode("utf8"))
    counters = {"func": 0, "var": 0, "type": 0, "field": 0}
    mapping: dict[str, str] = {}
    reverse_mapping: dict[str, str] = {}

    def classify_and_rename(node) -> str | None:
        name = node.text.decode("utf8")
        if name in mapping:
            return mapping[name]

        parent = node.parent
        if node.type == "type_identifier":
            kind = "type"
        elif node.type == "field_identifier":
            kind = "field"
        elif node.type == "identifier" and parent:
            if parent.type == "function_declarator":
                kind = "func"
            elif parent.type == "call_expression":
                kind = "func"
            else:
                kind = "var"
        else:
            return None

        counters[kind] += 1
        placeholder = f"{kind}{counters[kind]}"
        mapping[name] = placeholder
        reverse_mapping[placeholder] = name
        return placeholder

    # Walk AST and build replacement map
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type in ("identifier", "type_identifier", "field_identifier"):
            classify_and_rename(node)
        stack.extend(reversed(node.children))

    # Apply replacements to source text using word-boundary regex
    # (simple str.replace would corrupt e.g. 'var1' inside 'var10')
    normalized = source
    for original, placeholder in sorted(mapping.items(), key=lambda x: -len(x[0])):
        normalized = re.sub(rf'\b{re.escape(original)}\b', placeholder, normalized)

    return normalized, reverse_mapping
```

### Pseudo-Code Normalization

When using Ghidra/IDA decompiler output as input, normalize it before feeding
to the model. Key transformations (adapted from SK²Decompile):

1. **Hex to decimal**: `0x1A` → `26` (MSVC6 codegen uses decimal in most contexts)
2. **Strip calling convention noise**: Remove redundant `__cdecl` on non-exported functions
3. **Replace IDA typedefs**: `_DWORD` → `unsigned int`, `_BYTE` → `unsigned char`, etc.
4. **Remove decompiler comments**: Strip `/**/` and `//` artifacts
5. **clang-format**: Normalize whitespace for consistent tokenization

```python
# normalize_pseudo.py — Clean up decompiler output for model input

import re
import subprocess

# IDA/Ghidra typedef → MSVC6 C type
TYPEDEF_MAP = {
    "_DWORD": "unsigned int",
    "_WORD": "unsigned short",
    "_BYTE": "unsigned char",
    "_QWORD": "unsigned __int64",
    "_BOOL4": "int",
    "_BOOL1": "char",
    "BOOL": "int",
    "LPVOID": "void *",
    "DWORD": "unsigned long",
    "WORD": "unsigned short",
    "BYTE": "unsigned char",
    "LONG": "long",
    "UINT": "unsigned int",
    # NOTE: These typedefs are normalized in the *pseudo-code input* only.
    # The model's *output* should preserve Win32 typedefs (BOOL, DWORD, etc.)
    # when that's what MSVC6 expects — they affect codegen (e.g. BOOL is int,
    # but DWORD is unsigned long, which changes sign-extension behavior).
    "size_t": "unsigned int",
}

def normalize_pseudo(code: str) -> str:
    # Remove comments
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)

    # Hex literals to decimal
    code = re.compile(r'\b(0x[0-9a-fA-F]+)([uUlL]{0,3})\b').sub(
        lambda m: str(int(m.group(1), 16)) + m.group(2), code
    )

    # Replace typedefs
    for alias, real_type in TYPEDEF_MAP.items():
        code = re.sub(rf'\b{re.escape(alias)}\b', real_type, code)

    # Format with clang-format for consistent whitespace
    try:
        proc = subprocess.run(
            ["clang-format", "--style=Google"],
            input=code, text=True, capture_output=True, timeout=2,
        )
        if proc.returncode == 0:
            code = proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return code.strip()
```

### Training Data Format for LLM Fine-Tuning

Structure training data as instruction-following JSONL, compatible with
LLaMA-Factory or any SFT framework. The single model is trained on
normalized pseudo-code → matching C source:

```json
{
  "instruction": "",
  "input": "# This is the pseudo code:\nvoid __stdcall func1(int var1, int var2) {\n  var2 = func2(var1 + 4);\n  if (var2) {\n    *(type1 *)(var1 + 8) = var2;\n  }\n}\n# What is the source code?\n",
  "output": "void __stdcall CEntity_SetPosition(CEntity *this, int x, int y) {\n  int result = ValidateCoord(this->x + x);\n  if (result) {\n    this->position = result;\n  }\n}",
  "system": ""
}
```

The input is normalized pseudo-code (placeholders for identifiers), and the
output is the real MSVC6-matching source. This teaches the model to recover
both structure and naming in a single pass.

For **data augmentation**, also include normalized-output variants to reinforce
structural learning:

```json
{
  "instruction": "",
  "input": "# This is the pseudo code:\nvoid __stdcall func1(int var1, int var2) {\n  ...\n}\n# What is the source code?\n",
  "output": "void __stdcall func1(type1 *var1, int var2, int var3) {\n  int var4 = func2(var1->field1 + var2);\n  if (var4) {\n    var1->field2 = var4;\n  }\n}",
  "system": ""
}
```

### Generating LLM Training Pairs from Rebrew Data

```python
# make_llm_pairs.py — Convert rebrew JSONL → single-model SFT format

import json
from normalize_source import normalize_source
from normalize_pseudo import normalize_pseudo

def convert_to_sft_pairs(input_jsonl: str, output_jsonl: str):
    with open(input_jsonl) as fin, open(output_jsonl, "w") as fout:
        for line in fin:
            rec = json.loads(line)
            source = rec["source"]
            # Only use good matches (score < 1000) for SFT training
            if rec["score"] > 1000:
                continue

            # Normalize the pseudo-code input (strip noise, hex→dec, typedefs)
            pseudo = normalize_pseudo(source)
            normalized_pseudo, _ = normalize_source(pseudo)

            # Primary pair: normalized pseudo → real source
            pair = {
                "instruction": "",
                "input": f"# This is the pseudo code:\n{normalized_pseudo}\n# What is the source code?\n",
                "output": source,
                "system": "",
            }
            fout.write(json.dumps(pair) + "\n")

            # Augmentation: normalized pseudo → normalized source
            # (teaches structural patterns independent of naming)
            normalized_source, _ = normalize_source(source)
            aug = {
                "instruction": "",
                "input": f"# This is the pseudo code:\n{normalized_pseudo}\n# What is the source code?\n",
                "output": normalized_source,
                "system": "",
            }
            fout.write(json.dumps(aug) + "\n")
```

### SFT Training Configuration

Fine-tune a base model (e.g., `LLM4Binary/llm4decompile-6.7b-v2` or a smaller
1.5B model for faster iteration) using LLaMA-Factory:

```yaml
# sft_config.yaml — LLaMA-Factory training config for rebrew

model_name_or_path: LLM4Binary/llm4decompile-6.7b-v2
trust_remote_code: true

stage: sft
do_train: true
finetuning_type: full
deepspeed: examples/deepspeed/ds_z2_config.json

dataset: rebrew_sft
template: sk2decompile
cutoff_len: 2048
overwrite_cache: true
preprocessing_num_workers: 16

output_dir: saves/rebrew-skeleton
logging_steps: 10
save_steps: 500
plot_loss: true
overwrite_output_dir: true

per_device_train_batch_size: 8
gradient_accumulation_steps: 8
learning_rate: 3.0e-6
num_train_epochs: 2.0
lr_scheduler_type: cosine_with_min_lr
lr_scheduler_kwargs: {"min_lr": 3.0e-7}
warmup_ratio: 0.02
bf16: true
```

### Base Model Selection & Evaluation

#### Qwen3 Small Models for Decompilation

The Qwen3 family (April 2025) offers compelling small models for this use case.
Each Qwen3 model matches the performance of a Qwen2.5 model roughly 2× its
size — Qwen3-4B ≈ Qwen2.5-7B, Qwen3-1.7B ≈ Qwen2.5-3B.

| Model | Params | EvalPlus | MultiPL-E | VRAM (QLoRA) | Verdict |
|---|---|---|---|---|---|
| Qwen3-0.6B | 0.6B | 36.2 | 24.6 | ~4 GB | Skip — too weak at C codegen |
| Qwen3-1.7B | 1.7B | 52.7 | 42.7 | ~6 GB | Marginal — needs heavy fine-tuning |
| **Qwen3-4B** | **4B** | **63.5** | **53.1** | **~10 GB** | **Sweet spot for rebrew** |
| Qwen3-8B | 8B | 67.7 | 58.8 | ~20 GB | Best quality if VRAM allows |

**Why Qwen3-0.6B is too small**: At 36% EvalPlus, the model struggles to
produce syntactically correct C. LLM4Decompile research showed 1.3B models
achieve only ~10% re-executability vs ~21% for 6B models. A 0.6B model would
be worse. Domain-specific fine-tuning can't compensate for fundamentally weak
code generation ability.

**Why Qwen3-1.7B is borderline**: 52.7% EvalPlus means roughly half the
generated code has issues. Could work if VRAM is severely limited (<8GB) and
training data is large (100k+ pairs), but expect lower match rates. The model
understands C syntax but frequently gets types and control flow wrong.

**Why Qwen3-4B is the sweet spot**: 63.5% EvalPlus is in the range where
the model reliably generates correct C structures. This is the same capability
tier as Qwen2.5-7B, which is proven for code tasks. Fine-tunable with QLoRA
on a single 10-16GB GPU (RTX 3060/4060). MSVC6 codegen is a narrow domain —
the model doesn't need to be a generalist, it just needs enough base coding
ability to learn the pattern. 4B provides that.

**Qwen3-8B for best results**: If you have a 24GB GPU (RTX 3090/4090, A5000),
the 8B model provides a meaningful quality boost. 128K native context (vs 32K
for 4B) also helps with longer functions, though most MSVC6 functions fit in
2K tokens.

#### Code-Specialized Alternatives

| Model | Params | Notes |
|---|---|---|
| `LLM4Binary/llm4decompile-6.7b-v2` | 6.7B | Pretrained on decompilation, best domain fit |
| `Qwen/Qwen3-Coder-30B-A3B` | 30B (3B active) | MoE — only 3B params active per token |
| `Qwen/Qwen2.5-Coder-3B` | 3B | Code-specific pretraining, proven for fine-tuning |

**`llm4decompile-6.7b-v2`** remains the best starting point when you have
the VRAM (~24GB for QLoRA). It already understands decompiler pseudo-code →
source code mapping. Fine-tuning only needs to teach MSVC6/Win32 idioms.

**`Qwen3-Coder-30B-A3B`** (MoE) is interesting: 30B total params but only
3B active per forward pass, so inference cost is similar to a 3B dense model.
Trained with RL on executable coding tasks. However, MoE fine-tuning is less
mature tooling-wise, and the model is optimized for agentic coding (SWE-Bench)
rather than decompilation.

#### Qwen3.5 Small Models (March 2026)

Qwen3.5 introduced a small model series (0.8B, 2B, 4B, 9B) under Apache 2.0.
All models are natively multimodal (text + image + video) and use a hybrid
**Gated DeltaNet + Attention** architecture with a 3:1 ratio: every 4 blocks
consist of 3 Gated DeltaNet (linear attention) blocks and 1 full quadratic
attention block. This gives constant memory complexity with sequence length
while preserving reasoning quality from the full attention layers.

**Architecture (Qwen3.5-4B):**

```
Layers: 32 (8 × [3 × GatedDeltaNet + 1 × GatedAttention])
Hidden dim: 2560
DeltaNet heads: 32 (V), 16 (QK), head_dim=128
Attention heads: 16 (Q), 4 (KV), head_dim=256
FFN intermediate: 9216
Vocab: 248,320 tokens (201 languages)
Context: 262,144 native, extensible to 1M via YaRN
```

| Model | Params | MMLU-Pro | GPQA-D | LiveCodeBench v6 | OJBench | VRAM (LoRA) | VRAM (inference) |
|---|---|---|---|---|---|---|---|
| Qwen3.5-0.8B | 0.8B | — | — | — | — | ~3 GB | ~1.6 GB |
| Qwen3.5-2B | 2B | — | — | — | — | ~5 GB | ~4 GB |
| **Qwen3.5-4B** | **4B** | **79.1** | **76.2** | **55.8** | **24.1** | **~10 GB** | **~8 GB** |
| Qwen3.5-9B | 9B | 82.5 | 81.7 | 65.6 | 29.2 | ~22 GB | ~18 GB |

**Comparison with Qwen3 at similar sizes:**

| Benchmark | Qwen3-4B | Qwen3.5-4B | Delta |
|---|---|---|---|
| MMLU-Pro | ~63* | 79.1 | +16 |
| GPQA Diamond | ~55* | 76.2 | +21 |
| LiveCodeBench v6 | — | 55.8 | — |
| Intelligence Index | 18 | 27 | +9 |

_*Qwen3-4B base scores estimated from technical report scaling; instruct variants differ._

Qwen3.5-4B represents a generational leap over Qwen3-4B on reasoning and
knowledge benchmarks. The Intelligence Index shows a +50% improvement (18→27).
On coding specifically, LiveCodeBench v6 score of 55.8 is solid for a 4B model.

**Pros for rebrew:**
- **262K native context** — handles any function length, room for few-shot prompts
- **Stronger reasoning** than Qwen3-4B — GPQA Diamond 76.2 vs ~55 suggests
  better ability to reason about code structure and type relationships
- **Text-only mode** works via `--language-model-only` in vLLM, which strips the
  vision encoder and frees VRAM for KV cache
- **Same LoRA targets** as standard transformers — the DeltaNet layers have
  Q/K/V/gate projections that map to `q_proj, k_proj, v_proj, o_proj,
  gate_proj, up_proj, down_proj` (identical to Qwen3)
- **Dense architecture** for small variants (0.8B-9B are all dense, not MoE),
  so fine-tuning is straightforward
- **Knowledge distillation** from 397B teacher model gives the small models
  disproportionately strong capabilities for their size

**Cons for rebrew:**
- **QLoRA not recommended** — Qwen team explicitly warns against 4-bit
  quantized training on Qwen3.5 due to "higher than normal quantization
  differences." Must use bf16 LoRA or full fine-tune, which requires more VRAM
- **Multimodal overhead** — the vision encoder weights are loaded even in
  text-only mode (just not used). This wastes ~15-20% of model size on
  parameters that don't help decompilation
- **Novel architecture** — Gated DeltaNet is newer than standard transformers.
  While LoRA works (same target modules), the ecosystem is less battle-tested.
  Unsloth notes "custom Mamba Triton kernels may cause slower compilation"
- **Requires transformers v5+** — may conflict with other dependencies
- **No code-specific pretraining** — unlike Qwen2.5-Coder or LLM4Decompile,
  Qwen3.5 is a generalist. LiveCodeBench 55.8 is good but not code-specialized

**Verdict**: Qwen3.5-4B is a **strong contender** if you can use bf16 LoRA
(needs ~10GB VRAM). The reasoning improvements over Qwen3-4B are substantial
and may translate to better understanding of type relationships and MSVC6
codegen patterns. However, the QLoRA restriction means you need at least
10GB VRAM — if you only have 8GB and must use 4-bit quantization, stick with
Qwen3-4B instead.

For the 9B variant: at 22GB for LoRA training, it competes with
`llm4decompile-6.7b-v2` for VRAM budget. The 6.7B decompilation model
wins on domain pretraining; Qwen3.5-9B wins on raw reasoning capability.
If starting from scratch (no decompilation pretraining), Qwen3.5-9B is
the stronger base.

#### Recommendation

| VRAM Budget | Best Choice | Why |
|---|---|---|
| 8 GB | Qwen3-4B (4-bit QLoRA) | Smallest model with reliable C codegen; QLoRA works on Qwen3 |
| 10-16 GB | **Qwen3.5-4B (bf16 LoRA)** | Strongest 4B model available; superior reasoning |
| 16 GB | Qwen3.5-4B (bf16 LoRA) or Qwen3-8B (QLoRA) | Qwen3.5-4B if reasoning matters; Qwen3-8B if code breadth matters |
| 24 GB+ | `llm4decompile-6.7b-v2` (QLoRA) or Qwen3.5-9B (LoRA) | Domain pretraining vs raw capability |
| 40 GB+ | `llm4decompile-6.7b-v2` (full fine-tune) | Maximum quality, domain-pretrained |

---

## Part 7: Reinforcement Learning with Compiler Feedback

_The most impactful technique from SK²Decompile for rebrew._

After SFT, use reinforcement learning (GRPO) with rebrew's own compile-and-compare
pipeline as the reward signal. This is more powerful than SK²Decompile's approach
because rebrew can provide _byte-level match scores_, not just "compiles or not."

### Reward Functions

#### Reward A: Structure Recovery (compilability + structural similarity)

```python
# reward_structure.py — Reward for Phase 1 (skeleton) RL training

import os
import re
import subprocess
import tempfile


def compute_score(candidate: str, ground_truth: str, extra_info: dict | None = None) -> float:
    """Reward = compilability (0 or 1) + placeholder Jaccard similarity."""

    # Component 1: Does it compile with MSVC6?
    compile_ok = _msvc6_compiles(candidate, extra_info)
    if not compile_ok:
        return 0.0

    # Component 2: Placeholder set similarity (Jaccard)
    patterns = [r'\bfunc\w*\b', r'\btype\w*\b', r'\bvar\w*\b', r'\bfield\w*\b']
    cand_terms = set()
    gt_terms = set()
    for p in patterns:
        cand_terms.update(re.findall(p, candidate))
        gt_terms.update(re.findall(p, ground_truth))

    if not cand_terms and not gt_terms:
        return 1.0  # both empty = trivially correct

    intersection = len(cand_terms & gt_terms)
    union = len(cand_terms | gt_terms)
    jaccard = intersection / union if union else 0.0

    return 1.0 + jaccard  # range [1.0, 2.0] when compilable


def _msvc6_compiles(source: str, extra_info: dict | None) -> bool:
    """Try to compile source with MSVC6 via Wine/wibo."""
    # This would call rebrew's compile_to_obj() internally
    # Simplified here for illustration
    with tempfile.TemporaryDirectory() as tmpdir:
        src_file = os.path.join(tmpdir, "temp.c")
        header = extra_info.get("header", "") if extra_info else ""
        with open(src_file, "w") as f:
            f.write(f"{header}\n\n{source}")
        try:
            proc = subprocess.run(
                ["wibo", "cl.exe", "/c", "/nologo", src_file],
                capture_output=True, timeout=10,
            )
            return proc.returncode == 0
        except Exception:
            return False
```

#### Reward B: Byte-Level Match Score (rebrew-native)

This is rebrew's unique advantage — use the actual binary diff as a reward:

```python
# reward_match.py — Reward using rebrew's compile_and_compare

from rebrew.compile import compile_and_compare


def compute_score(candidate: str, ground_truth: str, extra_info: dict | None = None) -> float:
    """Reward based on actual byte-level match against target binary.

    Returns a score in [0, 2] where:
    - 0.0 = doesn't compile
    - 0.0-1.0 = compiles but poor match
    - 1.0-2.0 = good match (1.0 + normalized similarity)
    - 2.0 = exact byte match
    """
    cfg = extra_info.get("config") if extra_info else None
    target_bytes = extra_info.get("target_bytes") if extra_info else None
    if not cfg or not target_bytes:
        return 0.0

    result = compile_and_compare(candidate, cfg, target_bytes)
    if not result or result.status == "ERROR":
        return 0.0

    # Normalize: score of 0 = perfect match = reward 2.0
    # score of 10000+ = poor match = reward ~0.0
    max_score = 10000.0
    normalized = max(0.0, 1.0 - (result.delta / max_score))

    return 1.0 + normalized  # [1.0, 2.0] when compilable
```

### GRPO Training Configuration

GRPO (Group Relative Policy Optimization) trains the model by generating
multiple candidates per prompt and using relative reward ranking:

| Parameter | Value | Notes |
|---|---|---|
| `train_batch_size` | 64-128 | Depends on VRAM |
| `max_prompt_length` | 1024 | Pseudo-code input |
| `max_response_length` | 2048 | Generated source |
| `lr` | 1e-6 | Conservative to preserve SFT knowledge |
| `kl_loss_coef` | 0.01 | Prevents reward hacking |
| `rollout.n` | 8-16 | Candidates per prompt for GRPO |
| `total_epochs` | 2 | RL training is quick |

### Why Compiler-as-Reward Works Well for Rebrew

1. **Precise signal**: Rebrew's byte-level scoring gives a continuous,
   fine-grained reward (not just pass/fail compilation)
2. **Ground truth available**: We have exact target bytes for every function,
   so the reward directly measures what we care about
3. **No proxy metrics**: Unlike general decompilation where "correctness" is
   fuzzy, binary matching has an objective ground truth
4. **Cheap to evaluate**: MSVC6 compiles in <1 second per candidate, making
   RL rollouts practical

---

## Part 8: Data Quality & Advanced Techniques

### Identifier Similarity via Embeddings

For Phase 2 (skin/naming), use embedding cosine similarity as a training signal
instead of exact string matching. This rewards semantically reasonable names
even if they don't exactly match the original:

```python
# Extract identifiers from C source using tree-sitter, then compare
# via embedding similarity (see SK²Decompile's embedding_gte.py)

def build_naming_summary(source: str) -> str:
    """Extract classified identifiers and build a summary string."""
    ids = extract_identifiers_ts(source)  # from normalize_source.py
    parts = []
    for kind in ("func", "type", "field", "var"):
        names = ids.get(kind, [])
        if names:
            parts.append(f"{kind}: {' '.join(names[:64])}")
    return " || ".join(parts)

# Then compute: cosine_similarity(embed(summary_candidate), embed(summary_reference))
# Use any embedding model (e.g., GTE, Qwen3-Embedding)
```

### Curriculum Learning

1. **Phase 1**: Train on all pairs (learn general source-binary relationships)
2. **Phase 2**: Fine-tune on near-miss pairs (score < 5000) to learn the
   subtle transformations that matter for exact matching
3. **Phase 3**: Fine-tune specifically on exact matches (score ≈ 0) to learn
   what "correct" looks like

### Monitoring & Metrics

| Metric | Target | Meaning |
|---|---|---|
| Score predictor MAE | < 0.05 | Can reliably rank candidates |
| Mutation classifier top-5 accuracy | > 50% | Model suggests useful mutations |
| GA convergence speed improvement | > 2× | Model-guided GA finds matches faster |
| LLM exact match rate | > 10% | Model produces byte-exact matches directly |
| LLM compilability rate | > 80% | Model output compiles successfully |
| RL reward improvement | > 30% | RL phase improves over SFT baseline |

### Recommended Approach Order

For getting started, work through these approaches in order of complexity:

1. **Score Predictor** (Part 3A) — Easiest. Validates the data pipeline works.
   Small CNN model, trains in hours on a single GPU.

2. **Mutation Classifier** (Part 3B) — Medium. Requires enriched dataset with
   mutation labels. Directly useful for GA guidance.

3. **LLM SFT** (Part 6) — Requires more compute (16GB+ VRAM) but potentially
   the most impactful. Start with a 1.5B model for fast iteration.

4. **RL with Compiler Feedback** (Part 7) — Most advanced. Requires a working
   SFT model first. Rebrew's byte-level scoring makes this uniquely powerful
   compared to generic decompilation approaches.
