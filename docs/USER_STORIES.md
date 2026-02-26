# User Stories & Workflow Diagrams

> [!NOTE]
> These stories describe the **target architecture** for rebrew workflows.
> Some tools and orchestration steps (e.g. agent batch processing, LLM pipelines)
> are aspirational and not yet implemented.

User stories for the Rebrew decompilation workbench, organized by persona and workflow.

---

## Personas

| Persona | Description |
|---------|-------------|
| **RE Dev** | A reverse engineer manually decompiling functions |
| **AI Operator** | Someone running AI-assisted batch pipelines |
| **Project Lead** | Sets up projects, reviews progress, manages targets |
| **Contributor** | New team member learning the workflow |

---

## 1. Project Initialization

> **As a Project Lead**, I want to initialize a new rebrew project for a binary so that my team has a standardized workspace with config, directories, and toolchain ready.

### Acceptance Criteria
- `rebrew.toml` created with target binary, format, arch, and compiler settings
- Source, bin, and output directories scaffolded
- Compiler detected from PE Rich Header or CRT prologue patterns
- Running `rebrew-init` a second time changes nothing (idempotent)

```mermaid
graph TD
    A["Obtain target binary<br/>(e.g. game.dll)"] --> B["rebrew-init --target game<br/>--binary game.dll --compiler msvc6"]
    B --> C["rebrew.toml created"]
    B --> D["src/game/ directory created"]
    B --> E["bin/game/ directory created"]
    C --> F["rebrew-cfg show"]
    F --> G["Project ready for RE work"]

    style A fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style G fill:#d1fae5,stroke:#059669,color:#065f46
```

---

## 2. Adding a Second Target Binary

> **As a Project Lead**, I want to add a second binary (e.g. client.exe) to an existing project so that shared code between DLL and EXE can be tracked together.

### Acceptance Criteria
- New `[targets.client_exe]` section added to `rebrew.toml`
- Existing target config untouched
- Origins and cflags presets configurable per-target
- Shared source directory pattern (`src/shared/`) documented

```mermaid
graph TD
    A["Existing project with<br/>server.dll target"] --> B["rebrew-cfg add-target client.exe<br/>--binary original/client.exe"]
    B --> C["rebrew-cfg add-origin ZLIB<br/>--target client.exe"]
    C --> D["rebrew-cfg set-cflags GAME<br/>'/O2 /Gd' --target client.exe"]
    D --> E["Both targets in rebrew.toml"]
    E --> F["rebrew-next --target client.exe"]

    style A fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style F fill:#d1fae5,stroke:#059669,color:#065f46
```

---

## 3. Function Discovery & Triage

> **As an RE Dev**, I want to discover all functions in a binary and triage them by type (library, game, CRT) so that I can prioritize which ones to reverse first.

### Acceptance Criteria
- Function list generated (r2 / Ghidra / lief)
- FLIRT signatures auto-identify CRT/zlib/Lua functions (~20-40%)
- `rebrew-triage` classifies functions by origin, size, and matchability
- Functions ranked by size and tagged with origin
- IAT thunks, SEH helpers, and ASM builtins flagged as non-matchable

```mermaid
graph TD
    A["Target binary loaded"] --> B["radare2 / Ghidra:<br/>function boundary detection"]
    B --> C["functions.json<br/>(VA, size, name)"]
    C --> D{"rebrew-flirt:<br/>FLIRT match?"}
    D -->|"Match (CRT/zlib)"| E["Mark as LIBRARY<br/>compile from reference"]
    D -->|"No match"| F{"Named export?"}
    F -->|Yes| G["Named STUB"]
    F -->|No| H["Anonymous STUB<br/>(FUN_XXXXXXXX)"]
    E --> I["Seed RAG database"]
    G --> T["rebrew-triage<br/>classify & prioritize"]
    H --> T
    T --> J["rebrew-next --stats<br/>prioritize by size"]

    style A fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style I fill:#d1fae5,stroke:#059669,color:#065f46
    style J fill:#d1fae5,stroke:#059669,color:#065f46
    style D fill:#fef3c7,stroke:#d97706,color:#92400e
    style F fill:#fef3c7,stroke:#d97706,color:#92400e
```

---

## 4. Manual Decompilation (Single Function)

> **As an RE Dev**, I want to pick a function, write C89 source, and verify it produces byte-identical output so that I can incrementally build the decompiled codebase.

### Acceptance Criteria
- `rebrew-next` shows prioritized list of uncovered functions
- `rebrew-skeleton` creates annotated `.c` file
- `rebrew-test` classifies result as EXACT / RELOC / MATCHING / MISMATCH
- Annotation header updated with correct STATUS and BLOCKER (if any)
- `rebrew-promote` used to promote status on match

```mermaid
graph TD
    Pick["rebrew-next --origin GAME<br/>pick smallest function"] --> Skel["rebrew-skeleton 0xVA"]
    Skel --> Decompile["Get ASM / Ghidra decompilation"]
    Decompile --> Write["Write C89 source code"]
    Write --> Test{"rebrew-test<br/>src/target/func.c"}
    Test -->|EXACT| Promote["rebrew-promote<br/>→ STATUS: EXACT"]
    Promote --> Done["✅ Done"]
    Test -->|RELOC| PromoteR["rebrew-promote<br/>→ STATUS: RELOC"]
    PromoteR --> DoneR["✅ Done"]
    Test -->|MISMATCH| Diff["rebrew-match --diff-only"]
    Test -->|COMPILE ERROR| Write
    Diff --> Flags{"Unsure about<br/>compiler flags?"}
    Flags -->|Yes| Sweep["rebrew-match<br/>--flag-sweep-only"]
    Sweep --> Write
    Flags -->|No| Write

    style Pick fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style Promote fill:#d1fae5,stroke:#059669,color:#065f46
    style PromoteR fill:#d1fae5,stroke:#059669,color:#065f46
    style Done fill:#d1fae5,stroke:#059669,color:#065f46
    style DoneR fill:#d1fae5,stroke:#059669,color:#065f46
    style Test fill:#fef3c7,stroke:#d97706,color:#92400e
    style Flags fill:#fef3c7,stroke:#d97706,color:#92400e
```

---

## 5. GA-Assisted Matching (Workflow B)

> **As an RE Dev**, I want to hand off a MATCHING function to the genetic algorithm so that it can brute-force the last few byte differences without me manually tweaking comparison operators.

### Acceptance Criteria
- GA accepts my `.c` file as seed
- 40+ mutation operators applied (if-swaps, loop transforms, operand commutation)
- Results cached in SQLite `BuildCache` to prevent duplicate compilations
- GA finds EXACT/RELOC or reports stagnation after N generations

```mermaid
graph TD
    A["Function at STATUS: MATCHING<br/>(small byte delta)"] --> B["rebrew-match func.c<br/>--generations 200 --pop-size 64"]
    B --> C["GA mutates C AST<br/>(40+ operators)"]
    C --> D["Compile each candidate<br/>(MSVC6 via Wine)"]
    D --> E{"Fitness improved?"}
    E -->|"EXACT / RELOC"| F["✅ Match found!<br/>Update annotation"]
    E -->|"Improved but not exact"| G["Continue evolving<br/>(next generation)"]
    E -->|"Stagnation<br/>(50 gen no improvement)"| H["Add BLOCKER note<br/>escalate to LLM"]
    G --> C

    style A fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style F fill:#d1fae5,stroke:#059669,color:#065f46
    style H fill:#fee2e2,stroke:#dc2626,color:#991b1b
    style E fill:#fef3c7,stroke:#d97706,color:#92400e
```

---

## 6. AI Zero-Shot Decompilation (Workflow A)

> **As an AI Operator**, I want the LLM to generate an initial C implementation from assembly so that I get a semantic baseline without manual effort.

### Acceptance Criteria
- ASM extracted via `rebrew-asm` and fed to LLM with RAG context
- RAG resolves called function signatures, globals, strings, and caller context
- Output normalized (C89 dialect, proper annotation header prepended)
- Result tested and classified automatically

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant DB as SQLite RAG
    participant LLM as LLM
    participant T as rebrew-test

    O->>O: Extract ASM via rebrew-asm
    O->>DB: Query all referenced VAs
    DB-->>O: Function sigs + globals + strings
    O->>LLM: ASM + RAG context + compiler rules
    LLM-->>O: Generated C source

    loop Up to N iterations
        O->>T: Compile & compare
        T-->>O: Result (EXACT/RELOC/MATCHING)
        alt EXACT or RELOC
            O->>DB: Ingest new match into RAG
            Note over O: Done ✅
        else MATCHING / MISMATCH
            O->>LLM: Diff feedback + corrections
            LLM-->>O: Revised C source
        end
    end
```

---

## 7. Autonomous Agent Batch Processing

> **As an AI Operator**, I want to run the agent overnight to process an entire binary's worth of functions so that I can review results in the morning.

### Acceptance Criteria
- Agent auto-selects workflow (A/B/C/D/E) per function based on state
- Score monotonicity enforced (never makes a function worse)
- Shadow workspace (`staging/`) used — never writes directly to `src/`
- Git branch `agent/batch-<timestamp>` created for all changes
- Run report generated with stats, stalled functions, and audit trail

```mermaid
graph TD
    Start["Agent starts<br/>load agent.yml"] --> Queue["Build work queue<br/>from rebrew-next"]
    Queue --> Empty{"Queue empty?"}
    Empty -->|Yes| Report["Generate run report<br/>agent_run_TIMESTAMP.md"]
    Empty -->|No| Pop["Pop next function"]
    Pop --> Select["select_workflow()"]

    Select --> WA["Workflow A:<br/>Zero-shot LLM"]
    Select --> WB["Workflow B:<br/>GA refinement"]
    Select --> WC["Workflow C:<br/>Diff resolver"]
    Select --> WE["Workflow E:<br/>LLM improvement"]

    WA --> Result{"Result?"}
    WB --> Result
    WC --> Result
    WE --> Result

    Result -->|"EXACT / RELOC"| Stage["Write to staging/<br/>score gate check"]
    Result -->|MATCHING| Requeue["Update state<br/>re-queue"]
    Result -->|STALLED| Log["Log for<br/>human review"]

    Stage --> Regression["rebrew-verify<br/>regression gate"]
    Regression -->|Pass| Commit["Promote to src/<br/>git commit"]
    Regression -->|Fail| Rollback["Rollback<br/>mark STALLED"]

    Commit --> Queue
    Rollback --> Queue
    Requeue --> Queue
    Log --> Queue
    Report --> Done["Agent exits"]

    style Start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style Done fill:#d1fae5,stroke:#059669,color:#065f46
    style Log fill:#fee2e2,stroke:#dc2626,color:#991b1b
    style Rollback fill:#fee2e2,stroke:#dc2626,color:#991b1b
    style Empty fill:#fef3c7,stroke:#d97706,color:#92400e
    style Result fill:#fef3c7,stroke:#d97706,color:#92400e
```

---

## 8. Ghidra ↔ Local Sync

> **As an RE Dev**, I want improvements from my `.c` files pushed to Ghidra (and vice versa) so that the decompiler always shows resolved names and correct types.

### Acceptance Criteria
- `rebrew-sync --push` pushes function names, comments, and bookmarks to Ghidra via ReVa MCP
- Generic `func_XXXXXXXX` labels are skipped by default (`--skip-generic`)
- Struct definitions pushed via `parse-c-structure` MCP tool
- Ghidra decompilation and struct info can be pulled into local `.c` files
- Sync is bidirectional and incremental

```mermaid
graph LR
    subgraph "Local (.c files)"
        L1["Function names<br/>& signatures"]
        L2["Struct definitions"]
        L3["STATUS / ORIGIN<br/>annotations"]
    end

    subgraph "Ghidra Project"
        G1["Labels & renames"]
        G2["Data Type Manager"]
        G3["Decompiler output"]
    end

    L1 -->|"rebrew-sync --push<br/>(create-label)"| G1
    L3 -->|"rebrew-sync --push<br/>(set-comment)"| G1
    L2 -->|"parse-c-structure"| G2
    G3 -->|"get-decompilation"| L1
    G2 -->|"get-structure-info"| L2
```

### Recommended Sync Cycle

```mermaid
graph TD
    A["Start reversing<br/>a function"] --> B["Pull decompilation<br/>(Ghidra → Local)"]
    B --> C["Pull struct defs<br/>(Ghidra → Local)"]
    C --> D["Write/update .c file"]
    D --> E["rebrew-test"]
    E --> F["Push names back<br/>(Local → Ghidra)"]
    F --> G["Push new structs<br/>(Local → Ghidra)"]
    G --> H{"More functions<br/>using these types?"}
    H -->|Yes| I["Re-pull decompilation<br/>(resolved names now)"]
    I --> D
    H -->|No| J["Done"]

    style A fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style J fill:#d1fae5,stroke:#059669,color:#065f46
    style H fill:#fef3c7,stroke:#d97706,color:#92400e
```

---

## 9. Cold-Start Bootstrapping (Workflow D)

> **As a Project Lead**, I want to bootstrap an entirely new binary from scratch so that the RAG database gets seeded progressively and enables the snowball effect.

### Acceptance Criteria
- `rebrew-init` scaffolds the project directory and config
- Function boundaries detected via radare2/Ghidra
- FLIRT identifies library functions automatically
- `rebrew-triage` classifies and prioritizes all functions
- Smallest leaf functions processed first (snowball strategy)
- Each match enriches RAG for subsequent functions

```mermaid
graph TD
    A["New binary<br/>(no prior RE work)"] --> Init["rebrew-init<br/>scaffold project"]
    Init --> B["Parse PE / ELF<br/>detect sections"]
    B --> C["Function boundary<br/>detection"]
    C --> D["FLIRT signature<br/>matching"]
    D -->|"~20-40% matched"| E["Compile from<br/>reference source"]
    D -->|"Unmatched"| F["rebrew-triage<br/>classify functions"]
    E --> G["Seed RAG database"]
    F --> H["rebrew-next<br/>sort by size"]
    H --> I["LLM generates<br/>tiny leaf functions"]
    I --> J{"rebrew-test"}
    J -->|"EXACT/RELOC"| G
    J -->|"MATCHING"| K["GA refinement"]
    K -->|Success| G
    K -->|Stalled| L["Diff resolver<br/>(Workflow C)"]
    L --> J
    G -->|"Snowball:<br/>richer context"| I

    style A fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style G fill:#d1fae5,stroke:#059669,color:#065f46
    style J fill:#fef3c7,stroke:#d97706,color:#92400e
```

---

## 10. Progress Monitoring & Verification

> **As a Project Lead**, I want to see at-a-glance progress stats and verify all existing matches still hold so that I can track coverage and catch regressions.

### Acceptance Criteria
- `rebrew-status` shows at-a-glance reversing progress overview
- `rebrew-next --stats` shows function counts by status and origin
- `rebrew-verify` bulk-compiles and re-verifies all `.c` files
- `rebrew-catalog --json` regenerates coverage JSON and function registry
- `rebrew-build-db` updates the dashboard database
- `rebrew-verify` regression gate prevents breaking existing matches

```mermaid
graph TD
    A["Check project status"] --> S["rebrew-status"]
    S --> B["rebrew-next --stats"]
    B --> C["Coverage summary:<br/>EXACT / RELOC / MATCHING / STUB"]

    D["Verify integrity"] --> E["rebrew-verify"]
    E --> F{"All files compile<br/>& match?"}
    F -->|Yes| G["✅ All green"]
    F -->|No| H["❌ Regressions found<br/>report affected files"]

    I["Generate catalog"] --> J["rebrew-catalog --json"]
    J --> BD["rebrew-build-db"]
    BD --> K["coverage.db +<br/>dashboard updated"]

    style A fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style D fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style I fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style G fill:#d1fae5,stroke:#059669,color:#065f46
    style H fill:#fee2e2,stroke:#dc2626,color:#991b1b
    style F fill:#fef3c7,stroke:#d97706,color:#92400e
```

---

## 11. Annotation Linting & Quality

> **As a Contributor**, I want the linter to catch annotation mistakes in my `.c` files so that all files follow the project's annotation standard.

### Acceptance Criteria
- `rebrew-lint` checks all annotation fields (FUNCTION, STATUS, ORIGIN, SIZE, CFLAGS)
- Error codes E001–E017 for hard errors, W001–W015 for warnings
- `rebrew-lint --fix` auto-migrates old annotation formats
- Running lint twice changes nothing (idempotent)

```mermaid
graph TD
    A["Write or edit a .c file"] --> B["rebrew-lint"]
    B --> C{"Annotations valid?"}
    C -->|Yes| D["✅ Clean"]
    C -->|No| E["Report errors<br/>(E001-E017, W001-W015)"]
    E --> F{"Auto-fixable?"}
    F -->|Yes| G["rebrew-lint --fix"]
    G --> B
    F -->|No| H["Manual fix required"]
    H --> A

    style A fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style D fill:#d1fae5,stroke:#059669,color:#065f46
    style C fill:#fef3c7,stroke:#d97706,color:#92400e
    style F fill:#fef3c7,stroke:#d97706,color:#92400e
```

---

## 12. FLIRT Signature Identification

> **As an RE Dev**, I want to scan the target binary against FLIRT signatures so that known library functions (CRT, zlib, Lua) are identified without wasting LLM tokens.

### Acceptance Criteria
- `.sig` / `.pat` files loaded from signature directory
- Scans `.text` section in 16-byte aligned chunks
- Matches reported with VA and function name
- Custom `.pat` files can be generated from any `.lib` archive

```mermaid
graph TD
    A["Obtain FLIRT<br/>signatures (.sig/.pat)"] --> B["rebrew-flirt flirt_sigs/"]
    B --> C["Load & compile<br/>signature patterns"]
    C --> D["Scan .text section<br/>(16-byte aligned)"]
    D --> E{"Matches found?"}
    E -->|Yes| F["Report: VA → name<br/>(e.g. _malloc, adler32)"]
    E -->|No matches| G["No library functions<br/>identified"]
    F --> H["Mark as LIBRARY<br/>in annotations"]

    I["Custom .lib file"] --> J["python -m rebrew.gen_flirt_pat<br/>→ custom.pat"]
    J --> A

    style A fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style H fill:#d1fae5,stroke:#059669,color:#065f46
    style G fill:#fee2e2,stroke:#dc2626,color:#991b1b
    style E fill:#fef3c7,stroke:#d97706,color:#92400e
```

---

## 13. Improving Existing Decompilations (Workflow E)

> **As an AI Operator**, I want the LLM to take a fresh pass at existing MATCHING functions so that functions close to RELOC can be pushed over the finish line.

### Acceptance Criteria
- Existing `.c` file + diff fed to LLM with BLOCKER context
- Targeted fixes (swap if/else, adjust comparisons) without full rewrite
- If still MATCHING after LLM, hand off to GA (Workflow B)
- Score must improve or change is rejected

```mermaid
graph TD
    A["MATCHING function<br/>(existing .c file)"] --> B["rebrew-test<br/>capture current diff"]
    B --> C["Feed to LLM:<br/>source + diff + BLOCKER"]
    C --> D["LLM suggests<br/>targeted fixes"]
    D --> E{"rebrew-test<br/>re-check"}
    E -->|"EXACT / RELOC"| F["✅ Promoted!"]
    E -->|"Improved MATCHING"| G["Accept improvement<br/>optionally → GA"]
    E -->|"Same / Worse"| H["Reject change"]
    G --> I["rebrew-match func.c<br/>(Workflow B)"]
    I -->|"EXACT / RELOC"| F

    style A fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style F fill:#d1fae5,stroke:#059669,color:#065f46
    style H fill:#fee2e2,stroke:#dc2626,color:#991b1b
    style E fill:#fef3c7,stroke:#d97706,color:#92400e
```

---

## 14. Cosmetic Improvements on Matched Functions

> **As an RE Dev**, I want to rename variables and add comments on EXACT/RELOC functions without risking the byte match so that the codebase is more readable over time.

### Acceptance Criteria
- Variable renames, comments, whitespace changes are allowed on frozen functions
- Change compiled → bytes compared → **must be byte-identical**
- If bytes differ at all, the edit is rejected (it wasn't purely cosmetic)

```mermaid
graph TD
    A["EXACT/RELOC function"] --> B["LLM or human suggests<br/>better variable names"]
    B --> C["Apply renames in<br/>staging/VA.c"]
    C --> D{"Compile +<br/>byte-compare"}
    D -->|"Bytes identical"| E["✅ Accept cosmetic edit<br/>promote to src/"]
    D -->|"Bytes differ"| F["❌ Reject:<br/>rename affected codegen"]
    E --> G["Add comments based<br/>on ASM semantics"]
    G --> C

    style A fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style E fill:#d1fae5,stroke:#059669,color:#065f46
    style F fill:#fee2e2,stroke:#dc2626,color:#991b1b
    style D fill:#fef3c7,stroke:#d97706,color:#92400e
```

---

## End-to-End Pipeline Summary

> **As an AI Operator**, I want the full pipeline from `.exe` to `.c` files to run autonomously so that overnight batch processing maximizes coverage.

```mermaid
graph LR
    subgraph "Phase 1: Discovery"
        A["target.dll"] --> B["Parse PE<br/>sections"]
        B --> C["Function boundary<br/>detection"]
        C --> D["functions.json"]
    end

    subgraph "Phase 2: Triage"
        D --> E{"FLIRT?"}
        E -->|Yes| F["Compile from<br/>reference"]
        E -->|No| G["STUB files<br/>created"]
    end

    subgraph "Phase 3: Batch Reverse"
        F --> H["RAG DB"]
        G --> I["LLM + GA loop"]
        I -->|"EXACT/RELOC"| H
        I -->|Stalled| J["Human review"]
        H -->|"Snowball"| I
    end

    subgraph "Phase 4: Output"
        H --> K["src/*.c files"]
        H --> L["Run report"]
    end

    style A fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    style K fill:#d1fae5,stroke:#059669,color:#065f46
    style L fill:#d1fae5,stroke:#059669,color:#065f46
    style J fill:#fee2e2,stroke:#dc2626,color:#991b1b
    style E fill:#fef3c7,stroke:#d97706,color:#92400e
```
