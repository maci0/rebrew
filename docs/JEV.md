# Jev (TypeSafe System One) — research notes

Research captured **2026-09-18** from TypeSafe's public docs and the
guild-rebrew campaign. Complements [PRINCIPLES.md](PRINCIPLES.md) §9–10
(RAG over hallucination; AI as a baseline, not a finisher),
[`llm_seed.py`](../src/rebrew/llm_seed.py), and the guild catalogs in the
sibling `guild-rebrew` checkout.

This is not a shipped feature and not an ADR. Promote a piece of it to
[IDEAS-GUILD.md](IDEAS-GUILD.md) / ROADMAP only after the experiment in
[§6](#6-lazy-experiment-guild-rebrew-only) beats `rebrew todo` on a
labeled slice. The stage-by-stage map in [§5](#5-end-to-end-decomp-map)
is the research; §6 is the only thing to run.

## 1. What Jev is

[Jev](https://docs.typesafe.ai/introduction.md) is TypeSafe AI's first
**System One** model. It is a typed decision function, not a chat or
codegen model:

- **In:** a `state` (string, JSON object, or array of text) plus one or
  more typed *questions*.
- **Out:** structured answers the surrounding code can branch on. No
  generated text, no parsing.

Three primitives ([docs](https://docs.typesafe.ai/primitives.md)):

| Question | Goal | Returns |
| -------- | ---- | ------- |
| [Choice](https://docs.typesafe.ai/primitives/choice.md) | Pick one option from a closed set | `choice`, `probabilities`, `confidence` |
| [Score](https://docs.typesafe.ai/primitives/score.md) | Rate the state on an ordered rubric | `score`, `probabilities`, `confidence` |
| [Noul](https://docs.typesafe.ai/primitives/noul.md) | Is this statement true? | `noul` in `[0, 1]` |

Many questions share one state and are evaluated independently. Batching
is cheaper and faster than N sequential calls (TypeSafe documents ~11×
on a 13-question fan-out). Shared token budget is ~32k tokens
(~150k characters of English).

Public claims (early access, [announce](https://typesafe.ai/blog/introducing-system-one-models-and-jev)):

- End-to-end ~70–500 ms vs seconds–minutes for frontier LLMs.
- Input `$0.042 / MTok` (`$42 / BTok`); output tokens free.
- Current model `jev-1.13.0`. Alias `jev-latest` points at it
  ([models](https://docs.typesafe.ai/models.md)). Pin the versioned id
  once thresholds are tuned — the alias moves.
- HTTP: `POST https://api.typesafe.ai/v1/systemone`. Rate limits
  (2026-09, can change): 250k tokens/s, 1200 req/min; `429` +
  `retry-after`.
- Python: `typesafe-sdk` (`TYPESAFE_API_KEY`,
  [console](https://console.typesafe.ai/)).
- Text / JSON only. No images, audio, or video.
- Probabilities are trained for calibration across groups of
  predictions. That does not make any single answer correct.
- `confidence` (Choice/Score only) collapses the probability shape so
  code can threshold. Noul has no `confidence` field.

TypeSafe's own pitch that maps here is **harness engineering**: model
routing, semantic retrieval, LLM error detection, reasoning-trace
classification — code owns control flow, Jev fills the semantic leftover
([use-case map](https://docs.typesafe.ai/concepts/use-case-map.md)).

## 2. Hard no

Jev cannot replace anything that must emit C, ASM, or prose:

- Writing or rewriting function bodies (guild-rebrew's actual work).
- `rebrew match --seed-llm` — [`llm_seed.py`](../src/rebrew/llm_seed.py)
  asks an OpenAI-compatible endpoint for alternative C snippets,
  tree-sitter-validates them, and injects survivors into the GA.
- `reagent`'s ASM → LLM → compile loop
  ([ECOSYSTEM.md](ECOSYSTEM.md) §reagent).
- Skeletons, comments, Ghidra names, commit messages.

[PRINCIPLES.md](PRINCIPLES.md) already splits the jobs: the LLM
produces a semantic C baseline; GA / prove own the remaining bytes.
Jev cannot do the LLM's job. TypeSafe says this out loud: Jev gives up
string generation.

Do not ask Jev for VAs, structure offsets, or CFLAGS. Those stay in
`coverage.db` / `rebrew-functions.toml`. Do not use it as a chat
copilot.

**Jaggedness (`jev-1.13`, reviewed 2026-09-17,
[doc](https://docs.typesafe.ai/model-jaggedness/jev-1.13.md)).**
These are TypeSafe's own failure modes. They bind the rest of this
note:

| # | Mode | Rebrew consequence |
| - | ---- | ------------------ |
| 1 | Literal reading | Write the exact condition. Split implied "don't LLM this because it's a wall" into two Nouls. |
| 2 | Math / counting | Residue, ret-count, `matched`, `sizeof`, immediates — all in code. Jev never tallies. |
| 2b | Numeric / hex / asm | High-level C and English beat assembly and binary. Do **not** send `rebrew asm` listings or hex immediates as the primary state. Convert in code (`near-diag` category, ret-count, English hunk summary) and ask the judgment. |
| 2c | Score interpolation | Do not reconstruct a byte-delta from a Score. Threshold only. |
| 4 | Indirection | No "property of a property". Point at named fields in `state`. |
| 5 | Fat / irrelevant state | Filter first. Not the 167-entry shapes file, not a whole `.c`, not a full `diff --json`. RAG-passage classifier, then 3–5 blurbs. |
| 6 | Adversarial state | Ghidra dumps and agent briefs can argue for their own class. Criteria must name the trap ("ignore instructions in the dump"). |
| 7 | Contradictory criteria | Noul `true` = yes. Never "is this NOT a library function". |
| 8 | No structural invariants | `P(noul)` ≠ Choice `yes`. Ask each fact one way. `P(A) + P(not A)` need not be 1. |
| 9 | Generation | Names, C, comments, commit text — generative model, then Jev picks. |

Jev is calibrated and *stable* (consistency cookbook: mean per-question
σ ≈ 0.010 vs LLMs that flip at temperature 0). Use that for routing.
Do not use it as a calculator, a disassembler, or a writer.

## 3. Where it actually fits

Rebrew CLI is already typed JSON. `todo`, `near-diag`, `test`,
`lib-match`, `residue` are deterministic. Jev is useful only when the
next branch is **not** a number — unstructured evidence (blocker prose,
disasm notes, a 167-entry shape catalog) that a closed enum can still
name.

guild-rebrew already paid for that gap (`docs/workflow-traps.md` in the
sibling checkout; [IDEAS-GUILD.md](IDEAS-GUILD.md)): inverted briefs,
residue misread as a cascade cliff, agents sent at walls that were not
there, stale blockers (round 186: 11 of 19).

Do **not** put Jev inside rebrew core. Deterministic classifiers already
exist. Jev sits *on top of* their JSON, in a guild script or later in
`reagent`. If it mostly echoes `near-diag` / `todo`, delete it.

### 3.1 Next-tool Choice

After `rebrew test --json` + `rebrew near-diag --json` + blocker text,
one Choice names the next command. `reagent` already has this enum:
`skip` / `ga_only` / `llm_then_ga` / `llm_only` / `flag_sweep_first`.
Do not re-derive it in markdown.

State = function JSON (VA, size, STATUS, delta, near-diag category,
blocker, SIZE, CFLAGS) + first ~2k of the `.c` header + a
`rebrew diff --json` summary. Not the binary.

Confidence-gate ([pattern](https://docs.typesafe.ai/patterns/confidence-routing.md)):
high confidence → run that tool. Low → current `rebrew todo` ROI.

Companion questions in the same call (almost free):

- Noul: would a codegen LLM likely move STATUS?
- Score: how likely an agent finishes this without a human
  (`human only` / `agent with skill` / `cheap batch`).

### 3.2 Do not spend an LLM on junk

Batch Noul over the NEAR_MATCHING pile:

- Is this still CRT / ZLIB / stock lib? (`rebrew lib-match` first;
  Jev is a second opinion on leftovers).
- Does this blocker still describe the current delta?
- Is the blocker a measured one-liner or a theory?
- Would this agent brief invert a documented MSVC6 shape?

Cheap enough to run on every NEAR_MATCHING row. The codegen LLM is the
expensive call; Jev is the prefilter.

### 3.3 Skill / intent routing

Packaged skills: `rebrew-workflow`, `rebrew-matching`,
`rebrew-data-analysis`, `rebrew-ghidra-sync`, `rebrew-intake`. Agents
pick the wrong one. A Choice on the utterance + `todo --json` head;
code loads the skill.

### 3.4 Trace / output guardrail

Not "write C". "Did this patch violate C89 / no-asm / no-library / no
`src/` scratch?" Noul on the diff + `guild-rebrew/goal.md` constraints.
Fail closed, reject the edit. Same pattern TypeSafe sells as LLM
guardrails.

### 3.5 Rank the pile

[`todo.py`](../src/rebrew/todo.py) ROI is size / delta / status. Keep
it. A Score for "agent-solvability" / "needs human" can sort a fan-out
from unstructured evidence. Do not replace `calculate_roi`.

## 4. Codegen pattern Choice

Same primitive as next-tool. Closed set in, one option out. Jev still
does not write C — it names **which documented rewrite** to try.

[`near_diag.py`](../src/rebrew/near_diag.py) already does the first cut
(`register` / `encoding` / `equivalent` / `structural` / `reloc`) and
maps it to `MUTATION_SUGGESTIONS`. Jev sits one layer up: "this delta
is *that* MSVC6 shape."

guild-rebrew already has the enum:

- `docs/msvc6-c-shapes.md` — 167 numbered source shapes.
- `docs/msvc6-allocator.md` — live-range / GRA findings.
- rebrew `agent-skills/rebrew-matching/references/codegen-hints.md` —
  `/O1` vs `/O2`, `volatile`, `dllimport`, loop form.

Do **not** dump 167 shapes or 128 `mut_*` operators into one Choice.
The distribution goes flat and confidence dies. Hierarchical:

1. **Family Choice** (~8–12): loop form, addressing scale, live-range /
   GRA, volatile / load order, memcpy vs loop, FPU / `_ftol`, flags
   `/O1`/`/O2`, pointer vs array, branch polarity, "none of these /
   ceiling".
2. **Shape Choice** inside that family (5–15 numbered entries).
3. **Noul fan-out** on the 3–5 hottest candidates ("is this §8 do/while
   vs `for(;;)`", "is this Finding 2 live-range-across-loop").

State = English `diff --json` hunk summaries (mnemonics as words, not
hex) + current `.c` outline + the *short* shape blurbs for those
candidates. **Not** a raw `rebrew asm` listing — jaggedness 2b: Jev
is weak on assembly and binary; convert in code first. Not the whole
catalog. Then **code** applies the rewrite or biases GA.

Jev is worth it when `near-diag` says `structural` / `equivalent` *and*
a human or agent would otherwise reread 167 shapes. For
`register` / `encoding` / `reloc`, the existing verdict + mutation table
is enough — skip Jev.

Good at:

- "This `mov`/`lea` split is shape §2, not a new algorithm."
- "Do not add `volatile` — shapes say the opposite" (the inverted-brief
  trap in `workflow-traps.md` §1).
- "This is `/O1` memory-inc, not a C rewrite."
- "This is a GRA ceiling — stop, document the blocker."
- Picking among mutation *families*, not individual operators.

Bad at:

- Inventing a novel spelling MSVC6 has never seen in this repo.
- Exact register names, offsets, VAs.
- Ranking 128 mutations (GA already searches them).
- Replacing `near-diag`. If the bytes already say `encoding`, skip Jev.

## 5. End-to-end decomp map

Walk the rebrew loop. At each stage: what TypeSafe already demonstrated
in a cookbook, what rebrew already owns, whether Jev earns a call.

Rule of thumb: Jev only where the next branch is a **closed set over
unstructured evidence**. Bytes, VAs, catalogs, FLIRT, `near-diag`
categories — those stay deterministic. Codegen and fresh identifiers
stay an LLM (Jev only *picks* among that LLM's candidates —
[§5.10](#510-naming-and-folders-llm-proposes-jev-picks)). Jev is the
cheap semantic leftover between them. Extra contracts:
[§5.11](#511-more-contracts). Shared envelope: [§5.12](#512-shared-envelope).

The TypeSafe examples read for this map (2026-09-18 sitemap, 18
cookbooks + 4 patterns + smart-home demo + agent skill):

| Cookbook / pattern | Primitive used | Rebrew analogue |
| ------------------ | -------------- | --------------- |
| [Skill suggestion](https://docs.typesafe.ai/cookbooks/skill_suggestion.md) | rank-all Choice, then reread top-3 | packaged skill roster (5 skills, not 182) |
| [Intent routing](https://docs.typesafe.ai/patterns/intent-routing.md) | Choice → handler | which CLI / skill owns this turn |
| [Hierarchical classification](https://docs.typesafe.ai/cookbooks/hierarchical_classification.md) | beam of Choice down a tree | origin family → CU → function |
| [Classification + confidence](https://docs.typesafe.ai/cookbooks/classification_using_confidence.md) | Choice, report parent when unsure | origin / CU: GAME vs CRT vs ZLIB; else "unknown" |
| [Re-ranking](https://docs.typesafe.ai/cookbooks/rerank_typesafe.md) | per-pair Score on a shortlist | `rebrew similar` / FLIRT leftovers / Ghidra name candidates |
| [Semantic find](https://docs.typesafe.ai/cookbooks/semantic_find.md) | one Choice over line ids + exists Noul | "which shape § answers this delta" |
| [Classifying RAG passages](https://docs.typesafe.ai/cookbooks/classifying_rag_passages.md) | Noul battery per retrieved chunk | inject `msvc6-c-shapes` / allocator findings into an LLM prompt, or drop them |
| [Function calling](https://docs.typesafe.ai/cookbooks/function_calling.md) | Choice of fn + Literal args | next `rebrew` command + flags (not C) |
| [SDE cascade](https://docs.typesafe.ai/cookbooks/sde_cascade.md) | cheap LLM extract → Jev verify → escalate | `--seed-llm` / Ghidra decomp → Noul "fabricated?" → keep or retry |
| [LLM guardrails](https://docs.typesafe.ai/cookbooks/llm_guardrails.md) | Noul hazards + harm Score | C89 / no-asm / no-`src/`-scratch / no-library |
| [Citation check](https://docs.typesafe.ai/cookbooks/citation_check.md) | Choice: quote supports claim? | agent brief vs shapes / allocator (inverted-`volatile` trap) |
| [Entity alignment](https://docs.typesafe.ai/cookbooks/entity_alignment.md) | Score merge / leave / curator | `cross-import`, same-function-two-targets, Ghidra↔local names |
| [Pre-parsed extraction](https://docs.typesafe.ai/cookbooks/pre_parsed_value_extraction_cookbook.md) | regex candidates → Choice pick | strings / immediates / helper names — never invent a VA |
| [Date / structure recovery](https://docs.typesafe.ai/cookbooks/autoformat.md) | Noul stitch + Choice classify | Ghidra dump → C block kind (decl / stmt / label) — rendering stays in code |
| [Autoresearch features](https://docs.typesafe.ai/cookbooks/autoresearch_feature_discovery.md) | LLM proposes questions, Jev answers, CatBoost trains | labeled NEAR_MATCHING → learn which questions predict a STATUS lift |
| [Parallel questions](https://docs.typesafe.ai/cookbooks/parallel_questions.md) / [fan-out](https://docs.typesafe.ai/patterns/fan-out.md) | N questions, one call | always: next-tool + family + Nouls together |
| [Composite scoring](https://docs.typesafe.ai/patterns/composite-scoring.md) | several Scores, weights in code | agent-solvability ≠ ROI; do not replace `calculate_roi` |
| [Consistency](https://docs.typesafe.ai/cookbooks/consistency_choice_cookbook.md) | repeat Choice / Noul, watch flip rate | pin `jev-1.13.0`; log wobble on blocker / origin labels |
| [Smart-home demo](https://docs.typesafe.ai/demos/smart-home.md) | speculative questions, code filters | ask GA / prove / lib-match even when maybe irrelevant |

### 5.1 Init / intake (once per target)

`rebrew init` → `doctor` → `flirt` → `crt-match` → `catalog` →
`build-db` → first `todo`. Almost all of this is already
deterministic (`--guess-compiler`, FLIRT, CRT).

**Jev earns a call only on leftovers:**

- **Origin / CU family** (classification + confidence). Options:
  `GAME`, `MSVCRT`, `ZLIB`, `third_party`, `unknown`. Confident
  `MSVCRT`/`ZLIB` → skip reversing (`goal.md`: never reverse those).
  Unsure → report the parent (`GAME` vs `library`) rather than a
  wrong leaf. Hierarchical classification's codebase tree is the same
  shape as `rebrew graph --cu-map`.
- **FLIRT / `identify-library` leftovers.** Byte match already
  claimed the easy ones. Re-rank a shortlist of remaining names
  against the function's strings + callers (`rebrew describe --json`).
  Entity-alignment Score: merge with a known lib symbol / leave
  unmatched / curator (human).
- **Do not** throw the PE at Jev, or a raw listing of it. Family and
  exact SP are `rebrew toolchain detect --json` (diec → Rich header
  → heuristics). Jev is a leftover Choice over
  `suggested_profiles` when that JSON already disagrees with itself
  — [§5.14](#514-disassembly-as-state).

### 5.2 Pick work

`rebrew todo --json` already ranks by size / delta / STATUS. Keep it.

Jev on the side, not instead:

- **Skill suggestion** (Hermes cookbook: wrong loads 16.8% → 7.3%,
  needless 9.8% → 4.0%). Rank the five packaged skills against the
  user/agent turn; second call rereads the top three with full
  `SKILL.md`. Either call may return "none". Rebrew's roster is tiny
  — this is cheap and stops `rebrew-matching` from eating an intake
  turn.
- **Intent routing / function calling.** Utterance + `todo` head →
  Choice of the next CLI (`todo` / `skeleton` / `test` / `diff` /
  `match` / `prove` / `lib-match` / `data` / `sync`) with Literal
  flags. Code runs the command. Jev does not invent flags that the
  CLI does not have.
- **Composite Score** for "agent-solvability" to sort a fan-out.
  Weights stay in code. Do not replace `calculate_roi`.

### 5.3 Skeleton / first C (the expensive LLM)

`rebrew skeleton` + `rebrew decompile` / Ghidra / `--seed-llm` write
C. Jev cannot.

**Jev as the SDE-cascade verifier around that LLM:**

1. Cheap/local LLM (or Ghidra) emits a body.
2. One `system_one` call, Noul battery: C89? undeclared ident?
  invented VA / offset? looks like CRT? contradicts `rebrew asm`
  call skeleton? violates `goal.md` (asm / naked / library)?
3. Any fire → drop or escalate to a bigger LLM. None fire →
  `rebrew test`. Schema-valid C that is still wrong is the whole
  point of that cookbook (their mini extract fit JSON Schema and
  was fabricated).

**Pre-parsed extraction** for constants: regex/Capstone over the
disasm for immediates and strings, Jev Choice picks which candidate
is "the timeout" / "the table count". Code copies the span.
Never let Jev emit a hex literal.

**Structure recovery** (autoformat cookbook) is the closest they
have to "decompile": Noul "does this line continue the previous
statement?" + Choice of block kind, then **code** renders. Useful
as a Ghidra-dump cleaner in front of `rebrew fix`, not as a C
writer. Words stay from the input.

### 5.4 Test / diff / near-diag (the loop)

`rebrew test` / `diff` / `near-diag` / `gap-trace` / `residue` are
the source of truth. Do not re-predict `matched` from prose.

Jev after those JSON blobs, only when the byte class is ambiguous
(`structural` / `equivalent`):

- **Next-tool Choice** — [§3.1](#31-next-tool-choice). Same shape as
  the smart-home demo: speculative questions for GA / prove /
  flag-sweep / lib-match in one call; code ignores the irrelevant.
- **Pattern family Choice** — [§4](#4-codegen-pattern-choice).
  Hierarchical: family → numbered shape. Semantic-find's "Choice
  over line ids" is literally "which `msvc6-c-shapes.md` heading
  explains this delta", with an `exists` Noul for "none of these /
  ceiling".
- **Citation check** on the agent brief against the shape /
  allocator paragraph it cites. This is the inverted-`volatile`
  trap, productized.
- **RAG-passage classifier** on whatever context an LLM is about
  to see: keep the finding, flag a contradiction, drop a
  prompt-injection-shaped "ignore the catalog". `rebrew similar`
  / `describe` chunks are the corpus; BM25/`similar` is the
  shortlist; Jev re-ranks (their legal re-rank: top-1 5% → 18%).
- **Consistency**. If origin / blocker / family labels flip across
  repeats, treat as low confidence and fall back to `todo`. Pin
  `jev-1.13.0`.

Skip Jev when `near-diag` already says `register` / `encoding` /
`reloc`. The mutation table and `rebrew prove` own those.

### 5.5 Match / GA / prove

GA and angr are search. Jev does not search.

Optional prior, not a replacement:

- Choice of `--mutation-focus register|equivalent|structural`
  (already a flag). Same family Choice as §4.
- Noul: "is this a GRA / encoding ceiling?" → `rebrew blocker set`
  and stop, instead of another 200 generations. guild-rebrew
  burned rounds here.
- Do not rank 128 `mut_*` ops. Do not pick CFLAGS (flag-sweep
  owns that; `diagnose` traces resolution).

### 5.6 Data / BSS / types / Ghidra

`rebrew data`, `calibrate-bss`, `recover-structs` are layout math.
Jev does not invent offsets.

Leftovers:

- **Dispatch / vtable vs data** when the byte classifier is unsure
  (Choice over `rebrew data --dispatch` candidates).
- **Entity alignment** for Ghidra name vs local name vs
  `cross-import` from `server.dll` onto `Europa1400Gold_TL.exe`:
  merge / leave / curator. Merge is the expensive mistake — three
  Score levels, no fitted threshold, companion Nouls naming the
  disagreeing field.
- **Type-conflict triage** (`rebrew lint` W016 etc.): Choice of
  which TU's declaration wins, confidence-gate to a human.

Sync itself (`rebrew sync --push/--pull`) stays BinSync. Apply a
chosen name with `rebrew rename`, never by editing strings. See
[§5.10](#510-naming-and-folders-llm-proposes-jev-picks).

### 5.7 Verify / lint / round-trip / link

`rebrew verify`, `lint`, `round-trip`, `residue`, postlink are
gates. They already fail closed. Jev adding a second opinion on
"is this EXACT" is duplicate cost.

The one leftover: **stale-blocker Noul** over the
NEAR_MATCHING pile before a human reads it (round 186: 11/19
stale). That is catalog hygiene, not a substitute for `verify`.

### 5.8 Agent harness (cross-cutting)

This is TypeSafe's "harness engineering" pitch, and the only
layer that should see Jev on every turn:

| Check | Cookbook | Action |
| ----- | -------- | ------ |
| Which skill | skill suggestion | load at most one |
| Which CLI | function calling / intent | run it |
| May this LLM patch land | guardrails + citation check | reject on C89 / asm / library / inverted brief / `src/` scratch |
| Was the LLM extraction fabricated | SDE cascade | drop / escalate |
| Which catalog paragraphs to inject | RAG passage + re-rank | keep / flag / drop |
| Stop and document | ceiling Noul | `blocker set`, no more generations |

Speculative fan-out: ask all of those in **one** `system_one` call
with the function JSON. Code reads the relevant answers. Parallel
questions cookbook: 13-in-1 was 12.2× cheaper and 10.0× faster
than 13 calls, answers unchanged.

### 5.9 What still never fits

- Any stage whose output is C, ASM, a fresh identifier, a comment,
  a commit, or a VA / offset / CFLAGS literal. A small LLM may
  *propose* identifiers; Jev only *picks* among a closed candidate
  list — [§5.10](#510-naming-and-folders-llm-proposes-jev-picks).
- Any stage whose output is already a number from the compiler
  (`test`, `residue`, `near-diag` category, FLIRT hit, ROI).
- Autoresearch-style "let an LLM invent new questions, train
  CatBoost on Jev answers" — interesting once there is a labeled
  NEAR_MATCHING slice, not before. YAGNI until §6 has data.

### 5.10 Naming and folders (LLM proposes, Jev picks)

Jev still cannot emit `gm_AllocSpieler`. Open vocabulary is the
LLM's job. The SDE-cascade cookbook is the whole pattern: small
model extracts, Jev verifies / selects, code applies, escalate
when confidence is low.

guild-rebrew already has the closed sets this needs
(`docs/naming_conventions.md`):

- **Tree** attested from `__FILE__` / PDB: `DieGildeAddOn/{command,game,loadsave,auxillary}/…`, `Units/{Error,m_alloc,net,vfs}/…`.
- **Module prefixes**: `cm_ gm_ lb_ ahm_ gv_ sim_ amt_ ls_ plt_ m_ vfs_ srv_`.
- **Shape**: `prefix_VerbNoun`, German nouns (`Objekt`, `Spieler`, `Aemter`), English verbs. `cm_Chk*` / `cm_Ex*` are a two-phase pair.
- **CU clusters** from `rebrew graph --cu-map` (contiguous `.text` + calls). The map does not name files.

A project without `__FILE__` strings has a weaker tree (CU clusters
only). Do not invent folders; stop at "this cluster is one TU".

#### Function / file names

1. **Candidates from evidence, not from the model.** Debug strings,
   log format strings, PDB, Ghidra labels, already-renamed callees,
   the prefix table, `rebrew similar` siblings. Regex over those
   spans (pre-parsed extraction). The small LLM may *add* 3–5
   `prefix_VerbNoun` guesses constrained to attested prefixes and
   the German/English lexicon in that doc — it does not get a blank
   page.
2. **Jev Choice** over that shortlist, plus `none` / `human`.
   Companion Nouls: does the prefix match the CU's attested module?
   Does a `cm_ChkX` exist without `cm_ExX` (or the reverse)?
   Entity-alignment Score if Ghidra and local already disagree:
   merge / leave / curator. Merge is the expensive mistake.
3. **Confidence-gate.** High → `rebrew rename`. Low → leave
   `FUN_…` / the skeleton name. Classification-with-confidence:
   if the leaf name is unsure, keep the prefix (`gm_*`) and stop.
4. **Never** let Jev or the LLM write the identifier into a `.c`
   file. `rebrew rename` is the only mutator (xrefs, metadata,
   filename).

Locals, struct fields, globals: same cascade, smaller lexicon.
Candidates = debug strings + `rebrew data` labels + field names
already used in this CU + Ghidra. Jev picks among those. A
plausible English local (`playerCount`) that appears in no
evidence stays `i` / `p` until evidence shows up. German
attested nouns beat English guesses (`nSpieler` over
`playerCount` if the CU already uses `Spieler`).

#### Folder / TU reconstruction

Two layers. Do not mix them.

**Layer A — which functions share a `.c` (deterministic).**
`rebrew graph --cu-map` + `rebrew merge-sweep`. Jev does not
split or merge TUs; a wrong merge moves every later symbol.

**Layer B — what to call that TU / which attested directory it
lives in (semantic).** Hierarchical classification's codebase
tree is this: beam of Choice down
`D:\Develop\` → `DieGildeAddOn` vs `Units` → `game` vs `command`
→ `spiel.c` vs `aemter.c`. Options at each node are the attested
paths plus `unknown`. Low confidence → stop at the parent
(`game/`, not a guessed `inventory.c`).

Semantic-find over `__FILE__` strings: Choice of which debug
path this cluster belongs to, plus an `exists` Noul for "no
string names this TU". Entity-alignment if two clusters both
want `spiel.c`: merge / leave / curator.

Apply with `rebrew rename` / a move of the `.c` onto the
attested relative path. Do not create directories that
`naming_conventions.md` does not list.

#### What the small LLM is for

| LLM writes | Jev decides | Code does |
| ---------- | ----------- | --------- |
| 3–5 `prefix_VerbNoun` guesses from strings + prefix table | pick one or `none` | `rebrew rename` |
| "this CU feels like inventory" | Choice among attested files (`spiel.c`, `aemter.c`, …) | move the file |
| local-name guesses from a Ghidra dump | pick among spans the dump / `data` already contains | edit via rename / a structured locals field |
| nothing (no evidence) | `none` / human | leave `FUN_` / `i` |

The LLM never sees a blank "name this function" prompt. Every
guess is grounded in a retrieved string or an attested prefix.
That is [PRINCIPLES.md](PRINCIPLES.md) §9 (RAG over hallucination)
applied to identifiers. Jev is the verifier that the guess is in
the closed set and fits the CU.

If the small LLM is already Ghidra/`--seed-llm` for the body,
reuse that call: ask it for a candidate *list* in the same
response, then one `system_one` over those names. Do not add a
second LLM just for naming.

Skip this cascade when the name is already attested (FLIRT,
export, PDB, `__FILE__` leaf). Those are facts, not guesses.

### 5.11 More contracts

Same three primitives. Each row: closed options, state, action
the surrounding code takes. None of these emit C or a fresh
identifier. Skip any row whose answer is already a number from
`test` / `near-diag` / FLIRT / `cu-map`.

#### Clone / family (intake + start-function)

`rebrew similar` ranks STUBs by CFG against a solved function.
That rank is structural, not semantic. Jev re-ranks the top 10
the way the legal re-rank cookbook re-ranks BM25.

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `same_family` | Score: `clone` / `cousin` / `unrelated` | `clone` → copy the solved `.c` and retarget VAs; `cousin` → skeleton + steal helpers; `unrelated` → ignore `similar` |
| `seed_from` | Choice of those 10 + `none` | `--seed-file` / `--seed-solved` for GA; do not copy if `none` |

State = solved source header + STUB `describe --json` (callers,
callees, strings). Pairwise, not all-vs-all.

#### Statement order vs spelling (the guild win pattern)

guild-rebrew TODO: every landed residue win in rounds 254–431 was
a statement/definition **order** change. No spelling change
landed. Probes that changed spelling were reverted.

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `edit_kind` | Choice: `move_block` / `change_spelling` / `volatile_site` / `ceiling` | `move_block` → diff top-level block order against `rebrew asm` (shapes §84 method) and move statements; `change_spelling` → only if `near-diag` is `equivalent`; `ceiling` → `blocker set`, stop |
| `worth_linktest` | Noul | Queue for serialized `linktest` only if high; object `matched`/`aligned` lie (measure-traps §1–2) |

State = `diff --json` hunk list (block ids, not bytes) + current
`.c` outline (function-level statements, no bodies).

#### Wall detector (stop the loop)

codegen-walls.md is a closed list. Ask it *before* another 200
GA generations or a volatile sweep.

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `wall` | Choice: `gra` / `epilogue_merge` / `volatile_site` / `add_vs_lea` / `flag_inert` / `none` | not `none` → `blocker set` with that wall, skip GA |
| `epilogue_fold` | Noul: N ref rets vs 1 obj ret, bodies identical | shapes §74 / walls §2 — stop |

State = `near-diag` category + ret-count from `asm --json` +
blocker text. Deterministic ret-count first; Jev only when the
counts are messy.

#### Shared-type lift (data / types round)

goal.md: lift shared layouts into `rebrew_types.h` /
`game_structs.h` / `game_common.h`. `types.h` is Ghidra-pulled,
never final. Duplicate `LNK4006` is a finding, not a `/FORCE`.

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `lift_to` | Choice: `rebrew_types.h` / `game_structs.h` / `game_common.h` / `stay_local` / `human` | stay_local if one TU; human if two headers fit |
| `same_layout` | Noul on a candidate pair of struct defs | high → propose lift; code still checks `sizeof` against the binary |

State = both typedef texts + `sizeof` + list of TUs that include
them. Jev does not invent a field name (that's §5.10).

#### String → owner

`"name(): …"` log strings are the attested naming method. RevEng
attribution was wrong twice; confirmation is `push` of the
literal in the owner's disasm (IDEAS-GUILD).

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `owner` | Choice of functions whose window contains the immediate, plus `none` | `none` → leave unattributed; else a naming candidate for §5.10 |
| `verified_push` | Noul | low → do not use this string as a name source |

Candidates from Capstone/asm, not from Jev (pre-parsed
extraction). Jev only picks the owner.

#### Data-edit danger

AcceptConnections rounds 518/520: local 0 diffs, gate `.text`
+180 from COMDAT literal emission.

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `churns_text` | Noul | high → refuse the data-only commit until a link-test slot exists |
| `edit_scope` | Choice: `safe_data` / `needs_linktest` / `touches_comdat` | queue / skip |

State = `rebrew data --json` diff + which TUs reference the
symbol. Not a substitute for measuring; a prefilter on the
serialized link-test queue.

#### Decompiler backend / seed policy

`rebrew decompile` has kuna / r2ghidra / ghidra. `--seed-llm` is
optional. Pick the expensive path only when the cheap one is
hopeless.

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `decomp_backend` | Choice: `kuna` / `r2ghidra` / `ghidra` / `skip` | `rebrew decompile --backend …` |
| `seed_policy` | Choice: `none` / `seed_solved` / `seed_llm` / `both` | flags on `rebrew match` |

State = size, `near-diag`, whether a solved sibling exists,
whether `[llm]` is configured. Skip `seed_llm` when
`llm_worth_it` from §3.2 is low.

#### Agent-brief compiler (before dispatch)

workflow-traps §1: a brief inverted shapes §52 (`volatile`); 14
probes refuted the brief. File-ownership collisions. Scratch in
`src/`.

One `system_one` over the draft brief + the cited shape
paragraph + `list_agents` file claims:

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `brief_inverts_docs` | Noul | high → do not launch; rewrite |
| `cites_wrong_shape` | Choice of shape headings + `none` | citation-check cookbook |
| `file_collision` | Noul | high → wait; code also diffs the running set (do not trust Jev alone here) |
| `probe_in_src` | Noul | high → reject; probes go in `.scratch/` |
| `asks_linktest` | Noul | high → strip that step; agents cannot link-test |

The file-collision Noul is advisory. The deterministic
`list_agents` diff is the gate.

#### Commit / gate readiness

`scripts/gate.sh` is the real gate. Jev as a pre-hook on the
commit message + named paths, not a replacement.

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `named_paths_only` | Noul | low → refuse `git add -A` (workflow-traps §1) |
| `measured` | Noul | low → refuse; every kept edit was link-tested |
| `residue_claim` | Choice: `improves` / `neutral` / `unmeasured` | `unmeasured` → refuse; `improves` still needs `gate.sh` |
| `note_stale` | Noul on each `NOTE` / blocker in the diff | high → `blocker` refresh before commit |

#### Finding-home router

IDEAS-GUILD "finding router": one finding, one home, discipline
only.

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `home` | Choice: `msvc6-c-shapes` / `msvc6-allocator` / `codegen-walls` / `measure-traps` / `workflow-traps` / `naming_conventions` / `TODO` / `drop` | append with VA + delta template; `drop` if not a finding |

State = the probe log + whether `rebrew test` confirmed it.
Do not invent a new doc.

#### Human interrupt / loop detector

Score on the last N agent turns for one VA (commands run, STATUS
unchanged, residue flat).

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `progress` | Score: `moving` / `flat` / `regressing` | `flat` after a threshold → `blocker set` + human; `regressing` → revert the last unmeasured edit |
| `solvability` | Score: `human_only` / `agent_with_skill` / `cheap_batch` | same as §3.1; demote the VA on the fan-out |

State = the turn log (CLI names + exit codes + deltas), not the
C. Consistency cookbook: if this Score flips across repeats,
treat as `human_only`.

#### Cross-target import

`server.dll` vs `Europa1400Gold_TL.exe` share game logic. ADR 009
`cross-import` already copies a matched body to a new VA.

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `same_function` | Score: `merge` / `leave` / `curator` | `merge` → `rebrew cross-import`; `leave` → independent; curator if calling convention / CU differs |
| `prefix_ok` | Noul: client prefixes (`ch_ ai_ he_ d2_ …`) used on a server symbol | high → reject the name (goal.md: never reuse client prefixes) |

Entity-alignment cookbook exactly. Merge is the expensive
mistake.

#### Switch / calling-convention leftovers

Only when `rebrew switch` / `stack-cmp` did not already label it.

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `dispatch` | Choice: `jump_table` / `if_cascade` / `call_table` / `unknown` | jump_table → `rebrew switch`; unknown → human |
| `conv` | Choice: `cdecl` / `stdcall` / `fastcall` / `thiscall` / `unknown` | write `CALLING` only on high confidence; stack-cmp remains the check |

### 5.12 Shared envelope

One script, four *modes*. Same HTTP call, different question
packs. Never a rebrew subcommand until §6 wins.

```
state = {
  mode,                    // function | catalog | brief | commit
  function: { va, name, size, status, delta, near_diag, blocker,
              cflags, toolchain, filename, prefix? },
  evidence: { hunk_summary, describe, similar_top10,
              strings_in_window, cu_cluster, cited_docs[] },
  source_head,             // first ~2k of the .c, truncated
  llm_candidates[]         // optional; names / files / backends
}
questions = pack_for(mode) // always many, one request
```

**Packs** (all questions in the pack go in one call):

| Mode | When | Pack |
| ---- | ---- | ---- |
| `function` | after `test`/`near-diag` on one VA | next_tool, pattern_family, llm_worth_it, edit_kind, wall, seed_policy, same_family, solvability |
| `catalog` | batch over NEAR_MATCHING / STUB / start-data | lib leftover, blocker_stale, origin, lift_to, owner, churns_text |
| `brief` | before launching an agent | brief_inverts_docs, cites_wrong_shape, file_collision, probe_in_src, asks_linktest, skill |
| `commit` | before `gate.sh` | named_paths_only, measured, residue_claim, note_stale |

**Action table** (code, not Jev):

```
if answer.confidence < T_act: follow rebrew todo / human
elif noul > T_yes or choice in AUTO:
    run mapped CLI (rename, blocker set, decompile, cross-import, …)
elif choice == skip/ceiling/human or noul in (T_no, T_yes):
    record and stop
```

Pin `jev-1.13.0`. Log `(va, mode, question, choice, confidence,
todo_command, action_taken)`. Thresholds start conservative
(`T_act ≈ 0.7`, `T_yes ≈ 0.8`) and only move after the labeled
week in §6.

Token budget: keep `state` under ~8k tokens. Truncate `.c`.
**No raw asm / hex / residue integers as the thing Jev must
compare** (jaggedness 2 / 2b / 5). Cited docs = the 3–5
shape/allocator blurbs the RAG-passage classifier already kept,
not the 167-entry file. Convert counts in code; send named
buckets (`delta_band: small|medium|ceiling`).

Failure: HTTP 429 → empty answers, follow `todo` (same as
`llm_seed.py` on 429). Never block the compile loop on Jev
being down.

High-stakes actions (`rename`, `cross-import` merge, `ceiling`
blocker, lift a shared type): optional second call with a fresh
`uid` (consistency cookbook). Mean σ on TypeSafe Nouls was
~0.01; if the two calls disagree on the *choice*, treat as
human. Do not average Scores to invent a byte count.

### 5.13 Deeper bounds and extra help

Research pass over jaggedness, advanced structured criteria,
consistency numbers, `behavioral-verdicts.md`, Relumea PRDs 02/03.
This pass *removes* more than it adds.

#### What this pass kills

- Sending `rebrew asm` / hex dumps / opcode listings as Jev
  state. TypeSafe: high-level language and English beat
  assembly and binary. `near-diag` already turned bytes into a
  category; that category is the input.
- Asking Jev to count residue, ret-sites, `matched`, immediates,
  or `sizeof`. Counting is jaggedness 2. Code tallies; Jev
  judges a *named* candidate.
- Reconstructing a delta from a Score (interpolation). Threshold
  only.
- One Noul that is the negation of another, then summing to 1.
  Ask each fact one way.
- Fat state: whole `msvc6-c-shapes.md`, whole function body,
  whole `diff --json`. Filter in code; 3–5 blurbs.

The statement-order vs spelling Choice in [§5.11](#511-more-contracts)
still holds if the state is an English outline of top-level
blocks, not the listing.

#### Behavioral verdict (Clean vs live bug vs wall)

guild-rebrew `docs/behavioral-verdicts.md`: 19 largest residue
carriers, read-only C-vs-reference review that **ignored** GRA /
scheduling / spill (those are walls). Verdicts: live bug, clean,
fixed. `gm_AllocSpieler` slot[9] is a live bug whose correct
fix is unlandable (+393 linked). That distinction is semantic,
not a byte count.

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `verdict` | Score: `live_bug` / `codegen_wall` / `clean` / `unlandable` | `codegen_wall` / `clean` → stop; `unlandable` → `blocker set` with the measured cost; `live_bug` → allow a C edit |
| `same_behavior` | Noul on two English cards (C stores/bounds/calls vs reference stores/bounds/calls) | low → the cards disagree; do not call it clean |

State = two short English *behavior cards*, produced by a small
LLM from C and from Ghidra/`asm` **in English** ("else stores 0
into slot[9]"; "reference stores (char)arg8"). Jev never sees
the listing. Citation-check cookbook. This is the only honest
way to ask "is this residue a bug" without pretending Jev can
read x86.

#### Relumea personas → one router

PRD 02 wants Architect / Type Theorist / Linguist / Critic as
four LLM agents. That is the thing TypeSafe's intent-routing
cookbook exists to collapse.

| Persona | Already a Jev pack | LLM still needed? |
| ------- | ------------------ | ----------------- |
| Architect | origin / CU / folder Choice (§5.1, §5.10) | no |
| Type Theorist | `lift_to` / `same_layout` (§5.11) | only to propose a field-name candidate list |
| Linguist | naming cascade (§5.10) | yes, 3–5 guesses |
| Critic | SDE cascade + guardrails + `verdict` | no, except the behavior-card writer |

`reagent` already has `skip` / `ga_only` / `llm_then_ga` /
`llm_only` / `flag_sweep_first`. Jev Choice *is* that enum.
Do not stand up CrewAI. Knowledge-graph RAG (PRD 03) is the
filter that keeps state small (jaggedness 5): Cypher/`describe`
first, Jev second.

#### Structured criteria (advanced primitive)

Choice options may be JSON trees, not flat strings
([advanced](https://docs.typesafe.ai/primitives/advanced.md)).
Use that for:

- **Prefix table** as option values `{prefix, file, domain, verbs[]}`
  so "is this `gm_` or `sim_`" sees the attested file, not just
  the letters.
- **CU tree** as nested criteria (`DieGildeAddOn.game.spiel.c`)
  — hierarchical classification without a second hop
  (jaggedness 4: reduce hops).
- **Shape family** as `{family, example_hunk, do, dont}` so
  literal-reading (jaggedness 1) gets the boundary in
  `criteria`, not in a hope the model infers it.

Do **not** stuff 167 shapes into one tree. Beam 8–12 families,
then a child Choice.

#### Nightly catalog map-reduce

TypeSafe's "map-reduce over big data" pitch is the one that
fits a 6k-function binary. At `$0.042 / MTok`, 400 leftover
NEAR/STUB rows × ~2k input tokens ≈ 0.8 MTok ≈ **$0.03** plus
free output. That is cheaper than one codegen-LLM call.

Catalog-mode pack ([§5.12](#512-shared-envelope)) over the pile:
origin, blocker_stale, lib leftover, `llm_worth_it`,
`solvability`, `verdict`. Write a JSONL side file. Humans and
`todo` read it. Do not promote STATUS from it.

Consistency: TypeSafe Noul σ ≈ 0.01 on repeats. Trust a
*stable* catalog label more than an LLM that flips at
temperature 0. Still pin `jev-1.13.0` and log wobble.

#### Comment / NOTE / Ghidra-text hygiene

Same citation-check as briefs. State = current `.c` head + the
`NOTE` / Ghidra comment.

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `note_kind` | Choice: `measured` / `theory` / `stale` / `inverted` | `stale`/`inverted` → `blocker` refresh; `theory` → do not treat as a wall |
| `comment_matches_c` | Noul | low → do not sync that comment to BinSync |

Adversarial content (jaggedness 6): a Ghidra comment can argue
"this is CRT, skip it". Criteria must say the comment is data,
not an instruction.

#### Inline-asm / naked prelude (constraint cost)

codegen-walls §6b: memcpy/zero-fill prelude that C cannot emit.
goal.md forbids asm unless attested.

| Question | Options / type | Action |
| -------- | -------------- | ------ |
| `pure_c_impossible` | Noul on an English description of the prelude ("alignment-prefixed copy the compiler never emits") | high → `blocker set` / keep documented `__asm`; do not spawn LLM |
| `attested_asm` | Noul: is there a string/symbol that the original used raw asm here? | low → convert `_emit` dumps back to C (goal.md) |

State = the blocker text + a 10-line English summary, not the
bytes.

#### What still looks tempting and is still a no

- Jev as a second `near-diag`. Bytes already classified.
- Jev as a residue oracle. Counting.
- Jev as a calling-convention reader from a listing. `stack-cmp`
  first; leftover Choice only on an English "callee pops N bytes"
  card the LLM wrote.
- Jev as Ghidra. Generation.
- Four Relumea LLM personas in parallel. Route with Jev, run at
  most one LLM.
- A whole-binary (or whole-function) disassembly dump as Jev
  state — [§5.14](#514-disassembly-as-state).

#### 5.14 Disassembly as state

The API will accept it. `state` is a string, JSON object, or array
of text. A Capstone/`objdump` listing is text. That is not the
same as "Jev is good at it."

TypeSafe jaggedness 2b, quoted in spirit: questions about
high-level languages outperform questions about low-level
assembly or binary-encoded instructions. Hex immediates and
opcode bytes are the color-as-`#rrggbb` case — convert in code,
ask the judgment.

What "simple" has to mean, or it is a no:

| Input | Jev? | Why |
| ----- | ---- | --- |
| PE / ELF bytes | no | not text; and the useful bits are headers `detect` already parsed |
| `objdump -d` of the binary | no | fat state (jaggedness 5) + counting idioms (jaggedness 2) + asm (2b) |
| Full `rebrew asm <VA>` listing | no | same; `near-diag` already classified the bytes |
| 8–20 **English idiom lines** code already counted | leftover only | "142 `rep movs/stos`; 94 `push ebp; mov ebp,esp`; 16 `mov edi,edi` 2-byte nops; both `/O1` push-`[mem]` and `/O2` load-first wrappers" — that is `toolchain detect` evidence, not a listing |
| One **English behavior card** for one function ("else stores 0 into slot[9]") | yes | §5.13 verdict; a small LLM wrote the card from C/`asm` |

guild-rebrew already measured the detector limit
(`general-knowledge.md`): `rebrew toolchain detect` on
`server.dll` returns `"confidence": "high"` while `version_hint`
says "may be MSVC 4.x/5.0" and evidence includes **5 pre-6.0
constant-hoist sites**. It cannot split SP0–SP6. Nine local
MSVC6 images collapse to **three real generators** (base /
`sp5-pp` / `sp6`). A Jev Choice over `{msvc-6.0, msvc-6.0-sp6,
msvc-6.0-sp5-pp, unknown}` on that *evidence JSON* is the
leftover. Sending the `.text` listing will not invent the Rich
header (`C1 9782` = SP6) that `detect` already reads.

Per-function "which flags / which SP pin": same rule. Code
counts the idioms (`push [mem]` vs `mov eax,[mem]; push eax`,
`rep stos`, `lea esp,[esp]`). Jev Choice over a **short**
option list (`/O1`, `/O2`, `/O2 /Oy`, `sp5-pp`, `unknown`)
given those counts as named buckets. Not the listing.

If you still want to try a snippet: cap it. One prologue + one
epilogue + one memcpy-shaped loop, **mnemonics as words**, no
hex, no addresses, no whole `.text`. Treat it as an A/B against
`detect --json` on a labeled set of binaries. If Jev's Choice
does not beat `suggested_profiles` + Rich-header pin, delete
the listing path.

Default: `rebrew toolchain detect --json` is the compiler ID.
Jev only when that JSON already disagrees with itself.

#### 5.15 jevopt and the reverse (Jev as compiler advisor, rebrew as Jev oracle)

[jevopt](https://github.com/Ramneet-Singh/jevopt) (reviewed 2026-09-21)
is the forward direction this note deliberately avoids: a C/C++ compiler
driver that puts Jev inside the optimization loop. At every
discretionary call site, a Clang 21 / `-Oz` LLVM plugin sends Jev the
caller/callee IR, the original source, build context, and 7 structural
facts; Jev returns a typed two-way `Choice` (`inline` / `do_not_inline`)
through a FIFO channel, and the trace (state, probabilities, decision,
hashes) lands in `result.json`. The released `jevopt-embench` run
(`jev-1.13.0`, all 19 Embench 1.0 programs, `.text` bytes, no LTO) beats
Clang `-Oz` on 7/19 programs — including statemate at −58.20% — ties on
2/19, loses on 10/19, geometric mean **+7.87%**. The author's own
conclusion matches §4 here: keep the prompt small and fixed, withhold
the compiler's suggested answer to avoid bias, and treat per-program
wins as real even under an aggregate loss (ship the smaller of the two
binaries). Jev outputs are stochastic run to run; the released
`runs/jevopt-embench` traces are the pinned evidence.

The reverse is what rebrew can offer Jev: an objective, deterministic
reward signal Jev normally lacks. Every Jev codegen-family Choice in
[§4](#4-codegen-pattern-choice) bottoms out in `rebrew test` byte
comparison — `EXACT` / `NEAR_MATCHING` plus delta — instead of a second
model's opinion. Candidate C rewrite → compile → measured delta scores
the Choice that proposed it. That closes the loop jevopt leaves open
(stochastic answers, no ground truth beyond `.text` size) and obeys
this note's standing rules: code counts, Jev judges a named candidate,
state stays a short English card rather than IR/ASM.

Two concrete assets transfer directly:

- `runs/jevopt-embench` decision traces as a prior on which inline
  decisions move size (inline-vs-call is one more shape family in the
  §4 beam, alongside loop form / addressing / live-range / flags).
- [corpus.json](codegen/corpus.json) (17938 per-function byte records
  across toolchains/flags) as a labeled eval set: ask a Jev Choice over
  a short option list given counted idiom buckets, score against the
  recorded bytes. Same A/B bar as §5.14 — if the Choice does not beat
  `detect --json` + Rich-header pin on a labeled slice, delete it.

## 6. Lazy experiment (guild-rebrew only)

One script. No rebrew package change. No new CLI.

1. `rebrew todo --json` + per-item `near-diag --json` + blocker.
2. One `system_one` call, many questions (next-tool + pattern family +
   the Noul prefilters in [§3.1](#31-next-tool-choice)–[§3.2](#32-do-not-spend-an-llm-on-junk)).
3. If `next.confidence` is at or above a threshold, print that command.
   Else print the current todo command.
4. Log disagreement vs `near-diag` / `todo` for a week on a labeled
   slice of NEAR_MATCHING.

Keep the script only if it catches lib-shaped / stale-blocker /
"don't LLM this" / inverted-brief cases that `todo` misses. If it
echoes `near-diag`, delete it.

Promote a family list into `near-diag` or a `reagent` pre-router only
after those labeled wins. Do not add `typesafe-sdk` to rebrew until
then.

Sketch of the questions (criteria text is the contract; keep it in the
script, not in rebrew):

```json
{
  "next_tool": {
    "type": "choice",
    "instructions": "Which tool should run next for this NEAR_MATCHING function?",
    "criteria": {
      "edit_c": "C shape wrong; rewrite source",
      "flag_sweep": "flag-sensitive, same C",
      "ga": "small encoding/register delta, GA can search",
      "prove": "register/encoding only; byte identity not required",
      "lib_match": "looks like CRT/ZLIB/stock lib",
      "skip": "documented ceiling / naked / library"
    }
  },
  "pattern_family": {
    "type": "choice",
    "instructions": "Which MSVC6 codegen family explains the remaining delta?",
    "criteria": {
      "loop_form": "for/do/while / post-decrement / early return",
      "addressing": "scale, ptr vs array, folded offset",
      "live_range": "GRA / first-use order / flag in dl vs bl",
      "volatile_order": "load/store pinning, folded cmp hiding a load",
      "opt_flags": "/O1 vs /O2 / /Oi / Oy",
      "fpu": "fimul vs fild+fmulp, _ftol vs (int)",
      "memcpy_loop": "inline memset/memcpy vs C loop",
      "ceiling": "unreproducible from C; document and stop"
    }
  },
  "llm_worth_it": {
    "type": "noul",
    "instructions": "Would spending a codegen LLM on this function likely move STATUS?"
  },
  "brief_inverts_docs": {
    "type": "noul",
    "instructions": "Would the proposed C change invert a documented MSVC6 shape?"
  }
}
```

## 7. Sources

- TypeSafe docs: <https://docs.typesafe.ai/introduction.md>
- Index: <https://docs.typesafe.ai/llms.txt>
- Sitemap (18 cookbooks + patterns + demo, 2026-09-18): <https://docs.typesafe.ai/sitemap.xml>
- Announce: <https://typesafe.ai/blog/introducing-system-one-models-and-jev>
- Models: <https://docs.typesafe.ai/models.md> (`jev-1.13.0`, alias `jev-latest`)
- Use-case map (harness engineering): <https://docs.typesafe.ai/concepts/use-case-map.md>
- Patterns: <https://docs.typesafe.ai/patterns.md>
- Cookbooks used in [§5](#5-end-to-end-decomp-map): skill suggestion, intent routing, hierarchical classification, classification+confidence, re-rank, semantic find, RAG passages, function calling, SDE cascade, LLM guardrails, citation check, entity alignment, pre-parsed extraction, structure recovery, parallel questions, composite scoring, consistency, smart-home demo
- Jaggedness (binds §2 / §5.13): <https://docs.typesafe.ai/model-jaggedness/jev-1.13.md>
- Structured criteria: <https://docs.typesafe.ai/primitives/advanced.md>
- Consistency Noul σ ≈ 0.01: <https://docs.typesafe.ai/cookbooks/consistency_noul_cookbook.md>
- API: `POST https://api.typesafe.ai/v1/systemone`, pin `jev-1.13.0`
- SDK: `uv add typesafe-sdk` / `pip install typesafe-sdk`
- Playground: <https://console.typesafe.ai/playground>
- Agent skill: <https://docs.typesafe.ai/agent-skill.md>
