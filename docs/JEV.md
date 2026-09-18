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

State = `rebrew asm --json` window + `rebrew diff --json` + current `.c`
+ the *short* shape blurbs for those candidates. Not the whole catalog.
Then **code** applies the rewrite or biases GA.

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
categories — those stay deterministic. Codegen, comments, names —
those stay an LLM. Jev is the cheap semantic leftover between them.

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
- **Do not** let Jev pick the compiler profile. `rebrew doctor` /
  `--guess-compiler` own that.

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

Sync itself (`rebrew sync --push/--pull`) stays BinSync. Jev does
not pick a name.

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

- Any stage whose output is C, ASM, a name, a comment, a commit,
  or a VA / offset / CFLAGS literal.
- Any stage whose output is already a number from the compiler
  (`test`, `residue`, `near-diag` category, FLIRT hit, ROI).
- Autoresearch-style "let an LLM invent new questions, train
  CatBoost on Jev answers" — interesting once there is a labeled
  NEAR_MATCHING slice, not before. YAGNI until §6 has data.

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
- API: `POST https://api.typesafe.ai/v1/systemone`, pin `jev-1.13.0`
- SDK: `uv add typesafe-sdk` / `pip install typesafe-sdk`
- Playground: <https://console.typesafe.ai/playground>
- Agent skill: <https://docs.typesafe.ai/agent-skill.md>
