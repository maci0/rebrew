# Jev (TypeSafe System One) — research notes

Research captured **2026-09-18** from TypeSafe's public docs and the
guild-rebrew campaign. Complements [PRINCIPLES.md](PRINCIPLES.md) §9–10
(RAG over hallucination; AI as a baseline, not a finisher),
[`llm_seed.py`](../src/rebrew/llm_seed.py), and the guild catalogs in the
sibling `guild-rebrew` checkout.

This is not a shipped feature and not an ADR. Promote a piece of it to
[IDEAS-GUILD.md](IDEAS-GUILD.md) / ROADMAP only after the experiment in
[§5](#5-lazy-experiment-guild-rebrew-only) beats `rebrew todo` on a
labeled slice.

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
- Input `$0.042 / MTok`; output tokens free.
- Model id `jev-latest`. HTTP: `POST https://api.typesafe.ai/v1/systemone`.
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

## 5. Lazy experiment (guild-rebrew only)

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

## 6. Sources

- TypeSafe docs: <https://docs.typesafe.ai/introduction.md>
- Index: <https://docs.typesafe.ai/llms.txt>
- Announce: <https://typesafe.ai/blog/introducing-system-one-models-and-jev>
- Use-case map (harness engineering): <https://docs.typesafe.ai/concepts/use-case-map.md>
- Patterns: <https://docs.typesafe.ai/patterns.md>
- API: `POST https://api.typesafe.ai/v1/systemone`, model `jev-latest`
- SDK: `uv add typesafe-sdk` / `pip install typesafe-sdk`
- Playground: <https://console.typesafe.ai/playground>
