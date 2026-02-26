# Rebrew Tooling Improvement Ideas

Ideas collected during hands-on workflow testing in guild-rebrew, prioritized by impact.

---

## Prioritized Ideas

| # | Idea | Impact | Effort | Priority |
|---|------|--------|--------|----------|
| 3 | [CRT source cross-reference tool](#3-crt-source-cross-reference-tool) | 🔴 High | Medium (2–3 days) | **P0** |

---

## Idea Details

### 3. CRT source cross-reference tool

**Pain**: Identifying which CRT source file a function came from requires manual search through `tools/MSVC600/VC98/CRT/SRC/`.

**Proposed**: `rebrew-crt-match 0xVA` — given a VA, search the MSVC6 CRT source for likely matches based on function size, call graph, and string references. Rank candidates by similarity.

**Impact**: CRT functions are verbatim copies of the reference source. Automating the lookup saves significant manual research time on ~100 MSVCRT-origin functions.

---
