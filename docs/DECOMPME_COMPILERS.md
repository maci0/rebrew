# decomp.me Compiler Infrastructure — Research Notes

Research captured **2026-08-24** from the decomp.me platform's backing
repos (see [Acquisition](#1-acquisition)).  Complements the corpus work:
decomp.me is the DM source cited throughout [codegen/RULES.md](codegen/RULES.md),
and this document records exactly what their compiler fleet contains,
how it is packaged, and how it maps to (and differs from) rebrew's own
toolchain infrastructure.

## 1. Acquisition

- **Live API is not directly scrapable**: `https://decomp.me/api/*`
  returns a Cloudflare 403 challenge to non-browser clients, and the
  `api.decomp.me` subdomain does not exist.
- **Scraped instead** the decompme GitHub org — the backing data the
  API serves:
  - `decompme/compilers` (1.3 MB, shallow) — the compiler fleet.
  - `decompme/decomp.me` (4.3 MB, shallow) — the site source (Django
    backend + Next.js frontend) with the API routes and the compiler
    definitions.
- **Location**: `third-party/decompme-api/` (sibling of the existing
  `third-party/decompedia/` practice-doc export; see that folder's
  README).
- **API surface** (from `site/backend/coreapp/urls.py`, mounted at
  `/api/`): `compilers`, `compiler`, `platform`, `library`, `search`,
  `stats`, `user`, `users/<slug>`, `healthz`.  The compiler list the
  API serves is built from `site/backend/coreapp/compilers.py`.

## 2. Docker toolchain infrastructure

decomp.me runs every compiler inside a Docker image — the same
architecture idea as rebrew, with a different runtime split:

- **Dockerfile generation**: `template.py` (Jinja2) generates one
  Dockerfile per compiler from `values.yaml` + per-platform templates
  (`templates/win32/msvc.j2`, `templates/common/default.j2`,
  `templates/ps1/psyq.j2`, …).  Generated files say "Do not edit
  manually".
- **Multi-stage build**: an `alpine` base downloads the compiler
  tarball (e.g. `msvc6.0.tar.gz` from the OmniBlade/decomp.me
  releases) and extracts it to `/compilers/<platform>/<id>`; a
  `scratch` `release` stage copies only `/compilers`.  **The final
  image is a bare compiler tree — no runtime.**
- **Distribution**: a GitHub Action builds each image and pushes to
  **ghcr.io**; decomp.me deployment pulls from the registry.
- **Runtime split vs rebrew**:

  | | decomp.me | rebrew |
  |---|---|---|
  | Image contents | bare compiler tree (scratch stage) | compiler + wine/DOSBox runtime baked in |
  | win32 compilers run under | wibo, on the sandbox side (`WATCOM_CC = ${WIBO} wcc386.exe …`) | wine inside the image entrypoint wrapper |
  | Registry | ghcr.io via GitHub Action | locally built `rebrew/msvc:*` |

  Both mount the compiler dir as a drive (`Z:` on decomp.me); rebrew
  mounts the workdir and passes `/I` include paths per version.

## 3. The fleet

- **234 compiler definitions** in `compilers/values.yaml`.
- Platforms: `win32`, `msdos`, `n64`, `gba`, `gc_wii`, `ps1`, `ps2`,
  `n3ds`, `nds`, `android_x86`, `macosx`, `dreamcast`, `common`, …
- **x86-relevant subset**: the MSVC line (below), `bcc2.0`/`bcc3.1`
  (Turbo C 2.0/3.1 — we have these as `borland-tc`), and the
  **commercial Watcom line `wcc10.0a/10.5/10.5a/10.6/11.0`** (we only
  have Open Watcom 2.0).
- The rest (MWCC/Metrowerks fleet, ARM compilers, console GCCs for
  PS1/PS2/N64/GBA/NDS/3DS, clang 3.9–9.0, PPC MSVC) is non-x86 and
  out of the corpus scope.

## 4. MSVC line and SP mapping

Display names from `site/frontend/src/lib/i18n/locales/en/compilers.json`:

| decomp.me id | Display name | Maps to our corpus |
|---|---|---|
| `msvc4.0` | Microsoft Visual C/C++ 4.0 | 4.0 missing; per decompedia MSVC.md, **4.0/4.1/4.2 are byte-identical to each other and to VC 2.0** — our 4.1 covers the codegen |
| `msvc4.1` | 4.1 | ✓ (ours: msvc 4.1) |
| `msvc4.2` | 4.2 | same as 4.1 codegen-wise (see above) |
| `msvc6.0` | 6.0 | ✓ (ours: 6.0 RTM, cl 12.00.8168) |
| `msvc6.3` | 6.0 SP3 | ✓ (ours: 6.0 SP3, 8447) |
| `msvc6.4` | 6.0 SP4 | ✓ (SP4, 8804) |
| `msvc6.5` | 6.0 SP5 | ✓ (SP5, 8966) |
| **`msvc6.5pp`** | **6.0 SP5 w/ Processor Pack** | **missing — see §5** |
| `msvc6.6` | 6.0 SP6 | ✓ (SP6, 9782) |
| `msvc7.0` | 7.0 .NET 2002 | ✓ |
| `msvc7.1` | 7.1 .NET 2003 | ✓ |
| `msvc8.0` | 8.0 | ✓ (8.0 RTM) |
| **`msvc8.0p`** | **8.0 (Patched)** | **missing — see §5** |

The 6.0 SP mapping confirms RULES.md J2: decomp.me's 6.3–6.6 split is
CRT/header-driven (each carries a different C1 build: 8168 RTM, 8447
SP3, 8804 SP4+, 8966 SP5, 9782 SP6), while our corpus verified the SP
line as **codegen-identical** across SP1–SP6 (only the 7.0 SP1 memset
shapes differ).  So our SP rows are the codegen equivalents of their
6.3–6.6 IDs.

### The `pp` / `p` variants

- **`msvc6.5pp` = "6.0 SP5 w/ Processor Pack"** — a distinct tarball
  (`msvc6.5pp.tar.gz`) from the same OmniBlade release set.  The
  Processor Pack was Microsoft's free VC 6.0 add-on that upgraded cl
  with SSE/SSE2 code generation (the `/arch:SSE`-era instruction
  support).  A separate compiler ID because the PP cl generates code
  stock 6.0 cannot (a unique era marker for SSE-capable 6.0).
- **`msvc8.0p` = "8.0 (Patched)"** — a patched snapshot of VC 8.0
  (VS2005, cl 14.00.50727) from the `widberg/msvc8.0` preservation
  repo — two different git commits: `msvc8.0` = `d6c4aa2`, `msvc8.0p`
  = `52c8293`.
- Both are defined identically in `site/backend/coreapp/compilers.py`
  (`MSVCCompiler(id=…, cc=CL_WIN)`); the variant identity lives in the
  packaged binaries, not in the backend.

## 5. Sync gaps vs our corpus

**decomp.me has, we don't (x86-relevant):**

| Gap | Value for the corpus |
|---|---|
| `msvc6.5pp` (SP5 + Processor Pack) | the SSE-capable 6.0 cl — a unique codegen era we cannot produce today |
| `msvc8.0p` (patched 8.0) | a patched 8.0 snapshot |
| Commercial Watcom `wcc10.0a/10.5/10.5a/10.6/11.0` | **highest payoff**: a whole commercial codegen line we only know from Agner Fog; directly relevant to RULES.md A2's open question (AF table 5's `ax,dx,bx,cx` 4-register `__fastcall`, "not reproduced by Open Watcom 2.0 — may be commercial-10.x-specific").  The `values.yaml` has the exact source tarball URLs |
| `msvc4.0` / `msvc4.2` | **not a real gap** — decompedia MSVC.md states 4.0/4.1/4.2 are byte-identical to each other and to VC 2.0 |

**We have, decomp.me doesn't**: msvc 2.0, 5.0, 9.0, 10.0, 11.0; the
16-bit MSVC 1.0/1.5/1.52 line; Delphi 1.0; Zig; MinGW GCC (decomp.me
hosts MSVC up to 8.0 only).

**No automated sync** — the two fleets are independent builds of the
same upstream binaries (archaic-msvc / OmniBlade releases); rebrew
pins sources sha256-verified at image build time, decomp.me pulls its
own registry images.

## 6. Integration details worth knowing

- **Watcom invocation** (from `compilers.py`): decomp.me runs
  `wcc386.exe` under wibo with `-zq -i="Z:${COMPILER_DIR}/h"
  -i="Z:${COMPILER_DIR}/h/nt"` — the compiler tree is mounted as the
  `Z:` drive and Watcom's include paths are passed explicitly
  (matching our `-I/tmp/cur_wc/h` finding for 16-bit wcc).
- **MSVC tarball sources**: `OmniBlade/decomp.me` releases
  (`msvcwin9x/`), `roblabla/MSVC-7.0-Portable`, `widberg/msvc8.0`.
- **CL.EXE wrapper convention**: same `cl` binary set we probe; no new
  compiler binaries for the versions we already cover.

## 7. Open questions / next steps

1. **Probe `msvc6.5pp`** — does the Processor Pack cl emit SSE at
   `/O2` (a 6.0-with-SSE marker absent from our corpus)?  One tarball
   + our wine wrapper + the `/I` table would answer it.
2. **Probe commercial Watcom `wcc10.x`** — resolves A2's 4-register
   fastcall question and adds the commercial codegen line (lea/div/
   FPU forms unknown to us).
3. **Probe `msvc8.0p`** — whether the patched snapshot differs in
   codegen from our 8.0 RTM/SP1 rows.
4. Keep the guild-doc re-check loop (the doc still grows between
   sessions) and mine the remaining local codegen-claim docs
   (docs/CODEGEN_PATTERNS.md is now fully probed via probe28).
# decomp.me Snippet API — scrape guide

How to scrape decomp.me's code-snippet data ("scratches" — the code +
compiler + flags + score records its matching platform stores) for
codegen research, and what has been scraped so far.

Companion to [DECOMPME_COMPILERS.md](DECOMPME_COMPILERS.md) (the
compiler fleet) — same scrape session, 2026-08-24.

## What "snippets" are

decomp.me has no `/api/snippets` endpoint.  The snippet data lives in
the **scratch** API (`/api/scratch`) — one record per scratchpad: a
user's C/C++ `source_code`, the `compiler` id, `compiler_flags`,
`platform`, a `target_assembly`, and a match `score`/`max_score`.
Exactly the data a codegen corpus wants: real code × real compilers ×
real flags × match outcome.

## Endpoints (from `site/backend/coreapp/urls.py` + `views/scratch.py`)

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/scratch` | GET | list scratches (filterable, cursor-paginated) |
| `/api/scratch/<slug>` | GET | one scratch (full `source_code`, flags, score) |
| `/api/scratch/<slug>/compile` | POST | compile a scratch (re-run the compiler) |
| `/api/scratch` | POST | create a scratch |
| `/api/scratch-count` | GET | total count |

**Filters** (`filters/scratch.py`): `?platform=<id>` (e.g. `win32`),
`?compiler=<id>` (e.g. `msvc6.0`), `?preset=<id>`, `?has_owner=`.
**Pagination** (`pagination.py`): cursor-based — `?page_size=N`, follow
the `next` cursor field in the response envelope.

**Scratch fields** (`models/scratch.py`): `slug`, `name`,
`description`, `creation_time`, `last_updated`, `compiler`,
`platform`, `compiler_flags`, `diff_flags`, `preset`,
`target_assembly`, `source_code`, `score`, `max_score`, `family`,
`parent`, `owner`.

## The scrape procedure

Script: `third-party/decompme-api/scrape_snippets.sh` (also in the
scraped `compilers/`/`site/` trees).  It iterates the x86 compiler ids
(`msvc4.0 … msvc8.0p`, `bcc2.0/3.1`, `wcc10.x`), pulls
`/api/scratch?platform=win32&compiler=<id>&page_size=50`, saves each
page as `snippets-x86/<id>_pN.json`, follows the `next` cursor, and
flattens everything into `snippets-x86/all_snippets.json`.

Manual equivalent (one compiler, first page):

```bash
curl -s -A "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0" \
  "https://decomp.me/api/scratch?platform=win32&compiler=msvc6.0&page_size=50"
```

### The Cloudflare wall

`decomp.me/api/*` returns a **403 Cloudflare challenge** to non-browser
clients (verified 2026-08-24 for `/api/scratch`,
`/api/scratch-count`, `/api/compilers`, `/api/platform` — a browser
User-Agent alone does not help).  Workarounds, in order of preference:

1. **`cf_clearance` cookie** — pass the challenge in a real browser,
   copy the cookie, then
   `COOKIE='cf_clearance=…' ./scrape_snippets.sh`.
2. **Self-hosted instance** — `docker compose up` the `decomp.me` repo
   (scraped in `third-party/decompme-api/site/`) and point `BASE` at
   it.  This also gives you the DB seed (its scratch sample data) and
   full API access without the CF layer.  **This is the recommended
   route for a large scrape.**
3. Scrape from a network without the CF block (some VPS/CI egresses
   pass; unstable).

The script stops at the first 403 per compiler — it never hammers.

## What has been scraped so far (2026-08-24)

- **Live API**: blocked (CF 403) — the run above confirms the block
  and the script's safe-stop behavior.
- **Repo-local x86-relevant samples** → `third-party/decompme-api/snippets-x86/`
  (with `manifest.json`): the only x86-compatible snippets present in
  the repo source (frontend scratch-state fixtures + the portable C
  from the backend tests).  The full corpus is DB-only and needs one
  of the workarounds above.
- **API knowledge**: endpoints, fields, filters, pagination captured
  from the scraped `site/backend` source — documented above.

## Next steps

1. Run one of the CF workarounds, then `./scrape_snippets.sh`.
2. Fold high-value snippets into the corpus as probe sources: pick
   snippets with `compiler=msvc6.x` + `/O2` + good `score`, compile
   them through our toolchain matrix, and cross-check our per-version
   byte matrices against decomp.me's recorded `target_assembly`.
