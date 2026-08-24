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
