# decomp.me compiler fleet

How the decomp.me compiler fleet is packaged, which IDs map onto rebrew
profiles, and what the probes of the compilers rebrew does not ship found.
Companion to [codegen/RULES.md](codegen/RULES.md) (rules J2 and A2 cite this
fleet) and to the per-version files. Captured 2026-08-24 from the decompme
GitHub org, then probed (rules catalog rounds 26 and 27).

The checkout used for the capture is
`~/Desktop/ai-decomp/third-party/decompme-api/` (sibling of the `decompedia/`
practice-doc checkout).

## 1. Where the definitions live

`https://decomp.me/api/*` returns a Cloudflare 403 challenge to non-browser
clients. The `api.decomp.me` subdomain does not exist. The compiler list the
API serves is the source in the `decompme` GitHub org:

- `decompme/compilers`: the fleet. `compilers/values.yaml` holds the
  definitions (234 entries, 226 distinct IDs in the captured snapshot; some IDs have multiple host-architecture entries).
- `decompme/decomp.me`: the site (Django backend, Next.js frontend).
  Routes mount at `/api/` from `site/backend/coreapp/urls.py`: `compilers`,
  `compiler`, `platform`, `library`, `search`, `stats`, `user`,
  `users/<slug>`, `healthz`, plus the scratch routes in section 4. The
  compiler objects are built in `site/backend/coreapp/compilers.py`.
  Display names are in
  `site/frontend/src/lib/i18n/locales/en/compilers.json`.

## 2. Images

decomp.me runs every compiler in Docker, as rebrew does, with a different
split of what the image contains.

`template.py` (Jinja2) generates one Dockerfile per compiler from
`values.yaml` and the per-platform templates (`templates/win32/msvc.j2`,
`templates/common/default.j2`, `templates/ps1/psyq.j2`). Generated files say
"Do not edit manually". The build is multi-stage: an `alpine` stage downloads
the compiler tarball (for example `msvc6.0.tar.gz` from the OmniBlade/decomp.me
releases) and extracts it to `/compilers/<platform>/<id>`; a `scratch`
`release` stage copies only `/compilers`. The published image is a bare
compiler tree, with no runtime. A GitHub Action pushes each image to ghcr.io.

| | decomp.me | rebrew |
|---|---|---|
| Image contents | bare compiler tree (scratch stage) | compiler plus wine or DOSBox, baked in |
| win32 compilers run under | wibo, on the sandbox side (`WATCOM_CC = ${WIBO} wcc386.exe …`) | wine, inside the image entrypoint |
| Registry | ghcr.io | locally built `rebrew/msvc:*` |

Both mount the compiler dir as a drive (`Z:` on decomp.me). Rebrew mounts the
workdir and passes `/I` include paths per version.

Watcom invocation, from `compilers.py`: `wcc386.exe` under wibo with
`-zq -i="Z:${COMPILER_DIR}/h" -i="Z:${COMPILER_DIR}/h/nt"`. The compiler tree
is the `Z:` drive and the include paths are explicit (the same shape as
rebrew's `-I/tmp/cur_wc/h` for 16-bit wcc).

MSVC tarball sources: `OmniBlade/decomp.me` releases (`msvcwin9x/`),
`roblabla/MSVC-7.0-Portable`, `widberg/msvc8.0`. The `cl` binary set is the
same one the rebrew probes use. Versions both fleets already cover add no
new compiler binary.

The two fleets are independent builds of the same upstream binaries
(archaic-msvc and the OmniBlade releases). Rebrew pins sources, sha256-checked
at image build time. decomp.me pulls its own registry images. There is no
automated sync between them.

## 3. ID mapping

Platforms in `values.yaml`: `win32`, `msdos`, `n64`, `gba`, `gc_wii`, `ps1`,
`ps2`, `n3ds`, `nds`, `android_x86`, `macosx`, `dreamcast`, `common`, and
others. The non-x86 set (MWCC/Metrowerks, ARM, console GCCs for
PS1/PS2/N64/GBA/NDS/3DS, clang 3.9-9.0, PPC MSVC) is outside the corpus.

| decomp.me id | Display name | Rebrew |
|---|---|---|
| `msvc4.0` | Microsoft Visual C/C++ 4.0 | `msvc-4.0`. 4.0/4.1/4.2 are codegen-identical to each other and to VC 2.0 |
| `msvc4.1` | 4.1 | `msvc-4.1` |
| `msvc4.2` | 4.2 | `msvc-4.2` (same codegen as 4.1) |
| `msvc6.0` | 6.0 | `msvc-6.0` RTM, cl 12.00.8168 |
| `msvc6.3` | 6.0 SP3 | `msvc-6.0-sp3`, 8447 |
| `msvc6.4` | 6.0 SP4 | SP4, 8804 |
| `msvc6.5` | 6.0 SP5 | SP5, 8966 |
| `msvc6.5pp` | 6.0 SP5 w/ Processor Pack | `msvc-6.0-sp5-pp`. See below |
| `msvc6.6` | 6.0 SP6 | SP6, 9782 |
| `msvc7.0` | 7.0 .NET 2002 | `msvc-7.0-rtm` |
| `msvc7.1` | 7.1 .NET 2003 | `msvc-7.1` |
| `msvc8.0` | 8.0 | `msvc-8.0` RTM |
| `msvc8.0p` | 8.0 (Patched) | not shipped. See below |
| `bcc2.0` / `bcc3.1` | Turbo C 2.0 / 3.1 | `borland-2.0`, `borland-3.1` |
| `wcc10.0a`, `wcc10.5`, `wcc10.5a`, `wcc10.6`, `wcc11.0` | commercial Watcom | not shipped. See below |

`msvc6.3` through `msvc6.6` are separate IDs because each carries a different
C1 build (8168 RTM, 8447 SP3, 8804 SP4 and later, 8966 SP5, 9782 SP6). The
corpus measured SP1-SP6 codegen as byte-identical (rule J2). The split is
CRT and headers, not instruction selection. Rebrew's SP rows are the codegen
equivalent of those IDs. The 7.0 SP1 memset shapes are the exception, and
they are an MSVC service pack, not a decomp.me ID.

Rebrew ships, and decomp.me does not: MSVC 2.0, 5.0, 9.0, 10.0, 11.0; the
16-bit MSVC 1.0/1.5/1.52 line; Delphi 1.0; Zig; MinGW GCC. decomp.me hosts
MSVC up to 8.0 only.

### `msvc6.5pp` (Processor Pack)

`msvc6.5pp.tar.gz` is a distinct tarball in the same OmniBlade release set.
The Processor Pack was Microsoft's free VC 6.0 add-on. Rebrew ships it as
`msvc-6.0-sp5-pp` (`rebrew/msvc:6.0-sp5-pp-win32`), built from
`archaic-msvc/msvc600_sp5_vcpp`. The pack replaces the code generator
(`c2.dll` 13.00.9044.0), adds MASM 6.15 (`ml.exe`), and installs the
MMX/SSE/SSE2 intrinsic headers. See
[TOOLCHAIN.md](TOOLCHAIN.md) ("VC6 + Processor Pack (msvc-6.0-sp5-pp)").

`cl.exe` is unchanged at 12.00.8804. `/O2` and `/O2 /G6` codegen is
byte-identical to stock SP5 on the probe shapes, so the pack adds no corpus
rows (rule J2, [msvc-6.md](codegen/msvc/msvc-6.md)). `/arch:SSE` and `/G7`
are rejected with D4002. `/G5`, `/G6`, and `/QIfist` are accepted. SSE/SSE2
code comes from the pack's intrinsics, or from `.asm` through the shipped
MASM. The `13.10.xxxx` compiler line is VC 7.1, not this pack, and SP6
removes the pack.

### `msvc8.0p` (patched 8.0)

A patched snapshot of VC 8.0 (VS2005, cl 14.00.50727) from `widberg/msvc8.0`:
`values.yaml` pins `msvc8.0` to commit
`d6c4aa208c8345c78a9f68ba6ef911ee94c6a6e1` and `msvc8.0p` to
`52c8293f8b8d6441c594cf096542290c17a4d70e`. Both are
`MSVCCompiler(id=…, cc=CL_WIN)` in `compilers.py`. The difference is the
packaged binaries.

Probed codegen is ordinary VC 8 (the FP reload dance `d9 5c 24 04 …`, and
`add eax,1` for an increment). No new corpus rows against rebrew's 8.0
RTM/SP1 ([msvc-8.md](codegen/msvc/msvc-8.md), rule J2). Rebrew does not ship
an image for it.

### Commercial Watcom 10.x / 11.0

`wcc10.0a`, `wcc10.5`, `wcc10.5a`, `wcc10.6`, and `wcc11.0` are the
commercial line. Rebrew ships only Open Watcom 2.0. The probes ran the
decomp.me tarballs under wibo (decomp.me's own runner) and folded 35 rows
into the corpus under `watcom/<ver>` at `-otexan`
([open-watcom.md](codegen/watcom/open-watcom.md), rule A2):

- `wcc386` has no `__fastcall` keyword. The 4-register convention is
  `#pragma aux parm [eax] [edx] [ebx] [ecx]`, and the wrapper loads eax, edx,
  ebx, ecx (the 4th argument in ecx, not on the stack). That confirms Agner
  Fog table 5. `__fastcall` is an Open Watcom keyword.
- 10.0a, 10.5, 10.5a, and 10.6 are byte-identical across the probe set. 11.0
  differs: its `idiv` divisor loads into ecx (`b9 0a … f7 f9`) where 10.x
  uses ebx (`bb 0a … f7 fb`), and `idx7` swaps the register roles.
- `/10` is a real `idiv` (signed `cdq; idiv`, unsigned `xor edx,edx; div`),
  with no reciprocal multiply. 32-bit FP functions clean their own stack
  (`ret 0x10` on a two-double function).
- 34 of the 35 rows are byte-unique across the corpus. `udiv10_` on 11.0
  shares its ecx-divisor form with Open Watcom 2.0.
- 16-bit `wcc.exe` in the 10.5 tarball is a `binnt/wcc.exe` launcher stub
  that references a missing `binw/wcc.exe`. The 16-bit commercial line needs
  other release tarballs.

## 4. Scratch API

decomp.me stores matching records as scratches, not under `/api/snippets`.
One scratch holds a user's `source_code`, the `compiler` id, `compiler_flags`,
`platform`, a `target_assembly`, and `score` / `max_score`.

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/scratch` | GET | list scratches (filterable, cursor-paginated) |
| `/api/scratch/<slug>` | GET | one scratch (full source, flags, score) |
| `/api/scratch/<slug>/compile` | POST | compile a scratch again |
| `/api/scratch` | POST | create a scratch |
| `/api/scratch-count` | GET | total count |

Filters (`filters/scratch.py`): `platform` (for example `win32`), `compiler`
(for example `msvc6.0`), `preset`, `has_owner`. Pagination (`pagination.py`)
is cursor-based: `page_size`, then the `next` field of the envelope. Fields
(`models/scratch.py`): `slug`, `name`, `description`, `creation_time`,
`last_updated`, `compiler`, `platform`, `compiler_flags`, `diff_flags`,
`preset`, `target_assembly`, `source_code`, `score`, `max_score`, `family`,
`parent`, `owner`.

The capture script is
`~/Desktop/ai-decomp/third-party/decompme-api/scrape_snippets.sh`. It walks
the x86 compiler ids, requests
`/api/scratch?platform=win32&compiler=<id>&page_size=50`, stores each page as
`snippets-x86/<id>_pN.json`, follows `next`, and flattens to
`snippets-x86/all_snippets.json`. One page by hand:

```bash
curl -s -A "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0" \
  "https://decomp.me/api/scratch?platform=win32&compiler=msvc6.0&page_size=50"
```

The same 403 covers `/api/scratch`, `/api/scratch-count`, `/api/compilers`,
and `/api/platform`. A browser User-Agent does not pass it. Ways through, in
order:

1. A `cf_clearance` cookie from a real browser:
   `COOKIE='cf_clearance=…' ./scrape_snippets.sh`.
2. A self-hosted instance: `docker compose up` the scraped `site/` tree and
   point `BASE` at it. That also serves the DB seed. This is the route for a
   large scrape.
3. Egress that the challenge does not block. Unstable.

The script stops at the first 403 per compiler.

As of the 2026-08-24 run the live API was blocked. The only x86-compatible
snippets on disk are the ones in the repo source (frontend scratch-state
fixtures and the portable C from the backend tests), under
`snippets-x86/` with `manifest.json`. The full corpus is in the database and
needs one of the routes above.
