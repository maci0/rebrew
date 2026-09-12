"""match_sweep.py — build-parameter resolution and compiler/flag sweeps.

Resolves the build parameters shared across match modes and runs the
single-function and batch flag/toolchain sweeps.
"""

from __future__ import annotations

import logging
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.analysis import capstone_mode_for_arch
from rebrew.annotation import (
    Annotation,
    min_valid_va_for,
    parse_c_file_multi,
    parse_source_metadata,
)
from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import EXIT_MISMATCH, error_exit, json_print, parse_va
from rebrew.coff_reloc import build_iat_region, smart_reloc_compare
from rebrew.compile import resolve_compiler_env
from rebrew.config import ProjectConfig
from rebrew.match_batch import (
    StubInfo,
)
from rebrew.matcher import (
    build_candidate_obj_only,
    flag_sweep,
    score_candidate,
    structural_similarity,
)
from rebrew.sources import target_marker
from rebrew.toolchain import TOOLCHAINS
from rebrew.utils import read_source_text

log = logging.getLogger(__name__)
console = Console(stderr=True)


def print_structural_similarity(sim: Any) -> None:
    """Print a :class:`StructuralSimilarity` result to the console."""
    verdict = "flag sweep MAY help" if sim.flag_sensitive else "flags unlikely to help"
    console.print(f"\nStructural similarity ({verdict}):")
    console.print(
        f"  Instructions: {sim.exact} exact, {sim.reloc_only} reloc, "
        f"{sim.register_only} register, {sim.structural} structural "
        f"(of {sim.total_insns} total)"
    )
    console.print(
        f"  Mnemonic match: {sim.mnemonic_match_ratio:.1%}  |  "
        f"Structural ratio: {sim.structural_ratio:.1%}"
    )


def _compile_cflags(cflags: str, base_cf: str, posix_style: bool = False) -> str:
    """Build the effective compile flags: base_cflags first (when it carries
    ``/c``), else the ``/nologo /c`` glue.  ONE definition shared by the
    single-function, flag-sweep, and batch-GA paths — a divergent copy in the
    sweep path silently dropped ``base_cflags`` (e.g. ``/MT``), so a
    sweep-reported exact could demote on the next test/verify.

    For POSIX-style compilers (gcc-pe/mingw, clang) the ``/nologo /c`` glue
    is omitted — ``-c`` is added by the compile command builders.

    A ``base_cf`` WITHOUT ``/c`` (e.g. a bare ``/MT``) is preserved AND gets
    the glue inserted: the old code dropped it entirely in that branch — the
    same silent flag-loss regression class this function consolidates.
    """
    if posix_style:
        return f"{base_cf} {cflags}".strip() if base_cf else cflags
    if base_cf and "/c" in base_cf:
        return f"{base_cf} {cflags}".strip()
    if "/c" not in cflags:
        if base_cf:
            return f"/nologo /c {base_cf} {cflags}".strip()
        return f"/nologo /c {cflags}".strip()
    # cflags already carries /c: keep base_cf (it may hold /MT etc.) and add no
    # second glue.  Dropping it here made every path compile a different
    # runtime configuration than the one the metadata declares.
    return f"{base_cf} {cflags}".strip() if base_cf else cflags


#: --mutation-focus category → selection weight for its suggested operators
#: (everything else keeps the default 1.0).


@dataclass
class _BuildParams:
    """Resolved build parameters shared across all modes."""

    cfg: Any
    seed_c: Path
    seed_src: str
    cl: str
    inc: str
    cflags: str
    symbol: str
    target_bytes: bytes
    va_int: int
    target_size: int
    msvc_env: dict[str, str] | None
    cc: Any  # CacheBackend | None


def _select_annotation(annos: list[Annotation], symbol: str | None) -> Annotation | None:
    """Pick the annotation whose symbol or name matches *symbol*.

    ``rebrew match`` on a multi-function file with ``--symbol`` must target
    THAT function; falling back to the first annotation silently compares
    the wrong bytes (false EXACT + wrong solution records).
    """
    if not symbol:
        return None
    want = symbol.strip().lstrip("_").lower()
    for a in annos:
        for candidate in (a.symbol or "", a.name or ""):
            if candidate.strip().lstrip("_").lower() == want:
                return a
    return None


def resolve_build_params(
    cfg: Any,
    seed_c: str,
    cl: str | None,
    inc: str | None,
    cflags: str | None,
    symbol: str | None,
    target_va: str | None,
    target_size: int | None,
    ignore_lint: bool,
    json_output: bool,
) -> _BuildParams:
    """Resolve config, annotations, compiler, and target bytes into build params."""
    seed_c_path = Path(seed_c)
    if not seed_c_path.exists():
        # Run the existence check unconditionally — with an explicit --symbol
        # the old guard below was skipped and read_source_text raised a raw
        # FileNotFoundError traceback.
        error_exit(f"Source not found: {seed_c}", json_mode=json_output)
    annos = parse_c_file_multi(
        seed_c_path, target_name=target_marker(cfg), metadata_dir=cfg.metadata_dir
    )
    # Prefer the VA-matched annotation when a VA is given (diff/match/prove
    # invoked as `rebrew diff 0x<va>` on a multi-function file must target
    # THAT function — the old first-annotation fallback silently diffed a
    # different function and reported a false match).
    anno = _select_annotation(annos, symbol)
    if anno is None and target_va:
        # target_va is validated by the parse below before bytes are
        # extracted, so it is safe to parse here for the VA match.
        want_va = parse_va(target_va, json_mode=json_output)
        anno = next((a for a in annos if a.va == want_va), None)
    if anno is None:
        if target_va and not symbol:
            # A requested VA that the resolved file does not annotate must not
            # silently fall back to the first annotation — that compiles the
            # WRONG function's symbol and diffs it against the requested
            # address (the `rebrew diff 0x<va>` false-match regression class,
            # same rule as test/prove/near-diag).  An explicit --symbol is a
            # deliberate override and still allowed.
            error_exit(
                f"No annotation for VA {target_va} in {seed_c} — the resolved "
                "file covers different functions (pass --symbol to override)",
                json_mode=json_output,
            )
        anno = annos[0] if annos else None
    if anno:
        eval_errs, eval_warns = anno.validate(min_va=min_valid_va_for(cfg))
        if not json_output:
            for e in eval_errs:
                console.print(f"[bold red]LINT ERROR:[/bold red] {e}")
            for w in eval_warns:
                console.print(f"[bold yellow]LINT WARNING:[/bold yellow] {w}")
        if eval_errs and not ignore_lint:
            error_exit(
                "Aborting due to annotation errors. Fix them or use --ignore-lint to override.",
                json_mode=json_output,
            )

    meta = parse_source_metadata(seed_c, metadata_dir=cfg.metadata_dir)
    compile_cfg = cfg

    # Use shared helper for compiler env resolution — the returned msvc_env
    # IS msvc_env_from_config(cfg) (the old code computed it a second time
    # and discarded the helper's copy).
    cl_resolved, inc_resolved, msvc_env, cc = resolve_compiler_env(cfg)
    # Per-library / per-function toolchain override: the nearest
    # rebrew-libraries.toml (walk-up from the source dir) or the function's
    # own TOOLCHAIN/CFLAGS select the docker image and flags.  These must come
    # from the SELECTED annotation: ``meta`` is the file's FIRST annotation's
    # fields only, so on a multi-function file `--symbol foo` would otherwise
    # compile foo with the first block's flags.
    from rebrew.cli import resolve_compile_overrides

    toolchain_meta = (anno.toolchain if anno else "") or meta.get("TOOLCHAIN")
    cflags_meta = (anno.cflags if anno else "") or meta.get("CFLAGS")
    toolchain_name, _lib_cflags = resolve_compile_overrides(
        cfg,
        Path(seed_c).resolve().parent,
        toolchain_meta,
        cflags_meta,
        getattr(anno, "module", "") if anno else "",
    )
    if toolchain_name:
        from rebrew.toolchain import TOOLCHAINS

        tc_spec = TOOLCHAINS.get(toolchain_name)
        if tc_spec is None or tc_spec.image is None:
            error_exit(
                f"metadata TOOLCHAIN {toolchain_name!r} has no docker image — "
                "every compile runs through its docker image; "
                f"run `rebrew toolchain build {toolchain_name}` first",
                json_mode=json_output,
            )
        # Route the GA compile through the overridden toolchain by pointing
        # the compile config at its profile (compile_to_obj resolves the
        # image from the profile).  The cl/inc/env fields stay as resolved
        # for the default profile; image-backed compiles ignore them.
        # Shallow-copy (not vars→SimpleNamespace): ProjectConfig carries
        # computed properties (metadata_dir, posix_style, capstone_*), and
        # ``vars()`` only copies stored fields — a SimpleNamespace copy
        # would silently drop them and break DIR32 name resolution.
        import copy

        compile_cfg = copy.copy(compile_cfg)
        compile_cfg.compiler_profile = toolchain_name
    if cl is not None:
        # Caller override: resolve paths relative to root
        try:
            cl_parts = shlex.split(cl)
        except ValueError:
            cl_parts = cl.split()
        cl_parts_res = []
        for part in cl_parts:
            p = cfg.root / part
            cl_parts_res.append(str(p) if p.exists() else part)
        cl_resolved = " ".join(cl_parts_res)
    if inc is not None:
        inc_path = cfg.root / inc
        inc_resolved = str(inc_path) if inc_path.exists() else inc

    if not symbol and anno:
        symbol = anno.symbol
    if not symbol:
        if not Path(seed_c).exists():
            error_exit(f"Source not found: {seed_c}", json_mode=json_output)
        error_exit(
            "--symbol required (could not derive from C function definition)", json_mode=json_output
        )

    if not cflags:
        # Single source of truth: per-function CFLAGS → per-library
        # rebrew-libraries.toml → cflags_presets → [compiler].cflags →
        # "/O2 /Gd" (shared with verify/test/prove so every tool compiles
        # the same function with the same flags).
        cflags = _lib_cflags
    cflags = _compile_cflags(
        cflags,
        getattr(compile_cfg, "base_cflags", "") or "",
        posix_style=bool(getattr(compile_cfg, "posix_style", False)),
    )

    if not target_va:
        if anno and anno.va:
            target_va = f"0x{anno.va:08x}"
        else:
            for marker_key in ("FUNCTION", "LIBRARY", "STUB"):
                func_meta = meta.get(marker_key)
                if func_meta and "0x" in func_meta:
                    after_hex = func_meta.split("0x")[1].split()
                    if after_hex:
                        target_va = "0x" + after_hex[0]
                        break

    if target_size is None:
        if anno and anno.size:
            target_size = anno.size
        elif "SIZE" in meta:
            try:
                target_size = int(meta["SIZE"])
            except ValueError:
                error_exit(f"Invalid SIZE metadata: {meta['SIZE']!r}", json_mode=json_output)

    if target_va and target_size:
        va_int = parse_va(target_va, json_mode=json_output)
        target_bytes = extract_raw_bytes(cfg.target_binary, va_int, target_size)
    else:
        error_exit("Need VA and SIZE (from source metadata or CLI)", json_mode=json_output)

    if not target_bytes:
        error_exit("Could not extract target bytes", json_mode=json_output)

    seed_src, _ = read_source_text(seed_c_path)

    return _BuildParams(
        cfg=compile_cfg,
        seed_c=seed_c_path,
        seed_src=seed_src,
        cl=cl_resolved,
        inc=inc_resolved,
        cflags=cflags,
        symbol=symbol,
        target_bytes=target_bytes,
        va_int=va_int,
        target_size=target_size,
        msvc_env=msvc_env,
        cc=cc,
    )


# ---------------------------------------------------------------------------
# Single-function: flag sweep
# ---------------------------------------------------------------------------


def _run_single_flag_sweep(
    p: _BuildParams,
    tier: str,
    jobs: int,
    json_output: bool,
) -> None:
    """Run compiler flag sweep on one function and report results."""
    try:
        results = flag_sweep(
            p.seed_src,
            p.target_bytes,
            p.cl,
            p.inc,
            p.cflags,
            p.symbol,
            jobs,
            tier=tier,
            env=p.msvc_env,
            cache=p.cc,
            timeout=p.cfg.compile_timeout,
            extra_include_dirs=[str(p.seed_c.parent.resolve())],
            posix_style=getattr(p.cfg, "posix_style", False),
            profile=getattr(p.cfg, "compiler_profile", ""),
            cfg=p.cfg,
        )
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)

    sim_res = None
    res = build_candidate_obj_only(
        p.seed_src,
        p.cl,
        p.inc,
        p.cflags,
        p.symbol,
        env=p.msvc_env,
        cache=p.cc,
        timeout=p.cfg.compile_timeout,
        posix_style=getattr(p.cfg, "posix_style", False),
        profile=getattr(p.cfg, "compiler_profile", ""),
        cfg=p.cfg,
    )
    if res.ok and res.obj_bytes:
        obj_bytes = res.obj_bytes
        if len(obj_bytes) > len(p.target_bytes):
            obj_bytes = obj_bytes[: len(p.target_bytes)]

        sim_cs_mode = capstone_mode_for_arch(getattr(p.cfg, "arch", ""))
        sim_res = structural_similarity(
            p.target_bytes, obj_bytes, res.reloc_offsets, cs_mode=sim_cs_mode
        )

    best_score = results[0][0] if results else float("inf")

    if json_output:
        sweep_items = [
            {"score": round(s, 2), "flags": f, "exact": s < 0.1} for s, f in results[:20]
        ]
        payload: dict[str, Any] = {
            "source": str(p.seed_c),
            "symbol": p.symbol,
            "mode": "flag_sweep",
            "tier": tier,
            "best_score": round(best_score, 2) if best_score < float("inf") else None,
            "best_flags": results[0][1] if results else None,
            "exact": best_score < 0.1,
            "results": sweep_items,
        }
        if sim_res is not None:
            payload["structural_similarity"] = {
                "total_insns": sim_res.total_insns,
                "exact": sim_res.exact,
                "reloc_only": sim_res.reloc_only,
                "register_only": sim_res.register_only,
                "structural": sim_res.structural,
                "mnemonic_match_ratio": sim_res.mnemonic_match_ratio,
                "structural_ratio": sim_res.structural_ratio,
                "flag_sensitive": sim_res.flag_sensitive,
            }
        json_print(payload)
    else:
        for score, flags_str in results[:10]:
            console.print(f"{score:.2f}: {flags_str}")
        if sim_res is not None:
            print_structural_similarity(sim_res)

    if best_score < 0.1:
        return
    raise typer.Exit(code=EXIT_MISMATCH)


def run_flag_sweep(
    stub: StubInfo,
    cfg: ProjectConfig,
    tier: str = "targeted",
    jobs: int = 4,
) -> tuple[float, str, list[tuple[float, str]]]:
    """Run a compiler flag sweep on a single StubInfo in-process.

    Returns ``(best_score, best_flags, all_results)``.
    """

    filepath = stub.filepath
    va_int = int(stub.va, 16)
    size = stub.size
    symbol = stub.symbol
    # Same shared override chain as the GA path (docs/TOOLCHAIN.md): a
    # library's own TOOLCHAIN/CFLAGS must drive its sweep, not the project
    # default.
    from rebrew.cli import resolve_compile_overrides

    toolchain_name, cflags = resolve_compile_overrides(
        cfg,
        filepath.parent,
        getattr(stub, "toolchain", "") or None,
        stub.cflags or None,
        getattr(stub, "module", ""),
    )

    source, _ = read_source_text(filepath)
    target_bytes = extract_raw_bytes(cfg.target_binary, va_int, size)
    if not target_bytes:
        return float("inf"), "", []

    cl_cmd, inc_dir, msvc_env, cc = resolve_compiler_env(cfg)

    # Unconditional, like the single-function and batch-GA paths: a resolved
    # CFLAGS that already contains /c must not skip base_cflags (/MT etc.).
    cflags = _compile_cflags(
        cflags,
        getattr(cfg, "base_cflags", "") or "",
        posix_style=bool(getattr(cfg, "posix_style", False)),
    )

    # NOTE: no redirect_stdout here — mutating process-global stdout is not
    # thread-safe under --sweep-then-ga batch (-j N) and silently loses later
    # prints (incl. the --json report).  flag_sweep logs via logging, not stdout.
    try:
        results = flag_sweep(
            source,
            target_bytes,
            cl_cmd,
            inc_dir,
            cflags,
            symbol,
            n_jobs=jobs,
            tier=tier,
            env=msvc_env,
            cache=cc,
            extra_include_dirs=[str(filepath.parent.resolve())],
            timeout=cfg.compile_timeout,
            posix_style=bool(getattr(cfg, "posix_style", False)),
            profile=str(toolchain_name or getattr(cfg, "compiler_profile", "") or ""),
            cfg=cfg,
        )
    except ValueError as exc:
        # The flag sweep is MSVC-only — a posix project must not silently
        # waste compiles; surface it as a per-function failure.
        return float("inf"), str(exc), []

    if not results:
        return float("inf"), "", []

    best_score, best_flags = results[0]
    return best_score, best_flags, results


# ---------------------------------------------------------------------------
# Single-function: GA run
# ---------------------------------------------------------------------------


def _sweep_filter_matches(name: str, verarch: str, filters: list[str]) -> bool:
    """True when *name* (profile id, e.g. msvc600sp6) matches a sweep filter.

    A filter matches when it is the profile name itself ("msvc6"), a prefix
    of the profile id ("msvc2" -> msvc200), or a substring of the version-arch
    ("6.0" -> every 6.0 line incl. SPs; "win16" -> all 16-bit DOSBox
    toolchains).  This is what lets a Y2K binary exclude the pre-5.0 line
    with --sweep-exclude-toolchains 2.0,4.0."""
    n = name.lower()
    va = verarch.lower()
    for f in filters:
        f = f.strip().lower()
        if not f:
            continue
        if f == n or n.startswith(f) or f in va:
            return True
    return False


def _vendored_msvc_toolchains(
    cfg: Any,
    only: str = "",
    exclude: str = "",
) -> list[tuple[str, str, str]]:
    """Return (profile, cl_cmd, inc_dir) for every image-backed MSVC toolchain.

    Execution is docker-only: the cl_cmd/inc_dir are inert for image-backed
    profiles (the image bakes the compiler + includes), so they are returned
    empty and only the profile names matter — the sweep routes each compile
    through that profile's image.  *only* / *exclude* are comma-separated
    profile-name or version-prefix filters (see :func:`_sweep_filter_matches`);
    the configured profile's own compiler is prepended as the baseline and is
    subject to the same filters ("--sweep-toolchains 4.0" means ONLY 4.0).
    """

    only_f = [f for f in (only or "").split(",") if f.strip()]
    excl_f = [f for f in (exclude or "").split(",") if f.strip()]

    out: list[tuple[str, str, str]] = []
    for name, spec in sorted(TOOLCHAINS.items()):
        if spec.image is not None and spec.family == "msvc" and spec.binary == "cl":
            verarch = spec.image.rsplit(":", 1)[-1] if spec.image else ""
            if only_f and not _sweep_filter_matches(name, verarch, only_f):
                continue
            if _sweep_filter_matches(name, verarch, excl_f):
                continue
            out.append((name, "", ""))
    # The configured profile's own compiler joins the sweep as the baseline
    # under the same filters: "--sweep-toolchains msvc4.0" means ONLY that
    # toolchain, so the configured msvc6 must not be silently swept anyway.
    # Drop any loop entry for it first, then prepend: the baseline stays
    # first without being listed twice.
    configured = getattr(cfg, "compiler_profile", "") or "msvc6"
    out = [entry for entry in out if entry[0] != configured]
    cfg_spec = TOOLCHAINS.get(configured)
    verarch = cfg_spec.image.rsplit(":", 1)[-1] if cfg_spec is not None and cfg_spec.image else ""
    only_ok = not only_f or _sweep_filter_matches(configured, verarch, only_f)
    excl_ok = not _sweep_filter_matches(configured, verarch, excl_f)
    if only_ok and excl_ok:
        out.insert(0, (configured, "", ""))
    return out


def _run_single_toolchain_sweep(
    p: _BuildParams, json_output: bool, only: str = "", exclude: str = ""
) -> None:
    """Compile the seed with each vendored MSVC toolchain and report the best."""
    toolchains = _vendored_msvc_toolchains(p.cfg, only, exclude)
    # Catalog + IAT region are constant across toolchains — computed once,
    # not per iteration (the old code called build_iat_region inside the
    # loop and passed name_to_va via a getattr that never existed, so reloc
    # targets were never validated: a wrong-callee source could tag "EXACT").
    from rebrew.coff_reloc import build_name_to_va

    name_to_va = build_name_to_va(p.cfg)
    iat_region = build_iat_region(p.cfg)
    results: list[tuple[float, bool, int, int, str]] = []
    for profile, cl_cmd, inc_dir in toolchains:
        res = build_candidate_obj_only(
            p.seed_src,
            cl_cmd,
            inc_dir,
            p.cflags,
            p.symbol,
            env=p.msvc_env,
            cache=p.cc,
            timeout=p.cfg.compile_timeout,
            extra_include_dirs=[str(p.seed_c.parent.resolve())],
            profile=profile,
            cfg=p.cfg,
        )
        if not (res.ok and res.obj_bytes):
            results.append((float("inf"), False, 0, 0, profile))
            continue
        obj = res.obj_bytes
        # 16-bit targets must be scored in 16-bit mode with 2-byte reloc
        # slots (omf16 emits rel16/disp16); the 32-bit defaults would
        # produce wrong mnemonics and mask the bytes after every reloc.
        _cs_mode = capstone_mode_for_arch(getattr(p.cfg, "arch", ""))
        _ptr_size = getattr(p.cfg, "pointer_size", 4)
        score = score_candidate(
            p.target_bytes, obj, res.reloc_offsets, cs_mode=_cs_mode, pointer_size=_ptr_size
        )
        score_val: float = score.total
        matched, count, total, _relocs, _inv = smart_reloc_compare(
            obj[: len(p.target_bytes)],
            p.target_bytes,
            res.reloc_offsets,
            name_to_va=name_to_va,
            section_va=p.va_int,
            iat_region=iat_region,
        )
        results.append((score_val, matched, count, total, profile))

    results.sort(key=lambda r: r[0])
    if json_output:
        json_print(
            {
                "sweep": "toolchain",
                "symbol": p.symbol,
                "results": [
                    {
                        "toolchain": profile,
                        "score": score,
                        "matched": matched,
                        "bytes": f"{count}/{total}",
                    }
                    for score, matched, count, total, profile in results
                ],
                "best": results[0][4] if results else None,
            }
        )
        return

    console.print("[bold]Toolchain sweep:[/bold]")
    for score_val, matched, count, total, profile in results:
        tag = "[green]EXACT[/green]" if matched and count == total else ""
        console.print(f"  {profile:10s} score={score_val:9.2f}  {count}/{total} bytes {tag}")
    if results:
        best = results[0]
        if best[1] and best[2] == best[3]:
            console.print(
                f"[green]Full match with {best[4]} — switch the project profile or set per-function CFLAGS.[/green]"
            )


def _run_single_toolchain_flag_sweep(
    p: _BuildParams,
    tier: str,
    jobs: int,
    json_output: bool,
    only: str = "",
    exclude: str = "",
) -> None:
    """Flag-sweep with each vendored MSVC toolchain; report per-toolchain best.

    Answers "which MSVC version AND which flags built this function" in one
    run — the two-dimension question a decompiler faces when the configured
    profile does not byte-match (``--sweep-toolchain`` alone only tries the
    project's cflags; ``--flag-sweep`` alone only tries the project's
    compiler).
    """
    toolchains = _vendored_msvc_toolchains(p.cfg, only, exclude)
    rows: list[dict[str, Any]] = []
    for profile, cl_cmd, inc_dir in toolchains:
        results = flag_sweep(
            p.seed_src,
            p.target_bytes,
            cl_cmd,
            inc_dir,
            p.cflags,
            p.symbol,
            jobs,
            tier=tier,
            env=p.msvc_env,
            cache=p.cc,
            timeout=p.cfg.compile_timeout,
            extra_include_dirs=[str(p.seed_c.parent.resolve())],
            profile=profile,
            cfg=p.cfg,
        )
        best_score, best_flags = results[0] if results else (float("inf"), "")
        rows.append(
            {
                "toolchain": profile,
                "best_score": best_score if best_score < float("inf") else None,
                "flags": best_flags,
                "exact": best_score < 0.1,
            }
        )

    rows.sort(
        key=lambda r: (
            r["best_score"] is None,
            r["best_score"] if r["best_score"] is not None else float("inf"),
        )
    )
    if json_output:
        json_print(
            {
                "sweep": "toolchain+flags",
                "results": rows,
                "best": rows[0]["toolchain"] if rows else None,
            }
        )
        return

    console.print("[bold]Toolchain + flag sweep:[/bold]")
    for r in rows:
        tag = "[green]EXACT[/green]" if r["exact"] else ""
        score = f"{r['best_score']:.2f}" if r["best_score"] is not None else "    n/a"
        console.print(
            f"  {r['toolchain']:10s} best={score:>9s}  {r['flags'] or '(no flags)'} {tag}"
        )
    if rows and rows[0]["exact"]:
        console.print(
            f"[green]Full match with {rows[0]['toolchain']} — switch the project profile "
            "or set per-function CFLAGS.[/green]"
        )
