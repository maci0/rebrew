"""export.py — Export rebrew annotations to a BinSync state directory.

Writes function metadata, global variables, and struct definitions in
BinSync's TOML layout so any BinSync-aware decompiler plugin can import the
project's reverse-engineering artifacts.

Layout produced::

    <outdir>/
        functions/
            <hex>.toml   -- one per function annotation
        global_vars.toml -- DATA/GLOBAL annotations
        structs/
            <name>.toml  -- one per struct definition (with fields when available)
        enums.toml       -- one table per enum (with member values)
        typedefs.toml    -- one table per standalone typedef

The export carries only BinSync-native fields — rebrew's STATUS/CFLAGS
stay in ``rebrew-functions.toml`` (STATUS is verify-earned; an old
``[rebrew] STATUS=… CFLAGS=…`` comment was write-only and was removed).
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tomlkit
import typer

from rebrew.annotation import span_contains_factory
from rebrew.binsync import serial
from rebrew.binsync.git import run_git
from rebrew.binsync.state import (
    acknowledge_sync,
    artifact_hash,
    load_sync_baseline,
    local_sync_records,
    merge_sync_record,
    remote_sync_records,
    resolve_global_names,
    resolve_global_types,
    result_count,
    result_paths,
    sync_health,
    sync_health_messages,
)
from rebrew.catalog import scan_reversed_dir
from rebrew.cli import TargetOption, console, error_exit, json_print, require_config, run_standalone
from rebrew.config import ProjectConfig, inventory_path_for
from rebrew.utils import atomic_write_locked, md5_file, strip_body

app = typer.Typer(
    help="Export rebrew annotations to a BinSync state directory.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binsync-export ./binsync_state · · · · · · Export all annotations\n\n"
        "  rebrew binsync-export ./state --dry-run · · · · · Preview without writing\n\n"
        "  rebrew binsync-export ./state --json · · · · · · · Machine-readable output\n\n"
        "  rebrew binsync-export ./state --module SERVER · · Export one module only\n\n"
        "  rebrew binsync-export ./state --git · · · · · · · Export + git commit\n\n"
        "[dim]Produces BinSync-compatible TOML layout: functions/, global_vars.toml, "
        "structs/ — BinSync-native fields only (STATUS/CFLAGS stay in "
        "rebrew-functions.toml).[/dim]"
    ),
)


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CatalogFunction:
    """A catalog-only function, shaped like the annotation the export reads.

    Everything the export reads through ``getattr`` with a default (``symbol``,
    ``note``, ``ghidra``, ``prototype``, ``locals``, ``comments``) is absent by
    design: a discovered function has no source annotation to carry it.
    """

    va: int
    size: int
    name: str


# ---------------------------------------------------------------------------
# Global type resolution
# ---------------------------------------------------------------------------


def _as_int(value: object, default: int = 0) -> int:
    """Best-effort int from a metadata value (accepts decimal/hex strings).

    Finite integral floats (``16.0``) are accepted; non-integral floats and
    bools are rejected (``int(True)`` would invent size 1; ``int(12.9)``
    would truncate).  Unparseable values fall back to *default*.
    """
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value.is_integer() and abs(value) < 1e15:
            return int(value)
        return default
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def _write_function_toml(
    path: Path,
    *,
    name: str,
    va: int,
    size: int,
    prototype: str,
    locals_map: dict[int, dict[str, object]] | None = None,
) -> None:
    """Write one declib ``Function`` artifact.

    Carries the name, addr, size, prototype (body-stripped), and any stack
    variables from the LOCALS metadata.  rebrew's note/ghidra provenance and
    per-instruction comments live in ``comments.toml`` (see
    :func:`_write_comments_toml`), which is where upstream keeps them.
    """
    sig = strip_body(prototype) if prototype else ""
    func = serial.new_function(va, size, name=name or None, prototype=sig or None)
    for offset, variable in (locals_map or {}).items():
        serial.add_stack_variable(
            func,
            offset=offset,
            name=str(variable.get("name") or ""),
            type_=str(variable.get("type") or "") or None,
            size=_as_int(variable.get("size")) or None,
            addr=va,
        )
    serial.dump_artifact(path, func)


def _write_comments_toml(path: Path, comments: list[tuple[int, int, str]]) -> None:
    """Write decib ``Comment`` artifacts keyed by address."""
    artifacts = [
        serial.new_comment(addr, func_addr, comment)
        for addr, func_addr, comment in sorted(comments)
    ]
    serial.dump_many(path, "comment", artifacts, key="addr")


def _write_global_vars_toml(
    path: Path,
    globals_list: list[tuple[int, str, int, str, str | None]],
) -> None:
    """Write declib ``GlobalVariable`` artifacts keyed by address.

    Section is not part of declib's ``GlobalVariable``; import/overlay derive
    it from the binary by address instead of carrying it in the state.
    """
    artifacts = [
        serial.new_global_variable(va, name, type_ or "char", size if size > 0 else None)
        for va, name, size, type_, _section in sorted(globals_list)
    ]
    serial.dump_many(path, "global_variable", artifacts, key="addr")


# ---------------------------------------------------------------------------
# Struct field extraction
# ---------------------------------------------------------------------------


def _write_struct_toml(
    path: Path,
    name: str,
    fields: list[dict[str, Any]] | None = None,
) -> None:
    """Write one declib ``Struct`` artifact (members keyed by byte offset).

    Missing member offsets/sizes are filled from the field order and
    :func:`rebrew.types.type_size`.
    """
    from rebrew.types import type_size

    members: dict[int, tuple[str, str | None, int | None]] = {}
    next_offset = 0
    for field in fields or []:
        member_name = str(field.get("name") or "")
        if not member_name:
            continue
        member_type = str(field.get("type") or "int")
        size = field.get("size")
        offset = field.get("offset")
        if offset is None:
            offset = next_offset
        member_size = int(size) if size is not None else (type_size(member_type) or 0)
        members[int(offset)] = (member_name, member_type, member_size)
        next_offset = int(offset) + member_size
    size_total = max((off + (m[2] or 0) for off, m in members.items()), default=0)
    serial.dump_artifact(path, serial.new_struct(name, size_total, members))


# ---------------------------------------------------------------------------
# Enum / typedef extraction
# ---------------------------------------------------------------------------


def _write_enums_toml(path: Path, enums: dict[str, tuple[str, dict[str, int]]]) -> None:
    """Write declib ``enums.toml`` (``Enum.dumps_many`` keyed by name).

    declib's Enum carries only the name and member values; the raw body text
    that :func:`collect_enum_definitions` collected is not representable and
    is dropped (import synthesizes a typedef from name + members).
    """
    artifacts = [serial.new_enum(name, members) for name, (_raw, members) in sorted(enums.items())]
    serial.dump_many(path, "enum", artifacts, key="name")


def _write_typedefs_toml(path: Path, typedefs: dict[str, tuple[str, str]]) -> None:
    """Write declib ``typedefs.toml`` (``Typedef.dumps_many`` keyed by name)."""
    artifacts = [
        serial.new_typedef(name, underlying)
        for name, (_raw, underlying) in sorted(typedefs.items())
    ]
    serial.dump_many(path, "typedef", artifacts, key="name")


# ---------------------------------------------------------------------------
# Validation + git helpers
# ---------------------------------------------------------------------------


def _validate_binsync_dir(outdir: Path) -> list[str]:
    """Validate a written declib BinSync state directory; return warning strings."""
    warnings: list[str] = []
    funcs_dir = outdir / serial.FUNCTIONS_DIR
    if funcs_dir.is_dir():
        for toml_path in funcs_dir.glob("*.toml"):
            func = serial.load_artifact(toml_path, "function")
            if func is None:
                warnings.append(f"{toml_path.name}: unparseable Function artifact")
                continue
            if func.addr is None:
                warnings.append(f"{toml_path.name}: missing addr")
            if not func.name:
                warnings.append(f"{toml_path.name}: missing name")
    gv = outdir / serial.GLOBAL_VARS_FILE
    if gv.exists():
        for gvar in serial.load_many(gv, "global_variable"):
            if gvar.addr is None or not gvar.name:
                warnings.append("global_vars.toml: entry missing addr/name")
    return warnings


def _git_commit_state_dir(state_dir: Path, target: str) -> str | None:
    """Stage + commit the BinSync state directory.

    Returns the new commit hash on success, ``None`` on skip/failure (caller
    decides whether to surface a warning).
    """
    git_dir = state_dir / ".git"
    if not git_dir.exists():
        console.print(
            f"[yellow]warning:[/yellow] {state_dir} is not a git repository — skipping git commit"
        )
        return None
    probe = run_git(state_dir, "--version", timeout=5)
    if probe.returncode == 127:
        console.print("[yellow]warning:[/yellow] git not found — skipping commit")
        return None

    result = run_git(state_dir, "add", "-A", timeout=15)
    if result.returncode != 0:
        console.print(f"[yellow]warning:[/yellow] git add failed: {result.stderr.strip()}")
        return None

    status = run_git(state_dir, "status", "--porcelain", timeout=10)
    if status.returncode == 0 and not status.stdout.strip():
        console.print("[dim]No changes to commit.[/dim]")
        return None

    utc = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
    msg = f"rebrew binsync-export: {target} @ {utc}"
    commit = run_git(state_dir, "commit", "-m", msg, timeout=15)
    if commit.returncode != 0:
        # Empty commit (nothing changed) is not an error
        if (
            "nothing to commit" in commit.stdout.lower()
            or "nothing to commit" in commit.stderr.lower()
        ):
            console.print("[dim]No changes to commit.[/dim]")
            return None
        console.print(f"[yellow]warning:[/yellow] git commit failed: {commit.stderr.strip()}")
        return None

    rev = run_git(state_dir, "rev-parse", "HEAD", timeout=10)
    commit_hash = rev.stdout.strip() if rev.returncode == 0 else None
    prefix = f"{commit_hash[:8]} " if commit_hash else ""
    console.print(f"[green]Committed[/green] {prefix}— {msg}")
    return commit_hash


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    outdir: Path = typer.Argument(..., help="Output directory for the BinSync state"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    module: str | None = typer.Option(
        None, "--module", help="Only export this module (e.g. SERVER)"
    ),
    git_commit: bool = typer.Option(
        False, "--git", help="Stage and commit the state directory with git"
    ),
    clean: bool = typer.Option(
        False, "--clean", help="Remove orphan function TOMLs no longer in the catalog/annotations"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Export rebrew annotations to a BinSync state directory.

    Produces a ``functions/`` tree, ``global_vars.toml``, and ``structs/``
    placeholders compatible with BinSync's TOML state format.
    """
    cfg = require_config(target=target, json_mode=json_output)

    result = export_state(
        cfg,
        outdir,
        dry_run=dry_run,
        module=module,
        git_commit=git_commit,
        clean=clean,
    )
    print_export_result(result, json_output=json_output, dry_run=dry_run)


def export_state(
    cfg: ProjectConfig,
    outdir: Path,
    *,
    dry_run: bool,
    module: str | None = None,
    git_commit: bool = False,
    clean: bool = False,
) -> dict[str, object]:
    """Export rebrew annotations to a BinSync state directory (programmatic).

    Returns the result dict (counts + written paths + warnings).  ``empty``
    is True when there was nothing to export — the CLI turns that into an
    error, programmatic callers decide.
    """
    entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    # Optional module filter applies to both annotations and catalog entries
    if module is not None:
        entries = [e for e in entries if getattr(e, "module", "") == module]

    # Partition annotations
    func_entries = [e for e in entries if e.is_function]
    global_entries = [e for e in entries if e.is_data]

    # Also include functions from the project file / catalog that have not yet
    # been reversed (no .c annotation).  This makes BinSync reflect the full
    # binary, not just the reversed subset, so that collaborators see the
    # complete function list with offsets and sizes.
    catalog_func_entries: list[object] = []
    try:
        import warnings

        from rebrew.catalog import build_function_registry, cached_function_list

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            funcs = cached_function_list(cfg)
        ghidra_path = inventory_path_for(cfg.reversed_dir, cfg)
        bin_path = cfg.target_binary
        registry = build_function_registry(funcs, cfg, ghidra_path, bin_path)
        reversed_vas = {e.va for e in func_entries}
        # `va in reversed_vas` is an exact START match, so a catalog VA falling
        # *inside* an annotated function was exported as a separate function.
        # Heuristic discovery produces these constantly: it emits switch arms as
        # pseudo-functions (`case.0x1000ad61.*`) and splits bodies it cannot
        # walk.  Exporting them pollutes the shared state, and because import
        # reads the same state back, `sync --pull` then proposes creating them
        # as real functions -- inside code that is already EXACT/RELOC.
        # Build spans from the annotated sizes and skip anything they contain.
        annotated_spans = sorted(
            (e.va, e.va + int(getattr(e, "size", 0) or 0))
            for e in func_entries
            if int(getattr(e, "size", 0) or 0) > 0
        )
        _inside_annotated = span_contains_factory(annotated_spans)

        for va, reg_entry in registry.items():
            if va in reversed_vas or _inside_annotated(va):
                continue
            # Skip IAT thunks — they are not user functions
            if reg_entry.get("is_thunk"):
                continue
            size = int(reg_entry.get("canonical_size", 0) or 0)
            if size <= 0:
                continue
            # Fabricate a minimal annotation-like object for export.
            # Keep raw name only (no leading underscore) — the export step
            # derives the symbol, so stdcall decoration @N would be double-counted
            # if we pre-decorate here, and calling convention is unknown for
            # catalog-only entries anyway.
            raw_name = (
                reg_entry.get("list_name") or reg_entry.get("ghidra_name") or f"func_{va:08x}"
            )
            catalog_func_entries.append(
                _CatalogFunction(
                    va=va,
                    size=size,
                    name=raw_name,
                )
            )
    except Exception as exc:
        # A failed catalog scan would silently ship an incomplete export
        # (every not-yet-reversed function missing) — surface it.
        logger.warning("Catalog scan failed — export omits catalog-only functions", exc_info=True)
        console.print(
            f"[yellow]warning:[/] catalog scan failed ({exc.__class__.__name__}: {exc}); "
            "export includes annotations only, no catalog-only functions"
        )

    if module is not None:
        # Catalog-only entries carry no module attribution (""), so under a
        # --module filter they would all be exported unconditionally,
        # violating the filter contract.
        catalog_func_entries = []

    # Nothing at all to export?
    if not func_entries and not catalog_func_entries and not global_entries:
        return {
            "outdir": str(outdir),
            "dry_run": dry_run,
            "functions": 0,
            "globals": 0,
            "structs": 0,
            "enums": 0,
            "typedefs": 0,
            "function_files": [],
            "global_vars_file": None,
            "struct_files": [],
            "enums_file": None,
            "typedefs_file": None,
            "comments": 0,
            "comments_file": None,
            "metadata_file": None,
            "empty": True,
        }

    # Collect global vars with real names + types
    va_to_name = resolve_global_names(cfg, global_entries)
    va_to_type = resolve_global_types(cfg, global_entries)
    globals_list: list[tuple[int, str, int, str, str | None]] = []
    for e in global_entries:
        gname = va_to_name.get(e.va) or e.symbol or e.name or f"g_{e.va:08x}"
        gtype = va_to_type.get(e.va, "char")
        section = getattr(e, "section", "") or None
        globals_list.append((e.va, gname, e.size, gtype, section))

    struct_defs: dict[str, tuple[str, list[dict[str, Any]]]] = {
        e.struct: ("", []) for e in func_entries if e.struct
    }
    # Merge annotation funcs + catalog-only funcs for export
    all_func_entries: list[object] = list(func_entries) + list(catalog_func_entries)
    local_records = local_sync_records(cfg, all_func_entries + list(global_entries))
    remote_records = (
        remote_sync_records(cfg, outdir, local=local_records) if outdir.exists() else {}
    )
    health = sync_health(cfg, outdir, local_records, remote_records)
    if health["blocked"]:
        raise ValueError(f"sync refused: {', '.join(health['issues'])}")
    baseline = load_sync_baseline(cfg, outdir)
    if not dry_run:
        funcs_dir = outdir / "functions"
        funcs_dir.mkdir(parents=True, exist_ok=True)
        if struct_defs:
            (outdir / "structs").mkdir(parents=True, exist_ok=True)

    merged_records = {
        key: merge_sync_record(key, fields, remote_records.get(key, {}), baseline)
        for key, fields in local_records.items()
        if key not in baseline or key in remote_records
    }
    globals_list = [
        (
            int(key.rsplit(".", 1)[1], 16),
            fields.get("name", ""),
            _as_int(fields.get("size")),
            fields.get("type", "char"),
            None,
        )
        for key, fields in {**remote_records, **merged_records}.items()
        if key.startswith("global.")
    ]
    written_funcs: list[str] = []
    comment_artifacts: list[tuple[int, int, str]] = []
    metadata_comments: dict[int, tuple[int, str]] = {}
    for entry in all_func_entries:
        va = entry.va  # type: ignore[attr-defined]
        name = getattr(entry, "symbol", "") or getattr(entry, "name", "") or f"func_{va:08x}"

        key = next(
            k for k in local_records if k.startswith("function.") and k.endswith(f".0x{va:x}")
        )
        fields = merged_records.get(key)
        if fields is None:
            continue  # remote removal needs explicit resolution; do not resurrect it
        name = fields.get("name", name)
        func_path = outdir / "functions" / f"{va:08x}.toml"
        if not dry_run:
            _write_function_toml(
                func_path,
                name=name,
                va=va,
                size=_as_int(fields.get("size")),
                prototype=str(fields.get("prototype") or ""),
                locals_map={_as_int(k): v for k, v in (fields.get("stack_vars") or {}).items()},
            )
        written_funcs.append(str(func_path))

        # rebrew provenance comments live in comments.toml (upstream's home
        # for them), not the function file.
        note = fields.get("note", "")
        ghidra = fields.get("ghidra", "")
        if note:
            comment_artifacts.append((va + 1, va, f"[rebrew:note] {note}"))
        if ghidra and ghidra != name:
            comment_artifacts.append((va + 2, va, f"[rebrew:ghidra] {ghidra}"))
        for addr, comment in (fields.get("comments") or {}).items():
            if isinstance(comment, dict):
                metadata_comments[int(str(addr), 0)] = (va, str(comment.get("comment") or ""))

    # A source ``// ANALYSIS @ 0xADDR: text`` marker wins over the metadata
    # entry for the same address (the analyst edited it in source), so edits
    # flow out to comments.toml.
    merged_comments = dict(metadata_comments)

    comment_artifacts.extend(
        (addr, owner, text) for addr, (owner, text) in sorted(merged_comments.items())
    )

    from rebrew.binsync.state import load_binsync_comments

    existing_comments = load_binsync_comments(outdir) if outdir.exists() else {}
    emitted = {addr for addr, _owner, _text in comment_artifacts}
    comment_artifacts.extend(
        (addr, int(comment.get("func_addr") or addr), str(comment.get("comment") or ""))
        for addr, comment in existing_comments.items()
        if addr not in emitted
        and not any(
            key.startswith("function.") and key.endswith(f".0x{comment.get('func_addr', 0):x}")
            for key in merged_records
        )
    )
    written_comments = ""
    if comment_artifacts or (outdir / "comments.toml").exists():
        comments_path = outdir / "comments.toml"
        if not dry_run:
            _write_comments_toml(comments_path, comment_artifacts)
        written_comments = str(comments_path)

    written_globals = ""
    if globals_list:
        global_path = outdir / "global_vars.toml"
        if not dry_run:
            _write_global_vars_toml(global_path, globals_list)
        written_globals = str(global_path)

    written_structs: list[str] = []
    merged_types = {**remote_records, **merged_records}
    for sname in struct_defs:
        key = f"struct.{sname}"
        if key not in baseline or key in remote_records:
            merged_types.setdefault(key, {"definition": {}})
    for key, record in sorted(merged_types.items()):
        if not key.startswith("struct."):
            continue
        sname = key.split(".", 1)[1]
        fields_ = record.get("definition") or {}
        struct_fields = [{"name": name, **member} for name, member in fields_.items()]
        spath = outdir / "structs" / f"{serial.sanitize_name(sname)}.toml"
        if not dry_run:
            spath.parent.mkdir(parents=True, exist_ok=True)
            _write_struct_toml(spath, sname, fields=struct_fields or None)
        written_structs.append(str(spath))

    written_enums = ""
    merged_enums = {
        key.split(".", 1)[1]: ("", record["definition"])
        for key, record in merged_types.items()
        if key.startswith("enum.")
    }
    if merged_enums:
        enum_path = outdir / "enums.toml"
        if not dry_run:
            _write_enums_toml(enum_path, merged_enums)
        written_enums = str(enum_path)

    written_typedefs = ""
    merged_typedefs = {
        key.split(".", 1)[1]: ("", record["definition"])
        for key, record in merged_types.items()
        if key.startswith("typedef.")
    }
    if merged_typedefs:
        typedef_path = outdir / "typedefs.toml"
        if not dry_run:
            _write_typedefs_toml(typedef_path, merged_typedefs)
        written_typedefs = str(typedef_path)

    # State.parse requires metadata.toml; user is the repo identity or rebrew.
    metadata_file = ""
    if not dry_run:
        serial.write_metadata(outdir, user=serial.state_user(outdir))
        metadata_file = str(outdir / serial.METADATA_FILE)

    # BinSync binds a repo to one binary through the MD5 at its root.  Emit it
    # so a state dir is self-identifying and doctor can catch a dir pointed at
    # the wrong target.
    binary_hash = ""
    if not dry_run:
        binary_hash = _write_binary_hash(outdir, cfg)

    # --clean before manifest/git so the committed tree matches on-disk state
    # and a re-export with identical content is a no-op.
    cleaned: list[str] = []
    if clean and not dry_run:
        try:
            alive_vas = {int(e.va) for e in all_func_entries}  # type: ignore[attr-defined]
            funcs_dir = outdir / "functions"
            if funcs_dir.is_dir():
                for p in funcs_dir.glob("*.toml"):
                    try:
                        va = int(p.stem, 16)
                    except ValueError:
                        continue
                    if va not in alive_vas:
                        p.unlink()
                        cleaned.append(str(p))
                if cleaned:
                    console.print(f"[dim]Cleaned {len(cleaned)} orphan TOML(s)[/dim]")
        except Exception as exc:
            # --clean is an explicit request: silently skipping it would leave
            # the user believing stale TOMLs are gone (state-dir drift).
            logger.warning("Orphan TOML cleanup failed", exc_info=True)
            console.print(
                f"[yellow]warning:[/] --clean failed ({exc.__class__.__name__}: {exc}); "
                "orphan TOMLs were left in place"
            )

    # Validation warnings (non-fatal)
    warnings_list: list[str] = []
    if not dry_run:
        warnings_list = _validate_binsync_dir(outdir)
        for w in warnings_list:
            console.print(f"[yellow]warning:[/yellow] {w}")

    # Freshness manifest BEFORE git so an unchanged re-export leaves a clean
    # tree (no post-commit timestamp dirt that the next --git would commit).
    # The commit id is returned in the CLI result / git log — writing it back
    # into manifest.toml after commit would re-dirty the working tree.
    manifest_hash = ""
    if not dry_run:
        manifest_hash = _write_manifest(
            outdir,
            None,
            target=getattr(cfg, "target_name", "") or "",
            binary_hash=binary_hash,
            input_hash=health["input_hash"],
        )
        shared_records = remote_sync_records(cfg, outdir, local=local_records)
        acknowledge_sync(cfg, outdir, local_records, shared_records)
        health = sync_health(cfg, outdir, local_records, shared_records)

    # Optional git commit (opt-in, after all writes including manifest)
    commit_hash: str | None = None
    if git_commit and not dry_run:
        commit_hash = _git_commit_state_dir(outdir, cfg.target_name or cfg.marker or "default")

    return {
        "outdir": str(outdir),
        "dry_run": dry_run,
        "functions": len(written_funcs),
        "globals": len(globals_list),
        "structs": len(written_structs),
        "enums": len(merged_enums),
        "typedefs": len(merged_typedefs),
        "function_files": written_funcs,
        "global_vars_file": written_globals or None,
        "struct_files": written_structs,
        "enums_file": written_enums or None,
        "typedefs_file": written_typedefs or None,
        "comments": len(comment_artifacts),
        "comments_file": written_comments or None,
        "metadata_file": metadata_file or None,
        "warnings": warnings_list,
        "cleaned": cleaned,
        "commit": commit_hash,
        "manifest": manifest_hash,
        "binary_hash": binary_hash,
        "module": module,
        "empty": False,
        "health": health,
    }


def _write_binary_hash(outdir: Path, cfg: ProjectConfig) -> str:
    """Write ``binary_hash`` (MD5 of the target binary) to the state root.

    Returns the digest, or "" when the target binary is unavailable (the
    check that consumes it skips rather than reporting a false mismatch).
    """
    binary = getattr(cfg, "target_binary", None)
    if binary is None or not Path(binary).exists():
        return ""
    digest = md5_file(Path(binary))
    serial.write_state_text(outdir / "binary_hash", digest)
    return digest


def _write_manifest(
    outdir: Path,
    commit_hash: str | None,
    *,
    target: str = "",
    binary_hash: str = "",
    input_hash: str = "",
) -> str:
    """Write ``manifest.toml`` (timestamp, content hash, commit) and return the hash.

    Idempotent: when ``content_hash`` / ``target`` / ``binary_hash`` match the
    existing manifest, the file is left untouched (``exported_at`` preserved)
    unless only the ``commit`` field needs updating — then ``exported_at`` is
    still preserved so a re-export cannot create timestamp-only git churn.

    Raises:
        OSError: An artifact under *outdir* cannot be read.  The manifest is
            left unchanged — a hash that skipped that file would report the
            tree unchanged while it still differed on disk.
    """
    from datetime import UTC, datetime

    from rebrew.metadata import FORMAT_VERSION

    content_hash = artifact_hash(outdir)
    manifest_path = outdir / "manifest.toml"
    existing: dict[str, Any] | None = None
    if manifest_path.exists():
        try:
            # utf-8-sig: Windows editors may prefix EF BB BF; plain utf-8
            # leaves U+FEFF and tomlkit rejects the file (EmptyKeyError).
            parsed = tomlkit.parse(manifest_path.read_text(encoding="utf-8-sig"))
            if isinstance(parsed, dict):
                existing = dict(parsed)
        except (OSError, TypeError, ValueError, tomlkit.exceptions.TOMLKitError):
            existing = None
    if existing is not None and existing.get("content_hash") == content_hash:
        same_target = not target or existing.get("target") == target
        same_binary = not binary_hash or existing.get("binary_hash") == binary_hash
        same_input = not input_hash or existing.get("input_hash") == input_hash
        same_schema = existing.get("metadata_schema") == FORMAT_VERSION
        if same_target and same_binary and same_input and same_schema:
            existing_commit = existing.get("commit")
            if commit_hash is None or commit_hash == existing_commit:
                # Fully unchanged — no rewrite, no timestamp bump.
                return content_hash
            # Content same; only the commit field needs a touch.
            doc = tomlkit.document()
            doc["exported_at"] = existing.get("exported_at") or datetime.now(UTC).isoformat()
            doc["content_hash"] = content_hash
            doc["metadata_schema"] = FORMAT_VERSION
            if input_hash:
                doc["input_hash"] = input_hash
            if target or existing.get("target"):
                doc["target"] = target or existing.get("target")
            if binary_hash or existing.get("binary_hash"):
                doc["binary_hash"] = binary_hash or existing.get("binary_hash")
            doc["commit"] = commit_hash
            atomic_write_locked(manifest_path, tomlkit.dumps(doc), encoding="utf-8")
            return content_hash
    doc = tomlkit.document()
    doc["exported_at"] = datetime.now(UTC).isoformat()
    doc["content_hash"] = content_hash
    doc["metadata_schema"] = FORMAT_VERSION
    if input_hash:
        doc["input_hash"] = input_hash
    if target:
        doc["target"] = target
    if binary_hash:
        doc["binary_hash"] = binary_hash
    if commit_hash:
        doc["commit"] = commit_hash
    atomic_write_locked(manifest_path, tomlkit.dumps(doc), encoding="utf-8")
    return content_hash


def print_export_result(result: dict[str, object], *, json_output: bool, dry_run: bool) -> None:
    """Render an :func:`export_state` result (the CLI summary path)."""
    if bool(result.get("empty")):
        error_exit("No annotations found.", json_mode=json_output)

    outdir = str(result["outdir"])
    written_funcs = result_count(result, "functions")
    globals_list = result_count(result, "globals")
    written_structs = result_count(result, "structs")
    written_enums = result_count(result, "enums")
    written_typedefs = result_count(result, "typedefs")
    written_comments = result_count(result, "comments")
    warnings_list = result_paths(result, "warnings")
    cleaned = result_paths(result, "cleaned")
    commit_hash = result.get("commit")
    module = result.get("module")
    if json_output:
        payload: dict[str, object] = {
            "outdir": outdir,
            "dry_run": dry_run,
            "functions": written_funcs,
            "globals": globals_list,
            "structs": written_structs,
            "enums": written_enums,
            "typedefs": written_typedefs,
            "comments": written_comments,
            "function_files": result_paths(result, "function_files"),
            "global_vars_file": result.get("global_vars_file"),
            "struct_files": result_paths(result, "struct_files"),
            "enums_file": result.get("enums_file"),
            "typedefs_file": result.get("typedefs_file"),
            "comments_file": result.get("comments_file"),
            "metadata_file": result.get("metadata_file"),
        }
        if "health" in result:
            payload["health"] = result["health"]
        if warnings_list:
            payload["warnings"] = warnings_list
        if cleaned:
            payload["cleaned"] = cleaned
        if commit_hash:
            payload["commit"] = commit_hash
        if module is not None:
            payload["module"] = module
        json_print(payload)
    else:
        action = "[dim]would write[/dim]" if dry_run else "Wrote"
        console.print(
            f"{action} [bold]{written_funcs}[/bold] functions, "
            f"[bold]{globals_list}[/bold] globals, "
            f"[bold]{written_structs}[/bold] structs, "
            f"[bold]{written_enums}[/bold] enums, "
            f"[bold]{written_typedefs}[/bold] typedefs, "
            f"[bold]{written_comments}[/bold] comments "
            f"to [cyan]{outdir}[/cyan]"
        )
        health = result.get("health", {})
        if isinstance(health, dict):
            for message in sync_health_messages(health):
                console.print(message, markup=False)


def main_entry() -> None:
    """Run the Typer CLI application."""
    run_standalone(main)


if __name__ == "__main__":
    main_entry()
