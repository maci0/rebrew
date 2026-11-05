"""Materialize optional function anchors without creating or changing bindings."""

lazy import hashlib
lazy import json
lazy from pathlib import Path
lazy from typing import Any

import typer

lazy from rebrew.c_parser import find_c_function_definitions
lazy from rebrew.cli import (
    EXPECTED_DIGEST_HELP,
    console,
    error_exit,
    json_print,
    require_config,
    run_cli,
)
lazy from rebrew.config import ProjectConfig
lazy from rebrew.metadata.anchors import add_address_anchor, parse_address_anchors
lazy from rebrew.metadata.binding_history import retired_binding
lazy from rebrew.metadata.bindings import function_rows_for_file, source_bindings
lazy from rebrew.metadata.functions import load_metadata
lazy from rebrew.metadata.storage import metadata_store_paths, metadata_write_lock, snapshot_input
lazy from rebrew.rename_ops import FileChange, RenamePlan, SourceEdit, apply_rename_plan
lazy from rebrew.utils import preset_module_key, read_source_text

app = typer.Typer(
    context_settings={"allow_interspersed_args": True},
    help="Materialize ADDRESS anchors for existing canonical function bindings.",
    epilog=(
        "[bold]Examples:[/bold]\n\n  rebrew source anchors src/unit.c --dry-run --json\n\n"
        "apply the reviewed preview with --expected-digest DIGEST. "
        "All modules bound to selected files are included. Ambiguous definitions are refused."
    ),
)


def materialize_anchors(
    cfg: ProjectConfig,
    files: list[Path],
    *,
    dry_run: bool = True,
    expected_digest: str | None = None,
) -> dict[str, Any]:
    """Plan all selected files before publishing, retaining encoding and provenance."""
    paths = sorted({(cfg.root / path).resolve() for path in files})
    if not paths or any(
        not path.is_relative_to(cfg.root.resolve())
        or not path.is_file()
        or path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}
        for path in paths
    ):
        raise ValueError("select existing C/C++ sources inside the project")
    inputs = set(metadata_store_paths(cfg.metadata_dir)) | set(paths)
    config = cfg.root / "rebrew-project.toml"
    if config.exists():
        inputs.add(config)
    original = {path: snapshot_input(path) for path in inputs}
    entries = load_metadata(cfg.metadata_dir)
    changes = []
    bindings = []
    for path in paths:
        text, encoding = read_source_text(path)
        source_bindings(
            text,
            path,
            None,
            None,
            cfg.metadata_dir,
            project_root=cfg.root,
            function_entries=entries,
        )
        definitions = find_c_function_definitions(text)
        rows = function_rows_for_file(path, cfg.metadata_dir, entries, project_root=cfg.root)
        active = {(module, va): row for module, va, row in rows if not retired_binding(row)}
        seen = set()
        for anchor in parse_address_anchors(text):
            key = (preset_module_key(anchor.module), anchor.va)
            if key in seen:
                raise ValueError(
                    f"{path}: duplicate ADDRESS anchor for {anchor.module}.{anchor.va:#x}"
                )
            seen.add(key)
            if anchor.kind == "FUNCTION" and (
                key not in active or active[key].get("name") != anchor.name
            ):
                raise ValueError(f"{path}: existing anchor has no active canonical binding")
        updated = text
        edits = []
        for module, va, row in sorted(rows, key=lambda item: (item[0], item[1])):
            if retired_binding(row):
                continue
            name = str(row.get("name") or "")
            lines = [line for candidate, line in definitions if candidate == name]
            if len(lines) != 1:
                raise ValueError(f"{path}: {module}.{va:#x} requires one definition of {name!r}")
            if (preset_module_key(module), va) not in seen:
                updated = add_address_anchor(updated, module, va, name)
            bindings.append({"file": str(path), "module": module, "va": va, "name": name})
            edits.append(SourceEdit(lines[0], 1, "address anchor"))
        # Check every generated anchor against canonical identities, including other modules.
        source_bindings(
            updated,
            path,
            None,
            None,
            cfg.metadata_dir,
            project_root=cfg.root,
            function_entries=entries,
        )
        if updated != text:
            changes.append(FileChange(path, text, updated, encoding, edits))
    payload = {
        "inputs": {str(p): hashlib.sha256(raw).hexdigest() for p, raw in original.items()},
        "outputs": {str(c.path): c.new_text for c in changes},
        "bindings": bindings,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    if expected_digest is not None and digest != expected_digest:
        raise ValueError("anchor inputs changed; review a new preview")
    report = {
        "input_digest": digest,
        "bindings": bindings,
        "files": [
            {"file": str(c.path), "before": c.old_text, "after": c.new_text} for c in changes
        ],
        "dry_run": dry_run,
        "verdicts_changed": False,
    }
    if any(snapshot_input(path) != raw for path, raw in original.items()):
        raise ValueError("anchor inputs changed during planning")
    if not dry_run:
        if expected_digest is None:
            raise ValueError("apply requires --expected-digest from a reviewed --dry-run")
        with metadata_write_lock(cfg.metadata_dir, "rebrew-functions.toml"):
            if set(metadata_store_paths(cfg.metadata_dir)) | set(paths) | (
                {config} if config.exists() else set()
            ) != inputs or any(snapshot_input(path) != raw for path, raw in original.items()):
                raise ValueError("anchor inputs changed before publication")
            apply_rename_plan(cfg, RenamePlan("anchors", "", "", files=changes))
    return report


@app.callback(invoke_without_command=True)
def main(
    files: list[Path] = typer.Argument(..., help="Source files with existing canonical bindings"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    expected_digest: str | None = typer.Option(
        None, "--expected-digest", help=EXPECTED_DIGEST_HELP
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Write only optional ADDRESS comments; never create identities or earn verdicts."""
    cfg = require_config(json_mode=json_output)
    try:
        report = materialize_anchors(cfg, files, dry_run=dry_run, expected_digest=expected_digest)
    except (OSError, ValueError, RuntimeError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        console.print(report)


def main_entry() -> None:
    """Run the Typer CLI application."""
    run_cli(app)
