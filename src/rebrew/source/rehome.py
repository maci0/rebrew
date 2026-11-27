"""rehome.py - Point function and data rows at the source file that now defines them.

Moving a function's definition between multi-function files (restoring the
original translation-unit layout) leaves its row's ``file`` naming the old
file, and ``rebrew test`` then looks for the symbol in the wrong object.
``merge`` and ``split`` retarget the rows they move; a hand move had no writer.
A renamed or moved file (``git mv``) leaves every function and data row that
names it stale; ``--from OLD --to NEW`` retargets them all at once.
"""

lazy from pathlib import Path
lazy from typing import Any

import typer

from rebrew.cli import TargetOption, console, error_exit, json_print, require_config

app = typer.Typer(
    help="Point function and data rows at the source file that now defines them.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source rehome 0x1000ca90=src/game/command.c  # Re-home one function\n\n"
        "  rebrew source rehome 0x1000ca90=a.c 0x1000cb20=a.c --dry-run\n\n"
        "  # Join a shared definition\n"
        "  rebrew source rehome 0x4f13a0=src/game/ahm.c:ahm_CountBusyWorkers -t TL\n\n"
        "  rebrew source rehome --from src/a/x.c --to src/b/y.c  # After git mv\n\n"
        "[dim]The destination must define each moved function (or NAME after a colon, which also renames the row); the definition text is not moved. A LIBRARY row may move to a library_*.h header, which declares no bodies.[/dim]"
    ),
)


def _source(cfg: Any, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = cfg.root / path
    if not path.is_file():
        raise ValueError(f"{value} is not a file")
    return path


def _row_name(entry: dict[str, Any]) -> str:
    return str(entry.get("name") or str(entry.get("symbol") or "").lstrip("_"))


def _defines(path: Path, defined: set[str], name: str, entry: dict[str, Any]) -> bool:
    """Whether *path* can own the row: it defines *name*, or it is a library header.

    A ``library_*.h`` header declares no bodies (the linker supplies them), so a
    LIBRARY row moves to one without a definition check.
    """
    library_header = path.name.startswith("library_") and path.name.endswith(".h")
    return name in defined or (entry.get("kind") == "LIBRARY" and library_header)


def _defined_names(path: Path) -> set[str]:
    from rebrew.c_syntax.parser import find_c_function_definitions
    from rebrew.utils import read_source_text

    text, _encoding = read_source_text(path)
    return {fn for fn, _ in find_c_function_definitions(text)}


def _rows_naming(
    cfg: Any, path: Path
) -> tuple[list[tuple[str, int, dict[str, Any]]], list[tuple[str, int, dict[str, Any]]]]:
    """Function rows and data rows, across every module, whose ``file`` names *rel*."""
    from rebrew.metadata.bindings import function_rows_for_file
    from rebrew.metadata.data import load_data_metadata
    from rebrew.metadata.functions import identity_file, load_metadata, stored_file_matches

    metadata_dir = cfg.metadata_dir
    rel = identity_file(path, metadata_dir)
    return (
        sorted(
            function_rows_for_file(
                path,
                metadata_dir,
                load_metadata(metadata_dir, deepcopy=False),
                project_root=cfg.root,
            )
        ),
        sorted(
            (module, va, entry)
            for (module, va), entry in load_data_metadata(metadata_dir, deepcopy=False).items()
            if stored_file_matches(str(entry.get("file") or ""), rel)
        ),
    )


def _split_bind(value: str) -> tuple[str, str | None]:
    """``PATH:NAME`` -> (PATH, NAME); a plain ``PATH`` binds no new name."""
    from rebrew.utils import is_safe_c_ident

    path, sep, name = value.rpartition(":")
    if sep and path and is_safe_c_ident(name):
        return path, name
    return value, None


def _check_definition_ownership(cfg: Any, rows: list[dict[str, Any]]) -> None:
    """Refuse a source definition already claimed at another VA in its target."""
    from rebrew.metadata.binding_history import retired_binding
    from rebrew.metadata.bindings import function_rows_for_file
    from rebrew.metadata.functions import load_metadata
    from rebrew.utils import preset_module_key

    stored = load_metadata(cfg.metadata_dir, deepcopy=False)
    changes = {
        (row["module"], row["va"]): stored.get((row["module"], row["va"]), {}) | row["identity"]
        for row in rows
    }
    if len(changes) != len(rows):
        raise ValueError("rehome repeats a function address")
    effective = stored | changes
    for (module, va), entry in changes.items():
        root = cfg.root if entry.get("kind") == "LIBRARY" else cfg.metadata_dir
        providers = function_rows_for_file(
            root / entry["file"], cfg.metadata_dir, effective, project_root=cfg.root
        )
        for other_module, other_va, other in providers:
            if (
                other_va != va
                and preset_module_key(other_module) == preset_module_key(module)
                and not retired_binding(other)
                and (
                    _row_name(other) == _row_name(entry)
                    or (entry.get("symbol") and other.get("symbol") == entry["symbol"])
                )
            ):
                raise ValueError(
                    f"replacement definition/symbol already belongs to {other_module}.0x{other_va:x}"
                )


def rehome_functions(cfg: Any, specs: list[str], *, dry_run: bool = False) -> list[dict[str, Any]]:
    """Set each ``0xVA=PATH`` function row's ``file`` to PATH after checking PATH defines it.

    ``0xVA=PATH:NAME`` binds the row to the definition NAME in PATH instead of
    its current name: the row's ``name`` becomes NAME and its ``symbol`` keeps
    its decoration around NAME. This is how a second module's row joins an
    existing shared definition.
    """
    from rebrew.config import target_module
    from rebrew.metadata.functions import (
        get_entry,
        identity_file,
        record_function_rows,
        validate_identity_file,
    )
    from rebrew.source.rename_ops import redecorated_symbol

    module = target_module(cfg) or ""
    if not module:
        raise ValueError("no target module configured to address the function metadata")
    rows: list[dict[str, Any]] = []
    evidence_moves: list[tuple[Path, Path]] = []
    for spec in specs:
        va_s, sep, value = spec.partition("=")
        value = value.strip()
        if not sep or not value:
            raise ValueError(f"rehome wants 0xVA=PATH or 0xVA=PATH:NAME, got {spec!r}")
        va = int(va_s, 16)
        entry = get_entry(cfg.metadata_dir, va, module)
        old_name = _row_name(entry)
        if not old_name:
            raise ValueError(f"no function row at {module}.0x{va:x}")
        value, bind = _split_bind(value)
        name = bind or old_name
        path = _source(cfg, value)
        if not _defines(path, _defined_names(path), name, entry):
            raise ValueError(f"{value} does not define {name}")
        owner_root = cfg.root if entry.get("kind") == "LIBRARY" else cfg.metadata_dir
        identity = validate_identity_file(identity_file(path, owner_root))
        old_file = str(entry.get("file") or "")
        if old_file and old_file != identity:
            evidence_moves.append((owner_root / old_file, path))
        row: dict[str, Any] = {
            "va": f"0x{va:x}",
            "name": name,
            "old_file": old_file,
            "file": identity,
        }
        if bind is not None and bind != old_name:
            old_symbol = str(entry.get("symbol") or f"_{old_name}")
            row["old_name"] = old_name
            row["symbol"] = redecorated_symbol(old_symbol, bind)
        rows.append(row)
    updates = [
        {
            "module": module,
            "va": int(r["va"], 16),
            "identity": {"file": r["file"]}
            | ({"name": r["name"], "symbol": r["symbol"]} if "symbol" in r else {}),
        }
        for r in rows
    ]
    _check_definition_ownership(cfg, updates)
    if not dry_run:
        record_function_rows(cfg.metadata_dir, updates, overwrite_name=True, updated_by="rehome")
        for old_path, new_path in evidence_moves:
            _follow_assembly_evidence(cfg, old_path, new_path)
    return rows


def retarget_file(
    cfg: Any, old: str, new: str, *, dry_run: bool = False
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Point every function and data row naming *old* at *new*, in every module.

    *new* must exist and define each moved function by name; data rows only
    need *new* to exist. *old* may already be gone. Each store takes one
    locked write, functions first. Returns the function rows and data rows.
    """
    from rebrew.metadata.data import set_data_fields_batch
    from rebrew.metadata.functions import (
        identity_file,
        record_function_rows,
        validate_identity_file,
    )

    old_path = Path(old) if Path(old).is_absolute() else cfg.root / old
    old_rel = validate_identity_file(identity_file(old_path, cfg.metadata_dir))
    new_path = _source(cfg, new)
    new_rel = validate_identity_file(identity_file(new_path, cfg.metadata_dir))
    if old_rel == new_rel:
        raise ValueError(f"--from and --to name the same file: {new_rel}")
    functions, data = _rows_naming(cfg, old_path)
    if not functions and not data:
        raise ValueError(f"no function or data row names {old_rel}")
    defined = _defined_names(new_path)
    function_rows: list[dict[str, Any]] = []
    for module, va, entry in functions:
        name = _row_name(entry)
        if not name:
            raise ValueError(f"function row {module}.0x{va:x} has no name to check in {new}")
        if not _defines(new_path, defined, name, entry):
            raise ValueError(f"{new} does not define {name} ({module}.0x{va:x})")
        owner_root = cfg.root if entry.get("kind") == "LIBRARY" else cfg.metadata_dir
        function_rows.append(
            {
                "module": module,
                "va": f"0x{va:x}",
                "name": name,
                "old_file": str(entry.get("file") or ""),
                "file": validate_identity_file(identity_file(new_path, owner_root)),
            }
        )
    data_rows = [
        {
            "module": module,
            "va": f"0x{va:x}",
            "name": str(entry.get("name") or ""),
            "old_file": str(entry.get("file") or ""),
            "file": new_rel,
        }
        for module, va, entry in data
    ]
    updates = [
        {"module": row["module"], "va": int(row["va"], 16), "identity": {"file": row["file"]}}
        for row in function_rows
    ]
    _check_definition_ownership(cfg, updates)
    if not dry_run:
        record_function_rows(cfg.metadata_dir, updates, updated_by="rehome")
        set_data_fields_batch(
            cfg.metadata_dir,
            [
                {"module": module, "va": va, "fields": {"file": new_rel}, "updated_by": "rehome"}
                for module, va, _entry in data
            ],
        )
        _follow_assembly_evidence(cfg, old_path, new_path)
    return function_rows, data_rows


def _follow_assembly_evidence(cfg: Any, old_path: Path, new_path: Path) -> None:
    """Keep documented original-assembly records filed under the live path.

    Assembly provenance is keyed by source path, so a moved file would lose its
    reviewed evidence and fall back to "whole-function asm is not allowed".
    """
    from rebrew.metadata.source_provenance import rename_source_provenance

    directory = cfg.metadata_dir.resolve()
    if not old_path.exists() and not new_path.exists():
        return
    try:
        rename_source_provenance(directory, {}, move=(old_path, new_path))
    except ValueError:
        # A record already under the new path means an earlier pass moved it.
        return


@app.callback(invoke_without_command=True)
def main(
    specs: list[str] | None = typer.Argument(
        None,
        metavar="0xVA=PATH[:NAME]",
        help="Function VA and its new file; :NAME binds the row to that definition",
    ),
    from_file: str | None = typer.Option(
        None,
        "--from",
        help="Retarget every row naming this old source path; requires --to; excludes positional specs",
        metavar="<path>",
    ),
    to_file: str | None = typer.Option(
        None,
        "--to",
        help="New source path; requires --from; excludes positional specs",
        metavar="<path>",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Point function and data rows at the source file that now defines them."""
    bulk = from_file is not None or to_file is not None
    if bulk and (from_file is None or to_file is None):
        error_exit("--from and --to go together", json_mode=json_output)
    if bulk == bool(specs):
        error_exit("give 0xVA=PATH specs or --from OLD --to NEW", json_mode=json_output)
    cfg = require_config(target=target, json_mode=json_output)
    data: list[dict[str, Any]] = []
    try:
        if from_file is not None and to_file is not None:
            rows, data = retarget_file(cfg, from_file, to_file, dry_run=dry_run)
        else:
            rows = rehome_functions(cfg, specs or [], dry_run=dry_run)
    except ValueError as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        if bulk:
            json_print({"rows": rows, "data": data, "dry_run": dry_run})
        else:
            json_print({"rows": rows, "dry_run": dry_run})
        return
    for r in rows:
        console.print(f"{r['va']} {r['name']}: {r['old_file'] or '-'} -> {r['file']}")
    for r in data:
        console.print(f"data {r['va']} {r['name'] or '-'}: {r['old_file']} -> {r['file']}")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
