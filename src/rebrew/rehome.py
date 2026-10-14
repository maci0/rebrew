"""rehome.py - Point function and data rows at the source file that now defines them.

Moving a function's definition between multi-function files (restoring the
original translation-unit layout) leaves its row's ``file`` naming the old
file, and ``rebrew test`` then looks for the symbol in the wrong object.
``merge`` and ``split`` retarget the rows they move; a hand move had no writer.
A renamed or moved file (``git mv``) leaves every function and data row that
names it stale; ``--from OLD --to NEW`` retargets them all at once.
"""

from pathlib import Path
from typing import Any

import typer

from rebrew.cli import TargetOption, console, error_exit, json_print, require_config

app = typer.Typer(
    help="Point function and data rows at the source file that now defines them.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source rehome 0x1000ca90=src/game/command.c · Re-home one function\n\n"
        "  rebrew source rehome 0x1000ca90=a.c 0x1000cb20=a.c --dry-run\n\n"
        "  rebrew source rehome 0x4f13a0=src/game/ahm.c:ahm_CountBusyWorkers -t TL · Join a shared definition\n\n"
        "  rebrew source rehome --from src/a/x.c --to src/b/y.c · After git mv\n\n"
        "[dim]The destination must define each moved function (or NAME after a colon, which also renames the row); the definition text is not moved.[/dim]"
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


def _defined_names(path: Path) -> set[str]:
    from rebrew.c_parser import find_c_function_definitions

    return {fn for fn, _ in find_c_function_definitions(path.read_text(errors="replace"))}


def _rows_naming(
    metadata_dir: Any, rel: str
) -> tuple[list[tuple[str, int, dict[str, Any]]], list[tuple[str, int, dict[str, Any]]]]:
    """Function rows and data rows, across every module, whose ``file`` names *rel*."""
    from rebrew.metadata.data import load_data_metadata
    from rebrew.metadata.functions import load_metadata, stored_file_matches

    def naming(
        store: dict[tuple[str, int], dict[str, Any]],
    ) -> list[tuple[str, int, dict[str, Any]]]:
        return sorted(
            (module, va, entry)
            for (module, va), entry in store.items()
            if stored_file_matches(str(entry.get("file") or ""), rel)
        )

    return (
        naming(load_metadata(metadata_dir, deepcopy=False)),
        naming(load_data_metadata(metadata_dir)),
    )


def _split_bind(value: str) -> tuple[str, str | None]:
    """``PATH:NAME`` -> (PATH, NAME); a plain ``PATH`` binds no new name."""
    from rebrew.utils import is_safe_c_ident

    path, sep, name = value.rpartition(":")
    if sep and path and is_safe_c_ident(name):
        return path, name
    return value, None


def rehome_functions(cfg: Any, specs: list[str], *, dry_run: bool = False) -> list[dict[str, Any]]:
    """Set each ``0xVA=PATH`` function row's ``file`` to PATH after checking PATH defines it.

    ``0xVA=PATH:NAME`` binds the row to the definition NAME in PATH instead of
    its current name: the row's ``name`` becomes NAME and its ``symbol`` keeps
    its decoration around NAME. This is how a second module's row joins an
    existing shared definition.
    """
    from rebrew.metadata.functions import (
        get_entry,
        identity_file,
        record_function_rows,
        validate_identity_file,
    )
    from rebrew.rename_ops import redecorated_symbol
    from rebrew.sources import target_marker

    module = target_marker(cfg) or ""
    if not module:
        raise ValueError("no target marker configured to address the function metadata")
    rows: list[dict[str, Any]] = []
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
        if name not in _defined_names(path):
            raise ValueError(f"{value} does not define {name}")
        identity = validate_identity_file(identity_file(path, cfg.metadata_dir))
        row: dict[str, Any] = {
            "va": f"0x{va:x}",
            "name": name,
            "old_file": str(entry.get("file") or ""),
            "file": identity,
        }
        if bind is not None and bind != old_name:
            old_symbol = str(entry.get("symbol") or f"_{old_name}")
            row["old_name"] = old_name
            row["symbol"] = redecorated_symbol(old_symbol, bind)
        rows.append(row)
    if not dry_run:
        record_function_rows(
            cfg.metadata_dir,
            [
                {
                    "module": module,
                    "va": int(r["va"], 16),
                    "identity": {"file": r["file"]}
                    | ({"name": r["name"], "symbol": r["symbol"]} if "symbol" in r else {}),
                }
                for r in rows
            ],
            overwrite_name=True,
            updated_by="rehome",
        )
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
    functions, data = _rows_naming(cfg.metadata_dir, old_rel)
    if not functions and not data:
        raise ValueError(f"no function or data row names {old_rel}")
    defined = _defined_names(new_path)
    function_rows: list[dict[str, Any]] = []
    for module, va, entry in functions:
        name = _row_name(entry)
        if not name:
            raise ValueError(f"function row {module}.0x{va:x} has no name to check in {new}")
        if name not in defined:
            raise ValueError(f"{new} does not define {name} ({module}.0x{va:x})")
        function_rows.append(
            {
                "module": module,
                "va": f"0x{va:x}",
                "name": name,
                "old_file": str(entry.get("file") or ""),
                "file": new_rel,
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
    if not dry_run:
        record_function_rows(
            cfg.metadata_dir,
            [
                {"module": module, "va": va, "identity": {"file": new_rel}}
                for module, va, _entry in functions
            ],
            updated_by="rehome",
        )
        set_data_fields_batch(
            cfg.metadata_dir,
            [
                {"module": module, "va": va, "fields": {"file": new_rel}, "updated_by": "rehome"}
                for module, va, _entry in data
            ],
        )
    return function_rows, data_rows


@app.callback(invoke_without_command=True)
def main(
    specs: list[str] | None = typer.Argument(
        None,
        metavar="0xVA=PATH[:NAME]",
        help="Function VA and its new file; :NAME binds the row to that definition",
    ),
    from_file: str | None = typer.Option(
        None, "--from", help="Old source path: retarget every row naming it"
    ),
    to_file: str | None = typer.Option(None, "--to", help="New source path for --from"),
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
