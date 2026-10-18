"""Preview reviewed retirement/replacement of a native function's source claim."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import typer

from rebrew.c_parser import function_signatures
from rebrew.c_rename import ORDINARY_ROLES, ParsedSource, definitions, occurrences
from rebrew.cli import (
    EXPECTED_DIGEST_HELP,
    TargetOption,
    console,
    error_exit,
    json_print,
    parse_va,
    require_config,
)
from rebrew.config import ProjectConfig, target_module
from rebrew.metadata.binding_history import change_source_binding, validate_binding_history
from rebrew.metadata.bindings import derive_c_symbol
from rebrew.metadata.functions import get_entry, identity_file, load_metadata
from rebrew.metadata.source_provenance import function_definition_hashes
from rebrew.sources import iter_sources
from rebrew.utils import preset_module_key, read_source_text

app = typer.Typer(
    help="Review and change source bindings while retaining native inventory and evidence.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source binding retire 0x401000 --reason proof --dry-run\n\n"
        "  rebrew source binding rebind 0x401000 src/f.c --reason proof\n\n"
        "Preview first; --expected-digest rejects changed review inputs."
    ),
)


def _change(
    cfg: ProjectConfig,
    va: int,
    *,
    source: Path | None,
    name: str | None,
    symbol: str | None,
    counterpart_va: int | None,
    reason: str,
    dry_run: bool,
    expected_digest: str | None,
) -> dict[str, Any]:
    module = target_module(cfg) or ""
    current = get_entry(cfg.metadata_dir, va, module)
    history = validate_binding_history(current.get("binding_history", []))
    identity = None
    inputs: dict[Path, str] = {}

    def pin(path: Path, parsed_text: str | None = None) -> None:
        raw = path.read_bytes()
        if parsed_text is not None and (
            read_source_text(path)[0] != parsed_text or path.read_bytes() != raw
        ):
            raise ValueError(f"binding review input changed while parsing: {path}")
        inputs[path.resolve()] = hashlib.sha256(raw).hexdigest()

    pin(cfg.target_binary)
    if source is not None:
        source = source.resolve()
        if not source.is_relative_to(cfg.root.resolve()):
            raise ValueError("replacement source must be inside the project")
        text, _ = read_source_text(source)
        definition_hashes = function_definition_hashes(text)
        name = name or str(
            current.get("name") or (history[-1]["previous"].get("name") if history else "")
        )
        if not name or name not in definition_hashes:
            raise ValueError("replacement must contain one unambiguous definition; select --name")
        pin(source, text)
        # Preserve library ancestry without accepting a new attribution by name.
        kind = str(
            current.get("kind")
            or (history[-1]["previous"].get("kind") if history else None)
            or "FUNCTION"
        )
        if kind != "LIBRARY" and source not in {
            path.resolve() for path in iter_sources(cfg.reversed_dir, cfg)
        }:
            raise ValueError("replacement is outside the target/shared source discovery roots")
        root = cfg.root if kind == "LIBRARY" else cfg.metadata_dir
        identity = {
            "file": identity_file(source, root),
            "name": name,
            "symbol": symbol or derive_c_symbol(name, function_signatures(text)[name]),
            "kind": kind,
        }
        local = any(item.static for item in definitions(ParsedSource.parse(text), name))
        if not local:
            for (other_module, other_va), other in load_metadata(
                cfg.metadata_dir, deepcopy=False
            ).items():
                if other_va == va or preset_module_key(other_module) != preset_module_key(module):
                    continue
                if not other.get("file") or other.get("symbol") != identity["symbol"]:
                    continue
                other_root = cfg.root if other.get("kind") == "LIBRARY" else cfg.metadata_dir
                other_path = (other_root / other["file"]).resolve()
                if other_path == source:
                    if other.get("name") == name or other.get("symbol") == identity["symbol"]:
                        raise ValueError(
                            f"replacement definition already belongs to {other_module}.0x{other_va:x}"
                        )
                    continue
                other_text, _ = read_source_text(other_path)
                pin(other_path, other_text)
                other_definitions = definitions(
                    ParsedSource.parse(other_text), str(other.get("name") or "")
                )
                if not other_definitions or not all(item.static for item in other_definitions):
                    raise ValueError(
                        f"external symbol already belongs to {other_module}.0x{other_va:x}"
                    )
    old_name = str(current.get("name") or "")
    references = []
    for path in iter_sources(cfg.reversed_dir, cfg):
        text, _ = read_source_text(path)
        if not old_name or old_name not in text:
            continue
        parsed = ParsedSource.parse(text)
        sites = [site for site in occurrences(parsed, old_name) if site.role in ORDINARY_ROLES]
        if sites:
            pin(path, text)
            references.append(
                {
                    "file": identity_file(path, cfg.root),
                    "lines": sorted({site.line for site in sites}),
                }
            )
    if counterpart_va is not None:
        other = get_entry(cfg.metadata_dir, counterpart_va, module)
        if other.get("file"):
            root = cfg.root if other.get("kind") == "LIBRARY" else cfg.metadata_dir
            counterpart = (root / other["file"]).resolve()
            text, _ = read_source_text(counterpart)
            if str(other.get("name") or "") not in function_definition_hashes(text):
                raise ValueError("counterpart no longer has its recorded unique definition")
            pin(counterpart, text)
    preview = change_source_binding(
        cfg.metadata_dir,
        module,
        va,
        reason=reason,
        identity=identity,
        counterpart_va=counterpart_va,
        dry_run=True,
        expected_inputs=inputs,
        project_root=cfg.root,
    )
    digest_inputs = {str(path): digest for path, digest in inputs.items()}
    digest_inputs["metadata"] = preview["input_digest"]
    digest = hashlib.sha256(json.dumps(digest_inputs, sort_keys=True).encode()).hexdigest()
    if expected_digest is not None and digest != expected_digest:
        raise ValueError("binding review inputs changed; review a new preview")
    result = (
        preview
        if dry_run
        else change_source_binding(
            cfg.metadata_dir,
            module,
            va,
            reason=reason,
            identity=identity,
            counterpart_va=counterpart_va,
            expected_digest=preview["input_digest"],
            expected_inputs=inputs,
            project_root=cfg.root,
        )
    )
    return {
        **result,
        "input_digest": digest,
        "source_references": references,
        "references_rewritten": False,
    }


def _emit(result: dict[str, Any], json_output: bool) -> None:
    if json_output:
        json_print(result)
    else:
        console.print(result)


@app.command(
    epilog=(
        "[bold]Examples:[/bold]\n\n  rebrew source binding retire 0x401000 --reason proof --dry-run"
    )
)
def retire(
    va: str = typer.Argument(..., help="Native function address"),
    reason: str = typer.Option(
        ..., "--reason", help="Reviewed evidence explaining the incorrect binding"
    ),
    counterpart: str | None = typer.Option(
        None, "--counterpart", help="Existing native counterpart; its binding/verdict is preserved"
    ),
    expected_digest: str | None = typer.Option(
        None, "--expected-digest", help=EXPECTED_DIGEST_HELP
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Retire an incorrect source claim without deleting its native row or evidence."""
    cfg = require_config(target=target, json_mode=json_output)
    try:
        result = _change(
            cfg,
            parse_va(va, json_mode=json_output),
            source=None,
            name=None,
            symbol=None,
            counterpart_va=parse_va(counterpart, json_mode=json_output) if counterpart else None,
            reason=reason,
            dry_run=dry_run,
            expected_digest=expected_digest,
        )
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    _emit(result, json_output)


@app.command(
    epilog=(
        "[bold]Examples:[/bold]\n\n  rebrew source binding rebind 0x401000 src/f.c --reason proof"
    )
)
def rebind(
    va: str = typer.Argument(..., help="Native function address"),
    source: Path = typer.Argument(..., help="Source containing the replacement definition"),
    name: str | None = typer.Option(
        None, "--name", help="Replacement C definition (default: current or last retired name)"
    ),
    symbol: str | None = typer.Option(
        None, "--symbol", help="Native object symbol (default: derived from definition)"
    ),
    reason: str = typer.Option(
        ..., "--reason", help="Reviewed native evidence supporting this binding"
    ),
    expected_digest: str | None = typer.Option(
        None, "--expected-digest", help=EXPECTED_DIGEST_HELP
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Bind a unique definition; the replacement must earn its own comparison verdict."""
    cfg = require_config(target=target, json_mode=json_output)
    try:
        result = _change(
            cfg,
            parse_va(va, json_mode=json_output),
            source=source,
            name=name,
            symbol=symbol,
            counterpart_va=None,
            reason=reason,
            dry_run=dry_run,
            expected_digest=expected_digest,
        )
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    _emit(result, json_output)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)


if __name__ == "__main__":
    main_entry()
