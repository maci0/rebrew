"""Read-only all-target source organization and independent raw-link validation."""

from __future__ import annotations

import hashlib
import json
from graphlib import CycleError, TopologicalSorter
from itertools import pairwise
from pathlib import Path
from typing import Any

from rebrew.binary_gate import compare_snapshots, snapshot_binary
from rebrew.c_parser import find_extern_variables, function_definition_spans, function_signatures
from rebrew.c_rename import ParsedSource
from rebrew.c_rename import definitions as source_definitions
from rebrew.compiler.overrides import resolve_compile_overrides
from rebrew.config import ProjectConfig, load_config, module_marker
from rebrew.formats.binary_loader import load_binary
from rebrew.formats.pe_headers import SECTION_ENTRY_SIZE, pe_layout
from rebrew.metadata.bindings import FUNCTION_KINDS, read_source_bindings
from rebrew.rename_ops import c_name_from_symbol
from rebrew.source_contracts import contract_contexts
from rebrew.source_selection import collect_target_sources
from rebrew.utils import detect_source_encoding
from rebrew.workspace.config import read_config, targets_table


def organization_configs(cfg: ProjectConfig) -> list[ProjectConfig]:
    """Load every target before drawing cross-target organization conclusions."""
    if not (cfg.root / "rebrew-project.toml").is_file():
        return [cfg]
    return [
        load_config(root=cfg.root, target=name) for name in targets_table(read_config(cfg.root))
    ] or [cfg]


def review_organization(
    cfgs: list[ProjectConfig],
    files: list[Path],
    *,
    destination: Path | None = None,
    shared: bool = False,
) -> dict[str, Any]:
    """Preview providers, original TU inputs, native order constraints and risks.

    The common order is a constraint result, not a proposed source rewrite.
    Headers, macros and attached comments retain their original TU context in
    the input inventory; no definitions or directives are moved by this audit.
    """
    if not cfgs or not files:
        raise ValueError("organization review requires targets and source files")
    root = cfgs[0].root.resolve()
    if any(cfg.root.resolve() != root for cfg in cfgs):
        raise ValueError("organization targets must belong to one project")
    paths = sorted({(root / path).resolve() for path in files})
    if any(
        not path.is_relative_to(root)
        or not path.is_file()
        or path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}
        for path in paths
    ):
        raise ValueError("review existing C/C++ sources inside the project")
    destination = (root / destination).resolve() if destination is not None else None
    if destination is not None and not destination.is_relative_to(root):
        raise ValueError("organization destination must stay inside the project")
    inputs: dict[Path, bytes] = {path: path.read_bytes() for path in paths}
    absent_inputs: set[Path] = set()
    for cfg in cfgs:
        candidates = {
            cfg.root / "rebrew-project.toml",
            *(
                cfg.metadata_dir / name
                for name in (
                    "rebrew-functions.toml",
                    "rebrew-data.toml",
                    "rebrew-source.toml",
                    "rebrew-types.toml",
                )
            ),
        }
        for source in paths:
            for parent in (source.parent, *source.parents):
                if parent == cfg.root.resolve().parent:
                    break
                candidates.add(parent / "rebrew-libraries.toml")
        for candidate in candidates:
            if candidate.is_file():
                inputs.setdefault(candidate, candidate.read_bytes())
            else:
                absent_inputs.add(candidate)
    definitions: dict[str, dict[str, Any]] = {}
    by_file: dict[Path, list[str]] = {}
    storage: list[dict[str, Any]] = []
    problems: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    for path in paths:
        raw = inputs[path]
        text = raw.decode(detect_source_encoding(raw))
        signatures = function_signatures(text)
        spans = function_definition_spans(text)
        seen: set[str] = set()
        ids = []
        for name, start, end in spans:
            identifier = name if shared else f"{path.relative_to(root).as_posix()}::{name}"
            if name in seen:
                problems.append({"kind": "duplicate_definition", "file": str(path), "name": name})
            seen.add(name)
            body = text.encode("utf-8", errors="surrogateescape")[start:end]
            digest = hashlib.sha256(body).hexdigest()
            if identifier in definitions and definitions[identifier]["body_hash"] != digest:
                problems.append({"kind": "different_shared_bodies", "definition": identifier})
            item = definitions.setdefault(
                identifier,
                {
                    "id": identifier,
                    "name": name,
                    "sources": [],
                    "body_hash": digest,
                    "prototype": signatures.get(name, ""),
                    "bindings": [],
                },
            )
            item["sources"].append(str(path))
            ids.append(identifier)
        parsed_source = ParsedSource.parse(text)
        if parsed_source.tree.root_node.has_error:
            unknown.append(
                {"file": str(path), "reason": "C syntax contains parse errors or missing tokens"}
            )
        for variable in find_extern_variables(text, include_definitions=True):
            if variable.is_definition:
                owner_definitions = source_definitions(parsed_source, variable.name)
                storage.append(
                    {
                        "name": variable.name,
                        "source": str(path),
                        "line": variable.line,
                        "type": variable.type_str,
                        "static": any(owner.static for owner in owner_definitions),
                        "declaration": variable.declaration,
                    }
                )
        by_file[path] = ids
        if not spans:
            unknown.append({"file": str(path), "reason": "no bounded C function definitions"})
    if destination is not None:
        namespace: dict[str, set[str]] = {}
        for item in definitions.values():
            namespace.setdefault(item["name"], set()).update(item["sources"])
        for item in storage:
            namespace.setdefault(item["name"], set()).add(item["source"])
        for name, owners in namespace.items():
            if len(owners) > 1 and (not shared or any(item["name"] == name for item in storage)):
                problems.append(
                    {
                        "kind": "merged_ordinary_namespace_collision",
                        "name": name,
                        "sources": sorted(owners),
                    }
                )
    graph: dict[str, set[str]] = {identifier: set() for identifier in definitions}
    edges = []
    targets = []
    all_ids = set(definitions)
    for cfg in cfgs:
        sources, _foreign = collect_target_sources(cfg, module_marker(cfg))
        active = set(sources) & set(paths)
        participating = bool(active)
        compiled = {identifier for path in active for identifier in by_file[path]}
        leaks = sorted(all_ids - compiled) if participating else []
        if destination is not None and leaks:
            problems.append(
                {
                    "kind": "foreign_definitions_in_merged_tu",
                    "target": cfg.target_name,
                    "definitions": leaks,
                }
            )
        contexts, missing = contract_contexts(cfg, selected_sources=active)
        unknown.extend({"target": cfg.target_name, **item} for item in missing)
        for path in contexts:
            inputs.setdefault(path, path.read_bytes())
        header_locals: list[dict[str, Any]] = []
        for header, users in contexts.items():
            if header in paths:
                continue
            raw = inputs[header]
            text = raw.decode(detect_source_encoding(raw))
            parsed_header = ParsedSource.parse(text)
            if parsed_header.tree.root_node.has_error:
                unknown.append(
                    {
                        "file": str(header),
                        "reason": "C syntax contains parse errors or missing tokens",
                    }
                )
            local_names = {
                variable.name
                for variable in find_extern_variables(text, include_definitions=True)
                if variable.is_definition
            } | set(function_signatures(text))
            for name in sorted(local_names):
                for owner in source_definitions(parsed_header, name):
                    if owner.static:
                        item = {
                            "name": name,
                            "header": str(header),
                            "kind": owner.kind,
                            "line": owner.line,
                            "contexts": sorted(str(user) for user in users),
                        }
                        header_locals.append(item)
                        if destination is not None and len(users) > 1:
                            problems.append(
                                {
                                    **item,
                                    "declaration_kind": item["kind"],
                                    "kind": "header_local_instances_would_change",
                                    "target": cfg.target_name,
                                }
                            )
        native_order = []
        flags: list[dict[str, Any]] = []
        for source in sorted(active):
            annotations = read_source_bindings(
                source,
                target_name=module_marker(cfg),
                metadata_dir=cfg.metadata_dir,
                project_root=cfg.root,
            )
            settings = set()
            bound_names = set()
            for ann in annotations:
                if ann.kind not in FUNCTION_KINDS:
                    continue
                candidate_ids = {
                    name if shared else f"{source.relative_to(root).as_posix()}::{name}"
                    for name in {ann.name, c_name_from_symbol(ann.symbol)}
                } & set(by_file[source])
                identifier = next(iter(candidate_ids)) if len(candidate_ids) == 1 else ""
                if not identifier:
                    unknown.append(
                        {
                            "target": cfg.target_name,
                            "file": str(source),
                            "name": ann.name,
                            "reason": "binding has no bounded selected definition",
                        }
                    )
                    continue
                bound_names.add(identifier)
                native_order.append((ann.va, identifier))
                definitions[identifier]["bindings"].append(
                    {
                        "target": cfg.target_name,
                        "module": ann.module,
                        "va": ann.va,
                        "symbol": ann.symbol,
                    }
                )
                settings.add(
                    resolve_compile_overrides(
                        cfg, source.parent, ann.toolchain or None, ann.cflags or None, ann.module
                    )
                )
            for identifier in set(by_file[source]) - bound_names:
                unknown.append(
                    {
                        "target": cfg.target_name,
                        "definition": identifier,
                        "reason": "definition has no native binding; retain original TU context",
                    }
                )
            if not settings:
                settings.add(
                    resolve_compile_overrides(cfg, source.parent, None, None, module_marker(cfg))
                )
            flags.append(
                {
                    "source": str(source),
                    "settings": [
                        {"toolchain": toolchain, "cflags": cflags}
                        for toolchain, cflags in sorted(settings, key=str)
                    ],
                    "includes": sorted(
                        str(p) for p, users in contexts.items() if source in users and p != source
                    ),
                }
            )
        if (
            destination is not None
            and len(
                {
                    (entry["toolchain"], entry["cflags"])
                    for source in flags
                    for entry in source["settings"]
                }
            )
            > 1
        ):
            problems.append({"kind": "incompatible_tu_compile_settings", "target": cfg.target_name})
        ordered = [identifier for _va, identifier in sorted(native_order)]
        for before, after in pairwise(ordered):
            if before == after:
                continue
            graph[after].add(before)
            edges.append({"target": cfg.target_name, "before": before, "after": after})
        for path in cfg.metadata_dir.glob("rebrew-*.toml"):
            inputs.setdefault(path, path.read_bytes())
        if (cfg.root / "rebrew-project.toml").is_file():
            inputs.setdefault(
                cfg.root / "rebrew-project.toml", (cfg.root / "rebrew-project.toml").read_bytes()
            )
        raw_link = cfg.raw_link
        baseline: dict[str, Any] = {"path": str(raw_link) if raw_link else None, "available": False}
        if raw_link is not None and raw_link.is_file():
            inputs.setdefault(raw_link, raw_link.read_bytes())
            baseline.update(
                available=True,
                sha256=hashlib.sha256(inputs[raw_link]).hexdigest(),
                size=len(inputs[raw_link]),
            )
        targets.append(
            {
                "target": cfg.target_name,
                "active_inputs": [str(path) for path in sorted(active)],
                "definition_order": ordered,
                "contexts": flags,
                "storage_providers": [item for item in storage if Path(item["source"]) in active],
                "header_local_instances": header_locals,
                "external_archives": list((cfg.external_libs or {}).items()),
                "raw_link_before": baseline,
                "raw_link_after": "requires a raw rebuild and organize check; object matches do not prove placement",
            }
        )
    cycle = []
    try:
        common = list(TopologicalSorter(graph).static_order())
    except CycleError as exc:
        common = []
        cycle = list(exc.args[1])
        problems.append(
            {
                "kind": "conflicting_target_orders",
                "cycle": cycle,
                "resolution": "review native bindings or split source units; do not choose one target's order",
            }
        )
    if any(path.read_bytes() != raw for path, raw in inputs.items()) or any(
        path.exists() for path in absent_inputs
    ):
        raise ValueError("organization review inputs changed while reading")
    input_hashes = {
        str(path): hashlib.sha256(raw).hexdigest() for path, raw in sorted(inputs.items())
    }
    return {
        "input_digest": hashlib.sha256(
            json.dumps(input_hashes, sort_keys=True).encode()
        ).hexdigest(),
        "input_hashes": input_hashes,
        "destination": str(destination) if destination else None,
        "definitions": list(definitions.values()),
        "storage_definitions": storage,
        "targets": targets,
        "order_constraints": edges,
        "order_policy": "stored native VA constraints; COMDAT/linker policies require raw-link validation",
        "common_definition_order": common,
        "cycle": cycle,
        "problems": problems,
        "unknown": unknown,
        "verification_required": [
            "compile every affected target with its original TU settings",
            "compare raw links including full .text and initialized data",
            "verify affected definitions, callers and data; retained STATUS is historical",
        ],
        "safe_to_reorganize": False,
        "source_changed": False,
        "verdicts_changed": False,
    }


def check_reorganization(before: Path, after: Path) -> dict[str, Any]:
    """Compare complete raw links and region placement without earning source STATUS."""
    if before.resolve() == after.resolve() or before.samefile(after):
        raise ValueError(
            "preserve an independent before artifact; raw links must be distinct files"
        )
    validated: list[bytes] = []
    expected_section_counts: list[int] = []
    for path in (before, after):
        raw = path.read_bytes()
        validated.append(raw)
        layout = pe_layout(raw)
        if layout is None or layout.magic not in {0x10B, 0x20B}:
            raise ValueError("raw organization checks currently require complete PE images")
        if (
            not layout.number_of_sections
            or layout.section_table_offset + layout.number_of_sections * SECTION_ENTRY_SIZE
            > len(raw)
            or len(layout.sections) != layout.number_of_sections
        ):
            raise ValueError("raw PE section table is incomplete")
        if any(
            section.pointer_to_raw_data + section.size_of_raw_data > len(raw)
            for section in layout.sections
        ):
            raise ValueError("raw PE section is not fully file-backed")
        expected_section_counts.append(layout.number_of_sections)
        names = [section.name for section in layout.sections]
        if len(set(names)) != len(names):
            raise ValueError(
                "duplicate PE section names cannot establish complete region accounting"
            )
    snapshots = [snapshot_binary(path) for path in (before, after)]
    if any(snapshot["file"] != raw for snapshot, raw in zip(snapshots, validated, strict=True)):
        raise ValueError("raw links changed after section validation")
    comparison = compare_snapshots(*snapshots)
    if comparison["errors"]:
        return {**comparison, "regions": [], "reference_verified": False, "verdicts_changed": False}
    images = [load_binary(path) for path in (before, after)]
    if any(
        image.data != raw or len(image.sections) != count
        for image, raw, count in zip(images, validated, expected_section_counts, strict=True)
    ):
        raise ValueError("raw image parser returned incomplete or changed sections")
    regions = []
    for name in sorted(set(images[0].sections) | set(images[1].sections)):
        left, right = (image.sections.get(name) for image in images)
        values = []
        for image, section in zip(images, (left, right), strict=True):
            if section is None:
                values.append(b"")
                continue
            start, end = section.file_offset, section.file_offset + section.raw_size
            if start < 0 or end > len(image.data):
                raise ValueError(f"section {name} is not fully file-backed")
            values.append(image.data[start:end])
        a, b = values
        same = sum(x == y for x, y in zip(a, b, strict=False))
        regions.append(
            {
                "section": name,
                "same_bytes": same,
                "different_or_missing": max(len(a), len(b)) - same,
                "before_bytes": len(a),
                "after_bytes": len(b),
                "same_placement": left is not None
                and right is not None
                and (left.va, left.file_offset, left.size, left.raw_size)
                == (right.va, right.file_offset, right.size, right.raw_size),
                "bss_bytes_verified": 0,
            }
        )
    if any(
        path.read_bytes() != snapshot["file"]
        for path, snapshot in zip((before, after), snapshots, strict=True)
    ):
        raise ValueError("raw links changed while comparing")
    return {
        **comparison,
        "regions": regions,
        "before_hash": hashlib.sha256(snapshots[0]["file"]).hexdigest(),
        "after_hash": hashlib.sha256(snapshots[1]["file"]).hexdigest(),
        "reference_verified": False,
        "verdicts_changed": False,
    }
