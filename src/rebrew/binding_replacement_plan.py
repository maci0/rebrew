"""Read-only review of a proposed target-scoped bound-function replacement.

This module does not apply edits. Decisions describe reviewed ownership, not
proof of native equivalence or preprocessor activity.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
lazy from pathlib import Path

from rebrew.binding_replacement_conditions import macro_change_re, target_structural_view
from rebrew.c_parser import mask_msvc_syntax, mask_va_arg_types, parse_c_source
from rebrew.c_rename import (
    ORDINARY_ROLES,
    ROLE_COMMENT,
    ROLE_IDENT,
    ROLE_LITERAL,
    ROLE_MACRO_NAME,
    ParsedSource,
    declarator_name,
    definitions,
    non_external_function_declarations,
    occurrences,
)
from rebrew.compiler.compile import effective_compile_flags
from rebrew.compiler.overrides import resolve_compile_overrides_cached
from rebrew.config import ProjectConfig, inventory_path_for
from rebrew.metadata.binding_history import retired_binding
from rebrew.metadata.functions import load_metadata
from rebrew.metadata.storage import input_exists, metadata_store_paths, snapshot_input
from rebrew.source_contracts import contract_contexts
from rebrew.source_organization import organization_configs
from rebrew.source_selection import collect_target_sources
from rebrew.sources import iter_sources_and_headers
from rebrew.utils import path_identity, read_source_text


def _parse(text: str) -> ParsedSource:
    tree, _ = parse_c_source(mask_va_arg_types(mask_msvc_syntax(text)))
    return ParsedSource(text=text, data=text.encode("utf-8", errors="surrogateescape"), tree=tree)


def _function_scope(node: Any) -> tuple[int, int] | None:
    while node is not None:
        if node.type == "function_definition":
            return (node.start_byte, node.end_byte)
        node = node.parent
    return None


def _local_shadows(parsed: ParsedSource, name: str) -> set[tuple[int, int]]:
    scopes: set[tuple[int, int]] = set()
    for hit in occurrences(parsed, name):
        node = parsed.tree.root_node.descendant_for_byte_range(hit.start, hit.end)
        current = node
        while current is not None and current.type != "function_definition":
            if current.type in {"declaration", "parameter_declaration", "type_definition"}:
                names = {
                    declarator_name(d, parsed) for d in current.children_by_field_name("declarator")
                }
                scope = _function_scope(current)
                if name in names and scope is not None:
                    scopes.add(scope)
                break
            current = current.parent
    return scopes


def _plan_binding_replacement(
    configs: list[ProjectConfig],
    identities: dict[str, int],
    donor: Path,
    replacement: Path,
    old_name: str,
    new_name: str,
    ownership: dict[str, str] | None = None,
    *,
    evidence: list[Path] | None = None,
    expected_digest: str | None = None,
    guard_states: dict[str, dict[str, bool]] | None = None,
    image_headers: Any = None,
) -> dict[str, Any]:
    """Inventory explicit occurrence decisions and pin their complete inputs.

    Ownership keys are ``relative/path:byte_offset:target`` and values are
    ``replace``, ``preserve``, or ``inactive``. Every target is reviewed for
    every C identifier occurrence, including declarations and definitions.
    Unknown contexts are not silently inferred from missing metadata. The
    plan intentionally reports apply as unavailable. Pass None to discover
    ownership keys without deciding them.
    """
    guard_states = guard_states or {}
    discovery_only = ownership is None
    ownership = {} if ownership is None else ownership
    if not configs or not identities or not old_name.isidentifier() or not new_name.isidentifier():
        raise ValueError("targets, donor identities and C names are required")
    if old_name == new_name:
        raise ValueError("donor and replacement names must differ")
    root = configs[0].root.resolve()
    if any(cfg.root.resolve() != root for cfg in configs):
        raise ValueError("all targets must belong to one project")
    targets = {cfg.target_name or cfg.module: cfg for cfg in configs}
    if len(targets) != len(configs) or set(identities) - targets.keys():
        raise ValueError("target names must be unique and every identity needs a target")
    config_path = root / "rebrew-project.toml"

    def config_snapshot() -> tuple[bytes | None, dict[str, Any]]:
        content = snapshot_input(config_path) if input_exists(config_path) else None
        return content, path_identity(config_path)

    initial_config = config_snapshot()
    if initial_config[0] is not None:
        configured = {c.target_name or c.module: c for c in organization_configs(configs[0])}
        if config_snapshot() != initial_config:
            raise ValueError("project config changed while loading targets")
        if set(targets) != set(configured):
            raise ValueError("review must include every configured target")
        if any(
            targets[name].as_dict() != current.as_dict() for name, current in configured.items()
        ):
            raise ValueError("target configuration is stale; reload before review")
    lexical_paths = {config_path, (root / donor).absolute(), (root / replacement).absolute()}
    lexical_paths.update((root / path).absolute() for path in (evidence or []))
    donor = (root / donor).resolve()
    replacement = (root / replacement).resolve()
    for path in (donor, replacement):
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError("donor and replacement must be project files")
    if donor == replacement:
        raise ValueError("donor and replacement must be distinct files")

    files: set[Path] = set()
    selected: dict[str, set[Path]] = {}
    watched: set[Path] = {root / "rebrew-project.toml", donor, replacement}
    closure_unknown: list[dict[str, Any]] = []
    contexts: dict[str, Any] = {}
    unknown_by_target: dict[str, list[dict[str, Any]]] = {}
    metadata_flags: dict[str, dict[Path, list[str]]] = {}
    closures: dict[str, set[Path]] = {}
    header_contexts: dict[str, dict[Path, set[Path]]] = {}
    discovery_names: dict[str, set[Path]] = {}
    selected_names: dict[str, set[Path]] = {}
    observed_contents: dict[Path, bytes] = {}
    include_paths: list[tuple[Path, Path]] = []
    observed_identities: dict[Path, dict[str, Any]] = {}
    include_shadows: list[tuple[str, str, tuple[str, ...]]] = []
    include_probes: list[tuple[str, tuple[str, ...]]] = []
    for target, cfg in targets.items():
        discovered = list(iter_sources_and_headers(cfg.reversed_dir, cfg))
        discovery_names[target] = {path.absolute() for path in discovered}
        lexical_paths.update(path.absolute() for path in discovered)
        files.update(path.resolve() for path in discovered)
        sources, _ = collect_target_sources(cfg, cfg.module)
        selected_names[target] = {path.absolute() for path in sources}
        lexical_paths.update(path.absolute() for path in sources)
        selected[target] = {path.resolve() for path in sources}
        files.update(selected[target])
        watched.update(metadata_store_paths(cfg.metadata_dir))
        for source_path in selected[target]:
            for parent in (source_path.parent, *source_path.parents):
                if not parent.is_relative_to(root):
                    break
                watched.add(parent / "rebrew-libraries.toml")
        watched.add(inventory_path_for(cfg.reversed_dir, cfg))
        if cfg.target_binary != Path():
            watched.add(cfg.target_binary.resolve())
        headers, unknown = contract_contexts(
            cfg,
            observed_contents=observed_contents,
            lexical_includes=include_paths,
            observed_identities=observed_identities,
            include_shadows=include_shadows,
            include_probes=include_probes,
            image_headers=image_headers,
        )
        unknown_by_target[target] = unknown
        closure_unknown.extend({"target": target, **item} for item in unknown)
        header_contexts[target] = {}
        for header, consumers in headers.items():
            for consumer in consumers:
                header_contexts[target].setdefault(consumer.resolve(), set()).add(header.resolve())
        closures[target] = {path.resolve() for path in headers}
        watched.update(closures[target])
        files.update(path for path in closures[target] if path.is_relative_to(root))
        contexts[target] = cfg.as_dict()
        rows = load_metadata(cfg.metadata_dir)
        metadata_flags[target] = {}
        for (module, _va), row in rows.items():
            if module == cfg.module and row.get("file") and row.get("cflags"):
                source_path = (cfg.metadata_dir / row["file"]).resolve()
                metadata_flags[target].setdefault(source_path, []).append(str(row["cflags"]))
        if target in identities:
            row = rows.get((cfg.module, identities[target]), {})
            if not row.get("file") or retired_binding(row):
                raise ValueError(f"{target} donor identity is missing or retired")
            if (cfg.metadata_dir / row["file"]).resolve() != donor or row.get("name") != old_name:
                raise ValueError(f"{target} donor identity does not own the selected definition")
            if donor not in selected[target] or replacement not in selected[target]:
                raise ValueError(f"{target} donor or replacement provider is not selected")
    watched.update((root / path).resolve() for path in (evidence or []))
    files.update((donor, replacement))
    if any(not path.is_relative_to(root) for path in files):
        raise ValueError("source discovery escaped the project")
    watched.update(files)
    for lexical, resolved in include_paths:
        if lexical.resolve() != resolved:
            raise ValueError("include path changed while planning")
        lexical_paths.add(lexical)
    for _mode, _name, directories in include_shadows:
        lexical_paths.update(Path(directory).absolute() for directory in directories)
    for _name, directories in include_probes:
        lexical_paths.update(Path(directory).absolute() for directory in directories)
    identities_before = {str(path): path_identity(path) for path in sorted(lexical_paths)}
    if any(
        identities_before[str(path)] != identity for path, identity in observed_identities.items()
    ):
        raise ValueError("include identity changed while planning")

    def inputs() -> dict[str, str | None]:
        return {
            str(path): hashlib.sha256(snapshot_input(path)).hexdigest()
            if input_exists(path)
            else None
            for path in sorted(watched)
        }

    before = inputs()
    if image_headers is not None:
        image_headers.verify()
    if config_snapshot() != initial_config:
        raise ValueError("project config changed while planning")
    if any(
        before.get(str(path)) != hashlib.sha256(raw).hexdigest()
        for path, raw in observed_contents.items()
    ):
        raise ValueError("include closure inputs changed while planning")
    donor_definition_lines: set[int] = set()
    for path, name in ((donor, old_name), (replacement, new_name)):
        source = _parse(read_source_text(path)[0])
        found = [d for d in definitions(source, name) if not d.definitely_inactive]
        if len(found) != 1 or found[0].kind != "function" or found[0].static:
            raise ValueError(f"{path}: expected one external definition of {name}")
        if path == donor:
            donor_definition_lines.add(found[0].line)

    macro_cache: dict[Path, bool] = {}

    def defines_new_name(path: Path) -> bool:
        if path not in macro_cache:
            source = _parse(read_source_text(path)[0])
            macro_cache[path] = any(
                o.role == ROLE_MACRO_NAME for o in occurrences(source, new_name)
            )
        return macro_cache[path]

    references: list[dict[str, Any]] = []
    expected_keys: set[str] = set()
    configured_names = {
        define.split("=", 1)[0] for candidate in configs for define in candidate.defines
    }
    header_text_cache: dict[Path, str] = {}

    def header_text(header: Path) -> str:
        if header not in header_text_cache:
            header_text_cache[header] = read_source_text(header)[0]
        return header_text_cache[header]

    for path in sorted(files):
        text, _ = read_source_text(path)
        parsed = _parse(text)
        target_views = [parsed]
        collisions = [d for d in definitions(parsed, new_name) if not d.definitely_inactive]
        if path != replacement and collisions:
            raise ValueError(f"{path}: replacement name already has a definition")
        hits = [
            o for o in occurrences(parsed, old_name) if o.role not in {ROLE_COMMENT, ROLE_LITERAL}
        ]
        if hits and image_headers is not None:
            for target in targets:
                consumers = {path} if path in selected[target] else set()
                consumers.update(
                    consumer
                    for consumer, headers in header_contexts[target].items()
                    if path in headers
                )
                if any(
                    str(consumer) == item.get("context")
                    for consumer in consumers
                    for item in unknown_by_target[target]
                ):
                    raise ValueError(f"{path}: target {target} include closure is incomplete")
        if hits and parsed.tree.root_node.has_error:
            views: list[ParsedSource] = []
            for target, cfg in targets.items():
                if path not in selected[target]:
                    continue
                if any(str(path) == item.get("context") for item in unknown_by_target[target]):
                    raise ValueError(f"{path}: target {target} include closure is incomplete")
                state = guard_states.get(target, {})
                for define in cfg.defines:
                    name = define.split("=", 1)[0]
                    if name in state and not state[name]:
                        raise ValueError(
                            f"{target}: guard state conflicts with target define {name}"
                        )
                masked_view, names = target_structural_view(text, state)
                target_names = {define.split("=", 1)[0] for define in cfg.defines}
                for name in names:
                    if name not in configured_names:
                        raise ValueError(
                            f"{target}: guard macro has no configured target definition: {name}"
                        )
                    if state[name] != (name in target_names):
                        raise ValueError(
                            f"{target}: guard state conflicts with configured target defines: {name}"
                        )
                    overrides = metadata_flags[target].get(path, []) or [""]
                    for override in overrides:
                        _toolchain, resolved_flags = resolve_compile_overrides_cached(
                            cfg, path.parent, None, override or None, cfg.module
                        )
                        effective = effective_compile_flags(cfg, None, resolved_flags, path.parent)
                        if name in " ".join([cfg.base_cflags or "", resolved_flags]):
                            raise ValueError(
                                f"{target}: guard macro appears in additional compiler flags"
                            )
                        if any(
                            flag.lower().startswith("/fi") or flag in {"-include", "-imacros"}
                            for flag in effective
                        ):
                            raise ValueError(
                                f"{target}: forced compiler include has unknown macro effects"
                            )
                    for header in header_contexts[target].get(path, set()):
                        if macro_change_re(name).search(header_text(header)):
                            raise ValueError(f"{header}: include changes guard macro {name}")
                tree, _ = parse_c_source(masked_view)
                if tree.root_node.has_error:
                    raise ValueError(f"{path}: target {target} structural view has syntax errors")
                views.append(ParsedSource(text=text, data=masked_view, tree=tree))
            if not views:
                raise ValueError(f"{path}: ambiguous C syntax with no selected target")
            view_hits = [
                {
                    (o.start, o.end, o.role)
                    for o in occurrences(view, old_name)
                    if o.role not in {ROLE_COMMENT, ROLE_LITERAL}
                }
                for view in views
            ]
            if any(found != view_hits[0] for found in view_hits[1:]):
                raise ValueError(f"{path}: target guards change reference ownership")
            target_views = views
            parsed = views[0]
            hits = [
                o
                for o in occurrences(parsed, old_name)
                if o.role not in {ROLE_COMMENT, ROLE_LITERAL}
            ]
        relative = path.relative_to(root).as_posix()
        for view in target_views if hits else []:
            shadowed = _local_shadows(view, new_name)
            for hit in hits:
                node = view.tree.root_node.descendant_for_byte_range(hit.start, hit.end)
                if _function_scope(node) in shadowed:
                    raise ValueError(f"{relative}:{hit.line}: replacement name has a local shadow")
            if non_external_function_declarations(view, new_name):
                raise ValueError(f"{relative}: replacement name has a conflicting declaration")
        if hits:
            possible_headers: set[Path] = set()
            for target_contexts in header_contexts.values():
                possible_headers.update(target_contexts.get(path, set()))
                if path.suffix.lower() == ".h":
                    for consumer, includes in target_contexts.items():
                        if path in includes:
                            possible_headers.add(consumer)
                            possible_headers.update(includes)
            for context_path in {path, *possible_headers}:
                if defines_new_name(context_path):
                    raise ValueError(f"{context_path}: replacement name has a macro definition")
                context_source = _parse(read_source_text(context_path)[0])
                if non_external_function_declarations(context_source, new_name):
                    raise ValueError(
                        f"{context_path}: replacement name has a conflicting declaration"
                    )
        for hit in hits:
            if hit.role not in ORDINARY_ROLES or hit.role != ROLE_IDENT:
                raise ValueError(f"{relative}:{hit.line}: ambiguous macro or identifier role")
            site_decisions: set[str] = set()
            for target in sorted(targets):
                key = f"{relative}:{hit.start}:{target}"
                expected_keys.add(key)
                decision = "undecided" if discovery_only else ownership.get(key)
                if not discovery_only and decision not in {"replace", "preserve", "inactive"}:
                    raise ValueError(f"missing or ambiguous ownership: {key}")
                if (
                    path.suffix.lower() != ".h"
                    and path not in selected[target]
                    and decision not in {"inactive", "undecided"}
                ):
                    raise ValueError(f"{key}: source is not selected for this target")
                if decision == "replace" and target not in identities:
                    raise ValueError(f"{key}: target has no reviewed replacement identity")
                if path == donor and hit.line in donor_definition_lines and decision == "replace":
                    raise ValueError(f"{key}: donor definition cannot be rewritten as a reference")
                if decision in {"replace", "preserve"}:
                    site_decisions.add(decision)
                references.append(
                    {
                        "file": relative,
                        "offset": hit.start,
                        "line": hit.line,
                        "column": hit.column,
                        "target": target,
                        "decision": decision,
                    }
                )
            if site_decisions == {"replace", "preserve"}:
                raise ValueError(f"{relative}:{hit.line}: conflicting target ownership")
    if not discovery_only and set(ownership) != expected_keys:
        raise ValueError("ownership contains stale or unknown occurrences")
    rediscovered = {
        p.resolve() for cfg in configs for p in iter_sources_and_headers(cfg.reversed_dir, cfg)
    }
    final_include_paths: list[tuple[Path, Path]] = []
    final_contents: dict[Path, bytes] = {}
    final_identities: dict[Path, dict[str, Any]] = {}
    final_shadows: list[tuple[str, str, tuple[str, ...]]] = []
    final_probes: list[tuple[str, tuple[str, ...]]] = []
    for target, cfg in targets.items():
        current, _ = collect_target_sources(cfg, cfg.module)
        if (
            {p.absolute() for p in current} != selected_names[target]
            or {p.resolve() for p in current} != selected[target]
            or {p.absolute() for p in iter_sources_and_headers(cfg.reversed_dir, cfg)}
            != discovery_names[target]
        ):
            raise ValueError("target source selection changed while planning")
        rediscovered.update(p.resolve() for p in current)
        headers, unknown = contract_contexts(
            cfg,
            observed_contents=final_contents,
            lexical_includes=final_include_paths,
            observed_identities=final_identities,
            include_shadows=final_shadows,
            include_probes=final_probes,
            image_headers=image_headers,
        )
        current_headers = {path.resolve() for path in headers}
        current_contexts: dict[Path, set[Path]] = {}
        for header, consumers in headers.items():
            for consumer in consumers:
                current_contexts.setdefault(consumer.resolve(), set()).add(header.resolve())
        if (
            current_contexts != header_contexts[target]
            or current_headers != closures[target]
            or (
                [{"target": target, **item} for item in unknown]
                != [item for item in closure_unknown if item["target"] == target]
            )
        ):
            raise ValueError("include closure changed while planning")
        rediscovered.update(path for path in current_headers if path.is_relative_to(root))
    if (
        set(include_paths) != set(final_include_paths)
        or final_contents != observed_contents
        or final_identities != observed_identities
        or set(final_shadows) != set(include_shadows)
        or set(final_probes) != set(include_probes)
    ):
        raise ValueError("include closure changed while planning")
    if (
        rediscovered | {donor, replacement} != files
        or before != inputs()
        or identities_before != {str(path): path_identity(path) for path in sorted(lexical_paths)}
    ):
        raise ValueError("review inputs changed while planning")
    if image_headers is not None:
        image_headers.verify()
    payload = {
        "identities": identities,
        "donor": str(donor),
        "replacement": str(replacement),
        "old_name": old_name,
        "new_name": new_name,
        "references": references,
        "input_hashes": before,
        "path_identities": identities_before,
        "discovered": sorted(str(p) for p in files),
        "target_sources": {t: sorted(str(p) for p in paths) for t, paths in selected.items()},
        "target_contexts": contexts,
        "guard_states": guard_states,
        "include_unknown": closure_unknown,
        "include_shadows": sorted(set(include_shadows)),
        "include_probes": sorted(set(include_probes)),
    }
    if image_headers is not None:
        payload["compiler_images"] = {
            profile: tree["id"] for profile, tree in image_headers.trees.items()
        }
        payload = image_headers.normalize(payload)
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    if expected_digest is not None and expected_digest != digest:
        raise ValueError("review inputs changed; create a new plan")
    return {
        **payload,
        "input_digest": digest,
        "apply_available": False,
        "ownership_complete": not discovery_only,
        "safety_review_complete": False,
        "macro_scope_unknown": {
            "include_contexts": closure_unknown,
            "other": [
                "conditional macro activity, command-line macros and scope are not preprocessed"
            ],
        },
        "limitations": [
            "ownership_complete means only that decisions were supplied",
            "native equivalence, preprocessor activity and target guard decisions require review",
            "macro scope and shadowing checks are conservative, not preprocessor proof",
            "linker references and unresolved include contexts require review",
            "source discovery excludes symlinked files and directories",
        ],
    }


def plan_binding_replacement(
    configs: list[ProjectConfig],
    identities: dict[str, int],
    donor: Path,
    replacement: Path,
    old_name: str,
    new_name: str,
    ownership: dict[str, str] | None = None,
    *,
    evidence: list[Path] | None = None,
    expected_digest: str | None = None,
    guard_states: dict[str, dict[str, bool]] | None = None,
    use_image_headers: bool = False,
) -> dict[str, Any]:
    """Plan without writes, optionally resolving SDK headers from admitted images."""
    from contextlib import nullcontext

    from rebrew.compiler.image_headers import ImageHeaders

    with ImageHeaders() if use_image_headers else nullcontext() as headers:
        return _plan_binding_replacement(
            configs,
            identities,
            donor,
            replacement,
            old_name,
            new_name,
            ownership,
            evidence=evidence,
            expected_digest=expected_digest,
            guard_states=guard_states,
            image_headers=headers,
        )
