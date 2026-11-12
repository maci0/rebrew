"""Shared target participation for build providers and source-context audits."""

lazy from collections.abc import Sequence
lazy from pathlib import Path

lazy from rebrew.config import ProjectConfig
lazy from rebrew.function_providers import bind_compiled_source
lazy from rebrew.metadata.bindings import SourceBinding, read_source_bindings
lazy from rebrew.metadata.functions import identity_file, load_metadata
lazy from rebrew.sources import iter_sources
lazy from rebrew.utils import preset_module_key


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="surrogateescape")


def collect_target_sources(
    cfg: ProjectConfig,
    target_module_name: str,
    *,
    sources: Sequence[Path] | None = None,
) -> tuple[list[Path], list[Path]]:
    """``(own, foreign)`` absolute source paths for *target_module_name*.

    *own* holds target-bound identities, target-scoped support files, and
    unbound helpers. *foreign* holds files bound only to other targets.
    *sources* is an already-discovered source list; the walk runs only when
    a caller has none.
    """
    from rebrew.metadata.source_provenance import load_source_files

    own: list[Path] = []
    foreign: list[Path] = []
    # Library providers are project-root relative; FUNCTION rows use metadata-relative
    # paths. Retain every module's bindings
    # before deciding a body is an unannotated helper shared by all targets.
    from rebrew.metadata.binding_history import historical_source_files

    retired_sources: set[Path] = set()
    library_entries: dict[Path, list[SourceBinding]] = {}
    # ``metadata_dir`` probes the ancestors for the store on every access, and
    # the loop below visits every source in the tree.
    metadata_dir = cfg.metadata_dir
    project_root = getattr(cfg, "root", None)
    # One read for the whole tree: read_source_bindings otherwise re-resolves
    # and re-fingerprints the store once per source below.
    function_entries = load_metadata(metadata_dir, deepcopy=False)
    for (module, va), row in function_entries.items():
        retired_sources.update(historical_source_files(row, metadata_dir, cfg.root))
        stored = str(row.get("file", ""))
        if (
            not va
            or row.get("kind") not in {"FUNCTION", "LIBRARY"}
            or Path(stored).suffix.casefold() not in {".c", ".cpp", ".cc", ".cxx"}
        ):
            continue
        bound = bind_compiled_source(
            cfg, SourceBinding(module=module, va=va, kind=str(row["kind"])), row
        )
        source = (cfg.reversed_dir / bound.filepath).resolve()
        if not source.is_file():
            raise ValueError(f"compiled source is missing: {source}")
        library_entries.setdefault(source, []).append(bound)
    # One store read for the whole tree: probing it per unbound source made the
    # walk stat and glob the metadata collection once per file. Loaded only
    # when a source has no annotation, so a fully bound tree pays nothing.
    support_modules: dict[str, set[str]] | None = None
    metadata_root = metadata_dir.resolve()
    discovered = sources if sources is not None else iter_sources(cfg.reversed_dir, cfg)
    source_files = set(discovered) | set(library_entries)
    target_key = preset_module_key(target_module_name)
    for src in sorted(source_files):
        resolved = src.resolve()
        anns = [
            a
            for a in read_source_bindings(
                src,
                metadata_dir=metadata_dir,
                project_root=project_root,
                function_entries=function_entries,
                with_prototypes=False,
            )
            if a.va
        ]
        anns.extend(library_entries.get(resolved, []))
        if not anns:
            # An anchor that resolved to no live row still names a module: a
            # leftover of another target's claim must not join this build as a
            # shared helper, or it drags that target's unbound callees in.
            from rebrew.metadata.anchors import parse_address_anchors

            raw = parse_address_anchors(_read(src), syntax=getattr(cfg, "address_comments", None))
            modules_named = {preset_module_key(a.module) for a in raw if a.va}
            if modules_named and target_key not in modules_named:
                foreign.append(resolved)
                continue
            relative = identity_file(resolved, metadata_root)
            if support_modules is None:
                support_modules = {}
                for record in load_source_files(metadata_dir):
                    support_modules.setdefault(record.file, set()).add(record.module)
            modules = support_modules.get(relative, set())
            if not modules and resolved in retired_sources:
                foreign.append(resolved)
            elif not modules or target_key in modules:
                own.append(resolved)
            else:
                foreign.append(resolved)
            continue
        if any(preset_module_key(a.module) == target_key for a in anns):
            own.append(resolved)
        else:
            foreign.append(resolved)
    return sorted(own), sorted(foreign)
