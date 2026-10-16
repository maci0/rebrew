"""Shared target participation for build providers and source-context audits."""

from pathlib import Path

from rebrew.config import ProjectConfig
from rebrew.function_providers import bind_library_source
from rebrew.metadata.bindings import SourceBinding, read_source_bindings
from rebrew.metadata.functions import identity_file, load_metadata
from rebrew.sources import iter_sources
from rebrew.utils import preset_module_key


def collect_target_sources(
    cfg: ProjectConfig, target_module_name: str
) -> tuple[list[Path], list[Path]]:
    """``(own, foreign)`` absolute source paths for *target_module_name*.

    *own* holds target-bound identities, target-scoped support files, and
    unbound helpers. *foreign* holds files bound only to other targets.
    """
    from rebrew.metadata.source_provenance import load_source_files

    own: list[Path] = []
    foreign: list[Path] = []
    # Explicit compiled-library bindings are project-root relative. The pure-C
    # parser uses metadata-relative paths, so retain every module's bindings
    # before deciding a body is an unannotated helper shared by all targets.
    from rebrew.metadata.binding_history import historical_source_files

    retired_sources: set[Path] = set()
    library_entries: dict[Path, list[SourceBinding]] = {}
    for (module, va), row in load_metadata(cfg.metadata_dir, deepcopy=False).items():
        retired_sources.update(historical_source_files(row, cfg.metadata_dir, cfg.root))
        stored = str(row.get("file", ""))
        if (
            not va
            or row.get("kind") != "LIBRARY"
            or Path(stored).suffix.casefold() not in {".c", ".cpp", ".cc", ".cxx"}
        ):
            continue
        bound = bind_library_source(cfg, SourceBinding(module=module, va=va, kind="LIBRARY"), row)
        source = (cfg.reversed_dir / bound.filepath).resolve()
        if not source.is_file():
            raise ValueError(f"compiled library source is missing: {source}")
        library_entries.setdefault(source, []).append(bound)
    source_files = set(iter_sources(cfg.reversed_dir, cfg)) | set(library_entries)
    for src in sorted(source_files):
        anns = [
            a
            for a in read_source_bindings(
                src, metadata_dir=cfg.metadata_dir, project_root=getattr(cfg, "root", None)
            )
            if a.va
        ]
        anns.extend(library_entries.get(src.resolve(), []))
        if not anns:
            relative = identity_file(src.resolve(), cfg.metadata_dir.resolve())
            modules = {
                record.module
                for record in load_source_files(cfg.metadata_dir)
                if record.file == relative
            }
            if not modules and src.resolve() in retired_sources:
                foreign.append(src.resolve())
            elif not modules or preset_module_key(target_module_name) in modules:
                own.append(src.resolve())
            else:
                foreign.append(src.resolve())
            continue
        if any(preset_module_key(a.module) == preset_module_key(target_module_name) for a in anns):
            own.append(src.resolve())
        else:
            foreign.append(src.resolve())
    return sorted(own), sorted(foreign)
