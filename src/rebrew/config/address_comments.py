"""Address-comment formatting dialects and cached project comment layout."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
lazy from pathlib import Path

from rebrew.config.constants import (
    ADDRESS_COMMENT_TEMPLATES,
    DEFAULT_ADDRESS_COMMENT_REGEX,
)
from rebrew.config.schema import (
    as_table,
    normalized_targets,
    read_toml_doc,
    required_path,
)
from rebrew.errors import (
    ConfigError,
)
lazy from rebrew.utils import (
    path_is_relative_to,
    preset_module_key,
    resolved_path,
)


@dataclass(frozen=True)
class AddressCommentFormat:
    """Comment dialect, body regex and rendering template for source addresses."""

    style: str = "c89"
    regex: str = DEFAULT_ADDRESS_COMMENT_REGEX
    template: str = ""

    def __post_init__(self) -> None:
        from string import Template

        if self.style not in ADDRESS_COMMENT_TEMPLATES:
            raise ConfigError("address_comments.style must be c89, cpp or delphi")
        try:
            pattern = re.compile(self.regex)
        except re.error as exc:
            raise ConfigError(f"invalid address_comments.regex: {exc}") from exc
        if not {"module", "va"} <= pattern.groupindex.keys():
            raise ConfigError("address_comments.regex needs named module and va groups")
        template = self.render_template
        parsed = Template(template)
        if not parsed.is_valid() or set(parsed.get_identifiers()) != {"module", "va"}:
            raise ConfigError("address_comments.template needs $module and $va only")
        if "\n" in template or "\r" in template:
            raise ConfigError("address_comments.template must be one line")
        pairs = (("{", "}"), ("(*", "*)")) if self.style == "delphi" else (("/*", "*/"), ("//", ""))
        for opening, closing in pairs:
            if template.startswith(opening) and (not closing or template.endswith(closing)):
                body = template[len(opening) : -len(closing) if closing else None]
                if closing and closing in body:
                    break
                sample = Template(body).substitute(module="TARGET", va="0x00001000").strip()
                match = pattern.fullmatch(sample)
                if match and match["module"] == "TARGET" and match["va"] == "0x00001000":
                    return
        raise ConfigError("address_comments.template must round-trip through its dialect and regex")

    @property
    def render_template(self) -> str:
        """The explicit template or the dialect's built-in default."""
        return self.template or ADDRESS_COMMENT_TEMPLATES[self.style]


DEFAULT_ADDRESS_COMMENTS = AddressCommentFormat()


@dataclass(frozen=True)
class AddressCommentTarget:
    """One target's comment dialect and the resolved root its sources live under."""

    module_key: str
    source_root: Path
    comments: AddressCommentFormat


@dataclass(frozen=True)
class AddressCommentLayout:
    """Comment dialects and resolved source roots for one project document."""

    project_comments: AddressCommentFormat
    shared_root: Path | None
    targets: tuple[AddressCommentTarget, ...]


#: Resolved source roots and comment dialects for one parsed document. The
#: per-file walk otherwise called ``Path.resolve`` on every target root.
#: One slot per path; the cap drops projects this process stopped reading.
PROJECT_LAYOUT: dict[Path, tuple[tuple[int, int, int, int], AddressCommentLayout]] = {}
PROJECT_CACHE_MAX = 8


def parse_address_comment_format(project: Any, target: Any = None) -> AddressCommentFormat:
    """Resolve project defaults and per-target overrides without reading a binary."""
    values: dict[str, str] = {}
    for table in (project, target):
        if table is None:
            continue
        if not isinstance(table, dict) or set(table) - {"style", "regex", "template"}:
            raise ConfigError("address_comments accepts only style, regex and template")
        if any(not isinstance(v, str) or not v for v in table.values()):
            raise ConfigError("address_comments values must be non-empty strings")
        values.update(table)
    return AddressCommentFormat(**values) if values else DEFAULT_ADDRESS_COMMENTS


#: Parsed ``rebrew-project.toml`` per path, keyed on its stat so an edit is re-read.
#: Source discovery asks once per file (10,900 files on guild-rebrew).
#: Bounded: the key is the path, and a stamp change is a new entry, so a
#: long-lived process that rewrites or walks many project files would
#: otherwise retain every previous document.
PROJECT_TOML: dict[Path, tuple[tuple[int, int, int, int], dict[str, Any]]] = {}


def remember_project_cache(cache: dict[Path, Any], path: Path, value: Any) -> None:
    """Store *value* for *path*, dropping the oldest path past the cap.

    Replacing *path* moves it to the end, so a live project is not the one
    evicted when a later path fills the map.
    """
    cache.pop(path, None)
    cache[path] = value
    while len(cache) > PROJECT_CACHE_MAX:
        del cache[next(iter(cache))]


def project_toml(path: Path) -> dict[str, Any]:
    """Read-only parsed project config; callers must not mutate the result."""
    st = path.stat()
    # ctime too: a same-length rewrite can keep mtime, size and inode, and a
    # stale parse would then bind every later source against the old config.
    stamp = (st.st_mtime_ns, st.st_size, st.st_ino, st.st_ctime_ns)
    hit = PROJECT_TOML.get(path)
    if hit is not None and hit[0] == stamp:
        # A hit is the live project: leave it at the tail so the next insert
        # evicts a project this process is no longer reading.
        PROJECT_TOML[path] = PROJECT_TOML.pop(path)
        return hit[1]
    raw = read_toml_doc(path)
    remember_project_cache(PROJECT_TOML, path, (stamp, raw))
    return raw


def address_comment_layout(root: Path, raw: dict[str, Any]) -> AddressCommentLayout:
    """Resolve source roots once per parsed document, not once per source file."""
    project = as_table(raw.get("project", {}), "project")
    targets = normalized_targets(as_table(raw.get("targets", {}), "targets"))
    shared = project.get("shared_dir", "src/shared")
    shared_root = (
        required_path(root, shared, "src/shared", "shared_dir").resolve() if shared else None
    )
    rows = []
    for name, target in targets.items():
        target_module_name = str(target.get("module") or re.sub(r"[^A-Za-z0-9_]", "", name.upper()))
        rows.append(
            AddressCommentTarget(
                module_key=preset_module_key(target_module_name),
                source_root=required_path(
                    root, target.get("reversed_dir"), f"src/{name}", "reversed_dir"
                ).resolve(),
                comments=parse_address_comment_format(
                    project.get("address_comments"), target.get("address_comments")
                ),
            )
        )
    return AddressCommentLayout(
        project_comments=parse_address_comment_format(project.get("address_comments")),
        shared_root=shared_root,
        targets=tuple(rows),
    )


def cached_address_comment_layout(root: Path) -> AddressCommentLayout:
    """Layout for *root*, reused while ``rebrew-project.toml`` is unchanged."""
    path = root / "rebrew-project.toml"
    st = path.stat()
    stamp = (st.st_mtime_ns, st.st_size, st.st_ino, st.st_ctime_ns)
    hit = PROJECT_LAYOUT.get(path)
    if hit is not None and hit[0] == stamp:
        PROJECT_LAYOUT[path] = PROJECT_LAYOUT.pop(path)
        return hit[1]
    layout = address_comment_layout(root, project_toml(path))
    remember_project_cache(PROJECT_LAYOUT, path, (stamp, layout))
    return layout


def address_comments_for_file(
    filepath: Path, *, module: str | None = None, project_root: Path | None = None
) -> AddressCommentFormat:
    """Read source-comment settings for metadata APIs that have a path, not a config.

    Shared files must have compatible target dialects. This reads configuration
    only: source discovery must not load the reference binary or a toolchain.
    """
    from rebrew.workspace.config import walk_up_to_root

    root = project_root or walk_up_to_root(filepath.parent)
    if root is None or not (root / "rebrew-project.toml").is_file():
        return DEFAULT_ADDRESS_COMMENTS
    layout = cached_address_comment_layout(root)
    module_key = preset_module_key(module) if module else None
    # The memo read_source_text fills for the same file.
    resolved = resolved_path(filepath)
    in_shared = layout.shared_root is not None and path_is_relative_to(resolved, layout.shared_root)
    selected = [
        target.comments
        for target in layout.targets
        if (module_key is None or target.module_key == module_key)
        and (module or in_shared or path_is_relative_to(resolved, target.source_root))
    ]
    if len(set(selected)) > 1:
        raise ConfigError(f"{filepath}: shared source has incompatible address_comments settings")
    return selected[0] if selected else layout.project_comments
