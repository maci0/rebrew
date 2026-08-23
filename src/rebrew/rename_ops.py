"""rename_ops.py - Cross-reference rename operations.

Reusable rename engine shared by the ``rebrew rename`` CLI and library
callers (Ghidra sync pull, BinSync import): rewrites the function
definition, call sites, and ``extern`` declarations across the reversed
tree, optionally renaming the source file.  Pure filesystem/metadata
logic — no CLI or output concerns.
"""

import logging
import re
from pathlib import Path

from rebrew.annotation import parse_c_file_multi
from rebrew.config import ProjectConfig
from rebrew.sources import iter_sources
from rebrew.utils import atomic_write_text, read_source_text

logger = logging.getLogger(__name__)


def collect_matching_files(
    cfg: ProjectConfig, filepath: Path, pattern: re.Pattern[str]
) -> list[Path]:
    """Source files whose content matches *pattern* (rename candidates)."""
    matched: list[Path] = []
    candidates = [filepath] + [s for s in iter_sources(cfg.reversed_dir, cfg) if s != filepath]
    for src in candidates:
        try:
            text, _ = read_source_text(src)
            if pattern.search(text):
                matched.append(src)
        except OSError:
            continue
    return matched


def rename_function_everywhere(
    cfg: ProjectConfig,
    filepath: Path,
    old_name: str,
    old_sym: str,
    target_func: str,
    rename_file: bool = True,
    new_filename: str | None = None,
    dry_run: bool = False,
) -> int:
    """Perform a full cross-reference rename. Returns number of files modified."""
    actual_old_name = old_sym.lstrip("_") if old_sym.startswith("_") else old_name
    # __stdcall symbols carry a decorated suffix (foo@8) that never appears
    # in the C source — strip it or nothing matches.
    actual_old_name = re.sub(r"@\d+$", "", actual_old_name)
    if not actual_old_name:
        # An annotation-only stub with no meaningful name (sync --pull passes
        # name=""/symbol="" for these): re.sub with an empty pattern would
        # match at every word boundary and mangle the whole file.
        raise ValueError(
            f"cannot rename {filepath}: old name is empty (missing FUNCTION marker or symbol)"
        )
    # All validation happens BEFORE any write: a parse failure or target-file
    # collision must abort the rename with nothing mutated on disk (the old
    # order renamed references in every file, then hit the unguarded
    # parse_c_file_multi and left a half-applied rename behind).
    rename_target: Path | None = None
    if rename_file and not dry_run:
        try:
            multi_function_file = (
                len(parse_c_file_multi(filepath, metadata_dir=filepath.parent)) > 1
            )
        except Exception as exc:  # abort before mutating anything
            raise ValueError(f"cannot rename {filepath}: annotation parse failed: {exc}")
        if multi_function_file and not new_filename:
            rename_file = False  # auto-rename unsafe for multi-function files
        if rename_file:  # re-check: the multi-function guard may have disabled renaming
            if new_filename:
                if not new_filename.endswith(filepath.suffix):
                    new_filename = new_filename + filepath.suffix
                # Preserve original directory unless caller passes a path
                if "/" in new_filename or "\\" in new_filename:
                    target_file = cfg.reversed_dir / new_filename
                else:
                    target_file = filepath.with_name(new_filename)
            else:
                stem = filepath.stem
                if stem in (actual_old_name, old_sym):
                    target_file = filepath.with_name(f"{target_func}{filepath.suffix}")
                else:
                    target_file = filepath

            if target_file != filepath:
                if target_file.exists():
                    raise FileExistsError(
                        f"Cannot rename {filepath.name} → {target_file.name}: "
                        f"target already exists (different VA). "
                        f"Use --file to pick a different filename."
                    )
                rename_target = target_file

    if dry_run:
        # Preview mode: count files that would be modified without writing.
        pattern = re.compile(r"\b" + re.escape(actual_old_name) + r"\b")
        return len(collect_matching_files(cfg, filepath, pattern))

    updated_files = 0

    # 1. Symbol is now derived from C function definition — no SYMBOL annotation update needed
    # The function definition rename at step 2 handles symbol derivation automatically

    # 2. Update function definition & calls in file
    try:
        content, encoding = read_source_text(filepath)
        # Replacement via callable: target_func is literal, never interpreted
        # as re backreference syntax (e.g. a name containing ``\1``).
        new_content = re.sub(
            r"\b" + re.escape(actual_old_name) + r"\b", lambda _m: target_func, content
        )
        if new_content != content:
            atomic_write_text(filepath, new_content, encoding=encoding)
            updated_files += 1
    except OSError as exc:
        # The primary file is the definition — renaming references elsewhere
        # while the definition keeps the old name breaks every call site.
        # Abort the whole rename rather than half-applying it.
        logger.error("Failed to update primary file %s: %s", filepath, exc)
        raise

    # 3. Find and update externs across all files
    for src_file in iter_sources(cfg.reversed_dir, cfg):
        if src_file == filepath:
            continue

        try:
            content, encoding = read_source_text(src_file)
            new_content = re.sub(
                r"\b" + re.escape(actual_old_name) + r"\b", lambda _m: target_func, content
            )
            if new_content != content:
                atomic_write_text(src_file, new_content, encoding=encoding)
                updated_files += 1
        except OSError as exc:
            logger.warning(
                "Failed to update cross-reference in %s: %s — manual update required",
                src_file,
                exc,
            )

    # 4. Rename file if needed — skip when file has multiple annotations
    #    (renaming would disassociate the other functions from their file).
    if rename_target is not None:
        filepath.rename(rename_target)

    return updated_files
