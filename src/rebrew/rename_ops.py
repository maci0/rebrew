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


def substitute_name(pattern: re.Pattern[str], replacement: str, text: str) -> str:
    """Substitute *pattern* in *text*, leaving literals and macro names alone.

    The CLI contract is that macros and string literals are not rewritten; a
    plain ``pattern.sub`` over the raw text rewrote ``puts("foo")``, changing
    the data a byte-matched function emits.  Spans come from
    :func:`rebrew.c_parser.protected_spans` (string/char literals and ``#define``
    names) and the substitution runs over the gaps between them, on BYTES so a
    multibyte character before a span cannot shift it.

    Falls back to the plain substitution (with a warning) when tree-sitter is
    unavailable, so a rename still works without the optional parser.
    """
    try:
        from rebrew.c_parser import protected_spans

        spans = protected_spans(text)
    except ImportError:
        logger.warning(
            "tree-sitter unavailable — string literals and macro names WILL be rewritten"
        )
        return pattern.sub(replacement, text)
    if not spans:
        return pattern.sub(replacement, text)

    data = text.encode("utf-8")
    byte_pattern = re.compile(pattern.pattern.encode("utf-8"))
    byte_replacement = replacement.encode("utf-8")
    out: list[bytes] = []
    pos = 0
    for start, end in spans:
        out.append(byte_pattern.sub(byte_replacement, data[pos:start]))
        out.append(data[start:end])
        pos = end
    out.append(byte_pattern.sub(byte_replacement, data[pos:]))
    return b"".join(out).decode("utf-8")


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
        except (OSError, UnicodeDecodeError):
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
    # Strip exactly ONE leading underscore: MSVC decorates a cdecl name with
    # one (`_foo` for foo), so a function genuinely named `_foo` carries the
    # symbol `__foo` — `lstrip("_")` turned that into `foo` and renamed an
    # unrelated function instead.
    actual_old_name = old_sym.removeprefix("_") if old_sym.startswith("_") else old_name
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
    if not target_func.isidentifier():
        raise ValueError(f"target function name {target_func!r} is not a valid C identifier")
    rename_target: Path | None = None
    if rename_file and not dry_run:
        try:
            multi_function_file = (
                len(
                    parse_c_file_multi(
                        filepath, metadata_dir=getattr(cfg, "metadata_dir", filepath.parent)
                    )
                )
                > 1
            )
        except Exception as exc:  # abort before mutating anything
            raise ValueError(f"cannot rename {filepath}: annotation parse failed: {exc}")
        if multi_function_file and not new_filename:
            rename_file = False  # auto-rename unsafe for multi-function files
        if rename_file:  # re-check: the multi-function guard may have disabled renaming
            if new_filename:
                if Path(new_filename).suffix != filepath.suffix:
                    new_filename = new_filename + filepath.suffix
                # Preserve original directory unless caller passes a path
                if "/" in new_filename or "\\" in new_filename:
                    candidate = (cfg.reversed_dir / new_filename).resolve()
                    try:
                        candidate.relative_to(cfg.reversed_dir.resolve())
                    except ValueError:
                        raise ValueError(f"new filename escapes reversed_dir: {new_filename!r}")
                    target_file = candidate
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
        # Literals and macro names are left alone (see substitute_name), and
        # target_func is literal, never interpreted as re backreference syntax
        # (e.g. a name containing ``\1``) — the replacement is a plain string.
        new_content = substitute_name(
            re.compile(r"\b" + re.escape(actual_old_name) + r"\b"), target_func, content
        )
        if new_content != content:
            atomic_write_text(filepath, new_content, encoding=encoding)
            updated_files += 1
    except (OSError, UnicodeEncodeError) as exc:
        # The primary file is the definition — renaming references elsewhere
        # while the definition keeps the old name breaks every call site.
        # Abort the whole rename rather than half-applying it.  A source with
        # an undefined byte in its encoding (e.g. CP1252 0x81 read back as
        # U+FFFD) raises UnicodeEncodeError, not OSError, on write.
        logger.error("Failed to update primary file %s: %s", filepath, exc)
        raise

    # 3. Find and update externs across all files
    for src_file in iter_sources(cfg.reversed_dir, cfg):
        if src_file == filepath:
            continue

        try:
            content, encoding = read_source_text(src_file)
            new_content = substitute_name(
                re.compile(r"\b" + re.escape(actual_old_name) + r"\b"), target_func, content
            )
            if new_content != content:
                atomic_write_text(src_file, new_content, encoding=encoding)
                updated_files += 1
        except (OSError, UnicodeEncodeError) as exc:
            logger.warning(
                "Failed to update cross-reference in %s: %s — manual update required",
                src_file,
                exc,
            )

    # 4. Rename file if needed — skip when file has multiple annotations
    #    (renaming would disassociate the other functions from their file).
    if rename_target is not None:
        try:
            filepath.rename(rename_target)
        except OSError as exc:
            logger.error("Failed to rename %s -> %s: %s", filepath, rename_target, exc)
            raise

    return updated_files
