"""rename_ops.py - Cross-reference rename operations.

Reusable rename engine shared by the ``rebrew source rename`` CLI and library
callers (Ghidra sync pull, BinSync import): rewrites the function
definition, call sites, and ``extern`` declarations across the reversed
tree, optionally renaming the source file.  Pure filesystem/metadata
logic — no CLI or output concerns.
"""

import logging
import re
from collections.abc import Sequence
from pathlib import Path

from rebrew.annotation import Annotation, parse_c_file_multi
from rebrew.c_parser import find_c_function_definitions
from rebrew.config import ProjectConfig
from rebrew.errors import RebrewError
from rebrew.sources import iter_sources_and_headers
from rebrew.utils import atomic_write_text, is_safe_c_ident, read_source_text

logger = logging.getLogger(__name__)

# MSVC ``@N`` suffix. Vectorcall is ``name@@N`` and fastcall is ``@name@N``;
# stripping one ``@N`` is not enough to rebuild either spelling.
_AT_DECORATION_RE = re.compile(r"@\d+$")


def redecorated_symbol(old_sym: str, new_name: str, *, underscore: bool | None = None) -> str:
    """Keep MSVC decoration when the C name changes.

    ``_old@12`` stays ``_new@12``. ``old@@12`` stays ``new@@12``.
    ``@old@4`` stays ``@new@4``. One ``@N`` strip used to report
    ``_new@12`` for a vectorcall symbol.

    ``underscore=True`` is the cdecl ``_`` the rename JSON has always
    added. Leaving it None copies whether *old_sym* already had one.
    """
    suffix = _AT_DECORATION_RE.search(old_sym)
    tail = suffix.group(0) if suffix else ""
    body = old_sym[: suffix.start()] if suffix else old_sym
    if body.endswith("@"):
        return f"{new_name}@{tail}"
    if body.startswith("@") and not body.startswith("@@"):
        return f"@{new_name}{tail}"
    if underscore is None:
        underscore = old_sym.startswith("_")
    return f"{'_' if underscore else ''}{new_name}{tail}"


def c_name_from_symbol(symbol: str) -> str:
    """C identifier inside an MSVC decorated symbol.

    ``_foo`` and ``_foo@8`` are ``foo``. ``foo@@12`` is ``foo``.
    ``@foo@4`` is ``foo``. One leading underscore is the cdecl
    decoration; ``__foo`` is the function ``_foo``.
    """
    name = symbol[1:] if symbol.startswith("_") else symbol
    name = _AT_DECORATION_RE.sub("", name)
    if name.endswith("@"):
        name = name[:-1]
    elif name.startswith("@") and not name.startswith("@@"):
        name = name[1:]
    return name


def rename_source_name(old_name: str, old_sym: str) -> str:
    """C name a rename searches for.

    A leading ``_`` is cdecl or stdcall decoration. ``hook@@12`` and
    ``@keeps@4`` have none, so an empty stored name used to refuse the
    rename.
    """
    if old_sym and (old_sym.startswith("_") or not old_name):
        return c_name_from_symbol(old_sym)
    return c_name_from_symbol(old_name) if old_name else old_name


class RenameError(RebrewError, RuntimeError):
    """A cross-reference rename could not reach every file that names it.

    Two moments raise this.  After the fact (:func:`rename_function_everywhere`):
    the definition file was rewritten (and possibly renamed) but one or more
    other sources could not be, so they still call the old symbol and the
    tree no longer compiles.  Before any write
    (:func:`collect_matching_files`): a source could not be read, so the
    candidate set is unknown and proceeding would split source from
    metadata.  ``files`` carries the offending paths, so the caller can name
    them instead of only logging, and :meth:`RebrewError.to_dict` carries
    them so a persisted failure still names the sources.
    """

    _STRUCTURED_FIELDS = (*RebrewError._STRUCTURED_FIELDS, "files")

    def __init__(self, message: str, *, files: Sequence[Path]) -> None:
        super().__init__(message)
        self.files = list(files)


def substitute_name(pattern: re.Pattern[str], replacement: str, text: str) -> str:
    """Substitute *pattern* in *text*, leaving literals and macro names alone.

    The CLI contract is that macros and string literals are not rewritten; a
    plain ``pattern.sub`` over the raw text rewrote ``puts("foo")``, changing
    the data a byte-matched function emits.  Spans come from
    :func:`rebrew.c_parser.protected_spans` (string/char literals and ``#define``
    names). Gaps are cut by BYTE offset, so a multibyte character before a span
    cannot shift it, then decoded and substituted with the original ``str``
    pattern: a bytes regex would make ``\\b`` ASCII-only (``éfoo`` matched) and
    drop the pattern's flags.

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

    # Same encoding and handler as c_parser.parse_c_source, so the spans line up.
    data = text.encode("utf-8", errors="surrogateescape")

    def _str(chunk: bytes) -> str:
        return chunk.decode("utf-8", errors="surrogateescape")

    out: list[str] = []
    pos = 0
    for start, end in spans:
        out.append(pattern.sub(replacement, _str(data[pos:start])))
        out.append(_str(data[start:end]))
        pos = end
    out.append(pattern.sub(replacement, _str(data[pos:])))
    return "".join(out)


def collect_matching_files(
    cfg: ProjectConfig, filepath: Path, pattern: re.Pattern[str]
) -> list[Path]:
    """Source files whose content matches *pattern* (rename candidates).

    Raises :class:`RenameError` when a candidate could not be read.  The
    candidate list is what decides how far the rename reaches: a source
    skipped here is never rewritten, and the definition plus the metadata
    still get the new name, leaving a call site on the old one — a split
    tree reported as a successful rename.  The same file on the write path
    raises, so the scan has to agree with it.
    """
    matched: list[Path] = []
    unreadable: list[Path] = []
    candidates = [filepath] + [
        s for s in iter_sources_and_headers(cfg.reversed_dir, cfg) if s != filepath
    ]
    for src in candidates:
        try:
            text, _ = read_source_text(src)
        except (OSError, UnicodeDecodeError):
            unreadable.append(src)
            continue
        if pattern.search(text):
            matched.append(src)
    if unreadable:
        listed = ", ".join(str(p) for p in unreadable)
        raise RenameError(
            f"cannot plan the rename: these sources could not be read, so a "
            f"reference to the old name may be left behind: {listed}. Fix the "
            f"permissions (or encoding) and re-run.",
            files=unreadable,
        )
    return matched


def _rename_annotations(cfg: ProjectConfig, path: Path) -> list[Annotation]:
    """Read every target's identities, including mixed migrated/inline files."""
    from rebrew.metadata import load_metadata

    metadata_dir = getattr(cfg, "metadata_dir", path.parent)
    parsed = parse_c_file_multi(path, metadata_dir=metadata_dir)
    by_identity = {(e.module, e.va, e.marker_type): e for e in parsed}
    for module in {m for m, _va in load_metadata(metadata_dir, deepcopy=False)}:
        for e in parse_c_file_multi(path, target_name=module, metadata_dir=metadata_dir):
            by_identity[(e.module, e.va, e.marker_type)] = e
    return list(by_identity.values())


def collect_function_rename_files(
    cfg: ProjectConfig, filepath: Path, pattern: re.Pattern[str], old_name: str
) -> list[Path]:
    """Plan references without joining independent same-name target symbols.

    A shared definition's markers identify every target that owns that body.
    Independent definitions in other targets retain their own references.
    Common headers and mixed target files cannot disambiguate such bindings;
    reject them before writing instead of silently renaming both symbols.
    Unique symbols keep the ordinary project-wide rename behavior.
    """
    from rebrew.utils import preset_module_key

    annotations: dict[Path, list[Annotation]] = {}

    def entries(path: Path) -> list[Annotation]:
        if path not in annotations:
            annotations[path] = _rename_annotations(cfg, path)
        return annotations[path]

    def owner_modules(path: Path) -> set[str]:
        return {
            preset_module_key(e.module)
            for e in entries(path)
            if e.module
            and e.marker_type in ("FUNCTION", "LIBRARY")
            # ``hook@@12`` is ``hook``. One ``@N`` strip left ``hook@``,
            # so this set was empty and another target's ``hook`` was renamed.
            and (
                e.name == old_name
                or (e.symbol.strip() and c_name_from_symbol(e.symbol) == old_name)
            )
        }

    owners = owner_modules(filepath)
    if not owners:
        return collect_matching_files(cfg, filepath, pattern)
    matched = collect_matching_files(cfg, filepath, pattern)
    protected: set[str] = set()
    ambiguous: list[Path] = []
    for path in matched:
        text, _encoding = read_source_text(path)
        definitions = [
            name for name, _line in find_c_function_definitions(text) if name == old_name
        ]
        if path == filepath:
            if len(definitions) > 1:
                ambiguous.append(path)
            continue
        if not definitions:
            continue
        other_owners = owner_modules(path)
        if not other_owners or other_owners & owners:
            ambiguous.append(path)
        protected.update(other_owners)
    if not protected and not ambiguous:
        return matched
    selected: list[Path] = []
    for path in matched:
        if path == filepath:
            selected.append(path)
            continue
        modules = {preset_module_key(e.module) for e in entries(path) if e.module}
        if not modules or (modules & owners and modules & protected):
            ambiguous.append(path)
        elif modules & owners:
            selected.append(path)
    if ambiguous:
        raise RenameError(
            f"cannot rename {old_name}: ambiguous references to independent target symbols; "
            "separate or annotate their ownership before renaming; no files were changed",
            files=sorted(set(ambiguous)),
        )
    return selected


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
    """Perform a full cross-reference rename. Returns number of files modified.

    Raises :class:`RenameError` when a source that referenced the old name
    could not be rewritten; the definition rename is left in place, so the
    caller must surface the failure rather than report success.
    """
    # One leading underscore is cdecl/stdcall decoration (`__foo` is the
    # function `_foo`). ``hook@@12`` and ``@keeps@4`` carry no leading
    # underscore; an empty stored name still names the C function.
    actual_old_name = rename_source_name(old_name, old_sym)
    if not actual_old_name:
        # An annotation-only stub with no meaningful name (sync pull passes
        # name=""/symbol="" for these): re.sub with an empty pattern would
        # match at every word boundary and mangle the whole file.
        raise ValueError(
            f"cannot rename {filepath}: old name is empty (missing FUNCTION marker or symbol)"
        )
    # All validation happens BEFORE any write: a parse failure or target-file
    # collision must abort the rename with nothing mutated on disk (the old
    # order renamed references in every file, then hit the unguarded
    # parse_c_file_multi and left a half-applied rename behind).
    if not is_safe_c_ident(target_func):
        raise ValueError(f"target function name {target_func!r} is not a valid C identifier")
    # One compile for the whole tree walk — recompiling per file was O(files)
    # of identical Pattern construction on a rename that only differs by content.
    name_re = re.compile(r"\b" + re.escape(actual_old_name) + r"\b")

    rename_target: Path | None = None
    if rename_file:  # dry runs validate too: a preview must fail where the write would
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
            if dry_run:  # a preview writes nothing; the real run reports this
                return len(collect_function_rename_files(cfg, filepath, name_re, actual_old_name))
            raise ValueError(f"cannot rename {filepath}: annotation parse failed: {exc}") from exc
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
                    except ValueError as exc:
                        raise ValueError(
                            f"new filename escapes reversed_dir: {new_filename!r}"
                        ) from exc
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

    if not dry_run:
        # Keep the primary-file error contract; a missing definition cannot
        # leave any rewritten references behind.
        read_source_text(filepath)
    candidates = collect_function_rename_files(cfg, filepath, name_re, actual_old_name)
    if dry_run:
        # Preview mode: count files that would be modified without writing.
        return len([p for p in candidates if name_re.search(read_source_text(p)[0])])

    from rebrew.metadata import load_metadata, record_migrated_markers
    from rebrew.utils import rel_display_path

    metadata_dir = getattr(cfg, "metadata_dir", filepath.parent)
    metadata = load_metadata(metadata_dir, deepcopy=False)
    identities = []
    for entry in _rename_annotations(cfg, filepath):
        if not metadata.get((entry.module, entry.va), {}).get("file"):
            continue
        identity = {}
        if rename_target is not None:
            identity["file"] = rel_display_path(rename_target, getattr(cfg, "root", metadata_dir))
        if entry.name == actual_old_name or c_name_from_symbol(entry.symbol) == actual_old_name:
            identity["name"] = target_func
            identity["symbol"] = redecorated_symbol(entry.symbol, target_func)
        if identity:
            identities.append({"module": entry.module, "va": entry.va, "identity": identity})

    updated_files = 0

    # Update function definition & calls in file
    try:
        content, encoding = read_source_text(filepath)
        # Literals and macro names are left alone (see substitute_name), and
        # target_func is literal, never interpreted as re backreference syntax
        # (e.g. a name containing ``\1``) — the replacement is a plain string.
        new_content = substitute_name(name_re, target_func, content)
        if new_content != content:
            atomic_write_text(filepath, new_content, encoding=encoding)
            updated_files += 1
    except (OSError, UnicodeEncodeError):
        # The primary file is the definition — renaming references elsewhere
        # while the definition keeps the old name breaks every call site.
        # Abort the whole rename rather than half-applying it.  A source with
        # an undefined byte in its encoding (e.g. CP1252 0x81 read back as
        # U+FFFD) raises UnicodeEncodeError, not OSError, on write.
        logger.exception("Failed to update primary file %s", filepath)
        raise

    # Find and update externs across all files
    stale: list[Path] = []
    for src_file in candidates:
        if src_file == filepath:
            continue

        try:
            content, encoding = read_source_text(src_file)
            new_content = substitute_name(name_re, target_func, content)
            if new_content != content:
                atomic_write_text(src_file, new_content, encoding=encoding)
                updated_files += 1
        except (OSError, UnicodeEncodeError) as exc:
            logger.warning(
                "Failed to update cross-reference in %s: %s — manual update required",
                src_file,
                exc,
            )
            stale.append(src_file)

    # Rename file if needed — skip when file has multiple annotations
    #    (renaming would disassociate the other functions from their file).
    if rename_target is not None:
        try:
            filepath.rename(rename_target)
        except OSError:
            logger.exception("Failed to rename %s -> %s", filepath, rename_target)
            raise

    # The definition now carries the new name, so a call site left on the old
    # one is a compile error the caller must hear about: a warning plus exit 0
    # reports a rename that broke the tree as a rename that succeeded.
    if stale:
        listed = ", ".join(str(p) for p in stale)
        raise RenameError(
            f"renamed {actual_old_name} to {target_func}, but these files still "
            f"reference the old name: {listed}. Fix them by hand (permissions or "
            f"encoding) and re-run.",
            files=stale,
        )

    record_migrated_markers(metadata_dir, identities, overwrite_name=True)
    return updated_files
