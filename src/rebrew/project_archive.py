"""project_archive.py – Unpack an untrusted rebrew project archive into an empty directory.

A tar (plain or compressed) or zip archive is read member by member and written
by this module only: regular files and directories, under portable relative
names, within entry and byte bounds.  Links, devices, FIFOs, absolute or
``..`` names, duplicate or case-colliding names and anything past a bound
refuse the whole archive with :class:`ProjectArchiveError` before the member is
written.  Nothing from the archive keeps a mode bit or runs.
"""

from __future__ import annotations

from typing import IO, TYPE_CHECKING
lazy import io
lazy import tarfile
lazy import unicodedata
lazy import zipfile
lazy import zlib

from rebrew.errors import RebrewError  # base class: definition-time use
lazy from rebrew.utils import portable_path_parts

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

#: Most members (files and directories) one archive may hold.
ARCHIVE_MAX_ENTRIES = 32768

#: Most bytes the archive's files may hold once unpacked.
ARCHIVE_MAX_BYTES = 256 << 20

#: The project configuration that marks the project root inside the archive.
PROJECT_CONFIG = "rebrew-project.toml"

_CHUNK = 1 << 20

_NOT_REGULAR = "is not a regular file or directory"


class ProjectArchiveError(RebrewError):
    """The archive is not one this module unpacks; the message names the member and is safe to show."""


def _members(archive: Path) -> Iterator[tuple[str, bool, int, IO[bytes] | None, str]]:
    """Yield ``(name, is_dir, declared size, reader, refusal)`` per member; refusal is "" for an allowed type."""
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as zipped:
            for info in zipped.infolist():
                mode = (info.external_attr >> 16) & 0o170000 if info.create_system == 3 else 0
                is_dir = info.is_dir()
                refusal = "" if mode in (0, 0o100000, 0o040000) else _NOT_REGULAR
                if refusal or is_dir:
                    yield info.filename, is_dir, 0, None, refusal
                    continue
                with zipped.open(info) as reader:
                    yield info.filename, False, info.file_size, reader, ""
        return
    if not tarfile.is_tarfile(archive):
        raise ProjectArchiveError("the archive is neither a tar nor a zip file")
    with tarfile.open(archive, mode="r:*") as tarred:
        while (member := tarred.next()) is not None:
            if member.isdir():
                yield member.name, True, 0, None, ""
            elif member.isreg():
                yield member.name, False, member.size, tarred.extractfile(member), ""
            else:
                yield member.name, False, 0, None, _NOT_REGULAR


def _unpack(archive: Path, into: Path) -> None:
    """Write every allowed member of *archive* under *into*, refusing the archive at the first bad one."""
    seen: set[str] = set()
    files: set[str] = set()
    entries = 0
    total = 0
    for raw, is_dir, declared, reader, refusal in _members(archive):
        name = raw.removeprefix("./").rstrip("/") if is_dir else raw.removeprefix("./")
        shown = raw[:200]
        entries += 1
        if entries > ARCHIVE_MAX_ENTRIES:
            raise ProjectArchiveError(f"the archive has more than {ARCHIVE_MAX_ENTRIES} entries")
        if refusal:
            raise ProjectArchiveError(f"archive member {shown!r} {refusal}")
        parts = portable_path_parts(unicodedata.normalize("NFC", name))
        if not parts or raw.startswith("/"):
            raise ProjectArchiveError(
                f"archive member {shown!r} is not a relative path inside the project"
            )
        folded = "/".join(parts).casefold()
        if folded in seen:
            raise ProjectArchiveError(f"archive member {shown!r} repeats an earlier name")
        if any("/".join(parts[:depth]).casefold() in files for depth in range(1, len(parts))):
            raise ProjectArchiveError(f"archive member {shown!r} lies under a file")
        seen.add(folded)
        target = into.joinpath(*parts)
        if is_dir:
            target.mkdir(parents=True, exist_ok=True)
            continue
        if declared > ARCHIVE_MAX_BYTES - total:
            raise ProjectArchiveError(f"the archive unpacks to more than {ARCHIVE_MAX_BYTES} bytes")
        files.add(folded)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as out:
            source = reader if reader is not None else io.BytesIO()
            while chunk := source.read(_CHUNK):
                total += len(chunk)
                if total > ARCHIVE_MAX_BYTES:
                    raise ProjectArchiveError(
                        f"the archive unpacks to more than {ARCHIVE_MAX_BYTES} bytes"
                    )
                out.write(chunk)
        target.chmod(0o644)


def unpack_project_archive(archive: Path, into: Path) -> Path:
    """Unpack *archive* into the empty directory *into* and return the project root.

    The root is *into* when the archive holds ``rebrew-project.toml`` at its
    top, or its one top-level directory when that directory holds it (an
    archive made with a path prefix).
    """
    if any(into.iterdir()):
        raise ValueError(f"{into} is not empty")
    try:
        _unpack(archive, into)
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, zlib.error) as exc:
        raise ProjectArchiveError(f"the archive is damaged ({type(exc).__name__})") from None
    if (into / PROJECT_CONFIG).is_file():
        return into
    tops = list(into.iterdir())
    if len(tops) == 1 and tops[0].is_dir() and (tops[0] / PROJECT_CONFIG).is_file():
        return tops[0]
    raise ProjectArchiveError(
        f"the archive has no {PROJECT_CONFIG} at its top level or in its one top-level directory"
    )
