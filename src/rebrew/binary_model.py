"""Format-agnostic data model for a parsed binary.

The types here are the contract every format loader fills in
(``rebrew.binary_loader`` and the per-format loaders it dispatches to) and
every consumer reads.  They sit in their own module so a format loader can
build a :class:`BinaryInfo` without importing the dispatcher that selects it:
keeping them in ``rebrew.binary_loader`` made the loader depend on its own
loaders.

Usage::

    from rebrew.binary_loader import load_binary
    from rebrew.binary_model import BinaryInfo

    info: BinaryInfo = load_binary("path/to/binary")
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from rebrew.utils import BYTES_PER_MIB

if TYPE_CHECKING:
    from rebrew.ne_loader import NeHeader, NeImportModule, NeSegment

#: Cap on any single byte request or lazily-read file image, so a corrupt
#: size field cannot pull a multi-gigabyte file into memory.
MAX_BINARY_SIZE = 512 * BYTES_PER_MIB  # 512 MiB

# Guards the lazy ``BinaryInfo.data`` fill.  One global lock rather than a
# per-instance one: the instance cache holds at most _LOAD_BINARY_CACHE_MAX
# entries and in practice a run touches one target binary, so contention is
# a non-issue.  Make it per-instance if that ever stops being true.
_data_load_lock = threading.Lock()


#: Section names that hold code when a format states no executable flag of its
#: own.  PE and Mach-O name the text section, ELF flags it SHF_EXECINSTR, and a
#: stripped NE image has neither, so every reader of :attr:`SectionInfo.is_code`
#: resolves the unknown case here instead of re-deciding it per call site.
CODE_SECTION_NAMES = frozenset({".text", "text", "__text", "CODE"})


@dataclass
class SectionInfo:
    """Metadata for a single section in a binary."""

    name: str
    va: int  # virtual address (absolute)
    size: int  # virtual size (mapped)
    file_offset: int  # offset in the file on disk
    raw_size: int  # size on disk (may differ from virtual size)
    # SHF_EXECINSTR.  Only the ELF loader states it; PE and Mach-O leave it
    # None, meaning the format carries no such flag rather than that the
    # section is data.  Read it through `is_code_section` unless the
    # distinction is the point.
    is_code: bool | None = None

    @property
    def is_code_section(self) -> bool:
        """True when this section holds code, flag or name.

        The single resolution of the three-state :attr:`is_code`: a stated
        flag wins either way, and an absent one falls back to the name.
        """
        if self.is_code is None:
            return self.name in CODE_SECTION_NAMES
        return self.is_code


@dataclass
class BinaryInfo:
    """Format-agnostic representation of a parsed binary."""

    path: Path
    format: str  # "pe", "elf", "macho"
    arch: str = ""  # "x86_32", "mips32", "ppc32", ... (multi-arch P0)
    endian: str = ""  # "little" / "big" / "" = unknown (multi-arch P0)
    # Bytes per target pointer (4 or 8), 0 when the format's loader did not
    # fill it in.  Only the ELF loader populates this — it reads the ident
    # EI_CLASS byte, the one place a word size is stated outright instead of
    # having to be inferred from the arch name.
    pointer_size: int = 0

    image_base: int = 0

    # .text section shortcuts (most-used for rebrew)
    text_va: int = 0
    text_size: int = 0
    text_raw_offset: int = 0

    sections: dict[str, SectionInfo] = field(default_factory=dict)

    # NE tables, filled by the NE loader; unset for every other format.
    ne_header: NeHeader | None = None
    ne_segments: list[NeSegment] = field(default_factory=list)
    ne_imports: list[NeImportModule] = field(default_factory=list)

    # Lazy-loaded; shared across workers via ``_load_binary_cache``.
    _data: bytes | None = field(default=None, repr=False)

    # Filled by ``load_binary`` for cache invalidation.  Inode is required:
    # a same-size rename-over (``atomic_write_bytes``, ``cp -p`` + ``mv``)
    # in one mtime tick changes the inode and not the size, and mtime+size
    # alone would keep serving the previous image's section map and bytes.
    _cache_mtime_ns: int = field(default=0, repr=False)
    _cache_fsize: int = field(default=0, repr=False)
    _cache_ino: int = field(default=0, repr=False)

    @property
    def data(self) -> bytes:
        """Raw file bytes, loaded lazily.

        Uses a single ``read_bytes()`` call so that the size check is
        performed on the bytes we actually read, not a separate ``stat()``
        that could race with a file replacement between the two syscalls.

        ``BinaryInfo`` instances are shared across worker threads via
        ``_load_binary_cache``, so the lazy fill is guarded: without the
        lock every worker of ``rebrew verify --jobs N`` that touches a cold
        instance reads the whole target binary itself, spiking peak memory
        to N copies of the file for no benefit.
        """
        if self._data is None:
            with _data_load_lock:
                # Re-check: another thread may have filled it while we waited.
                if self._data is None:
                    # Check the size on disk first: read_bytes() would already
                    # have allocated the whole file the cap exists to bound.
                    size = self.path.stat().st_size
                    if size > MAX_BINARY_SIZE:
                        raise ValueError(
                            f"Binary file too large ({size / BYTES_PER_MIB:.0f} MiB): {self.path}"
                        )
                    raw = self.path.read_bytes()
                    if len(raw) > MAX_BINARY_SIZE:
                        raise ValueError(
                            f"Binary file too large "
                            f"({len(raw) / BYTES_PER_MIB:.0f} MiB): {self.path}"
                        )
                    self._data = raw
        return self._data


__all__ = ["MAX_BINARY_SIZE", "CODE_SECTION_NAMES", "BinaryInfo", "SectionInfo"]
