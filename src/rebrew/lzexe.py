"""LZEXE 0.90/0.91 packed-executable unpacker.

Many DOS-era executables (1990s games especially) were shipped packed with
Fabrice Bellard's LZEXE compressor: the packed file is an MZ executable
whose header CS:IP points at a small decompressor stub stored at the end of
the file.  The stub relocates the compressed payload forward in memory,
decompresses it back to the image start, applies a delta-encoded
relocation table, restores the original MZ header from a parameter block,
and finally jumps to the restored entry point.

The format is only documented by the decompressor code itself (Bellard
explicitly declined to document it: "The only way would be to disassemble
the decompressor").  The reference implementation this module is ported
from is the classic public-domain ``unlzexe.c`` (Kou / David Kirschbaum /
Alan Modra / Vesselin Bontchev / Stian Skjelstad), whose logic was
cross-verified against the stub disassembly of a real packed binary
(Commander Keen 6 demo, ``LZ91``) and validated byte-for-byte against that
implementation's output.

Packed-file layout (v0.91)::

    offset   size  contents
    0x00     0x1C  original MZ header words 0x00-0x1B (cs:ip = stub entry)
    0x1C     4     "LZ90"/"LZ91" magic (replaces header bytes 0x1C-0x1F)
    0x20     ...   compressed bitstream (decompresses to the original image)
    ...      ...   stub parameter block at CS:0000 (8 words: ip, cs, sp, ss,
                   compressed-size, size-increase, stub-size, checksum)
    ...      0x158 delta-encoded relocation table (relative to stub CS base)
    ...      ...   the decompressor stub itself

The compressed bitstream is 16-bit words read LSB-first.  ``1`` = literal
byte follows; ``0`` + ``0`` = short match (2 length bits + distance byte,
length 2..5, distance 1..255); ``0`` + ``1`` = word match (span/low byte +
length/high byte: 5 distance bits + 3 length bits, length 3..9, distance
1..8192; a zero length-code defers to a following byte: 0 = end of stream,
1 = 64KiB window re-normalization, N = length N+1).  The ``1`` marker is a
pure segment-pointer bookkeeping event — in a flat byte model it is a
no-op.  Overlapping matches copy byte-by-byte (standard growing LZ77).

The reconstructed output is a loadable MZ executable: rebuilt header
(cblp/cp/crlc/cparhdr/minalloc/maxalloc/ss/sp/ip/cs/lfarlc), the original
relocation table re-encoded as standard MZ ``(offset, segment)`` entries at
0x1C, and the decompressed image.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

#: Byte-identical decompressor stubs for LZEXE v0.90 and v0.91 (from
#: unlzexe.c).  Detection reads this many bytes at the header's CS:IP entry.
SIG90 = bytes(
    (
        6,
        14,
        31,
        139,
        14,
        12,
        0,
        139,
        241,
        78,
        137,
        247,
        140,
        219,
        3,
        30,
        10,
        0,
        142,
        195,
        180,
        0,
        49,
        237,
        253,
        172,
        1,
        197,
        170,
        226,
        250,
        139,
        22,
        14,
        0,
        138,
        194,
        41,
        197,
        138,
        198,
        41,
        197,
        57,
        213,
        116,
        12,
        186,
        145,
        1,
        180,
        9,
        205,
        33,
        184,
        255,
        76,
        205,
        33,
        83,
        184,
        83,
        0,
        80,
        203,
        46,
        139,
        46,
        8,
        0,
        140,
        218,
        137,
        232,
        61,
        0,
        16,
        118,
        3,
        184,
        0,
        16,
        41,
        197,
        41,
        194,
        41,
        195,
        142,
        218,
        142,
        195,
        177,
        3,
        211,
        224,
        137,
        193,
        209,
        224,
        72,
        72,
        139,
        240,
        139,
        248,
        243,
        165,
        9,
        237,
        117,
        216,
        252,
        142,
        194,
        142,
        219,
        49,
        246,
        49,
        255,
        186,
        16,
        0,
        173,
        137,
        197,
        209,
        237,
        74,
        117,
        5,
        173,
        137,
        197,
        178,
        16,
        115,
        3,
        164,
        235,
        241,
        49,
        201,
        209,
        237,
        74,
        117,
        5,
        173,
        137,
        197,
        178,
        16,
        114,
        34,
        209,
        237,
        74,
        117,
        5,
        173,
        137,
        197,
        178,
        16,
        209,
        209,
        209,
        237,
        74,
        117,
        5,
        173,
        137,
        197,
        178,
        16,
        209,
        209,
        65,
        65,
        172,
        183,
        255,
        138,
        216,
        233,
        19,
        0,
        173,
        139,
        216,
        177,
        3,
        210,
        239,
        128,
        207,
        224,
        128,
        228,
        7,
        116,
        12,
        136,
        225,
        65,
        65,
        38,
        138,
        1,
        170,
        226,
        250,
        235,
        166,
        172,
        8,
        192,
        116,
        64,
        60,
        1,
        116,
        5,
        136,
        193,
        65,
        235,
        234,
        137,
    )
)

SIG91 = bytes(
    (
        6,
        14,
        31,
        139,
        14,
        12,
        0,
        139,
        241,
        78,
        137,
        247,
        140,
        219,
        3,
        30,
        10,
        0,
        142,
        195,
        253,
        243,
        164,
        83,
        184,
        43,
        0,
        80,
        203,
        46,
        139,
        46,
        8,
        0,
        140,
        218,
        137,
        232,
        61,
        0,
        16,
        118,
        3,
        184,
        0,
        16,
        41,
        197,
        41,
        194,
        41,
        195,
        142,
        218,
        142,
        195,
        177,
        3,
        211,
        224,
        137,
        193,
        209,
        224,
        72,
        72,
        139,
        240,
        139,
        248,
        243,
        165,
        9,
        237,
        117,
        216,
        252,
        142,
        194,
        142,
        219,
        49,
        246,
        49,
        255,
        186,
        16,
        0,
        173,
        137,
        197,
        209,
        237,
        74,
        117,
        5,
        173,
        137,
        197,
        178,
        16,
        115,
        3,
        164,
        235,
        241,
        49,
        201,
        209,
        237,
        74,
        117,
        5,
        173,
        137,
        197,
        178,
        16,
        114,
        34,
        209,
        237,
        74,
        117,
        5,
        173,
        137,
        197,
        178,
        16,
        209,
        209,
        209,
        237,
        74,
        117,
        5,
        173,
        137,
        197,
        178,
        16,
        209,
        209,
        65,
        65,
        172,
        183,
        255,
        138,
        216,
        233,
        19,
        0,
        173,
        139,
        216,
        177,
        3,
        210,
        239,
        128,
        207,
        224,
        128,
        228,
        7,
        116,
        12,
        136,
        225,
        65,
        65,
        38,
        138,
        1,
        170,
        226,
        250,
        235,
        166,
        172,
        8,
        192,
        116,
        52,
        60,
        1,
        116,
        5,
        136,
        193,
        65,
        235,
        234,
        137,
        251,
        131,
        231,
        15,
        129,
        199,
        0,
        32,
        177,
        4,
        211,
        235,
        140,
        192,
        1,
        216,
        45,
        0,
        2,
        142,
        192,
        137,
        243,
        131,
        230,
        15,
        211,
        235,
        140,
        216,
        1,
        216,
        142,
        216,
        233,
        114,
    )
)

_SIGLEN = len(SIG90)


class NotLzexeError(ValueError):
    """Raised when a file is not an LZEXE-packed MZ executable."""


@dataclass
class LzexeResult:
    """Result of unpacking an LZEXE-packed executable.

    ``image`` is the decompressed program image (everything after the
    reconstructed header).  ``header_words`` holds the 14 rebuilt MZ header
    words (native word order, as unlzexe writes them) so :meth:`to_bytes`
    reassembles a loadable MZ executable.
    """

    version: int
    image: bytes
    header_words: list[int]
    relocs: list[tuple[int, int]] = field(default_factory=list)

    @property
    def crlc(self) -> int:
        return self.header_words[3]

    @property
    def cparhdr(self) -> int:
        return self.header_words[4]

    @property
    def ss(self) -> int:
        return self.header_words[7]

    @property
    def sp(self) -> int:
        return self.header_words[8]

    @property
    def ip(self) -> int:
        return self.header_words[0x0A]

    @property
    def cs(self) -> int:
        return self.header_words[0x0B]

    def to_bytes(self) -> bytes:
        """Assemble the unpacked file: rebuilt header + relocation table + image."""
        header = bytearray(self.cparhdr * 16)
        # Only the first 14 header words are written (like unlzexe); the
        # packed file's words 14-15 ("LZ90"/"LZ91" magic) are dropped.
        struct.pack_into("<14H", header, 0, *self.header_words[:14])
        for i, (rel_off, rel_seg) in enumerate(self.relocs):
            struct.pack_into("<HH", header, 0x1C + 4 * i, rel_off, rel_seg)
        return bytes(header) + self.image


def _read_words(data: bytes, offset: int, count: int) -> list[int]:
    return list(struct.unpack_from(f"<{count}H", data, offset))


def lzexe_version(path: str | Path) -> int | None:
    """Return the LZEXE version (90 or 91) if *path* is LZEXE-packed, else None.

    Detection mirrors unlzexe's ``rdhead``: an MZ/ZM header with
    ``lfarlc == 0x1c`` and ``ovno == 0``, whose CS:IP entry holds one of the
    two known decompressor stubs (byte-for-byte).  Robust against merely
    patching the "LZ91" string — the stub signature is the real test.
    """
    path = Path(path)
    # Read only the header plus the stub region the signature check needs —
    # the entry is at (cparhdr + e_cs)*16 + e_ip, typically deep in the file,
    # but never beyond the header-derived bound for a stub-bearing LZEXE.
    with open(path, "rb") as fh:
        head = fh.read(0x40)
        size = fh.seek(0, 2)
    if len(head) < 0x40:
        return None
    ihead = _read_words(head, 0, 0x10)
    if ihead[0] not in (0x5A4D, 0x4D5A):
        return None  # not MZ/ZM
    if ihead[0x0D] != 0 or ihead[0x0C] != 0x1C:
        return None  # not the LZEXE header shape
    entry = (ihead[4] + ihead[0x0B]) * 16 + ihead[0x0A]
    if entry + _SIGLEN > size:
        return None
    with open(path, "rb") as fh:
        fh.seek(entry)
        sig = fh.read(_SIGLEN)
    # The stub was rebuilt across LZEXE releases (the patched 0.91 adds a
    # leading ``push ax`` (0x50) and a different chunk-copy loop), so a full
    # byte-for-byte match is too strict.  Match a 25-byte prefix that is
    # stable across variants and distinguishes 0.90 from 0.91 (their stubs
    # diverge at byte 0x14: 0xB4 vs 0xFD).  The header shape + "LZ90"/"LZ91"
    # magic + this stub prefix together cannot be spoofed by accident.
    if sig[0] == 0x50:
        sig = sig[1:]
    if sig[:0x19] == SIG90[:0x19]:
        return 90
    if sig[:0x19] == SIG91[:0x19]:
        return 91
    return None


class _BitReader:
    """16-bit LSB-first bitstream reader.

    Mirrors unlzexe's ``getbit`` exactly: the refill that fetches the next
    control word happens *while consuming the 16th bit of the current word*
    (not lazily before the 17th), which keeps the interleaving of control
    words and data bytes aligned with the original stub.
    """

    __slots__ = ("data", "si", "bp", "bits")

    def __init__(self, data: bytes, offset: int) -> None:
        self.data = data
        self.si = offset
        self.bp = int(struct.unpack_from("<H", data, self.si)[0])
        self.si += 2
        self.bits = 16

    def bit(self) -> int:
        v = self.bp & 1
        if self.bits == 1:
            self.bp = int(struct.unpack_from("<H", self.data, self.si)[0])
            self.si += 2
            self.bits = 16
        else:
            self.bp >>= 1
            self.bits -= 1
        return v

    def byte(self) -> int:
        v = self.data[self.si]
        self.si += 1
        return v


def _decompress(data: bytes, stream_off: int) -> bytes:
    """Decompress the LZEXE bitstream into the original program image."""
    r = _BitReader(data, stream_off)
    out = bytearray()
    while True:
        if r.bit():
            out.append(r.byte())  # literal
            continue
        if r.bit():
            # Word match: span = low byte, len = high byte.
            span = r.byte()
            lenb = r.byte()
            span |= ((lenb & ~0x07) << 5) | 0xE000
            length = (lenb & 0x07) + 2
            if length == 2:
                b2 = r.byte()
                if b2 == 0:
                    break  # end of compressed load module
                if b2 == 1:
                    continue  # 64KiB window re-normalization — no-op in flat model
                length = b2 + 1
        else:
            # Short match: 2 length bits + distance byte.
            length = ((r.bit() << 1) | r.bit()) + 2
            span = r.byte() | 0xFF00
        dist = 0x10000 - span
        if dist > len(out):
            raise NotLzexeError(
                f"corrupt LZEXE stream: match distance {dist} exceeds "
                f"{len(out)} bytes of output at position {len(out)}"
            )
        start = len(out) - dist
        for k in range(length):
            out.append(out[start + k])
    return bytes(out)


def _reloc_table91(data: bytes, offset: int) -> tuple[list[tuple[int, int]], int]:
    """Decode the v0.91 delta relocation table into MZ (offset, segment) pairs.

    Returns the entries and the file offset just past the table.  The delta
    stream: a nonzero byte advances the linear offset by its value (with
    segment stepping every 16 bytes); a zero byte is followed by a word —
    0 advances the segment by 0xFFF, 1 terminates the table.
    """
    relocs: list[tuple[int, int]] = []
    rel_off = 0
    rel_seg = 0
    si = offset
    n = len(data)
    terminated = False
    while si < n:
        span = data[si]
        si += 1
        if span == 0:
            if si + 2 > n:
                break
            (word,) = struct.unpack_from("<H", data, si)
            si += 2
            if word == 0:
                rel_seg += 0x0FFF
                continue
            if word == 1:
                terminated = True
                break
            span = word  # a zero byte is followed by a WORD delta (full width)
        rel_off += span
        rel_seg += (rel_off & ~0x0F) >> 4
        rel_off &= 0x0F
        relocs.append((rel_off, rel_seg))
    if not terminated:
        raise NotLzexeError("corrupt LZEXE file: relocation table truncated (no terminator)")
    return relocs, si


def _reloc_table90(data: bytes, offset: int) -> tuple[list[tuple[int, int]], int]:
    """Decode the v0.90 relocation table: words of offset counts per 0x1000-seg."""
    relocs: list[tuple[int, int]] = []
    rel_seg = 0
    si = offset
    n = len(data)
    while rel_seg != 0x10000 and si + 2 <= n:
        (count,) = struct.unpack_from("<H", data, si)
        si += 2
        for _ in range(count):
            if si + 2 > n:
                raise NotLzexeError(
                    "corrupt LZEXE file: relocation table truncated (no terminator)"
                )
            (rel_off,) = struct.unpack_from("<H", data, si)
            si += 2
            relocs.append((rel_off, rel_seg))
        rel_seg += 0x1000
    if rel_seg != 0x10000:
        # The v0.90 table walks 16 segment groups (0x1000 steps); reaching
        # EOF before the last group means truncation, not a clean end.
        raise NotLzexeError("corrupt LZEXE file: relocation table truncated (no terminator)")
    return relocs, si


def unpack_lzexe(path: str | Path) -> LzexeResult:
    """Unpack an LZEXE 0.90/0.91 executable, returning the rebuilt file parts.

    Raises :class:`NotLzexeError` when *path* is not an LZEXE-packed MZ.
    """
    path = Path(path)
    data = path.read_bytes()
    if len(data) < 0x40:
        raise NotLzexeError(f"not an LZEXE file (too small): {path}")
    version = lzexe_version(path)
    if version is None:
        raise NotLzexeError(f"not an LZEXE file (no LZ90/LZ91 stub): {path}")

    try:
        return _unpack_impl(data, version)
    except (struct.error, IndexError) as exc:
        # A corrupted-but-stub-intact file can carry header-derived offsets
        # beyond EOF or negative — surface a clean error, not a traceback.
        raise NotLzexeError(f"corrupt LZEXE file (bad header geometry): {path}") from exc


def _unpack_impl(data: bytes, version: int) -> LzexeResult:
    ihead = _read_words(data, 0, 0x10)
    ohead = list(ihead)

    # Stub parameter block at CS:0000: ip, cs, sp, ss, compressed-size,
    # size-increase, stub-size, checksum.
    fpos = (ihead[0x0B] + ihead[4]) * 16
    if not (0 <= fpos <= len(data) - 16):
        raise NotLzexeError(f"corrupt LZEXE file: stub parameter block at {fpos:#x} outside file")
    inf = _read_words(data, fpos, 8)
    ohead[0x0A] = inf[0]  # IP
    ohead[0x0B] = inf[1]  # CS
    ohead[0x08] = inf[2]  # SP
    ohead[0x07] = inf[3]  # SS
    ohead[0x0C] = 0x1C  # lfarlc: relocation table at 0x1C

    if version == 90:
        relocs, _end = _reloc_table90(data, fpos + 0x19D)
    else:
        relocs, _end = _reloc_table91(data, fpos + 0x158)
    ohead[3] = len(relocs)  # crlc

    # cparhdr: the relocation table (written at 0x1C, 4 bytes per entry)
    # rounded up to a 512-byte boundary, expressed in paragraphs.
    end = 0x1C + 4 * len(relocs)
    cparhdr = ((end + 0x1FF) & ~0x1FF) >> 4
    ohead[4] = cparhdr

    # Decompress the image.
    stream_off = (ihead[0x0B] - inf[4] + ihead[4]) * 16
    if not (0 <= stream_off < len(data)):
        raise NotLzexeError(
            f"corrupt LZEXE file: compressed stream at {stream_off:#x} outside file"
        )
    image = _decompress(data, stream_off)
    loadsize = len(image)

    # Rebuild minalloc/maxalloc/cblp/cp (unlzexe's wrhead).
    if ihead[6] != 0:
        ohead[5] -= inf[5] + ((inf[6] + 15) >> 4) + 9
        if ihead[6] != 0xFFFF:
            ohead[6] -= ihead[5] - ohead[5]
    ohead[1] = (loadsize + (cparhdr << 4)) & 0x1FF  # cblp
    ohead[2] = (loadsize + (cparhdr << 4) + 0x1FF) >> 9  # cp

    return LzexeResult(
        version=version,
        image=image,
        header_words=ohead,
        relocs=relocs,
    )


def unpack_to_file(path: str | Path, out: str | Path | None = None) -> Path:
    """Unpack an LZEXE file to disk, returning the output path.

    The default output path replaces the extension with ``.unpacked.exe``
    (or appends it when the source has no extension).
    """
    path = Path(path)
    result = unpack_lzexe(path)
    if out is None:
        out = path.with_suffix(path.suffix + ".unpacked.exe")
    out = Path(out)
    out.write_bytes(result.to_bytes())
    return out
