"""pdb_cvdump.py — read MSVC PDBs through the WDK ``cvdump.exe`` tool.

Adapted from reccmp (isledecomp/reccmp, MIT License)
``cvdump/runner.py`` + ``cvdump/parser.py``.

MSVC 6-era PDBs (and older) cannot be read by ``llvm-pdbutil`` — the WDK's
``cvdump.exe`` (run under wine on Linux) still parses them.  This module is
the scoped rebrew port: the runner that locates/involves cvdump, plus a
parser for the sections rebrew consumes today —

- ``LINES``          — per-source-file line→address pairs (function extents)
- ``PUBLICS``        — mangled public symbols (functions, strings, vtables)
- ``SECTION CONTRIBUTIONS`` — per-module symbol sizes (data sizing)
- ``MODULES``        — object/library files linked into the binary

Full type-leaf (``TYPES``/``SYMBOLS``) import is deferred; a module that
needs struct layouts should use the Ghidra/BinSync path instead.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

#: cvdump dump-option flag per section group (same flags as reccmp).
_CVDUMP_FLAGS: dict[str, str] = {
    "lines": "-l",
    "publics": "-p",
    "section_contributions": "-seccontrib",
    "modules": "-m",
}


#: Upper bound for ``winepath``; a first run may initialise a wine prefix.
_WINEPATH_TIMEOUT_S = 120


def cvdump_exe_path() -> str | None:
    """Locate ``cvdump.exe``: ``REBREW_CVDUMP`` env override, then PATH.

    A non-empty override that is not a file raises ``FileNotFoundError``
    instead of silently running whichever ``cvdump.exe`` is on PATH.
    """
    override = os.environ.get("REBREW_CVDUMP", "").strip()
    if override:
        if not Path(override).is_file():
            raise FileNotFoundError(f"REBREW_CVDUMP={override!r} is not a file")
        return override
    return shutil.which("cvdump.exe")


def _cmd_line(pdb: Path, flags: list[str]) -> list[str]:
    exe = cvdump_exe_path()
    assert exe is not None
    # wine needs a Windows-style path.  surrogateescape, not the locale
    # default: a PDB under a non-ASCII directory crashes a strict decode
    # under LANG=C, and the surrogates re-encode to the original bytes when
    # subprocess passes win_path back to wine.
    win_path = subprocess.run(
        ["winepath", "-w", str(pdb)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        check=False,
        timeout=_WINEPATH_TIMEOUT_S,
    ).stdout.strip()
    return ["wine", exe, *flags, win_path or str(pdb)]


def iter_cvdump_sections(stream: Iterable[str]) -> Iterator[tuple[str, str]]:
    """Split cvdump output at its ``*** SECTION NAME`` headers."""
    r_section = re.compile(r"\*{3} ([A-Z]{2,}.+)\n")
    section: str | None = None
    lines: list[str] = []
    for line in stream:
        if line.startswith("*") and (match := r_section.match(line)) is not None:
            if section is not None:
                yield (section, "".join(lines))
            section = match.group(1)
            lines.clear()
        else:
            lines.append(line)
    if section is not None:
        yield (section, "".join(lines))


# ---------------------------------------------------------------------------
# Parsed records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PublicsEntry:
    """One ``S_PUB32`` public symbol (functions, strings, vtables)."""

    type: str
    section: int
    offset: int
    flags: int
    name: str


@dataclass(frozen=True)
class SizeRefEntry:
    """Per-module symbol size estimate from SECTION CONTRIBUTIONS."""

    module: int
    section: int
    offset: int
    size: int


@dataclass(frozen=True)
class ModuleEntry:
    """One object/library file linked into the binary."""

    id: int
    lib: str
    obj: str


@dataclass(frozen=True)
class LineValue:
    """One source line→(section, offset) pair."""

    line_number: int
    section: int
    offset: int


@dataclass
class CvdumpParser:
    """Parser for the cvdump sections rebrew consumes."""

    lines: dict[str, list[LineValue]] = field(default_factory=dict)
    publics: list[PublicsEntry] = field(default_factory=list)
    sizerefs: list[SizeRefEntry] = field(default_factory=list)
    modules: list[ModuleEntry] = field(default_factory=list)

    _lines_section_no: int = 0
    _lines_file: str = ""

    _line_addr_pairs = re.compile(r"\s+(?P<line_no>\d+) (?P<addr>[A-F0-9]{8})")
    _lines_subsection = re.compile(
        r"^\s*(?P<filename>.+?) \((?:None|\w+: [0-9A-F]+?)\), "
        r"(?P<section>[A-F0-9]{4}):(?P<start>[A-F0-9]{8})-"
        r"(?P<end>[A-F0-9]{8}), line/addr pairs = (?P<len>\d+)"
    )
    _publics_line = re.compile(
        r"^(?P<type>\w+): \[(?P<section>[A-F0-9]{4}):(?P<offset>[A-F0-9]{8})], "
        r"Flags: (?P<flags>[A-F0-9]{8}), (?P<name>\S+)"
    )
    _section_contrib = re.compile(
        r"\s*(?P<module>[A-F0-9]{4})  (?P<section>[A-F0-9]{4}):(?P<offset>[A-F0-9]{8})  "
        r"(?P<size>[A-F0-9]{8})  (?P<flags>[A-F0-9]{8})"
    )
    _module_line = re.compile(r"(?P<id>[A-F0-9]{4})(?: \"(?P<lib>.+?)\")?(?: \"(?P<obj>.+?)\")")

    def read_section(self, name: str, section: str) -> None:
        """Route one cvdump section body to its parser."""
        if name == "LINES":
            for line in section.splitlines():
                self._lines_section(line)
        elif name == "PUBLICS":
            for line in section.splitlines():
                self._publics_section(line)
        elif name == "SECTION CONTRIBUTIONS":
            for line in section.splitlines():
                self._section_contributions(line)
        elif name == "MODULES":
            for line in section.splitlines():
                self._modules_section(line)

    def _lines_section(self, line: str) -> None:
        if (m := self._lines_subsection.match(line)) is not None:
            self._lines_file = m.group("filename")
            self._lines_section_no = int(m.group("section"), 16)
            return
        for line_no, offset in self._line_addr_pairs.findall(line):
            self.lines.setdefault(self._lines_file, []).append(
                LineValue(int(line_no), self._lines_section_no, int(offset, 16))
            )

    def _publics_section(self, line: str) -> None:
        if (m := self._publics_line.match(line)) is not None:
            self.publics.append(
                PublicsEntry(
                    type=m.group("type"),
                    section=int(m.group("section"), 16),
                    offset=int(m.group("offset"), 16),
                    flags=int(m.group("flags"), 16),
                    name=m.group("name"),
                )
            )

    def _section_contributions(self, line: str) -> None:
        if (m := self._section_contrib.match(line)) is not None:
            self.sizerefs.append(
                SizeRefEntry(
                    module=int(m.group("module"), 16),
                    section=int(m.group("section"), 16),
                    offset=int(m.group("offset"), 16),
                    size=int(m.group("size"), 16),
                )
            )

    def _modules_section(self, line: str) -> None:
        if (m := self._module_line.match(line)) is not None:
            self.modules.append(
                ModuleEntry(
                    id=int(m.group("id"), 16),
                    lib=m.group("lib") or "",
                    obj=m.group("obj"),
                )
            )


class Cvdump:
    """Builder-style runner: ``Cvdump(pdb).publics().modules().run()``."""

    def __init__(self, pdb: str | Path) -> None:
        self._pdb = Path(pdb)
        self.options: set[str] = set()

    def lines(self) -> Cvdump:
        self.options.add("lines")
        return self

    def publics(self) -> Cvdump:
        self.options.add("publics")
        return self

    def section_contributions(self) -> Cvdump:
        self.options.add("section_contributions")
        return self

    def modules(self) -> Cvdump:
        self.options.add("modules")
        return self

    def cmd_line(self) -> list[str]:
        flags = [_CVDUMP_FLAGS[opt] for opt in sorted(self.options)]
        return _cmd_line(self._pdb, flags)

    def run(self) -> CvdumpParser:
        """Run cvdump (wine on POSIX) and parse the requested sections."""
        parser = CvdumpParser()
        proc = subprocess.Popen(
            self.cmd_line(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        assert proc.stdout is not None
        # cvdump prints PDB names as raw ANSI bytes (cp1252/Shift-JIS paths).
        # surrogateescape keeps each byte, so two paths differing only in
        # non-ASCII stay distinct ``lines`` keys; "ignore" merged them.
        wrap = io.TextIOWrapper(proc.stdout, encoding="utf-8", errors="surrogateescape")
        try:
            for name, section in iter_cvdump_sections(wrap):
                parser.read_section(name, section)
            returncode = proc.wait()
        finally:
            # An abort mid-parse must not leave the cvdump/wine child running
            # or hold the stdout pipe: kill and reap it, then drop the wrap.
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            wrap.close()
        # A failed dump (missing wine, unreadable PDB) yields no sections;
        # returning that empty parse would read as "PDB has no symbols".
        if returncode != 0:
            raise RuntimeError(f"cvdump exited with status {returncode} reading {self._pdb}")
        return parser
