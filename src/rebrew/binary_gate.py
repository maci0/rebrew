"""binary_gate.py - Whole-binary parity primitives for the CI gate.

Track 2 of the gap-analysis goal: a project can be 100% EXACT on functions
and still ship a non-identical PE.  Pure comparison logic (dicts/bytes in,
report out) plus a thin binary-reading layer that snapshots one binary's
gate-relevant facts.  The ``verify --whole-binary`` wiring lives in
``verify.py``.
"""

from pathlib import Path
from typing import Any


def pe_relocation_snapshot(data: bytes) -> tuple[list[str], dict[str, int]]:
    """Read PE fixups and separate their block bytes from reserved section space."""
    import lief

    pe = lief.PE.parse(data)
    if pe is None:
        raise ValueError("cannot parse PE base relocations")
    entries = sorted(
        f"0x{block.virtual_address + entry.position:08x}:{int(entry.type)}"
        for block in pe.relocations
        for entry in block.entries
        if int(entry.type) != 0
    )
    directory = pe.data_directory(lief.PE.DataDirectory.TYPES.BASE_RELOCATION_TABLE)
    block_bytes = sum(block.block_size for block in pe.relocations)
    # A PE without a base relocation directory yields no DataDirectory at all.
    section = directory.section if directory is not None and directory.has_section else None
    section_bytes = section.virtual_size if section is not None else 0
    return entries, {
        "block_bytes": block_bytes,
        "directory_bytes": directory.size if directory is not None else 0,
        "section_bytes": section_bytes,
        "reserved_bytes": max(0, section_bytes - block_bytes),
    }


def compare_sections(expected: dict[str, int], actual: dict[str, int]) -> dict[str, Any]:
    """Compare ``{section: size}`` maps; report per-section drifts."""
    diffs: list[dict[str, Any]] = []
    for name in sorted(set(expected) | set(actual)):
        exp = expected.get(name)
        got = actual.get(name)
        if exp != got:
            diffs.append({"section": name, "expected": exp, "actual": got})
    return {"match": not diffs, "diffs": diffs}


def compare_name_sets(expected: list[str], actual: list[str]) -> dict[str, Any]:
    """Compare export/import name lists (order-insensitive)."""
    exp_set, got_set = set(expected), set(actual)
    missing = sorted(exp_set - got_set)
    added = sorted(got_set - exp_set)
    return {"match": not missing and not added, "missing": missing, "added": added}


def compare_bytes(expected: bytes, actual: bytes) -> dict[str, Any]:
    """Compare raw bytes; report the first differing offset (or length drift)."""
    if expected == actual:
        return {"match": True, "first_diff": None}
    first_diff = next(
        (i for i, (a, b) in enumerate(zip(expected, actual, strict=False)) if a != b),
        min(len(expected), len(actual)),
    )
    return {"match": False, "first_diff": first_diff}


def snapshot_binary(binary_path: Path) -> dict[str, Any]:
    """Snapshot gate-relevant facts of one binary: sections, exports, imports, resources.

    Returns ``sections`` (``{name: virtual size}``), ``exports`` (sorted
    names), ``imports`` (sorted ``dll!name``), ``file`` (all raw bytes), ``rsrc`` (raw ``.rsrc`` bytes
    or None), ``relocations`` (PE RVA/type keys excluding ABSOLUTE padding),
    and ``headers`` (image base).
    Never raises: an unreadable binary or a failed import/export parse sets
    ``error`` (None on success), which :func:`compare_snapshots` reports as
    drift so two unparseable binaries cannot pass the gate.
    """
    from rebrew.binary_loader import load_binary

    empty: dict[str, Any] = {
        "sections": {},
        "exports": [],
        "imports": [],
        "rsrc": None,
        "headers": {},
        "error": None,
        "file": b"",
        "relocations": [],
        "relocation_layout": {},
    }
    try:
        info = load_binary(binary_path)
    except (OSError, ValueError) as exc:
        return {**empty, "error": f"cannot load {binary_path}: {exc}"}
    error: str | None = None
    sections = {name: sec.size for name, sec in info.sections.items()}
    rsrc: bytes | None = None
    sec = info.sections.get(".rsrc")
    if sec is not None:
        # A section claiming more bytes than the file holds is a corrupt header;
        # slicing would silently yield a short resource rather than fail.
        end = sec.file_offset + sec.raw_size
        if sec.file_offset >= 0 and end <= len(info.data):
            rsrc = bytes(info.data[sec.file_offset : end])
        else:
            rsrc = None
    try:
        from rebrew.binary_loader import parse_exports
        from rebrew.import_table import parse_imports

        exports = parse_exports(binary_path)
        imports = sorted(
            {f"{r.get('dll', '')}!{r.get('name', '')}" for r in parse_imports(binary_path)}
        )
        relocations, relocation_layout = (
            pe_relocation_snapshot(bytes(info.data)) if info.format == "pe" else ([], {})
        )
    except Exception as exc:
        exports, imports = [], []
        relocations = []
        relocation_layout = {}
        error = f"import/export/relocation parse failed for {binary_path}: {exc}"
    return {
        "sections": sections,
        "exports": exports,
        "imports": imports,
        "rsrc": rsrc,
        "headers": {"image_base": info.image_base},
        "error": error,
        "file": bytes(info.data),
        "relocations": relocations,
        "relocation_layout": relocation_layout,
    }


def compare_snapshots(expected: dict[str, Any], actual: dict[str, Any]) -> dict[str, Any]:
    """Compare two :func:`snapshot_binary` results; report per-area verdicts."""
    sections = compare_sections(expected["sections"], actual["sections"])
    exports = compare_name_sets(expected["exports"], actual["exports"])
    imports = compare_name_sets(expected["imports"], actual["imports"])
    relocations = compare_name_sets(expected["relocations"], actual["relocations"])
    relocations["expected_layout"] = expected["relocation_layout"]
    relocations["actual_layout"] = actual["relocation_layout"]
    if expected["rsrc"] is None and actual["rsrc"] is None:
        rsrc: dict[str, Any] = {"match": True, "first_diff": None}
    elif expected["rsrc"] is None or actual["rsrc"] is None:
        rsrc = {"match": False, "first_diff": None}
    else:
        rsrc = compare_bytes(expected["rsrc"], actual["rsrc"])
    headers_match = expected["headers"] == actual["headers"]
    file = compare_bytes(expected["file"], actual["file"])
    match = sections["match"] and exports["match"] and imports["match"] and rsrc["match"]
    errors = [e for e in (expected.get("error"), actual.get("error")) if e]
    match = bool(match and headers_match and file["match"] and relocations["match"] and not errors)
    return {
        "match": match,
        "errors": errors,
        "file": file,
        "sections": sections,
        "exports": exports,
        "imports": imports,
        "relocations": relocations,
        "rsrc": rsrc,
        "headers": {
            "match": headers_match,
            "expected": expected["headers"],
            "actual": actual["headers"],
        },
    }


def layout_fingerprint(binary_path: Path) -> str:
    """Hash the layout-relevant bytes of *binary_path* (headers + section table).

    Covers the PE headers through the section table plus each section's
    VA/size/raw-size triple — the facts the committed ``layout/<target>/``
    scaffolding must match.  Section *contents* are excluded (content drift
    is the function/data verifiers' job).  Returns "" when unreadable.
    """
    import hashlib

    try:
        from rebrew.binary_loader import load_binary

        info = load_binary(binary_path)
    except (OSError, ValueError):
        return ""
    h = hashlib.sha256()
    if info.format == "pe":
        from rebrew.pe_headers import SECTION_ENTRY_SIZE, pe_layout

        layout = pe_layout(info.data)
        if layout is None or len(layout.sections) != layout.number_of_sections:
            return ""
        header_end = layout.section_table_offset + layout.number_of_sections * SECTION_ENTRY_SIZE
        h.update(info.data[:header_end])
    for name in sorted(info.sections):
        sec = info.sections[name]
        h.update(name.encode("utf-8", "replace"))
        h.update(sec.va.to_bytes(8, "little"))
        h.update(sec.size.to_bytes(8, "little"))
        h.update(sec.raw_size.to_bytes(8, "little"))
    h.update(info.image_base.to_bytes(8, "little"))
    return h.hexdigest()


def check_layout_freshness(pkg_dir: Path, binary_path: Path) -> dict[str, Any]:
    """Compare the stored layout fingerprint against the reference binary.

    The fingerprint lives in ``<pkg_dir>/layout.fingerprint`` (written by
    ``rebrew gen-layout``); absence means the package predates fingerprints
    and freshness is unknown (not a failure).  A mismatch means the reference
    binary changed since the scaffolding was generated — the layout package
    must be regenerated.  A fingerprint that exists but cannot be read is a
    failure: it would otherwise pass a package built against another binary.
    """
    fingerprint_file = pkg_dir / "layout.fingerprint"
    if not fingerprint_file.exists():
        return {"match": True, "status": "unknown", "expected": None, "actual": None}
    try:
        recorded = fingerprint_file.read_text(encoding="utf-8").strip().split()
    except OSError as exc:
        # Present but unreadable is not the same as absent: reporting it as
        # "unknown" would pass the freshness gate for a package scaffolded
        # against a different reference binary.
        return {
            "match": False,
            "status": "unreadable",
            "expected": None,
            "actual": None,
            "error": f"cannot read {fingerprint_file}: {exc}",
        }
    if not recorded:
        return {"match": True, "status": "unknown", "expected": None, "actual": None}
    expected = recorded[0]
    actual = layout_fingerprint(binary_path)
    if not actual:
        return {"match": True, "status": "unknown", "expected": expected, "actual": None}
    match = expected == actual
    return {
        "match": match,
        "status": "fresh" if match else "stale",
        "expected": expected,
        "actual": actual,
    }
