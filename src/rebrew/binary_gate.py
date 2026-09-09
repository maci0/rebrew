"""binary_gate.py - Whole-binary parity primitives for the CI gate.

Track 2 of the gap-analysis goal: a project can be 100% EXACT on functions
and still ship a non-identical PE.  Pure comparison logic (dicts/bytes in,
report out) plus a thin binary-reading layer that snapshots one binary's
gate-relevant facts.  The ``verify --whole-binary`` wiring lives in
``verify.py``.
"""

from pathlib import Path
from typing import Any


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
    names), ``imports`` (sorted ``dll!name``), ``rsrc`` (raw ``.rsrc`` bytes
    or None), and ``headers`` (image base, entry point, section count).
    Best-effort: unparseable inputs snapshot as empty facts, never raise.
    """
    from rebrew.binary_loader import load_binary

    empty: dict[str, Any] = {
        "sections": {},
        "exports": [],
        "imports": [],
        "rsrc": None,
        "headers": {},
    }
    try:
        info = load_binary(binary_path)
    except (OSError, ValueError):
        return empty
    sections = {name: sec.size for name, sec in info.sections.items()}
    rsrc: bytes | None = None
    sec = info.sections.get(".rsrc")
    if sec is not None:
        try:
            rsrc = bytes(info.data[sec.file_offset : sec.file_offset + sec.raw_size])
        except (IndexError, TypeError):
            rsrc = None
    try:
        from rebrew.exports import parse_exports
        from rebrew.imports import parse_imports

        exports = parse_exports(binary_path)
        imports = sorted(
            {f"{r.get('dll', '')}!{r.get('name', '')}" for r in parse_imports(binary_path)}
        )
    except Exception:
        exports, imports = [], []
    return {
        "sections": sections,
        "exports": exports,
        "imports": imports,
        "rsrc": rsrc,
        "headers": {"image_base": info.image_base},
    }


def compare_snapshots(expected: dict[str, Any], actual: dict[str, Any]) -> dict[str, Any]:
    """Compare two :func:`snapshot_binary` results; report per-area verdicts."""
    sections = compare_sections(expected["sections"], actual["sections"])
    exports = compare_name_sets(expected["exports"], actual["exports"])
    imports = compare_name_sets(expected["imports"], actual["imports"])
    if expected["rsrc"] is None and actual["rsrc"] is None:
        rsrc: dict[str, Any] = {"match": True, "first_diff": None}
    elif expected["rsrc"] is None or actual["rsrc"] is None:
        rsrc = {"match": False, "first_diff": None}
    else:
        rsrc = compare_bytes(expected["rsrc"], actual["rsrc"])
    headers_match = expected["headers"] == actual["headers"]
    match = sections["match"] and exports["match"] and imports["match"] and rsrc["match"]
    match = bool(match and headers_match)
    return {
        "match": match,
        "sections": sections,
        "exports": exports,
        "imports": imports,
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
    must be regenerated.
    """
    fingerprint_file = pkg_dir / "layout.fingerprint"
    if not fingerprint_file.exists():
        return {"match": True, "status": "unknown", "expected": None, "actual": None}
    try:
        expected = fingerprint_file.read_text(encoding="utf-8").strip().split()[0]
    except OSError:
        return {"match": True, "status": "unknown", "expected": None, "actual": None}
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
