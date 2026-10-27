"""Linked-image EXACT: a RELOC function whose bytes in the raw link equal the reference.

The object compare masks relocation slots, so a function with one relocation
can only reach RELOC there.  The raw link resolves those slots.  When the
built image places the function at its reference VA and its bytes
``[va, va + size)`` equal the reference's with no masking, the compiler and
linker produced the reference bytes, which is what EXACT claims.

``rebrew verify --text`` with an acknowledged raw link records that as EXACT
with linked evidence in the function's ``verification`` table: the usual
comparison inputs plus ``linked_image`` (the image path, project-relative when
inside the root) and ``linked_image_hash`` (its SHA-256).  A later object
compare of RELOC keeps EXACT only while that evidence still describes the
comparison: same compile inputs and the same image bytes.  Any other verdict,
an input change, or a rebuilt image with different bytes records the object
verdict as usual.
"""

from __future__ import annotations

import threading
lazy import hashlib
lazy import json
lazy from pathlib import Path
lazy from typing import Any

__all__ = [
    "LINKED_MESSAGE",
    "image_sha256",
    "linked_evidence",
    "linked_exact_holds",
    "linked_image_current",
    "promote_linked_exact",
]

#: Appended to a result message when EXACT comes from the linked image.
LINKED_MESSAGE = "EXACT in the raw link (linked bytes identical)"

#: Comparison inputs that must be unchanged for linked evidence to hold.
_COMPILE_FIELDS = (
    "source_hash",
    "headers_hash",
    "compiler_hash",
    "toolchain",
    "cflags",
    "defines",
    "context_hash",
    "reference_hash",
    "reference_size",
    "module",
    "va",
)

_HASH_CHUNK = 1 << 20

_hash_lock = threading.Lock()
_hash_memo: dict[tuple[str, int, int, int], str] = {}


def image_sha256(path: Path) -> str:
    """SHA-256 of *path*, memoized per (path, mtime_ns, size, inode).

    Raises :class:`OSError` when the file cannot be read.
    """
    resolved = path.resolve()
    st = resolved.stat()
    key = (str(resolved), st.st_mtime_ns, st.st_size, st.st_ino)
    with _hash_lock:
        cached = _hash_memo.get(key)
    if cached is not None:
        return cached
    digest = hashlib.sha256()
    with resolved.open("rb") as fh:
        while chunk := fh.read(_HASH_CHUNK):
            digest.update(chunk)
    value = digest.hexdigest()
    with _hash_lock:
        _hash_memo[key] = value
    return value


def _image_ref(cfg: Any, image: Path) -> str:
    """*image* relative to the project root when inside it, else absolute (posix)."""
    resolved = image.resolve()
    try:
        return resolved.relative_to(Path(cfg.root).resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def _image_path(cfg: Any, ref: str) -> Path:
    path = Path(ref)
    return path if path.is_absolute() else Path(cfg.root) / path


def linked_evidence(inputs: dict[str, str], image_ref: str, image_hash: str) -> dict[str, str]:
    """Comparison *inputs* extended with the linked image, with a fresh ``input_hash``."""
    evidence = {k: v for k, v in inputs.items() if k not in {"input_hash", "status", "writer"}}
    evidence["linked_image"] = image_ref
    evidence["linked_image_hash"] = image_hash
    evidence["input_hash"] = hashlib.sha256(
        json.dumps(evidence, sort_keys=True, ensure_ascii=True).encode()
    ).hexdigest()
    return evidence


def linked_image_current(cfg: Any, stored: dict[str, Any] | None) -> bool:
    """True when *stored* is linked EXACT evidence and its image still has the recorded hash."""
    if not stored or stored.get("status") != "EXACT":
        return False
    ref, recorded = stored.get("linked_image"), stored.get("linked_image_hash")
    if not isinstance(ref, str) or not isinstance(recorded, str) or not ref or not recorded:
        return False
    try:
        return image_sha256(_image_path(cfg, ref)) == recorded
    except OSError:
        return False


def linked_exact_holds(
    cfg: Any, stored: dict[str, Any] | None, measured: dict[str, str] | None
) -> dict[str, str] | None:
    """The evidence to keep when an object RELOC is still a linked EXACT, else None.

    *stored* is the function's ``verification`` table and *measured* the
    comparison inputs of the object compare that just returned RELOC.  The
    linked evidence holds when every compile input matches and the recorded
    image still hashes to the recorded digest.
    """
    if not measured or not stored or not linked_image_current(cfg, stored):
        return None
    if any(stored.get(k) != measured.get(k) for k in _COMPILE_FIELDS):
        return None
    return linked_evidence(measured, str(stored["linked_image"]), str(stored["linked_image_hash"]))


def _first_diff(a: bytes, b: bytes) -> int:
    for i, (x, y) in enumerate(zip(a, b, strict=False)):
        if x != y:
            return i
    return min(len(a), len(b))


def promote_linked_exact(
    cfg: Any,
    entries: list[Any],
    results: list[dict[str, Any]],
    built: Path,
    placed_vas: set[int],
    *,
    context_hash: str,
    write: bool,
) -> dict[str, Any]:
    """Promote RELOC rows whose linked bytes equal the reference to EXACT.

    *results* are the run's report rows; *placed_vas* the annotated VAs the
    built image places there.  A candidate is a RELOC row placed at its VA
    whose source is not newer than *built* and whose built bytes equal the
    reference bytes.  With *write*, each candidate's STATUS becomes EXACT with
    linked evidence in one locked metadata write and its row is rewritten;
    without it the rows and the store stay unchanged.  Returns the report
    block: counts plus the rows that were not promoted, with the reason.
    """
    from rebrew.compiler.compile import clears_blocker
    from rebrew.compiler.overrides import resolve_compile_overrides_cached
    from rebrew.formats.binary_loader import extract_raw_bytes
    from rebrew.metadata.functions import is_status_parked, update_statuses_batch
    from rebrew.sources import contained_path, source_roots
    from rebrew.verify_hash import comparison_inputs

    by_va = {int(e.va): e for e in entries}
    image_hash = image_sha256(built)
    image_ref = _image_ref(cfg, built)
    built_mtime = built.stat().st_mtime_ns
    report: dict[str, Any] = {
        "image": image_ref,
        "image_hash": image_hash,
        "candidates": 0,
        "identical": 0,
        "promoted": 0,
        "kept_reloc": [],
    }
    updates: list[dict[str, Any]] = []
    promoted_rows: list[dict[str, Any]] = []

    def _keep(row: dict[str, Any], reason: str, **extra: Any) -> None:
        report["kept_reloc"].append(
            {"va": row["va"], "name": row.get("name", ""), "reason": reason, **extra}
        )

    for row in results:
        if row.get("status") != "RELOC":
            continue
        report["candidates"] += 1
        va = int(str(row["va"]), 16)
        entry = by_va.get(va)
        if entry is None or is_status_parked(getattr(entry, "status", "") or ""):
            _keep(row, "parked" if entry is not None else "no annotation")
            continue
        if va not in placed_vas:
            _keep(row, "not placed at its reference VA")
            continue
        source = contained_path(source_roots(cfg), getattr(entry, "filepath", ""))
        if source is None or not source.is_file():
            _keep(row, "source not found")
            continue
        if source.stat().st_mtime_ns > built_mtime:
            _keep(row, "source newer than the built image")
            continue
        size = int(getattr(entry, "size", 0) or 0)
        reference = extract_raw_bytes(cfg.target_binary, va, size) if size > 0 else b""
        linked = extract_raw_bytes(built, va, size) if size > 0 else b""
        if not reference or len(reference) != size:
            _keep(row, "reference bytes unreadable")
            continue
        if linked != reference:
            _keep(row, "linked bytes differ", first_diff=_first_diff(linked, reference))
            continue
        report["identical"] += 1
        toolchain, cflags = resolve_compile_overrides_cached(
            cfg,
            source.parent,
            getattr(entry, "toolchain", ""),
            getattr(entry, "cflags", ""),
            getattr(entry, "module", ""),
        )
        inputs = comparison_inputs(
            cfg,
            source,
            reference,
            toolchain=toolchain,
            cflags=cflags,
            module=entry.module,
            va=va,
            context_hash=context_hash,
        )
        if inputs is None:
            _keep(row, "comparison inputs unreadable")
            continue
        updates.append(
            {
                "module": entry.module,
                "va": va,
                "new_status": "EXACT",
                "clear_blockers": clears_blocker("EXACT", source),
                "updated_by": "verify",
                "verification": {
                    **linked_evidence(inputs, image_ref, image_hash),
                    "status": "EXACT",
                    "writer": "verify",
                },
            }
        )
        promoted_rows.append(row)

    if write and updates:
        update_statuses_batch(cfg.metadata_dir, updates)
        for row in promoted_rows:
            row["status"] = "EXACT"
            row["message"] = LINKED_MESSAGE
        report["promoted"] = len(promoted_rows)
    return report
