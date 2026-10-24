"""Selected native inventory extent repairs guarded by complete binary/input hashes."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from rebrew.catalog.models import FunctionEntry
from rebrew.config import ProjectConfig, inventory_path_for
from rebrew.formats.binary_loader import load_binary
from rebrew.utils import atomic_write_text, file_lock


def _validate_merges(merges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Reject malformed merge specifications before any input is read.

    Each pair names a surviving head row and the immediately following row it
    absorbs. Order is preserved: chained merges rely on it.
    """
    checked: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    for pair in merges:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise ValueError("merges require (head, tail) address pairs")
        head, tail = pair
        for value in (head, tail):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError("merge addresses must be non-negative integers")
        if head >= tail:
            raise ValueError(f"merge head 0x{head:x} must precede tail 0x{tail:x}")
        if (head, tail) in seen:
            raise ValueError(f"duplicate merge 0x{head:x}=0x{tail:x}")
        seen.add((head, tail))
        checked.append((head, tail))
    return checked


def repair_inventory_extents(
    cfg: ProjectConfig,
    updates: dict[int, int],
    *,
    reason: str,
    dry_run: bool = False,
    expected_digest: str | None = None,
    add_missing: bool = False,
    merges: list[tuple[int, int]] | None = None,
) -> dict[str, Any]:
    """Repair selected sizes without replacing unrelated rows or earned measurements.

    Reasons record reviewed native evidence, not an inferred byte match. Every
    selected span must fit file-backed executable bytes and stop before the next
    inventory start. Preview creates no files; apply rechecks both full inputs
    under the inventory lock before one atomic publication. Explicit admission
    may add reviewed missing entries, but cannot overlap any retained extent.

    A merge pair ``(head, tail)`` is the inverse of a split: when the head row
    is immediately followed by the tail row and the reviewed evidence shows one
    routine, the head extent grows to the tail's end and the tail row is
    removed with its own extent history preserved on the head. The command
    still touches only the native inventory; source bindings and verdicts are
    retired through their own reviewed writers.
    """
    merge_list = _validate_merges(list(merges or []))
    if not updates and not merge_list:
        raise ValueError("extent repairs require at least one size or merge")
    if any(
        not isinstance(va, int)
        or isinstance(va, bool)
        or va < 0
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        for va, size in updates.items()
    ):
        raise ValueError("extent repairs require non-negative addresses and positive sizes")
    if merge_list and any(head in updates for head, _tail in merge_list):
        raise ValueError("a row cannot be both merged and resized in one review")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
        raise ValueError("extent repair reason must contain 1–2000 characters")
    if not isinstance(add_missing, bool):
        raise ValueError("add_missing must be a Boolean")
    inventory = inventory_path_for(cfg.reversed_dir, cfg)

    def prepare() -> tuple[list[dict[str, Any]], dict[str, Any]]:
        inventory_stat = inventory.stat()
        binary_stat = cfg.target_binary.stat()
        raw = inventory.read_bytes()
        binary_raw = cfg.target_binary.read_bytes()
        binary_hash = hashlib.sha256(binary_raw).hexdigest()
        inventory_hash = hashlib.sha256(raw).hexdigest()
        digest = hashlib.sha256(
            json.dumps(
                {
                    "target": cfg.target_name,
                    "inventory": str(inventory.resolve()),
                    "binary": str(cfg.target_binary.resolve()),
                    "inventory_hash": inventory_hash,
                    "binary_hash": binary_hash,
                    "updates": sorted(updates.items()),
                    "merges": [list(pair) for pair in merge_list],
                    "reason": reason.strip(),
                    "add_missing": add_missing,
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        if expected_digest is not None and digest != expected_digest:
            raise ValueError("inventory review inputs changed; review a new preview")
        document = json.loads(raw.decode("utf-8-sig"))
        if not isinstance(document, list) or any(not isinstance(row, dict) for row in document):
            raise ValueError("native inventory must be an array of function rows")
        rows: dict[int, dict[str, Any]] = {}
        for row in document:
            entry = FunctionEntry.from_dict(row)
            if entry.va in rows or entry.va < 0 or entry.size < 0:
                raise ValueError("native inventory has duplicate addresses or negative extents")
            rows[entry.va] = row
        binary = load_binary(cfg.target_binary)

        def complete_span(va: int, size: int) -> bool:
            sections = [
                section
                for section in binary.sections.values()
                if section.is_code_section
                and section.va <= va
                and va + size <= section.va + min(section.size, section.raw_size)
                and section.file_offset >= 0
                and section.file_offset + (va - section.va) + size <= len(binary_raw)
            ]
            return len(sections) == 1

        merged: list[dict[str, Any]] = []
        for head_va, tail_va in merge_list:
            if head_va not in rows or tail_va not in rows:
                missing = head_va if head_va not in rows else tail_va
                raise ValueError(f"merge address 0x{missing:x} is absent from inventory")
            head_row = rows[head_va]
            tail_row = rows[tail_va]
            for label, row in (("head", head_row), ("tail", tail_row)):
                if row.get("_generated_by"):
                    raise ValueError(
                        f"{label} row 0x{FunctionEntry.from_dict(row).va:x} is derived "
                        "coverage and cannot establish native extents"
                    )
            head_size = FunctionEntry.from_dict(head_row).size
            tail_size = FunctionEntry.from_dict(tail_row).size
            if head_size <= 0 or tail_size <= 0:
                raise ValueError("merge requires positive head and tail extents")
            if head_va + head_size != tail_va:
                raise ValueError(
                    f"merge head 0x{head_va:x}+{head_size} does not end at tail 0x{tail_va:x}"
                )
            new_size = tail_va + tail_size - head_va
            if not complete_span(head_va, new_size):
                raise ValueError(
                    f"0x{head_va:x}+{new_size} is not a complete file-backed executable span"
                )
            event = {
                "old_size": head_size,
                "new_size": new_size,
                "reason": reason.strip(),
                "binary_hash": binary_hash,
                "changed_at": datetime.now(UTC).isoformat(),
                "merged": {
                    "va": tail_va,
                    "size": tail_size,
                    "name": str(tail_row.get("name") or ""),
                    "extent_history": tail_row.get("extent_history", []),
                },
            }
            history = head_row.get("extent_history", [])
            if not isinstance(history, list) or any(not isinstance(item, dict) for item in history):
                raise ValueError("extent_history must be an array of evidence tables")
            head_row["extent_history"] = [*history, event]
            head_row["size"] = new_size
            document = [row for row in document if row is not tail_row]
            del rows[tail_va]
            merged.append(
                {
                    "va": f"0x{head_va:x}",
                    "tail": f"0x{tail_va:x}",
                    "old_size": head_size,
                    "new_size": new_size,
                }
            )

        unknown = set(updates) - rows.keys()
        if unknown and not add_missing:
            raise ValueError(f"selected addresses are absent from inventory: {sorted(unknown)}")
        for va in sorted(unknown):
            row = {"va": va, "size": 0, "name": f"fcn.{va:08x}"}
            rows[va] = row
            # Preserve the relative order and contents of every pre-existing row.
            index = next(
                (i for i, item in enumerate(document) if FunctionEntry.from_dict(item).va > va),
                len(document),
            )
            document.insert(index, row)
        starts = sorted(rows)
        following = dict(zip(starts, [*starts[1:], None], strict=True))
        changed = []
        for va, size in sorted(updates.items()):
            row = rows[va]
            if row.get("_generated_by"):
                raise ValueError("derived coverage rows cannot establish native inventory extents")
            if not complete_span(va, size):
                raise ValueError(f"0x{va:x}+{size} is not a complete file-backed executable span")
            next_va = following[va]
            if next_va is not None and va + size > next_va:
                raise ValueError(f"0x{va:x}+{size} overlaps next inventory start 0x{next_va:x}")
            if va in unknown:
                for other_va, other in rows.items():
                    other_size = updates.get(other_va, FunctionEntry.from_dict(other).size)
                    if other_va != va and va < other_va + other_size and other_va < va + size:
                        raise ValueError(
                            f"0x{va:x}+{size} overlaps inventory extent 0x{other_va:x}"
                        )
            old_size = None if va in unknown else FunctionEntry.from_dict(row).size
            if old_size == size:
                continue
            event = {
                "old_size": old_size,
                "new_size": size,
                "reason": reason.strip(),
                "binary_hash": binary_hash,
                "changed_at": datetime.now(UTC).isoformat(),
            }
            history = row.get("extent_history", [])
            if not isinstance(history, list) or any(not isinstance(item, dict) for item in history):
                raise ValueError("extent_history must be an array of evidence tables")
            row["extent_history"] = [*history, event]
            row["size"] = size
            changed.append({"va": f"0x{va:x}", **event})

        def identity(stat: Any) -> tuple[int, int, int, int]:
            return stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns

        if (
            inventory.read_bytes() != raw
            or cfg.target_binary.read_bytes() != binary_raw
            or identity(inventory.stat()) != identity(inventory_stat)
            or identity(cfg.target_binary.stat()) != identity(binary_stat)
        ):
            raise ValueError("inventory review inputs changed while reading; retry")
        return document, {
            "dry_run": dry_run,
            "input_digest": digest,
            "repairs": changed,
            "merges": merged,
            "binary_hash": binary_hash,
            "measurements_changed": False,
        }

    document, report = prepare()
    if not dry_run:
        with file_lock(inventory.with_suffix(inventory.suffix + ".lock")):
            document, report = prepare()
            if report["repairs"] or report["merges"]:
                atomic_write_text(
                    inventory,
                    json.dumps(document, indent=2) + "\n",
                    mode=inventory.stat().st_mode & 0o777,
                )
    return report
