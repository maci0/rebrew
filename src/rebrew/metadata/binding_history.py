"""Reviewed source-identity changes without discarding native comparison evidence."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rebrew.metadata.document import (
    build_metadata_key_index,
    load_metadata_for_write,
    resolve_metadata_key,
    stamp_format,
)
from rebrew.metadata.functions import (
    FUNCTION_IDENTITY_FIELDS,
    METADATA_FIELDS,
    METADATA_FILENAME,
    identity_file,
    resolve_metadata_dir,
    stamp_provenance,
    validate_identity_file,
    validate_provenance_table,
)
from rebrew.metadata.storage import input_digest, metadata_store, metadata_write_lock
from rebrew.utils import is_safe_c_ident, preset_module_key

# History stores only the claim and its measurement, never another copy of history.
_PREVIOUS_FIELDS = frozenset(FUNCTION_IDENTITY_FIELDS) | {
    "status",
    "size",
    "cflags",
    "toolchain",
    "verification",
    "blocker",
    "blocker_delta",
}


def validate_binding_history(value: Any) -> list[dict[str, Any]]:
    """Validate complete events; generic metadata edits cannot write this field."""
    if not isinstance(value, list):
        raise ValueError("binding_history must be an array")
    for event in value:
        if not isinstance(event, dict) or set(event) != {
            "action",
            "reason",
            "changed_at",
            "previous",
            "replacement",
            "counterpart_va",
        }:
            raise ValueError("invalid source binding history event")
        if event["action"] not in {"retire", "rebind"}:
            raise ValueError("invalid source binding history action")
        reason = event["reason"]
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
            raise ValueError("binding reason must contain 1–2000 characters")
        stamp = datetime.fromisoformat(event["changed_at"])
        if stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError("binding history changed_at requires a timezone")
        previous, replacement = event["previous"], event["replacement"]
        if not isinstance(previous, dict) or set(previous) - _PREVIOUS_FIELDS:
            raise ValueError("invalid previous binding claim")
        if "verification" in previous:
            validate_provenance_table("verification", previous["verification"])
        if not isinstance(replacement, dict) or set(replacement) - set(FUNCTION_IDENTITY_FIELDS):
            raise ValueError("invalid replacement binding claim")
        for claim in [previous, replacement]:
            for key in FUNCTION_IDENTITY_FIELDS:
                if key in claim and not isinstance(claim[key], str):
                    raise ValueError(f"binding history {key} must be a string")
            if claim.get("file"):
                validate_identity_file(claim["file"])
        counterpart = event["counterpart_va"]
        if not isinstance(counterpart, int) or isinstance(counterpart, bool) or counterpart < 0:
            raise ValueError("binding history counterpart_va must be non-negative")
    return copy.deepcopy(value)


def retired_binding(entry: dict[str, Any]) -> bool:
    """Whether the last explicit identity change retired this native row."""
    history = entry.get("binding_history", [])
    return bool(history and validate_binding_history(history)[-1]["action"] == "retire")


def historical_source_files(
    entry: dict[str, Any], metadata_dir: Path, project_root: Path
) -> set[Path]:
    """Former source claims in reviewed events; active bindings still take priority."""
    paths: set[Path] = set()
    for event in validate_binding_history(entry.get("binding_history", [])):
        claim = event["previous"]
        if claim.get("file"):
            root = project_root if claim.get("kind") == "LIBRARY" else metadata_dir
            paths.add((root / validate_identity_file(claim["file"])).resolve())
    return paths


def historical_source_anchor(
    entry: dict[str, Any],
    filepath: Path,
    name: str,
    metadata_dir: Path,
    project_root: Path,
) -> bool:
    """Whether a reviewed change explicitly retired this file/name's old address anchor."""
    if not entry.get("binding_history"):
        return False
    path = filepath.resolve()
    current_root = project_root if entry.get("kind") == "LIBRARY" else metadata_dir
    if (
        entry.get("file")
        and (current_root / entry["file"]).resolve() == path
        and entry.get("name") == name
    ):
        return False
    for event in validate_binding_history(entry["binding_history"]):
        previous = event["previous"]
        root = project_root if previous.get("kind") == "LIBRARY" else metadata_dir
        if (
            previous.get("file")
            and (not previous.get("name") or previous.get("name") == name)
            and (root / previous["file"]).resolve() == path
        ):
            return True
    return False


def change_source_binding(
    directory: Path | str | Any,
    module: str,
    va: int,
    *,
    reason: str,
    identity: dict[str, str] | None = None,
    counterpart_va: int | None = None,
    dry_run: bool = False,
    expected_digest: str | None = None,
    expected_inputs: dict[Path, str] | None = None,
    project_root: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Retire or replace one source claim, retaining native size and all evidence.

    No comparison verdict is copied from a counterpart or retained for a changed
    claim. The counterpart is checked and left byte-for-byte unchanged. Preview
    reads create no files; apply validates again under the shared writer lock.
    """
    if not module or not isinstance(va, int) or isinstance(va, bool) or va < 0:
        raise ValueError("source binding changes require a module and non-negative VA")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
        raise ValueError("binding reason must contain 1–2000 characters")
    if counterpart_va is not None and (
        not isinstance(counterpart_va, int)
        or isinstance(counterpart_va, bool)
        or counterpart_va <= 0
        or identity is not None
        or counterpart_va == va
    ):
        raise ValueError("a distinct positive counterpart can only accompany retirement")
    if identity is not None:
        if set(identity) != set(FUNCTION_IDENTITY_FIELDS):
            raise ValueError("rebind requires file, symbol, name and kind")
        if any(not isinstance(value, str) or not value for value in identity.values()):
            raise ValueError("replacement identity fields must be non-empty strings")
        identity = {**identity, "file": validate_identity_file(identity["file"])}
        if not is_safe_c_ident(identity["name"]):
            raise ValueError("replacement name must be a C identifier")
        if identity["kind"] not in {"FUNCTION", "STUB", "LIBRARY"}:
            raise ValueError("replacement must bind a function")
    if expected_digest is not None and (
        len(expected_digest) != 64 or any(c not in "0123456789abcdef" for c in expected_digest)
    ):
        raise ValueError("expected digest must be a lowercase SHA-256 hex digest")
    directory = resolve_metadata_dir(directory)
    if project_root is None:
        from rebrew.workspace.config import walk_up_to_root

        project_root = walk_up_to_root(directory) or directory
    if identity is not None:
        root = project_root if identity["kind"] == "LIBRARY" else directory
        identity = {
            **identity,
            "file": validate_identity_file(
                identity_file((root / identity["file"]).resolve(), root)
            ),
        }
    path = directory / METADATA_FILENAME
    fields = METADATA_FIELDS | {key.upper() for key in FUNCTION_IDENTITY_FIELDS}

    def prepare() -> tuple[Any, dict[str, Any]]:
        for input_path, expected in (expected_inputs or {}).items():
            if input_digest(input_path) != expected:
                raise ValueError(f"binding review input changed: {input_path}")
        before = metadata_store(path).snapshot()
        digest = metadata_store(path).digest()
        if expected_digest is not None and digest != expected_digest:
            raise ValueError("function metadata changed since preview; review a new preview")
        doc = load_metadata_for_write(path, "function metadata", known_fields=fields)
        if metadata_store(path).snapshot() != before:
            raise ValueError("function metadata changed while reading; retry")
        key = resolve_metadata_key(doc, module, va)
        if key not in doc:
            raise ValueError(f"no native metadata row for {module}.0x{va:x}")
        entry = doc[key]
        history = validate_binding_history(entry.get("binding_history", []))
        if identity is None and (retired_binding(entry) or not entry.get("file")):
            raise ValueError("native row has no current source binding to retire")
        if identity is not None and all(entry.get(k) == v for k, v in identity.items()):
            raise ValueError("replacement is already the current source binding")
        if counterpart_va is not None:
            other_key = resolve_metadata_key(doc, module, counterpart_va)
            counterpart = doc.get(other_key, {})
            if not counterpart.get("file") or retired_binding(counterpart):
                raise ValueError("counterpart must have a current source binding in this target")
        if identity is not None:
            replacement_root = project_root if identity["kind"] == "LIBRARY" else directory
            replacement_path = (replacement_root / identity["file"]).resolve()
            for (other_module, other_va), other_key in build_metadata_key_index(doc).items():
                other = doc[other_key]
                if other_va == va or preset_module_key(other_module) != preset_module_key(module):
                    continue
                if not other.get("file") or retired_binding(other):
                    continue
                other_root = project_root if other.get("kind") == "LIBRARY" else directory
                other_path = (other_root / validate_identity_file(str(other["file"]))).resolve()
                if other_path == replacement_path and (
                    other.get("name") == identity["name"]
                    or other.get("symbol") == identity["symbol"]
                ):
                    raise ValueError(
                        f"replacement definition/symbol already belongs to {other_module}.0x{other_va:x}"
                    )
        previous = {
            key: copy.deepcopy(value) for key, value in entry.items() if key in _PREVIOUS_FIELDS
        }
        event = {
            "action": "retire" if identity is None else "rebind",
            "reason": reason.strip(),
            "changed_at": (now or datetime.now(UTC)).isoformat(),
            "previous": previous,
            "replacement": identity or {},
            "counterpart_va": counterpart_va or 0,
        }
        entry["binding_history"] = validate_binding_history([*history, event])
        for key in (*FUNCTION_IDENTITY_FIELDS, "status", "blocker", "blocker_delta"):
            entry.pop(key, None)
        if identity is not None:
            entry.update(identity)
        stamp_provenance(entry, "rehome", now=now)
        return doc, {
            "dry_run": dry_run,
            "input_digest": digest,
            "module": module,
            "va": f"0x{va:x}",
            **event,
        }

    doc, report = prepare()
    if not dry_run:
        with metadata_write_lock(directory, METADATA_FILENAME):
            doc, report = prepare()
            stamp_format(doc)
            metadata_store(path).write(doc, "metadata")
            # The normal reader's stat fingerprint notices the atomic replacement.
    return report
