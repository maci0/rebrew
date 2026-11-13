"""Versioned, closed readset for a retained coverage calculation.

Origin labels describe the server-verified custody of each input; this codec
cannot authenticate that custody. The dispatch caller must verify it before
constructing the envelope.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import unicodedata
from pathlib import Path
from typing import Any
lazy import os

from rebrew.errors import RebrewError

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_GENERATION = re.compile(r"[0-9a-f]{32}\Z")
_ORIGINS = frozenset({"source", "analysis", "verification"})
_FIELDS = frozenset(
    {
        "version",
        "source_revision",
        "generation",
        "binary_sha256",
        "target",
        "readset",
        "analysis_manifest",
        "verification_digest",
    }
)
_ENTRY_FIELDS = frozenset({"path", "present", "origin", "digest", "size"})


class CoverageInputError(RebrewError, ValueError):
    """The declared coverage input is malformed or differs from its readset."""


def confined_snapshot_config(cfg: Any, root: Path) -> None:
    """Refuse config paths outside the retained snapshot."""
    from rebrew.config import inventory_path_for

    for parent in root.parents:
        if any(
            (parent / name).exists()
            for name in ("rebrew-project.toml", "rebrew-libraries.toml", ".rebrew")
        ):
            raise CoverageInputError("retained snapshot has project metadata outside its root")
    paths = [
        cfg.target_binary,
        cfg.reversed_dir,
        cfg.shared_dir,
        cfg.bin_dir,
        cfg.output_dir,
        cfg.raw_link,
        cfg.compiler_includes,
        cfg.compiler_libs,
        inventory_path_for(cfg.reversed_dir, cfg),
        *cfg.crt_sources.values(),
        *(value for value in cfg.external_libs.values() if "/" in value or "\\" in value),
    ]
    for candidate in paths:
        if candidate is None or candidate == Path():
            continue
        if "\\" in str(candidate):
            raise CoverageInputError("retained project configuration contains an unsupported path")
        path = Path(candidate)
        if not path.is_absolute():
            path = root / path
        if not path.resolve().is_relative_to(root):
            raise CoverageInputError("retained project configuration escapes the snapshot")
    if not cfg.metadata_dir.resolve().is_relative_to(root):
        raise CoverageInputError("retained project metadata escapes the snapshot")


def _path(value: Any) -> str:
    from rebrew.utils import portable_path_parts

    if (
        type(value) is not str
        or not portable_path_parts(value)
        or len(value.split("/")) > 32
        or unicodedata.normalize("NFC", value) != value
    ):
        raise CoverageInputError("invalid coverage input path")
    try:
        if len(value.encode("utf-8")) > 1024:
            raise CoverageInputError("invalid coverage input path")
    except UnicodeEncodeError:
        raise CoverageInputError("invalid coverage input path") from None
    return value


def canonical_coverage_input(value: Any) -> bytes:
    """Validate and encode v1 as sorted compact UTF-8 JSON, without a newline."""
    if type(value) is not dict or set(value) != _FIELDS:
        raise CoverageInputError("invalid coverage input fields")
    if type(value["version"]) is not int or value["version"] != 1:
        raise CoverageInputError("unsupported coverage input version")
    for key in ("source_revision", "binary_sha256", "analysis_manifest", "verification_digest"):
        if type(value[key]) is not str or not _SHA.fullmatch(value[key]):
            raise CoverageInputError(f"invalid {key}")
    if type(value["generation"]) is not str or not _GENERATION.fullmatch(value["generation"]):
        raise CoverageInputError("invalid generation")
    if type(value["target"]) is not str or not value["target"]:
        raise CoverageInputError("invalid target")
    entries = value["readset"]
    if type(entries) is not list or not entries or len(entries) > 4096:
        raise CoverageInputError("invalid coverage readset")
    previous = b""
    for entry in entries:
        if type(entry) is not dict or set(entry) != _ENTRY_FIELDS:
            raise CoverageInputError("invalid coverage readset entry")
        name = _path(entry["path"]).encode("utf-8")
        if name <= previous:
            raise CoverageInputError("coverage readset must be sorted and unique")
        previous = name
        if (
            type(entry["present"]) is not bool
            or type(entry["origin"]) is not str
            or entry["origin"] not in _ORIGINS
        ):
            raise CoverageInputError("invalid coverage input custody")
        if type(entry["size"]) is not int or not 0 <= entry["size"] <= (1 << 63) - 1:
            raise CoverageInputError("invalid coverage input size")
        if entry["present"]:
            if type(entry["digest"]) is not str or not _SHA.fullmatch(entry["digest"]):
                raise CoverageInputError("invalid coverage input digest")
        elif entry["digest"] != "" or entry["size"] != 0:
            raise CoverageInputError("absent input must have empty digest and zero size")
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    except UnicodeEncodeError:
        raise CoverageInputError("invalid coverage input text") from None


def coverage_input_digest(value: Any) -> str:
    """SHA-256 of the canonical coverage input envelope."""
    return hashlib.sha256(canonical_coverage_input(value)).hexdigest()


def _lstat_confined(root: Path, name: str) -> os.stat_result | None:
    """``lstat`` ``name`` under ``root``, refusing any symlink component."""
    from rebrew.utils import portable_path_parts

    parts = portable_path_parts(name)
    if not parts:
        raise CoverageInputError("coverage input contains a symlink")
    path = root
    info: os.stat_result | None = None
    for part in parts:
        path = path / part
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(info.st_mode):
            raise CoverageInputError("coverage input contains a symlink")
    return info


def verify_coverage_readset(root: Path, value: Any, required_paths: set[str]) -> None:
    """Check exact path membership, presence, content and private-root confinement.

    ``required_paths`` must come from the coverage reader's current config and
    transitive input discovery, never from the caller's envelope.
    """
    canonical_coverage_input(value)
    root = root.resolve(strict=True)
    entries = {entry["path"]: entry for entry in value["readset"]}
    if set(entries) != required_paths:
        raise CoverageInputError("coverage readset does not match reader inputs")
    for name, entry in entries.items():
        info = _lstat_confined(root, name)
        if info is None:
            if entry["present"]:
                raise CoverageInputError("coverage input is missing")
            continue
        if not entry["present"]:
            raise CoverageInputError("absent coverage input exists")
        if not stat.S_ISREG(info.st_mode) or info.st_size != entry["size"]:
            raise CoverageInputError("coverage input size or type changed")
        digest = hashlib.sha256()
        with (root / name).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        if digest.hexdigest() != entry["digest"]:
            raise CoverageInputError("coverage input digest changed")


def rebrew_coverage_paths(root: Path, target: str) -> set[str]:
    """Discover Rebrew's current coverage inputs inside a confined snapshot."""
    from rebrew.config import load_config
    from rebrew.coverage_project import coverage_inputs

    root = root.resolve(strict=True)
    cfg = load_config(root, target=target)
    confined_snapshot_config(cfg, root)
    # ownership_inputs opens compile_commands.json before reporting its source paths.
    if cfg.raw_link is not None:
        commands_path = cfg.raw_link.parent / "compile_commands.json"
        if not commands_path.resolve().is_relative_to(root):
            raise CoverageInputError("compile commands escape the snapshot")
        if commands_path.is_file():
            try:
                raw = commands_path.read_bytes()
                if len(raw) > 1024 * 1024:
                    raise CoverageInputError("compile commands exceed the input bound")
                commands = json.loads(raw)
                if type(commands) is not list:
                    raise CoverageInputError("invalid compile commands")
                for command in commands:
                    if type(command) is not dict or any(
                        type(command.get(key)) is not str
                        or not command[key]
                        or "\\" in command[key]
                        or "\x00" in command[key]
                        for key in ("directory", "file")
                    ):
                        raise CoverageInputError("invalid compile command path")
                    directory = Path(command["directory"])
                    if not directory.is_absolute() or not directory.resolve().is_relative_to(root):
                        raise CoverageInputError("compile directory escapes the snapshot")
                    source = Path(command["file"])
                    if not source.is_absolute():
                        source = directory / source
                    if not source.resolve().is_relative_to(root):
                        raise CoverageInputError("compile source escapes the snapshot")
            except (OSError, ValueError, UnicodeDecodeError) as exc:
                raise CoverageInputError("invalid compile commands") from exc
    paths: set[str] = set()
    for item in coverage_inputs(cfg):
        path = Path(item[0])
        if not path.is_absolute():
            raise CoverageInputError("coverage reader returned a relative path")
        try:
            relative = path.relative_to(root)
        except ValueError:
            if path.exists() or path.is_symlink():
                raise CoverageInputError("coverage reader depends on external data") from None
            continue
        name = relative.as_posix()
        _path(name)
        paths.add(name)
    return paths


def plan_coverage_readset(root: Path, target: str) -> list[dict[str, Any]]:
    """Describe the staged paths discovered by Rebrew, without assigning custody."""
    root = root.resolve(strict=True)
    result: list[dict[str, Any]] = []
    for name in sorted(rebrew_coverage_paths(root, target), key=lambda p: p.encode("utf-8")):
        info = _lstat_confined(root, name)
        if info is None:
            result.append({"path": name, "present": False, "digest": "", "size": 0})
            continue
        if not stat.S_ISREG(info.st_mode):
            raise CoverageInputError("coverage input is not a regular file")
        digest = hashlib.sha256()
        with (root / name).open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        result.append(
            {"path": name, "present": True, "digest": digest.hexdigest(), "size": info.st_size}
        )
    return result


def plan_coverage_config(root: Path, target: str) -> tuple[dict[str, Any], list[str]]:
    """Return one target's effective config mapping and its scanned source paths.

    The config is loaded from the snapshot at *root* and refused when any path
    in it leaves the snapshot. Path values in the mapping are POSIX paths
    relative to *root* (``""`` when unset); the other values are the
    ``ProjectConfig`` fields of the same name. The source list holds every
    source and header ``iter_sources`` / ``iter_headers`` find under the
    target's ``reversed_dir``, relative to *root*, sorted by UTF-8 bytes.
    Raises :class:`CoverageInputError` when the config or a source escapes the
    snapshot.
    """
    from rebrew.config import inventory_path_for, load_config
    from rebrew.sources import iter_headers, iter_sources

    root = root.resolve(strict=True)
    cfg = load_config(root, target=target)
    confined_snapshot_config(cfg, root)

    def relative(path: Path | None) -> str:
        if path is None or path == Path():
            return ""
        try:
            return path.resolve().relative_to(root).as_posix()
        except ValueError:
            raise CoverageInputError("coverage config escapes snapshot") from None

    config = {
        "target": cfg.target_name,
        "binary": relative(cfg.target_binary),
        "reversed_dir": relative(cfg.reversed_dir),
        "shared_dir": relative(cfg.shared_dir),
        "inventory": relative(inventory_path_for(cfg.reversed_dir, cfg)),
        "metadata_dir": relative(cfg.metadata_dir),
        "compiler_includes": relative(cfg.compiler_includes),
        "compiler_libs": relative(cfg.compiler_libs),
        "raw_link": relative(cfg.raw_link),
        "source_ext": cfg.source_ext,
        "module": cfg.module,
        "arch": cfg.arch,
        "binary_format": cfg.binary_format,
        "compiler_profile": cfg.compiler_profile,
        "cflags": cfg.cflags,
        "base_cflags": cfg.base_cflags,
        "defines": cfg.defines,
        "external_libs": cfg.external_libs,
        "crt_sources": cfg.crt_sources,
    }
    source_paths = {
        relative(path)
        for path in (*iter_sources(cfg.reversed_dir, cfg), *iter_headers(cfg.reversed_dir, cfg))
    }
    return config, sorted(source_paths, key=lambda item: item.encode("utf-8"))


_RECORD_FIELDS = frozenset(
    {
        "verification_id",
        "source",
        "source_sha256",
        "va",
        "size",
        "status",
        "match_count",
        "total",
        "obj_size",
        "reloc_count",
        "result_digest",
    }
)


def canonical_verification_records(records: Any) -> bytes:
    """Encode trusted backend projections of current verified function results.

    Custody and published-source identity are verified by the dispatch caller.
    """
    if type(records) is not list or len(records) > 4096:
        raise CoverageInputError("invalid verification record set")
    previous: tuple[int, int, bytes, bytes] | None = None
    seen_va: set[int] = set()
    canonical: list[dict[str, Any]] = []
    for row in records:
        if type(row) is not dict or set(row) != _RECORD_FIELDS:
            raise CoverageInputError("invalid verification record fields")
        source = _path(row["source"])
        ident = row["verification_id"]
        if type(ident) is not str or not ident:
            raise CoverageInputError("invalid verification identity")
        for field in ("source_sha256", "result_digest"):
            if type(row[field]) is not str or not _SHA.fullmatch(row[field]):
                raise CoverageInputError("invalid verification digest")
        va, size = row["va"], row["size"]
        if (
            type(va) is not int
            or not 0 <= va <= (1 << 63) - 1
            or type(size) is not int
            or not 0 < size <= (1 << 63) - 1
        ):
            raise CoverageInputError("invalid verification extent")
        status = row["status"]
        if type(status) is not str:
            raise CoverageInputError("verification status is not yet qualified")
        # The metadata layer canonicalizes case and folds the NEAR_MATCH alias
        # at every read/write, so a worker's persisted verdict may arrive in
        # either spelling; the digest must be computed over the canonical form
        # the rest of the trust chain compares against.
        from rebrew.metadata.functions import canonical_status

        status = canonical_status(status)
        row = {**row, "status": status}
        if status not in (
            "EXACT",
            "RELOC",
            "SIZE_MISMATCH",
            "NEAR_MATCHING",
            "STUB",
        ):
            raise CoverageInputError("verification status is not yet qualified")
        if type(row["reloc_count"]) is not int or not 0 <= row["reloc_count"] <= (1 << 63) - 1:
            raise CoverageInputError("invalid verification reloc count")
        if status != "RELOC" and row["reloc_count"] != 0:
            raise CoverageInputError("verification relocations are not yet qualified")
        if status == "RELOC" and row["reloc_count"] == 0:
            raise CoverageInputError("RELOC verification requires relocations")
        for field in ("match_count", "total", "obj_size"):
            if type(row[field]) is not int or not 0 <= row[field] <= (1 << 63) - 1:
                raise CoverageInputError("invalid verification count")
        obj_size, total, matches = row["obj_size"], row["total"], row["match_count"]
        if (
            total != max(size, obj_size)
            or matches > min(size, obj_size)
            or (status in ("EXACT", "RELOC") and (obj_size != size or matches != size))
            or (status == "SIZE_MISMATCH" and obj_size == size)
            or (status == "NEAR_MATCHING" and (obj_size != size or matches == size))
            or (status == "STUB" and matches == size)
        ):
            raise CoverageInputError("verification counts do not match the result")
        if va in seen_va:
            raise CoverageInputError("ambiguous verification address")
        seen_va.add(va)
        try:
            key = (va, size, source.encode("utf-8"), ident.encode("utf-8"))
        except UnicodeEncodeError:
            raise CoverageInputError("invalid verification identity") from None
        if previous is not None and key <= previous:
            raise CoverageInputError("verification records must be sorted and unique")
        previous = key
        canonical.append(row)
    return json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def verification_records_digest(records: Any) -> str:
    """SHA-256 of the canonical verification-records list."""
    return hashlib.sha256(canonical_verification_records(records)).hexdigest()


def validate_coverage_execution(
    root: Path, target: str, binary_sha256: str, envelope: Any, expected_digest: str, records: Any
) -> None:
    """Recheck a backend-authenticated plan against a separately staged execution."""
    if type(expected_digest) is not str or not _SHA.fullmatch(expected_digest):
        raise CoverageInputError("invalid coverage input digest")
    if coverage_input_digest(envelope) != expected_digest:
        raise CoverageInputError("coverage input digest changed")
    if envelope["target"] != target or envelope["binary_sha256"] != binary_sha256:
        raise CoverageInputError("coverage input target or binary changed")
    if verification_records_digest(records) != envelope["verification_digest"]:
        raise CoverageInputError("coverage verification set changed")
    entries = {entry["path"]: entry for entry in envelope["readset"]}
    for record in records:
        source = entries.get(record["source"])
        if (
            source is None
            or not source["present"]
            or source["origin"] != "source"
            or source["digest"] != record["source_sha256"]
        ):
            raise CoverageInputError("verified function source differs from the retained source")
    verify_coverage_readset(root, envelope, rebrew_coverage_paths(root, target))
    from rebrew.catalog.loaders import load_function_structure
    from rebrew.config import inventory_path_for, load_config

    root = root.resolve(strict=True)
    cfg = load_config(root, target=target)
    inventory = inventory_path_for(cfg.reversed_dir, cfg).resolve()
    try:
        name = inventory.relative_to(root).as_posix()
    except ValueError:
        raise CoverageInputError("coverage inventory escapes the snapshot") from None
    entry = entries.get(name)
    if entry is None or not entry["present"] or entry["origin"] != "analysis":
        raise CoverageInputError("coverage inventory lacks analysis custody")
    try:
        functions = load_function_structure(inventory)
    except (OSError, ValueError, TypeError) as exc:
        raise CoverageInputError("coverage inventory is unreadable") from exc
    extents: dict[int, int] = {}
    for function in functions:
        if function.va < 0 or function.size < 0 or function.va in extents:
            raise CoverageInputError("coverage inventory has ambiguous function extents")
        extents[function.va] = function.size
    for record in records:
        if extents.get(record["va"]) != record["size"]:
            raise CoverageInputError("verified function disagrees with analysis inventory")
