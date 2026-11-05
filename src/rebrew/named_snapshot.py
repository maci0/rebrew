"""Named decompilation over a complete, content-addressed source snapshot."""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import unicodedata
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from rebrew.config import ProjectConfig
    from rebrew.ops import DecompileSnapshotRequest, SecuritySnapshotRequest, WorkerConfig


def _valid_path(path: str) -> bool:
    parts = path.split("/")
    return (
        bool(path)
        and len(path.encode("utf-8")) <= 1024
        and len(parts) <= 32
        and unicodedata.normalize("NFC", path) == path
        and "\\" not in path
        and all(ord(c) >= 32 and ord(c) != 127 for c in path)
        and all(part not in ("", ".", "..") for part in parts)
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate manifest key")
        out[key] = value
    return out


def _validate_manifest(req: Any) -> None:
    from rebrew import ops

    try:
        encoded = req.source_manifest.encode("utf-8")
        if len(encoded) > 2 * 1024 * 1024:
            raise ValueError("manifest too large")
        manifest = json.loads(req.source_manifest, object_pairs_hook=_unique_object)
        if (
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
            != encoded
        ):
            raise ValueError("noncanonical manifest")
        if hashlib.sha256(encoded).hexdigest() != req.source_snapshot_sha256:
            raise ValueError("manifest digest differs")
        if (
            type(manifest) is not dict
            or set(manifest) != {"complete", "exclusions", "files", "origin", "version"}
            or manifest["complete"] is not True
            or manifest["exclusions"] != []
            or manifest["origin"] not in ("files", "tree")
            or type(manifest["version"]) is not int
            or manifest["version"] != 1
            or type(manifest["files"]) is not list
            or len(manifest["files"]) != len(req.files)
            or not 1 <= len(req.files) <= 1024
        ):
            raise ValueError("invalid complete manifest")
        previous = ""
        total = 0
        for item, entry in zip(manifest["files"], req.files, strict=True):
            if (
                type(item) is not dict
                or set(item) != {"digest", "path", "size"}
                or type(item["path"]) is not str
                or type(item["digest"]) is not str
                or type(item["size"]) is not int
                or (item["path"], item["digest"], item["size"])
                != (entry.path, entry.digest, entry.size)
                or not re.fullmatch(r"[0-9a-f]{64}", entry.digest)
                or not 0 <= entry.size <= 1024 * 1024
                or not _valid_path(entry.path)
                or entry.path <= previous
                or any(
                    part in (".git", ".hg", ".jj", ".gitattributes") or part.startswith(".relumea-")
                    for part in entry.path.split("/")
                )
                or bool(entry.key) == bool(entry.url)
            ):
                raise ValueError("invalid manifest entry")
            previous = entry.path
            total += entry.size
        if total > 32 * 1024 * 1024 or not any(
            entry.path == "rebrew-project.toml" for entry in req.files
        ):
            raise ValueError("invalid manifest bounds or missing project config")
    except KeyError, TypeError, ValueError, UnicodeError, RecursionError:
        raise ops._invalid("invalid retained source manifest") from None


def _capture_files(config: Any, req: Any) -> tuple[list[Any], str, int]:
    from rebrew import ops

    try:
        raw = req.analysis_manifest.encode("utf-8")
        if (
            len(raw) > 2 * 1024 * 1024
            or hashlib.sha256(raw).hexdigest() != req.analysis_manifest_sha256
        ):
            raise ValueError("capture digest differs")
        capture = json.loads(req.analysis_manifest, object_pairs_hook=_unique_object)
        if (
            type(capture) is not dict
            or not {"version", "binary_sha256", "target", "entries"} <= set(capture)
            or set(capture)
            - {"version", "binary_sha256", "target", "inventory_path", "report_path", "entries"}
            or type(capture["version"]) is not int
            or capture["version"] != 1
            or capture["binary_sha256"] != req.sha256
            or capture["target"] != req.rebrew_target
            or type(capture["entries"]) is not list
            or not 1 <= len(capture["entries"]) <= 1024
            or not re.fullmatch(r"[0-9a-f]{32}", req.generation)
        ):
            raise ValueError("invalid capture")
        ordered: list[dict[str, Any]] = []
        refs = iter(req.analysis_files)
        selected: dict[str, Any] = {}
        reserved: dict[str, dict[str, Any]] = {}
        total = 0
        previous = ""
        binary_path = ""
        binary_size = 0
        baseline_config = False
        for item in capture["entries"]:
            if type(item) is not dict or not {"path", "kind", "size", "digest"} <= item.keys():
                raise ValueError("invalid capture entry")
            path, kind, size, digest = (item[k] for k in ("path", "kind", "size", "digest"))
            role, key = item.get("role", ""), item.get("object_key", "")
            if (
                type(path) is not str
                or type(kind) is not str
                or type(size) is not int
                or type(digest) is not str
                or type(role) is not str
                or type(key) is not str
                or not _valid_path(path)
                or path <= previous
                or size < 0
            ):
                raise ValueError("invalid capture path")
            previous = path
            row: dict[str, Any] = {"path": path, "kind": kind}
            if role:
                row["role"] = role
            row.update(size=size, digest=digest)
            if key:
                row["object_key"] = key
            if row != item:
                raise ValueError("invalid capture fields")
            ordered.append(row)
            reserved[path] = item
            if kind == "absent":
                if role or key or size or digest:
                    raise ValueError("invalid absent capture")
            elif kind == "binary":
                if binary_path or role or key or size <= 0 or digest != req.sha256:
                    raise ValueError("invalid binary capture")
                binary_path, binary_size = path, size
            elif kind == "file":
                if (
                    role not in ("source", "analysis")
                    or not key
                    or size > 1024 * 1024
                    or not re.fullmatch(r"[0-9a-f]{64}", digest)
                ):
                    raise ValueError("invalid file capture")
                entry = next(refs)
                if (
                    (entry.path, entry.digest, entry.size) != (path, digest, size)
                    or bool(entry.key) == bool(entry.url)
                    or (entry.key and entry.key != key)
                ):
                    raise ValueError("capture object differs")
                total += size
                if role == "analysis" and path != "rebrew-project.toml":
                    selected[path] = entry
                if role == "analysis" and path == "rebrew-project.toml":
                    baseline_config = True
            else:
                raise ValueError("invalid capture kind")
        if (
            next(refs, None) is not None
            or not binary_path
            or not baseline_config
            or total > 8 * 1024 * 1024
        ):
            raise ValueError("invalid capture bounds")
        for field in ("inventory_path", "report_path"):
            if field not in capture:
                continue
            path = capture[field]
            if type(path) is not str or not _valid_path(path):
                raise ValueError("invalid selected capture path")
            if field == "report_path" and path != ".relumea/analysis-report.json":
                raise ValueError("invalid captured report path")
            item = reserved.get(path)
            if item is None or item["kind"] != "file" or item.get("role") != "analysis":
                raise ValueError("selected capture path is not an analysis file")
        canonical = {
            "version": 1,
            "binary_sha256": req.sha256,
            "target": req.rebrew_target,
        }
        for field in ("inventory_path", "report_path"):
            if field in capture:
                canonical[field] = capture[field]
        canonical["entries"] = ordered
        if json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode("utf-8") != raw:
            raise ValueError("noncanonical capture")
        for entry in req.files:
            for path in reserved:
                if entry.path.startswith(path + "/") or path.startswith(entry.path + "/"):
                    raise ValueError("overlapping capture paths")
            prior = reserved.get(entry.path)
            if prior and not (
                prior["kind"] == "file"
                and (
                    (entry.path == "rebrew-project.toml" and prior.get("role") == "analysis")
                    or (entry.path != "rebrew-project.toml" and prior.get("role") == "source")
                )
            ):
                raise ValueError("protected capture path")
            selected[entry.path] = entry
        for entry in req.analysis_files:
            with ops.binary_file(config, entry.key, entry.url, entry.digest, "key") as source:
                with source.open("rb") as handle:
                    data = handle.read(entry.size + 1)
                if len(data) != entry.size or hashlib.sha256(data).hexdigest() != entry.digest:
                    raise ValueError("capture content differs")
        return [selected[p] for p in sorted(selected)], binary_path, binary_size
    except KeyError, TypeError, ValueError, UnicodeError, RecursionError, StopIteration:
        raise ops._invalid("invalid retained analysis capture") from None


@contextlib.contextmanager
def retained_snapshot(
    config: WorkerConfig, req: DecompileSnapshotRequest | SecuritySnapshotRequest
) -> Iterator[tuple[Path, ProjectConfig, set[Path], Callable[[], None]]]:
    from rebrew import ops
    from rebrew.config import load_config

    _validate_manifest(req)
    try:
        revision_size = len(req.source_revision.encode("utf-8"))
    except UnicodeError:
        raise ops._invalid("invalid retained snapshot request") from None
    if (
        not req.source_revision
        or revision_size > 256
        or any(ord(c) < 32 or ord(c) == 127 for c in req.source_revision)
        or bool(req.binary_key) == bool(req.binary_url)
    ):
        raise ops._invalid("invalid retained snapshot request")
    ops.confined_dir(config, req.project_dir, "project_dir")
    scratch = config.require_workspace() / ops.SCRATCH_DIR
    if scratch.is_symlink() or (scratch.exists() and not scratch.is_dir()):
        raise ops._invalid("invalid worker scratch directory")
    merged, binary_path, binary_size = _capture_files(config, req)
    with ops.retained_target_snapshot(
        config, merged, req.rebrew_target, req.sha256, req.binary_key, req.binary_url
    ) as root:
        cfg = load_config(root, target=req.rebrew_target)
        ops.confined_snapshot_config(cfg, root)
        if (
            cfg.target_binary.resolve() != root / binary_path
            or cfg.target_binary.stat().st_size != binary_size
        ):
            raise ops._invalid("retained binary differs from analysis capture")
        retained = {root / entry.path for entry in merged}

        def verify_files() -> None:
            for entry in merged:
                path = root / entry.path
                parents = [
                    root.joinpath(*path.relative_to(root).parts[:i])
                    for i in range(1, len(path.relative_to(root).parts) + 1)
                ]
                if (
                    any(part.is_symlink() for part in parents)
                    or not path.is_file()
                    or path.stat().st_size != entry.size
                    or ops._file_sha256(path) != entry.digest
                ):
                    raise ops._invalid("retained source changed during operation")

        verify_files()
        yield root, cfg, retained, verify_files
        verify_files()
