"""Run source operations against a retained target and return isolated proposals."""

lazy import base64
lazy import hashlib
lazy import os
lazy import shutil
lazy import tempfile
lazy from pathlib import Path
lazy from typing import Any


def snapshot_mutation(config: Any, req: Any) -> dict[str, Any]:
    """Execute one bounded operation without exposing the published worktree."""
    from rebrew import ops
    from rebrew.config import load_config
    from rebrew.workspace import read_config, target_binary, targets_table

    def invalid(detail: str) -> ops.OpsError:
        return ops.OpsError(detail, code=ops.INVALID_REQUEST, status=400)

    def digest_file(path: Path) -> str:
        with path.open("rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest()

    def checked_path(root: Path, value: str, *, existing: bool = True) -> Path:
        if not value or "\\" in value or any(p in {"", ".", ".."} for p in value.split("/")):
            raise invalid("invalid proposal path")
        path = root / value
        if path.resolve() != path:
            raise invalid("proposal path escapes the snapshot or follows a symlink")
        if existing and (value not in retained_paths or not path.is_file()):
            raise invalid("proposal source is not in the retained manifest")
        return path

    retained_paths = {entry.path for entry in req.files}
    if req.operation not in {"data-set", "rename", "split", "merge", "variants", "decompme"}:
        raise invalid("unknown retained source operation")
    if req.va < 0 or req.size < 0:
        raise invalid("address and size must not be negative")
    with (
        ops.retained_target_snapshot(
            config, req.files, req.rebrew_target, req.sha256, req.binary_key, req.binary_url
        ) as snapshot,
        tempfile.TemporaryDirectory(prefix="source-proposal-", dir=snapshot.parent) as temp,
    ):
        root = Path(temp).resolve()
        shutil.copytree(snapshot, root, dirs_exist_ok=True)
        selected = targets_table(read_config(root)).get(req.rebrew_target)
        if not isinstance(selected, dict):
            raise invalid("selected target is missing")
        binary = target_binary(root, selected)
        if binary is None or not binary.resolve().is_relative_to(root):
            raise invalid("target binary escapes the snapshot")
        binary = binary.resolve()
        if digest_file(binary) != req.sha256:
            raise invalid("target binary changed")
        project = (root / "rebrew-project.toml").read_bytes()
        cfg = load_config(root, target=req.rebrew_target)
        ops.confined_snapshot_config(cfg, root)
        metadata_cache = (cfg.metadata_dir / ".rebrew" / "metadata-doc").resolve()
        target = f"--target={req.rebrew_target}"
        dry = ["--dry-run"] if req.dry_run else []
        if req.operation in {"variants", "decompme"}:
            if req.size <= 0:
                raise invalid("a function extent is required")
            if req.operation == "variants" and "output/ga_runs/best.c" in retained_paths:
                raise invalid("variant output conflicts with a retained source file")
            source = checked_path(root, req.source)
            candidate = req.candidate.encode("utf-8")
            if (
                len(candidate) > 2_000_000
                or hashlib.sha256(candidate).hexdigest() != req.candidate_sha256
            ):
                raise invalid("candidate does not match its digest")
            source.write_bytes(candidate)
            ops.remote_header_refusal(cfg, [source])
            if req.operation == "variants":
                if req.generations < 1 or req.population < 1 or req.seed < 0:
                    raise invalid("invalid variant search bounds")
                arguments = [
                    "match",
                    "run",
                    "--json",
                    f"--generations={req.generations}",
                    f"--pop-size={req.population}",
                    f"--seed={req.seed}",
                    f"--va=0x{req.va:x}",
                    f"--size={req.size}",
                    target,
                    "--",
                    str(source),
                ]
                result = ops.run_rebrew(
                    arguments, root, ops.SEARCH_TIMEOUT_SECONDS, outcome_exit=True
                )
            else:
                result = ops.run_rebrew(
                    [
                        "export",
                        "decompme",
                        "--json",
                        *dry,
                        f"--va=0x{req.va:x}",
                        f"--size={req.size}",
                        target,
                        "--",
                        str(source),
                    ],
                    root,
                    ops.COMMAND_TIMEOUT_SECONDS,
                )
            if (
                source.is_symlink()
                or not source.resolve().is_relative_to(root)
                or digest_file(source) != req.candidate_sha256
            ):
                raise invalid("candidate changed during execution")
            if req.operation == "variants" and "best_source_path" in result:
                raw_path = result.pop("best_source_path")
                if not isinstance(raw_path, str):
                    raise invalid("variant result has an invalid source path")
                best = Path(raw_path)
                if not best.is_absolute():
                    best = root / best
                if (
                    best.is_symlink()
                    or best.resolve() != root / "output/ga_runs/best.c"
                    or not best.is_file()
                    or best.stat().st_size > 2_000_000
                ):
                    raise invalid("variant source is missing or escapes its output directory")
                data = best.read_bytes()
                try:
                    result["best_source"] = data.decode("utf-8")
                except UnicodeDecodeError:
                    raise invalid("variant source is not UTF-8") from None
                result["best_source_sha256"] = hashlib.sha256(data).hexdigest()
            if "source" in result:
                result["source"] = req.source
            if "source_file" in result:
                result["source_file"] = req.source
        elif req.operation == "data-set":
            options = [
                f"{option}=0x{req.va:x}={value}"
                for field, option in ops.DATA_FIELD_OPTIONS.items()
                if (value := getattr(req, field))
            ]
            if req.size:
                options.append(f"--size=0x{req.va:x}={req.size}")
            if not options:
                raise invalid("data set requires at least one field")
            result = ops.run_rebrew(
                ["data", "set", "--json", *options, *dry, target], root, ops.COMMAND_TIMEOUT_SECONDS
            )
        elif req.operation == "rename":
            selector = ops.RENAME_KINDS.get(req.kind)
            if selector is None or not req.old_name or not req.new_name:
                raise invalid("invalid rename")
            result = ops.run_rebrew(
                [
                    "source",
                    "rename",
                    "--json",
                    *selector,
                    *dry,
                    target,
                    "--",
                    req.old_name,
                    req.new_name,
                ],
                root,
                ops.COMMAND_TIMEOUT_SECONDS,
            )
        elif req.operation == "split":
            source = checked_path(root, req.source)
            va = [f"--va=0x{req.va:x}"] if req.va else []
            result = ops.run_rebrew(
                ["source", "split", "--json", *va, *dry, target, "--", str(source)],
                root,
                ops.COMMAND_TIMEOUT_SECONDS,
            )
        else:
            if len(req.sources) < 2 or len(req.sources) > 1024:
                raise invalid("merge requires at least two bounded sources")
            sources = [str(checked_path(root, source)) for source in req.sources]
            output = checked_path(root, req.output, existing=False)
            if output.exists():
                raise invalid("merge output already exists")
            result = ops.run_rebrew(
                ["source", "merge", "--json", f"--output={output}", *dry, target, "--", *sources],
                root,
                ops.COMMAND_TIMEOUT_SECONDS,
            )
        if (
            binary.is_symlink()
            or not binary.resolve().is_relative_to(root)
            or digest_file(binary) != req.sha256
            or (root / "rebrew-project.toml").read_bytes() != project
        ):
            raise invalid("target binary or project configuration changed")
        if req.operation in {"variants", "decompme"}:
            for entry in req.files:
                if entry.path == req.source:
                    continue
                path = checked_path(root, entry.path)
                if (
                    path.is_symlink()
                    or path.stat().st_size != entry.size
                    or digest_file(path) != entry.digest
                ):
                    raise invalid("retained source changed during execution")
            return {"result": result}
        proposal = []
        total = 0
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in dirs:
                path = Path(directory) / name
                if path.is_symlink() or name in {".git", ".hg", ".jj"}:
                    raise invalid("proposal contains a control directory or symlink")
            for name in files:
                path = Path(directory) / name
                relative = path.relative_to(root).as_posix()
                if path.is_symlink() or not path.is_file() or name == ".gitattributes":
                    raise invalid("proposal contains a control file or symlink")
                if path == binary and relative not in retained_paths:
                    continue
                if path.resolve().is_relative_to(metadata_cache):
                    if relative not in retained_paths:
                        continue
                    path = snapshot / relative
                if path.stat().st_size > 1024 * 1024:
                    raise invalid("proposal exceeds source bounds")
                data = path.read_bytes()
                total += len(data)
                if len(data) > 1024 * 1024 or total > 32 * 1024 * 1024 or len(proposal) >= 1024:
                    raise invalid("proposal exceeds source bounds")
                proposal.append(
                    {
                        "path": relative,
                        "digest": hashlib.sha256(data).hexdigest(),
                        "size": len(data),
                        "content": base64.b64encode(data).decode("ascii"),
                    }
                )
        proposal.sort(key=lambda item: item["path"])
        return {"result": result, "files": proposal}
