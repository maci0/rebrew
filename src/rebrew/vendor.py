"""Reproduce vendored source trees from pinned pristine files and ordered patches."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import typer

from rebrew.cli import EXIT_MISMATCH, RootOption, console, error_exit, json_print, require_root
from rebrew.errors import RebrewError
from rebrew.utils import atomic_write_bytes


class VendorError(RebrewError, ValueError):
    """A vendored tree does not match its manifest."""


@dataclass(frozen=True)
class Manifest:
    """Pinned inputs and the complete file inventory for one generated tree."""

    path: Path
    root: Path
    name: str
    pristine: Path
    checksums: Path
    output: Path
    files: tuple[str, ...]
    patches: tuple[Path, ...]


def load_manifest(root: Path, path: Path) -> Manifest:
    path = _inside(root, path)
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    for key in ("name", "version", "url", "sha256", "pristine", "checksums", "output"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise VendorError(f"{path}: {key} must be a nonempty string")
    if len(data["sha256"]) != 64 or any(c not in "0123456789abcdef" for c in data["sha256"]):
        raise VendorError(f"{path}: sha256 must be a lowercase SHA-256 digest")
    for key in ("files", "patches"):
        values = data.get(key)
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise VendorError(f"{path}: {key} must be a list of relative paths")
        for value in values:
            _relative(value)
        if len(values) != len(set(values)):
            raise VendorError(f"{path}: {key} contains duplicate paths")
    if not data["files"]:
        raise VendorError(f"{path}: files must be nonempty")
    manifest = Manifest(
        path=path,
        root=root,
        name=data["name"],
        pristine=_inside(root, _relative(data["pristine"])),
        checksums=_inside(root, _relative(data["checksums"])),
        output=_inside(root, _relative(data["output"])),
        files=tuple(data["files"]),
        patches=tuple(_inside(root, path.parent / value) for value in data["patches"]),
    )
    return manifest


def _relative(value: str) -> Path:
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts or path == Path("."):
        raise VendorError(f"expected a nonempty relative path, got {value!r}")
    return path


def _inside(root: Path, path: Path) -> Path:
    candidate = root / path
    if not candidate.resolve().is_relative_to(root):
        raise VendorError(f"{candidate}: path escapes root {root}")
    for parent in (candidate, *candidate.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise VendorError(f"{candidate}: symlinks are not supported")
    return candidate


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_pristine(root: Path, manifest: Manifest) -> None:
    """Every listed file matches its hash and the pristine tree holds no other file."""
    listed: dict[Path, str] = {}
    for line in manifest.checksums.read_text().splitlines():
        digest, _, name = line.partition("  ")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest) or not name:
            raise VendorError(f"{manifest.checksums}: malformed line {line!r}")
        candidate = _inside(root, _relative(name))
        if candidate in listed:
            raise VendorError(f"{manifest.checksums}: duplicate checksum for {name}")
        listed[candidate] = digest
    if not manifest.pristine.is_dir():
        raise VendorError(f"{manifest.pristine}: pristine directory is missing")
    for path in manifest.pristine.rglob("*"):
        _inside(root, path)
    errors = [
        f"{path.relative_to(root)}: sha256 differs from {manifest.checksums.relative_to(root)}"
        for path, digest in listed.items()
        if path.is_relative_to(manifest.pristine) and (not path.is_file() or sha256(path) != digest)
    ]
    errors += [
        f"{path.relative_to(root)}: not in {manifest.checksums.relative_to(root)}"
        for path in sorted(manifest.pristine.rglob("*"))
        if path.is_file() and path not in listed
    ]
    errors += [
        f"{manifest.name}: {name} is not a pinned pristine file"
        for name in manifest.files
        if manifest.pristine / name not in listed
    ]
    if errors:
        raise VendorError("\n".join(errors))


def stage(manifest: Manifest, stage_root: Path) -> Path:
    """Copy the pristine files into a fresh stage directory and apply the patches."""
    target = stage_root
    target.mkdir()
    for name in manifest.files:
        (target / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(manifest.pristine / name, target / name)
    for patch in manifest.patches:
        # The stdlib has no unified-diff applier; GNU patch is the one dependency here.
        result = subprocess.run(
            [
                "patch",
                "-p1",
                "--batch",
                "--forward",
                "--fuzz=0",
                "--quiet",
                "--no-backup-if-mismatch",
                "--reject-file=-",
                "-d",
                str(target),
                "-i",
                str(patch),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise VendorError(f"{patch.name} does not apply:\n{result.stdout}{result.stderr}")
    produced = {p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()}
    if produced != set(manifest.files):
        raise VendorError(f"{manifest.name}: patches must produce exactly the listed files")
    for path in target.rglob("*"):
        _inside(target.resolve(), path)

    return target


def output_files(manifest: Manifest) -> set[str]:
    if manifest.output.exists() and not manifest.output.is_dir():
        raise VendorError(f"{manifest.output}: output must be a directory")
    if not manifest.output.is_dir():
        return set()
    for path in manifest.output.rglob("*"):
        _inside(manifest.root, path)
    return {
        p.relative_to(manifest.output).as_posix() for p in manifest.output.rglob("*") if p.is_file()
    }


def check(manifest: Manifest, staged: Path) -> None:
    present = output_files(manifest)
    errors = [
        f"{manifest.output.name}/{name}: missing" for name in manifest.files if name not in present
    ]
    errors += [
        f"{manifest.output.name}/{name}: not in {manifest.path.name}"
        for name in sorted(present - set(manifest.files))
    ]
    errors += [
        f"{manifest.output.name}/{name}: differs from pristine + patches"
        for name in manifest.files
        if name in present and (manifest.output / name).read_bytes() != (staged / name).read_bytes()
    ]
    if errors:
        raise VendorError(
            "\n".join(errors) + "\nedit a patch, then run rebrew library vendor MANIFEST --sync"
        )


def sync(manifest: Manifest, staged: Path) -> None:
    for name in sorted(output_files(manifest) - set(manifest.files)):
        (manifest.output / name).unlink()
    for directory in sorted(manifest.output.rglob("*"), reverse=True):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
    for name in manifest.files:
        (manifest.output / name).parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(manifest.output / name, (staged / name).read_bytes())


def vendor_trees(root: Path, paths: list[Path], *, write: bool = False) -> list[dict[str, Any]]:
    """Validate and stage every manifest before checking or changing any output."""
    root = root.resolve()
    manifests = [load_manifest(root, path) for path in paths]
    inputs = [p for m in manifests for p in (m.pristine, m.path, m.checksums, *m.patches)]
    outputs = [m.output for m in manifests]
    for output in outputs:
        for other in inputs + outputs:
            if other == output and outputs.count(other) == 1 and other not in inputs:
                continue
            if output.is_relative_to(other) or other.is_relative_to(output):
                raise VendorError(f"{output}: output overlaps another input or output {other}")
    with TemporaryDirectory(prefix="rebrew-vendor-") as directory:
        staged = []
        for index, manifest in enumerate(manifests):
            verify_pristine(root, manifest)
            output_files(manifest)
            staged.append(stage(manifest, Path(directory) / str(index)))
        for manifest, target in zip(manifests, staged, strict=True):
            (sync if write else check)(manifest, target)
    return [
        {
            "name": m.name,
            "manifest": str(m.path),
            "output": str(m.output),
            "files": len(m.files),
            "patches": len(m.patches),
            "mode": "sync" if write else "check",
        }
        for m in manifests
    ]


app = typer.Typer(
    help="Check or regenerate vendored sources from pristine files plus ordered patches.",
    rich_markup_mode="rich",
    epilog=(
        "Examples:\n\n  rebrew library vendor references/vendor/zlib/vendor.toml\n\n"
        "  rebrew library vendor references/vendor/zlib/vendor.toml --sync\n"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    manifests: list[Path] = typer.Argument(..., help="Vendor TOML manifests (relative to root)"),
    sync_output: bool = typer.Option(False, "--sync", help="Regenerate the output trees"),
    root: Path | None = RootOption,
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Check pinned originals, apply patches without fuzz, then compare or sync output."""
    base = require_root(root, json_mode=json_output)
    try:
        result = vendor_trees(base, manifests, write=sync_output)
    except VendorError as exc:
        error_exit(str(exc), json_mode=json_output, code=EXIT_MISMATCH)
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print({"libraries": result})
    else:
        for row in result:
            console.print(
                f"{row['name']}: {row['patches']} patches, {row['mode']} ok", markup=False
            )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
