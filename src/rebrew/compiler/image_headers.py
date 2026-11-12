"""Fresh image-bound MSVC header trees for read-only include reviews."""

from __future__ import annotations

import hashlib
import io
import subprocess
import tarfile
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from rebrew.compiler.toolchain import (
    docker_hardening_args,
    get_toolchain,
    image_content_id,
    image_msvc_env,
)
from rebrew.utils import container_runtime, run_process_group


class ImageHeaders:
    """Extract headers directly from admitted images; never trust a host cache."""

    def __init__(self, runtime: str | None = None) -> None:
        self.runtime = container_runtime(runtime)
        self.temp = tempfile.TemporaryDirectory(prefix="rebrew-image-headers-")
        self.trees: dict[str, dict[str, Any]] = {}

    def __enter__(self) -> ImageHeaders:
        return self

    def __exit__(self, *args: Any) -> None:
        self.temp.cleanup()

    def _image_id(self, image: str) -> str:
        try:
            result = run_process_group(
                [self.runtime, "image", "inspect", "--format", "{{.Id}}", image],
                capture_output=True,
                timeout=30,
            )
            result.check_returncode()
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError(f"cannot inspect compiler image {image}") from exc
        identity = image_content_id(result.stdout.decode("ascii", errors="replace"))
        if not identity:
            raise ValueError(f"compiler image has no immutable id: {image}")
        return identity

    def get(self, profile: str) -> Path:
        """Return the image's INCLUDE directory, extracted from its content ID."""
        if profile in self.trees:
            return Path(self.trees[profile]["root"])
        spec = get_toolchain(profile)
        if not spec.image or not spec.tool_root or not image_msvc_env(spec):
            raise ValueError(f"unsupported image header profile: {profile}")
        image_id = self._image_id(spec.image)
        include = str(Path(spec.tool_root).parent / "Include")
        name = "rebrew-headers-" + uuid.uuid4().hex[:12]
        try:
            result = run_process_group(
                [
                    self.runtime,
                    "run",
                    "--rm",
                    *docker_hardening_args(pull=False),
                    "--pull=never",
                    "--name",
                    name,
                    "--entrypoint",
                    "tar",
                    image_id,
                    "-C",
                    include,
                    "-cf",
                    "-",
                    ".",
                ],
                capture_output=True,
                timeout=120,
            )
            result.check_returncode()
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError(f"cannot extract headers from compiler image {image_id}") from exc
        root = (
            Path(self.temp.name)
            / image_id.removeprefix("sha256:")
            / hashlib.sha256(include.encode()).hexdigest()
        )
        root.mkdir(parents=True, exist_ok=True)
        manifest: dict[str, str] = {}
        directories: set[str] = set()
        try:
            with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
                for entry in archive:
                    path = PurePosixPath(entry.name)
                    if path.is_absolute() or ".." in path.parts or "\\" in entry.name:
                        raise ValueError("unsafe image header path")
                    directories.update(parent.as_posix() for parent in path.parents if parent.parts)
                    if entry.isdir():
                        if path.parts:
                            directories.add(path.as_posix())
                            root.joinpath(*path.parts).mkdir(parents=True, exist_ok=True)
                        continue
                    if not entry.isfile() or not path.parts or entry.size > 100_000_000:
                        raise ValueError("unsupported image header entry")
                    key = path.as_posix()
                    if key in manifest:
                        raise ValueError("duplicate image header entry")
                    stream = archive.extractfile(entry)
                    if stream is None:
                        raise ValueError("unreadable image header entry")
                    data = stream.read()
                    manifest[key] = hashlib.sha256(data).hexdigest()
                    destination = root.joinpath(*path.parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
        except (OSError, tarfile.TarError) as exc:
            raise ValueError("invalid compiler image header archive") from exc
        if not manifest:
            raise ValueError("compiler image header archive is empty")
        names = [*manifest, *directories]
        if len({name.casefold() for name in names}) != len(names):
            raise ValueError("ambiguous case-insensitive image header path")
        self.trees[profile] = {
            "image": spec.image,
            "id": image_id,
            "root": root,
            "manifest": manifest,
            "directories": directories,
            "include": include,
        }
        self.verify()
        return root

    def verify(self) -> None:
        """Reject changed image tags, extracted files, symlinks or discovery sets."""
        for tree in self.trees.values():
            if self._image_id(tree["image"]) != tree["id"]:
                raise ValueError("compiler image changed during header review")
            root = tree["root"]
            actual = {}
            directories = set()
            for path in root.rglob("*"):
                if path.is_symlink():
                    raise ValueError("image header extraction changed")
                if path.is_file():
                    actual[path.relative_to(root).as_posix()] = hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
                elif path.is_dir():
                    directories.add(path.relative_to(root).as_posix())
                else:
                    raise ValueError("image header extraction changed")
            if actual != tree["manifest"] or directories != tree["directories"]:
                raise ValueError("image header extraction changed")

    def normalize(self, value: Any) -> Any:
        """Replace temporary paths with stable image identities in a report."""
        if isinstance(value, str):
            for tree in self.trees.values():
                value = value.replace(str(tree["root"]), "image://" + tree["id"] + tree["include"])
            return value
        if isinstance(value, list):
            return [self.normalize(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.normalize(item) for item in value)
        if isinstance(value, dict):
            return {self.normalize(key): self.normalize(item) for key, item in value.items()}
        return value
