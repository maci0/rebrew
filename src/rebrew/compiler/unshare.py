"""Experimental rootless image runner for explicitly opted-in verification.

Docker prepares an immutable local image once. Compiler invocations use the
packaged native namespace helper and a disposable rootless overlay. This is a
limited MSVC/Wine backend, not a general OCI runtime or a Docker security peer.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import threading
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any

from rebrew.compiler.temp_dirs import remove_temp_dir, writable_temp_dir, xdg_cache_home
from rebrew.errors import RebrewError
from rebrew.utils import container_runtime, file_lock, run_process_group

__all__ = ["UnshareError", "backend_identity", "prepare_backend", "run_unshare"]

_PREPARE_LOCK = threading.RLock()
_SOURCE = Path(__file__).with_name("unshare_runner.c")
_CACHE_ABI = "2"


class UnshareError(RebrewError, RuntimeError):
    """The experimental runner could not prepare or execute a compile."""


@lru_cache(maxsize=1)
def backend_identity() -> str:
    """Identify the native setup code and Python profile builder in cache keys."""
    digest = hashlib.sha256(_SOURCE.read_bytes() + Path(__file__).read_bytes()).hexdigest()
    return f"experimental-unshare-{_CACHE_ABI}-{digest}"


def _cache_root() -> Path:
    root = xdg_cache_home() / "rebrew" / "experimental-unshare"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or root.stat().st_uid != os.getuid():
        raise UnshareError(f"experimental cache must be an owned directory: {root}")
    root.chmod(0o700)
    if any(c in str(root.resolve()) for c in ",:\\\n\r"):
        raise UnshareError(
            "experimental cache path cannot contain comma, colon, backslash or newline"
        )
    return root


def _command(args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        return run_process_group(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UnshareError(f"experimental runner command failed: {args[0]}: {exc}") from exc


def _require_success(result: subprocess.CompletedProcess[str], what: str) -> None:
    if result.returncode:
        raise UnshareError(f"{what}: {(result.stderr or result.stdout).strip()[-2000:]}")


def _helper(root: Path) -> Path:
    directory = root / "helpers" / backend_identity()
    helper = directory / "runner"
    manifest = directory / "sha256"
    if helper.is_file() and manifest.is_file():
        if hashlib.sha256(helper.read_bytes()).hexdigest() == manifest.read_text().strip():
            return helper
        raise UnshareError(f"experimental helper failed its digest check; remove {directory}")
    cc, pkg = shutil.which("cc"), shutil.which("pkg-config")
    if not cc or not pkg:
        raise UnshareError(
            "--experimental-unshare needs cc, pkg-config and json-c development files"
        )
    flags = _command([pkg, "--cflags", "--libs", "json-c"])
    _require_success(flags, "json-c development files missing (install libjson-c-dev/json-c)")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    partial = directory / "runner.partial"
    try:
        build = _command(
            [
                cc,
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(_SOURCE),
                "-o",
                str(partial),
                *shlex.split(flags.stdout),
            ]
        )
        _require_success(build, "could not build experimental namespace helper")
        partial.chmod(0o700)
        digest = hashlib.sha256(partial.read_bytes()).hexdigest()
        partial.replace(helper)
        manifest.write_text(digest + "\n")
    finally:
        partial.unlink(missing_ok=True)
    return helper


def _unpack(archive: Path, destination: Path) -> None:
    """Extract local image contents before links; never write through a link."""
    links: list[tarfile.TarInfo] = []
    directories: list[tuple[Path, int, float]] = []
    with tarfile.open(archive) as stream:
        for member in stream:
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise UnshareError(f"unsafe image archive path: {member.name}")
            target = destination.joinpath(*relative.parts)
            if member.issym() or member.islnk():
                links.append(member)
            elif member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                directories.append((target, member.mode & 0o1777, member.mtime))
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = stream.extractfile(member)
                if source is None:
                    raise UnshareError(f"image archive has no bytes for {member.name}")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(member.mode & 0o1777)
                os.utime(target, (member.mtime, member.mtime))
            elif not (member.ischr() or member.isblk() or member.isfifo()):
                raise UnshareError(f"unsupported image archive entry: {member.name}")
        # Absolute symlinks refer to container paths. Install them only after all
        # writes, so an image cannot redirect extraction onto the host.
        for member in sorted(links, key=lambda row: row.issym()):
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.parent.resolve().is_relative_to(destination):
                raise UnshareError(f"image link parent escapes rootfs: {member.name}")
            if member.issym():
                target.symlink_to(member.linkname)
                os.utime(target, (member.mtime, member.mtime), follow_symlinks=False)
            else:
                original = destination / member.linkname
                if not original.resolve().is_relative_to(destination) or not original.is_file():
                    raise UnshareError(f"unsafe image hard link: {member.name}")
                os.link(original, target)
    for directory, mode, mtime in reversed(directories):
        directory.chmod(mode)
        os.utime(directory, (mtime, mtime), follow_symlinks=False)


def _image(root: Path, image_id: str) -> tuple[Path, dict[str, Any]]:
    directory = root / "images-v2" / image_id.removeprefix("sha256:")
    manifest = directory / "image.json"
    if manifest.is_file() and (directory / "rootfs").is_dir():
        info = json.loads(manifest.read_text())
        if info.get("Id") != image_id:
            raise UnshareError(f"experimental image cache identity mismatch: {directory}")
        return directory / "rootfs", info
    runtime = container_runtime()
    inspected = _command([runtime, "image", "inspect", image_id])
    _require_success(inspected, f"cannot inspect admitted image {image_id}")
    info = json.loads(inspected.stdout)[0]
    if info.get("Id") != image_id or info.get("Config", {}).get("User") not in (
        "rebrew",
        "1000",
        "1000:1000",
    ):
        raise UnshareError("experimental image must retain the admitted id and use UID/GID 1000")
    directory.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="prepare-", dir=directory.parent))
    name = "rebrew-unshare-export-" + os.urandom(6).hex()
    try:
        created = _command(
            [
                runtime,
                "create",
                "--pull=never",
                "--network=none",
                "--name",
                name,
                "--entrypoint",
                "/bin/true",
                image_id,
            ]
        )
        _require_success(created, "cannot create image-export container")
        archive = staging / "rootfs.tar"
        exported = _command([runtime, "export", "--output", str(archive), name])
        _require_success(exported, "cannot export admitted image")
        filesystem = staging / "rootfs"
        filesystem.mkdir()
        _unpack(archive, filesystem)
        archive.unlink()
        _initialize_wineprefix(filesystem, info, _helper(root))
        (staging / "image.json").write_text(json.dumps(info) + "\n")
        staging.replace(directory)
    finally:
        try:
            removed = _command([runtime, "rm", "--force", name])
            _require_success(removed, "cannot remove image-export container")
        except UnshareError as exc:
            logging.getLogger(__name__).warning("image-export cleanup failed for %s: %s", name, exc)
        if staging.exists():
            shutil.rmtree(staging)
    return directory / "rootfs", info


def _remove_bundle(bundle: Path) -> None:
    """Remove private overlay work, including overlayfs mode-000 directories."""
    for parent, directories, _ in os.walk(bundle, topdown=True, followlinks=False):
        for name in directories:
            directory = Path(parent) / name
            if not directory.is_symlink():
                directory.chmod(directory.stat().st_mode | 0o700)
    remove_temp_dir(bundle)


def _initialize_wineprefix(rootfs: Path, info: dict[str, Any], helper: Path) -> None:
    """Seed Wine once before publishing the image cache; compiles keep private overlays."""
    bundle = writable_temp_dir("rebrew_unshare_")
    try:
        for child in ("rootfs", "upper", "overlay-work", "work"):
            (bundle / child).mkdir()
        prefix = rootfs / "opt/wineprefix"
        if not prefix.resolve().is_relative_to(rootfs.resolve()):
            raise UnshareError("cached Wine prefix escapes the prepared image")
        prefix.mkdir(parents=True, exist_ok=True)
        profile = _profile(
            rootfs,
            info,
            bundle,
            [
                "-c",
                "WINEPREFIX=/work /usr/bin/wine wineboot -u && WINEPREFIX=/work /usr/bin/wineserver -w",
            ],
            "/bin/sh",
            prefix,
            [],
            {},
        )
        path = bundle / "config.json"
        path.write_text(json.dumps(profile) + "\n")
        result = _command([str(helper), str(path)], timeout=120)
        _require_success(result, "cannot initialize cached Wine prefix")
    finally:
        _remove_bundle(bundle)


def prepare_backend() -> Path:
    """Check prerequisites and build the opt-in native helper once, under a lock."""
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise UnshareError("--experimental-unshare currently requires Linux x86_64")
    if os.geteuid() == 0:
        raise UnshareError("--experimental-unshare must run as an unprivileged user")
    root = _cache_root()
    with _PREPARE_LOCK, file_lock(root / "prepare.lock"):
        return _helper(root)


def _profile(
    rootfs: Path,
    info: dict[str, Any],
    bundle: Path,
    args: list[str],
    entrypoint: str | None,
    workdir: Path,
    mounts: list[tuple[str, str]],
    env: dict[str, str],
    project_cwd: Path | None = None,
) -> dict[str, Any]:
    destination = "/work"
    cwd = "/work"
    if project_cwd is not None:
        destination = str(workdir.resolve())
        resolved_cwd = project_cwd.resolve()
        if not resolved_cwd.is_relative_to(workdir.resolve()):
            raise UnshareError("CMake cwd must be inside the mounted project root")
        cwd = str(resolved_cwd)
    config = info["Config"]
    command = [entrypoint] if entrypoint else config.get("Entrypoint")
    if (
        not command
        or len(command) != 1
        or not isinstance(command[0], str)
        or not command[0].startswith("/")
    ):
        raise UnshareError("experimental image requires one absolute entrypoint")
    environment = dict(item.split("=", 1) for item in config.get("Env", []) if "=" in item)
    environment.update(env)
    environment.setdefault("XDG_CACHE_HOME", "/tmp")
    if (
        environment.get("HOME") != "/home/rebrew"
        or environment.get("WINEPREFIX") != "/opt/wineprefix"
    ):
        raise UnshareError(
            "experimental image requires HOME=/home/rebrew and WINEPREFIX=/opt/wineprefix"
        )
    profile_mounts: list[dict[str, Any]] = [
        {"destination": "/proc", "type": "proc", "source": "proc"},
        {
            "destination": "/dev",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
        },
        {
            "destination": "/dev/pts",
            "type": "devpts",
            "source": "devpts",
            "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"],
        },
        {
            "destination": "/dev/shm",
            "type": "tmpfs",
            "source": "shm",
            "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"],
        },
        # A same-path project under /tmp must not be hidden by this mount.
        {
            "destination": "/tmp",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": ["nosuid", "nodev", "mode=1777"],
        },
        {
            "destination": destination,
            "type": "bind",
            "source": str(workdir.resolve()),
            "options": ["rbind", "rw", "nosuid", "nodev"],
        },
    ]
    for destination in ("/opt/wineprefix", "/home/rebrew"):
        profile_mounts.append(
            {
                "destination": destination,
                "type": "bind",
                "source": str(bundle / "rootfs") + destination,
                "options": ["rbind", "rw", "nosuid", "nodev"],
            }
        )
    profile_mounts.extend(
        {
            "destination": destination,
            "type": "bind",
            "source": str(Path(source).resolve()),
            "options": ["rbind", "ro", "nosuid", "nodev"],
        }
        for source, destination in mounts
    )
    return {
        "ociVersion": "1.0.0",
        "process": {
            "terminal": False,
            "user": {"uid": 1000, "gid": 1000},
            "args": [*command, *args],
            "env": [f"{k}={v}" for k, v in environment.items()],
            "cwd": cwd,
            "capabilities": {
                k: [] for k in ("bounding", "effective", "inheritable", "permitted", "ambient")
            },
            "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
            "noNewPrivileges": True,
        },
        "root": {"path": str(rootfs), "readonly": True},
        "hostname": "rebrew",
        "mounts": profile_mounts,
        "linux": {
            "namespaces": [
                {"type": k} for k in ("pid", "network", "ipc", "uts", "user", "cgroup", "mount")
            ],
            "maskedPaths": [
                "/proc/acpi",
                "/proc/asound",
                "/proc/kcore",
                "/proc/keys",
                "/proc/latency_stats",
                "/proc/timer_list",
                "/proc/timer_stats",
                "/proc/sched_debug",
                "/sys/firmware",
                "/proc/scsi",
            ],
            "readonlyPaths": [
                "/proc/bus",
                "/proc/fs",
                "/proc/irq",
                "/proc/sys",
                "/proc/sysrq-trigger",
            ],
            "uidMappings": [{"containerID": 1000, "hostID": os.getuid(), "size": 1}],
            "gidMappings": [{"containerID": 1000, "hostID": os.getgid(), "size": 1}],
        },
    }


def run_unshare(
    image_id: str,
    args: list[str],
    *,
    entrypoint: str | None,
    workdir: Path,
    mounts: list[tuple[str, str]],
    env: dict[str, str],
    timeout: int,
    project_cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one compiler in disposable namespaces; never fall back to Docker."""
    if (
        len(image_id) != 71
        or not image_id.startswith("sha256:")
        or any(c not in "0123456789abcdef" for c in image_id[7:])
    ):
        raise UnshareError("experimental runner requires an admitted immutable image id")
    helper = prepare_backend()
    root = _cache_root()
    bundle = writable_temp_dir("rebrew_unshare_")
    try:
        if any(c in str(bundle) for c in ",:\\\n\r"):
            raise UnshareError(
                "experimental runtime path contains an unsupported overlay separator"
            )
        with _PREPARE_LOCK, file_lock(root / "prepare.lock"):
            rootfs, info = _image(root, image_id)
        for child in ("rootfs", "upper", "overlay-work"):
            (bundle / child).mkdir()
        profile = _profile(
            rootfs, info, bundle, args, entrypoint, workdir, mounts, env, project_cwd
        )
        path = bundle / "config.json"
        path.write_text(json.dumps(profile) + "\n")
        result = _command([str(helper), str(path)], timeout=timeout)
        if result.returncode == 125 and result.stderr.startswith("rebrew-unshare:"):
            raise UnshareError(result.stderr.strip() or "experimental namespace setup failed")
        return result
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        raise UnshareError(f"experimental runner preparation failed: {exc}") from exc
    finally:
        _remove_bundle(bundle)
