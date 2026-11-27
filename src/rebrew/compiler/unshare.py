"""Experimental rootless image runner, used when ``execution_backend = "unshare"``.

Docker prepares an immutable local image once. Compiler invocations use the
packaged native namespace helper and a disposable rootless overlay. This is a
limited MSVC/Wine backend, not a general OCI runtime or a Docker security peer.

Under :func:`serve_sessions` (``rebrew build warm-sessions``), runs that pass a
``session`` reuse a long-lived sandbox built from identical inputs instead, so
Wine's session boot is paid once per sandbox rather than once per run.
"""

from __future__ import annotations

import contextlib
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
lazy import hashlib
lazy import logging
lazy import os
lazy import platform
lazy import shlex
lazy import shutil
lazy import socket
lazy import subprocess
lazy import sys
lazy import tarfile
lazy import tempfile
lazy import time
lazy from collections.abc import Iterator
lazy from dataclasses import asdict
lazy from typing import Any

lazy import msgspec

from rebrew.errors import RebrewError
lazy from rebrew.compiler.temp_dirs import remove_temp_dir, writable_temp_dir, xdg_cache_home
lazy from rebrew.utils import atomic_write_text, container_runtime, file_lock, run_process_group

__all__ = [
    "SESSIONS_ENV",
    "UnshareError",
    "backend_identity",
    "forget_image_tag",
    "prepare_backend",
    "record_image_tag",
    "recorded_image_id",
    "run_unshare",
    "serve_sessions",
]

_PREPARE_LOCK = threading.RLock()
_SOURCE = Path(__file__).with_name("unshare_runner.c")
_CACHE_ABI = "3"


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
    if root.is_symlink() or (hasattr(os, "getuid") and root.stat().st_uid != os.getuid()):
        raise UnshareError(f"experimental cache must be an owned directory: {root}")
    root.chmod(0o700)
    if any(c in str(root.resolve()) for c in ",:\\\n\r"):
        raise UnshareError(
            "experimental cache path cannot contain comma, colon, backslash or newline"
        )
    return root


#: Tag -> image id each tag was last admitted as, so a compile can reuse its
#: exported image without asking the container runtime again.
_TAGS_FILE = "image-tags.json"


def _tags(root: Path) -> dict[str, str]:
    try:
        data = msgspec.json.decode((root / _TAGS_FILE).read_bytes())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise UnshareError(
            f"invalid experimental image tag record: {root / _TAGS_FILE}: {exc}"
        ) from exc
    if not isinstance(data, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in data.items()
    ):
        raise UnshareError(f"invalid experimental image tag record: {root / _TAGS_FILE}")
    return data


def _update_tags(change: dict[str, str | None]) -> None:
    root = _cache_root()
    with _PREPARE_LOCK, file_lock(root / "prepare.lock"):
        tags = _tags(root)
        for tag, image_id in change.items():
            if image_id is None:
                tags.pop(tag, None)
            else:
                tags[tag] = image_id
        atomic_write_text(
            root / _TAGS_FILE,
            msgspec.json.format(msgspec.json.encode(tags, order="sorted"), indent=2).decode("utf-8")
            + "\n",
        )


def record_image_tag(tag: str, image_id: str) -> None:
    """Remember that *tag* was admitted as *image_id*."""
    _update_tags({tag: image_id})


def forget_image_tag(tag: str | None = None) -> None:
    """Drop the admission record of *tag* (every tag when ``None``) after a retag."""
    if tag is not None:
        _update_tags({tag: None})
        return
    root = _cache_root()
    with _PREPARE_LOCK, file_lock(root / "prepare.lock"):
        (root / _TAGS_FILE).unlink(missing_ok=True)


def recorded_image_id(tag: str) -> str:
    """The id *tag* was last admitted as, when that image is already exported; else ``""``.

    The exported manifest must name the same id and still list *tag*, so a record
    whose export was removed or belongs to another tag falls back to admission.
    """
    root = _cache_root()
    image_id = _tags(root).get(tag, "")
    if not image_id.startswith("sha256:"):
        return ""
    directory = root / "images-v2" / image_id.removeprefix("sha256:")
    try:
        info = msgspec.json.decode((directory / "image.json").read_bytes())
    except OSError, ValueError:
        return ""
    if (
        isinstance(info, dict)
        and info.get("Id") == image_id
        and tag in (info.get("RepoTags") or [])
        and (directory / "rootfs").is_dir()
    ):
        return image_id
    return ""


def _command(
    args: list[str], *, timeout: int = 120, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    try:
        return run_process_group(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
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
    # Read the current toolchain provenance up front: the cached helper is
    # only reusable when both the compiler identity and the epoch it was
    # built with still match.  Comparing the recorded values in the hit
    # path (instead of merely recording them) is what makes a toolchain
    # upgrade rebuild instead of reusing a stale helper.
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "0")
    if not epoch.isdigit():
        epoch = "0"
    cc, pkg = shutil.which("cc"), shutil.which("pkg-config")
    if not cc or not pkg:
        raise UnshareError(
            "--experimental-unshare needs cc, pkg-config and json-c development files"
        )
    cc_ver = _command([cc, "--version"])
    cc_version = (
        (cc_ver.stdout or "").splitlines()[0]
        if cc_ver.returncode == 0 and cc_ver.stdout
        else "unknown"
    )
    if helper.is_file() and manifest.is_file():
        recorded = manifest.read_text(encoding="utf-8").strip().splitlines()
        if recorded and hashlib.sha256(helper.read_bytes()).hexdigest() == recorded[0]:
            # A manifest written before the cc-version line existed has no
            # provenance; rebuild once to record it.  A manifest whose cc
            # or epoch no longer matches the current toolchain is likewise
            # stale: fall through to rebuild rather than reuse it.
            if (
                len(recorded) >= 3
                and recorded[1] == f"cc={cc_version}"
                and recorded[2] == f"epoch={epoch}"
            ):
                return helper
            if len(recorded) == 1:
                pass  # fall through to rebuild with provenance
            elif len(recorded) >= 3:
                pass  # stale compiler or epoch: rebuild below
            else:
                return helper
        else:
            raise UnshareError(f"experimental helper failed its digest check; remove {directory}")
    flags = _command([pkg, "--cflags", "--libs", "json-c"])
    _require_success(flags, "json-c development files missing (install libjson-c-dev/json-c)")
    # Reproducible helper build: honor SOURCE_DATE_EPOCH (gcc uses it for
    # __DATE__/__TIME__ when -Wdate-time is on), map the full source path
    # and the build directory out of DWARF/__FILE__, strip the compiler
    # ident, and pin locale/TZ so the cached binary does not depend on the
    # caller's environment. The cache identity (backend_identity) already
    # hashes the source; the cc/epoch comparison in the hit path above
    # rebuilds when the toolchain or epoch changed since the cached build.
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    partial = directory / "runner.partial"
    try:
        build_env = dict(os.environ)
        build_env.update(
            {
                "SOURCE_DATE_EPOCH": epoch,
                "TZ": "UTC",
                "LC_ALL": "C",
                "ZERO_AR_DATE": "1",
            }
        )
        build = _command(
            [
                cc,
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fstack-protector-strong",
                "-D_FORTIFY_SOURCE=2",
                "-fPIE",
                "-pie",
                "-Wl,-z,relro,-z,now",
                "-Wl,-z,noexecstack",
                "-ffile-prefix-map=" + str(_SOURCE.parent) + "=.",
                "-ffile-prefix-map=" + str(Path.cwd()) + "=.",
                "-fdebug-prefix-map=" + str(_SOURCE.parent) + "=.",
                "-fdebug-prefix-map=" + str(Path.cwd()) + "=.",
                "-fno-ident",
                "-Wdate-time",
                # The binary carries no build-id: a GNU build-id is a hash of
                # the ELF contents, which differ between machines only when a
                # prefix map or a toolchain revision differs, and the digest
                # recorded below already identifies this exact output.  A
                # build-id therefore only varies the binary it indexes.
                "-Wl,--build-id=none",
                "-s",
                str(_SOURCE),
                "-o",
                str(partial),
                *shlex.split(flags.stdout),
            ],
            env=build_env,
        )
        _require_success(build, "could not build experimental namespace helper")
        partial.chmod(0o700)
        digest = hashlib.sha256(partial.read_bytes()).hexdigest()
        partial.replace(helper)
        manifest.write_text(f"{digest}\ncc={cc_version}\nepoch={epoch}\n", encoding="utf-8")
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
                if target.exists() and target.is_symlink():
                    raise UnshareError(f"unsafe image archive path: {member.name}")
                target.mkdir(parents=True, exist_ok=True)
                if not target.is_relative_to(destination.resolve()):
                    raise UnshareError(f"unsafe image archive path: {member.name}")
                directories.append((target, member.mode & 0o1777, member.mtime))
            elif member.isfile():
                if target.parent.exists() and target.parent.is_symlink():
                    raise UnshareError(f"unsafe image archive path: {member.name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                if not target.parent.resolve().is_relative_to(destination.resolve()):
                    raise UnshareError(f"unsafe image archive path: {member.name}")
                source = stream.extractfile(member)
                if source is None:
                    raise UnshareError(f"image archive has no bytes for {member.name}")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(member.mode & 0o1777)
                os.utime(target, (member.mtime, member.mtime))
            elif member.ischr() or member.isblk() or member.isfifo():
                # Device/FIFO nodes carry no payload and would only
                # materialize host device handles inside the staged rootfs;
                # refuse them outright rather than silently skipping, so a
                # compromised image fails closed.
                raise UnshareError(f"unsafe image archive entry: {member.name}")
            else:
                raise UnshareError(f"unsupported image archive entry: {member.name}")
        # Absolute symlinks refer to container paths. Install them only after all
        # writes, so an image cannot redirect extraction onto the host.
        for member in sorted(links, key=lambda row: row.issym()):
            target = destination / member.name
            if not target.parent.resolve().is_relative_to(destination):
                raise UnshareError(f"image link parent escapes rootfs: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                target.symlink_to(member.linkname)
                os.utime(target, (member.mtime, member.mtime), follow_symlinks=False)
            else:
                hardlink = PurePosixPath(member.linkname)
                if hardlink.is_absolute() or ".." in hardlink.parts or not hardlink.parts:
                    raise UnshareError(f"unsafe image hard link: {member.name}")
                original = destination.joinpath(*hardlink.parts)
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
        info = msgspec.json.decode(manifest.read_bytes())
        if not isinstance(info, dict) or not isinstance(info.get("Config"), dict):
            raise UnshareError(f"invalid experimental image cache metadata: {directory}")
        if info.get("Id") != image_id:
            raise UnshareError(f"experimental image cache identity mismatch: {directory}")
        return directory / "rootfs", info
    runtime = container_runtime()
    inspected = _command([runtime, "image", "inspect", image_id])
    _require_success(inspected, f"cannot inspect admitted image {image_id}")
    records = msgspec.json.decode(inspected.stdout)
    if (
        not isinstance(records, list)
        or len(records) != 1
        or not isinstance(records[0], dict)
        or not isinstance(records[0].get("Config"), dict)
    ):
        raise UnshareError("invalid experimental image inspection metadata")
    info = records[0]
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
        (staging / "image.json").write_text(
            msgspec.json.encode(info).decode("utf-8") + "\n", encoding="utf-8"
        )
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
        path.write_text(msgspec.json.encode(profile).decode("utf-8") + "\n", encoding="utf-8")
        result = _command([str(helper), str(path)], timeout=120)
        _require_success(result, "cannot initialize cached Wine prefix")
    finally:
        _remove_bundle(bundle)


def prepare_backend() -> Path:
    """Check prerequisites and build the opt-in native helper once, under a lock."""
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise UnshareError("--experimental-unshare currently requires Linux x86_64")
    # os.geteuid is POSIX-only; this backend is Linux-only by the check above,
    # but a capability probe keeps the intent explicit and avoids AttributeError
    # if platform detection ever changes.
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise UnshareError("--experimental-unshare must run as an unprivileged user")
    root = _cache_root()
    with _PREPARE_LOCK, file_lock(root / "prepare.lock"):
        return _helper(root)


def _process_args(info: dict[str, Any], entrypoint: str | None, args: list[str]) -> list[str]:
    """The argv one run executes: *entrypoint* (default: the image's) then *args*."""
    command = [entrypoint] if entrypoint else info["Config"].get("Entrypoint")
    if (
        not command
        or len(command) != 1
        or not isinstance(command[0], str)
        or not command[0].startswith("/")
    ):
        raise UnshareError("experimental image requires one absolute entrypoint")
    return [*command, *args]


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
    process_args = _process_args(info, entrypoint, args)
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
            "args": process_args,
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
            # getuid/getgid are POSIX-only; prepare_backend() already gated
            # this to Linux, so the probe is unreachable on Windows but keeps
            # the mapping honest if the gate ever widens.
            "uidMappings": [
                {
                    "containerID": 1000,
                    "hostID": os.getuid() if hasattr(os, "getuid") else 1000,
                    "size": 1,
                }
            ],
            "gidMappings": [
                {
                    "containerID": 1000,
                    "hostID": os.getgid() if hasattr(os, "getgid") else 1000,
                    "size": 1,
                }
            ],
        },
    }


def _admitted(image_id: str) -> bool:
    return (
        len(image_id) == 71
        and image_id.startswith("sha256:")
        and all(c in "0123456789abcdef" for c in image_id[7:])
    )


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
    session: list[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run one compiler in disposable namespaces; never fall back to Docker.

    *session*, with *project_cwd*, is the argv that starts state later runs may
    share (Wine's persistent ``wineserver -p``). When :data:`SESSIONS_ENV`
    names a running :func:`serve_sessions`, the run goes to a warm sandbox built
    from the same image, session, project root, mounts and environment; with no
    server answering it runs in a fresh sandbox, as without *session*.
    """
    if not _admitted(image_id):
        raise UnshareError("experimental runner requires an admitted immutable image id")
    if session is not None and project_cwd is None:
        raise UnshareError("a warm session needs a same-path project mount (project_cwd)")
    address = os.environ.get(SESSIONS_ENV, "")
    result = None
    if session is not None and project_cwd is not None and address:
        key = _SessionKey(
            image_id,
            tuple(session),
            str(workdir.resolve()),
            tuple((str(Path(source).resolve()), target) for source, target in mounts),
            tuple(sorted(env.items())),
        )
        request = _SessionRequest(key, entrypoint, tuple(args), str(project_cwd.resolve()), timeout)
        result = _run_in_session(address, request)
    if result is None:
        result = _run_fresh(image_id, args, entrypoint, workdir, mounts, env, timeout, project_cwd)
    if result.returncode == 125 and result.stderr.startswith("rebrew-unshare:"):
        raise UnshareError(result.stderr.strip() or "experimental namespace setup failed")
    return result


def _run_fresh(
    image_id: str,
    args: list[str],
    entrypoint: str | None,
    workdir: Path,
    mounts: list[tuple[str, str]],
    env: dict[str, str],
    timeout: int,
    project_cwd: Path | None,
) -> subprocess.CompletedProcess[str]:
    """Run once in a sandbox of its own, removed afterwards."""
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
        path.write_text(msgspec.json.encode(profile).decode("utf-8") + "\n", encoding="utf-8")
        return _command([str(helper), str(path)], timeout=timeout)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        raise UnshareError(f"experimental runner preparation failed: {exc}") from exc
    finally:
        _remove_bundle(bundle)


# ---------------------------------------------------------------------------
# Warm sessions: long-lived sandboxes shared by runs with identical inputs
# ---------------------------------------------------------------------------

#: Names the control socket of a running :func:`serve_sessions`; the build
#: command it runs inherits it.
SESSIONS_ENV = "REBREW_UNSHARE_SESSIONS"
#: Largest request in bytes, and REQUEST_MAX in unshare_runner.c. It stays
#: below the default socket send buffer, which bounds one SOCK_SEQPACKET packet.
_SESSION_REQUEST_MAX = 128 * 1024
#: Largest server answer in bytes: a JSON status or error message.
_SESSION_ANSWER_MAX = 64 * 1024
#: A worker answers each run with its exit status as a native int32.
_STATUS_BYTES = 4
#: Statuses from here up are a signal death (128 + signal); that sandbox is not reused.
_SIGNALLED_STATUS = 128
#: Seconds past the run's own timeout a client waits for the server to answer.
_SESSION_ANSWER_GRACE_S = 30
#: Seconds a stopped sandbox gets to exit after its channel closes.
_SESSION_STOP_TIMEOUT_S = 10
#: Characters of a stopped sandbox's log kept in an error message.
_LOG_TAIL_CHARS = 2000


@dataclass(frozen=True)
class _SessionKey:
    """Every input a warm sandbox is built from; runs share one only when all are equal."""

    image_id: str
    session: tuple[str, ...]
    workdir: str
    mounts: tuple[tuple[str, str], ...]
    env: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class _SessionRequest:
    """One run for a warm sandbox: its key and what may differ per run."""

    key: _SessionKey
    entrypoint: str | None
    args: tuple[str, ...]
    cwd: str
    timeout: int


@contextlib.contextmanager
def _short_path(address: str) -> Iterator[str]:
    """*address* spelled through a descriptor of its directory, so a deep cache
    home stays under the 108-byte AF_UNIX path limit."""
    path = Path(address)
    directory = os.open(path.parent, os.O_PATH | os.O_CLOEXEC)
    try:
        yield f"/proc/self/fd/{directory}/{path.name}"
    finally:
        os.close(directory)


def _universal_newlines(data: bytes) -> str:
    """*data* decoded as ``subprocess.run(text=True, errors="replace")`` decodes it."""
    return data.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")


def _run_in_session(
    address: str, request: _SessionRequest
) -> subprocess.CompletedProcess[str] | None:
    """Run *request* in a warm sandbox; ``None`` when no server listens at *address*."""
    log = logging.getLogger(__name__)
    message = msgspec.json.encode(asdict(request))
    if len(message) > _SESSION_REQUEST_MAX:
        log.warning("warm session request is %d bytes; running in a fresh sandbox", len(message))
        return None
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
        try:
            with _short_path(address) as path:
                connection.connect(path)
        except FileNotFoundError, ConnectionRefusedError:
            log.warning("%s=%s does not answer; running in a fresh sandbox", SESSIONS_ENV, address)
            return None
        connection.settimeout(request.timeout + _SESSION_ANSWER_GRACE_S)
        with (
            open(os.memfd_create("rebrew-stdout", os.MFD_CLOEXEC), "w+b") as out,
            open(os.memfd_create("rebrew-stderr", os.MFD_CLOEXEC), "w+b") as err,
        ):
            try:
                socket.send_fds(connection, [message], [out.fileno(), err.fileno()])
                answer = connection.recv(_SESSION_ANSWER_MAX)
            except TimeoutError as exc:
                raise UnshareError(
                    f"warm session server {address} gave no answer within "
                    f"{request.timeout + _SESSION_ANSWER_GRACE_S}s"
                ) from exc
            except OSError as exc:
                raise UnshareError(f"warm session server {address} failed: {exc}") from exc
            try:
                reply = msgspec.json.decode(answer) if answer else {}
            except ValueError:
                reply = {}
            if isinstance(reply, dict) and isinstance(reply.get("error"), str):
                raise UnshareError(reply["error"])
            if not isinstance(reply, dict) or type(reply.get("returncode")) is not int:
                raise UnshareError(f"warm session server {address} closed without an answer")
            out.seek(0)
            err.seek(0)
            stdout, stderr = _universal_newlines(out.read()), _universal_newlines(err.read())
    return subprocess.CompletedProcess([address], reply["returncode"], stdout, stderr)


def _text(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError(f"expected a string, got {type(value).__name__}")
    return value


def _pair(value: Any) -> tuple[str, str]:
    if not isinstance(value, list) or len(value) != 2:
        raise TypeError("expected a pair of strings")
    return _text(value[0]), _text(value[1])


def _decode_request(message: bytes) -> _SessionRequest:
    """The request in *message*; the control socket is a trust boundary."""
    try:
        raw = msgspec.json.decode(message)
        key = raw["key"]
        request = _SessionRequest(
            _SessionKey(
                _text(key["image_id"]),
                tuple(_text(arg) for arg in key["session"]),
                _text(key["workdir"]),
                tuple(_pair(mount) for mount in key["mounts"]),
                tuple(_pair(item) for item in key["env"]),
            ),
            None if raw["entrypoint"] is None else _text(raw["entrypoint"]),
            tuple(_text(arg) for arg in raw["args"]),
            _text(raw["cwd"]),
            raw["timeout"],
        )
    except (ValueError, KeyError, TypeError) as exc:
        raise UnshareError(f"malformed warm session request: {exc}") from exc
    workdir = Path(request.key.workdir)
    if (
        not _admitted(request.key.image_id)
        or not request.key.session
        or type(request.timeout) is not int
        or request.timeout < 1
        or not workdir.is_absolute()
    ):
        raise UnshareError("malformed warm session request")
    if not Path(request.cwd).resolve().is_relative_to(workdir.resolve()):
        raise UnshareError("CMake cwd must be inside the mounted project root")
    return request


class _SessionWorker:
    """One warm sandbox: a serving helper and the private bundle it overlays."""

    def __init__(self, key: _SessionKey) -> None:
        helper = prepare_backend()
        root = _cache_root()
        with _PREPARE_LOCK, file_lock(root / "prepare.lock"):
            rootfs, self._info = _image(root, key.image_id)
        self.key = key
        self._bundle = writable_temp_dir("rebrew_unshare_")
        try:
            if any(c in str(self._bundle) for c in ",:\\\n\r"):
                raise UnshareError(
                    "experimental runtime path contains an unsupported overlay separator"
                )
            for child in ("rootfs", "upper", "overlay-work"):
                (self._bundle / child).mkdir()
            workdir = Path(key.workdir)
            profile = _profile(
                rootfs,
                self._info,
                self._bundle,
                list(key.session[1:]),
                key.session[0],
                workdir,
                list(key.mounts),
                dict(key.env),
                workdir,
            )
            config = self._bundle / "config.json"
            config.write_text(msgspec.json.encode(profile).decode("utf-8") + "\n", encoding="utf-8")
            self._channel, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                with theirs, (self._bundle / "session.log").open("wb") as log:
                    self._process = subprocess.Popen(
                        [str(helper), "--serve", str(theirs.fileno()), str(config)],
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=log,
                        pass_fds=(theirs.fileno(),),
                        start_new_session=True,
                    )
            except BaseException:
                self._channel.close()
                raise
        except BaseException:
            _remove_bundle(self._bundle)
            raise

    def _log_tail(self) -> str:
        try:
            text = (self._bundle / "session.log").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        return f": {text.strip()[-_LOG_TAIL_CHARS:]}" if text.strip() else ""

    def run(self, request: _SessionRequest, fds: list[int], deadline: float) -> int:
        """Run *request* with *fds* as its stdout and stderr; return its exit status."""
        argv = _process_args(self._info, request.entrypoint, list(request.args))
        message = msgspec.json.encode({"args": argv, "cwd": request.cwd})
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            self._channel.settimeout(remaining)
            socket.send_fds(self._channel, [message], fds)
            status = self._channel.recv(_STATUS_BYTES)
        except TimeoutError as exc:
            raise UnshareError(
                f"warm session run timed out after {request.timeout} seconds"
            ) from exc
        except OSError as exc:
            raise UnshareError(f"warm session failed: {exc}{self._log_tail()}") from exc
        if len(status) != _STATUS_BYTES:
            raise UnshareError(f"warm session exited{self._log_tail()}")
        return int.from_bytes(status, sys.byteorder, signed=True)

    def interrupt(self) -> None:
        """Close the channel: the helper kills its namespace, and a run in flight fails."""
        with contextlib.suppress(OSError):  # already shut down by an earlier stop
            self._channel.shutdown(socket.SHUT_RDWR)

    def stop(self) -> None:
        """End the session, wait for the sandbox to exit and remove its bundle."""
        self.interrupt()
        self._channel.close()
        try:
            self._process.wait(timeout=_SESSION_STOP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait()
        try:
            _remove_bundle(self._bundle)
        except OSError as exc:
            # The stale-sandbox sweep reclaims it; the session itself is gone.
            logging.getLogger(__name__).warning(
                "warm session cleanup failed for %s: %s", self._bundle, exc
            )


class _SessionPool:
    """At most *limit* warm sandboxes, each running one request at a time."""

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._idle: list[_SessionWorker] = []  # least recently used first
        self._busy: set[_SessionWorker] = set()
        self._starting = 0
        self._closed = False
        self._changed = threading.Condition()

    def acquire(self, key: _SessionKey, deadline: float) -> _SessionWorker:
        """An idle sandbox for *key*, else a new one; at the limit, the least recently used idle one makes room."""
        evicted: _SessionWorker | None = None
        with self._changed:
            while True:
                if self._closed:
                    raise UnshareError("warm sessions are shutting down")
                for worker in reversed(self._idle):
                    if worker.key == key:
                        self._idle.remove(worker)
                        self._busy.add(worker)
                        return worker
                if len(self._idle) + len(self._busy) + self._starting < self._limit:
                    break
                if self._idle:
                    evicted = self._idle.pop(0)
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise UnshareError(
                        f"all {self._limit} warm sessions stayed busy past the run's timeout"
                    )
                self._changed.wait(remaining)
            self._starting += 1
        started: _SessionWorker | None = None
        try:
            if evicted is not None:
                evicted.stop()
            started = _SessionWorker(key)
        except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
            raise UnshareError(f"warm session preparation failed: {exc}") from exc
        finally:
            with self._changed:
                self._starting -= 1
                if started is not None:
                    self._busy.add(started)
                self._changed.notify_all()
        return started

    def release(self, worker: _SessionWorker, *, reusable: bool) -> None:
        """Return *worker* after a run; a sandbox that failed or was signalled is stopped."""
        with self._changed:
            self._busy.discard(worker)
            self._changed.notify_all()
            if reusable and not self._closed:
                self._idle.append(worker)
                return
        worker.stop()

    def close(self) -> None:
        """Stop every sandbox; runs still in flight end with an error."""
        with self._changed:
            self._closed = True
            idle, self._idle = self._idle, []
            for worker in self._busy:
                worker.interrupt()
        for worker in idle:
            worker.stop()
        with self._changed:
            self._changed.wait_for(
                lambda: not self._busy and not self._starting, _SESSION_STOP_TIMEOUT_S
            )


def _answer(connection: socket.socket, pool: _SessionPool) -> None:
    """Run one client's request in a warm sandbox and send its exit status or error."""
    fds: list[int] = []
    with connection:
        try:
            message, fds, flags, _ = socket.recv_fds(
                connection, _SESSION_REQUEST_MAX, 2, socket.MSG_CMSG_CLOEXEC
            )
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(fds) != 2:
                raise UnshareError("malformed warm session request")
            request = _decode_request(message)
            deadline = time.monotonic() + request.timeout
            worker = pool.acquire(request.key, deadline)
            status = _SIGNALLED_STATUS
            try:
                status = worker.run(request, fds, deadline)
            finally:
                pool.release(worker, reusable=status < _SIGNALLED_STATUS)
            answer: dict[str, int | str] = {"returncode": status}
        except UnshareError as exc:
            answer = {"error": str(exc)}
        finally:
            for fd in fds:
                os.close(fd)
        # A client that timed out or was interrupted has gone; nobody is left to tell.
        with contextlib.suppress(OSError):
            connection.send(msgspec.json.encode(answer))


def _accept(listener: socket.socket, pool: _SessionPool) -> None:
    """Answer each connection on its own thread until *listener* shuts down."""
    while True:
        try:
            connection, _ = listener.accept()
        except OSError:
            return  # shut down: the build command has finished
        threading.Thread(target=_answer, args=(connection, pool), daemon=True).start()


def serve_sessions(command: list[str], *, workers: int) -> int:
    """Run *command* with warm sandboxes for its unshare runs; return its exit status.

    The command inherits :data:`SESSIONS_ENV`. Each run that passes a session
    goes to an idle sandbox built from the same inputs, or a new one; at most
    *workers* exist at once, and each runs one request at a time with its own
    Wine prefix overlay. A run past its timeout kills its sandbox. Every sandbox
    stops when the command exits, or when this process dies.
    """
    directory = writable_temp_dir("rebrew_sessions_")
    address = str(directory / "control")
    pool = _SessionPool(workers)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        with _short_path(address) as path:
            listener.bind(path)
        listener.listen()
        threading.Thread(target=_accept, args=(listener, pool), daemon=True).start()
        child = subprocess.Popen(command, env={**os.environ, SESSIONS_ENV: address})
        try:
            return child.wait()
        except KeyboardInterrupt:
            # The terminal interrupted the command too; let it finish exiting.
            child.wait()
            raise
    finally:
        with contextlib.suppress(OSError):  # never bound, or already shut down
            listener.shutdown(socket.SHUT_RDWR)
        listener.close()
        pool.close()
        remove_temp_dir(directory)
