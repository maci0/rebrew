"""Experimental rootless image runner for explicitly opted-in verification.

Docker prepares an immutable local image once. Compiler invocations use the
packaged native namespace helper and a disposable rootless overlay. This is a
limited MSVC/Wine backend, not a general OCI runtime or a Docker security peer.
"""

from __future__ import annotations

import threading
from functools import lru_cache
from pathlib import Path, PurePosixPath
lazy import hashlib
lazy import json
lazy import logging
lazy import os
lazy import platform
lazy import shlex
lazy import shutil
lazy import subprocess
lazy import tarfile
lazy import tempfile
lazy from typing import Any

from rebrew.errors import RebrewError
lazy from rebrew.compiler.temp_dirs import remove_temp_dir, writable_temp_dir, xdg_cache_home
lazy from rebrew.utils import container_runtime, file_lock, run_process_group

__all__ = ["UnshareError", "backend_identity", "prepare_backend", "run_unshare"]

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
    if root.is_symlink() or root.stat().st_uid != os.getuid():
        raise UnshareError(f"experimental cache must be an owned directory: {root}")
    root.chmod(0o700)
    if any(c in str(root.resolve()) for c in ",:\\\n\r"):
        raise UnshareError(
            "experimental cache path cannot contain comma, colon, backslash or newline"
        )
    return root


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
        info = json.loads(manifest.read_text(encoding="utf-8"))
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
        (staging / "image.json").write_text(json.dumps(info) + "\n", encoding="utf-8")
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
        path.write_text(json.dumps(profile) + "\n", encoding="utf-8")
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
        path.write_text(json.dumps(profile) + "\n", encoding="utf-8")
        result = _command([str(helper), str(path)], timeout=timeout)
        if result.returncode == 125 and result.stderr.startswith("rebrew-unshare:"):
            raise UnshareError(result.stderr.strip() or "experimental namespace setup failed")
        return result
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        raise UnshareError(f"experimental runner preparation failed: {exc}") from exc
    finally:
        _remove_bundle(bundle)
