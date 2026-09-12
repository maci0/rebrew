"""toolchain.py — standardized toolchain invocation (docker-only for Windows/DOS).

Modeled on Godbolt / Compiler Explorer's convention: **one container image
per toolchain-version**, with the compiler behind a wrapper inside the image
so the host invocation is uniform — ``docker run <image> <compiler> <args>``.
The image encapsulates the runtime quirks (MSVC under wine, DCC/TCC under
DOSBox), so the host-side code never needs per-toolchain runner glue.

Execution is **docker-only for every Windows/DOS toolchain** (all wine- and
dosbox-runtime specs): the host never calls CL.EXE / DCC.EXE / TCC.EXE /
bcc32.exe directly, and there is no wine/wibo host fallback.  The docker
build source (Dockerfiles, wrapper scripts, the shared ``base``) lives in
the standalone **rebrew-toolchains** checkout — the sibling repo
(overridable via ``REBREW_TOOLCHAINS_DIR``) — so rebrew no longer vendors
build files in-repo; ``rebrew toolchain build``/``vendor`` read them from
there, and the smoke gate verifies the image output is byte-reproducible.
Native-Linux toolchains without an image (gcc-pe, the wcc 16-bit binary)
exec their vendored/PATH binary directly; they are not Windows binaries, so
no wine is involved.

A :class:`ToolchainSpec` describes how to invoke one compiler version:
its image tag, the compiler executable (and any wrapper), and the flag
style/object-format conventions the rest of rebrew needs to drive it.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tomllib
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rebrew.registry import RegistryError, merge_provider_dict
from rebrew.toolchain_data import BUILTIN_TOOLCHAINS
from rebrew.toolchain_paths import TOOLCHAINS_REPO_URL, toolchains_repo
from rebrew.toolchain_spec import ToolchainSpec
from rebrew.utils import container_runtime

_RUN_TIMEOUT = 300

_docker_available_cache: bool | None = None


class ToolchainError(RuntimeError):
    """The toolchain cannot be invoked (missing image/path/binary)."""


@dataclass
class RunResult:
    """Outcome of a toolchain invocation."""

    returncode: int
    stdout: str
    stderr: str
    backend: str  # "docker" | "native" (host wine/dosbox execution removed)

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def require_toolchains_repo() -> Path:
    """The rebrew-toolchains checkout, or an actionable error when missing.

    Only commands that actually consume the build source (``rebrew
    toolchain build``/``vendor``/``update``) call this — plain
    registry/status commands never touch the checkout."""
    repo = toolchains_repo()
    if not repo.is_dir():
        raise ToolchainError(
            f"rebrew-toolchains checkout not found at {repo} — the docker "
            f"build source lives there now (clone {TOOLCHAINS_REPO_URL} "
            "next to this repo, or set REBREW_TOOLCHAINS_DIR=<path>)"
        )
    return repo


# ---------------------------------------------------------------------------
# Registry assembly — built-ins + entry points + project-level overlay
# ---------------------------------------------------------------------------

#: setuptools entry-point group whose providers yield toolchain specs.  A
#: provider is a zero-arg callable returning ``dict[str, ToolchainSpec]``.
TOOLCHAIN_ENTRY_POINT_GROUP = "rebrew.toolchains"

#: Env var pointing at a directory of project-level toolchain ``*.toml``
#: files.  Each file is one or more ``name = { … }`` tables of
#: :class:`ToolchainSpec` fields — the project-level overlay that adds
#: custom compilers without touching rebrew source.
TOOLCHAIN_OVERLAY_ENV = "REBREW_TOOLCHAIN_OVERLAY_DIR"


def toolchain_from_toml(name: str, table: dict[str, Any], source: str) -> ToolchainSpec:
    """Build a :class:`ToolchainSpec` from a declarative TOML table.

    Only known spec fields are accepted — a typo'd key is a declaration
    error rather than a silent fallback to the field default."""
    known = set(ToolchainSpec.__dataclass_fields__) - {"name"}
    unknown = set(table) - known
    if unknown:
        raise RegistryError(
            f"bad toolchain {name!r} in {source}: unknown field(s) {sorted(unknown)}"
        )
    host_path = table.get("host_path")
    bits_raw = table.get("bits")
    return ToolchainSpec(
        name=name,
        image=table.get("image"),
        binary=str(table.get("binary") or ""),
        image_binary=table.get("image_binary"),
        runtime=str(table.get("runtime") or "native"),
        flags_style=str(table.get("flags_style") or "msvc"),
        obj_ext=str(table.get("obj_ext") or ".obj"),
        host_path=Path(host_path) if host_path else None,
        host_bin=str(table.get("host_bin") or "Bin"),
        tool_root=table.get("tool_root"),
        bits=int(bits_raw) if bits_raw else None,
        description=str(table.get("description") or ""),
    )


def toolchain_to_toml(spec: ToolchainSpec) -> dict[str, Any]:
    """Serialize a :class:`ToolchainSpec` into a TOML table.

    Defaults are dropped, so ``toolchain_from_toml`` round-trips it."""
    table: dict[str, Any] = {}
    for field in (
        "image",
        "binary",
        "image_binary",
        "runtime",
        "flags_style",
        "obj_ext",
        "host_bin",
        "tool_root",
        "description",
    ):
        value = getattr(spec, field)
        if value:
            table[field] = value
    if spec.host_path is not None:
        table["host_path"] = str(spec.host_path)
    if spec.bits is not None:
        table["bits"] = spec.bits
    return table


def _merge_entry_point_toolchains(registry: dict[str, ToolchainSpec]) -> None:
    """Merge every ``rebrew.toolchains`` entry-point provider into *registry*."""
    from rebrew.registry import entry_point_registrations, import_registration

    for reg in entry_point_registrations(TOOLCHAIN_ENTRY_POINT_GROUP):
        before = set(registry)
        merge_provider_dict(registry, import_registration(reg), reg.origin, group=reg.group)
        for name in set(registry) - before:
            TOOLCHAIN_ORIGINS[name] = f"entry-point:{reg.module}"


def _toolchain_overlay_dir() -> Path | None:
    """The project-level toolchain overlay dir, or None when unset."""
    env = os.environ.get(TOOLCHAIN_OVERLAY_ENV)
    if not env:
        return None
    path = Path(env)
    if not path.is_dir():
        raise ToolchainError(f"{TOOLCHAIN_OVERLAY_ENV}={env} is not a directory")
    return path


def _merge_toolchain_overlay(registry: dict[str, ToolchainSpec]) -> None:
    """Merge project-level ``*.toml`` toolchain files into *registry*."""
    from rebrew.registry import merge_into

    overlay = _toolchain_overlay_dir()
    if overlay is None:
        return
    for path in sorted(overlay.glob("*.toml")):
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ToolchainError(f"bad toolchain overlay {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ToolchainError(f"bad toolchain overlay {path}: must be a TOML table")
        for name, table in raw.items():
            if not isinstance(table, dict):
                raise ToolchainError(f"bad toolchain overlay {path}: {name!r} must be a table")
            spec = toolchain_from_toml(name, table, str(path))
            merge_into(registry, name, spec, f"data-file {path}", group="toolchains")
            TOOLCHAIN_ORIGINS[name] = f"data-file {path}"


def build_toolchain_registry() -> dict[str, ToolchainSpec]:
    """The full registry: packaged built-ins + entry points + TOML overlay.

    Merging order: built-ins first, then ``rebrew.toolchains`` entry-point
    providers, then the ``REBREW_TOOLCHAIN_OVERLAY_DIR`` TOML files.  A
    duplicate name between any two sources raises :class:`RegistryError`
    (single-source discipline — a compiler must never be ambiguous).

    Also repopulates :data:`TOOLCHAIN_ORIGINS` with each name's provenance
    (``"packaged"`` / ``"entry-point"`` / ``"data-file <path>"``), so
    ``rebrew toolchain list`` can show where a toolchain came from."""
    global TOOLCHAIN_ORIGINS
    registry = dict(BUILTIN_TOOLCHAINS)
    TOOLCHAIN_ORIGINS = dict.fromkeys(registry, "packaged")
    _merge_entry_point_toolchains(registry)
    _merge_toolchain_overlay(registry)
    return registry


#: Provenance of each registered toolchain name (built alongside
#: :func:`build_toolchain_registry`): "packaged", "entry-point:<module>",
#: or "data-file <path>".  A name not present is packaged (defensive default).
TOOLCHAIN_ORIGINS: dict[str, str] = {}


#: The canonical toolchain registry.  Profiles in config.py map to these by
#: name; ``rebrew toolchain list`` shows them.  Built from
#: :func:`build_toolchain_registry` so entry-point providers and the
#: project-level TOML overlay extend it without touching host source.
TOOLCHAINS: dict[str, ToolchainSpec] = build_toolchain_registry()


def refresh_toolchain_registry() -> dict[str, ToolchainSpec]:
    """Re-run discovery and refresh the :data:`TOOLCHAINS` snapshot.

    Long-lived processes (a dashboard, an agent harness) can pick up
    toolchains installed after startup without a restart.  Also refreshes
    :data:`TOOLCHAIN_ORIGINS` (built alongside the registry)."""
    global TOOLCHAINS

    TOOLCHAINS = build_toolchain_registry()
    return TOOLCHAINS


def get_toolchain(name: str) -> ToolchainSpec:
    """Look up a toolchain by name (profile id)."""
    try:
        return TOOLCHAINS[name]
    except KeyError:
        raise ToolchainError(f"unknown toolchain {name!r} (known: {sorted(TOOLCHAINS)})") from None


def docker_available() -> bool:
    """True when docker is installed and its daemon responds (cached)."""
    global _docker_available_cache
    if _docker_available_cache is None:
        try:
            r = subprocess.run(
                [container_runtime(), "info"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            _docker_available_cache = r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            _docker_available_cache = False
    return _docker_available_cache


_image_presence: dict[str, bool] = {}


def kill_container(name: str, timeout: int = 30) -> None:
    """Best-effort ``docker kill`` of a timed-out run container.

    The container was started with ``--rm``, so killing it also removes it.
    All errors are suppressed: this is cleanup on an error path — losing the
    kill race must not mask the original timeout with a secondary failure.
    """
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run([container_runtime(), "kill", name], capture_output=True, timeout=timeout)


def image_present(tag: str, use_cache: bool = True) -> bool:
    """True when a docker image for *tag* is present locally (cached)."""
    if use_cache and tag in _image_presence:
        return _image_presence[tag]
    if not docker_available():
        return False
    try:
        r = subprocess.run(
            [container_runtime(), "image", "inspect", tag],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        # A hung daemon must surface as ToolchainError (callers catch that),
        # not a raw TimeoutExpired escaping into the compile/GA path — and
        # not a silent False, which would misreport a present image as
        # "not built".
        raise ToolchainError(f"docker image inspect {tag} failed: {exc}") from exc
    _image_presence[tag] = r.returncode == 0
    return _image_presence[tag]


def _image_id(tag: str) -> str | None:
    """Full docker image id for *tag* (``sha256:...``), or ``None`` when the
    tag does not resolve or docker is unavailable.  Uncached — the swap
    primitive calls it around image changes where freshness matters."""
    if not docker_available():
        return None
    try:
        r = subprocess.run(
            [container_runtime(), "image", "inspect", "--format", "{{.Id}}", tag],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolchainError(f"docker image inspect {tag} failed: {exc}") from exc
    if r.returncode != 0 or not r.stdout.strip():
        return None
    return r.stdout.strip()


def _retag_image(src: str, dst: str) -> None:
    """Point the *dst* tag at *src* (an image id or tag)."""
    r = subprocess.run(
        [container_runtime(), "tag", src, dst], capture_output=True, text=True, timeout=60
    )
    if r.returncode != 0:
        raise ToolchainError(f"docker tag {src} -> {dst} failed: {r.stderr[-300:]}")


def swap_toolchain_image(tag: str, op: Callable[[], None]) -> str:
    """Transactionally replace the docker image under *tag* (backup→swap→rollback).

    Records the current image id under *tag* (the backup), runs *op* — which
    must build or pull the replacement; docker's tag-on-success is the swap —
    then verifies *tag* still resolves.  If *op* raises, or the tag ends up
    unresolvable, the previous image is re-tagged under *tag* (rollback), so a
    failed build/pull never leaves the toolchain half-registered (a pin or
    cache entry pointing at a dangling tag).

    Returns the image id *tag* resolves to after a successful swap.
    """
    backup = _image_id(tag)
    try:
        op()
    except Exception:
        # Rollback: restore the previous image under the tag.  A normal
        # build/pull failure leaves the old tag in place (docker only re-tags
        # on success), so the restore is a no-op check in that case; it only
        # acts when the tag was left dangling or repointed at something else.
        if backup is not None:
            with contextlib.suppress(ToolchainError):
                if _image_id(tag) != backup:
                    _retag_image(backup, tag)
        raise
    current = _image_id(tag)
    if current is None:
        if backup is not None:
            with contextlib.suppress(ToolchainError):
                _retag_image(backup, tag)
        raise ToolchainError(
            f"image tag {tag!r} does not resolve after the swap"
            + (" — previous image restored" if backup is not None else " (no previous image)")
        )
    return current


def _match_binary(dir: Path, binary: str) -> Path | None:
    """Case-insensitive match of *binary* in *dir*, tolerating a ``.exe``
    suffix (vendored Windows trees store ``CL.EXE`` / ``cl.exe`` while specs
    name the binary ``cl``)."""
    want = {binary.lower(), (binary + ".exe").lower()}
    try:
        for entry in dir.iterdir():
            if entry.is_file() and entry.name.lower() in want:
                return entry
    except OSError:
        pass
    return None


def vendored_binary(spec: ToolchainSpec) -> Path | None:
    """Locate the spec's compiler inside its vendored host tree.

    Case-insensitive on both the ``host_bin`` subdir (``Bin`` vs ``BIN`` —
    MSVC400's tree is all-caps, MSVC 4.2/5.0's is lowercase) and the binary
    name (``cl`` matches ``CL.EXE``).  Returns ``None`` when the spec has
    no ``host_path`` or nothing matches — the PATH fallback is the caller's
    decision (``_resolve_binary`` uses it; the vendor guard must not).
    """
    if spec.host_path is None:
        return None
    host = Path(spec.host_path)
    # Canonical layout: the actual toolchain lives one level deep under
    # ``source/`` (<family>/<ver>-<arch>/source/... — vendored into the
    # rebrew-toolchains checkout) so every vendored tree has the same shape.
    if (host / "source").is_dir():
        host = host / "source"
    hit = _match_binary(host, spec.binary)
    if hit is not None:
        return hit
    # The compiler usually lives in a subdir (Bin for MSVC, binl for
    # Watcom); DOS-era vendored trees are uppercase (BIN, not Bin) —
    # match the host_bin subdir case-insensitively before giving up
    # (MSVC 1.52's toolchain/msvc/1.52-win16/BIN/CL.EXE would otherwise never
    # resolve).
    if spec.host_bin:
        try:
            for entry in host.iterdir():
                if entry.is_dir() and entry.name.lower() == spec.host_bin.lower():
                    hit = _match_binary(entry, spec.binary)
                    if hit is not None:
                        return hit
            # Product trees nest the compiler one level deeper (VC98/Bin for
            # the MSVC 6 master and SP5, Vc7/bin for 7.0/7.1, VC/bin for
            # 8.0+): look for <top>/<wrapper>/<host_bin>/<binary> so those
            # resolve too (msvc6's wrapped layout previously never did).
            for wrapper in host.iterdir():
                if not wrapper.is_dir():
                    continue
                for entry in wrapper.iterdir():
                    if entry.is_dir() and entry.name.lower() == spec.host_bin.lower():
                        hit = _match_binary(entry, spec.binary)
                        if hit is not None:
                            return hit
        except OSError:
            pass
    return None


def image_msvc_env(spec: ToolchainSpec) -> dict[str, str]:
    """INCLUDE/LIB for an image-backed MSVC run, derived from ``tool_root``.

    The images' ``cl`` wrapper is not the only place the include/lib trees
    come from: several MSVC 6.0 service-pack images ship a wrapper that
    exports neither, so a compile fails with C1083 unless the runner supplies
    them.  Both paths are the toolchain's own tree, seen through wine's ``Z:``
    drive (the container's root filesystem), matching the CMake bridge.

    Returns an empty mapping for specs that are not image-backed wine MSVC
    toolchains, so native and non-MSVC runtimes are untouched.
    """
    if not (spec.image and spec.runtime == "wine" and spec.family == "msvc" and spec.tool_root):
        return {}
    root = Path(spec.tool_root).parent
    return {
        "INCLUDE": "Z:" + str(root / "Include").replace("/", "\\"),
        "LIB": "Z:" + str(root / "Lib").replace("/", "\\"),
    }


def _resolve_binary(spec: ToolchainSpec) -> str:
    """The host-side compiler path for a native-runtime spec (no image):
    vendored dir / PATH binary.  Raises ToolchainError when nothing
    resolvable exists.  Only native-Linux toolchains (gcc-pe, watcom16
    wcc) reach this — wine/dosbox toolchains are docker-only."""
    hit = vendored_binary(spec)
    if hit is not None:
        return str(hit)
    found = shutil.which(spec.binary)
    if found:
        return found
    raise ToolchainError(
        f"toolchain {spec.name!r}: no native binary ({spec.binary}) found — "
        "run `rebrew toolchain vendor <name>` into the rebrew-toolchains "
        "checkout or install it on PATH"
    )


def run_toolchain(
    spec: ToolchainSpec,
    args: list[str],
    *,
    workdir: str | Path | None = None,
    timeout: int = _RUN_TIMEOUT,
    mounts: list[tuple[str, str]] | None = None,
) -> RunResult:
    """Invoke a toolchain's compiler through its docker image (uniform backend).

    Execution is docker-only for every Windows/DOS toolchain: the images
    encapsulate the runtime (MSVC under wine, DCC/TCC under DOSBox) and the
    host never calls CL.EXE / DCC.EXE / TCC.EXE / bcc32.exe directly.  A
    missing image is a hard error (run `rebrew toolchain build <name>`) —
    there is deliberately no wine/wibo/dosbox host fallback anymore.

    Native-Linux toolchains without an image (gcc-pe, watcom16 wcc) exec the
    vendored/PATH binary directly — they are not Windows binaries, so no
    wine glue is involved.

    The container runs with ``--network=none`` — compilation is strictly
    local (source in, object out), and the toolchain image needs no egress
    (a malformed image cannot reach the network during a build).

    Args:
        spec: The toolchain to run.
        args: Compiler arguments (flags, source, output).
        workdir: Host directory mounted into the container (docker) or the
            process cwd (native).  Required for docker.
        mounts: Extra ``(host_dir, container_dir)`` bind mounts, used to
            expose project include trees to the container (each host dir is
            mounted read-write at the container path).
        timeout: Subprocess timeout.

    Raises:
        ToolchainError: no docker daemon/image for a docker toolchain, or no
            native binary for a native-runtime toolchain.
    """
    workdir = Path(workdir) if workdir is not None else Path.cwd()
    try:
        workdir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # An un-creatable workdir must surface as a ToolchainError (callers
        # catch that), not a raw OSError escaping into the GA/flag-sweep path.
        raise ToolchainError(f"cannot create workdir {workdir}: {exc}") from exc

    if spec.image is not None:
        if not docker_available():
            raise ToolchainError("docker is not available — cannot run toolchain images")
        if not image_present(spec.image):
            raise ToolchainError(
                f"toolchain {spec.name!r}: docker image {spec.image} not built — "
                f"run `rebrew toolchain build {spec.name}`"
            )
        cmd = [
            container_runtime(),
            "run",
            "--rm",
            "--network=none",  # compile-only containers — no egress needed
            # A stable name lets the timeout path kill the container: when the
            # docker CLI is killed, dockerd keeps the (attached) container
            # running, so a hung compile would linger forever and accumulate
            # one orphan per timed-out invocation.
            "--name",
            f"rebrew-{uuid.uuid4().hex[:12]}",
            "-v",
            f"{workdir.resolve()}:/work",
            "-w",
            "/work",
        ]
        for host_dir, container_dir in mounts or []:
            cmd += ["-v", f"{Path(host_dir).resolve()}:{container_dir}"]
        for key, value in image_msvc_env(spec).items():
            cmd += ["-e", f"{key}={value}"]
        cmd.append(spec.image)
        if spec.image_binary is not None:
            cmd.append(spec.image_binary)
        cmd.extend(args)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            kill_container(str(cmd[cmd.index("--name") + 1]))
            raise ToolchainError(f"docker invocation failed: {exc}") from exc
        except OSError as exc:
            raise ToolchainError(f"docker invocation failed: {exc}") from exc
        return RunResult(r.returncode, r.stdout, r.stderr, backend="docker")

    if spec.runtime == "native":
        # Native-Linux compiler (gcc-pe, watcom16 wcc) — vendored/PATH binary
        # executed directly.  These are NOT Windows binaries; no wine glue.
        binary = _resolve_binary(spec)
        env = dict(os.environ)
        try:
            r = subprocess.run(
                [binary, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
                cwd=str(workdir),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolchainError(f"toolchain invocation failed: {exc}") from exc
        return RunResult(r.returncode, r.stdout, r.stderr, backend="native")

    raise ToolchainError(
        f"toolchain {spec.name!r} ({spec.runtime}) has no docker image — every "
        "Windows/DOS toolchain runs only through its docker image; "
        f"run `rebrew toolchain build {spec.name}`"
    )


def list_toolchains() -> list[dict[str, Any]]:
    """Registry view for `rebrew toolchain list --json`."""
    return [
        {
            "name": s.name,
            "image": s.image,
            "binary": s.binary,
            "runtime": s.runtime,
            "flags_style": s.flags_style,
            "obj_ext": s.obj_ext,
            "host_path": str(s.host_path) if s.host_path else None,
            "description": s.description,
            "origin": TOOLCHAIN_ORIGINS.get(s.name, "packaged"),
            "docker": docker_available(),
        }
        for s in TOOLCHAINS.values()
    ]


def pull_toolchain(name: str, timeout: int = 1200) -> tuple[str, bool]:
    """Pull a toolchain's docker image (docker backend).

    Locally-built images (via ``rebrew toolchain build``) are already
    present and have no registry to pull from — treat that as a successful
    no-op instead of a confusing "pull access denied" failure.

    The pull runs through :func:`swap_toolchain_image` (backup→swap→rollback):
    a failed pull leaves the previously registered image under the tag.

    Returns ``(image_tag, was_already_present)``.
    """
    spec = get_toolchain(name)
    if spec.image is None:
        raise ToolchainError(f"toolchain {name!r} has no docker image (host-only)")
    image = spec.image  # narrowed local — mypy does not narrow into the closure
    if not docker_available():
        raise ToolchainError("docker is not available — cannot pull images")
    _image_presence.pop(image, None)
    if image_present(image):
        return image, True

    def _pull() -> None:
        r = subprocess.run(
            [container_runtime(), "pull", image],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if r.returncode != 0:
            raise ToolchainError(
                f"{container_runtime()} pull {spec.image} failed: {r.stderr[-400:]}.  "
                f"rebrew images are BUILT from pinned sources, not pushed to a "
                f"registry — run `rebrew toolchain build {name}` instead"
            )

    swap_toolchain_image(image, _pull)
    return image, False


__all__ = [
    "RunResult",
    "ToolchainError",
    "ToolchainSpec",
    "TOOLCHAINS",
    "docker_available",
    "get_toolchain",
    "list_toolchains",
    "pull_toolchain",
    "run_toolchain",
    "swap_toolchain_image",
]
