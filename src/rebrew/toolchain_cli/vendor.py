"""vendor.py — Pinned toolchain download verification, archive extraction, and vendoring helpers."""

from __future__ import annotations

from typing import Any
lazy import shutil
lazy import time
lazy from collections.abc import Callable
lazy from dataclasses import replace
lazy from pathlib import Path

lazy import tenacity

lazy from rebrew.cli import error_exit
lazy from rebrew.compiler.toolchain import ToolchainError

__all__ = [
    "DOWNLOAD_REDIRECT_LIMIT",
    "EXTRACT_TIMEOUT_S",
    "HTTP_ATTEMPTS",
    "HTTP_RETRY_BACKOFF_S",
    "MAX_PINNED_DOWNLOAD_BYTES",
    "TOOLCHAIN_DOWNLOAD_HOST_SUFFIXES",
    "TRACKED_META_PATTERNS",
    "abort_incomplete_vendor",
    "download_pinned_url",
    "flatten_wrapper_dir",
    "probe_vendored",
    "safe_extract_tar",
    "trusted_toolchain_download_host",
    "trusted_toolchain_download_url",
    "vendor_tree_complete",
]

#: Cap on each archive-extraction subprocess in `rebrew toolchain vendor`
#: (matches the curl download timeout).  Without it a stuck filesystem or
#: an unzip prompting for an encrypted-archive password hangs forever.
EXTRACT_TIMEOUT_S = 1800

#: Redirect hops a pinned download may follow before giving up.  Bounded
#: because every hop re-validates the host, and an unbounded chain would
#: otherwise loop.
DOWNLOAD_REDIRECT_LIMIT = 10

#: Transport attempts for one GitHub request, and the base delay (seconds) of
#: the exponential backoff between them (``base * 2**attempt``).  Shared by the
#: pinned-media download (budget: per redirect target) and the upstream commit
#: lookup: both are single requests whose one transient failure is a mirror
#: blip, not a source that moved.
HTTP_ATTEMPTS = 3
HTTP_RETRY_BACKOFF_S = 0.5

#: Cap on a pinned download's body.  The sha256 pin is checked only after the
#: body lands, so without a running cap a compromised mirror could stream
#: without bound and fill the disk before the pin ever runs (DoS).  Toolchain
#: media is a few hundred MiB at most; 2 GiB leaves generous headroom.
MAX_PINNED_DOWNLOAD_BYTES = 2 * 1024**3

#: Tracked repo metadata kept when a vendored host tree is cleared or
#: refreshed.  Docker build inputs, wrapper scripts, the pinned media and the
#: per-toolchain docs are repo content, never vendored payload.
TRACKED_META_PATTERNS = (
    "Dockerfile",
    "pak_extract.py",
    "wrapper-common.sh",
    ".dockerignore",
    "*.sh",
    "*.tar.xz",
    "*.md",
)

#: Host suffixes pinned toolchain media may resolve to (and redirect through).
#: A compromised CDN Location must not pivot ``httpx`` at link-local /
#: intranet listeners (same SSRF class as :mod:`rebrew.wibo`).
TOOLCHAIN_DOWNLOAD_HOST_SUFFIXES = frozenset(
    {
        "github.com",
        "githubusercontent.com",
        "gnu.org",
    }
)


def trusted_toolchain_download_host(hostname: str | None) -> bool:
    """True when *hostname* is exactly an allow-listed suffix or a subdomain."""
    if not hostname:
        return False
    host = hostname.lower().rstrip(".")
    return any(
        host == suffix or host.endswith("." + suffix) for suffix in TOOLCHAIN_DOWNLOAD_HOST_SUFFIXES
    )


def trusted_toolchain_download_url(url: str) -> str:
    """Return *url* when it is https on an allow-listed download host; else raise.

    Mirrors :func:`rebrew.wibo._trusted_wibo_download_url`: pinned SOURCES URLs
    and their CDN redirects stay on known publishers; off-list hosts are refused
    before bytes are fetched.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not trusted_toolchain_download_host(host) or not parsed.path:
        raise ToolchainError(f"toolchain download URL is not a trusted https host: {url!r}")
    return url.strip()


def safe_extract_tar(archive: Path, dest: Path, *, strip_components: int = 0) -> None:
    """Extract *archive* into *dest* with PEP 706 ``filter='data'`` containment.

    Replaces ``tar xf`` so a compromised pin cannot write ``../`` or absolute
    members outside *dest* (zip-slip).  *strip_components* mirrors
    ``tar --strip-components``.
    """
    import tarfile

    dest.mkdir(parents=True, exist_ok=True)
    dest_root = dest.resolve()
    with tarfile.open(archive) as tf:
        if strip_components <= 0:
            tf.extractall(dest, filter="data")
            return
        for member in tf.getmembers():
            name = member.name.lstrip("/")
            parts = Path(name).parts
            if ".." in parts:
                raise ToolchainError(f"refusing unsafe tar member: {member.name!r}")
            if len(parts) <= strip_components:
                continue
            stripped = str(Path(*parts[strip_components:]))
            if member.islnk():
                link = Path(member.linkname)
                if link.is_absolute() or ".." in link.parts or len(link.parts) <= strip_components:
                    raise ToolchainError(f"refusing unsafe tar hard link: {member.linkname!r}")
                member.linkname = str(Path(*link.parts[strip_components:]))
            member.name = stripped
            target = (dest_root / stripped).resolve()
            if not target.is_relative_to(dest_root):
                raise ToolchainError(f"refusing path escape in tar member: {name!r}")
            tf.extract(member, dest, filter="data")


def download_pinned_url(
    url: str,
    dest: Path,
    *,
    timeout: float = 1800,
    sleep: Callable[[float], None] | None = None,
) -> None:
    """Download *url* to *dest*, following redirects only while hosts stay trusted.

    Replaces ``curl -sL`` so a poisoned ``Location`` cannot SSRF the workstation
    (metadata endpoints, intranet) before the sha256 pin check runs.

    A transport failure is retried (a multi-hundred-MB media fetch over a
    flaky link is the common case, and the caller's sha256 check makes a
    re-fetch safe).  Each attempt truncates *dest*, so a failed or abandoned
    attempt unlinks the partial file rather than leaving a short archive that
    reads as a complete download.  The retry budget is per redirect target:
    following a redirect does not spend an attempt, so a multi-hop chain
    still gets the full budget on the hop that actually transfers bytes.
    """
    from urllib.parse import urljoin

    import httpx

    nap = sleep if sleep is not None else time.sleep
    current = trusted_toolchain_download_url(url)

    def _fetch_hop(hop_url: str) -> str | None:
        try:
            with httpx.stream(
                "GET", hop_url, timeout=timeout, follow_redirects=False, trust_env=False
            ) as resp:
                if resp.status_code in {301, 302, 303, 307, 308}:
                    location = resp.headers.get("location")
                    if not location:
                        raise ToolchainError(
                            f"toolchain download redirect missing Location from {hop_url!r}"
                        )
                    return trusted_toolchain_download_url(urljoin(hop_url, location))
                resp.raise_for_status()
                received = 0
                with dest.open("wb") as fh:
                    for chunk in resp.iter_bytes():
                        received += len(chunk)
                        if received > MAX_PINNED_DOWNLOAD_BYTES:
                            raise ToolchainError(
                                f"toolchain download exceeds {MAX_PINNED_DOWNLOAD_BYTES} bytes from {hop_url!r}"
                            )
                        fh.write(chunk)
                return None
        except BaseException:
            dest.unlink(missing_ok=True)
            raise

    for _hop in range(DOWNLOAD_REDIRECT_LIMIT):
        retrying = tenacity.Retrying(
            stop=tenacity.stop_after_attempt(HTTP_ATTEMPTS),
            retry=tenacity.retry_if_exception_type((httpx.HTTPError, OSError)),
            wait=tenacity.wait_exponential(multiplier=HTTP_RETRY_BACKOFF_S, exp_base=2),
            sleep=nap,
            reraise=True,
        )
        try:
            next_url = retrying(_fetch_hop, current)
        except (httpx.HTTPError, OSError) as exc:
            # A disk-full / permission failure on the write must surface as a
            # ToolchainError with the cause, not escape as an unhandled OSError
            # leaving a partial archive at *dest*.
            dest.unlink(missing_ok=True)
            raise ToolchainError(f"toolchain download failed from {current!r}: {exc}") from exc
        if next_url is None:
            return
        # A redirect consumed this hop without transferring bytes; the next hop
        # starts a fresh transport budget.  A chain longer than the limit still
        # terminates.
        current = next_url
    dest.unlink(missing_ok=True)
    raise ToolchainError(f"toolchain download exceeded redirect limit from {url!r}")


def flatten_wrapper_dir(payload: Path, extract_dir: Path) -> None:
    """Move *payload*'s children into *extract_dir*, unwrapping a single
    top-level directory first (``TC/``, ``mingw32/``) so the host tree has
    the same flat shape as every other toolchain."""
    contents = [p for p in payload.iterdir() if p.is_dir() and not p.is_symlink()]
    if len(contents) == 1 and not any(p.is_file() or p.is_symlink() for p in payload.iterdir()):
        payload = contents[0]
    extract_root = extract_dir.resolve()
    for child in payload.iterdir():
        # Symlink / ``..`` members would let a hostile archive escape *extract_dir*
        # (zip-slip class) after the sha256 pin check of a compromised pin.
        if child.is_symlink() or child.name in {".", ".."}:
            raise ToolchainError(f"refusing unsafe path in toolchain archive: {child.name!r}")
        dest = (extract_dir / child.name).resolve()
        if not dest.is_relative_to(extract_root):
            raise ToolchainError(f"refusing path escape in toolchain archive: {child.name!r}")
        # shutil.move: *payload* is staged in the system temp dir, often tmpfs,
        # so a bare rename into the on-disk tree fails with EXDEV.
        shutil.move(child, extract_dir / child.name)


def probe_vendored(spec: Any, host: Path) -> Path | None:
    """Locate the toolchain's binary under *host*, or ``None`` if absent.

    Falls back to the pre-``source/`` flat layout, so a tree vendored before
    the canonical nesting still resolves.
    """
    from rebrew.compiler.toolchain import vendored_binary

    probe = vendored_binary(replace(spec, host_path=host))
    if probe is None:
        probe = vendored_binary(replace(spec, host_path=host / "source"))
    return probe


def vendor_tree_complete(host: Path, name: str) -> bool:
    """True when *host* already holds a usable vendored compiler for *name*.

    Used so a failed prior ``vendor`` (empty or partial ``source/``) can be
    retried instead of refusing to clobber forever.
    """
    from rebrew.compiler.toolchain import get_toolchain

    return probe_vendored(get_toolchain(name), host) is not None


def abort_incomplete_vendor(extract_dir: Path, msg: str, *, json_mode: bool) -> None:
    """Remove a partial extract tree, then exit — so the next vendor can retry."""
    if extract_dir.exists():
        shutil.rmtree(extract_dir, ignore_errors=True)
    error_exit(msg, json_mode=json_mode)
