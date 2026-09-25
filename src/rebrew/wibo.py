"""Helpers for locating and downloading wibo runner binaries.

Wibo is a lightweight Win32 PE loader used as a faster alternative to Wine for
running MSVC toolchain binaries. This module finds an existing wibo binary or
downloads and verifies the latest release asset from GitHub.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import platform
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

if TYPE_CHECKING:
    import httpx

from rebrew.utils import close_response

_WIBO_API_URL = "https://api.github.com/repos/decompals/wibo/releases/latest"
_WIBO_DEFAULT_PATH = Path("tools/wibo")

#: Hosts GitHub release assets may resolve to.  A compromised or MITM'd
#: release JSON must not redirect ``httpx`` at arbitrary URLs (SSRF /
#: internal-metadata pivot).
_WIBO_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "objects.githubusercontent.com",
        "github-releases.githubusercontent.com",
        "release-assets.githubusercontent.com",
    }
)
#: The metadata GET stays on the API host. ``/releases/latest`` answers 302
#: to the tag URL on the same host; an off-host hop would substitute the digest.
_WIBO_METADATA_HOSTS = frozenset({"api.github.com"})


def _wibo_asset_name() -> str:
    """Return the correct wibo asset name for the current platform.

    Host support matches the project claim (Linux x86 only): there is no
    macOS/Windows download path, and Linux aarch64 has no upstream asset.
    """
    machine = platform.machine().lower()
    if sys.platform.startswith("linux"):
        if machine in {"x86_64", "amd64"}:
            return "wibo-x86_64"
        if machine in {"i686", "i386"}:
            return "wibo-i686"

    raise RuntimeError(
        "Unsupported platform for wibo: need Linux x86_64 or i686 "
        f"(platform={sys.platform!r}, machine={platform.machine()!r})"
    )


_NETWORK_TIMEOUT_S = 30  # Fail fast rather than hang indefinitely in CI/automation


def _trusted_wibo_download_url(url: str) -> str:
    """Return *url* when it is an https GitHub release asset URL; else raise.

    Matches the same-origin discipline used by :mod:`rebrew.recompile_client`:
    release metadata can name any ``browser_download_url``, so the client must
    refuse off-GitHub hosts before fetching bytes (or following redirects).
    """
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in _WIBO_DOWNLOAD_HOSTS or not parsed.path:
        raise RuntimeError(
            f"wibo release asset download URL is not a trusted GitHub https host: {url!r}"
        )
    return url


def _get_with_trusted_redirects(url: str) -> httpx.Response:
    """GET *url*, following redirects only while each hop stays on the allow-list.

    Intermediate 3xx responses are closed before the next hop so a multi-redirect
    download does not pin one connection (and its pool slot) per hop until GC.
    The final response is owned by the caller.
    """
    import httpx  # deferred: ~46 ms of startup for non-wibo commands

    current = _trusted_wibo_download_url(url)
    for _ in range(10):
        resp = httpx.get(current, timeout=_NETWORK_TIMEOUT_S, follow_redirects=False)
        if resp.status_code not in {301, 302, 303, 307, 308}:
            return resp
        try:
            location = resp.headers.get("location")
            if not location:
                raise RuntimeError(f"wibo download redirect missing Location from {current!r}")
            current = _trusted_wibo_download_url(urljoin(current, location))
        finally:
            close_response(resp)
    raise RuntimeError(f"wibo download exceeded redirect limit from {url!r}")


def _trusted_wibo_metadata_url(url: str) -> str:
    """Return *url* when it is https on ``api.github.com``; else raise."""
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in _WIBO_METADATA_HOSTS or not parsed.path:
        raise RuntimeError(f"wibo release metadata URL is not https://api.github.com: {url!r}")
    return url.strip()


def _read_release_metadata() -> dict[str, Any]:
    """Fetch and parse latest release metadata from GitHub.

    Redirects are followed only while each hop stays on ``api.github.com``.
    ``/releases/latest`` is a same-host 302; an off-host ``Location`` would
    substitute the JSON that supplies the asset digest.
    """
    import httpx  # deferred: ~46 ms of startup for non-wibo commands

    current = _trusted_wibo_metadata_url(_WIBO_API_URL)
    for _ in range(10):
        try:
            resp = httpx.get(current, timeout=_NETWORK_TIMEOUT_S, follow_redirects=False)
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"Failed to fetch wibo release metadata from {current!r}: {exc}"
            ) from exc
        try:
            if resp.status_code in {301, 302, 303, 307, 308}:
                location = resp.headers.get("location")
                if not location:
                    raise RuntimeError(
                        f"wibo release metadata redirect missing Location from {current!r}"
                    )
                current = _trusted_wibo_metadata_url(urljoin(current, location))
                continue
            resp.raise_for_status()
            try:
                data = resp.json()
            except ValueError as exc:
                raise RuntimeError(
                    f"Invalid JSON in wibo release metadata from {current!r}: {exc}"
                ) from exc
        finally:
            close_response(resp)
        if not isinstance(data, dict):
            raise RuntimeError("Invalid wibo release metadata response")
        return data
    raise RuntimeError(f"wibo release metadata exceeded redirect limit from {_WIBO_API_URL!r}")


def download_wibo(dest: Path) -> str:
    """Download latest wibo release binary to *dest* and return release tag_name.

    Raises RuntimeError if the asset is not found, download fails,
    or SHA-256 verification fails.
    """
    import httpx  # deferred: ~46 ms of startup for non-wibo commands

    release = _read_release_metadata()
    tag_name = str(release.get("tag_name", ""))
    asset_name = _wibo_asset_name()
    assets_raw = release.get("assets", [])
    if not isinstance(assets_raw, list):
        raise RuntimeError("Invalid wibo release metadata: assets is not a list")

    selected_asset: dict[str, Any] | None = None
    for asset in assets_raw:
        if isinstance(asset, dict) and asset.get("name") == asset_name:
            selected_asset = asset
            break

    if selected_asset is None:
        raise RuntimeError(f"wibo release asset not found: {asset_name}")

    download_url = selected_asset.get("browser_download_url")
    digest = selected_asset.get("digest")
    if not isinstance(download_url, str) or not download_url:
        raise RuntimeError(f"wibo release asset missing download URL: {asset_name}")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise RuntimeError(f"wibo release asset missing SHA256 digest: {asset_name}")
    expected_sha256 = digest.removeprefix("sha256:")
    # Validate before the GET so a poisoned browser_download_url never leaves
    # the process (SSRF against link-local / intranet listeners).
    download_url = _trusted_wibo_download_url(download_url)

    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        resp = _get_with_trusted_redirects(download_url)
        try:
            resp.raise_for_status()
            body = resp.content
        finally:
            close_response(resp)
    except httpx.HTTPError as exc:
        raise RuntimeError(
            f"Failed to download wibo asset {asset_name} from {download_url}: {exc}"
        ) from exc

    actual_sha256 = hashlib.sha256(body).hexdigest()
    if actual_sha256 != expected_sha256:
        raise RuntimeError(
            f"SHA256 mismatch for downloaded wibo: expected {expected_sha256}, got {actual_sha256}"
        )

    # Write via tempfile + os.replace for crash-safe placement
    fd, tmp_path = tempfile.mkstemp(dir=str(dest.parent), prefix=".wibo_")
    try:
        f = os.fdopen(fd, "wb")
        fd = -1
        with f:
            f.write(body)
        os.chmod(tmp_path, stat.S_IRUSR | stat.S_IXUSR)
        os.replace(tmp_path, str(dest))
    except BaseException:
        if fd != -1:
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    return tag_name


def find_wibo(project_root: Path | None = None) -> Path | None:
    """Find wibo from PATH first, then from project-local tools/wibo."""
    found_in_path = shutil.which("wibo")
    if found_in_path:
        return Path(found_in_path)

    if project_root is None:
        return None

    local_wibo = project_root / _WIBO_DEFAULT_PATH
    if local_wibo.exists() and local_wibo.is_file():
        return local_wibo
    return None
