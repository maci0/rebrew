"""Helpers for locating and downloading wibo runner binaries.

Wibo is a lightweight Win32 PE loader used as a faster alternative to Wine for
running MSVC toolchain binaries. This module finds an existing wibo binary or
downloads and verifies the latest release asset from GitHub.
"""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
import stat
import sys
import urllib.request
from pathlib import Path

_WIBO_API_URL = "https://api.github.com/repos/decompals/wibo/releases/latest"
_WIBO_DEFAULT_PATH = Path("tools/wibo")


def _wibo_asset_name() -> str:
    """Return the correct wibo asset name for the current platform."""
    if sys.platform == "darwin":
        return "wibo-macos"

    if sys.platform.startswith("linux"):
        machine = platform.machine().lower()
        if machine in {"x86_64", "amd64"}:
            return "wibo-x86_64"
        if machine in {"i686", "i386"}:
            return "wibo-i686"

    raise RuntimeError(
        f"Unsupported platform for wibo: platform={sys.platform!r}, machine={platform.machine()!r}"
    )


_NETWORK_TIMEOUT_S = 30  # Fail fast rather than hang indefinitely in CI/automation


def _read_release_metadata() -> dict[str, object]:
    """Fetch and parse latest release metadata from GitHub."""
    with urllib.request.urlopen(_WIBO_API_URL, timeout=_NETWORK_TIMEOUT_S) as response:
        payload = response.read().decode("utf-8")
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise RuntimeError("Invalid wibo release metadata response")
    return data


def download_wibo(dest: Path, *, quiet: bool = False) -> str:
    """Download latest wibo release binary to dest and return release tag_name."""
    del quiet

    release = _read_release_metadata()
    tag_name = str(release.get("tag_name", ""))
    asset_name = _wibo_asset_name()
    assets_raw = release.get("assets", [])
    if not isinstance(assets_raw, list):
        raise RuntimeError("Invalid wibo release metadata: assets is not a list")

    selected_asset: dict[str, object] | None = None
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

    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(download_url, timeout=_NETWORK_TIMEOUT_S) as resp:
        dest.write_bytes(resp.read())

    actual_sha256 = hashlib.sha256(dest.read_bytes()).hexdigest()
    if actual_sha256 != expected_sha256:
        dest.unlink(missing_ok=True)
        raise RuntimeError(
            f"SHA256 mismatch for downloaded wibo: expected {expected_sha256}, got {actual_sha256}"
        )

    # Owner read+execute only — wibo is a static binary, never needs modification
    dest.chmod(stat.S_IRUSR | stat.S_IXUSR)
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


def ensure_wibo(project_root: Path, *, quiet: bool = False) -> Path:
    """Find wibo or download it to project_root/tools/wibo."""
    found = find_wibo(project_root)
    if found is not None:
        return found

    dest = project_root / _WIBO_DEFAULT_PATH
    download_wibo(dest, quiet=quiet)
    return dest
