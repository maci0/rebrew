"""updates.py — Upstream pin drift and GitHub commit-SHA helpers for toolchains."""

from __future__ import annotations

import threading
lazy import re
lazy import time

lazy from rebrew.compiler.toolchain import ToolchainError
lazy from rebrew.toolchain_cli.vendor import HTTP_ATTEMPTS, HTTP_RETRY_BACKOFF_S
lazy from rebrew.utils import RETRYABLE_HTTP_STATUS, read_capped_body

__all__ = [
    "CODELOAD_RE",
    "COMMIT_SHA_PATTERN",
    "GITHUB_SHA_MEDIA_TYPE",
    "MAX_LIVE_SHA_BYTES",
    "MOVING_RELEASE",
    "SHA_REPLY_EXCERPT_CHARS",
    "STATUS_CURRENT",
    "STATUS_STATIC_ASSET",
    "STATUS_STATIC_TARBALL",
    "codeload_pattern",
    "codeload_ref",
    "github_auth_headers",
    "live_commit_sha",
]

#: ``check-updates`` row values. The two ``static`` spellings mark a source
#: that cannot drift (an immutable release asset, a tarball pinned inside the
#: recompile-toolchains checkout); the nightly gate in
#: ``.github/workflows/toolchain-sync.yml`` allowlists these exact strings, so
#: ``tests/test_ci_pins.py`` fails when the two sides drift apart.
STATUS_CURRENT = "current"
STATUS_STATIC_ASSET = "static (immutable release asset)"
STATUS_STATIC_TARBALL = "static (pinned tarball in recompile-toolchains)"

#: Cap on the ``live_commit_sha`` GitHub API reply, applied while it streams
#: in.  The reply is the 40-byte sha alone (``GITHUB_SHA_MEDIA_TYPE``); 1 MiB
#: is generous (same bound as wibo release metadata).
MAX_LIVE_SHA_BYTES = 1024**2

#: GitHub media type for the commit endpoint that answers with the sha alone.
#: The default JSON lists the commit's files with their patches: 1,184,601
#: bytes for archaic-msvc/msvc710_sp1, past ``MAX_LIVE_SHA_BYTES``.
GITHUB_SHA_MEDIA_TYPE = "application/vnd.github.sha"

#: A commit sha as the pins in `SOURCES` record it.
COMMIT_SHA_PATTERN = r"[0-9a-f]{40}"

#: Characters of a reply that is not a sha quoted in the error.
SHA_REPLY_EXCERPT_CHARS = 80

#: A GitHub codeload tarball: owner, repository, and the branch (``refs/heads/<b>``)
#: or the commit (40 hex, recompile-toolchains 1.18.0's form) it names.
CODELOAD_RE = (
    r"https://codeload\.github\.com/([^/]+)/([^/]+)/tar\.gz/"
    r"(?:refs/heads/([A-Za-z0-9._-]+)|([0-9a-f]{40}))"
)
_CODELOAD_PATTERN: re.Pattern[str] | None = None
_CODELOAD_PATTERN_LOCK = threading.Lock()

MOVING_RELEASE = "Last-CI-build"


def codeload_pattern() -> re.Pattern[str]:
    """Compiled codeload pattern (module import lazily loads ``re``)."""
    with _CODELOAD_PATTERN_LOCK:
        global _CODELOAD_PATTERN
        if _CODELOAD_PATTERN is None:
            _CODELOAD_PATTERN = re.compile(CODELOAD_RE)
        return _CODELOAD_PATTERN


def codeload_ref(m: re.Match[str]) -> str:
    """The ref whose head a codeload pin is compared with: its branch, or ``HEAD``
    (the default branch) for a pin that names a commit."""
    return m.group(3) or "HEAD"


def github_auth_headers() -> dict[str, str]:
    """GitHub API headers (auth when GH_TOKEN/GITHUB_TOKEN is set)."""
    import os

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    base = {"User-Agent": "rebrew-toolchain"}
    if token:
        base["Authorization"] = f"Bearer {token}"
    return base


def live_commit_sha(owner: str, repo: str, branch: str) -> str:
    """Current default-branch commit sha for a GitHub repo (GitHub API —
    cheap: no tarball download).

    A transport failure or a retryable status is retried on the module's
    shared backoff: check-updates loops this once per source, and one 502
    from the API otherwise turns the nightly drift gate red without the pin
    having moved. A non-retryable status (404, 403) is raised on the first
    attempt, so a wrong repository still reports itself.
    """
    import httpx

    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{branch}"
    # No automatic redirects: an off-host Location would still receive the
    # optional GH_TOKEN Authorization header before httpx's strip runs.
    # The stream closes on every exit path: check-updates loops this once per
    # source, and an unclosed response pins the connection until GC.
    for attempt in range(HTTP_ATTEMPTS):
        try:
            with httpx.stream(
                "GET",
                url,
                headers={**github_auth_headers(), "Accept": GITHUB_SHA_MEDIA_TYPE},
                timeout=20,
                follow_redirects=False,
                trust_env=False,
            ) as resp:
                resp.raise_for_status()
                raw = read_capped_body(resp, MAX_LIVE_SHA_BYTES)
            if raw is None:
                raise ToolchainError(
                    f"GitHub API reply for {owner}/{repo}@{branch} exceeds "
                    f"{MAX_LIVE_SHA_BYTES} bytes"
                )
            sha = raw.decode("ascii", errors="replace").strip()
            if not re.fullmatch(COMMIT_SHA_PATTERN, sha):
                raise ToolchainError(
                    f"GitHub API reply for {owner}/{repo}@{branch} is not a commit sha: "
                    f"{sha[:SHA_REPLY_EXCERPT_CHARS]!r}"
                )
            return sha
        except httpx.HTTPStatusError as exc:
            if (
                exc.response.status_code not in RETRYABLE_HTTP_STATUS
                or attempt + 1 == HTTP_ATTEMPTS
            ):
                raise
        except httpx.HTTPError:
            if attempt + 1 == HTTP_ATTEMPTS:
                raise
        time.sleep(HTTP_RETRY_BACKOFF_S * 2**attempt)
    raise ToolchainError(f"unreachable: no attempt made for {url!r}")
