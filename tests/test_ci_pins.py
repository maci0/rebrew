"""CI pin contract — workflow pins stay aligned with Makefile / uv.lock.

``RESEMBL_REF`` and ``UV_VERSION`` are duplicated across ``ci.yml``,
``toolchain-sync.yml``, and (for resembl) the Makefile.  They have drifted
before (v1.0.0 vs v2.0.0; uv 0.12.2 vs local).  Third-party Actions must stay
commit-SHA pinned so a retargeted major tag cannot silently change CI.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
SYNC_YML = ROOT / ".github" / "workflows" / "toolchain-sync.yml"
MAKEFILE = ROOT / "Makefile"
UV_LOCK = ROOT / "uv.lock"

_ENV_RE = re.compile(r'(?m)^\s*(?P<key>[A-Z][A-Z0-9_]+):\s*"(?P<val>[^"]+)"\s*$')
_USES_RE = re.compile(r"(?m)^\s+uses:\s+(?P<uses>\S+)\s*(?:#.*)?$")
_SHA_REF_RE = re.compile(r"^[0-9a-f]{40}$")


def _workflow_env(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    # Only the top-level workflow ``env:`` block (before ``jobs:``).
    head = text.split("\njobs:", 1)[0]
    return {m.group("key"): m.group("val") for m in _ENV_RE.finditer(head)}


def _makefile_resembl_ref() -> str:
    text = MAKEFILE.read_text(encoding="utf-8")
    m = re.search(r"(?m)^RESEMBL_REF\s*\?=\s*(\S+)\s*$", text)
    assert m is not None, "RESEMBL_REF missing from Makefile"
    return m.group(1)


def _lock_resembl_version() -> str:
    text = UV_LOCK.read_text(encoding="utf-8")
    m = re.search(
        r'(?m)^name = "resembl"\nversion = "([^"]+)"\nsource = \{ directory = "\.\./resembl" \}',
        text,
    )
    assert m is not None, "resembl path dep missing from uv.lock"
    return m.group(1)


class TestCiPins:
    def test_uv_version_shared_across_workflows(self) -> None:
        ci = _workflow_env(CI_YML)
        sync = _workflow_env(SYNC_YML)
        assert "UV_VERSION" in ci and "UV_VERSION" in sync
        assert ci["UV_VERSION"] == sync["UV_VERSION"]

    def test_resembl_ref_aligned(self) -> None:
        ci = _workflow_env(CI_YML)
        sync = _workflow_env(SYNC_YML)
        make_ref = _makefile_resembl_ref()
        lock_ver = _lock_resembl_version()
        assert ci["RESEMBL_REF"] == sync["RESEMBL_REF"] == make_ref
        assert make_ref.lstrip("v") == lock_ver

    def test_third_party_actions_are_sha_pinned(self) -> None:
        unpinned: list[str] = []
        for path in (CI_YML, SYNC_YML):
            for m in _USES_RE.finditer(path.read_text(encoding="utf-8")):
                uses = m.group("uses")
                if uses.startswith("./") or uses.startswith("docker://"):
                    continue
                _, _, ref = uses.partition("@")
                # Allow an optional trailing comment already stripped by the regex.
                if not _SHA_REF_RE.match(ref):
                    unpinned.append(f"{path.relative_to(ROOT)}: {uses}")
        assert unpinned == [], (
            f"third-party Actions must be commit-SHA pinned (got floating refs: {unpinned})"
        )

    @pytest.mark.parametrize("path", [CI_YML, SYNC_YML, MAKEFILE, ROOT / ".pre-commit-config.yaml"])
    def test_uv_run_preserves_lockfile(self, path: Path) -> None:
        commands = [
            match.group(1)
            for line in path.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
            for match in re.finditer(r"\buv run\s+(\S+)", line)
        ]
        assert commands, path
        assert all(command in {"--frozen", "--locked", "--no-sync"} for command in commands), (
            f"{path.relative_to(ROOT)} has uv run commands that can rewrite uv.lock"
        )
