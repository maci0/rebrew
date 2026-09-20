"""CI pin contract — workflow pins stay aligned with Makefile / uv.lock.

``RESEMBL_REF`` and ``UV_VERSION`` are duplicated across ``ci.yml``,
``toolchain-sync.yml``, and (for resembl) the Makefile.  They have drifted
before (v1.0.0 vs v2.0.0; uv 0.12.2 vs local).  Third-party Actions must stay
commit-SHA pinned so a retargeted major tag cannot silently change CI.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import textwrap
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


def _makefile_uv_version() -> str:
    text = MAKEFILE.read_text(encoding="utf-8")
    m = re.search(r"(?m)^UV_VERSION\s*\?=\s*(\S+)\s*$", text)
    assert m is not None, "UV_VERSION missing from Makefile"
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
        make_uv = _makefile_uv_version()
        assert "UV_VERSION" in ci and "UV_VERSION" in sync
        assert ci["UV_VERSION"] == sync["UV_VERSION"] == make_uv

    def test_resembl_ref_aligned(self) -> None:
        ci = _workflow_env(CI_YML)
        sync = _workflow_env(SYNC_YML)
        make_ref = _makefile_resembl_ref()
        lock_ver = _lock_resembl_version()
        assert ci["RESEMBL_REF"] == sync["RESEMBL_REF"] == make_ref
        assert make_ref.lstrip("v") == lock_ver

    def test_hermetic_jobs_pin_exact_python_patch(self) -> None:
        """Lint / pre-commit / package / cli-contract / toolchain-sync use
        the exact ``.python-version`` patch.  The test matrix may float on
        the 3.13/3.14 minors for compatibility coverage.
        """
        python_version = (ROOT / ".python-version").read_text(encoding="utf-8").strip()
        assert re.fullmatch(r"3\.13\.\d+", python_version), python_version
        pin = f'python-version: "{python_version}"'
        for path in (CI_YML, SYNC_YML):
            text = path.read_text(encoding="utf-8")
            assert pin in text, f"{path.relative_to(ROOT)} missing {pin}"
        # setup-uv steps must not float on a bare "3.13" (matrix stays 3.13/3.14).
        floating = re.findall(
            r"(?m)^          python-version: \"3\.13\"\s*$",
            CI_YML.read_text(encoding="utf-8"),
        )
        assert floating == [], f"hermetic CI jobs must pin {python_version}, not float on 3.13"
        assert 'python-version: "3.13"' not in SYNC_YML.read_text(encoding="utf-8")

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

    def test_runners_pin_ubuntu_lts(self) -> None:
        """Float on ubuntu-latest silently switches major images; pin the LTS."""
        for path in (CI_YML, SYNC_YML):
            text = path.read_text(encoding="utf-8")
            assert "runs-on: ubuntu-latest" not in text, path.name
            assert "runs-on: ubuntu-24.04" in text, path.name

    def test_cache_write_permission(self) -> None:
        """setup-uv enable-cache needs actions:write to persist the uv cache."""
        for path in (CI_YML, SYNC_YML):
            head = path.read_text(encoding="utf-8").split("\njobs:", 1)[0]
            assert "contents: read" in head, path.name
            assert "actions: write" in head, path.name

    def test_resembl_clone_uses_retry_helper(self) -> None:
        """Network flakes cloning resembl must retry (same posture as apt-get)."""
        helper = ROOT / "tools" / "ci_clone_resembl.sh"
        assert helper.is_file()
        text = helper.read_text(encoding="utf-8")
        assert "for attempt in 1 2 3" in text
        assert "GIT_TERMINAL_PROMPT=0" in text
        assert "basename is not 'resembl'" in text
        for path in (CI_YML, SYNC_YML):
            wf = path.read_text(encoding="utf-8")
            assert "bash tools/ci_clone_resembl.sh" in wf, path.name
            assert "git clone --depth 1 --branch" not in wf, path.name

    def test_test_job_fetches_tags(self) -> None:
        """Packaging CHANGELOG↔tag contract needs tags on the shallow checkout."""
        text = CI_YML.read_text(encoding="utf-8")
        test_job = text.split("\n  test:\n", 1)[1].split("\n  pre-commit:\n", 1)[0]
        assert "fetch-tags: true" in test_job

    def test_makefile_recipes_are_posix_sh(self) -> None:
        """Make invokes /bin/sh; on Debian/Ubuntu that is dash (no pipefail)."""
        text = MAKEFILE.read_text(encoding="utf-8")
        assert "pipefail" not in text, (
            "Makefile recipes must stay POSIX sh (set -eu); pipefail is bash-only "
            "and breaks make on stock Debian/Ubuntu where /bin/sh is dash"
        )
        assert "set -eu" in text

    def test_package_smoke_honors_lockfile(self) -> None:
        """Wheel smoke-install must not resolve runtime deps from live PyPI.

        ``uv pip install dist/*.whl`` ignores ``uv.lock``; the package job
        syncs locked deps with ``--no-install-project`` then overlays the
        wheel with ``--no-deps``.
        """
        text = CI_YML.read_text(encoding="utf-8")
        package_job = text.split("\n  package:\n", 1)[1].split("\n  cli-contract:\n", 1)[0]
        assert "uv sync --frozen --no-dev --no-default-groups --no-install-project" in package_job
        assert "uv pip install --python .venv-pkg --no-deps" in package_job
        assert 'uv pip install --python .venv-pkg "${wheels[0]}"' not in package_job
        assert "dist/rebrew.buildinfo" in package_job
        # Repro check must not hide a failing build behind `tail`.
        assert "dist-repro" in package_job
        assert "| tail" not in package_job

    def test_makefile_build_writes_buildinfo_and_cleans_residue(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        assert "dist/rebrew.buildinfo" in text
        assert "rm -rf build rebrew.egg-info" in text

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


class TestToolchainSync:
    @pytest.mark.parametrize(
        ("status", "drifted", "expected"),
        [
            ("current", [], 0),
            ("static (immutable release asset)", [], 0),
            ("static (pinned tarball in rebrew-toolchains)", [], 0),
            ("DRIFTED old -> new", ["compiler"], 1),
            ("check failed (HTTPStatusError)", [], 1),
            ("unpinned (live abc123)", [], 1),
            ("unknown", [], 1),
            ("current", ["compiler"], 1),
            (None, [], 1),
        ],
    )
    def test_drift_gate(self, status: str | None, drifted: list[str], expected: int) -> None:
        if not shutil.which("jq"):
            pytest.skip("jq is required by the Ubuntu workflow")
        script = textwrap.dedent(SYNC_YML.read_text(encoding="utf-8").rsplit("run: |\n", 1)[1])
        stub = """
uv() {
    [[ "$*" == 'run --frozen rebrew toolchain check-updates --json' ]] || return 99
    printf 'source check invoked\\n' >&2
    printf '%s\\n' "$CHECK_RESULT"
}
"""
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", stub + script],
            env={
                **os.environ,
                "CHECK_RESULT": json.dumps(
                    {"toolchains": {"compiler": status} if status else {}, "drifted": drifted}
                ),
            },
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == expected, result.stdout + result.stderr
        assert result.stderr.count("source check invoked") == 1
        if status is not None:
            assert status in result.stdout
