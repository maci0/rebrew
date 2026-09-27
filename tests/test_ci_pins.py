"""CI pin contract — workflow pins stay aligned with Makefile / uv.lock.

The uv / Python / resembl pins live once, as the input defaults of the local
composite action ``.github/actions/uv-env``; the Makefile mirrors them for the
contributor path.  They drifted before, when each workflow carried its own copy
(v1.0.0 vs v2.0.0; uv 0.12.2 vs local), so these tests also fail a workflow that
re-declares them.  Third-party Actions must stay commit-SHA pinned so a
retargeted major tag cannot silently change CI.
"""

from __future__ import annotations

import base64
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
UV_ENV_ACTION = ROOT / ".github" / "actions" / "uv-env" / "action.yml"
UV_ENV_USES = "./.github/actions/uv-env"
DEPENDABOT_YML = ROOT / ".github" / "dependabot.yml"
MAKEFILE = ROOT / "Makefile"
UV_LOCK = ROOT / "uv.lock"

_ENV_RE = re.compile(r'(?m)^\s*(?P<key>[A-Z][A-Z0-9_]+):\s*"(?P<val>[^"]+)"\s*$')
_USES_RE = re.compile(r"(?m)^\s+uses:\s+(?P<uses>\S+)\s*(?:#.*)?$")
_SHA_REF_RE = re.compile(r"^[0-9a-f]{40}$")


def _makefile_prereqs(target: str) -> set[str]:
    """Prerequisites of a Makefile target (order-independent, no recipe lines)."""
    text = MAKEFILE.read_text(encoding="utf-8")
    match = re.search(rf"(?m)^{re.escape(target)}:(?P<deps>[^\n]*)$", text)
    assert match is not None, f"no {target} target in the Makefile"
    return set(match.group("deps").split())


# Prereqs that transitively reach ensure-uv.  setup/build/sbom check the uv
# version as well, so they route through warn-uv-version instead.
_UV_PREFLIGHTS = {"ensure-uv", "warn-uv-version", "ensure-resembl"}


def _makefile_uv_targets() -> set[str]:
    """Targets whose recipe actually executes ``uv``, read from the Makefile.

    Derived from the recipes rather than a hand-listed set of names: the
    hand-listed version went stale, and `release-check` and `sdist-check` ran
    uv with no preflight at all, so a host without uv read their failure as a
    bug in the target instead of a missing toolchain.
    """
    # `help` prints "uv sync" and "uv $(UV_VERSION)" inside quoted prose and
    # never runs either; nothing else in the file has uv inside a string.
    skipped = {"help"}
    text = MAKEFILE.read_text(encoding="utf-8")
    found: set[str] = set()
    for match in re.finditer(
        r"(?m)^(?P<name>[A-Za-z][A-Za-z0-9_.-]*):(?P<deps>[^\n]*)\n(?P<recipe>(?:[ \t].*\n|\n)*)",
        text,
    ):
        name = match.group("name")
        if name in skipped or ".PHONY" in match.group("deps"):
            continue
        if re.search(r"(?m)(?:^[ \t]*|[;&|(`]\s*|\$\(\s*)uv\s", match.group("recipe")):
            found.add(name)
    return found


def _workflow_env(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    # Only the top-level workflow ``env:`` block (before ``jobs:``).
    head = text.split("\njobs:", 1)[0]
    return {m.group("key"): m.group("val") for m in _ENV_RE.finditer(head)}


def _uv_env_defaults() -> dict[str, str]:
    """Input-name -> default for the shared composite action (the pin site)."""
    import yaml

    action = yaml.safe_load(UV_ENV_ACTION.read_text(encoding="utf-8"))
    return {name: spec["default"] for name, spec in action["inputs"].items()}


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


def _makefile_resembl_sha() -> str:
    text = MAKEFILE.read_text(encoding="utf-8")
    m = re.search(r"(?m)^RESEMBL_SHA\s*\?=\s*(\S+)\s*$", text)
    assert m is not None, "RESEMBL_SHA missing from Makefile"
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
    def test_uv_version_pinned_once(self) -> None:
        """One pin site (the composite action), mirrored by the Makefile."""
        assert _uv_env_defaults()["uv-version"] == _makefile_uv_version()
        for path in (CI_YML, SYNC_YML):
            assert "UV_VERSION" not in _workflow_env(path), (
                f"{path.name}: uv is pinned in {UV_ENV_ACTION.name}; a workflow copy drifts"
            )

    def test_resembl_ref_aligned(self) -> None:
        make_ref = _makefile_resembl_ref()
        assert _uv_env_defaults()["resembl-ref"] == make_ref
        assert make_ref.lstrip("v") == _lock_resembl_version()
        # Tags are mutable: the clone verifies the tag against this commit,
        # and `make setup` refuses a checkout whose HEAD is not that commit.
        sha = _uv_env_defaults()["resembl-sha"]
        assert _SHA_REF_RE.match(sha)
        assert _makefile_resembl_sha() == sha
        recipe = MAKEFILE.read_text(encoding="utf-8").split("ensure-resembl: ensure-uv\n", 1)[1]
        recipe = recipe.split("\nensure-nasm:", 1)[0]
        assert "rev-parse HEAD" in recipe
        assert "RESEMBL_SHA" in recipe
        assert "RESEMBL_SHA" in (ROOT / "tools" / "ci_clone_resembl.sh").read_text(encoding="utf-8")
        for path in (CI_YML, SYNC_YML):
            assert "RESEMBL_REF" not in _workflow_env(path), (
                f"{path.name}: resembl is pinned in {UV_ENV_ACTION.name}; a workflow copy drifts"
            )

    def test_hermetic_jobs_pin_exact_python_patch(self) -> None:
        """Every job but the test matrix takes the action's default, which is
        the exact ``.python-version`` patch.  The matrix's 3.13 entry (which
        runs the coverage gate) pins that same patch; only 3.14 floats on its
        minor for forward-compat coverage.
        """
        python_version = (ROOT / ".python-version").read_text(encoding="utf-8").strip()
        assert re.fullmatch(r"3\.13\.\d+", python_version), python_version
        assert _uv_env_defaults()["python-version"] == python_version
        # Only the test matrix may override it, and only with the matrix value
        # (the first hit is the matrix declaration itself).
        ci = CI_YML.read_text(encoding="utf-8")
        overrides = re.findall(r"(?m)^\s+python-version: (.+)$", ci)
        assert overrides == [f'["{python_version}", "3.14"]', "${{ matrix.python-version }}"], (
            overrides
        )
        assert f"matrix.python-version == '{python_version}'" in ci
        assert f"matrix.python-version != '{python_version}'" in ci
        assert "python-version:" not in SYNC_YML.read_text(encoding="utf-8")

    def test_every_job_uses_the_shared_setup_action(self) -> None:
        """No job may hand-roll setup-uv: that is how the pins drifted before."""
        import yaml

        for path in (CI_YML, SYNC_YML):
            assert "astral-sh/setup-uv@" not in path.read_text(encoding="utf-8"), path.name
            jobs = yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]
            for name, spec in jobs.items():
                uses = [step.get("uses") for step in spec["steps"]]
                assert UV_ENV_USES in uses, f"{path.name}:{name} does not use {UV_ENV_USES}"

    def test_dependabot_scans_the_composite_action(self) -> None:
        """A composite action in a subdirectory is skipped unless listed, so its
        setup-uv SHA would never be refreshed."""
        import yaml

        updates = yaml.safe_load(DEPENDABOT_YML.read_text(encoding="utf-8"))["updates"]
        actions = [u for u in updates if u["package-ecosystem"] == "github-actions"]
        assert actions, "no github-actions Dependabot entry"
        scanned = {d for u in actions for d in u.get("directories", [u.get("directory")])}
        assert "/" in scanned
        assert "/.github/actions/uv-env" in scanned, scanned

    def test_third_party_actions_are_sha_pinned(self) -> None:
        unpinned: list[str] = []
        for path in (CI_YML, SYNC_YML, UV_ENV_ACTION):
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

    @pytest.mark.parametrize(
        ("job", "floor"),
        [
            # Floors, not the declared values: the gate is "a job needs at
            # least this long", so raising a timeout is allowed and shrinking
            # it below the work it does is not. A kill mid-job is reported as
            # a failure of whichever gate was running, which reads as a code
            # defect when the cause is a cold cache or a slow index.
            ("lint", 20),  # `uv sync --all-extras` installs angr, then `uv audit` queries PyPI
            ("package", 30),  # five build/resolve cycles plus a clean-venv smoke install
        ],
    )
    def test_heavy_jobs_get_a_timeout_above_their_work(self, job: str, floor: int) -> None:
        """``timeout-minutes`` must cover the steps the job actually runs.

        Every job declares one, but a floor alone does not make it fit: the
        package job builds the sdist, the wheel, both again in the
        reproducibility tree, and a wheel from the sdist, then creates a venv
        for the smoke install. At the original 10 minutes a cold Actions cache
        killed the run mid-``uv sync`` and the commit lost its verified wheel
        (that job's artifact is why ``cancel-in-progress`` stays off for
        pushes) instead of failing a gate.
        """
        import yaml

        jobs = yaml.safe_load(CI_YML.read_text(encoding="utf-8"))["jobs"]
        minutes = jobs[job]["timeout-minutes"]
        assert minutes >= floor, f"ci.yml:{job} timeout-minutes={minutes} is below {floor}"

    def test_both_workflows_can_be_re_run_by_hand(self) -> None:
        """A mirror or runner that stays down past three retries needs a re-run path.

        The retriers in tools/ci_apt_install.sh and tools/ci_clone_resembl.sh
        cap at three attempts, so the remaining recovery is re-running the
        pipeline; re-running a failed job alone cannot pick up a fixed mirror or
        a new runner image.
        """
        import yaml

        for path in (CI_YML, SYNC_YML):
            triggers = yaml.safe_load(path.read_text(encoding="utf-8"))[True]
            assert "workflow_dispatch" in triggers, path.name

    def test_managed_python_is_cached(self) -> None:
        """setup-uv leaves cache-python off, so each job re-downloads CPython.

        The interpreter is pinned to an exact patch, so caching the managed
        install costs one cache entry and saves a mirror download per job.
        """
        import yaml

        action = yaml.safe_load(UV_ENV_ACTION.read_text(encoding="utf-8"))
        setup_uv = next(
            step
            for step in action["runs"]["steps"]
            if str(step.get("uses", "")).startswith("astral-sh/setup-uv@")
        )
        assert setup_uv["with"]["cache-python"] is True
        assert setup_uv["with"]["enable-cache"] is True

    def test_token_permissions_read_only(self) -> None:
        """GITHUB_TOKEN stays contents:read; the Actions cache uses the runner token."""
        for path in (CI_YML, SYNC_YML):
            text = path.read_text(encoding="utf-8")
            head = text.split("\njobs:", 1)[0]
            assert "contents: read" in head, path.name
            assert ": write" not in text, path.name

    def test_gh_token_scoped_to_needing_steps(self) -> None:
        """Do not expose secrets.GITHUB_TOKEN to pytest/ruff/mypy via workflow env.

        Map GH_TOKEN only onto resembl-clone steps (and toolchain check-updates).
        The package job never needs it.
        """
        for path in (CI_YML, SYNC_YML):
            head = path.read_text(encoding="utf-8").split("\njobs:", 1)[0]
            assert "GH_TOKEN:" not in head, (
                f"{path.name}: GH_TOKEN must not be workflow-wide "
                "(scope it to clone / API steps only)"
            )
        ci = CI_YML.read_text(encoding="utf-8")
        package_job = ci.split("\n  package:\n", 1)[1].split("\n  cli-contract:\n", 1)[0]
        assert "GH_TOKEN:" not in package_job
        assert "github-token:" not in package_job, (
            "the package job never clones resembl and must not receive the token"
        )
        # Inside the action the token is a step-level env on the clone step only.
        action = UV_ENV_ACTION.read_text(encoding="utf-8")
        assert "GH_TOKEN: ${{ inputs.github-token }}" in action
        clone_step, _, uv_step = action.partition("- name: Set up uv\n")
        assert "GH_TOKEN" in clone_step and "GH_TOKEN" not in uv_step
        sync = SYNC_YML.read_text(encoding="utf-8")
        drift = sync.rsplit("name: Check toolchain source drift\n", 1)[1]
        assert "GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}" in drift.split("run: |", 1)[0]

    def test_package_job_uploads_dist_artifacts(self) -> None:
        """Verified wheel/sdist/SBOM/buildinfo must be retained after smoke."""
        text = CI_YML.read_text(encoding="utf-8")
        package_job = text.split("\n  package:\n", 1)[1].split("\n  cli-contract:\n", 1)[0]
        assert "actions/upload-artifact@" in package_job
        assert "dist/rebrew.cdx.json" in package_job
        assert "retention-days: 14" in package_job
        assert "if-no-files-found: error" in package_job

    def test_sbom_outlives_every_later_build(self) -> None:
        """``make build`` clears dist/*.cdx.json and ``sdist-check`` rebuilds.

        The SBOM must be the last build-touching step in the package job and
        the last target in ``pr-check``; anything that runs ``make build``
        afterwards deletes the BOM, and the upload's
        ``if-no-files-found: error`` stays green because the wheel, sdist and
        buildinfo patterns still match.
        """
        text = CI_YML.read_text(encoding="utf-8")
        package_job = text.split("\n  package:\n", 1)[1].split("\n  cli-contract:\n", 1)[0]
        steps = package_job.split("\n      - name: ")[1:]
        sbom = next(i for i, step in enumerate(steps) if "make sbom" in step)
        for later in steps[sbom + 1 :]:
            assert "make sbom" not in later
            # A step that reaches `make build` (directly or via sdist-check)
            # drops the BOM the previous step wrote.
            assert not re.search(r"(?m)^\s*run:.*\bmake (build|sdist-check)\b", later), later
        assert "test -s dist/rebrew.cdx.json" in steps[sbom], (
            "the SBOM step must prove it wrote one"
        )

        pr_check = MAKEFILE.read_text(encoding="utf-8")
        deps = re.search(r"(?m)^pr-check:(?P<deps>[^\n]*)$", pr_check)
        assert deps is not None
        order = deps.group("deps").split()
        assert order.index("sdist-check") < order.index("sbom")
        # No build-touching prerequisite on `sbom` itself: one there would
        # rebuild dist/ and drop the BOM it just wrote.
        assert not _makefile_prereqs("sbom") & {"build", "sdist-check"}

    def test_resembl_clone_uses_retry_helper(self) -> None:
        """Network flakes cloning resembl must retry (same posture as apt-get)."""
        helper = ROOT / "tools" / "ci_clone_resembl.sh"
        assert helper.is_file()
        text = helper.read_text(encoding="utf-8")
        # The retry policy is named, not a bare `1 2 3` / `* 5` in the loop:
        # ci_apt_install.sh states the same two values and both docstrings
        # point at the other, so a change to one has to be visible in the other.
        assert "for ((attempt = 1; attempt <= MAX_ATTEMPTS; attempt++))" in text
        assert "sleep $((attempt * RETRY_BASE_DELAY_SECONDS))" in text
        apt = (ROOT / "tools" / "ci_apt_install.sh").read_text(encoding="utf-8")
        for name in ("MAX_ATTEMPTS", "RETRY_BASE_DELAY_SECONDS"):
            value = re.search(rf"(?m)^{name}=(\d+)$", text).group(1)
            assert re.search(rf"(?m)^{name}=(\d+)$", apt).group(1) == value, name
        assert "GIT_TERMINAL_PROMPT=0" in text
        assert "basename is not 'resembl'" in text
        # Token must live in a mode-0600 gitconfig, not on git argv (ps leak).
        assert "GIT_CONFIG_GLOBAL" in text
        assert "extraheader = AUTHORIZATION: basic" in text
        assert 'auth_args=(-c "http.https://github.com/.extraheader=' not in text
        assert text.index("umask 077") < text.index('"$(mktemp)"')
        assert text.index('token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"') < text.index(
            "unset GH_TOKEN GITHUB_TOKEN"
        )
        assert text.index("unset GH_TOKEN GITHUB_TOKEN") < text.index("clone --depth 1 --branch")
        assert "core.hooksPath=/dev/null" in text
        assert "core.fsmonitor=" in text
        assert "GIT_LFS_SKIP_SMUDGE=1" in text
        assert 'rm -rf -- "${dest}"' in text
        assert "bash tools/ci_clone_resembl.sh" in UV_ENV_ACTION.read_text(encoding="utf-8")
        for path in (CI_YML, SYNC_YML):
            wf = path.read_text(encoding="utf-8")
            assert "git clone --depth 1 --branch" not in wf, path.name

    def test_env_installs_assert_the_lock_is_current(self) -> None:
        """``uv sync --frozen`` never compares ``uv.lock`` to ``pyproject.toml``.

        It only skips the lock update, so a dependency edited without
        ``uv lock`` installs the previous set and every gate in the job then
        runs against an environment the manifest does not describe.  Every
        install that can read the sibling checkout syncs with ``--locked``.
        The one frozen sync left is the ``smoke-wheel`` overlay: re-resolving
        reads ``[tool.uv.sources]``, and running without ``../resembl`` is
        that target's whole point.
        """
        workflows = CI_YML.read_text(encoding="utf-8") + SYNC_YML.read_text(encoding="utf-8")
        installs = re.findall(r"(?m)^\s*run: (uv sync .*)$", workflows)
        assert installs, "no uv sync install step found in the workflows"
        assert [step for step in installs if "--locked" not in step] == []

        makefile = MAKEFILE.read_text(encoding="utf-8")
        assert "UV_SYNC_FLAGS ?= --locked --all-extras --group similarity" in makefile
        overlays = re.findall(r"(?m)^\s*(UV_PROJECT_ENVIRONMENT=\.venv-pkg uv sync .*)$", makefile)
        assert len(overlays) == 1, overlays
        assert "--frozen" in overlays[0] and "--no-install-project" in overlays[0]

    def test_main_push_is_not_cancelled(self) -> None:
        """PR updates cancel the previous run; a main push must finish.

        The package job uploads ``rebrew-dist-<sha>``. Cancelling that run
        drops the verified wheel for that commit.
        """
        head = CI_YML.read_text(encoding="utf-8").split("\njobs:", 1)[0]
        assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in head
        assert "cancel-in-progress: true" not in head

    def test_clone_refuses_non_resembl_dest(self, tmp_path: Path) -> None:
        """``rm -rf`` must not run against a path that is not a resembl checkout."""
        victim = tmp_path / "other"
        victim.write_text("keep", encoding="utf-8")
        result = subprocess.run(
            ["bash", str(ROOT / "tools" / "ci_clone_resembl.sh"), str(victim)],
            env={
                **os.environ,
                "RESEMBL_REF": "v2.0.0",
                "RESEMBL_SHA": "a" * 40,
                "GH_TOKEN": "should-not-be-used",
            },
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == 1
        assert "basename is not 'resembl'" in result.stderr
        assert victim.read_text(encoding="utf-8") == "keep"

    def test_clone_hides_token_from_git(self, tmp_path: Path) -> None:
        """git's argv and environment must not carry the GitHub token.

        The config file is created mode 0600 and removed when the script exits.
        """
        bindir = tmp_path / "bin"
        bindir.mkdir()
        log = tmp_path / "git.log"
        fake = bindir / "git"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\n"
            "from pathlib import Path\n"
            f"log = Path({str(log)!r})\n"
            "with log.open('a', encoding='utf-8') as fh:\n"
            "    fh.write('ARGV ' + ' '.join(sys.argv[1:]) + '\\n')\n"
            "    if os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN'):\n"
            "        fh.write('TOKEN_IN_ENV\\n')\n"
            "    fh.write('LFS ' + os.environ.get('GIT_LFS_SKIP_SMUDGE', '') + '\\n')\n"
            "    cfg = os.environ.get('GIT_CONFIG_GLOBAL', '')\n"
            "    if cfg and os.path.isfile(cfg):\n"
            "        mode = os.stat(cfg).st_mode & 0o777\n"
            "        fh.write(f'MODE {mode:03o}\\n')\n"
            "        fh.write('CFG ' + cfg + '\\n')\n"
            "        fh.write(Path(cfg).read_text(encoding='utf-8'))\n"
            "args = sys.argv[1:]\n"
            "if 'rev-parse' in args:\n"
            "    print(os.environ['EXPECT_SHA'])\n"
            "    raise SystemExit(0)\n"
            "if 'clone' in args:\n"
            "    Path(args[-1]).mkdir(parents=True, exist_ok=True)\n"
            "    raise SystemExit(0)\n"
            "raise SystemExit('unexpected git args')\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        token = "test-token-not-a-secret"
        sha = "a" * 40
        dest = tmp_path / "resembl"
        env = {
            **os.environ,
            "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
            "GH_TOKEN": token,
            "GITHUB_TOKEN": "other-secret-not-used",
            "RESEMBL_REF": "v2.0.0",
            "RESEMBL_SHA": sha,
            "EXPECT_SHA": sha,
        }
        env.pop("GIT_CONFIG_GLOBAL", None)
        result = subprocess.run(
            ["bash", str(ROOT / "tools" / "ci_clone_resembl.sh"), str(dest)],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        recorded = log.read_text(encoding="utf-8") if log.exists() else ""
        assert result.returncode == 0, result.stdout + result.stderr + recorded
        assert "TOKEN_IN_ENV" not in recorded
        assert token not in "\n".join(
            line for line in recorded.splitlines() if line.startswith("ARGV ")
        )
        assert "core.hooksPath=/dev/null" in recorded
        assert "core.fsmonitor=" in recorded
        assert "filter.lfs.smudge=" in recorded
        assert "LFS 1" in recorded
        assert "MODE 600" in recorded
        assert "-- https://github.com/maci0/resembl.git" in recorded
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        assert f"AUTHORIZATION: basic {basic}" in recorded
        cfg_line = next(line for line in recorded.splitlines() if line.startswith("CFG "))
        assert not Path(cfg_line.removeprefix("CFG ")).exists()
        assert dest.is_dir()

    def test_test_job_fetches_tags(self) -> None:
        """Packaging CHANGELOG↔tag contract needs each tag commit on this branch.

        ``fetch-tags`` on a depth-1 checkout fetches tag objects that are not
        ancestors of HEAD, so ``git describe`` still fails.
        """
        text = CI_YML.read_text(encoding="utf-8")
        test_job = text.split("\n  test:\n", 1)[1].split("\n  pre-commit:\n", 1)[0]
        assert "fetch-depth: 0" in test_job
        assert "fetch-tags: true" in test_job

    def test_makefile_recipes_are_posix_sh(self) -> None:
        """Make invokes /bin/sh; on Debian/Ubuntu that is dash (no pipefail)."""
        text = MAKEFILE.read_text(encoding="utf-8")
        assert "pipefail" not in text, (
            "Makefile recipes must stay POSIX sh (set -eu); pipefail is bash-only "
            "and breaks make on stock Debian/Ubuntu where /bin/sh is dash"
        )
        assert "set -eu" in text

    def test_buildinfo_rule_rebuilds_on_a_source_edit(self) -> None:
        """A stale dist/ must not pass `sdist-check` / `smoke-wheel`.

        Both depend on `dist/rebrew.buildinfo` instead of the phony `build`
        (see test_sdist_check_does_not_rebuild_over_the_sbom), which leaves
        make free to accept a buildinfo older than the tree it describes: a
        contributor edits a source file, runs `make sdist-check` on its own,
        and the gate compares a previous wheel against a previous sdist.  The
        file rule therefore carries the build's inputs, minus the __pycache__
        and egg-info a test run or a bare `uv build` writes on every pass.
        """
        text = MAKEFILE.read_text(encoding="utf-8")
        assert "BUILD_INPUTS :=" in text
        assert "-not -path '*/__pycache__/*'" in text
        assert "-not -path '*.egg-info/*'" in text
        assert "dist/rebrew.buildinfo: $(BUILD_INPUTS) $(BUILD_INPUT_DIRS)" in text
        # The normalizer rewrites both archives after the build, so it decides
        # the shipped bytes; it lives under tools/, not src/, so a rewrite of
        # it was invisible to the find() above and left dist/ describing the
        # previous tree.  .python-version picks the interpreter uv builds with.
        build_inputs = text.split("BUILD_INPUTS :=", 1)[1].split("\n\n", 1)[0]
        assert "tools/normalize_sdist.py" in build_inputs
        assert ".python-version" in build_inputs
        # The sdist ships the top-level docs and license files, and the wheel
        # ships the license files under dist-info, so editing one changes the
        # artifacts.  None lives under src/, so the find() above cannot see it.
        for doc in ("README.md", "CHANGELOG.md", "SECURITY.md", "LICENSE", "NOTICE"):
            assert doc in build_inputs, f"{doc} ships but is not a build input"

    def test_buildinfo_rule_rebuilds_on_a_source_add_or_delete(self) -> None:
        """`BUILD_INPUTS` alone cannot see a file appearing or disappearing.

        `find src -type f` lists only what exists when make expands it, and
        make rebuilds a target when a prerequisite is *newer*, not when one
        goes away.  Adding a module or deleting one therefore left every
        listed prerequisite untouched, the buildinfo file looked current, and
        `make sdist-check` / `make smoke-wheel` verified the previous tree's
        artifacts.  The directories are prerequisites for that reason: a
        directory's mtime moves exactly when an entry inside it is created,
        removed, or renamed, and it settles again as soon as it does, so a
        test run does not put the rule into a rebuild loop.
        """
        text = MAKEFILE.read_text(encoding="utf-8")
        assert "BUILD_INPUT_DIRS :=" in text
        dirs = text.split("BUILD_INPUT_DIRS :=", 1)[1].split("\n\n", 1)[0]
        assert "find src -type d" in dirs
        # Same residue exclusions: a test run rewrites __pycache__ on every
        # pass and `uv build` creates and removes egg-info, so a narrower
        # filter here rebuilds dist/ constantly without changing a shipped
        # byte.
        assert "-not -path '*/__pycache__*'" in dirs
        assert "-not -path '*.egg-info*'" in dirs

    def test_makefile_is_sequential(self) -> None:
        """Targets that share dist/ must not run concurrently under `make -j`.

        `build` deletes dist/*.whl, dist/*.tar.gz, dist/*.buildinfo and
        dist/*.cdx.json before it builds; `sbom` writes dist/rebrew.cdx.json;
        `sdist-check` and `smoke-wheel` read the wheel `build` leaves there.
        Make orders prerequisites only by dependency, never by position on the
        line, so without .NOTPARALLEL a `make -j pr-check` deleted the BOM it
        had just generated (the failure test_sbom_outlives_every_later_build
        exists for) and raced the phony `build` against the recursive one
        behind dist/rebrew.buildinfo.
        """
        text = MAKEFILE.read_text(encoding="utf-8")
        assert ".NOTPARALLEL:" in text

    def test_shipped_wheel_is_built_from_the_source_tree(self) -> None:
        """`make sdist-check` must compare two independently built wheels.

        Bare `uv build` builds the wheel *from the sdist it just wrote*, so
        the shipped wheel and the sdist-check wheel shared an input.  A
        MANIFEST.in prune that dropped a runtime file then removed it from
        both, and the gate meant to catch exactly that stayed green on a
        wheel missing `agent-skills/`.  Two `uv build` calls, one per format,
        each from the source tree, restore the independence.
        """
        text = MAKEFILE.read_text(encoding="utf-8")
        build = text.split("\nbuild: warn-uv-version\n", 1)[1].split("\n# CycloneDX", 1)[0]
        invocations = re.findall(r"(?m)^\t+uv build (?P<flags>.*)$", build)
        assert len(invocations) == 2, build
        assert any("--sdist" in flags for flags in invocations), invocations
        assert any("--wheel" in flags for flags in invocations), invocations
        # Neither call may name an sdist as its input.
        assert not any(".tar.gz" in flags for flags in invocations), invocations

    def test_sdist_check_does_not_rebuild_over_the_sbom(self) -> None:
        """`sdist-check` must not re-run `build` and wipe dist/.

        `build` is phony and opens by deleting dist/*.whl, dist/*.tar.gz,
        dist/*.buildinfo and dist/*.cdx.json.  The CI package job runs
        `make sdist-check` as its own invocation after `make sbom`, so a
        `sdist-check: build` prerequisite rebuilt the tree and dropped the
        SBOM and buildinfo the upload step requires (`if-no-files-found:
        error` then fails, or an upload without them ships).  Depending on
        the buildinfo file builds only when dist/ is empty.
        """
        text = MAKEFILE.read_text(encoding="utf-8")
        assert _makefile_prereqs("sdist-check") == {"dist/rebrew.buildinfo", "ensure-uv"}
        assert "dist/rebrew.buildinfo:" in text, (
            "dist/rebrew.buildinfo needs a rule that runs `make build` when dist/ is empty"
        )
        # `build` must still clean dist/ itself; that is what makes the file
        # rule above the right trigger.
        build = text.split("\nbuild: warn-uv-version\n", 1)[1].split("\n# CycloneDX", 1)[0]
        assert "dist/*.cdx.json" in build

    def test_pr_check_builds_before_both_dist_consumers(self) -> None:
        """`pr-check` runs the targets itself, so the order is its own doing.

        `build` clears `dist/`, so it has to come first; `sdist-check` and
        `sbom` both read what it leaves there and neither rebuilds.  The old
        rule put `sbom` before `sdist-check` because `sdist-check` used to
        depend on the phony `build` and so deleted `dist/*.cdx.json`; it now
        depends on `dist/rebrew.buildinfo` and builds only when `dist/` is
        empty, so `sbom` last survives the run.
        """
        text = MAKEFILE.read_text(encoding="utf-8")
        match = re.search(r"(?m)^pr-check:(?P<deps>[^\n]*)$", text)
        assert match is not None
        deps = match.group("deps").split()
        assert deps.index("build") < deps.index("sdist-check")
        assert deps.index("build") < deps.index("sbom")

    def test_package_smoke_honors_lockfile(self) -> None:
        """Wheel smoke-install must not resolve runtime deps from live PyPI.

        ``uv pip install dist/*.whl`` ignores ``uv.lock``; the package job
        syncs locked deps with ``--no-install-project`` then overlays the
        wheel with ``--no-deps``.  The build itself must go through
        ``make build`` so buildinfo / locale knobs cannot drift from the
        Makefile, and the smoke install through ``make smoke-wheel`` for the
        same reason.
        """
        text = CI_YML.read_text(encoding="utf-8")
        package_job = text.split("\n  package:\n", 1)[1].split("\n  cli-contract:\n", 1)[0]
        assert "make build" in package_job
        assert "setuptools=80.10.2" not in package_job
        assert "make smoke-wheel" in package_job
        # The recipe lives in the Makefile only: the two copies drifted
        # before, so an inline `uv venv` / `uv sync` is a regression.
        assert "uv venv .venv-pkg" not in package_job
        assert ".venv-pkg/bin/python" not in package_job
        recipe = (
            MAKEFILE.read_text(encoding="utf-8").split("\nsmoke-wheel:", 1)[1].split("\n#", 1)[0]
        )
        assert "uv sync --frozen --no-dev --no-default-groups --no-install-project" in recipe
        assert "uv pip install --python .venv-pkg --no-deps" in recipe
        assert "dist/rebrew.buildinfo" in package_job
        # Repro check rebuilds through `make build` at another path (no
        # re-inlined recipe) and must not hide a failing build behind `tail`.
        # The reproducibility check itself is pinned in
        # test_repro_tree_is_removed_on_every_exit_path /
        # test_repro_check_runs_from_the_makefile, which read the Makefile.
        assert "uv build" not in package_job
        assert "| tail" not in package_job

    def test_version_independent_gates_run_on_one_matrix_entry(self) -> None:
        """Fixture freshness and the idempotency sweep read the tree, not the
        interpreter, so running them on both matrix entries doubles their cost
        for a result that cannot differ.  Same posture as the coverage floor.
        """
        test_job = (
            CI_YML.read_text(encoding="utf-8")
            .split("\n  test:\n", 1)[1]
            .split("\n  pre-commit:\n", 1)[0]
        )
        steps = test_job.split("\n      - name: ")[1:]
        assert steps, "no steps in the test job"
        pinned = (ROOT / ".python-version").read_text(encoding="utf-8").strip()
        for target in ("make gen-fixtures-check", "make idempotency-check"):
            step = next(block for block in steps if target in block)
            assert f"if: matrix.python-version == '{pinned}'" in step, step

    def test_repro_tree_is_removed_on_every_exit_path(self) -> None:
        """A failed reproducibility check must not leave the second tree behind.

        A hash mismatch exits non-zero and ends the recipe, so a trailing
        ``rm -rf`` never runs and the extracted source copy under
        ``.scratch/rebuild`` outlives it. An EXIT trap covers the build
        failure, the mismatch, and the happy path alike.
        """
        text = MAKEFILE.read_text(encoding="utf-8")
        recipe = re.search(
            r"(?m)^build-repro:.*?^\t@set -eu; \\$(?P<body>.*?)(?=\n\n)",
            text,
            re.S,
        )
        assert recipe is not None, "build-repro target not found"
        body = recipe.group("body")
        assert "trap 'rm -rf -- \"$$repro\"' EXIT" in body
        # The trap is armed before the tree is created, and the literal
        # trailing rm is gone (the trap replaced it).
        assert body.index("trap ") < body.index('mkdir -p "$$repro"')
        assert body.count("rm -rf") == 2, (
            "the trap and the pre-extract clean are the only removals; a trailing "
            "rm -rf is what the trap replaced"
        )
        # umask must apply to the extract. Set after tar, it never reaches
        # the source modes setuptools copies into the wheel.
        assert re.search(
            r"umask 077; \\\n\trm -rf \"\$\$repro\"; \\\n\tmkdir -p \"\$\$repro\"; \\\n"
            r"\tgit archive HEAD \| tar -x -C \"\$\$repro\"",
            body,
        )
        # The second build has no .git of its own, so the epoch travels in
        # the environment; a different path, TZ and locale come with it.
        assert "SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) TZ=Asia/Tokyo LC_ALL=C.UTF-8" in body

    def test_repro_check_runs_from_the_makefile(self) -> None:
        """CI calls the target: an inline recipe is a gate no contributor can run.

        The package job's reproducibility step used to inline the whole
        `git archive` / rebuild / hash-diff sequence in YAML, so a
        non-reproducible artifact surfaced only after the push. The step now
        exports the commit epoch and runs the target, and ``pr-check`` runs it
        with everything else.
        """
        package_job = (
            CI_YML.read_text(encoding="utf-8")
            .split("\n  package:\n", 1)[1]
            .split("\n  cli-contract:\n", 1)[0]
        )
        step = next(
            block for block in package_job.split("\n      - name: ") if "make build-repro" in block
        )
        assert "git archive" not in step.split("run:", 1)[1], "the recipe is inlined in CI again"
        # The copy has no .git, so the second build needs the epoch from the
        # environment; the Makefile default cannot supply it.
        assert "SOURCE_DATE_EPOCH=" in step
        assert "export SOURCE_DATE_EPOCH" in step
        pr_check = re.search(
            r"(?m)^pr-check:(?P<deps>[^\n]*)$", MAKEFILE.read_text(encoding="utf-8")
        )
        assert pr_check is not None
        assert "build-repro" in pr_check.group("deps").split()

    def test_no_recipe_comment_swallows_the_rest_of_its_line(self) -> None:
        """A `#` line inside a backslash-continued recipe eats the code after it.

        Make hands the joined recipe to one shell, so a recipe line beginning
        with `#` comments out everything up to the newline of the last physical
        line it was continued into.  `release-check` carried its "notes split
        across the two headings" comment there, so the `UNREL=$$(awk ...)`
        assignment and the `[ -n "$$UNREL" ]` check built on it were skipped
        and the target died on an unbound variable instead of naming the
        changelog problem.  Keep recipe prose in a comment above the target.
        """
        offenders = [
            f"{i}: {line.strip()}"
            for i, line in enumerate(MAKEFILE.read_text(encoding="utf-8").splitlines(), 1)
            if line.startswith("\t#")
        ]
        assert not offenders, (
            "comment inside a continued recipe; move it above the target: " + "; ".join(offenders)
        )

    def test_buildinfo_version_matches_the_artifacts_it_sits_beside(self) -> None:
        """The manifest must not name a version dist/ does not carry.

        ``dist/rebrew.buildinfo`` is the record a third party rebuilds from, and
        every dist/ consumer (``sdist-check``, ``smoke-wheel``, the CI upload)
        locates the artifacts by name.  The recipe parsed ``__version__`` for
        the ``version=`` line without checking it against what the build left
        in dist/, so a stale build cache or egg-info shipped
        ``rebrew-<old>-*.whl`` next to a manifest claiming the new version and
        every gate stayed green on the wrong pair.
        """
        build = MAKEFILE.read_text(encoding="utf-8")
        build = build.split("\nbuild: warn-uv-version\n", 1)[1].split("\n# Prove the wheel", 1)[0]
        version_line = next(
            line for line in build.splitlines() if line.strip().startswith("ver=$$(")
        )
        assert "src/rebrew/__init__.py" in version_line
        after = build.split(version_line, 1)[1]
        assert "set -- dist/rebrew-$$ver-*.whl" in after
        assert '[ -f "dist/rebrew-$$ver.tar.gz" ]' in after
        # Both checks must precede the redirect that writes the manifest, so a
        # mismatch fails the build instead of recording it.
        assert after.index("dist/rebrew-$$ver.tar.gz") < after.index("> dist/rebrew.buildinfo")

    def test_makefile_build_writes_buildinfo_and_cleans_residue(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        assert "dist/rebrew.buildinfo" in text
        assert "rm -rf build rebrew.egg-info" in text
        # Clean before building too: setuptools packs leftover build/lib files
        # into the wheel.
        assert text.index("rm -rf build rebrew.egg-info") < text.index(
            "uv build --sdist --out-dir dist --build-constraints"
        )
        # setuptools pin must be read from pyproject.toml, not hardcoded —
        # otherwise bumping build-system.requires leaves a lying buildinfo.
        assert "setuptools=80.10.2" not in text
        assert r"setuptools==\(" in text or "setuptools==" in text
        assert "python-version=" in text
        assert "source-commit=" in text
        assert "source-dirty=" in text

    def test_buildinfo_records_the_artifacts_and_the_lock_it_ships_with(self) -> None:
        """The manifest must name the bytes beside it, not only the knobs.

        ``dist/rebrew.buildinfo`` travels with the wheel, the sdist and the
        SBOM.  It recorded the build-backend pin but neither ``uv.lock`` (the
        input the SBOM inventories and the smoke install resolves) nor the
        sha256 of the two archives, so a consumer holding the artifacts could
        not tell whether the provenance described them, and a rebuild attempt
        had no lock to reproduce the dependency set from.
        """
        text = MAKEFILE.read_text(encoding="utf-8")
        for key in ("uv-lock-sha256=", "wheel-sha256=", "sdist-sha256="):
            assert f'echo "{key}' in text, key
        assert "lksum=$$(sha uv.lock)" in text
        # The hashes must be taken after normalize_sdist.py rewrites both
        # archives, or the manifest describes bytes that never shipped.
        normalize = text.index("tools/normalize_sdist.py dist/*.tar.gz dist/*.whl")
        assert normalize < text.index("wheelsum=$$(sha")
        assert normalize < text.index("sdistsum=$$(sha")
        # CI's package job asserts the same lines on the artifact it uploads.
        package_job = CI_YML.read_text(encoding="utf-8")
        for key in ("wheel-sha256=", "sdist-sha256=", "uv-lock-sha256="):
            assert f"grep -q '^{key}' dist/rebrew.buildinfo" in package_job, key

    def test_build_warns_on_an_uncommitted_tree(self) -> None:
        """Artifacts from a dirty tree match no commit, and build-repro says so.

        ``source-dirty=`` recorded the fact and nothing read it, so a build
        from uncommitted edits produced a dist/ whose provenance named a commit
        it was not built from, and the failure surfaced later as an unrelated
        reproducibility mismatch.
        """
        build = MAKEFILE.read_text(encoding="utf-8")
        build = build.split("\nbuild: warn-uv-version\n", 1)[1].split("\n# Prove the wheel", 1)[0]
        lines = build.splitlines()
        warn = next(line for line in lines if "uncommitted changes" in line)
        guard = next(line for line in lines if line.strip().startswith("dirty="))
        # A `git archive` copy has no .git, so the guard must resolve to n/a
        # rather than warn (or fail) on every `make build-repro` rebuild.
        assert "git rev-parse --git-dir" in guard
        assert "git status --porcelain" in lines[lines.index(guard) + 1]
        assert "echo n/a" in lines[lines.index(guard) + 2]
        assert lines.index(guard) < lines.index(warn)
        assert 'if [ "$$dirty" = yes ]' in lines[lines.index(warn) - 1]
        assert "build-repro" in warn
        # One `git status` call feeds both the warning and the manifest line.
        assert 'echo "source-dirty=$$dirty"' in build
        assert build.count("git status --porcelain") == 1

    def test_buildinfo_setuptools_matches_pyproject_pin(self) -> None:
        """Static contract: Makefile sed pattern matches the exact pyproject pin."""
        import tomllib

        requires = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
            "build-system"
        ]["requires"]
        assert len(requires) == 1
        assert requires[0].startswith("setuptools==")
        pin = requires[0].removeprefix("setuptools==")
        # The recipe must be able to extract that pin (same sed as make build).
        extracted = subprocess.run(
            [
                "sed",
                "-n",
                r's/^requires = \["setuptools==\([0-9.][0-9.]*\)"\]/\1/p',
                str(ROOT / "pyproject.toml"),
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        assert extracted == pin, (extracted, pin)

    def test_pytest_loads_ansi_env_plugin(self) -> None:
        """Bare ``uv run pytest`` must disable typer/Rich ANSI like ``make test``.

        ``FORCE_COLOR`` / ``GITHUB_ACTIONS`` otherwise split version digits and
        option names across escape sequences and fail CliRunner assertions.
        """
        import tomllib

        plugin = ROOT / "tests" / "pytest_ansi_env.py"
        assert plugin.is_file()
        text = plugin.read_text(encoding="utf-8")
        assert 'os.environ["NO_COLOR"]' in text
        assert 'os.environ["TERM"]' in text
        assert 'os.environ["_TYPER_FORCE_DISABLE_TERMINAL"]' in text
        ini = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        pytest_ini = ini["tool"]["pytest"]["ini_options"]
        assert "tests" in pytest_ini["pythonpath"]
        assert pytest_ini["addopts"] == ["-p", "pytest_ansi_env"]

    def test_coverage_floor_matches_pyproject(self) -> None:
        """slipcover ignores [tool.slipcover]; ``make coverage`` passes the floor."""
        import tomllib

        text = MAKEFILE.read_text(encoding="utf-8")
        m = re.search(r"(?m)^COV_FLOOR\s*\?=\s*(\d+)\s*$", text)
        assert m is not None, "COV_FLOOR missing from Makefile"
        assert "--fail-under $(COV_FLOOR)" in text
        ini = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        assert int(m.group(1)) == ini["tool"]["slipcover"]["fail_under"]

    def test_bare_pytest_survives_force_color(self) -> None:
        """Regression: FORCE_COLOR alone used to break --version / skills show."""
        env = {
            **os.environ,
            "FORCE_COLOR": "1",
            "GITHUB_ACTIONS": "true",
        }
        # Drop recipe-level guards so only the pytest plugin can save us.
        for key in ("NO_COLOR", "TERM", "_TYPER_FORCE_DISABLE_TERMINAL"):
            env.pop(key, None)
        result = subprocess.run(
            [
                "uv",
                "run",
                "--frozen",
                "pytest",
                "tests/test_main.py::TestUmbrellaCli::test_version_matches_module",
                "tests/test_skills.py::TestCLISkillsShow::test_show_unknown_skill_fails",
                "-q",
                "--tb=line",
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    def test_package_job_inlines_no_python(self) -> None:
        """Python in a `run:` block is a shell string with an exit code and no
        traceback; the checks live in tools/ so a failure names a file and a
        line, and the repo keeps one language per command.
        """
        text = CI_YML.read_text(encoding="utf-8")
        assert "python -c" not in text, "move the check into tools/ and call it"
        package_job = text.split("\n  package:\n", 1)[1].split("\n  cli-contract:\n", 1)[0]
        # make sbom owns the SBOM build; generate_sbom.py validates its own
        # output, so the job needs no second inline parse to gate the document.
        assert "make sbom" in package_job
        assert "make smoke-wheel" in package_job
        assert (ROOT / "tools" / "smoke_wheel_install.py").is_file()

    def test_readme_development_uv_runs_are_frozen(self) -> None:
        """README Development is the clean-clone path — bare ``uv run`` can rewrite the lock."""
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        section = text.split("## Development\n", 1)[1].split("\n## ", 1)[0]
        commands = [m.group(1) for m in re.finditer(r"(?m)(?<![\w-])uv run\s+(\S+)", section)]
        assert all(cmd in {"--frozen", "--locked", "--no-sync"} for cmd in commands), (
            f"README Development has lock-unsafe uv run: {commands}"
        )

    def test_makefile_setup_warns_without_nasm(self) -> None:
        """Bootstrap should name the nasm host dep before the first test failure."""
        text = MAKEFILE.read_text(encoding="utf-8")
        assert "warn-nasm" in text
        assert {"ensure-resembl", "warn-nasm"} <= _makefile_prereqs("setup")
        assert "Before a PR: make all && make check && make build" in text

    def test_makefile_test_one_runs_without_nasm(self) -> None:
        """Single-file loop must not hard-fail on nasm; the nasm tests skip on their own."""
        assert "warn-nasm" in _makefile_prereqs("test-one")
        assert "ensure-nasm" in _makefile_prereqs("test")

    def test_pr_check_installs_the_built_wheel(self) -> None:
        """The wheel smoke install is a CI gate; pr-check has to run it locally.

        ``import rebrew`` and the console script read none of the files
        package-data carries, so a wheel missing ``agent-skills/`` or
        ``py.typed`` installs and runs fine and only fails for the user.
        """
        text = MAKEFILE.read_text(encoding="utf-8")
        match = re.search(r"(?m)^pr-check:(?P<deps>[^\n]*)$", text)
        assert match is not None
        deps = match.group("deps").split()
        assert "smoke-wheel" in deps
        # After build (which clears dist/) and after sdist-check, so the
        # installed wheel is the one the sdist comparison accepted.
        assert deps.index("build") < deps.index("smoke-wheel")
        assert deps.index("sdist-check") < deps.index("smoke-wheel")
        recipe = text.split("\nsmoke-wheel:", 1)[1].split("\n#", 1)[0]
        # Locked runtime deps, then the wheel overlaid with --no-deps: a live
        # PyPI resolve must not drift past the audited lock.
        assert "uv sync --frozen --no-dev --no-default-groups --no-install-project" in recipe
        assert "uv pip install --python .venv-pkg --no-deps" in recipe
        assert "tools/smoke_wheel_install.py" in recipe
        assert ".venv-pkg/bin/rebrew --help" in recipe
        # A missing artifact must be named, not globbed literally into uv.
        assert '[ -f "$$1" ]' in recipe

    def test_clone_resembl_preflights_bash(self) -> None:
        """``tools/ci_clone_resembl.sh`` is bash; the target says so, the shell does not."""
        text = MAKEFILE.read_text(encoding="utf-8")
        assert "ensure-bash" in _makefile_prereqs("clone-resembl")
        assert "command -v bash" in text
        assert (
            (ROOT / "tools" / "ci_clone_resembl.sh")
            .read_text(encoding="utf-8")
            .startswith("#!/usr/bin/env bash")
        )

    @pytest.mark.parametrize("target", sorted(_makefile_uv_targets()))
    def test_uv_targets_preflight_uv(self, target: str) -> None:
        """A missing uv must be a named error, not a bare ``uv: not found`` from the recipe."""
        assert _UV_PREFLIGHTS & _makefile_prereqs(target), (
            f"make {target} runs uv without a preflight"
        )

    def test_uv_target_discovery_finds_every_recipe_caller(self) -> None:
        """The derived set must not silently go empty and pass the gate above."""
        discovered = _makefile_uv_targets()
        assert {"test", "test-one", "mypy", "build", "release-check", "sdist-check"} <= discovered

    def test_mypy_preflights_the_prove_extra(self) -> None:
        """Without the extra every angr reference is Any: 39 phantom mypy errors, no cause."""
        assert "ensure-extras" in _makefile_prereqs("mypy")
        hook = (
            (ROOT / ".pre-commit-config.yaml")
            .read_text(encoding="utf-8")
            .split("- id: mypy\n", 1)[1]
            .split("- id:", 1)[0]
        )
        assert re.search(r"(?m)^\s*entry: make --no-print-directory mypy\s*$", hook)

    def test_mypy_preflights_the_similarity_group(self) -> None:
        """scoring.py imports rapidfuzz/resembl, both typed: silence would hide a real gap."""
        text = MAKEFILE.read_text(encoding="utf-8")
        guard = text.split("ensure-extras:\n", 1)[1].split("\n\n", 1)[0]
        assert "import rapidfuzz, resembl" in guard
        assert "--group similarity" in guard
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        overrides = pyproject.split("[[tool.mypy.overrides]]", 1)[1]
        assert '"rapidfuzz"' not in overrides, (
            "rapidfuzz ships type information; an ignore_missing_imports entry would "
            "mute the check instead of asking for the group to be installed"
        )

    def test_pre_push_pytest_hook_runs_make_test(self) -> None:
        """Pre-push must hit ``ensure-nasm``; a bare pytest skips asm tests CI runs."""
        text = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        hook = text.split("- id: pytest\n", 1)[1].split("- id:", 1)[0]
        assert re.search(r"(?m)^\s*entry: make --no-print-directory test\s*$", hook)
        assert "stages: [pre-push]" in hook

    def test_shellcheck_hook_is_installed_before_it_runs(self) -> None:
        """The hook exits 0 without shellcheck, so CI must install it or the gate is silent."""
        text = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        hook = text.split("- id: shellcheck\n", 1)[1].split("- id:", 1)[0]
        assert "command -v shellcheck" in hook
        assert "types: [shell]" in hook
        ci = CI_YML.read_text(encoding="utf-8")
        pre_commit_job = next(
            block
            for block in re.split(r"\n(?=  [a-z][a-z-]*:\n)", ci)
            if block.splitlines()[0].strip().rstrip(":") == "pre-commit"
        )
        assert "shellcheck" in pre_commit_job
        assert pre_commit_job.index("shellcheck") < pre_commit_job.index("make check")

    @pytest.mark.parametrize(
        "path",
        [
            CI_YML,
            SYNC_YML,
            MAKEFILE,
            ROOT / ".pre-commit-config.yaml",
            ROOT / "docs" / "ADDING_A_COMMAND.md",
            ROOT / "docs" / "DEVELOPMENT.md",
            ROOT / "docs" / "CI.md",
            ROOT / "docs" / "TOOLCHAIN.md",
            ROOT / "docs" / "FLIRT_SIGNATURES.md",
            ROOT / "tools" / "generate_sbom.py",
            ROOT / "tools" / "normalize_sdist.py",
            ROOT / "tools" / "bench_hotpaths.py",
            ROOT / "tools" / "validate_skill_commands.py",
            ROOT / "tools" / "sync_decomp_flags.py",
        ],
    )
    def test_uv_run_preserves_lockfile(self, path: Path) -> None:
        commands = [
            match.group(1)
            for line in path.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
            for match in re.finditer(r"\buv run\s+(\S+)", line)
        ]
        # A workflow delegates to the Makefile / tools/ and may legitimately
        # carry no `uv run` at all; the guard is that none is lock-unsafe.
        if path.suffix == ".yml":
            return
        assert commands, path
        # --no-project never reads or writes uv.lock (uv warns that --frozen
        # is a no-op beside it).
        allowed = {"--frozen", "--locked", "--no-sync", "--no-project"}
        assert all(command in allowed for command in commands), (
            f"{path.relative_to(ROOT)} has uv run commands that can rewrite uv.lock"
        )


class TestCiAptInstall:
    """One retrying helper for every apt step (nasm, shellcheck).

    Both packages come from apt mirrors that flake under load; an inlined
    retry loop per job is how one of them ends up without a retry.
    """

    HELPER = ROOT / "tools" / "ci_apt_install.sh"

    def test_helper_retries_and_reports_the_package(self) -> None:
        assert self.HELPER.is_file()
        text = self.HELPER.read_text(encoding="utf-8")
        assert "MAX_ATTEMPTS=3" in text
        assert "RETRY_BASE_DELAY_SECONDS=5" in text
        assert 'retry "apt-get update" run_root apt-get update -qq' in text
        assert "DEBIAN_FRONTEND=noninteractive" in text
        assert "--no-install-recommends" in text
        # Success is proven by the binary, not by apt's exit code alone.
        assert "is still not on PATH" in text

    def test_every_apt_step_uses_the_helper(self) -> None:
        """No workflow may inline `apt-get install`: the retrying helper is the
        one place the mirror-flake policy lives, and the drift result gate's
        `jq` is as much a host dependency as nasm and shellcheck.
        """
        for path in (CI_YML, SYNC_YML):
            text = path.read_text(encoding="utf-8")
            assert "apt-get install" not in text, (
                f"{path.name}: call tools/ci_apt_install.sh instead"
            )
        ci = CI_YML.read_text(encoding="utf-8")
        assert ci.count("bash tools/ci_apt_install.sh") == 2, ci
        for pkg in ("nasm", "shellcheck"):
            assert f"bash tools/ci_apt_install.sh {pkg}" in ci, pkg
        sync = SYNC_YML.read_text(encoding="utf-8")
        assert "bash tools/ci_apt_install.sh jq" in sync

    def test_install_is_skipped_when_the_binary_exists(self, tmp_path: Path) -> None:
        """A runner image that already ships the package needs no apt round trip."""
        bindir = tmp_path / "bin"
        bindir.mkdir()
        fake = bindir / "apt-get"
        fake.write_text(
            "#!/usr/bin/env python3\nimport sys\n"
            "print('apt-get ran: ' + ' '.join(sys.argv[1:]), file=sys.stderr)\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        stub = bindir / "shellcheck"
        stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        stub.chmod(0o755)
        env = {**os.environ, "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"}
        result = subprocess.run(
            ["bash", str(self.HELPER), "shellcheck"],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "already on PATH: shellcheck" in result.stdout
        assert "apt-get ran" not in result.stderr

    def test_persistent_apt_failure_fails_the_step(self, tmp_path: Path) -> None:
        """Every attempt failing must exit non-zero instead of looping on success."""
        bindir = tmp_path / "bin"
        bindir.mkdir()
        calls = tmp_path / "calls"
        fake = bindir / "apt-get"
        fake.write_text(
            "#!/usr/bin/env python3\nimport os, sys\n"
            "from pathlib import Path\n"
            f"Path({str(calls)!r}).open('a').write(' '.join(sys.argv[1:]) + '\\n')\n"
            "raise SystemExit(100)\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        # The helper retries with a backoff sleep and elevates through sudo;
        # stub both so the test asserts the retry contract, not the wall clock.
        passthrough = bindir / "sudo"
        passthrough.write_text('#!/bin/sh\nexec "$@"\n', encoding="utf-8")
        passthrough.chmod(0o755)
        nap = bindir / "sleep"
        nap.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        nap.chmod(0o755)
        env = {**os.environ, "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"}
        result = subprocess.run(
            ["bash", str(self.HELPER), "definitely-not-installed"],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 1
        assert "apt-get update failed after 3 attempts" in result.stderr
        # install must not run when update never succeeded
        assert "install" not in calls.read_text(encoding="utf-8")


class TestToolchainSync:
    def test_drift_gate_parses_with_a_declared_host_dependency(self) -> None:
        """``jq`` gates the drift verdict, so the job installs it before use.

        Assuming the runner image keeps shipping ``jq`` makes a nightly
        failure mode the repo cannot fix by re-running: a dropped package
        fails every run until the image is pinned differently. Same posture
        as the shellcheck install in ci.yml's pre-commit job.
        """
        sync = SYNC_YML.read_text(encoding="utf-8")
        _, _, rest = sync.partition("      - name: Install jq (drift result gate)")
        assert rest, "no jq install step in toolchain-sync.yml"
        step, _, drift = rest.partition("      - name: Check toolchain source drift\n")
        assert step, "the jq install is not its own step"
        assert "bash tools/ci_apt_install.sh jq" in step, step
        assert "jq --version" in step, step
        assert "jq -e" in drift, drift

    def test_drift_gate_allowlist_matches_the_reported_statuses(self) -> None:
        """The gate must accept exactly the statuses ``check-updates`` emits.

        A wording change in ``rebrew.toolchain_cli`` used to leave the
        ``jq`` allowlist naming an old spelling: every source then reads as
        neither current nor static and the nightly fails with a bare exit
        code. The two lists now live in the source as ``STATUS_*`` constants
        and the gate reads them from a single ``$ok`` value, so only the
        wording can drift, and this test fails when it does.
        """
        from rebrew.toolchain_cli import (
            STATUS_CURRENT,
            STATUS_STATIC_ASSET,
            STATUS_STATIC_TARBALL,
        )

        sync = SYNC_YML.read_text(encoding="utf-8")
        m = re.search(r"(?m)^          ok='(?P<list>\[[^']*\])'$", sync)
        assert m, "no ok= allowlist in the drift step"
        assert json.loads(m.group("list")) == [
            STATUS_CURRENT,
            STATUS_STATIC_ASSET,
            STATUS_STATIC_TARBALL,
        ]
        # The diagnostic must read the same list, not restate the spellings.
        drift = sync.rsplit("name: Check toolchain source drift\n", 1)[1]
        assert drift.count('--argjson ok "$ok"') == 2, drift
        assert '"static (' not in drift.split("ok='", 1)[1].split("'", 1)[1], drift

    def test_drift_gate_names_the_failing_sources(self) -> None:
        """A red nightly must say which source failed, not just exit 1."""
        drift = SYNC_YML.read_text(encoding="utf-8").rsplit(
            "name: Check toolchain source drift\n", 1
        )[1]
        assert "sources that are neither current nor static:" in drift
        assert "select(.value as $s | $ok | index($s) | not)" in drift

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
        # A failing verdict names the source it is about, so a red nightly
        # says which pin to look at instead of only what the exit code was.
        from rebrew.toolchain_cli import STATUS_CURRENT, STATUS_STATIC_ASSET, STATUS_STATIC_TARBALL

        passing = {STATUS_CURRENT, STATUS_STATIC_ASSET, STATUS_STATIC_TARBALL}
        if expected == 1 and status is not None and status not in passing:
            assert f"  compiler: {status}" in result.stderr, result.stderr
        else:
            assert "neither current nor static" not in result.stderr, result.stderr
