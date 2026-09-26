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

    def test_resembl_clone_uses_retry_helper(self) -> None:
        """Network flakes cloning resembl must retry (same posture as apt-get)."""
        helper = ROOT / "tools" / "ci_clone_resembl.sh"
        assert helper.is_file()
        text = helper.read_text(encoding="utf-8")
        assert "for attempt in 1 2 3" in text
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
        wheel with ``--no-deps``.  The build itself must go through
        ``make build`` so buildinfo / locale knobs cannot drift from the
        Makefile.
        """
        text = CI_YML.read_text(encoding="utf-8")
        package_job = text.split("\n  package:\n", 1)[1].split("\n  cli-contract:\n", 1)[0]
        assert "make build" in package_job
        assert "setuptools=80.10.2" not in package_job
        assert "uv sync --frozen --no-dev --no-default-groups --no-install-project" in package_job
        assert "uv pip install --python .venv-pkg --no-deps" in package_job
        assert 'uv pip install --python .venv-pkg "${wheels[0]}"' not in package_job
        assert "dist/rebrew.buildinfo" in package_job
        # Repro check rebuilds through `make build` at another path (no
        # re-inlined recipe) and must not hide a failing build behind `tail`.
        assert "make -C ../rebrew-repro build" in package_job
        assert "uv build" not in package_job
        assert "| tail" not in package_job
        # umask must apply to the extract. Set after tar, it never reaches
        # the source modes setuptools copies into the wheel.
        assert re.search(
            r"umask 077\n\s+mkdir \.\./rebrew-repro\n"
            r"\s+git archive HEAD \| tar -x -C \.\./rebrew-repro",
            package_job,
        )

    def test_makefile_build_writes_buildinfo_and_cleans_residue(self) -> None:
        text = MAKEFILE.read_text(encoding="utf-8")
        assert "dist/rebrew.buildinfo" in text
        assert "rm -rf build rebrew.egg-info" in text
        # Clean before building too: setuptools packs leftover build/lib files
        # into the wheel.
        assert text.index("rm -rf build rebrew.egg-info") < text.index(
            "uv build --build-constraints"
        )
        # setuptools pin must be read from pyproject.toml, not hardcoded —
        # otherwise bumping build-system.requires leaves a lying buildinfo.
        assert "setuptools=80.10.2" not in text
        assert r"setuptools==\(" in text or "setuptools==" in text
        assert "python-version=" in text
        assert "source-commit=" in text
        assert "source-dirty=" in text

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
        assert re.search(r"(?m)^setup:\s*ensure-resembl\s+warn-nasm\s*$", text)
        assert "Before a PR: make all && make check && make build" in text

    def test_makefile_test_one_runs_without_nasm(self) -> None:
        """Single-file loop must not hard-fail on nasm; the nasm tests skip on their own."""
        text = MAKEFILE.read_text(encoding="utf-8")
        assert re.search(r"(?m)^test-one:\s*warn-nasm\s*$", text)
        assert re.search(r"(?m)^test:\s*ensure-nasm\s*$", text)

    def test_pre_push_pytest_hook_runs_make_test(self) -> None:
        """Pre-push must hit ``ensure-nasm``; a bare pytest skips asm tests CI runs."""
        text = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
        hook = text.split("- id: pytest\n", 1)[1].split("- id:", 1)[0]
        assert re.search(r"(?m)^\s*entry: make --no-print-directory test\s*$", hook)
        assert "stages: [pre-push]" in hook

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
        assert commands, path
        # --no-project never reads or writes uv.lock (uv warns that --frozen
        # is a no-op beside it).
        allowed = {"--frozen", "--locked", "--no-sync", "--no-project"}
        assert all(command in allowed for command in commands), (
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
