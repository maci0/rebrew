"""repo.py: the BinSync git repository behind a state directory.

BinSync keeps one branch per user, ``binsync/<user>``, created from the
``binsync/__root__`` commit, and reads a user's state from that branch's
``metadata.toml``.  rebrew is one such user:

* :func:`resolve_user` picks the one identity rebrew writes as: the
  ``metadata.toml`` ``user`` and the branch suffix are always the same name.
* :func:`checkout_user_branch` puts the working tree on rebrew's own branch
  before an export writes into it, so a push never lands on another user's
  branch.
* :func:`peer_refs` and :func:`peer_snapshot` expose every other user's branch
  as a read-only directory for import.

Every git call goes through :func:`rebrew.binsync.git.run_git`.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
lazy import hashlib
lazy import shutil
lazy import subprocess
lazy from collections.abc import Iterator
lazy from pathlib import Path
lazy from typing import Any

lazy from rebrew.binsync.git import GIT_NETWORK_TIMEOUT, one_line, run_git
lazy from rebrew.config import ProjectConfig

log = logging.getLogger(__name__)

#: The BinSync root branch (upstream resolves the state root from it).
ROOT_BRANCH = "binsync/__root__"

#: Prefix of every BinSync user branch.
BRANCH_PREFIX = "binsync/"

#: Repo-local git config key ``rebrew binsync init`` records the user under.
USER_CONFIG_KEY = "rebrew.user"

#: User name when neither ``--user``, the config, nor the state repo names one.
DEFAULT_USER = "rebrew"


def user_branch(user: str) -> str:
    """The BinSync branch that holds *user*'s state."""
    return f"{BRANCH_PREFIX}{user}"


def _probe_dir(state_dir: Path) -> Path:
    """The nearest existing directory at or above *state_dir* (git needs a cwd)."""
    for candidate in (state_dir, *state_dir.parents):
        if candidate.is_dir():
            return candidate
    return Path.cwd()


def validate_user(user: str, state_dir: Path) -> str:
    """Return *user* when ``binsync/<user>`` is a branch BinSync can use, else raise.

    BinSync rejects an empty name, a trailing ``/`` and ``__root__``, and
    names users by the last ``/`` component of the branch, so a ``/`` inside
    the name would split one user into two.  The rest is git's own branch-name
    rule (``git check-ref-format --branch``): no spaces, ``..``, ``~``, ``^``,
    ``:``, ``?``, ``*``, ``[``, ``\\``, control characters, or a ``.lock``
    suffix.

    Raises:
        ValueError: the name cannot be a BinSync user branch.
    """
    if not user or "/" in user or "__root__" in user:
        raise ValueError(
            f"invalid BinSync user {user!r}: it must be non-empty, contain no '/', "
            "and not name __root__; pass --user or set targets.<name>.binsync_user"
        )
    check = run_git(_probe_dir(state_dir), "check-ref-format", "--branch", user_branch(user))
    if check.returncode != 0:
        raise ValueError(
            f"invalid BinSync user {user!r}: {user_branch(user)!r} is not a valid git branch "
            "name; pass --user or set targets.<name>.binsync_user to a name without spaces"
        )
    return user


def is_binsync_repo(state_dir: Path) -> bool:
    """True when *state_dir* is a git repo with a ``binsync/__root__`` branch."""
    if not (state_dir / ".git").exists():
        return False
    probe = run_git(state_dir, "rev-parse", "--verify", "--quiet", f"refs/heads/{ROOT_BRANCH}")
    return probe.returncode == 0


def recorded_user(state_dir: Path) -> str:
    """The user ``rebrew binsync init`` recorded in the state repo, or ``""``."""
    if not (state_dir / ".git").exists():
        return ""
    result = run_git(state_dir, "config", "--local", "--get", USER_CONFIG_KEY)
    return result.stdout.strip() if result.returncode == 0 else ""


USER_HELP = (
    "BinSync user rebrew writes as (default: targets.<name>.binsync_user, "
    "the user 'rebrew binsync init' recorded, else rebrew)"
)


def resolve_user(cfg: Any, state_dir: Path, explicit: str | None = None) -> str:
    """The validated BinSync user rebrew writes as.

    Precedence: *explicit* (``--user``), ``targets.<name>.binsync_user``, the
    user ``rebrew binsync init`` recorded in the state repo, then
    :data:`DEFAULT_USER`.  ``git config user.name`` is never used: it is a
    person's display name, usually with spaces, and BinSync derives the
    branch from the same string.

    Raises:
        ValueError: the selected name cannot be a BinSync user branch.
    """
    configured = str(getattr(cfg, "binsync_user", "") or "")
    user = explicit or configured or recorded_user(state_dir) or DEFAULT_USER
    return validate_user(user, state_dir)


def current_branch(state_dir: Path) -> str:
    """The checked-out branch name, or ``""`` when detached or unborn."""
    result = run_git(state_dir, "symbolic-ref", "--quiet", "--short", "HEAD")
    return result.stdout.strip() if result.returncode == 0 else ""


def checkout_user_branch(state_dir: Path, user: str) -> None:
    """Check out ``binsync/<user>``, creating it from the root branch if absent.

    A working tree on another branch with uncommitted changes is refused: the
    checkout would carry that user's edits onto rebrew's branch.

    Raises:
        ValueError: the tree is dirty on another branch, or git failed.
    """
    own = user_branch(user)
    current = current_branch(state_dir)
    if current == own:
        return
    status = run_git(state_dir, "status", "--porcelain", "--untracked-files=no")
    if status.returncode != 0:
        raise ValueError(f"git status failed in {state_dir}: {one_line(status.stderr)}")
    if status.stdout.strip():
        raise ValueError(
            f"{state_dir} has uncommitted changes on {current or 'a detached HEAD'}; commit "
            f"or discard them before rebrew switches to {own}"
        )
    exists = run_git(state_dir, "rev-parse", "--verify", "--quiet", f"refs/heads/{own}")
    args = (own,) if exists.returncode == 0 else ("-b", own, ROOT_BRANCH)
    switched = run_git(state_dir, "checkout", "-q", *args)
    if switched.returncode != 0:
        raise ValueError(
            f"git checkout {own} failed: {one_line(switched.stderr or switched.stdout)}"
        )


def peer_refs(state_dir: Path, user: str, remote: str = "origin") -> dict[str, str]:
    """``{peer_user: ref}`` for every BinSync user branch other than *user*.

    Like BinSync's own ref selection, a remote-tracking ``<remote>/binsync/<u>``
    wins over the local branch of the same user, so a fetched peer is read at
    its fetched tip.

    Raises:
        ValueError: git cannot list the refs.
    """
    listing = run_git(
        state_dir,
        "for-each-ref",
        "--format=%(refname)",
        f"refs/heads/{BRANCH_PREFIX}",
        f"refs/remotes/{remote}/{BRANCH_PREFIX}",
    )
    if listing.returncode != 0:
        raise ValueError(f"git for-each-ref failed: {one_line(listing.stderr)}")
    refs: dict[str, str] = {}
    for ref in listing.stdout.split():
        name = ref.rsplit("/", 1)[1]
        if name in {"__root__", user}:
            continue
        if name not in refs or ref.startswith("refs/remotes/"):
            refs[name] = ref
    return dict(sorted(refs.items()))


def fetch_peers(state_dir: Path, remote: str) -> subprocess.CompletedProcess[str] | None:
    """Fetch every ``binsync/*`` branch of *remote* into its tracking refs.

    Returns ``None`` when the repo has no such remote (a local-only state
    repo), else git's result.  Only tracking refs move: no local branch,
    index or working tree changes.
    """
    remotes = run_git(state_dir, "remote")
    if remote not in remotes.stdout.split():
        return None
    refspec = f"+refs/heads/{BRANCH_PREFIX}*:refs/remotes/{remote}/{BRANCH_PREFIX}*"
    return run_git(state_dir, "fetch", "--prune", remote, refspec, timeout=GIT_NETWORK_TIMEOUT)


def _peer_dir(cfg: ProjectConfig, state_dir: Path, peer: str) -> Path:
    """Stable project-local directory a peer's branch is checked out into.

    Stable per (state dir, peer) so the sync baseline keyed by that path is
    the per-peer baseline.
    """
    key = hashlib.sha256(str(state_dir.resolve()).encode()).hexdigest()[:16]
    root = Path(getattr(cfg, "root", None) or Path(cfg.reversed_dir).parent)
    return root / ".rebrew" / "sync" / "peers" / key / peer


def _remove_worktree(state_dir: Path, path: Path) -> None:
    """Drop a peer worktree and its registration; a missing one is fine."""
    run_git(state_dir, "worktree", "remove", "--force", str(path))
    if path.exists():
        shutil.rmtree(path)
    run_git(state_dir, "worktree", "prune")


@contextmanager
def peer_snapshot(cfg: ProjectConfig, state_dir: Path, peer: str, ref: str) -> Iterator[Path]:
    """Check out *ref* detached into the peer's directory for the duration.

    The state dir's own branch, index and working tree are untouched.

    Raises:
        ValueError: git cannot create the worktree.
    """
    path = _peer_dir(cfg, state_dir, peer)
    path.parent.mkdir(parents=True, exist_ok=True)
    _remove_worktree(state_dir, path)
    added = run_git(state_dir, "worktree", "add", "--detach", "--force", str(path), ref)
    if added.returncode != 0:
        raise ValueError(f"git worktree add {ref} failed: {one_line(added.stderr or added.stdout)}")
    try:
        yield path
    finally:
        _remove_worktree(state_dir, path)
