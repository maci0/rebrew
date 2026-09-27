"""git.py — sandboxed git invocations against a BinSync state directory.

The BinSync envelope commands (``init``, ``export``, ``cli``) and the state
serializer (:mod:`rebrew.binsync.serial`) all drive git the same way, and all
of them must: every invocation goes through :func:`git_argv`, which neutralizes
the repo-local settings that execute a program.  Those helpers live here, below
the command modules, so :mod:`rebrew.binsync.serial` can reach them without
importing a Typer command.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

#: Seconds any single git invocation may run.
_GIT_TIMEOUT = 30

#: Repo-local git settings that execute a program. Command-line ``-c`` outranks
#: ``.git/config``. ``GIT_SSH_COMMAND``, when set, still outranks ``core.sshCommand``.
_GIT_EXEC_OVERRIDES: tuple[str, ...] = (
    "core.fsmonitor=",
    "core.hooksPath=/dev/null",
    "protocol.ext.allow=never",
    "core.sshCommand=ssh",
    "gpg.program=gpg",
)


def one_line(text: str) -> str:
    """Collapse *text* to one sanitized line for an error message."""
    return " ".join(text.split())


def git_argv(directory: Path, *args: str) -> list[str]:
    """``git -C directory`` argv that ignores repo-local execution config.

    A BinSync state directory is a git repo the analyst may have received as a
    tree, not via ``git clone``. ``core.fsmonitor``, ``.git/hooks``,
    ``core.sshCommand``, ``gpg.program``, and an ``ext::`` remote run on
    add, commit, checkout, and pull.
    """
    cmd = ["git"]
    for item in _GIT_EXEC_OVERRIDES:
        cmd.extend(("-c", item))
    cmd.extend(("-C", str(directory)))
    cmd.extend(args)
    return cmd


def run_git(directory: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run ``git -C directory <args>`` without raising on a non-zero exit."""
    argv = git_argv(directory, *args)
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_GIT_TIMEOUT,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(argv, 127, "", "git not found")
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("git invocation failed", exc_info=True)
        return subprocess.CompletedProcess(argv, 1, "", str(exc))
