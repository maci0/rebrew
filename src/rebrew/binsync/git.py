"""git.py — sandboxed git invocations against a BinSync state directory.

The BinSync envelope commands (``init``, ``export``, ``cli``) and the state
serializer (:mod:`rebrew.binsync.serial`) all drive git the same way, and all
of them must: every invocation goes through :func:`run_git`, which runs the
argv from :func:`git_argv` (neutralizing the repo-local settings that execute a
program) in its own process group and kills the group on timeout.  Those
helpers live here, below the command modules, so :mod:`rebrew.binsync.serial`
can reach them without importing a Typer command.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from rebrew.utils import run_process_group

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


def run_git(
    directory: Path, *args: str, timeout: float = _GIT_TIMEOUT
) -> subprocess.CompletedProcess[str]:
    """Run ``git -C directory <args>`` without raising on a non-zero exit.

    Group-killed: a ``push``/``pull`` over ssh spawns an ``ssh`` child, and a
    plain ``subprocess.run`` timeout SIGKILLs only ``git`` itself, so the ssh
    transport (and the remote session it holds) outlives the call.  A failure
    to spawn, run, or finish comes back as a nonzero ``CompletedProcess``.

    ``surrogateescape``, like every other hash of process and path text here:
    a state-dir file name or config value is not required to be valid UTF-8,
    and the platform default decode either mojibakes it or raises
    ``UnicodeDecodeError`` — a ``ValueError``, so it escaped the handler
    below and killed the command.
    """
    argv = git_argv(directory, *args)
    try:
        return run_process_group(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            timeout=timeout,
        )
    except FileNotFoundError:
        return subprocess.CompletedProcess(argv, 127, "", "git not found")
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("git invocation failed", exc_info=True)
        return subprocess.CompletedProcess(argv, 1, "", str(exc))
