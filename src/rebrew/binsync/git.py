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
lazy import os
lazy import subprocess
lazy from pathlib import Path

lazy from rebrew.utils import run_process_group

log = logging.getLogger(__name__)

#: Seconds any single git invocation may run.
_GIT_TIMEOUT = 30

#: Seconds a git invocation that talks to a remote may run. The default
#: ``_GIT_TIMEOUT`` is sized for local config probes and is short enough to
#: group-kill a ``push``/``pull`` mid-transfer on a slow link, which leaves a
#: half-written remote ref and an error the operator reads as a refusal.
GIT_NETWORK_TIMEOUT = 600

#: Repo-local git settings that execute a program. Command-line ``-c`` outranks
#: ``.git/config``. ``GIT_SSH_COMMAND``, when set, still outranks ``core.sshCommand``.
_GIT_EXEC_OVERRIDES: tuple[str, ...] = (
    "core.fsmonitor=",
    f"core.hooksPath={os.devnull}",
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


def validate_remote(remote: str) -> str:
    """Return *remote* when it is safe to pass to ``git fetch``/``git push``.

    A leading ``-`` makes git parse the value as an option rather than a
    remote: ``--upload-pack=<cmd>`` (fetch) and ``--receive-pack=<cmd>``
    (push) run an arbitrary command.  A ``<scheme>::`` remote (``ext::``,
    ``fd::``) is git's command-execution transport (``ext::sh -c …`` runs
    the command).  Spaces and control characters enable option smuggling
    and NUL truncation.  ``..`` enables refspec/path confusion.  A leading
    ``+`` is a force-push refspec prefix.  A leading/trailing space would
    let a wrapper split the value into an option.  ``--remote`` is operator
    input (a wrapper script can also supply it), so the argv is built with a
    ``--`` separator as a backstop, but rejecting the shape here means a
    mistyped option is a clear error instead of git's "strange pathname"
    diagnostic.

    Raises:
        ValueError: the name is empty, starts with ``-`` or ``+``, contains
            spaces or control characters, contains ``..``, or uses a
            command transport.
    """
    if not remote or not remote.strip():
        raise ValueError("invalid git remote: it must be non-empty")
    if remote.startswith("-"):
        raise ValueError(
            f"invalid git remote {remote!r}: a remote must not start with '-'; "
            "pass a configured remote name or a URL"
        )
    if remote.startswith("+"):
        raise ValueError(
            f"invalid git remote {remote!r}: a remote must not start with '+'; "
            "a leading '+' is a force-update refspec"
        )
    if remote != remote.strip():
        raise ValueError(f"invalid git remote {remote!r}: no leading or trailing whitespace")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in remote):
        raise ValueError(f"invalid git remote {remote!r}: control characters are not allowed")
    if " " in remote or "\t" in remote:
        raise ValueError(f"invalid git remote {remote!r}: spaces are not allowed")
    if ".." in remote:
        raise ValueError(f"invalid git remote {remote!r}: '..' is not allowed")
    # ``ext::`` / ``fd::`` and any other ``<transport>::`` command transport.
    # The check runs after the space check so ``ext::sh -c …`` is caught
    # as a transport even when it also contains spaces.
    if "::" in remote:
        raise ValueError(
            f"invalid git remote {remote!r}: a '<transport>::' remote would run a command"
        )
    return remote


def run_git(
    directory: Path, *args: str, timeout: float = _GIT_TIMEOUT
) -> subprocess.CompletedProcess[str]:
    """Run ``git -C directory <args>`` without raising on a non-zero exit.

    Group-killed: a ``push``/``pull`` over ssh spawns an ``ssh`` child, and a
    plain ``subprocess.run`` timeout SIGKILLs only ``git`` itself, so the ssh
    transport (and the remote session it holds) outlives the call.  A failure
    to spawn, run, or finish comes back as a nonzero ``CompletedProcess``.

    ``timeout`` defaults to :data:`_GIT_TIMEOUT`, sized for a local probe; a
    remote transfer must pass :data:`GIT_NETWORK_TIMEOUT`.

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
