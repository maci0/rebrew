"""call_progress.py – The counted progress a long command reports to the process that started it.

``rebrew verify`` and ``rebrew build round-trip`` report how many functions of
how many they have finished: one JSON line ``{"done": N, "total": M}`` per
update, written to the file descriptor :data:`PROGRESS_FD_ENV` names, at most
one every :data:`WRITE_INTERVAL_SECONDS` and always the final count.  The op
worker (:mod:`rebrew.ops`) starts them with a pipe there (:class:`ProgressPipe`)
and relays each new count to its caller.  Without the variable nothing is
written.  The counts are the command's own: a function is done once its
verdict (or its splice) is settled, never by elapsed time.
"""

from dataclasses import dataclass, field
lazy import json
lazy import os
lazy import time

from rebrew.errors import ConfigError

#: Names the file descriptor a command writes its progress lines to.
PROGRESS_FD_ENV = "REBREW_PROGRESS_FD"

#: Least seconds between two written counts; the final count is always written.
WRITE_INTERVAL_SECONDS = 0.5

#: Longest progress line a reader keeps; a longer one is dropped.
MAX_LINE_BYTES = 4096

#: Bytes read from the pipe per read call.
_READ_BYTES = 65536


@dataclass
class ProgressReporter:
    """Writes a command's counts to its parent's pipe; inert without one."""

    fd: int | None
    _last: float | None = field(default=None, init=False)

    @classmethod
    def from_environment(cls) -> ProgressReporter:
        """The reporter :data:`PROGRESS_FD_ENV` names, or an inert one when it is unset.

        Raises :class:`ConfigError` when the variable names no open file descriptor.
        """
        value = os.environ.get(PROGRESS_FD_ENV)
        if value is None:
            return cls(None)
        try:
            fd = int(value)
            os.fstat(fd)
        except ValueError, OSError:
            raise ConfigError(
                f"{PROGRESS_FD_ENV} must name an open file descriptor, got {value!r}"
            ) from None
        # A full pipe drops the update instead of stalling the command: the
        # reader keeps only the newest count anyway.
        os.set_blocking(fd, False)
        return cls(fd)

    def report(self, done: int, total: int) -> None:
        """Write ``done`` of ``total``; a count with no total, or one too soon after the last, is skipped."""
        if self.fd is None or total < 1:
            return
        now = time.monotonic()
        if done < total and self._last is not None and now - self._last < WRITE_INTERVAL_SECONDS:
            return
        try:
            os.write(self.fd, json.dumps({"done": done, "total": total}).encode() + b"\n")
        except BlockingIOError:
            return
        except OSError:
            # The reader went away (its call ended or was cancelled): the
            # command's result does not depend on anyone watching it.
            self.fd = None
            return
        self._last = now


class ProgressPipe:
    """The pipe a parent hands a child command as :data:`PROGRESS_FD_ENV`, and the newest count read from it."""

    def __init__(self) -> None:
        self._read, self.write_fd = os.pipe()
        os.set_blocking(self._read, False)
        self._write_open = True
        self._pending = b""
        self._forwarded: tuple[int, int] | None = None

    def close_write(self) -> None:
        """Close the parent's copy of the write end, once the child holds its own."""
        if self._write_open:
            self._write_open = False
            os.close(self.write_fd)

    def close(self) -> None:
        """Close both ends."""
        self.close_write()
        os.close(self._read)

    def poll(self) -> tuple[int, int] | None:
        """The newest valid ``(done, total)`` written since the last poll, or ``None`` when it did not change."""
        newest: tuple[int, int] | None = None
        while True:
            try:
                chunk = os.read(self._read, _READ_BYTES)
            except BlockingIOError:
                break
            if not chunk:
                break
            *lines, self._pending = (self._pending + chunk).split(b"\n")
            if len(self._pending) > MAX_LINE_BYTES:
                self._pending = b""
            for line in lines:
                count = _count(line)
                if count is not None:
                    newest = count
        if newest is None or newest == self._forwarded:
            return None
        self._forwarded = newest
        return newest


def _count(line: bytes) -> tuple[int, int] | None:
    """The ``(done, total)`` of one progress line, or ``None`` for a line that is not one."""
    if len(line) > MAX_LINE_BYTES:
        return None
    try:
        payload = json.loads(line)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    done, total = payload.get("done"), payload.get("total")
    if type(done) is not int or type(total) is not int or not 0 <= done <= total or total < 1:
        return None
    return done, total
