"""Tests for rebrew.call_progress: the counts a long command writes and its parent reads."""

import os
import time
lazy from collections.abc import Iterator

import pytest

from rebrew import call_progress
from rebrew.call_progress import PROGRESS_FD_ENV, ProgressPipe, ProgressReporter
from rebrew.errors import ConfigError


@pytest.fixture
def pipe() -> Iterator[ProgressPipe]:
    opened = ProgressPipe()
    try:
        yield opened
    finally:
        opened.close()


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """A monotonic clock the test moves by hand."""
    now = [100.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    return now


def _reporter(pipe: ProgressPipe, monkeypatch: pytest.MonkeyPatch) -> ProgressReporter:
    monkeypatch.setenv(PROGRESS_FD_ENV, str(pipe.write_fd))
    return ProgressReporter.from_environment()


class TestReporter:
    def test_without_the_variable_nothing_is_written(
        self, pipe: ProgressPipe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(PROGRESS_FD_ENV, raising=False)
        ProgressReporter.from_environment().report(1, 2)
        pipe.close_write()
        assert pipe.poll() is None

    def test_the_parent_reads_the_newest_count(
        self, pipe: ProgressPipe, monkeypatch: pytest.MonkeyPatch, clock: list[float]
    ) -> None:
        reporter = _reporter(pipe, monkeypatch)
        reporter.report(0, 316)
        assert pipe.poll() == (0, 316)
        clock[0] += call_progress.WRITE_INTERVAL_SECONDS
        reporter.report(143, 316)
        assert pipe.poll() == (143, 316)
        # Nothing new was written: the parent has nothing to forward.
        assert pipe.poll() is None

    def test_counts_within_the_interval_are_dropped_but_the_last_is_written(
        self, pipe: ProgressPipe, monkeypatch: pytest.MonkeyPatch, clock: list[float]
    ) -> None:
        reporter = _reporter(pipe, monkeypatch)
        reporter.report(0, 3)
        assert pipe.poll() == (0, 3)
        reporter.report(1, 3)
        reporter.report(2, 3)
        assert pipe.poll() is None
        reporter.report(3, 3)
        assert pipe.poll() == (3, 3)

    def test_a_count_with_no_total_is_not_written(
        self, pipe: ProgressPipe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _reporter(pipe, monkeypatch).report(0, 0)
        assert pipe.poll() is None

    def test_a_reader_that_left_ends_the_reports_without_failing_the_command(
        self, monkeypatch: pytest.MonkeyPatch, clock: list[float]
    ) -> None:
        read, write = os.pipe()
        try:
            monkeypatch.setenv(PROGRESS_FD_ENV, str(write))
            reporter = ProgressReporter.from_environment()
            os.close(read)
            reporter.report(1, 2)
            clock[0] += call_progress.WRITE_INTERVAL_SECONDS
            reporter.report(2, 2)
        finally:
            os.close(write)

    @pytest.mark.parametrize("value", ["three", "-1", "999999"])
    def test_a_variable_that_names_no_open_descriptor_fails_loud(
        self, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(PROGRESS_FD_ENV, value)
        with pytest.raises(ConfigError, match=PROGRESS_FD_ENV):
            ProgressReporter.from_environment()


class TestPipe:
    def test_malformed_and_impossible_lines_are_skipped(self, pipe: ProgressPipe) -> None:
        for line in (
            b"not json\n",
            b'{"done": 4, "total": 3}\n',
            b'{"done": -1, "total": 3}\n',
            b'{"done": true, "total": 3}\n',
            b'{"done": 1}\n',
            b"[1, 3]\n",
        ):
            os.write(pipe.write_fd, line)
        assert pipe.poll() is None
        os.write(pipe.write_fd, b'{"done": 2, "total": 3}\n{"done": 9')
        assert pipe.poll() == (2, 3)
        os.write(pipe.write_fd, b', "total": 9}\n')
        assert pipe.poll() == (9, 9)

    def test_an_endless_line_is_dropped(self, pipe: ProgressPipe) -> None:
        os.write(pipe.write_fd, b"x" * (call_progress.MAX_LINE_BYTES + 1))
        assert pipe.poll() is None
        os.write(pipe.write_fd, b'\n{"done": 1, "total": 2}\n')
        assert pipe.poll() == (1, 2)

    def test_an_unchanged_count_is_not_forwarded_twice(self, pipe: ProgressPipe) -> None:
        os.write(pipe.write_fd, b'{"done": 1, "total": 2}\n')
        assert pipe.poll() == (1, 2)
        os.write(pipe.write_fd, b'{"done": 1, "total": 2}\n')
        assert pipe.poll() is None
