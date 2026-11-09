"""Tests for the telemetry exporter's dropped-span self-monitoring.

A saturated trace exporter must not silently lose traces: the drop is
counted and logged once, not once per dropped span, which would spam the
log exactly when the collector is already struggling.
"""

from __future__ import annotations

import logging
import queue as queue_module
import threading

import pytest

from rebrew import telemetry


def test_full_queue_counts_dropped_spans_and_logs_once(caplog: pytest.LogCaptureFixture) -> None:
    exporter = telemetry._Exporter.__new__(telemetry._Exporter)
    exporter._closed = threading.Event()
    exporter._queue = queue_module.Queue(2)
    exporter._lock = threading.Lock()
    exporter._dropped = 0
    spans = [
        telemetry.Span("s", telemetry.KIND_INTERNAL, "a" * 32, "b" * 16, "", 0) for _ in range(3)
    ]
    with caplog.at_level(logging.WARNING, logger="rebrew.telemetry"):
        exporter.submit(spans[0])
        exporter.submit(spans[1])
        exporter.submit(spans[2])
        exporter.submit(spans[2])
    assert exporter.dropped_spans == 2
    warnings = [r for r in caplog.records if "trace queue full" in r.getMessage()]
    assert len(warnings) == 1
