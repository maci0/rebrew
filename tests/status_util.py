"""Shared helpers for tests that intercept batched STATUS writes."""

from typing import Any


def accept_status_batch(
    metadata_dir: Any,
    updates: list[dict[str, Any]],
    *,
    status_outcomes: list[bool] | None = None,
) -> int:
    """Accept every queued row and mirror the batch writer's outcome contract."""
    if status_outcomes is not None:
        status_outcomes[:] = [True] * len(updates)
    return len(updates)


def refuse_status_batch(
    metadata_dir: Any,
    updates: list[dict[str, Any]],
    *,
    status_outcomes: list[bool] | None = None,
) -> int:
    """Refuse every queued row and mirror the batch writer's outcome contract."""
    if status_outcomes is not None:
        status_outcomes[:] = [False] * len(updates)
    return 0
