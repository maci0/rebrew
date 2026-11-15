"""data_scan helpers the scans share."""

from __future__ import annotations

from typing import Any

import pytest


def test_target_visibility_reads_the_cached_anchors(monkeypatch: pytest.MonkeyPatch) -> None:
    """The check passes the source as read, so a file ending in a newline is not parsed again."""
    import rebrew.metadata.anchors as anchors
    from rebrew.data_scan import _source_visible_to_target

    text = "// ADDRESS: VISCHECK 0x1000\nint visible_check;\n"
    anchors.parse_address_anchors(text)
    calls: list[str] = []
    real = anchors._parse_address_anchors

    def counted(source: str, syntax: Any) -> Any:
        calls.append(source)
        return real(source, syntax)

    monkeypatch.setattr(anchors, "_parse_address_anchors", counted)
    assert _source_visible_to_target(text, None)
    assert calls == []
