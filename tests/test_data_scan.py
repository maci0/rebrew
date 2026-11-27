"""data_scan helpers the scans share."""

from __future__ import annotations

from typing import Any

import pytest


def test_annotated_global_at_zero_has_a_location(tmp_path) -> None:
    from source_util import write_source

    from rebrew.config import ProjectConfig
    from rebrew.data.scan import enrich_with_sections, scan_globals, verify_bss_layout

    source = tmp_path / "src"
    source.mkdir()
    cfg = ProjectConfig(root=tmp_path, reversed_dir=source, module="DOS", arch="x86_16")
    write_source(
        source / "globals.c",
        "/* ADDRESS: DOS 0x0 */\nint g_start;\nextern int g_unbound;\n",
        metadata_dir=tmp_path,
        metadata_fields={"DOS.0x0": {"kind": "GLOBAL", "size": 2}},
    )
    scan = scan_globals(source, cfg=cfg)
    assert scan.globals["g_start"].to_dict()["va"] == "0x00000000"
    assert "va" not in scan.globals["g_unbound"].to_dict()
    sections = {".bss": {"va": 0, "size": 4}}
    enrich_with_sections(scan, sections)
    assert scan.globals["g_start"].section == ".bss"
    assert [entry.name for entry in verify_bss_layout(scan, sections).known_entries] == ["g_start"]


def test_target_visibility_reads_the_cached_anchors(monkeypatch: pytest.MonkeyPatch) -> None:
    """The check passes the source as read, so a file ending in a newline is not parsed again."""
    import rebrew.metadata.anchors as anchors
    from rebrew.data.scan import _source_visible_to_target

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
