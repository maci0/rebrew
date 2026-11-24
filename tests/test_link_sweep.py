"""Exit contract for a link sweep whose every candidate fails."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner


@pytest.mark.parametrize("json_output", [False, True])
def test_all_failed_links_exit_two_after_reporting(
    tmp_path, monkeypatch: pytest.MonkeyPatch, json_output: bool
) -> None:
    from rebrew import link_sweep

    binary = tmp_path / "reference.exe"
    binary.write_bytes(b"reference")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(
        link_sweep,
        "require_config",
        lambda *_args, **_kwargs: SimpleNamespace(target_binary=binary),
    )
    monkeypatch.setattr(link_sweep, "parse_pe", lambda _data: (None, None, None, None))
    monkeypatch.setattr(link_sweep, "_read_fields", lambda _path: {"Machine": 0x14C})
    monkeypatch.setattr(
        link_sweep,
        "_candidates",
        lambda _pe: [SimpleNamespace(name="base", options=[])],
    )
    monkeypatch.setattr(link_sweep.tempfile, "mkdtemp", lambda **_kwargs: str(scratch))
    monkeypatch.setattr(
        link_sweep,
        "run_process_group",
        lambda *_args, **_kwargs: SimpleNamespace(stderr="link failed", returncode=1),
    )

    argv = ["--link-cmd", "link {out} {options}"]
    if json_output:
        argv.append("--json")
    result = CliRunner().invoke(link_sweep.app, argv)

    assert result.exit_code == 2, result.output
    if json_output:
        report = json.loads(result.stdout)
        assert report["results"][0]["link_failed"] is True
        error = json.loads(result.stderr.strip().splitlines()[-1])["error"]
        assert error["kind"] == "failure"
        assert error["message"] == "no candidate linked"
    else:
        assert result.stdout == ""
        assert "No candidate linked" in result.stderr
        assert "error: no candidate linked" in result.stderr
