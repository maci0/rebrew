"""Fail-closed include search while capturing an MSVC translation unit."""

import json
import os
from pathlib import Path

import pytest
from test_preprocessed_context import _fixture

from rebrew.compiler import preprocessed_context as capture


def test_unreadable_earlier_root_is_not_a_miss(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source, database, _ = _fixture(tmp_path, monkeypatch)
    early, late = tmp_path / "early", tmp_path / "late"
    early.mkdir()
    late.mkdir()
    (early / "api.h").write_text("#define VALUE 1\n")
    (late / "api.h").write_text("#define VALUE 2\n")
    source.write_text("#include <api.h>\nint f(void) { return VALUE; }\n")
    entries = json.loads(database.read_text())
    entries[0]["arguments"][7:7] = [f"/I{early}", f"/I{late}"]
    database.write_text(json.dumps(entries))
    scandir = os.scandir
    is_file = Path.is_file

    def unreadable(path):
        if not isinstance(path, int) and Path(path) == early:
            raise PermissionError("unreadable")
        return scandir(path)

    def not_a_file(path):
        return False if path == early / "api.h" else is_file(path)

    monkeypatch.setattr(os, "scandir", unreadable)
    monkeypatch.setattr(Path, "is_file", not_a_file)
    with pytest.raises(ValueError, match="include closure"):
        capture.capture_msvc_context(tmp_path, database, source, output="TL.obj")


def test_absent_earlier_header_allows_later_winner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source, database, _ = _fixture(tmp_path, monkeypatch)
    early, late = tmp_path / "early", tmp_path / "late"
    early.mkdir()
    late.mkdir()
    header = late / "api.h"
    header.write_text("#define VALUE 2\n")
    source.write_text("#include <api.h>\nint f(void) { return VALUE; }\n")
    entries = json.loads(database.read_text())
    entries[0]["arguments"][7:7] = [f"/I{early}", f"/I{late}"]
    database.write_text(json.dumps(entries))
    result = capture.capture_msvc_context(tmp_path, database, source, output="TL.obj")
    assert result["conservative_include_closure_complete"]
    assert str(header) in result["files"]


@pytest.mark.parametrize("nested", [False, True])
def test_case_collision_added_during_capture_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, nested: bool
):
    source, database, _ = _fixture(tmp_path, monkeypatch)
    directory = source.parent / "nested" if nested else source.parent
    directory.mkdir(exist_ok=True)
    (directory / "Api.h").write_text("#define VALUE 1\n")
    source.write_text(
        f'#include "{("nested/" if nested else "")}api.h"\nint f(void) {{ return VALUE; }}\n'
    )
    run = capture.run_toolchain

    def add_collision(*args, **kwargs):
        result = run(*args, **kwargs)
        (directory / "API.h").write_text("#define VALUE 1\n")
        return result

    monkeypatch.setattr(capture, "run_toolchain", add_collision)
    with pytest.raises(ValueError, match="ambiguous"):
        capture.capture_msvc_context(tmp_path, database, source, output="TL.obj")
