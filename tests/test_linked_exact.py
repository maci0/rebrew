"""Linked-image EXACT: ``rebrew verify --text`` promotion, stickiness, and invalidation.

The object compare is mocked (no toolchain container); everything else runs
for real: the project config, the reference and built PE images, the
metadata store, the verify cache, ``rebrew status``.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import pytest
from bin_util import make_pe
from cli_json import cli_payload
from source_util import write_source
from typer.testing import CliRunner

from rebrew.compiler.compile import CompareResult, CompareStatus
from rebrew.config import load_config
from rebrew.metadata.functions import get_entry

_VA = 0x401000
# call rel32 (one relocation in the object) + ret
_CODE = b"\xe8\x10\x00\x00\x00\xc3"
_SIZE = len(_CODE)


def _project(root: Path) -> Path:
    (root / "rebrew-project.toml").write_text(
        '[project]\ndefault_target="server"\n'
        '[targets.server]\nbinary="server.dll"\nreversed_dir="src"\n'
    )
    (root / "server.dll").write_bytes(make_pe(_CODE + b"\xcc" * 10))
    (root / "src").mkdir()
    source = root / "src" / "foo.c"
    write_source(
        source,
        f"/* ADDRESS: SERVER 0x{_VA:x} */\n\nint foo(void) {{ return 1; }}\n",
        metadata_fields={f"SERVER.0x{_VA:x}": {"kind": "FUNCTION", "size": int(f"{_SIZE}", 0)}},
    )
    built = root / "build" / "server"
    built.parent.mkdir()
    built.write_bytes(make_pe(_CODE + b"\xcc" * 10))
    _age(source)
    return built


def _age(path: Path) -> None:
    """Make *path* older than the built image."""
    os.utime(path, ns=(1_000_000_000, 1_000_000_000))


#: The object verdict the mocked compare returns; a test may change it mid-run.
_VERDICT: dict[str, CompareStatus] = {"status": "RELOC"}


def _compare(*_args: Any, **_kwargs: Any) -> CompareResult:
    status = _VERDICT["status"]
    matched = status in {"EXACT", "RELOC"}
    return CompareResult(
        matched=matched,
        status=status,
        match_percent=100.0 if matched else 80.0,
        delta=0 if matched else 1,
        obj_bytes=_CODE,
        reloc_offsets=[1] if status == "RELOC" else [],
        message=status,
    )


def _mock(monkeypatch: pytest.MonkeyPatch, *, placed: bool = True) -> None:
    from rebrew.verify_hash import expected_text_functions

    _VERDICT["status"] = "RELOC"
    monkeypatch.setattr("rebrew.compiler.compile.compile_and_compare", _compare)
    monkeypatch.setattr("rebrew.test.compile_and_compare", _compare)
    monkeypatch.setattr("rebrew.compiler.compile.precompile_batch", lambda *a, **k: {})
    monkeypatch.setattr(
        "rebrew.text_audit.collect_actual_vas",
        lambda root, built: expected_text_functions(load_config(root=root)) if placed else {},
    )


def _verify(root: Path, *args: str) -> dict[str, Any]:
    from rebrew.metadata.functions import clear_metadata_cache
    from rebrew.verify import app

    clear_metadata_cache()
    result = CliRunner().invoke(app, [*args, "--json", "--root", str(root)])
    assert result.exit_code in (0, 1), result.output
    report: dict[str, Any] = cli_payload(result)
    return report


def _row(report: dict[str, Any]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = [r for r in report["results"] if r["va"] == f"0x{_VA:08x}"]
    (row,) = rows
    return row


def _stored(root: Path) -> dict[str, Any]:
    from rebrew.metadata.functions import clear_metadata_cache

    clear_metadata_cache()
    return get_entry(root, _VA, "SERVER")


class TestPromotion:
    def test_identical_raw_link_promotes_reloc_to_exact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built = _project(tmp_path)
        _mock(monkeypatch)
        report = _verify(tmp_path, "--text", "--raw-link")
        assert _row(report)["status"] == "EXACT"
        linked = report["text"]["linked"]
        assert (linked["candidates"], linked["identical"], linked["promoted"]) == (1, 1, 1)
        entry = _stored(tmp_path)
        assert entry["status"] == "EXACT"
        evidence = entry["verification"]
        assert evidence["status"] == "EXACT"
        assert evidence["writer"] == "verify"
        assert evidence["linked_image"] == "build/server"
        assert evidence["linked_image_hash"] == hashlib.sha256(built.read_bytes()).hexdigest()

        from rebrew.status import collect_status

        counts = collect_status(load_config(root=tmp_path)).status_counts
        assert counts.get("EXACT") == 1
        assert not counts.get("RELOC")

    def test_without_raw_link_ack_reports_but_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path)
        _mock(monkeypatch)
        report = _verify(tmp_path, "--text")
        linked = report["text"]["linked"]
        assert (linked["identical"], linked["promoted"]) == (1, 0)
        assert linked["raw_link_status_suppressed"] is True
        assert _row(report)["status"] == "RELOC"
        assert _stored(tmp_path)["status"] == "RELOC"

    def test_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _project(tmp_path)
        _mock(monkeypatch)
        _verify(tmp_path, "--no-promote")
        report = _verify(tmp_path, "--text", "--raw-link", "--dry-run")
        assert report["text"]["linked"]["promoted"] == 0
        assert _row(report)["status"] == "RELOC"

    def test_differing_linked_bytes_stay_reloc(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built = _project(tmp_path)
        built.write_bytes(make_pe(b"\xe8\x20\x00\x00\x00\xc3" + b"\xcc" * 10))
        _mock(monkeypatch)
        report = _verify(tmp_path, "--text", "--raw-link")
        assert _row(report)["status"] == "RELOC"
        (kept,) = report["text"]["linked"]["kept_reloc"]
        assert kept["reason"] == "linked bytes differ"
        assert kept["first_diff"] == 1
        assert _stored(tmp_path)["status"] == "RELOC"

    def test_unplaced_function_stays_reloc(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path)
        _mock(monkeypatch, placed=False)
        report = _verify(tmp_path, "--text", "--raw-link")
        (kept,) = report["text"]["linked"]["kept_reloc"]
        assert kept["reason"] == "not placed at its reference VA"
        assert _stored(tmp_path)["status"] == "RELOC"

    def test_source_newer_than_build_stays_reloc(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built = _project(tmp_path)
        _age(built)
        os.utime(tmp_path / "src" / "foo.c", None)
        _mock(monkeypatch)
        report = _verify(tmp_path, "--text", "--raw-link")
        (kept,) = report["text"]["linked"]["kept_reloc"]
        assert kept["reason"] == "source newer than the built image"
        assert _stored(tmp_path)["status"] == "RELOC"


class TestStickiness:
    @pytest.mark.parametrize("full", [False, True])
    def test_plain_verify_keeps_linked_exact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, full: bool
    ) -> None:
        _project(tmp_path)
        _mock(monkeypatch)
        _verify(tmp_path, "--text", "--raw-link")
        evidence = _stored(tmp_path)["verification"]
        report = _verify(tmp_path, *(["--no-cache"] if full else []))
        assert _row(report)["status"] == "EXACT"
        entry = _stored(tmp_path)
        assert entry["status"] == "EXACT"
        assert entry["verification"] == evidence

    def test_rebuilt_image_demotes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        built = _project(tmp_path)
        _mock(monkeypatch)
        _verify(tmp_path, "--text", "--raw-link")
        built.write_bytes(make_pe(_CODE + b"\x90" * 10))
        report = _verify(tmp_path)
        assert _row(report)["status"] == "RELOC"
        entry = _stored(tmp_path)
        assert entry["status"] == "RELOC"
        assert "linked_image_hash" not in entry["verification"]

    def test_source_change_demotes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _project(tmp_path)
        _mock(monkeypatch)
        _verify(tmp_path, "--text", "--raw-link")
        source = tmp_path / "src" / "foo.c"
        source.write_text(source.read_text().replace("return 1", "return 2"))
        report = _verify(tmp_path)
        assert _row(report)["status"] == "RELOC"
        assert _stored(tmp_path)["status"] == "RELOC"

    def test_real_byte_change_demotes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path)
        _mock(monkeypatch)
        _verify(tmp_path, "--text", "--raw-link")
        _VERDICT["status"] = "NEAR_MATCHING"
        report = _verify(tmp_path, "--no-cache")
        assert _row(report)["status"] == "NEAR_MATCHING"
        assert _stored(tmp_path)["status"] == "NEAR_MATCHING"

    def test_rebrew_test_keeps_linked_exact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.app.main import app
        from rebrew.metadata.functions import clear_metadata_cache

        _project(tmp_path)
        _mock(monkeypatch)
        _verify(tmp_path, "--text", "--raw-link")
        evidence = _stored(tmp_path)["verification"]
        clear_metadata_cache()
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["test", "src/foo.c", "--json"])
        assert result.exit_code == 0, result.output
        assert cli_payload(result)["status"] == "EXACT"
        entry = _stored(tmp_path)
        assert entry["status"] == "EXACT"
        assert entry["verification"]["linked_image_hash"] == evidence["linked_image_hash"]

    def test_rebrew_test_multi_function_file_keeps_linked_exact(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.app.main import app

        _project(tmp_path)
        source = tmp_path / "src" / "foo.c"
        source.write_text(
            source.read_text()
            + f"/* ADDRESS: SERVER 0x{_VA + 0x10:x} */\nint bar(void) {{ return 0; }}\n"
        )
        _age(source)
        _mock(monkeypatch)
        _verify(tmp_path, "--text", "--raw-link")
        assert _stored(tmp_path)["status"] == "EXACT"
        obj = tmp_path / "foo.obj"
        obj.write_bytes(b"")
        monkeypatch.setattr("rebrew.test.compile_to_obj", lambda *a, **k: (str(obj), ""))
        monkeypatch.setattr(
            "rebrew.test.parse_obj_symbol_and_relocs", lambda *a, **k: (_CODE, {}, {})
        )
        monkeypatch.setattr(
            "rebrew.test.smart_reloc_compare",
            lambda obj_bytes, *a, **k: (True, len(obj_bytes), len(obj_bytes), [1], []),
        )
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["test", "src/foo.c", "--json"])
        rows = {r["va"]: r["status"] for r in cli_payload(result)["results"]}
        assert rows[f"0x{_VA:08x}"] == "EXACT"
        entry = _stored(tmp_path)
        assert entry["status"] == "EXACT"
        assert "linked_image_hash" in entry["verification"]


def _write_map(built: Path, va: int) -> None:
    built.with_suffix(".map").write_text(
        " Start         Length     Name                   Class\n"
        " 0001:00000000 00000010H .text                   CODE\n\n"
        "  Address         Publics by Value              Rva+Base     Lib:Object\n\n"
        f" 0001:00000000       _foo                       {va:08x} f   foo.obj\n"
    )


class TestLinkMapPlacement:
    def test_map_places_function_without_object_walk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built = _project(tmp_path)
        _write_map(built, _VA)
        _mock(monkeypatch, placed=False)
        report = _verify(tmp_path, "--text", "--raw-link")
        assert report["text"]["linked"]["placement"] == str(built.with_suffix(".map"))
        assert report["text"]["linked"]["promoted"] == 1
        assert _stored(tmp_path)["status"] == "EXACT"

    def test_map_placing_function_elsewhere_keeps_reloc(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built = _project(tmp_path)
        _write_map(built, _VA + 0x10)
        _mock(monkeypatch)
        report = _verify(tmp_path, "--text", "--raw-link")
        (kept,) = report["text"]["linked"]["kept_reloc"]
        assert kept["reason"] == "not placed at its reference VA"
        assert _stored(tmp_path)["status"] == "RELOC"
