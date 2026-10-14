"""Assembly previews, output files and machine-readable summaries."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from source_util import write_source
from typer.testing import CliRunner

from rebrew.asm import app
from rebrew.metadata.functions import get_entry

_CODE = bytes.fromhex("558bec83ec08b801000000c9c3")


def _project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    source = tmp_path / "src"
    source.mkdir()
    write_source(
        source / "f.c",
        "// ADDRESS: SERVER 0x1000\nint f(void) { return 0; }\n",
        metadata_dir=tmp_path,
        metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION", "size": len(_CODE)}},
    )
    raw = tmp_path / "input.bin"
    raw.write_bytes(_CODE)
    cfg = SimpleNamespace(
        root=tmp_path,
        target_name="server",
        marker="SERVER",
        target_binary=tmp_path / "absent.dll",
        reversed_dir=source,
        metadata_dir=tmp_path,
        source_ext=".c",
        compiler_profile="msvc-6.0",
        arch="x86_32",
    )
    monkeypatch.setattr("rebrew.asm.require_config", lambda **kwargs: cfg)
    monkeypatch.setattr("rebrew.formats.binary_loader.extract_raw_bytes", lambda *a, **kw: _CODE)
    return cfg


def _state(root: Path) -> dict[str, tuple[bytes, int]]:
    return {
        str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mtime_ns)
        for path in root.rglob("*")
        if path.is_file()
    }


def _forbid_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("Dry runs must not generate files or invoke NASM")

    for name in [
        "disassemble_to_nasm",
        "verify_roundtrip",
        "_run_nasm",
        "_record_inline_c_identity",
    ]:
        monkeypatch.setattr(f"rebrew.asm.{name}", refuse)


def _fake_nasm(code: bytes, va: int, label: str) -> tuple[str, dict[str, Any]]:
    return "bits 32\nret\n", {
        "base_va": va,
        "total_bytes": len(code),
        "total_instructions": 7,
        "nasm_ok": 7,
        "pct_nasm": 100.0,
        "db_fallbacks": 0,
    }


class TestShowArtifacts:
    @pytest.mark.parametrize("inline_c", [False, True])
    @pytest.mark.parametrize("existing", [False, True])
    def test_preview_preserves_files_and_metadata_without_nasm(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inline_c: bool, existing: bool
    ) -> None:
        _project(tmp_path, monkeypatch)
        output = tmp_path / "output" / ("f.c" if inline_c else "f.asm")
        if existing:
            output.parent.mkdir()
            output.write_text("Keep this file\n")
        before = _state(tmp_path)
        _forbid_generation(monkeypatch)
        args = [
            "show",
            "--format",
            "nasm",
            "--bin",
            str(tmp_path / "input.bin"),
            "--base-va",
            "1000",
            "--output",
            str(output),
            "--verify",
            "--dry-run",
            "--json",
        ]
        if inline_c:
            args.append("--inline-c")
        result = CliRunner().invoke(app, args)
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["output"] == str(output)
        assert payload["written"] is False
        assert payload["dry_run"] is True
        assert "roundtrip_pass" not in payload
        assert _state(tmp_path) == before
        assert output.parent.exists() is existing

    @pytest.mark.parametrize("inline_c", [False, True])
    def test_json_does_not_suppress_the_artifact_or_requested_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inline_c: bool
    ) -> None:
        _project(tmp_path, monkeypatch)
        monkeypatch.setattr("rebrew.asm.disassemble_to_nasm", _fake_nasm)
        output = tmp_path / "output" / ("f.c" if inline_c else "f.asm")
        before = (tmp_path / "rebrew-functions.toml").read_bytes()
        args = [
            "show",
            "--format",
            "nasm",
            "--bin",
            str(tmp_path / "input.bin"),
            "--base-va",
            "1000",
            "--output",
            str(output),
            "--json",
        ]
        if inline_c:
            args.append("--inline-c")
        result = CliRunner().invoke(app, args)
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["output"] == str(output)
        assert payload["written"] is True
        assert payload["dry_run"] is False
        if inline_c:
            assert "ADDRESS: SERVER 0x00001000" in output.read_text()
            assert "REBREW_ALLOW_NAKED" in output.read_text()
            entry = get_entry(tmp_path, 0x1000, "SERVER")
            assert entry["file"] == "output/f.c"
            assert entry["source"] == "naked"
        else:
            assert output.read_text() == "bits 32\nret\n"
            assert (tmp_path / "rebrew-functions.toml").read_bytes() == before


class TestBatchArtifacts:
    @pytest.mark.parametrize("alias", [False, True])
    def test_repeated_inline_generation_does_not_ingest_its_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, alias: bool
    ) -> None:
        from rebrew.metadata.functions import load_metadata

        cfg = _project(tmp_path, monkeypatch)
        monkeypatch.setattr("rebrew.asm.disassemble_to_nasm", _fake_nasm)
        generated = cfg.reversed_dir / "generated"
        output = generated
        if alias:
            generated.mkdir()
            output = tmp_path / "output-alias"
            output.symlink_to(generated, target_is_directory=True)
        args = ["batch", "--inline-c", "--output", str(output), "--json"]
        first = CliRunner().invoke(app, args)
        assert first.exit_code == 0, first.output
        metadata = load_metadata(tmp_path)
        metadata_bytes = (tmp_path / "rebrew-functions.toml").read_bytes()
        generated_files = _state(generated)
        second = CliRunner().invoke(app, args)
        assert second.exit_code == 0, second.output
        assert json.loads(second.stdout)["total"] == 1
        assert json.loads(second.stdout)["files"] == json.loads(first.stdout)["files"]
        assert load_metadata(tmp_path) == metadata
        assert (tmp_path / "rebrew-functions.toml").read_bytes() == metadata_bytes
        assert _state(generated) == generated_files
        assert list(generated.iterdir()) == [generated / "f.c.00001000.c"]

    @pytest.mark.parametrize(
        "destination", ["selected", "parent", "project", "alias", "shared", "other"]
    )
    def test_dangerous_output_roots_are_rejected_before_inventory_or_probes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, destination: str
    ) -> None:
        cfg = _project(tmp_path, monkeypatch)
        cfg.shared_dir = tmp_path / "shared"
        cfg.shared_dir.mkdir()
        cfg.all_targets = ["server", "client"]
        other = tmp_path / "client"
        other.mkdir()
        monkeypatch.setattr(
            "rebrew.asm.load_config", lambda root, target: SimpleNamespace(reversed_dir=other)
        )
        destinations = {
            "selected": cfg.reversed_dir,
            "parent": cfg.reversed_dir.parent,
            "project": tmp_path,
            "shared": cfg.shared_dir,
            "other": other,
        }
        if destination == "alias":
            output = tmp_path / "alias"
            output.symlink_to(cfg.reversed_dir, target_is_directory=True)
        else:
            output = destinations[destination]
        before = _state(tmp_path)
        _forbid_generation(monkeypatch)

        def refuse(*args: Any, **kwargs: Any) -> None:
            raise AssertionError(
                "Unsafe output must stop before source scanning or byte extraction"
            )

        monkeypatch.setattr("rebrew.asm.iter_sources", refuse)
        monkeypatch.setattr("rebrew.formats.binary_loader.extract_raw_bytes", refuse)
        result = CliRunner().invoke(
            app, ["batch", "--output", str(output), "--inline-c", "--verify", "--dry-run", "--json"]
        )
        assert result.exit_code == 2, result.output
        payload = json.loads(result.stdout)
        assert "must not equal or contain configured source directory" in payload["error"]
        assert payload["code"] == 2
        assert _state(tmp_path) == before

    @pytest.mark.parametrize("marker,va", [("SERVER", 0x1000), ("CLIENT", 0x2000)])
    @pytest.mark.parametrize("dry_run", [False, True])
    def test_shared_source_selects_only_this_targets_function_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, marker: str, va: int, dry_run: bool
    ) -> None:
        from rebrew.metadata.functions import load_metadata

        cfg = _project(tmp_path, monkeypatch)
        cfg.marker = marker
        source = cfg.reversed_dir / "f.c"
        write_source(
            source,
            "// ADDRESS: SERVER 0x1000\n// ADDRESS: CLIENT 0x2000\n"
            "int f(void) { return 0; }\n"
            "// ADDRESS: SERVER 0x3000\nchar data[13];\n",
            metadata_dir=tmp_path,
            metadata_fields={
                "SERVER.0x1000": {"kind": "FUNCTION", "size": len(_CODE)},
                "CLIENT.0x2000": {"kind": "FUNCTION", "size": len(_CODE)},
                "SERVER.0x3000": {"kind": "GLOBAL", "size": len(_CODE), "status": "EXACT"},
            },
        )
        before = load_metadata(tmp_path)
        before_files = _state(tmp_path)
        extracted: list[int] = []

        def extract(binary: Path, address: int, size: int) -> bytes:
            extracted.append(address)
            return _CODE

        monkeypatch.setattr("rebrew.formats.binary_loader.extract_raw_bytes", extract)
        monkeypatch.setattr("rebrew.asm.disassemble_to_nasm", _fake_nasm)
        output = tmp_path / "output"
        args = ["batch", "--inline-c", "--output", str(output), "--json"]
        if dry_run:
            args.append("--dry-run")
        result = CliRunner().invoke(app, args)
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        artifact = output / f"f.c.{va:08x}.c"
        assert payload["total"] == 1
        assert payload["files"] == [str(artifact)]
        assert extracted == [va]
        after = load_metadata(tmp_path)
        assert after.keys() == before.keys()
        if dry_run:
            assert after == before
            assert _state(tmp_path) == before_files
        else:
            assert after[(marker, va)]["file"] == f"output/{artifact.name}"
            assert after[(marker, va)]["source"] == "naked"
            assert {key: row for key, row in after.items() if key != (marker, va)} == {
                key: row for key, row in before.items() if key != (marker, va)
            }
            assert source.read_bytes() == before_files["src/f.c"][0]
            assert (tmp_path / "rebrew-data.toml").read_bytes() == before_files["rebrew-data.toml"][
                0
            ]

    @pytest.mark.parametrize("existing", [False, True])
    def test_preview_reports_planned_files_without_writing_or_verifying(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool
    ) -> None:
        _project(tmp_path, monkeypatch)
        output = tmp_path / "output"
        artifact = output / "f.c.00001000.c"
        if existing:
            output.mkdir()
            artifact.write_text("Keep this file\n")
        before = _state(tmp_path)
        _forbid_generation(monkeypatch)
        result = CliRunner().invoke(
            app, ["batch", "--output", str(output), "--inline-c", "--verify", "--dry-run", "--json"]
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload == {
            "output": str(output),
            "total": 1,
            "ok": 0,
            "failed": 0,
            "skipped": 0,
            "planned": 1,
            "written": 0,
            "files": [str(artifact)],
            "dry_run": True,
        }
        assert _state(tmp_path) == before
        assert output.exists() is existing

    def test_json_reports_written_files_and_extraction_skips(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _project(tmp_path, monkeypatch)
        write_source(
            cfg.reversed_dir / "g.c",
            "// ADDRESS: SERVER 0x2000\nint g(void) { return 0; }\n",
            metadata_dir=tmp_path,
            metadata_fields={"SERVER.0x2000": {"kind": "FUNCTION", "size": len(_CODE)}},
        )
        monkeypatch.setattr(
            "rebrew.formats.binary_loader.extract_raw_bytes",
            lambda binary, va, size: _CODE if va == 0x1000 else None,
        )
        monkeypatch.setattr("rebrew.asm.disassemble_to_nasm", _fake_nasm)
        output = tmp_path / "output"
        result = CliRunner().invoke(app, ["batch", "--output", str(output), "--json"])
        assert result.exit_code == 0, result.output
        artifact = output / "f.c.00001000.asm"
        assert json.loads(result.stdout) == {
            "output": str(output),
            "total": 2,
            "ok": 1,
            "failed": 0,
            "skipped": 1,
            "planned": 1,
            "written": 1,
            "files": [str(artifact)],
            "dry_run": False,
        }
        assert artifact.read_text() == "bits 32\nret\n"
        assert "SKIP" in result.stderr
