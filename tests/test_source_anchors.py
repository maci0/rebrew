"""Canonical anchors are optional, guarded source edits, never new identities."""

lazy from pathlib import Path

import pytest
from tree_snapshot import snapshot_with_stat

from rebrew.config import ProjectConfig
from rebrew.metadata.functions import (
    load_metadata,
    record_function_identity,
    set_fields,
    update_source_status,
)
from rebrew.source_anchors import materialize_anchors


def _project(tmp_path: Path) -> tuple[ProjectConfig, Path]:
    source = tmp_path / "src" / "unit.c"
    source.parent.mkdir()
    source.write_bytes(b"/* original spelling: caf\xe9 */\r\nint f(void) { return 1; }\r\n")
    cfg = ProjectConfig(root=tmp_path, reversed_dir=source.parent, module="A")
    for module, va in [("A", 0x401000), ("B", 0x501000)]:
        record_function_identity(
            tmp_path,
            module=module,
            va=va,
            file="src/unit.c",
            name="f",
            symbol="_f",
            kind="FUNCTION",
            size=6,
        )
    update_source_status(tmp_path, "EXACT", va=0x401000, module="A")
    return cfg, source


def test_preview_apply_all_modules_encoding_and_idempotence(tmp_path: Path) -> None:
    cfg, source = _project(tmp_path)
    before = snapshot_with_stat(tmp_path)
    metadata = load_metadata(tmp_path)
    plan = materialize_anchors(cfg, [source])
    assert before == snapshot_with_stat(tmp_path)
    assert len(plan["bindings"]) == 2 and len(plan["files"]) == 1
    materialize_anchors(cfg, [source], dry_run=False, expected_digest=plan["input_digest"])
    raw = source.read_bytes()
    assert b"caf\xe9" in raw and b"\n" not in raw.replace(b"\r\n", b"")
    assert b"/* ADDRESS: A 0x00401000 */" in raw
    assert b"/* ADDRESS: B 0x00501000 */" in raw
    assert load_metadata(tmp_path) == metadata
    assert materialize_anchors(cfg, [source])["files"] == []


@pytest.mark.parametrize("change", ["source", "metadata"])
def test_stale_digest_writes_nothing(tmp_path: Path, change: str) -> None:
    cfg, source = _project(tmp_path)
    plan = materialize_anchors(cfg, [source])
    if change == "source":
        source.write_bytes(source.read_bytes() + b"/* changed */\r\n")
    else:
        set_fields(tmp_path, 0x401000, {"note": "new evidence"}, module="A")
    before = snapshot_with_stat(tmp_path)
    with pytest.raises(ValueError, match="inputs changed"):
        materialize_anchors(cfg, [source], dry_run=False, expected_digest=plan["input_digest"])
    assert before == snapshot_with_stat(tmp_path)


def test_apply_requires_digest(tmp_path: Path) -> None:
    cfg, source = _project(tmp_path)
    before = snapshot_with_stat(tmp_path)
    with pytest.raises(ValueError, match="requires --expected-digest"):
        materialize_anchors(cfg, [source], dry_run=False)
    assert before == snapshot_with_stat(tmp_path)


@pytest.mark.parametrize(
    "text",
    [
        "int f(void) { return 1; }\nint f(void) { return 2; }\n",
        "/* ADDRESS: A 0x00401001 */\nint f(void) { return 1; }\n",
        "int other(void) { return 1; }\n",
    ],
)
def test_ambiguous_missing_or_conflicting_binding_refused(tmp_path: Path, text: str) -> None:
    cfg, source = _project(tmp_path)
    source.write_text(text)
    before = snapshot_with_stat(tmp_path)
    with pytest.raises(ValueError):
        materialize_anchors(cfg, [source])
    assert before == snapshot_with_stat(tmp_path)


def test_multifile_failure_keeps_first_file_unchanged(tmp_path: Path) -> None:
    cfg, source = _project(tmp_path)
    broken = source.with_name("z.c")
    broken.write_text("int wrong(void) { return 0; }\n")
    record_function_identity(
        tmp_path,
        module="A",
        va=0x401100,
        file="src/z.c",
        name="missing",
        symbol="_missing",
        kind="FUNCTION",
        size=3,
    )
    before = snapshot_with_stat(tmp_path)
    with pytest.raises(ValueError):
        materialize_anchors(cfg, [source, broken])
    assert before == snapshot_with_stat(tmp_path)


def test_retired_identity_is_not_reactivated(tmp_path: Path) -> None:
    from rebrew.metadata.binding_history import change_source_binding

    cfg, source = _project(tmp_path)
    change_source_binding(tmp_path, "A", 0x401000, reason="wrong source identity")
    preview = materialize_anchors(cfg, [source])
    assert [b["module"] for b in preview["bindings"]] == ["B"]
    materialize_anchors(cfg, [source], dry_run=False, expected_digest=preview["input_digest"])
    assert b"ADDRESS: A" not in source.read_bytes()


def test_cli_preview_and_apply(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    from typer.testing import CliRunner

    from rebrew.source_anchors import app

    cfg, source = _project(tmp_path)
    monkeypatch.setattr("rebrew.source_anchors.require_config", lambda **kwargs: cfg)
    runner = CliRunner()
    result = runner.invoke(app, [str(source), "--dry-run", "--json"])
    assert result.exit_code == 0, result.output
    digest = json.loads(result.output)["input_digest"]
    result = runner.invoke(app, [str(source), "--expected-digest", digest, "--json"])
    assert result.exit_code == 0, result.output
    assert not json.loads(result.output)["verdicts_changed"]


def test_duplicate_anchors_refused_without_writes(tmp_path: Path) -> None:
    cfg, source = _project(tmp_path)
    marker = b"/* ADDRESS: A 0x00401000 */\r\n"
    source.write_bytes(marker + marker + source.read_bytes())
    before = snapshot_with_stat(tmp_path)
    with pytest.raises(ValueError, match="duplicate ADDRESS"):
        materialize_anchors(cfg, [source])
    assert before == snapshot_with_stat(tmp_path)


@pytest.mark.parametrize("stale", [False, True])
def test_source_provenance_is_byte_exact_after_anchors(tmp_path: Path, stale: bool) -> None:
    from rebrew.metadata.source_provenance import document_assembly

    cfg, source = _project(tmp_path)
    document_assembly(tmp_path, source, "f", "A", "Reviewed original assembly")
    if stale:
        source.write_bytes(source.read_bytes().replace(b"return 1", b"return 2"))
    metadata = (tmp_path / "rebrew-functions.toml").read_bytes()
    preview = materialize_anchors(cfg, [source])
    materialize_anchors(cfg, [source], dry_run=False, expected_digest=preview["input_digest"])
    assert (tmp_path / "rebrew-functions.toml").read_bytes() == metadata


def test_second_write_failure_restores_sources_and_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import rebrew.rename_ops as rename_ops

    cfg, source = _project(tmp_path)
    second = source.with_name("z.c")
    second.write_text("int z(void) { return 0; }\n")
    record_function_identity(
        tmp_path,
        module="A",
        va=0x401100,
        file="src/z.c",
        name="z",
        symbol="_z",
        kind="FUNCTION",
        size=3,
    )
    preview = materialize_anchors(cfg, [source, second])
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    write = rename_ops.atomic_write_text

    def fail(path: Path, text: str, *, encoding: str = "utf-8") -> None:
        if path == second and "ADDRESS:" in text:
            raise PermissionError("injected second source write failure")
        write(path, text, encoding=encoding)

    monkeypatch.setattr(rename_ops, "atomic_write_text", fail)
    with pytest.raises(rename_ops.RenameError, match="restored"):
        materialize_anchors(
            cfg, [source, second], dry_run=False, expected_digest=preview["input_digest"]
        )
    assert {p: p.read_bytes() for p in before} == before


def test_existing_module_spelling_is_preserved(tmp_path: Path) -> None:
    cfg, source = _project(tmp_path)
    source.write_bytes(b"/* ADDRESS: a 0x00401000 */\r\n" + source.read_bytes())
    preview = materialize_anchors(cfg, [source])
    materialize_anchors(cfg, [source], dry_run=False, expected_digest=preview["input_digest"])
    assert source.read_bytes().count(b"0x00401000") == 1
