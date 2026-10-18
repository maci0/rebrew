"""Function and addressless source writers preserve each other's durable records."""

from pathlib import Path

import pytest

from rebrew.metadata import functions
from rebrew.metadata.source_provenance import (
    consolidate_source_metadata,
    document_assembly,
    load_source_files,
    load_source_provenance,
    replace_source_metadata,
    set_source_file,
)


@pytest.mark.parametrize(
    "writer",
    ["field", "fields", "batch", "rows", "status", "remove", "delete", "replace"],
)
def test_function_writers_preserve_addressless_records(tmp_path: Path, writer: str) -> None:
    helper = tmp_path / "helper.c"
    helper.write_text("static void fill(void) { __asm { nop } }\n")
    rows = {
        ("S", 0x1000): {"note": "edit", "status": "STUB"},
        ("C", 0x2000): {
            "name": "other",
            "status": "EXACT",
            "verification": {"status": "EXACT", "writer": "verify", "input_hash": "a" * 64},
        },
    }
    functions.save_metadata(tmp_path, rows)
    document_assembly(tmp_path, helper, "fill", "S", "Original inline assembly")
    set_source_file(tmp_path, "helper.c", "C", "native link support")
    definitions, files = load_source_provenance(tmp_path), load_source_files(tmp_path)

    if writer == "field":
        functions.update_field(tmp_path, 0x1000, "note", "changed", "S")
    elif writer == "fields":
        functions.set_fields(tmp_path, 0x1000, {"note": "changed"}, "S")
    elif writer == "batch":
        functions.set_fields_batch(
            tmp_path, [{"module": "S", "va": 0x1000, "fields": {"note": "changed"}}]
        )
    elif writer == "rows":
        functions.record_function_rows(
            tmp_path, [{"module": "S", "va": 0x1000, "fields": {"note": "changed"}}]
        )
    elif writer == "status":
        functions.update_statuses_batch(
            tmp_path, [{"module": "S", "va": 0x1000, "new_status": "RELOC"}]
        )
    elif writer == "remove":
        functions.remove_fields_batch(tmp_path, [{"module": "S", "va": 0x1000, "keys": ["note"]}])
    elif writer == "delete":
        functions.delete_entries_batch(tmp_path, [("S", 0x1000)])
    else:
        functions.save_metadata(tmp_path, rows)

    edited = functions.get_entry(tmp_path, 0x1000, "S")
    if writer == "delete":
        assert edited == {}
    elif writer == "remove":
        assert "note" not in edited
    elif writer == "status":
        assert edited["status"] == "RELOC"
    elif writer != "replace":
        assert edited["note"] == "changed"
    assert load_source_provenance(tmp_path) == definitions
    assert load_source_files(tmp_path) == files
    assert functions.get_entry(tmp_path, 0x2000, "C") == rows[("C", 0x2000)]
    assert not (tmp_path / "rebrew-source.toml").exists()


def test_source_replacement_preserves_function_state(tmp_path: Path) -> None:
    import hashlib

    row = {
        "status": "EXACT",
        "verification": {"status": "EXACT", "writer": "verify", "input_hash": "a" * 64},
        "status_history": [
            {
                "old_status": "RELOC",
                "new_status": "EXACT",
                "changed_at": "2026-10-01T00:00:00+00:00",
                "updated_by": "verify",
            }
        ],
    }
    functions.save_metadata(tmp_path, {("S", 0x1000): row})
    path = tmp_path / "rebrew-functions.toml"
    replace_source_metadata(
        tmp_path, [], [], expected_hash=hashlib.sha256(path.read_bytes()).hexdigest()
    )
    assert functions.load_metadata(tmp_path) == {("S", 0x1000): row}


@pytest.mark.parametrize("existing_function", [False, True])
def test_failed_source_retirement_restores_original_stores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_function: bool
) -> None:
    function = tmp_path / "rebrew-functions.toml"
    source = tmp_path / "rebrew-source.toml"
    original_function = b'format = 2\n["S.0x1000"]\nstatus="EXACT"\n' if existing_function else None
    if original_function is not None:
        function.write_bytes(original_function)
    original_source = b"format=2\n[definitions]\n[files]\n"
    source.write_bytes(original_source)
    preview = consolidate_source_metadata(tmp_path, dry_run=True)
    unlink = Path.unlink

    def refuse_retirement(path: Path, missing_ok: bool = False) -> None:
        if path == source:
            raise OSError("cannot retire source store")
        unlink(path, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", refuse_retirement)
    with pytest.raises(OSError, match="cannot retire"):
        consolidate_source_metadata(tmp_path, expected_digest=preview["input_digest"])
    assert source.read_bytes() == original_source
    if original_function is None:
        assert not function.exists()
    else:
        assert function.read_bytes() == original_function


@pytest.mark.parametrize("source_value", ["1", "true", '"text"', "[]", "[1]"])
def test_invalid_source_section_is_rejected_without_writing(
    tmp_path: Path, source_value: str
) -> None:
    path = tmp_path / "rebrew-functions.toml"
    original = f"format = 3\nsource = {source_value}\n"
    path.write_text(original)
    for reader in (functions.load_metadata, load_source_provenance, load_source_files):
        with pytest.raises(ValueError):
            reader(tmp_path)
    with pytest.raises(ValueError):
        set_source_file(tmp_path, "support.c", "S", "native support")
    assert path.read_text() == original
