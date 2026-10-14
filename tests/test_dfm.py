"""Lossless form streams, candidate scope, and malformed input handling."""

import json
import struct
from pathlib import Path

import pytest
from bin_util import make_ne
from typer.testing import CliRunner

from rebrew.app.main import app
from rebrew.formats.dfm import (
    Binary,
    Component,
    DfmError,
    False_,
    Identifier,
    Int8,
    Int16,
    Int32,
    Reader,
    SetOfIdentifiers,
    Str,
    True_,
    encode,
    parse_form,
    parse_forms,
    roundtrip,
    scan_forms,
)


def _form() -> bytes:
    component = Component(
        "TForm",
        "Main",
        props=[
            ("Small", Int8(-127)),
            ("Width", Int16(1234)),
            ("Long", Int32(-123456)),
            ("Caption", Str("caf\xe9 'test'")),
            ("OnClose", Identifier("FormClose")),
            ("Visible", True_),
            ("Enabled", False_),
            ("Flags", SetOfIdentifiers(["akLeft", "akTop"])),
            ("Picture", Binary(b"TPF0" + bytes(16))),
        ],
        kids=[Component("TButton", "Button", props=[("Caption", Str("Done"))])],
    )
    return b"TPF0" + encode(component)


class TestFormCodec:
    def test_wire_types_property_order_and_children_roundtrip(self) -> None:
        original = _form()
        root, end = parse_form(original)
        assert end == len(original)
        assert encode(root) == original[4:]
        assert root.events() == [("OnClose", "FormClose")]
        assert [c.name for c in root.walk()] == ["Main", "Button"]
        assert roundtrip(original) == (1, [])
        assert len(scan_forms(original)[0]) == 1  # embedded TPF0 is picture data

    @pytest.mark.parametrize("size", [0, 3, 5, 10, 22])
    def test_truncated_values_never_escape_as_index_or_struct_errors(self, size: int) -> None:
        with pytest.raises(DfmError):
            parse_form(_form()[:size])

    def test_unsupported_stream_is_visible_beside_a_valid_stream(self) -> None:
        invalid = b"TPF0\x05TForm\x04Main\x01x\x05" + bytes(10)
        valid = _form()
        forms, errors = scan_forms(invalid + valid)
        assert len(forms) == 1
        assert forms[0][0] == len(invalid)
        assert "unsupported value type" in errors[0]["error"]
        with pytest.raises(DfmError, match="could not be decoded"):
            parse_forms(invalid + valid)

    def test_ne_code_marker_is_not_a_form(self) -> None:
        code = _form()
        image = make_ne(segments=[(code, 0)]) + _form()
        assert len(parse_forms(image)) == 1
        assert parse_forms(image)[0][0] >= len(image) - len(_form())

    def test_large_binary_length_and_unterminated_set_are_rejected(self) -> None:
        with pytest.raises(DfmError, match="truncated"):
            Reader(struct.pack("<I", 0xFFFFFFFF), 0).value(0x0A)
        with pytest.raises(DfmError, match="truncated"):
            Reader(b"\x01x", 0).value(0x0B)

    def test_excessive_nesting_is_rejected(self) -> None:
        header = b"\x01T\x01x\x00"
        with pytest.raises(DfmError, match="128"):
            parse_form(b"TPF0" + header * 129 + bytes(129))

    def test_encoding_never_truncates_short_strings_or_signed_bytes(self) -> None:
        with pytest.raises(DfmError, match="255"):
            Str("x" * 256).encode()
        with pytest.raises(DfmError, match="signed byte"):
            Int8(256).encode()


class TestFormCommand:
    def test_cli_reports_stream_roundtrip_and_event_names(self, tmp_path: Path) -> None:
        path = tmp_path / "form.dfm"
        path.write_bytes(_form())
        result = CliRunner().invoke(app, ["binary", "forms", str(path), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["unsupported_candidates"] == []
        assert payload["forms"][0]["roundtrip"] is True
        assert payload["forms"][0]["events"][0]["handler"] == "FormClose"

    def test_cli_returns_error_for_unsupported_candidate(self, tmp_path: Path) -> None:
        path = tmp_path / "form.dfm"
        path.write_bytes(b"TPF0\x05TForm\x04Main\x01x\xff")
        result = CliRunner().invoke(app, ["binary", "forms", str(path), "--json"])
        assert result.exit_code == 2, result.output
        assert len(json.loads(result.stdout)["unsupported_candidates"]) == 1
