from pathlib import Path

from rebrew.annotation import update_annotation_key


def test_update_annotation_key_multiple_funcs(tmp_path: Path):
    cfile = tmp_path / "test.c"
    cfile.write_text(
        """// FUNCTION: GAME 0x1000
// STATUS: EXACT
// SYMBOL: func_1000
// CFLAGS: /O2
// SIZE: 10
void func_1000() {}

// FUNCTION: GAME 0x2000
// SYMBOL: func_2000
// SIZE: 10
void func_2000() {}
""",
        encoding="utf-8",
    )

    assert update_annotation_key(cfile, 0x1000, "SYMBOL", "ResetScore")
    assert update_annotation_key(cfile, 0x2000, "SYMBOL", "AddScore")

    text = cfile.read_text(encoding="utf-8")
    assert "// SYMBOL: ResetScore" in text
    assert "// SYMBOL: func_1000" not in text
    assert "// SYMBOL: AddScore" in text
    assert "// SYMBOL: func_2000" not in text
