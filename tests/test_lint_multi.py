from pathlib import Path

from rebrew.lint import lint_file


def _write_c(tmp_path: Path, filename: str, content: str) -> Path:
    f = tmp_path / filename
    f.write_text(content, encoding="utf-8")
    return f


MULTI_BLOCK_FILE = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
// SYMBOL: _func1

int func1() { return 1; }

// FUNCTION: CLIENT 0x10009990
// STATUS: EXACT
// ORIGIN: GAME
// CFLAGS: /O2 /Gd
// SYMBOL: _func2

int func2() { return 2; }
"""


def test_multi_block_linting(tmp_path: Path):
    f = _write_c(tmp_path, "func1.c", MULTI_BLOCK_FILE)

    # It should detect missing SIZE in the second block
    res = lint_file(f)

    assert not res.passed
    assert len(res.errors) == 1

    line, code, msg = res.errors[0]
    assert code == "E007"
    assert "[CLIENT 0x10009990]" in msg
    assert "Missing // SIZE:" in msg


def test_multi_block_all_valid(tmp_path: Path):
    valid_multi = MULTI_BLOCK_FILE.replace(
        "// CFLAGS: /O2 /Gd\n// SYMBOL: _func2",
        "// SIZE: 42\n// CFLAGS: /O2 /Gd\n// SYMBOL: _func2",
    )
    f = _write_c(tmp_path, "func1.c", valid_multi)

    res = lint_file(f)
    assert res.passed
