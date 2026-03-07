from pathlib import Path

from rebrew.lint import lint_file


def _write_c(tmp_path: Path, filename: str, content: str) -> Path:
    f = tmp_path / filename
    f.write_text(content, encoding="utf-8")
    return f


MULTI_BLOCK_FILE = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// SIZE: 31
// CFLAGS: /O2 /Gd

int func1() { return 1; }

// FUNCTION: CLIENT 0x10009990
// STATUS: EXACT
// CFLAGS: /O2 /Gd

int func2() { return 2; }
"""


def test_multi_block_linting(tmp_path: Path):
    """Multi-block file should pass even when a block has no SIZE in source.

    SIZE is sidecar-only; E007 is no longer emitted.
    """
    f = _write_c(tmp_path, "func1.c", MULTI_BLOCK_FILE)
    res = lint_file(f)
    # Both blocks have STATUS — no errors expected
    assert res.passed
    assert not any(code == "E007" for _, code, _ in res.errors)


def test_multi_block_missing_status(tmp_path: Path):
    """Multi-block file with a missing STATUS should still error."""
    content = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// CFLAGS: /O2 /Gd

int func1() { return 1; }

// FUNCTION: CLIENT 0x10009990
// CFLAGS: /O2 /Gd

int func2() { return 2; }
"""
    f = _write_c(tmp_path, "func1.c", content)
    res = lint_file(f)
    assert not res.passed
    assert any(code == "E003" for _, code, _ in res.errors)


def test_multi_block_all_valid(tmp_path: Path):
    f = _write_c(tmp_path, "func1.c", MULTI_BLOCK_FILE)
    res = lint_file(f)
    assert res.passed
