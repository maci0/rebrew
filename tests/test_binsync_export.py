"""Tests for binsync_export.py."""

import os
from pathlib import Path
from typing import Any, cast

import tomlkit
from typer.testing import CliRunner

from rebrew.main import app

runner = CliRunner()


def test_binsync_export(tmp_path: Path) -> None:
    # 1. Create a dummy rebrew project
    cfg_file = tmp_path / "rebrew-project.toml"
    cfg_file.write_text(
        """
[targets.server]
binary = "server.dll"
reversed_dir = "src"
""",
        encoding="utf-8",
    )

    src_dir = tmp_path / "src"
    src_dir.mkdir()

    # Create dummy annotated files
    f1 = src_dir / "file1.c"
    f1.write_text(
        """// FUNCTION: SERVER 0x10001000
// STATUS: EXACT
// SIZE: 31
int foo() { return 1; }
""",
        encoding="utf-8",
    )

    f2 = src_dir / "file2.c"
    f2.write_text(
        """// FUNCTION: SERVER 0x20002000
// STATUS: MATCHING
// SYMBOL: my_matching_func
double bar() { return 2.0; }
""",
        encoding="utf-8",
    )

    # Note: data/global are skipped according to the code

    outdir = tmp_path / "binsync_out"

    # 2. Run binsync-export
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        result = runner.invoke(app, ["binsync-export", str(outdir)])
    finally:
        os.chdir(cwd)

    print("CLI Output:", result.output)
    assert result.exit_code == 0

    # 3. Verify directory structure
    assert outdir.exists()
    funcs_dir = outdir / "functions"
    assert funcs_dir.exists()

    f1_toml = funcs_dir / "10001000.toml"
    assert f1_toml.exists()

    doc1 = tomlkit.loads(f1_toml.read_text(encoding="utf-8"))
    assert "info" in doc1
    info1 = cast(dict[str, Any], doc1["info"])
    assert info1["addr"] == 0x10001000
    assert info1["name"] == "_foo"  # derived from C function definition
    assert info1["size"] == 31

    f2_toml = funcs_dir / "20002000.toml"
    assert f2_toml.exists()
    doc2 = tomlkit.loads(f2_toml.read_text(encoding="utf-8"))
    info2 = cast(dict[str, Any], doc2["info"])
    assert info2["addr"] == 0x20002000
    assert info2["name"] == "_bar"  # derived from C function definition
    assert "size" not in info2  # Size was not provided, shouldn't be zero-sized
