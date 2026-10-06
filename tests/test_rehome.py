"""`rebrew source rehome`: retarget a function row at the file that now defines it."""

import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.rehome import rehome_functions


def _cfg(tmp_path: Path) -> SimpleNamespace:
    (tmp_path / "src").mkdir(exist_ok=True)
    (tmp_path / "rebrew-functions.toml").write_text(
        '["SERVER.0x1000"]\nname = "f"\nsymbol = "_f"\nfile = "src/a.c"\nmarker_type = "FUNCTION"\n',
        encoding="utf-8",
    )
    return SimpleNamespace(
        root=tmp_path, metadata_dir=tmp_path, marker="SERVER", target_name="SERVER"
    )


def test_points_row_at_defining_file(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    (tmp_path / "src" / "b.c").write_text(
        "int g(void);\nint f(void)\n{\n\treturn g();\n}\n", encoding="utf-8"
    )
    rows = rehome_functions(cfg, ["0x1000=src/b.c"], dry_run=True)
    assert rows[0]["old_file"] == "src/a.c" and rows[0]["file"].endswith("b.c")
    meta = tmp_path / "rebrew-functions.toml"
    assert 'file = "src/a.c"' in meta.read_text(encoding="utf-8")
    rehome_functions(cfg, ["0x1000=src/b.c"])
    row = tomllib.loads(meta.read_text(encoding="utf-8"))["SERVER.0x1000"]
    assert row["file"] == rows[0]["file"]
    assert row["updated_by"] == "rehome"


def test_rejects_file_without_definition(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    (tmp_path / "src" / "c.c").write_text(
        "int f(void);\nint h(void)\n{\n\treturn f();\n}\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="does not define f"):
        rehome_functions(cfg, ["0x1000=src/c.c"])


def test_rejects_unknown_row(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    (tmp_path / "src" / "b.c").write_text("int f(void)\n{\n\treturn 0;\n}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no function row"):
        rehome_functions(cfg, ["0x2000=src/b.c"])
