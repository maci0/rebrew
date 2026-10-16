"""`rebrew source rehome`: retarget function and data rows at the file that now defines them."""

import shutil
import tomllib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cli_json import cli_payload
from source_util import write_store_fixture
from typer.testing import CliRunner

from rebrew.app.main import app
from rebrew.rehome import rehome_functions

FIXTURES = Path(__file__).parent / "fixtures"


def _cfg(tmp_path: Path) -> SimpleNamespace:
    (tmp_path / "src").mkdir(exist_ok=True)
    write_store_fixture(
        tmp_path / "rebrew-functions.toml",
        'format = 2\n["SERVER.0x1000"]\nname = "f"\nsymbol = "_f"\nfile = "src/a.c"\nkind = "FUNCTION"\n',
        encoding="utf-8",
    )
    return SimpleNamespace(
        root=tmp_path, metadata_dir=tmp_path, module="SERVER", target_name="SERVER"
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


def test_binds_row_to_named_definition(tmp_path: Path) -> None:
    """``PATH:NAME`` joins an existing definition: file, name and decorated symbol change."""
    cfg = _cfg(tmp_path)
    meta = tmp_path / "rebrew-functions.toml"
    write_store_fixture(
        meta,
        'format = 2\n["SERVER.0x1000"]\nname = "fcn_00001000"\nsymbol = "_fcn_00001000@8"\nfile = "src/a.c"\nkind = "FUNCTION"\n',
        encoding="utf-8",
    )
    (tmp_path / "src" / "shared.c").write_text(
        "int __stdcall gm_Shared(int a, int b)\n{\n\treturn a + b;\n}\n", encoding="utf-8"
    )
    rows = rehome_functions(cfg, ["0x1000=src/shared.c:gm_Shared"])
    assert rows[0]["old_name"] == "fcn_00001000"
    row = tomllib.loads(meta.read_text(encoding="utf-8"))["SERVER.0x1000"]
    assert (row["name"], row["symbol"]) == ("gm_Shared", "_gm_Shared@8")
    assert row["file"].endswith("shared.c")
    with pytest.raises(ValueError, match="does not define gm_Other"):
        rehome_functions(cfg, ["0x1000=src/shared.c:gm_Other"])


def test_rejects_unknown_row(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    (tmp_path / "src" / "b.c").write_text("int f(void)\n{\n\treturn 0;\n}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no function row"):
        rehome_functions(cfg, ["0x2000=src/b.c"])


_PROJECT_TOML = """\
[project]
name = "rehome"
default_target = "SERVER"
jobs = 1

[targets."SERVER"]
binary = "original/mini_pe.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src"
source_ext = ".c"
module = "SERVER"

[compiler]
profile = "mingw-16.2.0"
command = "i686-w64-mingw32-gcc"
cflags = "-O2"
"""

_FUNCTIONS_TOML = 'format = 2\n["SERVER.0x1000"]\nname = "f"\nsymbol = "_f"\nfile = "src/a/x.c"\nkind = "FUNCTION"\nstatus = "EXACT"\n\n["CLIENT.0x5000"]\nname = "f"\nsymbol = "_f"\nfile = "src/a/x.c"\nkind = "FUNCTION"\n\n["SERVER.0x2000"]\nname = "other"\nsymbol = "_other"\nfile = "src/a/z.c"\nkind = "FUNCTION"\n'

_DATA_TOML = 'format = 2\n["SERVER.0x3000"]\nname = "g_count"\nfile = "src/a/x.c"\n\n["SERVER.0x4000"]\nname = "g_other"\nfile = "src/a/z.c"\n'


class TestRetargetFile:
    """`rebrew source rehome --from OLD --to NEW` after a file moved."""

    def _project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str) -> Path:
        root = tmp_path / "project"
        (root / "original").mkdir(parents=True)
        (root / "src" / "b").mkdir(parents=True)
        shutil.copy(FIXTURES / "mini_pe.exe", root / "original" / "mini_pe.exe")
        (root / "rebrew-project.toml").write_text(_PROJECT_TOML, encoding="utf-8")
        write_store_fixture(root / "rebrew-functions.toml", _FUNCTIONS_TOML, encoding="utf-8")
        write_store_fixture(root / "rebrew-data.toml", _DATA_TOML, encoding="utf-8")
        (root / "src" / "b" / "y.c").write_text(body, encoding="utf-8")
        monkeypatch.chdir(root)
        return root

    def _rehome(self, *args: str) -> Any:
        return CliRunner().invoke(app, ["source", "rehome", *args])

    def _stores(self, root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
        return (
            tomllib.loads((root / "rebrew-functions.toml").read_text(encoding="utf-8")),
            tomllib.loads((root / "rebrew-data.toml").read_text(encoding="utf-8")),
        )

    def test_moves_every_row_naming_the_old_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = self._project(
            tmp_path, monkeypatch, "int g_count;\nint f(void)\n{\n\treturn 0;\n}\n"
        )
        result = self._rehome("--from", "src/a/x.c", "--to", "src/b/y.c", "--json")
        assert result.exit_code == 0, result.output
        payload = cli_payload(result)
        assert [(r["module"], r["va"], r["file"]) for r in payload["rows"]] == [
            ("CLIENT", "0x5000", "src/b/y.c"),
            ("SERVER", "0x1000", "src/b/y.c"),
        ]
        assert [(r["va"], r["name"]) for r in payload["data"]] == [("0x3000", "g_count")]
        functions, data = self._stores(root)
        for key in ("SERVER.0x1000", "CLIENT.0x5000"):
            assert functions[key]["file"] == "src/b/y.c"
            assert functions[key]["updated_by"] == "rehome"
        assert functions["SERVER.0x1000"]["status"] == "EXACT"
        assert functions["SERVER.0x2000"]["file"] == "src/a/z.c"
        assert data["SERVER.0x3000"]["file"] == "src/b/y.c"
        assert data["SERVER.0x3000"]["updated_by"] == "rehome"
        assert data["SERVER.0x4000"]["file"] == "src/a/z.c"

    def test_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        root = self._project(tmp_path, monkeypatch, "int f(void)\n{\n\treturn 0;\n}\n")
        result = self._rehome("--from", "src/a/x.c", "--to", "src/b/y.c", "--dry-run", "--json")
        assert result.exit_code == 0, result.output
        payload = cli_payload(result)
        assert payload["dry_run"] is True
        assert len(payload["rows"]) == 2 and len(payload["data"]) == 1
        assert (root / "rebrew-functions.toml").read_text(encoding="utf-8") == _FUNCTIONS_TOML
        assert (root / "rebrew-data.toml").read_text(encoding="utf-8") == _DATA_TOML

    def test_refuses_a_destination_missing_a_function(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = self._project(tmp_path, monkeypatch, "int h(void)\n{\n\treturn 0;\n}\n")
        result = self._rehome("--from", "src/a/x.c", "--to", "src/b/y.c", "--json")
        assert result.exit_code != 0
        assert "does not define f" in result.output
        assert (root / "rebrew-functions.toml").read_text(encoding="utf-8") == _FUNCTIONS_TOML
        assert (root / "rebrew-data.toml").read_text(encoding="utf-8") == _DATA_TOML

    def test_refuses_a_missing_destination(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._project(tmp_path, monkeypatch, "")
        result = self._rehome("--from", "src/a/x.c", "--to", "src/b/nope.c", "--json")
        assert result.exit_code != 0
        assert "src/b/nope.c is not a file" in result.output

    def test_refuses_a_path_no_row_names(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._project(tmp_path, monkeypatch, "int f(void)\n{\n\treturn 0;\n}\n")
        result = self._rehome("--from", "src/a/w.c", "--to", "src/b/y.c", "--json")
        assert result.exit_code != 0
        assert "no function or data row names src/a/w.c" in result.output

    @pytest.mark.parametrize(
        "args",
        [
            ["--from", "src/a/x.c"],
            ["--to", "src/b/y.c"],
            ["0x1000=src/b/y.c", "--from", "src/a/x.c", "--to", "src/b/y.c"],
            [],
        ],
    )
    def test_refuses_mixed_or_partial_forms(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]
    ) -> None:
        root = self._project(tmp_path, monkeypatch, "int f(void)\n{\n\treturn 0;\n}\n")
        result = self._rehome(*args, "--json")
        assert result.exit_code != 0
        assert (root / "rebrew-functions.toml").read_text(encoding="utf-8") == _FUNCTIONS_TOML
