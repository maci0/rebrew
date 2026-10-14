"""`rebrew source symbolize`: raw relocated addresses become the data symbols the link defines."""

import json
import struct
from pathlib import Path
from types import SimpleNamespace

import lief
import pytest
from source_util import write_store_fixture
from typer.testing import CliRunner

import rebrew.symbolize as symbolize

_FIXTURE = Path(__file__).parent / "fixtures" / "mini_pe.exe"
_HIGHLOW = lief.PE.RelocationEntry.BASE_TYPES.HIGHLOW

# Reference .text at 0x401000: f (0x20 bytes), g (0x10), k (0x10).
_F_VALUES = [0x10003000, 0x10003008, 0x10004000, 0x10003020, 0x10003010, 0x10003030]
_G_VALUES = [0x10003000, 0x10003000]
_K_VALUES = [0x10003000]
_CODE = (
    struct.pack("<6I", *_F_VALUES)
    + b"\x90" * 8
    + struct.pack("<2I", *_G_VALUES)
    + b"\x90" * 8
    + struct.pack("<I", *_K_VALUES)
    + b"\x90" * 12
)
_REF_SITES = [0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x20, 0x24, 0x30]
# The build puts every function 0x10 later and already relocates g's second operand.
_SHIFT = 0x10
_BUILT_SITES = [_SHIFT + 0x24]

_SOURCE = """\
extern int g_other;

int f(void)
{
    return *(int *) 0x10003000 + *(int *) 0x10003008 + *(int *) 0x10004000
        + *(int *) 0x10003020 + *(int *) 0x10003010 + *(int *) 0x10003030;
}

int g(void)
{
    if (f() == *(int *) 0x10003000) {
        return 1;
    }
    return *(int *) 0x10003000 + (int) 0x10003000;
}

int k(void)
{
    return *(int *) 0x10003000;
}
"""

_MAP = """\
 0001:00000010       _f                         00401010 f   net.c.obj
 0001:00000030       _g                         00401030 f   net.c.obj
 0001:00000040       _k                         00401040 f   other.c.obj
 0003:00000000       _g_table                   10003000     net.c.obj
 0003:00000020       _g_real                    10003020     net.c.obj
 0003:00000010       _g_gap_10003010            10003010     bss.c.obj
"""

_FUNCTIONS = 'format = 2\n["SERVER.0x401000"]\nsymbol = "_f"\nsize = 32\nfile = "src/net.c"\nkind = "FUNCTION"\n\n["SERVER.0x401020"]\nsymbol = "_g"\nsize = 16\nfile = "src/net.c"\nkind = "FUNCTION"\n\n["SERVER.0x401030"]\nsymbol = "_k"\nsize = 16\nfile = "src/net.c"\nkind = "FUNCTION"\n'

_DATA = 'format = 2\n["SERVER.0x10003000"]\nname = "g_table"\nsize = 16\nsection = ".data"\n\n["SERVER.0x10003010"]\nname = "g_gap_10003010"\nsize = 4\nsection = ".bss"\nstorage_kind = "span"\n\n["SERVER.0x10003020"]\nname = "lbl_10003020"\nlink_symbol = "_g_real"\nsize = 4\nsection = ".data"\n\n["SERVER.0x10003030"]\nname = "g_unlinked"\nsize = 4\nsection = ".data"\n'


def _pe(path: Path, code: bytes, sites: list[int]) -> Path:
    binary = lief.PE.parse(_FIXTURE)
    assert binary is not None
    section = binary.get_section(".text")
    assert section is not None
    section.content = list(code)
    section.virtual_size = len(code)
    block = lief.PE.Relocation()
    block.virtual_address = 0x1000
    for site in sites:
        block.add_entry(lief.PE.RelocationEntry(site, _HIGHLOW))
    binary.add_relocation(block)
    binary.write(str(path))
    return path


def _project(tmp_path: Path, source: str = _SOURCE) -> SimpleNamespace:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "net.c").write_text(source, encoding="utf-8")
    write_store_fixture(tmp_path / "rebrew-functions.toml", _FUNCTIONS, encoding="utf-8")
    write_store_fixture(tmp_path / "rebrew-data.toml", _DATA, encoding="utf-8")
    (tmp_path / "build").mkdir()
    built = _pe(tmp_path / "build" / "server.dll", b"\x90" * _SHIFT + _CODE, _BUILT_SITES)
    (tmp_path / "build" / "server.map").write_text(_MAP, encoding="utf-8")
    return SimpleNamespace(
        root=tmp_path,
        metadata_dir=tmp_path,
        reversed_dir=tmp_path / "src",
        target_binary=_pe(tmp_path / "server.dll", _CODE, _REF_SITES),
        raw_link=built,
        marker="SERVER",
        target_name="SERVER",
        all_markers=["SERVER"],
    )


def _run(cfg: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, *args: str) -> tuple[int, str]:
    from rebrew.app.main import app as umbrella

    monkeypatch.setattr(symbolize, "require_config", lambda **kwargs: cfg)
    result = CliRunner().invoke(
        umbrella, ["source", "symbolize", str(cfg.root / "src" / "net.c"), *args]
    )
    return result.exit_code, result.output


def _source(cfg: SimpleNamespace) -> str:
    path: Path = cfg.root / "src" / "net.c"
    return path.read_text(encoding="utf-8")


class TestSymbolize:
    def test_rewrites_missing_sites_to_defined_rows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _project(tmp_path)
        code, output = _run(cfg, monkeypatch, "--json")
        assert code == 0, output
        report = json.loads(output)
        assert _source(cfg) == _SOURCE.replace(
            "*(int *) 0x10003000 + *(int *) 0x10003008",
            "*(int *) &g_table + *(int *) ((char *) &g_table + 0x8)",
        ).replace("*(int *) 0x10003020", "*(int *) &g_real").replace(
            "if (f() == *(int *) 0x10003000)", "if (f() == *(int *) &g_table)"
        ).replace(
            "return *(int *) 0x10003000 + (int) 0x10003000;",
            "return *(int *) &g_table + (int) 0x10003000;",
        )
        assert report["changed"] == 5
        assert {(r["function"], r["value"], r["count"]) for r in report["rewrites"]} == {
            ("f", "0x10003000", 1),
            ("f", "0x10003008", 1),
            ("f", "0x10003020", 1),
            ("g", "0x10003000", 2),
        }
        # No row, a padding span, and a row the link does not define.
        assert sorted(r["value"] for r in report["unresolved"]) == [
            "0x10003010",
            "0x10003030",
            "0x10004000",
        ]
        # k's row names this file but the map links k from another object.
        assert report["unlinked"] == ["_k"]
        assert "return *(int *) 0x10003000;\n}" in _source(cfg)

    def test_dry_run_leaves_the_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _project(tmp_path)
        code, output = _run(cfg, monkeypatch, "--dry-run")
        assert code == 0, output
        assert "would rewrite 5 operands" in output
        assert _source(cfg) == _SOURCE

    def test_rerun_changes_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _project(tmp_path)
        _run(cfg, monkeypatch)
        once = _source(cfg)
        code, output = _run(cfg, monkeypatch, "--json")
        assert code == 0, output
        assert json.loads(output)["changed"] == 0
        assert _source(cfg) == once

    def test_skip_matches_the_definition_not_a_call_site(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``g`` calls ``f`` in ``if (f() == ...) {``; skipping f must leave g rewritten."""
        cfg = _project(tmp_path)
        code, output = _run(cfg, monkeypatch, "--skip", "f", "--json")
        assert code == 0, output
        text = _source(cfg)
        assert "*(int *) 0x10003000 + *(int *) 0x10003008" in text
        assert "if (f() == *(int *) &g_table) {" in text
        assert "return *(int *) &g_table + (int) 0x10003000;" in text
        skipped = {r["function"] for r in json.loads(output)["rewrites"] if r["skipped"]}
        assert skipped == {"f"}

    def test_skip_after_earlier_rewrites_keeps_its_span(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Rewrites in f lengthen the text before g; skipping g still covers all of g."""
        cfg = _project(tmp_path)
        code, output = _run(cfg, monkeypatch, "--skip", "g")
        assert code == 0, output
        text = _source(cfg)
        assert "*(int *) &g_table + *(int *) ((char *) &g_table + 0x8)" in text
        g_body = text[text.index("int g(void)") : text.index("int k(void)")]
        assert g_body.count("0x10003000") == 3

    def test_unknown_skip_fails(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = _project(tmp_path)
        code, output = _run(cfg, monkeypatch, "--skip", "nope", "--json")
        assert code != 0
        assert "nope" in json.loads(output)["error"]
        assert _source(cfg) == _SOURCE


class TestDeclare:
    def test_appends_to_the_extern_line_without_new_lines(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _project(tmp_path)
        code, output = _run(
            cfg, monkeypatch, "--declare", "g_table", "--declare", "g_other", "--json"
        )
        assert code == 0, output
        text = _source(cfg)
        assert text.splitlines()[0] == "extern int g_other; extern char g_table[];"
        assert text.count("\n") == _SOURCE.count("\n")
        assert json.loads(output)["declared"] == ["g_table"]
        _run(cfg, monkeypatch, "--declare", "g_table")
        assert _source(cfg) == text

    def test_needs_an_extern_line(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        source = _SOURCE.replace("extern int g_other;\n", "")
        cfg = _project(tmp_path, source)
        code, output = _run(cfg, monkeypatch, "--declare", "g_table", "--json")
        assert code != 0
        assert "extern" in json.loads(output)["error"]
        assert _source(cfg) == source

    def test_rejects_a_non_identifier(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _project(tmp_path)
        code, output = _run(cfg, monkeypatch, "--declare", "a b", "--json")
        assert code != 0
        assert "a b" in json.loads(output)["error"]


def test_missing_raw_link_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _project(tmp_path)
    (tmp_path / "build" / "server.map").unlink()
    code, output = _run(cfg, monkeypatch, "--json")
    assert code != 0
    assert "link map" in json.loads(output)["error"]


def test_mounted_under_source() -> None:
    from rebrew.app.main import app as umbrella

    result = CliRunner().invoke(umbrella, ["source", "symbolize", "--help"])
    assert result.exit_code == 0, result.output
    assert "--declare" in result.output
