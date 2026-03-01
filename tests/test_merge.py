"""Tests for the rebrew merge command."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from typer.testing import CliRunner

from rebrew.merge import app

runner = CliRunner()


def _make_cfg(tmp_path: Path, marker: str = "SERVER") -> Any:
    return SimpleNamespace(marker=marker, source_ext=".c", reversed_dir=tmp_path)


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _single(
    va: int,
    symbol: str,
    *,
    preamble: str = "",
    status: str = "EXACT",
    origin: str = "GAME",
    size: int = 10,
    cflags: str = "/O2",
    extra: str = "",
    module: str = "SERVER",
) -> str:
    name = symbol.lstrip("_")
    return (
        f"{preamble}"
        f"// FUNCTION: {module} 0x{va:08x}\n"
        f"// STATUS: {status}\n"
        f"// ORIGIN: {origin}\n"
        f"// SIZE: {size}\n"
        f"// CFLAGS: {cflags}\n"
        f"// SYMBOL: {symbol}\n"
        f"{extra}"
        "\n"
        f"int {name}(void) {{ return {va & 1}; }}\n"
    )


class TestMergeBasic:
    def test_merges_two_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_func_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_func_b"))
        out = tmp_path / "merged.c"
        monkeypatch.setattr("rebrew.merge.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, ["--output", str(out), str(a), str(b)])
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert "_func_a" in text
        assert "_func_b" in text

    def test_deduplicates_include_lines(self, tmp_path: Path, monkeypatch: Any) -> None:
        include = "#include <stdio.h>\n"
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a", preamble=include))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b", preamble=include))
        out = tmp_path / "merged.c"
        monkeypatch.setattr("rebrew.merge.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, ["--output", str(out), str(a), str(b)])
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert text.count("#include <stdio.h>") == 1

    def test_deduplicates_extern_declarations(self, tmp_path: Path, monkeypatch: Any) -> None:
        ext = "extern int g_value;\n"
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a", preamble=ext))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b", preamble=ext))
        out = tmp_path / "merged.c"
        monkeypatch.setattr("rebrew.merge.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, ["--output", str(out), str(a), str(b)])
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert text.count("extern int g_value;") == 1

    def test_sorts_function_blocks_by_va(self, tmp_path: Path, monkeypatch: Any) -> None:
        high = _write(tmp_path / "high.c", _single(0x10003000, "_high"))
        low = _write(tmp_path / "low.c", _single(0x10001000, "_low"))
        out = tmp_path / "merged.c"
        monkeypatch.setattr("rebrew.merge.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, ["--output", str(out), str(high), str(low)])
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert text.find("0x10001000") < text.find("0x10003000")

    def test_dry_run_does_not_create_output(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b"))
        out = tmp_path / "merged.c"
        monkeypatch.setattr("rebrew.merge.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, ["--output", str(out), "--dry-run", str(a), str(b)])
        assert result.exit_code == 0
        assert not out.exists()

    def test_errors_with_fewer_than_two_files(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))
        out = tmp_path / "merged.c"
        monkeypatch.setattr("rebrew.merge.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, ["--output", str(out), str(a)])
        assert result.exit_code != 0
        assert "at least two source files" in result.output

    def test_errors_when_output_exists_without_force(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b"))
        out = _write(tmp_path / "merged.c", "stale\n")
        monkeypatch.setattr("rebrew.merge.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, ["--output", str(out), str(a), str(b)])
        assert result.exit_code != 0
        assert "Output file already exists" in result.output

    def test_delete_removes_inputs_after_success(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b"))
        out = tmp_path / "merged.c"
        monkeypatch.setattr("rebrew.merge.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, ["--output", str(out), "--delete", str(a), str(b)])
        assert result.exit_code == 0
        assert out.exists()
        assert not a.exists()
        assert not b.exists()

    def test_json_output_structure(self, tmp_path: Path, monkeypatch: Any) -> None:
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b"))
        out = tmp_path / "merged.c"
        payloads: list[dict[str, Any]] = []
        monkeypatch.setattr("rebrew.merge.get_config", lambda target=None: _make_cfg(tmp_path))
        monkeypatch.setattr("rebrew.merge.json_print", lambda data: payloads.append(data))

        result = runner.invoke(app, ["--output", str(out), "--json", str(a), str(b)])
        assert result.exit_code == 0
        assert len(payloads) == 1
        payload = payloads[0]
        assert payload["count"] == 2
        assert payload["input_count"] == 2
        assert "inputs" in payload
        assert "vas" in payload

    def test_preserves_all_annotation_keys(self, tmp_path: Path, monkeypatch: Any) -> None:
        extra = (
            "// BLOCKER: manual\n"
            "// BLOCKER_DELTA: 5\n"
            "// SOURCE: CRT.C:10\n"
            "// NOTE: note text\n"
            "// GHIDRA: yes\n"
            "// STRUCT: Foo\n"
            "// CALLERS: _caller\n"
            "// GLOBALS: g1, g2\n"
        )
        a = _write(tmp_path / "a.c", _single(0x10001000, "_a", extra=extra, status="MATCHING"))
        b = _write(tmp_path / "b.c", _single(0x10002000, "_b", status="EXACT"))
        out = tmp_path / "merged.c"
        monkeypatch.setattr("rebrew.merge.get_config", lambda target=None: _make_cfg(tmp_path))

        result = runner.invoke(app, ["--output", str(out), str(a), str(b)])
        assert result.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert "// STATUS: MATCHING" in text
        assert "// ORIGIN: GAME" in text
        assert "// SIZE: 10" in text
        assert "// CFLAGS: /O2" in text
        assert "// SYMBOL: _a" in text
        assert "// BLOCKER: manual" in text
        assert "// BLOCKER_DELTA: 5" in text
        assert "// SOURCE: CRT.C:10" in text
        assert "// NOTE: note text" in text
        assert "// GHIDRA: yes" in text
        assert "// STRUCT: Foo" in text
        assert "// CALLERS: _caller" in text
        assert "// GLOBALS: g1, g2" in text
