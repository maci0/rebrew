"""Tests for rebrew skeleton.py — decomp renderers, fetch_xref_context, CLI modes."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.skeleton import (
    _render_annotation_block,
    fetch_xref_context,
    generate_annotation_block,
    generate_skeleton,
    list_uncovered,
)


def _cfg(tmp_path: Path, **overrides: object) -> SimpleNamespace:
    src = tmp_path / "src" / "SERVER"
    src.mkdir(parents=True, exist_ok=True)
    defaults: dict = {
        "root": tmp_path,
        "target_name": "SERVER",
        "target_binary": tmp_path / "fake.dll",
        "reversed_dir": src,
        "metadata_dir": tmp_path,
        "marker": "SERVER",
        "source_ext": ".c",
        "library_modules": set(),
        "ignored_symbols": [],
        "base_cflags": "/O2",
        "dll_exports": {},
        "iat_thunks": set(),
        "function_list": "",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestRenderersWithDecomp:
    def test_skeleton_with_decomp(self) -> None:
        # _render_skeleton was consolidated into _render_annotation_block; the
        # origin_comment branch (always empty) is gone, todo_text is the hook.
        out = _render_annotation_block(
            marker="FUNCTION",
            cfg_marker="SERVER",
            va=0x1000,
            xref_context="/* === Cross-references ===",
            decomp_code="undefined4 func(void) { return 0; }",
            decomp_backend="r2ghidra",
            func_name="my_func",
            ghidra_name="my_func",
            todo_text="Implement based on Ghidra decompilation",
        )
        assert "/* === Decompilation (r2ghidra) === */" in out
        assert "undefined4 func(void) { return 0; }" in out
        assert "/* === End decompilation === */" in out

    def test_fenced_naked_stub_two_branches(self) -> None:
        """A thiscall skeleton (MSVC 5.0 has no __thiscall) must emit the
        REBREW_ALLOW_NAKED fence: naked + inline-asm branch for round-trip
        verification, an idiomatic C fallback for the comparison build."""
        fenced = (
            "#ifdef REBREW_ALLOW_NAKED\n"
            "__declspec(naked) int f(void *self, int a1)\n"
            "#else\n"
            "int f(void *self, int a1)\n"
            "#endif"
        )
        out = _render_annotation_block(
            marker="FUNCTION",
            cfg_marker="SERVER",
            va=0x1000,
            xref_context="",
            decomp_code=None,
            decomp_backend="decompiler",
            func_name="f",
            ghidra_name="f",
            convention_stub=fenced,
            convention_note="thiscall + 1 stack arg(s) — write the body as inline asm",
        )
        assert "#ifdef REBREW_ALLOW_NAKED" in out
        assert "__declspec(naked) int f(void *self, int a1)" in out
        assert "#else" in out
        assert "idiomatic C89 fallback" in out
        assert "return 0;" in out
        assert "#endif" in out

    def test_annotation_block_with_decomp(self) -> None:
        out = _render_annotation_block(
            marker="FUNCTION",
            cfg_marker="SERVER",
            va=0x1000,
            xref_context="/* ctx */",
            decomp_code="void f(void) {}",
            decomp_backend="ghidra",
            func_name="f",
            ghidra_name="f",
        )
        assert "/* === Decompilation (ghidra) === */" in out
        assert "void f(void) {}" in out
        assert "/* === End decompilation === */" in out

    def test_generate_skeleton_with_decomp(self) -> None:
        cfg = _cfg(Path("/tmp"))
        out = generate_skeleton(
            cfg,
            0x1000,
            "my_func",
            decomp_code="int my_func(void){return 1;}",
            decomp_backend="r2dec",
            xref_context="/* ctx */",
        )
        assert "my_func" in out
        assert "Decompilation (r2dec)" in out

    def test_generate_annotation_block_custom_name(self) -> None:
        cfg = _cfg(Path("/tmp"))
        out = generate_annotation_block(cfg, 0x1000, "ghidra_name", custom_name="renamed")
        assert "int __cdecl renamed(void)" in out


class TestFetchXrefContext:
    def _patch_fetch(self, monkeypatch: pytest.MonkeyPatch, responses: list) -> None:
        import rebrew.ghidra.client as client

        class _FakeClient:
            def __init__(self, timeout: float = 30.0) -> None:
                pass

            def __enter__(self) -> "_FakeClient":
                return self

            def __exit__(self, *a: object) -> None:
                return None

        monkeypatch.setattr(client.httpx, "Client", _FakeClient)
        monkeypatch.setattr(client, "init_mcp_session", lambda *a, **k: "sess")
        monkeypatch.setattr(client, "fetch_mcp_tool_raw", lambda *a, **k: responses.pop(0))

    def test_non_dict_xrefs_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_fetch(monkeypatch, ["not a dict"])
        assert fetch_xref_context("http://x", "/p", 0x1000) is None

    def test_empty_references_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_fetch(monkeypatch, [{"referencesTo": []}])
        assert fetch_xref_context("http://x", "/p", 0x1000) is None

    def test_no_callers_or_data_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_fetch(monkeypatch, [{"referencesTo": [{"isCall": False, "isData": False}]}])
        assert fetch_xref_context("http://x", "/p", 0x1000) is None

    def test_full_success_with_decomp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        xrefs = {
            "referencesTo": [
                {
                    "fromAddress": "0x2000",
                    "fromFunction": {"name": "caller_a", "context": "  int x = f();"},
                    "isCall": True,
                },
                {
                    "fromAddress": "0x2000",
                    "fromFunction": {"name": "caller_a"},
                    "isCall": True,
                },  # duplicate → skipped
                {
                    "fromAddress": "0x3000",
                    "fromSymbol": {"name": "sym_caller"},  # symbol fallback
                    "isCall": True,
                },
                {
                    "fromAddress": "0x4000",
                    "isData": True,
                    "referenceType": "PTR",
                    "fromFunction": {"name": "data_ref"},
                },
            ]
        }
        self._patch_fetch(
            monkeypatch,
            [
                xrefs,
                {"decompilation": "int caller_a(void) { return f(); }"},
                "int sym_caller(void){}",
            ],
        )
        out = fetch_xref_context("http://x", "/p", 0x1000, max_callers=2)
        assert out is not None
        assert "Cross-references (2 callers)" in out
        assert "caller_a (0x2000)" in out
        assert "sym_caller (0x3000)" in out
        assert "Data references: 1" in out
        assert "=== Caller: caller_a (0x2000) - decompilation ===" in out

    def test_http_error_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        import rebrew.ghidra.client as client

        class _FakeClient:
            def __init__(self, timeout: float = 30.0) -> None:
                pass

            def __enter__(self) -> "_FakeClient":
                return self

            def __exit__(self, *a: object) -> None:
                return None

        monkeypatch.setattr(client.httpx, "Client", _FakeClient)
        monkeypatch.setattr(
            client,
            "init_mcp_session",
            lambda *a, **k: (_ for _ in ()).throw(httpx.RequestError("down", request=None)),
        )
        assert fetch_xref_context("http://x", "/p", 0x1000) is None


class TestListUncoveredExtras:
    def test_ignored_symbol_skipped(self) -> None:
        from rebrew.catalog import FunctionEntry

        cfg = _cfg(Path("/tmp"), ignored_symbols=["_chkstk"])
        funcs = [
            FunctionEntry(va=0x1000, size=50, name="wanted"),
            FunctionEntry(va=0x2000, size=50, name="_chkstk"),
        ]
        uncovered = list_uncovered(funcs, {}, cfg)  # type: ignore[arg-type]
        assert [u[2] for u in uncovered] == ["wanted"]

    def test_size_bounds(self) -> None:
        from rebrew.catalog import FunctionEntry

        cfg = _cfg(Path("/tmp"))
        funcs = [
            FunctionEntry(va=0x1000, size=5, name="small"),
            FunctionEntry(va=0x2000, size=5000, name="huge"),
            FunctionEntry(va=0x3000, size=100, name="ok"),
        ]
        uncovered = list_uncovered(funcs, {}, cfg, min_size=10, max_size=999)  # type: ignore[arg-type]
        assert [u[2] for u in uncovered] == ["ok"]


class TestSkeletonCli:
    def _setup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
        cfg = _cfg(tmp_path)
        monkeypatch.setattr("rebrew.skeleton.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.skeleton.load_function_structure", lambda p: [])
        monkeypatch.setattr("rebrew.skeleton.load_existing_vas", lambda d, cfg=None: {})
        monkeypatch.setattr("rebrew.skeleton._fetch_extras", lambda *a, **k: (None, None, None))
        return cfg

    def test_batch_mode_writes_files(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.catalog import FunctionEntry
        from rebrew.skeleton import app

        cfg = self._setup(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.skeleton.load_function_structure",
            lambda p: [FunctionEntry(va=0x1000, size=64, name="func_a")],
        )
        result = CliRunner().invoke(app, ["--batch", "1", "--json"])
        assert result.exit_code == 0
        assert (cfg.reversed_dir / "func_a.c").exists()
        data = json.loads(result.stdout)
        assert data["count"] == 1

    def test_single_va_mode(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.skeleton import app

        self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, ["0x1000", "--name", "my_func", "--json"])
        assert result.exit_code != 0  # VA not in catalog → error path


class TestSkeletonCliModes:
    def _setup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
        cfg = _cfg(tmp_path)
        monkeypatch.setattr("rebrew.skeleton.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.skeleton.load_function_structure",
            lambda p: [
                __import__("rebrew.catalog", fromlist=["FunctionEntry"]).FunctionEntry(
                    va=0x1000, size=64, name="func_a"
                )
            ],
        )
        monkeypatch.setattr("rebrew.skeleton.load_existing_vas", lambda d, cfg=None: {})
        monkeypatch.setattr("rebrew.skeleton._fetch_extras", lambda *a, **k: (None, None, None))
        return cfg

    def test_single_va_creates_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from rebrew.skeleton import app

        cfg = self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, ["--json", "0x1000"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["action"] == "created"
        assert "func_a.c" in data["file"]
        assert (cfg.reversed_dir / "func_a.c").exists()

    def test_va_not_found_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.skeleton import app

        self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, ["--json", "0x9999"])
        assert result.exit_code != 0
        assert "not found in function_structure.json" in result.output

    def test_append_mode(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from rebrew.skeleton import app

        cfg = self._setup(tmp_path, monkeypatch)
        target = cfg.reversed_dir / "multi.c"
        target.write_text(
            "// FUNCTION: SERVER 0x2000\nint other(void) { return 0; }\n", encoding="utf-8"
        )
        result = CliRunner().invoke(app, ["--append", "multi.c", "--json", "0x1000"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["action"] == "appended"
        text = target.read_text(encoding="utf-8")
        assert "0x00001000" in text  # new block appended (8-digit VA format)

    def test_append_missing_target_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.skeleton import app

        self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, ["--append", "nope.c", "--json", "0x1000"])
        assert result.exit_code != 0
        assert "does not exist" in result.output

    def test_append_legacy_encoding_preserved(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Appending to a cp1252-encoded .c must not crash and must keep the
        file's encoding (regression: strict UTF-8 read + UTF-8 write)."""
        from rebrew.skeleton import app
        from rebrew.utils import read_source_text

        cfg = self._setup(tmp_path, monkeypatch)
        target = cfg.reversed_dir / "multi.c"
        original = (
            b"// FUNCTION: SERVER 0x2000\n// Caf\xe9 comment\nint other(void) { return 0; }\n"
        )
        target.write_bytes(original)
        result = CliRunner().invoke(app, ["--append", "multi.c", "--json", "0x1000"])
        assert result.exit_code == 0, result.output
        text, encoding = read_source_text(target)
        assert encoding == "cp1252"  # encoding survived the append
        assert "\u00e9" in text  # the legacy byte round-tripped
        assert "0x00001000" in text  # new block appended

    def test_append_existing_va_skips(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.skeleton import app

        cfg = self._setup(tmp_path, monkeypatch)
        target = cfg.reversed_dir / "multi.c"
        target.write_text(
            "// FUNCTION: SERVER 0x1000\nint func_a(void) { return 0; }\n", encoding="utf-8"
        )
        result = CliRunner().invoke(app, ["--append", "multi.c", "0x1000"])
        # Refusal is an ERROR (non-zero), not success — the old exit 0 told
        # automation "appended" when nothing was written.  Exit 1 (mismatch:
        # needs --force) per the tool's refusal semantics.
        assert result.exit_code != 0
        assert "already in" in result.output
        assert target.read_text(encoding="utf-8").count("0x1000") == 1

    def test_batch_existing_skips(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.skeleton import app

        cfg = self._setup(tmp_path, monkeypatch)
        (cfg.reversed_dir / "func_a.c").write_text("existing", encoding="utf-8")
        result = CliRunner().invoke(app, ["--batch", "1", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["count"] == 0  # skipped because the file exists
        assert (cfg.reversed_dir / "func_a.c").read_text(encoding="utf-8") == "existing"

    def test_batch_none_uncovered(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.skeleton import app

        self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, ["--batch", "1", "--min-size", "100"])
        assert result.exit_code == 0
        assert "No uncovered functions" in result.output

    def test_batch_none_uncovered_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Batch with nothing to do still emits machine-readable JSON."""
        import json

        from rebrew.skeleton import app

        self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, ["--batch", "1", "--min-size", "100", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["action"] == "none"
        assert data["count"] == 0
        assert data["created"] == []

    def test_single_already_covered_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A covered VA reports JSON instead of empty stdout."""
        import json

        from rebrew.skeleton import app

        cfg = self._setup(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.skeleton.load_existing_vas", lambda d, cfg=None: {0x1000: "func_a.c"}
        )
        result = CliRunner().invoke(app, ["--json", "0x1000"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["action"] == "none"
        assert data["covered_by"] == "func_a.c"
        assert not (cfg.reversed_dir / "func_a.c").exists()
