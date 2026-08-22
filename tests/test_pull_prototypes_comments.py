"""Tests for ghidra/commands.pull_prototypes and pull_comments with mocked MCP."""

from pathlib import Path
from types import SimpleNamespace

import pytest


def _cfg(tmp_path: Path) -> SimpleNamespace:
    src = tmp_path / "src" / "SERVER"
    src.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(
        reversed_dir=src,
        metadata_dir=tmp_path,
        marker="SERVER",
        root=tmp_path,
        source_ext=".c",
    )


class _FakeClient:
    def __init__(self, script: list | None = None) -> None:
        self._script = list(script or [])

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def post(self, *_a: object, **_k: object) -> object:
        return SimpleNamespace(status_code=200, text="", headers={}, json=lambda: {})


def _patch_base(
    monkeypatch: pytest.MonkeyPatch,
    *,
    pages: list | None = None,
    offline: bool = False,
) -> None:
    import rebrew.ghidra.commands as cmds

    monkeypatch.setattr(cmds.httpx, "Client", lambda **kw: _FakeClient())
    if offline:
        import httpx

        def _offline(*_a: object, **_k: object) -> object:
            raise httpx.RequestError("refused", request=None)

        monkeypatch.setattr(cmds, "init_mcp_session", _offline)
    else:
        monkeypatch.setattr(cmds, "init_mcp_session", lambda *a, **k: "sess")

    def _raw(*_a: object, **_k: object) -> object:
        if not pages:
            return []
        return pages.pop(0)

    monkeypatch.setattr(cmds, "fetch_mcp_tool_raw", _raw)


def _func_entry(va: int, filepath: str = "func.c", **extra: object) -> dict:
    entry: dict = {
        "va": va,
        "marker_type": "FUNCTION",
        "symbol": "_my_func",
        "name": "my_func",
        "module": "SERVER",
        "filepath": filepath,
        "prototype": "",
    }
    entry.update(extra)
    return entry


class TestPullPrototypes:
    def test_updates_prototype_annotation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        func_c = cfg.reversed_dir / "func.c"
        func_c.write_text(
            "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        page = [
            {"totalCount": 1, "nextStartIndex": 1},
            {"address": "0x1000", "signature": "int my_func(int a, int b)"},
        ]
        _patch_base(monkeypatch, pages=[page, []])
        cmds.pull_prototypes([_func_entry(0x1000)], cfg, "http://x", "/p", dry_run=False)
        updated = func_c.read_text(encoding="utf-8")
        assert "// PROTOTYPE: int my_func(int a, int b)" in updated

    def test_fallback_to_decompilation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        func_c = cfg.reversed_dir / "func.c"
        func_c.write_text(
            "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        # No "signature" key in the function entry → get-decompilation fallback.
        page = [{"address": "0x1000", "name": "my_func"}]
        # Second call returns the decompiled signature as a bare string.
        _patch_base(monkeypatch, pages=[page, "int my_func(int a)"])
        cmds.pull_prototypes([_func_entry(0x1000)], cfg, "http://x", "/p", dry_run=False)
        assert "// PROTOTYPE: int my_func(int a)" in func_c.read_text(encoding="utf-8")

    def test_replace_externs(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        func_c = cfg.reversed_dir / "func.c"
        func_c.write_text(
            "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        externs_c = cfg.reversed_dir / "externs.c"
        externs_c.write_text(
            "// FUNCTION: SERVER 0x2000\nextern int my_func(void);\n", encoding="utf-8"
        )
        page = [
            {"totalCount": 1, "nextStartIndex": 1},
            {"address": "0x1000", "signature": "int my_func(int a, int b)"},
        ]
        _patch_base(monkeypatch, pages=[page, []])
        cmds.pull_prototypes(
            [_func_entry(0x1000)], cfg, "http://x", "/p", dry_run=False, replace_externs=True
        )
        assert "extern int my_func(int a, int b);" in externs_c.read_text(encoding="utf-8")

    def test_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        func_c = cfg.reversed_dir / "func.c"
        func_c.write_text(
            "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        page = [
            {"totalCount": 1, "nextStartIndex": 1},
            {"address": "0x1000", "signature": "int my_func(int a)"},
        ]
        _patch_base(monkeypatch, pages=[page, []])
        cmds.pull_prototypes([_func_entry(0x1000)], cfg, "http://x", "/p", dry_run=True)
        assert "// PROTOTYPE:" not in func_c.read_text(encoding="utf-8")

    def test_non_function_entries_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        page = [
            {"totalCount": 1, "nextStartIndex": 1},
            {"address": "0x1000", "signature": "int g(int)"},
        ]
        _patch_base(monkeypatch, pages=[page, []])
        data_entry = {
            "va": 0x1000,
            "marker_type": "DATA",
            "symbol": "g",
            "name": "g",
            "module": "SERVER",
            "filepath": "globals.c",
        }
        cmds.pull_prototypes([data_entry], cfg, "http://x", "/p", dry_run=False)
        assert not (cfg.reversed_dir / "globals.c").exists()

    def test_connect_failure_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        _patch_base(monkeypatch, offline=True)
        with pytest.raises(RuntimeError, match="Error connecting to MCP"):
            cmds.pull_prototypes([], cfg, "http://x", "/p", dry_run=False)


class TestPullComments:
    def test_pulls_comments_into_analysis(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        func_c = cfg.reversed_dir / "func.c"
        func_c.write_text(
            "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        from rebrew.metadata import get_entry

        entries = [{"va": 0x1000, "size": 0x40, "marker_type": "FUNCTION", "filepath": "func.c"}]
        response = {"comments": [{"address": "0x1005", "comment": "sets up the frame"}]}
        _patch_base(monkeypatch, pages=[response])
        cmds.pull_comments(entries, cfg, "http://x", "/p", dry_run=False)
        entry = get_entry(cfg.metadata_dir, 0x1000, "SERVER")
        assert entry.get("analysis") == "sets up the frame"

    def test_rebrew_comments_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        func_c = cfg.reversed_dir / "func.c"
        func_c.write_text(
            "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [{"va": 0x1000, "size": 0x40, "marker_type": "FUNCTION", "filepath": "func.c"}]
        from rebrew.metadata import get_entry

        response = {"comments": [{"address": "0x1005", "comment": "[rebrew] generated"}]}
        _patch_base(monkeypatch, pages=[response])
        cmds.pull_comments(entries, cfg, "http://x", "/p", dry_run=False)
        assert get_entry(cfg.metadata_dir, 0x1000, "SERVER") == {}

    def test_comment_outside_entry_range_ignored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        func_c = cfg.reversed_dir / "func.c"
        func_c.write_text(
            "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        entries = [{"va": 0x1000, "size": 0x40, "marker_type": "FUNCTION", "filepath": "func.c"}]
        from rebrew.metadata import get_entry

        response = {"comments": [{"address": "0x2000", "comment": "unrelated"}]}
        _patch_base(monkeypatch, pages=[response])
        cmds.pull_comments(entries, cfg, "http://x", "/p", dry_run=False)
        assert get_entry(cfg.metadata_dir, 0x1000, "SERVER") == {}

    def test_empty_response_no_crash(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds
        from rebrew.metadata import get_entry

        cfg = _cfg(tmp_path)
        func_c = cfg.reversed_dir / "func.c"
        original = "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n"
        func_c.write_text(original, encoding="utf-8")
        entries = [{"va": 0x1000, "size": 0x40, "marker_type": "FUNCTION", "filepath": "func.c"}]
        _patch_base(monkeypatch, pages=[{}])
        cmds.pull_comments(entries, cfg, "http://x", "/p", dry_run=False)
        # An empty response must leave both sources and metadata untouched.
        assert func_c.read_text(encoding="utf-8") == original
        assert get_entry(cfg.metadata_dir, 0x1000, "SERVER") == {}

    def test_no_entries_with_va_early_return(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)

        def _fail_fetch(*_a: object, **_k: object) -> object:
            raise AssertionError("fetch_mcp_tool_raw must not be called without VAs")

        monkeypatch.setattr(cmds.httpx, "Client", lambda **kw: _FakeClient())
        monkeypatch.setattr(cmds, "init_mcp_session", lambda *a, **k: "sess")
        monkeypatch.setattr(cmds, "fetch_mcp_tool_raw", _fail_fetch)
        cmds.pull_comments([{"va": None}], cfg, "http://x", "/p", dry_run=False)

    def test_connect_failure_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        entries = [{"va": 0x1000, "size": 0x40, "marker_type": "FUNCTION", "filepath": "func.c"}]
        _patch_base(monkeypatch, offline=True)
        with pytest.raises(RuntimeError, match="Error connecting to MCP"):
            cmds.pull_comments(entries, cfg, "http://x", "/p", dry_run=False)


class TestPullPrototypesDictFallback:
    def test_decompilation_dict_signature(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        func_c = cfg.reversed_dir / "func.c"
        func_c.write_text(
            "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        page = [{"address": "0x1000", "name": "my_func"}]
        # Fallback returns {"signature": "..."} dict.
        _patch_base(monkeypatch, pages=[page, {"signature": "int my_func(int a)"}])
        cmds.pull_prototypes([_func_entry(0x1000)], cfg, "http://x", "/p", dry_run=False)
        assert "// PROTOTYPE: int my_func(int a)" in func_c.read_text(encoding="utf-8")

    def test_decompilation_dict_decompilation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        func_c = cfg.reversed_dir / "func.c"
        func_c.write_text(
            "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        page = [{"address": "0x1000", "name": "my_func"}]
        _patch_base(monkeypatch, pages=[page, {"decompilation": "int my_func(int a)"}])
        cmds.pull_prototypes([_func_entry(0x1000)], cfg, "http://x", "/p", dry_run=False)
        assert "// PROTOTYPE: int my_func(int a)" in func_c.read_text(encoding="utf-8")

    def test_pagination_two_pages(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.ghidra.commands as cmds

        cfg = _cfg(tmp_path)
        func_c = cfg.reversed_dir / "func.c"
        func_c.write_text(
            "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        page1 = [
            {"totalCount": 2, "nextStartIndex": 1},
            {"address": "0x1000", "signature": "int my_func(int a)"},
        ]
        page2 = [
            {"totalCount": 2, "nextStartIndex": 2},
            {"address": "0x2000", "signature": "int other(void)"},
        ]
        _patch_base(monkeypatch, pages=[page1, page2, []])
        cmds.pull_prototypes([_func_entry(0x1000)], cfg, "http://x", "/p", dry_run=False)
        assert "// PROTOTYPE: int my_func(int a)" in func_c.read_text(encoding="utf-8")
