"""Tests for rename.py — cross-reference rename with dry-run and file renaming."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cli_json import cli_payload
from source_util import SourceFixture, write_source, write_store_fixture

from rebrew import rename_ops
from rebrew.rename_ops import rename_function_everywhere


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(reversed_dir=tmp_path, metadata_dir=tmp_path)


def _src(tmp_path: Path, name: str, content: str) -> Path:
    f = tmp_path / name
    write_source(f, content, encoding="utf-8")
    return f


def _patch_sources(monkeypatch: pytest.MonkeyPatch, files: list[Path]) -> None:
    monkeypatch.setattr("rebrew.rename_ops.iter_sources_and_headers", lambda _d, _c: files)


class TestRenameFunctionEverywhere:
    def test_decorated_symbol_renames_when_the_name_is_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A vectorcall or fastcall symbol still names the C function.

        The name was taken from the symbol only when it started with ``_``,
        so ``hook@@12`` and ``@keeps@4`` were an empty name and the rename
        refused.
        """
        hook = _src(
            tmp_path,
            "hook.c",
            "void __vectorcall hook(int a) { return; }\n",
        )
        _patch_sources(monkeypatch, [hook])
        count = rename_function_everywhere(
            _cfg(tmp_path), hook, "", "hook@@12", "new_hook", rename_file=False
        )
        assert count == 1
        assert hook.read_text(encoding="utf-8") == (
            "void __vectorcall new_hook(int a) { return; }\n"
        )

        keeps = _src(
            tmp_path,
            "keeps.c",
            "void __fastcall keeps(int a) { return; }\n",
        )
        _patch_sources(monkeypatch, [keeps])
        count = rename_function_everywhere(
            _cfg(tmp_path), keeps, "", "@keeps@4", "new_keeps", rename_file=False
        )
        assert count == 1
        assert keeps.read_text(encoding="utf-8") == (
            "void __fastcall new_keeps(int a) { return; }\n"
        )

    def test_dry_run_counts_without_writing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(tmp_path, "func_a.c", "int func_a(void) { return 1; }\n")
        b = _src(tmp_path, "other.c", "extern int func_a(void);\n")
        _patch_sources(monkeypatch, [a, b])
        count = rename_function_everywhere(
            _cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn", dry_run=True
        )
        assert count == 2  # both files reference func_a
        # Nothing written.
        assert "func_a" in a.read_text()
        assert "func_a" in b.read_text()

    def test_renames_primary_and_cross_refs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(tmp_path, "func_a.c", "int func_a(void) { return func_a(); }\n")
        b = _src(tmp_path, "other.c", "extern int func_a(void);\n")
        _patch_sources(monkeypatch, [a, b])
        count = rename_function_everywhere(_cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn")
        assert count == 2
        renamed = tmp_path / "renamed_fn.c"  # file auto-renamed to match
        assert "renamed_fn" in renamed.read_text()
        assert "func_a" not in renamed.read_text()
        assert "renamed_fn" in b.read_text()

    def test_underscore_symbol_stripped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(tmp_path, "func_a.c", "int func_a(void) { return 1; }\n")
        _patch_sources(monkeypatch, [a])
        # old_sym "_func_a" → matches "func_a" via underscore stripping.
        count = rename_function_everywhere(_cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn")
        assert count == 1
        renamed = tmp_path / "renamed_fn.c"
        assert "renamed_fn" in renamed.read_text()

    def test_file_renamed_when_stem_matches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(tmp_path, "func_a.c", "int func_a(void) { return 1; }\n")
        _patch_sources(monkeypatch, [a])
        rename_function_everywhere(_cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn")
        assert (tmp_path / "renamed_fn.c").exists()
        assert not a.exists()

    def test_new_filename_suffix_added(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(tmp_path, "func_a.c", "int func_a(void) { return 1; }\n")
        _patch_sources(monkeypatch, [a])
        rename_function_everywhere(
            _cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn", new_filename="custom"
        )
        # The explicit stem names the file, and the body is rewritten inside it.
        assert (tmp_path / "custom.c").read_text() == "int renamed_fn(void) { return 1; }\n"
        assert not (tmp_path / "func_a.c").exists()

    def test_target_exists_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        a = _src(tmp_path, "func_a.c", "int func_a(void) { return 1; }\n")
        _src(tmp_path, "renamed_fn.c", "int renamed_fn(void) { return 2; }\n")
        _patch_sources(monkeypatch, [a])
        with pytest.raises(FileExistsError, match="already exists"):
            rename_function_everywhere(_cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn")

    def test_dry_run_target_exists_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(tmp_path, "func_a.c", "int func_a(void) { return 1; }\n")
        _src(tmp_path, "renamed_fn.c", "int renamed_fn(void) { return 2; }\n")
        _patch_sources(monkeypatch, [a])
        with pytest.raises(FileExistsError, match="already exists"):
            rename_function_everywhere(
                _cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn", dry_run=True
            )
        assert "func_a" in a.read_text()

    def test_multi_function_file_not_auto_renamed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(
            tmp_path,
            "func_a.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\nint func_a(void) { return 1; }\n/* ADDRESS: SERVER 0x10002000 */\nint func_b(void) { return 2; }\n",
                {
                    "SERVER.0x10001000": {"kind": "FUNCTION"},
                    "SERVER.0x10002000": {"kind": "FUNCTION"},
                },
            ),
        )
        _patch_sources(monkeypatch, [a])
        rename_function_everywhere(_cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn")
        # File not renamed (multi-function), content still updated.
        assert a.exists()
        assert "renamed_fn" in a.read_text()


class TestRenameTargetIsolation:
    def test_migrated_shared_identity_and_file_follow_the_rename(self, tmp_path: Path) -> None:
        from rebrew.metadata.bindings import read_source_bindings
        from rebrew.metadata.functions import get_entry, save_metadata

        src = tmp_path / "src"
        src.mkdir()
        primary = _src(src, "old_fn.c", "int old_fn(void) { return 1; }\n")
        server = _src(src, "server.c", "int old_fn(void) { return 2; }\n")
        _src(
            src,
            "caller.c",
            SourceFixture(
                "/* ADDRESS: TL 0x403000 */\nint call(void) { return old_fn(); }\n",
                {"TL.0x403000": {"kind": "FUNCTION"}},
            ),
        )
        save_metadata(
            tmp_path,
            {
                (module, va): {
                    "file": filename,
                    "name": "old_fn",
                    "symbol": "_old_fn",
                    "kind": "FUNCTION",
                    "size": 6,
                    "status": "EXACT",
                }
                for module, va, filename in [
                    ("TL", 0x401000, "src/old_fn.c"),
                    ("GOLD", 0x402000, "src/old_fn.c"),
                    ("SERVER", 0x10001000, "src/server.c"),
                ]
            },
        )
        original_server = get_entry(tmp_path, 0x10001000, "SERVER")
        cfg = SimpleNamespace(root=tmp_path, reversed_dir=src, metadata_dir=tmp_path)
        count = rename_function_everywhere(
            cfg, primary, "old_fn", "_old_fn", "new_fn", new_filename="new_fn.c"
        )
        assert count == 2
        assert not primary.exists()
        renamed = src / "new_fn.c"
        assert "new_fn" in renamed.read_text()
        assert "old_fn" in server.read_text()
        assert get_entry(tmp_path, 0x10001000, "SERVER") == original_server
        parsed = read_source_bindings(renamed, metadata_dir=tmp_path)
        assert {(e.module, e.name, e.symbol) for e in parsed} == {
            ("TL", "new_fn", "_new_fn"),
            ("GOLD", "new_fn", "_new_fn"),
        }
        for module, va in [("TL", 0x401000), ("GOLD", 0x402000)]:
            assert get_entry(tmp_path, va, module)["file"] == "src/new_fn.c"
            assert get_entry(tmp_path, va, module)["status"] == "EXACT"

    def test_globals_follow_the_renamed_file(self, tmp_path: Path) -> None:
        import tomllib

        from rebrew.metadata.functions import save_metadata

        src = tmp_path / "src"
        src.mkdir()
        primary = _src(src, "old_fn.c", "int g_hits;\nint old_fn(void) { return g_hits; }\n")
        save_metadata(
            tmp_path,
            {
                ("TL", 0x401000): {
                    "file": "src/old_fn.c",
                    "name": "old_fn",
                    "symbol": "_old_fn",
                    "kind": "FUNCTION",
                }
            },
        )
        data_toml = 'format = 2\n["TL.0x500000"]\nname = "g_hits"\nfile = "src/old_fn.c"\n\n["TL.0x500004"]\nname = "g_else"\nfile = "src/else.c"\n'
        write_source(tmp_path / "rebrew-data.toml", data_toml, encoding="utf-8")
        cfg = SimpleNamespace(root=tmp_path, reversed_dir=src, metadata_dir=tmp_path)
        rename_function_everywhere(
            cfg, primary, "old_fn", "_old_fn", "new_fn", new_filename="new_fn.c", dry_run=True
        )
        assert (tmp_path / "rebrew-data.toml").read_text(encoding="utf-8") == data_toml
        rename_function_everywhere(
            cfg, primary, "old_fn", "_old_fn", "new_fn", new_filename="new_fn.c"
        )
        data = tomllib.loads((tmp_path / "rebrew-data.toml").read_text(encoding="utf-8"))
        assert data["TL.0x500000"]["file"] == "src/new_fn.c"
        assert data["TL.0x500000"]["updated_by"] == "rename"
        assert data["TL.0x500004"]["file"] == "src/else.c"

    @pytest.mark.parametrize("dry_run", [False, True])
    def test_shared_owner_does_not_rename_independent_server_symbol(
        self, tmp_path: Path, dry_run: bool
    ) -> None:
        primary = _src(
            tmp_path,
            "client.c",
            SourceFixture(
                "/* ADDRESS: TL 0x401000 */\n/* ADDRESS: GOLD 0x402000 */\nint old_fn(void) { return 1; }\n",
                {"TL.0x401000": {"kind": "FUNCTION"}, "GOLD.0x402000": {"kind": "FUNCTION"}},
            ),
        )
        server = _src(
            tmp_path,
            "server.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\nint old_fn(void) { return 2; }\n",
                {"SERVER.0x10001000": {"kind": "FUNCTION"}},
            ),
        )
        server_caller = _src(
            tmp_path,
            "server_caller.c",
            SourceFixture(
                "extern int old_fn(void);\n/* ADDRESS: SERVER 0x10002000 */\nint server_call(void) { return old_fn(); }\n",
                {"SERVER.0x10002000": {"kind": "FUNCTION"}},
            ),
        )
        callers = [
            _src(
                tmp_path,
                f"{module}.c",
                SourceFixture(
                    f"extern int old_fn(void);\n/* ADDRESS: {module} 0x403000 */\nint {module}_call(void) {{ return old_fn(); }}\n",
                    {f"{module}.0x403000": {"kind": "FUNCTION"}},
                ),
            )
            for module in ["TL", "GOLD"]
        ]
        original = {p: p.read_bytes() for p in tmp_path.glob("*.c")}
        count = rename_function_everywhere(
            _cfg(tmp_path), primary, "old_fn", "_old_fn", "new_fn", dry_run=dry_run
        )
        assert count == 3
        assert server.read_bytes() == original[server]
        assert server_caller.read_bytes() == original[server_caller]
        for p in [primary, *callers]:
            if dry_run:
                assert p.read_bytes() == original[p]
            else:
                assert "new_fn" in p.read_text()
                assert "old_fn" not in p.read_text()

    @pytest.mark.parametrize("dry_run", [False, True])
    @pytest.mark.parametrize("mixed", [False, True])
    def test_ambiguous_common_reference_fails_before_writing(
        self, tmp_path: Path, dry_run: bool, mixed: bool
    ) -> None:
        primary = _src(
            tmp_path,
            "client.c",
            SourceFixture(
                "/* ADDRESS: TL 0x401000 */\nint old_fn(void) { return 1; }\n",
                {"TL.0x401000": {"kind": "FUNCTION"}},
            ),
        )
        _src(
            tmp_path,
            "server.c",
            SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\nint old_fn(void) { return 2; }\n",
                {"SERVER.0x10001000": {"kind": "FUNCTION"}},
            ),
        )
        text = "extern int old_fn(void);\n"
        if mixed:
            text += SourceFixture(
                "/* ADDRESS: TL 0x402000 */\nint tl_call(void) { return old_fn(); }\n/* ADDRESS: SERVER 0x10002000 */\nint srv_call(void) { return old_fn(); }\n",
                {"TL.0x402000": {"kind": "FUNCTION"}, "SERVER.0x10002000": {"kind": "FUNCTION"}},
            )
        ambiguous = _src(tmp_path, "common.c" if mixed else "common.h", text)
        original = {p: p.read_bytes() for p in tmp_path.iterdir()}
        with pytest.raises(rename_ops.RenameError, match="ambiguous") as excinfo:
            rename_function_everywhere(
                _cfg(tmp_path), primary, "old_fn", "_old_fn", "new_fn", dry_run=dry_run
            )
        assert ambiguous in excinfo.value.files
        assert {p: p.read_bytes() for p in tmp_path.iterdir()} == original

    def test_empty_vectorcall_name_does_not_rename_another_target(self, tmp_path: Path) -> None:
        """``hook@@12`` with an empty name owns only its module.

        Stripping one ``@N`` left ``hook@``, so the owner set was empty and
        the rename also rewrote the other target's cdecl ``hook``.
        """
        from rebrew.metadata.functions import save_metadata

        primary = _src(tmp_path, "hook.c", "void __vectorcall hook(int a) { return; }\n")
        other = _src(tmp_path, "other.c", "int hook(void) { return 2; }\n")
        save_metadata(
            tmp_path,
            {
                ("TL", 0x401000): {
                    "file": "hook.c",
                    "name": "",
                    "symbol": "hook@@12",
                    "kind": "FUNCTION",
                },
                ("SERVER", 0x10001000): {
                    "file": "other.c",
                    "name": "hook",
                    "symbol": "_hook",
                    "kind": "FUNCTION",
                },
            },
        )
        count = rename_function_everywhere(
            _cfg(tmp_path), primary, "", "hook@@12", "new_hook", rename_file=False
        )
        assert count == 1
        assert primary.read_text(encoding="utf-8") == (
            "void __vectorcall new_hook(int a) { return; }\n"
        )
        assert other.read_text(encoding="utf-8") == "int hook(void) { return 2; }\n"


class TestRenameEdgeCases:
    def test_dry_run_unreadable_file_fails(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A candidate the scan cannot read fails the dry run.

        The write path already raises on an unreadable source (the definition
        renamed, the call site left behind).  Skipping it in the scan instead
        made the preview under-report and the run silently leave the tree
        split, so both now stop.
        """
        from rebrew.rename_ops import RenameError, rename_function_everywhere

        src = tmp_path / "src"
        src.mkdir()
        (src / "bad.c").mkdir()  # directory matching *.c → read raises OSError
        cfg = SimpleNamespace(reversed_dir=src, source_ext=".c")
        with pytest.raises(RenameError) as excinfo:
            rename_function_everywhere(
                cfg, src / "bad.c", "old_fn", "_old_fn", "new_fn", dry_run=True
            )
        assert excinfo.value.files == [src / "bad.c"]

    def test_primary_file_oserror_warns(self, tmp_path: Path, monkeypatch: Any) -> None:
        """A missing/unreadable primary file aborts the rename BEFORE any
        reference is rewritten — continuing would leave the definition with
        the old name while every call site got the new one (regression: the
        old code warned and half-applied the rename)."""
        import pytest

        from rebrew.rename_ops import rename_function_everywhere

        src = tmp_path / "src"
        src.mkdir()
        cfg = SimpleNamespace(reversed_dir=src, source_ext=".c")
        # Missing primary file → abort with a clean error, nothing mutated.
        with pytest.raises(FileNotFoundError):
            rename_function_everywhere(cfg, src / "missing.c", "old_fn", "_old_fn", "new_fn")
        # No reference rewrite happened: a sibling file keeps the old name.
        sibling = src / "e.c"
        sibling.write_text("extern int old_fn(void);\n", encoding="utf-8")
        with pytest.raises(FileNotFoundError):
            rename_function_everywhere(cfg, src / "missing.c", "old_fn", "_old_fn", "new_fn")
        assert "old_fn" in sibling.read_text(encoding="utf-8")

    def test_extern_oserror_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.rename_ops import RenameError, rename_function_everywhere

        src = tmp_path / "src"
        src.mkdir()
        primary = src / "f.c"
        primary.write_text("int old_fn(void) { return 0; }\n", encoding="utf-8")
        bad = src / "bad.c"
        bad.write_text("extern int old_fn(void);\n", encoding="utf-8")
        (src / "e.c").write_text("extern int old_fn(void);\n", encoding="utf-8")
        real_read = rename_ops.read_source_text

        def _read(path: Path) -> tuple[str, str]:
            if path == bad:
                raise PermissionError(f"cannot read {path}")
            return real_read(path)

        monkeypatch.setattr(rename_ops, "read_source_text", _read)
        cfg = SimpleNamespace(reversed_dir=src, source_ext=".c")
        # The same preflight plan protects both preview and writes: an
        # unreadable reference aborts before changing the definition.
        with pytest.raises(RenameError) as excinfo:
            rename_function_everywhere(cfg, primary, "old_fn", "_old_fn", "new_fn")
        assert excinfo.value.files == [bad]
        assert "old_fn" in primary.read_text(encoding="utf-8")
        assert "old_fn" in (src / "e.c").read_text(encoding="utf-8")
        assert "old_fn" in bad.read_text(encoding="utf-8")

    def test_new_filename_absolute_path(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.rename_ops import rename_function_everywhere

        src = tmp_path / "src"
        src.mkdir()
        primary = src / "old_fn.c"
        primary.write_text("int old_fn(void) { return 0; }\n", encoding="utf-8")
        (src / "sub").mkdir()  # nested target dir must exist for Path.rename
        cfg = SimpleNamespace(reversed_dir=src, source_ext=".c")
        rename_function_everywhere(
            cfg, primary, "old_fn", "_old_fn", "new_fn", new_filename="sub/new_file"
        )
        assert (src / "sub" / "new_file.c").read_text() == "int new_fn(void) { return 0; }\n"
        assert not primary.exists()

    def test_stem_not_matching_keeps_file(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.rename_ops import rename_function_everywhere

        src = tmp_path / "src"
        src.mkdir()
        primary = src / "unrelated.c"
        primary.write_text("int old_fn(void) { return 0; }\n", encoding="utf-8")
        cfg = SimpleNamespace(reversed_dir=src, source_ext=".c")
        rename_function_everywhere(cfg, primary, "old_fn", "_old_fn", "new_fn")
        # stem != old name → the file keeps its name, but the body still renames.
        assert (src / "unrelated.c").read_text() == "int new_fn(void) { return 0; }\n"
        assert [p.name for p in src.iterdir()] == ["unrelated.c"]


class TestRenameCli:
    def test_json_preserves_stdcall_suffix(self, tmp_path: Path, monkeypatch: Any) -> None:

        source = tmp_path / "src" / "SERVER" / "old_fn.c"
        source.parent.mkdir(parents=True)
        write_source(
            source,
            "/* ADDRESS: SERVER 0x1000 */\nint __stdcall old_fn(int a, int b, int c) { return 1; }\n",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        result = self._invoke(
            tmp_path,
            monkeypatch,
            "--dry-run",
            "--json",
            "old_fn",
            "new_fn",
            entries=[
                SimpleNamespace(name="old_fn", symbol="_old_fn@12", filepath="old_fn.c", va=0x1000)
            ],
        )
        assert result.exit_code == 0, result.output
        assert cli_payload(result)["new_symbol"] == "_new_fn@12"

    def test_json_preserves_vectorcall_and_fastcall(self, tmp_path: Path, monkeypatch: Any) -> None:
        """``name@@N`` and ``@name@N`` stay decorated after a rename.

        The reported symbol kept only one ``@N`` and always added ``_``,
        so ``hook@@12`` became ``_new_hook@12``.
        """

        source = tmp_path / "src" / "SERVER" / "hook.c"
        source.parent.mkdir(parents=True)
        write_source(
            source,
            "/* ADDRESS: SERVER 0x1000 */\nvoid __vectorcall hook(int a, int b, int c) { return; }\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        result = self._invoke(
            tmp_path,
            monkeypatch,
            "--dry-run",
            "--json",
            "hook",
            "new_hook",
            entries=[SimpleNamespace(name="hook", symbol="hook@@12", filepath="hook.c", va=0x1000)],
        )
        assert result.exit_code == 0, result.output
        assert cli_payload(result)["new_symbol"] == "new_hook@@12"

        fast = tmp_path / "src" / "SERVER" / "keeps.c"
        write_source(
            fast,
            "/* ADDRESS: SERVER 0x1004 */\nvoid __fastcall keeps(int a) { return; }\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1004": {"kind": "FUNCTION"}},
        )
        result = self._invoke(
            tmp_path,
            monkeypatch,
            "--dry-run",
            "--json",
            "keeps",
            "new_keeps",
            entries=[
                SimpleNamespace(name="keeps", symbol="@keeps@4", filepath="keeps.c", va=0x1004)
            ],
        )
        assert result.exit_code == 0, result.output
        assert cli_payload(result)["new_symbol"] == "@new_keeps@4"

    def _invoke(
        self, tmp_path: Path, monkeypatch: Any, *args: str, entries: list[Any] | None = None
    ) -> Any:
        from typer.testing import CliRunner

        from rebrew.rename import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            marker="SERVER",
            metadata_dir=tmp_path,
            source_ext=".c",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: cfg)
        if entries is None:
            entries = [
                SimpleNamespace(name="old_fn", symbol="_old_fn", filepath="old_fn.c", va=0x1000)
            ]
        monkeypatch.setattr(
            "rebrew.rename.scan_reversed_dir",
            lambda d, cfg=None: entries,
        )
        return CliRunner().invoke(app, list(args))

    def test_json_output(self, tmp_path: Path, monkeypatch: Any) -> None:

        f = tmp_path / "src" / "SERVER" / "old_fn.c"
        f.parent.mkdir(parents=True)
        write_source(
            f,
            "/* ADDRESS: SERVER 0x1000 */\nint old_fn(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        result = self._invoke(tmp_path, monkeypatch, "--json", "old_fn", "new_fn")
        assert result.exit_code == 0
        data = cli_payload(result)
        assert data["new_name"] == "new_fn"
        assert data["files_updated"] >= 1

    def test_not_found_errors(self, tmp_path: Path, monkeypatch: Any) -> None:
        result = self._invoke(tmp_path, monkeypatch, "--json", "nope", "new_fn")
        assert result.exit_code != 0
        assert "Could not find function" in result.output

    def test_failure_names_the_files_it_could_not_rewrite(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A stale call site is the actionable half of a rename failure.

        ``RenameError`` carries the offending sources so the operator can open
        them; the CLI reported only the message, which named the operation but
        not the files.
        """
        from rebrew.rename_ops import RenameError

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        stale = src / "stale.c"
        stale.write_text("extern int old_fn(void);\n", encoding="utf-8")
        monkeypatch.setattr(
            "rebrew.rename.plan_symbol_rename",
            lambda *a, **kw: (_ for _ in ()).throw(
                RenameError("call sites not rewritten", files=[stale])
            ),
        )
        result = self._invoke(tmp_path, monkeypatch, "old_fn", "new_fn")
        assert result.exit_code != 0
        assert "call sites not rewritten" in result.output
        assert "stale.c" in result.output

    def test_failure_output_stays_within_the_file_cap(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from rebrew.rename import _RENAME_FAILURE_FILE_LIMIT
        from rebrew.rename_ops import RenameError

        src = tmp_path / "src" / "SERVER"
        many = [src / f"f{i:03d}.c" for i in range(_RENAME_FAILURE_FILE_LIMIT + 5)]
        monkeypatch.setattr(
            "rebrew.rename.plan_symbol_rename",
            lambda *a, **kw: (_ for _ in ()).throw(
                RenameError("call sites not rewritten", files=many)
            ),
        )
        result = self._invoke(tmp_path, monkeypatch, "old_fn", "new_fn")
        assert result.exit_code != 0
        assert "5 more" in result.output
        assert f"f{_RENAME_FAILURE_FILE_LIMIT + 4:03d}.c" not in result.output

    def test_zero_padded_va_identifier(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Regression: discovery writes zero-padded VAs (0x00001000);
        rename must accept them like every other VA-taking tool."""
        f = tmp_path / "src" / "SERVER" / "old_fn.c"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("int old_fn(void) { return 0; }\n", encoding="utf-8")
        result = self._invoke(tmp_path, monkeypatch, "--dry-run", "0x00001000", "new_fn")
        assert result.exit_code == 0, result.output
        assert "new_fn" in result.output

    def test_unicode_normalization_nfc_nfd_target_ident(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        f = tmp_path / "src" / "SERVER" / "func_é.c"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("int func_é(void) { return 0; }\n", encoding="utf-8")
        # Stored name is NFC (precomposed é)
        entries = [
            SimpleNamespace(
                name="func_\u00e9",
                symbol="_func_\u00e9",
                filepath="func_\u00e9.c",
                va=0x1000,
            )
        ]
        # Query with NFD decomposed form (e + combining acute)
        nfd_ident = "func_\u0065\u0301"
        result = self._invoke(
            tmp_path, monkeypatch, "--dry-run", nfd_ident, "new_fn", entries=entries
        )
        assert result.exit_code == 0, result.output
        assert "new_fn" in result.output

    def test_source_file_outside_reversed_dir_errors(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A metadata filepath escaping reversed_dir must fail before any write."""
        outside = tmp_path / "outside.c"
        outside.write_text("int old_fn(void) { return 0; }\n", encoding="utf-8")
        entries = [
            SimpleNamespace(name="old_fn", symbol="_old_fn", filepath="../outside.c", va=0x1000)
        ]
        result = self._invoke(tmp_path, monkeypatch, "--json", "old_fn", "new_fn", entries=entries)
        assert result.exit_code != 0
        assert "escapes reversed_dir" in result.output
        assert outside.read_text(encoding="utf-8") == "int old_fn(void) { return 0; }\n"

    def test_multiple_matches_errors(self, tmp_path: Path, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from rebrew.rename import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True)
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            marker="SERVER",
            metadata_dir=tmp_path,
            source_ext=".c",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.rename.scan_reversed_dir",
            lambda d, cfg=None: [
                SimpleNamespace(name="dup", symbol="_dup", filepath="a.c", va=0x1000),
                SimpleNamespace(name="dup", symbol="_dup", filepath="b.c", va=0x2000),
            ],
        )
        result = CliRunner().invoke(app, ["--json", "dup", "new_fn"])
        assert result.exit_code != 0
        assert "Be more specific" in result.output

    def test_rename_onto_existing_symbol_errors(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Renaming onto an existing function's symbol must be rejected —
        otherwise two functions share one name (duplicate definition)."""
        from typer.testing import CliRunner

        from rebrew.rename import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True)
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            marker="SERVER",
            metadata_dir=tmp_path,
            source_ext=".c",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.rename.scan_reversed_dir",
            lambda d, cfg=None: [
                SimpleNamespace(name="old_fn", symbol="_old_fn", filepath="old_fn.c", va=0x1000),
                SimpleNamespace(name="taken", symbol="_taken", filepath="taken.c", va=0x2000),
            ],
        )
        result = CliRunner().invoke(app, ["--json", "old_fn", "taken"])
        assert result.exit_code != 0
        assert "duplicate symbol" in result.output

    def test_rename_onto_stdcall_decorated_symbol_errors(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A __stdcall collision carries a decorated suffix (_foo@8) — the
        plain-name check must not miss it."""
        from typer.testing import CliRunner

        from rebrew.rename import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True)
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            marker="SERVER",
            metadata_dir=tmp_path,
            source_ext=".c",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.rename.scan_reversed_dir",
            lambda d, cfg=None: [
                SimpleNamespace(name="old_fn", symbol="_old_fn", filepath="old_fn.c", va=0x1000),
                SimpleNamespace(name="taken2", symbol="_taken2@8", filepath="taken2.c", va=0x2000),
            ],
        )
        result = CliRunner().invoke(app, ["--json", "old_fn", "taken2"])
        assert result.exit_code != 0
        assert "duplicate symbol" in result.output

    def test_rename_onto_vectorcall_or_fastcall_symbol_errors(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """``name@@N`` and ``@name@N`` are the C function ``name``.

        The stored label can differ. The collision check only looked for
        ``_name@``, so these decorated symbols were not duplicates.
        ``taken`` is not ``taken2``.
        """
        from typer.testing import CliRunner

        from rebrew.rename import app

        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True)
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            marker="SERVER",
            metadata_dir=tmp_path,
            source_ext=".c",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: cfg)

        def scan_for(symbol: str):
            return lambda d, cfg=None: [
                SimpleNamespace(name="old_fn", symbol="_old_fn", filepath="old_fn.c", va=0x1000),
                SimpleNamespace(name="ghidra_taken", symbol=symbol, filepath="taken.c", va=0x2000),
            ]

        for symbol in ("taken2@@12", "@taken2@4"):
            monkeypatch.setattr("rebrew.rename.scan_reversed_dir", scan_for(symbol))
            result = CliRunner().invoke(app, ["--json", "old_fn", "taken2"])
            assert result.exit_code != 0
            assert "duplicate symbol" in result.output

        monkeypatch.setattr("rebrew.rename.scan_reversed_dir", scan_for("taken2@@12"))
        result = CliRunner().invoke(app, ["--json", "old_fn", "taken"])
        assert "duplicate symbol" not in result.output

    def test_invalid_identifier_rejected(self, tmp_path: Path, monkeypatch: Any) -> None:
        # C keyword and non-identifier names must fail before any rename.
        result = self._invoke(tmp_path, monkeypatch, "--json", "old_fn", "int")
        assert result.exit_code != 0
        assert "not a valid C identifier" in result.output

        result = self._invoke(tmp_path, monkeypatch, "--json", "old_fn", "bad name")
        assert result.exit_code != 0
        assert "not a valid C identifier" in result.output

    def test_non_ascii_identifier_rejected(self, tmp_path: Path, monkeypatch: Any) -> None:
        # `str.isidentifier()` accepts these; a C89 compiler does not.
        for name in ("café", "名前"):
            result = self._invoke(tmp_path, monkeypatch, "--json", "old_fn", name)
            assert result.exit_code != 0
            assert "not a valid C identifier" in result.output

    def test_rename_by_va(self, tmp_path: Path, monkeypatch: Any) -> None:

        f = tmp_path / "src" / "SERVER" / "old_fn.c"
        f.parent.mkdir(parents=True)
        write_source(
            f,
            "/* ADDRESS: SERVER 0x1000 */\nint old_fn(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        result = self._invoke(tmp_path, monkeypatch, "--json", "0x1000", "new_fn")
        assert result.exit_code == 0
        data = cli_payload(result)
        assert data["new_name"] == "new_fn"

    def test_json_dry_run_flag(self, tmp_path: Path, monkeypatch: Any) -> None:

        f = tmp_path / "src" / "SERVER" / "old_fn.c"
        f.parent.mkdir(parents=True)
        write_source(
            f,
            "/* ADDRESS: SERVER 0x1000 */\nint old_fn(void) { return 0; }\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        result = self._invoke(tmp_path, monkeypatch, "--json", "--dry-run", "old_fn", "new_fn")
        assert result.exit_code == 0
        data = cli_payload(result)
        assert data["dry_run"] is True
        # The count is what the run would rewrite, not what it did.
        assert data["files_updated"] == 1
        # Dry run must not have rewritten the file.
        assert "new_fn" not in f.read_text(encoding="utf-8")


class TestRenameData:
    def _cfg(self, tmp_path: Path):
        from types import SimpleNamespace

        return SimpleNamespace(
            root=tmp_path,
            reversed_dir=tmp_path / "src",
            metadata_dir=tmp_path,
            source_ext=".c",
            marker="SERVER",
        )

    def _project(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        write_source(
            src / "g.c",
            "/* ADDRESS: SERVER 0x2000 */\nint g_old;\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x2000": {"kind": "GLOBAL"}},
        )
        write_source(
            src / "use.c",
            "/* ADDRESS: SERVER 0x1000 */\nint f(void){return g_old;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x2000"]\nname = "g_old"\nsize = 4\nsection = ".data"\n',
            encoding="utf-8",
        )

    def test_rename_data(self, tmp_path: Path, monkeypatch) -> None:
        import typer as _typer
        from typer.testing import CliRunner

        from rebrew.metadata.data import get_data_entry
        from rebrew.rename import main as _rename_main

        app = _typer.Typer()
        app.command()(_rename_main)

        self._project(tmp_path)
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: self._cfg(tmp_path))
        res = CliRunner().invoke(app, ["g_old", "g_new", "--data"])
        assert res.exit_code == 0, res.output
        assert get_data_entry(tmp_path, 0x2000, "SERVER").get("name") == "g_new"
        text = (tmp_path / "src" / "use.c").read_text(encoding="utf-8")
        assert "g_new" in text and "g_old" not in text

    def test_rename_data_follows_link_symbol(self, tmp_path: Path, monkeypatch) -> None:
        """The native linker symbol of the renamed definition keeps its decoration."""
        import typer as _typer
        from typer.testing import CliRunner

        from rebrew.metadata.data import get_data_entry
        from rebrew.rename import main as _rename_main

        app = _typer.Typer()
        app.command()(_rename_main)

        self._project(tmp_path)
        store = tmp_path / "rebrew-data.toml"
        write_store_fixture(
            store, store.read_text(encoding="utf-8") + 'link_symbol = "_g_old"\n', encoding="utf-8"
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: self._cfg(tmp_path))
        res = CliRunner().invoke(app, ["g_old", "g_new", "--data"])
        assert res.exit_code == 0, res.output
        assert get_data_entry(tmp_path, 0x2000, "SERVER").get("link_symbol") == "_g_new"

    def test_rename_data_updates_header(self, tmp_path: Path, monkeypatch) -> None:
        """A header extern is a declaration of the same global and is renamed."""
        import typer as _typer
        from typer.testing import CliRunner

        from rebrew.rename import main as _rename_main

        app = _typer.Typer()
        app.command()(_rename_main)

        self._project(tmp_path)
        (tmp_path / "src" / "g.h").write_text("extern int g_old;\n", encoding="utf-8")
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: self._cfg(tmp_path))
        res = CliRunner().invoke(app, ["g_old", "g_new", "--data"])
        assert res.exit_code == 0, res.output
        header = (tmp_path / "src" / "g.h").read_text(encoding="utf-8")
        assert header == "extern int g_new;\n"

    def test_rename_data_dry_run(self, tmp_path: Path, monkeypatch) -> None:
        import typer as _typer
        from typer.testing import CliRunner

        from rebrew.metadata.data import get_data_entry
        from rebrew.rename import main as _rename_main

        app = _typer.Typer()
        app.command()(_rename_main)

        self._project(tmp_path)
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: self._cfg(tmp_path))
        res = CliRunner().invoke(app, ["g_old", "g_new", "--data", "--dry-run"])
        assert res.exit_code == 0, res.output
        assert get_data_entry(tmp_path, 0x2000, "SERVER").get("name") == "g_old"

    def test_rename_data_read_error_aborts_before_metadata(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Unreadable source must abort before rewriting rebrew-data.toml."""
        import typer as _typer
        from typer.testing import CliRunner

        from rebrew.metadata.data import get_data_entry
        from rebrew.rename import main as _rename_main

        app = _typer.Typer()
        app.command()(_rename_main)

        self._project(tmp_path)
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: self._cfg(tmp_path))

        def _boom(_path: Path) -> tuple[str, str]:
            raise OSError(13, "Permission denied")

        monkeypatch.setattr("rebrew.rename_ops.read_source_text", _boom)
        res = CliRunner().invoke(app, ["g_old", "g_new", "--data"])
        assert res.exit_code != 0
        assert get_data_entry(tmp_path, 0x2000, "SERVER").get("name") == "g_old"

    def test_rename_data_metadata_only(self, tmp_path: Path, monkeypatch) -> None:
        """A metadata-only entry (no marker) renames via the metadata store."""
        import typer as _typer
        from typer.testing import CliRunner

        from rebrew.metadata.data import get_data_entry
        from rebrew.rename import main as _rename_main

        app = _typer.Typer()
        app.command()(_rename_main)

        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        write_source(
            src / "use.c",
            "/* ADDRESS: SERVER 0x1000 */\nint f(void){return $SG18890;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x313fc"]\nname = "$SG18890"\nsize = 4\n',
            encoding="utf-8",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: self._cfg(tmp_path))
        res = CliRunner().invoke(app, ["0x313fc", "g_100313fc", "--data"])
        assert res.exit_code == 0, res.output
        assert get_data_entry(tmp_path, 0x313FC, "SERVER").get("name") == "g_100313fc"
        text = (src / "use.c").read_text(encoding="utf-8")
        assert "g_100313fc" in text

    def test_rename_data_metadata_only_dry_run(self, tmp_path: Path, monkeypatch) -> None:
        import typer as _typer
        from typer.testing import CliRunner

        from rebrew.metadata.data import get_data_entry
        from rebrew.rename import main as _rename_main

        app = _typer.Typer()
        app.command()(_rename_main)

        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        write_source(
            src / "use.c",
            "/* ADDRESS: SERVER 0x1000 */\nint f(void){return 0;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x313fc"]\nname = "$SG18890"\nsize = 4\n',
            encoding="utf-8",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: self._cfg(tmp_path))
        res = CliRunner().invoke(app, ["$SG18890", "g_100313fc", "--data", "--dry-run"])
        assert res.exit_code == 0, res.output
        assert get_data_entry(tmp_path, 0x313FC, "SERVER").get("name") == "$SG18890"

    def test_rename_data_metadata_only_unreadable_sibling_aborts(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """One unreadable source must abort the metadata-only rename too.

        The candidate scan used to skip it, so the write loop never saw the
        failure it aborts on: the TOML entry took the new name while the
        unreadable file kept the old one, and the command reported success.
        """
        import typer as _typer
        from typer.testing import CliRunner

        from rebrew.metadata.data import get_data_entry
        from rebrew.rename import main as _rename_main

        app = _typer.Typer()
        app.command()(_rename_main)

        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        write_source(
            src / "use.c",
            "/* ADDRESS: SERVER 0x1000 */\nint f(void){return $SG18890;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        locked = src / "locked.c"
        locked.write_text("int g(void){ return $SG18890; }\n", encoding="utf-8")
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x313fc"]\nname = "$SG18890"\nsize = 4\n',
            encoding="utf-8",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: self._cfg(tmp_path))
        real_read = rename_ops.read_source_text

        def _read(path: Path) -> tuple[str, str]:
            if path == locked:
                raise PermissionError(13, "Permission denied")
            return real_read(path)

        monkeypatch.setattr(rename_ops, "read_source_text", _read)
        res = CliRunner().invoke(app, ["$SG18890", "g_100313fc", "--data"])
        assert res.exit_code != 0
        assert str(locked) in res.output
        assert get_data_entry(tmp_path, 0x313FC, "SERVER").get("name") == "$SG18890"
        assert "$SG18890" in locked.read_text(encoding="utf-8")

    def test_rename_data_source_file_outside_source_roots_errors(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """A data entry's metadata filepath escaping the source roots must fail
        before any write: the value is joined onto reversed_dir and then read
        and rewritten, so a `../` value would edit a file outside the tree."""
        from types import SimpleNamespace

        import typer as _typer
        from typer.testing import CliRunner

        from rebrew.metadata.data import get_data_entry
        from rebrew.rename import main as _rename_main

        app = _typer.Typer()
        app.command()(_rename_main)

        self._project(tmp_path)
        outside = tmp_path.parent / "outside_data_rename.c"
        outside.write_text("int g_old;\n", encoding="utf-8")
        entries = [
            SimpleNamespace(
                name="g_old",
                symbol="g_old",
                filepath="../../outside_data_rename.c",
                va=0x2000,
                module="SERVER",
                is_data=True,
            )
        ]
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: self._cfg(tmp_path))
        monkeypatch.setattr("rebrew.rename.scan_reversed_dir", lambda *a, **kw: entries)
        res = CliRunner().invoke(app, ["g_old", "g_new", "--data"])
        assert res.exit_code != 0
        assert "escapes the source roots" in res.output
        assert outside.read_text(encoding="utf-8") == "int g_old;\n"
        assert get_data_entry(tmp_path, 0x2000, "SERVER").get("name") == "g_old"

    def test_rename_data_collision_refused(self, tmp_path: Path, monkeypatch) -> None:
        import typer as _typer
        from typer.testing import CliRunner

        from rebrew.metadata.data import get_data_entry
        from rebrew.rename import main as _rename_main

        app = _typer.Typer()
        app.command()(_rename_main)

        self._project(tmp_path)
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: self._cfg(tmp_path))
        res = CliRunner().invoke(app, ["g_old", "f", "--data"])
        assert res.exit_code == 2
        assert "would create a duplicate symbol" in res.output
        assert get_data_entry(tmp_path, 0x2000, "SERVER").get("name") == "g_old"

    def test_rename_data_onto_decorated_function_symbol_errors(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """A function symbol ``hook@@12`` is the C name ``hook``.

        The data collision check compared the symbol to ``hook`` and
        ``_hook`` only, so a different stored label hid the decoration.
        ``hoo`` is not ``hook``.
        """
        import typer as _typer
        from typer.testing import CliRunner

        from rebrew.metadata.data import get_data_entry
        from rebrew.rename import main as _rename_main

        app = _typer.Typer()
        app.command()(_rename_main)
        src = tmp_path / "src"
        src.mkdir()
        (src / "g.c").write_text("int g_old;\n", encoding="utf-8")
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x2000"]\nname = "g_old"\nsize = 4\nsection = ".data"\n',
            encoding="utf-8",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: self._cfg(tmp_path))
        data = SimpleNamespace(
            name="g_old", symbol="g_old", filepath="g.c", va=0x2000, module="SERVER", is_data=True
        )

        def scan_for(symbol: str):
            return lambda d, cfg=None: [
                data,
                SimpleNamespace(
                    name="ghidra_hook",
                    symbol=symbol,
                    filepath="h.c",
                    va=0x1000,
                    module="SERVER",
                    is_data=False,
                ),
            ]

        for symbol in ("_hook@8", "hook@@12", "@hook@4"):
            monkeypatch.setattr("rebrew.rename.scan_reversed_dir", scan_for(symbol))
            res = CliRunner().invoke(app, ["g_old", "hook", "--data"])
            assert res.exit_code == 2
            assert "would create a duplicate symbol" in res.output
            assert get_data_entry(tmp_path, 0x2000, "SERVER").get("name") == "g_old"

        monkeypatch.setattr("rebrew.rename.scan_reversed_dir", scan_for("hook@@12"))
        res = CliRunner().invoke(app, ["g_old", "hoo", "--data", "--dry-run"])
        assert res.exit_code == 0
        assert "duplicate symbol" not in res.output

    def test_metadata_only_rename_onto_decorated_symbol_errors(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """A global with no marker still shares the linker's namespace.

        The metadata-only collision check compared labels, so a function
        symbol ``_hook``, ``_hook@8``, ``hook@@12``, or ``@hook@4`` did
        not block the rename. ``hoo`` is not ``hook``.
        """
        import typer as _typer
        from typer.testing import CliRunner

        from rebrew.metadata.data import get_data_entry
        from rebrew.rename import main as _rename_main

        app = _typer.Typer()
        app.command()(_rename_main)
        src = tmp_path / "src"
        src.mkdir()
        (src / "g.c").write_text("int g_old;\n", encoding="utf-8")
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x2000"]\nname = "g_old"\nsize = 4\nsection = ".data"\n',
            encoding="utf-8",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: self._cfg(tmp_path))

        def scan_for(symbol: str):
            return lambda d, cfg=None: [
                SimpleNamespace(
                    name="ghidra_hook",
                    symbol=symbol,
                    filepath="h.c",
                    va=0x1000,
                    module="SERVER",
                    is_data=False,
                ),
            ]

        for symbol in ("_hook", "_hook@8", "hook@@12", "@hook@4"):
            monkeypatch.setattr("rebrew.rename.scan_reversed_dir", scan_for(symbol))
            res = CliRunner().invoke(app, ["g_old", "hook", "--data"])
            assert res.exit_code == 2, symbol
            assert "would create a duplicate symbol" in res.output
            assert get_data_entry(tmp_path, 0x2000, "SERVER").get("name") == "g_old"

        monkeypatch.setattr("rebrew.rename.scan_reversed_dir", scan_for("hook@@12"))
        res = CliRunner().invoke(app, ["g_old", "hoo", "--data", "--dry-run"])
        assert res.exit_code == 0
        assert "duplicate symbol" not in res.output


class TestUnderscoreNameDerivation:
    def test_double_underscore_symbol_matches_the_underscored_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A function named `_foo` carries the cdecl symbol `__foo`.
        `lstrip("_")` produced `foo`, so the rename either matched nothing or
        rewrote an unrelated `foo` in the same project."""
        target = _src(
            tmp_path, "a.c", "int _foo(void) { return 1; }\nint foo(void) { return 2; }\n"
        )
        _patch_sources(monkeypatch, [target])
        count = rename_function_everywhere(_cfg(tmp_path), target, "_foo", "__foo", "renamed_fn")
        assert count == 1
        text = target.read_text(encoding="utf-8")
        assert "int renamed_fn(void)" in text
        # The unrelated single-underscore function is untouched.
        assert "int foo(void) { return 2; }" in text


class TestProtectedSpans:
    def test_substitution_skips_literals_and_macro_names(self) -> None:
        """Literals and a macro's own name are not occurrences of the function.

        A raw-text substitution rewrote ``puts("foo")``, changing the data a
        byte-matched function emits.
        """
        from rebrew.c_rename import ORDINARY_ROLES, ParsedSource, occurrences, rewrite

        src = ParsedSource.parse(
            "int foo(void) { return 1; }\n"
            'void caller(void) { puts("foo"); foo(); }\n'
            "#define foo(x) ((x) + 1)\n"
        )
        spans = [(o.start, o.end) for o in occurrences(src, "foo") if o.role in ORDINARY_ROLES]
        out = rewrite(src, spans, "bar")
        assert "int bar(void)" in out
        assert "bar();" in out
        assert 'puts("foo")' in out
        assert "#define foo(x)" in out

    def test_word_boundary_is_unicode(self) -> None:
        """A non-ASCII letter is part of the word: ``éfoo`` is not ``foo``."""
        from rebrew.c_rename import ParsedSource, occurrences

        src = ParsedSource.parse("int éfoo; int foo(void);\n")
        assert [o.column for o in occurrences(src, "foo")] == [15]

    def test_macro_name_spans_cover_defines(self) -> None:
        from rebrew.c_parser import protected_spans

        src = "int foo(void) { return 1; }\n#define foo 2\nchar c = 'f';\n"
        spans = [src.encode("utf-8")[s:e].decode("utf-8") for s, e in protected_spans(src)]
        # Exactly two spans: the macro's NAME (not its body) and the char literal.
        # The function's own name is NOT protected (it must be renamed).
        assert spans == ["foo", "'f'"]


class TestFunctionReferenceBinding:
    @pytest.mark.parametrize("preview", [True, False])
    @pytest.mark.parametrize("conflict", [None, "other-target-definition", "missing", "escape"])
    @pytest.mark.parametrize("return_type", ["int", "z_off_t"])
    def test_binds_compiled_library_outside_reversed_dir(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        preview: bool,
        conflict: str | None,
        return_type: str,
    ) -> None:

        from typer.testing import CliRunner

        from rebrew.metadata.functions import record_function_identity
        from rebrew.rename import app

        source_dir = tmp_path / "src"
        source_dir.mkdir()
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()
        _src(
            vendor_dir,
            "external.h",
            "#define ZEXPORT\ntypedef long z_off_t;\ntypedef void *gzFile;\n",
        )
        provider = _src(
            vendor_dir,
            "writer.c",
            '#include "external.h"\n'
            f"{return_type} ZEXPORT gzseek (file, offset, whence) "
            "gzFile file; z_off_t offset; int whence; { return offset + whence; }\n",
        )
        caller = _src(
            source_dir,
            "caller.c",
            '#include "../vendor/external.h"\n'
            f"{return_type} placeholder(gzFile, z_off_t, int); "
            "int caller(void) { return placeholder(0, 2, 3); }\n",
        )
        record_function_identity(
            tmp_path,
            module="CLIENT",
            va=0x1000,
            file="vendor/writer.c",
            kind="LIBRARY",
            name="gzseek",
            symbol="_gzseek",
        )
        if conflict == "other-target-definition":
            _src(vendor_dir, "twin.c", "int gzseek(int x) { return x + 1; }\n")
            record_function_identity(
                tmp_path,
                module="OTHER",
                va=0x2000,
                file="vendor/twin.c",
                kind="LIBRARY",
                name="gzseek",
                symbol="_gzseek",
            )
        elif conflict == "missing":
            provider.unlink()
        elif conflict == "escape":
            provider.unlink()
            provider.symlink_to(tmp_path.parent / "outside-writer.c")
        cfg = _cfg(tmp_path)
        cfg.root, cfg.reversed_dir, cfg.marker, cfg.source_ext = (
            tmp_path,
            source_dir,
            "CLIENT",
            ".c",
        )
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: cfg)
        before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
        result = CliRunner().invoke(
            app, ["--json", *(["--dry-run"] if preview else []), "placeholder", "CLIENT.0x1000"]
        )
        if conflict is None:
            assert result.exit_code == 0, result.output
            assert cli_payload(result)["rows"] == []
        else:
            assert result.exit_code == 2, result.output
            reason = {
                "other-target-definition": "one external function definition",
                "missing": "could not be read",
                "escape": "escapes the project",
            }[conflict]
            assert reason in result.output
        for path, content in before.items():
            expected = (
                content.replace(b"placeholder", b"gzseek")
                if path == caller and conflict is None and not preview
                else content
            )
            assert path.read_bytes() == expected

    @pytest.mark.parametrize(
        "header_text",
        [
            SourceFixture(
                "\n// _free\n",
                {"CLIENT.0x1000": {"kind": "LIBRARY", "name": "free", "symbol": "_free"}},
            ),
            "void free(void*);\n",
        ],
    )
    @pytest.mark.parametrize("preview", [True, False])
    def test_binds_linked_library_without_creating_source_or_changing_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, preview: bool, header_text: str
    ) -> None:

        from typer.testing import CliRunner

        from rebrew.metadata.functions import record_function_identity
        from rebrew.rename import app

        header = _src(tmp_path, "library_crt.h", header_text)
        caller = _src(
            tmp_path,
            "caller.c",
            "void placeholder(void*); void caller(void* p) { placeholder(p); }\n",
        )
        _src(tmp_path, "other.c", "void free(void*); void other(int free) { free++; }\n")
        record_function_identity(
            tmp_path,
            module="CLIENT",
            va=0x1000,
            file="library_crt.h",
            kind="LIBRARY",
            name="free",
            symbol="_free",
        )
        cfg = _cfg(tmp_path)
        cfg.root, cfg.marker, cfg.source_ext = tmp_path, "CLIENT", ".c"
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: cfg)
        original = caller.read_bytes()
        metadata = (tmp_path / "rebrew-functions.toml").read_bytes()
        result = CliRunner().invoke(
            app, ["--json", *(["--dry-run"] if preview else []), "placeholder", "CLIENT.0x1000"]
        )
        assert result.exit_code == 0, result.output
        assert cli_payload(result)["rows"] == []
        assert caller.read_bytes() == (
            original if preview else original.replace(b"placeholder", b"free")
        )
        assert header.read_text() == header_text
        assert (tmp_path / "rebrew-functions.toml").read_bytes() == metadata
        assert not any("free(void* p) {" in p.read_text() for p in tmp_path.glob("*.c"))

    @pytest.mark.parametrize("conflict", ["missing-header", "project-definition", "variable"])
    def test_refuses_unbacked_or_shadowed_library_binding(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, conflict: str
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.metadata.functions import record_function_identity
        from rebrew.rename import app

        if conflict != "missing-header":
            _src(
                tmp_path,
                "library_crt.h",
                SourceFixture(
                    "\n// _free\n",
                    {"CLIENT.0x1000": {"kind": "LIBRARY", "name": "free", "symbol": "_free"}},
                ),
            )
        caller = _src(tmp_path, "caller.c", "void placeholder(void*);\n")
        if conflict == "project-definition":
            _src(tmp_path, "shadow.c", "void free(void* p) {}\n")
        elif conflict == "variable":
            caller.write_text("void placeholder(void*); extern int free;\n")
        record_function_identity(
            tmp_path,
            module="CLIENT",
            va=0x1000,
            file="library_crt.h",
            kind="LIBRARY",
            name="free",
            symbol="_free",
        )
        cfg = _cfg(tmp_path)
        cfg.root, cfg.marker, cfg.source_ext = tmp_path, "CLIENT", ".c"
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: cfg)
        metadata = (tmp_path / "rebrew-functions.toml").read_bytes()
        result = CliRunner().invoke(app, ["--json", "placeholder", "CLIENT.0x1000"])
        assert result.exit_code == 2, result.output
        expected = "void placeholder(void*);" + (
            " extern int free;" if conflict == "variable" else ""
        )
        assert caller.read_text() == expected + "\n"
        assert (tmp_path / "rebrew-functions.toml").read_bytes() == metadata

    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *args: str) -> Any:
        from typer.testing import CliRunner

        from rebrew.metadata.functions import record_function_identity
        from rebrew.rename import app

        record_function_identity(
            tmp_path,
            module="CLIENT",
            va=0x1000,
            file="builder.c",
            kind="FUNCTION",
            name="BuildEvent",
            symbol="_BuildEvent",
        )
        cfg = _cfg(tmp_path)
        cfg.root = tmp_path
        cfg.marker = "CLIENT"
        cfg.source_ext = ".c"
        monkeypatch.setattr("rebrew.rename.require_config", lambda **kw: cfg)
        return CliRunner().invoke(app, ["--json", *args, "placeholder", "CLIENT.0x1000"])

    def test_preview_and_apply_preserve_destination_and_metadata(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        builder = _src(tmp_path, "builder.c", "int BuildEvent(void) { return 1; }\n")
        caller = _src(
            tmp_path,
            "caller.c",
            "int placeholder(void); int caller(void) { return placeholder(); }\n"
            'char *label = "placeholder"; /* placeholder */\n',
        )
        original = caller.read_bytes()
        preview = self._invoke(tmp_path, monkeypatch, "--dry-run")
        assert preview.exit_code == 0, preview.output
        plan = cli_payload(preview)
        assert plan["new_name"] == "BuildEvent"
        assert plan["rows"] == []
        assert plan["files_updated"] == 1
        assert caller.read_bytes() == original
        metadata = (tmp_path / "rebrew-functions.toml").read_bytes()
        result = self._invoke(tmp_path, monkeypatch)
        assert result.exit_code == 0, result.output
        assert caller.read_text() == (
            "int BuildEvent(void); int caller(void) { return BuildEvent(); }\n"
            'char *label = "placeholder"; /* placeholder */\n'
        )
        assert builder.read_text() == "int BuildEvent(void) { return 1; }\n"
        assert (tmp_path / "rebrew-functions.toml").read_bytes() == metadata

    @pytest.mark.parametrize(
        "conflict",
        [
            "int placeholder(void) { return 0; }",
            "extern int placeholder;",
            "int caller(int placeholder) { return placeholder; }",
            "int placeholder(void); int caller(int placeholder) { return placeholder; }",
            "int (*placeholder)(void);",
            "typedef int placeholder(void);",
            "static int placeholder(void);",
            "#define placeholder() 0",
            SourceFixture(
                "\n// _placeholder\nint placeholder(void);",
                {
                    "CLIENT.0x2000": {
                        "kind": "LIBRARY",
                        "name": "placeholder",
                        "symbol": "_placeholder",
                    }
                },
            ),
            "extern int BuildEvent; int placeholder(void);",
            "#define BuildEvent() 1\nint placeholder(void);",
        ],
    )
    def test_rejects_non_placeholder_names_without_writes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, conflict: str
    ) -> None:
        builder = _src(tmp_path, "builder.c", "int BuildEvent(void) { return 1; }\n")
        caller = _src(tmp_path, "caller.c", conflict + "\n")
        result = self._invoke(tmp_path, monkeypatch)
        assert result.exit_code != 0, result.output
        assert builder.read_text() == "int BuildEvent(void) { return 1; }\n"
        assert caller.read_text() == conflict + "\n"

    @pytest.mark.parametrize(
        "destination",
        [
            "static int BuildEvent(void) { return 1; }",
            "int Other(void) { return 1; }",
            "int BuildEvent;",
            "int BuildEvent(void);",
        ],
    )
    def test_requires_external_destination_definition(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, destination: str
    ) -> None:
        builder = _src(tmp_path, "builder.c", destination + "\n")
        caller = _src(tmp_path, "caller.c", "int placeholder(void);\n")
        result = self._invoke(tmp_path, monkeypatch)
        assert result.exit_code != 0, result.output
        assert builder.read_text() == destination + "\n"
        assert caller.read_text() == "int placeholder(void);\n"

    def test_rejects_independent_destination_twin(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _src(tmp_path, "builder.c", "int BuildEvent(void) { return 1; }\n")
        _src(tmp_path, "twin.c", "int BuildEvent(void) { return 2; }\n")
        caller = _src(tmp_path, "caller.c", "int placeholder(void);\n")
        result = self._invoke(tmp_path, monkeypatch)
        assert result.exit_code != 0, result.output
        assert caller.read_text() == "int placeholder(void);\n"

    def test_rejects_managed_library_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.functions import record_function_identity

        _src(tmp_path, "builder.c", "int BuildEvent(void) { return 1; }\n")
        caller = _src(tmp_path, "caller.c", "int placeholder(void);\n")
        record_function_identity(
            tmp_path,
            module="CLIENT",
            va=0x2000,
            file="caller.c",
            kind="LIBRARY",
            name="placeholder",
            symbol="_placeholder",
        )
        result = self._invoke(tmp_path, monkeypatch)
        assert result.exit_code != 0, result.output
        assert caller.read_text() == "int placeholder(void);\n"

    @pytest.mark.parametrize(
        "declaration,kind",
        [
            ("int (*name)(void);", "variable"),
            ("int *name(void) { return 0; }", "function"),
            ("int (*name(void))(void) { return 0; }", "function"),
            ("int (*name[2])(void);", "variable"),
        ],
    )
    def test_declarator_classification(self, declaration: str, kind: str) -> None:
        from rebrew.c_rename import ParsedSource, definitions

        assert [d.kind for d in definitions(ParsedSource.parse(declaration), "name")] == [kind]

    @pytest.mark.parametrize("options", [("--file", "other.c"), ("--all-modules",), ("--data",)])
    def test_rejects_identity_and_non_function_modes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, options: tuple[str, ...]
    ) -> None:
        _src(tmp_path, "builder.c", "int BuildEvent(void) { return 1; }\n")
        caller = _src(tmp_path, "caller.c", "int placeholder(void);\n")
        result = self._invoke(tmp_path, monkeypatch, *options)
        assert result.exit_code != 0, result.output
        assert caller.read_text() == "int placeholder(void);\n"


class TestRenameDoesNotTouchLiterals:
    def test_rename_keeps_string_literal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        a = _src(
            tmp_path,
            "func_a.c",
            'int func_a(void) { puts("func_a"); return 1; }\n',
        )
        _patch_sources(monkeypatch, [a])
        count = rename_function_everywhere(_cfg(tmp_path), a, "func_a", "_func_a", "renamed_fn")
        assert count == 1
        text = (tmp_path / "renamed_fn.c").read_text(encoding="utf-8")
        assert "int renamed_fn(void)" in text
        assert 'puts("func_a")' in text  # literal untouched
