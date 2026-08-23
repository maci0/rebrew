"""End-to-end tests for the rebrew round-trip CLI."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.cli import EXIT_MISMATCH, EXIT_OK
from rebrew.round_trip import _run_round_trip, app

runner = CliRunner()


class TestRoundTripCli:
    def test_help_lists_required_flags(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        for flag in ("--json", "--out", "--dry-run", "--filter", "--strict-catalog", "--target"):
            assert flag in result.stdout

    def test_no_config_errors_cleanly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["--json"])
        # require_config raises typer.Exit; treat any non-zero as success here.
        assert result.exit_code != 0


def _make_fake_cfg(tmp_path: Path) -> SimpleNamespace:
    """Minimal ProjectConfig stand-in for round-trip tests.

    Field names match the canonical ones in ``config.py`` so that production
    code paths can read them without translation.
    """
    binary = tmp_path / "fake.dll"
    # 1 KiB blob with one function at offset 0x100 starting with NOPs.
    binary.write_bytes(b"\x00" * 0x100 + b"\x90\x90\x90\x90\xc3" + b"\x00" * 0xFB)
    src_dir = tmp_path / "src" / "FAKE"
    src_dir.mkdir(parents=True)
    return SimpleNamespace(
        target_name="FAKE",
        target_binary=binary,
        reversed_dir=src_dir,
        image_base=0x10000000,
        dll_exports={},
    )


class TestSplicePipeline:
    def test_empty_project_round_trip_is_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No matched functions → reasm == original → exit 0."""
        cfg = _make_fake_cfg(tmp_path)
        # Stub enumeration + catalog loading — neither has annotated sources to walk.
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))

        code = _run_round_trip(cfg, out=None, no_write=True, symbol_filter=None, json_output=False)
        assert code == EXIT_OK

    def test_compile_drift_marks_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A function in the splice set whose compile result fails must be
        reported and exit non-zero."""
        cfg = _make_fake_cfg(tmp_path)
        fn = SimpleNamespace(
            symbol="_myfunc",
            va=0x10000100,
            size=5,
            status="EXACT",
            path=cfg.reversed_dir / "myfunc.c",
            module="FAKE",
            cflags=["/O2"],
        )
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))
        # _compile_and_extract returns (text, relocs, str_syms, local_labels, ok, detail).
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn, work_dir: (b"", [], {}, {}, False, "cl.exe failed"),
        )

        code = _run_round_trip(cfg, out=None, no_write=True, symbol_filter=None, json_output=False)
        assert code == EXIT_MISMATCH

    def test_allow_naked_appends_define(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--allow-naked must add the REBREW_ALLOW_NAKED define (style-correct
        for the toolchain) to every splice compile — the round-trip-only switch
        that selects the fenced __declspec(naked) branch of naked sources."""
        cfg = _make_fake_cfg(tmp_path)
        cfg.posix_style = False
        fn = SimpleNamespace(
            symbol="_myfunc",
            va=0x10000100,
            size=5,
            status="EXACT",
            path=cfg.reversed_dir / "myfunc.c",
            module="FAKE",
            cflags=["/O2"],
        )
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))
        seen: dict = {}

        def _fake_compile(cfg, fn, work_dir):  # noqa: ARG001
            seen["cflags"] = list(fn.cflags)
            # ok=False avoids the post-compile binary parse (fake.dll is not a
            # real PE) — the cflags capture is what this test asserts.
            return (b"", [], {}, {}, False, "skip")

        monkeypatch.setattr("rebrew.round_trip._compile_and_extract", _fake_compile)

        _run_round_trip(
            cfg, out=None, no_write=True, symbol_filter=None, json_output=False, allow_naked=True
        )
        assert "/DREBREW_ALLOW_NAKED" in seen["cflags"]

        # posix style uses -D (reset the shared fn between calls)
        cfg.posix_style = True
        fn.cflags = ["/O2"]
        _run_round_trip(
            cfg, out=None, no_write=True, symbol_filter=None, json_output=False, allow_naked=True
        )
        assert "-DREBREW_ALLOW_NAKED" in seen["cflags"]

        # without the flag, no define is added
        fn.cflags = ["/O2"]
        seen.clear()
        _run_round_trip(cfg, out=None, no_write=True, symbol_filter=None, json_output=False)
        assert all("ALLOW_NAKED" not in f for f in seen["cflags"])

    def test_allow_naked_reports_fenced_functions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--allow-naked must report the fenced naked functions (the exact set
        that requires REBREW_ALLOW_NAKED for byte-identity) so the reccmp
        recomp build matrix can be checked against it."""
        cfg = _make_fake_cfg(tmp_path)
        cfg.posix_style = True
        fenced_src = cfg.reversed_dir / "naked.c"
        fenced_src.write_text(
            "#ifdef REBREW_ALLOW_NAKED\n"
            "__declspec(naked) void naked(void) { __asm { ret } }\n"
            "#else\n"
            "void naked(void) { /* fallback */ }\n"
            "#endif\n",
            encoding="utf-8",
        )
        plain_src = cfg.reversed_dir / "plain.c"
        plain_src.write_text("int plain(void) { return 0; }\n", encoding="utf-8")
        fn_naked = SimpleNamespace(
            symbol="_naked",
            va=0x10000100,
            size=5,
            status="EXACT",
            path=fenced_src,
            module="FAKE",
            cflags=["/O2"],
        )
        fn_plain = SimpleNamespace(
            symbol="_plain",
            va=0x10000200,
            size=5,
            status="EXACT",
            path=plain_src,
            module="FAKE",
            cflags=["/O2"],
        )
        monkeypatch.setattr(
            "rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn_naked, fn_plain], [], 0)
        )
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))

        def _fake_compile(cfg, fn, work_dir):  # noqa: ARG001
            return (b"", [], {}, {}, False, "skip")

        monkeypatch.setattr("rebrew.round_trip._compile_and_extract", _fake_compile)
        captured: dict = {}
        monkeypatch.setattr("rebrew.round_trip.json_print", lambda d: captured.update(d))

        _run_round_trip(
            cfg, out=None, no_write=True, symbol_filter=None, json_output=True, allow_naked=True
        )
        fenced = captured["fenced_naked"]
        assert fenced["count"] == 1
        assert fenced["vas"] == ["0x10000100"]

    def test_source_is_naked_fenced(self, tmp_path: Path) -> None:
        from rebrew.round_trip import _source_is_naked_fenced

        fenced = tmp_path / "fenced.c"
        fenced.write_text(
            "#ifdef REBREW_ALLOW_NAKED\n__declspec(naked) void f(void) {}\n#endif\n",
            encoding="utf-8",
        )
        assert _source_is_naked_fenced(fenced) is True

        plain = tmp_path / "plain.c"
        plain.write_text("int f(void) { return 0; }\n", encoding="utf-8")
        assert _source_is_naked_fenced(plain) is False

        assert _source_is_naked_fenced(tmp_path / "missing.c") is False

    def test_clean_round_trip_writes_reasm(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Identical compile bytes + correct file offset → reasm hash equals original."""
        cfg = _make_fake_cfg(tmp_path)
        fn = SimpleNamespace(
            symbol="_myfunc",
            va=0x10000100,
            size=5,
            status="EXACT",
            path=cfg.reversed_dir / "myfunc.c",
            module="FAKE",
            cflags=["/O2"],
        )
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))
        # Identical bytes (no relocs) → splice is a byte-level no-op.
        original_slice = cfg.target_binary.read_bytes()[0x100:0x105]
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn, work_dir: (original_slice, [], {}, {}, True, ""),
        )
        # Stub the PE loader so we don't need a real PE to compute file offset.
        from types import SimpleNamespace as SN

        fake_info = SN(text_size=0x100)
        monkeypatch.setattr("rebrew.round_trip.load_binary", lambda p: fake_info)
        monkeypatch.setattr("rebrew.round_trip.va_to_file_offset", lambda info, va: 0x100)

        out = tmp_path / "fake.reasm"
        code = _run_round_trip(cfg, out=out, no_write=False, symbol_filter=None, json_output=False)
        assert code == EXIT_OK
        assert out.exists()
        assert out.read_bytes() == cfg.target_binary.read_bytes()

    @pytest.mark.parametrize(
        ("strict_catalog", "expected_code"),
        [
            pytest.param(False, EXIT_OK, id="gap-is-not-mismatch"),
            pytest.param(True, EXIT_MISMATCH, id="strict-catalog-fails-on-gap"),
        ],
    )
    def test_unresolved_symbol_exit_code(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        strict_catalog: bool,
        expected_code: int,
    ) -> None:
        """Unresolved symbols are skipped by default; --strict-catalog exits non-zero."""
        from rebrew.core.matching import UnresolvedSymbolError
        from rebrew.matcher.parsers import CoffRelocRecord

        cfg = _make_fake_cfg(tmp_path)
        fn = SimpleNamespace(
            symbol="_myfunc",
            va=0x10000100,
            size=5,
            status="EXACT",
            path=cfg.reversed_dir / "myfunc.c",
            module="FAKE",
            cflags=["/O2"],
        )
        original_slice = cfg.target_binary.read_bytes()[0x100:0x105]
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn, work_dir: (
                original_slice,
                [CoffRelocRecord(offset=1, type=0x6, symbol="_missing")],
                {},
                {},
                True,
                "",
            ),
        )

        def _boom(*_a: object, **_k: object) -> bytes:
            raise UnresolvedSymbolError("_missing")

        monkeypatch.setattr("rebrew.round_trip.apply_coff_relocations", _boom)
        monkeypatch.setattr(
            "rebrew.round_trip.load_binary", lambda p: SimpleNamespace(text_size=0x100)
        )

        code = _run_round_trip(
            cfg,
            out=None,
            no_write=True,
            symbol_filter=None,
            json_output=False,
            strict_catalog=strict_catalog,
        )
        assert code == expected_code

    def test_catalog_resolution_drift_exits_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Patched bytes that diverge from the PE original must fail the run."""
        cfg = _make_fake_cfg(tmp_path)
        fn = SimpleNamespace(
            symbol="_myfunc",
            va=0x10000100,
            size=5,
            status="EXACT",
            path=cfg.reversed_dir / "myfunc.c",
            module="FAKE",
            cflags=["/O2"],
        )
        # Compile returns different bytes than the PE slice at 0x100.
        drifted = b"\xde\xad\xbe\xef\x00"
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn, work_dir: (drifted, [], {}, {}, True, ""),
        )
        monkeypatch.setattr(
            "rebrew.round_trip.apply_coff_relocations",
            lambda text, relocs, resolve_va, **kw: text,
        )
        monkeypatch.setattr(
            "rebrew.round_trip.load_binary", lambda p: SimpleNamespace(text_size=0x100)
        )
        monkeypatch.setattr("rebrew.round_trip.va_to_file_offset", lambda info, va: 0x100)

        code = _run_round_trip(cfg, out=None, no_write=True, symbol_filter=None, json_output=False)
        assert code == EXIT_MISMATCH


class TestStringSymbolHelpers:
    def test_sg_key_normalizes(self) -> None:
        from rebrew.round_trip import _sg_key

        assert _sg_key("_$SG123") == "$SG123"
        assert _sg_key("$SG456") == "$SG456"

    def test_resolve_string_in_rdata(self) -> None:
        from rebrew.round_trip import _resolve_string_symbols_in_target

        # target: .rdata at file offset 0x10, VA 0x405000, size 0x20
        target = b"\x00" * 0x10 + b"Hello World\x00" + b"\x00" * 10
        sections = {".rdata": SimpleNamespace(va=0x405000, size=0x20, file_offset=0x10)}
        found = _resolve_string_symbols_in_target(target, {"$SG1": b"Hello World\x00"}, sections)
        assert found == {"$SG1": 0x405000}

    def test_resolve_string_not_found(self) -> None:
        from rebrew.round_trip import _resolve_string_symbols_in_target

        target = b"\x00" * 64
        sections = {".rdata": SimpleNamespace(va=0x405000, size=0x20, file_offset=0x10)}
        found = _resolve_string_symbols_in_target(target, {"$SG1": b"nope\x00"}, sections)
        assert found == {}

    def test_prefix_binds_to_longer_target_string(self) -> None:
        """A literal that is a strict prefix of the target's copy (e.g. the
        source is missing a trailing ``\\n``) binds to the start of the longer
        target string — the address the reloc actually needs."""
        from rebrew.round_trip import _resolve_string_symbols_in_target

        target = b"\x00" * 0x10 + b"Hello World\n\x00" + b"\x00" * 10
        sections = {".rdata": SimpleNamespace(va=0x405000, size=0x20, file_offset=0x10)}
        # "Hello World\x00" (with NUL) is not present; the no-NUL probe
        # "Hello World" binds to the longer string's start at VA 0x405000.
        found = _resolve_string_symbols_in_target(target, {"$SG1": b"Hello World\x00"}, sections)
        assert found == {"$SG1": 0x405000}

    def test_exact_match_preferred_over_prefix(self) -> None:
        """When both the terminated literal and a longer superset exist, the
        exact (terminated) match wins."""
        from rebrew.round_trip import _resolve_string_symbols_in_target

        target = b"\x00" * 0x10 + b"Hello World\x00" + b"Hello World long\x00"
        sections = {".rdata": SimpleNamespace(va=0x405000, size=0x40, file_offset=0x10)}
        found = _resolve_string_symbols_in_target(target, {"$SG1": b"Hello World\x00"}, sections)
        assert found == {"$SG1": 0x405000}

    def test_prefix_not_present_still_empty(self) -> None:
        """A literal absent from the target entirely (even as a prefix probe)
        still yields no binding."""
        from rebrew.round_trip import _resolve_string_symbols_in_target

        target = b"\x00" * 0x10 + b"Goodbye World\x00"
        sections = {".rdata": SimpleNamespace(va=0x405000, size=0x20, file_offset=0x10)}
        found = _resolve_string_symbols_in_target(target, {"$SG1": b"Hello\x00"}, sections)
        assert found == {}

    def test_empty_content_skipped(self) -> None:
        from rebrew.round_trip import _resolve_string_symbols_in_target

        sections = {".rdata": SimpleNamespace(va=0x405000, size=0x20, file_offset=0)}
        found = _resolve_string_symbols_in_target(b"\x00" * 32, {"$SG1": b""}, sections)
        assert found == {}

    def test_mismatch_shape(self) -> None:
        from rebrew.round_trip import _mismatch

        m = _mismatch(
            SimpleNamespace(va=0x1000, name="f", symbol="_f", status="EXACT"), "REASON", "detail"
        )
        assert m["va"] == "0x00001000"
        assert m["symbol"] == "_f"
        assert m["status"] == "EXACT"
        assert m["reason"] == "REASON"
        assert m["detail"] == "detail"

    def test_extract_string_symbols_empty(self, tmp_path: Path) -> None:
        from rebrew.round_trip import _extract_string_symbols

        assert _extract_string_symbols(tmp_path / "none.obj", set()) == {}


class TestLoadCatalogs:
    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(
            dll_exports={0x5000: "ExportFn"},
            reversed_dir=tmp_path / "src",
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
        )

    def test_exports_and_annotations(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.round_trip import _load_catalogs

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True, exist_ok=True)
        (cfg.reversed_dir / "func.c").write_text(
            "// FUNCTION: SERVER 0x10001000\nint func_a(void) { return 1; }\n",
            encoding="utf-8",
        )
        (cfg.reversed_dir / "rebrew-function.toml").write_text(
            '["SERVER.0x10001000"]\nstatus = "EXACT"\n', encoding="utf-8"
        )
        funcs, data = _load_catalogs(cfg)
        assert funcs[0x5000] == "ExportFn"  # from dll_exports
        assert funcs[0x10001000] == "func_a"  # from annotation
        assert data == {}  # no rebrew-data.toml

    def test_data_names_from_data_metadata(self, tmp_path: Path) -> None:
        from rebrew.round_trip import _load_catalogs

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True, exist_ok=True)
        (tmp_path / "rebrew-data.toml").write_text(
            '["SERVER.0x10002000"]\nname = "g_counter"\n', encoding="utf-8"
        )
        _funcs, data = _load_catalogs(cfg)
        assert data == {"g_counter": 0x10002000}

    def test_data_annotation_does_not_shadow_function(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A DATA/GLOBAL annotation must not shadow a same-named function.

        Regression: an IAT import slot annotated as DATA with the same name as
        the real function made REL32 calls resolve to the data slot
        (CreateListenSocket: function@0x10009e60 vs data@0x101deb14).
        """
        from rebrew.core.matching import build_symbol_resolver
        from rebrew.round_trip import _load_catalogs

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True, exist_ok=True)
        (cfg.reversed_dir / "server.c").write_text(
            "// FUNCTION: SERVER 0x1000\n// CreateListenSocket\n"
            "int CreateListenSocket(void) { return 0; }\n\n"
            "// DATA: SERVER 0x2000\n// CreateListenSocket\n"
            "unsigned int CreateListenSocket_slot;\n",
            encoding="utf-8",
        )
        funcs, data = _load_catalogs(cfg)
        assert funcs.get(0x1000) == "CreateListenSocket"
        assert 0x2000 not in funcs
        assert data.get("CreateListenSocket") == 0x2000
        resolver = build_symbol_resolver(funcs, data)
        assert resolver("_CreateListenSocket") == 0x1000  # the function, not the slot

    def test_library_annotation_enters_funcs(self, tmp_path: Path) -> None:
        from rebrew.round_trip import _load_catalogs

        cfg = self._cfg(tmp_path)
        cfg.reversed_dir.mkdir(parents=True, exist_ok=True)
        (cfg.reversed_dir / "library_msvc.h").write_text(
            "// LIBRARY: SERVER 0x3000\n// _strlen\n", encoding="utf-8"
        )
        funcs, _data = _load_catalogs(cfg)
        assert funcs.get(0x3000) == "_strlen"


class TestCollectSpliceSet:
    """Tests for round_trip._collect_splice_set (annotation/metadata partitioning)."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        src = tmp_path / "src"
        src.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            cflags="/O2 /Gd",
        )

    def _write_fn(
        self,
        cfg: SimpleNamespace,
        symbol: str,
        va: int,
        status: str,
        *,
        size: int = 0,
        ann_cflags: str = "",
    ) -> Path:
        """Write a .c file with a FUNCTION annotation plus its metadata entry.

        STATUS always lives in ``rebrew-function.toml`` (never the .c file);
        SIZE/CFLAGS may live in either, mirroring production layouts.
        """
        from rebrew.metadata import update_field, update_source_status

        lines = [f"// FUNCTION: SERVER 0x{va:08x}", f"// SYMBOL: {symbol}"]
        if ann_cflags:
            lines.append(f"// CFLAGS: {ann_cflags}")
        lines.append(f"int {symbol.lstrip('_')}(void) {{ return 0; }}")
        path = cfg.reversed_dir / f"{symbol}.c"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        update_source_status(cfg.metadata_dir, status, "SERVER", va)
        if size:
            update_field(cfg.metadata_dir, va, "size", size, "SERVER")
        return path

    def test_partitions_by_status(self, tmp_path: Path) -> None:
        from rebrew.round_trip import _collect_splice_set

        cfg = self._cfg(tmp_path)
        self._write_fn(cfg, "_exact_fn", 0x10001000, "EXACT", size=32)
        self._write_fn(cfg, "_reloc_fn", 0x10002000, "RELOC", size=16)
        self._write_fn(cfg, "_proven_fn", 0x10003000, "PROVEN")
        self._write_fn(cfg, "_near_fn", 0x10004000, "NEAR_MATCHING")

        splice, proven, other = _collect_splice_set(cfg, None)
        assert [f.symbol for f in splice] == ["_exact_fn", "_reloc_fn"]
        assert [f.symbol for f in proven] == ["_proven_fn"]
        assert other == 1

    def test_missing_metadata_defaults_to_stub(self, tmp_path: Path) -> None:
        """No metadata entry → status defaults to STUB → counted as other."""
        from rebrew.round_trip import _collect_splice_set

        cfg = self._cfg(tmp_path)
        path = cfg.reversed_dir / "_stub.c"
        path.write_text(
            "// FUNCTION: SERVER 0x10001000\nint stub(void) { return 0; }\n",
            encoding="utf-8",
        )
        splice, proven, other = _collect_splice_set(cfg, None)
        assert splice == []
        assert proven == []
        assert other == 1

    def test_symbol_filter_substring(self, tmp_path: Path) -> None:
        from rebrew.round_trip import _collect_splice_set

        cfg = self._cfg(tmp_path)
        self._write_fn(cfg, "_alpha", 0x10001000, "EXACT")
        self._write_fn(cfg, "_beta", 0x10002000, "EXACT")
        splice, _proven, other = _collect_splice_set(cfg, "beta")
        assert [f.symbol for f in splice] == ["_beta"]
        assert other == 0

    def test_cflags_precedence(self, tmp_path: Path) -> None:
        """Metadata cflags > annotation cflags > project-default cflags."""
        from rebrew.metadata import update_field
        from rebrew.round_trip import _collect_splice_set

        cfg = self._cfg(tmp_path)
        # (a) metadata cflags only → wins
        self._write_fn(cfg, "_meta_flags", 0x10001000, "EXACT")
        update_field(cfg.metadata_dir, 0x10001000, "cflags", "/O1 /Gy", "SERVER")
        # (b) annotation CFLAGS in KV block, no metadata → picked up
        self._write_fn(cfg, "_kv_flags", 0x10002000, "EXACT", ann_cflags="/O0")
        # (c) neither → project-default cfg.cflags fallback
        self._write_fn(cfg, "_plain", 0x10003000, "EXACT")

        splice, _proven, _other = _collect_splice_set(cfg, None)
        by_sym = {f.symbol: f for f in splice}
        assert by_sym["_meta_flags"].cflags == ["/O1", "/Gy"]
        assert by_sym["_kv_flags"].cflags == ["/O0"]
        assert by_sym["_plain"].cflags == ["/O2", "/Gd"]

    def test_fn_fields_from_annotation_and_metadata(self, tmp_path: Path) -> None:
        from rebrew.round_trip import _collect_splice_set

        cfg = self._cfg(tmp_path)
        self._write_fn(cfg, "_sized", 0x10001000, "EXACT", size=123)

        splice, _proven, _other = _collect_splice_set(cfg, None)
        assert len(splice) == 1
        fn = splice[0]
        assert fn.symbol == "_sized"
        assert fn.va == 0x10001000
        assert fn.size == 123
        assert fn.status == "EXACT"
        assert fn.module == "SERVER"
        assert fn.path == cfg.reversed_dir / "_sized.c"

    def test_size_zero_when_metadata_missing(self, tmp_path: Path) -> None:
        from rebrew.round_trip import _collect_splice_set

        cfg = self._cfg(tmp_path)
        self._write_fn(cfg, "_nosize", 0x10001000, "EXACT")
        splice, _proven, _other = _collect_splice_set(cfg, None)
        assert splice[0].size == 0


class TestRoundTripGoldenPe:
    """_run_round_trip against a real hand-built PE (only compile is stubbed)."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        import bin_util

        code = b"\x55\x8b\xec\x83\xec\x08\x8b\x45\x08\xc9\xc3" + b"\x90" * (64 - 11)
        binary = tmp_path / "golden.dll"
        binary.write_bytes(bin_util.make_pe(code))
        src = tmp_path / "src" / "SERVER"
        src.mkdir(parents=True, exist_ok=True)
        (src / "myfunc.c").write_text(
            "// FUNCTION: SERVER 0x00401000\n// SYMBOL: _myfunc\nint myfunc(void) { return 0; }\n",
            encoding="utf-8",
        )
        from rebrew.metadata import update_field, update_source_status

        update_source_status(tmp_path, "EXACT", "SERVER", 0x401000)
        update_field(tmp_path, 0x401000, "size", 64, "SERVER")
        return SimpleNamespace(
            image_base=0x400000,
            target_binary=binary,
            target_name="SERVER",
            reversed_dir=src,
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
            dll_exports={},
            iat_thunks=set(),
        )

    def test_round_trip_splices_real_binary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Real PE parsing/VA→offset/splice; only the compiler is stubbed."""
        from rebrew.round_trip import _run_round_trip

        cfg = self._cfg(tmp_path)
        # Real pipeline: parse_obj_symbol_bytes strips trailing NOP padding, so
        # the compile result is the 11 real code bytes — matching the target's
        # trimmed span (the golden blob has 53 trailing NOPs).
        code = b"\x55\x8b\xec\x83\xec\x08\x8b\x45\x08\xc9\xc3"
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn, work_dir: (code, [], {}, {}, True, ""),
        )
        out = tmp_path / "golden.reasm"
        code_ret = _run_round_trip(
            cfg, out=out, no_write=False, symbol_filter=None, json_output=False
        )
        assert code_ret == EXIT_OK
        assert out.exists()
        assert out.read_bytes() == cfg.target_binary.read_bytes()

    def test_round_trip_detects_drift(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Drifted compile bytes (reloc-free) → compile_drift mismatch."""
        from rebrew.round_trip import _run_round_trip

        cfg = self._cfg(tmp_path)
        drifted = b"\xde\xad\xbe\xef" + b"\x00" * 60
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn, work_dir: (drifted, [], {}, {}, True, ""),
        )
        code_ret = _run_round_trip(
            cfg, out=None, no_write=True, symbol_filter=None, json_output=False
        )
        assert code_ret == EXIT_MISMATCH


class TestPaddingInclusiveSize:
    def test_padding_inclusive_size_splices_ok(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SIZE including trailing NOP padding must not false-'oversize'.

        Regression: cm_ExAllocThemaPredigt has SIZE 176 but compiles to 172
        (4 trailing padding bytes in the target). round-trip required
        len(compiled) >= SIZE and reported 'oversize'; test/verify (which
        trim trailing padding) pass such functions.
        """
        blob = b"\x00" * 0x100 + b"\xc3\x90\x90\x90\x90" + b"\x00" * 0xFB
        binary = tmp_path / "fake.dll"
        binary.write_bytes(blob)
        cfg = SimpleNamespace(
            target_name="FAKE",
            target_binary=binary,
            reversed_dir=tmp_path / "src" / "FAKE",
            image_base=0x10000000,
            dll_exports={},
        )
        fn = SimpleNamespace(
            symbol="_myfunc",
            va=0x10000100,
            size=5,  # 1 byte real code + 4 NOP padding
            status="EXACT",
            path=cfg.reversed_dir / "myfunc.c",
            module="FAKE",
            cflags=["/O2"],
        )
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))
        # The compiler emits only the real code — no trailing padding.
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn, work_dir: (b"\xc3", [], {}, {}, True, ""),
        )
        monkeypatch.setattr(
            "rebrew.round_trip.apply_coff_relocations",
            lambda text, relocs, resolve_va, **kw: text,
        )
        monkeypatch.setattr(
            "rebrew.round_trip.load_binary", lambda p: SimpleNamespace(text_size=0x100)
        )
        monkeypatch.setattr("rebrew.round_trip.va_to_file_offset", lambda info, va: 0x100)

        code = _run_round_trip(cfg, out=None, no_write=True, symbol_filter=None, json_output=False)
        assert code == EXIT_OK

    def test_oversize_still_detected_when_real_code_short(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A genuinely short compile (less than the trimmed function) stays oversize."""
        blob = b"\x00" * 0x100 + b"\x55\x8b\xec\x5d\xc3" + b"\x00" * 0xFB
        binary = tmp_path / "fake.dll"
        binary.write_bytes(blob)
        cfg = SimpleNamespace(
            target_name="FAKE",
            target_binary=binary,
            reversed_dir=tmp_path / "src" / "FAKE",
            image_base=0x10000000,
            dll_exports={},
        )
        fn = SimpleNamespace(
            symbol="_myfunc",
            va=0x10000100,
            size=5,
            status="EXACT",
            path=cfg.reversed_dir / "myfunc.c",
            module="FAKE",
            cflags=["/O2"],
        )
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))
        # Compiled is 2 bytes but the real function is 5 — genuine oversize.
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn, work_dir: (b"\x55\x8b", [], {}, {}, True, ""),
        )
        monkeypatch.setattr(
            "rebrew.round_trip.apply_coff_relocations",
            lambda text, relocs, resolve_va, **kw: text,
        )
        monkeypatch.setattr(
            "rebrew.round_trip.load_binary", lambda p: SimpleNamespace(text_size=0x100)
        )
        monkeypatch.setattr("rebrew.round_trip.va_to_file_offset", lambda info, va: 0x100)

        code = _run_round_trip(cfg, out=None, no_write=True, symbol_filter=None, json_output=False)
        assert code == EXIT_MISMATCH

    def test_oversize_detected_when_compile_longer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A compile LONGER than the target's real code span must fail too —
        its tail would be silently dropped by the splice, so it is not
        verified."""
        blob = b"\x00" * 0x100 + b"\x55\x8b\xec\x5d\xc3" + b"\x00" * 0xFB
        binary = tmp_path / "fake.dll"
        binary.write_bytes(blob)
        cfg = SimpleNamespace(
            target_name="FAKE",
            target_binary=binary,
            reversed_dir=tmp_path / "src" / "FAKE",
            image_base=0x10000000,
            dll_exports={},
        )
        fn = SimpleNamespace(
            symbol="_myfunc",
            va=0x10000100,
            size=5,
            status="EXACT",
            path=cfg.reversed_dir / "myfunc.c",
            module="FAKE",
            cflags=["/O2"],
        )
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))
        # Compiled is 6 bytes but the real function is 5 (prefix-identical,
        # extra tail) — must be flagged, not silently truncated.
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn, work_dir: (b"\x55\x8b\xec\x5d\xc3\x90", [], {}, {}, True, ""),
        )
        monkeypatch.setattr(
            "rebrew.round_trip.apply_coff_relocations",
            lambda text, relocs, resolve_va, **kw: text,
        )
        monkeypatch.setattr(
            "rebrew.round_trip.load_binary", lambda p: SimpleNamespace(text_size=0x100)
        )
        monkeypatch.setattr("rebrew.round_trip.va_to_file_offset", lambda info, va: 0x100)

        code = _run_round_trip(cfg, out=None, no_write=True, symbol_filter=None, json_output=False)
        assert code == EXIT_MISMATCH


class TestDriftDetail:
    def test_rel32_target_decoding(self) -> None:
        from rebrew.round_trip import _rel32_target

        # call rel32 at fn offset 4: disp bytes 04 00 00 00 → target fn_va + 4 + 4 + 4
        blob = b"\x00" * 4 + b"\x04\x00\x00\x00" + b"\x00" * 4
        assert _rel32_target(blob, 4, 0x10000000) == 0x1000000C

    def test_rel32_target_out_of_range(self) -> None:
        from rebrew.round_trip import _rel32_target

        assert _rel32_target(b"\x00" * 2, 4, 0x1000) is None

    def test_target_name_lookup(self) -> None:
        from rebrew.round_trip import _target_name

        funcs = {0x1000: "foo", 0x2000: "bar"}
        assert _target_name(funcs, 0x1000) == "foo"
        assert _target_name(funcs, 0x9999) == ""
        assert _target_name(funcs, None) == "?"

    def test_drift_detail_names_call_targets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A diff inside a REL32 reloc reports both call targets by name."""
        blob = b"\x00" * 0x100 + b"\xe8\x00\x00\x00\x00" + b"\x00" * 0xFB
        binary = tmp_path / "fake.dll"
        binary.write_bytes(blob)
        cfg = SimpleNamespace(
            target_name="FAKE",
            target_binary=binary,
            reversed_dir=tmp_path / "src" / "FAKE",
            image_base=0x10000000,
            dll_exports={},
        )
        fn = SimpleNamespace(
            symbol="_myfunc",
            va=0x10000100,
            size=5,
            status="EXACT",
            path=cfg.reversed_dir / "myfunc.c",
            module="FAKE",
            cflags=["/O2"],
        )
        from rebrew.matcher.parsers import CoffRelocRecord

        reloc = CoffRelocRecord(offset=1, type=0x14, symbol="_callee")

        def _fake_compile(cfg, fn, work_dir):
            # Source encodes call disp 0x10 → target 0x10000105 + 0x10 = 0x10000115
            return (b"\xe8\x10\x00\x00\x00", [reloc], {}, {}, True, "")

        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], [], 0))
        monkeypatch.setattr(
            "rebrew.round_trip._load_catalogs", lambda cfg: ({0x10000115: "_callee"}, {})
        )
        monkeypatch.setattr("rebrew.round_trip._compile_and_extract", _fake_compile)
        monkeypatch.setattr(
            "rebrew.round_trip.apply_coff_relocations",
            lambda text, relocs, resolve_va, **kw: text,
        )
        monkeypatch.setattr(
            "rebrew.round_trip.load_binary", lambda p: SimpleNamespace(text_size=0x100)
        )
        monkeypatch.setattr("rebrew.round_trip.va_to_file_offset", lambda info, va: 0x100)

        captured: dict[str, object] = {}

        def _capture_mismatch(fn, reason, detail):
            captured["detail"] = detail
            return {
                "symbol": fn.symbol,
                "va": "0x10000100",
                "status": "EXACT",
                "reason": reason,
                "detail": detail,
            }

        monkeypatch.setattr("rebrew.round_trip._mismatch", _capture_mismatch)
        _run_round_trip(cfg, out=None, no_write=True, symbol_filter=None, json_output=False)
        detail = captured.get("detail")
        assert isinstance(detail, str)
        assert "reloc@0x1" in detail
        assert "source → 0x10000115 (_callee)" in detail
        assert "target → 0x10000105" in detail  # original blob: call → next-IP(0x10000105) + 0


class TestListName:
    def test_lists_function_list_names(self, tmp_path: Path) -> None:
        from rebrew.round_trip import _list_name

        cfg = SimpleNamespace(
            function_list=str(tmp_path / "functions.txt"),
        )
        (tmp_path / "functions.txt").write_text(
            "  0x1001a286     19  fcn.1001a286\n", encoding="utf-8"
        )
        assert _list_name(cfg, 0x1001A286) == "fcn.1001a286"
        assert _list_name(cfg, 0x999999) == ""
        assert _list_name(cfg, None) == ""

    def test_missing_function_list_returns_empty(self, tmp_path: Path) -> None:
        from rebrew.round_trip import _list_name

        cfg = SimpleNamespace(function_list=str(tmp_path / "nope.txt"))
        assert _list_name(cfg, 0x1000) == ""


class TestReasonCounts:
    """The JSON report aggregates skipped/mismatch reasons for at-a-glance
    triage (e.g. "92 skipped: 85 unresolved_symbol, ...")."""

    def test_reason_counts_aggregate(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import json

        from rebrew.core.matching import UnresolvedSymbolError
        from rebrew.matcher.parsers import CoffRelocRecord

        cfg = _make_fake_cfg(tmp_path)
        fn = SimpleNamespace(
            symbol="_myfunc",
            va=0x10000100,
            size=5,
            status="EXACT",
            path=cfg.reversed_dir / "myfunc.c",
            module="FAKE",
            cflags=["/O2"],
        )
        monkeypatch.setattr("rebrew.round_trip.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([fn], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))
        monkeypatch.setattr(
            "rebrew.round_trip._compile_and_extract",
            lambda cfg, fn, work_dir: (
                b"\x90\x90\x90\x90\xc3",
                [CoffRelocRecord(offset=1, type=0x6, symbol="_missing")],
                {},
                {},
                True,
                "",
            ),
        )

        def _boom(*_a: object, **_k: object) -> bytes:
            raise UnresolvedSymbolError("_missing")

        monkeypatch.setattr("rebrew.round_trip.apply_coff_relocations", _boom)
        monkeypatch.setattr(
            "rebrew.round_trip.load_binary", lambda p: SimpleNamespace(text_size=0x100)
        )
        result = runner.invoke(app, ["--json", "--dry-run"])
        assert result.exit_code == EXIT_OK
        data = json.loads(result.stdout)
        assert data["reason_counts"] == {"unresolved_symbol": 1}
        assert data["skipped_catalog"][0]["reason"] == "unresolved_symbol"


class TestExtractStringSymbolsMangled:
    """MSVC ??_C@ mangled string constants (static string arrays) must be
    extracted like $SG<N> constants — round-trip functions referencing them
    were previously skipped as unresolved symbols."""

    def test_extracts_c_mangled_string(self, tmp_path: Path) -> None:
        from bin_util import make_coff_obj

        from rebrew.round_trip import _extract_string_symbols

        # Section data: code first, then the string at offset 0x20.
        code = b"\x90" * 0x20 + b"Sending Broadcast\x00\x00"
        sym = "??_C@_0BC@GMNE@Sending?5Broadcast?$AA@"
        obj = make_coff_obj(code, section_symbols=[(sym, 0x20)])
        obj_path = tmp_path / "x.obj"
        obj_path.write_bytes(obj)
        out = _extract_string_symbols(obj_path, {sym})
        assert out == {sym: b"Sending Broadcast\x00"}

    def test_extracts_sg_and_c_mangled(self, tmp_path: Path) -> None:
        from bin_util import make_coff_obj

        from rebrew.round_trip import _extract_string_symbols

        code = b"\x90" * 0x20 + b"sg-string\x00" + b"\x00" * 4 + b"cc-string\x00\x00"
        sg = "??_C@_0BC@AAAA@sg?9string?$AA@"
        cc = "??_C@_0BC@BBBB@cc?9string?$AA@"
        obj = make_coff_obj(code, section_symbols=[(sg, 0x20), (cc, 0x2E)])
        obj_path = tmp_path / "x.obj"
        obj_path.write_bytes(obj)
        out = _extract_string_symbols(obj_path, {sg, cc})
        assert out == {sg: b"sg-string\x00", cc: b"cc-string\x00"}


class TestNameEncodedVa:
    """Ghidra auto-names encode their VA in the trailing hex digits
    (``_g_1003546c``, ``_s_<preview>_1002d9ec``); round-trip uses this as a
    fallback when the catalog cannot resolve a symbol by name."""

    def test_g_symbol_hex_suffix(self) -> None:
        from rebrew.round_trip import _name_encoded_va

        assert _name_encoded_va("_g_1003546c") == 0x1003546C

    def test_s_symbol_preview_suffix(self) -> None:
        from rebrew.round_trip import _name_encoded_va

        assert _name_encoded_va("_s_plt_SetPlantMap____Map_is_not_al_1002d9ec") == 0x1002D9EC

    def test_eight_digit_suffix(self) -> None:
        from rebrew.round_trip import _name_encoded_va

        assert _name_encoded_va("_g_myvar_12345678") == 0x12345678

    def test_nine_digit_suffix_rejected(self) -> None:
        # 9+ trailing hex digits are not a 32-bit VA — the decoder must not
        # truncate the run to 8 and invent a plausible-but-wrong VA.
        from rebrew.round_trip import _name_encoded_va

        assert _name_encoded_va("_g_123456789") is None
        assert _name_encoded_va("_g_abcdef0123456789") is None

    def test_four_digit_suffix_ignored(self) -> None:
        # "_g_timestamp_0b6c" — 4 hex digits is not a VA-sized suffix.
        from rebrew.round_trip import _name_encoded_va

        assert _name_encoded_va("_g_timestamp_0b6c") is None

    def test_plain_name_ignored(self) -> None:
        from rebrew.round_trip import _name_encoded_va

        assert _name_encoded_va("_g_counter") is None
        assert _name_encoded_va("main") is None

    def test_below_image_base_floor_ignored(self) -> None:
        # Sub-0x100000 suffixes are not plausible VAs for this binary's layout.
        from rebrew.round_trip import _name_encoded_va

        assert _name_encoded_va("_g_000355c0") is None

    def test_resolver_fallback_only_on_catalog_miss(self) -> None:
        from rebrew.round_trip import _make_resolver

        resolve_va = _make_resolver({0x1002000: "_target_fn"}, {"_named_data": 0x1003000})
        # Catalog hit for both function and data symbols.
        assert resolve_va("_target_fn") == 0x1002000
        assert resolve_va("_named_data") == 0x1003000
        # Fallback fires only for unknown symbols with a VA-shaped suffix.
        assert resolve_va("_g_1003546c") == 0x1003546C
        # No catalog hit and no VA-shaped suffix → None (caller skips).
        assert resolve_va("_g_counter") is None

    def test_local_labels_resolve_after_catalog_miss(self) -> None:
        from rebrew.round_trip import _make_resolver

        resolve_va = _make_resolver(
            {0x1002000: "_target_fn"},
            {},
            {"$L19774": 0x10017A44, "$L19062": 0x10017A00},
        )
        assert resolve_va("$L19774") == 0x10017A44
        assert resolve_va("$L19062") == 0x10017A00
        # Catalog still wins over the local map when both could match.
        assert resolve_va("_target_fn") == 0x1002000
        # Unknown symbol with a hex suffix still falls through to the VA decode.
        assert resolve_va("_g_1003546c") == 0x1003546C


class TestLocalLabels:
    """``$L<N>`` jump/dispatch tables are emitted into .text right after the
    function; their target VA is ``fn_va + (label_offset - fn_offset)``."""

    def test_maps_same_section_labels(self, tmp_path: Path) -> None:
        from bin_util import make_coff_obj

        from rebrew.round_trip import _extract_local_labels

        code = b"\x90" * 0xB5  # 181 bytes: code + inline jump/dispatch tables
        obj = make_coff_obj(
            code,
            func_symbol="_f",
            func_value=0,
            section_symbols=[("$L19774", 0x94), ("$L19062", 0x50)],
        )
        obj_path = tmp_path / "x.obj"
        obj_path.write_bytes(obj)
        out = _extract_local_labels(obj_path, "_f", 0x100179B0)
        assert out == {"$L19774": 0x10017A44, "$L19062": 0x10017A00}

    def test_fn_offset_shifts_mapping(self, tmp_path: Path) -> None:
        from bin_util import make_coff_obj

        from rebrew.round_trip import _extract_local_labels

        # Function starts at section offset 0x20 (other functions precede it
        # in the same .c file), so label VAs are relative to that.
        obj = make_coff_obj(
            b"\x90" * 0x40,
            func_symbol="_f",
            func_value=0x20,
            section_symbols=[("$L5", 0x38)],
        )
        obj_path = tmp_path / "x.obj"
        obj_path.write_bytes(obj)
        out = _extract_local_labels(obj_path, "_f", 0x10001000)
        assert out == {"$L5": 0x10001018}

    def test_non_dollar_symbols_excluded(self, tmp_path: Path) -> None:
        """Non-``$`` names never enter the local map; ``$``-prefixed same-section
        labels do (the generic compiler-label rule — ``$SG`` strings normally
        live in .rdata and are excluded by the section filter anyway)."""
        from bin_util import make_coff_obj

        from rebrew.round_trip import _extract_local_labels

        obj = make_coff_obj(
            b"\x90" * 0x20,
            func_symbol="_f",
            section_symbols=[("_g_counter", 0x10), ("$SG3", 0x8)],
        )
        obj_path = tmp_path / "x.obj"
        obj_path.write_bytes(obj)
        out = _extract_local_labels(obj_path, "_f", 0x10001000)
        assert out == {"$SG3": 0x10001008}

    def test_cleanup_loop_labels_mapped(self, tmp_path: Path) -> None:
        """``$cleanup_loop$<N>`` is another MSVC ``$``-prefixed .text label
        form (goto/cleanup blocks) with the same offset semantics as ``$L``."""
        from bin_util import make_coff_obj

        from rebrew.round_trip import _extract_local_labels

        obj = make_coff_obj(
            b"\x90" * 0x40,
            func_symbol="_f",
            func_value=0,
            section_symbols=[("$cleanup_loop$18831", 0x30)],
        )
        obj_path = tmp_path / "x.obj"
        obj_path.write_bytes(obj)
        out = _extract_local_labels(obj_path, "_f", 0x10017000)
        assert out == {"$cleanup_loop$18831": 0x10017030}

    def test_missing_fn_symbol_returns_empty(self, tmp_path: Path) -> None:
        from bin_util import make_coff_obj

        from rebrew.round_trip import _extract_local_labels

        obj_path = tmp_path / "x.obj"
        obj_path.write_bytes(make_coff_obj(b"\x90" * 0x10))
        assert _extract_local_labels(obj_path, "_nope", 0x10001000) == {}

    def test_referenced_scopes_to_own_labels(self, tmp_path: Path) -> None:
        """With a referenced set, only the function's own reloc symbols are
        mapped — a sibling function's ``$L`` label (same section, different
        layout) must not enter the map."""
        from bin_util import make_coff_obj

        from rebrew.round_trip import _extract_local_labels

        obj = make_coff_obj(
            b"\x90" * 0x80,
            func_symbol="_f",
            func_value=0,
            section_symbols=[("$L100", 0x60), ("$L999", 0x20)],
        )
        obj_path = tmp_path / "x.obj"
        obj_path.write_bytes(obj)
        # Only $L100 is referenced by this function's relocs.
        out = _extract_local_labels(obj_path, "_f", 0x10001000, referenced={"$L100"})
        assert out == {"$L100": 0x10001060}


class TestFixHeaders:
    """--fix-headers patches the reasm PE header and reports parity."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        from types import SimpleNamespace as SN

        return SN(
            target_name="SERVER",
            target_binary=tmp_path / "golden.dll",
            reversed_dir=tmp_path / "src" / "SERVER",
            metadata_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
            root=tmp_path,
            dll_exports={},
            iat_thunks=set(),
            image_base=0x10000000,
            text_va=0x10001000,
            text_raw_offset=0x200,
        )

    def _run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, json_output: bool) -> Path:
        from bin_util import make_pe

        from rebrew.round_trip import _run_round_trip

        binary = tmp_path / "golden.dll"
        binary.write_bytes(make_pe(b"\x55\x8b\xec\xc3", text_va=0x1000, image_base=0x10000000))
        cfg = self._cfg(tmp_path)
        cfg.target_binary = binary
        (cfg.reversed_dir).mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))
        out = tmp_path / "r.reasm"
        _run_round_trip(
            cfg,
            out=out,
            no_write=False,
            symbol_filter=None,
            json_output=json_output,
            fix_headers=True,
        )
        return out

    def test_header_parity_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        import json

        self._run(tmp_path, monkeypatch, json_output=True)
        data = json.loads(capsys.readouterr().out)
        parity = data.get("header_parity")
        assert parity, "header_parity missing from --fix-headers report"
        fields = {p["field"] for p in parity}
        assert "dll_characteristics" in fields
        assert "linker_version_major" in fields

    def test_fix_headers_with_original_values_is_identical(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With no [link] config, every patchable field is copied from the
        original — the reasm differs only in the (now valid) checksum."""
        from bin_util import make_pe

        from rebrew.pe_headers import _pe_checksum, read_pe_header_fields

        binary = tmp_path / "golden.dll"
        original = make_pe(b"\x55\x8b\xec\xc3", text_va=0x1000, image_base=0x10000000)
        binary.write_bytes(original)
        out = self._run(tmp_path, monkeypatch, json_output=False)

        reasm = out.read_bytes()
        orig_fields = read_pe_header_fields(original)
        reasm_fields = read_pe_header_fields(reasm)
        assert orig_fields is not None and reasm_fields is not None
        # Every patchable field now matches the original (checksum is
        # recomputed, not copied — asserted separately below).
        from rebrew.pe_headers import _PATCHABLE

        for label in _PATCHABLE - {"checksum"}:
            assert reasm_fields.values[label] == orig_fields.values[label], label
        # The checksum was recomputed and is now valid.
        assert reasm_fields.values["checksum"] == _pe_checksum(reasm)

    def test_config_link_values_applied(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """[link] configured values (e.g. TSAWARE) override the original's."""
        from bin_util import make_pe

        from rebrew.config import LinkConfig
        from rebrew.pe_headers import read_pe_header_fields

        binary = tmp_path / "golden.dll"
        binary.write_bytes(make_pe(b"\x55\x8b\xec\xc3", text_va=0x1000, image_base=0x10000000))
        cfg = self._cfg(tmp_path)
        cfg.link = LinkConfig(tsaware=True, linker_version="5.12", timestamp=0x37F6657C)
        (cfg.reversed_dir).mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr("rebrew.round_trip._collect_splice_set", lambda cfg, f: ([], [], 0))
        monkeypatch.setattr("rebrew.round_trip._load_catalogs", lambda cfg: ({}, {}))
        out = tmp_path / "r.reasm"
        from rebrew.round_trip import _run_round_trip

        _run_round_trip(
            cfg, out=out, no_write=False, symbol_filter=None, json_output=False, fix_headers=True
        )
        fields = read_pe_header_fields(out.read_bytes())
        assert fields is not None
        assert fields.values["dll_characteristics"] == 0x8000
        assert fields.values["linker_version_major"] == 5
        assert fields.values["linker_version_minor"] == 12
        assert fields.values["timestamp"] == 0x37F6657C

    def test_malformed_link_version_warns(self, tmp_path: Path) -> None:
        """A malformed `linker_version` ("5", "abc") must warn, not silently
        drop the patch — the old `except ValueError: pass` made --fix-headers
        skip the field while the parity report showed an unexplained mismatch
        (config-review F7)."""
        import pytest

        from rebrew.config import LinkConfig

        with pytest.warns(UserWarning, match="not a valid 'N.N' version"):
            fields = LinkConfig(linker_version="5").to_patch_fields()
        assert "linker_version_major" not in fields

        with pytest.warns(UserWarning, match="not a valid 'N.N' version"):
            fields = LinkConfig(os_version="abc").to_patch_fields()
        assert "os_version_major" not in fields

        # Valid forms still parse.
        fields = LinkConfig(linker_version="5.12", subsystem_version="4.0").to_patch_fields()
        assert fields["linker_version_major"] == 5
        assert fields["linker_version_minor"] == 12
        assert fields["subsystem_version_major"] == 4
        assert fields["subsystem_version_minor"] == 0
