"""Tests for rebrew.utils."""

import contextlib
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from rebrew.utils import (
    atomic_write_bytes,
    atomic_write_text,
    clear_source_text_memo,
    clip_span,
    container_runtime,
    detect_source_encoding,
    filename_component,
    floor_pct,
    is_safe_c_ident,
    load_tomllib,
    merged_span_bytes,
    read_compile_source,
    read_source_text,
    read_toml_text,
    run_process_group,
    strip_bidi_format,
)


def test_container_runtime_defaults_to_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REBREW_CONTAINER_RUNTIME", raising=False)
    assert container_runtime() == "docker"


def test_load_tomllib_strips_utf8_bom(tmp_path: Path) -> None:
    """BOM-prefixed TOML must parse (Notepad / some IDEs write EF BB BF)."""
    path = tmp_path / "x.toml"
    path.write_bytes(b'\xef\xbb\xbfname = "ok"\n')
    assert read_toml_text(path) == 'name = "ok"\n'
    assert load_tomllib(path) == {"name": "ok"}


def test_container_runtime_empty_treated_as_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REBREW_CONTAINER_RUNTIME", "   ")
    assert container_runtime() == "docker"


def test_container_runtime_honors_podman(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REBREW_CONTAINER_RUNTIME", "podman")
    assert container_runtime() == "podman"


def test_container_runtime_invalid_chars_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REBREW_CONTAINER_RUNTIME", "docker; rm -rf /")
    with pytest.raises(ValueError, match="contains invalid characters"):
        container_runtime()


def test_container_runtime_unknown_name_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REBREW_CONTAINER_RUNTIME", "dockre")
    with pytest.raises(ValueError, match="is not a known container runtime"):
        container_runtime()


def test_container_runtime_accepts_binary_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REBREW_CONTAINER_RUNTIME", "/opt/bin/ctr-runc")
    assert container_runtime() == "/opt/bin/ctr-runc"


def test_atomic_write_text_success(tmp_path: Path) -> None:
    f = tmp_path / "test.txt"
    atomic_write_text(f, "hello world")
    assert f.read_text() == "hello world"
    assert list(tmp_path.iterdir()) == [f]


def test_atomic_write_text_preserves_lf(tmp_path: Path) -> None:
    """Writes must not translate ``\\n`` to ``os.linesep`` (Windows default)."""
    f = tmp_path / "lf.txt"
    atomic_write_text(f, "a\nb\n")
    assert f.read_bytes() == b"a\nb\n"
    assert list(tmp_path.iterdir()) == [f]


def test_atomic_write_text_ignores_planted_symlink(tmp_path: Path) -> None:
    """A symlink planted at the target is replaced, not written through."""
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched")
    link = tmp_path / "link.txt"
    link.symlink_to(outside)
    atomic_write_text(link, "payload")
    assert outside.read_text() == "untouched"
    assert not link.is_symlink()
    assert link.read_text() == "payload"


def test_atomic_write_bytes_ignores_planted_symlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"untouched")
    link = tmp_path / "link.bin"
    link.symlink_to(outside)
    atomic_write_bytes(link, b"payload")
    assert outside.read_bytes() == b"untouched"
    assert link.read_bytes() == b"payload"


def test_filename_component_is_one_safe_component() -> None:
    assert filename_component("sub/dir/evil") == "sub_dir_evil"
    assert filename_component("/etc/passwd") == "_etc_passwd"
    assert filename_component("..").startswith("sym_")
    assert "/" not in filename_component("../../x")
    assert filename_component("sym") == "sym"
    assert filename_component("").startswith("sym_")
    assert len(filename_component("a" * 500)) <= 200


def test_atomic_write_text_overwrite(tmp_path: Path) -> None:
    f = tmp_path / "test.txt"
    f.write_text("old")
    atomic_write_text(f, "new")
    assert f.read_text() == "new"


def test_atomic_write_text_identical_is_noop(tmp_path: Path) -> None:
    """A second write of the same bytes must not bump mtime (verify cache /
    git dirty).  Re-runs of catalog/gen-stubs/exports hit this path."""
    f = tmp_path / "same.txt"
    atomic_write_text(f, "stable\n")
    before = f.stat().st_mtime_ns
    atomic_write_text(f, "stable\n")
    assert f.read_text(encoding="utf-8") == "stable\n"
    assert f.stat().st_mtime_ns == before


def test_atomic_write_bytes_identical_is_noop(tmp_path: Path) -> None:
    """A second write of the same bytes must not bump mtime.

    ``postlink``, round-trip reassembly, and report sidecars all republish
    through :func:`atomic_write_bytes`.  A converged re-run has to leave the
    file alone; a different payload still replaces it.
    """
    from rebrew.utils import atomic_write_bytes

    f = tmp_path / "same.bin"
    atomic_write_bytes(f, b"stable")
    os.utime(f, ns=(1_000_000_000, 1_000_000_000))
    atomic_write_bytes(f, b"stable")
    assert f.read_bytes() == b"stable"
    assert f.stat().st_mtime_ns == 1_000_000_000
    atomic_write_bytes(f, b"changed")
    assert f.read_bytes() == b"changed"
    assert f.stat().st_mtime_ns != 1_000_000_000


def test_atomic_write_text_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    f = tmp_path / "test.txt"

    # Mock os.replace to fail to simulate crash during write
    def mock_replace(*args, **kwargs):
        raise OSError("Simulated crash")

    monkeypatch.setattr(os, "replace", mock_replace)

    with pytest.raises(OSError, match="Simulated crash"):
        atomic_write_text(f, "bad")

    # File shouldn't be touched/created
    assert not f.exists()
    # Temp file should be cleaned up by the exception handler
    assert list(tmp_path.iterdir()) == []


class TestAtomicWriteLocked:
    def test_leaves_file_readonly(self, tmp_path: Path) -> None:
        from rebrew.utils import atomic_write_locked

        f = tmp_path / "meta.toml"
        atomic_write_locked(f, 'status = "EXACT"\n')
        assert f.read_text() == 'status = "EXACT"\n'
        assert (f.stat().st_mode & 0o777) == 0o444

    def test_failed_relock_is_reported(self, tmp_path: Path, monkeypatch, caplog) -> None:
        """A chmod that fails leaves the store world-writable; say so.

        os.replace installs the temp's 0644 inode, so the trailing chmod is
        the only thing restoring 0444.  A silent failure would leave every
        tool-owned metadata file editable by hand for the rest of the run.
        """
        import logging
        import os

        from rebrew import utils

        f = tmp_path / "meta.toml"
        real_chmod = os.chmod

        def _chmod(path, mode, *a, **kw):
            if Path(path) == f and mode == 0o444:
                raise OSError(30, "Read-only file system")
            return real_chmod(path, mode, *a, **kw)

        monkeypatch.setattr(utils.os, "chmod", _chmod)
        with caplog.at_level(logging.WARNING, logger="rebrew.utils"):
            utils.atomic_write_locked(f, 'status = "EXACT"\n')
        assert f.read_text() == 'status = "EXACT"\n'
        assert any("could not re-lock" in r.message for r in caplog.records)

    def test_rewrite_works_via_chmod_before(self, tmp_path: Path) -> None:
        """Repeated tool writes chmod writable before touching, so the lock
        never blocks the sanctioned path."""
        from rebrew.utils import atomic_write_locked

        f = tmp_path / "meta.toml"
        for i in range(3):
            atomic_write_locked(f, f"n = {i}\n")
            assert f.read_text() == f"n = {i}\n"
            assert (f.stat().st_mode & 0o777) == 0o444

    def test_direct_edit_fails_permission_denied(self, tmp_path: Path) -> None:
        """A hand edit of a locked file fails with Permission denied — the
        guard that stops agents from touching metadata directly."""
        import os

        if os.name != "posix":
            pytest.skip("permission semantics are POSIX-specific")
        from rebrew.utils import atomic_write_locked

        f = tmp_path / "meta.toml"
        atomic_write_locked(f, 'status = "EXACT"\n')
        with pytest.raises(PermissionError):
            f.write_text('status = "STUB"\n')

    def test_failed_rewrite_re_locks_readonly(self, tmp_path: Path, monkeypatch) -> None:
        """A write failure after chmod-writable must re-lock the existing file.

        Without the re-lock, a disk-full or interrupt left tool-owned metadata
        world-writable and broke the hand-edit guard.
        """
        import os

        if os.name != "posix":
            pytest.skip("permission semantics are POSIX-specific")
        from rebrew import utils as utils_mod
        from rebrew.utils import atomic_write_locked

        f = tmp_path / "meta.toml"
        atomic_write_locked(f, 'status = "EXACT"\n')
        assert (f.stat().st_mode & 0o777) == 0o444

        def _boom(filepath: Path, text: str, encoding: str = "utf-8") -> None:
            raise OSError("simulated write failure")

        monkeypatch.setattr(utils_mod, "atomic_write_text", _boom)
        with pytest.raises(OSError, match="simulated write failure"):
            atomic_write_locked(f, 'status = "STUB"\n')
        assert f.read_text() == 'status = "EXACT"\n'
        assert (f.stat().st_mode & 0o777) == 0o444


# ---------------------------------------------------------------------------
# filter_wine_stderr (canonical implementation in rebrew.compile)
# ---------------------------------------------------------------------------


class TestFilterWineStderr:
    def test_strips_wine_noise(self) -> None:
        from rebrew.compile import filter_wine_stderr

        noisy = "0042:err:ntdll:something broken\nreal error: missing ;\n"
        result = filter_wine_stderr(noisy)
        assert "err:ntdll" not in result
        assert "real error: missing ;" in result

    def test_strips_fixme_winediag(self) -> None:
        from rebrew.compile import filter_wine_stderr

        result = filter_wine_stderr("0042:fixme:winediag:test\nactual output")
        assert "fixme" not in result
        assert "actual output" in result

    def test_empty_string(self) -> None:
        from rebrew.compile import filter_wine_stderr

        assert filter_wine_stderr("") == ""

    def test_strips_libegl_dri3_noise(self) -> None:
        """Headless Xvfb compiles emit libEGL/DRI3 display noise with no
        [hex]: prefix — it must be stripped so a real compile error is not
        drowned (seen on wine-runtime MSVC 4.0/5.0 under Xvfb)."""
        from rebrew.compile import filter_wine_stderr

        noisy = (
            "libEGL warning: DRI3 error: Could not get DRI3 device\n"
            "libEGL warning: Ensure your X server supports DRI3 to get accelerated rendering\n"
            "f.c(3) : error C2143: syntax error\n"
        )
        result = filter_wine_stderr(noisy)
        assert "libEGL" not in result
        assert "DRI3" not in result
        assert "error C2143" in result


class TestFoldIdent:
    def test_nfd_matches_nfc_and_sharp_s_matches_ss(self) -> None:
        from rebrew.utils import fold_ident

        assert fold_ident("CAF\u00c9") == fold_ident("CAFE\u0301")
        assert fold_ident("stra\u00dfe") == fold_ident("STRASSE") == "strasse"
        assert fold_ident("SERVER") == fold_ident("server")


class TestAsciiSlug:
    def test_accents_keep_their_base_letter(self) -> None:
        from rebrew.utils import ascii_slug

        assert ascii_slug("Café") == "cafe"
        assert ascii_slug("Über") == "uber"
        assert ascii_slug("CAFÉ") == ascii_slug("CAFE\u0301") == "cafe"

    def test_sharp_s_expands(self) -> None:
        from rebrew.utils import ascii_slug

        assert ascii_slug("straße") == ascii_slug("STRASSE") == "strasse"

    def test_no_latin_left_is_empty_not_a_prefix(self) -> None:
        from rebrew.utils import ascii_slug

        assert ascii_slug("日本語") == ""
        assert ascii_slug("🎮") == ""


class TestSafeShlexSplit:
    def test_normal(self) -> None:
        from rebrew.utils import safe_shlex_split

        assert safe_shlex_split('/O2 "/I with space" /Gd') == ["/O2", "/I with space", "/Gd"]

    def test_unbalanced_quotes_fallback(self) -> None:
        from rebrew.utils import safe_shlex_split

        assert safe_shlex_split('/O2 "unbalanced /Gd') == ["/O2", '"unbalanced', "/Gd"]


class TestWatchFiles:
    def test_failed_run_reported_then_continues(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failing retest is reported (swallowed) and the loop keeps watching."""
        import time

        from rebrew.utils import watch_files

        f = tmp_path / "f.c"
        f.write_text("v1", encoding="utf-8")
        calls = {"n": 0}
        sleeps = {"n": 0}

        def _retest() -> None:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("compile failed")

        def _sleep(s: float) -> None:
            sleeps["n"] += 1
            if sleeps["n"] == 1:
                f.write_text("v2", encoding="utf-8")  # first change → failing run
            elif sleeps["n"] == 2:
                f.write_text("v3", encoding="utf-8")  # second change → ok run
            else:
                raise KeyboardInterrupt

        monkeypatch.setattr(time, "sleep", _sleep)
        # watch_files catches KeyboardInterrupt itself ("Watch stopped.").
        watch_files([f], _retest, interval=0.01)
        # Retest ran at least twice; the first failure was swallowed.
        assert calls["n"] >= 2


class TestStripCommentBlocks:
    def test_string_literal_slash_star_survives(self) -> None:
        from rebrew.utils import strip_comment_blocks

        src = 'const char *s = "a/*b";\nint code(void);\n'
        assert strip_comment_blocks(src) == 'const char *s = "a/*b";\nint code(void);'

    def test_other_quote_kind_inside_literal_does_not_close_it(self) -> None:
        from rebrew.utils import strip_comment_blocks

        src = "if (c == '\"') x = 1; /* a */\nconst char *s = \"it's\"; /* b */\n"
        assert strip_comment_blocks(src) == ("if (c == '\"') x = 1; \nconst char *s = \"it's\"; ")

    def test_same_line_comment_keeps_trailing_code(self) -> None:
        from rebrew.utils import strip_comment_blocks

        src = "int x = 1 /* init */ + 2;\n"
        stripped = strip_comment_blocks(src)
        assert "+ 2;" in stripped
        assert "init" not in stripped

    def test_multi_line_block_removed_code_kept(self) -> None:
        from rebrew.utils import strip_comment_blocks

        src = "/* a\n * b\n */\nint x;\n"
        assert strip_comment_blocks(src) == "int x;"

    def test_pointer_deref_not_mistaken_for_comment(self) -> None:
        from rebrew.utils import strip_comment_blocks

        assert strip_comment_blocks("*ptr = x;") == "*ptr = x;"

    def test_orphaned_continuation_lines_dropped(self) -> None:
        from rebrew.utils import strip_comment_blocks

        src = "*    Size: 26B\n*    Symbol: _a\nint code(void);\n"
        assert strip_comment_blocks(src) == "int code(void);"

    def test_code_after_multiline_block_close_kept(self) -> None:
        from rebrew.utils import strip_comment_blocks

        src = "/* a\n * b\n */ int x;\n"
        stripped = strip_comment_blocks(src)
        assert "int x;" in stripped
        assert "b" not in stripped.split("int x;")[0]

    def test_multiple_same_line_comments(self) -> None:
        from rebrew.utils import strip_comment_blocks

        src = "a = b /* c */ + d /* e */;\n"
        stripped = strip_comment_blocks(src)
        assert "a = b" in stripped and "+ d" in stripped and ";" in stripped
        assert "/*" not in stripped and "*/" not in stripped

    def test_line_comment_slash_star_does_not_open_block(self) -> None:
        from rebrew.utils import strip_comment_blocks

        src = "int x; // /* note\nint y;\n"
        stripped = strip_comment_blocks(src)
        assert "int x;" in stripped and "int y;" in stripped
        assert "note" not in stripped

    def test_string_slash_slash_preserved(self) -> None:
        from rebrew.utils import strip_comment_blocks

        src = 'const char *s = "a//b";\nint c;\n'
        assert strip_comment_blocks(src) == 'const char *s = "a//b";\nint c;'


class TestAtomicWriteParents:
    def test_creates_missing_parent_dirs(self, tmp_path: Path) -> None:
        from rebrew.utils import atomic_write_text

        target = tmp_path / "deep" / "nested" / "file.txt"
        atomic_write_text(target, "hello")
        assert target.read_text(encoding="utf-8") == "hello"

    def test_star_prefixed_close_line_ends_block(self) -> None:
        """A ` * comment */` closing line must close the block (the orphaned
        `* `-line drop must not swallow it while in_block)."""
        from rebrew.utils import strip_comment_blocks

        src = "/*\n * comment */\nint x;\n"
        assert strip_comment_blocks(src) == "int x;"


# ---------------------------------------------------------------------------
# Source-encoding detection & preservation (R18)
# ---------------------------------------------------------------------------


class TestSourceEncoding:
    """Legacy-encoded C sources must round-trip without U+FFFD corruption."""

    def test_detect_utf8(self) -> None:
        assert detect_source_encoding("int x; // héllo\n".encode()) == "utf-8"

    def test_detect_cp1252(self) -> None:
        # 'é' in cp1252 is a single byte 0xE9, invalid as UTF-8.
        data = "// Café menu\n".encode("cp1252")
        assert detect_source_encoding(data) == "cp1252"

    def test_detect_shift_jis(self) -> None:
        data = "// 日本語コメント\n".encode("shift_jis")
        assert detect_source_encoding(data) == "shift_jis"

    def test_detect_utf8_bom_is_sig(self) -> None:
        assert detect_source_encoding(b"\xef\xbb\xbfint x;\n") == "utf-8-sig"

    def test_bom_leading_marker_parses_and_survives_write_back(self, tmp_path: Path) -> None:
        """A Notepad-saved BOM must not hide the first ``// FUNCTION:`` line."""
        from rebrew.utils import atomic_write_text, read_source_text

        f = tmp_path / "bom.c"
        f.write_bytes(b"\xef\xbb\xbf// FUNCTION: TEST 0x1000\nint f(void) { return 1; }\n")
        text, encoding = read_source_text(f)
        assert not text.startswith("\ufeff")
        assert encoding == "utf-8-sig"
        atomic_write_text(f, text.replace("return 1", "return 2"), encoding=encoding)
        assert (
            f.read_bytes() == b"\xef\xbb\xbf// FUNCTION: TEST 0x1000\nint f(void) { return 2; }\n"
        )

    def test_read_compile_source_preserves_cp1252_bytes(self, tmp_path: Path) -> None:
        """Compile-path read must keep 0xE9 as a surrogate, not Unicode é.

        Concrete input: ``char *s = "Caf\\xe9";`` on disk as cp1252.  Decoding
        via read_source_text then writing UTF-8 would turn the literal into
        UTF-8 ``Caf\\xc3\\xa9`` and break byte-identical MSVC matching.
        """
        f = tmp_path / "legacy.c"
        original = b'char *s = "Caf\xe9";\n'
        f.write_bytes(original)
        text = read_compile_source(f)
        assert "\udce9" in text  # lone surrogate for byte 0xE9
        assert "Café" not in text
        out = tmp_path / "staged.c"
        atomic_write_text(out, text, encoding="utf-8", errors="surrogateescape")
        assert out.read_bytes() == original

    def test_atomic_write_text_surrogateescape_roundtrip(self, tmp_path: Path) -> None:
        """GA best.c writes must accept surrogateescaped compile seeds."""
        f = tmp_path / "best.c"
        text = b"void f(void){int x=\x93;}\n".decode("utf-8", "surrogateescape")
        atomic_write_text(f, text, encoding="utf-8", errors="surrogateescape")
        assert f.read_bytes() == b"void f(void){int x=\x93;}\n"

    def test_read_write_roundtrip_cp1252(self, tmp_path: Path) -> None:
        f = tmp_path / "legacy.c"
        original = b"// FUNCTION: GAME 0x1000\n// Caf\xe9 comment\nint f(void) { return 1; }\n"
        f.write_bytes(original)

        text, encoding = read_source_text(f)
        assert encoding == "cp1252"
        assert "Café" in text
        atomic_write_text(f, text.replace("Café", "Cafe+1"), encoding=encoding)
        # Non-ASCII byte survives byte-for-byte; only the intended edit changed.
        assert f.read_bytes() == original.replace(b"Caf\xe9", b"Cafe+1")

    def test_read_write_roundtrip_shift_jis(self, tmp_path: Path) -> None:
        f = tmp_path / "jpn.c"
        original = (
            b"// FUNCTION: GAME 0x2000\n// \x93\xfa\x96{\x8c\xea\nint f(void) { return 1; }\n"
        )
        f.write_bytes(original)

        text, encoding = read_source_text(f)
        assert encoding == "shift_jis"
        atomic_write_text(f, text + "// tail\n", encoding=encoding)
        assert f.read_bytes().startswith(original)

    def test_read_write_roundtrip_cp1252_undefined_byte(self, tmp_path: Path) -> None:
        """0x81 is undefined in CP1252: read must not raise, write-back must
        reproduce the file byte-for-byte.

        Regression: the cp1252 fallback decoded 0x81 to U+FFFD, and the
        write-back (``encoding="cp1252"``) then raised UnicodeEncodeError,
        so ``rebrew rename`` crashed on such a source.
        """
        f = tmp_path / "legacy.c"
        # 0x81 followed by a space: not a valid Shift-JIS pair, and not CP1252.
        original = b"// FUNCTION: GAME 0x1000\n// \x81 caf\xe9\n"
        f.write_bytes(original)
        text, encoding = read_source_text(f)
        assert encoding == "latin-1"
        assert "\ufffd" not in text
        atomic_write_text(f, text, encoding=encoding)
        assert f.read_bytes() == original

    def test_read_random_bytes_does_not_crash(self, tmp_path: Path) -> None:
        """Binary garbage in a source file must not crash the tolerant reader."""
        import random

        rng = random.Random(12)
        f = tmp_path / "garbage.c"
        for _ in range(50):
            raw = bytes(rng.randrange(256) for _ in range(400))
            f.write_bytes(raw)
            text, encoding = read_source_text(f)
            assert encoding in {"utf-8", "shift_jis", "cp1252", "latin-1"}
            assert text == raw.decode(encoding, errors="replace")


class TestSourceTextMemo:
    """A cached source must never be served after the file changed, whether
    the change went through :func:`atomic_write_text` or a rebuild that
    pushed the evicted entry out of the LRU."""

    def test_write_invalidates_memo(self, tmp_path: Path) -> None:
        f = tmp_path / "a.c"
        f.write_text("// one\n", encoding="utf-8")
        assert read_source_text(f)[0] == "// one\n"
        atomic_write_text(f, "// two\n", encoding="utf-8")
        assert read_source_text(f)[0] == "// two\n"

    def test_repeated_reads_are_stable(self, tmp_path: Path) -> None:
        f = tmp_path / "b.c"
        f.write_text("// body\n", encoding="utf-8")
        for _ in range(3):
            assert read_source_text(f)[0] == "// body\n"
        clear_source_text_memo()
        assert read_source_text(f)[0] == "// body\n"

    def test_out_of_band_edit_is_not_served_stale(self, tmp_path: Path) -> None:
        f = tmp_path / "c.c"
        f.write_text("// old\n", encoding="utf-8")
        assert read_source_text(f)[0] == "// old\n"
        # A rebuild bumps inode/size, so the stat fingerprint misses the cache.
        f.unlink()
        f.write_text("// new and longer\n", encoding="utf-8")
        assert read_source_text(f)[0] == "// new and longer\n"


class TestWritableTempDir:
    """Sandbox dirs must live on a real-disk, container-visible location —
    and never directly in the home directory (cache sandboxes go under
    $XDG_CACHE_HOME/rebrew/tmp or ~/.cache/rebrew/tmp so stragglers stay
    out of ~)."""

    def test_creates_prefixed_dir(self) -> None:
        from rebrew.utils import writable_temp_dir

        d = writable_temp_dir("rebrew_test_")
        try:
            assert d.is_dir()
            assert d.name.startswith("rebrew_test_")
        finally:
            import shutil

            shutil.rmtree(d, ignore_errors=True)

    def test_created_under_allowed_parents(self) -> None:
        import tempfile

        from rebrew.utils import writable_temp_dir

        xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
        cache_root = Path(xdg) if xdg else Path.home() / ".cache"
        allowed = {
            cache_root / "rebrew" / "tmp",
            Path(__file__).resolve().parents[1] / ".cache",
            Path(tempfile.gettempdir()),
        }
        d = writable_temp_dir("rebrew_test_")
        try:
            assert d.parent in allowed, f"temp dir escaped to {d.parent}"
        finally:
            import shutil

            shutil.rmtree(d, ignore_errors=True)

    def test_honors_xdg_cache_home(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.utils import writable_temp_dir

        xdg = tmp_path / "xdg-cache"
        monkeypatch.setenv("XDG_CACHE_HOME", str(xdg))
        d = writable_temp_dir("rebrew_test_")
        try:
            assert d.parent == xdg / "rebrew" / "tmp"
        finally:
            import shutil

            shutil.rmtree(d, ignore_errors=True)

    def test_ignores_relative_xdg_cache_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A relative XDG_CACHE_HOME is invalid per the XDG spec: use ~/.cache."""
        from rebrew.utils import writable_temp_dir

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("XDG_CACHE_HOME", "rel-cache")
        d = writable_temp_dir("rebrew_test_")
        try:
            assert d.is_absolute()
            assert not (tmp_path / "rel-cache").exists()
        finally:
            import shutil

            shutil.rmtree(d, ignore_errors=True)

    def test_not_directly_in_home(self) -> None:
        from rebrew.utils import writable_temp_dir

        d = writable_temp_dir("rebrew_test_")
        try:
            assert d.parent != Path.home()
        finally:
            import shutil

            shutil.rmtree(d, ignore_errors=True)

    def test_wheel_install_skips_install_tree(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without a source checkout, fall through to the system temp dir,
        never into the interpreter's lib/ (the wheel install prefix)."""
        import tempfile

        import rebrew.utils as utils

        blocked = tmp_path / "file"
        blocked.write_text("")
        monkeypatch.setenv("XDG_CACHE_HOME", str(blocked))
        monkeypatch.setattr(utils, "SOURCE_CHECKOUT", None)
        d = utils.writable_temp_dir("rebrew_test_")
        try:
            assert d.parent == Path(tempfile.gettempdir())
        finally:
            import shutil

            shutil.rmtree(d, ignore_errors=True)

    def test_wheel_install_has_no_vendored_tools(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.utils as utils

        monkeypatch.setattr(utils, "SOURCE_CHECKOUT", None)
        assert utils.find_install_tool("tools/diec") is None

    def test_skips_tmpfs_candidate_when_real_disk_required(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """DOSBox cannot drive a tmpfs mount, so a tmpfs XDG_CACHE_HOME is
        skipped rather than preferred: the probe, not the candidate order,
        enforces the constraint."""
        import tempfile

        import rebrew.utils as utils

        ram = tmp_path / "ram-cache"
        real = tmp_path / "disk-cache"
        monkeypatch.setenv("XDG_CACHE_HOME", str(ram))
        monkeypatch.setattr(utils, "SOURCE_CHECKOUT", None)
        monkeypatch.setattr(utils, "on_ram_filesystem", lambda p: p.is_relative_to(ram))
        monkeypatch.setattr(tempfile, "gettempdir", lambda: str(real))
        d = utils.writable_temp_dir("rebrew_test_", require_real_disk=True)
        try:
            assert d.parent == real
            assert not list(ram.glob("rebrew_test_*"))
        finally:
            import shutil

            shutil.rmtree(d, ignore_errors=True)

    def test_all_tmpfs_candidates_fail_loud(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No real-disk candidate is an error naming the constraint, not a
        tmpfs dir handed back to fail later inside DOSBox."""
        import rebrew.utils as utils

        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "ram"))
        monkeypatch.setattr(utils, "SOURCE_CHECKOUT", None)
        monkeypatch.setattr(utils, "on_ram_filesystem", lambda p: True)
        with pytest.raises(OSError, match="real disk"):
            utils.writable_temp_dir("rebrew_test_", require_real_disk=True)

    def test_tmpfs_tolerated_without_the_requirement(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The plain workdir callers (docker mounts, host compilers) are fine
        on tmpfs, so the default must not reject it."""
        import rebrew.utils as utils

        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
        monkeypatch.setattr(utils, "on_ram_filesystem", lambda p: True)
        d = utils.writable_temp_dir("rebrew_test_")
        try:
            assert d.is_dir()
        finally:
            import shutil

            shutil.rmtree(d, ignore_errors=True)


class TestOnRamFilesystem:
    """The tmpfs probe reads /proc/self/mountinfo and picks the longest
    matching mount point."""

    def test_matches_a_mountinfo_line(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.utils as utils

        table = tmp_path / "mountinfo"
        table.write_text(
            "36 25 0:32 / / rw,relatime - ext4 /dev/sda1 rw\n"
            "99 25 0:99 / /run/user/1000 rw,nosuid - tmpfs tmpfs rw,size=163840k\n"
        )
        monkeypatch.setattr(utils, "_MOUNTINFO", table)
        assert utils.on_ram_filesystem(Path("/run/user/1000/sandbox")) is True
        assert utils.on_ram_filesystem(Path("/var/tmp/sandbox")) is False

    def test_nested_mount_wins_over_parent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A tmpfs bind mount under a real-disk parent must be reported as
        tmpfs: the longest mount point is the one that applies."""
        import rebrew.utils as utils

        table = tmp_path / "mountinfo"
        table.write_text(
            "36 25 0:32 / / rw,relatime - ext4 /dev/sda1 rw\n"
            "99 25 0:99 / /home/u/.cache/ram rw,nosuid - tmpfs tmpfs rw,size=163840k\n"
        )
        monkeypatch.setattr(utils, "_MOUNTINFO", table)
        assert utils.on_ram_filesystem(Path("/home/u/.cache/ram/rebrew")) is True
        assert utils.on_ram_filesystem(Path("/home/u/.cache/disk/rebrew")) is False

    def test_octal_escaped_mount_point(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The kernel escapes space/tab/newline/backslash in a mount point."""
        import rebrew.utils as utils

        table = tmp_path / "mountinfo"
        table.write_text("99 25 0:99 / /mnt/my\\040ram rw,nosuid - tmpfs tmpfs rw\n")
        monkeypatch.setattr(utils, "_MOUNTINFO", table)
        assert utils.on_ram_filesystem(Path("/mnt/my ram/x")) is True

    def test_missing_mountinfo_assumes_real_disk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A namespace without /proc cannot be probed; refusing every dir
        there would break the common case."""
        import rebrew.utils as utils

        monkeypatch.setattr(utils, "_MOUNTINFO", tmp_path / "absent")
        assert utils.on_ram_filesystem(tmp_path) is False


class TestRemoveTempDir:
    def test_removes_dir(self, tmp_path: Path) -> None:
        from rebrew.utils import remove_temp_dir

        d = tmp_path / "sandbox"
        d.mkdir()
        (d / "t.c").write_text("int x;\n")
        remove_temp_dir(d)
        assert not d.exists()

    def test_repeated_cleanup(self, tmp_path: Path) -> None:
        from rebrew.utils import remove_temp_dir

        d = tmp_path / "sandbox"
        d.mkdir()
        (d / "t.c").write_text("int x;\n")
        remove_temp_dir(d, delay=0)
        remove_temp_dir(d, delay=0)
        assert not d.exists()

    def test_retry_after_directory_removed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import errno
        import shutil

        from rebrew.utils import remove_temp_dir

        d = tmp_path / "sandbox"
        d.mkdir()
        (d / "t.c").write_text("int x;\n")
        rmtree = shutil.rmtree
        calls = 0

        def remove_then_fail(path: Path) -> None:
            nonlocal calls
            calls += 1
            rmtree(path)
            raise OSError(errno.EBUSY, "Device or resource busy")

        monkeypatch.setattr(shutil, "rmtree", remove_then_fail)
        remove_temp_dir(d, retries=2, delay=0)
        assert calls == 2
        assert not d.exists()

    def test_raises_when_never_removable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import shutil

        from rebrew.utils import remove_temp_dir

        d = tmp_path / "sandbox"
        d.mkdir()

        def always_busy(*args: object, **kwargs: object) -> None:
            raise OSError("Device or resource busy")

        monkeypatch.setattr(shutil, "rmtree", always_busy)
        with pytest.raises(OSError, match="busy"):
            remove_temp_dir(d, retries=1)


class TestParseIntLiteral:
    def test_hex_prefix(self) -> None:
        from rebrew.utils import parse_int_literal

        assert parse_int_literal("0x10") == 16
        assert parse_int_literal("0X1F") == 31
        assert parse_int_literal("-0x10") == -16
        assert parse_int_literal("+0x10") == 16

    def test_decimal_by_default(self) -> None:
        from rebrew.utils import parse_int_literal

        assert parse_int_literal("10") == 10

    def test_explicit_base(self) -> None:
        from rebrew.utils import parse_int_literal

        assert parse_int_literal("10", base=16) == 16
        assert parse_int_literal("0x10", base=8) == 16

    def test_strips_whitespace(self) -> None:
        from rebrew.utils import parse_int_literal

        assert parse_int_literal("  12 ") == 12

    def test_invalid_raises(self) -> None:
        from rebrew.utils import parse_int_literal

        with pytest.raises(ValueError, match="invalid literal for int"):
            parse_int_literal("nope")
        with pytest.raises(ValueError, match="invalid literal for int"):
            parse_int_literal("")


class TestParseCIntegerLiteral:
    def test_c_radix_and_suffix(self) -> None:
        from rebrew.utils import parse_c_integer_literal

        assert parse_c_integer_literal("0x10") == 16
        assert parse_c_integer_literal("0x10u") == 16
        assert parse_c_integer_literal("0x10UL") == 16
        assert parse_c_integer_literal("010") == 8
        assert parse_c_integer_literal("010u") == 8
        assert parse_c_integer_literal("10") == 10
        assert parse_c_integer_literal("08") == 8
        assert parse_c_integer_literal("-0x10") == -16

    def test_rejects_non_integers(self) -> None:
        from rebrew.utils import parse_c_integer_literal

        with pytest.raises(ValueError, match="invalid literal for int"):
            parse_c_integer_literal("N")
        with pytest.raises(ValueError, match="not a C integer constant"):
            parse_c_integer_literal("'a'")
        with pytest.raises(ValueError, match="not a C integer constant"):
            parse_c_integer_literal("")
        with pytest.raises(ValueError, match="not a C integer constant"):
            parse_c_integer_literal("0x")
        with pytest.raises(ValueError, match="invalid literal for int"):
            parse_c_integer_literal("1.5")


class TestTomlWriteRecovery:
    @pytest.mark.parametrize("store", ["functions", "data"])
    @pytest.mark.parametrize("failure", ["read", "backup"])
    def test_failed_recovery_does_not_overwrite_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, store: str, failure: str
    ) -> None:
        from rebrew.data_metadata import set_data_field
        from rebrew.metadata import update_field

        path = tmp_path / f"rebrew-{store}.toml"
        original = b"{broken" if failure == "backup" else b'["SERVER.0x2000"]\nsize = 80\n'
        path.write_bytes(original)
        error = PermissionError(f"{failure} denied for {path}")
        if failure == "read":
            read_text = Path.read_text

            def _read(self: Path, *args: Any, **kwargs: Any) -> str:
                if self == path:
                    raise error
                return read_text(self, *args, **kwargs)

            monkeypatch.setattr(Path, "read_text", _read)
        else:
            replace = os.replace

            def _replace(src: Path, dst: Path) -> None:
                if src == path:
                    raise error
                replace(src, dst)

            monkeypatch.setattr(os, "replace", _replace)

        writer = update_field if store == "functions" else set_data_field
        with pytest.raises(OSError, match=f"{failure} denied"):
            writer(tmp_path, 0x1000, "size", 42, "SERVER")

        assert path.read_bytes() == original
        assert not list(tmp_path.glob("*.corrupt"))

    @pytest.mark.parametrize("internal", [False, True])
    def test_unexpected_parser_failure_does_not_move_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, internal: bool
    ) -> None:
        import tomlkit
        from tomlkit.exceptions import InternalParserError

        from rebrew.utils import load_toml_for_write

        path = tmp_path / "metadata.toml"
        original = "size = 80\n"
        path.write_text(original, encoding="utf-8")
        error = (
            InternalParserError(1, 1, "parser failed")
            if internal
            else RuntimeError("parser failed")
        )

        def _parse(text: str) -> None:
            raise error

        monkeypatch.setattr(tomlkit, "parse", _parse)
        with pytest.raises(type(error), match="parser failed"):
            load_toml_for_write(path, "metadata")
        assert path.read_text(encoding="utf-8") == original
        assert not list(tmp_path.glob("*.corrupt"))

    @pytest.mark.parametrize("original", [b"size = ", b"\xff"])
    def test_corrupt_content_is_preserved_before_recovery(
        self, tmp_path: Path, original: bytes
    ) -> None:
        from rebrew.utils import load_toml_for_write

        path = tmp_path / "metadata.toml"
        path.write_bytes(original)
        assert load_toml_for_write(path, "metadata") == {}
        assert path.with_suffix(".toml.corrupt").read_bytes() == original
        assert not path.exists()

    def test_missing_store_starts_empty(self, tmp_path: Path) -> None:
        from rebrew.utils import load_toml_for_write

        path = tmp_path / "missing.toml"
        assert load_toml_for_write(path, "metadata") == {}
        assert not path.exists()


class TestPreserveCorrupt:
    def test_first_salvage_uses_plain_suffix(self, tmp_path: Path) -> None:
        from rebrew.utils import preserve_corrupt

        path = tmp_path / "meta.toml"
        path.write_text("broken", encoding="utf-8")
        backup = preserve_corrupt(path)
        assert backup == tmp_path / "meta.toml.corrupt"
        assert backup is not None and backup.read_text(encoding="utf-8") == "broken"
        assert not path.exists()

    def test_second_salvage_does_not_clobber(self, tmp_path: Path) -> None:
        from rebrew.utils import preserve_corrupt

        first = tmp_path / "meta.toml"
        first.write_text("first", encoding="utf-8")
        assert preserve_corrupt(first) == tmp_path / "meta.toml.corrupt"

        second = tmp_path / "meta.toml"
        second.write_text("second", encoding="utf-8")
        backup = preserve_corrupt(second)
        assert backup is not None
        assert backup != tmp_path / "meta.toml.corrupt"
        assert backup.name.startswith("meta.toml.")
        assert backup.name.endswith(".corrupt")
        assert (tmp_path / "meta.toml.corrupt").read_text(encoding="utf-8") == "first"
        assert backup.read_text(encoding="utf-8") == "second"

    def test_same_second_collision_keeps_both(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A wall-clock step-back that reuses a prior suffix must not overwrite."""
        from rebrew.utils import preserve_corrupt

        plain = tmp_path / "meta.toml.corrupt"
        plain.write_text("kept", encoding="utf-8")
        # Force every candidate onto one pre-existing ns name, then free the bump.
        taken = tmp_path / "meta.toml.100.corrupt"
        taken.write_text("earlier", encoding="utf-8")
        calls = {"n": 0}

        def fake_time_ns() -> int:
            calls["n"] += 1
            return 100

        monkeypatch.setattr("rebrew.utils.time.time_ns", fake_time_ns)
        path = tmp_path / "meta.toml"
        path.write_text("newest", encoding="utf-8")
        backup = preserve_corrupt(path)
        assert backup == tmp_path / "meta.toml.101.corrupt"
        assert taken.read_text(encoding="utf-8") == "earlier"
        assert backup is not None and backup.read_text(encoding="utf-8") == "newest"

    def test_exhausted_corrupt_slots_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every free-slot candidate occupied must raise, not hang forever."""
        from rebrew.utils import preserve_corrupt

        plain = tmp_path / "meta.toml.corrupt"
        plain.write_text("kept", encoding="utf-8")
        monkeypatch.setattr("rebrew.utils.time.time_ns", lambda: 1)
        # Path.exists is True for every candidate (plain + ns bumps).
        monkeypatch.setattr(Path, "exists", lambda self: True)
        path = tmp_path / "meta.toml"
        path.write_text("newest", encoding="utf-8")
        with pytest.raises(OSError, match="no free .corrupt slot"):
            preserve_corrupt(path)


def _assert_grandchild_killed(pidfile: Path) -> None:
    """Poll until the pid in *pidfile* is gone or a zombie; kill it on failure.

    A missing or empty *pidfile* means the group kill landed before the
    grandchild recorded itself, so it is already dead.
    """
    text = pidfile.read_text() if pidfile.exists() else ""
    if not text.strip():
        return
    pid = int(text)
    stat = Path(f"/proc/{pid}/stat")

    def _alive() -> bool:
        try:
            return stat.read_text().rsplit(") ", 1)[1][0] != "Z"
        except (FileNotFoundError, ProcessLookupError):
            return False

    deadline = time.monotonic() + 5
    try:
        while _alive():
            assert time.monotonic() < deadline, "grandchild outlived the timeout kill"
            time.sleep(0.02)
    finally:
        with contextlib.suppress(ProcessLookupError, OSError):
            sigkill = getattr(signal, "SIGKILL", getattr(signal, "SIGTERM", 9))
            os.kill(pid, sigkill)


class TestRunProcessGroup:
    def test_returns_output_and_returncode(self) -> None:
        r = run_process_group(
            ["sh", "-c", "echo out; echo err >&2; exit 3"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert (r.returncode, r.stdout, r.stderr) == (3, "out\n", "err\n")

    def test_input_reaches_stdin(self) -> None:
        r = run_process_group(
            ["sh", "-c", "cat"],
            input=b"hello\n",
            capture_output=True,
            timeout=10,
        )
        assert r.returncode == 0
        assert r.stdout == b"hello\n"

    def test_timeout_kills_grandchildren(self, tmp_path: Path) -> None:
        """A driver's background child must die with it on timeout, not
        keep running as an orphan (plain subprocess.run kills only the
        direct child)."""
        pidfile = tmp_path / "grandchild.pid"
        script = f"sh -c 'echo $$ > \"{pidfile}\"; exec sleep 30' & wait"
        with pytest.raises(subprocess.TimeoutExpired):
            run_process_group(["sh", "-c", script], capture_output=True, timeout=1)
        _assert_grandchild_killed(pidfile)

    def test_timeout_kills_detached_pipe_holder(self, tmp_path: Path) -> None:
        """A setsid grandchild holding stdout must die without pinning the caller.

        Group-kill misses a child that already left the session. Waiting on
        the pipe it inherited then blocks until that child exits.
        """
        pidfile = tmp_path / "detached.pid"
        script = (
            "import os, time\n"
            "from pathlib import Path\n"
            "pidfile = Path(os.environ['REBREW_TEST_PIDFILE'])\n"
            "r, w = os.pipe()\n"
            "if os.fork() == 0:\n"
            "    os.close(r)\n"
            "    os.setsid()\n"
            "    pidfile.write_text(str(os.getpid()))\n"
            "    os.write(w, b'x')\n"
            "    os.close(w)\n"
            "    time.sleep(120)\n"
            "    raise SystemExit(0)\n"
            "os.close(w)\n"
            "os.read(r, 1)\n"
            "os.close(r)\n"
            "time.sleep(120)\n"
        )
        env = os.environ.copy()
        env["REBREW_TEST_PIDFILE"] = str(pidfile)
        caught: list[BaseException] = []

        def _run() -> None:
            try:
                run_process_group(
                    [sys.executable, "-c", script],
                    capture_output=True,
                    timeout=1,
                    env=env,
                )
            except BaseException as exc:
                caught.append(exc)

        worker = threading.Thread(target=_run)
        worker.start()
        worker.join(15)
        stuck = worker.is_alive()
        try:
            if stuck:
                text = pidfile.read_text() if pidfile.exists() else ""
                if text.strip():
                    with contextlib.suppress(ProcessLookupError, OSError, ValueError):
                        os.kill(int(text), signal.SIGKILL)
                worker.join(5)
            else:
                _assert_grandchild_killed(pidfile)
        finally:
            text = pidfile.read_text() if pidfile.exists() else ""
            if text.strip():
                with contextlib.suppress(ProcessLookupError, OSError, ValueError):
                    os.kill(int(text), signal.SIGKILL)
        assert not stuck
        assert len(caught) == 1
        assert isinstance(caught[0], subprocess.TimeoutExpired)


class TestMd5File:
    def test_md5_file_usedforsecurity_false(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import hashlib

        from rebrew.utils import md5_file

        sample = tmp_path / "data.bin"
        sample.write_bytes(b"hello world")
        created_flags: list[bool] = []
        real_md5 = hashlib.md5

        def _fake_md5(*args: object, **kwargs: object) -> object:
            created_flags.append(bool(kwargs.get("usedforsecurity", True)))
            return real_md5(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(hashlib, "md5", _fake_md5)
        res = md5_file(sample)
        assert res == real_md5(b"hello world").hexdigest()
        assert created_flags == [False]


class TestFloorPct:
    def test_never_rounds_a_miss_up_to_100(self) -> None:
        assert floor_pct(2809, 2810) == 99.9
        assert floor_pct(99996, 100000, 2) == 99.99

    def test_exact_decimal_survives_float_error(self) -> None:
        assert floor_pct(573, 1000) == 57.3  # 57.3 * 10 is 572.999... in binary

    def test_zero_whole(self) -> None:
        assert floor_pct(5, 0) == 0.0


class TestClipSpan:
    def test_last_start_is_never_clipped(self) -> None:
        # Nothing follows the last known start, so its size is taken as given.
        assert clip_span([0x1000, 0x2000], 0x2000, 0x40) == 0x40

    def test_run_past_the_next_start_is_cut_at_it(self) -> None:
        # A discoverer that missed a start: 0x1000 must not run through 0x1100.
        assert clip_span([0x1000, 0x1100], 0x1000, 0x200) == 0x100

    def test_size_ending_inside_the_gap_is_untouched(self) -> None:
        assert clip_span([0x1000, 0x1100], 0x1000, 0x20) == 0x20

    def test_a_function_never_clips_against_its_own_start(self) -> None:
        # The va itself is in the list; clipping must look strictly forward.
        assert clip_span([0x1000, 0x1000, 0x1100], 0x1000, 0x200) == 0x100

    def test_no_starts_leaves_the_size_alone(self) -> None:
        assert clip_span([], 0x1000, 0x200) == 0x200

    def test_clipped_sizes_never_double_count_the_neighbour(self) -> None:
        """The invariant clip_span exists for: a size that overruns the next
        start would make the summed coverage exceed the real extent."""
        starts = [0x1000, 0x1010, 0x1040]
        raw = [(0x1000, 0x40), (0x1010, 0x80)]  # the second overruns 0x1040
        clipped = [(va, clip_span(starts, va, size)) for va, size in raw]
        assert clipped == [(0x1000, 0x10), (0x1010, 0x30)]
        assert sum(size for _, size in clipped) == starts[-1] - starts[0]


class TestMergedSpanBytes:
    def test_overlapping_spans_count_once(self) -> None:
        # Two names for one address, plus a neighbour that overlaps the first.
        assert merged_span_bytes([(0x1000, 0x1010), (0x1008, 0x1020)]) == 0x20

    def test_empty_and_inverted_spans_are_dropped(self) -> None:
        assert merged_span_bytes([]) == 0
        assert merged_span_bytes([(0x10, 0x10), (0x20, 0x18)]) == 0

    def test_section_clips_and_never_exceeds_it(self) -> None:
        spans = [(0x1000, 0x1100)]
        assert merged_span_bytes(spans, (0x1000, 0x10)) == 0x10
        assert merged_span_bytes(spans, (0x2000, 0x10)) == 0


class TestSourceLines:
    def test_only_newline_ends_a_line(self) -> None:
        from rebrew.utils import split_source_lines

        text = 'char *s = "a\x0bb\x0cc\x85d\u2028e";\nint f(void) { return 0; }\n'
        assert split_source_lines(text) == [
            'char *s = "a\x0bb\x0cc\x85d\u2028e";',
            "int f(void) { return 0; }",
        ]

    def test_trailing_newline_state_round_trips(self) -> None:
        from rebrew.utils import join_source_lines, split_source_lines

        for text in ("a\nb\n", "a\nb", "", "a\n\n"):
            assert join_source_lines(text, split_source_lines(text)) == text

    def test_latin1_source_survives_split_and_join(self) -> None:
        from rebrew.utils import join_source_lines, split_source_lines

        raw = b'char *s = "caf\xe9 \x85 end";\nint f(void) { return 0; }\n'
        text = raw.decode("latin-1")
        rebuilt = join_source_lines(text, split_source_lines(text))
        assert rebuilt.encode("latin-1") == raw


class TestIsSafeCIdent:
    """The gate that decides whether external text lands verbatim in C source.

    Names arrive from linker output, BinSync state, and the CLI.  A name that
    passes is emitted into a generated ``.c`` unchanged, so the accepted set
    must be C89 ASCII identifiers and nothing wider.
    """

    @pytest.mark.parametrize("name", ["func_a", "_private", "A1", "x"])
    def test_plain_c_identifiers(self, name: str) -> None:
        assert is_safe_c_ident(name)

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "1abc",  # leading digit
            "has space",
            "func(x)",  # anything that could carry an injection
            "a\nb",
            "café",  # str.isidentifier() would accept this; MSVC6 would not
            "名前",
            "abcé",  # trailing non-ASCII
        ],
    )
    def test_rejected(self, name: str) -> None:
        assert not is_safe_c_ident(name)

    def test_anchored_at_both_ends(self) -> None:
        """A valid prefix followed by junk is still junk."""
        assert not is_safe_c_ident('ok; system("x")')


class TestStripBidiFormat:
    """Invisible reordering characters must not reach a status column or DOM."""

    def test_removes_reordering_characters(self) -> None:
        assert strip_bidi_format("sub_A\u202etxt\u202c") == "sub_Atxt"

    def test_removes_invisible_operators_and_bom(self) -> None:
        assert strip_bidi_format("a\u200bb\u2060c\ufeff") == "abc"

    def test_leaves_visible_text_alone(self) -> None:
        assert strip_bidi_format("func_a") == "func_a"

    def test_keeps_ordinary_unicode(self) -> None:
        """Scrubbing targets invisible formatting, not every non-ASCII char."""
        assert strip_bidi_format("café") == "café"


class TestInterruptiblePool:
    """A Ctrl+C must not wait for the other workers to finish their run."""

    def test_base_exception_does_not_block_on_running_workers(self) -> None:
        import threading

        from rebrew.utils import interruptible_pool

        started = threading.Event()
        release = threading.Event()

        def _slow(_i: int) -> None:
            started.set()
            release.wait(timeout=5)

        with pytest.raises(KeyboardInterrupt), interruptible_pool(2) as ex:
            for i in range(2):
                ex.submit(_slow, i)
            assert started.wait(timeout=5)
            raise KeyboardInterrupt
        # Reached without waiting out the 5 s the workers were told to hold.
        release.set()

    def test_clean_exit_waits_and_collects_results(self) -> None:
        from rebrew.utils import interruptible_pool

        with interruptible_pool(3) as ex:
            assert sorted(ex.map(lambda i: i * 2, range(4))) == [0, 2, 4, 6]
