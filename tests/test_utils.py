"""Tests for rebrew.utils."""

import os
from pathlib import Path

import pytest

from rebrew.utils import atomic_write_text, detect_source_encoding, read_source_text


def test_atomic_write_text_success(tmp_path: Path) -> None:
    f = tmp_path / "test.txt"
    atomic_write_text(f, "hello world")
    assert f.read_text() == "hello world"
    assert list(tmp_path.iterdir()) == [f]


def test_atomic_write_text_overwrite(tmp_path: Path) -> None:
    f = tmp_path / "test.txt"
    f.write_text("old")
    atomic_write_text(f, "new")
    assert f.read_text() == "new"


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


class TestQualifiedKey:
    def test_with_module(self) -> None:
        from rebrew.utils import qualified_key

        assert qualified_key("SERVER", 0x01006364) == "SERVER.0x01006364"

    def test_without_module(self) -> None:
        from rebrew.utils import qualified_key

        assert qualified_key(None, 0x01006364) == "0x01006364"


class TestParseMetadataKey:
    def test_valid(self) -> None:
        from rebrew.utils import parse_metadata_key

        assert parse_metadata_key("SERVER.0x01006364") == ("SERVER", 16802660)

    def test_invalid_hex_returns_none(self) -> None:
        from rebrew.utils import parse_metadata_key

        assert parse_metadata_key("SERVER.0xZZZ") is None

    def test_no_module_dot_returns_none(self) -> None:
        from rebrew.utils import parse_metadata_key

        assert parse_metadata_key("not_a_key") is None


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


class TestMetadataWriteLock:
    def test_fresh_directory_does_not_crash(self, tmp_path: Path) -> None:
        """First-ever write into a nonexistent metadata root must not raise:
        the ``.lock`` sidecar open happens before any data-write mkdir."""
        from rebrew.utils import metadata_write_lock

        target = tmp_path / "brand" / "new" / "rebrew-function.toml"
        with metadata_write_lock(target.parent, target.name):
            pass
        assert not target.exists()  # lock only — no data file implied

    def test_concurrent_writers_do_not_lose_updates(self, tmp_path: Path) -> None:
        """N threads doing read-modify-write cycles under the shared lock must
        all land: without serialization, last-writer-wins drops siblings."""
        import threading
        import tomllib

        from rebrew.utils import atomic_write_text, metadata_write_lock, parse_metadata_doc

        target = tmp_path / "rebrew-function.toml"
        atomic_write_text(target, "")

        def _write(i: int) -> None:
            with metadata_write_lock(tmp_path, "rebrew-function.toml"):
                doc = parse_metadata_doc(tomllib.loads(target.read_text(encoding="utf-8")))
                doc[("M", i)] = {"note": str(i)}
                lines = "".join(
                    f'["M.0x{va:x}"]\nnote = "{entry["note"]}"\n'
                    for (_, va), entry in sorted(doc.items(), key=lambda kv: kv[0])
                )
                atomic_write_text(target, lines)

        threads = [threading.Thread(target=_write, args=(i,)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        doc = parse_metadata_doc(tomllib.loads(target.read_text(encoding="utf-8")))
        assert {va for _, va in doc} == set(range(16))


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

    def test_read_cp1252_undefined_byte_does_not_crash(self, tmp_path: Path) -> None:
        """0x81 is undefined in CP1252 — must decode to U+FFFD, not raise.

        Regression: read_source_text used a strict cp1252 decode, crashing
        on the undefined CP1252 holes (0x81/0x8D/0x8F/0x90/0x9D) — found by
        fuzzing the annotation parser on non-UTF-8 sources.
        """
        f = tmp_path / "legacy.c"
        # 0x81 followed by a space: not a valid Shift-JIS pair, so detection
        # falls through to cp1252, where 0x81 is undefined -> U+FFFD.
        f.write_bytes(b"// FUNCTION: GAME 0x1000\n// caf\x81 e\n")
        text, encoding = read_source_text(f)
        assert encoding == "cp1252"
        assert "\ufffd" in text  # undefined byte replaced, no crash

    def test_read_random_bytes_does_not_crash(self, tmp_path: Path) -> None:
        """Binary garbage in a source file must not crash the tolerant reader."""
        import random

        rng = random.Random(12)
        f = tmp_path / "garbage.c"
        for _ in range(50):
            f.write_bytes(bytes(rng.randrange(256) for _ in range(400)))
            text, encoding = read_source_text(f)
            assert isinstance(text, str)
            assert isinstance(encoding, str)


class TestWritableTempDir:
    """Sandbox dirs must live on a real-disk, container-visible location —
    and never directly in the home directory (home sandboxes go under
    ~/.cache/rebrew/tmp so stragglers stay out of ~)."""

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

        allowed = {
            Path.home() / ".cache" / "rebrew" / "tmp",
            Path(__file__).resolve().parents[1] / ".cache",
            Path(tempfile.gettempdir()),
        }
        d = writable_temp_dir("rebrew_test_")
        try:
            assert d.parent in allowed, f"temp dir escaped to {d.parent}"
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


class TestRemoveTempDir:
    def test_removes_dir(self, tmp_path: Path) -> None:
        from rebrew.utils import remove_temp_dir

        d = tmp_path / "sandbox"
        d.mkdir()
        (d / "t.c").write_text("int x;\n")
        remove_temp_dir(d)
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
