"""Tests for rebrew.utils."""

import os
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from rebrew.utils import (
    atomic_write_text,
    container_runtime,
    detect_source_encoding,
    load_tomllib,
    read_compile_source,
    read_source_text,
    read_toml_text,
    run_process_group,
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


def test_atomic_write_text_success(tmp_path: Path) -> None:
    f = tmp_path / "test.txt"
    atomic_write_text(f, "hello world")
    assert f.read_text() == "hello world"
    assert list(tmp_path.iterdir()) == [f]


def test_atomic_write_text_preserves_lf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Writes must not translate ``\\n`` to ``os.linesep`` (Windows default)."""
    recorded: dict[str, object] = {}
    original = Path.write_text

    def _spy(
        self: Path,
        data: str,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> int:
        recorded["newline"] = newline
        return original(self, data, encoding=encoding, errors=errors, newline=newline)

    monkeypatch.setattr(Path, "write_text", _spy)
    f = tmp_path / "lf.txt"
    atomic_write_text(f, "a\nb\n")
    assert recorded["newline"] == ""
    assert f.read_bytes() == b"a\nb\n"


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


class TestResolveMetadataKey:
    def test_absent_entry_returns_canonical(self) -> None:
        from rebrew.utils import resolve_metadata_key

        assert resolve_metadata_key({}, "SERVER", 0x24000) == "SERVER.0x00024000"

    def test_canonical_key_preferred(self) -> None:
        from rebrew.utils import resolve_metadata_key

        doc = {"SERVER.0x00024000": {"status": "UNCHECKED"}}
        assert resolve_metadata_key(doc, "SERVER", 0x24000) == "SERVER.0x00024000"

    def test_non_canonical_spelling_resolved(self) -> None:
        from rebrew.utils import resolve_metadata_key

        doc = {"SERVER.0x24000": {"name": "g_iat_region"}}
        assert resolve_metadata_key(doc, "SERVER", 0x24000) == "SERVER.0x24000"

    def test_index_avoids_scan_for_absent_keys(self) -> None:
        from rebrew.utils import build_metadata_key_index, resolve_metadata_key

        doc = {"SERVER.0x24000": {"name": "g_iat_region"}}
        index = build_metadata_key_index(doc)
        assert resolve_metadata_key(doc, "SERVER", 0x24000, index=index) == "SERVER.0x24000"
        # New VA: indexed miss returns canonical without requiring a doc scan.
        assert resolve_metadata_key(doc, "SERVER", 0x25000, index=index) == "SERVER.0x00025000"

    def test_other_module_ignored(self) -> None:
        from rebrew.utils import resolve_metadata_key

        doc = {"OTHER.0x24000": {"name": "x"}}
        assert resolve_metadata_key(doc, "SERVER", 0x24000) == "SERVER.0x00024000"


class TestParseMetadataDocDuplicates:
    def test_duplicate_keys_merge_fields(self, caplog: pytest.LogCaptureFixture) -> None:
        """SERVER.0x24000 and SERVER.0x00024000 parse to one (module, va) —
        the fields must merge instead of the later table replacing the earlier."""
        import tomllib

        from rebrew.utils import parse_metadata_doc

        text = (
            '["SERVER.0x24000"]\n'
            'name = "g_iat_region"\n'
            'section = ".rdata"\n'
            "\n"
            '["SERVER.0x00024000"]\n'
            'status = "UNCHECKED"\n'
        )
        with caplog.at_level("WARNING", logger="rebrew.utils"):
            parsed = parse_metadata_doc(tomllib.loads(text))

        assert parsed[("SERVER", 0x24000)] == {
            "name": "g_iat_region",
            "section": ".rdata",
            "status": "UNCHECKED",
        }
        assert "Duplicate metadata keys" in caplog.text

    def test_later_key_wins_contested_field(self) -> None:
        from rebrew.utils import parse_metadata_doc

        parsed = parse_metadata_doc(
            {"SERVER.0x24000": {"size": 4}, "SERVER.0x00024000": {"size": 8}}
        )
        assert parsed[("SERVER", 0x24000)]["size"] == 8

    def test_no_duplicates_no_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        from rebrew.utils import parse_metadata_doc

        with caplog.at_level("WARNING", logger="rebrew.utils"):
            parse_metadata_doc({"SERVER.0x1000": {"status": "STUB"}})

        assert caplog.text == ""


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

        target = tmp_path / "brand" / "new" / "rebrew-functions.toml"
        with metadata_write_lock(target.parent, target.name):
            pass
        assert not target.exists()  # lock only — no data file implied

    def test_concurrent_writers_do_not_lose_updates(self, tmp_path: Path) -> None:
        """N threads doing read-modify-write cycles under the shared lock must
        all land: without serialization, last-writer-wins drops siblings."""
        import threading
        import tomllib

        from rebrew.utils import atomic_write_text, metadata_write_lock, parse_metadata_doc

        target = tmp_path / "rebrew-functions.toml"
        atomic_write_text(target, "")

        def _write(i: int) -> None:
            with metadata_write_lock(tmp_path, "rebrew-functions.toml"):
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

    def test_reentrant_nested_acquisition_does_not_deadlock(self, tmp_path: Path) -> None:
        """A nested acquisition on the same filename must not deadlock.

        The GA batch holds ``metadata_write_lock("rebrew-functions.toml")``
        while ``update_stub_to_matched`` promotes STATUS through
        ``update_source_status`` -> ``update_statuses_batch``, which locks the
        same file again.  A non-reentrant lock wedges the worker thread forever.
        """
        import threading

        from rebrew.utils import metadata_write_lock

        done = threading.Event()
        result: list[str] = []

        def _nested() -> None:
            with (
                metadata_write_lock(tmp_path, "rebrew-functions.toml"),
                metadata_write_lock(tmp_path, "rebrew-functions.toml"),
            ):
                result.append("inner")
            result.append("outer")
            done.set()

        worker = threading.Thread(target=_nested, daemon=True)
        worker.start()
        assert done.wait(timeout=10), "nested metadata_write_lock deadlocked"
        assert result == ["inner", "outer"]

    def test_nested_lock_on_other_directory_takes_its_flock(self, tmp_path: Path) -> None:
        """Holding the lock for one metadata root must not skip the ``flock``
        of a same-named file in another root: another process would then
        interleave its read-modify-write on the second file."""
        import fcntl

        from rebrew.utils import metadata_write_lock

        dir_a, dir_b = tmp_path / "a", tmp_path / "b"
        with (
            metadata_write_lock(dir_a, "rebrew-functions.toml"),
            metadata_write_lock(dir_b, "rebrew-functions.toml"),
            # A second open file description stands in for another process.
            (dir_b / "rebrew-functions.toml.lock").open("w") as other_fd,
            pytest.raises(BlockingIOError),
        ):
            fcntl.flock(other_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


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

        with pytest.raises(ValueError):
            parse_int_literal("nope")
        with pytest.raises(ValueError):
            parse_int_literal("")


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


class TestRunProcessGroup:
    def test_returns_output_and_returncode(self) -> None:
        r = run_process_group(
            ["sh", "-c", "echo out; echo err >&2; exit 3"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert (r.returncode, r.stdout, r.stderr) == (3, "out\n", "err\n")

    def test_timeout_kills_grandchildren(self, tmp_path: Path) -> None:
        """A driver's background child must die with it on timeout, not
        keep running as an orphan (plain subprocess.run kills only the
        direct child)."""
        marker = tmp_path / "orphan-ran"
        script = f"(sleep 1; touch '{marker}') & wait"
        with pytest.raises(subprocess.TimeoutExpired):
            run_process_group(["sh", "-c", script], capture_output=True, timeout=0.3)
        time.sleep(1.5)
        assert not marker.exists()
