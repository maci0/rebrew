"""Tests for the rebrew flirt module -- pure-function helpers."""

from pathlib import Path

from rebrew.flirt import _make_progress_printer, find_func_size, load_signatures

# ---------------------------------------------------------------------------
# find_func_size
# ---------------------------------------------------------------------------


class TestFindFuncSize:
    """Tests for find_func_size() function boundary estimation."""

    def test_ret_c3(self) -> None:
        """Finds C3 (ret) and returns offset + 1."""
        code = b"\x55\x8b\xec\xc3"  # push ebp; mov ebp, esp; ret
        size = find_func_size(code, 0)
        assert size == 4  # 0..3 inclusive, ret at index 3

    def test_ret_c2_imm16(self) -> None:
        """Finds C2 xx xx (ret imm16) and returns offset + 3."""
        code = b"\x55\x8b\xec\xc2\x08\x00"  # push ebp; mov ebp, esp; ret 8
        size = find_func_size(code, 0)
        assert size == 6

    def test_offset_nonzero(self) -> None:
        """Works with non-zero start offset."""
        code = b"\xcc\xcc\x55\x8b\xec\xc3"  # padding, then push/mov/ret
        size = find_func_size(code, 2)
        assert size == 4

    def test_no_ret_returns_max_scan(self) -> None:
        """When no ret is found, returns max_scan length."""
        code = bytes(100)  # 100 zero bytes, no ret
        size = find_func_size(code, 0)
        assert size == 100

    def test_ret_c2_near_end(self) -> None:
        """C2 at end-2 still works if there are 2 more bytes."""
        code = b"\x55\xc2\x04\x00"
        size = find_func_size(code, 0)
        assert size == 4

    def test_max_scan_capped_at_4096(self) -> None:
        """Max scan is capped at 4096 bytes."""
        code = bytes(8192)  # 8K of zeros
        size = find_func_size(code, 0)
        assert size == 4096

    def test_empty_at_offset(self) -> None:
        """When offset == len(code), max_scan is 0."""
        code = b"\xc3"
        size = find_func_size(code, 1)
        assert size == 0


# ---------------------------------------------------------------------------
# _make_progress_printer
# ---------------------------------------------------------------------------


class TestMakeProgressPrinter:
    """Tests for _make_progress_printer() factory."""

    def test_returns_callable(self) -> None:
        """Returns a callable in both modes."""
        fn = _make_progress_printer(json_output=False)
        assert callable(fn)

    def test_json_false_returns_print(self) -> None:
        """json_output=False returns the builtin print."""
        fn = _make_progress_printer(json_output=False)
        assert fn is print

    def test_json_true_returns_stderr_printer(self) -> None:
        """json_output=True returns a function that prints to stderr."""
        fn = _make_progress_printer(json_output=True)
        assert fn is not print
        assert callable(fn)

    def test_json_printer_writes_stderr(self, capsys) -> None:
        """The stderr printer writes to stderr, not stdout."""
        fn = _make_progress_printer(json_output=True)
        fn("hello from flirt")
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "hello from flirt" in captured.err

    def test_plain_printer_writes_stdout(self, capsys) -> None:
        """The plain printer writes to stdout."""
        fn = _make_progress_printer(json_output=False)
        fn("hello")
        captured = capsys.readouterr()
        assert "hello" in captured.out


# ---------------------------------------------------------------------------
# load_signatures
# ---------------------------------------------------------------------------


class TestLoadSignatures:
    """Tests for load_signatures() -- filesystem tests."""

    def test_missing_directory(self, tmp_path: Path) -> None:
        """Returns empty list when directory doesn't exist."""
        sigs = load_signatures(str(tmp_path / "nonexistent"), json_output=True)
        assert sigs == []

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Returns empty list when directory has no .sig/.pat files."""
        sig_dir = tmp_path / "sigs"
        sig_dir.mkdir()
        sigs = load_signatures(str(sig_dir), json_output=True)
        assert sigs == []

    def test_no_flirt_module(self, monkeypatch) -> None:
        """Returns empty list when flirt module is not available."""
        import rebrew.flirt as flirt_mod

        monkeypatch.setattr(flirt_mod, "flirt", None)
        sigs = load_signatures("/some/dir", json_output=True)
        assert sigs == []
