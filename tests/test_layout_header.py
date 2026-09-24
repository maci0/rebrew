"""Layout-package header facts (layout_meta.read_layout_header) — LIEF-free.

The committed ``layout/<target>/rebrew-layout.toml`` answers
image_base/text_va/text_size for status/lint/config without importing
LIEF (~0.11 s per command).  Freshness is the contract: a layout older
than the binary must fall back to a real parse, never serve stale VAs.
"""

from pathlib import Path

from rebrew.layout_meta import read_layout_header


def _write_layout(root: Path, target: str = "main") -> Path:
    pkg = root / "layout" / target
    pkg.mkdir(parents=True, exist_ok=True)
    toml = pkg / "rebrew-layout.toml"
    toml.write_text(
        "[layout]\n"
        "image_base = 4194304\n"  # 0x400000
        "\n"
        "[[layout.sections]]\n"
        'name = ".text"\n'
        "va = 4096\n"  # 0x1000 RVA
        "vs = 113\n"
        "raw = 512\n"
        "ptr = 512\n"
        "chars = 0\n",
        encoding="utf-8",
    )
    return toml


class TestReadLayoutHeader:
    def test_fresh_layout_returns_absolute_section_vas(self, tmp_path: Path) -> None:
        binp = tmp_path / "program.exe"
        binp.write_bytes(b"MZ")
        _write_layout(tmp_path)
        hdr = read_layout_header(tmp_path, "main", binp)
        assert hdr is not None
        assert hdr["image_base"] == 0x400000
        assert hdr["text_va"] == 0x401000
        assert hdr["text_size"] == 113
        assert hdr["text_raw_offset"] == 512
        assert hdr["sections"][0][0] == ".text"
        assert hdr["sections"][0][1] == 0x401000

    def test_stale_layout_falls_back(self, tmp_path: Path) -> None:
        toml = _write_layout(tmp_path)
        binp = tmp_path / "program.exe"
        binp.write_bytes(b"MZ")
        # binary newer than the layout → stale, must not be trusted
        import os

        os.utime(toml, (1, 1))
        assert read_layout_header(tmp_path, "main", binp) is None

    def test_missing_layout_returns_none(self, tmp_path: Path) -> None:
        binp = tmp_path / "program.exe"
        binp.write_bytes(b"MZ")
        assert read_layout_header(tmp_path, "main", binp) is None

    def test_malformed_layout_returns_none(self, tmp_path: Path) -> None:
        binp = tmp_path / "program.exe"
        binp.write_bytes(b"MZ")
        pkg = tmp_path / "layout" / "main"
        pkg.mkdir(parents=True)
        (pkg / "rebrew-layout.toml").write_text("not [ valid toml", encoding="utf-8")
        assert read_layout_header(tmp_path, "main", binp) is None


class TestLayoutFirstCallers:
    def test_config_detect_uses_layout_without_lief(self, tmp_path: Path, monkeypatch) -> None:
        """_detect_binary_layout answers from the package; LIEF never loads."""
        import sys

        from rebrew import binary_loader
        from rebrew.config import _detect_binary_layout

        binp = tmp_path / "program.exe"
        binp.write_bytes(b"MZ")
        _write_layout(tmp_path)

        def _boom(*a, **k):
            raise AssertionError("load_binary must not run when the layout is fresh")

        monkeypatch.setattr(binary_loader, "load_binary", _boom)
        # Membership must be unchanged: this call alone never imports lief.
        # (Never pop sys.modules here — a mid-suite pop desyncs
        # binary_loader.lief's cached attr from sys.modules and poisons
        # later tests that patch one against the other.)
        before = "lief" in sys.modules
        facts = _detect_binary_layout(binp, root=tmp_path, target="main")
        assert facts == {"image_base": 0x400000, "text_va": 0x401000, "text_raw_offset": 512}
        assert ("lief" in sys.modules) == before

    def test_text_size_uses_layout_without_lief(self, tmp_path: Path, monkeypatch) -> None:
        import sys

        from rebrew import binary_loader
        from rebrew.sections import get_text_section_size

        binp = tmp_path / "program.exe"
        binp.write_bytes(b"MZ")
        _write_layout(tmp_path)
        monkeypatch.setattr(
            binary_loader, "load_binary", lambda *a, **k: (_ for _ in ()).throw(AssertionError())
        )
        before = "lief" in sys.modules
        assert get_text_section_size(binp, root=tmp_path, target="main") == 113
        assert ("lief" in sys.modules) == before

    def test_missing_layout_falls_back_to_lief_path(self, tmp_path: Path) -> None:
        """No package → the old behaviour: zeros + a warning, no crash."""
        from rebrew.config import _detect_binary_layout

        binp = tmp_path / "program.exe"  # not a PE → detect fails soft
        binp.write_bytes(b"\x00" * 8)
        facts = _detect_binary_layout(binp, root=tmp_path, target="main")
        assert facts == {"image_base": 0, "text_va": 0, "text_raw_offset": 0}
