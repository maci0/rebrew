"""Unit tests for the whole-binary parity core."""

from pathlib import Path
from types import SimpleNamespace

import pytest


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class TestCompareSections:
    def test_matching_sections(self) -> None:
        from rebrew.binary_gate import compare_sections

        ref = {".text": 100, ".data": 20}
        assert compare_sections(ref, dict(ref)) == {"match": True, "diffs": []}

    def test_size_drift_flagged(self) -> None:
        from rebrew.binary_gate import compare_sections

        res = compare_sections({".text": 100}, {".text": 104})
        assert res["match"] is False
        assert res["diffs"] == [{"section": ".text", "expected": 100, "actual": 104}]

    def test_missing_and_added(self) -> None:
        from rebrew.binary_gate import compare_sections

        res = compare_sections({".text": 100}, {".data": 20})
        assert res["match"] is False
        names = {d["section"] for d in res["diffs"]}
        assert names == {".text", ".data"}


class TestCompareNameSets:
    def test_exports_match(self) -> None:
        from rebrew.binary_gate import compare_name_sets

        assert compare_name_sets(["a", "b"], ["b", "a"]) == {
            "match": True,
            "missing": [],
            "added": [],
        }

    def test_imports_drift(self) -> None:
        from rebrew.binary_gate import compare_name_sets

        res = compare_name_sets(["a", "b"], ["b", "c"])
        assert res["match"] is False
        assert res["missing"] == ["a"]
        assert res["added"] == ["c"]


class TestCompareBytes:
    def test_equal_bytes(self) -> None:
        from rebrew.binary_gate import compare_bytes

        assert compare_bytes(b"abc", b"abc") == {"match": True, "first_diff": None}

    def test_first_diff_reported(self) -> None:
        from rebrew.binary_gate import compare_bytes

        assert compare_bytes(b"abc", b"axc") == {"match": False, "first_diff": 1}

    def test_length_mismatch(self) -> None:
        from rebrew.binary_gate import compare_bytes

        res = compare_bytes(b"ab", b"abc")
        assert res["match"] is False
        assert res["first_diff"] == 2


class TestCompareSnapshots:
    def _snap(self, **over: object) -> dict:
        base: dict = {
            "sections": {".text": 100},
            "exports": ["a"],
            "imports": ["k.dll!f"],
            "rsrc": b"r",
            "headers": {"image_base": 0x400000},
            "error": None,
            "file": b"binary",
            "relocation_layout": {},
            "relocations": [],
        }
        base.update(over)
        return base

    def test_match(self) -> None:
        from rebrew.binary_gate import compare_snapshots

        s = self._snap()
        assert compare_snapshots(s, dict(s))["match"] is True

    def test_drift(self) -> None:
        from rebrew.binary_gate import compare_snapshots

        res = compare_snapshots(self._snap(), self._snap(exports=["b"]))
        assert res["match"] is False
        assert res["exports"]["missing"] == ["a"]

    @pytest.mark.parametrize("actual", [b"bXnary", b"binary-tail", b"binar"])
    def test_file_drift_with_identical_structure(self, actual: bytes) -> None:
        from rebrew.binary_gate import compare_snapshots

        res = compare_snapshots(self._snap(), self._snap(file=actual))
        assert res["match"] is False
        assert res["file"]["match"] is False
        assert res["sections"]["match"] is True

    def test_rsrc_absent_both_sides(self) -> None:
        from rebrew.binary_gate import compare_snapshots

        res = compare_snapshots(self._snap(rsrc=None), self._snap(rsrc=None))
        assert res["rsrc"]["match"] is True
        assert res["match"] is True

    def test_relocations_report_missing_and_extra(self) -> None:
        from rebrew.binary_gate import compare_snapshots

        res = compare_snapshots(
            self._snap(relocations=["0x00001004:3"]),
            self._snap(relocations=["0x00001008:3"]),
        )
        assert res["match"] is False
        assert res["relocations"]["missing"] == ["0x00001004:3"]
        assert res["relocations"]["added"] == ["0x00001008:3"]

    def test_absolute_padding_is_not_a_fixup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.binary_gate import pe_relocation_snapshot

        pe = SimpleNamespace(
            relocations=[
                SimpleNamespace(
                    virtual_address=0x2000,
                    block_size=12,
                    entries=[
                        SimpleNamespace(position=0, type=0),
                        SimpleNamespace(position=4, type=3),
                    ],
                )
            ],
            data_directory=lambda kind: SimpleNamespace(
                size=12, has_section=True, section=SimpleNamespace(virtual_size=2032)
            ),
        )
        monkeypatch.setattr("lief.PE.parse", lambda data: pe)
        assert pe_relocation_snapshot(b"pe") == (
            ["0x00002004:3"],
            {
                "block_bytes": 12,
                "directory_bytes": 12,
                "section_bytes": 2032,
                "reserved_bytes": 2020,
            },
        )

    def test_relocation_parse_failure_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.binary_gate import pe_relocation_snapshot

        monkeypatch.setattr("lief.PE.parse", lambda data: None)
        with pytest.raises(ValueError, match="base relocations"):
            pe_relocation_snapshot(b"invalid")

    def test_snapshot_exports_without_export_cli(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.binary_gate import snapshot_binary

        info = SimpleNamespace(
            sections={
                ".text": SimpleNamespace(size=100),
                ".rsrc": SimpleNamespace(size=8, file_offset=2, raw_size=3),
            },
            data=b"xxrsrc",
            image_base=0x400000,
            format="pe",
        )
        pe = SimpleNamespace(
            exported_functions=[SimpleNamespace(name=name) for name in ["b", "a", "b", ""]],
            relocations=[],
            data_directory=lambda kind: SimpleNamespace(size=0, has_section=False),
        )
        monkeypatch.setattr("rebrew.binary_loader.load_binary", lambda path: info)
        monkeypatch.setattr("lief.PE.parse", lambda path: pe)
        monkeypatch.setattr(
            "rebrew.import_table.parse_imports",
            lambda path: [{"dll": "kernel32.dll", "name": "ExitProcess"}],
        )

        assert snapshot_binary(Path("x.dll")) == {
            "sections": {".text": 100, ".rsrc": 8},
            "exports": ["a", "b"],
            "imports": ["kernel32.dll!ExitProcess"],
            "rsrc": b"rsr",
            "headers": {"image_base": 0x400000},
            "error": None,
            "file": b"xxrsrc",
            "relocation_layout": {
                "block_bytes": 0,
                "directory_bytes": 0,
                "section_bytes": 0,
                "reserved_bytes": 0,
            },
            "relocations": [],
        }

    def test_snapshot_missing_file(self, tmp_path: Path) -> None:
        from rebrew.binary_gate import snapshot_binary

        snap = snapshot_binary(tmp_path / "nope.dll")
        assert snap["sections"] == {}
        assert snap["error"] is not None
        assert "nope.dll" in snap["error"]

    def test_unreadable_both_sides_is_drift(self, tmp_path: Path) -> None:
        from rebrew.binary_gate import compare_snapshots, snapshot_binary

        res = compare_snapshots(
            snapshot_binary(tmp_path / "a.dll"), snapshot_binary(tmp_path / "b.dll")
        )
        assert res["match"] is False
        assert len(res["errors"]) == 2

    def test_import_parse_failure_is_drift(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.binary_gate import compare_snapshots, snapshot_binary

        info = SimpleNamespace(sections={}, data=b"", image_base=0x400000)
        monkeypatch.setattr("rebrew.binary_loader.load_binary", lambda path: info)
        monkeypatch.setattr("rebrew.binary_loader.parse_exports", lambda path: [])

        def _boom(path: Path) -> list[dict[str, str]]:
            raise ValueError("bad import table")

        monkeypatch.setattr("rebrew.import_table.parse_imports", _boom)
        snap = snapshot_binary(Path("x.dll"))
        assert "bad import table" in snap["error"]
        assert compare_snapshots(snap, dict(snap))["match"] is False


class TestLayoutFreshness:
    @pytest.mark.parametrize("pe32_plus", [False, True])
    @pytest.mark.parametrize("part", ["dos", "timestamp", "raw_pointer", "flags", "code"])
    def test_header_drift_excludes_section_contents(
        self, tmp_path: Path, pe32_plus: bool, part: str
    ) -> None:
        from bin_util import make_pe

        from rebrew.binary_gate import check_layout_freshness, layout_fingerprint
        from rebrew.pe_headers import pe_layout

        data = bytearray(make_pe(b"\x90\xc3", pe32_plus=pe32_plus))
        layout = pe_layout(data)
        assert layout is not None
        offsets = {
            "dos": 0x20,
            "timestamp": layout.e_lfanew + 8,
            "raw_pointer": layout.sections[0].header_offset + 20,
            "flags": layout.sections[0].header_offset + 36,
            "code": layout.sections[0].pointer_to_raw_data,
        }
        binary = tmp_path / "ref.dll"
        binary.write_bytes(data)
        fingerprint = layout_fingerprint(binary)
        assert fingerprint
        (tmp_path / "layout.fingerprint").write_text(fingerprint + "\n", encoding="utf-8")
        data[offsets[part]] ^= 1
        binary.write_bytes(data)

        result = check_layout_freshness(tmp_path, binary)
        assert result["match"] is (part == "code")
        assert result["status"] == ("fresh" if part == "code" else "stale")

    def test_missing_fingerprint_is_unknown(self, tmp_path: Path) -> None:
        from rebrew.binary_gate import check_layout_freshness

        res = check_layout_freshness(tmp_path, tmp_path / "ref.dll")
        assert res == {"match": True, "status": "unknown", "expected": None, "actual": None}

    def test_matching_fingerprint(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.binary_gate import check_layout_freshness

        (tmp_path / "layout.fingerprint").write_text("abc123\n", encoding="utf-8")
        monkeypatch.setattr("rebrew.binary_gate.layout_fingerprint", lambda p: "abc123")
        res = check_layout_freshness(tmp_path, tmp_path / "ref.dll")
        assert res["match"] is True
        assert res["status"] == "fresh"

    def test_stale_fingerprint(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.binary_gate import check_layout_freshness

        (tmp_path / "layout.fingerprint").write_text("abc123\n", encoding="utf-8")
        monkeypatch.setattr("rebrew.binary_gate.layout_fingerprint", lambda p: "def456")
        res = check_layout_freshness(tmp_path, tmp_path / "ref.dll")
        assert res["match"] is False
        assert res["status"] == "stale"

    def test_unreadable_fingerprint_is_not_fresh(self, tmp_path: Path, monkeypatch) -> None:
        """A present-but-unreadable fingerprint must fail the gate, not pass it.

        Reporting it as "unknown" (match) would let a layout package scaffolded
        against a different reference binary ship as fresh.
        """
        from rebrew.binary_gate import check_layout_freshness

        fp = tmp_path / "layout.fingerprint"
        fp.write_text("abc123\n", encoding="utf-8")
        monkeypatch.setattr(
            "rebrew.binary_gate.Path.read_text",
            lambda self, **kw: (_ for _ in ()).throw(PermissionError(self)),
        )
        res = check_layout_freshness(tmp_path, tmp_path / "ref.dll")
        assert res["match"] is False
        assert res["status"] == "unreadable"
        assert "layout.fingerprint" in res["error"]
