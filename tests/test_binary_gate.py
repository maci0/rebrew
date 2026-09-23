"""Unit tests for the whole-binary parity core."""

import sys
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

    def test_rsrc_absent_both_sides(self) -> None:
        from rebrew.binary_gate import compare_snapshots

        res = compare_snapshots(self._snap(rsrc=None), self._snap(rsrc=None))
        assert res["rsrc"]["match"] is True
        assert res["match"] is True

    def test_snapshot_exports_without_export_cli(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.binary_gate import snapshot_binary

        info = SimpleNamespace(
            sections={
                ".text": SimpleNamespace(size=100),
                ".rsrc": SimpleNamespace(size=8, file_offset=2, raw_size=3),
            },
            data=b"xxrsrc",
            image_base=0x400000,
        )
        pe = SimpleNamespace(
            exported_functions=[SimpleNamespace(name=name) for name in ["b", "a", "b", ""]]
        )
        monkeypatch.setattr("rebrew.binary_loader.load_binary", lambda path: info)
        monkeypatch.setattr("lief.PE.parse", lambda path: pe)
        monkeypatch.setattr(
            "rebrew.import_table.parse_imports",
            lambda path: [{"dll": "kernel32.dll", "name": "ExitProcess"}],
        )
        monkeypatch.setitem(sys.modules, "rebrew.exports", None)

        assert snapshot_binary(Path("x.dll")) == {
            "sections": {".text": 100, ".rsrc": 8},
            "exports": ["a", "b"],
            "imports": ["kernel32.dll!ExitProcess"],
            "rsrc": b"rsr",
            "headers": {"image_base": 0x400000},
            "error": None,
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
