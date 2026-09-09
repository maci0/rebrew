"""Unit tests for the whole-binary parity core."""

from pathlib import Path


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

    def test_snapshot_missing_file(self, tmp_path: Path) -> None:
        from rebrew.binary_gate import snapshot_binary

        snap = snapshot_binary(tmp_path / "nope.dll")
        assert snap == {
            "sections": {},
            "exports": [],
            "imports": [],
            "rsrc": None,
            "headers": {},
        }


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
