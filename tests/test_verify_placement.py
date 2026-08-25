"""Tests for rebrew verify_placement — .data VA comparison against data metadata.

The link pipeline is faked at the ``rebrew.data_layout`` boundary (link
objects + per-object symbol offsets) so the test exercises the placement
arithmetic: per-TU .data contributions accumulate in link order onto the
built ``.data`` base VA, then each symbol's computed VA is compared with the
metadata expectation.
"""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

FAKE_DATA_VA = 0x3000


def _project(tmp_path: Path) -> Path:
    root = tmp_path
    (root / "build").mkdir()
    (root / "build" / "server.dll").write_bytes(b"MZ")
    (root / "src").mkdir()
    (root / "src" / "rebrew-data.toml").write_text("", encoding="utf-8")
    return root


def _patch_layout(
    monkeypatch: pytest.MonkeyPatch,
    *,
    objects: list[tuple[int, dict[str, int]]] | None = None,
    expected: dict[str, int] | None = None,
    fail: Exception | None = None,
) -> None:
    import rebrew.data_layout as dl
    import rebrew.verify_placement as vp

    monkeypatch.setattr(vp, "built_data_va", lambda _dll: FAKE_DATA_VA)
    if expected is None:
        expected = {"sym_a": 0x3000, "sym_b": 0x3020}
    monkeypatch.setattr(dl, "data_symbols", lambda _metadata: expected)
    if fail is not None:
        monkeypatch.setattr(dl, "link_objects", lambda _root: (_ for _ in ()).throw(fail))
        return

    objs = [Path(f"/fake/obj{i}.obj") for i in range(len(objects or []))]

    def _offsets(obj: Path) -> tuple[int, dict[str, int]]:
        index = int(str(obj).removeprefix("/fake/obj").removesuffix(".obj"))
        return objects[index]

    monkeypatch.setattr(dl, "link_objects", lambda _root: objs)
    monkeypatch.setattr(dl, "obj_data_symbol_offsets", _offsets)


class TestVerifyPlacement:
    def test_missing_metadata_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.verify_placement import app

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["--data-metadata", "src/nope.toml"])
        assert result.exit_code == 2
        assert "data metadata not found" in result.output

    def test_missing_dll_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.verify_placement import app

        monkeypatch.chdir(tmp_path)
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "rebrew-data.toml").write_text("", encoding="utf-8")
        result = CliRunner().invoke(app, [])
        assert result.exit_code == 2
        # Rich wraps the long absolute path; match the pieces, not the wrap.
        assert "server.dll" in result.output
        assert "not found — build the project first" in result.output

    def test_custom_built_path_honored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--built must point the tool at a differently-named build output
        (e.g. notepad's np_recompiled.exe) instead of hardcoded
        build/server.dll — regression: the tool errored 'build/server.dll not
        found' on any project whose built binary had another name."""
        import rebrew.verify_placement as vp
        from rebrew.verify_placement import app

        monkeypatch.chdir(_project(tmp_path))
        (tmp_path / "build" / "other.dll").write_bytes(b"MZ")
        _patch_layout(monkeypatch, objects=[(16, {"sym_a": 0})])
        seen: list[Path] = []

        def _capture(dll: Path) -> int:
            seen.append(dll)
            return FAKE_DATA_VA

        monkeypatch.setattr(vp, "built_data_va", _capture)
        result = CliRunner().invoke(app, ["--built", "build/other.dll", "--json"])
        assert result.exit_code == 0
        assert seen == [tmp_path / "build" / "other.dll"]

    def test_custom_built_missing_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.verify_placement import app

        monkeypatch.chdir(_project(tmp_path))
        result = CliRunner().invoke(app, ["--built", "build/nope.dll"])
        assert result.exit_code == 2
        assert "nope.dll" in result.output
        # Rich wraps the message at 80 columns; the path length varies with
        # the pytest tmp dir, so normalize whitespace before the substring
        # check (the "not found" can land on a wrapped line).
        assert "not found" in " ".join(result.output.split())

    def test_object_inventory_failure_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.verify_placement import app

        monkeypatch.chdir(_project(tmp_path))
        _patch_layout(monkeypatch, fail=RuntimeError("objdump exploded"))
        result = CliRunner().invoke(app, [])
        assert result.exit_code == 2
        assert "cannot inventory build objects" in result.output

    def test_misplaced_symbol_detected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.verify_placement import app

        monkeypatch.chdir(_project(tmp_path))
        # sym_a lands exactly where the metadata says; sym_b drifts by -8.
        _patch_layout(monkeypatch, objects=[(16, {"sym_a": 0}), (16, {"sym_b": 8})])
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["symbols"] == 2
        assert payload["matched"] == 2
        assert payload["correct"] == 1
        assert payload["misplaced"] == 1
        assert payload["misplaced_list"] == [
            {"symbol": "sym_b", "expected": "0x3020", "actual": "0x3018", "delta": -8}
        ]

    def test_all_correct_reports_zero_misplaced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.verify_placement import app

        monkeypatch.chdir(_project(tmp_path))
        # sym_b is at offset 16 of TU #2 → base + 0x10 (TU#1 size) + 0x10.
        _patch_layout(
            monkeypatch,
            objects=[(16, {"sym_a": 0}), (16, {"sym_b": 16})],
            expected={"sym_a": 0x3000, "sym_b": 0x3020},
        )
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["correct"] == 2
        assert payload["misplaced"] == 0
        assert payload["misplaced_list"] == []

    def test_terminal_output_lists_misplaced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.verify_placement import app

        monkeypatch.chdir(_project(tmp_path))
        _patch_layout(monkeypatch, objects=[(16, {"sym_a": 0}), (16, {"sym_b": 8})])
        result = CliRunner().invoke(app, [])
        assert result.exit_code == 0
        assert "correct-VA: 1" in result.output
        assert "misplaced: 1" in result.output
        assert "sym_b" in result.output
        assert "exp 0x00003020" in result.output
        assert "our 0x00003018" in result.output
