"""Tests for per-library toolchain/flags overrides (rebrew-libraries.toml)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.compile_overrides import resolve_compile_overrides
from rebrew.library import app
from rebrew.metadata import (
    LIBRARY_METADATA_FILE,
    apply_library_presets,
    find_library_override,
    parse_library_metadata,
)


def _tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A project root with a nested library and a function dir under it."""
    proj = tmp_path / "proj"
    lib = proj / "refs" / "zlib"
    fn = lib / "f"
    for d in (proj, lib, fn):
        d.mkdir(parents=True)
    return proj, lib, fn


class TestLibraryMetadata:
    def test_absent_file_returns_empty(self, tmp_path: Path) -> None:
        assert parse_library_metadata(tmp_path / LIBRARY_METADATA_FILE) == {}

    def test_malformed_toml_raises(self, tmp_path: Path) -> None:
        from rebrew.metadata import LibraryOverrideError

        bad = tmp_path / LIBRARY_METADATA_FILE
        bad.write_text("toolchain = [unclosed\n", encoding="utf-8")
        with pytest.raises(LibraryOverrideError, match=r"bad rebrew-libraries\.toml at"):
            parse_library_metadata(bad)

    def test_unstatable_file_raises_not_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A present-but-unstatable file is not an absent one.  Returning {}
        would tell the caller the library file was consulted and had no
        overrides, so every function below it silently compiled with the
        project default flags and the resulting SIZE_MISMATCH looked like a
        source regression."""
        from rebrew.metadata import LibraryOverrideError

        bad = tmp_path / LIBRARY_METADATA_FILE
        bad.write_text('toolchain = "msvc-6.0"\n', encoding="utf-8")

        def _boom(_self: Path) -> object:
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(Path, "stat", _boom)
        with pytest.raises(LibraryOverrideError, match=r"cannot stat rebrew-libraries\.toml"):
            parse_library_metadata(bad)

    def test_non_string_field_raises(self, tmp_path: Path) -> None:
        """A table where a string belongs would be str()'d into the argv."""
        from rebrew.metadata import LibraryOverrideError

        bad = tmp_path / LIBRARY_METADATA_FILE
        bad.write_text('toolchain = { name = "msvc-6.0" }\n', encoding="utf-8")
        with pytest.raises(LibraryOverrideError, match="toolchain must be a string, got dict"):
            parse_library_metadata(bad)

    def test_unknown_key_warns_and_still_applies(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        proj, lib, fn = _tree(tmp_path)
        (lib / LIBRARY_METADATA_FILE).write_text(
            'toolchain = "msvc-6.0"\ntoolchn = "msvc-6.0-sp6"\n', encoding="utf-8"
        )
        with caplog.at_level("WARNING", logger="rebrew.metadata"):
            ovr = find_library_override(fn, proj)
        assert ovr is not None and ovr.toolchain == "msvc-6.0"
        assert "unrecognized keys: ['toolchn']" in caplog.text

    def test_unknown_toolchain_and_preset_warn(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        proj, lib, fn = _tree(tmp_path)
        (lib / LIBRARY_METADATA_FILE).write_text(
            'toolchain = "msvc-6.0-sp99"\nlibrary = "msvcrt-sttaic"\n', encoding="utf-8"
        )
        with caplog.at_level("WARNING", logger="rebrew.metadata"):
            ovr = find_library_override(fn, proj)
        # Declared fields still apply: a warning is not a silent drop.
        assert ovr is not None and ovr.toolchain == "msvc-6.0-sp99"
        assert "unknown toolchain 'msvc-6.0-sp99'" in caplog.text
        assert "unknown library preset 'msvcrt-sttaic'" in caplog.text

    def test_known_fields_do_not_warn(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        proj, lib, fn = _tree(tmp_path)
        (lib / LIBRARY_METADATA_FILE).write_text(
            'library = "msvcrt-static"\ntoolchain = "msvc-6.0"\ncflags = "/O2 /Gd"\n',
            encoding="utf-8",
        )
        with caplog.at_level("WARNING", logger="rebrew.metadata"):
            ovr = find_library_override(fn, proj)
        assert ovr is not None and ovr.presets == ("msvcrt-static",)
        assert "rebrew-libraries.toml" not in caplog.text

    def test_walk_up_finds_nearest(self, tmp_path: Path) -> None:
        proj, lib, fn = _tree(tmp_path)
        (proj / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc-6.0"\n', encoding="utf-8")
        (lib / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc-6.0-sp6"\n', encoding="utf-8")
        ovr = find_library_override(fn, proj)
        assert ovr is not None and ovr.path == lib / LIBRARY_METADATA_FILE
        assert ovr.toolchain == "msvc-6.0-sp6"  # nearest wins

    def test_no_override_returns_none(self, tmp_path: Path) -> None:
        proj, _, fn = _tree(tmp_path)
        assert find_library_override(fn, proj) is None

    def test_presets_fill_missing_fields(self) -> None:
        merged, presets = apply_library_presets({"library": "msvcrt-static"})
        assert presets == ("msvcrt-static",)
        assert merged["toolchain"] == "msvc-6.0"
        assert merged["cflags"] == "/O2 /Gd /MT"

    def test_explicit_fields_win_over_presets(self) -> None:
        merged, _ = apply_library_presets(
            {"library": "msvcrt-static", "toolchain": "msvc-6.0-sp6", "cflags": "/O1"}
        )
        assert merged["toolchain"] == "msvc-6.0-sp6"
        assert merged["cflags"] == "/O1"

    def test_unknown_preset_no_merge(self) -> None:
        merged, presets = apply_library_presets({"library": "nope"})
        assert presets == ()
        assert "toolchain" not in merged


class TestResolveCompileOverrides:
    def _cfg(self, tmp_path: Path, **over: object) -> SimpleNamespace:
        base: dict[str, object] = {
            "root": tmp_path,
            "cflags_presets": {},
            "cflags": "",
            "cflags_explicit": False,
        }
        base.update(over)
        return SimpleNamespace(**base)

    def test_per_function_beats_library(self, tmp_path: Path) -> None:
        proj, lib, fn = _tree(tmp_path)
        (lib / LIBRARY_METADATA_FILE).write_text(
            'toolchain = "msvc-6.0"\ncflags = "/O2 /Gd"\n', encoding="utf-8"
        )
        tc, cf = resolve_compile_overrides(
            self._cfg(tmp_path, root=proj),
            fn,
            "msvc-5.0",
            "/O1",
        )
        assert tc == "msvc-5.0"  # per-function wins
        assert cf == "/O1"

    def test_library_beats_default(self, tmp_path: Path) -> None:
        proj, lib, fn = _tree(tmp_path)
        (lib / LIBRARY_METADATA_FILE).write_text(
            'toolchain = "msvc-6.0-sp6"\ncflags = "/O2 /Gd /MT"\n', encoding="utf-8"
        )
        tc, cf = resolve_compile_overrides(self._cfg(tmp_path, root=proj), fn, None, None)
        assert tc == "msvc-6.0-sp6"
        assert cf == "/O2 /Gd /MT"

    def test_default_fallback(self, tmp_path: Path) -> None:
        proj, _, fn = _tree(tmp_path)
        tc, cf = resolve_compile_overrides(self._cfg(tmp_path, root=proj), fn, None, None)
        assert tc is None  # project default profile
        assert cf == "/O2 /Gd"  # resolve_cflags default

    def test_preset_drives_library(self, tmp_path: Path) -> None:
        proj, lib, fn = _tree(tmp_path)
        (lib / LIBRARY_METADATA_FILE).write_text('library = "msvcrt-static"\n', encoding="utf-8")
        tc, cf = resolve_compile_overrides(self._cfg(tmp_path, root=proj), fn, None, None)
        assert tc == "msvc-6.0"
        assert cf == "/O2 /Gd /MT"


class TestLibraryCli:
    def _invoke(self, *args: str) -> object:
        from typer.testing import CliRunner

        return CliRunner().invoke(app, list(args))

    def test_list_finds_all_overrides(self, tmp_path: Path) -> None:
        proj, lib, _ = _tree(tmp_path)
        (lib / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc-6.0"\n', encoding="utf-8")
        res = self._invoke("list", str(proj), "--json")
        assert res.exit_code == 0, res.output

        payload = json.loads(res.output)
        assert len(payload["libraries"]) == 1
        assert payload["libraries"][0]["toolchain"] == "msvc-6.0"

    def test_set_show_rm_roundtrip(self, tmp_path: Path) -> None:
        lib = tmp_path / "lib"
        lib.mkdir()
        res = self._invoke("set", str(lib), "--toolchain", "msvc-6.0", "--cflags", "/O2 /Gd")
        assert res.exit_code == 0, res.output
        assert (lib / LIBRARY_METADATA_FILE).exists()
        shown = self._invoke("show", str(lib), "--json")
        assert shown.exit_code == 0
        payload = json.loads(shown.output)
        assert payload["found"] is True
        assert payload["toolchain"] == "msvc-6.0"
        assert payload["cflags"] == "/O2 /Gd"
        removed = self._invoke("rm", str(lib))
        assert removed.exit_code == 0
        assert not (lib / LIBRARY_METADATA_FILE).exists()

    def test_show_stops_at_project_root(self, tmp_path: Path) -> None:
        proj, lib, _ = _tree(tmp_path)
        (proj / "rebrew-project.toml").write_text("", encoding="utf-8")
        (tmp_path / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc-6.0"\n', encoding="utf-8")
        shown = self._invoke("show", str(lib), "--json")
        assert shown.exit_code == 0, shown.output
        assert json.loads(shown.output)["found"] is False

    def test_set_library_with_preset_rejected(self, tmp_path: Path) -> None:
        lib = tmp_path / "lib"
        lib.mkdir()
        res = self._invoke("set", str(lib), "--library", "zlib", "--preset", "msvcrt-static")
        assert res.exit_code != 0
        assert "mutually exclusive" in res.output
        assert not (lib / LIBRARY_METADATA_FILE).exists()

    def test_set_preset_merges_explicit(self, tmp_path: Path) -> None:
        lib = tmp_path / "lib"
        lib.mkdir()
        res = self._invoke(
            "set", str(lib), "--preset", "msvcrt-static", "--toolchain", "msvc-6.0-sp6"
        )
        assert res.exit_code == 0, res.output
        text = (lib / LIBRARY_METADATA_FILE).read_text(encoding="utf-8")
        assert "msvcrt-static" in text
        assert "msvc-6.0-sp6" in text
        # the preset's cflags still fill in
        ovr = find_library_override(lib, tmp_path)
        assert ovr is not None and ovr.cflags == "/O2 /Gd /MT"

    def test_set_unknown_library_name_warns(self, tmp_path: Path) -> None:
        lib = tmp_path / "lib"
        lib.mkdir()
        res = self._invoke("set", str(lib), "--library", "msvcrt-sttaic")
        assert res.exit_code == 0, res.output
        assert "not a known library preset" in res.output
        assert "msvcrt-sttaic" in (lib / LIBRARY_METADATA_FILE).read_text(encoding="utf-8")

    def test_set_dry_run_writes_nothing(self, tmp_path: Path) -> None:
        lib = tmp_path / "lib"
        lib.mkdir()
        res = self._invoke("set", str(lib), "--toolchain", "msvc-6.0", "--dry-run")
        assert res.exit_code == 0, res.output
        assert "would write" in res.output
        assert not (lib / LIBRARY_METADATA_FILE).exists()

    def test_rm_dry_run_keeps_file(self, tmp_path: Path) -> None:
        lib = tmp_path / "lib"
        lib.mkdir()
        (lib / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc-6.0"\n', encoding="utf-8")
        res = self._invoke("rm", str(lib), "--dry-run")
        assert res.exit_code == 0, res.output
        assert "would remove" in res.output
        assert (lib / LIBRARY_METADATA_FILE).exists()

    def test_unknown_toolchain_fails(self, tmp_path: Path) -> None:
        lib = tmp_path / "lib"
        lib.mkdir()
        res = self._invoke("set", str(lib), "--toolchain", "bogus-nope")
        assert res.exit_code == 2
        assert "unknown toolchain" in res.output
        assert not (lib / LIBRARY_METADATA_FILE).exists()

    def test_known_toolchain_accepts_all_profiles(self, tmp_path: Path) -> None:
        """Every registry profile is settable (docker-backed and native)."""
        from rebrew.toolchain import TOOLCHAINS

        for name in sorted(TOOLCHAINS):
            lib = tmp_path / name
            lib.mkdir()
            res = self._invoke("set", str(lib), "--toolchain", name)
            assert res.exit_code == 0, f"{name}: {res.output}"
            ovr = find_library_override(lib, tmp_path)
            assert ovr is not None and ovr.toolchain == name, name

    def test_unknown_preset_fails(self, tmp_path: Path) -> None:
        lib = tmp_path / "lib"
        lib.mkdir()
        res = self._invoke("set", str(lib), "--preset", "nope")
        assert res.exit_code == 2

    def test_set_preserves_comments_and_key_order(self, tmp_path: Path) -> None:
        """An in-place edit keeps what a hand-written file carries."""
        lib = tmp_path / "lib"
        lib.mkdir()
        meta = lib / LIBRARY_METADATA_FILE
        meta.write_text(
            "# MSVC CRT, built with the static multithreaded runtime\n"
            'library = "msvcrt-static"\n'
            'toolchain = "msvc-6.0"\n',
            encoding="utf-8",
        )
        res = self._invoke("set", str(lib), "--cflags", "/O1")
        assert res.exit_code == 0, res.output
        text = meta.read_text(encoding="utf-8")
        assert "# MSVC CRT" in text
        assert text.index("library") < text.index("cflags")

    def test_set_refuses_malformed_store(self, tmp_path: Path) -> None:
        """A bad file is never silently replaced by a fresh document."""
        lib = tmp_path / "lib"
        lib.mkdir()
        meta = lib / LIBRARY_METADATA_FILE
        bad = "toolchain = \n"
        meta.write_text(bad, encoding="utf-8")
        res = self._invoke("set", str(lib), "--toolchain", "msvc-6.0")
        assert res.exit_code != 0
        assert meta.read_text(encoding="utf-8") == bad

    def test_set_writes_under_the_metadata_write_lock(self, tmp_path: Path) -> None:
        """The read-modify-write is serialized against a competing writer."""
        import threading

        from rebrew.utils import file_lock

        lib = tmp_path / "lib"
        lib.mkdir()
        meta = lib / LIBRARY_METADATA_FILE
        meta.write_text('toolchain = "msvc-6.0"\n', encoding="utf-8")

        held = threading.Event()
        release = threading.Event()
        errors: list[BaseException] = []

        def _hold() -> None:
            try:
                with file_lock(meta.with_suffix(meta.suffix + ".lock")):
                    held.set()
                    release.wait(10)
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)

        holder = threading.Thread(target=_hold, daemon=True)
        holder.start()
        assert held.wait(10)
        writer = threading.Thread(
            target=lambda: self._invoke("set", str(lib), "--cflags", "/O1"), daemon=True
        )
        writer.start()
        try:
            writer.join(2)
            assert writer.is_alive(), "set completed while another writer held the lock"
            assert 'cflags = "/O1"' not in meta.read_text(encoding="utf-8")
        finally:
            release.set()
            holder.join(10)
            writer.join(10)
        assert errors == []
        assert 'cflags = "/O1"' in meta.read_text(encoding="utf-8")


class TestLibraryCacheConcurrency:
    def test_negative_miss_sees_newly_created_file(self, tmp_path: Path) -> None:
        """A miss must not freeze 'no override' after a library file appears.

        Caching ``None`` hid hand-created (or uncleared) ``rebrew-libraries.toml``
        for the process lifetime and served project defaults instead.
        """
        from rebrew.metadata import (
            LIBRARY_METADATA_FILE,
            clear_library_override_cache,
            find_library_override,
        )

        lib = tmp_path / "lib"
        lib.mkdir()
        clear_library_override_cache()
        assert find_library_override(lib, tmp_path) is None
        (lib / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc-6.0"\n', encoding="utf-8")
        ovr = find_library_override(lib, tmp_path)
        assert ovr is not None and ovr.toolchain == "msvc-6.0"

    def test_nearer_library_file_created_later_wins(self, tmp_path: Path) -> None:
        """Nearest-wins must hold after an outer hit was already resolved."""
        from rebrew.metadata import (
            LIBRARY_METADATA_FILE,
            clear_library_override_cache,
            find_library_override,
        )

        inner = tmp_path / "lib" / "crt"
        inner.mkdir(parents=True)
        (tmp_path / "lib" / LIBRARY_METADATA_FILE).write_text(
            'toolchain = "msvc-6.0"\n', encoding="utf-8"
        )
        clear_library_override_cache()
        ovr = find_library_override(inner, tmp_path)
        assert ovr is not None and ovr.toolchain == "msvc-6.0"
        (inner / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc-4.2"\n', encoding="utf-8")
        ovr = find_library_override(inner, tmp_path)
        assert ovr is not None and ovr.toolchain == "msvc-4.2"

    def test_concurrent_deleted_library_file_lookup_does_not_raise(self, tmp_path: Path) -> None:
        """Workers that all observe a deleted library file must not raise."""
        import threading

        from thread_util import join_all

        from rebrew.metadata import (
            LIBRARY_METADATA_FILE,
            clear_library_override_cache,
            find_library_override,
        )

        lib = tmp_path / "lib"
        lib.mkdir()
        meta = lib / LIBRARY_METADATA_FILE
        meta.write_text('toolchain = "msvc-6.0"\n', encoding="utf-8")
        clear_library_override_cache()
        assert find_library_override(lib, tmp_path) is not None
        meta.unlink()

        errors: list[BaseException] = []

        def _worker() -> None:
            try:
                for _ in range(50):
                    find_library_override(lib, tmp_path)
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker, daemon=True) for _ in range(16)]
        for t in threads:
            t.start()
        join_all(threads)
        assert errors == []
