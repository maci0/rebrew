"""Tests for `rebrew diagnose` — the compile-config resolution trace.

Walks the declared-dependency chain (per-function metadata → nearest
rebrew-library.toml → project defaults) for a source file and validates the
declarations (unknown toolchains, preset contradictions, family drift).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from rebrew.diagnose import _warnings_for, diagnose_source


def _cfg(tmp_path: Path, **over: object) -> SimpleNamespace:
    """A minimal project config (SimpleNamespace — diagnose reads via getattr)."""
    base: dict[str, object] = {
        "root": tmp_path,
        "metadata_dir": None,
        "compiler_profile": "msvc6",
        "cflags": "",
        "cflags_explicit": False,
        "cflags_presets": {},
        "posix_style": False,
    }
    base.update(over)
    return SimpleNamespace(**base)


def _src(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def _lib(tmp_path: Path, body: str) -> Path:
    lib = tmp_path / "lib"
    lib.mkdir(exist_ok=True)
    (lib / "rebrew-library.toml").write_text(body, encoding="utf-8")
    return lib


_FN = "// FUNCTION: DEMO 0x01001000\nint f(int a) {{ return a + 1; }}\n"


class TestDiagnoseSource:
    def test_project_default_chain(self, tmp_path: Path) -> None:
        src = _src(tmp_path, "f.c", _FN)
        entry = diagnose_source(_cfg(tmp_path), src)
        fn = entry["functions"][0]
        assert fn["va"] == 0x01001000
        assert [s["source"] for s in fn["steps"]] == ["function", "library", "project"]
        assert fn["steps"][0] == {"source": "function", "toolchain": "", "cflags": ""}
        assert fn["steps"][1] == {"source": "library", "path": None}
        assert fn["effective"] == {"toolchain": "msvc6", "cflags": "/O2 /Gd"}
        assert fn["warnings"] == []

    def test_library_preset_chain(self, tmp_path: Path) -> None:
        lib = _lib(tmp_path, 'library = "watcom-runtime"\n')
        src = _src(lib, "g.c", "// FUNCTION: DEMO 0x01002000\nint g(int a) { return a * 2; }\n")
        fn = diagnose_source(_cfg(tmp_path), src)["functions"][0]
        lib_step = fn["steps"][1]
        assert lib_step["presets"] == ["watcom-runtime"]
        assert fn["effective"] == {"toolchain": "watcom", "cflags": "-ot"}
        assert fn["warnings"] == []

    def test_function_metadata_beats_all(self, tmp_path: Path) -> None:
        src = _src(
            tmp_path,
            "f2.c",
            "// FUNCTION: DEMO 0x01003000\n// TOOLCHAIN: msvc600sp6\n// CFLAGS: /O1\n"
            "int f2(int a) { return a - 1; }\n",
        )
        fn = diagnose_source(_cfg(tmp_path), src)["functions"][0]
        assert fn["steps"][0] == {
            "source": "function",
            "toolchain": "msvc600sp6",
            "cflags": "/O1",
        }
        assert fn["effective"] == {"toolchain": "msvc600sp6", "cflags": "/O1"}

    def test_explicit_empty_cflags_suppresses_fallback(self, tmp_path: Path) -> None:
        src = _src(tmp_path, "f.c", _FN)
        cfg = _cfg(tmp_path, cflags="", cflags_explicit=True)
        fn = diagnose_source(cfg, src)["functions"][0]
        assert fn["effective"]["cflags"] == ""  # no silent /O2 /Gd

    def test_posix_profile_no_fallback(self, tmp_path: Path) -> None:
        src = _src(tmp_path, "f.c", _FN)
        cfg = _cfg(tmp_path, compiler_profile="gcc-pe", posix_style=True)
        fn = diagnose_source(cfg, src)["functions"][0]
        assert fn["effective"]["cflags"] == ""

    def test_no_annotations_reports_default(self, tmp_path: Path) -> None:
        src = _src(tmp_path, "plain.c", "int f(int a) { return a; }\n")
        fn = diagnose_source(_cfg(tmp_path), src)["functions"][0]
        assert fn["va"] is None
        assert fn["effective"] == {"toolchain": "msvc6", "cflags": "/O2 /Gd"}


class TestDeclaredResolutionValidation:
    def test_unknown_function_toolchain_warning(self, tmp_path: Path) -> None:
        src = _src(
            tmp_path,
            "bad.c",
            "// FUNCTION: DEMO 0x01004000\n// TOOLCHAIN: msvc9\nint bad(int a) { return a; }\n",
        )
        fn = diagnose_source(_cfg(tmp_path), src)["functions"][0]
        assert any("unknown toolchain 'msvc9'" in w for w in fn["warnings"])

    def test_unknown_library_toolchain_warning(self, tmp_path: Path) -> None:
        lib = _lib(tmp_path, 'toolchain = "msvc9"\n')
        src = _src(lib, "g.c", "// FUNCTION: DEMO 0x01005000\nint g(int a) { return a; }\n")
        fn = diagnose_source(_cfg(tmp_path), src)["functions"][0]
        assert any("unknown toolchain 'msvc9'" in w for w in fn["warnings"])

    def test_preset_contradiction_warning(self, tmp_path: Path) -> None:
        lib = _lib(tmp_path, 'library = "watcom-runtime"\n')
        src = _src(
            lib,
            "g.c",
            "// FUNCTION: DEMO 0x01006000\n// TOOLCHAIN: msvc6\nint g(int a) { return a; }\n",
        )
        fn = diagnose_source(_cfg(tmp_path), src)["functions"][0]
        assert any("watcom-runtime" in w and "conflicting" in w for w in fn["warnings"])

    def test_family_mismatch_warning(self, tmp_path: Path) -> None:
        lib = _lib(tmp_path, 'toolchain = "watcom"\n')
        src = _src(
            lib,
            "g.c",
            "// FUNCTION: DEMO 0x01007000\n// TOOLCHAIN: msvc6\nint g(int a) { return a; }\n",
        )
        fn = diagnose_source(_cfg(tmp_path), src)["functions"][0]
        assert any("family msvc" in w and "family watcom" in w for w in fn["warnings"])

    def test_consistent_declarations_no_warnings(self, tmp_path: Path) -> None:
        lib = _lib(tmp_path, 'toolchain = "watcom"\n')
        src = _src(lib, "g.c", "// FUNCTION: DEMO 0x01008000\nint g(int a) { return a; }\n")
        fn = diagnose_source(_cfg(tmp_path), src)["functions"][0]
        assert fn["warnings"] == []


class TestWarningsHelper:
    def test_empty_steps_no_warnings(self) -> None:
        assert _warnings_for([], None) == []

    def test_unknown_toolchain_flags_library_declaration(self, tmp_path: Path) -> None:
        lib = _lib(tmp_path, 'toolchain = "msvc9"\n')
        steps = [
            {"source": "function", "toolchain": "", "cflags": ""},
            {
                "source": "library",
                "path": str(lib / "rebrew-library.toml"),
                "toolchain": "msvc9",
                "cflags": "",
                "presets": [],
            },
        ]
        warnings = _warnings_for(steps, None)
        assert any("unknown toolchain 'msvc9'" in w for w in warnings)
