"""Tests for shared multi-version sources (src/shared + per-target defines).

The isledecomp-style model: one source file serves multiple targets —
it carries one ``// FUNCTION: <target> <va>`` marker per target (the same
function at a different VA in each version) and ``#ifdef`` deltas driven by
the per-target ``defines``.  rebrew maps this onto its per-target machinery:
a project-level ``shared_dir`` (default ``src/shared``) scanned for every
target, with per-target compile-time defines.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew.config import ProjectConfig

CC = b"\xcc"


def _cfg(
    tmp_path: Path,
    target: str = "V2",
    *,
    shared: str = "src/shared",
    defines: list[str] | None = None,
) -> ProjectConfig:
    rev = tmp_path / f"src_{target}"
    rev.mkdir(parents=True, exist_ok=True)
    if shared:
        (tmp_path / shared).mkdir(parents=True, exist_ok=True)
    return ProjectConfig(
        root=tmp_path,
        target_name=target,
        marker=target,
        reversed_dir=rev,
        shared_dir=tmp_path / shared if shared else None,
        function_list=tmp_path / "functions.txt",
        defines=defines or [],
    )


class TestConfig:
    def test_shared_dir_and_defines_parsed(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text(
            "[project]\nname = 'p'\ndefault_target = 'V1'\nshared_dir = 'src/shared'\n"
            "[compiler]\nprofile = 'msvc6'\ncommand = 'CL.EXE'\n"
            "[targets.V1]\nbinary = 'a.exe'\ndefines = ['V1']\n"
            "[targets.V2]\nbinary = 'b.exe'\ndefines = ['V2', 'DEBUG']\n",
            encoding="utf-8",
        )
        (tmp_path / "a.exe").write_bytes(b"MZ")
        (tmp_path / "b.exe").write_bytes(b"MZ")

        from rebrew.config import load_config

        cfg1 = load_config(tmp_path, target="V1")
        cfg2 = load_config(tmp_path, target="V2")
        assert cfg1.shared_dir == tmp_path / "src" / "shared"
        assert cfg1.defines == ["V1"]
        assert cfg2.defines == ["V2", "DEBUG"]

    def test_shared_dir_can_be_disabled(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text(
            "[project]\nname = 'p'\ndefault_target = 'V1'\nshared_dir = ''\n"
            "[compiler]\nprofile = 'msvc6'\ncommand = 'CL.EXE'\n"
            "[targets.V1]\nbinary = 'a.exe'\n",
            encoding="utf-8",
        )
        (tmp_path / "a.exe").write_bytes(b"MZ")

        from rebrew.config import load_config

        assert load_config(tmp_path, target="V1").shared_dir is None

    def test_defines_defaults_empty(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        assert cfg.defines == []

    def test_defines_reject_non_string(self, tmp_path: Path) -> None:
        """Non-string define entries are dropped with a warning — str(None)
        would otherwise become a garbage -DNone flag."""
        from rebrew.config import _parse_defines

        assert _parse_defines(["V2", None, 42, "", "  DEBUG  "], "targets.X.defines") == [
            "V2",
            "DEBUG",
        ]

    def test_base_cflags_default_per_profile(self, tmp_path: Path) -> None:
        """A posix profile (gcc-pe) must NOT default to the MSVC glue
        base_cflags (/nologo /c /MT) — that breaks every gcc compile for
        hand-written tomls that omit base_cflags."""
        for profile, command, expected in (
            ("gcc-pe", "i686-w64-mingw32-gcc", ""),
            ("watcom", "wcc386", ""),
            ("msvc6", "CL.EXE", "/nologo /c /MT"),
        ):
            proj = tmp_path / profile
            proj.mkdir(parents=True, exist_ok=True)
            (proj / "rebrew-project.toml").write_text(
                f"[project]\nname = 'p'\ndefault_target = 'T'\n"
                f"[compiler]\nprofile = '{profile}'\ncommand = '{command}'\n"
                f"[targets.T]\nbinary = 'a.exe'\n",
                encoding="utf-8",
            )
            (proj / "a.exe").write_bytes(b"MZ")

            from rebrew.config import load_config

            assert load_config(proj, target="T").base_cflags == expected


class TestIterSources:
    def test_includes_shared_sources(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "local.c").write_text("int l(void){return 1;}\n", encoding="utf-8")
        (cfg.shared_dir / "common.c").write_text("int c(void){return 1;}\n", encoding="utf-8")

        from rebrew.sources import iter_sources

        files = iter_sources(cfg.reversed_dir, cfg)
        assert (cfg.reversed_dir / "local.c") in files
        assert (cfg.shared_dir / "common.c") in files

    def test_disabled_shared_dir_excluded(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path, shared="")
        (cfg.reversed_dir / "local.c").write_text("x", encoding="utf-8")

        from rebrew.sources import iter_sources

        files = iter_sources(cfg.reversed_dir, cfg)
        assert files == [cfg.reversed_dir / "local.c"]

    def test_absent_shared_dir_is_noop(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        cfg.shared_dir = tmp_path / "src" / "nope"  # never created
        (cfg.reversed_dir / "local.c").write_text("x", encoding="utf-8")

        from rebrew.sources import iter_sources

        assert iter_sources(cfg.reversed_dir, cfg) == [cfg.reversed_dir / "local.c"]

    def test_unrelated_dir_scan_excludes_shared(self, tmp_path: Path) -> None:
        """Shared sources belong to the target's reversed_dir scan ONLY — a
        scan of any other directory with cfg must not pull them in."""
        cfg = _cfg(tmp_path)
        (cfg.shared_dir / "s.c").write_text("x", encoding="utf-8")
        other = tmp_path / "elsewhere"
        other.mkdir(parents=True)
        (other / "o.c").write_text("x", encoding="utf-8")

        from rebrew.sources import iter_sources

        files = iter_sources(other, cfg)
        assert files == [other / "o.c"]


class TestMultiMarkerScan:
    """One shared file, one marker per target — each target sees only its own."""

    def test_shared_file_scans_per_target(self, tmp_path: Path) -> None:
        cfg_v1 = _cfg(tmp_path, "V1")
        cfg_v2 = _cfg(tmp_path, "V2")
        (cfg_v1.shared_dir / "common.c").write_text(
            "// FUNCTION: V1 0x401000\n// FUNCTION: V2 0x501000\nint common(void){ return 1; }\n",
            encoding="utf-8",
        )

        from rebrew.catalog.loaders import scan_reversed_dir

        e1 = scan_reversed_dir(cfg_v1.reversed_dir, cfg_v1)
        e2 = scan_reversed_dir(cfg_v2.reversed_dir, cfg_v2)
        assert [a.va for a in e1] == [0x401000]
        assert [a.va for a in e2] == [0x501000]

        # The filepath resolves from the target's reversed_dir back to the
        # shared file (../shared/common.c).
        resolved = (cfg_v2.reversed_dir / e2[0].filepath).resolve()
        assert resolved == (cfg_v2.shared_dir / "common.c").resolve()

    def test_local_and_shared_coexist(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "local.c").write_text(
            "// FUNCTION: V2 0x502000\nint local(void){ return 1; }\n", encoding="utf-8"
        )
        (cfg.shared_dir / "common.c").write_text(
            "// FUNCTION: V2 0x501000\nint common(void){ return 1; }\n", encoding="utf-8"
        )

        from rebrew.catalog.loaders import scan_reversed_dir

        vas = sorted(a.va for a in scan_reversed_dir(cfg.reversed_dir, cfg))
        assert vas == [0x501000, 0x502000]

    def test_stacked_markers_share_the_function_name(self, tmp_path: Path) -> None:
        """With one marker per target above a single implementation, only the
        last block sees the C definition — the parser must give every block
        the file's one function name (and a resolvable symbol) so each
        target's verify can extract the object symbol."""
        cfg_v1 = _cfg(tmp_path, "V1")
        cfg_v2 = _cfg(tmp_path, "V2")
        (cfg_v1.shared_dir / "common.c").write_text(
            "// FUNCTION: V1 0x401000\n// SIZE: 11\n"
            "// FUNCTION: V2 0x501000\n// SIZE: 11\n"
            "int common(void){ return 1; }\n",
            encoding="utf-8",
        )

        from rebrew.catalog.loaders import scan_reversed_dir

        e1 = scan_reversed_dir(cfg_v1.reversed_dir, cfg_v1)[0]
        e2 = scan_reversed_dir(cfg_v2.reversed_dir, cfg_v2)[0]
        assert e1.name == "common" and e1.symbol == "_common"
        assert e2.name == "common" and e2.symbol == "_common"

    def test_multi_function_file_unaffected(self, tmp_path: Path) -> None:
        """A file with genuinely different functions keeps per-block names —
        the one-name fallback does not fire."""
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "two.c").write_text(
            "// FUNCTION: V2 0x502000\nint alpha(void){ return 1; }\n"
            "// FUNCTION: V2 0x502010\nint beta(void){ return 2; }\n",
            encoding="utf-8",
        )

        from rebrew.catalog.loaders import scan_reversed_dir

        names = {a.name for a in scan_reversed_dir(cfg.reversed_dir, cfg)}
        assert names == {"alpha", "beta"}

    def test_bodyless_library_block_not_misnamed(self, tmp_path: Path) -> None:
        """The stacked-marker name fallback must not leak the file's function
        name onto a bodyless LIBRARY/STUB entry (a CRT import has no C body)."""
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "mixed.c").write_text(
            "// FUNCTION: V2 0x502000\nint real(void){ return 1; }\n// LIBRARY: V2 0x502100\n",
            encoding="utf-8",
        )

        from rebrew.catalog.loaders import scan_reversed_dir

        by_va = {a.va: a for a in scan_reversed_dir(cfg.reversed_dir, cfg)}
        assert by_va[0x502000].name == "real"
        assert by_va[0x502100].name == ""  # no body → no inherited name

    def test_shared_library_header_scanned(self, tmp_path: Path) -> None:
        """A library_*.h in the shared root contributes LIBRARY markers to
        every target's scan."""
        cfg = _cfg(tmp_path)
        (cfg.shared_dir / "library_foo.h").write_text(
            "// LIBRARY: V2 0x503000\n_foo_init\n", encoding="utf-8"
        )

        from rebrew.catalog.loaders import scan_reversed_dir

        vas = {a.va for a in scan_reversed_dir(cfg.reversed_dir, cfg)}
        assert 0x503000 in vas


class TestDefinesCompile:
    """Per-target defines reach the compiler with the right flag style."""

    def _run_compile(
        self, tmp_path: Path, monkeypatch, profile: str, defines: list[str]
    ) -> list[str]:
        from rebrew.compile import compile_to_obj

        captured: dict[str, list[str]] = {}

        def _fake_run(spec, args, *, workdir, timeout, mounts=None):
            captured["args"] = args
            (workdir / "f.obj").write_bytes(b"\x00OBJ")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("rebrew.compile.run_toolchain", _fake_run)

        cfg: Any = SimpleNamespace(
            compiler_includes=tmp_path,
            base_cflags="",
            compile_timeout=3,
            msvc_env=lambda: {},
            compiler_command="CL.EXE",
            compiler_libs=tmp_path,
            compiler_runner="",
            root=tmp_path,
            compiler_profile=profile,
            posix_style=False,
            defines=defines,
        )
        src = tmp_path / "f.c"
        src.write_text("int f(void){ return 1; }\n", encoding="utf-8")
        wd = tmp_path / "w"
        wd.mkdir()
        compile_to_obj(cfg, src, ["-O2"], wd, use_cache=False)
        return captured["args"]

    def test_msvc_style_slash_d(self, tmp_path: Path, monkeypatch) -> None:
        args = self._run_compile(tmp_path, monkeypatch, "msvc6", ["V2"])
        assert "/DV2" in args

    def test_posix_style_dash_d(self, tmp_path: Path, monkeypatch) -> None:
        args = self._run_compile(tmp_path, monkeypatch, "gcc-pe", ["V2"])
        assert "-DV2" in args

    def test_matcher_raw_path_applies_defines(self, tmp_path: Path, monkeypatch) -> None:
        """The GA's raw subprocess path (native gcc-pe) must compile with the
        per-target defines too, or GA results diverge from verify."""
        from rebrew.matcher.compiler import build_candidate_obj_only

        captured: dict[str, list[str]] = {}
        mini_obj = (Path(__file__).parent / "fixtures" / "mini.obj").read_bytes()

        def _fake_run(cmd, **kw):
            captured["cmd"] = cmd
            import pathlib

            cwd = pathlib.Path(kw.get("cwd", "."))
            (cwd / "cand.obj").write_bytes(mini_obj)
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("rebrew.matcher.compiler.subprocess.run", _fake_run)

        cfg = SimpleNamespace(defines=["V2"], root=tmp_path)
        build_candidate_obj_only(
            "int f(void){ return 1; }\n",
            "i686-w64-mingw32-gcc",
            str(tmp_path),
            "-O2",
            "_f",
            env=None,
            posix_style=True,
            cfg=cfg,
        )
        assert "-DV2" in captured["cmd"]

    def test_ga_cache_key_covers_defines(self) -> None:
        """The GA's per-run build cache key must change when the per-target
        defines change (a version switch alters #ifdef-driven codegen)."""
        from rebrew.match import _ga_cache_key

        base = ("src", "-O2", "gcc", "/inc")
        k1 = _ga_cache_key(*base, defines=[])
        k2 = _ga_cache_key(*base, defines=["V2"])
        assert k1 != k2

    def test_empty_inc_dir_raw_path_compiles(self, tmp_path: Path, monkeypatch) -> None:
        """The raw subprocess path must not emit a bare -I//I when the include
        dir is empty (gcc-pe allows no includes) — compile.py already guards
        this; the matcher path must too."""
        from rebrew.matcher.compiler import build_candidate_obj_only

        captured: dict[str, list[str]] = {}

        def _fake_run(cmd, **kw):
            captured["cmd"] = cmd
            import pathlib

            (pathlib.Path(kw.get("cwd", ".")) / "cand.obj").write_bytes(b"\x00OBJ")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr("rebrew.matcher.compiler.subprocess.run", _fake_run)

        build_candidate_obj_only(
            "int f(void){ return 1; }\n",
            "i686-w64-mingw32-gcc",
            "",  # empty include dir
            "-O2",
            "_f",
            posix_style=True,
            profile="gcc-pe",
            cfg=SimpleNamespace(defines=[], root=tmp_path),
        )
        assert "-I" not in captured["cmd"] or not any(
            f == "-I" or f == "/I" for f in captured["cmd"]
        )

    def test_flag_sweep_refused_for_posix(self) -> None:
        """The flag sweep explores MSVC flag combos — for a posix compiler
        every combo would fail; it must refuse loudly instead of silently
        wasting compiles."""
        import pytest

        from rebrew.matcher.compiler import flag_sweep

        with pytest.raises(ValueError, match="MSVC-only"):
            flag_sweep(
                "int f(void){ return 1; }\n",
                b"\xb8\x01\x00\x00\x00\xc3",
                "gcc",
                "",
                "",
                "_f",
                posix_style=True,
                profile="gcc-pe",
                cfg=None,
            )


class TestGANativeEndToEnd:
    """The full GA with a native (no-docker) toolchain — real compiles."""

    @pytest.mark.skipif(
        shutil.which("i686-w64-mingw32-gcc") is None,
        reason="gcc-pe toolchain not installed",
    )
    def test_ga_finds_exact_match_with_gcc_pe(self, tmp_path: Path) -> None:
        from bin_util import make_pe

        from rebrew.binary_loader import extract_raw_bytes
        from rebrew.match import BinaryMatchingGA

        # mov eax,1; ret — the seed below compiles to exactly this.
        target = bytes.fromhex("b8 01 00 00 00 c3")
        binary = tmp_path / "game.exe"
        binary.write_bytes(make_pe(target + CC * 16))

        cfg = ProjectConfig(
            root=tmp_path,
            target_name="GAME",
            marker="GAME",
            target_binary=binary,
            reversed_dir=tmp_path / "src" / "GAME",
            shared_dir=None,
            function_list=tmp_path / "functions.txt",
            compiler_command="i686-w64-mingw32-gcc",
            compiler_profile="gcc-pe",
            base_cflags="",
            cflags="-O2",
            compiler_includes="",
            compiler_libs="",
        )
        target_bytes = extract_raw_bytes(binary, 0x401000, len(target))

        ga = BinaryMatchingGA(
            seed_source="int f(void){ return 1; }\n",
            target_bytes=target_bytes,
            cl_cmd="i686-w64-mingw32-gcc",
            inc_dir=str(tmp_path),
            cflags="-O2",
            symbol="_f",
            out_dir=tmp_path / "ga",
            pop_size=4,
            num_generations=3,
            rng_seed=42,
            env=None,
            posix_style=True,
            profile="gcc-pe",
            cfg=cfg,
        )
        best_src, best_score = ga.run()
        assert best_score == 0.0  # exact match found by the native toolchain


class TestVerifySharedFile:
    """verify_entry resolves a shared filepath (../shared/...) and compiles it."""

    @pytest.mark.skipif(
        shutil.which("i686-w64-mingw32-gcc") is None,
        reason="gcc-pe toolchain not installed",
    )
    def test_verify_compiles_shared_function(self, tmp_path: Path) -> None:
        from bin_util import make_pe

        F1 = bytes.fromhex("55 8b ec 8b 05 00 00 00 00 5d c3")
        binary = tmp_path / "b.exe"
        binary.write_bytes(make_pe(F1 + CC * 16))

        cfg = ProjectConfig(
            root=tmp_path,
            target_name="V2",
            marker="V2",
            target_binary=binary,
            reversed_dir=tmp_path / "src_V2",
            shared_dir=tmp_path / "src" / "shared",
            function_list=tmp_path / "functions.txt",
            compiler_command="i686-w64-mingw32-gcc",
            compiler_profile="gcc-pe",
            base_cflags="",
            cflags="-O2",
            compiler_includes="",
            compiler_libs="",
            defines=["V2"],
        )
        (cfg.reversed_dir).mkdir(parents=True, exist_ok=True)
        cfg.shared_dir.mkdir(parents=True, exist_ok=True)
        (cfg.shared_dir / "f.c").write_text(
            "// FUNCTION: V2 0x401000\n// SIZE: 11\nint f(void){ return 1; }\n",
            encoding="utf-8",
        )

        from rebrew.catalog.loaders import scan_reversed_dir
        from rebrew.verify import verify_entry

        entries = scan_reversed_dir(cfg.reversed_dir, cfg)
        assert len(entries) == 1
        result = verify_entry(entries[0], cfg)
        # The shared file was found and compiled (not a tooling failure);
        # byte-exactness is not guaranteed with gcc-pe.
        assert result.status not in (
            "COMPILE_ERROR",
            "EXTRACT_ERROR",
            "INTERNAL_ERROR",
            "MISSING_FILE",
        ), result.message
