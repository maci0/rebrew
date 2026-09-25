"""Tests for rebrew.intake — one-shot binary onboarding."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from rebrew.intake import _suggest_profile, blocker_reason

FAKE_FUNCS = [(0x401000, 32, "fcn.00401000"), (0x401020, 8, "fcn.00401020")]


def _run_main(tmp_path: Path, monkeypatch, *, argv: list[str]) -> str:
    """Invoke the intake CLI (via the real `rebrew intake` command), capturing stdout."""
    from typer.testing import CliRunner

    import rebrew.main as main_mod

    runner = CliRunner()
    monkeypatch.chdir(tmp_path)

    def _fake_discover(binary: Path) -> list[tuple[int, int, str]]:
        return FAKE_FUNCS

    monkeypatch.setattr("rebrew.intake._enumerate_functions", _fake_discover)
    monkeypatch.setattr(
        "rebrew.intake._suggest_profile",
        lambda b: ("msvc-6.0", "msvc", "MSVC 6.0", []),
    )
    result = runner.invoke(main_mod.app, ["intake", *argv])
    assert result.exit_code == 0, result.output
    return result.output


class TestIntake:
    def test_dry_run_no_writes(self, tmp_path: Path, monkeypatch) -> None:
        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")
        out = _run_main(tmp_path, monkeypatch, argv=["game.exe", "--dry-run", "--json"])
        data = json.loads(out)
        assert data["dry_run"] is True
        assert data["profile"] == "msvc-6.0"
        assert data["family"] == "msvc"
        # The preview now runs the discoverers (read-only) so the user sees the real
        # function count before committing to the onboarding.
        assert data["function_count"] == 2
        assert not (tmp_path / "rebrew-project.toml").exists()

    def test_full_intake_writes_project(self, tmp_path: Path, monkeypatch) -> None:
        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")
        out = _run_main(tmp_path, monkeypatch, argv=["game.exe", "--json"])
        data = json.loads(out)
        assert data["functions"] == 2
        assert data["documented"] == 2
        assert data["target"] == "game"
        # function_structure.json written
        funcs = (tmp_path / "src" / "game" / "function_structure.json").read_text()
        assert "0x00401000" not in funcs  # VAs are ints, not hex strings
        assert "4198400" in funcs  # 0x401000
        assert "fcn.00401000" in funcs
        # STUB .c written
        stub = (tmp_path / "src" / "game" / "fcn_00401000.c").read_text()
        assert "// STUB: GAME 0x00401000" in stub
        # metadata has blocker + STUB
        meta = (tmp_path / "src" / "rebrew-functions.toml").read_text()
        assert "blocker" in meta
        assert 'status = "STUB"' in meta
        # documented stubs carry the disassembly-derived SIZE so rebrew test
        # can run on them (a size-less stub is untestable + reports MISSING_SIZE)
        assert "size = 32" in meta
        assert "size = 8" in meta
        # binary copied
        assert (tmp_path / "original" / "game.exe").exists()

    def test_rediscovery_does_not_recopy_or_rewrite_config(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """A second intake of the same binary leaves original/ and the project file alone."""
        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")
        _run_main(tmp_path, monkeypatch, argv=["game.exe", "--json"])
        dest = tmp_path / "original" / "game.exe"
        os.utime(dest, ns=(1_000_000_000, 1_000_000_000))
        toml = (tmp_path / "rebrew-project.toml").read_bytes()
        _run_main(tmp_path, monkeypatch, argv=["game.exe", "--json"])
        assert dest.read_bytes() == b"MZ"
        assert dest.stat().st_mtime_ns == 1_000_000_000
        assert (tmp_path / "rebrew-project.toml").read_bytes() == toml

    def test_rediscovery_replaces_a_changed_binary(self, tmp_path: Path, monkeypatch) -> None:
        """A different payload is still copied; only an identical dest is left alone."""
        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")
        _run_main(tmp_path, monkeypatch, argv=["game.exe", "--json"])
        binary.write_bytes(b"MZ-next")
        _run_main(tmp_path, monkeypatch, argv=["game.exe", "--json"])
        assert (tmp_path / "original" / "game.exe").read_bytes() == b"MZ-next"

    def test_intake_of_binary_already_in_original(self, tmp_path: Path, monkeypatch) -> None:
        """``rebrew intake original/<name>`` must converge, not copy the file onto itself."""
        original = tmp_path / "original"
        original.mkdir()
        binary = original / "game.exe"
        binary.write_bytes(b"MZ")
        os.utime(binary, ns=(1_000_000_000, 1_000_000_000))
        out = _run_main(tmp_path, monkeypatch, argv=["original/game.exe", "--json"])
        assert json.loads(out)["functions"] == 2
        assert binary.read_bytes() == b"MZ"
        assert binary.stat().st_mtime_ns == 1_000_000_000
        toml = (tmp_path / "rebrew-project.toml").read_bytes()
        _run_main(tmp_path, monkeypatch, argv=["original/game.exe", "--json"])
        assert binary.stat().st_mtime_ns == 1_000_000_000
        assert (tmp_path / "rebrew-project.toml").read_bytes() == toml

    @pytest.mark.parametrize("status", ["STUB", "RELOC"])
    def test_rediscovery_does_not_duplicate_renamed_functions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
    ) -> None:
        from rebrew.annotation import iter_annotations
        from rebrew.metadata import get_entry, update_field, update_source_status
        from rebrew.sources import iter_sources

        (tmp_path / "game.exe").write_bytes(b"MZ")
        argv = ["game.exe", "--json"]
        _run_main(tmp_path, monkeypatch, argv=argv)
        src_dir = tmp_path / "src" / "game"
        metadata_dir = tmp_path / "src"
        original = src_dir / "fcn_00401000.c"
        nested = src_dir / "render"
        nested.mkdir()
        renamed = nested / "render_frame.c"
        original.rename(renamed)
        update_source_status(metadata_dir, status, "GAME", 0x401000)
        update_field(metadata_dir, 0x401000, "blocker", "Needs float math", module="GAME")
        update_field(metadata_dir, 0x401000, "size", 30, module="GAME")
        expected_sources = {path: path.read_bytes() for path in iter_sources(src_dir)}

        for _ in range(2):
            _run_main(tmp_path, monkeypatch, argv=argv)
            assert not original.exists()
            assert {path: path.read_bytes() for path in iter_sources(src_dir)} == expected_sources
            annotations = [
                ann
                for _, anns in iter_annotations(iter_sources(src_dir), target="GAME")
                for ann in anns
                if ann["va"] == 0x401000
            ]
            assert len(annotations) == 1
            entry = get_entry(metadata_dir, 0x401000, "GAME")
            assert entry["status"] == status
            assert entry["blocker"] == "Needs float math"
            assert entry["size"] == 30

    def test_binary_missing_fails(self, tmp_path: Path, monkeypatch) -> None:
        from typer.testing import CliRunner

        import rebrew.main as main_mod

        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(main_mod.app, ["intake", "nope.exe", "--json"])
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_docker_toolchain_message_when_link_missing(self, tmp_path: Path, monkeypatch) -> None:
        """A docker-backed profile with no tools/ symlink must say the image
        is the toolchain (with the build command), not 'symlink tools/ yourself'
        — the first-run message a new user actually acts on."""
        from typer.testing import CliRunner

        import rebrew.main as main_mod

        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")
        monkeypatch.setattr("rebrew.intake._enumerate_functions", lambda b: FAKE_FUNCS)
        monkeypatch.setattr(
            "rebrew.intake._suggest_profile",
            lambda b: ("msvc-6.0", "msvc", "MSVC 6.0", []),
        )
        monkeypatch.setattr("rebrew.intake._link_toolchain", lambda project, profile: None)
        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(main_mod.app, ["intake", "game.exe"])
        assert result.exit_code == 0, result.output
        combined = result.stdout + result.stderr
        assert "docker image" in combined
        assert "toolchain build" in combined
        assert "symlink tools" not in combined

    def test_empty_discovery_fails(self, tmp_path: Path, monkeypatch) -> None:
        """Regression: no discoverer finding functions must not be
        reported as a successful 'Intake complete: functions: 0' — onboarding
        with an empty function list is useless and misleading."""
        from typer.testing import CliRunner

        import rebrew.main as main_mod

        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")
        monkeypatch.setattr("rebrew.intake._enumerate_functions", lambda b: [])
        monkeypatch.setattr(
            "rebrew.intake._suggest_profile",
            lambda b: ("msvc-6.0", "msvc", "MSVC 6.0", []),
        )
        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(main_mod.app, ["intake", "game.exe", "--json"])
        assert result.exit_code != 0
        assert "no functions" in result.output
        # scaffold may exist, but no success payload
        assert '"functions"' not in result.output

    def test_rediscovery_prunes_stale_stubs(self, tmp_path: Path, monkeypatch) -> None:
        """Regression: re-running intake after the function list changes must
        remove auto-generated stubs (and their metadata) for functions that no
        longer exist — otherwise status totals inflate (observed on the 16-bit
        SkiFree NE re-onboarding: 233 orphaned stubs from a broken first run)."""
        from typer.testing import CliRunner

        import rebrew.main as main_mod

        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")

        def _fake_discover_v1(binary: Path) -> list[tuple[int, int, str]]:
            return [(0x401000, 32, "fcn.00401000"), (0x402000, 64, "fcn.00402000")]

        monkeypatch.setattr("rebrew.intake._enumerate_functions", _fake_discover_v1)
        monkeypatch.setattr(
            "rebrew.intake._suggest_profile",
            lambda b: ("msvc-6.0", "msvc", "MSVC 6.0", []),
        )
        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        out1 = runner.invoke(main_mod.app, ["intake", "game.exe", "--json"])
        assert out1.exit_code == 0, out1.output
        assert (tmp_path / "src" / "game" / "fcn_00402000.c").exists()

        # Re-discovery: one function vanishes, one new one appears.
        monkeypatch.setattr(
            "rebrew.intake._enumerate_functions",
            lambda b: [(0x401000, 32, "fcn.00401000"), (0x403000, 16, "fcn.00403000")],
        )
        out2 = runner.invoke(main_mod.app, ["intake", "game.exe", "--json"])
        assert out2.exit_code == 0, out2.output
        # The vanished function's auto-stub is gone; the new one exists.
        assert not (tmp_path / "src" / "game" / "fcn_00402000.c").exists()
        assert (tmp_path / "src" / "game" / "fcn_00403000.c").exists()
        # Metadata entry for the vanished function is gone too.
        meta = (tmp_path / "src" / "rebrew-functions.toml").read_text()
        assert "0x00402000" not in meta
        assert "0x00403000" in meta

    def test_rediscovery_keeps_edited_stubs(self, tmp_path: Path, monkeypatch) -> None:
        """A stub the user has edited (no longer matching the auto-stub
        pattern) must survive re-discovery even if its VA vanishes."""
        from typer.testing import CliRunner

        import rebrew.main as main_mod

        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")
        monkeypatch.setattr(
            "rebrew.intake._enumerate_functions",
            lambda b: [(0x401000, 32, "fcn.00401000"), (0x402000, 64, "fcn.00402000")],
        )
        monkeypatch.setattr(
            "rebrew.intake._suggest_profile",
            lambda b: ("msvc-6.0", "msvc", "MSVC 6.0", []),
        )
        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        out1 = runner.invoke(main_mod.app, ["intake", "game.exe", "--json"])
        assert out1.exit_code == 0, out1.output

        # User replaces the stub with real source (no STUB header).
        stub = tmp_path / "src" / "game" / "fcn_00402000.c"
        stub.write_text("// my decompilation work\nint real_fn(void) { return 0; }\n")

        monkeypatch.setattr(
            "rebrew.intake._enumerate_functions",
            lambda b: [(0x401000, 32, "fcn.00401000")],
        )
        out2 = runner.invoke(main_mod.app, ["intake", "game.exe", "--json"])
        assert out2.exit_code == 0, out2.output
        assert stub.exists()  # edited file survives the prune

    def test_rediscovery_never_demotes_matched_or_clobbers_blocker(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Regression: re-running intake must NOT demote a function the user
        has matched (EXACT/RELOC/NEAR_MATCHING → STUB) nor clobber a
        user-written BLOCKER — the old classify_all wrote STUB + auto blocker
        for every function on every re-run, silently resetting the corpus."""
        from typer.testing import CliRunner

        import rebrew.main as main_mod

        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ")
        monkeypatch.setattr(
            "rebrew.intake._enumerate_functions",
            lambda b: [(0x401000, 32, "fcn.00401000"), (0x402000, 64, "fcn.00402000")],
        )
        monkeypatch.setattr(
            "rebrew.intake._suggest_profile",
            lambda b: ("msvc-6.0", "msvc", "MSVC 6.0", []),
        )
        runner = CliRunner()
        monkeypatch.chdir(tmp_path)
        out1 = runner.invoke(main_mod.app, ["intake", "game.exe", "--json"])
        assert out1.exit_code == 0, out1.output

        # User matches one function (RELOC) and hand-writes a BLOCKER on the
        # other — both must survive a re-run.
        from rebrew.metadata import update_source_status

        update_source_status(tmp_path / "src", "RELOC", "game", 0x401000)
        blocker = tmp_path / "src" / "game" / "fcn_00402000.c"
        blocker.write_text(
            "// STUB: game 0x00402000\n\nvoid fcn_00402000(void)\n{\n    /* user: needs float math */\n}\n"
        )

        out2 = runner.invoke(main_mod.app, ["intake", "game.exe", "--json"])
        assert out2.exit_code == 0, out2.output
        meta = (tmp_path / "src" / "rebrew-functions.toml").read_text()
        # The matched function is NOT demoted back to STUB.
        assert 'status = "RELOC"' in meta
        assert "0x00402000" in meta
        # The user blocker text survives (not replaced by the auto reason).
        assert "needs float math" in blocker.read_text()


class TestBlockers:
    def test_thunk_reason(self) -> None:
        assert "thunk" in blocker_reason("msvc", 6, "")

    def test_delphi_reason(self) -> None:
        assert "Delphi" in blocker_reason("delphi", 64, "")

    def test_mingw_reason(self) -> None:
        assert "MinGW" in blocker_reason("mingw", 64, "pre-8 GCC style")

    def test_default_reason(self) -> None:
        assert "pending" in blocker_reason("msvc", 64, "")


class TestSuggestProfile:
    def test_watcom_routes_to_watcom_profile(self, monkeypatch) -> None:
        from rebrew.toolchain_detect import ToolchainInfo

        def _fake_detect(path) -> ToolchainInfo:
            return ToolchainInfo(family="watcom", confidence="high", version_hint="Watcom C/C++")

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        profile, family, hint, notes = _suggest_profile(Path("x.exe"))
        assert profile == "watcom-2.0-win32"
        assert family == "watcom"
        assert any("watcom" in n for n in notes)

    def test_auto_detection_routing(self, monkeypatch) -> None:
        from rebrew.toolchain_detect import ToolchainInfo

        def _fake_detect(path) -> ToolchainInfo:
            return ToolchainInfo(family="mingw", confidence="high", version_hint="pre-8 GCC style")

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        profile, family, hint, notes = _suggest_profile(Path("x.exe"))
        assert profile == "mingw-16.2.0"
        assert family == "mingw"


class TestSuggestProfile16Bit:
    """intake must pick the msvc-1.52 (DOSBox) profile for 16-bit NE targets —
    a 32-bit msvc-6.0 profile would produce a project that fails doctor."""

    def test_ne_routes_to_msvc152(self, monkeypatch) -> None:
        from rebrew.toolchain_detect import ToolchainInfo

        def _fake_detect(path) -> ToolchainInfo:
            return ToolchainInfo(
                family="msvc",
                arch="x86_16",
                confidence="medium",
                version_hint="16-bit MSVC-style NE (no Borland segment markers)",
            )

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        profile, family, hint, notes = _suggest_profile(Path("x.exe"))
        assert profile == "msvc-1.52"
        assert family == "msvc"
        assert any("16-bit NE" in n for n in notes)

    def test_32bit_msvc_still_routes_to_msvc_6_0(self, monkeypatch) -> None:
        from rebrew.toolchain_detect import ToolchainInfo

        def _fake_detect(path) -> ToolchainInfo:
            return ToolchainInfo(family="msvc", confidence="high", version_hint="MSVC 6.0")

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        profile, family, hint, notes = _suggest_profile(Path("x.exe"))
        assert profile == "msvc-6.0"
        assert family == "msvc"


class TestToolchainLinks:
    """intake derives the vendored-toolchain link from the registry
    (image rebrew/<family>:<tag> -> <family>/<tag>), so every profile
    works without a hand-maintained list."""

    def test_msvc152_derived(self) -> None:
        from rebrew.intake import _link_names_for

        assert _link_names_for("msvc-1.52") == ("msvc/1.52-win16", "msvc/1.52-win16")

    def test_every_matchable_profile_derived(self) -> None:
        from rebrew.intake import _link_names_for

        assert _link_names_for("msvc-6.0") == ("msvc/6.0-win32", "msvc/6.0-win32")
        assert _link_names_for("msvc-5.0") == ("msvc/5.0-win32", "msvc/5.0-win32")
        assert _link_names_for("msvc-4.2") == ("msvc/4.2-win32", "msvc/4.2-win32")
        assert _link_names_for("msvc-6.0-sp3") == ("msvc/6.0-sp3-win32", "msvc/6.0-sp3-win32")
        assert _link_names_for("msvc-6.0-sp6") == ("msvc/6.0-sp6-win32", "msvc/6.0-sp6-win32")
        assert _link_names_for("msvc-7.0") == ("msvc/7.0-win32", "msvc/7.0-win32")
        assert _link_names_for("borland-3.1") == ("borland/3.1-win16", "borland/3.1-win16")
        assert _link_names_for("borland-2.0") == ("borland/2.0-win16", "borland/2.0-win16")

    def test_unknown_profile_has_no_link(self) -> None:
        from rebrew.intake import _link_names_for

        assert _link_names_for("no-such-profile") is None

    def test_image_backed_native_profile_derived(self) -> None:
        """mingw-16.2.0 is image-backed now (rebrew/mingw:16.2.0-win32), so its
        link name derives from the image like every other profile."""
        from rebrew.intake import _link_names_for

        assert _link_names_for("mingw-16.2.0") == ("mingw/16.2.0-win32", "mingw/16.2.0-win32")
        assert _link_names_for("watcom-2.0-win16") == ("watcom/2.0-win16", "watcom/2.0-win16")


class TestExplicitToolchainWarns:
    """intake --toolchain runs init's alignment checks (warn, don't silently
    onboard the wrong profile)."""

    def test_mismatched_explicit_toolchain_warns(
        self, tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from rebrew.intake import _warn_explicit_toolchain
        from rebrew.toolchain_detect import ToolchainInfo

        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 200)

        def _fake_detect(path):
            return ToolchainInfo(family="msvc", confidence="high", version_hint="MSVC 6.0")

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        notes: list[str] = []
        # 16-bit MZ binary with a 32-bit msvc-6.0 profile: arch warning expected
        _warn_explicit_toolchain(binary, "msvc-6.0", notes)
        assert "16-bit binary" in capsys.readouterr().err
        assert any("explicit --toolchain msvc-6.0" in n for n in notes)

    def test_aligned_explicit_toolchain_silent(
        self, tmp_path: Path, monkeypatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from rebrew.intake import _warn_explicit_toolchain
        from rebrew.toolchain_detect import ToolchainInfo

        binary = tmp_path / "game.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 200)

        def _fake_detect(path):
            return ToolchainInfo(
                family="borlandc",
                confidence="high",
                arch="x86_16",
                version_hint="Borland C/C++",
            )

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        notes: list[str] = []
        _warn_explicit_toolchain(binary, "borland-3.1", notes)
        assert "warning" not in capsys.readouterr().err


class TestWatcomLink:
    """watcom derives a registry link so intake on a Watcom binary auto-links
    toolchain/watcom/2.0-win32 (like msvc-1.52's msvc/1.52-win16)."""

    def test_watcom_has_link_entry(self) -> None:
        from rebrew.intake import _link_names_for

        assert _link_names_for("watcom-2.0-win32") == ("watcom/2.0-win32", "watcom/2.0-win32")


class TestSuggestProfileBorland:
    """intake's profile suggestion now shares the detector's
    family→profile mapping — a Borland DOS binary must suggest borland-3.1 (was
    wrongly defaulting to msvc-6.0 before the unification)."""

    def test_borlandc_suggests_borland_3_1_from_real_exe(self) -> None:
        fixture = Path(__file__).parent / "fixtures" / "tc16_hello.exe"
        profile, family, _, notes = _suggest_profile(fixture)
        assert family == "borlandc"
        assert profile == "borland-3.1"
        assert any("borland-3.1" in n for n in notes)

    def test_msvc16_ne_suggests_msvc152(self, monkeypatch) -> None:
        from rebrew.toolchain_detect import ToolchainInfo

        def _fake_detect(path):
            return ToolchainInfo(
                family="msvc",
                version_hint="16-bit MSVC-style NE",
                confidence="high",
                arch="x86_16",
                detected_by="ne",
            )

        monkeypatch.setattr("rebrew.toolchain_detect.detect_toolchain", _fake_detect)
        profile, family, _, notes = _suggest_profile(Path("/tmp/fake.exe"))
        assert family == "msvc"
        assert profile == "msvc-1.52"
        assert any("msvc-1.52" in n for n in notes)


class TestNativeFormatAndArch:
    """init assumes a 32-bit PE; intake corrects it from the header, so an ELF
    is not recorded as PE (nor an x86-64 one decoded as 32-bit x86)."""

    FIXTURES = Path(__file__).parent / "fixtures"

    def test_an_elf_reports_its_format_and_machine(self) -> None:
        from rebrew.intake import _native_format_and_arch

        assert _native_format_and_arch(self.FIXTURES / "mini.elf") == ("elf", "x86_32")

    def test_a_32bit_pe_or_unreadable_file_keeps_the_default(self, tmp_path: Path) -> None:
        from rebrew.intake import _native_format_and_arch

        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"not a binary")
        assert _native_format_and_arch(self.FIXTURES / "mini_pe.exe") is None
        assert _native_format_and_arch(junk) is None
        assert _native_format_and_arch(tmp_path / "missing.exe") is None


class TestPruneStaleStubs:
    """prune_stale_stubs cleans up both line-comment and block-comment stubs."""

    def test_prunes_line_and_block_stubs(self, tmp_path: Path) -> None:
        from rebrew.intake import prune_stale_stubs
        from rebrew.metadata import set_fields_batch

        src_dir = tmp_path / "src" / "target"
        src_dir.mkdir(parents=True)
        meta_dir = tmp_path / "src"

        (src_dir / "fcn_00401000.c").write_text(
            "// STUB: TARGET 0x00401000\n\nvoid fcn_00401000(void)\n{\n    /* reason */\n}\n"
        )
        (src_dir / "fcn_00401010.c").write_text(
            "// STUB: TARGET 0x00401010\n\nvoid fcn_00401010(void)\n{\n    /* reason */\n}\n"
        )
        (src_dir / "fcn_00401020.c").write_text(
            "/* STUB: TARGET 0x00401020 */\n\nvoid fcn_00401020(void)\n{\n    /* reason */\n}\n"
        )
        set_fields_batch(
            meta_dir,
            [
                {"module": "TARGET", "va": 0x401000, "fields": {"blocker": "reason"}},
                {"module": "TARGET", "va": 0x401010, "fields": {"blocker": "reason"}},
                {"module": "TARGET", "va": 0x401020, "fields": {"blocker": "reason"}},
            ],
        )
        funcs = [(0x401000, 32, "valid_fn")]
        pruned = prune_stale_stubs(tmp_path, src_dir, "TARGET", funcs, metadata_dir=meta_dir)
        assert pruned == 2
        assert (src_dir / "fcn_00401000.c").exists()
        assert not (src_dir / "fcn_00401010.c").exists()
        assert not (src_dir / "fcn_00401020.c").exists()

        # Re-running prune_stale_stubs is idempotent (prunes 0, touches nothing)
        assert prune_stale_stubs(tmp_path, src_dir, "TARGET", funcs, metadata_dir=meta_dir) == 0


class TestLinkToolchain:
    """_link_toolchain creates parent directories and is safe to re-run."""

    def test_link_toolchain_creates_parent_and_is_idempotent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.intake import _link_toolchain

        tools_src = tmp_path / "repo_tools" / "msvc" / "6.0-win32"
        tools_src.mkdir(parents=True)
        monkeypatch.setattr("rebrew.intake.REPO_TOOLS", tmp_path / "repo_tools")

        project = tmp_path / "project"
        project.mkdir()

        # First run: should create tools/msvc/6.0-win32 symlink
        linked1 = _link_toolchain(project, "msvc-6.0")
        assert linked1 is not None
        link_path = Path(linked1)
        assert link_path.is_symlink()
        assert link_path.resolve() == tools_src.resolve()

        # Re-running is idempotent: returns same link without error
        linked2 = _link_toolchain(project, "msvc-6.0")
        assert linked2 == linked1
