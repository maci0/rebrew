"""Tests for rebrew.tc16 — Turbo C++ 3.1 (16-bit DOS) compilation support."""

from __future__ import annotations

from pathlib import Path

import pytest

from rebrew.dosbox import make_sandbox_dir
from rebrew.tc16 import Tc16Error, compile_c

# The compile_c path symlinks the read-only vendored toolchain into the DOSBox
# sandbox; without the tree present (CI: toolchains are gitignored) the class
# can only fail at staging, so skip rather than red.
_REPO_TC16 = (
    Path(__file__).resolve().parents[1] / "toolchain" / "borland" / "3.1-win16" / "source"
)


def _fake_tcc(monkeypatch, sandbox: Path) -> None:
    """Simulate a successful DOSBox run: write the TCC log + a .OBJ."""

    def _run(args, **kwargs):  # noqa: ARG001
        (sandbox / "TCOUT.TXT").write_text("src.c\n", encoding="utf-8")
        (sandbox / "SRC.OBJ").write_bytes(b"\x80\x08\x00fake")
        return type("R", (), {"returncode": 0})()

    monkeypatch.setattr("rebrew.dosbox.subprocess.run", _run)


@pytest.mark.skipif(
    not (_REPO_TC16 / "BIN" / "TCC.EXE").exists(),
    reason="vendored Turbo C++ 3.1 toolchain not present (toolchain/borland/3.1-win16)",
)
class TestTc16Compile:
    def test_compile_c_produces_obj(self, tmp_path: Path, monkeypatch) -> None:
        _fake_tcc(monkeypatch, tmp_path)
        src = tmp_path / "add.c"
        src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
        res = compile_c(src, tmp_path)
        assert res.obj_path.exists()
        assert res.obj_path.name == "SRC.OBJ"

    def test_compile_c_no_object_raises(self, tmp_path: Path, monkeypatch) -> None:
        def _run(args, **kwargs):  # noqa: ARG001
            (tmp_path / "TCOUT.TXT").write_text("Error: cannot open", encoding="utf-8")

        monkeypatch.setattr("rebrew.dosbox.subprocess.run", _run)
        src = tmp_path / "bad.c"
        src.write_text("int x;\n", encoding="utf-8")
        with pytest.raises(Tc16Error, match="produced no object"):
            compile_c(src, tmp_path)

    def test_compile_c_missing_toolchain_raises(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr(
            "rebrew.tc16._find_tc16",
            lambda version="3.1": (_ for _ in ()).throw(Tc16Error("not vendored")),
        )
        with pytest.raises(Tc16Error, match="not vendored"):
            compile_c("int x;\n", tmp_path)


class TestHeadlessDosbox:
    """DOSBox must run fully headless — the dummy video/audio drivers are
    the guarantee that a compile never pops a window or touches audio."""

    def test_run_dosbox_env_is_headless(self, tmp_path: Path, monkeypatch) -> None:

        from rebrew import dosbox as dosbox_mod

        captured: dict = {}

        def _fake_run(args, **kwargs):  # noqa: ARG001
            captured["env"] = kwargs.get("env", {})
            return type("R", (), {"returncode": 0})()

        monkeypatch.setattr(dosbox_mod.shutil, "which", lambda _: "/usr/bin/dosbox")
        monkeypatch.setattr(dosbox_mod.subprocess, "run", _fake_run)
        (tmp_path / "probe.c").write_text("int x;\n", encoding="utf-8")
        dosbox_mod.run_dosbox(tmp_path, ["dir"])
        env = captured["env"]
        assert env.get("SDL_VIDEODRIVER") == "dummy"
        assert env.get("SDL_AUDIODRIVER") == "dummy"

    def test_wrapper_common_dosbox_is_headless(self) -> None:
        wrapper = Path(__file__).resolve().parents[1] / "toolchain" / "base" / "wrapper-common.sh"
        text = wrapper.read_text(encoding="utf-8")
        assert "SDL_VIDEODRIVER=dummy" in text
        assert "SDL_AUDIODRIVER=dummy" in text


class TestDosboxDriverSync:
    """The host DOSBox driver (rebrew.dosbox) and the toolchain-image
    driver (wrapper-common.sh's rebrew_dosbox_run) must generate identical
    DOSBox configs — they are the docker-less fallback and the
    containerized path for the same 16-bit compilers, so a headless/driver
    fix in one must reach the other."""

    def test_host_and_image_conf_templates_match(self) -> None:
        from rebrew import dosbox as dosbox_mod

        wrapper = Path(__file__).resolve().parents[1] / "toolchain" / "base" / "wrapper-common.sh"
        wtext = wrapper.read_text(encoding="utf-8")
        sandbox = "/tmp/sbx"
        autoexec = "C:\\BIN\\TCC.EXE -c t.c"

        # Host side: the shared conf builder.
        host_conf = dosbox_mod._build_dosbox_conf(Path(sandbox), [autoexec])

        # Image side: the wrapper's single printf builds the same config.
        import re

        m = re.search(
            r"printf '(\[sdl\][^']*)' \\",
            wtext,
        )
        assert m, "wrapper-common.sh conf printf not found"
        fmt = m.group(1).replace("\\n", "\n").replace("%s", "{}")
        image_conf = fmt.format(sandbox, autoexec)

        assert host_conf == image_conf, (
            "host and image DOSBox confs drifted — update both "
            "(src/rebrew/dosbox.py and toolchain/base/wrapper-common.sh)"
        )


@pytest.mark.skipif(
    not (_REPO_TC16 / "BIN" / "TCC.EXE").exists(),
    reason="vendored Turbo C++ 3.1 toolchain not present (toolchain/borland/3.1-win16)",
)
def test_tc16_compile_parse_match_roundtrip() -> None:
    """End-to-end: TCC → Borland OMF → parse → compile_and_compare against
    the object's own bytes yields EXACT (the full matching loop)."""
    from types import SimpleNamespace

    from rebrew.compile import compile_and_compare, compile_to_obj

    work = make_sandbox_dir("tc16-match-")
    src_dir = work / "src"
    src_dir.mkdir()
    src = src_dir / "add.c"
    src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    cfg = SimpleNamespace(
        root=Path("."),
        compiler_profile="tc16",
        compiler_command="TCC.EXE",
        compiler_runner="",
        posix_style=True,
        compiler_includes=src_dir,
        base_cflags="",
        cflags="",
        cflags_presets={},
        compile_timeout=240,
    )
    obj, err = compile_to_obj(cfg, src, [], work, use_cache=False)
    assert obj is not None, err
    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs

    code, relocs, records = parse_obj_symbol_and_relocs(obj, "_add")
    assert code is not None
    assert code[:2] == bytes.fromhex("55 8b")  # push bp; mov bp,sp (Borland cdecl)
    res = compile_and_compare(cfg, src, "_add", code, [], use_cache=False)
    assert res.matched is True
    assert res.match_percent == 100.0


@pytest.mark.skipif(
    not (_REPO_TC16 / "BIN" / "TCC.EXE").exists(),
    reason="vendored Turbo C++ 3.1 toolchain not present (toolchain/borland/3.1-win16)",
)
def test_tc16_object_no_trailing_checksum_byte() -> None:
    """TCC/wcc16 LEDATA records end with an OMF checksum byte (whole-record
    sum ≡ 0 mod 256); the omf16 parser must drop it or the code slice
    carries a spurious trailing byte that breaks byte-matching."""

    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs
    from rebrew.tc16 import compile_c

    wd = make_sandbox_dir("tc16-chk-")
    src = wd / "add.c"
    src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    r = compile_c(src, wd, timeout=120)
    code, relocs, _ = parse_obj_symbol_and_relocs(r.obj_path, "_add")
    # The exact bytes of `add` in the TCC-built tc16_hello.exe fixture.
    assert code == bytes.fromhex("55 8b ec 8b 46 04 03 46 06 eb 00 5d c3")


@pytest.mark.skipif(
    not (_REPO_TC16 / "BIN" / "TCC.EXE").exists(),
    reason="vendored Turbo C++ 3.1 toolchain not present (toolchain/borland/3.1-win16)",
)
def test_mz_fixture_add_matches() -> None:
    """End-to-end DOS match: the `add` function extracted from the MZ
    fixture at its discovered VA (0x291) equals the tc16-compiled code."""
    from types import SimpleNamespace

    from rebrew.binary_loader import extract_raw_bytes
    from rebrew.compile import compile_and_compare
    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs
    from rebrew.tc16 import compile_c

    fixture = Path(__file__).parent / "fixtures" / "tc16_hello.exe"
    assert fixture.exists(), "tc16_hello.exe fixture missing"
    target = extract_raw_bytes(fixture, 0x291, 13)
    assert target == bytes.fromhex("55 8b ec 8b 46 04 03 46 06 eb 00 5d c3")

    wd = make_sandbox_dir("tc16-mz-")
    src = wd / "add.c"
    src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    r = compile_c(src, wd, timeout=120)
    code, relocs, _ = parse_obj_symbol_and_relocs(r.obj_path, "_add")
    assert code == target
    res = compile_and_compare(
        SimpleNamespace(
            root=Path("."),
            compiler_profile="tc16",
            compiler_command="TCC.EXE",
            compiler_runner="",
            posix_style=True,
            compiler_includes=wd,
            base_cflags="",
            cflags="",
            cflags_presets={},
            compile_timeout=240,
        ),
        src,
        "_add",
        target,
        [],
        use_cache=False,
    )
    assert res.status == "EXACT"


@pytest.mark.skipif(
    not (_REPO_TC16 / "BIN" / "TCC.EXE").exists(),
    reason="vendored Turbo C++ 3.1 toolchain not present (toolchain/borland/3.1-win16)",
)
def test_mz_fixture_main_matches_with_reloc() -> None:
    """`main` from the MZ fixture calls `add` (e8 rel16) — the intra-binary
    call slot must be relocation-masked for the match (RELOC, 20/20)."""
    from types import SimpleNamespace

    from rebrew.binary_loader import extract_raw_bytes
    from rebrew.compile import compile_and_compare
    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs
    from rebrew.tc16 import compile_c

    fixture = Path(__file__).parent / "fixtures" / "tc16_hello.exe"
    target = extract_raw_bytes(fixture, 0x29E, 20)
    assert target[:2] == bytes.fromhex("55 8b")  # push bp; mov bp,sp

    wd = make_sandbox_dir("tc16-mz-main-")
    src = wd / "main.c"
    src.write_text(
        "int add(int a, int b);\nint main(void) { return add(2, 3); }\n", encoding="utf-8"
    )
    r = compile_c(src, wd, timeout=120)
    code, relocs, _ = parse_obj_symbol_and_relocs(r.obj_path, "_main")
    assert code is not None
    assert any(k < 20 for k in (relocs or {}))  # the e8 call slot is a reloc
    res = compile_and_compare(
        SimpleNamespace(
            root=Path("."),
            compiler_profile="tc16",
            compiler_command="TCC.EXE",
            compiler_runner="",
            posix_style=True,
            compiler_includes=wd,
            base_cflags="",
            cflags="",
            cflags_presets={},
            compile_timeout=240,
        ),
        src,
        "_main",
        target,
        [],
        use_cache=False,
    )
    assert res.status == "RELOC"
    assert res.match_percent == 100.0


_REPO_TC20 = (
    Path(__file__).resolve().parents[1] / "toolchain" / "borland" / "2.0-win16" / "source"
)


@pytest.mark.skipif(
    not (_REPO_TC20 / "BIN" / "TCC.EXE").exists(),
    reason="vendored Turbo C 2.0 toolchain not present (toolchain/borland/2.0-win16)",
)
def test_tc20_compiles_and_parses() -> None:
    """Turbo C 2.0 (the 1988/89 compiler — Keen-era DOS games) compiles to
    the same Borland 16-bit OMF and parses through omf16 with the classic
    cdecl prologue (identical simple-function codegen to TCC 3.1)."""

    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs

    wd = make_sandbox_dir("tc20-")
    src = wd / "add.c"
    src.write_text("int add(int a, int b) { return a + b; }\n", encoding="utf-8")
    r = compile_c(src, wd, timeout=120, version="2.0")
    code, relocs, _ = parse_obj_symbol_and_relocs(r.obj_path, "_add")
    assert code == bytes.fromhex("55 8b ec 8b 46 04 03 46 06 eb 00 5d c3")
    assert relocs == {}
    assert "Turbo C" in r.log or "Version 2" in r.log


@pytest.mark.skipif(
    not (_REPO_TC16 / "BIN" / "TCC.EXE").exists(),
    reason="vendored Turbo C++ 3.1 toolchain not present (toolchain/borland/3.1-win16)",
)
def test_tc16_pascal_symbol_matches_via_cdecl_name() -> None:
    """A `pascal` function compiles to an UPPERCASE no-underscore OMF symbol
    (FCN_042E); looking it up by the C-level name (_fcn_042e) must resolve."""

    from rebrew.matcher.parsers import parse_obj_symbol_and_relocs

    wd = make_sandbox_dir("tc16-pascal-")
    src = wd / "f.c"
    src.write_text("int pascal fcn_042e(int a, int b) { return a + b; }\n", encoding="utf-8")
    r = compile_c(src, wd, timeout=120, version="3.1")
    code, relocs, _ = parse_obj_symbol_and_relocs(r.obj_path, "_fcn_042e")
    assert code is not None
    # pascal pushes args left-to-right, so [bp+4] is the LAST arg.
    assert code == bytes.fromhex("55 8b ec 8b 46 06 03 46 04 eb 00 5d c2 04 00")
