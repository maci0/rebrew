"""tests/test_json_purity.py — ``--json`` stdout must be pure JSON.

Every ``--json`` CLI invocation must emit ONLY the JSON payload on stdout;
human-facing progress and warnings belong on stderr.  A single preamble line
(LIEF log, "Scanning...", a warning banner) would break ``json.loads`` for
every scripted consumer, so this contract is pinned across the offline CLI
surface using the checked-in binary fixtures (``tests/fixtures/``) — no wine,
no vendored toolchain, no network.

The fixture project is assembled in a temp dir per test: the project toml
points at ``original/mini_pe.exe`` (the fixture PE) with one STUB function.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.main import app

FIXTURES = Path(__file__).parent / "fixtures"

# (argv, allowed exit codes) — commands that need no compiler/toolchain.
_JSON_COMMANDS: list[tuple[str, set[int]]] = [
    ("status --json", {0}),
    ("strings --json", {0}),
    ("imports --json", {0}),
    ("asm --json 0x401000", {0}),
    ("switch --json 0x401000", {0}),  # no dispatch in the fixture → empty result
    ("describe --json 0x401000", {0}),
    ("xrefs original/mini_pe.exe 0x401000 --json", {0}),
    ("verify --dry-run --json", {1}),  # 1 = candidates awaiting verification
    ("analyze --json", {0}),
    ("todo --json", {0}),
    ("lint --json", {0}),
    ("data --json", {0}),
    (
        "doctor --json",
        {0, 1},
    ),  # 1 = a check fails (e.g. compiler absent in CI); stdout stays pure JSON
    ("cache stats --json", {0}),
    ("cfg show --json", {0}),
    ("flirt --binary original/mini_pe.exe --json", {2}),  # 2 = no signatures loaded
    # Session-era commands — must keep stdout JSON-pure even on error paths.
    ("pdb-info original/mini_pe.exe --json", {2}),  # 2 = no sibling .pdb
    ("analyze --function 0x401000 --json", {0}),
    ("similar 0x401000 --json", {0}),
    ("identify-library --dry-run --json", {0}),
    ("discover-functions original/mini_pe.exe --json", {0, 2}),  # 2 = rizin absent
    ("binsync-export bsx --dry-run --json", {0}),
    ("binsync-import bsx --dry-run --json", {2}),  # 2 = no state dir yet
    ("binsync-diff bsx --json", {2}),  # 2 = no state dir yet
    ("report --json", {0}),
    (f"gen-flirt-pat {FIXTURES}/mini.lib --json", {0}),
    ("document-unmatched --json", {0}),
    ("catalog --json", {0}),
    ("skeleton --json 0x401000", {0}),
    ("verify-placement --json", {2}),  # 2 = no rebrew-data.toml in the fixture
    ("text-audit --json", {0, 2}),  # 2 = no built binary in the fixture
    ("calibrate-bss --json", {2}),  # 2 = no link.txt / layout in the fixture
    ("gen-layout --json", {0, 2}),
    ("gen-link-stubs --json", {2}),  # 2 = no rebrew-data.toml in the fixture
    ("link-sweep --json", {2}),  # 2 = no link.txt in the fixture
    ("diff --json src/SERVER/fcn.c", {0, 2}),
    ("extract list --json", {0}),
    ("diagnose --json src/SERVER/fcn.c", {0}),
    ("pe-info --json", {0}),
    ("context --json", {0}),
    ("graph --json", {0}),
    ("crypto-scan --json", {0}),
    ("fingerprints --json", {0}),
    ("rename --json 0x401000 newname --dry-run", {0}),
    ("blocker show --json 0x401000", {0}),
    ("refactor --json", {0}),
    ("layout-map --json", {0}),
    ("inline-strings --json", {0, 2}),
    ("lib-match --json", {0, 2}),
    ("crt-match --json", {0, 2}),
    ("identify-library --json", {0}),
    ("switch --json", {0, 2}),
    ("merge-sweep --json", {0}),
    ("near-diag --json src/SERVER/fcn.c", {0, 2}),
    ("orphans --json", {0}),
    ("solutions --json", {0}),
    ("symbol-addrs --json", {0}),
    ("stack-cmp --json src/SERVER/fcn.c", {0, 2}),
    ("build-db --json", {0, 2}),
    ("postlink --json build/x.dll original/mini_pe.exe", {0, 2}),
    ("round-trip --json", {0}),
    ("prove --json src/SERVER/fcn.c", {0, 2}),
    ("match --json src/SERVER/fcn.c --dry-run", {0, 2}),
    ("decompile --json 0x401000", {0, 2}),
    ("fix --json src/SERVER/fcn.c --dry-run", {0}),
    ("climb --json src/SERVER/fcn.c --dry-run", {0, 2}),
    ("sync --json", {0, 2}),
    ("gen-stubs --json", {0, 2}),
    ("link-order --json", {0, 2}),
    ("order-sources --json src/SERVER/fcn.c", {0}),
    ("binary-similarity --json original/mini_pe.exe", {0, 2}),
    ("test --json", {0, 1, 2}),
    ("verify --json", {0, 1, 2}),
    ("types --json", {0}),
    ("split --json", {0, 2}),
    ("skills list --json", {0}),
    ("security-scan --json", {0}),
    ("recover-structs --json", {0, 2}),
    ("drift --json src/SERVER/fcn.c", {0, 2}),
]

_PROJECT_TOML = """\
[project]
name = "jsonprobe"
default_target = "SERVER"
jobs = 1

[targets."SERVER"]
binary = "original/mini_pe.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src/SERVER"
bin_dir = "bin/SERVER"
source_ext = ".c"
marker = "SERVER"

[compiler]
profile = "mingw-16.2.0"
runner = ""
command = "i686-w64-mingw32-gcc"
includes = ""
libs = ""
cflags = "-O2"
base_cflags = ""
timeout = 60
"""


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Assemble a minimal rebrew project around the fixture PE."""
    root = tmp_path / "project"
    (root / "original").mkdir(parents=True)
    (root / "src" / "SERVER").mkdir(parents=True)
    (root / "bin" / "SERVER").mkdir(parents=True)
    shutil.copy(FIXTURES / "mini_pe.exe", root / "original" / "mini_pe.exe")
    (root / "rebrew-project.toml").write_text(_PROJECT_TOML, encoding="utf-8")
    (root / "src" / "SERVER" / "function_structure.json").write_text(
        json.dumps(
            [
                {"va": 0x00401000, "size": 11, "name": "_func1"},
                {"va": 0x00401010, "size": 10, "name": "_func2"},
            ]
        ),
        encoding="utf-8",
    )
    (root / "src" / "SERVER" / "fcn.c").write_text(
        "// FUNCTION: SERVER 0x00401000\nint __cdecl _func1(void) { return 0; }\n",
        encoding="utf-8",
    )
    # Hermetic FLIRT scan: a sibling rebrew-flirt-sigs checkout on the host
    # would otherwise load standard sigs and flip flirt's exit code.
    empty_sigs = tmp_path / "no-flirt-sigs"
    empty_sigs.mkdir()
    monkeypatch.setenv("REBREW_FLIRT_SIGS_DIR", str(empty_sigs))
    monkeypatch.chdir(root)
    return root


@pytest.mark.parametrize(
    ("argv", "exit_codes"),
    _JSON_COMMANDS,
    ids=[argv.replace(" ", "_") for argv, _ in _JSON_COMMANDS],
)
def test_json_stdout_is_pure_json(project: Path, argv: str, exit_codes: set[int]) -> None:
    """stdout is exactly one JSON document — json.loads must succeed on it."""
    result = CliRunner().invoke(app, argv.split())
    assert result.exit_code in exit_codes, (
        f"rebrew {argv} exited {result.exit_code}, want {sorted(exit_codes)}:\n{result.output}"
    )
    assert result.stdout.strip(), f"rebrew {argv} --json produced empty stdout"
    # The whole stdout (no preamble) must parse as JSON.
    payload = json.loads(result.stdout)
    assert isinstance(payload, (dict, list))


@pytest.mark.parametrize(
    ("option", "key"),
    [("--link-config", "link_toml"), ("--layout-config", "layout_toml")],
)
def test_gen_layout_config_json(
    project: Path, monkeypatch: pytest.MonkeyPatch, option: str, key: str
) -> None:
    import tomllib

    from test_layout_meta import _make_pe

    (project / "original" / "mini_pe.exe").write_bytes(_make_pe([b".text", b".data", b".rdata"]))
    monkeypatch.setattr("rebrew.gen_layout._import_lib_symbols_from_image", lambda _stem: set())
    runner = CliRunner()
    plain = runner.invoke(app, ["gen-layout", option])
    assert plain.exit_code == 0, plain.output
    assert tomllib.loads(plain.stdout)
    result = runner.invoke(app, ["gen-layout", option, "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload[key] + "\n" == plain.stdout


def test_verify_chatter_goes_to_stderr(project: Path, capsys: pytest.CaptureFixture) -> None:
    """Human progress lines (verify's "Scanning...") must never reach stdout."""
    result = CliRunner().invoke(app, ["verify", "--dry-run", "--json"])
    assert "Scanning" in result.stderr  # on stderr, where consumers can ignore it
    json.loads(result.stdout)  # and stdout stays pure
