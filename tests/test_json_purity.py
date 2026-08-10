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
    ("describe --json 0x401000", {0}),
    ("xrefs original/mini_pe.exe 0x401000 --json", {0}),
    ("verify --dry-run --json", {1}),  # 1 = candidates awaiting verification
    ("analyze --json", {0}),
    ("todo --json", {0}),
    ("lint --json", {0}),
    ("data --json", {0}),
    ("doctor --json", {0}),
    ("cache stats --json", {0}),
    ("cfg show --json", {0}),
    ("flirt --exe original/mini_pe.exe --json", {1}),  # 1 = no signatures loaded
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
function_list = "src/SERVER/functions.txt"
bin_dir = "bin/SERVER"
source_ext = ".c"
marker = "SERVER"

[compiler]
profile = "gcc-pe"
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
    (root / "src" / "SERVER" / "functions.txt").write_text(
        "0x00401000 11 _func1\n0x00401010 10 _func2\n", encoding="utf-8"
    )
    (root / "src" / "SERVER" / "fcn.c").write_text(
        "// FUNCTION: SERVER 0x00401000\nint __cdecl _func1(void) { return 0; }\n",
        encoding="utf-8",
    )
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


def test_verify_chatter_goes_to_stderr(project: Path, capsys: pytest.CaptureFixture) -> None:
    """Human progress lines (verify's "Scanning...") must never reach stdout."""
    result = CliRunner().invoke(app, ["verify", "--dry-run", "--json"])
    assert "Scanning" in result.stderr  # on stderr, where consumers can ignore it
    json.loads(result.stdout)  # and stdout stays pure
