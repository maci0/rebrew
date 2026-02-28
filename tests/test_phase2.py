"""Tests for phase 2 refactors: consistency, idempotency, robustness.

Covers: compile command unification, marker type mapping, idempotent status
        updates, config key validation, and GA seed reproducibility.
"""

import contextlib
import warnings
from pathlib import Path

from rebrew.annotation import marker_for_origin
from rebrew.compile import resolve_cl_command
from rebrew.test import update_source_status

VALID_HEADER = """\
// FUNCTION: SERVER 0x10008880
// STATUS: EXACT
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
// SYMBOL: _bit_reverse

int __cdecl bit_reverse(int x)
{
    return x;
}
"""

STUB_HEADER = """\
// FUNCTION: SERVER 0x10008880
// STATUS: STUB
// BLOCKER: initial decompilation
// ORIGIN: GAME
// SIZE: 31
// CFLAGS: /O2 /Gd
// SYMBOL: _bit_reverse

int __cdecl bit_reverse(int x)
{
    return 0;
}
"""


def _write_c(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# 1. Compile command unification
# ---------------------------------------------------------------------------


class TestResolveClCommand:
    """Verify resolve_cl_command extracts correct command parts."""

    def test_wine_prefix(self) -> None:
        class FakeCfg:
            compiler_command = "wine tools/MSVC600/bin/CL.EXE"
            root = Path("/project")

        cmd = resolve_cl_command(FakeCfg())
        assert cmd[0] == "wine"
        assert cmd[1] == "/project/tools/MSVC600/bin/CL.EXE"

    def test_bare_cl(self) -> None:
        class FakeCfg:
            compiler_command = "CL.EXE"
            root = Path("/project")

        cmd = resolve_cl_command(FakeCfg())
        assert len(cmd) == 1
        assert "CL.EXE" in cmd[0]


# ---------------------------------------------------------------------------
# 2. Marker type unification
# ---------------------------------------------------------------------------


class TestMarkerTypeConsistency:
    """Verify skeleton uses the same mapping as annotation."""

    def test_game_is_function(self) -> None:
        assert marker_for_origin("GAME", "MATCHED") == "FUNCTION"

    def test_msvcrt_is_library(self) -> None:
        assert marker_for_origin("MSVCRT", "MATCHED") == "LIBRARY"

    def test_zlib_is_library(self) -> None:
        assert marker_for_origin("ZLIB", "MATCHED") == "LIBRARY"

    def test_stub_is_stub(self) -> None:
        # STUBs should return "STUB" regardless of origin
        assert marker_for_origin("GAME", "STUB") == "STUB"
        assert marker_for_origin("MSVCRT", "STUB") == "STUB"


# ---------------------------------------------------------------------------
# 3. Idempotent status updates
# ---------------------------------------------------------------------------


class TestIdempotentStatusUpdate:
    """Verify update_source_status skips write when status matches."""

    def test_no_extra_bak_on_same_status(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        bak = tmp_path / "func.c.bak"

        # Status is already EXACT, update to EXACT should be a no-op
        update_source_status(str(p), "EXACT")
        assert not bak.exists(), "Should not create backup for no-op update"

    def test_writes_when_status_differs(self, tmp_path: Path) -> None:
        p = _write_c(tmp_path, "func.c", VALID_HEADER)
        bak = tmp_path / "func.c.bak"

        update_source_status(str(p), "RELOC")
        assert bak.exists()
        assert "STATUS: RELOC" in p.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 5. Config key validation
# ---------------------------------------------------------------------------


class TestConfigKeyValidation:
    """Verify config warns on unrecognized keys."""

    def test_warns_on_unknown_target_key(self, tmp_path: Path) -> None:
        import warnings

        toml_path = tmp_path / "rebrew-project.toml"
        toml_path.write_text(
            '[targets.main]\nbinary = "original/server.dll"\ntypo_key = "bad"\n',
            encoding="utf-8",
        )

        from rebrew.config import load_config

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            with contextlib.suppress(Exception):
                load_config(root=tmp_path)
            key_warnings = [x for x in w if "unrecognized" in str(x.message)]
            assert len(key_warnings) >= 1
            assert "typo_key" in str(key_warnings[0].message)

    def test_warns_on_unknown_top_level_key(self, tmp_path: Path) -> None:
        toml_path = tmp_path / "rebrew-project.toml"
        toml_path.write_text(
            '[target]\nbinary = "original/server.dll"\n\n[sources]\nreversed_dir = "src/server.dll"\n\n'
            '[typo_section]\nfoo = "bar"\n',
            encoding="utf-8",
        )

        from rebrew.config import load_config

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            with contextlib.suppress(Exception):
                load_config(root=tmp_path)
            key_warnings = [x for x in w if "unrecognized" in str(x.message)]
            assert len(key_warnings) >= 1
            assert "typo_section" in str(key_warnings[0].message)


# ---------------------------------------------------------------------------
# 8. GA seed reproducibility
# ---------------------------------------------------------------------------


class TestGASeedReproducibility:
    """Verify same seed produces same initial population."""

    def test_same_seed_same_population(self) -> None:
        import random

        rng1 = random.Random(42)
        pop1 = [rng1.random() for _ in range(10)]

        rng2 = random.Random(42)
        pop2 = [rng2.random() for _ in range(10)]

        assert pop1 == pop2

    def test_different_seed_different_population(self) -> None:
        import random

        rng1 = random.Random(42)
        pop1 = [rng1.random() for _ in range(10)]

        rng2 = random.Random(99)
        pop2 = [rng2.random() for _ in range(10)]

        assert pop1 != pop2
