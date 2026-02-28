"""Tests for config refactors phase 3.

Covers: [project] section, base_cflags / compile_timeout,
marker field, and estimate_difficulty using ignored_symbols.
"""

from pathlib import Path

from rebrew.config import load_config
from rebrew.naming import estimate_difficulty, ignored_symbols

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_project(tmp_path: Path, toml_content: str) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(toml_content, encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# 1. [project] section parsing
# ---------------------------------------------------------------------------

TOML_WITH_PROJECT = """\
[project]
name = "Test Game"
jobs = 16
db_dir = "mydb"
output_dir = "myout"

[targets.main]
binary = "test.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src"
"""

TOML_WITHOUT_PROJECT = """\
[targets.main]
binary = "test.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src"
"""


class TestProjectSection:
    def test_project_name(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, TOML_WITH_PROJECT)
        cfg = load_config(root)
        assert cfg.project_name == "Test Game"

    def test_default_jobs(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, TOML_WITH_PROJECT)
        cfg = load_config(root)
        assert cfg.default_jobs == 16

    def test_db_dir_resolved(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, TOML_WITH_PROJECT)
        cfg = load_config(root)
        assert cfg.db_dir == root / "mydb"

    def test_output_dir_resolved(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, TOML_WITH_PROJECT)
        cfg = load_config(root)
        assert cfg.output_dir == root / "myout"

    def test_defaults_when_missing(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, TOML_WITHOUT_PROJECT)
        cfg = load_config(root)
        assert cfg.project_name == ""
        assert cfg.default_jobs == 4
        assert cfg.db_dir == root / "db"
        assert cfg.output_dir == root / "output"


# ---------------------------------------------------------------------------
# 2. Compiler base_cflags + compile_timeout
# ---------------------------------------------------------------------------

TOML_WITH_COMPILER = """\
[compiler]
base_cflags = "/nologo /c"
timeout = 30

[targets.main]
binary = "test.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src"
"""


class TestCompilerConfig:
    def test_base_cflags(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, TOML_WITH_COMPILER)
        cfg = load_config(root)
        assert cfg.base_cflags == "/nologo /c"

    def test_compile_timeout(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, TOML_WITH_COMPILER)
        cfg = load_config(root)
        assert cfg.compile_timeout == 30

    def test_defaults_when_missing(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, TOML_WITHOUT_PROJECT)
        cfg = load_config(root)
        assert cfg.base_cflags == "/nologo /c /MT"
        assert cfg.compile_timeout == 60


# ---------------------------------------------------------------------------
# 3. Marker field
# ---------------------------------------------------------------------------

TOML_WITH_MARKER = """\
[targets.server]
binary = "server.dll"
format = "pe"
arch = "x86_32"
marker = "MYMARKER"
reversed_dir = "src"
"""


class TestMarkerField:
    def test_explicit_marker(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, TOML_WITH_MARKER)
        cfg = load_config(root)
        assert cfg.marker == "MYMARKER"

    def test_default_marker(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, TOML_WITHOUT_PROJECT)
        cfg = load_config(root)
        assert cfg.marker == "MAIN"


# ---------------------------------------------------------------------------
# 4. estimate_difficulty with ignored symbols
# ---------------------------------------------------------------------------


class TestEstimateDifficulty:
    def test_ignored_returns_zero(self) -> None:
        d, _ = estimate_difficulty(100, "memset", "GAME", {"memset", "strcmp"})
        assert d == 0

    def test_not_ignored_nonzero(self) -> None:
        d, _ = estimate_difficulty(100, "foo_bar", "GAME", {"memset"})
        assert d > 0

    def test_empty_ignored(self) -> None:
        d, _ = estimate_difficulty(100, "memset", "GAME", set())
        assert d > 0

    def test_none_ignored(self) -> None:
        d, _ = estimate_difficulty(100, "memset", "GAME", None)
        assert d > 0

    def test_zlib_easy(self) -> None:
        d, _ = estimate_difficulty(50, "deflate", "ZLIB")
        assert d == 2  # small library origin with reference source

    def test_small_game_easy(self) -> None:
        d, _ = estimate_difficulty(50, "get_x", "GAME")
        assert d == 1

    def test_large_game_hard(self) -> None:
        d, _ = estimate_difficulty(500, "process_all", "GAME")
        assert d == 5


# ---------------------------------------------------------------------------
# 5. ignored_symbols helper
# ---------------------------------------------------------------------------


class TestIgnoredSymbolsHelper:
    def test_from_config(self, tmp_path: Path) -> None:
        toml = """\
[targets.main]
binary = "test.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src"
ignored_symbols = ["memset", "strcmp"]
"""
        root = _make_project(tmp_path, toml)
        cfg = load_config(root)
        result = ignored_symbols(cfg)
        assert result == {"memset", "strcmp"}

    def test_empty_when_not_set(self, tmp_path: Path) -> None:
        root = _make_project(tmp_path, TOML_WITHOUT_PROJECT)
        cfg = load_config(root)
        result = ignored_symbols(cfg)
        assert result == set()
