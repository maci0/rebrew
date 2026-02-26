"""Tests for the rebrew sync module -- pure-function helpers."""

from rebrew.sync import (
    _STATUS_BOOKMARK_CATEGORY,
    _is_generic_name,
    build_new_function_commands,
    build_size_sync_commands,
    build_sync_commands,
)

# ---------------------------------------------------------------------------
# _is_generic_name
# ---------------------------------------------------------------------------


class TestIsGenericName:
    """Tests for the _is_generic_name() helper."""

    def test_lowercase_generic(self) -> None:
        assert _is_generic_name("func_10006c00") is True

    def test_uppercase_generic(self) -> None:
        assert _is_generic_name("FUN_10006C00") is True

    def test_real_name(self) -> None:
        assert _is_generic_name("inflate_init") is False

    def test_underscore_prefix(self) -> None:
        assert _is_generic_name("_malloc") is False

    def test_empty_string(self) -> None:
        assert _is_generic_name("") is False

    def test_partial_match(self) -> None:
        """func_ prefix but non-hex suffix is not generic."""
        assert _is_generic_name("func_main_loop") is False

    def test_fun_prefix_hex(self) -> None:
        assert _is_generic_name("FUN_DEADBEEF") is True

    def test_func_prefix_mixed_case_hex(self) -> None:
        assert _is_generic_name("func_aAbBcCdD") is True


# ---------------------------------------------------------------------------
# _STATUS_BOOKMARK_CATEGORY
# ---------------------------------------------------------------------------


class TestStatusBookmarkCategory:
    """Tests for the _STATUS_BOOKMARK_CATEGORY mapping."""

    def test_exact(self) -> None:
        assert _STATUS_BOOKMARK_CATEGORY["EXACT"] == "rebrew/exact"

    def test_reloc(self) -> None:
        assert _STATUS_BOOKMARK_CATEGORY["RELOC"] == "rebrew/reloc"

    def test_matching(self) -> None:
        assert _STATUS_BOOKMARK_CATEGORY["MATCHING"] == "rebrew/matching"

    def test_matching_reloc(self) -> None:
        assert _STATUS_BOOKMARK_CATEGORY["MATCHING_RELOC"] == "rebrew/matching"

    def test_stub(self) -> None:
        assert _STATUS_BOOKMARK_CATEGORY["STUB"] == "rebrew/stub"

    def test_has_five_entries(self) -> None:
        assert len(_STATUS_BOOKMARK_CATEGORY) == 5


# ---------------------------------------------------------------------------
# build_sync_commands
# ---------------------------------------------------------------------------


def _make_entry(
    va: int = 0x10001000,
    name: str = "my_func",
    status: str = "RELOC",
    origin: str = "GAME",
    size: int = 100,
    cflags: str = "/O2 /Gd",
    symbol: str = "_my_func",
    marker_type: str = "FUNCTION",
    filepath: str = "src/server.dll/my_func.c",
) -> dict:
    return {
        "va": va,
        "name": name,
        "status": status,
        "origin": origin,
        "size": size,
        "cflags": cflags,
        "symbol": symbol,
        "marker_type": marker_type,
        "filepath": filepath,
    }


class TestBuildSyncCommands:
    """Tests for build_sync_commands()."""

    def test_basic_commands(self) -> None:
        """One entry produces label + comment + bookmark."""
        entries = [_make_entry()]
        cmds = build_sync_commands(entries, "/server.dll")
        tools = [c["tool"] for c in cmds]
        assert "create-label" in tools
        assert "set-comment" in tools
        assert "set-bookmark" in tools

    def test_skips_generic_labels(self, capsys) -> None:
        """Generic names are skipped when skip_generic_labels=True."""
        entries = [_make_entry(name="func_10001000")]
        cmds = build_sync_commands(entries, "/server.dll", skip_generic_labels=True)
        label_cmds = [c for c in cmds if c["tool"] == "create-label"]
        assert len(label_cmds) == 0

    def test_includes_generic_labels_when_disabled(self) -> None:
        """Generic names are included when skip_generic_labels=False."""
        entries = [_make_entry(name="func_10001000")]
        cmds = build_sync_commands(entries, "/server.dll", skip_generic_labels=False)
        label_cmds = [c for c in cmds if c["tool"] == "create-label"]
        assert len(label_cmds) == 1

    def test_create_functions_flag(self) -> None:
        """create_functions=True prepends create-function commands."""
        entries = [_make_entry()]
        cmds = build_sync_commands(entries, "/server.dll", create_functions=True)
        assert cmds[0]["tool"] == "create-function"

    def test_no_create_functions_by_default(self) -> None:
        """create_functions=False (default) omits create-function."""
        entries = [_make_entry()]
        cmds = build_sync_commands(entries, "/server.dll", create_functions=False)
        create_cmds = [c for c in cmds if c["tool"] == "create-function"]
        assert len(create_cmds) == 0

    def test_iat_thunks_skipped(self) -> None:
        """VAs in iat_thunks are skipped for create-function."""
        entries = [_make_entry(va=0x10001000)]
        cmds = build_sync_commands(
            entries,
            "/server.dll",
            create_functions=True,
            iat_thunks={0x10001000},
        )
        create_cmds = [c for c in cmds if c["tool"] == "create-function"]
        assert len(create_cmds) == 0

    def test_comment_contains_status(self) -> None:
        """Comment includes status info."""
        entries = [_make_entry(status="EXACT")]
        cmds = build_sync_commands(entries, "/server.dll")
        comment_cmds = [c for c in cmds if c["tool"] == "set-comment"]
        assert len(comment_cmds) == 1
        assert "EXACT" in comment_cmds[0]["args"]["comment"]

    def test_bookmark_category(self) -> None:
        """Bookmark uses _STATUS_BOOKMARK_CATEGORY mapping."""
        entries = [_make_entry(status="RELOC")]
        cmds = build_sync_commands(entries, "/server.dll")
        bm_cmds = [c for c in cmds if c["tool"] == "set-bookmark"]
        assert len(bm_cmds) == 1
        assert bm_cmds[0]["args"]["category"] == "rebrew/reloc"

    def test_empty_entries(self) -> None:
        """No entries produces no commands."""
        cmds = build_sync_commands([], "/server.dll")
        assert cmds == []

    def test_multiple_entries_same_va(self) -> None:
        """Multiple entries at the same VA are grouped — one label from primary."""
        entries = [
            _make_entry(va=0x1000, name="game_pool_alloc", filepath="a.c"),
            _make_entry(va=0x1000, name="game_pool_alloc", filepath="b.c"),
        ]
        cmds = build_sync_commands(entries, "/server.dll")
        # Should use first entry's name for label
        label_cmds = [c for c in cmds if c["tool"] == "create-label"]
        assert len(label_cmds) == 1
        assert label_cmds[0]["args"]["labelName"] == "game_pool_alloc"


# ---------------------------------------------------------------------------
# build_size_sync_commands
# ---------------------------------------------------------------------------


class TestBuildSizeSyncCommands:
    """Tests for build_size_sync_commands()."""

    def test_expands_when_canonical_larger(self) -> None:
        """Generates command when canonical_size > ghidra_size."""
        registry = {
            0x1000: {
                "size_by_tool": {"ghidra": 50, "r2": 80},
                "canonical_size": 80,
                "size_reason": "r2 larger",
            }
        }
        cmds = build_size_sync_commands(registry, "/server.dll")
        assert len(cmds) == 1
        assert cmds[0]["tool"] == "create-function"
        assert cmds[0]["args"]["address"] == "0x00001000"

    def test_no_command_when_equal(self) -> None:
        """No command when canonical_size == ghidra_size."""
        registry = {
            0x1000: {
                "size_by_tool": {"ghidra": 80, "r2": 80},
                "canonical_size": 80,
                "size_reason": "",
            }
        }
        cmds = build_size_sync_commands(registry, "/server.dll")
        assert len(cmds) == 0

    def test_no_command_when_canonical_smaller(self) -> None:
        """No command when canonical_size < ghidra_size."""
        registry = {
            0x1000: {
                "size_by_tool": {"ghidra": 80},
                "canonical_size": 50,
                "size_reason": "",
            }
        }
        cmds = build_size_sync_commands(registry, "/server.dll")
        assert len(cmds) == 0

    def test_skips_iat_thunks(self) -> None:
        """IAT thunk VAs are skipped."""
        registry = {
            0x1000: {
                "size_by_tool": {"ghidra": 50},
                "canonical_size": 80,
                "size_reason": "",
            }
        }
        cmds = build_size_sync_commands(registry, "/server.dll", iat_thunks={0x1000})
        assert len(cmds) == 0

    def test_skips_zero_sizes(self) -> None:
        """Entries with zero canonical or ghidra size are skipped."""
        registry = {
            0x1000: {
                "size_by_tool": {"ghidra": 0},
                "canonical_size": 80,
                "size_reason": "",
            }
        }
        cmds = build_size_sync_commands(registry, "/server.dll")
        assert len(cmds) == 0

    def test_empty_registry(self) -> None:
        cmds = build_size_sync_commands({}, "/server.dll")
        assert cmds == []


# ---------------------------------------------------------------------------
# build_new_function_commands
# ---------------------------------------------------------------------------


class TestBuildNewFunctionCommands:
    """Tests for build_new_function_commands()."""

    def test_r2_only_function(self) -> None:
        """Generates command for function detected by r2 but not ghidra."""
        registry = {
            0x2000: {
                "detected_by": ["r2"],
                "canonical_size": 64,
                "size_by_tool": {"r2": 64},
            }
        }
        cmds = build_new_function_commands(registry, "/server.dll")
        assert len(cmds) == 1
        assert cmds[0]["tool"] == "create-function"

    def test_both_detected_no_command(self) -> None:
        """No command when both r2 and ghidra detected the function."""
        registry = {
            0x2000: {
                "detected_by": ["r2", "ghidra"],
                "canonical_size": 64,
                "size_by_tool": {"r2": 64, "ghidra": 64},
            }
        }
        cmds = build_new_function_commands(registry, "/server.dll")
        assert len(cmds) == 0

    def test_ghidra_only_no_command(self) -> None:
        """No command when only ghidra detected the function."""
        registry = {
            0x2000: {
                "detected_by": ["ghidra"],
                "canonical_size": 64,
                "size_by_tool": {"ghidra": 64},
            }
        }
        cmds = build_new_function_commands(registry, "/server.dll")
        assert len(cmds) == 0

    def test_skips_zero_canonical_size(self) -> None:
        """Entries with zero canonical size are skipped."""
        registry = {
            0x2000: {
                "detected_by": ["r2"],
                "canonical_size": 0,
                "size_by_tool": {"r2": 0},
            }
        }
        cmds = build_new_function_commands(registry, "/server.dll")
        assert len(cmds) == 0

    def test_skips_iat_thunks(self) -> None:
        """IAT thunk VAs are skipped."""
        registry = {
            0x2000: {
                "detected_by": ["r2"],
                "canonical_size": 64,
                "size_by_tool": {"r2": 64},
            }
        }
        cmds = build_new_function_commands(registry, "/server.dll", iat_thunks={0x2000})
        assert len(cmds) == 0

    def test_empty_registry(self) -> None:
        cmds = build_new_function_commands({}, "/server.dll")
        assert cmds == []
