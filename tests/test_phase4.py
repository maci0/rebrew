"""Phase 4 tests — verify deduplication, dead code removal, and init template."""


# ---------------------------------------------------------------------------
# 1. Deduplication: canonical imports resolve correctly
# ---------------------------------------------------------------------------


def test_scan_reversed_dir_importable_from_catalog() -> None:
    """scan_reversed_dir is importable from its canonical home."""
    from rebrew.catalog import scan_reversed_dir

    assert callable(scan_reversed_dir)


def test_parse_r2_functions_importable_from_catalog() -> None:
    """parse_r2_functions is importable from its canonical home."""
    from rebrew.catalog import parse_r2_functions

    assert callable(parse_r2_functions)


def test_r2_bogus_vas_config_driven() -> None:
    """r2_bogus_vas are now config-driven, not hardcoded in catalog."""
    from rebrew.catalog import _DEFAULT_R2_BOGUS_SIZES

    # Default is empty — projects set their own via rebrew.toml
    assert isinstance(_DEFAULT_R2_BOGUS_SIZES, set)
    assert len(_DEFAULT_R2_BOGUS_SIZES) == 0


# ---------------------------------------------------------------------------
# 2. Re-exports: backward compat from verify.py still works
# ---------------------------------------------------------------------------


def test_scan_reversed_dir_reexported_from_verify() -> None:
    """scan_reversed_dir is still importable from verify for backwards compat."""
    from rebrew.verify import scan_reversed_dir

    assert callable(scan_reversed_dir)


def test_parse_r2_functions_reexported_from_verify() -> None:
    """parse_r2_functions is still importable from verify."""
    from rebrew.verify import parse_r2_functions

    assert callable(parse_r2_functions)


def test_r2_bogus_vas_via_config() -> None:
    """verify uses cfg.r2_bogus_vas instead of module-level constant."""
    from types import SimpleNamespace

    from rebrew.catalog import build_function_registry, make_r2_func

    bogus_va = 0xBEEF0000
    cfg = SimpleNamespace(iat_thunks=set(), dll_exports={}, r2_bogus_vas=[bogus_va])
    r2_funcs = [make_r2_func(bogus_va, 12345, "_bogus")]
    reg = build_function_registry(r2_funcs, cfg)
    assert bogus_va in reg
    assert "r2" not in reg[bogus_va]["size_by_tool"]


# ---------------------------------------------------------------------------
# 3. They point to the same object (not a copy)
# ---------------------------------------------------------------------------


def test_scan_reversed_dir_is_same_object() -> None:
    """catalog.scan_reversed_dir is verify.scan_reversed_dir."""
    from rebrew.catalog import scan_reversed_dir as cat_fn
    from rebrew.verify import scan_reversed_dir as ver_fn

    assert cat_fn is ver_fn


def test_parse_r2_functions_is_same_object() -> None:
    """catalog.parse_r2_functions is verify.parse_r2_functions."""
    from rebrew.catalog import parse_r2_functions as cat_fn
    from rebrew.verify import parse_r2_functions as ver_fn

    assert cat_fn is ver_fn


# ---------------------------------------------------------------------------
# 4. Dead code removed
# ---------------------------------------------------------------------------


def test_no_private_normalize_aliases() -> None:
    """_normalize_status and _normalize_cflags no longer exist in catalog."""
    import rebrew.catalog as cat

    assert not hasattr(cat, "_normalize_status")
    assert not hasattr(cat, "_normalize_cflags")


# ---------------------------------------------------------------------------
# 5. init.py template contains [project] section and new keys
# ---------------------------------------------------------------------------


def test_init_template_has_project_section() -> None:
    """The generated rebrew.toml template includes a [project] section."""
    from rebrew.init import DEFAULT_REBREW_TOML

    assert "[project]" in DEFAULT_REBREW_TOML


def test_init_template_has_base_cflags() -> None:
    """The generated rebrew.toml template includes base_cflags."""
    from rebrew.init import DEFAULT_REBREW_TOML

    assert "base_cflags" in DEFAULT_REBREW_TOML


def test_init_template_has_timeout() -> None:
    """The generated rebrew.toml template includes compile timeout."""
    from rebrew.init import DEFAULT_REBREW_TOML

    assert "timeout" in DEFAULT_REBREW_TOML


def test_init_template_has_ignored_symbols() -> None:
    """The generated rebrew.toml template includes ignored_symbols."""
    from rebrew.init import DEFAULT_REBREW_TOML

    assert "ignored_symbols" in DEFAULT_REBREW_TOML


def test_init_template_has_jobs() -> None:
    """The generated rebrew.toml template includes jobs."""
    from rebrew.init import DEFAULT_REBREW_TOML

    assert "jobs" in DEFAULT_REBREW_TOML


# ---------------------------------------------------------------------------
# 6. parse_r2_functions works correctly (functional test)
# ---------------------------------------------------------------------------


def test_parse_r2_functions_parses_correctly(tmp_path) -> None:
    """parse_r2_functions correctly parses a function list file."""
    from rebrew.catalog import parse_r2_functions

    func_list = tmp_path / "r2_functions.txt"
    func_list.write_text(
        "0x10001000 64 _my_func\n"
        "0x10002000 128 _other_func\n"
        "# comment line\n"
        "0x10003000 32 _third_func\n",
        encoding="utf-8",
    )

    funcs = parse_r2_functions(func_list)
    assert len(funcs) == 3
    assert funcs[0]["va"] == 0x10001000
    assert funcs[0]["size"] == 64
    assert funcs[0]["r2_name"] == "_my_func"
    assert funcs[1]["va"] == 0x10002000
    assert funcs[2]["r2_name"] == "_third_func"


# ---------------------------------------------------------------------------
# 7. scan_reversed_dir works correctly (functional test)
# ---------------------------------------------------------------------------


def test_scan_reversed_dir_finds_annotated_files(tmp_path) -> None:
    """scan_reversed_dir finds .c files with valid annotations."""
    from rebrew.catalog import scan_reversed_dir

    # Create a valid annotated file
    c_file = tmp_path / "game_func.c"
    c_file.write_text(
        "// FUNCTION: SERVER 0x10001000\n"
        "// STATUS: STUB\n"
        "// ORIGIN: GAME\n"
        "// SIZE: 64\n"
        "// CFLAGS: /O2 /Gd\n"
        "// SYMBOL: _my_func\n"
        "void __cdecl _my_func(void) {\n"
        "}\n",
        encoding="utf-8",
    )

    # Create a non-C file (should be ignored)
    (tmp_path / "readme.txt").write_text("ignore me", encoding="utf-8")

    entries = scan_reversed_dir(tmp_path)
    assert len(entries) == 1


# ---------------------------------------------------------------------------
# 8. skeleton.py imports are at top of file
# ---------------------------------------------------------------------------


def test_skeleton_imports_at_top() -> None:
    """skeleton.py should not have mid-file imports."""
    import inspect

    import rebrew.skeleton as skel

    src = inspect.getsource(skel)
    lines = src.split("\n")

    # After the module docstring ends, imports should be before any def/class
    in_imports = False
    past_imports = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            if past_imports:
                # An import after a function def is a mid-file import
                raise AssertionError(f"Mid-file import found: {stripped}")
            in_imports = True
        elif stripped.startswith("def ") or stripped.startswith("class "):
            if in_imports:
                past_imports = True


# ---------------------------------------------------------------------------
# 9. rebrew-init copies agent-skills into new project
# ---------------------------------------------------------------------------


def test_init_agents_md_has_skills_section() -> None:
    """AGENTS.md template references the agent-skills directory."""
    from rebrew.init import DEFAULT_AGENTS_MD

    assert "## Agent Skills" in DEFAULT_AGENTS_MD
    assert "rebrew-workflow" in DEFAULT_AGENTS_MD
    assert "rebrew-matching" in DEFAULT_AGENTS_MD
    assert "rebrew-sync" in DEFAULT_AGENTS_MD


def test_init_agent_skills_source_exists() -> None:
    """Bundled agent-skills directory exists in the package."""
    from rebrew.init import _AGENT_SKILLS_SRC

    assert _AGENT_SKILLS_SRC.is_dir()
    subdirs = sorted(d.name for d in _AGENT_SKILLS_SRC.iterdir() if d.is_dir())
    assert "rebrew-workflow" in subdirs
    assert "rebrew-matching" in subdirs
    assert "rebrew-sync" in subdirs
    assert "rebrew-data-analysis" in subdirs
    assert "rebrew-status-tracking" in subdirs


def test_init_copies_agent_skills(tmp_path) -> None:
    """rebrew-init copies agent-skills/ and substitutes <target>."""
    from rebrew.init import _copy_agent_skills

    _copy_agent_skills(tmp_path, "server.dll")

    skills_dir = tmp_path / "agent-skills"
    assert skills_dir.is_dir()

    # All 5 skill subdirectories present
    subdirs = sorted(d.name for d in skills_dir.iterdir() if d.is_dir())
    assert len(subdirs) == 5

    # Each has a SKILL.md
    for subdir in skills_dir.iterdir():
        if subdir.is_dir():
            assert (subdir / "SKILL.md").exists()

    # <target> replaced with actual target name
    for md_file in skills_dir.rglob("*.md"):
        content = md_file.read_text(encoding="utf-8")
        assert "<target>" not in content


def test_init_copies_agent_skills_idempotent(tmp_path) -> None:
    """Running _copy_agent_skills twice doesn't error (dirs_exist_ok)."""
    from rebrew.init import _copy_agent_skills

    _copy_agent_skills(tmp_path, "test")
    _copy_agent_skills(tmp_path, "test")  # should not raise

    assert (tmp_path / "agent-skills").is_dir()
