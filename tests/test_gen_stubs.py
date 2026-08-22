"""Tests for rebrew gen-stubs (unresolved linker symbol stub TU generation)."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.gen_stubs import (
    collect_extern_info,
    demangle_cdecl,
    ensure_param_names,
    generate_stubs,
    load_library_symbols,
    parse_extern_decl,
    parse_unresolved_symbols,
    simplify_type_for_stub,
)


def _write_src(tmp_path: Path, content: str) -> Path:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    p = src / "a.c"
    p.write_text(content, encoding="utf-8")
    return p


LNK_OUTPUT = """\
foo.obj : error LNK2019: unresolved external symbol _write_log referenced in function _main
bar.obj : error LNK2001: unresolved external symbol _thread_proc@4
baz.obj : error LNK2019: unresolved external symbol _g_counter referenced in function _main
qux.obj : error LNK2019: unresolved external symbol s_D__foo_1002c748 referenced in function _foo
"""


class TestParseLinkerOutput:
    def test_parses_lnk2001_and_2019(self) -> None:
        syms = parse_unresolved_symbols(LNK_OUTPUT)
        assert syms == {"_write_log", "_thread_proc@4", "_g_counter", "s_D__foo_1002c748"}

    def test_no_matches(self) -> None:
        assert parse_unresolved_symbols("fatal error C1083") == set()


class TestDemangle:
    def test_cdecl(self) -> None:
        assert demangle_cdecl("_write_log") == "write_log"

    def test_stdcall(self) -> None:
        assert demangle_cdecl("_thread_proc@4") == "thread_proc"

    def test_plain(self) -> None:
        assert demangle_cdecl("g_counter") == "g_counter"


class TestExternParsing:
    def test_function_with_cc(self) -> None:
        info = parse_extern_decl("extern int __cdecl foo(int, char*);")
        assert info is not None
        assert info["name"] == "foo"
        assert info["is_func"] is True
        assert info["calling_conv"] == "__cdecl"
        assert info["type"] == "int"

    def test_function_without_cc(self) -> None:
        info = parse_extern_decl("extern void bar(unsigned int);")
        assert info is not None
        assert info["name"] == "bar"
        assert info["calling_conv"] is None

    def test_array(self) -> None:
        info = parse_extern_decl("extern char g_buf[256];")
        assert info is not None
        assert info["is_array"] is True
        assert info["array_size"] == "256"

    def test_scalar(self) -> None:
        info = parse_extern_decl("extern int g_count;")
        assert info is not None
        assert info["name"] == "g_count"
        assert info["is_func"] is False
        assert info["is_array"] is False

    def test_type_keyword_rejected(self) -> None:
        assert parse_extern_decl("extern int char;") is None


class TestCollectExterns:
    def test_first_seen_wins(self, tmp_path: Path) -> None:
        p = _write_src(
            tmp_path,
            "extern int foo(int);\nextern int foo(char*, void*);\nextern void bar(void);\n",
        )
        src = p.parent
        infos = collect_extern_info(src)
        assert infos["foo"]["params"] == "(int)"
        assert "bar" in infos

    def test_skips_non_extern_lines(self, tmp_path: Path) -> None:
        p = _write_src(tmp_path, "int local = 3;\n/* extern int hidden; */\n")
        assert collect_extern_info(p.parent) == {}


class TestSimplify:
    def test_struct_ptr_to_void(self) -> None:
        assert simplify_type_for_stub("struct ENT*") == "void*"

    def test_known_typedefs(self) -> None:
        assert simplify_type_for_stub("DWORD") == "unsigned int"
        assert simplify_type_for_stub("uchar*") == "unsigned char*"

    def test_unknown_single_word(self) -> None:
        assert simplify_type_for_stub("SlotEntry") == "int"
        assert simplify_type_for_stub("Mystery*") == "void*"

    def test_primitive_kept(self) -> None:
        assert simplify_type_for_stub("int") == "int"


class TestParamNames:
    def test_names_added(self) -> None:
        assert ensure_param_names("(int, char*, void*)") == "(int a, char* b, void* c)"

    def test_named_untouched(self) -> None:
        assert ensure_param_names("(int count, char* buf)") == "(int count, char* buf)"

    def test_void_untouched(self) -> None:
        assert ensure_param_names("(void)") == "(void)"


class TestGenerate:
    def _externs(self) -> dict[str, dict]:
        return {
            "write_log": {
                "name": "write_log",
                "type": "int",
                "is_func": True,
                "calling_conv": "__cdecl",
                "params": "(char*)",
                "full_decl": "extern int __cdecl write_log(char*);",
                "is_array": False,
                "array_size": None,
            },
            "g_counter": {
                "name": "g_counter",
                "type": "int",
                "is_func": False,
                "calling_conv": None,
                "params": None,
                "full_decl": "extern int g_counter;",
                "is_array": False,
                "array_size": None,
            },
            "s_D__foo_1002c748": {
                "name": "s_D__foo_1002c748",
                "type": "char",
                "is_func": False,
                "calling_conv": None,
                "params": None,
                "full_decl": "extern char s_D__foo_1002c748[];",
                "is_array": True,
                "array_size": "1",
            },
        }

    def test_emits_globals_functions_strings(self) -> None:
        content = generate_stubs(
            ["_write_log", "_g_counter", "_thread_proc@4", "s_D__foo_1002c748"],
            self._externs(),
        )
        assert "int g_counter = 0;" in content
        assert "int __cdecl write_log(char* a)" in content
        assert "\treturn 0;" in content
        assert 'char s_D__foo_1002c748[1] = "";' in content
        # no extern info -> guessed global
        assert "int thread_proc = 0;" in content

    def test_specials_and_bss(self) -> None:
        specials = {
            "specials": {
                "thread_proc": {
                    "decl": "extern int __cdecl ServerMainThread(void*);",
                    "impl": "int __stdcall thread_proc(void* param)\n{\n\treturn ServerMainThread(param);\n}",
                }
            },
            "bss_arrays": [["g_player_slot_0", 0x264264]],
            "bss_tail_size": 0x1269F30,
        }
        content = generate_stubs(["_thread_proc@4"], {}, specials=specials)
        assert "int __stdcall thread_proc(void* param)" in content
        assert "extern int __cdecl ServerMainThread(void*);" in content
        assert "char g_player_slot_0[0x264264] = {0};" in content
        assert "unsigned char g_bss_tail[0x1269f30] = {0};" in content

    def test_footer_appended(self) -> None:
        content = generate_stubs([], {}, footer="/* marker */\nint _fltused = 0;")
        assert content.rstrip("\n").endswith("int _fltused = 0;")

    def test_guess_functions_by_name(self) -> None:
        content = generate_stubs(["_free_node", "_mystery_global"], {})
        assert "int __cdecl free_node(void)" in content
        assert "int mystery_global = 0;" in content


class TestLibraryFilter:
    def test_skips_library_symbols(self, tmp_path: Path) -> None:
        csv = tmp_path / "funcs.csv"
        csv.write_text("a|_malloc|malloc|library|0\nb|_myfn|myfn|game|1\n", encoding="utf-8")
        libs = load_library_symbols(csv)
        assert libs == {"_malloc", "malloc"}


class TestCli:
    def test_stdin_dry_run(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.gen_stubs import app

        monkeypatch.chdir(tmp_path)
        _write_src(tmp_path, "extern int g_counter;\nextern int __cdecl write_log(char*);\n")
        result = CliRunner().invoke(app, ["--dry-run"], input=LNK_OUTPUT)
        assert result.exit_code == 0
        assert "int g_counter = 0;" in result.output
        assert "int __cdecl write_log(char* a)" in result.output

    def test_log_file_writes_out(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.gen_stubs import app

        monkeypatch.chdir(tmp_path)
        _write_src(tmp_path, "extern int g_counter;\nextern int __cdecl write_log(char*);\n")
        log = tmp_path / "build.log"
        log.write_text(LNK_OUTPUT, encoding="utf-8")
        out = tmp_path / "stubs.c"
        result = CliRunner().invoke(app, ["--log", str(log), "--out", str(out)])
        assert result.exit_code == 0
        assert "int g_counter = 0;" in out.read_text(encoding="utf-8")
        assert "int __cdecl write_log(char* a)" in out.read_text(encoding="utf-8")

    def test_no_unresolved_is_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.gen_stubs import app

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["--dry-run"], input="fatal error C1083\n")
        assert result.exit_code == 2  # EXIT_ERROR
        assert "no unresolved symbols" in result.output

    def test_specials_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.gen_stubs import app

        monkeypatch.chdir(tmp_path)
        _write_src(tmp_path, "extern int g_counter;\nextern int __cdecl write_log(char*);\n")
        spec = tmp_path / "specials.toml"
        spec.write_text(
            "bss_tail_size = 0x1000\n\n"
            "[specials.thread_proc]\n"
            'decl = "extern int __cdecl ServerMainThread(void*);"\n'
            'impl = "int __stdcall thread_proc(void* p)\\n{\\n\\treturn ServerMainThread(p);\\n}"\n',
            encoding="utf-8",
        )
        result = CliRunner().invoke(app, ["--dry-run", "--specials", str(spec)], input=LNK_OUTPUT)
        assert result.exit_code == 0
        assert "int __stdcall thread_proc(void* p)" in result.output
        assert "unsigned char g_bss_tail[0x1000] = {0};" in result.output

    def test_cmake_stub_var_patched_and_restored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.gen_stubs import app

        monkeypatch.chdir(tmp_path)
        _write_src(tmp_path, "extern int g_counter;\nextern int __cdecl write_log(char*);\n")
        cmake = tmp_path / "CMakeLists.txt"
        cmake.write_text(
            'set(LINK_STUBS "${PROJECT_SOURCE_DIR}/src/link_stubs.c")\n'
            "add_library(x SHARED ${SOURCES} ${LINK_STUBS})\n",
            encoding="utf-8",
        )
        # Build command that proves the stub var was blanked: echo a resolved
        # link if LINK_STUBS was emptied, unresolved otherwise.
        build_cmd = (
            "grep -q 'set(LINK_STUBS \"\")' CMakeLists.txt && "
            "echo 'error LNK2019: unresolved external symbol _g_counter' || echo clean"
        )
        out = tmp_path / "stubs.c"
        result = CliRunner().invoke(
            app,
            [
                "--build-cmd",
                build_cmd,
                "--cmake-stub-var",
                "LINK_STUBS",
                "--out",
                str(out),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "int g_counter = 0;" in out.read_text(encoding="utf-8")
        # CMakeLists restored byte-exact.
        restored = cmake.read_text(encoding="utf-8")
        assert 'set(LINK_STUBS "${PROJECT_SOURCE_DIR}/src/link_stubs.c")' in restored

    def test_exclude_file_renamed_and_restored(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.gen_stubs import app

        monkeypatch.chdir(tmp_path)
        _write_src(tmp_path, "extern int g_counter;\nextern int __cdecl write_log(char*);\n")
        stub = tmp_path / "link_stubs.c"
        stub.write_text("int something = 1;\n", encoding="utf-8")
        build_cmd = (
            "test ! -e link_stubs.c && "
            "echo 'error LNK2019: unresolved external symbol _g_counter' || echo clean"
        )
        out = tmp_path / "stubs.c"
        result = CliRunner().invoke(
            app,
            [
                "--build-cmd",
                build_cmd,
                "--exclude-file",
                str(stub),
                "--out",
                str(out),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "int g_counter = 0;" in out.read_text(encoding="utf-8")
        assert stub.read_text(encoding="utf-8") == "int something = 1;\n"
