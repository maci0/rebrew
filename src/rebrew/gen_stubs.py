"""gen-stubs — generate a stub TU for unresolved linker symbols.

Byte-identity rebuilds of a whole binary need every symbol the reversed
sources reference to link.  This command turns the linker's unresolved
external symbols into a typed ``link_stubs.c``-style TU: it parses
``LNK2001``/``LNK2019`` errors from a build (or a saved log / stdin),
derives each symbol's type from ``extern`` declarations in the reversed
sources, and emits zero-init globals, string globals (``s_*``) and stub
functions with simplified C89 types.

Project policy — special forwarding stubs (``gm_*`` wrappers, stdcall
thread entries), the big non-tentative BSS arrays, the ``g_bss_tail`` pad
and a verbatim footer (e.g. a ``_fltused`` marker) are **not** rebrew's
business; supply them via ``--specials <toml>`` / ``--footer <file>``:

    [specials.thread_proc]
    decl = "extern int __cdecl ServerMainThread(void*);"
    impl = "int __stdcall thread_proc(void* param)\n{\n\treturn ServerMainThread(param);\n}"

    [[bss_arrays]]            # non-tentative, kept out of COMMON
    name = "g_player_slot_0"
    size = 0x264264

    bss_tail_size = 0x1269f30  # emits g_bss_tail[N]
    keep_stub_exceptions = ["_vfs_Crc32Update"]   # lib-tagged, but still stub

Usage:
    # Build without stubs and generate from the linker errors:
    rebrew gen-stubs --build-cmd "cmake --build build -j8" --cmake-stub-var LINK_STUBS
    # Or from a saved build log / piped output:
    rebrew gen-stubs --log build.log
    cmake --build build 2>&1 | rebrew gen-stubs
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
import typing
from collections.abc import Iterable
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import error_exit, json_print

console = Console(stderr=True)

app = typer.Typer(
    help="Generate a stub TU for unresolved linker symbols (LNK2001/LNK2019).",
    rich_markup_mode="rich",
)

# Symbol name helpers ----------------------------------------------------------


_DEMANGLE_RE = re.compile(r"@\d+$")


def demangle_cdecl(mangled: str) -> str:
    """Strip MSVC cdecl/stdcall mangling: ``_name`` -> ``name``, ``_name@N`` -> ``name``."""
    name = mangled
    if name.startswith("_"):
        name = name[1:]
    return _DEMANGLE_RE.sub("", name)


# --- linker output parsing ---------------------------------------------------


def parse_unresolved_symbols(linker_output: str) -> set[str]:
    """Parse MSVC LNK2001/LNK2019 errors to extract unresolved symbol names."""
    symbols: set[str] = set()
    for line in linker_output.splitlines():
        m = re.search(r"error LNK20(?:01|19): unresolved external symbol (\S+)", line)
        if m:
            symbols.add(m.group(1))
    return symbols


def load_library_symbols(csv_path: Path) -> set[str]:
    """The decorated symbol names tagged ``library`` in the functions CSV.

    These are satisfied by the static CRT lib — the linker pulls the members
    naturally; stubbing them would shadow the lib.
    """
    library_symbols: set[str] = set()
    for line in csv_path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split("|")
        if len(parts) >= 5 and parts[3] == "library":
            if parts[2]:
                library_symbols.add(parts[2])
            if parts[1]:
                library_symbols.add(parts[1])
    return library_symbols


# --- extern declaration parsing ----------------------------------------------


def parse_extern_decl(decl: str) -> dict[str, typing.Any] | None:
    """Parse a single extern declaration line into structured info."""
    rest = decl[len("extern") :].strip().rstrip(";").strip()

    # Function with calling convention: TYPE __cdecl NAME(PARAMS)
    m = re.match(r"(.*?)\b(__cdecl|__stdcall)\s+(\w+)\s*(\(.*)", rest)
    if m:
        ret_type = m.group(1).strip()
        cc = m.group(2)
        name = m.group(3)
        params = m.group(4)
        if not params.endswith(")"):
            params += ")"
        return {
            "name": name,
            "type": ret_type,
            "is_func": True,
            "calling_conv": cc,
            "params": params,
            "full_decl": decl,
            "is_array": False,
            "array_size": None,
        }

    # Function without calling convention: TYPE NAME(PARAMS)
    m = re.match(r"(.*?)\b(\w+)\s*(\(.*)", rest)
    if m and "(" in m.group(3):
        ret_type = m.group(1).strip()
        name = m.group(2)
        params = m.group(3)
        if not params.endswith(")"):
            params += ")"
        if name not in ("int", "char", "void", "short", "float", "double", "unsigned", "struct"):
            return {
                "name": name,
                "type": ret_type,
                "is_func": True,
                "calling_conv": None,
                "params": params,
                "full_decl": decl,
                "is_array": False,
                "array_size": None,
            }

    # Variable with array: TYPE NAME[SIZE]
    m = re.match(r"(.*?)\b(\w+)\s*(\[.*?\])", rest)
    if m:
        var_type = m.group(1).strip()
        name = m.group(2)
        if name not in ("int", "char", "void", "short", "float", "double", "unsigned", "struct"):
            size_m = re.search(r"\[(\d+)\]", m.group(3))
            return {
                "name": name,
                "type": var_type,
                "is_func": False,
                "calling_conv": None,
                "params": None,
                "full_decl": decl,
                "is_array": True,
                "array_size": size_m.group(1) if size_m else "1",
            }

    # Simple variable: TYPE NAME
    m = re.match(r"(.*?)\b(\w+)\s*$", rest)
    if m:
        var_type = m.group(1).strip()
        name = m.group(2)
        if name not in ("int", "char", "void", "short", "float", "double", "unsigned", "struct"):
            return {
                "name": name,
                "type": var_type,
                "is_func": False,
                "calling_conv": None,
                "params": None,
                "full_decl": decl,
                "is_array": False,
                "array_size": None,
            }

    return None


def collect_extern_info(src_dir: Path) -> dict[str, dict[str, typing.Any]]:
    """``symbol_name -> info`` from every ``extern`` line in *src_dir*'s sources.

    First-seen wins (the first declaration of a name sets its stub type).
    """
    externs: dict[str, dict[str, typing.Any]] = {}
    for src_file in sorted(src_dir.rglob("*.c")):
        for line in src_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("extern"):
                continue
            line = re.sub(r"/\*.*?\*/", "", line).strip().rstrip("; ").strip()
            info = parse_extern_decl(line)
            if info and info["name"] not in externs:
                externs[info["name"]] = info
    return externs


_KNOWN_TYPES = {
    "ENT": "int",
    "Record*": "int*",
    "SlotEntry": "int",
    "WORD*": "unsigned short*",
    "WORD": "unsigned short",
    "DWORD": "unsigned int",
    "LPVOID": "void*",
    "LPDWORD": "unsigned int*",
    "dispatch_fn": "int",
    "handler_func": "int",
    "undefined *": "void*",
    "undefined*": "void*",
    "uint": "unsigned int",
    "ushort": "unsigned short",
    "ushort*": "unsigned short*",
    "uint*": "unsigned int*",
    "ulong": "unsigned long",
    "ulong*": "unsigned long*",
    "uchar": "unsigned char",
    "uchar*": "unsigned char*",
}

_C_PRIMITIVES = {
    "int",
    "char",
    "short",
    "long",
    "float",
    "double",
    "void",
    "unsigned",
    "signed",
    "const",
}


def simplify_type_for_stub(type_str: str) -> str:
    """Map structs/typedefs to C89 basics — link_stubs can't see those types."""
    if re.match(r"struct\s+\w+\*", type_str):
        return "void*"
    if re.match(r"struct\s+\w+", type_str):
        return "int"
    if type_str in _KNOWN_TYPES:
        return _KNOWN_TYPES[type_str]
    base = type_str.rstrip("*").strip()
    tokens = base.split()
    if len(tokens) == 1 and tokens[0] not in _C_PRIMITIVES:
        return "void*" if "*" in type_str else "int"
    return type_str


def ensure_param_names(params_str: str) -> str:
    """MSVC6 requires parameter names in definitions, not just types.

    ``(int, char*, void*)`` -> ``(int a, char* b, void* c)``; leaves
    already-named params and ``(void)`` untouched.
    """
    inner = params_str.strip()
    if inner.startswith("("):
        inner = inner[1:]
    if inner.endswith(")"):
        inner = inner[:-1]
    inner = inner.strip()

    if not inner or inner == "void" or inner == "...":
        return params_str

    parts: list[str] = []
    depth = 0
    current = ""
    for ch in inner:
        if ch == "(":
            depth += 1
            current += ch
        elif ch == ")":
            depth -= 1
            current += ch
        elif ch == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())

    param_names = "abcdefghijklmnop"
    result_parts = []
    for i, part in enumerate(parts):
        if part == "...":
            result_parts.append(part)
            continue
        if part == "void" and len(parts) == 1:
            result_parts.append(part)
            continue
        tokens = part.split()
        has_name = False
        if len(tokens) >= 2:
            last = tokens[-1]
            if re.match(r"^[a-zA-Z_]\w*$", last) and last not in _C_PRIMITIVES | {"struct"}:
                has_name = True
            if last.startswith("*"):
                has_name = False
        if part.endswith("*"):
            has_name = False
        if not has_name:
            name = param_names[i] if i < len(param_names) else f"p{i}"
            result_parts.append(f"{part} {name}")
        else:
            result_parts.append(part)

    return "(" + ", ".join(result_parts) + ")"


def make_return_value(ret_type: str) -> str | None:
    """Appropriate return value for a stub function (None for void)."""
    rt = ret_type.strip()
    if rt == "void":
        return None
    if "*" in rt:
        return "(void*) 0"
    if rt == "float":
        return "0.0f"
    if rt == "double":
        return "0.0"
    return "0"


# --- generation ---------------------------------------------------------------


def _guess_function(name: str) -> bool:
    """No extern info: guess from naming conventions whether *name* is a function."""
    return bool(
        re.match(
            r"(func_|FUN_|sub_|cleanup_|check_|compute_|create_|find_|free_|get_|"
            r"search_|setup_|locked_|rand_|crt_|debug_|log_|assert_|game_|stream_|"
            r"mem_|write_|entity_|another_|compress_|classify|RecvGameSavegame|"
            r"FreeCommandBuffer|FreeHeapBlockWithRuntimeLock|WriteFileBufferLocked|"
            r"RandomBelow)",
            name,
        )
    )


def generate_stubs(
    unresolved: Iterable[str],
    extern_info: dict[str, dict[str, typing.Any]],
    specials: dict[str, typing.Any] | None = None,
    footer: str = "",
) -> str:
    """The complete stub TU text for *unresolved* symbol names."""
    specials = specials or {}
    special_entries: dict[str, dict[str, typing.Any]] = specials.get("specials", {})
    bss_arrays: list[list[typing.Any]] = specials.get("bss_arrays", [])
    bss_tail: int = int(specials.get("bss_tail_size", 0) or 0)

    demangled = {demangle_cdecl(sym): sym for sym in unresolved}
    special_list: list[str] = []
    globals_list: list[str] = []
    functions_list: list[str] = []
    string_globals: list[str] = []
    for name in sorted(demangled):
        if name in special_entries:
            special_list.append(name)
            continue
        info = extern_info.get(name)
        if name.startswith("s_"):
            string_globals.append(name)
        elif info and info["is_func"]:
            functions_list.append(name)
        elif info and not info["is_func"]:
            globals_list.append(name)
        elif _guess_function(name):
            functions_list.append(name)
        else:
            globals_list.append(name)

    lines = [
        "/* link_stubs.c - Stub definitions for unresolved external symbols.",
        " * AUTO-GENERATED by rebrew gen-stubs",
        " * These are NOT part of the rebrew matching pipeline - rebrew test",
        " * compiles individual files and does not use this file.",
        " *",
        " * DO NOT edit manually. Regenerate with: rebrew gen-stubs",
        " */",
        "",
        "/* Global variable stubs */",
        "#include <time.h>",
        "",
    ]
    # All stubs are zero-initialized (non-tentative) so MSVC6 emits them into
    # the object's .bss -> PE .data VirtualSize with raw=0, deterministically.
    for name in sorted(globals_list):
        info = extern_info.get(name)
        if info:
            var_type = simplify_type_for_stub(info["type"])
            if info["is_array"]:
                size = int(info["array_size"] or "1", 0)
                lines.append(f"{var_type} {name}[{size}] = {{0}};")
            else:
                lines.append(f"{var_type} {name} = 0;")
        else:
            lines.append(f"int {name} = 0;")
    lines.append("")

    if bss_arrays:
        lines.append("/* Big BSS arrays (non-tentative; see --specials bss_arrays) */")
        for name, size in bss_arrays:
            lines.append(f"char {name}[0x{int(size):x}] = {{0}};")
        lines.append("")

    if bss_tail > 0:
        lines.append("/* BSS tail pad: grows .data VS toward the reference (calibrate-bss) */")
        lines.append(f"unsigned char g_bss_tail[0x{bss_tail:x}] = {{0}};")
        lines.append("")

    if string_globals:
        lines.append("/* String literal globals */")
        for name in sorted(string_globals):
            info = extern_info.get(name)
            decl_size = info["array_size"] if info and info["is_array"] else "1"
            lines.append(f'char {name}[{decl_size}] = "";')
        lines.append("")

    if special_list:
        lines.append("/* Special forwarding stubs */")
        for name in sorted(special_list):
            spec = special_entries[name]
            if spec.get("decl"):
                lines.append(spec["decl"])
                lines.append("")
            lines.append(spec["impl"])
            lines.append("")

    lines.append("/* Function stubs */")
    for name in sorted(functions_list):
        info = extern_info.get(name)
        if info and info["is_func"]:
            ret_type = simplify_type_for_stub(info["type"])
            cc = info["calling_conv"] or "__cdecl"
            params = info["params"] if info["params"] else "(void)"
            params = re.sub(r"struct\s+\w+\*", "void*", params)
            params = re.sub(r"\buint\b", "unsigned int", params)
            params = re.sub(r"\bushort\b", "unsigned short", params)
            params = re.sub(r"\bulong\b", "unsigned long", params)
            params = re.sub(r"\buchar\b", "unsigned char", params)
            params = ensure_param_names(params)
            ret_val = make_return_value(ret_type)
            if ret_val is None:
                lines.append(f"void {cc} {name}{params}")
                lines.append("{")
                lines.append("}")
            else:
                lines.append(f"{ret_type} {cc} {name}{params}")
                lines.append("{")
                lines.append(f"\treturn {ret_val};")
                lines.append("}")
        else:
            lines.append(f"int __cdecl {name}(void)")
            lines.append("{")
            lines.append("\treturn 0;")
            lines.append("}")
        lines.append("")

    if footer:
        lines.append(footer.rstrip("\n"))
        lines.append("")

    return "\n".join(lines) + "\n"


# --- build integration ---------------------------------------------------------


def _run_build(
    root: Path, build_cmd: str, exclude_file: Path | None, cmake_stub_var: str | None
) -> str:
    """Run *build_cmd* in *root*, returning combined output.

    *exclude_file* is renamed away for the duration (``.off``) and restored
    afterwards; *cmake_stub_var* temporarily blanks a ``set(NAME "path")``
    line in ``CMakeLists.txt`` so the stub TU drops out of the link.  Both
    restore in ``finally`` so a failed build never leaves the tree broken.
    """
    cmake_path = root / "CMakeLists.txt"
    original_cmake = cmake_path.read_text(encoding="utf-8") if cmake_path.exists() else None
    patched_cmake: str | None = None
    renamed: tuple[Path, Path] | None = None

    if exclude_file is not None and exclude_file.exists():
        renamed = (exclude_file, exclude_file.with_suffix(".c.off"))
        exclude_file.rename(renamed[1])

    if cmake_stub_var and original_cmake is not None:
        patched = re.sub(
            rf'^(\s*set\(\s*{re.escape(cmake_stub_var)}\s+)"[^"]*"',
            r'\1""',
            original_cmake,
            count=1,
            flags=re.M,
        )
        if patched != original_cmake:
            patched_cmake = patched
            cmake_path.write_text(patched, encoding="utf-8")
        else:
            error_exit(
                f"--cmake-stub-var {cmake_stub_var}: no 'set({cmake_stub_var} \"...\")' "
                f"line found in {cmake_path}"
            )

    try:
        result = subprocess.run(
            build_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=600,
            cwd=root,
        )
        return result.stdout + result.stderr
    finally:
        if patched_cmake is not None and original_cmake is not None:
            cmake_path.write_text(original_cmake, encoding="utf-8")
        if renamed is not None:
            renamed[1].rename(renamed[0])


def _load_specials(path: Path) -> dict[str, typing.Any]:
    with open(path, "rb") as f:
        return tomllib.load(f)


@app.callback(invoke_without_command=True)
def main(
    out: Path = typer.Option(Path("src/link_stubs.c"), "--out", help="Output TU path"),
    source_dir: Path | None = typer.Option(
        None, "--source-dir", help="Directory of reversed sources (extern decl scan)"
    ),
    library_csv: Path | None = typer.Option(
        None, "--library-csv", help="Functions CSV to filter CRT library symbols"
    ),
    build_cmd: str | None = typer.Option(
        None, "--build-cmd", help="Build command whose output is parsed for LNK2001/2019"
    ),
    exclude_file: Path | None = typer.Option(
        None,
        "--exclude-file",
        help="With --build-cmd: temporarily rename this TU out of the build (.off)",
    ),
    cmake_stub_var: str | None = typer.Option(
        None,
        "--cmake-stub-var",
        help="With --build-cmd: blank 'set(VAR \"...\")' in CMakeLists.txt for the build",
    ),
    log: Path | None = typer.Option(
        None, "--log", help="Read linker output from this file instead of building/stdin"
    ),
    specials: Path | None = typer.Option(
        None, "--specials", help="TOML with project specials/bss arrays/bss_tail_size/exceptions"
    ),
    footer: Path | None = typer.Option(
        None, "--footer", help="Text file appended verbatim (e.g. a _fltused marker)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print instead of writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Generate a stub TU for unresolved linker symbols."""
    root = Path.cwd()

    # 1. Collect linker output.
    if build_cmd:
        console.print(f"[dim]building: {build_cmd}[/dim]")
        if exclude_file is not None and not exclude_file.is_absolute():
            exclude_file = root / exclude_file
        linker_output = _run_build(root, build_cmd, exclude_file, cmake_stub_var)
    elif log is not None:
        linker_output = log.read_text(encoding="utf-8", errors="replace")
    else:
        linker_output = sys.stdin.read()
    unresolved = parse_unresolved_symbols(linker_output)
    if not unresolved:
        error_exit(
            "no unresolved symbols found — is the build configured without "
            "the stub TU? (see --build-cmd/--exclude-file/--cmake-stub-var)",
            json_mode=json_output,
        )

    # 2. Filter CRT library symbols (provided by the static lib).
    if library_csv is not None:
        library_symbols = load_library_symbols(library_csv)
        exceptions: set[str] = set()
        if specials is not None:
            exceptions = set(_load_specials(specials).get("keep_stub_exceptions", []))
        stubbed: set[str] = set()
        skipped = 0
        for sym in unresolved:
            demangled = demangle_cdecl(sym)
            if sym in exceptions or demangled in exceptions:
                stubbed.add(sym)
            elif sym in library_symbols or demangled in library_symbols:
                skipped += 1
            else:
                stubbed.add(sym)
        if skipped:
            console.print(f"[dim]skipped {skipped} library symbols (provided by CRT lib)[/dim]")
        unresolved = stubbed
        if not unresolved:
            error_exit("all unresolved symbols are library symbols", json_mode=json_output)

    # 3. Derive stub types from the sources' extern declarations.
    src = (root / source_dir) if source_dir is not None else root / "src"
    if not src.is_dir():
        error_exit(f"source directory not found: {src}", json_mode=json_output)
    extern_info = collect_extern_info(src)

    # 4. Generate.
    spec_dict = _load_specials(specials) if specials is not None else {}
    footer_text = footer.read_text(encoding="utf-8", errors="replace") if footer is not None else ""
    content = generate_stubs(unresolved, extern_info, spec_dict, footer_text)

    if dry_run or json_output:
        if json_output:
            json_print(
                {
                    "unresolved": len(unresolved),
                    "externs": len(extern_info),
                    "generated": content,
                }
            )
        else:
            print(content)
        return

    target = out if out.is_absolute() else root / out
    target.write_text(content, encoding="utf-8")
    console.print(f"[green]gen-stubs:[/] wrote {target} ({len(unresolved)} symbols)")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
