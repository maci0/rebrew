"""Focused CPU-time workloads for source-scan optimization rounds.

Run with ``uv run --frozen python -m tools.bench_source_scans CASE``. Compare
the same runner against two source checkouts via PYTHONPATH; inputs, output
hashes, CPU/wall samples and call counts make the experiment reviewable.
"""

from __future__ import annotations

lazy import argparse
lazy import cProfile
lazy import hashlib
lazy import json
lazy import tempfile
lazy from collections.abc import Callable
lazy from dataclasses import asdict, is_dataclass
lazy from pathlib import Path
lazy from typing import Any

lazy from tools.bench_hotpaths import measure

CASES = (
    "parse_cache",
    "signature_walk",
    "mask_conventions",
    "variable_text",
    "anchor_comments",
    "data_bindings",
    "prototype_lines",
    "variable_lines",
    "asm_tokens",
    "pointer_names",
    "include_scan",
    "struct_scan",
    "named_string_reuse",
)


def workload(case: str, root: Path) -> Callable[[], Any]:
    """Prepare deterministic inputs outside the timed region."""
    from rebrew import c_parser
    from rebrew.metadata.anchors import parse_address_anchors
    from rebrew.metadata.bindings import source_bindings
    from rebrew.metadata.data import save_data_metadata
    from rebrew.metadata.functions import save_metadata

    functions = "".join(f"int f{i}(int x) {{ return x + {i}; }}\n" for i in range(500))
    if case == "parse_cache":
        raw = functions.encode()
        return lambda: [
            c_parser.parse_c_source(src)[0].root_node.named_child_count
            for _ in range(200)
            for src in (functions, raw)
        ]
    if case == "signature_walk":
        source = "".join(f"int g{i}[4] = {{1, 2, 3, 4}};\n" for i in range(1000)) + functions
        return lambda: [c_parser.function_signatures(source) for _ in range(5)]
    if case == "mask_conventions":
        sources = (functions, functions.replace("int f", "int __stdcall f"))
        return lambda: [c_parser.mask_msvc_syntax(src) for _ in range(10) for src in sources]
    if case == "variable_text":
        locals_ = "".join(f'int v{i} = {i}; const char *s{i} = "hello";\n' for i in range(20))
        source = "".join(f"int g{i}; void f{i}(void) {{ {locals_} }}\n" for i in range(100))
        return lambda: c_parser.find_extern_variables(source, include_definitions=True)
    if case == "anchor_comments":
        source = "".join(
            f"/* ADDRESS: S 0x{0x1000 + i * 16:x} */\n/* {'comment ' * 60}\n */\n"
            f'int f{i}(void) {{ const char *s = "/* not a comment */"; return {i}; }}\n'
            for i in range(200)
        )
        return lambda: parse_address_anchors(source)
    if case == "data_bindings":
        source = "".join(f"/* ADDRESS: S 0x{0x8000 + i * 4:x} */\nint g{i};\n" for i in range(1000))
        save_data_metadata(
            root,
            {
                ("S", 0x8000 + i * 4): {"name": f"g{i}", "file": "many.c", "size": 4}
                for i in range(1000)
            },
            expected_hash=None,
        )
        return lambda: source_bindings(source, root / "many.c", "S", root, root)
    if case == "prototype_lines":
        save_metadata(
            root,
            {
                ("S", 0x1000 + i * 16): {"name": f"f{i}", "file": "many.c", "size": 8}
                for i in range(500)
            },
        )
        return lambda: source_bindings(functions, root / "many.c", "S", root, root)
    if case == "variable_lines":
        source = "".join(f"/* {'padding ' * 10} */\nextern int g{i};\n" for i in range(3000))
        return lambda: c_parser.find_extern_variables(source)
    if case == "asm_tokens":
        source = "".join(
            f"int f{i}(void) {{ __asm {{ mov eax, g\n add eax, 1\n }} return 0; }}\n"
            for i in range(300)
        )
        return lambda: c_parser.mask_msvc_syntax(source)
    if case == "pointer_names":
        params = ", ".join(f"int p{i}" for i in range(20))
        source = "".join(f"extern int (*callback{i})({params});\n" for i in range(300))
        return lambda: c_parser.find_extern_variables(source)
    if case == "include_scan":
        from rebrew.source_paths import rebase_includes

        (root / "local.h").write_text("int provider;\n")
        source = '#include "local.h"\nint table[] = {' + ",".join(map(str, range(5000))) + "};\n"
        return lambda: rebase_includes(source, root, root / "out")
    if case == "struct_scan":
        from rebrew.type_metadata import struct_definition_names

        source = "typedef struct ITEM { int value; } Item;\nint table[] = {"
        source += ",".join(map(str, range(5000))) + "};\n"
        return lambda: sorted(struct_definition_names(source))
    if case == "named_string_reuse":
        from rebrew.inline_strings import inline_named_strings

        owner, other = root / "owner.c", root / "other.c"
        names = [f"s_value_{i}" for i in range(30)]
        owner.write_text(
            "".join(f'char {name}[] = "value";\n' for name in names)
            + "int f(void) { return "
            + "+".join(name + "[0]" for name in names)
            + "; }\n"
        )
        other.write_text(
            "/* "
            + " ".join(names)
            + " */\n"
            + "".join(f"int f{i}(void) {{ return {i}; }}\n" for i in range(200))
        )
        return lambda: inline_named_strings(owner, "s_", [other], True)
    raise ValueError(case)


def _serialize(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    raise TypeError(type(value).__name__)


def main() -> None:
    """Emit one report with medians, raw samples, output identity and profiled work."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=CASES)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        run = workload(args.case, Path(directory))
        output = json.dumps(run(), sort_keys=True, default=_serialize).encode()
        timing = measure(run, repeat=9)
        profile = cProfile.Profile()
        profile.runcall(run)
        calls: dict[str, int] = {}
        for entry in profile.getstats():
            code = entry.code
            name = (
                code if isinstance(code, str) else f"{Path(code.co_filename).name}:{code.co_name}"
            )
            calls[name] = calls.get(name, 0) + entry.callcount
        print(
            json.dumps(
                {
                    "case": args.case,
                    "output_sha256": hashlib.sha256(output).hexdigest(),
                    "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    **timing,
                    "calls": calls,
                },
                indent=2,
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    main()
