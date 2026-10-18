"""Correctness and work budgets for the additional source-scan experiments."""

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew import c_parser
from rebrew.metadata.anchors import parse_address_anchors
from rebrew.metadata.bindings import SourceBinding, source_bindings
from rebrew.metadata.data import save_data_metadata
from rebrew.metadata.functions import save_metadata
from tools.bench_source_scans import CASES, workload


class TestParseCache:
    def test_exact_content_keys_reuse_str_bytes_and_still_evict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(c_parser._tls, "parse_memo", None, raising=False)
        monkeypatch.setattr(c_parser, "_PARSE_MEMO_MAX", 2)
        text = "/* café */ int f(void) { return 1; }\n"
        first, raw = c_parser.parse_c_source(text)
        assert c_parser.parse_c_source(bytes(bytearray(raw)))[0] is first
        second, _ = c_parser.parse_c_source(text.replace("1", "2"))
        assert second is not first
        c_parser.parse_c_source("int third;")
        assert len(c_parser._tls.parse_memo) == 2
        assert c_parser.parse_c_source(text)[0] is not first

    def test_surrogateescape_bytes_keep_their_offsets(self) -> None:
        raw = b"/* caf\xe9 */ int f(void) { return 1; }\n"
        tree, result = c_parser.parse_c_source(raw.decode("utf-8", "surrogateescape"))
        assert result == raw
        assert c_parser.parse_c_source(raw)[0] is tree


class TestTraversalBudgets:
    def test_signature_inventory_skips_punctuation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        source = "#ifdef S\nint g[3] = {1, 2, 3};\nint f(int x) { return x; }\n#endif\n"
        tree, raw = c_parser.parse_c_source(source)

        class Node:
            def __init__(self, node: Any) -> None:
                self.node = node

            def __getattr__(self, name: str) -> Any:
                return getattr(self.node, name)

            @property
            def named_children(self) -> list[Any]:
                return [Node(child) for child in self.node.named_children]

            @property
            def children(self) -> Any:
                pytest.fail("signature traversal requested punctuation nodes")

        monkeypatch.setattr(
            c_parser,
            "parse_c_source",
            lambda _: (SimpleNamespace(root_node=Node(tree.root_node)), raw),
        )
        assert c_parser.function_signatures(source) == {"f": "int f(int x)"}

    def test_declaration_scan_does_not_decode_unused_initializers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        read = c_parser.node_text
        initializers = []

        def counted(node: Any, raw: bytes) -> str:
            assert node.type not in {";", "number_literal"}
            if node.type == "init_declarator":
                initializers.append(read(node, raw))
            return read(node, raw)

        monkeypatch.setattr(c_parser, "node_text", counted)
        found = c_parser.find_extern_variables(
            "int g = 1; void f(void) { int local = 2; }", include_definitions=True
        )
        assert [(v.name, v.type_str) for v in found] == [("g", "int")]
        assert initializers == ["g = 1"]

    def test_data_lookup_work_is_linear_and_new_aliases_are_reused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        count = 100
        save_data_metadata(
            tmp_path,
            {
                ("S", 0x8000 + i * 4): {"name": f"g{i}", "file": "many.c", "size": 4}
                for i in range(count)
            },
            expected_hash=None,
        )
        descriptor = SourceBinding.is_data
        reads = 0

        def is_data(row: SourceBinding) -> bool:
            nonlocal reads
            reads += 1
            return bool(descriptor.__get__(row, SourceBinding))

        monkeypatch.setattr(SourceBinding, "is_data", property(is_data))
        text = "".join(
            f"/* ADDRESS: S 0x{0x8000 + i * 4:x} */\nextern int g{i};\n" for i in range(count)
        )
        result = source_bindings(text, tmp_path / "many.c", None, tmp_path, tmp_path)
        assert len(result) == count
        assert reads <= 3 * count
        # A different name at the same address is a separate view; a repeated
        # anchor for that view reuses the newly appended binding.
        text += "/* ADDRESS: S 0x8000 */\nextern int view;\n" * 2
        result = source_bindings(text, tmp_path / "many.c", None, tmp_path, tmp_path)
        assert [(v.name, v.line) for v in result if v.va == 0x8000] == [("g0", 1), ("view", 203)]


class TestSourceCoordinates:
    def test_comment_translation_preserves_utf8_crlf_and_line_binding(self) -> None:
        source = (
            "/* ADDRESS: S 0x1000 */\r\n/* café\r\n"
            + "long comment " * 100
            + " */\r\nint f(void) { return 0; }\r\n"
        )
        (anchor,) = parse_address_anchors(source)
        assert (anchor.name, anchor.line, anchor.definition_line) == ("f", 1, 4)

    def test_normalized_assembly_keeps_declaration_and_filter_lines(self) -> None:
        source = (
            "/* café */\r\nvoid first(void) { __asm {\r\n mov eax, 1\r\n } }\r\n"
            "extern int\r\n global;\r\nvoid second(void) { extern int local; }\r\n"
        )
        visited: list[int] = []

        def select(line: int) -> bool:
            visited.append(line)
            return line == 7

        found = c_parser.find_extern_variables(source, function_filter=select)
        assert [(v.name, v.line, v.end_line) for v in found] == [("global", 5, 6), ("local", 7, 7)]
        assert visited == [2, 7]

    def test_assembly_tokens_keep_strings_comments_and_gnu_asm(self) -> None:
        source = (
            '/* __asm é */\nvoid f(void) { const char *s = "_asm"; '
            '__asm("nop"); __asm { mov eax, 1\n } }\n'
        )
        masked = c_parser.mask_msvc_syntax(source)
        assert "/* __asm é */" in masked
        assert '"_asm"' in masked
        assert '__asm("nop")' in masked
        assert "mov eax" not in masked
        assert len(masked.encode()) == len(source.encode())

    def test_callback_names_do_not_remove_nested_parameter_types(self) -> None:
        found = c_parser.find_extern_variables(
            "extern int (*callback)(int callback, int (*nested)(int value));"
        )
        assert len(found) == 1
        assert found[0].name == "callback"
        assert found[0].type_str == "int (*)(int, int (*)(int))"


class TestBenchmarkInputs:
    @pytest.mark.parametrize("case", CASES)
    def test_workload_runs_and_returns_results(self, case: str, tmp_path: Path) -> None:
        result = workload(case, tmp_path)()
        assert result


class TestMetadataInventory:
    @pytest.mark.parametrize("count", [1, 32])
    def test_status_and_catalog_skip_parsing_registered_sources(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, count: int
    ) -> None:
        from rebrew.catalog import scan_reversed_dir
        from rebrew.config import load_config
        from rebrew.metadata import anchors, functions
        from rebrew.status import collect_status

        (tmp_path / "src").mkdir()
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\nname = "scan"\ndefault_target = "game"\n'
            '[targets.game]\nbinary = "game.exe"\nformat = "pe"\n'
            'arch = "x86_32"\nmodule = "S"\nreversed_dir = "src"\n'
        )
        cfg = load_config(tmp_path)
        rows = {}
        for i in range(count):
            # The first file has a dangling anchor. Its durable identity and
            # verdict must still appear in inventory views.
            (tmp_path / "src" / f"f{i}.c").write_text(
                "/* ADDRESS: S 0x1000 */\n" if i == 0 else f"int f{i}(void) {{ return {i}; }}"
            )
            rows[("S", 0x1000 + i * 16)] = {
                "file": f"src/f{i}.c",
                "name": f"f{i}",
                "symbol": f"_f{i}",
                "kind": "FUNCTION",
                "size": 8,
                "status": "EXACT",
            }
        (tmp_path / "src" / "library_runtime.h").write_text("int runtime(void);\n")
        for module in ("S", "OTHER"):
            rows[(module, 0x9000)] = {
                "file": "src/library_runtime.h",
                "name": f"runtime_{module}",
                "symbol": f"_runtime_{module}",
                "kind": "LIBRARY",
                "size": 8,
            }
        save_metadata(tmp_path, rows)
        loads = 0
        load = functions.load_metadata

        def counted_load(*args: Any, **kwargs: Any) -> Any:
            nonlocal loads
            loads += 1
            return load(*args, **kwargs)

        def no_parse(*args: Any, **kwargs: Any) -> Any:
            pytest.fail("inventory parsed a metadata-backed source")

        monkeypatch.setattr(functions, "load_metadata", counted_load)
        monkeypatch.setattr(c_parser, "parse_c_source", no_parse)
        monkeypatch.setattr(anchors, "parse_c_source", no_parse)
        report = collect_status(cfg)
        assert report.load_error == ""
        assert report.total_functions == report.covered_functions == count
        assert report.status_counts == {"EXACT": count}
        assert report.library_identified == 1
        assert loads == 1
        loads = 0
        entries = scan_reversed_dir(cfg.reversed_dir, cfg, inventory_only=True)
        assert sorted((e.va, e.name, e.symbol, e.size, e.status) for e in entries) == [
            (0x1000 + i * 16, f"f{i}", f"_f{i}", 8, "EXACT") for i in range(count)
        ] + [(0x9000, "runtime_S", "_runtime_S", 8, "")]
        assert loads == 1

    def test_inventory_keeps_source_only_anchors_and_filters_exact_paths_and_modules(
        self, tmp_path: Path
    ) -> None:
        from rebrew.metadata.bindings import iter_source_bindings

        (tmp_path / "left").mkdir()
        (tmp_path / "right").mkdir()
        registered = tmp_path / "left" / "same.c"
        source_only = tmp_path / "right" / "same.c"
        foreign = tmp_path / "foreign.c"
        registered.write_text("/* ADDRESS: S 0x1000 */\n")
        foreign.write_text("/* ADDRESS: OTHER 0x2000 */\n")
        source_only.write_text(
            "/* ADDRESS: S 0x3000 */\nint own(void) { return 1; }\n"
            "/* ADDRESS: OTHER 0x4000 */\nint other(void) { return 2; }\n"
        )
        save_metadata(
            tmp_path,
            {
                ("S", 0x1000): {"file": "left/same.c", "name": "stored", "symbol": "_stored"},
                ("OTHER", 0x2000): {"file": "foreign.c", "name": "foreign"},
            },
        )
        save_data_metadata(
            tmp_path,
            {
                ("S", 0x5000): {"file": "left/same.c", "name": "global", "size": 4},
                ("OTHER", 0x6000): {"file": "left/same.c", "name": "foreign_global"},
            },
            expected_hash=None,
        )
        found = iter_source_bindings(
            [registered, source_only, foreign],
            target="S",
            metadata_dir=tmp_path,
            inventory_only=True,
        )
        assert [(path, [(a.va, a.name) for a in rows]) for path, rows in found] == [
            (registered, [(0x1000, "stored"), (0x5000, "global")]),
            (source_only, [(0x3000, "own")]),
        ]

    def test_default_batch_still_reads_prototypes_and_rejects_bad_anchors(
        self, tmp_path: Path
    ) -> None:
        from rebrew.metadata.bindings import iter_source_bindings, read_source_bindings

        source = tmp_path / "f.c"
        source.write_text("int __stdcall f(int n) { return n; }\n")
        save_metadata(tmp_path, {("S", 0x1000): {"file": "f.c", "name": "f", "symbol": "_f@4"}})
        ((_, [entry]),) = iter_source_bindings([source], target="S", metadata_dir=tmp_path)
        assert entry.prototype == "int __stdcall f(int n)"
        source.write_text("/* ADDRESS: S 0x1000 */\n")
        with pytest.raises(ValueError):
            read_source_bindings(source, metadata_dir=tmp_path)
