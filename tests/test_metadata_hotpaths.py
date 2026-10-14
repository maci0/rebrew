"""Deterministic work budgets for repeated metadata-backed source scans."""

from pathlib import Path
from typing import Any

import pytest

from rebrew.metadata import bindings, source_provenance
from rebrew.metadata.data import save_data_metadata
from rebrew.metadata.functions import record_function_identity, save_metadata
from rebrew.metadata.source_provenance import (
    SourceFilePurpose,
    load_source_files,
    load_source_provenance,
    replace_source_metadata,
    set_source_file,
)
from rebrew.utils import load_tomllib, read_source_text


class TestBindingWork:
    def test_pre_read_source_does_not_reopen_the_file_or_clone_the_data_store(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        file = tmp_path / "one.c"
        file.write_text("int f(int x) { return x; }\n")
        record_function_identity(
            tmp_path, module="S", va=0x1000, file="one.c", name="f", kind="FUNCTION", size=8
        )
        save_data_metadata(
            tmp_path,
            {
                ("S", 0x8000 + i * 4): {"name": f"g{i}", "file": "pool.c", "size": 4}
                for i in range(1000)
            },
            expected_hash=None,
        )

        def unexpected(*args: Any, **kwargs: Any) -> Any:
            pytest.fail("pre-read source was reopened or the full data map was copied")

        monkeypatch.setattr(bindings, "read_source_text", unexpected)
        monkeypatch.setattr("rebrew.metadata.data.load_data_metadata", unexpected)
        found = bindings.source_bindings(
            "int f(float x) { return 0; }\n", file, None, None, tmp_path
        )
        assert len(found) == 1
        assert found[0].prototype == "int f(float x)"

    def test_read_source_reads_once(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        file = tmp_path / "one.c"
        file.write_text("int f(void) { return 0; }\n")
        record_function_identity(
            tmp_path, module="S", va=0x1000, file="one.c", name="f", kind="FUNCTION", size=8
        )
        reads = []
        real = read_source_text

        def read(path: Path) -> tuple[str, str]:
            reads.append(path)
            return real(path)

        monkeypatch.setattr(bindings, "read_source_text", read)
        assert bindings.read_source_bindings(file, metadata_dir=tmp_path)[0].name == "f"
        assert reads == [file]

    def test_unbound_anchors_load_the_function_map_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.functions import load_metadata

        file = tmp_path / "many.c"
        text = "".join(
            f"/* ADDRESS: S 0x{0x1000 + i * 16:x} */\nint f{i}(void) {{return 0;}}\n"
            for i in range(100)
        )
        file.write_text(text)
        save_metadata(tmp_path, {("S", 0x1000 + i * 16): {"size": 8} for i in range(100)})
        reads = []

        def read(*args: Any, **kwargs: Any) -> Any:
            reads.append(1)
            return load_metadata(*args, **kwargs)

        monkeypatch.setattr("rebrew.metadata.functions.load_metadata", read)
        assert len(bindings.read_source_bindings(file, metadata_dir=tmp_path)) == 100
        assert len(reads) == 2  # File index plus one shared address lookup map.


class TestSourcePurposeWork:
    def test_both_views_share_one_parse_until_an_atomic_edit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        replace_source_metadata(
            tmp_path, [], [SourceFilePurpose("one.c", "S", "first")], expected_hash=None
        )
        reads = []
        real = load_tomllib

        def read(path: Path) -> Any:
            reads.append(path)
            return real(path)

        monkeypatch.setattr(source_provenance, "load_tomllib", read)
        original = load_source_files(tmp_path)
        for _ in range(5):
            assert load_source_files(tmp_path) == original
            assert load_source_provenance(tmp_path) == ()
        assert len(reads) == 1
        set_source_file(tmp_path, "one.c", "S", "second")
        assert load_source_files(tmp_path)[0].purpose == "second"
        assert original[0].purpose == "first"
        assert len(reads) == 2
        path = tmp_path / "rebrew-source.toml"
        path.unlink()
        assert load_source_files(tmp_path) == ()
        path.write_text("format = 1\n[files]\n[definitions]\n")
        with pytest.raises(ValueError, match="format = 2"):
            load_source_files(tmp_path)


class TestCommentScanWork:
    def test_ignored_function_bodies_are_not_walked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from types import SimpleNamespace

        from rebrew.c_parser import parse_c_source
        from rebrew.metadata.anchors import metadata_comments

        source = "/* NOTE: global */\nint f(void) { /* NOTE: local */ return 0; }\n"
        tree, raw = parse_c_source(source)

        class Node:
            def __init__(self, node: Any) -> None:
                self.node = node

            def __getattr__(self, name: str) -> Any:
                return getattr(self.node, name)

            @property
            def named_children(self) -> list[Any]:
                assert self.node.type != "function_definition", "walked an ignored function body"
                return [Node(child) for child in self.node.named_children]

        monkeypatch.setattr(
            "rebrew.metadata.anchors.parse_c_source",
            lambda text: (SimpleNamespace(root_node=Node(tree.root_node)), raw),
        )
        assert metadata_comments(source) == [(1, "NOTE")]
