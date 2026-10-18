"""Target isolation and definition ownership in generated linker anchors."""

from pathlib import Path

from rebrew.config import load_config
from rebrew.link_anchors import anchor_symbols
from rebrew.metadata.functions import record_function_identity


class TestLinkAnchors:
    def test_native_symbols_target_order_and_explicit_storage(self, tmp_path: Path) -> None:
        (tmp_path / "rebrew-project.toml").write_text("""[project]
default_target = "server"
[targets.server]
binary = "server.dll"
reversed_dir = "src"
module = "SERVER"
[targets.client]
binary = "client.exe"
reversed_dir = "src"
module = "CLIENT"
""")
        source = tmp_path / "src"
        source.mkdir()
        for va, name, module, kind in [
            (0x10002000, "second", "SERVER", "FUNCTION"),
            (0x10001000, "first", "SERVER", "FUNCTION"),
            (0x10003000, "crt", "SERVER", "LIBRARY"),
            (0x401000, "client", "CLIENT", "FUNCTION"),
        ]:
            path = source / f"{name}.c"
            path.write_text(f"void {name}(void) {{}}\n")
            record_function_identity(
                tmp_path,
                va=va,
                module=module,
                file=str(path.relative_to(tmp_path)),
                symbol=f"_{name}@4",
                name=name,
                kind=kind,
            )
        data = source / "constants.c"
        data.write_text(
            "extern int declared; static int private_value = 2;\nconst int exposed = 3; extern int allocated = 4;\n"
        )
        report = anchor_symbols(load_config(tmp_path, target="server"), [data], ["_mark"], "_")
        assert report["symbols"] == ["_first@4", "_second@4", "_allocated", "_exposed", "_mark"]
        assert report["functions"] == 2
