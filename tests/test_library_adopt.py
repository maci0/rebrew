"""`library adopt` records a proved stock-archive identity over a FUNCTION claim."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bin_util import make_coff_obj, make_lib_archive, make_pe
from typer.testing import CliRunner

from rebrew.app.main import app as umbrella
from rebrew.metadata.functions import get_entry, record_function_identity, update_source_status

CODE = bytes(range(0x10, 0x30))
VA = 0x401000


def _project(tmp_path: Path, members=None):
    pe = tmp_path / "target.exe"
    pe.write_bytes(make_pe(CODE, image_base=0x400000, text_va=0x1000))
    lib = tmp_path / "mylib.lib"
    if members is None:
        members = [("body.obj", make_coff_obj(CODE, func_symbol="_mylibfn"))]
    lib.write_bytes(make_lib_archive(members))
    src = tmp_path / "src"
    src.mkdir()
    (src / "f.c").write_text(f"/* ADDRESS: SERVER 0x{VA:x} */\nint f(void) {{ return 0; }}\n")
    record_function_identity(
        tmp_path,
        module="SERVER",
        va=VA,
        file="src/f.c",
        name="f",
        symbol="_f",
        kind="FUNCTION",
        size=len(CODE),
    )
    update_source_status(tmp_path, "STUB", module="SERVER", va=VA)
    cfg = SimpleNamespace(
        root=tmp_path,
        reversed_dir=src,
        metadata_dir=tmp_path,
        module="SERVER",
        target_name="SERVER",
        target_binary=pe,
        compiler_profile="msvc-6.0",
        shared_dir=None,
        source_ext=".c",
    )
    return cfg, lib


def _adopt(cfg, lib, *extra: str):
    with (
        patch("rebrew.library.require_config", return_value=cfg),
        patch("rebrew.lib_match.external_archive_args", return_value=([lib], [])),
    ):
        return CliRunner().invoke(
            umbrella,
            ["library", "adopt", f"0x{VA:x}", "--reason", "unique stock body", *extra],
        )


class TestLibraryAdopt:
    def test_dry_run_writes_nothing_and_reports_digest(self, tmp_path: Path) -> None:
        cfg, lib = _project(tmp_path)
        result = _adopt(cfg, lib, "--dry-run", "--json")
        assert result.exit_code == 0, result.output
        import json as json_mod

        payload = json_mod.loads(result.output)
        assert payload["action"] == "rebind"
        assert payload["symbol"] == "_mylibfn"
        assert len(payload["input_digest"]) == 64
        assert not (cfg.reversed_dir / "library_mylib.h").exists()
        assert get_entry(cfg.metadata_dir, VA, "SERVER")["kind"] == "FUNCTION"

    def test_apply_records_library_identity_and_header(self, tmp_path: Path) -> None:
        cfg, lib = _project(tmp_path)
        preview = _adopt(cfg, lib, "--dry-run", "--json")
        import json as json_mod

        digest = json_mod.loads(preview.output)["input_digest"]
        result = _adopt(cfg, lib, "--expected-digest", digest, "--json")
        assert result.exit_code == 0, result.output
        row = get_entry(cfg.metadata_dir, VA, "SERVER")
        assert row["kind"] == "LIBRARY"
        assert row["symbol"] == "_mylibfn"
        assert row["name"] == "mylibfn"
        assert row["file"] == "src/library_mylib.h"
        assert "status" not in row
        assert row["binding_history"][-1]["action"] == "rebind"
        assert row["binding_history"][-1]["previous"]["kind"] == "FUNCTION"
        header = cfg.reversed_dir / "library_mylib.h"
        assert header.is_file()
        assert "Library function identities" in header.read_text()

    def test_adoption_drops_the_previous_byte_verdict(self, tmp_path: Path) -> None:
        # The verdict describes the retired claim's compile.  Leaving it on the
        # row let status readers fall back to it and report a byte result for
        # source nobody compiles any more.
        from rebrew.metadata.functions import set_fields_batch

        cfg, lib = _project(tmp_path)
        set_fields_batch(
            tmp_path,
            [
                {
                    "module": "SERVER",
                    "va": VA,
                    "fields": {
                        "verification": {
                            "status": "EXTRACT_ERROR",
                            "source_hash": "0" * 64,
                            "reference_hash": "1" * 64,
                            "reference_size": str(len(CODE)),
                            "headers_hash": "2" * 64,
                            "compiler_hash": "3" * 64,
                            "toolchain": "(default)",
                            "cflags": "/O2 /Gd",
                            "context_hash": "",
                            "defines": "[]",
                            "input_hash": "4" * 64,
                            "writer": "verify",
                        }
                    },
                }
            ],
        )
        assert (
            get_entry(cfg.metadata_dir, VA, "SERVER")["verification"]["status"] == "EXTRACT_ERROR"
        )
        result = _adopt(cfg, lib, "--json")
        assert result.exit_code == 0, result.output
        row = get_entry(cfg.metadata_dir, VA, "SERVER")
        assert row["kind"] == "LIBRARY"
        assert "verification" not in row

    def test_wrong_digest_is_refused(self, tmp_path: Path) -> None:
        cfg, lib = _project(tmp_path)
        before = get_entry(cfg.metadata_dir, VA, "SERVER")
        result = _adopt(cfg, lib, "--expected-digest", "0" * 64, "--json")
        assert result.exit_code == 2
        assert get_entry(cfg.metadata_dir, VA, "SERVER") == before

    def test_already_library_is_refused(self, tmp_path: Path) -> None:
        cfg, lib = _project(tmp_path)
        get_entry(cfg.metadata_dir, VA, "SERVER")
        (cfg.reversed_dir / "library_mylib.h").write_text("/* identities live in metadata */\n")
        from rebrew.metadata.binding_history import change_source_binding

        change_source_binding(
            cfg.metadata_dir,
            "SERVER",
            VA,
            reason="already library",
            identity={
                "file": "src/library_mylib.h",
                "symbol": "_mylibfn",
                "name": "mylibfn",
                "kind": "LIBRARY",
            },
            project_root=cfg.root,
        )
        result = _adopt(cfg, lib, "--json")
        assert result.exit_code == 2
        assert "already" in result.output

    def test_ambiguous_match_is_refused(self, tmp_path: Path) -> None:
        cfg, lib = _project(
            tmp_path,
            members=[
                ("a.obj", make_coff_obj(CODE, func_symbol="_one")),
                ("b.obj", make_coff_obj(CODE, func_symbol="_two")),
            ],
        )
        before = get_entry(cfg.metadata_dir, VA, "SERVER")
        result = _adopt(cfg, lib, "--json")
        assert result.exit_code == 2
        assert "ambiguous" in result.output
        assert get_entry(cfg.metadata_dir, VA, "SERVER") == before

    def test_symbol_selects_one_of_several_byte_identical_aliases(self, tmp_path: Path) -> None:
        # Two archive members carry the same bytes under different symbols; the
        # reviewed symbol is what the identity records, so --symbol must resolve
        # the ambiguity instead of forcing a re-pin of the project.
        cfg, lib = _project(
            tmp_path,
            members=[
                ("a.obj", make_coff_obj(CODE, func_symbol="_one")),
                ("b.obj", make_coff_obj(CODE, func_symbol="_two")),
            ],
        )
        result = _adopt(cfg, lib, "--symbol", "_two", "--json")
        assert result.exit_code == 0, result.output
        row = get_entry(cfg.metadata_dir, VA, "SERVER")
        assert row["kind"] == "LIBRARY"
        assert row["symbol"] == "_two"

    def test_symbol_that_names_no_candidate_is_refused(self, tmp_path: Path) -> None:
        cfg, lib = _project(
            tmp_path,
            members=[
                ("a.obj", make_coff_obj(CODE, func_symbol="_one")),
                ("b.obj", make_coff_obj(CODE, func_symbol="_two")),
            ],
        )
        before = get_entry(cfg.metadata_dir, VA, "SERVER")
        result = _adopt(cfg, lib, "--symbol", "_three", "--json")
        assert result.exit_code == 2
        assert "no candidate named" in result.output
        assert get_entry(cfg.metadata_dir, VA, "SERVER") == before

    def test_no_match_is_refused(self, tmp_path: Path) -> None:
        cfg, lib = _project(tmp_path)
        cfg.target_binary.write_bytes(
            make_pe(bytes(range(0x80, 0xA0)), image_base=0x400000, text_va=0x1000)
        )
        before = get_entry(cfg.metadata_dir, VA, "SERVER")
        result = _adopt(cfg, lib, "--json")
        assert result.exit_code == 2
        assert "does not match" in result.output
        assert get_entry(cfg.metadata_dir, VA, "SERVER") == before

    def test_vendored_object_match_is_refused(self, tmp_path: Path) -> None:
        cfg, _lib = _project(tmp_path)
        with (
            patch("rebrew.library.require_config", return_value=cfg),
            patch(
                "rebrew.lib_match.project_match_index",
                return_value=({"_x": [("x.c.obj", CODE, set())]}, [], []),
            ),
        ):
            result = CliRunner().invoke(
                umbrella,
                ["library", "adopt", f"0x{VA:x}", "--reason", "vendored", "--json"],
            )
        assert result.exit_code == 2
        assert "bind-source" in result.output
        assert get_entry(cfg.metadata_dir, VA, "SERVER")["kind"] == "FUNCTION"


def _bare_project(tmp_path: Path):
    """Same PE/archive as _project, but no metadata row and an inventory entry."""
    import json

    pe = tmp_path / "target.exe"
    pe.write_bytes(make_pe(CODE, image_base=0x400000, text_va=0x1000))
    lib = tmp_path / "mylib.lib"
    lib.write_bytes(make_lib_archive([("body.obj", make_coff_obj(CODE, func_symbol="_mylibfn"))]))
    src = tmp_path / "src"
    src.mkdir()
    inventory = src / "function_structure.json"
    inventory.write_text(json.dumps([{"va": VA, "size": len(CODE), "name": "f"}]), encoding="utf-8")
    return SimpleNamespace(
        root=tmp_path,
        reversed_dir=src,
        metadata_dir=tmp_path,
        module="SERVER",
        target_name="SERVER",
        target_binary=pe,
        compiler_profile="msvc-6.0",
        shared_dir=None,
        source_ext=".c",
        inventory_file=inventory,
    )


class TestLibraryAdoptNoClaim:
    """Adopt works when the VA has no metadata row; uniqueness is the gate."""

    def test_dry_run_reports_without_writing(self, tmp_path: Path) -> None:
        cfg = _bare_project(tmp_path)
        lib = tmp_path / "mylib.lib"
        result = _adopt(cfg, lib, "--dry-run", "--json")
        assert result.exit_code == 0, result.output
        import json as json_mod

        payload = json_mod.loads(result.output)
        assert payload["symbol"] == "_mylibfn"
        assert payload["action"] == "record"
        assert not get_entry(cfg.metadata_dir, VA, "SERVER")
        assert not (cfg.reversed_dir / "library_mylib.h").exists()

    def test_apply_records_library_row_without_history(self, tmp_path: Path) -> None:
        cfg = _bare_project(tmp_path)
        lib = tmp_path / "mylib.lib"
        result = _adopt(cfg, lib, "--json")
        assert result.exit_code == 0, result.output
        row = get_entry(cfg.metadata_dir, VA, "SERVER")
        assert row is not None
        assert row["kind"] == "LIBRARY"
        assert row["symbol"] == "_mylibfn"
        assert row["file"] == "src/library_mylib.h"
        assert "binding_history" not in row
        assert "status" not in row
        assert (cfg.reversed_dir / "library_mylib.h").is_file()

    def test_concurrent_claim_is_not_overwritten(self, tmp_path: Path) -> None:
        cfg = _bare_project(tmp_path)

        def claim(*_args: object) -> None:
            record_function_identity(
                cfg.metadata_dir,
                module="SERVER",
                va=VA,
                file="src/claimed.c",
                name="claimed",
                symbol="_claimed",
                kind="FUNCTION",
            )

        with patch("rebrew.identify_library.prepare_library_header", side_effect=claim):
            result = _adopt(cfg, tmp_path / "mylib.lib", "--json")
        assert result.exit_code == 2, result.output
        assert "inputs changed" in result.output
        assert get_entry(cfg.metadata_dir, VA, "SERVER")["file"] == "src/claimed.c"

    def test_inventory_extent_change_invalidates_the_preview(self, tmp_path: Path) -> None:
        import json

        cfg = _bare_project(tmp_path)
        lib = tmp_path / "mylib.lib"
        preview = _adopt(cfg, lib, "--dry-run", "--json")
        assert preview.exit_code == 0, preview.output
        digest = json.loads(preview.output)["input_digest"]
        cfg.inventory_file.write_text(json.dumps([{"va": VA, "size": len(CODE) - 1}]))
        result = _adopt(cfg, lib, "--expected-digest", digest, "--json")
        assert result.exit_code == 2, result.output
        assert not get_entry(cfg.metadata_dir, VA, "SERVER")
        assert not (cfg.reversed_dir / "library_mylib.h").exists()

    def test_address_only_row_preserves_historical_verdict(self, tmp_path: Path) -> None:
        from rebrew.metadata.functions import update_field

        cfg = _bare_project(tmp_path)
        update_field(cfg.metadata_dir, VA, "size", len(CODE), module="SERVER")
        update_source_status(cfg.metadata_dir, "EXACT", module="SERVER", va=VA)
        result = _adopt(cfg, tmp_path / "mylib.lib", "--json")
        assert result.exit_code == 0, result.output
        row = get_entry(cfg.metadata_dir, VA, "SERVER")
        assert row["kind"] == "LIBRARY"
        assert "status" not in row
        assert row["binding_history"][-1]["previous"]["status"] == "EXACT"
        assert row["size"] == len(CODE)


class TestLibraryAdoptSymbolNames:
    """A unique archive match with no C-identifier name still gets a row."""

    def test_mangled_symbol_gets_a_safe_display_name(self, tmp_path: Path) -> None:
        from bin_util import make_coff_obj, make_lib_archive, make_pe

        pe = tmp_path / "target.exe"
        pe.write_bytes(make_pe(CODE, image_base=0x400000, text_va=0x1000))
        lib = tmp_path / "dx.lib"
        lib.write_bytes(
            make_lib_archive([("body.obj", make_coff_obj(CODE, func_symbol="?fn@@YA"))])
        )
        src = tmp_path / "src"
        src.mkdir()
        (src / "f.c").write_text(f"/* ADDRESS: SERVER 0x{VA:x} */\nint f(void) {{ return 0; }}\n")
        record_function_identity(
            tmp_path,
            module="SERVER",
            va=VA,
            file="src/f.c",
            name="f",
            symbol="_f",
            kind="FUNCTION",
            size=len(CODE),
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=tmp_path,
            module="SERVER",
            target_name="SERVER",
            target_binary=pe,
            compiler_profile="msvc-6.0",
            shared_dir=None,
            source_ext=".c",
        )
        result = _adopt(cfg, lib, "--json")
        assert result.exit_code == 0, result.output
        row = get_entry(tmp_path, VA, "SERVER")
        assert row["kind"] == "LIBRARY"
        assert row["symbol"] == "?fn@@YA"
        assert row["name"] == "fn_YA"
        assert row["name"].isidentifier()
