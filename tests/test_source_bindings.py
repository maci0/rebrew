"""Address-only sources bind syntax; dedicated stores own every other field."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.metadata.bindings import read_source_bindings, source_bindings
from rebrew.metadata.data import save_data_metadata
from rebrew.metadata.functions import record_function_identity, update_field
from rebrew.metadata.source_provenance import load_source_files, set_source_file
from rebrew.source_register import plan_registration


def _record(root: Path, module: str, va: int, file: str, name: str, size: int = 7) -> None:
    record_function_identity(
        root,
        module=module,
        va=va,
        file=file,
        name=name,
        symbol="_" + name,
        kind="FUNCTION",
        size=size,
    )


class TestSourceBindings:
    def test_invalid_anchor_reports_source_path(self, tmp_path: Path) -> None:
        source = tmp_path / "misplaced.c"
        source.write_text("// ADDRESS: S 0x1000\n#include <string.h>\nint f(void) { return 1; }\n")

        with pytest.raises(ValueError, match="address must precede") as error:
            read_source_bindings(source, metadata_dir=tmp_path)

        assert str(source) in str(error.value)
        assert "line 1" in str(error.value)

    def test_metadata_only_and_anchored_definitions_coexist(self, tmp_path: Path) -> None:
        source = tmp_path / "both.c"
        source.write_text(
            "int first(void) { return 1; }\n// ADDRESS: S 0x2000\nint second(void) { return 2; }\n"
        )
        _record(tmp_path, "S", 0x1000, "both.c", "first", 5)
        _record(tmp_path, "S", 0x2000, "both.c", "second", 8)
        update_field(tmp_path, 0x2000, "cflags", "/O1", module="S")
        bindings = read_source_bindings(source, metadata_dir=tmp_path)
        assert {(b.name, b.va, b.size, b.cflags) for b in bindings} == {
            ("first", 0x1000, 5, ""),
            ("second", 0x2000, 8, "/O1"),
        }

    def test_multiple_targets_for_functions_and_data(self, tmp_path: Path) -> None:
        source = tmp_path / "shared.c"
        source.write_text(
            "// ADDRESS: S 0x1000\n// ADDRESS: C 0x2000\nint f(void) { return g; }\n"
            "// ADDRESS: S 0x3000\n// ADDRESS: C 0x4000\nconst int g = 3;\n"
        )
        _record(tmp_path, "S", 0x1000, "shared.c", "f", 7)
        _record(tmp_path, "C", 0x2000, "shared.c", "f", 9)
        save_data_metadata(
            tmp_path,
            {
                ("S", 0x3000): {"file": "shared.c", "name": "g", "kind": "DATA", "size": 4},
                ("C", 0x4000): {"file": "shared.c", "name": "g", "kind": "DATA", "size": 4},
            },
            expected_hash=None,
        )
        for module, addresses in [("S", {0x1000, 0x3000}), ("C", {0x2000, 0x4000})]:
            bindings = read_source_bindings(source, target_name=module, metadata_dir=tmp_path)
            assert {b.va for b in bindings} == addresses
            assert sum(b.is_data for b in bindings) == 1

    @pytest.mark.parametrize(
        "tag",
        [
            "FUNCTION: S 0x1000",
            "SIZE: 12",
            "CFLAGS: /O2",
            "SOURCE: naked",
            "STRUCT: State",
            "CALLERS: send",
            "STATUS: EXACT",
            "STATUS_HISTORY: forged",
            "SUPPORT: S link shim",
        ],
    )
    def test_old_source_metadata_is_rejected(self, tmp_path: Path, tag: str) -> None:
        source = tmp_path / "f.c"
        source.write_text(f"// {tag}\nint f(void) {{ return 0; }}\n")
        _record(tmp_path, "S", 0x1000, "f.c", "f")
        with pytest.raises(ValueError, match="not a source field"):
            read_source_bindings(source, metadata_dir=tmp_path)

    def test_state_comes_from_metadata_even_with_multiple_function_rows(
        self, tmp_path: Path
    ) -> None:
        source = tmp_path / "f.c"
        source.write_text("int f(void) { return 0; }\nint g(void) { return 1; }\n")
        for va, name in [(0x1000, "f"), (0x2000, "g")]:
            _record(tmp_path, "S", va, "f.c", name)
        for key, value in [("source", "naked"), ("struct", "State"), ("callers", "send")]:
            update_field(tmp_path, 0x1000, key, value, module="S")
        bindings = {b.name: b for b in read_source_bindings(source, metadata_dir=tmp_path)}
        assert (bindings["f"].source, bindings["f"].struct, bindings["f"].callers) == (
            "naked",
            "State",
            "send",
        )
        assert bindings["g"].source == ""

    def test_pre_read_source_controls_binding(self, tmp_path: Path) -> None:
        source = tmp_path / "f.c"
        source.write_text("int stale(void) { return 0; }\n")
        text = "// ADDRESS: S 0x1000\nint current(void) { return 1; }\n"
        assert source_bindings(text, source, None, None, None)[0].name == "current"

    def test_conflicting_name_is_not_silently_rebound(self, tmp_path: Path) -> None:
        source = tmp_path / "f.c"
        source.write_text("// ADDRESS: S 0x1000\nint wrong(void) { return 0; }\n")
        _record(tmp_path, "S", 0x1000, "f.c", "right")
        with pytest.raises(ValueError, match="metadata names"):
            read_source_bindings(source, metadata_dir=tmp_path)

    def test_old_store_schema_has_no_reader(self, tmp_path: Path) -> None:
        source = tmp_path / "f.c"
        source.write_text("int f(void) { return 0; }\n")
        (tmp_path / "rebrew-functions.toml").write_text(
            'format = 1\n["S.0x1000"]\nfile="f.c"\nmarker_type="FUNCTION"\n'
        )
        with pytest.raises(ValueError, match="format = 2"):
            read_source_bindings(source, metadata_dir=tmp_path)

    def test_regular_body_comments_are_not_metadata(self, tmp_path: Path) -> None:
        source = tmp_path / "f.c"
        source.write_text(
            "// ADDRESS: S 0x1000\nint f(void) {\n// NOTE: this explains code\nreturn 0;\n}\n"
        )
        assert read_source_bindings(source)[0].name == "f"


class TestRegistration:
    def test_registration_never_imports_source_state(self, tmp_path: Path) -> None:
        source = tmp_path / "f.c"
        source.write_text("// ADDRESS: S 0x1000\nint f(void) { return 0; }\n")
        cfg = SimpleNamespace(
            root=tmp_path,
            metadata_dir=tmp_path,
            target_modules={"S"},
            library_modules=set(),
            external_libs={},
        )
        functions, data = plan_registration(cfg, [source])
        assert functions[0]["identity"]["kind"] == "FUNCTION"
        assert "fields" not in functions[0]
        assert data == []
        assert not (tmp_path / "rebrew-functions.toml").exists()

    def test_registration_refreshes_matching_calling_convention(self, tmp_path: Path) -> None:
        from rebrew.metadata.functions import save_metadata

        source = tmp_path / "main.c"
        source.write_text(
            "/* ADDRESS: S 0x1000 */\n"
            "int __stdcall main(void *instance, void *previous, char *command, int show)\n"
            "{ return 0; }\n"
            "/* ADDRESS: S 0x1004 */\n"
            "int other(void) { return 1; }\n"
        )
        save_metadata(
            tmp_path,
            {
                ("S", 0x1000): {
                    "file": "main.c",
                    "name": "main",
                    "symbol": "_main",
                    "kind": "FUNCTION",
                },
                ("S", 0x1004): {
                    "file": "main.c",
                    "name": "other",
                    "symbol": "_holdrand",
                    "kind": "FUNCTION",
                },
            },
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            metadata_dir=tmp_path,
            target_modules={"S"},
            library_modules=set(),
            external_libs={},
        )
        functions, _data = plan_registration(cfg, [source])
        symbols = {row["va"]: row["identity"]["symbol"] for row in functions}
        assert symbols[0x1000] == "_main@16"
        assert symbols[0x1004] == "_holdrand"

    def test_duplicate_address_different_definitions_refuses_before_writes(
        self, tmp_path: Path
    ) -> None:
        paths = []
        for name in ("f", "g"):
            source = tmp_path / f"{name}.c"
            source.write_text(f"// ADDRESS: S 0x1000\nint {name}(void) {{ return 0; }}\n")
            paths.append(source)
        cfg = SimpleNamespace(
            root=tmp_path,
            metadata_dir=tmp_path,
            target_modules={"S"},
            library_modules=set(),
            external_libs={},
        )
        with pytest.raises(ValueError, match="several declarations"):
            plan_registration(cfg, paths)
        assert not (tmp_path / "rebrew-functions.toml").exists()

    def test_support_purpose_is_dedicated_file_metadata(self, tmp_path: Path) -> None:
        set_source_file(tmp_path, "src/shims.c", "S", "native link layout")
        assert [(r.file, r.module, r.purpose) for r in load_source_files(tmp_path)] == [
            ("src/shims.c", "S", "native link layout")
        ]
        assert (tmp_path / "rebrew-source.toml").stat().st_mode & 0o222 == 0


class TestReviewedReplacement:
    def test_function_replacement_requires_the_reviewed_digest(self, tmp_path: Path) -> None:
        import hashlib

        from rebrew.metadata.functions import load_metadata, save_metadata

        rows = {
            ("S", 0x1000): {
                "file": "f.c",
                "name": "f",
                "status": "EXACT",
                "verification": {"writer": "verify", "input_hash": "a" * 64},
            }
        }
        save_metadata(tmp_path, rows, expected_hash=None)
        path = tmp_path / "rebrew-functions.toml"
        original = path.read_bytes()
        with pytest.raises(ValueError, match="changed since"):
            save_metadata(tmp_path, {}, expected_hash="wrong")
        assert path.read_bytes() == original
        save_metadata(tmp_path, rows, expected_hash=hashlib.sha256(original).hexdigest())
        assert load_metadata(tmp_path) == rows
        assert path.stat().st_mode & 0o777 == 0o444

    def test_data_replacement_requires_the_reviewed_digest(self, tmp_path: Path) -> None:
        import hashlib

        rows = {
            ("S", 0x1000): {
                "file": "f.c",
                "name": "g",
                "size": 4,
                "status": "VERIFIED",
                "verification": {"status": "VERIFIED", "writer": "verify", "input_hash": "a" * 64},
            }
        }
        save_data_metadata(tmp_path, rows, expected_hash=None)
        path = tmp_path / "rebrew-data.toml"
        original = path.read_bytes()
        with pytest.raises(ValueError, match="changed since"):
            save_data_metadata(tmp_path, {}, expected_hash="wrong")
        assert path.read_bytes() == original
        save_data_metadata(tmp_path, rows, expected_hash=hashlib.sha256(original).hexdigest())
        from rebrew.metadata.data import load_data_metadata

        assert load_data_metadata(tmp_path) == rows
        assert path.stat().st_mode & 0o777 == 0o444

    def test_source_replacement_preserves_evidence_and_purposes(self, tmp_path: Path) -> None:
        from rebrew.metadata.source_provenance import (
            AssemblyProvenance,
            SourceFilePurpose,
            load_source_provenance,
            replace_source_metadata,
        )

        evidence = AssemblyProvenance("f.c", "f", "S", "a" * 64, "Reviewed original assembly")
        purpose = SourceFilePurpose("support.c", "S", "native link layout")
        replace_source_metadata(tmp_path, [evidence], [purpose], expected_hash=None)
        assert load_source_provenance(tmp_path) == (evidence,)
        assert load_source_files(tmp_path) == (purpose,)
        before = (tmp_path / "rebrew-source.toml").read_bytes()
        with pytest.raises(ValueError, match="changed since"):
            replace_source_metadata(tmp_path, [], [], expected_hash=None)
        assert (tmp_path / "rebrew-source.toml").read_bytes() == before


class TestIdentityOnlyScan:
    def test_identity_scan_skips_unneeded_prototypes_but_validates_anchors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata import bindings

        source = tmp_path / "identity.c"
        text = "int f(void) { return 1; }\n"
        source.write_text(text)
        _record(tmp_path, "S", 0x1000, "identity.c", "f")

        def _unexpected(*args: object, **kwargs: object) -> None:
            raise AssertionError("identity-only scan extracted a prototype")

        monkeypatch.setattr(bindings, "_DefinitionPrototypes", _unexpected)
        rows = source_bindings(text, source, "S", None, tmp_path, with_prototypes=False)
        assert [(row.name, row.va, row.size) for row in rows] == [("f", 0x1000, 7)]
        with pytest.raises(ValueError, match="exactly one"):
            source_bindings(
                "// ADDRESS: S 0x1000\nint a,b;", source, "S", None, tmp_path, with_prototypes=False
            )
