"""Reviewed source claims retain native identities and historical comparisons."""

from pathlib import Path
from unittest.mock import patch

import pytest
from cli_json import cli_payload
from typer.testing import CliRunner

from rebrew.config import ProjectConfig
from rebrew.metadata.binding_history import change_source_binding
from rebrew.metadata.bindings import read_source_bindings
from rebrew.metadata.functions import (
    get_entry,
    record_function_identity,
    update_field,
    update_source_status,
)


def _project(tmp_path: Path) -> ProjectConfig:
    src = tmp_path / "src"
    src.mkdir()
    binary = tmp_path / "reference.exe"
    binary.write_bytes(b"native input")
    cfg = ProjectConfig(root=tmp_path, reversed_dir=src, module="GAME", target_binary=binary)
    for name, va in [("f", 0x401000), ("g", 0x402000)]:
        path = src / f"{name}.c"
        path.write_text(f"/* ADDRESS: GAME 0x{va:x} */\nint {name}(void) {{ return 1; }}\n")
        record_function_identity(
            tmp_path,
            module="GAME",
            va=va,
            file=f"src/{name}.c",
            name=name,
            symbol=f"_{name}",
            kind="FUNCTION",
            size=4,
        )
        update_source_status(
            tmp_path,
            "EXACT",
            module="GAME",
            va=va,
            updated_by="verify",
            verification={"status": "EXACT", "writer": "verify", "input_hash": "a" * 64},
        )
    return cfg


class TestSourceBindingHistory:
    def test_preview_preserves_every_file_and_mode(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        before = {
            path: (path.read_bytes(), path.stat()) for path in tmp_path.rglob("*") if path.is_file()
        }
        report = change_source_binding(
            cfg.metadata_dir, "GAME", 0x401000, reason="native proof", dry_run=True
        )
        assert report["previous"]["status"] == "EXACT"
        assert before == {
            path: (path.read_bytes(), path.stat()) for path in tmp_path.rglob("*") if path.is_file()
        }

    def test_retirement_preserves_native_measurement_and_counterpart(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        other = get_entry(cfg.metadata_dir, 0x402000, "GAME")
        before = get_entry(cfg.metadata_dir, 0x401000, "GAME")
        source = cfg.reversed_dir / "f.c"
        source_bytes = source.read_bytes()
        change_source_binding(
            cfg.metadata_dir,
            "GAME",
            0x401000,
            reason="wrong native routine",
            counterpart_va=0x402000,
        )
        row = get_entry(cfg.metadata_dir, 0x401000, "GAME")
        assert row["size"] == before["size"]
        assert row["verification"] == before["verification"]
        assert "file" not in row and "status" not in row
        assert row["binding_history"][-1]["previous"]["status"] == "EXACT"
        assert get_entry(cfg.metadata_dir, 0x402000, "GAME") == other
        assert source.read_bytes() == source_bytes
        assert (
            read_source_bindings(source, metadata_dir=cfg.metadata_dir, project_root=cfg.root) == []
        )
        with pytest.raises(ValueError, match="retired"):
            update_source_status(cfg.metadata_dir, "EXACT", module="GAME", va=0x401000, force=True)
        with pytest.raises(ValueError, match="reviewed rebind"):
            record_function_identity(
                cfg.metadata_dir,
                module="GAME",
                va=0x401000,
                file="src/f.c",
                name="f",
                symbol="_f",
                kind="FUNCTION",
            )

    def test_orphan_anchor_of_a_retired_row_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        """A stale file for a retired row must not fail the whole source scan.

        The historical-anchor guard only excuses the file recorded in the
        retirement history. A different file left over from a skeleton wave (the
        real-world case: a regenerated name) used to raise from
        ``read_source_bindings`` and took every compile down with it.
        """
        cfg = _project(tmp_path)
        change_source_binding(cfg.metadata_dir, "GAME", 0x401000, reason="wrong identity")
        stale = cfg.reversed_dir / "stale.c"
        stale.write_text("/* ADDRESS: GAME 0x401000 */\nvoid stale(void) {}\n")
        assert (
            read_source_bindings(stale, metadata_dir=cfg.metadata_dir, project_root=cfg.root) == []
        )

    def test_retired_tu_is_inactive_and_history_is_not_pruned(self, tmp_path: Path) -> None:
        from rebrew.lint import lint_file
        from rebrew.orphans import split_prunable
        from rebrew.source_selection import collect_target_sources

        cfg = _project(tmp_path)
        change_source_binding(cfg.metadata_dir, "GAME", 0x401000, reason="wrong identity")
        own, foreign = collect_target_sources(cfg, "GAME")
        assert cfg.reversed_dir / "f.c" in foreign
        assert cfg.reversed_dir / "g.c" in own
        assert not lint_file(cfg.reversed_dir / "f.c", cfg=cfg).errors
        assert (
            split_prunable(
                cfg, [("GAME", 0x401000, "rebrew-functions.toml")], [], include_matched=True
            )
            == []
        )

    def test_rebind_drops_current_verdict_and_keeps_old_anchor_historical(
        self, tmp_path: Path
    ) -> None:
        cfg = _project(tmp_path)
        replacement = cfg.reversed_dir / "replacement.c"
        replacement.write_text("int replacement(void) { return 2; }\n")
        identity = {
            "file": "src/replacement.c",
            "name": "replacement",
            "symbol": "_replacement",
            "kind": "FUNCTION",
        }
        change_source_binding(
            cfg.metadata_dir, "GAME", 0x401000, reason="complete native proof", identity=identity
        )
        row = get_entry(cfg.metadata_dir, 0x401000, "GAME")
        assert row["file"] == identity["file"]
        assert "status" not in row
        assert row["verification"]["status"] == "EXACT"
        assert (
            read_source_bindings(
                cfg.reversed_dir / "f.c", metadata_dir=cfg.metadata_dir, project_root=cfg.root
            )
            == []
        )
        assert (
            read_source_bindings(replacement, metadata_dir=cfg.metadata_dir, project_root=cfg.root)[
                0
            ].symbol
            == "_replacement"
        )

    @pytest.mark.parametrize("field", ["binding_history", "status_history"])
    def test_generic_writer_cannot_forge_history(self, tmp_path: Path, field: str) -> None:
        cfg = _project(tmp_path)
        path = cfg.metadata_dir / "rebrew-functions.toml"
        before = path.read_bytes()
        with pytest.raises(ValueError, match="history"):
            update_field(cfg.metadata_dir, 0x401000, field, [], module="GAME")
        assert path.read_bytes() == before

    def test_stale_store_and_external_inputs_rejected(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        preview = change_source_binding(
            cfg.metadata_dir, "GAME", 0x401000, reason="proof", dry_run=True
        )
        update_field(cfg.metadata_dir, 0x401000, "note", "other edit", module="GAME")
        path = cfg.metadata_dir / "rebrew-functions.toml"
        before = path.read_bytes()
        with pytest.raises(ValueError, match="changed since preview"):
            change_source_binding(
                cfg.metadata_dir,
                "GAME",
                0x401000,
                reason="proof",
                expected_digest=preview["input_digest"],
            )
        with pytest.raises(ValueError, match="review input changed"):
            change_source_binding(
                cfg.metadata_dir,
                "GAME",
                0x401000,
                reason="proof",
                expected_inputs={cfg.target_binary: "0" * 64},
            )
        assert path.read_bytes() == before

    def test_invalid_later_claim_is_never_published(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        path = cfg.metadata_dir / "rebrew-functions.toml"
        before = path.read_bytes(), path.stat()
        with pytest.raises(ValueError):
            change_source_binding(
                cfg.metadata_dir,
                "GAME",
                0x401000,
                reason="proof",
                identity={
                    "file": "../escape.c",
                    "name": "f",
                    "symbol": "_f",
                    "kind": "FUNCTION",
                },
            )
        assert (path.read_bytes(), path.stat()) == before


class TestBindingCommands:
    def test_preview_then_guarded_apply_and_counterpart_preservation(self, tmp_path: Path) -> None:
        from rebrew.source_binding import app

        cfg = _project(tmp_path)
        original = get_entry(cfg.metadata_dir, 0x402000, "GAME")
        args = [
            "retire",
            "0x401000",
            "--reason",
            "wrong routine",
            "--counterpart",
            "0x402000",
            "--json",
        ]
        with patch("rebrew.source_binding.require_config", return_value=cfg):
            preview = CliRunner().invoke(app, [*args, "--dry-run"])
            assert preview.exit_code == 0, preview.output
            digest = cli_payload(preview)["input_digest"]
            cfg.target_binary.write_bytes(b"changed binary")
            rejected = CliRunner().invoke(app, [*args, "--expected-digest", digest])
            assert rejected.exit_code == 2
            assert get_entry(cfg.metadata_dir, 0x401000, "GAME")["status"] == "EXACT"
            preview = CliRunner().invoke(app, [*args, "--dry-run"])
            applied = CliRunner().invoke(
                app, [*args, "--expected-digest", cli_payload(preview)["input_digest"]]
            )
            assert applied.exit_code == 0, applied.output
        assert get_entry(cfg.metadata_dir, 0x402000, "GAME") == original

    def test_ambiguous_replacement_rejected_without_changes(self, tmp_path: Path) -> None:
        from rebrew.source_binding import app

        cfg = _project(tmp_path)
        source = cfg.reversed_dir / "bad.c"
        source.write_text("int f(void){return 1;}\nint f(void){return 2;}\n")
        before = (cfg.metadata_dir / "rebrew-functions.toml").read_bytes()
        with patch("rebrew.source_binding.require_config", return_value=cfg):
            result = CliRunner().invoke(
                app,
                ["rebind", "0x401000", str(source), "--name", "f", "--reason", "proof", "--json"],
            )
        assert result.exit_code == 2
        assert (cfg.metadata_dir / "rebrew-functions.toml").read_bytes() == before


class TestRebindRejectingControls:
    def test_existing_same_target_definition_cannot_own_second_va(self, tmp_path: Path) -> None:
        cfg = _project(tmp_path)
        before = (cfg.metadata_dir / "rebrew-functions.toml").read_bytes()
        with pytest.raises(ValueError, match="already belongs"):
            change_source_binding(
                cfg.metadata_dir,
                "GAME",
                0x401000,
                reason="proof",
                identity={
                    "file": "src/g.c",
                    "name": "g",
                    "symbol": "_g",
                    "kind": "FUNCTION",
                },
            )
        assert (cfg.metadata_dir / "rebrew-functions.toml").read_bytes() == before

    def test_undiscoverable_destination_is_rejected(self, tmp_path: Path) -> None:
        from rebrew.source_binding import app

        cfg = _project(tmp_path)
        source = cfg.root / "outside.c"
        source.write_text("int f(void) { return 1; }\n")
        before = (cfg.metadata_dir / "rebrew-functions.toml").read_bytes()
        with patch("rebrew.source_binding.require_config", return_value=cfg):
            result = CliRunner().invoke(
                app, ["rebind", "0x401000", str(source), "--reason", "proof", "--json"]
            )
        assert result.exit_code == 2
        assert "discovery roots" in cli_payload(result)["error"]
        assert (cfg.metadata_dir / "rebrew-functions.toml").read_bytes() == before

    def test_rebind_after_retire_keeps_library_ancestry(self, tmp_path: Path) -> None:
        from rebrew.source_binding import app
        from rebrew.source_selection import collect_target_sources

        cfg = _project(tmp_path)
        record_function_identity(
            cfg.metadata_dir,
            module="GAME",
            va=0x401000,
            file="src/f.c",
            name="f",
            symbol="_f",
            kind="LIBRARY",
        )
        change_source_binding(cfg.metadata_dir, "GAME", 0x401000, reason="wrong library source")
        source = cfg.root / "vendor/native.c"
        source.parent.mkdir()
        source.write_text("int f(void) { return 2; }\n")
        with patch("rebrew.source_binding.require_config", return_value=cfg):
            result = CliRunner().invoke(
                app,
                [
                    "rebind",
                    "0x401000",
                    str(source),
                    "--name",
                    "f",
                    "--reason",
                    "native proof",
                    "--json",
                ],
            )
        assert result.exit_code == 0, result.output
        row = get_entry(cfg.metadata_dir, 0x401000, "GAME")
        assert row["kind"] == "LIBRARY"
        assert source in collect_target_sources(cfg, "GAME")[0]
        assert "status" not in row

    def test_change_between_parse_and_hash_is_rejected(self, tmp_path: Path) -> None:
        import rebrew.source_binding as command

        cfg = _project(tmp_path)
        source = cfg.reversed_dir / "replacement.c"
        source.write_text("int f(void) { return 2; }\n")
        before = (cfg.metadata_dir / "rebrew-functions.toml").read_bytes()
        original = command.function_definition_hashes

        def changing_definitions(text: str) -> dict[str, str]:
            result = original(text)
            source.write_text("int unrelated(void) { return 2; }\n")
            return result

        with (
            patch("rebrew.source_binding.require_config", return_value=cfg),
            patch("rebrew.source_binding.function_definition_hashes", changing_definitions),
        ):
            result = CliRunner().invoke(
                command.app,
                ["rebind", "0x401000", str(source), "--name", "f", "--reason", "proof", "--json"],
            )
        assert result.exit_code == 2
        assert "changed while parsing" in cli_payload(result)["error"]
        assert (cfg.metadata_dir / "rebrew-functions.toml").read_bytes() == before


class TestStaticDefinitionScope:
    def test_distinct_static_symbols_in_separate_tus_can_rebind(self, tmp_path: Path) -> None:
        from rebrew.source_binding import app

        cfg = _project(tmp_path)
        existing = cfg.reversed_dir / "g.c"
        existing.write_text("static int g(void) { return 1; }\n")
        replacement = cfg.reversed_dir / "replacement.c"
        replacement.write_text("static int g(void) { return 2; }\n")
        with patch("rebrew.source_binding.require_config", return_value=cfg):
            result = CliRunner().invoke(
                app,
                [
                    "rebind",
                    "0x401000",
                    str(replacement),
                    "--name",
                    "g",
                    "--reason",
                    "native proof",
                    "--json",
                ],
            )
        assert result.exit_code == 0, result.output
        assert get_entry(cfg.metadata_dir, 0x401000, "GAME")["file"] == "src/replacement.c"
        assert get_entry(cfg.metadata_dir, 0x402000, "GAME")["file"] == "src/g.c"

    def test_duplicate_external_symbol_in_separate_tus_rejected(self, tmp_path: Path) -> None:
        from rebrew.source_binding import app

        cfg = _project(tmp_path)
        replacement = cfg.reversed_dir / "replacement.c"
        replacement.write_text("int g(void) { return 2; }\n")
        before = (cfg.metadata_dir / "rebrew-functions.toml").read_bytes()
        with patch("rebrew.source_binding.require_config", return_value=cfg):
            result = CliRunner().invoke(
                app,
                [
                    "rebind",
                    "0x401000",
                    str(replacement),
                    "--name",
                    "g",
                    "--reason",
                    "proof",
                    "--json",
                ],
            )
        assert result.exit_code == 2
        assert "external symbol" in cli_payload(result)["error"]
        assert (cfg.metadata_dir / "rebrew-functions.toml").read_bytes() == before


class TestCanonicalDefinitionCollision:
    @pytest.mark.parametrize("stored", ["src/./g.c", "src//g.c", "src/alias.c"])
    def test_alias_paths_cannot_give_one_definition_two_native_owners(
        self, tmp_path: Path, stored: str
    ) -> None:
        from source_util import write_store_fixture

        from rebrew.source_binding import app

        cfg = _project(tmp_path)
        (cfg.reversed_dir / "alias.c").symlink_to("g.c")
        metadata = cfg.metadata_dir / "rebrew-functions.toml"
        text = metadata.read_text().replace('file = "src/g.c"', f'file = "{stored}"')
        write_store_fixture(metadata, text)
        before = metadata.read_bytes()
        with patch("rebrew.source_binding.require_config", return_value=cfg):
            result = CliRunner().invoke(
                app,
                [
                    "rebind",
                    "0x401000",
                    str(cfg.reversed_dir / "g.c"),
                    "--name",
                    "g",
                    "--reason",
                    "proof",
                    "--json",
                ],
            )
        assert result.exit_code == 2
        assert "already belongs" in cli_payload(result)["error"]
        assert metadata.read_bytes() == before
        with pytest.raises(ValueError, match="already belongs"):
            change_source_binding(
                cfg.metadata_dir,
                "GAME",
                0x401000,
                reason="proof",
                identity={
                    "file": "src/g.c",
                    "name": "g",
                    "symbol": "_g",
                    "kind": "FUNCTION",
                },
                project_root=cfg.root,
            )
        assert metadata.read_bytes() == before


def test_guarded_binding_accepts_variadic_pointer_payload(tmp_path: Path) -> None:
    from rebrew.source_binding import app

    cfg = _project(tmp_path)
    source = cfg.reversed_dir / "replacement.c"
    source.write_text(
        "#include <stdarg.h>\nchar* replacement(int id, ...) { va_list ap; char* p; va_start(ap,id); p=va_arg(ap,char*); va_end(ap); return p; }\n"
    )
    with patch("rebrew.source_binding.require_config", return_value=cfg):
        args = [
            "rebind",
            "0x401000",
            str(source),
            "--name",
            "replacement",
            "--reason",
            "native proof",
            "--json",
        ]
        preview = CliRunner().invoke(app, [*args, "--dry-run"])
        assert preview.exit_code == 0, preview.output
        digest = cli_payload(preview)["input_digest"]
        result = CliRunner().invoke(app, [*args, "--expected-digest", digest])
    assert result.exit_code == 0, result.output
    row = get_entry(cfg.metadata_dir, 0x401000, "GAME")
    assert row["name"] == "replacement" and "status" not in row
    assert row["binding_history"][-1]["previous"]["status"] == "EXACT"


def test_kr_export_rebind_preview_accepts_the_named_definition(tmp_path: Path) -> None:
    from rebrew.source_binding import app

    cfg = _project(tmp_path)
    source = cfg.reversed_dir / "unzip.c"
    source.write_text(
        "#ifndef local\n#  define local static\n#endif\n"
        "local int unzlocal_getByte(fin,pi)\n\tFILE *fin;\n\tint *pi;\n{ return 0; }\n"
        "extern int ZEXPORT unzStringFileNameCompare (fileName1,fileName2,iCaseSensitivity)\n"
        "\tconst char* fileName1;\n\tconst char* fileName2;\n\tint iCaseSensitivity;\n"
        "{ return strcmp(fileName1,fileName2); }\n"
        "extern int ZEXPORT unzeof (file)\n\tunzFile file;\n{ return 0; }\n"
    )
    before = get_entry(cfg.metadata_dir, 0x401000, "GAME")
    with patch("rebrew.source_binding.require_config", return_value=cfg):
        preview = CliRunner().invoke(
            app,
            [
                "rebind",
                "0x401000",
                str(source),
                "--name",
                "unzStringFileNameCompare",
                "--symbol",
                "_unzStringFileNameCompare",
                "--reason",
                "minizip K&R definition",
                "--dry-run",
                "--json",
            ],
        )
    assert preview.exit_code == 0, preview.output
    payload = cli_payload(preview)
    assert payload["replacement"]["name"] == "unzStringFileNameCompare"
    assert payload["replacement"]["symbol"] == "_unzStringFileNameCompare"
    assert payload["replacement"]["kind"] == "FUNCTION"
    assert payload["dry_run"] is True
    assert get_entry(cfg.metadata_dir, 0x401000, "GAME") == before


@pytest.mark.parametrize(
    ("text", "name", "symbol"),
    [
        (
            "extern int ZEXPORT unzStringFileNameCompare (const char *a, const char *b, int c);\n",
            "unzStringFileNameCompare",
            "_unzStringFileNameCompare",
        ),
        (
            "extern int ZEXPORT unzStringFileNameCompare (fileName1,fileName2,iCaseSensitivity)\n"
            "\tconst char* fileName1;\n\tconst char* fileName2;\n\tint iCaseSensitivity;\n"
            "{ return 0; }\n"
            "extern int ZEXPORT unzStringFileNameCompare (fileName1,fileName2,iCaseSensitivity)\n"
            "\tconst char* fileName1;\n\tconst char* fileName2;\n\tint iCaseSensitivity;\n"
            "{ return 1; }\n",
            "unzStringFileNameCompare",
            "_unzStringFileNameCompare",
        ),
        (
            "extern int ZEXPORT unzStringFileNameCompare (fileName1)\n"
            "\tconst char* fileName1;\n{ return +; }\n",
            "unzStringFileNameCompare",
            "_unzStringFileNameCompare",
        ),
        (
            "extern int ZEXPORT unzStringFileNameCompare (fileName1,fileName2,iCaseSensitivity)\n"
            "\tconst char* fileName1;\n\tconst char* fileName2;\n\tint iCaseSensitivity;\n"
            "{ return 0; }\n",
            "unzlocal_getByte",
            "_unzlocal_getByte",
        ),
        (
            "int unzStringFileNameCompare;\n",
            "unzStringFileNameCompare",
            "_unzStringFileNameCompare",
        ),
    ],
)
def test_kr_rebind_refuses_unbounded_or_mismatched_names(
    tmp_path: Path, text: str, name: str, symbol: str
) -> None:
    from rebrew.source_binding import app

    cfg = _project(tmp_path)
    source = cfg.reversed_dir / "unzip.c"
    source.write_text(text)
    before = get_entry(cfg.metadata_dir, 0x401000, "GAME")
    with patch("rebrew.source_binding.require_config", return_value=cfg):
        result = CliRunner().invoke(
            app,
            [
                "rebind",
                "0x401000",
                str(source),
                "--name",
                name,
                "--symbol",
                symbol,
                "--reason",
                "minizip K&R definition",
                "--dry-run",
                "--json",
            ],
        )
    assert result.exit_code == 2
    assert "unambiguous definition" in cli_payload(result)["error"]
    assert get_entry(cfg.metadata_dir, 0x401000, "GAME") == before


def test_malformed_va_arg_binding_preserves_previous_identity(tmp_path: Path) -> None:
    from rebrew.source_binding import app

    cfg = _project(tmp_path)
    source = cfg.reversed_dir / "replacement.c"
    source.write_text("void replacement(int id, ...) { va_arg(ap,char* +); }\n")
    before = get_entry(cfg.metadata_dir, 0x401000, "GAME")
    with patch("rebrew.source_binding.require_config", return_value=cfg):
        result = CliRunner().invoke(
            app,
            [
                "rebind",
                "0x401000",
                str(source),
                "--name",
                "replacement",
                "--reason",
                "proof",
                "--json",
            ],
        )
    assert result.exit_code == 2
    assert get_entry(cfg.metadata_dir, 0x401000, "GAME") == before


class TestBatchBindingChanges:
    def _counting_store(self, calls: list[int]):
        from rebrew.metadata import binding_history as module

        real = module.metadata_store

        class CountingStore:
            def __init__(self, path):
                self._store = real(path)

            def __getattr__(self, name):
                return getattr(self._store, name)

            def write(self, *args, **kwargs):
                calls.append(1)
                return self._store.write(*args, **kwargs)

        return patch.object(module, "metadata_store", CountingStore)

    def test_batch_rebinds_two_rows_in_one_write(self, tmp_path: Path) -> None:
        from rebrew.metadata.binding_history import change_source_bindings_batch

        cfg = _project(tmp_path)
        (cfg.reversed_dir / "library_game.h").write_text("/* identities live in metadata */\n")
        identities = [
            {"file": "src/library_game.h", "symbol": "_lib", "name": "lib", "kind": "LIBRARY"},
            {"file": "src/library_game.h", "symbol": "_lib2", "name": "lib2", "kind": "LIBRARY"},
        ]
        calls: list[int] = []
        with self._counting_store(calls):
            report = change_source_bindings_batch(
                cfg.metadata_dir,
                [
                    {
                        "module": "GAME",
                        "va": 0x401000,
                        "reason": "stock body",
                        "identity": identities[0],
                    },
                    {
                        "module": "GAME",
                        "va": 0x402000,
                        "reason": "stock body",
                        "identity": identities[1],
                    },
                ],
            )
        assert len(calls) == 1
        assert [change["va"] for change in report["changes"]] == ["0x401000", "0x402000"]
        for va in (0x401000, 0x402000):
            row = get_entry(cfg.metadata_dir, va, "GAME")
            assert row["kind"] == "LIBRARY"
            assert row["file"] == "src/library_game.h"
            assert "status" not in row
            assert row["binding_history"][-1]["action"] == "rebind"

    def test_batch_conflict_publishes_nothing(self, tmp_path: Path) -> None:
        from rebrew.metadata.binding_history import change_source_bindings_batch

        cfg = _project(tmp_path)
        (cfg.reversed_dir / "library_game.h").write_text("/* identities live in metadata */\n")
        identity = {
            "file": "src/library_game.h",
            "symbol": "_lib",
            "name": "lib",
            "kind": "LIBRARY",
        }
        before_f = get_entry(cfg.metadata_dir, 0x401000, "GAME")
        before_g = get_entry(cfg.metadata_dir, 0x402000, "GAME")
        calls: list[int] = []
        with (
            self._counting_store(calls),
            pytest.raises(ValueError, match="already belongs to"),
        ):
            change_source_bindings_batch(
                cfg.metadata_dir,
                [
                    {
                        "module": "GAME",
                        "va": 0x401000,
                        "reason": "stock body",
                        "identity": identity,
                    },
                    {
                        "module": "GAME",
                        "va": 0x402000,
                        "reason": "stock body",
                        "identity": identity,
                    },
                ],
            )
        assert calls == []
        assert get_entry(cfg.metadata_dir, 0x401000, "GAME") == before_f
        assert get_entry(cfg.metadata_dir, 0x402000, "GAME") == before_g

    def test_preview_digest_guards_apply_and_writes_nothing(self, tmp_path: Path) -> None:
        from rebrew.metadata.binding_history import change_source_bindings_batch

        cfg = _project(tmp_path)
        before = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
        changes = [{"module": "GAME", "va": 0x401000, "reason": "wrong native routine"}]
        preview = change_source_bindings_batch(cfg.metadata_dir, changes, dry_run=True)
        assert preview["changes"][0]["action"] == "retire"
        assert before == {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
        with pytest.raises(ValueError, match="inputs changed|changed since preview"):
            change_source_bindings_batch(
                cfg.metadata_dir,
                changes,
                expected_digest="0" * 64,
            )
        applied = change_source_bindings_batch(
            cfg.metadata_dir, changes, expected_digest=preview["input_digest"]
        )
        assert applied["changes"][0]["va"] == "0x401000"
        assert not get_entry(cfg.metadata_dir, 0x401000, "GAME").get("file")

    def test_batch_retires_and_rebinds_together(self, tmp_path: Path) -> None:
        from rebrew.metadata.binding_history import change_source_bindings_batch

        cfg = _project(tmp_path)
        (cfg.reversed_dir / "replacement.c").write_text("int replacement(void) { return 2; }\n")
        identity = {
            "file": "src/replacement.c",
            "symbol": "_replacement",
            "name": "replacement",
            "kind": "FUNCTION",
        }
        report = change_source_bindings_batch(
            cfg.metadata_dir,
            [
                {"module": "GAME", "va": 0x401000, "reason": "wrong routine"},
                {"module": "GAME", "va": 0x402000, "reason": "renamed", "identity": identity},
            ],
        )
        assert [change["action"] for change in report["changes"]] == ["retire", "rebind"]
        assert not get_entry(cfg.metadata_dir, 0x401000, "GAME").get("file")
        assert get_entry(cfg.metadata_dir, 0x402000, "GAME")["file"] == "src/replacement.c"

    def test_batch_refreshes_retirement_after_owner_scan(self, tmp_path: Path) -> None:
        from rebrew.metadata.binding_history import change_source_bindings_batch

        cfg = _project(tmp_path)
        replacement = {"file": "src/new.c", "symbol": "_new", "name": "new", "kind": "FUNCTION"}
        old_owner = {"file": "src/g.c", "symbol": "_g", "name": "g", "kind": "FUNCTION"}
        report = change_source_bindings_batch(
            cfg.metadata_dir,
            [
                {"module": "GAME", "va": 0x401000, "reason": "move", "identity": replacement},
                {"module": "GAME", "va": 0x402000, "reason": "retire"},
                {"module": "GAME", "va": 0x401000, "reason": "claim", "identity": old_owner},
            ],
        )
        assert [event["action"] for event in report["changes"]] == ["rebind", "retire", "rebind"]
        assert get_entry(cfg.metadata_dir, 0x401000, "GAME")["name"] == "g"
        assert not get_entry(cfg.metadata_dir, 0x402000, "GAME").get("file")


@pytest.mark.parametrize(
    ("source_text", "accepted"),
    [
        (
            "#ifndef local\n#define local static\n#endif\nlocal int f(a) int a; { return a; }\n",
            True,
        ),
        ("#define local static\nlocal int f(a) int a; { return +; }\n", False),
        (
            "#define local static\n#if X\nlocal int f(a) int a; { return a; }\n#else\nlocal int f(a) int a; { return a; }\n#endif\n",
            False,
        ),
        ("#define local static +\nlocal int f(a) int a; { return a; }\n", False),
    ],
)
def test_binding_storage_macro_definition(tmp_path: Path, source_text: str, accepted: bool) -> None:
    from rebrew.source_binding import app

    cfg = _project(tmp_path)
    source = cfg.reversed_dir / "replacement.c"
    source.write_text(source_text)
    with patch("rebrew.source_binding.require_config", return_value=cfg):
        result = CliRunner().invoke(
            app,
            [
                "rebind",
                "0x401000",
                str(source),
                "--name",
                "f",
                "--reason",
                "proof",
                "--dry-run",
                "--json",
            ],
        )
    assert (result.exit_code == 0) is accepted, result.output


def test_binding_conditional_storage_macro_does_not_bypass_external_collision(
    tmp_path: Path,
) -> None:
    from rebrew.source_binding import app

    cfg = _project(tmp_path)
    source = cfg.reversed_dir / "replacement.c"
    source.write_text(
        "#ifndef local\n#define local static\n#endif\nlocal int g(a) int a; { return a; }\n"
    )
    with patch("rebrew.source_binding.require_config", return_value=cfg):
        result = CliRunner().invoke(
            app,
            [
                "rebind",
                "0x401000",
                str(source),
                "--name",
                "g",
                "--reason",
                "proof",
                "--dry-run",
                "--json",
            ],
        )
    assert result.exit_code == 2
    assert "external symbol" in cli_payload(result)["error"]


@pytest.mark.parametrize("batch", [False, True])
def test_apply_parses_metadata_only_under_lock(tmp_path: Path, batch: bool) -> None:
    from rebrew.metadata import binding_history

    cfg = _project(tmp_path)
    with patch.object(
        binding_history, "load_metadata_for_write", wraps=binding_history.load_metadata_for_write
    ) as load:
        if batch:
            binding_history.change_source_bindings_batch(
                cfg.metadata_dir, [{"module": "GAME", "va": 0x401000, "reason": "proof"}]
            )
        else:
            binding_history.change_source_binding(
                cfg.metadata_dir, "GAME", 0x401000, reason="proof"
            )
    assert load.call_count == 1


def test_apply_rechecks_review_input_after_acquiring_lock(tmp_path: Path) -> None:
    from contextlib import contextmanager

    from rebrew.metadata import binding_history
    from rebrew.metadata.storage import input_digest

    cfg = _project(tmp_path)
    source = cfg.reversed_dir / "f.c"
    expected = input_digest(source)
    lock = binding_history.metadata_write_lock

    @contextmanager
    def changed_before_lock(*args, **kwargs):
        with lock(*args, **kwargs):
            source.write_text("int f(void) { return 2; }\n")
            yield

    with (
        patch.object(binding_history, "metadata_write_lock", changed_before_lock),
        pytest.raises(ValueError, match="binding review input changed"),
    ):
        binding_history.change_source_binding(
            cfg.metadata_dir,
            "GAME",
            0x401000,
            reason="proof",
            expected_inputs={source: expected},
        )
    assert get_entry(cfg.metadata_dir, 0x401000, "GAME")["file"] == "src/f.c"
