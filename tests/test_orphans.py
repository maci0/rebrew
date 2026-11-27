"""Tests for rebrew orphans CLI — list/prune orphaned metadata blocks + drop."""

from types import SimpleNamespace
lazy from pathlib import Path

import pytest
from cli_json import cli_payload
from source_util import write_source, write_store_fixture
from typer.testing import CliRunner


def _mock_cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    cfg = SimpleNamespace(
        root=tmp_path,
        reversed_dir=tmp_path / "reversed",
        metadata_dir=tmp_path,
        module="SERVER",
        source_ext=".c",
        shared_dir=None,
        dll_exports={},
    )
    import rebrew.cli as cli_mod
    import rebrew.orphans as orph

    monkeypatch.setattr(cli_mod, "load_config", lambda **kw: cfg)
    monkeypatch.setattr(orph, "require_config", lambda **kw: cfg)
    return cfg


def _write_project(tmp_path: Path, matched_orphan: bool = False) -> None:
    src = tmp_path / "reversed"
    src.mkdir(exist_ok=True)
    write_source(
        src / "foo.c",
        "/* ADDRESS: SERVER 0x1000 */\nint foo(void){return 0;}\n",
        encoding="utf-8",
        metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
    )
    blocks = 'format = 3\n["SERVER.0x1000"]\nstatus = "STUB"\nsize = 16\n\n["SERVER.0x2000"]\nstatus = "STUB"\nsize = 16\n'
    if matched_orphan:
        blocks += '\n["SERVER.0x3000"]\nstatus = "EXACT"\nsize = 16\n'
    write_store_fixture(tmp_path / "rebrew-functions.toml", blocks, encoding="utf-8")


class TestOrphansList:
    def test_lists_orphan_leaves_live(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["list"])
        assert res.exit_code == 0, res.output
        assert "0x2000" in res.output
        assert "0x1000" not in res.output

    def test_clean_tree_reports_none(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        write_source(
            src / "foo.c",
            "/* ADDRESS: SERVER 0x1000 */\nint foo(void){return 0;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 3\n["SERVER.0x1000"]\nstatus = "STUB"\n',
            encoding="utf-8",
        )
        res = CliRunner().invoke(app, ["list"])
        assert res.exit_code == 0, res.output
        assert "No orphaned" in res.output

    def test_json_lists_orphans(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:

        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["list", "--json"])
        assert res.exit_code == 0, res.output
        payload = cli_payload(res)
        assert payload["orphans"] == [
            {
                "module": "SERVER",
                "va": "0x2000",
                "store": "rebrew-functions.toml",
                "status": "STUB",
            }
        ]


class TestOrphansPrune:
    @pytest.mark.parametrize("evidence", ["source", "inventory"])
    def test_prune_keeps_a_live_dos_address_zero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, evidence: str
    ) -> None:
        import shutil
        from pathlib import Path

        from rebrew.app.main import app
        from rebrew.config import inventory_path_for, load_config
        from rebrew.metadata.functions import get_entry, record_function_identity

        reference = Path(__file__).parent / "fixtures" / "tc16_hello.exe"
        shutil.copyfile(reference, tmp_path / "hello.exe")
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "DOS"\nshared_dir = ""\n'
            '[targets.DOS]\nbinary = "hello.exe"\nreversed_dir = "src"\nmodule = "DOS"\n'
            'arch = "x86_16"\nformat = "mz"\n',
            encoding="utf-8",
        )
        source = tmp_path / "src" / "entry.c"
        source.parent.mkdir()
        cfg = load_config(tmp_path)
        if evidence == "source":
            source.write_text("/* ADDRESS: DOS 0x0 */\nint entry(void) { return 0; }\n")
        else:
            inventory = inventory_path_for(source.parent, cfg)
            inventory.parent.mkdir(parents=True, exist_ok=True)
            inventory.write_text('[{"va": 0, "size": 4, "name": "entry"}]')
        record_function_identity(
            cfg.metadata_dir,
            module="DOS",
            va=0,
            file="src/entry.c",
            name="entry",
            symbol="_entry",
            kind="FUNCTION",
            size=4,
        )
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["orphans", "prune", "--json"])
        assert result.exit_code == 0, result.output
        assert cli_payload(result)["pruned"] == 0
        assert get_entry(cfg.metadata_dir, 0, "DOS")["size"] == 4

    def test_prune_deletes_only_orphan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.functions import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["prune"])
        assert res.exit_code == 0, res.output
        assert "deleted 1" in res.output
        assert get_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_entry(tmp_path, 0x1000, "SERVER").get("status") == "STUB"

    def test_prune_dry_run_writes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.functions import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["prune", "--dry-run"])
        assert res.exit_code == 0, res.output
        assert "would be deleted" in res.output
        assert get_entry(tmp_path, 0x2000, "SERVER").get("status") == "STUB"

    def test_prune_json_deletes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Regression: `orphans prune --json` used to short-circuit on the listing path
        and report pruned: 0 without deleting anything."""

        from rebrew.metadata.functions import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["prune", "--json"])
        assert res.exit_code == 0, res.output
        out = cli_payload(res)
        assert out["pruned"] == 1
        assert get_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_entry(tmp_path, 0x1000, "SERVER").get("status") == "STUB"

    def test_prune_include_matched_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`orphans prune --include-matched --json` reports held_back 0 and prunes matched."""

        from rebrew.metadata.functions import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path, matched_orphan=True)
        res = CliRunner().invoke(app, ["prune", "--include-matched", "--json"])
        assert res.exit_code == 0, res.output
        out = cli_payload(res)
        assert out["pruned"] == 2
        assert out["held_back"] == 0
        assert get_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_entry(tmp_path, 0x3000, "SERVER") == {}


class TestKnownSourceWidening:
    """Ghidra/exports-only VAs are known functions, not orphans.

    A metadata block whose VA appears only in the Ghidra structure cache or
    the export table must survive orphan pruning — the source marker may
    simply not be reversed yet.
    """

    def _project_with_extra_known(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> SimpleNamespace:
        from rebrew.config import FUNCTION_STRUCTURE_JSON

        cfg = _mock_cfg(tmp_path, monkeypatch)
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        write_source(
            src / "foo.c",
            "/* ADDRESS: SERVER 0x1000 */\nint foo(void){return 0;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 3\n["SERVER.0x1000"]\nstatus = "STUB"\n\n["SERVER.0x2000"]\nstatus = "STUB"\nsize = 16\n\n["SERVER.0x3000"]\nstatus = "STUB"\nsize = 16\n\n["SERVER.0x4000"]\nstatus = "STUB"\nsize = 16\n',
            encoding="utf-8",
        )
        (src / FUNCTION_STRUCTURE_JSON).write_text(
            '[{"va": 8192, "size": 16, "name": "ghidra_fn"}]', encoding="utf-8"
        )
        cfg.dll_exports = {0x3000: "exp_fn"}
        return cfg

    def test_ghidra_and_export_vas_not_orphans(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        from rebrew.orphans import app

        self._project_with_extra_known(tmp_path, monkeypatch)
        res = CliRunner().invoke(app, ["list", "--json"])
        assert res.exit_code == 0, res.output
        payload = cli_payload(res)
        vas = sorted(o["va"] for o in payload["orphans"])
        # 0x2000 lives only in the Ghidra structure cache, 0x3000 only in
        # dll_exports — both are known functions, not orphans.
        assert "0x2000" not in vas
        assert "0x3000" not in vas
        assert "0x4000" in vas  # truly unknown → orphan

    def test_prune_keeps_ghidra_and_export_blocks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.functions import get_entry
        from rebrew.orphans import app

        self._project_with_extra_known(tmp_path, monkeypatch)
        res = CliRunner().invoke(app, ["prune", "--include-matched"])
        assert res.exit_code == 0, res.output
        assert get_entry(tmp_path, 0x2000, "SERVER").get("status") == "STUB"
        assert get_entry(tmp_path, 0x3000, "SERVER").get("status") == "STUB"
        assert get_entry(tmp_path, 0x4000, "SERVER") == {}


class TestDataOrphansNameExemption:
    """A name never claims a data block: named entries with no VA marker
    are orphans like any other (stale names used to accumulate silently)."""

    def _data_project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _mock_cfg(tmp_path, monkeypatch)
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        write_source(
            src / "g.c",
            "/* ADDRESS: SERVER 0x1000 */\nint g_live;\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "GLOBAL"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x1000"]\nname = "g_live"\nsection = ".data"\nsize = 4\n\n["SERVER.0x2000"]\nname = "g_stale"\nsection = ".data"\nsize = 4\n\n["SERVER.0x3000"]\nsection = ".data"\nsize = 4\n\n["SERVER.0x4000"]\nname = "import_slot"\nsection = ".idata"\nsize = 4\n',
            encoding="utf-8",
        )

    def test_named_stale_entry_is_orphan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:

        from rebrew.orphans import app

        self._data_project(tmp_path, monkeypatch)
        res = CliRunner().invoke(app, ["list", "--json"])
        assert res.exit_code == 0, res.output
        vas = sorted(
            o["va"] for o in cli_payload(res)["orphans"] if o["store"] == "rebrew-data.toml"
        )
        assert vas == ["0x2000", "0x3000"]

    def test_prune_deletes_named_stale_keeps_import_inventory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.data import get_data_entry
        from rebrew.orphans import app

        self._data_project(tmp_path, monkeypatch)
        res = CliRunner().invoke(app, ["prune", "--include-matched"])
        assert res.exit_code == 0, res.output
        assert get_data_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_data_entry(tmp_path, 0x3000, "SERVER") == {}
        assert get_data_entry(tmp_path, 0x1000, "SERVER").get("name") == "g_live"
        assert get_data_entry(tmp_path, 0x4000, "SERVER").get("name") == "import_slot"

    @pytest.mark.parametrize("include_matched", [False, True])
    @pytest.mark.parametrize("operation", ["prune", "shared_guard"])
    def test_verified_data_requires_explicit_matched_pruning(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        include_matched: bool,
        operation: str,
    ) -> None:
        from rebrew.metadata.data import get_data_entry
        from rebrew.orphans import app, split_prunable

        self._data_project(tmp_path, monkeypatch)
        write_store_fixture(
            tmp_path / "rebrew-data.toml",
            'format = 2\n["SERVER.0x2000"]\nname = "g_verified"\nsize = 4\n'
            'status = "VERIFIED"\n["SERVER.0x2000".verification]\n'
            'status = "VERIFIED"\nmeasured_at = "2026-10-15T00:00:00Z"\n'
            '["SERVER.0x3000"]\nname = "g_unchecked"\nsize = 4\nstatus = "UNCHECKED"\n',
            encoding="utf-8",
        )
        before = get_data_entry(tmp_path, 0x2000, "SERVER")
        if operation == "prune":
            args = ["prune"] + (["--include-matched"] if include_matched else [])
            res = CliRunner().invoke(app, args)
            assert res.exit_code == 0, res.output
            assert get_data_entry(tmp_path, 0x3000, "SERVER") == {}
            assert get_data_entry(tmp_path, 0x2000, "SERVER") == ({} if include_matched else before)
        else:
            cfg = SimpleNamespace(metadata_dir=tmp_path)
            doomed = split_prunable(
                cfg,
                [],
                [("SERVER", 0x2000, "rebrew-data.toml"), ("SERVER", 0x3000, "rebrew-data.toml")],
                include_matched=include_matched,
            )
            assert {row["va"] for row in doomed} == (
                {"0x2000", "0x3000"} if include_matched else {"0x3000"}
            )
            assert get_data_entry(tmp_path, 0x2000, "SERVER") == before


class TestOrphansDrop:
    def test_drop_by_va(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.metadata.functions import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["drop", "0x2000"])
        assert res.exit_code == 0, res.output
        assert get_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_entry(tmp_path, 0x1000, "SERVER").get("status") == "STUB"

    def test_drop_missing_va_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["drop", "0x9999"])
        assert res.exit_code != 0
        assert "nothing to drop" in res.output

    def test_drop_dry_run_keeps_block(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.functions import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        res = CliRunner().invoke(app, ["drop", "0x2000", "--dry-run"])
        assert res.exit_code == 0, res.output
        assert "Would drop" in res.output
        assert get_entry(tmp_path, 0x2000, "SERVER").get("status") == "STUB"


class TestBatchDeletes:
    def test_delete_entries_batch(self, tmp_path: Path) -> None:
        from rebrew.metadata.functions import delete_entries_batch, get_entry, save_metadata

        save_metadata(
            tmp_path,
            {
                ("SERVER", 0x1000): {"status": "STUB"},
                ("SERVER", 0x2000): {"status": "STUB", "size": 16},
            },
        )
        assert delete_entries_batch(tmp_path, [("SERVER", 0x2000), ("SERVER", 0x9999)]) == 1
        assert get_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_entry(tmp_path, 0x1000, "SERVER").get("status") == "STUB"

    def test_delete_data_entries_batch(self, tmp_path: Path) -> None:
        from rebrew.metadata.data import delete_data_entries_batch, get_data_entry, set_data_field

        set_data_field(tmp_path, 0x1000, "section", ".data", module="SERVER")
        set_data_field(tmp_path, 0x2000, "section", ".rdata", module="SERVER")
        assert delete_data_entries_batch(tmp_path, [("SERVER", 0x2000)]) == 1
        assert get_data_entry(tmp_path, 0x2000, "SERVER") == {}
        assert get_data_entry(tmp_path, 0x1000, "SERVER").get("section") == ".data"

    @pytest.mark.parametrize("earned", ["EXACT", "PROVEN"])
    def test_earned_orphan_held_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, earned: str
    ) -> None:
        from rebrew.metadata.functions import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        write_source(
            src / "foo.c",
            "/* ADDRESS: SERVER 0x1000 */\nint foo(void){return 0;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            f'format = 3\n["SERVER.0x1000"]\nstatus = "STUB"\n\n["SERVER.0x2000"]\nstatus = "{earned}"\nsize = 16\n\n["SERVER.0x3000"]\nstatus = "STUB"\n',
            encoding="utf-8",
        )
        res = CliRunner().invoke(app, ["prune"])
        assert res.exit_code == 0, res.output
        assert "Holding back 1 earned" in res.output
        assert "deleted 1" in res.output
        assert get_entry(tmp_path, 0x2000, "SERVER").get("status") == earned
        assert get_entry(tmp_path, 0x3000, "SERVER") == {}

    def test_include_matched_prunes_all(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.functions import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        write_source(
            src / "foo.c",
            "/* ADDRESS: SERVER 0x1000 */\nint foo(void){return 0;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 3\n["SERVER.0x1000"]\nstatus = "STUB"\n\n["SERVER.0x2000"]\nstatus = "EXACT"\nsize = 16\n',
            encoding="utf-8",
        )
        res = CliRunner().invoke(app, ["prune", "--include-matched"])
        assert res.exit_code == 0, res.output
        assert get_entry(tmp_path, 0x2000, "SERVER") == {}


class TestCorruptInventoryFailClosed:
    """A corrupt function_structure.json must not classify orphans.

    Treating corruption as an empty inventory would mark every unreversed
    metadata block as an orphan — ``orphans prune`` would then delete earned STATUS.
    """

    def test_corrupt_structure_refuses_to_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.config import FUNCTION_STRUCTURE_JSON
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        write_source(
            src / "foo.c",
            "/* ADDRESS: SERVER 0x1000 */\nint foo(void){return 0;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 3\n["SERVER.0x1000"]\nstatus = "STUB"\n\n["SERVER.0x2000"]\nstatus = "EXACT"\nsize = 16\n',
            encoding="utf-8",
        )
        (src / FUNCTION_STRUCTURE_JSON).write_text("[{broken", encoding="utf-8")
        res = CliRunner().invoke(app, ["list"])
        assert res.exit_code != 0
        assert "function inventory" in res.output.lower()
        assert "Refusing" in res.output

    def test_corrupt_structure_refuses_to_prune(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.config import FUNCTION_STRUCTURE_JSON
        from rebrew.metadata.functions import get_entry
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        src = tmp_path / "reversed"
        src.mkdir(exist_ok=True)
        write_source(
            src / "foo.c",
            "/* ADDRESS: SERVER 0x1000 */\nint foo(void){return 0;}\n",
            encoding="utf-8",
            metadata_fields={"SERVER.0x1000": {"kind": "FUNCTION"}},
        )
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 3\n["SERVER.0x1000"]\nstatus = "STUB"\n\n["SERVER.0x2000"]\nstatus = "EXACT"\nsize = 16\n',
            encoding="utf-8",
        )
        (src / FUNCTION_STRUCTURE_JSON).write_text("[{broken", encoding="utf-8")
        res = CliRunner().invoke(app, ["prune"])
        assert res.exit_code != 0
        # Earned STATUS must survive — prune must not run.
        assert get_entry(tmp_path, 0x2000, "SERVER").get("status") == "EXACT"


class TestSupportFileOrphans:
    """A support-file purpose whose file is gone is an orphan of its own module."""

    def _register(self, tmp_path: Path) -> None:
        from rebrew.metadata.source_provenance import set_source_file

        (tmp_path / "reversed" / "shim.c").write_text("int shim;\n", encoding="utf-8")
        set_source_file(tmp_path, "reversed/shim.c", "SERVER", "native link layout")
        set_source_file(tmp_path, "reversed/gone.c", "SERVER", "evidence only")
        set_source_file(tmp_path, "reversed/gone.c", "GOLD", "evidence only")

    def _purposes(self, tmp_path: Path) -> set[tuple[str, str]]:
        from rebrew.metadata.source_provenance import load_source_files

        return {(r.file, r.module) for r in load_source_files(tmp_path)}

    def test_list_reports_a_missing_support_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        self._register(tmp_path)
        res = CliRunner().invoke(app, ["list", "--json"])
        assert res.exit_code == 0, res.output
        assert cli_payload(res)["support_files"] == [
            {"file": "reversed/gone.c", "module": "SERVER", "purpose": "evidence only"}
        ]
        text = CliRunner().invoke(app, ["list"])
        assert "orphan support file reversed/gone.c (SERVER)" in text.output

    def test_dry_run_keeps_and_prune_removes_only_this_module(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        self._register(tmp_path)
        before = self._purposes(tmp_path)
        preview = CliRunner().invoke(app, ["prune", "--dry-run", "--json"])
        assert preview.exit_code == 0, preview.output
        assert cli_payload(preview)["pruned_support_files"] == 0
        assert self._purposes(tmp_path) == before

        res = CliRunner().invoke(app, ["prune", "--json"])
        assert res.exit_code == 0, res.output
        assert cli_payload(res)["pruned_support_files"] == 1
        assert self._purposes(tmp_path) == {
            ("reversed/shim.c", "SERVER"),
            ("reversed/gone.c", "GOLD"),
        }

    def test_drop_support_removes_one_purpose_of_an_existing_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        self._register(tmp_path)
        shim = str(tmp_path / "reversed" / "shim.c")
        before = self._purposes(tmp_path)
        preview = CliRunner().invoke(app, ["drop", shim, "--support", "--dry-run", "--json"])
        assert preview.exit_code == 0, preview.output
        assert cli_payload(preview)["dropped"] == 0
        assert self._purposes(tmp_path) == before

        res = CliRunner().invoke(app, ["drop", shim, "--support", "--json"])
        assert res.exit_code == 0, res.output
        assert cli_payload(res) == {
            "file": "reversed/shim.c",
            "module": "SERVER",
            "purpose": "native link layout",
            "dropped": 1,
            "dry_run": False,
        }
        assert self._purposes(tmp_path) == before - {("reversed/shim.c", "SERVER")}
        assert (tmp_path / "reversed" / "shim.c").exists()

    def test_drop_support_refuses_a_file_without_a_purpose_in_this_module(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.orphans import app

        _mock_cfg(tmp_path, monkeypatch)
        _write_project(tmp_path)
        self._register(tmp_path)
        foo = str(tmp_path / "reversed" / "foo.c")
        res = CliRunner().invoke(app, ["drop", foo, "--support", "--json"])
        assert res.exit_code == 2, res.output
        assert "No support-file purpose for reversed/foo.c in SERVER" in cli_payload(res)["error"]
        assert ("reversed/gone.c", "GOLD") in self._purposes(tmp_path)
