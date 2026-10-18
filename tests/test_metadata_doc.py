"""Tests for rebrew.metadata.document: qualified-key algebra, doc parse/build, write lock."""

from pathlib import Path
from typing import Any

import pytest


class TestParsedDocumentCache:
    def test_second_load_does_not_parse_again(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A new process reuses the parsed rows. The parse count does not move with load."""
        import rebrew.metadata.files as document
        from rebrew.metadata.functions import clear_metadata_cache, load_metadata
        from rebrew.utils import load_tomllib

        store = tmp_path / "rebrew-functions.toml"
        store.write_text(
            'format = 3\n["GAME.0x00001000"]\nname = "f"\nkind = "FUNCTION"\n',
            encoding="utf-8",
        )
        parses = 0
        real = load_tomllib

        def counting(path: Path) -> dict[str, Any]:
            nonlocal parses
            parses += 1
            return real(path)

        monkeypatch.setattr(document, "load_tomllib", counting)
        first = load_metadata(tmp_path, deepcopy=False)
        assert parses == 1
        assert first[("GAME", 0x1000)]["name"] == "f"
        clear_metadata_cache()
        second = load_metadata(tmp_path, deepcopy=False)
        assert parses == 1
        assert second[("GAME", 0x1000)]["name"] == "f"

        store.write_text(
            'format = 3\n["GAME.0x00001000"]\nname = "g"\nkind = "FUNCTION"\n',
            encoding="utf-8",
        )
        clear_metadata_cache()
        third = load_metadata(tmp_path, deepcopy=False)
        assert parses == 2
        assert third[("GAME", 0x1000)]["name"] == "g"

        (tmp_path / ".rebrew" / "metadata-doc" / "rebrew-functions.toml.json").write_text(
            "{", encoding="utf-8"
        )
        clear_metadata_cache()
        assert load_metadata(tmp_path, deepcopy=False)[("GAME", 0x1000)]["name"] == "g"
        assert parses == 3


class TestQualifiedKey:
    def test_with_module(self) -> None:
        from rebrew.metadata.document import qualified_key

        assert qualified_key("SERVER", 0x01006364) == "SERVER.0x01006364"

    def test_without_module(self) -> None:
        from rebrew.metadata.document import qualified_key

        with pytest.raises(ValueError, match="non-empty target"):
            qualified_key(None, 0x01006364)

    def test_nfd_module_normalized_to_nfc(self) -> None:
        from rebrew.metadata.document import qualified_key

        nfd = "MOD_\u0065\u0301"
        assert qualified_key(nfd, 0x1000) == "MOD_\u00e9.0x00001000"


class TestCanonicalVaKey:
    """A cache row's VA and a hand-typed todo key must land on one key even
    when they are spelled differently; anything that is not a VA has to stay
    distinct instead of collapsing onto a neighbour."""

    def test_hex_spellings_collapse_onto_one_int(self) -> None:
        from rebrew.metadata.document import canonical_va_key

        assert canonical_va_key("0x1000") == canonical_va_key("0x00001000") == 0x1000
        assert canonical_va_key(" 0X1000 ") == 0x1000

    def test_int_passes_through(self) -> None:
        from rebrew.metadata.document import canonical_va_key

        assert canonical_va_key(0x1000) == 0x1000

    def test_non_va_values_stay_distinct(self) -> None:
        from rebrew.metadata.document import canonical_va_key

        assert canonical_va_key("0xZZZZ") == "0xZZZZ"
        assert canonical_va_key("Main") == "Main"
        assert canonical_va_key(None) == "None"
        assert len({canonical_va_key(v) for v in ("0xZZZZ", "Main", 12.0)}) == 3


class TestParseMetadataKey:
    @pytest.mark.parametrize("address", ["0x1_0", "0x١0", "0x10 ", "0x", "0x-4"])
    def test_non_ascii_or_padded_address_is_rejected(self, address: str) -> None:
        from rebrew.metadata.document import parse_metadata_key

        assert parse_metadata_key(f"SERVER.{address}") is None

    def test_uppercase_prefix_and_dotted_module_use_the_same_identity(self) -> None:
        from rebrew.metadata.document import parse_metadata_key

        assert parse_metadata_key("srv.0x10.0X00002400") == ("srv.0x10", 0x2400)

    def test_valid(self) -> None:
        from rebrew.metadata.document import parse_metadata_key

        assert parse_metadata_key("SERVER.0x01006364") == ("SERVER", 16802660)

    def test_nfd_module_normalized_to_nfc(self) -> None:
        from rebrew.metadata.document import parse_metadata_key

        nfd_key = "MOD_\u0065\u0301.0x00001000"
        assert parse_metadata_key(nfd_key) == ("MOD_\u00e9", 0x1000)

    def test_invalid_hex_returns_none(self) -> None:
        from rebrew.metadata.document import parse_metadata_key

        assert parse_metadata_key("SERVER.0xZZZ") is None

    def test_no_module_dot_returns_none(self) -> None:
        from rebrew.metadata.document import parse_metadata_key

        assert parse_metadata_key("not_a_key") is None


class TestResolveMetadataKey:
    @pytest.mark.parametrize("indexed", [False, True])
    def test_duplicate_identity_is_rejected(self, indexed: bool) -> None:
        from rebrew.metadata.document import build_metadata_key_index, resolve_metadata_key

        doc = {"SERVER.0x00001000": {"status": "VERIFIED"}, "SERVER.0X1000": {"status": "DRIFT"}}
        with pytest.raises(ValueError, match="duplicate metadata keys"):
            if indexed:
                build_metadata_key_index(doc)
            else:
                resolve_metadata_key(doc, "SERVER", 0x1000)
        assert len(doc) == 2

    def test_absent_entry_returns_canonical(self) -> None:
        from rebrew.metadata.document import resolve_metadata_key

        assert resolve_metadata_key({}, "SERVER", 0x24000) == "SERVER.0x00024000"

    def test_canonical_key_preferred(self) -> None:
        from rebrew.metadata.document import resolve_metadata_key

        doc = {"SERVER.0x00024000": {"status": "UNCHECKED"}}
        assert resolve_metadata_key(doc, "SERVER", 0x24000) == "SERVER.0x00024000"

    def test_non_canonical_spelling_resolved(self) -> None:
        from rebrew.metadata.document import resolve_metadata_key

        doc = {"SERVER.0x24000": {"name": "g_iat_region"}}
        assert resolve_metadata_key(doc, "SERVER", 0x24000) == "SERVER.0x24000"

    def test_index_avoids_scan_for_absent_keys(self) -> None:
        from rebrew.metadata.document import build_metadata_key_index, resolve_metadata_key

        doc = {"SERVER.0x24000": {"name": "g_iat_region"}}
        index = build_metadata_key_index(doc)
        assert resolve_metadata_key(doc, "SERVER", 0x24000, index=index) == "SERVER.0x24000"
        # New VA: indexed miss returns canonical without requiring a doc scan.
        assert resolve_metadata_key(doc, "SERVER", 0x25000, index=index) == "SERVER.0x00025000"

    def test_other_module_ignored(self) -> None:
        from rebrew.metadata.document import resolve_metadata_key

        doc = {"OTHER.0x24000": {"name": "x"}}
        assert resolve_metadata_key(doc, "SERVER", 0x24000) == "SERVER.0x00024000"

    def test_unicode_nfc_nfd_module_resolved(self) -> None:
        from rebrew.metadata.document import build_metadata_key_index, resolve_metadata_key

        # Entry in doc uses NFC precomposed character (Ö)
        doc = {"M\u00d6DULE.0x24000": {"name": "g_iat_region"}}
        # Lookup using decomposed NFD character (O + combining diaeresis)
        nfd_mod = "MO\u0308DULE"
        assert resolve_metadata_key(doc, nfd_mod, 0x24000) == "M\u00d6DULE.0x24000"
        # Indexed lookup also succeeds
        index = build_metadata_key_index(doc)
        assert resolve_metadata_key(doc, nfd_mod, 0x24000, index=index) == "M\u00d6DULE.0x24000"


class TestParseMetadataDocValidation:
    @pytest.mark.parametrize("second", ["SERVER.0x00001000", "SERVER.0X1000"])
    def test_duplicate_keys_are_rejected(self, second: str) -> None:
        from rebrew.metadata.document import parse_metadata_doc

        document = {"format": 2, "SERVER.0x1000": {"size": 4}, second: {"size": 8}}
        with pytest.raises(ValueError, match="duplicate metadata"):
            parse_metadata_doc(document)
        assert document["SERVER.0x1000"] == {"size": 4}

    def test_known_fields_read_without_warnings(self, caplog: pytest.LogCaptureFixture) -> None:
        from rebrew.metadata.document import parse_metadata_doc

        assert parse_metadata_doc(
            {"format": 2, "S.0x1000": {"size": 4}}, known_fields=frozenset({"SIZE"})
        ) == {("S", 0x1000): {"size": 4}}
        assert caplog.text == ""

    @pytest.mark.parametrize("field", ["CFLAGSS", "SIZE", "marker_type"])
    def test_unknown_or_retired_field_is_rejected(self, field: str) -> None:
        from rebrew.metadata.document import parse_metadata_doc

        with pytest.raises(ValueError):
            parse_metadata_doc(
                {"format": 2, "S.0x1000": {field: 4}},
                known_fields=frozenset({"SIZE"}),
                source="store.toml",
            )

    @pytest.mark.parametrize("version", [None, 1, 3, True, 2.0, "2"])
    def test_current_integer_format_is_required(self, version: object) -> None:
        from rebrew.metadata.document import parse_metadata_doc

        with pytest.raises(ValueError, match="format = 2"):
            parse_metadata_doc({"format": version})


class TestMetadataWriteLock:
    def test_fresh_directory_does_not_crash(self, tmp_path: Path) -> None:
        """First-ever write into a nonexistent metadata root must not raise:
        the ``.lock`` sidecar open happens before any data-write mkdir."""
        from rebrew.metadata.storage import metadata_write_lock

        target = tmp_path / "brand" / "new" / "rebrew-functions.toml"
        with metadata_write_lock(target.parent, target.name):
            pass
        assert not target.exists()  # lock only — no data file implied

    def test_concurrent_writers_do_not_lose_updates(self, tmp_path: Path) -> None:
        """N threads doing read-modify-write cycles under the shared lock must
        all land: without serialization, last-writer-wins drops siblings."""
        import threading
        import tomllib

        from thread_util import join_all

        from rebrew.metadata.document import parse_metadata_doc
        from rebrew.metadata.storage import metadata_write_lock
        from rebrew.utils import atomic_write_text

        target = tmp_path / "rebrew-functions.toml"
        atomic_write_text(target, "format = 2\n")

        def _write(i: int) -> None:
            with metadata_write_lock(tmp_path, "rebrew-functions.toml"):
                doc = parse_metadata_doc(tomllib.loads(target.read_text(encoding="utf-8")))
                doc[("M", i)] = {"note": str(i)}
                lines = "format = 2\n" + "".join(
                    f"""["M.0x{va:x}"]\nnote = "{entry["note"]}"\n"""
                    for (_, va), entry in sorted(doc.items(), key=lambda kv: kv[0])
                )
                atomic_write_text(target, lines)

        threads = [threading.Thread(target=_write, args=(i,), daemon=True) for i in range(16)]
        for t in threads:
            t.start()
        join_all(threads)

        doc = parse_metadata_doc(tomllib.loads(target.read_text(encoding="utf-8")))
        assert {va for _, va in doc} == set(range(16))

    def test_reentrant_nested_acquisition_does_not_deadlock(self, tmp_path: Path) -> None:
        """A nested acquisition on the same filename must not deadlock.

        The GA batch holds ``metadata_write_lock("rebrew-functions.toml")``
        while ``update_stub_to_matched`` promotes STATUS through
        ``update_source_status`` -> ``update_statuses_batch``, which locks the
        same file again.  A non-reentrant lock wedges the worker thread forever.
        """
        import threading

        from rebrew.metadata.storage import metadata_write_lock

        done = threading.Event()
        result: list[str] = []

        def _nested() -> None:
            with (
                metadata_write_lock(tmp_path, "rebrew-functions.toml"),
                metadata_write_lock(tmp_path, "rebrew-functions.toml"),
            ):
                result.append("inner")
            result.append("outer")
            done.set()

        worker = threading.Thread(target=_nested, daemon=True)
        worker.start()
        assert done.wait(timeout=10), "nested metadata_write_lock deadlocked"
        assert result == ["inner", "outer"]

    def test_nested_lock_on_other_directory_takes_its_flock(self, tmp_path: Path) -> None:
        """Holding the lock for one metadata root must not skip the ``flock``
        of a same-named file in another root: another process would then
        interleave its read-modify-write on the second file."""
        fcntl = pytest.importorskip("fcntl")

        from rebrew.metadata.storage import metadata_write_lock

        dir_a, dir_b = tmp_path / "a", tmp_path / "b"
        with (
            metadata_write_lock(dir_a, "rebrew-functions.toml"),
            metadata_write_lock(dir_b, "rebrew-functions.toml"),
            # A second open file description stands in for another process.
            (dir_b / "rebrew-functions.toml.lock").open("w") as other_fd,
            pytest.raises(BlockingIOError),
        ):
            fcntl.flock(other_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
