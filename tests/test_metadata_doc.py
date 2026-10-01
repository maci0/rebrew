"""Tests for rebrew.metadata_doc: qualified-key algebra, doc parse/build, write lock."""

from pathlib import Path

import pytest


class TestQualifiedKey:
    def test_with_module(self) -> None:
        from rebrew.metadata_doc import qualified_key

        assert qualified_key("SERVER", 0x01006364) == "SERVER.0x01006364"

    def test_without_module(self) -> None:
        from rebrew.metadata_doc import qualified_key

        assert qualified_key(None, 0x01006364) == "0x01006364"

    def test_nfd_module_normalized_to_nfc(self) -> None:
        from rebrew.metadata_doc import qualified_key

        nfd = "MOD_\u0065\u0301"
        assert qualified_key(nfd, 0x1000) == "MOD_\u00e9.0x00001000"


class TestCanonicalVaKey:
    """A cache row's VA and a hand-typed todo key must land on one key even
    when they are spelled differently; anything that is not a VA has to stay
    distinct instead of collapsing onto a neighbour."""

    def test_hex_spellings_collapse_onto_one_int(self) -> None:
        from rebrew.metadata_doc import canonical_va_key

        assert canonical_va_key("0x1000") == canonical_va_key("0x00001000") == 0x1000
        assert canonical_va_key(" 0X1000 ") == 0x1000

    def test_int_passes_through(self) -> None:
        from rebrew.metadata_doc import canonical_va_key

        assert canonical_va_key(0x1000) == 0x1000

    def test_non_va_values_stay_distinct(self) -> None:
        from rebrew.metadata_doc import canonical_va_key

        assert canonical_va_key("0xZZZZ") == "0xZZZZ"
        assert canonical_va_key("Main") == "Main"
        assert canonical_va_key(None) == "None"
        assert len({canonical_va_key(v) for v in ("0xZZZZ", "Main", 12.0)}) == 3


class TestParseMetadataKey:
    @pytest.mark.parametrize("address", ["0x1_0", "0x١0", "0x10 ", "0x", "0x-4"])
    def test_non_ascii_or_padded_address_is_rejected(self, address: str) -> None:
        from rebrew.metadata_doc import parse_metadata_key

        assert parse_metadata_key(f"SERVER.{address}") is None

    def test_uppercase_prefix_and_dotted_module_use_the_same_identity(self) -> None:
        from rebrew.metadata_doc import parse_metadata_key

        assert parse_metadata_key("srv.0x10.0X00002400") == ("srv.0x10", 0x2400)

    def test_valid(self) -> None:
        from rebrew.metadata_doc import parse_metadata_key

        assert parse_metadata_key("SERVER.0x01006364") == ("SERVER", 16802660)

    def test_nfd_module_normalized_to_nfc(self) -> None:
        from rebrew.metadata_doc import parse_metadata_key

        nfd_key = "MOD_\u0065\u0301.0x00001000"
        assert parse_metadata_key(nfd_key) == ("MOD_\u00e9", 0x1000)

    def test_invalid_hex_returns_none(self) -> None:
        from rebrew.metadata_doc import parse_metadata_key

        assert parse_metadata_key("SERVER.0xZZZ") is None

    def test_no_module_dot_returns_none(self) -> None:
        from rebrew.metadata_doc import parse_metadata_key

        assert parse_metadata_key("not_a_key") is None


class TestResolveMetadataKey:
    @pytest.mark.parametrize("indexed", [False, True])
    def test_duplicate_identity_is_rejected(self, indexed: bool) -> None:
        from rebrew.metadata_doc import build_metadata_key_index, resolve_metadata_key

        doc = {"SERVER.0x00001000": {"status": "VERIFIED"}, "SERVER.0X1000": {"status": "DRIFT"}}
        with pytest.raises(ValueError, match="duplicate metadata keys"):
            if indexed:
                build_metadata_key_index(doc)
            else:
                resolve_metadata_key(doc, "SERVER", 0x1000)
        assert len(doc) == 2

    def test_absent_entry_returns_canonical(self) -> None:
        from rebrew.metadata_doc import resolve_metadata_key

        assert resolve_metadata_key({}, "SERVER", 0x24000) == "SERVER.0x00024000"

    def test_canonical_key_preferred(self) -> None:
        from rebrew.metadata_doc import resolve_metadata_key

        doc = {"SERVER.0x00024000": {"status": "UNCHECKED"}}
        assert resolve_metadata_key(doc, "SERVER", 0x24000) == "SERVER.0x00024000"

    def test_non_canonical_spelling_resolved(self) -> None:
        from rebrew.metadata_doc import resolve_metadata_key

        doc = {"SERVER.0x24000": {"name": "g_iat_region"}}
        assert resolve_metadata_key(doc, "SERVER", 0x24000) == "SERVER.0x24000"

    def test_index_avoids_scan_for_absent_keys(self) -> None:
        from rebrew.metadata_doc import build_metadata_key_index, resolve_metadata_key

        doc = {"SERVER.0x24000": {"name": "g_iat_region"}}
        index = build_metadata_key_index(doc)
        assert resolve_metadata_key(doc, "SERVER", 0x24000, index=index) == "SERVER.0x24000"
        # New VA: indexed miss returns canonical without requiring a doc scan.
        assert resolve_metadata_key(doc, "SERVER", 0x25000, index=index) == "SERVER.0x00025000"

    def test_other_module_ignored(self) -> None:
        from rebrew.metadata_doc import resolve_metadata_key

        doc = {"OTHER.0x24000": {"name": "x"}}
        assert resolve_metadata_key(doc, "SERVER", 0x24000) == "SERVER.0x00024000"

    def test_unicode_nfc_nfd_module_resolved(self) -> None:
        from rebrew.metadata_doc import build_metadata_key_index, resolve_metadata_key

        # Entry in doc uses NFC precomposed character (Ö)
        doc = {"M\u00d6DULE.0x24000": {"name": "g_iat_region"}}
        # Lookup using decomposed NFD character (O + combining diaeresis)
        nfd_mod = "MO\u0308DULE"
        assert resolve_metadata_key(doc, nfd_mod, 0x24000) == "M\u00d6DULE.0x24000"
        # Indexed lookup also succeeds
        index = build_metadata_key_index(doc)
        assert resolve_metadata_key(doc, nfd_mod, 0x24000, index=index) == "M\u00d6DULE.0x24000"


class TestParseMetadataDocDuplicates:
    def test_duplicate_keys_merge_fields(self, caplog: pytest.LogCaptureFixture) -> None:
        """SERVER.0x24000 and SERVER.0x00024000 parse to one (module, va) —
        the fields must merge instead of the later table replacing the earlier."""
        import tomllib

        from rebrew.metadata_doc import parse_metadata_doc

        text = (
            '["SERVER.0x24000"]\n'
            'name = "g_iat_region"\n'
            'section = ".rdata"\n'
            "\n"
            '["SERVER.0x00024000"]\n'
            'status = "UNCHECKED"\n'
        )
        with caplog.at_level("WARNING", logger="rebrew.metadata_doc"):
            parsed = parse_metadata_doc(tomllib.loads(text))

        assert parsed[("SERVER", 0x24000)] == {
            "name": "g_iat_region",
            "section": ".rdata",
            "status": "UNCHECKED",
        }
        assert "Duplicate metadata keys" in caplog.text

    def test_later_key_wins_contested_field(self) -> None:
        from rebrew.metadata_doc import parse_metadata_doc

        parsed = parse_metadata_doc(
            {"SERVER.0x24000": {"size": 4}, "SERVER.0x00024000": {"size": 8}}
        )
        assert parsed[("SERVER", 0x24000)]["size"] == 8

    def test_no_duplicates_no_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        from rebrew.metadata_doc import parse_metadata_doc

        with caplog.at_level("WARNING", logger="rebrew.metadata_doc"):
            parse_metadata_doc({"SERVER.0x1000": {"status": "STUB"}})

        assert caplog.text == ""

    def test_unknown_key_warns_when_field_set_known(self, caplog: pytest.LogCaptureFixture) -> None:
        """A hand-edited CFLAGSS is dropped by every reader: say so."""
        from rebrew.metadata_doc import parse_metadata_doc

        with caplog.at_level("WARNING", logger="rebrew.metadata_doc"):
            parse_metadata_doc(
                {"SERVER.0x1000": {"CFLAGSS": "/O2", "cflags": "/O1"}},
                known_fields=frozenset({"STATUS", "CFLAGS"}),
                source="rebrew-functions.toml",
            )

        assert "['CFLAGSS']" in caplog.text
        assert "SERVER.0x00001000" in caplog.text
        assert "rebrew-functions.toml" in caplog.text

    def test_known_keys_do_not_warn(self, caplog: pytest.LogCaptureFixture) -> None:
        from rebrew.metadata_doc import parse_metadata_doc

        with caplog.at_level("WARNING", logger="rebrew.metadata_doc"):
            parse_metadata_doc(
                {"SERVER.0x1000": {"cflags": "/O2", "file": "a.c"}},
                known_fields=frozenset({"STATUS", "CFLAGS", "FILE"}),
            )

        assert caplog.text == ""

    def test_report_is_capped_per_file(self, caplog: pytest.LogCaptureFixture) -> None:
        from rebrew.metadata_doc import parse_metadata_doc

        doc = {f"SERVER.0x{va:04x}": {"typo": 1} for va in range(10)}
        with caplog.at_level("WARNING", logger="rebrew.metadata_doc"):
            parse_metadata_doc(doc, known_fields=frozenset({"STATUS"}), source="m.toml")

        assert "(+5 more entries)" in caplog.text


class TestMetadataWriteLock:
    def test_fresh_directory_does_not_crash(self, tmp_path: Path) -> None:
        """First-ever write into a nonexistent metadata root must not raise:
        the ``.lock`` sidecar open happens before any data-write mkdir."""
        from rebrew.metadata_doc import metadata_write_lock

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

        from rebrew.metadata_doc import metadata_write_lock, parse_metadata_doc
        from rebrew.utils import atomic_write_text

        target = tmp_path / "rebrew-functions.toml"
        atomic_write_text(target, "")

        def _write(i: int) -> None:
            with metadata_write_lock(tmp_path, "rebrew-functions.toml"):
                doc = parse_metadata_doc(tomllib.loads(target.read_text(encoding="utf-8")))
                doc[("M", i)] = {"note": str(i)}
                lines = "".join(
                    f'["M.0x{va:x}"]\nnote = "{entry["note"]}"\n'
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

        from rebrew.metadata_doc import metadata_write_lock

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

        from rebrew.metadata_doc import metadata_write_lock

        dir_a, dir_b = tmp_path / "a", tmp_path / "b"
        with (
            metadata_write_lock(dir_a, "rebrew-functions.toml"),
            metadata_write_lock(dir_b, "rebrew-functions.toml"),
            # A second open file description stands in for another process.
            (dir_b / "rebrew-functions.toml.lock").open("w") as other_fd,
            pytest.raises(BlockingIOError),
        ):
            fcntl.flock(other_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
