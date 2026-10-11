"""``PROVENANCE_TAGS`` is exactly the set of tags the shipped writers stamp.

The set exists so "who last wrote this row" is answerable from the store, and
``rebrew lint`` reports W031 for a tag outside it.  A tag no writer produces is
a name a reader must still keep recognizing, and a writer whose tag is missing
from the set makes its own tool report against its own output.  Both are
silent, so the suite reads the writers rather than a hand-copied list.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from rebrew.metadata import PROVENANCE_TAGS

_SRC = Path(__file__).resolve().parent.parent / "src" / "rebrew"

#: ``updated_by="x"`` keyword and ``"updated_by": "x"`` dict entry.  A tag
#: threaded through a variable instead is covered by the ``document-unmatched``
#: round-trip below.
_LITERAL = re.compile(r"""["']?updated_by["']?[=:]\s*["']([a-z0-9-]+)["']""")

#: ``metadata_model`` maps the store key to the attribute of the same name, so
#: the pair's key appears as its own value there.
_NOT_A_TAG = frozenset({"updated_by"})


def _stamped_tags() -> set[str]:
    """Return every literal provenance tag the shipped writers emit."""
    found: set[str] = set()
    for path in sorted(_SRC.rglob("*.py")):
        if path.name == "metadata.py":
            continue  # declares the vocabulary and names tags in error text
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if (
                        kw.arg == "updated_by"
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        found.add(kw.value.value)
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=True):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "updated_by"
                        and isinstance(value, ast.Constant)
                        and isinstance(value.value, str)
                    ):
                        found.add(value.value)
    return found - _NOT_A_TAG


class TestProvenanceVocabulary:
    def test_every_stamped_tag_is_declared(self) -> None:
        """A writer may not stamp a tag ``rebrew lint`` would report against."""
        undeclared = sorted(_stamped_tags() - PROVENANCE_TAGS)
        assert not undeclared, (
            "these tags are stamped by a writer but absent from "
            f"metadata.PROVENANCE_TAGS: {undeclared}"
        )

    def test_every_declared_tag_is_stamped(self) -> None:
        """A tag nothing stamps is a name every reader must still carry."""
        unstamped = sorted(PROVENANCE_TAGS - _stamped_tags())
        assert not unstamped, f"declared tags no shipped writer stamps: {unstamped}"

    def test_literal_scan_agrees_with_the_ast_scan(self) -> None:
        """The AST scan is the one under test; a regex backs it up cheaply."""
        text = "\n".join(p.read_text(encoding="utf-8") for p in sorted(_SRC.rglob("*.py")))
        assert set(_LITERAL.findall(text)) - _NOT_A_TAG == _stamped_tags()


class TestBatchWriterStampsProvenance:
    def test_batch_write_records_the_pair(self, tmp_path: Path) -> None:
        from rebrew.metadata import set_fields_batch

        assert (
            set_fields_batch(
                tmp_path,
                [
                    {
                        "module": "APP",
                        "va": 0x24000,
                        "fields": {"blocker": "x"},
                        "updated_by": "lint",
                    }
                ],
            )
            == 1
        )
        toml_text = (tmp_path / "rebrew-functions.toml").read_text(encoding="utf-8")
        assert 'updated_by = "lint"' in toml_text
        assert "updated_at" in toml_text

    def test_unknown_tag_is_rejected(self, tmp_path: Path) -> None:
        """The write fails loud rather than producing a W031 store."""
        from rebrew.metadata import set_fields_batch

        with pytest.raises(ValueError, match="unknown provenance tag"):
            set_fields_batch(
                tmp_path,
                [
                    {
                        "module": "APP",
                        "va": 0x24000,
                        "fields": {"blocker": "x"},
                        "updated_by": "not-a-tool",
                    }
                ],
            )
        assert not (tmp_path / "rebrew-functions.toml").exists()


class TestFieldWriterProvenance:
    @pytest.mark.parametrize("writer", ["one", "several"])
    @pytest.mark.parametrize("existing", [False, True])
    def test_unknown_tag_cannot_change_the_store(
        self, tmp_path: Path, writer: str, existing: bool
    ) -> None:
        from rebrew.metadata import get_entry, set_fields, update_field

        path = tmp_path / "rebrew-functions.toml"
        if existing:
            update_field(tmp_path, 0x24000, "note", "keep", "APP", updated_by="lint")
        before = path.read_bytes() if path.exists() else None
        with pytest.raises(ValueError, match="Unknown provenance tag"):
            if writer == "one":
                update_field(tmp_path, 0x24000, "note", "changed", "APP", updated_by="not-a-tool")
            else:
                set_fields(
                    tmp_path,
                    0x24000,
                    {"note": "changed", "size": 17},
                    "APP",
                    updated_by="not-a-tool",
                )
        assert (path.read_bytes() if path.exists() else None) == before
        assert get_entry(tmp_path, 0x24000, "APP").get("note") == ("keep" if existing else None)

    def test_unknown_stamp_keeps_the_open_entry_unchanged(self) -> None:
        from rebrew.metadata import stamp_provenance

        entry = {"note": "keep", "updated_by": "lint", "updated_at": "2026-01-01T00:00:00+00:00"}
        before = dict(entry)
        with pytest.raises(ValueError, match="Unknown provenance tag"):
            stamp_provenance(entry, "not-a-tool")
        assert entry == before
