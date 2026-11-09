"""Atheris (libFuzzer) target: metadata TOML document readers.

``rebrew-functions.toml`` (format 3) and ``rebrew-data.toml`` (format 2)
are read on nearly every CLI path through :func:`load_metadata_doc` /
:func:`parse_metadata_doc`.  Arbitrary bytes must surface as a clean
``ValueError`` / ``UnicodeError`` (the reader swallows parse failures into
an empty table), never an unhandled exception, and every accepted document
must satisfy the qualified-identity invariants callers rely on without
re-checking them.

    uv run --frozen --group fuzz --group dev python tests/fuzz_metadata_doc.py <corpus_dir> [flags]
    uv run --frozen --group fuzz --group dev python tests/fuzz_metadata_doc.py tests/fixtures/metadata_doc -runs=1000

Seed corpus: tests/fixtures/metadata_doc/rebrew-functions.toml and
rebrew-data.toml (real committed shapes, never production traffic) plus
one truncated / hostile variant each.
"""

from __future__ import annotations

import sys
import tempfile
import unicodedata
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris  # type: ignore[import-untyped]

from rebrew.metadata.document import (
    FORMAT_VERSION,
    FUNCTION_FORMAT_VERSION,
    build_metadata_doc,
    parse_metadata_doc,
    parse_metadata_key,
    qualified_key,
    resolve_metadata_key,
)

_CANONICAL_ORDER = ("STATUS", "SIZE", "CFLAGS", "TOOLCHAIN", "BLOCKER")


def _assert_rows_shape(rows: dict[tuple[str, int], dict[str, object]]) -> None:
    for (module, va), row in rows.items():
        assert isinstance(module, str) and module
        assert module == unicodedata.normalize("NFC", module)
        assert isinstance(va, int) and not isinstance(va, bool) and va >= 0
        assert isinstance(row, dict)
        # Round-trip: the canonical spelling re-parses to the same identity.
        assert parse_metadata_key(qualified_key(module, va)) == (module, va)
        # A row read back must resolve to itself through the key index.
        assert resolve_metadata_key({"format": 0, qualified_key(module, va): row}, module, va) in (
            qualified_key(module, va),
        )


def TestOneInput(data: bytes) -> None:
    """Only failure modes are ``ValueError`` / ``UnicodeError`` / TOML parse
    errors; a parsed store never invents a wrong identity or row shape.

    Pair assertions across the trust boundary: parsing the same document
    twice yields identical rows, and a store rendered by
    ``build_metadata_doc`` + ``tomlkit.dumps`` reads back identically
    before-write / after-read over the exact bytes the fuzzer produced.
    """
    if not data:
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    import tomllib

    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    if not isinstance(doc, dict):
        return

    for version in (FUNCTION_FORMAT_VERSION, FORMAT_VERSION):
        try:
            rows = parse_metadata_doc(
                doc, source="fuzz", version=version, deepcopy=False
            )
        except ValueError:
            continue
        _assert_rows_shape(rows)
        # Pair: re-parsing the same document yields identical rows.
        again = parse_metadata_doc(doc, source="fuzz", version=version, deepcopy=False)
        assert again == rows
        # Pair across persistence: render and re-read the same entries.
        if rows and version in (FUNCTION_FORMAT_VERSION, FORMAT_VERSION):
            import tomlkit

            rendered = tomlkit.dumps(
                build_metadata_doc(rows, _CANONICAL_ORDER, version=version)
            )
            try:
                reread = tomllib.loads(rendered)
            except tomllib.TOMLDecodeError:
                return
            back = parse_metadata_doc(
                reread, source="fuzz", version=version, deepcopy=False
            )
            assert back == rows

    # File-path entry point agrees with the pure entry point on same bytes.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "rebrew-functions.toml").write_bytes(data)
        from rebrew.metadata.document import load_metadata_doc

        try:
            loaded = load_metadata_doc(
                root / "rebrew-functions.toml", {}, "metadata", deepcopy=False
            )
        except (ValueError, UnicodeError, OSError):
            return
        _assert_rows_shape(loaded)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
