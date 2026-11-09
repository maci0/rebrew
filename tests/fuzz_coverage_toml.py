"""Atheris (libFuzzer) target: coverage TOML document reader.

``coverage-*.toml`` is a portable, hand-editable export that the
dashboards read on every request through :func:`load_coverage_from` /
:func:`load_all_coverage_from`.  Arbitrary bytes must surface as a clean
``CoverageTomlError`` (or ``UnicodeDecodeError`` from the text layer),
never an unhandled exception, and every accepted document must satisfy
the model invariants the dashboards rely on without re-checking them.

    uv run --frozen --group fuzz --group dev python tests/fuzz_coverage_toml.py <corpus_dir> [flags]
    uv run --frozen --group fuzz --group dev python tests/fuzz_coverage_toml.py tests/fixtures/coverage_toml -runs=1000

Seed corpus: tests/fixtures/coverage_toml/coverage-server.dll.toml (a real
committed shape, never production traffic) plus one truncated / hostile
variant.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import atheris  # type: ignore[import-untyped]

from rebrew.coverage_toml import (
    _TOML_VERSION,
    CoverageSnapshot,
    CoverageTomlError,
    load_coverage_from,
    snapshot_from_document,
)

#: The target the seed corpus names; mutated inputs that keep ``version``
#: and ``target`` intact exercise the row translators below.
_TARGET = "server.dll"
_FAKE_PATH = Path("coverage-server.dll.toml")


def _assert_snapshot_invariants(snap: CoverageSnapshot) -> None:
    """The properties a dashboard reads without re-checking them."""
    assert snap.version == _TOML_VERSION
    assert isinstance(snap.target, str) and snap.target
    assert isinstance(snap.functions, tuple)
    assert isinstance(snap.globals, tuple)
    assert isinstance(snap.verify_results, tuple)
    assert isinstance(snap.history, tuple)
    for fn in snap.functions:
        assert isinstance(fn.va, int) and not isinstance(fn.va, bool)
        assert isinstance(fn.name, str)
        assert isinstance(fn.status, str)
        assert isinstance(fn.module, str)
        assert fn.size is None or isinstance(fn.size, int)
        assert fn.similarity is None or (isinstance(fn.similarity, float) and fn.similarity == fn.similarity and abs(fn.similarity) != float("inf"))
        for item in fn.files:
            assert isinstance(item, str)
        for item in fn.detected_by:
            assert isinstance(item, str)
    for glob in snap.globals:
        assert isinstance(glob.va, int) and not isinstance(glob.va, bool)
        assert isinstance(glob.name, str)
        assert isinstance(glob.size, int)
        assert isinstance(glob.storage_kind, str) and glob.storage_kind
        for item in glob.owners:
            assert isinstance(item, str)
    for section in snap.sections.values():
        assert isinstance(section.name, str) and section.name
        assert isinstance(section.size, int)
        assert section.va is None or isinstance(section.va, int)
        for cell in section.cells:
            assert isinstance(cell.start, int) and isinstance(cell.end, int)
            assert isinstance(cell.span, int)
            assert isinstance(cell.state, str)
            for item in cell.functions:
                assert isinstance(item, str)
    stats = snap.function_stats
    assert stats["total"] >= 0
    assert stats["covered_bytes"] >= 0
    assert stats["matched_bytes"] >= 0
    assert stats["matched_bytes"] <= stats["covered_bytes"] or stats["covered_bytes"] == 0
    assert stats["total_bytes"] >= 0
    # functions_by_va is built from exactly these rows.
    assert len(snap.functions_by_va) == len({fn.va for fn in snap.functions})
    for va, fn in snap.functions_by_va.items():
        assert fn.va == va
    # Frozen collections: a caller cannot edit a snapshot in place.
    for mapping in (snap.sections, snap.function_stats, snap.paths, snap.functions_by_va):
        try:
            mapping["__probe__"] = None  # type: ignore[index]
        except TypeError:
            pass
        else:  # pragma: no cover - a mutable mapping is a lost guarantee
            raise AssertionError("snapshot mapping is mutable")


def TestOneInput(data: bytes) -> None:
    """Only failure modes are ``CoverageTomlError`` / ``UnicodeDecodeError``;
    a parsed snapshot never invents a wrong version, target or row shape.

    Pair assertions across the trust boundary: a document parsed via
    ``snapshot_from_document`` must agree with the same bytes read through
    the file-path entry point, and re-parsing exactly the same bytes
    yields an identical snapshot.  Row translators fall back to defaults
    (``""`` / ``0`` / ``None``) rather than raising on wrong-typed fields,
    so an accepted document's rows are always well-typed.
    """
    if not data:
        return
    # Text layer: BOM / encoding handling is read_toml_text's contract;
    # undecodable bytes are a clean rejection, not a crash.
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    # TOML layer + schema layer via the pure entry point.
    import tomllib

    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    try:
        snap = snapshot_from_document(_FAKE_PATH, doc, _TARGET)
    except CoverageTomlError as exc:
        assert str(exc)
        return
    _assert_snapshot_invariants(snap)
    # Pair: the same document re-parsed yields an identical snapshot.
    again = snapshot_from_document(_FAKE_PATH, doc, _TARGET)
    assert again == snap
    # File-path entry point agrees with the pure entry point on the
    # same bytes (a wrong-target or malformed file is also clean).
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / f"coverage-{_TARGET}.toml").write_bytes(data)
        try:
            via_file = load_coverage_from(root, _TARGET)
        except CoverageTomlError:
            return
        assert via_file == snap


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
