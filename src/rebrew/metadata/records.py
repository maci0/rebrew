"""Record boundaries of a logical metadata document, shared by every backend."""

lazy from collections.abc import Iterator
lazy from pathlib import Path
lazy from typing import Any


def metadata_records(doc: Any, path: Path) -> Iterator[tuple[tuple[str, ...], Any]]:
    """Walk record boundaries, keeping shared schema containers separate from records."""
    depths = {
        "rebrew-source.toml": {"definitions": 4, "files": 3},
        "rebrew-types.toml": {"types": 3},
    }.get(path.name, {})

    def walk(
        value: Any, keys: tuple[str, ...], depth: int
    ) -> Iterator[tuple[tuple[str, ...], Any]]:
        if len(keys) == depth:
            yield keys, value
        else:
            for key, child in value.items():
                yield from walk(child, (*keys, key), depth)

    for key, value in doc.items():
        if key == "source" and path.name == "rebrew-functions.toml":
            for kind, records in value.items():
                yield from walk(records, (key, kind), 5 if kind == "definitions" else 4)
        elif key != "format":
            yield from walk(value, (key,), depths.get(key, 1))
