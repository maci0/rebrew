"""gen_dispatch_schema.py — write the closed sets rebrew enforces into the dispatch schema.

``tests/fixtures/dispatch/rebrew.schema.json`` is the dispatch contract the
backend mirrors byte for byte (``NOTE.txt``).  A request member rebrew refuses
every value but a closed set of, and a reply member drawn from one, carries that
set as its ``enum``.  This script takes each set from the constant the code
enforces, so the schema and the code cannot drift; ``tests/test_ops.py`` fails
when the checked-in schema is not what this script writes.

The schema is written the way the backend's generator writes it: two-space
indent, sorted keys, a final newline.  A frozenset's values are written sorted,
a tuple's in its own order.

Usage::

    python tools/gen_dispatch_schema.py          # (re)write the enums
    python tools/gen_dispatch_schema.py --check  # exit 1 when the file differs
"""

from __future__ import annotations

from pathlib import Path
lazy import argparse
lazy import json
lazy import sys
lazy from collections.abc import Collection, Iterator
lazy from typing import Any, get_args


def _project_root() -> Path:
    """The nearest directory above this file that holds ``pyproject.toml``."""
    for directory in Path(__file__).resolve().parents:
        if (directory / "pyproject.toml").is_file():
            return directory
    raise RuntimeError("no pyproject.toml above tools/gen_dispatch_schema.py")


SCHEMA = _project_root() / "tests" / "fixtures" / "dispatch" / "rebrew.schema.json"


def enforced_sets() -> Iterator[tuple[str, tuple[str, ...], Collection[str]]]:
    """``(op, path inside the op's entry, values)`` for every closed set the schema publishes."""
    from rebrew import ops
    from rebrew.decompiler import DecompilerReason, DecompilerState
    from rebrew.metadata.bindings import DATA_KINDS
    from rebrew.report import SITE_DATA_KINDS
    from rebrew.security_scan import SEVERITY_ORDER
    from rebrew.snapshot_mutations import OPERATIONS

    def request(field: str) -> tuple[str, ...]:
        return ("request", "properties", field)

    yield "rebrew.retained_source_operation", request("operation"), OPERATIONS
    # `kind` is a rename's kind or a data-set's kind; each operation refuses the
    # other's values, so the schema publishes their union.
    yield "rebrew.retained_source_operation", request("kind"), {*ops.RENAME_KINDS, *DATA_KINDS}
    yield "rebrew.flag_search", request("tier"), ops.FLAG_SEARCH_TIERS
    yield "rebrew.disassemble", request("format"), ops.DISASM_FORMATS
    yield "rebrew.reference_flirt", request("format"), ops.FLIRT_FORMATS
    yield "rebrew.decompile", request("backend"), ops.DECOMPILER_BACKENDS
    yield "rebrew.decompile_snapshot", request("backend"), ops.DECOMPILER_BACKENDS
    yield "rebrew.structs", request("decompiler"), ops.DECOMPILER_BACKENDS
    yield "rebrew.security_scan", request("min_severity"), SEVERITY_ORDER
    yield "rebrew.security_scan_snapshot", request("min_severity"), SEVERITY_ORDER
    manifest_kind = ("response", "properties", "manifest", "items", "properties", "kinds", "items")
    yield "rebrew.report", manifest_kind, SITE_DATA_KINDS
    decompiler = ("response", "properties", "decompilers", "items", "properties")
    yield (
        "rebrew.vocabulary",
        (*decompiler, "name"),
        ops.DECOMPILER_BACKENDS - {ops.AUTO_DECOMPILER},
    )
    yield "rebrew.vocabulary", (*decompiler, "state"), get_args(DecompilerState)
    yield "rebrew.vocabulary", (*decompiler, "reason"), get_args(DecompilerReason)


def render(text: str) -> str:
    """*text*, a dispatch schema, with every enforced set written as its ``enum``."""
    schema = json.loads(text)
    for op, path, values in enforced_sets():
        node: Any = schema["ops"][op]
        for step in path:
            node = node[step]
        node["enum"] = list(values) if isinstance(values, tuple) else sorted(values)
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the file differs")
    args = parser.parse_args()
    current = SCHEMA.read_text(encoding="utf-8")
    rendered = render(current)
    if args.check:
        if rendered != current:
            print(f"{SCHEMA} differs from the sets rebrew enforces", file=sys.stderr)
            return 1
        return 0
    SCHEMA.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
