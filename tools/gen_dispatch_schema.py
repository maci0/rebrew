"""gen_dispatch_schema.py — write what the code declares into the dispatch schema.

``tests/fixtures/dispatch/rebrew.schema.json`` is the dispatch contract the
backend mirrors byte for byte (``NOTE.txt``).  A request member rebrew refuses
every value but a closed set of, and a reply member drawn from one, carries that
set as its ``enum``; a reply :mod:`rebrew.ops_replies` declares is its op's
``response``, each reply member naming a workspace path
(``rebrew.ops_replies.WORKSPACE_PATHS``) a string of ``format`` ``workspace-path``;
the refusal codes and their statuses (``rebrew.ops.PROBLEMS``) are ``errors``, and
each op's entry carries the ones that op answers as its own ``errors``
(``rebrew.ops.DISPATCH_PROBLEMS`` and its ``OP_PROBLEMS``).  This script takes each
from the code, so the schema and the code cannot drift; ``tests/test_ops.py`` fails
when the checked-in schema is not what this script writes.

The schema is written the way the backend's generator writes it: two-space
indent, sorted keys, a final newline.  A frozenset's values are written sorted,
a tuple's in its own order.

Usage::

    python tools/gen_dispatch_schema.py          # (re)write the schema
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

#: The schema of a reply member naming a path in the engine's workspace
#: (``rebrew.ops_replies.WORKSPACE_PATHS``), written inline on each: the backend's
#: renderer inlines every definition and has no ``$ref``.
WORKSPACE_PATH = {"format": "workspace-path", "type": "string"}

#: Text the backend's renderer (Go types through invopop/jsonschema, every definition
#: inline) never writes; the schema must equal its rendering, so it holds none of it.
UNRENDERABLE = ('"$ref"', '"$defs"', '"type": [', '"required": []')


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
    finding = ("response", "properties", "findings", "items", "properties")
    yield "rebrew.security_scan", (*finding, "severity"), SEVERITY_ORDER
    yield "rebrew.security_scan", (*finding, "confidence"), SEVERITY_ORDER
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
    """*text*, a dispatch schema, with what the code declares written into it.

    Every enforced set as its ``enum``, every reply :mod:`rebrew.ops_replies`
    declares as its op's ``response``, each workspace path member as
    :data:`WORKSPACE_PATH`, :data:`rebrew.ops.PROBLEMS` as ``errors``, and
    each op's own codes as the ``errors`` of its entry.
    """
    from rebrew import ops
    from rebrew.ops_replies import DECLARED, WORKSPACE_PATHS, json_schema

    schema = json.loads(text)
    for op, declared in DECLARED.items():
        response = schema["ops"][op]["response"]
        schema["ops"][op]["response"] = {"$schema": response["$schema"], **json_schema(declared)}
    for op, paths in WORKSPACE_PATHS.items():
        for member_path in paths:
            parent: Any = schema["ops"][op]["response"]
            *lists, member = member_path.split("[].")
            for listed in lists:
                parent = parent["properties"][listed]["items"]
            handle = parent["properties"][member]
            nullable = {"type": "null"} in handle.get("oneOf", ()) or "null" in handle.get(
                "type", ()
            )
            parent["properties"][member] = (
                {"oneOf": [WORKSPACE_PATH, {"type": "null"}]} if nullable else WORKSPACE_PATH
            )
    schema["errors"] = {
        code: {"status": list(statuses)} for code, statuses in sorted(ops.PROBLEMS.items())
    }
    for op in ops.OPS:
        codes = ops.DISPATCH_PROBLEMS | ops.OP_PROBLEMS.get(op, frozenset())
        schema["ops"][op]["errors"] = {
            code: {"status": list(ops.PROBLEMS[code])} for code in sorted(codes)
        }
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
