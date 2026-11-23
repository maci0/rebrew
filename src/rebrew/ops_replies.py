"""ops_replies.py — the dispatch replies rebrew declares, one TypedDict per closed reply.

Each declared reply is both the code's contract and the published one:
``tools/gen_dispatch_schema.py`` writes its JSON schema into the dispatch schema
(:func:`json_schema`), and the op answers :func:`project` of what it built, the
members the declaration names and nothing else, so the two cannot drift.  A
member the code builds that the declaration does not name is dropped and logged.

A reply that carries the verdict of a remote compile that never ran names why with
:data:`NotRunReason`, a closed set, and its error's structured fields
(:class:`NotRunError`), never the compile client's message.
"""

import logging
import types
from typing import (
    Any,
    Literal,
    NotRequired,
    Required,
    TypedDict,
    Union,
    get_args,
    get_origin,
    get_type_hints,
    is_typeddict,
)

log = logging.getLogger(__name__)

#: Why a remote compile has no verdict (status ``NOT_RUN``): the kind of the
#: recompile client's failure (``rebrew.compiler.recompile_client.RecompileErrorKind``),
#: or the code of a compiler that is not offered (``CompilerNotOffered.error_code``).
NotRunReason = Literal[
    "network",
    "http",
    "validation",
    "protocol",
    "service",
    "deadline",
    "compiler_withdrawn",
    "compiler_not_installed",
]


class RemoteCompile(TypedDict):
    """What an op's recompile calls cost (``rebrew.compiler.compile.RemoteCompiles.totals``)."""

    count: int
    billed_undelivered: int
    unsettled: int
    wait_ms: int


class ByteMismatch(TypedDict):
    """One byte of the compiled object that differs from the target."""

    offset: int
    target: str
    got: str


class NotRunError(TypedDict, total=False):
    """A ``NOT_RUN`` verdict's error (``RebrewError.to_dict``) without its message."""

    type: str
    retryable: bool
    kind: str | None
    name: str | None
    status_code: int | None
    group: str | None
    error_code: str | None
    retry_after: float | None


class VerifyFunctionReply(TypedDict, total=False):
    """``rebrew.verify_function``: the ``rebrew test --json`` result of one source."""

    source: Required[str]
    symbol: Required[str]
    va: Required[str]
    size: Required[int]
    status: Required[str]
    match_count: Required[int]
    total: Required[int]
    reloc_count: Required[int]
    obj_size: Required[int]
    context_hash: Required[str | None]
    mismatches: Required[list[ByteMismatch]]
    compile: Required[dict[str, Any] | None]
    remote_compile: Required[RemoteCompile]
    not_run_reason: NotRunReason
    error: NotRunError
    relocation_bindings: list[dict[str, Any]]
    aligned_pairs: int
    target_instructions: int
    candidate_instructions: int
    hunks: int
    similarity: float
    instructions: dict[str, Any]
    compile_inputs: dict[str, Any]
    verdict_valid: bool


class TargetReportReply(TypedDict, total=False):
    """``rebrew.verify_target`` (``rebrew verify --json``) and ``rebrew.build``'s report members.

    ``results`` rows of status ``NOT_RUN`` carry ``not_run_reason`` in place of
    the compile client's message.  The commands' ``binary`` (the target's path)
    and ``out`` (where the rebuilt image was written) are not declared: a path of
    the engine's host never leaves it, and no consumer reads either.
    """

    remote_compile: Required[RemoteCompile]
    # rebrew verify --json
    schema_version: int
    provenance: str
    timestamp: str
    target: str
    context_hash: str | None
    dry_run: bool
    summary: dict[str, Any]
    size_divergences: list[dict[str, Any]]
    missing_sizes: list[dict[str, Any]]
    duplicate_vas: list[dict[str, Any]]
    results: list[dict[str, Any]]
    libraries: list[dict[str, Any]]
    data: dict[str, Any] | None
    text: dict[str, Any] | None
    whole_binary: dict[str, Any] | None
    functions_checked: bool
    raw_link_status_suppressed: bool
    sizes_fixed: int
    sizes_protected: list[dict[str, Any]]
    skipped: bool
    reason: str
    arch: str
    # rebrew build round-trip --json
    sha256_original: str
    sha256_reasm: str
    match: bool
    strict_catalog: bool
    spliced: int
    skipped_proven: int
    skipped_other: int
    fenced_naked: dict[str, Any]
    skipped_catalog: list[dict[str, Any]]
    mismatches: list[dict[str, Any]]
    reason_counts: dict[str, int]
    header_parity: list[dict[str, Any]]
    byte_coverage: dict[str, Any]


#: Members the command an op runs prints that its reply withholds, by op: each is a
#: path of the engine's host, which never leaves it, and no consumer reads it.
WITHHELD: dict[str, tuple[str, ...]] = {
    "rebrew.verify_target": ("binary",),
    "rebrew.build": ("binary", "out"),
}

#: The op each declared reply answers.
DECLARED: dict[str, Any] = {
    "rebrew.verify_function": VerifyFunctionReply,
    "rebrew.verify_target": TargetReportReply,
    "rebrew.build": TargetReportReply,
}


def _members(declared: Any) -> tuple[dict[str, Any], set[str]]:
    hints = get_type_hints(declared, include_extras=True)
    members: dict[str, Any] = {}
    for name, hint in hints.items():
        if get_origin(hint) in (Required, NotRequired):
            (hint,) = get_args(hint)
        members[name] = hint
    return members, set(declared.__required_keys__)


def _optional_inner(hint: Any) -> tuple[Any, bool]:
    if get_origin(hint) in (Union, types.UnionType):
        args = [arg for arg in get_args(hint) if arg is not type(None)]
        nullable = len(args) != len(get_args(hint))
        if len(args) == 1:
            return args[0], nullable
    return hint, False


_PRIMITIVES = {str: "string", int: "integer", float: "number", bool: "boolean"}


def json_schema(hint: Any) -> dict[str, Any]:
    """The JSON schema of the type *hint*: a TypedDict, a primitive, a list, a dict or a Literal."""
    inner, nullable = _optional_inner(hint)
    schema: dict[str, Any]
    if is_typeddict(inner):
        members, required = _members(inner)
        schema = {
            "additionalProperties": False,
            "properties": {name: json_schema(member) for name, member in members.items()},
            "type": "object",
        }
        # The backend's renderer omits an empty ``required``.
        if names := [name for name in members if name in required]:
            schema["required"] = names
    elif get_origin(inner) is Literal:
        schema = {"enum": list(get_args(inner)), "type": "string"}
    elif get_origin(inner) is list:
        (item,) = get_args(inner)
        schema = {"items": json_schema(item), "type": "array"}
    elif inner is dict or get_origin(inner) is dict:
        schema = {"type": "object"}
    elif inner in _PRIMITIVES:
        schema = {"type": _PRIMITIVES[inner]}
    else:
        raise TypeError(f"no JSON schema for {inner!r}")
    # The backend's renderer writes a nullable member this way and has no ``type`` array.
    return {"oneOf": [schema, {"type": "null"}]} if nullable else schema


def project(value: dict[str, Any], declared: Any, where: str) -> dict[str, Any]:
    """The members of *value* the TypedDict *declared* names, nested declared ones projected too.

    A member *value* holds that the declaration does not name is dropped and logged
    with *where*, so a reply carries exactly what the schema publishes; with
    :data:`rebrew.config.STRICT_REPLIES_ENV` set it raises :class:`ValueError`.
    """
    members, _required = _members(declared)
    dropped = sorted(set(value) - set(members))
    if dropped:
        import os

        from rebrew.config import STRICT_REPLIES_ENV, parse_env_bool

        strict = os.environ.get(STRICT_REPLIES_ENV, "")
        if parse_env_bool(STRICT_REPLIES_ENV, strict, default=False):
            raise ValueError(f"{where}: undeclared reply members {', '.join(dropped)}")
        log.warning("%s: dropped undeclared reply members %s", where, ", ".join(dropped))
    out: dict[str, Any] = {}
    for name, item in value.items():
        if name not in members:
            continue
        inner, _nullable = _optional_inner(members[name])
        if is_typeddict(inner) and isinstance(item, dict):
            item = project(item, inner, f"{where}.{name}")
        elif get_origin(inner) is list and isinstance(item, list):
            (element,) = get_args(inner)
            if is_typeddict(element):
                item = [
                    project(row, element, f"{where}.{name}") if isinstance(row, dict) else row
                    for row in item
                ]
        out[name] = item
    return out
