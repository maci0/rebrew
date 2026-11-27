"""Verify, build, candidate application, data, and retained snapshot ops."""

from __future__ import annotations

from pathlib import Path
lazy import base64
lazy import hashlib
lazy import math
lazy import os
lazy import re
lazy import shutil
lazy import tempfile
lazy from collections.abc import Iterable
lazy from typing import Any

from rebrew.errors import RebrewError
from rebrew.ops.core import (
    APPLY_METADATA_FILE,
    CANDIDATE_NAME_TAKEN,
    CANDIDATE_NOT_ONE_FUNCTION,
    COMMAND_TIMEOUT_SECONDS,
    COMPILE_NOT_RUN,
    COVERAGE_INPUT_UNVERIFIED,
    DATA_FIELD_OPTIONS,
    DECOMPILER_BACKENDS,
    FLAG_SEARCH_TIERS,
    FLIRT_FORMATS,
    MALFORMED_SIGNATURES,
    REMOTE_HEADERS,
    SCRATCH_DIR,
    SEARCH_TIMEOUT_SECONDS,
    OpsError,
    WorkerConfig,
    address_comment_refused,
    apply_project_cflags,
    attested_registry_digest,
    bounded,
    check_manifest_size,
    checked_cflags,
    escape_log_text,
    final_recompile_refusal,
    ghidra_outage,
    invalid_request,
    logger,
    no_decompilation,
    not_run_detail,
    ops_binding,
    refuse_compiler_not_offered,
    refuse_unoffered_decompiler,
    refusing_disagreeing_records,
    request_id,
    step,
    trace_id,
    verified_coverage_inputs_required,
)
from rebrew.ops.handlers_analysis import run_rebrew
from rebrew.ops.requests import (
    ApplyCandidateRequest,
    BuildRequest,
    CoverageReportRequest,
    DataListRequest,
    DataSetRequest,
    DecompileSnapshotRequest,
    FlagSearchRequest,
    ReferenceFlirtRequest,
    SecuritySnapshotRequest,
    SkeletonRequest,
    SnapshotMutationRequest,
    VerifyRequest,
    VerifyTargetRequest,
)
from rebrew.ops.staging import (
    address_va,
    binary_file,
    checked_coverage_input,
    confined_snapshot_config,
    project_file,
    project_root,
    retained_metadata_backend,
    retained_target_snapshot,
    stage_retained_snapshot,
    target_config,
    target_options,
)
lazy from rebrew.formats.binary_loader import load_binary
lazy from rebrew.utils import sha256_file, split_source_lines


def _flag(enabled: bool, option: str) -> list[str]:
    return [option] if enabled else []


def remote_header_refusal(cfg: Any, sources: Iterable[Path]) -> None:
    """Refuse a remote compile of a source whose project headers cannot ship.

    A remote compile ships the project headers a source reads as an include
    bundle (``compiler.compile.remote_include_bundle``; relumea ADR 0010,
    decision 4).  A source is refused before anything compiles when its
    bundle cannot be built (an ``#include`` a macro computes, a header outside
    the project root or not UTF-8, a DOS toolchain), or when sources need one
    and the configured recompile service does not accept bundles; that
    refusal names the first such source and the header it includes, and for
    several sources how many need one.  A service that cannot be asked is not
    a refusal: the compile reports that failure.  Local compiles pass.
    """
    override = ops_binding("remote_header_refusal", remote_header_refusal)
    if override is not remote_header_refusal:
        override(cfg, sources)
        return
    from rebrew.compiler.compile import recompile_url

    url = recompile_url(cfg)
    if url is None:
        return
    from rebrew.compiler import toolchain as toolchain_registry
    from rebrew.compiler.compile import (
        effective_compile_flags,
        remote_bundles_supported,
        remote_include_bundle,
    )
    from rebrew.compiler.recompile_client import RecompileError

    def shown(path: Path) -> str:
        return path.relative_to(cfg.root).as_posix() if path.is_relative_to(cfg.root) else path.name

    spec = toolchain_registry.TOOLCHAINS.get(getattr(cfg, "compiler_profile", "") or "")
    first = ""
    affected = total = 0
    for source in sources:
        total += 1
        parent = source.resolve().parent
        try:
            bundle = remote_include_bundle(
                cfg,
                spec,
                source.read_text(encoding="utf-8", errors="surrogateescape"),
                effective_compile_flags(cfg, spec, "", parent),
                parent,
            )
        except RecompileError as exc:
            raise OpsError(
                bounded(f"{shown(source)} {exc}; compile it with a local backend"),
                code=REMOTE_HEADERS,
                status=422,
            ) from None
        if bundle is None:
            continue
        affected += 1
        if not first:
            header = min(bundle.includes)
            more = len(bundle.includes) - 1
            first = f"{shown(source)} includes the project header {header}" + (
                f" and {more} more" if more else ""
            )
    if not affected or remote_bundles_supported(cfg) is not False:
        return
    extent = f"; {affected} of {total} sources read project headers" if total > 1 else ""
    raise OpsError(
        bounded(
            f"{first}{extent}. The recompile service at {url} does not accept include bundles:"
            " upgrade it, or compile with a local backend"
        ),
        code=REMOTE_HEADERS,
        status=422,
    )


def retained_compile_refusal(cfg: Any, sources: Iterable[Path]) -> None:
    """Use only the operator-configured remote compiler and confined include flags."""
    override = ops_binding("retained_compile_refusal", retained_compile_refusal)
    if override is not retained_compile_refusal:
        override(cfg, sources)
        return
    from rebrew.compiler.compile import effective_compile_flags, extract_include_dirs

    approved = os.environ.get("REBREW_RECOMPILE_URL", "").strip()
    if not approved or cfg.recompile_url != approved:
        raise OpsError("retained compilation requires the configured private recompile service")
    source_list = list(sources)
    for source in source_list:
        for flags in (cfg.cflags, *cfg.cflags_presets.values()):
            for item in extract_include_dirs(
                effective_compile_flags(cfg, None, flags, source.parent)
            ):
                if "\\" in item or not Path(item).resolve().is_relative_to(cfg.root):
                    raise invalid_request(
                        "compiler include directory escapes the retained snapshot"
                    )
    remote_header_refusal(cfg, source_list)


def reference_flirt(config: WorkerConfig, req: ReferenceFlirtRequest) -> dict[str, Any]:
    """Match one FLIRT ``.sig``/``.pat`` file against the target's code sections.

    ``rebrew library scan-signatures`` with that file alone: unambiguous
    matches of at least ``min_size`` bytes, and the count of ambiguous ones
    skipped.  The signatures are a stored file like a binary.
    """
    from rebrew.library.flirt import SignatureFileError, parse_signature_file

    if req.format not in FLIRT_FORMATS:
        raise invalid_request(f"format must be one of {', '.join(sorted(FLIRT_FORMATS))}")
    if req.min_size < 0:
        raise invalid_request(f"min_size must not be negative, got {req.min_size}")
    root = project_root(config, req.project_dir)
    target = target_options(root, req.sha256)
    signatures = req.signatures
    scratch = config.require_workspace() / SCRATCH_DIR
    with binary_file(
        config, signatures.file, signatures.url, signatures.sha256, "signatures.file"
    ) as path:
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="flirt-", dir=scratch) as directory:
            reference = Path(directory) / f"reference.{req.format}"
            shutil.copyfile(path, reference)
            try:
                parse_signature_file(reference)
            except SignatureFileError:
                raise OpsError(
                    f"the signatures are not a {req.format} file python-flirt reads",
                    code=MALFORMED_SIGNATURES,
                    status=422,
                ) from None
            arguments = ["library", "scan-signatures", "--json", f"--min-size={req.min_size}"]
            return run_rebrew(
                [*arguments, *target, "--", directory],
                root,
                ops_binding("COMMAND_TIMEOUT_SECONDS", COMMAND_TIMEOUT_SECONDS),
            )


def verify_function(config: WorkerConfig, req: VerifyRequest) -> dict[str, Any]:
    """Compile one source and byte-compare it to the target (``rebrew test <source> --json``).

    A mismatch is a result.  Without ``no_promote`` the comparison writes the
    function's STATUS into the project metadata, as ``rebrew test`` does.
    ``instructions`` (a candidate only) adds ``rebrew test --instructions``'s
    comparison.
    """
    from rebrew.verify.test import run_test

    if req.candidate:
        return verify_candidate(config, req)
    if req.instructions:
        raise invalid_request("instructions needs a candidate")

    root = project_root(config, req.project_dir)
    cfg = target_config(root, req.sha256)
    source = project_file(root, req.source, "source")
    remote_header_refusal(cfg, [source])
    result = run_test(cfg, source, no_promote=req.no_promote, json_output=True)
    if "source" in result:
        # The project's path for it, as a candidate's report names it: the host's never leaves.
        result["source"] = req.source
    return final_recompile_refusal(result)


def verify_candidate(config: WorkerConfig, req: VerifyRequest) -> dict[str, Any]:
    """Compare candidate text in a private snapshot of retained inputs.

    The candidate is judged by the bytes it compiles to, whatever it names its function: when the
    name differs from the registry's, the snapshot's registry follows it for the run, as an apply's
    does, and nothing leaves the op but the report.
    """
    return _run_candidate(config, req, apply=False)


#: The largest candidate text, in UTF-8 bytes, a verification or an apply compiles.
CANDIDATE_MAX_BYTES = 2_000_000


#: The function registry of a TOML project. A SQLite project's registry is its
#: ``rebrew-metadata.sqlite3`` store; an applied candidate returns its source and
#: the registry its config reads, and nothing else leaves the op.


def apply_candidate(config: WorkerConfig, req: ApplyCandidateRequest) -> dict[str, Any]:
    """Promote an exact candidate in a private snapshot and return the files that changed.

    The candidate takes the function's address anchor, ``rebrew test`` runs in promote mode with the attempt's
    flags, so rebrew's own writers record STATUS, SIZE and CFLAGS, and the function's identity (symbol and
    name) follows the candidate through rebrew's identity writer. A result that is not EXACT or RELOC is
    refused: nothing is published from a candidate that no longer matches. A SQLite project returns a
    closed, verified copy of its store in place of ``rebrew-functions.toml``.
    """
    return _run_candidate(config, req, apply=True)


def _candidate_with_anchor(candidate: str, module: str, va: int) -> str:
    """Keep the retained identity immediately above the candidate's definition."""
    from rebrew.c_syntax.parser import comment_nodes, find_c_function_definitions, parse_c_source
    from rebrew.config import DEFAULT_ADDRESS_COMMENT_REGEX
    from rebrew.metadata.anchors import address_comment, comment_body

    tree, raw = parse_c_source(candidate)
    removals = []
    for node in comment_nodes(tree):
        comment = raw[node.start_byte : node.end_byte].decode("utf-8")
        body = comment_body(comment)
        if not body.startswith("ADDRESS:"):
            continue
        match = re.fullmatch(DEFAULT_ADDRESS_COMMENT_REGEX, body)
        if match is None:
            raise address_comment_refused("invalid candidate ADDRESS comment")
        if int(match["va"], 16) != va:
            raise address_comment_refused("candidate ADDRESS comment names a different VA")
        start = raw.rfind(b"\n", 0, node.start_byte) + 1
        end = raw.find(b"\n", node.end_byte)
        end = len(raw) if end < 0 else end + 1
        if (
            "\n" in comment
            or raw[start : node.start_byte].strip()
            or raw[node.end_byte : end].strip()
        ):
            raise address_comment_refused("candidate ADDRESS comment must occupy one full line")
        if module:
            removals.append((start, end))
    if not module:
        return candidate
    for start, end in reversed(removals):
        raw = raw[:start] + raw[end:]
    candidate = raw.decode("utf-8")
    ((_, line),) = find_c_function_definitions(candidate)
    newline = "\r\n" if "\r\n" in candidate else "\n"
    lines = split_source_lines(candidate, keepends=True)
    lines.insert(line - 1, address_comment(module, va) + newline)
    return "".join(lines)


def _run_candidate(
    config: WorkerConfig, req: VerifyRequest | ApplyCandidateRequest, *, apply: bool
) -> dict[str, Any]:
    applying = req if isinstance(req, ApplyCandidateRequest) and apply else None
    from rebrew.c_syntax.parser import find_c_function_definitions
    from rebrew.config import load_config
    from rebrew.utils import portable_path_parts

    if len(req.candidate.encode()) > CANDIDATE_MAX_BYTES:
        raise invalid_request(f"the candidate is over {CANDIDATE_MAX_BYTES} bytes")
    definitions = find_c_function_definitions(req.candidate)
    if len(definitions) != 1:
        names = ", ".join(name for name, _ in definitions)
        raise OpsError(
            f"the candidate defines {len(definitions)} functions ({names}); it must define exactly one"
            if definitions
            else "the candidate defines no C function; it must define exactly one",
            code=CANDIDATE_NOT_ONE_FUNCTION,
            status=400,
        )
    name = definitions[0][0]
    if req.va < 0 or not 1 <= req.size <= 1048576:
        raise invalid_request("invalid function extent")
    check_manifest_size(req.files)
    paths = [f.path for f in req.files]
    if (
        len(set(paths)) != len(paths)
        or req.source not in paths
        or any(not portable_path_parts(path) for path in paths)
    ):
        raise invalid_request("invalid retained source manifest paths")
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="verify-candidate-", dir=scratch) as temp:
        root = Path(temp).resolve()
        destination = stage_retained_snapshot(
            config,
            root,
            req.files,
            req.rebrew_target,
            req.sha256,
            req.binary_key,
            req.binary_url,
            exclusive=False,
        )
        source = project_file(root, req.source, "source")
        if source.suffix.lower() != ".c":
            raise invalid_request("candidate source must be a C file")
        if sha256_file(source) != req.source_sha256:
            raise invalid_request("source does not match its retained digest")
        from rebrew.metadata.bindings import module_for_va

        module = module_for_va(source, req.va)
        if apply and not module:
            raise invalid_request("the function has no address anchor in the retained source")
        candidate = _candidate_with_anchor(req.candidate, module, req.va)
        source.write_text(candidate, encoding="utf-8")
        rewritten = apply_project_cflags(root, req.rebrew_target, req.project_cflags)
        cfg = load_config(root, target=req.rebrew_target)
        confined_snapshot_config(cfg, root)
        retained_compile_refusal(cfg, [source])
        from rebrew.c_syntax.parser import function_signatures
        from rebrew.metadata.bindings import derive_c_symbol

        symbol = derive_c_symbol(name, function_signatures(req.candidate).get(name, ""))
        # The registry is the snapshot's: an apply returns it, a verification compares it
        # with the renamed copy after the run.
        registry, renamed = follow_candidate_name(
            cfg, root, paths, module, req.va, name, symbol, always=apply
        )
        flags = checked_cflags(req.cflags)
        result = run_rebrew(
            [
                "test",
                "--json",
                *([] if apply else ["--no-promote"]),
                *_flag(isinstance(req, VerifyRequest) and req.instructions, "--instructions"),
                *([f"--cflags={flags}"] if flags else []),
                f"--target={req.rebrew_target}",
                f"--va=0x{req.va:x}",
                f"--size={req.size}",
                f"--symbol={symbol}",
                "--",
                str(source),
            ],
            root,
            ops_binding("COMMAND_TIMEOUT_SECONDS", COMMAND_TIMEOUT_SECONDS),
            outcome_exit=True,
        )
        if sha256_file(destination) != req.sha256 or (
            not apply and source.read_bytes() != candidate.encode("utf-8")
        ):
            raise invalid_request("snapshot candidate or binary changed during verification")
        if (
            not apply
            and renamed is not None
            and project_file(root, registry, "function registry").read_bytes() != renamed
        ):
            raise invalid_request("snapshot source changed during verification")
        for entry in req.files:
            if entry.path in {req.source, registry}:
                continue
            path = project_file(root, entry.path, "source file")
            size, digest = (
                rewritten
                if rewritten and entry.path == "rebrew-project.toml"
                else (entry.size, entry.digest)
            )
            if path.stat().st_size != size or sha256_file(path) != digest:
                raise invalid_request("snapshot source changed during verification")
        from rebrew.workspace.status import comparison_verdict_valid

        result["source"] = req.source
        result["compile_inputs"] = _compile_inputs(
            root, source, candidate.encode("utf-8"), result.get("compile")
        )
        result["verdict_valid"] = comparison_verdict_valid(result, req.source, req.va, req.size)
        if applying is not None:
            return _applied(root, applying, result, registry)
        return result


def _compile_inputs(
    root: Path, source: Path, compiled: bytes, remote: Any = None
) -> dict[str, Any]:
    """The project inputs a retained candidate compile read, in the descriptor shape.

    ``files`` are the compiled source, the project config (flags, toolchain)
    and each project header the remote compile shipped in its include bundle
    (*remote*, the ``compile`` block ``rebrew test --json`` reports); a header
    whose bytes are not the snapshot's is refused.  ``documents`` is the
    library settings document that overrides the flags, if any.
    """
    from rebrew.metadata.functions import nearest_library_metadata_path
    from rebrew.metadata.storage import metadata_store

    config = root / "rebrew-project.toml"
    files = [
        {
            "path": source.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(compiled).hexdigest(),
        },
        {"path": config.name, "sha256": sha256_file(config)},
    ]
    shipped = remote.get("includes", []) if isinstance(remote, dict) else []
    if not isinstance(shipped, list):
        raise OpsError("the compile reported a malformed include bundle")
    for header in shipped:
        if not isinstance(header, dict) or not all(
            isinstance(header.get(key), str) for key in ("path", "sha256")
        ):
            raise OpsError("the compile reported a malformed include bundle")
        path = project_file(root, header["path"], "include")
        if sha256_file(path) != header["sha256"]:
            raise invalid_request("snapshot source changed during verification")
        files.append({"path": header["path"], "sha256": header["sha256"]})
    documents = []
    library = nearest_library_metadata_path(source.parent, root)
    if library is not None:
        digest = metadata_store(library).digest()
        if digest is None:
            raise invalid_request("the library settings changed during verification")
        documents.append({"path": library.relative_to(root).as_posix(), "logical_sha256": digest})
    return {
        "files": sorted(files, key=lambda item: item["path"].encode("utf-8")),
        "documents": documents,
    }


def follow_candidate_name(
    cfg: Any,
    root: Path,
    staged: Iterable[str],
    module: str,
    va: int,
    name: str,
    symbol: str,
    *,
    always: bool = False,
) -> tuple[str, bytes | None]:
    """Point a staged snapshot's registry entry for *va* at a candidate's *name* and *symbol*.

    rebrew refuses to scan a source whose address anchor names a function other than the
    registry does, so a candidate compiled in a private snapshot (*root*) takes its function's
    registry entry with it. Nothing happens without an anchor *module*, or when the registry
    already holds *name* unless *always* (an apply, which records the derived symbol). A name or
    symbol another function of *module* holds is refused, 409 ``candidate-name-taken``.

    Answers the registry's snapshot-relative path and its bytes after the rename, which the
    caller checks again after the run, or ``("", None)`` when nothing changed.
    """
    if not module or (not always and _registry_name(cfg, module, va) == name):
        return "", None
    _refuse_taken_name(cfg, module, va, name, symbol)
    if cfg.metadata_dir.resolve() != root:
        raise invalid_request("the retained project keeps its function registry outside its root")
    registry = _applied_registry(root, list(staged))
    _move_identity(cfg, module, va, name, symbol)
    return registry, project_file(root, registry, "function registry").read_bytes()


def _registry_name(cfg: Any, module: str, va: int) -> str:
    """The name the snapshot's registry holds for the function at *va*; empty for none."""
    from rebrew.metadata.functions import get_entry

    return str(get_entry(cfg.metadata_dir, va, module).get("name", ""))


def _refuse_taken_name(cfg: Any, module: str, va: int, name: str, symbol: str) -> None:
    """Refuse a candidate naming its function as another function of *module* is named, or by its symbol."""
    from rebrew.metadata.functions import load_metadata

    entries = load_metadata(cfg.metadata_dir, deepcopy=False)
    for (other_module, other_va), entry in sorted(entries.items()):
        if other_module != module or other_va == va:
            continue
        if name == entry.get("name") or symbol == entry.get("symbol"):
            current = entries.get((module, va), {}).get("name", "")
            raise OpsError(
                f"the candidate names the function at 0x{va:08x}"
                f"{f' ({current})' if current else ''} {name!r}, "
                f"the name of the function at 0x{other_va:08x}; give it another name",
                code=CANDIDATE_NAME_TAKEN,
                status=409,
            )


def _move_identity(cfg: Any, module: str, va: int, name: str, symbol: str) -> None:
    """Point the function's registry entry at the candidate's name and symbol through rebrew's identity writer.

    rebrew refuses to test a source whose address anchor names a function other than the registry's, so this
    runs before the comparison, on the snapshot's registry only. *symbol* is the one rebrew derives from the
    candidate's prototype (``_add@8`` for a stdcall ``add``): the comparison names the same symbol, which an
    apply needs to record its STATUS.
    """
    from rebrew.metadata.functions import record_function_rows

    record_function_rows(
        cfg.metadata_dir,
        [{"module": module, "va": va, "identity": {"symbol": symbol, "name": name}, "fields": {}}],
        overwrite_name=True,
        updated_by="rename",
    )


def _applied_registry(root: Path, staged: list[str]) -> str:
    """The staged registry an apply writes: the one the config reads, never beside the other."""
    from rebrew.metadata.sqlite import DATABASE_FILENAME

    backend = retained_metadata_backend(root)
    registry, ignored = (
        (APPLY_METADATA_FILE, DATABASE_FILENAME)
        if backend == "toml"
        else (DATABASE_FILENAME, APPLY_METADATA_FILE)
    )
    if ignored in staged:
        raise invalid_request(
            f"the retained project carries {ignored}, which its {backend} metadata ignores"
        )
    if registry not in staged:
        raise invalid_request(f"the retained project carries no {registry}")
    return registry


def _applied(
    root: Path, req: ApplyCandidateRequest, result: dict[str, Any], registry: str
) -> dict[str, Any]:
    """Finish an apply: refuse a result that is not a byte match, return the changed files."""
    from rebrew.metadata.sqlite import (
        DATABASE_FILENAME,
        metadata_database_documents,
        snapshot_metadata_database,
    )

    if result.get("status") == "NOT_RUN":
        error = result.get("error")
        logger.warning(
            "%s apply_candidate: the compile did not run: %s trace_id=%s",
            request_id(),
            escape_log_text(str(result.get("message", ""))),
            trace_id(),
        )
        wait = error.get("retry_after") if isinstance(error, dict) else None
        raise OpsError(
            not_run_detail(error),
            code=COMPILE_NOT_RUN,
            status=503,
            retry_after=math.ceil(wait) if isinstance(wait, (int, float)) else None,
        )
    if result.get("status") not in {"EXACT", "RELOC"}:
        raise invalid_request(f"the candidate no longer matches: {result.get('status')}")
    changed = []
    for relative in (req.source, registry):
        if relative == DATABASE_FILENAME:
            # The live store may hold a rollback journal; publish a closed backup.
            with tempfile.TemporaryDirectory(prefix="applied-metadata-", dir=root.parent) as temp:
                try:
                    copy = snapshot_metadata_database(root, Path(temp) / DATABASE_FILENAME)
                    metadata_database_documents(copy)
                except (ValueError, OSError, RebrewError) as exc:
                    raise invalid_request(f"the applied metadata store is invalid: {exc}") from exc
                data = copy.read_bytes()
        else:
            data = project_file(root, relative, "applied file").read_bytes()
        if len(data) > 1024 * 1024:
            raise invalid_request("an applied file exceeds the 1 MiB limit")
        changed.append(
            {
                "path": relative,
                "size": len(data),
                "digest": hashlib.sha256(data).hexdigest(),
                "data": base64.b64encode(data).decode("ascii"),
            }
        )
    return {
        "result": result,
        "files": changed,
        "metadata": _published_metadata(root, changed),
        "attested_registry_digest": attested_registry_digest(changed),
    }


def _published_metadata(root: Path, published: list[dict[str, Any]]) -> dict[str, Any]:
    """Describe *root*'s metadata as published: a returned file's digest replaces the live one's.

    A SQLite store is published as a closed copy, whose bytes differ from the live database.
    """
    from rebrew.metadata_sets import describe_metadata

    digests = {item["path"]: item["digest"] for item in published}
    try:
        descriptor = describe_metadata(root, exclusive=False)
    except (OSError, ValueError, RebrewError) as exc:
        raise invalid_request(f"the applied metadata is invalid: {exc}") from exc
    for item in descriptor["files"]:
        item["sha256"] = digests.get(item["path"], item["sha256"])
    return descriptor


def _run_target_command(
    config: WorkerConfig,
    req: VerifyTargetRequest | BuildRequest,
    arguments: list[str],
) -> dict[str, Any]:
    """Run a whole-target rebrew command live or against a retained snapshot.

    Retained snapshots force the compile refusal; live runs refuse remote
    compilation of header-reading sources.  ``project_cflags`` requires the
    snapshot so the flags land on the private copy only.
    """
    from rebrew.config import load_config
    from rebrew.source.discovery import iter_sources

    if req.files:
        with retained_target_snapshot(
            config,
            req.files,
            req.rebrew_target,
            req.sha256,
            req.binary_key,
            req.binary_url,
            req.project_cflags,
        ) as snapshot:
            with step("loading the project config"):
                cfg = load_config(snapshot, target=req.rebrew_target)
            with step("checking the compiler is offered"):
                refuse_compiler_not_offered(cfg)
            with step("checking the sources for a remote compile"):
                retained_compile_refusal(cfg, iter_sources(cfg.reversed_dir, cfg))
            return run_rebrew(
                [*arguments, f"--target={req.rebrew_target}"],
                snapshot,
                SEARCH_TIMEOUT_SECONDS,
                outcome_exit=True,
            )
    if req.project_cflags:
        raise invalid_request("project_cflags needs a retained source snapshot")
    root = project_root(config, req.project_dir)
    with step("loading the project config"):
        cfg = target_config(root, req.sha256)
    with step("checking the compiler is offered"):
        refuse_compiler_not_offered(cfg)
    with step("checking the sources for a remote compile"):
        remote_header_refusal(cfg, iter_sources(cfg.reversed_dir, cfg))
    return run_rebrew(
        [*arguments, *target_options(root, req.sha256)],
        root,
        SEARCH_TIMEOUT_SECONDS,
        outcome_exit=True,
    )


def verify_target(config: WorkerConfig, req: VerifyTargetRequest) -> dict[str, Any]:
    """Re-verify every source of the target (``rebrew verify --json``); a mismatch is a result."""
    if req.files and not req.no_promote:
        raise invalid_request("retained target verification requires no_promote")
    arguments = [
        "verify",
        "--json",
        *_flag(req.no_promote, "--no-promote"),
        *_flag(req.instructions, "--instructions"),
    ]
    if req.files:
        arguments.append("--no-promote")
    return _run_target_command(config, req, arguments)


def build(config: WorkerConfig, req: BuildRequest) -> dict[str, Any]:
    """Splice every matched function back into the target and compare the image.

    ``rebrew build round-trip --json``; the rebuilt image is written beside the
    target's binary as ``<binary>.reasm``.  A byte difference is a result.
    """
    arguments = ["build", "round-trip", "--json", *_flag(req.fix_headers, "--fix-headers")]
    return _run_target_command(config, req, arguments)


def skeleton(config: WorkerConfig, req: SkeletonRequest) -> dict[str, Any]:
    """The C skeleton ``rebrew skeleton`` would write for ``va``, without writing it.

    ``name`` names the function; empty means ``FUN_<va>``.
    """
    from rebrew.binary.analysis import is_inside
    from rebrew.config import target_module
    from rebrew.skeleton import generate_skeleton

    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    va = address_va(req.va)
    if not is_inside(load_binary(cfg.target_binary), va):
        raise invalid_request(f"VA 0x{va:x} is outside the binary image")
    ghidra_name = req.name or f"FUN_{va:08x}"
    return {"source": generate_skeleton(cfg, va, ghidra_name, target_module(cfg), req.name or None)}


def coverage_report(config: WorkerConfig, req: CoverageReportRequest) -> dict[str, Any]:
    """The target's decomp.dev progress report (objdiff ``report.json``, version 2).

    ``report`` is the document ``rebrew coverage report --decomp-dev``
    writes; ``summary`` its totals (functions, code bytes, fuzzy match).
    """
    from rebrew.config import load_config
    from rebrew.coverage.report import decomp_dev_report

    if req.files:
        if req.coverage_input.version != 1 or not req.coverage_input_digest:
            verified_coverage_inputs_required()
        with retained_target_snapshot(
            config,
            req.files,
            req.rebrew_target,
            req.sha256,
            req.binary_key,
            req.binary_url,
        ) as snapshot:
            cfg = load_config(snapshot, target=req.rebrew_target)
            trusted = checked_coverage_input(snapshot, req)
            try:
                report, summary = decomp_dev_report(cfg, trusted=trusted)
            except ValueError as exc:
                raise OpsError(
                    bounded(str(exc)), code=COVERAGE_INPUT_UNVERIFIED, status=409
                ) from None
            checked_coverage_input(snapshot, req)
            return {"summary": summary, "report": report}
    if req.coverage_input.version or req.coverage_input_digest or req.verification_records:
        raise invalid_request("coverage input requires a retained snapshot")
    cfg = target_config(project_root(config, req.project_dir), req.sha256)
    report, summary = decomp_dev_report(cfg)
    return {"summary": summary, "report": report}


def flag_search(config: WorkerConfig, req: FlagSearchRequest) -> dict[str, Any]:
    """Run a bounded flag or compiler profile sweep for one project source.

    ``count_only`` stages the same snapshot and answers ``{"candidates": N}``, the
    compiles the search would make, so a caller can price it before it runs.
    """
    if req.va < 0 or req.tier not in FLAG_SEARCH_TIERS:
        raise invalid_request("invalid address or flag search tier")
    if not req.compare_toolchains and (req.toolchains or req.exclude_toolchains or req.with_flags):
        raise invalid_request("toolchain selection requires a toolchain comparison")
    if req.compare_toolchains and not req.with_flags and req.tier != "targeted":
        raise invalid_request("tier requires flag search during toolchain comparison")
    if any(
        len(value) > 1024 or "\x00" in value for value in (req.toolchains, req.exclude_toolchains)
    ):
        raise invalid_request("toolchain selectors must be at most 1024 characters")
    from rebrew.config import load_config

    check_manifest_size(req.files)
    paths = [f.path for f in req.files]
    if len(set(paths)) != len(paths) or req.source not in paths:
        raise invalid_request("invalid retained source manifest paths")
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="flag-search-", dir=scratch) as temp:
        root = Path(temp).resolve()
        destination = stage_retained_snapshot(
            config,
            root,
            req.files,
            req.rebrew_target,
            req.sha256,
            req.binary_key,
            req.binary_url,
            exclusive=True,
        )
        source = project_file(root, req.source, "source")
        if sha256_file(source) != req.source_sha256:
            raise invalid_request("source does not match its retained digest")
        cfg = load_config(root, target=req.rebrew_target)
        remote_header_refusal(cfg, [source])
        arguments = [
            "match",
            "toolchains" if req.compare_toolchains else "flags",
            "--json",
            "--jobs=2",
            f"--va=0x{req.va:x}",
        ]
        if not req.compare_toolchains or req.with_flags:
            arguments.append(f"--tier={req.tier}")
        if req.compare_toolchains:
            if not req.with_flags:
                arguments.remove("--jobs=2")
            arguments += _flag(req.with_flags, "--flags")
            if req.toolchains:
                arguments.append(f"--toolchains={req.toolchains}")
            if req.exclude_toolchains:
                arguments.append(f"--exclude-toolchains={req.exclude_toolchains}")
        if req.count_only:
            arguments.append("--count")
        result = run_rebrew(
            [*arguments, f"--target={req.rebrew_target}", "--", str(source)],
            root,
            SEARCH_TIMEOUT_SECONDS,
            outcome_exit=True,
        )
        if sha256_file(source) != req.source_sha256 or sha256_file(destination) != req.sha256:
            raise invalid_request("snapshot source or binary changed during flag search")
        return result


def data_list(config: WorkerConfig, req: DataListRequest) -> dict[str, Any]:
    """The target's global data inventory and section summary (``rebrew data list --json``)."""
    from rebrew.config import load_config

    if req.files:
        # Same contract as ``report`` and ``coverage_report``: a retained
        # snapshot that names a coverage input must carry the verified one,
        # so a caller cannot list a target under an input the other two ops
        # would refuse.
        if req.coverage_input.version != 1 or not req.coverage_input_digest:
            verified_coverage_inputs_required()
        with retained_target_snapshot(
            config,
            req.files,
            req.rebrew_target,
            req.sha256,
            req.binary_key,
            req.binary_url,
        ) as snapshot:
            load_config(snapshot, target=req.rebrew_target)
            checked_coverage_input(snapshot, req)
            return run_rebrew(
                ["data", "list", "--json", f"--target={req.rebrew_target}"],
                snapshot,
                ops_binding("COMMAND_TIMEOUT_SECONDS", COMMAND_TIMEOUT_SECONDS),
            )
    root = project_root(config, req.project_dir)
    return run_rebrew(
        ["data", "list", "--json", *target_options(root, req.sha256)],
        root,
        ops_binding("COMMAND_TIMEOUT_SECONDS", COMMAND_TIMEOUT_SECONDS),
    )


def data_set(config: WorkerConfig, req: DataSetRequest) -> dict[str, Any]:
    """Set non-verdict fields of the data row at ``va`` (``rebrew data set --json``).

    Every non-empty field is set at once; ``size`` 0 leaves the size alone.
    """
    root = project_root(config, req.project_dir)
    va = address_va(req.va)
    options = [
        f"{option}=0x{va:x}={value}"
        for field_name, option in DATA_FIELD_OPTIONS.items()
        if (value := getattr(req, field_name))
    ]
    if req.size < 0:
        raise invalid_request(f"size must not be negative, got {req.size}")
    if req.size:
        options.append(f"--size=0x{va:x}={req.size}")
    if not options:
        raise invalid_request("data_set needs at least one field to set")
    arguments = ["data", "set", "--json", *options, *_flag(req.dry_run, "--dry-run")]
    return run_rebrew(
        [*arguments, *target_options(root, req.sha256)],
        root,
        ops_binding("COMMAND_TIMEOUT_SECONDS", COMMAND_TIMEOUT_SECONDS),
    )


def retained_source_operation(config: WorkerConfig, req: SnapshotMutationRequest) -> dict[str, Any]:
    """Run an operation against an isolated retained target."""
    from rebrew.ops.snapshot_mutations import snapshot_mutation

    with refusing_disagreeing_records():
        return snapshot_mutation(config, req)


def decompile_snapshot(config: WorkerConfig, req: DecompileSnapshotRequest) -> dict[str, Any]:
    """Run the operation over a verified retained snapshot."""
    from rebrew.binary.analysis import is_inside
    from rebrew.c_syntax.name_decomp import apply_known_names
    from rebrew.c_syntax.struct_recover import existing_structs
    from rebrew.decompiler import fetch_decompilation
    from rebrew.ghidra import McpError
    from rebrew.ops.named_snapshot import retained_snapshot
    from rebrew.source.discovery import iter_library_headers, iter_sources

    if req.backend not in DECOMPILER_BACKENDS:
        raise invalid_request("invalid retained decompilation request")
    refuse_unoffered_decompiler(req.backend)
    va = address_va(req.va)
    with retained_snapshot(config, req) as (root, cfg, retained, verify_files):
        if not is_inside(load_binary(cfg.target_binary), va):
            raise invalid_request(f"VA 0x{va:x} is outside the binary image")
        sources = [
            *iter_sources(cfg.reversed_dir, cfg),
            *iter_library_headers(cfg.reversed_dir, cfg),
        ]
        if any(path.is_symlink() or path.resolve() not in retained for path in sources):
            raise invalid_request("source is not in the retained snapshot")
        definitions = existing_structs(sources)
        verify_files()
        try:
            code, backend = fetch_decompilation(req.backend, cfg.target_binary, va, root)
        except McpError as exc:
            raise ghidra_outage(exc) from None
        if not code:
            raise no_decompilation(req.backend, va)
        verify_files()
        pointer_width = int(getattr(cfg, "pointer_size", 4) or 4)
        code = apply_known_names(code, definitions, pointer_width=pointer_width).code
        verify_files()
    return {
        "code": code,
        "backend": backend,
        "source_revision": req.source_revision,
        "source_snapshot_sha256": req.source_snapshot_sha256,
        "analysis_manifest_sha256": req.analysis_manifest_sha256,
        "generation": req.generation,
    }


def security_scan_snapshot(config: WorkerConfig, req: SecuritySnapshotRequest) -> dict[str, Any]:
    """Run the operation over a verified retained snapshot."""
    from rebrew.ops.named_snapshot import retained_snapshot
    from rebrew.security_scan import SEVERITY_ORDER, filter_by_severity, scan_paths
    from rebrew.source.discovery import EXCLUDE_DIRS, iter_sources

    if req.min_severity not in SEVERITY_ORDER:
        raise invalid_request(f"min_severity must be one of {', '.join(SEVERITY_ORDER)}")
    with retained_snapshot(config, req) as (root, cfg, retained, verify_files):
        directory = cfg.reversed_dir.resolve()
        if not directory.is_relative_to(root):
            raise invalid_request("security source directory escapes the snapshot")
        expected = {
            path
            for path in retained
            if path.is_relative_to(directory)
            and path.suffix.lower() == ".c"
            and not any(part in EXCLUDE_DIRS for part in path.relative_to(directory).parts[:-1])
        }
        published = {root / entry.path for entry in req.files}
        if not expected.issubset(published):
            raise invalid_request("security source is not in the published snapshot")
        paths = iter_sources(directory) if directory.is_dir() else []
        if (
            any(path.is_symlink() or path.resolve() not in retained for path in paths)
            or set(paths) != expected
        ):
            raise invalid_request("security sources differ from the retained snapshot")
        verify_files()
        try:
            findings = scan_paths(paths, strict=True)
        except OSError:
            raise invalid_request("retained security source is unreadable") from None
        verify_files()
        for finding in findings:
            path = project_file(root, finding["file"].removeprefix(str(root) + "/"), "source")
            if path not in expected:
                raise invalid_request("security finding escapes the retained snapshot")
            finding["file"] = path.relative_to(root).as_posix()
        by_severity = dict.fromkeys(SEVERITY_ORDER, 0)
        for finding in findings:
            by_severity[str(finding["severity"])] += 1
        result = filter_by_severity(
            {
                "root": directory.relative_to(root).as_posix(),
                "files_scanned": len(paths),
                "findings": findings,
                "count": len(findings),
                "by_severity": by_severity,
            },
            req.min_severity,
        )
    return {
        "result": result,
        "source_revision": req.source_revision,
        "source_snapshot_sha256": req.source_snapshot_sha256,
        "generation": req.generation,
        "analysis_manifest_sha256": req.analysis_manifest_sha256,
    }
