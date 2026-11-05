"""Stable type identities with target-specific compiler and native layout evidence."""

import re
lazy import hashlib
lazy import json
lazy import shlex
lazy from dataclasses import replace
lazy from pathlib import Path
lazy from tempfile import TemporaryDirectory
lazy from typing import Any

lazy import tomlkit

lazy from rebrew.c_parser import mask_msvc_syntax, parse_c_source
lazy from rebrew.config import ProjectConfig
lazy from rebrew.metadata.functions import validate_identity_file
lazy from rebrew.metadata.storage import metadata_store, metadata_write_lock
lazy from rebrew.utils import (
    path_identity,
    preset_module_key,
    read_source_text,
)
lazy from rebrew.verify_hash import entry_headers_fp

TYPE_METADATA_FILENAME = "rebrew-types.toml"
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")


def _source_sha256(path: Path) -> str:
    """Streamed SHA-256 hex digest of *path*'s bytes."""
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


_FIELDS = frozenset(
    {
        "file",
        "symbol",
        "size",
        "native_size",
        "extent",
        "evidence",
        "offsets",
        "cflags",
        "source_hash",
        "headers_hash",
        "context_hash",
        "binary_hash",
    }
)
_HASH_FIELDS = ("source_hash", "headers_hash", "context_hash", "binary_hash")


def struct_definition_names(source: str) -> set[str]:
    """Find unique parseable struct definitions by their typedef or tag name."""
    tree, raw = parse_c_source(mask_msvc_syntax(source))
    counts: dict[str, int] = {}
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        pending.extend(node.children)
        if node.type != "struct_specifier" or node.child_by_field_name("body") is None:
            continue
        parent = node.parent
        name_nodes = [node.child_by_field_name("name")]
        if parent is not None and parent.type == "type_definition":
            name_nodes.append(parent.child_by_field_name("declarator"))
        names = {
            raw[n.start_byte : n.end_byte].decode("utf-8", errors="surrogateescape")
            for n in name_nodes
            if n is not None and n.type == "type_identifier"
        }
        for name in names:
            counts[name] = counts.get(name, 0) + (2 if node.has_error else 1)
    return {name for name, count in counts.items() if count == 1}


def validate_type_document(doc: Any) -> list[dict[str, Any]]:
    """Validate a parsed ``rebrew-types.toml`` document and flatten its rows.

    *doc* must be exactly ``{"format": 1, "types": {...}}``.  Module names must
    already be in ``preset_module_key`` form, every row carries the complete
    field set (a contained ``.c``/``.h`` file, a C-identifier symbol, positive
    ``size`` within ``native_size``, an ``allocation``/``stride`` extent,
    non-empty evidence, offsets inside the C view, and SHA-256 hashes), and one
    ``(module, file, symbol)`` binding cannot belong to two type identities.
    Returns one row per type/module pair with the identity under ``"id"``, or
    raises ``ValueError`` for the first violation.
    """
    if (
        set(doc) != {"format", "types"}
        or not isinstance(doc["format"], int)
        or isinstance(doc["format"], bool)
        or doc["format"] != 1
        or not isinstance(doc["types"], dict)
    ):
        raise ValueError("type metadata requires format = 1 and a types table")
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for identity, modules in doc["types"].items():
        if (
            not isinstance(identity, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9.-]*", identity)
            or not isinstance(modules, dict)
            or not modules
        ):
            raise ValueError(f"invalid type identity {identity!r}")
        for module, entry in modules.items():
            if (
                not isinstance(module, str)
                or not module
                or preset_module_key(module) != module
                or not isinstance(entry, dict)
                or not _FIELDS
                <= set(entry)
                <= _FIELDS | {"path_history", "path_revalidation_required"}
            ):
                raise ValueError(f"invalid type record {identity!r}:{module!r}")
            file, symbol = entry["file"], entry["symbol"]
            if (
                not isinstance(file, str)
                or not file
                or validate_identity_file(file) != file
                or Path(file).suffix.lower() not in {".c", ".h"}
                or any(c in file for c in ("\\", '"', "\n", "\r"))
            ):
                raise ValueError("type file must be a contained C source or header")
            if not isinstance(symbol, str) or not _IDENTIFIER.fullmatch(symbol):
                raise ValueError("type symbol must be a C identifier")
            for field in ("size", "native_size"):
                if (
                    not isinstance(entry[field], int)
                    or isinstance(entry[field], bool)
                    or entry[field] <= 0
                ):
                    raise ValueError(f"type {field} must be a positive integer")
            if (
                entry["size"] > entry["native_size"]
                or not isinstance(entry["extent"], str)
                or entry["extent"] not in {"allocation", "stride"}
            ):
                raise ValueError("C view must fit the evidenced native allocation or stride")
            if (
                not isinstance(entry["evidence"], str)
                or not entry["evidence"].strip()
                or len(entry["evidence"]) > 2000
            ):
                raise ValueError("type evidence must contain 1–2000 characters")
            if not isinstance(entry["cflags"], str):
                raise ValueError("type cflags must be a string")
            offsets = entry["offsets"]
            if not isinstance(offsets, dict) or any(
                not isinstance(k, str)
                or not _IDENTIFIER.fullmatch(k)
                or not isinstance(v, int)
                or isinstance(v, bool)
                or not 0 <= v < entry["size"]
                for k, v in offsets.items()
            ):
                raise ValueError("type offsets require member identifiers within the C view")
            for field in _HASH_FIELDS:
                if not isinstance(entry[field], str) or not re.fullmatch(
                    r"[0-9a-f]{64}", entry[field]
                ):
                    raise ValueError(f"invalid type {field}")
            if (
                "path_revalidation_required" in entry
                and entry["path_revalidation_required"] is not True
            ):
                raise ValueError("type path revalidation marker must be true")
            history = entry.get("path_history")
            if history is not None:
                if not isinstance(history, list) or not history:
                    raise ValueError("type path history must be a nonempty list")
                for prior in history:
                    if (
                        not isinstance(prior, dict)
                        or set(prior) != _FIELDS | {"freshness"}
                        or prior["freshness"] != "unassessed"
                    ):
                        raise ValueError("invalid type path history")
                    validate_type_document(
                        {"format": 1, "types": {"prior": {module: {k: prior[k] for k in _FIELDS}}}}
                    )
            if entry.get("path_revalidation_required") and not history:
                raise ValueError("type path revalidation requires path history")
            binding = (module, file, symbol)
            if binding in seen:
                raise ValueError(
                    f"{module}:{file}:{symbol} is already bound to another type identity"
                )
            seen.add(binding)
            records.append({"id": identity, "module": module, **entry})
    return records


def load_types(directory: Path) -> list[dict[str, Any]]:
    """Read and validate the managed store, without creating it."""
    path = directory / TYPE_METADATA_FILENAME
    store = metadata_store(path)
    if not store.exists():
        return []
    return validate_type_document(store.read("type metadata", validate=validate_type_document))


def rehome_type_bindings(
    directory: Path,
    old: str,
    new: str,
    *,
    dry_run: bool = False,
    expected_digest: str | None = None,
) -> dict[str, Any]:
    """Retarget type owners while retaining prior evidence as explicitly unassessed history.

    This does not move a source or prove the destination compile context. Use
    inside the same coordinated transaction as source and other owner changes.
    """
    if old == new or any(
        validate_identity_file(path) != path or Path(path).suffix.lower() not in {".c", ".h"}
        for path in (old, new)
    ):
        raise ValueError("type rehome requires distinct contained C source paths")
    path = directory / TYPE_METADATA_FILENAME
    if not dry_run:
        from rebrew.metadata.coordinated import require_staged_source_move

        require_staged_source_move(directory, old, new)
    with metadata_write_lock(directory, TYPE_METADATA_FILENAME):
        store = metadata_store(path)
        before = store.digest()
        if before is None:
            return {"input_digest": None, "rows": [], "written": False}
        doc = store.read("type metadata", validate=validate_type_document, roundtrip=True)
        records = validate_type_document(doc)
        rows = [r for r in records if r["file"] == old]
        if any(r.get("path_revalidation_required") for r in rows):
            raise ValueError("rebind invalidated type evidence before moving it again")
        digest = hashlib.sha256(json.dumps([before, old, new], sort_keys=True).encode()).hexdigest()
        for row in rows:
            entry = doc["types"][row["id"]][row["module"]]
            history = list(entry.get("path_history", []))
            history.append({"freshness": "unassessed", **{k: row[k] for k in _FIELDS}})
            entry["file"] = new
            entry["path_history"] = history
            entry["path_revalidation_required"] = True
        validate_type_document(doc)
        if store.digest() != before:
            raise ValueError("type metadata changed while planning rehome")
        if not dry_run and rows:
            if expected_digest != digest:
                raise ValueError("type rehome digest does not match preview")
            store.write(doc, "type metadata")
        return {"input_digest": digest, "rows": rows, "written": bool(rows) and not dry_run}


def _inputs(
    cfg: ProjectConfig,
    file: Path,
    symbol: str,
    cflags: str,
    *,
    binary_hash: str | None = None,
) -> dict[str, str]:
    source, _ = read_source_text(file)
    if symbol not in struct_definition_names(source):
        raise ValueError(f"{symbol!r} has no unique parseable struct definition in {file}")
    context = {
        key: str(getattr(cfg, key, ""))
        for key in (
            "compiler_profile",
            "base_cflags",
            "compiler_includes",
            "shared_dir",
            "defines",
            "compiler_command",
            "compiler_runner",
            "recompile_url",
        )
    }
    context["cflags"] = cflags
    return {
        "source_hash": _source_sha256(file),
        "headers_hash": entry_headers_fp(cfg, file, cflags),
        "context_hash": hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest(),
        "binary_hash": binary_hash or _source_sha256(cfg.target_binary),
    }


def compile_type(cfg: ProjectConfig, record: dict[str, Any]) -> None:
    """Compile C89 sizeof/offsetof assertions with the target compiler; never link."""
    from rebrew.compiler.compile import compile_to_obj, resolve_include_flags
    from rebrew.utils import safe_shlex_split

    file = (cfg.metadata_dir / record["file"]).resolve()
    file.relative_to(cfg.metadata_dir.resolve())
    source, _ = read_source_text(file)
    tree, _ = parse_c_source(mask_msvc_syntax(source))
    # A bare tag requires `struct`; a typedef name is already a type expression.
    spelling = record["symbol"]
    pending = [tree.root_node]
    typedef = False
    while pending:
        node = pending.pop()
        pending.extend(node.children)
        declarator = node.child_by_field_name("declarator")
        if (
            node.type == "type_definition"
            and declarator is not None
            and declarator.text.decode("utf-8", errors="surrogateescape") == spelling
        ):
            typedef = True
    if not typedef:
        spelling = "struct " + spelling
    assertions = [f"sizeof({spelling}) == {record['size']}"]
    assertions.extend(
        f"offsetof({spelling}, {name}) == {offset}" for name, offset in record["offsets"].items()
    )
    with TemporaryDirectory(prefix="rebrew-types-") as temp:
        workdir = Path(temp) / "obj"
        workdir.mkdir()
        probe = Path(temp) / "layout.c"
        probe.write_text(
            '#include <stddef.h>\n#include "'
            + file.as_posix()
            + '"\n'
            + "\n".join(
                f"typedef char rebrew_layout_{i}[({expr}) ? 1 : -1];"
                for i, expr in enumerate(assertions)
            )
            + "\n",
            encoding="utf-8",
        )
        flags = resolve_include_flags(safe_shlex_split(record["cflags"]), file.parent, cfg.root)
        cfg = replace(
            cfg,
            base_cflags=shlex.join(
                resolve_include_flags(safe_shlex_split(cfg.base_cflags), file.parent, cfg.root)
            ),
        )
        includes = [str(file.parent)]
        if cfg.shared_dir and file.parent.is_relative_to(Path(cfg.shared_dir).resolve()):
            includes.append(str(cfg.shared_dir))
        obj, error = compile_to_obj(
            cfg, probe, flags, workdir, extra_include_dirs=includes, use_cache=False
        )
        if not obj:
            raise ValueError(f"type layout compile failed for {record['symbol']}: {error}")


def bind_type(
    cfg: ProjectConfig,
    identity: str,
    file: Path,
    symbol: str,
    size: int,
    native_size: int,
    extent: str,
    evidence: str,
    offsets: dict[str, int],
    *,
    cflags: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Bind or refresh one stable identity after compiler validation, atomically."""
    directory = cfg.metadata_dir.resolve()
    root = Path(
        getattr(cfg, "root", None) or metadata_store(directory / TYPE_METADATA_FILENAME).root
    )
    config = root / "rebrew-project.toml"

    def config_snapshot() -> tuple[bytes | None, dict[str, Any]]:
        return (config.read_bytes() if config.is_file() else None, path_identity(config))

    initial_config = config_snapshot()
    if initial_config[0] is not None and isinstance(cfg, ProjectConfig):
        from rebrew.config import load_config

        current = load_config(cfg.root, target=cfg.target_name)
        if config_snapshot() != initial_config or current.as_dict() != cfg.as_dict():
            raise ValueError("type target configuration changed; reload and review")
    file = (directory / file).resolve()
    relative = file.relative_to(directory).as_posix()
    module = preset_module_key(cfg.module)
    flags = cfg.cflags if cflags is None else cflags
    entry = {
        "file": relative,
        "symbol": symbol,
        "size": size,
        "native_size": native_size,
        "extent": extent,
        "evidence": evidence.strip(),
        "offsets": offsets,
        "cflags": flags,
        **_inputs(cfg, file, symbol, flags),
    }
    record = validate_type_document({"format": 1, "types": {identity: {module: entry}}})[0]
    path = directory / TYPE_METADATA_FILENAME
    selected_store = metadata_store(path)
    before_digest = selected_store.digest()
    preview = selected_store.read("type metadata", validate=validate_type_document, roundtrip=True)
    if metadata_store(path).exists():
        validate_type_document(preview)
    else:
        preview["format"] = 1
        preview["types"] = tomlkit.table()
    previous = preview["types"].get(identity, {}).get(module, {})
    if previous.get("path_history"):
        entry["path_history"] = previous["path_history"]
    preview["types"].setdefault(identity, {})[module] = entry
    validate_type_document(preview)
    if not dry_run:
        if selected_store.name not in {"toml", "sqlite"}:
            raise ValueError("type binding requires the TOML or SQLite backend")
        compile_type(cfg, record)
    report = {**record, "dry_run": dry_run, "compiler_checked": not dry_run}
    if dry_run:
        return report
    from rebrew.metadata.coordinated import coordinated_inputs, coordinated_transaction

    if config_snapshot() != initial_config:
        raise ValueError("type project configuration changed during compilation")
    watched = [file]
    binary = getattr(cfg, "target_binary", None)
    if binary is not None and Path(binary).is_file():
        watched.append(Path(binary))
    expected = coordinated_inputs(directory, [], watched=watched)

    def validate_inputs() -> None:
        if config_snapshot() != initial_config:
            raise ValueError("type project configuration changed during compilation")
        if _inputs(cfg, file, symbol, flags) != {key: entry[key] for key in _HASH_FIELDS}:
            raise ValueError("type inputs changed during compilation; retry after reviewing them")

    with coordinated_transaction(
        directory,
        [],
        expected_inputs=expected,
        watched=watched,
        validate=validate_inputs,
        validate_after=validate_inputs,
        allow_unconfigured=True,
    ):
        doc = metadata_store(path).read(
            "type metadata", validate=validate_type_document, roundtrip=True
        )
        if metadata_store(path).exists():
            validate_type_document(doc)
        else:
            doc["format"] = 1
            doc["types"] = tomlkit.table()
        if metadata_store(path).digest() != before_digest:
            raise ValueError("type metadata changed during compilation; retry after reviewing it")
        if doc["types"].get(identity, {}).get(module) == entry:
            return report
        doc["types"].setdefault(identity, {})[module] = entry
        validate_type_document(doc)
        metadata_store(path).write(doc, "type metadata")
    return report


def check_types(cfg: ProjectConfig, *, compile_layouts: bool = False) -> list[dict[str, str]]:
    """Report invalid/stale bindings; compile only fresh records when requested."""
    findings = []
    try:
        records = load_types(cfg.metadata_dir)
    except (ValueError, OSError) as exc:
        return [{"id": "", "module": cfg.module, "issue": f"invalid type store: {exc}"}]
    known = {preset_module_key(m) for m in (getattr(cfg, "target_modules", None) or [cfg.module])}
    # Every record measures the same target binary. Hash it on the first
    # usable record instead of re-reading the image once per record.
    binary_hash: str | None = None
    for record in records:
        issue = ""
        if record["module"] not in known:
            issue = "unknown target module"
        elif record["module"] != preset_module_key(cfg.module):
            continue
        elif record.get("path_revalidation_required"):
            issue = "stale type evidence: source path changed; review and rebind"
        else:
            try:
                file = (cfg.metadata_dir / record["file"]).resolve()
                file.relative_to(cfg.metadata_dir.resolve())
                if binary_hash is None:
                    binary_hash = _source_sha256(cfg.target_binary)
                inputs = _inputs(
                    cfg, file, record["symbol"], record["cflags"], binary_hash=binary_hash
                )
                if any(record[key] != value for key, value in inputs.items()):
                    issue = "stale type evidence: source, headers, compiler context or native binary changed; review and rebind"
                elif compile_layouts:
                    compile_type(cfg, record)
            except (ValueError, OSError) as exc:
                issue = f"type binding cannot be checked: {exc}"
        if issue:
            findings.append({"id": record["id"], "module": record["module"], "issue": issue})
    return findings
