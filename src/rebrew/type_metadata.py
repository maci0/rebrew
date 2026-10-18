"""Stable type identities with target-specific compiler and native layout evidence."""

import hashlib
import json
import re
import shlex
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import tomlkit

from rebrew.c_parser import mask_msvc_syntax, parse_c_source
from rebrew.config import ProjectConfig
from rebrew.metadata.document import metadata_write_lock
from rebrew.metadata.functions import validate_identity_file
from rebrew.utils import (
    atomic_write_locked,
    load_toml_for_write_strict,
    preset_module_key,
    read_source_text,
)
from rebrew.verify_hash import entry_headers_fp

TYPE_METADATA_FILENAME = "rebrew-types.toml"
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
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
            raw[n.start_byte : n.end_byte].decode("utf-8")
            for n in name_nodes
            if n is not None and n.type == "type_identifier"
        }
        for name in names:
            counts[name] = counts.get(name, 0) + (2 if node.has_error else 1)
    return {name for name, count in counts.items() if count == 1}


def _validate(doc: Any) -> list[dict[str, Any]]:
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
                or set(entry) != _FIELDS
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
            for field in ("source_hash", "headers_hash", "context_hash", "binary_hash"):
                if not isinstance(entry[field], str) or not re.fullmatch(
                    r"[0-9a-f]{64}", entry[field]
                ):
                    raise ValueError(f"invalid type {field}")
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
    if not path.exists():
        return []
    return _validate(load_toml_for_write_strict(path, "type metadata"))


def _inputs(cfg: ProjectConfig, file: Path, symbol: str, cflags: str) -> dict[str, str]:
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
        "source_hash": hashlib.sha256(file.read_bytes()).hexdigest(),
        "headers_hash": entry_headers_fp(cfg, file, cflags),
        "context_hash": hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest(),
        "binary_hash": hashlib.sha256(cfg.target_binary.read_bytes()).hexdigest(),
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
            and declarator.text.decode() == spelling
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
            + "\n"
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
    record = _validate({"format": 1, "types": {identity: {module: entry}}})[0]
    path = directory / TYPE_METADATA_FILENAME
    preview = load_toml_for_write_strict(path, "type metadata")
    if path.exists():
        _validate(preview)
    else:
        preview["format"] = 1
        preview["types"] = tomlkit.table()
    preview["types"].setdefault(identity, {})[module] = entry
    _validate(preview)
    if not dry_run:
        compile_type(cfg, record)
    report = {**record, "dry_run": dry_run, "compiler_checked": not dry_run}
    if dry_run:
        return report
    with metadata_write_lock(directory, TYPE_METADATA_FILENAME):
        doc = load_toml_for_write_strict(path, "type metadata")
        if path.exists():
            _validate(doc)
        else:
            doc["format"] = 1
            doc["types"] = tomlkit.table()
        if _inputs(cfg, file, symbol, flags) != {
            key: entry[key]
            for key in ("source_hash", "headers_hash", "context_hash", "binary_hash")
        }:
            raise ValueError("type inputs changed during compilation; retry after reviewing them")
        if doc["types"].get(identity, {}).get(module) == entry:
            return report
        doc["types"].setdefault(identity, {})[module] = entry
        _validate(doc)
        atomic_write_locked(path, tomlkit.dumps(doc))
    return report


def check_types(cfg: ProjectConfig, *, compile_layouts: bool = False) -> list[dict[str, str]]:
    """Report invalid/stale bindings; compile only fresh records when requested."""
    findings = []
    try:
        records = load_types(cfg.metadata_dir)
    except (ValueError, OSError) as exc:
        return [{"id": "", "module": cfg.module, "issue": f"invalid type store: {exc}"}]
    known = {preset_module_key(m) for m in (getattr(cfg, "target_modules", None) or [cfg.module])}
    for record in records:
        issue = ""
        if record["module"] not in known:
            issue = "unknown target module"
        elif record["module"] != preset_module_key(cfg.module):
            continue
        else:
            try:
                file = (cfg.metadata_dir / record["file"]).resolve()
                file.relative_to(cfg.metadata_dir.resolve())
                inputs = _inputs(cfg, file, record["symbol"], record["cflags"])
                if any(record[key] != value for key, value in inputs.items()):
                    issue = "stale type evidence: source, headers, compiler context or native binary changed; review and rebind"
                elif compile_layouts:
                    compile_type(cfg, record)
            except (ValueError, OSError) as exc:
                issue = f"type binding cannot be checked: {exc}"
        if issue:
            findings.append({"id": record["id"], "module": record["module"], "issue": issue})
    return findings
