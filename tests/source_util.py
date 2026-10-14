"""Build source fixtures with address anchors and explicit canonical metadata."""

from pathlib import Path
from typing import Any, SupportsIndex, override

from rebrew.c_parser import find_c_function_definitions, find_extern_variables
from rebrew.metadata.anchors import parse_address_anchors
from rebrew.metadata.bindings import derive_c_symbol
from rebrew.metadata.data import record_data_rows, set_data_fields_batch
from rebrew.metadata.document import parse_metadata_key, qualified_key
from rebrew.metadata.functions import (
    get_entry,
    identity_file,
    record_function_identity,
    set_fields,
    update_source_status,
)
from rebrew.workspace.config import walk_up_to_root


def write_source(
    path: Path,
    text: str,
    *,
    metadata_fields: dict[str, dict[str, Any]] | None = None,
    metadata_dir: Path | None = None,
    encoding: str = "utf-8",
    **kwargs: Any,
) -> int:
    """Write C and explicit fixture state through the production metadata APIs."""
    if isinstance(text, SourceFixture):
        metadata_fields = {**text.metadata_fields, **(metadata_fields or {})}
    if metadata_fields is None:
        if path.name in {"rebrew-functions.toml", "rebrew-data.toml", "rebrew-source.toml"}:
            return write_store_fixture(path, text, encoding=encoding, **kwargs)
        return path.write_text(text, encoding=encoding, **kwargs)
    written = path.write_text(text, encoding=encoding, **kwargs)
    if metadata_dir is None:
        project = walk_up_to_root(path.parent)
        fixture_root = next(
            (
                parent
                for parent in (path.parent, *path.parents)
                if parent.parent.name.startswith("pytest-")
            ),
            path.parent,
        )
        metadata_dir = project or fixture_root
        if project is not None:
            for parent in (path.parent, *path.parent.parents):
                if (parent / "rebrew-functions.toml").is_file():
                    metadata_dir = parent
                if parent == project:
                    break
    definitions = find_c_function_definitions(text)
    variables = find_extern_variables(text, include_definitions=True)
    rows: dict[str, dict[str, Any]] = {}
    for key, fields in (metadata_fields or {}).items():
        parsed = parse_metadata_key(key)
        if parsed is None:
            raise ValueError(f"bad fixture identity {key!r}")
        canonical = qualified_key(*parsed)
        rows[canonical] = {**rows.get(canonical, {}), **fields}
    anchors = parse_address_anchors(text)
    identities = {(a.module, a.va): a for a in anchors}
    for address in anchors:
        rows.setdefault(f"{address.module}.0x{address.va:08x}", {})
    for qualified, raw in rows.items():
        parsed = parse_metadata_key(qualified)
        if parsed is None:
            raise ValueError(f"bad fixture identity {qualified!r}")
        module, va = parsed
        anchor = identities.get(parsed)
        fields = dict(raw)
        kind = fields.pop("kind", anchor.kind if anchor is not None else "FUNCTION")
        default_name = anchor.name if anchor is not None else ""
        if not default_name:
            if kind in {"DATA", "GLOBAL", "STRING", "VTABLE"} and len(variables) == 1:
                default_name = variables[0].name
            elif (
                kind not in {"DATA", "GLOBAL", "STRING", "VTABLE", "LIBRARY"}
                and len(definitions) == 1
            ):
                default_name = definitions[0][0]
        if not default_name and fields.get("symbol"):
            from rebrew.rename_ops import c_name_from_symbol

            default_name = c_name_from_symbol(str(fields["symbol"]))
        name = fields.pop("name", default_name)
        symbol = fields.pop(
            "symbol", derive_c_symbol(name, anchor.prototype if anchor is not None else "")
        )
        status = fields.pop("status", "STUB")
        relative = identity_file(path, metadata_dir)
        if kind in {"DATA", "GLOBAL", "STRING", "VTABLE"}:
            record_data_rows(
                metadata_dir,
                [
                    {
                        "module": module,
                        "va": va,
                        "identity": {"file": relative, "name": name, "kind": kind},
                    }
                ],
            )
            if fields:
                set_data_fields_batch(
                    metadata_dir, [{"module": module, "va": va, "fields": fields}]
                )
            if "status" in raw:
                set_data_fields_batch(
                    metadata_dir, [{"module": module, "va": va, "fields": {"status": status}}]
                )
        else:
            prior = get_entry(metadata_dir, va, module=module)
            record_function_identity(
                metadata_dir,
                module=module,
                va=va,
                file=relative,
                name=name,
                symbol=symbol,
                kind=kind,
                overwrite_name=True,
            )
            if fields:
                set_fields(metadata_dir, va, fields, module=module)
            if "status" not in prior or "status" in raw:
                update_source_status(
                    metadata_dir, status, module, va, force=True, clear_blockers=False
                )
    return written


class SourceFixture(str):
    """C text plus explicit setup records for shared project fixture builders."""

    __slots__ = ("metadata_fields",)

    metadata_fields: dict[str, dict[str, Any]]

    def __new__(cls, text: str, metadata_fields: dict[str, dict[str, Any]]) -> "SourceFixture":
        instance = super().__new__(cls, text)
        instance.metadata_fields = metadata_fields
        return instance

    @override
    def __add__(self, other: str) -> "SourceFixture":
        fields = {**self.metadata_fields}
        if isinstance(other, SourceFixture):
            for key, values in other.metadata_fields.items():
                fields[key] = {**fields.get(key, {}), **values}
        return SourceFixture(str.__add__(self, other), fields)

    def __radd__(self, other: str) -> "SourceFixture":
        return SourceFixture(str.__add__(other, self), self.metadata_fields)

    @override
    def replace(self, old: str, new: str, count: SupportsIndex = -1) -> "SourceFixture":
        def replace_fields(value: Any) -> Any:
            if isinstance(value, str):
                return value.replace(old, new, count)
            if isinstance(value, dict):
                return {replace_fields(k): replace_fields(v) for k, v in value.items()}
            if isinstance(value, list):
                return [replace_fields(v) for v in value]
            return value

        return SourceFixture(
            str.replace(self, old, new, count), replace_fields(self.metadata_fields)
        )


def write_store_fixture(path: Path, text: str, **kwargs: Any) -> int:
    """Create an external metadata fixture, including deliberately invalid documents."""
    path.unlink(missing_ok=True)
    return path.write_text(text, **kwargs)
