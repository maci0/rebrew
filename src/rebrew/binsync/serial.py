"""serial.py: declib wrapper for BinSync state artifacts.

declib is BinSync's artifact layer (the ``declib>=4.5`` dependency of the
``binsync`` extra).  Every declib touch in rebrew lives here: artifact
construction, TOML dump/load, and the on-disk state layout helpers.  A missing
declib raises an actionable "install rebrew[binsync]" error instead of an
opaque ImportError.

The layout matches ``binsync.core.state.State.dump``:

    metadata.toml        user + version (required by State.parse)
    functions/%08x.toml  one Function artifact per file
    structs/<name>.toml  one Struct artifact per file (name sanitized)
    comments.toml        Comment.dumps_many keyed by hex addr
    global_vars.toml     GlobalVariable.dumps_many keyed by hex addr
    enums.toml           Enum.dumps_many keyed by name
    typedefs.toml        Typedef.dumps_many keyed by name
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import tomlkit

log = logging.getLogger(__name__)

_DECLIB_MISSING_MSG = (
    "declib is required for BinSync state support (the 'binsync' extra).  Install it with:\n"
    "  uv tool install --reinstall 'rebrew[binsync] @ git+https://github.com/maci0/rebrew.git'   (or from a checkout: uv sync --extra binsync)"
)

#: ``metadata.toml`` version string rebrew writes.
REBREW_STATE_VERSION = "rebrew"

FUNCTIONS_DIR = "functions"
STRUCTS_DIR = "structs"
COMMENTS_FILE = "comments.toml"
GLOBAL_VARS_FILE = "global_vars.toml"
ENUMS_FILE = "enums.toml"
TYPEDEFS_FILE = "typedefs.toml"
METADATA_FILE = "metadata.toml"

#: Artifact-kind names accepted by the load/dump helpers.
_KIND_TO_CLASS: dict[str, str] = {
    "function": "Function",
    "struct": "Struct",
    "enum": "Enum",
    "typedef": "Typedef",
    "comment": "Comment",
    "global_variable": "GlobalVariable",
}


def _declib() -> Any:
    """Return the declib ``artifacts`` module, or raise an actionable error."""
    try:
        from declib import artifacts
    except ImportError as exc:
        raise ImportError(_DECLIB_MISSING_MSG) from exc
    return artifacts


def declib_available() -> bool:
    """True when declib (the ``binsync`` extra) imports."""
    import importlib.util

    return importlib.util.find_spec("declib") is not None


def require_declib(*, json_mode: bool) -> None:
    """Exit with the install hint (exit 2) before a command touches any state."""
    if not declib_available():
        from rebrew.cli import error_exit

        error_exit(_DECLIB_MISSING_MSG, json_mode=json_mode)


def _class_for(kind: str) -> Any:
    artifacts = _declib()
    try:
        return getattr(artifacts, _KIND_TO_CLASS[kind])
    except KeyError as exc:
        raise ValueError(f"unknown artifact kind {kind!r}") from exc


def sanitize_name(name: str) -> str:
    """C-style name sanitization (matches upstream ``State.sanitize_name``)."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", name)


# ---------------------------------------------------------------------------
# Constructors (callers never import declib)
# ---------------------------------------------------------------------------


def new_function(
    addr: int,
    size: int,
    name: str | None = None,
    prototype: str | None = None,
) -> Any:
    """A declib function artifact for BinSync state (name/prototype optional)."""
    artifacts = _declib()
    header = artifacts.FunctionHeader(name=name, addr=addr, type_=prototype)
    return artifacts.Function(addr=addr, size=size, header=header)


def add_stack_variable(
    func: Any,
    *,
    offset: int,
    name: str,
    type_: str | None,
    size: int | None,
    addr: int,
) -> None:
    """Attach a stack variable to a function artifact built by :func:`new_function`."""
    artifacts = _declib()
    func.stack_vars[offset] = artifacts.StackVariable(
        stack_offset=offset, name=name, type_=type_, size=size, addr=addr
    )


def new_struct(
    name: str,
    size: int,
    members: dict[int, tuple[str, str | None, int | None]],
) -> Any:
    """Build a Struct from ``{offset: (member_name, type, size)}``."""
    artifacts = _declib()
    struct = artifacts.Struct(name=name, size=size)
    for offset, (member_name, member_type, member_size) in members.items():
        struct.add_struct_member(member_name, offset, member_type, member_size)
    return struct


def new_enum(name: str, members: dict[str, int]) -> Any:
    """Build an Enum from ``{member_name: value}``."""
    artifacts = _declib()
    return artifacts.Enum(name=name, members=dict(members))


def new_typedef(name: str, type_: str | None) -> Any:
    """Build a Typedef aliasing *type_* under *name* (``None`` when unknown)."""
    artifacts = _declib()
    return artifacts.Typedef(name=name, type_=type_)


def new_global_variable(addr: int, name: str, type_: str | None, size: int | None) -> Any:
    """Build a GlobalVariable at *addr*; *size* is ``None`` when not recovered."""
    artifacts = _declib()
    return artifacts.GlobalVariable(addr=addr, name=name, type_=type_, size=size)


def new_comment(addr: int, func_addr: int, comment: str) -> Any:
    """Build a Comment hanging off *func_addr* at *addr*."""
    artifacts = _declib()
    return artifacts.Comment(addr=addr, func_addr=func_addr, comment=comment)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


#: Permission bits of a state file: BinSync's ``State.dump`` rewrites every
#: artifact in place on the same working tree, so state files stay writable.
STATE_FILE_MODE = 0o644


def write_state_text(path: Path, text: str) -> None:
    """Write a changed artifact only, preserving mtimes on identical re-exports.

    State files are left writable (:data:`STATE_FILE_MODE`), unlike rebrew's
    own metadata stores: the state directory is shared with BinSync, which
    writes the same files.  An identical file left read-only by an older
    rebrew is made writable without rewriting it.
    """
    import os
    import stat

    from rebrew.utils import atomic_write_text

    try:
        if path.read_text(encoding="utf-8-sig") == text:
            if not path.stat().st_mode & stat.S_IWUSR:
                os.chmod(path, STATE_FILE_MODE)
            return
    except FileNotFoundError:
        pass
    atomic_write_text(path, text, encoding="utf-8", mode=STATE_FILE_MODE)


def dump_artifact(path: Path, artifact: Any) -> None:
    """Write one artifact as a TOML file."""
    write_state_text(path, artifact.dumps())


def load_artifact(path: Path, kind: str) -> Any | None:
    """Load one artifact of *kind*, or ``None`` when absent/unreadable."""
    if not path.exists():
        return None
    try:
        # utf-8-sig: Windows editors may prefix EF BB BF; plain utf-8 leaves
        # U+FEFF and declib's TOML loader then rejects the file.
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        # Same visibility as the unparseable path: an I/O failure must not
        # look like a missing artifact on import/pull.
        log.warning("unreadable BinSync %s at %s", kind, path, exc_info=True)
        return None
    try:
        return _class_for(kind).loads(text)
    except Exception:
        log.warning("unparseable BinSync %s at %s", kind, path, exc_info=True)
        return None


def dump_many(path: Path, kind: str, artifacts: list[Any], *, key: str = "addr") -> None:
    """Write many artifacts keyed by *key*, including an explicitly emptied table."""
    text = _class_for(kind).dumps_many(artifacts, key_attr=key)
    write_state_text(path, text)


def load_many(path: Path, kind: str) -> list[Any]:
    """Load every artifact of *kind*; ``[]`` when absent or unparseable."""
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        log.warning("unreadable BinSync %s at %s", kind, path, exc_info=True)
        return []
    try:
        return list(_class_for(kind).loads_many(text))
    except Exception:
        log.warning("unparseable BinSync %s at %s", kind, path, exc_info=True)
        return []


# ---------------------------------------------------------------------------
# metadata.toml
# ---------------------------------------------------------------------------


def write_metadata(state_dir: Path, *, user: str, version: str = REBREW_STATE_VERSION) -> None:
    """Write the ``user``/``version`` metadata ``State.parse`` requires."""
    doc = tomlkit.document()
    doc["user"] = user
    doc["version"] = version
    write_state_text(state_dir / METADATA_FILE, tomlkit.dumps(doc))
