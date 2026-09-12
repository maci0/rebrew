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
import subprocess
from pathlib import Path
from typing import Any

import tomlkit

log = logging.getLogger(__name__)

_DECLIB_MISSING_MSG = (
    "declib is required for BinSync state support (the 'binsync' extra).  Install it with:\n"
    '  uv sync --extra binsync   (or: uv pip install -e ".[binsync]")'
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
    """True when declib is importable (used by callers that degrade gracefully)."""
    try:
        _declib()
    except ImportError:
        return False
    return True


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
# Layout paths
# ---------------------------------------------------------------------------


def function_path(state_dir: Path, addr: int) -> Path:
    return state_dir / FUNCTIONS_DIR / f"{addr:08x}.toml"


def struct_path(state_dir: Path, name: str) -> Path:
    return state_dir / STRUCTS_DIR / f"{sanitize_name(name)}.toml"


# ---------------------------------------------------------------------------
# Constructors (callers never import declib)
# ---------------------------------------------------------------------------


def new_function(
    addr: int,
    size: int,
    name: str | None = None,
    prototype: str | None = None,
) -> Any:
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
    artifacts = _declib()
    return artifacts.Enum(name=name, members=dict(members))


def new_typedef(name: str, type_: str | None) -> Any:
    artifacts = _declib()
    return artifacts.Typedef(name=name, type_=type_)


def new_global_variable(addr: int, name: str, type_: str | None, size: int | None) -> Any:
    artifacts = _declib()
    return artifacts.GlobalVariable(addr=addr, name=name, type_=type_, size=size)


def new_comment(addr: int, func_addr: int, comment: str) -> Any:
    artifacts = _declib()
    return artifacts.Comment(addr=addr, func_addr=func_addr, comment=comment)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def dump_artifact(path: Path, artifact: Any) -> None:
    """Write one artifact as a TOML file (write-locked 0444)."""
    from rebrew.utils import atomic_write_locked

    atomic_write_locked(path, artifact.dumps(), encoding="utf-8")


def load_artifact(path: Path, kind: str) -> Any | None:
    """Load one artifact of *kind*, or ``None`` when absent/unreadable."""
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        return _class_for(kind).loads(text)
    except Exception:
        log.debug("unparseable BinSync %s at %s", kind, path, exc_info=True)
        return None


def dump_many(path: Path, kind: str, artifacts: list[Any], *, key: str = "addr") -> None:
    """Write many artifacts keyed by *key* (skips an empty list, writes nothing)."""
    if not artifacts:
        return
    from rebrew.utils import atomic_write_locked

    text = _class_for(kind).dumps_many(artifacts, key_attr=key)
    atomic_write_locked(path, text, encoding="utf-8")


def load_many(path: Path, kind: str) -> list[Any]:
    """Load every artifact of *kind*; ``[]`` when absent or unparseable."""
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        return list(_class_for(kind).loads_many(text))
    except Exception:
        log.debug("unparseable BinSync %s at %s", kind, path, exc_info=True)
        return []


# ---------------------------------------------------------------------------
# metadata.toml
# ---------------------------------------------------------------------------


def write_metadata(state_dir: Path, *, user: str, version: str = REBREW_STATE_VERSION) -> None:
    """Write the ``user``/``version`` metadata ``State.parse`` requires."""
    from rebrew.utils import atomic_write_locked

    doc = tomlkit.document()
    doc["user"] = user
    doc["version"] = version
    atomic_write_locked(state_dir / METADATA_FILE, tomlkit.dumps(doc), encoding="utf-8")


def read_metadata(state_dir: Path) -> dict[str, str] | None:
    """Read ``metadata.toml``; ``None`` when absent, ``{}`` when unparseable."""
    path = state_dir / METADATA_FILE
    if not path.exists():
        return None
    try:
        doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception:
        log.debug("unparseable BinSync metadata.toml", exc_info=True)
        return {}
    out: dict[str, str] = {}
    for key in ("user", "version", "last_push_time"):
        value = doc.get(key)
        if isinstance(value, str) and value.strip():
            out[key] = value.strip()
    return out


def state_user(state_dir: Path) -> str:
    """``git config user.name`` for *state_dir*, else ``"rebrew"``."""
    try:
        result = subprocess.run(
            ["git", "-C", str(state_dir), "config", "user.name"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        log.debug("git user.name lookup failed", exc_info=True)
        return "rebrew"
    name = result.stdout.strip()
    return name if result.returncode == 0 and name else "rebrew"
