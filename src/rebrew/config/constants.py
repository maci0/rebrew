"""Configuration constants, architecture presets, warning helpers, and LinkConfig."""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict
lazy from collections.abc import Iterator, Mapping

lazy from rebrew.compiler.toolchain_spec import FlagsStyle
lazy from rebrew.metadata.storage import metadata_write_lock
lazy from rebrew.utils import (
    console,
    untrusted_text,
)
lazy from rebrew.workspace.config import CONFIG_NAME


class ConfigWarning(UserWarning):
    """Config problem already printed to stderr by :func:`config_warn`.

    :func:`rebrew.cli.run_cli` ignores this category so a CLI run shows each
    warning once, not a second time through Python's warning display.
    """


def config_warn(msg: str) -> None:
    """Emit a ConfigWarning and print a user-facing config warning to stderr."""
    import warnings

    warnings.warn(msg, ConfigWarning, stacklevel=2)
    # The message quotes values read from rebrew-project.toml, so it renders
    # as literal text: a `[bold]` in a project name must not be read as
    # markup, and an ESC must not reach the terminal.
    console.print(f"[yellow]warning:[/yellow] {untrusted_text(msg)}")


# ---------------------------------------------------------------------------
# Canonical project filenames and env-var names
#
# These live here because config is the layer every other module is allowed to
# import.  Each constant is *used* by a higher layer (``rebrew.metadata.functions``,
# ``rebrew.compiler.toolchain``, ``rebrew.skills``) but is part of the project layout
# and environment this module describes, so a reader that needed it used to
# import the higher module and closed an import cycle.
# ---------------------------------------------------------------------------

METADATA_FILENAME = "rebrew-functions.toml"
"""Function metadata TOML, read and written through ``ProjectConfig.metadata_dir``."""


@contextlib.contextmanager
def project_toml_lock(root: Path | str) -> Iterator[Path]:
    """Hold the ``rebrew-project.toml`` read-modify-write lock; yield its path.

    The project document is a store like any other, and its writers edit one
    key each: ``rebrew cfg target add`` adds a ``[targets]`` table, a splat
    import patches ``[targets.<name>].arch``, ``lint --fix`` drops a redundant
    ``cflags_presets`` entry.  Each parses the whole document, mutates its own
    keys, and writes the file back.  Two of those interleaving (an import in one
    terminal while ``lint --fix`` runs in another) each publish a document that
    is the other's parse plus their own edit, so one side's change is gone with
    no error and no trace.

    Same lock as ``rebrew-functions.toml`` and ``rebrew-data.toml`` — a
    per-filename re-entrant thread lock plus a ``.lock`` flock sidecar — so a
    second *process* waits instead of winning.  Every writer takes this around
    the whole read, the edit, and the write, not around the write alone.
    """
    root_path = Path(root)
    with metadata_write_lock(root_path, CONFIG_NAME):
        yield root_path / CONFIG_NAME


TOOLCHAIN_OVERLAY_ENV = "REBREW_TOOLCHAIN_OVERLAY_DIR"
"""Env var naming a directory of project-level toolchain ``*.toml`` overlays.

Each file holds one or more ``name = { … }`` tables of :class:`ToolchainSpec`
fields: the project-level overlay that adds custom compilers without touching
rebrew source.
"""

REBREW_SKILLS_DIR_ENV = "REBREW_SKILLS_DIR"
"""Env var naming a directory of user/community skills (one SKILL.md dir per
skill).  Unset means packaged skills only."""

REBREW_FLIRT_SIGS_DIR_ENV = "REBREW_FLIRT_SIGS_DIR"
"""Env var naming the recondb checkout (``*.sig``/``*.pat`` files).

Absent from the environment the sibling checkout is used.  A wrong value here
is the quiet kind of misconfiguration: the loader skips a directory that is not
one, so signature matching silently runs on fewer patterns."""

REBREW_PROJECTS_ROOT_ENV = "REBREW_PROJECTS_ROOT"
"""Env var naming the directory ``tools/audit_projects.py`` scans.  Without it
the audit walks the parent of the rebrew checkout, so a wrong value reports
zero projects rather than failing."""

LLM_PROJECT_ENDPOINT_TRUST_ENV = "REBREW_LLM_ALLOW_PROJECT_ENDPOINT"
"""Env var opting in to sending the env LLM key to a project-supplied
``[llm].endpoint``.  A cloned project file names the destination, so the
refusal is the default and this is the only way past it.  Parsed by
:func:`parse_env_bool`, so ``0``/``false``/``no``/``off`` keep the refusal."""

DECOMPME_API_ENV = "REBREW_DECOMPME_API"
"""Env var naming the decomp.me instance to upload to.

The scratch claim token the server issues is printed and kept in the upload
ledger, so the host that receives it is worth pinning once in the environment
instead of retyping ``--api`` per invocation.  A set-but-empty value is read as
unset (the flag's own value then applies), so a leftover blank export does not
break every upload."""

DECOMPME_UPLOADS_PATH_ENV = "REBREW_DECOMPME_UPLOADS_PATH"
"""Internal child-command override for the decomp.me upload ledger path.

Retained ops stage a temporary project root, so their child points this at a
durable worker-workspace ledger instead of a file deleted with the snapshot.
Unset keeps the ordinary project-local ledger."""

DECOMPME_UPLOADS_SCOPE_ENV = "REBREW_DECOMPME_UPLOADS_SCOPE"
"""Internal namespace mixed into a decomp.me upload's dedup digest.

Retained ops scope keys by project/user/target/source snapshot so a shared
worker ledger cannot return another project's claim token.  The job id is not
part of the scope: a retry may arrive under a new job."""

KUNA_SPECS_ENV = "KUNA_SPECS"
"""Env var naming a SLEIGH specs root the host ``kuna`` binary reads in place of its own.

The one documented directory knob outside the ``REBREW_`` namespace: kuna
reads it itself, and a value that is not a directory fails every decompile,
so it is checked like every other path knob and kept from kuna.  Read by
:mod:`rebrew.decompiler`, and reported by ``rebrew cfg effective``."""

XVFB_DISPLAY_ENV = "REBREW_XVFB_DISPLAY"
"""Env var recording the display rebrew's Xvfb lives on.  Written by
:mod:`rebrew.compiler.headless`; an operator may pin it, and only a local ``:N`` /
``:N.S`` display can ever be adopted."""

ALLOW_PRIVATE_DOWNLOAD_ENV = "REBREW_OPS_ALLOW_PRIVATE_DOWNLOAD"
"""Env var opting ``rebrew ops`` downloads of presigned URLs to private hosts.

Unset/empty keeps the SSRF refusal; a truthy value disables it.  Parsed
strictly by :func:`parse_env_bool`, so ``0``/``false``/``no``/``off`` keep the
refusal and a typo raises instead of silently granting the bypass."""

STRICT_REPLIES_ENV = "REBREW_OPS_STRICT_REPLIES"
"""Env var making an op fail on a reply member its declaration does not name.

Set (to ``1``) by rebrew's test suite, so a member a reply builder adds and
``rebrew.ops.replies`` does not declare fails the test that builds it.  Unset, the
member is dropped and logged.  Parsed by :func:`parse_env_bool`."""

GHIDRA_MCP_ENDPOINT_ENV = "REBREW_GHIDRA_MCP_ENDPOINT"
"""Env var naming the ReVa MCP endpoint of a Ghidra the ``ghidra`` decompiler uses.

Unset/empty: ``rebrew ops`` offers no ``ghidra`` decompiler, and ``rebrew
decompile`` and ``rebrew doctor`` use :data:`rebrew.ghidra.DEFAULT_MCP_ENDPOINT`.
A set value must be an ``http(s)`` URL with a host and without credentials."""

OTLP_ENDPOINT_ENV = "REBREW_OTLP_ENDPOINT"
"""Env var holding the OTLP/HTTP collector base URL for trace export.

Unset/empty leaves export off.  A set value must be an ``http(s)`` URL with a
host and no credentials; validated by :func:`validate_http_url` at telemetry
setup and in ``env_knob_errors``."""

#: A local X display, the only form :mod:`rebrew.compiler.headless` can resolve: the
#: socket probe and the ``/proc`` scan both key on ``/tmp/.X11-unix/X<n>``.
ENV_DISPLAY_RE = re.compile(r":\d+(?:\.\d+)?")

KEY_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]+")

# ---------------------------------------------------------------------------
# Canonical filename for the function structure cache
# ---------------------------------------------------------------------------

FUNCTION_STRUCTURE_JSON = "function_structure.json"
"""Tool-agnostic structural cache: ``[{va, size, name?}]``.

This file stores function *boundaries* (VA + size) discovered by any RE
tool (Ghidra, radare2, rizin).  Names are optional hints used only when
no source annotation exists.  Source annotations are always authoritative
for naming.
"""

#: Seconds before a compile subprocess is killed.  The single source for
#: ``ProjectConfig.compile_timeout``: its dataclass default, the
#: ``[compiler] timeout`` fallback, and the ``getattr(cfg, ...)`` fallbacks in
#: ``rebrew.compiler.compile`` all read this, so a mock-backed call cannot get a
#: different budget than a configured one.
DEFAULT_COMPILE_TIMEOUT = 60

#: Default ``[project] jobs`` parallelism.  The single source for
#: ``ProjectConfig.default_jobs``, the ``[project] jobs`` fallback, and the
#: value ``rebrew init`` writes into a new project file, so a generated
#: project and a hand-written one start at the same budget.
DEFAULT_PROJECT_JOBS = 4

#: Re-attempts of a retryable remote-compile failure, and the single source
#: for ``ProjectConfig.recompile_retries``, its ``[compiler]`` fallback, and
#: the ``getattr`` fallback in ``rebrew.compiler.compile``.
DEFAULT_RECOMPILE_RETRIES = 2
#: Highest ``[compiler] recompile_retries`` honored before clamping, on the
#: same terms as :data:`MAX_LLM_MAX_REQUESTS`.  Each re-attempt waits
#: ``retry_backoff_delay`` (capped at ``RETRY_BACKOFF_CAP``), so a value left
#: unclamped is a wall-clock budget nobody sized: a mistyped 20000 turns one
#: transient 503 into a compile that retries for about 44 hours before
#: reporting the error it could have reported in seconds.
MAX_RECOMPILE_RETRIES = 20

#: Remote compiles one process runs at once, the single source for
#: ``ProjectConfig.recompile_concurrency``, its ``[compiler]`` fallback, and
#: the ``getattr`` fallback in ``rebrew.compiler.compile``.  Below the default
#: 4 jobs (:data:`DEFAULT_PROJECT_JOBS`), so a whole-target run keeps fewer
#: compiles in flight at one service than it has workers.
DEFAULT_RECOMPILE_CONCURRENCY = 2

#: Maximum C source line length for lint W027 (0 disables the check).  Single
#: source for ``ProjectConfig.lint_max_line_length``, the
#: ``[project.lint] max_line_length`` fallback, and ``rebrew.lint``.
DEFAULT_LINT_MAX_LINE_LENGTH = 200
#: ``REBREW_LLM_MAX_REQUESTS`` process ceiling: the default budget, and the
#: highest value honored before clamping.
DEFAULT_LLM_MAX_REQUESTS = 32
MAX_LLM_MAX_REQUESTS = 10_000
#: ``REBREW_LLM_MAX_TOKENS`` process ceiling on billed LLM tokens.  A call
#: ceiling alone does not bound spend: one request bills a prompt plus a capped
#: completion, and raising ``REBREW_LLM_MAX_REQUESTS`` multiplies both, so a
#: ``--watch`` run on a long function can buy tens of millions of tokens under
#: a call count that reads small.  The default sits above what the default call
#: budget can spend, so it only binds once an operator has deliberately raised
#: that budget.
DEFAULT_LLM_MAX_TOKENS = 500_000
MAX_LLM_MAX_TOKENS = 100_000_000
#: ``REBREW_LLM_TIMEOUT`` per-request HTTP budget, in seconds.  The default
#: suits a hosted chat API; a local model on CPU needs the upper end, and a
#: value below :data:`MIN_LLM_TIMEOUT` cannot cover one request.
DEFAULT_LLM_TIMEOUT = 90
MIN_LLM_TIMEOUT = 5
MAX_LLM_TIMEOUT = 1_800
# ---------------------------------------------------------------------------
# Architecture presets
# ---------------------------------------------------------------------------


class ArchPreset(TypedDict):
    capstone_arch: str
    capstone_mode: str
    pointer_size: int
    padding_bytes: list[int]


ARCH_PRESETS: dict[str, ArchPreset] = {
    "xtensa": {
        "capstone_arch": "CS_ARCH_XTENSA",
        "capstone_mode": "CS_MODE_LITTLE_ENDIAN",
        "pointer_size": 4,
        "padding_bytes": [0x00],
    },
    "x86_16": {
        "capstone_arch": "CS_ARCH_X86",
        "capstone_mode": "CS_MODE_16",
        "pointer_size": 2,
        "padding_bytes": [0x90, 0x00],
    },
    "x86_32": {
        "capstone_arch": "CS_ARCH_X86",
        "capstone_mode": "CS_MODE_32",
        "pointer_size": 4,
        "padding_bytes": [0xCC, 0x90],
    },
    "x86_64": {
        "capstone_arch": "CS_ARCH_X86",
        "capstone_mode": "CS_MODE_64",
        "pointer_size": 8,
        "padding_bytes": [0xCC, 0x90],
    },
    "arm32": {
        "capstone_arch": "CS_ARCH_ARM",
        "capstone_mode": "CS_MODE_ARM",
        "pointer_size": 4,
        "padding_bytes": [0x00],
    },
    "arm64": {
        "capstone_arch": "CS_ARCH_ARM64",
        "capstone_mode": "CS_MODE_ARM",
        "pointer_size": 8,
        "padding_bytes": [0x00],
    },
    "mips32": {
        "capstone_arch": "CS_ARCH_MIPS",
        "capstone_mode": "CS_MODE_MIPS32",
        "pointer_size": 4,
        "padding_bytes": [0x00],
    },
    "mips64": {
        "capstone_arch": "CS_ARCH_MIPS",
        "capstone_mode": "CS_MODE_MIPS64",
        "pointer_size": 8,
        "padding_bytes": [0x00],
    },
    "ppc32": {
        "capstone_arch": "CS_ARCH_PPC",
        "capstone_mode": "CS_MODE_32",
        "pointer_size": 4,
        "padding_bytes": [0x60, 0x00, 0x00, 0x00],  # `nop`
    },
    "ppc64": {
        "capstone_arch": "CS_ARCH_PPC",
        "capstone_mode": "CS_MODE_64",
        "pointer_size": 8,
        "padding_bytes": [0x60, 0x00, 0x00, 0x00],
    },
    "sh2": {
        "capstone_arch": "CS_ARCH_SH",
        "capstone_mode": "CS_MODE_SH2",
        "pointer_size": 4,
        "padding_bytes": [0x00],
    },
}

#: Arches whose data (not the host) is big-endian by default.  The IDO, Saturn
#: and PowerPC targets are; x86 and ARM images are little-endian.  This set must
#: agree with :func:`rebrew.formats.binary_loader.endian_mode_bits`, or one target is
#: read little-endian for its data while its instructions decode big-endian.
#: A target that reverses the default (a little-endian MIPS or PPC build)
#: overrides this with the image header, the way capstone_mode does.
_ARCH_BIG_ENDIAN = frozenset({"mips32", "mips64", "ppc32", "ppc64", "sh2"})

#: Pointer width assumed for an arch string with no preset.  x86_32 is the
#: default architecture, so an unknown arch sizes like it rather than failing;
#: every preset arch carries its real width.
_DEFAULT_POINTER_SIZE = 4

#: Fill bytes assumed for an arch string with no preset, matching the x86_32
#: preset for the same reason as :data:`_DEFAULT_POINTER_SIZE`.
_DEFAULT_PADDING_BYTES: list[int] = [0xCC, 0x90]


def arch_pointer_size(arch: str) -> int:
    """On-disk pointer width in bytes for *arch*.

    The single source of truth for how wide a pointer-sized slot is in a
    target's data, so a reader cannot disagree with the preset table.
    """
    preset = ARCH_PRESETS.get(arch)
    return int(preset["pointer_size"]) if preset else _DEFAULT_POINTER_SIZE


def arch_padding_bytes(arch: str) -> list[int]:
    """Inter-function fill byte values for *arch*.

    The counterpart to :func:`arch_pointer_size`: both read the preset table
    so a config, a loader, and a gap classifier cannot disagree about the
    target's data layout.
    """
    preset = ARCH_PRESETS.get(arch)
    return list(preset["padding_bytes"]) if preset else list(_DEFAULT_PADDING_BYTES)


def arch_is_big_endian(arch: str) -> bool:
    """True when *arch* stores data big-endian by default.

    A target that reverses the default (a little-endian MIPS build) does not
    answer through this name alone; pass its image ``endian`` to
    :func:`arch_byte_order` instead.
    """
    return arch in _ARCH_BIG_ENDIAN


def arch_byte_order(arch: str, endian: str = "") -> str:
    """``struct`` byte-order prefix for *arch*'s data section.

    *endian* is the image's own byte order (``BinaryInfo.endian``: ``"big"``,
    ``"little"``, or ``""`` when the header does not say).  It wins whenever it
    is set, so a little-endian MIPS build reads little-endian instead of
    inheriting the arch default, exactly as
    :func:`rebrew.formats.binary_loader.endian_mode_bits` does for the instruction
    stream.  An empty *endian* falls back to :func:`arch_is_big_endian`.
    """
    if endian == "big":
        return ">"
    if endian == "little":
        return "<"
    return ">" if arch_is_big_endian(arch) else "<"


#: IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, the one bit ``link.tsaware``
#: owns.  Every other bit of DllCharacteristics (DYNAMIC_BASE, NX_COMPAT, ...)
#: belongs to the original binary and must survive the patch.
TSAWARE_BIT = 0x8000


@dataclass
class LinkConfig:
    """Declarative linker settings for byte-identical PE reconstruction.

    Mirrors the ``[link]`` section of ``rebrew-project.toml``.  ``rebrew
    build round-trip --fix-headers`` patches the reasm copy with these values, and
    the round-trip report's ``header_parity`` compares them against the
    original binary so header mismatches are visible (previously only .text
    bytes were checked).
    """

    file_align: int | None = None
    stack_reserve: int | None = None
    stack_commit: int | None = None
    tsaware: bool | None = None  # sets or clears TSAWARE_BIT in dll_characteristics
    linker_version: str | None = None  # e.g. "5.12"
    os_version: str | None = None  # e.g. "5.0"
    subsystem_version: str | None = None  # e.g. "4.0"
    timestamp: int | None = None  # seconds since epoch, hex-accepting

    def _version_pair(self, label: str, ver: str | None) -> tuple[int, int] | None:
        """Parse a ``"N.N"`` version string into ``(major, minor)``, or None.

        Warns on malformed values (``"5"``, ``"abc"``) instead of silently
        dropping them — a typo'd ``linker_version`` otherwise makes
        ``--fix-headers`` skip the patch while the parity report shows a
        mismatch the user cannot explain.
        """
        if not ver:
            return None
        try:
            major, minor = ver.split(".", 1)
            maj, mn = int(major), int(minor)
            if not (0 <= maj <= 65535 and 0 <= mn <= 65535):
                raise ValueError("out of range")
            return maj, mn
        except ValueError:
            config_warn(
                f"link.{label} = {ver!r} is not a valid 'N.N' version — "
                "the header patch for it will be skipped"
            )
            return None

    def to_patch_fields(self, original_fields: Mapping[str, int] | None = None) -> dict[str, int]:
        """Map configured values to pe_headers field labels (empty if unset).

        *original_fields* are the target's current header values.  They are
        needed only by the bit-flag ``tsaware`` setting, which sets or clears
        one bit of ``dll_characteristics`` rather than replacing the word: a
        target carrying ``DYNAMIC_BASE`` / ``NX_COMPAT`` keeps them either way.
        Without them the existing word is assumed to be 0.
        """
        fields: dict[str, int] = {}
        vp = self._version_pair("linker_version", self.linker_version)
        if vp is not None:
            fields["linker_version_major"], fields["linker_version_minor"] = vp
        for label, ver in (
            ("os_version", self.os_version),
            ("subsystem_version", self.subsystem_version),
        ):
            vp = self._version_pair(label, ver)
            if vp is not None:
                fields[f"{label}_major"], fields[f"{label}_minor"] = vp
        if self.tsaware is not None:
            current = (original_fields or {}).get("dll_characteristics", 0)
            fields["dll_characteristics"] = (
                current | TSAWARE_BIT if self.tsaware else current & ~TSAWARE_BIT
            )
        if self.stack_reserve is not None:
            fields["stack_reserve"] = self.stack_reserve
        if self.stack_commit is not None:
            fields["stack_commit"] = self.stack_commit
        if self.timestamp is not None:
            fields["timestamp"] = self.timestamp
        return fields


def profile_flags_style(profile: str) -> FlagsStyle | None:
    """The registered toolchain spec's ``flags_style`` for *profile*.

    ``None`` when *profile* is not a registry toolchain."""
    from rebrew.compiler.toolchain import TOOLCHAINS

    spec = TOOLCHAINS.get(profile)
    return getattr(spec, "flags_style", None)


DEFAULT_ADDRESS_COMMENT_REGEX = r"ADDRESS:\s+(?P<module>\S+)\s+(?P<va>0x[0-9a-fA-F]+)\s*"
ADDRESS_COMMENT_TEMPLATES = {
    "c89": "/* ADDRESS: $module $va */",
    "cpp": "// ADDRESS: $module $va",
    "delphi": "{ ADDRESS: $module $va }",
}


# ---------------------------------------------------------------------------
# Known TOML keys — validated at load time to catch typos
# ---------------------------------------------------------------------------

KNOWN_TOP_KEYS = {"targets", "compiler", "project", "link", "llm", "cache", "metadata"}

KNOWN_CACHE_KEYS = {"backend", "size_limit_mib"}

KNOWN_LLM_KEYS = {
    "endpoint",
    "api_key",
    "model",
    "max_requests",
    "max_tokens",
    "timeout",
}

KNOWN_LINK_KEYS = {
    "file_align",
    "stack_reserve",
    "stack_commit",
    "tsaware",
    "linker_version",
    "os_version",
    "subsystem_version",
    "timestamp",
}

KNOWN_TARGET_KEYS = {
    "address_comments",
    "binary",
    "arch",
    "format",
    "module",
    "reversed_dir",
    "bin_dir",
    "compiler",
    "defines",  # per-target compile-time defines (shared multi-version sources)
    "check_known_bindings",
    "r2_bogus_vas",
    "iat_thunks",
    "dll_exports",
    "ignored_symbols",
    "library_modules",
    "external_libs",
    "external_ranges",  # address bands filled by a statically linked library
    "crt_sources",
    "source_ext",
    "ghidra_program_path",
    "ghidra_backend",
    "binsync_state_dir",
    "binsync_user",
    "inventory_file",
    "origins",  # written by `rebrew cfg target add`; editor/UI only — NOT
    # used for annotation filtering (module filters come from the
    # annotations themselves).
    "raw_link",  # pre-postlink image. A missing file must not fall back to
    # the postlinked build/<target>. An unrecognised key is one a rewriter drops.
    "layout",  # Legacy inline layout block, retained so config rewriters preserve it.
    # `rebrew build layout --layout-config` emits the standalone
    # layout/<target>/rebrew-layout.toml document.
}

KNOWN_COMPILER_KEYS = {
    "command",
    "runner",
    "execution_backend",
    "includes",
    "libs",
    "cflags",
    "profile",
    "base_cflags",
    "timeout",
    "recompile_url",  # remote compile backend (or REBREW_RECOMPILE_URL env)
    "recompile_emit_assembly",  # assembly output for remote compiles
    "recompile_retries",  # re-attempts of a retryable remote-compile failure
    "recompile_concurrency",  # remote compiles one process runs at once
    "cflags_presets",  # written by `rebrew cfg module set-cflags` without --target (per-origin compiler flag overrides)
}

KNOWN_PROJECT_KEYS = {
    "address_comments",
    "name",
    "jobs",
    "output_dir",
    "default_target",
    "shared_dir",  # project-level shared sources root (multi-version)
    "lint",
}

KNOWN_LINT_KEYS = {
    "naming_convention",
    "brace_style",
    "indent_style",
    "max_line_length",
}

KNOWN_LINT_NAMING = frozenset({"none", "snake_case", "camelCase"})
KNOWN_LINT_BRACE = frozenset({"none", "same_line", "new_line"})
KNOWN_LINT_INDENT = frozenset({"none", "spaces", "tabs"})

KNOWN_FORMATS = {"pe", "elf", "macho", "ne", "mz"}
