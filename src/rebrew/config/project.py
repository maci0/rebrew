"""ProjectConfig dataclass, binary layout detection, and project loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
lazy import os
lazy import unicodedata
lazy from collections.abc import Mapping

from rebrew.config.address_comments import (
    AddressCommentFormat,
    parse_address_comment_format,
)
from rebrew.config.constants import (
    ARCH_PRESETS,
    DEFAULT_COMPILE_TIMEOUT,
    DEFAULT_LINT_MAX_LINE_LENGTH,
    DEFAULT_LLM_MAX_REQUESTS,
    DEFAULT_LLM_MAX_TOKENS,
    DEFAULT_LLM_TIMEOUT,
    DEFAULT_PROJECT_JOBS,
    DEFAULT_RECOMPILE_CONCURRENCY,
    DEFAULT_RECOMPILE_RETRIES,
    KNOWN_CACHE_KEYS,
    KNOWN_COMPILER_KEYS,
    KNOWN_FORMATS,
    KNOWN_LINK_KEYS,
    KNOWN_LINT_BRACE,
    KNOWN_LINT_INDENT,
    KNOWN_LINT_KEYS,
    KNOWN_LINT_NAMING,
    KNOWN_LLM_KEYS,
    KNOWN_PROJECT_KEYS,
    KNOWN_TARGET_KEYS,
    KNOWN_TOP_KEYS,
    MAX_RECOMPILE_RETRIES,
    METADATA_FILENAME,
    LinkConfig,
    arch_padding_bytes,
    arch_pointer_size,
    config_warn,
    profile_flags_style,
)
from rebrew.config.env import (
    insecure_endpoint_message,
    is_key_safe_endpoint,
    llm_budget_value,
    llm_max_requests,
    llm_max_tokens,
    llm_timeout,
    validate_http_url,
    validate_llm_model,
)
from rebrew.config.schema import (
    as_bool,
    as_str,
    as_table,
    install_tool_alt,
    merge_cflags_presets,
    non_negative_int,
    normalized_targets,
    parse_defines,
    parse_hex_dict,
    parse_int_list,
    parse_optional_int,
    parse_source_ext,
    parse_str_dict,
    parse_str_list,
    parse_va_ranges,
    positive_int,
    project_default_target,
    read_project_toml,
    required_path,
    resolve_path,
    safe_int,
    split_compiler_runner,
    target_module_value,
    validate_target_name,
)
from rebrew.errors import (
    ConfigError,
    ConfigKeyError,
    ConfigNotFoundError,
)
lazy from rebrew.metadata.storage import metadata_store
lazy from rebrew.utils import (
    BYTES_PER_MIB,
    load_tomllib,
)
lazy from rebrew.workspace import walk_up_to_root

_as_bool = as_bool


@dataclass
class ProjectConfig:
    """Parsed project configuration with computed paths."""

    # Root directory (where rebrew-project.toml lives)
    root: Path

    # Target name (key under [targets])
    target_name: str = ""

    # --- target fields ---
    target_binary: Path = field(default_factory=lambda: Path())
    binary_format: str = "pe"  # "pe", "elf", "macho"
    arch: str = "x86_32"  # "x86_32", "x86_64", etc.

    # --- per-target sources ---
    reversed_dir: Path = field(default_factory=lambda: Path())
    shared_dir: Path | None = None
    """Project-level shared-sources root (``src/shared`` by default).

    Sources here are scanned for EVERY target and may carry one
    ``/* ADDRESS: <module> <va> */`` anchor per target (the same function at
    a different VA in each version) plus ``#ifdef`` deltas driven by the
    per-target ``defines``.  ``None`` (or an empty ``[project] shared_dir``)
    disables shared sources.
    """
    bin_dir: Path = field(default_factory=lambda: Path())
    module: str = ""  # prefix in /* ADDRESS: SERVER 0x... */ (default: target_name.upper())
    address_comments: AddressCommentFormat = field(default_factory=AddressCommentFormat)
    r2_bogus_vas: list[int] = field(default_factory=list)  # VAs with known-bad r2 size data
    check_known_bindings: bool = False  # reject contradictory mapped native operands

    # --- project-level defaults ---
    metadata_backend: str = "toml"
    metadata_read_backends: tuple[str, ...] = ("toml",)
    metadata_write_backends: tuple[str, ...] = ("toml",)
    project_name: str = ""
    default_jobs: int = DEFAULT_PROJECT_JOBS  # see DEFAULT_PROJECT_JOBS
    output_dir: Path = field(default_factory=lambda: Path())
    # Image the linker wrote, before postlink copies reference bytes.
    # None: status scores only build/<target>.
    raw_link: Path | None = None

    # --- compiler ---
    compiler_profile: str = "msvc-6.0"
    compiler_command: str = "wine CL.EXE"
    compiler_runner: str = ""
    execution_backend: str = ""  # Empty on programmatic configs inherits the runtime environment.
    compiler_includes: Path = field(default_factory=lambda: Path())
    compiler_libs: Path = field(default_factory=lambda: Path())
    cflags: str = ""  # Default compiler flags (from [compiler] or per-target override)
    # True when `cflags` was EXPLICITLY present in the TOML — an empty
    # string then means "no default flags", not "fall back to /O2 /Gd".
    # (`cflags = ""` silently compiled with /O2 /Gd.)
    cflags_explicit: bool = False
    cflags_presets: dict[str, str] = field(default_factory=dict)
    """Per-module compiler flag overrides (``rebrew cfg module set-cflags``).

    ``[compiler.cflags_presets]`` (global) merged with
    ``[targets.X.compiler.cflags_presets]`` (per-key, target wins). Used by
    every compile path (``compile``, ``verify``, ``test``, ``match``, ``diff``,
    ``prove``, ``probe`` and ``diagnose``) as the CFLAGS fallback when neither
    per-function metadata nor the nearest library override supplies non-empty
    CFLAGS.
    """
    base_cflags: str = "/nologo /c /MT"  # Always-on flags prepended to every compile
    compile_timeout: int = DEFAULT_COMPILE_TIMEOUT  # see DEFAULT_COMPILE_TIMEOUT

    # --- recompile remote backend ([compiler] recompile_url or
    # REBREW_RECOMPILE_URL env) ---
    recompile_url: str = ""
    """Base URL of the recompile compile service (e.g. ``http://localhost:8000``).

    When set, every compile routes through ``POST /api/v1/compile`` instead
    of local docker images. Assembly output can be requested separately.
    Empty (the default) keeps local docker execution.
    """
    recompile_emit_assembly: bool = False
    """Request assembly output on remote compiles.

    Off by default. When on, every remote compile (test, verify, match)
    sends it; ``match --collect-pairs`` writes local pairs and does not touch
    this flag. Current Recompile treats training consent separately.
    """
    recompile_concurrency: int = DEFAULT_RECOMPILE_CONCURRENCY
    """Remote compiles this process runs at once (``>= 1``), whatever ``jobs`` is.

    One :class:`rebrew.compiler.recompile_client.ServiceGate` per service and
    value holds every compile of the process: the excess waits for a slot, and
    a ``Retry-After`` one reply names holds them all back.
    """
    recompile_retries: int = DEFAULT_RECOMPILE_RETRIES
    """Re-attempts of failures the remote answer table marks retryable (``0`` means one attempt).

    This includes transport failures, transient HTTP statuses and service
    outcomes such as ``publish_failed``. Capacity/throttle waits do not spend
    this budget, and a compiler rejection is never re-POSTed.
    """

    # --- per-target version defines ---
    defines: list[str] = field(default_factory=list)
    """Per-target compile-time defines (``targets.<name>.defines``).

    Each entry becomes ``-D<name>`` (posix) or ``/D<name>`` (MSVC) on every
    compile for this target — the version switch that makes shared
    multi-version sources work (``#ifdef V2`` blocks in a shared .c).
    """

    # --- [llm] section: optional LLM-assisted GA seeding ---
    # ``[llm] endpoint``/``model`` in rebrew-project.toml win over env;
    # ``REBREW_LLM_API_KEY`` wins when present (including empty) over TOML.
    llm_endpoint: str = ""
    llm_endpoint_from_project: bool = False
    """Whether :attr:`llm_endpoint` came from ``[llm].endpoint`` in the project
    file rather than ``REBREW_LLM_ENDPOINT``.

    The two have opposite trust: a checked-out tree names any host, so only a
    project endpoint needs ``REBREW_LLM_ALLOW_PROJECT_ENDPOINT`` before an
    operator key may be sent to it. The merged string alone cannot tell them
    apart, so the source is recorded here at load.
    """
    llm_api_key: str = field(default="", repr=False)
    llm_model: str = ""
    llm_max_requests: int = DEFAULT_LLM_MAX_REQUESTS
    """``REBREW_LLM_MAX_REQUESTS`` after clamping, the process call budget.

    Env-only (no ``[llm]`` counterpart).  Resolved here so ``rebrew cfg
    effective`` reports the ceiling in force: it decides whether seeding runs
    at all and how much it can bill, and the two knobs that say so are
    otherwise invisible outside a debug log.
    """
    llm_max_tokens: int = DEFAULT_LLM_MAX_TOKENS
    """``REBREW_LLM_MAX_TOKENS`` after clamping, the process token budget.

    Env-only (no ``[llm]`` counterpart), and the second half of the spend
    ceiling: ``llm_max_requests`` bounds how many times the endpoint is asked,
    this bounds what the answers cost.  Resolved at load so ``rebrew cfg
    effective`` reports the budget in force.
    """
    llm_timeout: int = DEFAULT_LLM_TIMEOUT
    """``REBREW_LLM_TIMEOUT`` after clamping, the per-request budget in seconds."""
    cache_backend: str = "diskcache"  # compile-cache store ([cache] backend)
    cache_size_limit_mib: int = 0  # compile-cache cap in MiB; 0 = built-in default

    @property
    def cache_size_limit(self) -> int:
        """Compile-cache size cap in bytes.

        ``[cache] size_limit_mib`` is the only knob: the packaged default
        (500 MiB) is a poor fit on a small disk, and a cap the project cannot
        move turns a disk-space problem into a ``rebrew cache clear``.
        ``0`` means "unset", which resolves to the backend's own default.
        """
        from rebrew.compiler.cache import DEFAULT_CACHE_SIZE_LIMIT_MIB

        mib = (
            self.cache_size_limit_mib
            if self.cache_size_limit_mib > 0
            else DEFAULT_CACHE_SIZE_LIMIT_MIB
        )
        return mib * BYTES_PER_MIB

    @property
    def posix_style(self) -> bool:
        """True when the compiler profile uses POSIX-style flags (-I/-o/-c).

        Read from the registry spec's ``flags_style``: gcc/clang/mingw/watcom
        take dash flags and ship their own headers, MSVC profiles use
        ``/I``/``/Fo``/``/c``.  Single source of truth for compile/flag routing
        across compiler/compile.py, diff.py, match.py, and matcher/compiler.py.
        """
        return profile_flags_style(self.compiler_profile) == "posix"

    # --- Derived from arch ---
    #  Not stored: both read ARCH_PRESETS through arch_pointer_size and
    #  arch_padding_bytes, so a hand-built config and a loaded one cannot
    #  disagree with the preset table about the target's data layout.

    @property
    def pointer_size(self) -> int:
        """On-disk pointer width in bytes for :attr:`arch`."""
        return arch_pointer_size(self.arch)

    @property
    def padding_bytes(self) -> list[int]:
        """Inter-function fill byte values for :attr:`arch`."""
        return arch_padding_bytes(self.arch)

    # --- PE-specific (computed at load time if format == "pe") ---
    image_base: int = 0
    text_va: int = 0

    # --- Project-specific (loaded from TOML if present) ---
    iat_thunks: list[int] = field(default_factory=list)
    dll_exports: dict[int, str] = field(default_factory=dict)
    ignored_symbols: list[str] = field(default_factory=list)
    library_modules: set[str] = field(
        default_factory=set
    )  # Module names using LIBRARY metadata (e.g. {"MSVCRT", "ZLIB"})
    # External .lib code, the one flag for "not our work": module name ->
    # link spec (the archive to link, e.g. "LIBCMT.lib",
    # "references/dxsdk8/lib/d3dx8.lib"; "" = identified external code with
    # no separate archive).  Rows attributed to these modules leave the
    # progress accounting, `rebrew library match` ingests the archives by
    # default, and `rebrew build cmake-sources` emits them as REBREW_EXTERNAL_LIBS
    # so the build links the stock archive.
    external_libs: dict[str, str] = field(default_factory=dict)
    #: Inclusive ``(lo, hi)`` address bands the target's binary fills from a
    #: linked library rather than from project sources (``targets.<name>.
    #: external_ranges``).  Tools that enumerate "work left" must skip them.
    external_ranges: list[tuple[int, int]] = field(default_factory=list)
    crt_sources: dict[str, str] = field(default_factory=dict)
    source_ext: str = ".c"  # Source file extension (e.g. ".c", ".cpp")
    ghidra_program_path: str = ""
    ghidra_backend: str = "reva"  # "reva" (MCP) or "cli" (ghidra-cli binary)
    binsync_state_dir: str = ""  # BinSync state dir for field sync (--state-dir default)
    binsync_user: str = ""  # BinSync user rebrew writes as (branch binsync/<user>)
    inventory_file: str = (
        ""  # Function inventory path override (default: reversed_dir/function_structure.json)
    )

    # --- Lint configuration ---
    lint_naming_convention: str = "none"  # "snake_case", "camelCase", or "none"
    lint_brace_style: str = "none"  # "same_line", "new_line", or "none"
    lint_indent_style: str = "none"  # "spaces", "tabs", or "none"
    lint_max_line_length: int = DEFAULT_LINT_MAX_LINE_LENGTH  # see DEFAULT_LINT_MAX_LINE_LENGTH

    # --- All known target names ---
    all_targets: list[str] = field(default_factory=list)

    # --- All known target modules (E012 allows stacked shared bindings) ---
    target_modules: set[str] = field(default_factory=set)

    # --- External library modules declared by ANY target, not just the active
    # one. A LIBRARY row for a module another target links (D3DX8 on the TL
    # client) is not a stale row, so lint W035 reads this while server.dll is
    # the default target. ---
    all_library_modules: set[str] = field(default_factory=set)

    # --- Linker settings for byte-identical reconstruction ([link]) ---
    link: LinkConfig = field(default_factory=LinkConfig)

    @property
    def capstone_arch(self) -> int:
        """Return capstone CS_ARCH_* constant."""
        import capstone

        preset = ARCH_PRESETS.get(self.arch)
        name = preset.get("capstone_arch", "CS_ARCH_X86") if preset else "CS_ARCH_X86"
        if not hasattr(capstone, name):
            raise NotImplementedError(
                f"installed Capstone cannot disassemble {self.arch}; use IDA or xt-objdump"
            )
        return int(getattr(capstone, name))

    @property
    def capstone_mode(self) -> int:
        """Return the capstone ``CS_MODE_*`` bits for this target.

        The preset supplies the architecture's base mode.  MIPS, PPC, and SH2
        also set ``CS_MODE_BIG_ENDIAN`` (IDO, GameCube/Wii, Saturn) unless the
        target image header is little-endian.  ARM sets that bit only when the
        image is big-endian.  x86 never sets it: capstone rejects the
        combination.
        """
        import capstone

        from rebrew.formats.binary_loader import endian_mode_bits, sniff_image_endian

        preset = ARCH_PRESETS.get(self.arch)
        name = preset.get("capstone_mode", "CS_MODE_32") if preset else "CS_MODE_32"
        mode = int(getattr(capstone, name))
        endian = ""
        binary = getattr(self, "target_binary", None)
        if binary is not None:
            path = Path(binary)
            if path.is_file():
                endian = sniff_image_endian(path)
        return mode | endian_mode_bits(getattr(self, "arch", "") or "", endian)

    @property
    def metadata_dir(self) -> Path:
        """Directory for function, data and source-provenance metadata.

        The store sits one level above the source tree — the project root
        when ``reversed_dir`` is ``src/<target>`` or ``src`` itself.  A
        project that still keeps the TOMLs inside ``src/`` resolves there
        until they move.  The search walks every ancestor up to ``root``,
        so a project whose store sits at the root still resolves there for
        a nested target instead of silently picking a per-target directory.
        All metadata reads/writes must go through this property so the
        location is centralized.
        """
        parent = self.reversed_dir.parent
        # No store one level above the source tree: the project may still
        # keep its TOMLs inside the source tree, or further up at ``root``.
        # The outermost store found wins, so every target of a multi-target
        # project reads and writes the same file.
        outermost: Path | None = self.reversed_dir if self.root == self.reversed_dir else None
        if metadata_store(self.reversed_dir / METADATA_FILENAME).exists():
            outermost = self.reversed_dir
        candidate = self.reversed_dir if self.root == self.reversed_dir else parent
        while True:
            if metadata_store(candidate / METADATA_FILENAME).exists():
                outermost = candidate
            if candidate == candidate.parent:
                break
            if self.root is not None:
                if candidate == self.root:
                    break
                if self.root not in candidate.parents:
                    # reversed_dir is not below root, so no ancestor of
                    # candidate is in scope; climbing further would adopt an
                    # unrelated store from outside the project.
                    break
            candidate = candidate.parent
        if outermost is None:
            if self.root is not None and self.root in self.reversed_dir.parents:
                outermost = self.root
            else:
                outermost = parent.parent if parent.name == "src" else parent
        if self.root is not None and "pgsql" in self.metadata_read_backends:
            raw = load_tomllib(self.root / "rebrew-project.toml")
            validate_source_directories(
                self.root,
                normalized_targets(raw["targets"]),
                self.target_name,
                self.shared_dir,
                metadata_root=outermost,
            )
        return outermost

    def __post_init__(self) -> None:
        """Coerce string path arguments to :class:`pathlib.Path` instances."""
        if self.root is not None and not isinstance(self.root, Path):
            self.root = Path(self.root)
        if self.target_binary is not None and not isinstance(self.target_binary, Path):
            self.target_binary = Path(self.target_binary)
        if self.reversed_dir is not None and not isinstance(self.reversed_dir, Path):
            self.reversed_dir = Path(self.reversed_dir)
        if self.shared_dir is not None and not isinstance(self.shared_dir, Path):
            self.shared_dir = Path(self.shared_dir)
        if self.bin_dir is not None and not isinstance(self.bin_dir, Path):
            self.bin_dir = Path(self.bin_dir)
        if self.output_dir is not None and not isinstance(self.output_dir, Path):
            self.output_dir = Path(self.output_dir)
        if self.raw_link is not None and not isinstance(self.raw_link, Path):
            self.raw_link = Path(self.raw_link)
        if self.compiler_includes is not None and not isinstance(self.compiler_includes, Path):
            self.compiler_includes = Path(self.compiler_includes)
        if self.compiler_libs is not None and not isinstance(self.compiler_libs, Path):
            self.compiler_libs = Path(self.compiler_libs)

    def as_dict(self, redact_secrets: bool = True) -> dict[str, Any]:
        """Return configuration as a dictionary, optionally redacting sensitive keys."""
        from rebrew.compiler.cache import DEFAULT_CACHE_SIZE_LIMIT_MIB

        return {
            "root": str(self.root),
            "target_name": self.target_name,
            "target_binary": str(self.target_binary),
            "binary_format": self.binary_format,
            "arch": self.arch,
            "reversed_dir": str(self.reversed_dir),
            "shared_dir": str(self.shared_dir) if self.shared_dir else None,
            "bin_dir": str(self.bin_dir),
            "module": self.module,
            "check_known_bindings": self.check_known_bindings,
            "project_name": self.project_name,
            "default_jobs": self.default_jobs,
            "output_dir": str(self.output_dir),
            "raw_link": str(self.raw_link) if self.raw_link else None,
            "compiler_profile": self.compiler_profile,
            "compiler_command": self.compiler_command,
            "compiler_runner": self.compiler_runner,
            "execution_backend": self.execution_backend
            or os.environ.get("REBREW_CONTAINER_RUNTIME", "").strip()
            or "docker",
            "compiler_includes": str(self.compiler_includes),
            "compiler_libs": str(self.compiler_libs),
            "cflags": self.cflags,
            "base_cflags": self.base_cflags,
            "compile_timeout": self.compile_timeout,
            "recompile_url": self.recompile_url,
            "recompile_emit_assembly": self.recompile_emit_assembly,
            "recompile_retries": self.recompile_retries,
            "recompile_concurrency": self.recompile_concurrency,
            "defines": list(self.defines),
            "llm_endpoint": self.llm_endpoint,
            "llm_api_key": ("***" if self.llm_api_key else "")
            if redact_secrets
            else self.llm_api_key,
            "llm_model": self.llm_model,
            "llm_max_requests": self.llm_max_requests,
            "llm_max_tokens": self.llm_max_tokens,
            "llm_timeout": self.llm_timeout,
            "cache_backend": self.cache_backend,
            "metadata_backend": self.metadata_backend,
            "metadata_read_backends": list(self.metadata_read_backends),
            "metadata_write_backends": list(self.metadata_write_backends),
            # The resolved cap, not the raw field: 0 means "unset" and falls
            # back to the backend default, which is the value that matters.
            "cache_size_limit_mib": self.cache_size_limit_mib or DEFAULT_CACHE_SIZE_LIMIT_MIB,
            "all_targets": list(self.all_targets),
            "ghidra_program_path": self.ghidra_program_path,
            "ghidra_backend": self.ghidra_backend,
            "binsync_state_dir": self.binsync_state_dir,
            "binsync_user": self.binsync_user,
            "inventory_file": self.inventory_file,
            "source_ext": self.source_ext,
            "address_comments": {
                "style": self.address_comments.style,
                "regex": self.address_comments.regex,
                "template": self.address_comments.template,
            },
            "lint_naming_convention": self.lint_naming_convention,
            "lint_brace_style": self.lint_brace_style,
            "lint_indent_style": self.lint_indent_style,
            "lint_max_line_length": self.lint_max_line_length,
        }

    def validate(self) -> None:
        """Validate configuration settings, raising :class:`ConfigError` on invalid values."""
        if self.arch and self.arch not in ARCH_PRESETS:
            raise ConfigError(
                f"unknown arch {self.arch!r} (known: {', '.join(sorted(ARCH_PRESETS))})"
            )
        if self.binary_format and self.binary_format not in KNOWN_FORMATS:
            raise ConfigError(
                f"unknown format {self.binary_format!r} (known: {', '.join(sorted(KNOWN_FORMATS))})"
            )
        if self.ghidra_backend and self.ghidra_backend not in ("reva", "cli"):
            raise ConfigError(f"unknown ghidra_backend {self.ghidra_backend!r} (known: reva, cli)")
        if self.compiler_profile:
            from rebrew.compiler.toolchain import TOOLCHAINS

            if self.compiler_profile not in TOOLCHAINS:
                raise ConfigError(
                    f"unknown profile {self.compiler_profile!r} (known: {', '.join(sorted(TOOLCHAINS))})"
                )
        if self.cache_backend:
            from rebrew.compiler.cache import available_cache_backends

            known_backends = available_cache_backends()
            if self.cache_backend not in known_backends:
                raise ConfigError(
                    f"cache_backend {self.cache_backend!r} is not a registered backend "
                    f"(known: {', '.join(known_backends)})"
                )
        if self.default_jobs is not None and self.default_jobs < 1:
            raise ConfigError(f"project.jobs ({self.default_jobs}) must be >= 1")
        if self.compile_timeout is not None and self.compile_timeout < 1:
            raise ConfigError(f"compiler.timeout ({self.compile_timeout}) must be >= 1")
        if self.recompile_concurrency < 1:
            raise ConfigError(
                f"compiler.recompile_concurrency ({self.recompile_concurrency}) must be >= 1"
            )
        if not 0 <= self.recompile_retries <= MAX_RECOMPILE_RETRIES:
            raise ConfigError(
                f"compiler.recompile_retries ({self.recompile_retries}) must be "
                f"0..{MAX_RECOMPILE_RETRIES}"
            )
        if self.lint_max_line_length is not None and self.lint_max_line_length < 0:
            raise ConfigError(f"lint_max_line_length ({self.lint_max_line_length}) must be >= 0")
        if (
            self.link.stack_reserve is not None
            and self.link.stack_commit is not None
            and self.link.stack_commit > self.link.stack_reserve
        ):
            raise ConfigError(
                f"link.stack_commit ({self.link.stack_commit}) exceeds link.stack_reserve "
                f"({self.link.stack_reserve}); the Windows loader rejects that image"
            )
        if self.recompile_url:
            validate_http_url(self.recompile_url, "compiler.recompile_url")
        if self.llm_endpoint:
            validate_http_url(self.llm_endpoint, "llm.endpoint")
        if self.llm_model:
            validate_llm_model(self.llm_model)
        if self.llm_api_key and self.llm_endpoint and not is_key_safe_endpoint(self.llm_endpoint):
            raise ConfigError(
                insecure_endpoint_message(from_project=self.llm_endpoint_from_project)
            )


_PE_HEADER_READ = 64 * 1024


def pe_header_layout(bin_path: Path, fmt: str) -> dict[str, int] | None:
    """``image_base``/``.text`` facts from the PE header alone, or ``None``.

    Importing LIEF to read three header fields costs ~0.11 s on every
    command, and a PE32 with a real ``.text`` section (the MSVC image this
    tool mostly sees) answers from the existing ``pe_headers`` parser.  Any
    other shape (PE32+, no ``.text``, non-PE) returns ``None`` so the loader
    keeps its alias and error paths in one place.
    """
    if fmt not in ("auto", "pe"):
        return None
    try:
        with bin_path.open("rb") as handle:
            data = handle.read(_PE_HEADER_READ)
    except OSError:
        return None
    from rebrew.formats.pe_headers import PE32_MAGIC, pe_image_base, pe_layout

    layout = pe_layout(data)
    if layout is None or layout.magic != PE32_MAGIC:
        return None
    text = next((section for section in layout.sections if section.name == ".text"), None)
    if text is None:
        return None
    image_base = pe_image_base(data)
    if image_base is None:
        return None
    return {
        "image_base": image_base,
        "text_va": image_base + text.virtual_address,
        "text_raw_offset": text.pointer_to_raw_data,
    }


def detect_binary_layout(
    bin_path: Path, fmt: str = "auto", root: Path | None = None, target: str = ""
) -> dict[str, int]:
    """Read image base and .text section from binary headers.

    Layout-package first: when ``layout/<target>/rebrew-layout.toml`` is
    present and fresher than *bin_path*, its committed facts answer the
    question (~1 ms) instead of importing LIEF (~0.11 s) — every command
    pays this at ``load_config``.  A plain PE32 then answers from the PE
    header, and everything else falls back to ``binary_loader`` (PE, ELF,
    Mach-O).
    """
    if root is not None and target:
        from rebrew.buildsys.layout_meta import read_layout_header

        hdr = read_layout_header(root, target, bin_path)
        if hdr is not None:
            return {
                "image_base": hdr["image_base"],
                "text_va": hdr["text_va"],
                "text_raw_offset": hdr["text_raw_offset"],
            }
    fast = pe_header_layout(bin_path, fmt)
    if fast is not None:
        return fast
    try:
        from rebrew.formats.binary_loader import load_binary

        info = load_binary(bin_path, fmt=fmt)
        return {
            "image_base": info.image_base,
            "text_va": info.text_va,
            "text_raw_offset": info.text_raw_offset,
        }
    except (ImportError, OSError, ValueError, AttributeError) as e:
        config_warn(f"Could not detect binary layout for {bin_path}: {e}")
        return {"image_base": 0, "text_va": 0, "text_raw_offset": 0}


# Well-known MSVC CRT source directory patterns (relative to the project's
# toolchain/ dir).  Each tuple is (relative_path_from_toolchain, origin_name).
_CRT_SOURCE_PATTERNS: list[tuple[str, str]] = [
    ("msvc/6.0-win32/VC98/CRT/SRC", "MSVCRT"),
    ("MSVC400/CRT/SRC", "MSVCRT"),
    ("msvc/4.2-win32/CRT/SRC", "MSVCRT"),
    ("msvc/7.0-win32/crt/src", "MSVCRT"),
]


def detect_crt_sources(root: Path) -> dict[str, str]:
    """Scan the ``toolchain/`` directory for known MSVC CRT source trees.

    Returns a dict mapping origin names (e.g. ``"MSVCRT"``) to relative paths
    suitable for use in ``crt_sources`` config entries.  Uses case-insensitive
    directory matching to handle varying MSVC packaging conventions.

    Only returns the *first* match per origin so that projects with multiple
    MSVC versions don't get duplicate entries.
    """
    tools_dir = root / "toolchain"
    if not tools_dir.is_dir():
        return {}

    found: dict[str, str] = {}
    for pattern, origin in _CRT_SOURCE_PATTERNS:
        if origin in found:
            continue  # first match wins per origin
        # Case-insensitive search: walk each component
        candidate = tools_dir
        for component in pattern.split("/"):
            matched_child = None
            if candidate.is_dir():
                component_norm = unicodedata.normalize("NFC", component).casefold()
                for child in candidate.iterdir():
                    if (
                        child.is_dir()
                        and unicodedata.normalize("NFC", child.name).casefold() == component_norm
                    ):
                        matched_child = child
                        break
            if matched_child is None:
                break
            candidate = matched_child
        else:
            # All components matched
            rel = candidate.relative_to(root)
            found[origin] = rel.as_posix()

    return found


def find_root(start: Path | str | None = None) -> Path:
    """Walk up from cwd to find rebrew-project.toml.

    Since rebrew is an installable package, __file__ may point into
    site-packages rather than the project directory.  We therefore
    search from the current working directory upward, similar to how
    ``git`` locates ``.git/``.

    *start*, when given, is an EXPLICIT project root — returned verbatim
    (no walk-up); load_config(root=X) expects X to contain the toml.
    """
    if start is not None:
        # Verbatim, whether or not it holds a toml: a bare temp dir from
        # find_root(tmp_path) expects pass-through, and load_config raises
        # the proper error.  There is no walk-up from an explicit root.
        return Path(start)
    found = walk_up_to_root(Path.cwd())
    if found is None:
        raise ConfigNotFoundError(
            "Could not find rebrew-project.toml in any parent of the current directory."
        )
    return found


def lint_enum(value: Any, allowed: frozenset[str], field_name: str) -> str:
    """Return a known lint enum value, warning and falling back on typos.

    A misspelled ``naming_convention = "snake-case"`` used to pass load and
    then silently disable the style rule (``!= "none"`` but matches no branch).
    """
    text = as_str(value, "none", field_name)
    if text in allowed:
        return text
    config_warn(
        f"{field_name} = {text!r} is not one of {sorted(allowed)}; using 'none'",
    )
    return "none"


def load_lint_settings(project_raw: Mapping[str, Any]) -> dict[str, Any]:
    """Parse ``[project.lint]`` into ProjectConfig field kwargs."""
    lint_raw = as_table(project_raw.get("lint", {}), "project.lint")
    unknown_lint = set(lint_raw) - KNOWN_LINT_KEYS
    if unknown_lint:
        config_warn(
            f"rebrew-project.toml [project.lint]: unrecognized keys: {sorted(unknown_lint)}"
        )
    return {
        "lint_naming_convention": lint_enum(
            lint_raw.get("naming_convention"),
            KNOWN_LINT_NAMING,
            "project.lint.naming_convention",
        ),
        "lint_brace_style": lint_enum(
            lint_raw.get("brace_style"),
            KNOWN_LINT_BRACE,
            "project.lint.brace_style",
        ),
        "lint_indent_style": lint_enum(
            lint_raw.get("indent_style"),
            KNOWN_LINT_INDENT,
            "project.lint.indent_style",
        ),
        "lint_max_line_length": non_negative_int(
            lint_raw.get("max_line_length"),
            DEFAULT_LINT_MAX_LINE_LENGTH,
            "project.lint.max_line_length",
        ),
    }


def apply_compile_cache_config(cfg: ProjectConfig, raw: dict[str, Any]) -> None:
    """The shared owner for full-config and build-driver cache settings."""
    # The store is a pluggable component (rebrew.cache_backends entry-point
    # group); the keying semantics are shared and fixed.  Unknown cache
    # keys warn like the other sections.  An unknown or empty *backend*
    # name fails here so a typo does not wait until the first compile.
    cache_raw = as_table(raw.get("cache", {}), "cache")
    unknown_cache = set(cache_raw) - KNOWN_CACHE_KEYS
    if unknown_cache:
        config_warn(f"rebrew-project.toml [cache]: unrecognized keys: {sorted(unknown_cache)}")
    from rebrew.compiler.cache import DEFAULT_CACHE_BACKEND, available_cache_backends

    if "backend" in cache_raw:
        backend = as_str(cache_raw.get("backend"), "", "cache.backend").strip()
        if not backend:
            raise ConfigError("rebrew-project.toml [cache].backend must not be empty")
    else:
        backend = DEFAULT_CACHE_BACKEND
    known_backends = available_cache_backends()
    if backend not in known_backends:
        raise ConfigError(
            f"rebrew-project.toml [cache].backend = {backend!r} is not a "
            f"registered backend (known: {', '.join(known_backends)})"
        )
    cfg.cache_backend = backend

    if "size_limit_mib" in cache_raw:
        size_mib = safe_int(cache_raw.get("size_limit_mib"), 0, "cache.size_limit_mib")
        if size_mib < 0:
            raise ConfigError("rebrew-project.toml [cache].size_limit_mib must be >= 0")
        cfg.cache_size_limit_mib = size_mib


def load_compile_cache_config(root: Path) -> ProjectConfig:
    """Load only cache settings, without unrelated target/binary analysis."""
    cfg = ProjectConfig(root=root)
    apply_compile_cache_config(cfg, load_tomllib(root / "rebrew-project.toml"))
    return cfg


def validate_source_directories(
    root: Path,
    targets: Mapping[str, Any],
    target: str,
    shared_dir: Any = "src/shared",
    *,
    metadata_root: Path | None = None,
) -> None:
    """Reject source roots that cannot have metadata-relative file identities."""
    source_dirs = {
        f"[targets.{name}].reversed_dir": required_path(
            root, data.get("reversed_dir"), f"src/{name}", f"[targets.{name}].reversed_dir"
        )
        for name, data in targets.items()
    }
    if shared_dir is not None and str(shared_dir).strip():
        source_dirs["[project].shared_dir"] = required_path(
            root, shared_dir, "src/shared", "[project].shared_dir"
        )
    if metadata_root is None:
        from rebrew.metadata.storage import backend_routes

        try:
            reads, _ = backend_routes(
                load_tomllib(root / "rebrew-project.toml").get("metadata", {})
            )
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc
        # A remote store's root is checked on first resolution, keeping config loads offline.
        if "pgsql" in reads:
            return
        metadata_root = ProjectConfig(
            root=root, reversed_dir=source_dirs[f"[targets.{target}].reversed_dir"]
        ).metadata_dir
    metadata_root = metadata_root.resolve()
    for field_name, directory in source_dirs.items():
        if not directory.resolve().is_relative_to(metadata_root):
            raise ConfigError(
                f"rebrew-project.toml {field_name} ({directory}) is outside metadata "
                f"directory {metadata_root}; move the store to the project root, "
                "or move the directory under the store"
            )


def load_config(
    root: Path | str | None = None,
    target: str | None = None,
) -> ProjectConfig:
    """Load rebrew-project.toml.

    Args:
        root: Project root directory.  Auto-detected if ``None``.
        target: Name of the target to load (key under ``[targets]``).
                Defaults to ``project.default_target``.

    """
    root = find_root(root)
    toml_path = root / "rebrew-project.toml"
    if not toml_path.exists():
        raise ConfigNotFoundError(f"Config not found: {toml_path}")

    raw = read_project_toml(toml_path)

    project_raw = as_table(raw.get("project", {}), "project")
    targets_dict = normalized_targets(as_table(raw.get("targets", {}), "targets"))
    global_compiler_raw = as_table(raw.get("compiler", {}), "compiler")

    # --- Validate known keys to catch typos ---
    unknown_top = set(raw) - KNOWN_TOP_KEYS
    if unknown_top:
        config_warn(
            f"rebrew-project.toml: unrecognized top-level keys: {sorted(unknown_top)}",
        )
    for sec_name, known_keys in (
        ("compiler", KNOWN_COMPILER_KEYS),
        ("project", KNOWN_PROJECT_KEYS),
        ("link", KNOWN_LINK_KEYS),
    ):
        sec = (
            as_table(raw.get("link", {}), "link")
            if sec_name == "link"
            else (global_compiler_raw if sec_name == "compiler" else project_raw)
        )
        unknown_sec = set(sec) - known_keys
        if unknown_sec:
            config_warn(
                f"rebrew-project.toml [{sec_name}]: unrecognized keys: {sorted(unknown_sec)}",
            )
    # read_project_toml has held every [targets.X] to a table.
    for tgt_name, tgt_data in targets_dict.items():
        if "marker" in tgt_data:
            raise ConfigError(
                f"rebrew-project.toml [targets.{tgt_name}]: marker was replaced by module; "
                "rename the key and retain its existing value"
            )
        unknown_tgt = set(tgt_data) - KNOWN_TARGET_KEYS
        if unknown_tgt:
            config_warn(
                f"rebrew-project.toml [targets.{tgt_name}]: unrecognized keys: {sorted(unknown_tgt)}",
            )
        # Compiler settings belong to the selected target. A malformed
        # sibling must fail its own run without poisoning a healthy one.
        sibling_compiler = tgt_data.get("compiler", {})
        unknown_target_compiler = (
            set(sibling_compiler) - KNOWN_COMPILER_KEYS
            if isinstance(sibling_compiler, dict)
            else set()
        )
        if unknown_target_compiler:
            config_warn(
                f"rebrew-project.toml [targets.{tgt_name}.compiler]: "
                f"unrecognized keys: {sorted(unknown_target_compiler)}",
            )

    if not targets_dict:
        raise ConfigKeyError("rebrew-project.toml has no [targets] section")
    all_target_names = list(targets_dict)
    for tgt_key in all_target_names:
        validate_target_name(tgt_key, f"rebrew-project.toml [targets] key {tgt_key!r}")

    global_compiler = global_compiler_raw

    if target is None:
        target = project_default_target(raw)
        if target is None:
            raise ConfigKeyError(
                "rebrew-project.toml [project] is missing 'default_target'. "
                f'Add: default_target = "{all_target_names[0]}"'
            )
    # Same reason the keys are NFC: a target name copied off a macOS volume
    # arrives NFD, and a byte comparison against the NFC key reports a target
    # that exists as missing.
    target = unicodedata.normalize("NFC", target)
    if target not in targets_dict:
        raise ConfigKeyError(
            f"Target '{target}' not found in rebrew-project.toml.  Available targets: {all_target_names}"
        )
    tgt = targets_dict[target]
    target_compiler = as_table(tgt.get("compiler", {}), f"targets.{target}.compiler")
    compiler = {**global_compiler, **target_compiler}
    compiler_runner, compiler_command = split_compiler_runner(compiler)
    execution_backend = compiler.get("execution_backend", "")
    if "execution_backend" in compiler and (
        not isinstance(execution_backend, str)
        or execution_backend not in ("docker", "podman", "unshare")
    ):
        raise ConfigError("compiler.execution_backend must be docker, podman, or unshare")

    sources = tgt

    # --- Validate value types for known fields ---
    # A typo'd format or arch fails here: substituting pe / x86_32 would run
    # the wrong layout detection, disassembler, and pointer size on the binary.
    fmt_val = tgt.get("format", "pe")
    if not isinstance(fmt_val, str) or fmt_val not in KNOWN_FORMATS:
        raise ConfigError(
            f"rebrew-project.toml [targets.{target}]: unknown format {fmt_val!r} "
            f"(known: {', '.join(sorted(KNOWN_FORMATS))})"
        )

    arch_name = tgt.get("arch", "x86_32")
    if not isinstance(arch_name, str) or arch_name not in ARCH_PRESETS:
        raise ConfigError(
            f"rebrew-project.toml [targets.{target}]: unknown arch {arch_name!r} "
            f"(known: {', '.join(sorted(ARCH_PRESETS))})"
        )

    # A typo'd profile fails too: substituting msvc-6.0 would compile with the
    # wrong toolchain and let `rebrew test` demote earned STATUS.  A name is
    # valid when it is a registered toolchain (plugins add toolchains via
    # rebrew.registry without editing config.py).  `rebrew cfg target set-compiler`
    # edits the TOML without loading it, so a bad profile stays repairable.
    from rebrew.compiler.toolchain import TOOLCHAINS

    profile_val = compiler.get("profile", "msvc-6.0")
    if not isinstance(profile_val, str) or profile_val not in TOOLCHAINS:
        raise ConfigError(
            f"rebrew-project.toml [compiler]: unknown profile {profile_val!r} "
            f"(known: {', '.join(sorted(TOOLCHAINS))})"
        )

    # An unknown arch fails at the end of this function, in validate(), with a
    # ConfigError naming the known arches.  Nothing before that needs the
    # preset: every arch-derived value is read through arch_pointer_size and
    # arch_padding_bytes, which fall back rather than raise.
    bin_rel = tgt.get("binary")
    if bin_rel is None:
        raise ConfigKeyError(f"Target '{target}' in rebrew-project.toml is missing 'binary' path")
    if isinstance(bin_rel, str) and not bin_rel.strip():
        raise ConfigKeyError(f"Target '{target}' in rebrew-project.toml has empty 'binary' path")
    resolved_bin = resolve_path(root, bin_rel)
    if resolved_bin is None:
        raise ConfigKeyError(f"Target '{target}' in rebrew-project.toml has invalid 'binary' path")
    bin_path: Path = resolved_bin

    reversed_dir = required_path(
        root, sources.get("reversed_dir"), f"src/{target}", f"[targets.{target}].reversed_dir"
    )
    # Shared sources: one project-level root scanned for every target (the
    # same .c serving multiple binaries with per-version address anchors / #ifdefs).
    # An explicitly empty value disables shared sources (None).
    shared_dir_raw = project_raw.get("shared_dir", "src/shared")
    if shared_dir_raw is None or not str(shared_dir_raw).strip():
        shared_dir = None
    else:
        shared_dir = required_path(root, shared_dir_raw, "src/shared", "[project].shared_dir")
    bin_dir = required_path(
        root, sources.get("bin_dir"), f"bin/{target}", f"[targets.{target}].bin_dir"
    )
    output_dir = required_path(
        root, project_raw.get("output_dir"), "output", "[project].output_dir"
    )

    # An explicitly empty includes/libs is valid and means "no extra dir" —
    # needed by mingw/mingw (own headers) and by decomp.me MSVC tarballs
    # (msvc-6.0-sp3-win32/6.6/7.0 ship Bin+Include but no Lib).  A *missing* key still
    # falls back to the conventional default path.
    def _explicit_empty(key: str) -> bool:
        raw = compiler.get(key)
        if raw is not None and not isinstance(raw, str):
            raise ConfigError(f"rebrew-project.toml compiler.{key} must be a path string")
        return raw is not None and not raw.strip()

    from rebrew.compiler.toolchain import resolve_msvc_toolchain

    msvc_layout = resolve_msvc_toolchain(root, profile_val)
    if _explicit_empty("includes"):
        compiler_includes = Path("")
    else:
        default_inc = "toolchain/msvc/6.0-win32/source/VC98/Include"
        if msvc_layout is not None and msvc_layout[1]:
            default_inc = msvc_layout[1]
        compiler_includes = required_path(
            root,
            compiler.get("includes"),
            default_inc,
            "compiler.includes",
        )
        # Project-local tools/ absent (no --link-tools-from)?  Fall back to
        # the rebrew install's own vendored tree so fresh projects compile
        # out of the box.  Only for project-relative defaults — an explicit
        # absolute path is the user's own.
        if not compiler_includes.exists():
            alt = install_tool_alt(compiler_includes, root)
            if alt is not None:
                compiler_includes = alt
    if _explicit_empty("libs"):
        compiler_libs = Path("")
    else:
        default_lib = "toolchain/msvc/6.0-win32/source/VC98/Lib"
        if msvc_layout is not None and msvc_layout[2]:
            default_lib = msvc_layout[2]
        compiler_libs = required_path(root, compiler.get("libs"), default_lib, "compiler.libs")
        if not compiler_libs.exists():
            alt = install_tool_alt(compiler_libs, root)
            if alt is not None:
                compiler_libs = alt

    source_ext = parse_source_ext(tgt.get("source_ext", ".c"))

    defines = parse_defines(tgt.get("defines"), f"targets.{target}.defines")

    # A typo'd ghidra_backend fails instead of silently using the other transport.
    ghidra_backend_val = tgt.get("ghidra_backend", "reva")
    if not isinstance(ghidra_backend_val, str) or ghidra_backend_val not in ("reva", "cli"):
        raise ConfigError(
            f"rebrew-project.toml [targets.{target}]: unknown ghidra_backend "
            f"{ghidra_backend_val!r} (known: reva, cli)"
        )

    # Remote recompile URL: env wins when present (even if empty); otherwise TOML
    if "REBREW_RECOMPILE_URL" in os.environ:
        recompile_raw = os.environ["REBREW_RECOMPILE_URL"].strip()
        recompile_label = "REBREW_RECOMPILE_URL"
    else:
        recompile_raw = as_str(compiler.get("recompile_url"), "", "compiler.recompile_url").strip()
        recompile_label = "compiler.recompile_url"
    recompile_url_val = validate_http_url(recompile_raw, recompile_label) if recompile_raw else ""
    if execution_backend == "unshare" and recompile_url_val:
        raise ConfigError("compiler.execution_backend = unshare conflicts with remote recompile")

    # Every target, not just the active one: a bad module on a sibling
    # target would otherwise wait until ``--target`` switched to it, and
    # ``target_modules`` would advertise a blank or unsplittable module.
    modules_by_target = {
        n: target_module_value(
            t.get("module") if isinstance(t, dict) else None,
            n,
            f"targets.{n}.module",
        )
        for n, t in targets_dict.items()
        if isinstance(n, str)
    }

    # Every target's external libraries and library_modules, not just the
    # active one's: a LIBRARY row belongs to whichever target links that
    # archive, so checked under the default target it would look orphaned.
    all_library_modules: set[str] = set()
    for _t in targets_dict.values():
        if not isinstance(_t, dict):
            continue
        for _name in parse_str_list(_t.get("library_modules", []), "library_modules"):
            if _name:
                all_library_modules.add(_name)
        _ext = _t.get("external_libs")
        if isinstance(_ext, dict):
            all_library_modules.update(k for k in _ext if k)

    cfg = ProjectConfig(
        root=root,
        target_name=target or "",
        # target
        target_binary=bin_path,
        binary_format=fmt_val,
        arch=arch_name,
        # sources
        reversed_dir=reversed_dir,
        shared_dir=shared_dir,
        bin_dir=bin_dir,
        # Derived when blank: raw upper() of `server.dll` is "SERVER.DLL",
        # which matches no identifier-shaped annotation module and silently
        # filters every function out of verify/todo/status.
        module=modules_by_target[target],
        address_comments=parse_address_comment_format(
            project_raw.get("address_comments"), tgt.get("address_comments")
        ),
        r2_bogus_vas=parse_int_list(tgt.get("r2_bogus_vas", []), "r2_bogus_vas"),
        check_known_bindings=_as_bool(
            tgt.get("check_known_bindings"), f"targets.{target}.check_known_bindings"
        ),
        # project-level defaults
        project_name=as_str(project_raw.get("name"), "", "project.name"),
        default_jobs=positive_int(
            project_raw.get("jobs", DEFAULT_PROJECT_JOBS), DEFAULT_PROJECT_JOBS, "project.jobs"
        ),
        output_dir=output_dir,
        raw_link=(
            required_path(root, tgt.get("raw_link"), "", f"targets.{target}.raw_link")
            if "raw_link" in tgt
            else None
        ),
        # compiler
        compiler_profile=profile_val,
        compiler_command=compiler_command,
        compiler_runner=compiler_runner,
        execution_backend=execution_backend,
        compiler_includes=compiler_includes,
        compiler_libs=compiler_libs,
        # User-facing defaults (optimization/codegen). base_cflags are always-on
        # flags prepended by compile_to_obj; they must stay separate.
        cflags=as_str(compiler.get("cflags"), "", "compiler.cflags"),
        cflags_explicit="cflags" in compiler,
        cflags_presets=merge_cflags_presets(
            global_compiler, target_compiler, target_name=target or ""
        ),
        defines=defines,
        base_cflags=as_str(
            compiler.get("base_cflags"),
            # The MSVC glue default breaks a posix-style compiler
            # (/nologo /c /MT is not gcc syntax).  init writes base_cflags = ""
            # for those profiles; the loader default must match so hand-written
            # tomls work too.
            "" if profile_flags_style(profile_val) == "posix" else "/nologo /c /MT",
            "compiler.base_cflags",
        ),
        compile_timeout=positive_int(
            compiler.get("timeout", DEFAULT_COMPILE_TIMEOUT),
            DEFAULT_COMPILE_TIMEOUT,
            "compiler.timeout",
        ),
        recompile_url=recompile_url_val,
        recompile_emit_assembly=_as_bool(
            compiler.get("recompile_emit_assembly"), "compiler.recompile_emit_assembly"
        ),
        recompile_retries=non_negative_int(
            compiler.get("recompile_retries", DEFAULT_RECOMPILE_RETRIES),
            DEFAULT_RECOMPILE_RETRIES,
            "compiler.recompile_retries",
            maximum=MAX_RECOMPILE_RETRIES,
        ),
        recompile_concurrency=positive_int(
            compiler.get("recompile_concurrency", DEFAULT_RECOMPILE_CONCURRENCY),
            DEFAULT_RECOMPILE_CONCURRENCY,
            "compiler.recompile_concurrency",
        ),
        # project-specific
        iat_thunks=parse_int_list(tgt.get("iat_thunks", []), "iat_thunks"),
        dll_exports=parse_hex_dict(tgt.get("dll_exports", {})),
        ignored_symbols=parse_str_list(tgt.get("ignored_symbols", []), "ignored_symbols"),
        library_modules=set(parse_str_list(tgt.get("library_modules", []), "library_modules")),
        # Library modules are upper-case ("D3DX8"); normalize so lookups
        # against parsed annotations never miss on spelling.
        external_libs={
            k.upper(): v
            for k, v in parse_str_dict(tgt.get("external_libs", {}), "external_libs").items()
        },
        external_ranges=parse_va_ranges(
            tgt.get("external_ranges", []), f"targets.{target}.external_ranges"
        ),
        crt_sources=parse_str_dict(tgt.get("crt_sources", {}), "crt_sources"),
        source_ext=source_ext,
        ghidra_program_path=as_str(
            tgt.get("ghidra_program_path"), "", f"targets.{target}.ghidra_program_path"
        ),
        ghidra_backend=ghidra_backend_val,
        binsync_state_dir=as_str(
            tgt.get("binsync_state_dir"), "", f"targets.{target}.binsync_state_dir"
        ),
        binsync_user=as_str(tgt.get("binsync_user"), "", f"targets.{target}.binsync_user"),
        inventory_file=as_str(tgt.get("inventory_file"), "", f"targets.{target}.inventory_file"),
        all_targets=all_target_names,
        target_modules=set(modules_by_target.values()),
        all_library_modules=all_library_modules,
        # lint configuration — validated enums; unknown keys warn like other sections
        **load_lint_settings(project_raw),
    )

    validate_source_directories(root, targets_dict, target, shared_dir)

    # Auto-detect CRT sources if not explicitly configured
    if not cfg.crt_sources:
        cfg.crt_sources = detect_crt_sources(root)

    # Auto-detect binary layout if the binary exists
    if cfg.target_binary.exists():
        layout = detect_binary_layout(
            cfg.target_binary,
            fmt=cfg.binary_format,
            root=root,
            target=str(getattr(cfg, "target_name", "") or ""),
        )
        cfg.image_base = layout["image_base"]
        cfg.text_va = layout["text_va"]
    else:
        # A typo'd/missing binary path silently leaves image_base/text_va at 0,
        # which surfaces later as baffling byte-offset math.  Warn at load time.
        config_warn(
            f"target binary not found: {cfg.target_binary} — "
            "image_base/text_va auto-detection skipped"
        )

    # --- [link] section: byte-identical PE reconstruction settings ---
    link_raw = as_table(raw.get("link", {}), "link")

    def _opt_str(key: str) -> str | None:
        v = link_raw.get(key)
        if v is None or isinstance(v, str):
            return v
        # A version read unquoted (linker_version = 6.0) is a TOML float, not
        # the string --fix-headers matches on.  Warn rather than drop it: a
        # silent drop looks like a parity mismatch the user cannot explain.
        config_warn(f"Expected string for link.{key}, got {v!r}; ignoring")
        return None

    tsaware_raw = link_raw.get("tsaware")
    if tsaware_raw is None:
        tsaware_val: bool | None = None
    elif isinstance(tsaware_raw, bool):
        tsaware_val = tsaware_raw
    else:
        # Match _as_bool: reject stringy "false" (bool("false") is True).
        config_warn(
            f"Expected boolean for link.tsaware, got {tsaware_raw!r}; ignoring",
        )
        tsaware_val = None

    cfg.link = LinkConfig(
        file_align=parse_optional_int(link_raw.get("file_align"), "link.file_align"),
        stack_reserve=parse_optional_int(link_raw.get("stack_reserve"), "link.stack_reserve"),
        stack_commit=parse_optional_int(link_raw.get("stack_commit"), "link.stack_commit"),
        tsaware=tsaware_val,
        linker_version=_opt_str("linker_version"),
        os_version=_opt_str("os_version"),
        subsystem_version=_opt_str("subsystem_version"),
        timestamp=parse_optional_int(link_raw.get("timestamp"), "link.timestamp"),
    )
    # link.file_align is informational: VC6's /ALIGN cannot raise FileAlignment,
    # so no patch path applies it (pe_headers.PATCHABLE excludes it and the
    # parity report iterates PATCHABLE).  Warn instead of silently ignoring it.
    if cfg.link.file_align is not None:
        config_warn(
            "link.file_align is informational only — FileAlignment cannot be "
            "patched into the header (it needs a relink) and is not applied by "
            "round-trip --fix-headers"
        )
    if (
        cfg.link.stack_reserve is not None
        and cfg.link.stack_commit is not None
        and cfg.link.stack_commit > cfg.link.stack_reserve
    ):
        raise ConfigError(
            "rebrew-project.toml link.stack_commit "
            f"({cfg.link.stack_commit}) exceeds link.stack_reserve "
            f"({cfg.link.stack_reserve}); the Windows loader rejects that image"
        )

    # --- [llm] section: optional LLM-assisted GA seeding ---
    # Documented in CONFIG.md; keys populate cfg.llm_*; env vars are the
    # fallback when a TOML field is empty (see llm_seed.llm_config /
    # _resolve_model).  ``match --seed-llm`` points users at ``[llm]``.
    llm_raw = as_table(raw.get("llm", {}), "llm")
    unknown_llm = set(llm_raw) - KNOWN_LLM_KEYS
    if unknown_llm:
        config_warn(f"rebrew-project.toml [llm]: unrecognized keys: {sorted(unknown_llm)}")

    raw_endpoint = as_str(llm_raw.get("endpoint"), "", "llm.endpoint").strip()
    if raw_endpoint:
        cfg.llm_endpoint = validate_http_url(raw_endpoint, "llm.endpoint")
        cfg.llm_endpoint_from_project = True
    elif "REBREW_LLM_ENDPOINT" in os.environ and os.environ["REBREW_LLM_ENDPOINT"].strip():
        cfg.llm_endpoint = validate_http_url(
            os.environ["REBREW_LLM_ENDPOINT"].strip(), "REBREW_LLM_ENDPOINT"
        )
    else:
        cfg.llm_endpoint = ""

    toml_api_key = as_str(llm_raw.get("api_key"), "", "llm.api_key").strip()
    if toml_api_key:
        config_warn(
            "[llm].api_key is set in rebrew-project.toml — prefer "
            "REBREW_LLM_API_KEY in the environment so the key is not committed"
        )
    if "REBREW_LLM_API_KEY" in os.environ:
        cfg.llm_api_key = os.environ["REBREW_LLM_API_KEY"].strip()
    else:
        cfg.llm_api_key = toml_api_key

    toml_model = as_str(llm_raw.get("model"), "", "llm.model").strip()
    if toml_model:
        cfg.llm_model = toml_model
    elif "REBREW_LLM_MODEL" in os.environ and os.environ["REBREW_LLM_MODEL"].strip():
        cfg.llm_model = os.environ["REBREW_LLM_MODEL"].strip()
    else:
        cfg.llm_model = ""

    if cfg.llm_model:
        validate_llm_model(cfg.llm_model)

    if cfg.llm_api_key:
        if not cfg.llm_endpoint:
            config_warn(
                "[llm].api_key is set but [llm].endpoint is empty — "
                "set endpoint (or REBREW_LLM_ENDPOINT) or LLM seeding stays disabled"
            )
        elif not is_key_safe_endpoint(cfg.llm_endpoint):
            raise ConfigError(insecure_endpoint_message(from_project=cfg.llm_endpoint_from_project))

    # Parsed here, not only validated: these three are the LLM budget, and
    # `rebrew cfg effective` has to report what is in force. A bad value still
    # raises ConfigError, so a typo fails at startup rather than at the first
    # billed request. Each reads the env knob first (present wins, so one run
    # can move the budget without editing the project file) and the [llm] field
    # otherwise, matching [compiler] recompile_url.
    cfg.llm_max_requests = llm_max_requests(
        llm_budget_value(llm_raw, "max_requests", "REBREW_LLM_MAX_REQUESTS")
    )
    cfg.llm_max_tokens = llm_max_tokens(
        llm_budget_value(llm_raw, "max_tokens", "REBREW_LLM_MAX_TOKENS")
    )
    cfg.llm_timeout = llm_timeout(llm_budget_value(llm_raw, "timeout", "REBREW_LLM_TIMEOUT"))

    # --- [cache] section: compile-cache backend selection ---
    apply_compile_cache_config(cfg, raw)

    from rebrew.metadata.storage import backend_routes

    try:
        cfg.metadata_read_backends, cfg.metadata_write_backends = backend_routes(
            raw.get("metadata", {})
        )
        cfg.metadata_backend = cfg.metadata_read_backends[0]
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    cfg.validate()
    return cfg


def compiler_dir(value: Path | str | None) -> str:
    """A configured compiler directory as a flag or env value, ``""`` if unset.

    ``compiler.includes`` and ``compiler.libs`` may be explicitly empty
    ("no extra dir", for a toolchain that ships its own headers), which the
    loader stores as :class:`pathlib.Path` ``""``.  That stringifies to ``"."``,
    so ``str(cfg.compiler_includes)`` looked like a real directory to every
    consumer that tested it for truth: ``-I.`` on the compile line, ``INCLUDE=.``
    for CL.EXE, a cwd bind-mount into the container, and a header count globbed
    out of the project root.  A path with no parts carries no directory.
    """
    if value is None:
        return ""
    text = str(value)
    return text if Path(text).parts else ""
