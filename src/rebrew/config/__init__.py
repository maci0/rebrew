"""Centralised project configuration loader for rebrew.

Reads ``rebrew-project.toml`` from the project root and exposes every setting as
simple attributes so that tool scripts no longer need to hardcode paths,
image-base addresses, or compiler flags.

The configuration supports **multiple targets**.  Each target has its own
binary, source directory, and function list.  Compiler settings default to
the global ``[compiler]`` section but can be overridden per target.

Usage in any tool::

    from rebrew.config import load_config

    cfg = load_config()                  # default target
    bin_path = cfg.target_binary         # Path object
    src_dir  = cfg.reversed_dir          # Path object
    arch     = cfg.arch                  # "x86_32"
    base     = cfg.image_base            # int, e.g. 0x10000000

To load a specific target::

    cfg = load_config(target="client_exe")
"""

from __future__ import annotations

from rebrew.config.address_comments import (
    DEFAULT_ADDRESS_COMMENTS as DEFAULT_ADDRESS_COMMENTS,
)
from rebrew.config.address_comments import (
    PROJECT_CACHE_MAX as PROJECT_CACHE_MAX,
)
from rebrew.config.address_comments import (
    PROJECT_LAYOUT as PROJECT_LAYOUT,
)
from rebrew.config.address_comments import (
    PROJECT_TOML as PROJECT_TOML,
)
from rebrew.config.address_comments import (
    AddressCommentFormat as AddressCommentFormat,
)
from rebrew.config.address_comments import (
    AddressCommentLayout as AddressCommentLayout,
)
from rebrew.config.address_comments import (
    AddressCommentTarget as AddressCommentTarget,
)
from rebrew.config.address_comments import (
    address_comment_layout as address_comment_layout,
)
from rebrew.config.address_comments import (
    address_comments_for_file as address_comments_for_file,
)
from rebrew.config.address_comments import (
    cached_address_comment_layout as cached_address_comment_layout,
)
from rebrew.config.address_comments import (
    parse_address_comment_format as parse_address_comment_format,
)
from rebrew.config.address_comments import (
    project_toml as project_toml,
)
from rebrew.config.address_comments import (
    remember_project_cache as remember_project_cache,
)
from rebrew.config.constants import (
    ADDRESS_COMMENT_TEMPLATES as ADDRESS_COMMENT_TEMPLATES,
)
from rebrew.config.constants import (
    ALLOW_PRIVATE_DOWNLOAD_ENV as ALLOW_PRIVATE_DOWNLOAD_ENV,
)
from rebrew.config.constants import (
    ARCH_PRESETS as ARCH_PRESETS,
)
from rebrew.config.constants import (
    DECOMPME_API_ENV as DECOMPME_API_ENV,
)
from rebrew.config.constants import (
    DECOMPME_UPLOADS_PATH_ENV as DECOMPME_UPLOADS_PATH_ENV,
)
from rebrew.config.constants import (
    DECOMPME_UPLOADS_SCOPE_ENV as DECOMPME_UPLOADS_SCOPE_ENV,
)
from rebrew.config.constants import (
    DEFAULT_ADDRESS_COMMENT_REGEX as DEFAULT_ADDRESS_COMMENT_REGEX,
)
from rebrew.config.constants import (
    DEFAULT_COMPILE_TIMEOUT as DEFAULT_COMPILE_TIMEOUT,
)
from rebrew.config.constants import (
    DEFAULT_LINT_MAX_LINE_LENGTH as DEFAULT_LINT_MAX_LINE_LENGTH,
)
from rebrew.config.constants import (
    DEFAULT_LLM_MAX_REQUESTS as DEFAULT_LLM_MAX_REQUESTS,
)
from rebrew.config.constants import (
    DEFAULT_LLM_MAX_TOKENS as DEFAULT_LLM_MAX_TOKENS,
)
from rebrew.config.constants import (
    DEFAULT_LLM_TIMEOUT as DEFAULT_LLM_TIMEOUT,
)
from rebrew.config.constants import (
    DEFAULT_PROJECT_JOBS as DEFAULT_PROJECT_JOBS,
)
from rebrew.config.constants import (
    DEFAULT_RECOMPILE_CONCURRENCY as DEFAULT_RECOMPILE_CONCURRENCY,
)
from rebrew.config.constants import (
    DEFAULT_RECOMPILE_RETRIES as DEFAULT_RECOMPILE_RETRIES,
)
from rebrew.config.constants import (
    ENV_DISPLAY_RE as ENV_DISPLAY_RE,
)
from rebrew.config.constants import (
    FUNCTION_STRUCTURE_JSON as FUNCTION_STRUCTURE_JSON,
)
from rebrew.config.constants import (
    GHIDRA_MCP_ENDPOINT_ENV as GHIDRA_MCP_ENDPOINT_ENV,
)
from rebrew.config.constants import (
    KEY_CONTROL_RE as KEY_CONTROL_RE,
)
from rebrew.config.constants import (
    KNOWN_CACHE_KEYS as KNOWN_CACHE_KEYS,
)
from rebrew.config.constants import (
    KNOWN_COMPILER_KEYS as KNOWN_COMPILER_KEYS,
)
from rebrew.config.constants import (
    KNOWN_FORMATS as KNOWN_FORMATS,
)
from rebrew.config.constants import (
    KNOWN_LINK_KEYS as KNOWN_LINK_KEYS,
)
from rebrew.config.constants import (
    KNOWN_LINT_BRACE as KNOWN_LINT_BRACE,
)
from rebrew.config.constants import (
    KNOWN_LINT_INDENT as KNOWN_LINT_INDENT,
)
from rebrew.config.constants import (
    KNOWN_LINT_KEYS as KNOWN_LINT_KEYS,
)
from rebrew.config.constants import (
    KNOWN_LINT_NAMING as KNOWN_LINT_NAMING,
)
from rebrew.config.constants import (
    KNOWN_LLM_KEYS as KNOWN_LLM_KEYS,
)
from rebrew.config.constants import (
    KNOWN_PROJECT_KEYS as KNOWN_PROJECT_KEYS,
)
from rebrew.config.constants import (
    KNOWN_TARGET_KEYS as KNOWN_TARGET_KEYS,
)
from rebrew.config.constants import (
    KNOWN_TOP_KEYS as KNOWN_TOP_KEYS,
)
from rebrew.config.constants import (
    KUNA_SPECS_ENV as KUNA_SPECS_ENV,
)
from rebrew.config.constants import (
    LLM_PROJECT_ENDPOINT_TRUST_ENV as LLM_PROJECT_ENDPOINT_TRUST_ENV,
)
from rebrew.config.constants import (
    MAX_LLM_MAX_REQUESTS as MAX_LLM_MAX_REQUESTS,
)
from rebrew.config.constants import (
    MAX_LLM_MAX_TOKENS as MAX_LLM_MAX_TOKENS,
)
from rebrew.config.constants import (
    MAX_LLM_TIMEOUT as MAX_LLM_TIMEOUT,
)
from rebrew.config.constants import (
    MAX_RECOMPILE_RETRIES as MAX_RECOMPILE_RETRIES,
)
from rebrew.config.constants import (
    METADATA_FILENAME as METADATA_FILENAME,
)
from rebrew.config.constants import (
    MIN_LLM_TIMEOUT as MIN_LLM_TIMEOUT,
)
from rebrew.config.constants import (
    OTLP_ENDPOINT_ENV as OTLP_ENDPOINT_ENV,
)
from rebrew.config.constants import (
    REBREW_FLIRT_SIGS_DIR_ENV as REBREW_FLIRT_SIGS_DIR_ENV,
)
from rebrew.config.constants import (
    REBREW_PROJECTS_ROOT_ENV as REBREW_PROJECTS_ROOT_ENV,
)
from rebrew.config.constants import (
    REBREW_SKILLS_DIR_ENV as REBREW_SKILLS_DIR_ENV,
)
from rebrew.config.constants import (
    STRICT_REPLIES_ENV as STRICT_REPLIES_ENV,
)
from rebrew.config.constants import (
    TOOLCHAIN_OVERLAY_ENV as TOOLCHAIN_OVERLAY_ENV,
)
from rebrew.config.constants import (
    TSAWARE_BIT as TSAWARE_BIT,
)
from rebrew.config.constants import (
    XVFB_DISPLAY_ENV as XVFB_DISPLAY_ENV,
)
from rebrew.config.constants import (
    ArchPreset as ArchPreset,
)
from rebrew.config.constants import (
    ConfigWarning as ConfigWarning,
)
from rebrew.config.constants import (
    LinkConfig as LinkConfig,
)
from rebrew.config.constants import (
    arch_byte_order as arch_byte_order,
)
from rebrew.config.constants import (
    arch_is_big_endian as arch_is_big_endian,
)
from rebrew.config.constants import (
    arch_padding_bytes as arch_padding_bytes,
)
from rebrew.config.constants import (
    arch_pointer_size as arch_pointer_size,
)
from rebrew.config.constants import (
    config_warn as config_warn,
)
from rebrew.config.constants import (
    profile_flags_style as profile_flags_style,
)
from rebrew.config.constants import (
    project_toml_lock as project_toml_lock,
)
from rebrew.config.env import (
    DEFAULT_LOG_LEVEL as DEFAULT_LOG_LEVEL,
)
from rebrew.config.env import (
    ENV_FALSE as ENV_FALSE,
)
from rebrew.config.env import (
    ENV_LOG_LEVELS as ENV_LOG_LEVELS,
)
from rebrew.config.env import (
    ENV_TRUE as ENV_TRUE,
)
from rebrew.config.env import (
    check_env_absolute_executable as check_env_absolute_executable,
)
from rebrew.config.env import (
    check_env_dir as check_env_dir,
)
from rebrew.config.env import (
    check_env_display as check_env_display,
)
from rebrew.config.env import (
    check_env_insecure_cluster_host as check_env_insecure_cluster_host,
)
from rebrew.config.env import (
    check_env_job_docker_image as check_env_job_docker_image,
)
from rebrew.config.env import (
    check_env_job_token as check_env_job_token,
)
from rebrew.config.env import (
    check_env_jobs_addr as check_env_jobs_addr,
)
from rebrew.config.env import (
    check_env_llm_api_key as check_env_llm_api_key,
)
from rebrew.config.env import (
    check_env_managed_compile_limit as check_env_managed_compile_limit,
)
from rebrew.config.env import (
    check_env_managed_compilers as check_env_managed_compilers,
)
from rebrew.config.env import (
    check_env_managed_recompile_url as check_env_managed_recompile_url,
)
from rebrew.config.env import (
    check_env_ops_allowed_hosts as check_env_ops_allowed_hosts,
)
from rebrew.config.env import (
    check_env_ops_existing_dir as check_env_ops_existing_dir,
)
from rebrew.config.env import (
    check_env_ops_positive_int as check_env_ops_positive_int,
)
from rebrew.config.env import (
    check_env_ops_token as check_env_ops_token,
)
from rebrew.config.env import (
    check_env_recompile_api_key as check_env_recompile_api_key,
)
from rebrew.config.env import (
    check_env_source_date_epoch as check_env_source_date_epoch,
)
from rebrew.config.env import (
    check_env_toolchain_pin as check_env_toolchain_pin,
)
from rebrew.config.env import (
    check_env_wineprefix as check_env_wineprefix,
)
from rebrew.config.env import (
    env_dir_path as env_dir_path,
)
from rebrew.config.env import (
    env_knob_errors as env_knob_errors,
)
from rebrew.config.env import (
    env_knob_parsers as env_knob_parsers,
)
from rebrew.config.env import (
    expand_env_path as expand_env_path,
)
from rebrew.config.env import (
    insecure_endpoint_message as insecure_endpoint_message,
)
from rebrew.config.env import (
    is_key_safe_endpoint as is_key_safe_endpoint,
)
from rebrew.config.env import (
    llm_budget_value as llm_budget_value,
)
from rebrew.config.env import (
    llm_max_requests as llm_max_requests,
)
from rebrew.config.env import (
    llm_max_tokens as llm_max_tokens,
)
from rebrew.config.env import (
    llm_timeout as llm_timeout,
)
from rebrew.config.env import (
    parse_bool as parse_bool,
)
from rebrew.config.env import (
    parse_env_bool as parse_env_bool,
)
from rebrew.config.env import (
    parse_env_log_level as parse_env_log_level,
)
from rebrew.config.env import (
    source_date_epoch as source_date_epoch,
)
from rebrew.config.env import (
    validate_http_url as validate_http_url,
)
from rebrew.config.env import (
    validate_llm_model as validate_llm_model,
)
from rebrew.config.env import (
    warn_env_dir as warn_env_dir,
)
from rebrew.config.project import (
    ProjectConfig as ProjectConfig,
)
from rebrew.config.project import (
    apply_compile_cache_config as apply_compile_cache_config,
)
from rebrew.config.project import (
    compiler_dir as compiler_dir,
)
from rebrew.config.project import (
    detect_binary_layout as detect_binary_layout,
)
from rebrew.config.project import (
    detect_crt_sources as detect_crt_sources,
)
from rebrew.config.project import (
    find_root as find_root,
)
from rebrew.config.project import (
    lint_enum as lint_enum,
)
from rebrew.config.project import (
    load_compile_cache_config as load_compile_cache_config,
)
from rebrew.config.project import (
    load_config as load_config,
)
from rebrew.config.project import (
    load_lint_settings as load_lint_settings,
)
from rebrew.config.project import (
    pe_header_layout as pe_header_layout,
)
from rebrew.config.project import (
    validate_source_directories as validate_source_directories,
)
from rebrew.config.schema import (
    DEFINE_NAME_RE as DEFINE_NAME_RE,
)
from rebrew.config.schema import (
    MODULE_STRIP_RE as MODULE_STRIP_RE,
)
from rebrew.config.schema import (
    PROJECT_TABLE_SECTIONS as PROJECT_TABLE_SECTIONS,
)
from rebrew.config.schema import (
    AddressCommentsStruct as AddressCommentsStruct,
)
from rebrew.config.schema import (
    CacheSectionStruct as CacheSectionStruct,
)
from rebrew.config.schema import (
    CompilerSectionStruct as CompilerSectionStruct,
)
from rebrew.config.schema import (
    LinkSectionStruct as LinkSectionStruct,
)
from rebrew.config.schema import (
    LintSectionStruct as LintSectionStruct,
)
from rebrew.config.schema import (
    LlmSectionStruct as LlmSectionStruct,
)
from rebrew.config.schema import (
    ProjectDocumentStruct as ProjectDocumentStruct,
)
from rebrew.config.schema import (
    ProjectSectionStruct as ProjectSectionStruct,
)
from rebrew.config.schema import (
    TargetSectionStruct as TargetSectionStruct,
)
from rebrew.config.schema import (
    as_bool as as_bool,
)
from rebrew.config.schema import (
    as_str as as_str,
)
from rebrew.config.schema import (
    as_table as as_table,
)
from rebrew.config.schema import (
    check_project_document as check_project_document,
)
from rebrew.config.schema import (
    install_tool_alt as install_tool_alt,
)
from rebrew.config.schema import (
    inventory_path_for as inventory_path_for,
)
from rebrew.config.schema import (
    merge_cflags_presets as merge_cflags_presets,
)
from rebrew.config.schema import (
    non_negative_int as non_negative_int,
)
from rebrew.config.schema import (
    normalized_targets as normalized_targets,
)
from rebrew.config.schema import (
    parse_defines as parse_defines,
)
from rebrew.config.schema import (
    parse_hex_dict as parse_hex_dict,
)
from rebrew.config.schema import (
    parse_int_list as parse_int_list,
)
from rebrew.config.schema import (
    parse_optional_int as parse_optional_int,
)
from rebrew.config.schema import (
    parse_source_ext as parse_source_ext,
)
from rebrew.config.schema import (
    parse_str_dict as parse_str_dict,
)
from rebrew.config.schema import (
    parse_str_list as parse_str_list,
)
from rebrew.config.schema import (
    parse_va_ranges as parse_va_ranges,
)
from rebrew.config.schema import (
    positive_int as positive_int,
)
from rebrew.config.schema import (
    project_default_target as project_default_target,
)
from rebrew.config.schema import (
    read_project_toml as read_project_toml,
)
from rebrew.config.schema import (
    read_toml_doc as read_toml_doc,
)
from rebrew.config.schema import (
    required_path as required_path,
)
from rebrew.config.schema import (
    resolve_path as resolve_path,
)
from rebrew.config.schema import (
    safe_int as safe_int,
)
from rebrew.config.schema import (
    split_compiler_runner as split_compiler_runner,
)
from rebrew.config.schema import (
    target_module as target_module,
)
from rebrew.config.schema import (
    target_module_value as target_module_value,
)
from rebrew.config.schema import (
    validate_target_name as validate_target_name,
)
from rebrew.errors import ConfigError as ConfigError
from rebrew.errors import ConfigKeyError as ConfigKeyError
from rebrew.errors import ConfigNotFoundError as ConfigNotFoundError
from rebrew.errors import RebrewError as RebrewError
from rebrew.utils import load_tomllib as load_tomllib

_DEFINE_NAME_RE = DEFINE_NAME_RE
_KNOWN_CACHE_KEYS = KNOWN_CACHE_KEYS
_KNOWN_COMPILER_KEYS = KNOWN_COMPILER_KEYS
_KNOWN_LINK_KEYS = KNOWN_LINK_KEYS
_KNOWN_LINT_KEYS = KNOWN_LINT_KEYS
_KNOWN_LLM_KEYS = KNOWN_LLM_KEYS
_KNOWN_TOP_KEYS = KNOWN_TOP_KEYS
_PROJECT_CACHE_MAX = PROJECT_CACHE_MAX
_PROJECT_LAYOUT = PROJECT_LAYOUT
_PROJECT_TOML = PROJECT_TOML
_as_str = as_str
_as_table = as_table
_config_warn = config_warn
_detect_binary_layout = detect_binary_layout
_merge_cflags_presets = merge_cflags_presets
_normalized_targets = normalized_targets
_parse_defines = parse_defines
_parse_hex_dict = parse_hex_dict
_parse_int_list = parse_int_list
_parse_optional_int = parse_optional_int
_parse_source_ext = parse_source_ext
_parse_str_dict = parse_str_dict
_parse_str_list = parse_str_list
_parse_va_ranges = parse_va_ranges
_pe_header_layout = pe_header_layout
_positive_int = positive_int
_resolve = resolve_path
_safe_int = safe_int
_split_compiler_runner = split_compiler_runner

__all__ = [
    "ALLOW_PRIVATE_DOWNLOAD_ENV",
    "ARCH_PRESETS",
    "DECOMPME_API_ENV",
    "DECOMPME_UPLOADS_PATH_ENV",
    "DECOMPME_UPLOADS_SCOPE_ENV",
    "DEFAULT_ADDRESS_COMMENTS",
    "DEFAULT_ADDRESS_COMMENT_REGEX",
    "DEFAULT_COMPILE_TIMEOUT",
    "DEFAULT_LINT_MAX_LINE_LENGTH",
    "DEFAULT_PROJECT_JOBS",
    "DEFAULT_RECOMPILE_CONCURRENCY",
    "DEFAULT_RECOMPILE_RETRIES",
    "FUNCTION_STRUCTURE_JSON",
    "KNOWN_FORMATS",
    "KNOWN_PROJECT_KEYS",
    "KNOWN_TARGET_KEYS",
    "KUNA_SPECS_ENV",
    "LLM_PROJECT_ENDPOINT_TRUST_ENV",
    "METADATA_FILENAME",
    "OTLP_ENDPOINT_ENV",
    "REBREW_FLIRT_SIGS_DIR_ENV",
    "REBREW_PROJECTS_ROOT_ENV",
    "REBREW_SKILLS_DIR_ENV",
    "TOOLCHAIN_OVERLAY_ENV",
    "XVFB_DISPLAY_ENV",
    "AddressCommentFormat",
    "ConfigError",
    "ConfigKeyError",
    "ConfigNotFoundError",
    "ConfigWarning",
    "LinkConfig",
    "ProjectConfig",
    "RebrewError",
    "address_comments_for_file",
    "arch_byte_order",
    "arch_is_big_endian",
    "arch_padding_bytes",
    "arch_pointer_size",
    "check_env_absolute_executable",
    "check_env_dir",
    "check_env_display",
    "check_env_insecure_cluster_host",
    "check_env_job_docker_image",
    "check_env_job_token",
    "check_env_jobs_addr",
    "check_env_llm_api_key",
    "check_env_managed_compile_limit",
    "check_env_managed_compilers",
    "check_env_managed_recompile_url",
    "check_env_ops_allowed_hosts",
    "check_env_ops_existing_dir",
    "check_env_ops_positive_int",
    "check_env_ops_token",
    "check_env_recompile_api_key",
    "check_env_source_date_epoch",
    "check_env_toolchain_pin",
    "check_env_wineprefix",
    "check_project_document",
    "compiler_dir",
    "detect_crt_sources",
    "env_dir_path",
    "env_knob_errors",
    "expand_env_path",
    "find_root",
    "insecure_endpoint_message",
    "inventory_path_for",
    "is_key_safe_endpoint",
    "llm_max_requests",
    "llm_max_tokens",
    "llm_timeout",
    "load_compile_cache_config",
    "load_config",
    "parse_address_comment_format",
    "parse_bool",
    "parse_env_bool",
    "parse_env_log_level",
    "profile_flags_style",
    "project_default_target",
    "project_toml_lock",
    "read_project_toml",
    "source_date_epoch",
    "target_module",
    "validate_http_url",
    "validate_llm_model",
    "validate_source_directories",
    "validate_target_name",
    "warn_env_dir",
]
