"""Environment variable validation, URL safety checks, and LLM budget parsing."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any
lazy import ipaddress
lazy import os
lazy from collections.abc import Callable, Mapping
lazy from functools import partial
lazy from urllib.parse import urlparse

from rebrew.config.constants import (
    ALLOW_PRIVATE_DOWNLOAD_ENV,
    DECOMPME_API_ENV,
    DEFAULT_LLM_MAX_REQUESTS,
    DEFAULT_LLM_MAX_TOKENS,
    DEFAULT_LLM_TIMEOUT,
    ENV_DISPLAY_RE,
    KEY_CONTROL_RE,
    KUNA_SPECS_ENV,
    LLM_PROJECT_ENDPOINT_TRUST_ENV,
    MAX_LLM_MAX_REQUESTS,
    MAX_LLM_MAX_TOKENS,
    MAX_LLM_TIMEOUT,
    MIN_LLM_TIMEOUT,
    OTLP_ENDPOINT_ENV,
    REBREW_FLIRT_SIGS_DIR_ENV,
    REBREW_PROJECTS_ROOT_ENV,
    REBREW_SKILLS_DIR_ENV,
    TOOLCHAIN_OVERLAY_ENV,
    XVFB_DISPLAY_ENV,
    config_warn,
)
from rebrew.errors import (
    ConfigError,
)


def validate_http_url(value: str, field_name: str) -> str:
    """Return *value* when it is an http(s) URL with a host; else raise.

    Empty / whitespace-only input is treated as unset (returns ``""``) so
    optional URL knobs stay optional.  A non-empty garbage value must not
    reach compile/HTTP and fail later as a cryptic connection error.
    Credentials in the authority (``http://user:pass@host/``) are refused:
    they sit in config/logs/process listings, and the sibling validators
    (telemetry's OTLP endpoint, the authenticated recompile base URL)
    already refuse them — the shared gate must not be the one place they
    pass.  ``parsed.port`` raises ``ValueError`` for a non-numeric or
    out-of-range port on access, which the ``except`` below turns into
    the same ``ConfigError``.
    """
    text = value.strip()
    if not text:
        return ""
    message = f"{field_name} must be an http(s) URL with a host and a valid port"
    try:
        parsed = urlparse(text)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in text)
            or (parsed.port is not None and not 1 <= parsed.port <= 65535)
        ):
            raise ConfigError(message)
    except ValueError:
        raise ConfigError(message) from None
    return text


_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_UNPINNED_MODELS = frozenset({"latest", "auto", "default"})


def is_key_safe_endpoint(endpoint: str) -> bool:
    """True when a bearer key may be sent to *endpoint*: https, or http to loopback.

    A malformed authority (``http://[::1``) makes ``urlparse`` raise, which
    ``validate_http_url`` converts to a ``ConfigError``. Callers that only
    want the answer get ``False``: an unparseable endpoint is never key-safe,
    nor is one carrying credentials in its authority (``validate_http_url``
    refuses those, so the gate must agree rather than call them safe).
    """
    try:
        parsed = urlparse(endpoint)
        if parsed.username is not None or parsed.password is not None:
            return False
    except ValueError:
        return False
    if parsed.scheme == "https":
        return True
    host = parsed.hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def insecure_endpoint_message(*, from_project: bool) -> str:
    """The one message for an endpoint that may not carry a bearer key.

    ``REBREW_LLM_ALLOW_PROJECT_ENDPOINT`` decides *which host* a project
    ``[llm].endpoint`` may send the env key to, not whether the transport is
    safe, and the two rules are checked apart: an operator who sets the opt-in
    for a plain-http endpoint still fails this check.  Naming the knob in the
    case it does not help is what told them nothing, so the project-endpoint
    case says so explicitly.
    """
    message = (
        "LLM endpoint must use https when an API key is set "
        "(plain http is allowed only for loopback hosts)"
    )
    if from_project:
        message += (
            f"; {LLM_PROJECT_ENDPOINT_TRUST_ENV} picks the host, not the transport, "
            "so it does not lift this: use an https or loopback endpoint"
        )
    return message


def validate_llm_model(model: str) -> str:
    """Validate a configured LLM model id, rejecting unpinned aliases and invalid chars."""
    if model.lower() in _UNPINNED_MODELS:
        raise ConfigError(f"LLM model {model!r} is an unpinned alias; set a dated model id")
    if not _MODEL_ID_RE.fullmatch(model):
        raise ConfigError(f"LLM model {model!r} has invalid characters or length")
    return model


#: Accepted spellings of a boolean config value (lowercased, stripped).
ENV_TRUE = frozenset({"1", "true", "yes", "on"})
ENV_FALSE = frozenset({"0", "false", "no", "off"})


def parse_bool(label: str, raw: Any, *, default: bool) -> bool:
    """Parse a boolean from a config value, strictly, or raise ``ConfigError``.

    Single source for the boolean vocabulary of the whole tool.  An env knob
    and a ``rebrew-functions.toml`` field that each spelled truthiness their
    own way give one spelling two meanings: ``skip = "off"`` read as *skip*
    while ``REBREW_WINE_HEADLESS=off`` read as *off*.  A reader that treats an
    unrecognized spelling as true is the worse half, because one typo then
    turns a gate on, so unknown is an error rather than a default.  Empty or
    unset keeps *default*.
    """
    value = str(raw).strip().lower()
    if not value:
        return default
    if value in ENV_TRUE:
        return True
    if value in ENV_FALSE:
        return False
    raise ConfigError(f"{label}={raw!r} is not a boolean (use 1/true/yes/on or 0/false/no/off)")


def parse_env_bool(name: str, raw: str, *, default: bool) -> bool:
    """Parse a boolean environment variable strictly, or raise ``ConfigError``.

    Every ``REBREW_*`` boolean knob routes here, so a typo
    (``REBREW_X=flase``) or a negated spelling (``REBREW_X=false``) can never be
    read as "on": an opt-in gate that treats anything non-empty as true turns
    one mistyped value into a wrong security decision.  Empty or unset keeps
    *default*.
    """
    return parse_bool(name, raw, default=default)


#: ``REBREW_LOG_LEVEL`` spellings, and the level each selects.
ENV_LOG_LEVELS: Mapping[str, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}

#: The level a rebrew run logs at when neither ``-v``/``-q`` nor
#: ``REBREW_LOG_LEVEL`` says otherwise.
DEFAULT_LOG_LEVEL = logging.WARNING


def parse_env_log_level(raw: str, *, default: int) -> int:
    """Parse ``REBREW_LOG_LEVEL`` into a logging level, or raise ``ConfigError``.

    The base level for a run that passes no ``-v``/``-q``; an explicit flag
    outranks it.  A container or CI job wraps several rebrew commands, so
    verbosity has to be settable once in the environment rather than edited
    into every command.  An unknown name raises instead of falling back, or a
    typo would silently leave the run at the default.
    """
    value = raw.strip().lower()
    if not value:
        return default
    if value not in ENV_LOG_LEVELS:
        raise ConfigError(f"REBREW_LOG_LEVEL={raw!r} is not a level ({', '.join(ENV_LOG_LEVELS)})")
    return ENV_LOG_LEVELS[value]


def expand_env_path(raw: str) -> Path | None:
    """Normalize a directory-valued env knob's text, or ``None`` when unset.

    The one ``~``-expansion rule, shared by :func:`env_dir_path` and the
    ``KUNA_SPECS`` check in :mod:`rebrew.decompiler`.  A shell does not expand
    ``~`` inside a quoted assignment (``KUNA_SPECS='~/kuna/specs'``) nor inside
    the ``.env`` file a direnv points at, which is where these values are
    usually written: the literal string then names no directory.
    """
    value = raw.strip()
    if not value:
        return None
    return Path(value).expanduser()


def env_dir_path(name: str, raw: str) -> Path | None:
    """Resolve a directory-valued env knob to a validated path, or ``None``.

    Single source for every ``REBREW_*`` path knob the point of use probes
    with ``is_dir()``.  A mistyped path otherwise degrades quietly: the
    consuming command runs with that knob silently out of play.

    A leading ``~`` is expanded before the check, and the *expanded* path is
    what the caller gets back.  A shell does not expand ``~`` inside a quoted
    assignment (``REBREW_SKILLS_DIR='~/skills'``) nor inside the ``.env`` file
    a direnv points at, which is where these knobs are usually written, so the
    literal string reached :func:`check_env_dir` unexpanded, failed ``is_dir()``,
    and reported a valid directory as "not a directory".  Resolving and
    validating together is what keeps that from reappearing: every caller
    holds the expanded path, so none of them can disagree with the check.
    """
    path = expand_env_path(raw)
    if path is None:
        return None
    if not path.is_dir():
        # Name the path that was actually probed: a ``~`` export reads as a
        # literal here, and the raw value alone leaves the user guessing where
        # rebrew looked.
        raise ConfigError(f"{name}={raw.strip()!r} is not a directory (resolved to {path})")
    return path


def check_env_dir(name: str, raw: str) -> None:
    """Raise unless a directory-valued env knob names a directory.

    Validation half of :func:`env_dir_path`, for the callers that only need
    the check (``rebrew cfg effective``).  Raises the same error for the same
    inputs, on the same ``~``-expanded basis.
    """
    env_dir_path(name, raw)


def warn_env_dir(name: str, raw: str) -> None:
    """Report a directory-valued env knob that names no directory, and continue.

    Same check and message as :func:`check_env_dir`, for the consumers that
    must stay non-fatal: an optional backend is documented to degrade to
    "unavailable" rather than abort the run, so a mistyped path there warns
    and falls back to discovery instead of raising out of a GA worker.
    """
    try:
        check_env_dir(name, raw)
    except ConfigError as exc:
        config_warn(str(exc))


def check_env_display(raw: str) -> None:
    """Raise unless ``REBREW_XVFB_DISPLAY`` is a local ``:N`` / ``:N.S`` display.

    The headless resolver only ever matches a value against the local
    ``/tmp/.X11-unix`` socket and the ``:N`` keys its ``/proc`` scan collects,
    so a hostname display (``host:0``), a missing colon, or an empty-number
    spelling can never be adopted.  Unset stays valid: the resolver then
    picks a free display itself.
    """
    value = raw.strip()
    if value and not ENV_DISPLAY_RE.fullmatch(value):
        raise ConfigError(
            f"{XVFB_DISPLAY_ENV}={value!r} is not a local X display (use :N, e.g. :99)"
        )


def check_env_insecure_cluster_host(raw: str) -> None:
    """Raise when ``REBREW_RECOMPILE_INSECURE_CLUSTER_HOST`` is not an in-cluster host."""
    value = raw.strip()
    if not value:
        return
    if (
        len(value) > 253
        or not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", value)
        or ".." in value
        or not value.endswith((".svc", ".svc.cluster.local"))
    ):
        raise ConfigError(
            f"REBREW_RECOMPILE_INSECURE_CLUSTER_HOST={value!r} must be one in-cluster "
            "service host ending in .svc or .svc.cluster.local"
        )


def check_env_recompile_api_key(raw: str) -> None:
    """Raise when ``REBREW_RECOMPILE_API_KEY`` is not a printable ASCII header value."""
    if raw and (not raw.isascii() or any(not 33 <= ord(c) <= 126 for c in raw)):
        raise ConfigError("REBREW_RECOMPILE_API_KEY is not a printable ASCII header value")


def check_env_llm_api_key(raw: str) -> None:
    """Raise when ``REBREW_LLM_API_KEY`` carries a control or bidi character.

    Mirrors ``llm_seed._reject_control_chars_in_key`` so
    ``rebrew cfg effective`` reports a CRLF-terminated key at config time
    instead of at seed time.  Unset/empty stays valid (clears TOML key).
    """
    stripped = raw.strip()
    if not stripped:
        return
    from rebrew.utils import strip_bidi_format

    if KEY_CONTROL_RE.search(stripped) or strip_bidi_format(stripped) != stripped:
        raise ConfigError("REBREW_LLM_API_KEY contains a control or bidi-format character")


def check_env_ops_token(raw: str, *, name: str = "REBREW_OPS_TOKEN") -> None:
    """Raise when the ops/job bearer token is short or carries control chars."""
    stripped = raw.strip()
    if stripped and len(stripped.encode("utf-8")) < 32:
        raise ConfigError(f"{name} must contain at least 32 bytes")
    if stripped:
        from rebrew.utils import strip_bidi_format

        if KEY_CONTROL_RE.search(stripped) or strip_bidi_format(stripped) != stripped:
            raise ConfigError(f"{name} contains a control or bidi-format character")


def check_env_job_token(raw: str) -> None:
    """Mirror :func:`check_env_ops_token` for the Go jobs owner, which
    reads ``REBREW_JOB_TOKEN`` (not the ops token) and also requires at
    least 32 bytes before it binds."""
    check_env_ops_token(raw, name="REBREW_JOB_TOKEN")


def check_env_jobs_addr(raw: str) -> None:
    """Raise when ``REBREW_JOBS_ADDR`` is not a loopback ``host:port``.

    The Go owner (``services/jobs/cmd/rebrew-jobs/main.go``
    ``isLoopbackAddr``) refuses any non-loopback bind with a fatal log;
    without this check a typo such as ``0.0.0.0:8089`` or ``bad-addr``
    is invisible to ``rebrew cfg effective`` until the owner dies.
    Unset stays valid: the owner then binds ``127.0.0.1:8089``.
    """
    value = raw.strip()
    if not value:
        return
    host, sep, port = value.rpartition(":")
    if not sep or not host or not port.isascii() or not port.isdecimal():
        raise ConfigError(f"REBREW_JOBS_ADDR={value!r} must be a loopback host:port")
    if not 1 <= int(port) <= 65535:
        raise ConfigError(f"REBREW_JOBS_ADDR={value!r} must be a loopback host:port")
    host = host.strip("[]")
    if host == "localhost":
        return
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        raise ConfigError(f"REBREW_JOBS_ADDR={value!r} must be a loopback host:port") from None
    if not addr.is_loopback:
        raise ConfigError(f"REBREW_JOBS_ADDR={value!r} must be a loopback host:port")


def check_env_managed_compile_limit(raw: str) -> None:
    """Raise when ``REBREW_MANAGED_COMPILE_LIMIT`` is outside 1..1000.

    The Go mediator (``compile_mediator.go`` ``NewCompileMediator``)
    accepts only ``1 <= max <= 1000``; a value such as ``0``, ``-5``
    or ``1001`` would only fail when the managed path is configured.
    Unset stays valid: the limit is required only with
    ``REBREW_MANAGED_RECOMPILE_URL``.
    """
    value = raw.strip()
    if not value:
        return
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigError(f"REBREW_MANAGED_COMPILE_LIMIT={value!r} is not an int") from exc
    if not 1 <= parsed <= 1000:
        raise ConfigError(f"REBREW_MANAGED_COMPILE_LIMIT={value!r} must be in 1..1000")


def check_env_managed_recompile_url(raw: str) -> None:
    """Raise when ``REBREW_MANAGED_RECOMPILE_URL`` is not a valid upstream.

    The Go mediator pins the upstream to ``https`` (or ``http`` to a
    loopback host) with no path, query, fragment or credentials
    (``compile_mediator.go`` ``NewCompileMediator``); the Python-side
    ``validate_http_url`` alone would accept an ``http`` URL to a public
    host or one with a path, which the owner then refuses.  Unset stays
    valid: the managed path is then disabled.
    """
    value = raw.strip()
    if not value:
        return
    validate_http_url(value, "REBREW_MANAGED_RECOMPILE_URL")
    parsed = urlparse(value)
    host = parsed.hostname or ""
    # Mirror the Go gate exactly: https, or http to 127.0.0.1 / ::1 only
    # (``localhost`` as a name is not accepted by the mediator, so it is
    # not accepted here either).
    loopback_http = parsed.scheme == "http" and host in ("127.0.0.1", "::1")
    if parsed.scheme != "https" and not loopback_http:
        raise ConfigError(
            f"REBREW_MANAGED_RECOMPILE_URL={value!r} must be https, "
            "or http to a loopback host (127.0.0.1 or ::1)"
        )
    if parsed.path or parsed.query or parsed.fragment:
        raise ConfigError(
            f"REBREW_MANAGED_RECOMPILE_URL={value!r} must have no path, query or fragment"
        )


def check_env_managed_compilers(raw: str) -> None:
    """Raise when ``REBREW_MANAGED_COMPILERS`` lists no compiler.

    The Go owner requires this knob (comma-separated, non-empty entries)
    with ``REBREW_MANAGED_RECOMPILE_URL`` and fails fast on an empty list;
    without this check an empty or all-blank value is invisible to
    ``rebrew cfg effective`` until the owner dies.  Unset stays valid:
    the list is required only with ``REBREW_MANAGED_RECOMPILE_URL``.
    """
    value = raw.strip()
    if not value:
        return
    if any(not entry.strip() for entry in value.split(",")):
        raise ConfigError(f"REBREW_MANAGED_COMPILERS={value!r} must list at least one compiler")


def check_env_absolute_executable(raw: str, *, name: str) -> None:
    """Raise when a binary-valued knob is not an absolute path.

    The Go owner (``job.go`` ``Open`` / ``docker_provider.go``
    ``check``) requires an absolute executable path and, for the Docker
    provider, a ``sha256:``-pinned image; a relative spelling would
    otherwise surface as a spawn failure inside a job.  Unset stays
    valid.
    """
    value = raw.strip()
    if not value:
        return
    if not Path(value).expanduser().is_absolute():
        raise ConfigError(f"{name}={value!r} must be an absolute path")


def check_env_job_docker_image(raw: str) -> None:
    """Raise when ``REBREW_JOB_DOCKER_IMAGE`` is not a sha256-pinned id."""
    value = raw.strip()
    if not value:
        return
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ConfigError(
            f"REBREW_JOB_DOCKER_IMAGE={value!r} must be a sha256: image id "
            "(sha256: followed by 64 lowercase hex digits)"
        )


def check_env_ops_allowed_hosts(raw: str) -> None:
    """Raise when ``REBREW_OPS_ALLOWED_HOSTS`` holds a non-DNS host or port."""
    from rebrew.utils import fold_host

    for item in raw.split(","):
        item = item.strip()
        if item and not re.fullmatch(r"[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?", fold_host(item)):
            raise ConfigError(
                "REBREW_OPS_ALLOWED_HOSTS must contain exact DNS names and optional ports"
            )


def check_env_ops_positive_int(raw: str, name: str) -> None:
    """Raise when the named env value is not a positive integer."""
    value = raw.strip()
    if not value:
        return
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigError(f"{name}={value!r} is not an int") from exc
    if parsed < 1:
        raise ConfigError(f"{name}={value!r} must be >= 1")


def check_env_ops_existing_dir(raw: str, name: str) -> None:
    """Raise when the named env value is not an absolute existing directory."""
    value = raw.strip()
    if not value:
        return
    path = Path(value).expanduser()
    if not path.is_absolute() or not path.is_dir():
        raise ConfigError(f"{name}={value!r} must be an absolute path to an existing directory")


def check_env_wineprefix(raw: str) -> None:
    """Raise when ``REBREW_WINEPREFIX`` is set to a relative path.

    A relative prefix would resolve against CMake's per-target build dir and
    reach ``docker -v`` as a named volume instead of a bind mount, so the
    value is only ever usable as an absolute path.
    """
    value = raw.strip()
    if value and not Path(value).expanduser().is_absolute():
        raise ConfigError(f"REBREW_WINEPREFIX={value!r} must be an absolute path")


def source_date_epoch() -> str | None:
    """Validated UTC build epoch, or None when the caller leaves real time enabled."""
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is not None:
        check_env_source_date_epoch(raw)
    return raw


def check_env_source_date_epoch(raw: str) -> None:
    """Require nonnegative decimal seconds representable as a UTC datetime."""
    if not raw.isascii() or not raw.isdecimal() or len(raw) > 12 or int(raw) > 253402300799:
        raise ConfigError("SOURCE_DATE_EPOCH must be decimal seconds in 0..253402300799")


def check_env_toolchain_pin(raw: str) -> None:
    """Raise when ``REBREW_TOOLCHAIN`` names a profile no toolchain registers.

    The cmake bridge reads the pin as a toolchain name, so a typo otherwise
    survives every config load and surfaces as a bridge failure from inside a
    CMake build, where the env var is the least obvious of the three sources
    the name can come from (the ``/REBREW_TOOLCHAIN:`` compile flag and
    ``[compiler] profile`` both still resolve).  Unset or blank leaves the
    bridge on the project profile.
    """
    value = raw.strip()
    if not value:
        return
    from rebrew.compiler.toolchain import registry_snapshot

    registry, _origins = registry_snapshot()
    if value not in registry:
        raise ConfigError(
            f"REBREW_TOOLCHAIN={value!r} is not a known toolchain "
            f"(known: {', '.join(sorted(registry))})"
        )


#: ``REBREW_*`` knobs whose value is only read at the point of use, so
#: ``load_config`` never sees them and a typo surfaces as a spawn failure from
#: inside a compile.  Each parser takes the raw value and returns ``None``; it
#: raises when the value is unusable.  Kept as data so ``rebrew config
#: effective`` can report them without re-deciding what a valid value is.
def env_knob_parsers() -> tuple[tuple[str, Callable[[str], Any]], ...]:
    """(name, parser) pairs for the lazily-read env knobs.

    Imports are deferred: ``rebrew.utils`` imports this module, so a
    top-level import would be a cycle.
    """
    from rebrew.compiler.toolchain_paths import TOOLCHAINS_DIR_ENV
    from rebrew.utils import container_runtime

    def _wine_headless(raw: str) -> None:
        parse_env_bool("REBREW_WINE_HEADLESS", raw, default=True)

    def _log_level(raw: str) -> None:
        parse_env_log_level(raw, default=DEFAULT_LOG_LEVEL)

    def _project_endpoint_trust(raw: str) -> None:
        parse_env_bool(LLM_PROJECT_ENDPOINT_TRUST_ENV, raw, default=False)

    def _decompme_api(raw: str) -> None:
        if raw.strip():
            validate_http_url(raw, DECOMPME_API_ENV)

    def _otlp_endpoint(raw: str) -> None:
        if raw.strip():
            validate_http_url(raw, OTLP_ENDPOINT_ENV)

    def _allow_private_download(raw: str) -> None:
        parse_env_bool(ALLOW_PRIVATE_DOWNLOAD_ENV, raw, default=False)

    def _recompile_url(raw: str) -> None:
        if raw.strip():
            validate_http_url(raw, "REBREW_RECOMPILE_URL")

    def _llm_endpoint(raw: str) -> None:
        if raw.strip():
            validate_http_url(raw, "REBREW_LLM_ENDPOINT")

    def _llm_model(raw: str) -> None:
        if raw.strip():
            validate_llm_model(raw.strip())

    return (
        (ALLOW_PRIVATE_DOWNLOAD_ENV, _allow_private_download),
        (OTLP_ENDPOINT_ENV, _otlp_endpoint),
        ("REBREW_CONTAINER_RUNTIME", container_runtime),
        (DECOMPME_API_ENV, _decompme_api),
        (REBREW_FLIRT_SIGS_DIR_ENV, partial(check_env_dir, REBREW_FLIRT_SIGS_DIR_ENV)),
        (KUNA_SPECS_ENV, partial(check_env_dir, KUNA_SPECS_ENV)),
        (LLM_PROJECT_ENDPOINT_TRUST_ENV, _project_endpoint_trust),
        ("REBREW_LOG_LEVEL", _log_level),
        (REBREW_PROJECTS_ROOT_ENV, partial(check_env_dir, REBREW_PROJECTS_ROOT_ENV)),
        (REBREW_SKILLS_DIR_ENV, partial(check_env_dir, REBREW_SKILLS_DIR_ENV)),
        (TOOLCHAIN_OVERLAY_ENV, partial(check_env_dir, TOOLCHAIN_OVERLAY_ENV)),
        (TOOLCHAINS_DIR_ENV, partial(check_env_dir, TOOLCHAINS_DIR_ENV)),
        ("REBREW_WINEPREFIX", check_env_wineprefix),
        ("SOURCE_DATE_EPOCH", check_env_source_date_epoch),
        ("REBREW_TOOLCHAIN", check_env_toolchain_pin),
        ("REBREW_WINE_HEADLESS", _wine_headless),
        (XVFB_DISPLAY_ENV, check_env_display),
        ("REBREW_RECOMPILE_URL", _recompile_url),
        ("REBREW_LLM_ENDPOINT", _llm_endpoint),
        ("REBREW_LLM_MODEL", _llm_model),
        ("REBREW_LLM_MAX_REQUESTS", llm_max_requests),
        ("REBREW_LLM_MAX_TOKENS", llm_max_tokens),
        ("REBREW_LLM_TIMEOUT", llm_timeout),
        ("REBREW_RECOMPILE_API_KEY", check_env_recompile_api_key),
        ("REBREW_LLM_API_KEY", check_env_llm_api_key),
        ("REBREW_RECOMPILE_INSECURE_CLUSTER_HOST", check_env_insecure_cluster_host),
        ("REBREW_OPS_TOKEN", check_env_ops_token),
        ("REBREW_OPS_ALLOWED_HOSTS", check_env_ops_allowed_hosts),
        (
            "REBREW_OPS_MAX_DOWNLOAD",
            partial(check_env_ops_positive_int, name="REBREW_OPS_MAX_DOWNLOAD"),
        ),
        (
            "REBREW_OPS_CONCURRENCY",
            partial(check_env_ops_positive_int, name="REBREW_OPS_CONCURRENCY"),
        ),
        (
            "REBREW_OPS_FILESTORE",
            partial(check_env_ops_existing_dir, name="REBREW_OPS_FILESTORE"),
        ),
        (
            "REBREW_OPS_WORKSPACE",
            partial(check_env_ops_existing_dir, name="REBREW_OPS_WORKSPACE"),
        ),
        ("REBREW_JOB_TOKEN", check_env_job_token),
        ("REBREW_JOBS_ADDR", check_env_jobs_addr),
        ("REBREW_MANAGED_COMPILE_LIMIT", check_env_managed_compile_limit),
        ("REBREW_MANAGED_RECOMPILE_URL", check_env_managed_recompile_url),
        ("REBREW_MANAGED_COMPILERS", check_env_managed_compilers),
        ("REBREW_WORKSPACE", partial(check_env_ops_existing_dir, name="REBREW_WORKSPACE")),
        ("REBREW_JOB_DIR", partial(check_env_ops_existing_dir, name="REBREW_JOB_DIR")),
        ("REBREW_BINARY", partial(check_env_absolute_executable, name="REBREW_BINARY")),
        (
            "REBREW_DOCKER_BINARY",
            partial(check_env_absolute_executable, name="REBREW_DOCKER_BINARY"),
        ),
        ("REBREW_JOB_DOCKER_IMAGE", check_env_job_docker_image),
    )


def env_knob_errors(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Map each set-but-unparseable lazily-read env knob to its error message.

    Reports; it never raises, so the caller can print the resolved
    configuration *and* the bad knobs in one pass.  The messages come from the
    same parsers the consuming code runs, so what this says a value is
    unacceptable is what a compile would say.
    """
    env = os.environ if environ is None else environ
    errors: dict[str, str] = {}
    for name, parser in env_knob_parsers():
        if name not in env:
            continue
        try:
            parser(env[name])
        except ValueError as exc:  # ConfigError is a ValueError
            errors[name] = str(exc)
    return errors


def llm_budget_value(llm_raw: dict[str, Any], key: str, env_name: str) -> str:
    """Raw text for one ``[llm]`` budget knob, the env variable winning.

    A set env variable is the whole value, empty included, so one run can
    spend nothing (``0``) without editing the project file. Otherwise the
    ``[llm]`` field is used when it is set; leaving both unset hands the
    parser its empty string, which is the documented default.

    Unlike the warn-and-default helpers around it, a wrong type raises: this
    is a billable ceiling, so a value that never reaches the parser is a
    configuration error rather than a budget quietly set elsewhere. An
    integral float (``timeout = 90.0``) is the one non-int spelling accepted,
    matching every other integer key in the loader.
    """
    if env_name in os.environ:
        return os.environ[env_name]
    value = llm_raw.get(key)
    if value is None:
        return ""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ConfigError(f"[llm].{key} must be an integer, got {type(value).__name__}")
    if isinstance(value, float) and not value.is_integer():
        raise ConfigError(f"[llm].{key} must be an integer, got {value!r}")
    return str(int(value)) if isinstance(value, float) else str(value)


def llm_max_requests(raw: str) -> int:
    """Parse the ``REBREW_LLM_MAX_REQUESTS`` ceiling, the process LLM call budget.

    Empty / unset keeps :data:`DEFAULT_LLM_MAX_REQUESTS`; ``0`` is an
    intentional kill switch.  A non-integer or negative value raises
    ``ConfigError`` so a typo cannot silently restore the default and bill a
    paid endpoint.  Above :data:`MAX_LLM_MAX_REQUESTS` the value clamps with a
    warning.  Single source for ``load_config`` (fail fast at startup) and
    ``rebrew.matching.llm_seed`` (per-call ceiling).
    """
    value = raw.strip()
    if not value:
        return DEFAULT_LLM_MAX_REQUESTS
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigError(f"REBREW_LLM_MAX_REQUESTS={value!r} is not an int") from exc
    if parsed < 0:
        raise ConfigError(f"REBREW_LLM_MAX_REQUESTS={value!r} must be >= 0")
    if parsed > MAX_LLM_MAX_REQUESTS:
        config_warn(
            f"REBREW_LLM_MAX_REQUESTS={value!r} exceeds {MAX_LLM_MAX_REQUESTS}; "
            f"clamping to {MAX_LLM_MAX_REQUESTS}"
        )
        return MAX_LLM_MAX_REQUESTS
    return parsed


def llm_max_tokens(raw: str) -> int:
    """Parse the ``REBREW_LLM_MAX_TOKENS`` ceiling, the process LLM token budget.

    Empty / unset keeps :data:`DEFAULT_LLM_MAX_TOKENS`; ``0`` is an intentional
    kill switch that lifts the ceiling, matching ``REBREW_LLM_MAX_REQUESTS=0``.
    A non-integer or negative value raises ``ConfigError`` so a typo cannot
    silently restore the default and bill a paid endpoint.  Above
    :data:`MAX_LLM_MAX_TOKENS` the value clamps with a warning.  Single source
    for ``load_config`` (fail fast at startup) and ``rebrew.matching.llm_seed`` (the
    per-call check).
    """
    value = raw.strip()
    if not value:
        return DEFAULT_LLM_MAX_TOKENS
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigError(f"REBREW_LLM_MAX_TOKENS={value!r} is not an int") from exc
    if parsed < 0:
        raise ConfigError(f"REBREW_LLM_MAX_TOKENS={value!r} must be >= 0")
    if parsed > MAX_LLM_MAX_TOKENS:
        config_warn(
            f"REBREW_LLM_MAX_TOKENS={value!r} exceeds {MAX_LLM_MAX_TOKENS}; "
            f"clamping to {MAX_LLM_MAX_TOKENS}"
        )
        return MAX_LLM_MAX_TOKENS
    return parsed


def llm_timeout(raw: str) -> int:
    """Parse the ``REBREW_LLM_TIMEOUT`` per-request HTTP budget, in seconds.

    Empty / unset keeps :data:`DEFAULT_LLM_TIMEOUT`.  A hosted chat API
    answers a capped completion in seconds, a local model on CPU takes
    minutes for the same payload, and the ceiling is what decides whether a
    billed request returns seeds or times out empty, so it is the one
    timeout a caller must be able to move.  A non-integer or out-of-range
    value raises ``ConfigError`` rather than silently falling back to a
    default that may be too short for the configured endpoint; values above
    :data:`MAX_LLM_TIMEOUT` clamp with a warning.  Single source for
    ``load_config`` (fail fast at startup) and ``rebrew.matching.llm_seed``.
    """
    value = raw.strip()
    if not value:
        return DEFAULT_LLM_TIMEOUT
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigError(f"REBREW_LLM_TIMEOUT={value!r} is not an int") from exc
    if parsed < MIN_LLM_TIMEOUT:
        raise ConfigError(
            f"REBREW_LLM_TIMEOUT={value!r} is below {MIN_LLM_TIMEOUT}s; "
            "one LLM request cannot complete in less"
        )
    if parsed > MAX_LLM_TIMEOUT:
        config_warn(
            f"REBREW_LLM_TIMEOUT={value!r} exceeds {MAX_LLM_TIMEOUT}; clamping to {MAX_LLM_TIMEOUT}"
        )
        return MAX_LLM_TIMEOUT
    return parsed
