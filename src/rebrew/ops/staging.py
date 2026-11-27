"""Filestore, URL download, workspace confinement, and retained snapshot staging."""

from __future__ import annotations

import contextlib
import threading
from pathlib import Path
lazy import dataclasses
lazy import hashlib
lazy import ipaddress
lazy import os
lazy import re
lazy import shutil
lazy import tempfile
lazy from collections.abc import Iterator
lazy from typing import Any
lazy from urllib.parse import urlsplit, urlunsplit

lazy import httpx

from rebrew.errors import RebrewError
from rebrew.ops.core import (
    APPLY_METADATA_FILE,
    COVERAGE_INPUT_UNVERIFIED,
    DNS_SLOTS,
    DNS_TIMEOUT_SECONDS,
    DOWNLOAD_CHUNK_BYTES,
    DOWNLOAD_TIMEOUT_SECONDS,
    MAX_READSET_FILE_BYTES,
    SCRATCH_DIR,
    SHA256_RE,
    OpsError,
    WorkerConfig,
    apply_project_cflags,
    bounded,
    check_cancelled,
    check_manifest_size,
    invalid_project_config,
    invalid_request,
    ops_binding,
    step,
)
lazy from rebrew.ops.requests import (
    RetainedFile,
)
lazy from rebrew.utils import path_is_relative_to, sha256_file

# ---------------------------------------------------------------------------
# Binary and project references
# ---------------------------------------------------------------------------


def sha256_hex(text: str) -> str:
    if SHA256_RE.match(text) is None:
        raise invalid_request("sha256 must be 64 lowercase hex digits")
    return text


def address_va(va: int) -> int:
    if va < 0:
        raise invalid_request(f"va must not be negative, got {va}")
    return va


def stored_file(config: WorkerConfig, key: str, sha256: str) -> Path:
    """The filestore file at *key*, checked to lie under the root and hash to *sha256*.

    Keys follow the backend filestore's rule: relative, clean, ``/``-separated.
    """
    root = config.require_filestore()
    wanted = sha256_hex(sha256)
    parts = key.split("/")
    if not key or "\\" in key or "\0" in key or any(p in ("", ".", "..") for p in parts):
        raise invalid_request("file key must be a clean relative filestore key")
    # A well-formed key the filestore cannot serve is this worker's storage (a
    # missing mount, a corrupt or substituted object), not the request: 500.
    try:
        path = root.joinpath(*parts).resolve(strict=True)
    except FileNotFoundError:
        raise OpsError("no stored file for the key") from None
    if not path_is_relative_to(path, root) or not path.is_file():
        raise OpsError("the key does not name a stored file")
    if sha256_file(path) != wanted:
        raise OpsError("the stored file does not match its sha256")
    return path


def check_download_host(hostname: str) -> str:
    """Resolve *hostname* and return a public address to fetch from.

    A bearer holder must not turn the worker into an SSRF probe of the
    loopback/private network: an IP literal is checked directly, and a DNS
    name is resolved and every address refused when it is not globally
    routable.  A resolution failure (timeout, resolver error, no answer) is
    refused rather than attempted, as an engine error (500): retryable, as a
    failed connection is; only a non-public address is a bad request (400).

    The returned address is pinned by :func:`download_file` so the fetch cannot
    re-resolve to a different (private) address between check and connect
    (DNS-rebinding TOCTOU): the check's answer is the fetch's destination.
    """
    import socket as _socket

    # getaddrinfo blocks with no timeout: a hung resolver would pin this
    # request thread (and its worker slot) for the kernel timeout. A timed-out
    # resolver cannot be cancelled, so retain at most DNS_RESOLUTION_LIMIT of
    # them and refuse further URL lookups until one finishes.
    slots = ops_binding("_DNS_SLOTS", DNS_SLOTS)
    if not slots.acquire(blocking=False):
        raise OpsError("url host cannot be resolved")
    _result: list[Any] = []
    _error: list[BaseException] = []

    def _resolve() -> None:
        try:
            _result.append(_socket.getaddrinfo(hostname, 443, type=_socket.SOCK_STREAM))
        except BaseException as exc:  # propagated below; resolve runs on a thread
            _error.append(exc)
        finally:
            slots.release()

    _thread = threading.Thread(target=_resolve, daemon=True)
    try:
        _thread.start()
    except BaseException:
        slots.release()
        raise
    _thread.join(ops_binding("DNS_TIMEOUT_SECONDS", DNS_TIMEOUT_SECONDS))
    if _thread.is_alive():
        raise OpsError("url host cannot be resolved")
    if _error:
        if isinstance(_error[0], OSError):
            raise OpsError("url host cannot be resolved") from None
        raise _error[0]
    infos = _result[0]
    if not infos:
        raise OpsError("url host cannot be resolved")
    pinned = ""
    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            raise OpsError("url host cannot be resolved") from None
        if not ip.is_global:
            raise invalid_request("url host must be a public address")
        if not pinned:
            pinned = address
    return pinned


def download_file(config: WorkerConfig, url: str, wanted: str, into: Path) -> None:
    """Write the body of a GET of the presigned HTTPS *url* to *into*.

    Redirects are not followed.  A body over ``max_download_bytes`` or one not
    hashing to *wanted* is refused.  Details never carry the URL: its query
    string is a credential.
    """

    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        raise invalid_request("url must be an https URL")
    from rebrew.config import ALLOW_PRIVATE_DOWNLOAD_ENV, parse_env_bool

    fetch_url = url
    fetch_headers: dict[str, str] = {}
    fetch_extensions: dict[str, Any] = {}
    if not parse_env_bool(
        ALLOW_PRIVATE_DOWNLOAD_ENV,
        os.environ.get(ALLOW_PRIVATE_DOWNLOAD_ENV, ""),
        default=False,
    ):
        hostname = parts.hostname
        pinned = check_download_host(hostname)
        # Pin the validated address: fetch the IP literal, keep the original
        # Host header and TLS SNI so the certificate still verifies against
        # the DNS name.  Without this the HTTP client would re-resolve the
        # name and could land on a private address the check never saw.
        if pinned != hostname:
            authority = f"[{pinned}]" if ":" in pinned else pinned
            if parts.port is not None:
                authority = f"{authority}:{parts.port}"
            fetch_url = urlunsplit(
                (parts.scheme, authority, parts.path, parts.query, parts.fragment)
            )
            fetch_headers["Host"] = parts.netloc
            fetch_extensions["sni_hostname"] = hostname
    limit = config.max_download_bytes
    digest = hashlib.sha256()
    received = 0
    # trust_env=False blocks ambient proxy redirection (a proxy could
    # resolve the name itself and bypass check_download_host), but it also
    # makes httpx ignore SSL_CERT_FILE/SSL_CERT_DIR, so an operator-pinned
    # CA bundle would silently fall back to certifi. Re-apply the operator
    # CA explicitly when present so private-CA downloads keep working.
    import ssl as _ssl

    _cafile = os.environ.get("SSL_CERT_FILE")
    _capath = os.environ.get("SSL_CERT_DIR")
    _verify: Any = True
    if _cafile:
        _verify = _ssl.create_default_context(cafile=_cafile)
    elif _capath:
        _verify = _ssl.create_default_context(capath=_capath)
    try:
        with (
            httpx.Client(
                timeout=DOWNLOAD_TIMEOUT_SECONDS,
                follow_redirects=False,
                trust_env=False,
                verify=_verify,
            ) as _http,
            _http.stream(
                "GET",
                fetch_url,
                headers=fetch_headers or None,
                extensions=fetch_extensions or None,
            ) as response,
            into.open("wb") as out,
        ):
            if response.status_code != 200:
                # Upstream 5xx is a server failure the caller cannot fix by
                # changing the request (retry later), not a 400 client error.
                if response.status_code >= 500:
                    raise OpsError(f"url answered HTTP {response.status_code}")
                raise invalid_request(f"url answered HTTP {response.status_code}")
            declared = response.headers.get("Content-Length", "")
            if declared.isdigit() and int(declared) > limit:
                raise invalid_request(f"url names more than {limit} bytes")
            for chunk in response.iter_bytes(DOWNLOAD_CHUNK_BYTES):
                check_cancelled()
                received += len(chunk)
                if received > limit:
                    raise invalid_request(f"url names more than {limit} bytes")
                digest.update(chunk)
                out.write(chunk)
    except (httpx.HTTPError, OSError) as exc:
        # A disk-full / permission failure on the write must surface as a
        # refusal with the cause, not escape as an unhandled OSError that
        # the caller reports as an internal error.  The partial file is
        # left for binary_file's finally to unlink.
        raise OpsError(f"url download failed: {exc}") from exc
    if digest.hexdigest() != wanted:
        raise invalid_request("the downloaded file does not match its sha256")


@contextlib.contextmanager
def binary_file(
    config: WorkerConfig, key: str, url: str, sha256: str, key_field: str
) -> Iterator[Path]:
    """The binary a request names by filestore *key* or by presigned *url*.

    Exactly one of the two is set.  A download lives under
    ``<workspace>/.scratch`` until the block ends.
    """
    if bool(key) == bool(url):
        raise invalid_request(f"exactly one of {key_field} and url must be set")
    check_cancelled()
    if key:
        with step("reading a stored file"):
            path = stored_file(config, key, sha256)
        yield path
        return
    wanted = sha256_hex(sha256)
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    handle, name = tempfile.mkstemp(prefix="download-", dir=scratch)
    os.close(handle)
    path = Path(name)
    try:
        with step("downloading a stored file"):
            download_file(config, url, wanted, path)
        yield path
    finally:
        path.unlink(missing_ok=True)


def confined_dir(config: WorkerConfig, text: str, what: str) -> Path:
    """The absolute directory *text*, resolved; inside the workspace when one is set."""
    path = Path(text)
    if not path.is_absolute():
        raise invalid_request(f"{what} must be an absolute path")
    resolved = path.resolve()
    if config.workspace is not None and not resolved.is_relative_to(config.workspace):
        raise invalid_request(f"{what} must be inside the worker workspace")
    return resolved


def project_root(config: WorkerConfig, project_dir: str) -> Path:
    """The rebrew project at *project_dir* (see :func:`confined_dir`)."""
    root = confined_dir(config, project_dir, "project_dir")
    if not (root / "rebrew-project.toml").is_file():
        raise invalid_request("project_dir is not a rebrew project (no rebrew-project.toml)")
    return root


def target_config(root: Path, sha256: str) -> Any:
    """The project config of the target whose binary hashes to *sha256*.

    An empty *sha256* selects the project's default target.
    """
    from rebrew.config import load_config
    from rebrew.workspace import read_config, target_binary, targets_table

    if not sha256:
        return load_config(root)
    wanted = sha256_hex(sha256)
    for name, entry in targets_table(read_config(root)).items():
        binary = target_binary(root, entry)
        if binary is not None and binary.is_file() and sha256_file(binary) == wanted:
            return load_config(root, target=name)
    raise invalid_request("no target of project_dir has a binary with that sha256")


def inside_dir(base: Path, relative: str, what: str, scope: str = "the worker workspace") -> Path:
    """*relative* resolved under *base*; an absolute path or an escape is refused."""
    if not relative or Path(relative).is_absolute():
        raise invalid_request(f"{what} must be a relative path")
    path = (base / relative).resolve()
    if path == base or not path_is_relative_to(path, base):
        raise invalid_request(f"{what} must stay inside {scope}")
    return path


def project_file(root: Path, relative: str, what: str) -> Path:
    """The existing file *relative* names inside the project at *root*."""
    path = inside_dir(root, relative, what, "project_dir")
    if not path.is_file():
        raise invalid_request(f"{what} is not a file of the project")
    return path


def target_options(root: Path, sha256: str) -> list[str]:
    """``--target`` for the target whose binary hashes to *sha256*; none for the default."""
    if not sha256:
        return []
    return [f"--target={target_config(root, sha256).target_name}"]


# ---------------------------------------------------------------------------
# Listings
# ---------------------------------------------------------------------------


def stage_retained_files(config: WorkerConfig, root: Path, files: Any, *, exclusive: bool) -> None:
    """Write a retained manifest into *root*, checking sizes and digests."""
    max_file_bytes = ops_binding("MAX_READSET_FILE_BYTES", MAX_READSET_FILE_BYTES)
    for entry in files:
        if (
            entry.size < 0
            or entry.size > max_file_bytes
            or not re.fullmatch(r"[0-9a-f]{64}", entry.digest)
        ):
            raise invalid_request("invalid retained source manifest entry")
        dest = inside_dir(root, entry.path, "source file", "snapshot")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if exclusive:
            with (
                binary_file(config, entry.key, entry.url, entry.digest, "key") as src,
                src.open("rb") as inp,
                dest.open("xb") as out,
            ):
                data = inp.read(entry.size + 1)
                if len(data) != entry.size or hashlib.sha256(data).hexdigest() != entry.digest:
                    raise invalid_request("source does not match retained manifest")
                out.write(data)
        else:
            with (
                binary_file(config, entry.key, entry.url, entry.digest, "key") as src,
                src.open("rb") as inp,
            ):
                data = inp.read(entry.size + 1)
            if len(data) != entry.size or hashlib.sha256(data).hexdigest() != entry.digest:
                raise invalid_request("source does not match retained manifest")
            dest.write_bytes(data)


def stage_retained_binary(
    config: WorkerConfig, root: Path, target: Any, sha256: str, key: str, url: str
) -> Path:
    """Copy the target binary into *root*, refusing a snapshot conflict."""
    from rebrew.workspace import target_binary

    destination = inside_dir(root, target["binary"], "target binary", "snapshot")
    with binary_file(config, key, url, sha256, "binary_key") as binary:
        if destination.exists():
            if not destination.is_file() or sha256_file(destination) != sha256:
                raise invalid_request("retained target binary conflicts with snapshot")
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(binary, destination)
        resolved = target_binary(root, target)
        if (
            resolved is None
            or resolved.resolve() != destination
            or sha256_file(destination) != sha256
        ):
            raise invalid_request("snapshot target binary does not match")
    return destination


def stage_retained_snapshot(
    config: WorkerConfig,
    root: Path,
    files: Any,
    target_name: str,
    sha256: str,
    binary_key: str,
    binary_url: str,
    *,
    exclusive: bool,
) -> Path:
    """Stage files and binary; return the destination."""
    from rebrew.workspace import read_config, targets_table

    stage_retained_files(config, root, files, exclusive=exclusive)
    target = targets_table(read_config(root)).get(target_name)
    if not isinstance(target, dict) or not isinstance(target.get("binary"), str):
        raise invalid_request("retained project has no selected target binary")
    return stage_retained_binary(config, root, target, sha256, binary_key, binary_url)


def retained_metadata_backend(root: Path) -> str:
    """The one local metadata backend a staged retained root reads, its SQLite store checked."""
    from rebrew.metadata.sqlite import DATABASE_FILENAME, metadata_database_documents
    from rebrew.metadata.storage import backend_routes
    from rebrew.workspace import read_config

    try:
        reads, writes = backend_routes(read_config(root).get("metadata", {}))
    except ValueError as exc:
        raise invalid_request(str(exc)) from exc
    if reads not in {("toml",), ("sqlite",)} or writes != reads:
        raise invalid_request("retained target requires one local metadata backend")
    if reads == ("sqlite",):
        try:
            documents = metadata_database_documents(root / DATABASE_FILENAME)
        except (ValueError, OSError, RebrewError) as exc:
            raise invalid_request(str(exc)) from exc
        if APPLY_METADATA_FILE not in documents:
            raise invalid_request("retained target requires SQLite function metadata")
    return reads[0]


def confined_snapshot_config(cfg: Any, root: Path) -> None:
    """Refuse project-config paths that could read or write outside a retained snapshot."""
    from rebrew.coverage.input_contract import CoverageInputError
    from rebrew.coverage.input_contract import confined_snapshot_config as check

    try:
        check(cfg, root)
    except CoverageInputError as exc:
        raise invalid_request(str(exc)) from exc


def retained_config(root: Path, target_name: str) -> Any:
    """The staged snapshot's project config; a config rebrew refuses is the caller's to fix: 400 invalid-project-config."""
    from rebrew.config import load_config
    from rebrew.errors import ConfigError

    try:
        return load_config(root, target=target_name)
    except ConfigError as exc:
        raise invalid_project_config(root, exc) from None


@contextlib.contextmanager
def retained_target_snapshot(
    config: WorkerConfig,
    files: list[RetainedFile],
    target_name: str,
    sha256: str,
    binary_key: str,
    binary_url: str,
    project_cflags: str = "",
) -> Iterator[Path]:
    """Stage a retained snapshot (manifest *files* and the target binary) and yield its root.

    The root is a fresh directory under ``<workspace>/.scratch``, removed when
    the block ends; the live project is never read.  Staging refuses a manifest
    over the readset bounds, a repeated or non-portable path, bytes that do not
    match, a ``rebrew-project.toml`` rebrew cannot load, config paths that leave
    the snapshot (``confined_snapshot_config``), metadata that is not one local
    backend, and a snapshot without its inventory and function metadata.  A
    block that ends without an exception is refused when it changed the binary
    or a staged file.  Every refusal is :class:`OpsError`.  *project_cflags*,
    when set, become the project cflags of the private copy
    (``apply_project_cflags``).
    """
    from rebrew.config import inventory_path_for
    from rebrew.utils import portable_path_parts

    if not target_name or not files:
        raise invalid_request("invalid retained source manifest")
    check_manifest_size(files)
    if len({f.path for f in files}) != len(files) or any(
        not portable_path_parts(f.path) for f in files
    ):
        raise invalid_request("duplicate retained source path")
    scratch = config.require_workspace() / SCRATCH_DIR
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="retained-target-", dir=scratch) as temp:
        root = Path(temp).resolve()
        with step("staging the retained snapshot"):
            destination = ops_binding("_stage_retained_snapshot", stage_retained_snapshot)(
                config, root, files, target_name, sha256, binary_key, binary_url, exclusive=False
            )
            from rebrew.metadata.sqlite import DATABASE_FILENAME

            backend = retained_metadata_backend(root)
            rewritten = apply_project_cflags(root, target_name, project_cflags)
            cfg = retained_config(root, target_name)
            confined_snapshot_config(cfg, root)
            registry, ignored = (
                root / DATABASE_FILENAME,
                cfg.metadata_dir / "rebrew-functions.toml",
            )
            if backend == "toml":
                registry, ignored = ignored, registry
            staged = {entry.path for entry in files}
            required = (inventory_path_for(cfg.reversed_dir, cfg), registry)
            if any(
                not path.is_file() or path.relative_to(root).as_posix() not in staged
                for path in required
            ):
                raise invalid_request(
                    "retained target requires its inventory and function metadata"
                )
            # The other backend's registry would be staged and never read.
            if ignored.relative_to(root).as_posix() in staged:
                raise invalid_request(
                    f"retained target carries {ignored.name}, which its {backend} metadata ignores"
                )
        yield root
        with step("checking the retained snapshot after the run"):
            if sha256_file(destination) != sha256:
                raise invalid_request("snapshot target binary changed during operation")
            for entry in files:
                path = project_file(root, entry.path, "source file")
                size, digest = (
                    rewritten
                    if rewritten and entry.path == "rebrew-project.toml"
                    else (entry.size, entry.digest)
                )
                if path.stat().st_size != size or sha256_file(path) != digest:
                    raise invalid_request("snapshot source changed during operation")


def checked_coverage_input(root: Path, req: Any) -> Any:
    """Validate the retained readset before and after each trusted calculation."""
    from rebrew.coverage.input_contract import CoverageInputError, validate_coverage_execution
    from rebrew.workspace.status import TrustedCoverage, TrustedVerification

    records = [dataclasses.asdict(record) for record in req.verification_records]
    try:
        validate_coverage_execution(
            root,
            req.rebrew_target,
            req.sha256,
            dataclasses.asdict(req.coverage_input),
            req.coverage_input_digest,
            records,
        )
        return TrustedCoverage(
            tuple(
                TrustedVerification(r.source, r.va, r.size, r.status, r.match_count)
                for r in req.verification_records
            )
        )
    except (CoverageInputError, ValueError) as exc:
        raise OpsError(bounded(str(exc)), code=COVERAGE_INPUT_UNVERIFIED, status=409) from None
