"""Capture a pinned MSVC translation unit's actual preprocessor output."""

from __future__ import annotations

lazy import hashlib
lazy import json
lazy import os
lazy import re
lazy import shlex
lazy import tempfile
lazy import unicodedata
lazy from dataclasses import replace
lazy from pathlib import Path
lazy from typing import Any

lazy from rebrew.compiler.image_headers import ImageHeaders
lazy from rebrew.compiler.toolchain import get_toolchain, run_toolchain
lazy from rebrew.utils import path_identity

_MARKER = re.compile(rb'^\s*#line\s+\d+\s+"((?:\\.|[^"\\])*)"', re.MULTILINE)
_SIMPLE = re.compile(r"(?i)^(?:[/\-](?:nologo|W[0-4]|O[0-2x]|G[drys]|M[DLT]d?|Z[7iI]|EH[a-z]+))$")
_LINE_DIRECTIVE = re.compile(r"(?im)^[ \t]*(?:#|%:)[ \t]*(?:line\b|[0-9]+)")
_INCLUDE_ALIAS = re.compile(r"(?im)^[ \t]*(?:#|%:)[ \t]*pragma[ \t]+include_alias\b")
_VOLATILE = re.compile(r"\b__(?:DATE|TIME|TIMESTAMP)__\b")

#: ``O_NOFOLLOW`` is absent on Windows (and older CPython builds in
#: general); ``getattr`` with a 0 default keeps the open working there,
#: mirroring :func:`rebrew.matcher.solutions._record_run`.  The resulting
#: un-followed symlink stays a refused input because the identity check
#: (``path_identity``/``is_symlink``) still runs before the open.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)

#: Windows drive-letter prefix (``C:``) in an include spelling.
_DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:")

#: MSVC ignored-option diagnostic ids (D4002/D4024/D4027/D9002).
_MSVC_IGNORED_OPT_RE = re.compile(r"\bD(?:4002|4024|4027|9002)\b")


def _read_nofollow(path: Path) -> bytes:
    """Read *path* bytes, refusing a final-component symlink where the OS allows it."""
    with os.fdopen(os.open(path, os.O_RDONLY | _O_NOFOLLOW), "rb") as stream:
        return stream.read()


def _unsafe_source(raw: bytes, *, allow_token_paste: bool = False) -> bool:
    from rebrew.compiler.cache import mask_preprocessor_comments

    masked = mask_preprocessor_comments(raw.decode("latin-1"))
    return bool(
        _LINE_DIRECTIVE.search(masked)
        or _INCLUDE_ALIAS.search(masked)
        or _VOLATILE.search(masked)
        or (not allow_token_paste and ("##" in masked or "%:%:" in masked))
    )


def _fold_name(part: str) -> str:
    return unicodedata.normalize("NFC", part).casefold()


def _protected(path: Path, root: Path) -> bool:
    for part in path.relative_to(root).parts:
        folded = _fold_name(part)
        if folded in {".git", ".ssh", ".aws", ".gnupg", "credentials"} or folded.startswith(".env"):
            return True
    return False


def _check_include_spellings(raw: bytes) -> None:
    from rebrew.compiler.cache import include_specs

    for _, name in include_specs(raw.decode("utf-8", "surrogateescape")):
        if "\\" in name:
            raise ValueError("backslash include spellings require compiler-specific review")
        if name.startswith("/") or _DRIVE_PREFIX_RE.match(name):
            raise ValueError("rooted include spellings require compiler-specific review")


def _check_missing_probes(probes: list[tuple[str, tuple[str, ...]]]) -> None:
    """Distinguish a missing earlier include from an unreadable search path."""
    for name, roots in probes:
        for root_name in roots:
            current = Path(root_name)
            for part in Path(name).parts:
                if part in ("", "."):
                    continue
                if part == "..":
                    current = current.parent
                    continue
                try:
                    with os.scandir(current) as entries:
                        matches = [
                            entry.name
                            for entry in entries
                            if _fold_name(entry.name) == _fold_name(part)
                        ]
                except FileNotFoundError:
                    break
                except OSError:
                    raise ValueError("cannot inspect an include search path") from None
                if len(matches) > 1:
                    raise ValueError("ambiguous case-insensitive include search path")
                if not matches:
                    break
                current = current / matches[0]
                if current.is_symlink():
                    raise ValueError("symlinked include search paths require review")
            else:
                raise ValueError("an earlier include candidate exists or is ambiguous")


def _check_case_path(root: Path, path: Path) -> None:
    """Refuse paths whose spelling is ambiguous to a case-insensitive compiler."""
    current = root
    for part in path.relative_to(root).parts:
        try:
            with os.scandir(current) as entries:
                matches = [
                    entry.name for entry in entries if _fold_name(entry.name) == _fold_name(part)
                ]
        except OSError:
            raise ValueError("cannot inspect a selected include path") from None
        if len(matches) != 1:
            raise ValueError("ambiguous or missing selected include path")
        current = current / matches[0]


def _closure(
    root: Path, source: Path, flags: list[str], sdk_root: Path, *, allow_token_paste: bool = False
) -> tuple[dict[str, str], dict[Path, bytes], dict[str, Any]]:
    """Conservatively prove the selected include closure before exposing files."""
    from rebrew.compiler.cache import scan_include_closure
    from rebrew.compiler.compile import extract_include_dirs

    if _protected(source, root):
        raise ValueError("protected source path cannot be mounted into the compiler")
    raw = _read_nofollow(source)
    if _unsafe_source(raw, allow_token_paste=allow_token_paste):
        raise ValueError(
            "source line directives, token pasting or volatile builtins require review"
        )
    _check_include_spellings(raw)
    contents: dict[str, bytes] = {}
    unresolved: list[tuple[str, tuple[str, ...]]] = []
    shadows: list[tuple[str, str, tuple[str, ...]]] = []
    probes: list[tuple[str, tuple[str, ...]]] = []
    lexical: list[tuple[Path, Path]] = []
    identities: dict[Path, dict[str, Any]] = {}
    includes = [*extract_include_dirs(flags), str(sdk_root)]
    try:
        paths, fallback, _stats, consistent = scan_include_closure(
            raw.decode("utf-8", "surrogateescape"),
            str(source.parent),
            tuple(includes),
            unresolved=unresolved,
            contents=contents,
            shadow=shadows,
            probes=probes,
            lexical=lexical,
            identities=identities,
            msvc_include_parents=True,
        )
    except OSError, ValueError:
        raise ValueError("ambiguous or unreadable preprocessing include closure") from None
    for data in (raw, *contents.values()):
        _check_include_spellings(data)
    if fallback or not consistent:
        raise ValueError("preprocessing include closure is incomplete or ambiguous")
    if any(
        Path(name.replace("\\", "/")).is_absolute() or ".." in Path(name.replace("\\", "/")).parts
        for name, _ in unresolved
    ):
        raise ValueError("missing include escapes a pinned search root")
    _check_missing_probes(
        [(name, roots) for mode, name, roots in shadows if mode in {"find", "escape"}]
        + probes
        + unresolved
    )
    if any(identity["links"] for identity in identities.values()):
        raise ValueError("symlinked preprocessing includes require review")
    _check_case_path(root, source)
    files: dict[Path, bytes] = {source: raw}
    for name in paths:
        path = Path(name)
        data = contents[name]
        if _unsafe_source(data, allow_token_paste=allow_token_paste):
            raise ValueError("line directives, token pasting or volatile builtins require review")
        if path.is_relative_to(sdk_root):
            _check_case_path(sdk_root, path)
            continue
        if not path.is_relative_to(root) or _protected(path, root):
            raise ValueError("protected or external include cannot be mounted into the compiler")
        _check_case_path(root, path)
        files[path] = data
    hashes: dict[str, str] = {}
    for path, data in files.items():
        if path_identity(path)["links"]:
            raise ValueError("symlinked preprocessing inputs require review")
        with os.fdopen(os.open(path, os.O_RDONLY | _O_NOFOLLOW), "rb") as stream:
            before_stat = os.fstat(stream.fileno())
            current = stream.read()
            after_stat = os.fstat(stream.fileno())
        if (
            before_stat.st_dev,
            before_stat.st_ino,
            before_stat.st_size,
            before_stat.st_mtime_ns,
            before_stat.st_ctime_ns,
            before_stat.st_mode,
        ) != (
            after_stat.st_dev,
            after_stat.st_ino,
            after_stat.st_size,
            after_stat.st_mtime_ns,
            after_stat.st_ctime_ns,
            after_stat.st_mode,
        ):
            raise ValueError("preprocessing input changed during closure review")
        current_stat = path.stat()
        if (current_stat.st_dev, current_stat.st_ino) != (after_stat.st_dev, after_stat.st_ino):
            raise ValueError("preprocessing input changed during closure review")
        if current != data:
            raise ValueError("preprocessing input changed during closure review")
        mode = path.stat().st_mode & 0o777
        if mode & 0o444 != 0o444:
            raise ValueError("selected preprocessing input permissions require review")
        for directory in (path.parent, *path.parents):
            if not directory.is_relative_to(root):
                break
            if directory.stat().st_mode & 0o555 != 0o555:
                raise ValueError("selected preprocessing directory permissions require review")
        hashes[str(path)] = hashlib.sha256(data).hexdigest()
        hashes["mode:" + str(path)] = oct(mode)
        hashes["mtime:" + str(path)] = str(after_stat.st_mtime_ns)
    proof = {
        "paths": list(paths),
        "shadows": shadows,
        "probes": probes,
        "unresolved": unresolved,
        "lexical": [(str(a), str(b)) for a, b in lexical],
        "identities": {str(path): value for path, value in identities.items()},
    }
    return hashes, files, proof


def _command(entry: dict[str, Any], root: Path, source: Path) -> tuple[str, list[str]]:
    """Admit the bounded CMake driver command without changing flag order."""
    cwd = Path(entry["directory"]).resolve()
    if not cwd.is_relative_to(root):
        raise ValueError("compile directory is outside the project")
    words = list(entry["arguments"]) if "arguments" in entry else shlex.split(entry["command"])
    try:
        index = words.index("--")
    except ValueError as exc:
        raise ValueError("compile command is not a Rebrew build driver invocation") from exc
    if index < 4 or words[index - 3 : index] != ["build", "driver", "cl"]:
        raise ValueError("compile command is not a Rebrew build driver invocation")
    args = words[index + 1 :]
    profile = ""
    flags: list[str] = []
    sources = 0
    i = 0
    while i < len(args):
        token = args[i]
        lower = token.lower()
        if lower.startswith("/rebrew_toolchain:"):
            value = token.split(":", 1)[1]
            if profile and profile != value:
                raise ValueError("compile command has conflicting toolchain profiles")
            profile = value
        elif lower in {"/c", "-c"}:
            pass
        elif token.startswith(("/Fo", "/Fd", "-Fo", "-Fd")):
            if len(token) == 3:
                i += 1
                if i >= len(args):
                    raise ValueError("compile output option has no argument")
        elif token in {"/I", "-I", "/D", "-D", "/U", "-U"}:
            i += 1
            if i >= len(args):
                raise ValueError("compiler option has no argument")
            value = args[i]
            if token[1] == "I":
                lexical = Path(value)
                if not lexical.is_absolute() or path_identity(lexical)["links"]:
                    raise ValueError("include directory must be absolute and free of symlinks")
                include = lexical.resolve()
                if not include.is_relative_to(root) or not include.is_dir():
                    raise ValueError("include directory must exist inside the project")
                value = str(include)
            flags.extend([token, value])
        elif token.startswith(("/I", "-I")):
            lexical = Path(token[2:])
            if not lexical.is_absolute() or path_identity(lexical)["links"]:
                raise ValueError("include directory must be absolute and free of symlinks")
            include = lexical.resolve()
            if not include.is_relative_to(root) or not include.is_dir():
                raise ValueError("include directory must exist inside the project")
            flags.append(token[:2] + str(include))
        elif (token.startswith(("/D", "-D", "/U", "-U")) and len(token) > 2) or _SIMPLE.fullmatch(
            token
        ):
            flags.append(token)
        elif (cwd / token).resolve() == source:
            sources += 1
        else:
            raise ValueError(f"unsupported or ambiguous compiler argument: {token}")
        i += 1
    if not profile or sources != 1:
        raise ValueError("compile command must name one source and one explicit toolchain")
    return profile, flags


def _reported_inputs(
    expanded: bytes,
    *,
    root: Path,
    staged: Path,
    before: dict[str, str],
    sdk_root: Path,
    sdk_include: str,
    sdk_files: dict[str, str],
    closure_paths: set[str],
    allow_token_paste: bool,
) -> list[str]:
    """Validate compiler-reported paths and reject spoofing or volatile builtins."""
    markers = []
    sdk_prefix = sdk_include.replace("/", "\\").lower()
    sdk_names = {_fold_name(name): name for name in sdk_files}
    scanned: set[Path] = set()
    for match in _MARKER.finditer(expanded):
        marker = match.group(1).replace(b"\\\\", b"\\").decode("utf-8", "surrogateescape")
        if marker.lower().startswith("z:\\"):
            path = marker[2:]
        elif marker.startswith("/"):
            path = marker.replace("/", "\\")
        else:
            raise ValueError(f"unverified preprocessor line marker: {marker}")
        if path.lower().startswith(sdk_prefix + "\\"):
            relative = _fold_name(path[len(sdk_prefix) + 1 :].replace("\\", "/"))
            if relative not in sdk_names:
                raise ValueError(f"preprocessor named an unpinned SDK file: {marker}")
            inspected = sdk_root / sdk_names[relative]
            if str(inspected) not in closure_paths:
                raise ValueError(
                    "compiler reported an SDK file outside the reviewed include closure"
                )
        else:
            lexical = Path(path.replace("\\", "/"))
            if path_identity(lexical)["links"]:
                raise ValueError(f"symlinked preprocessor input requires review: {marker}")
            project_path = lexical.resolve()
            if str(project_path) not in before:
                raise ValueError(f"preprocessor read an unpinned file: {marker}")
            inspected = staged / project_path.relative_to(root)
        if inspected not in scanned:
            if _unsafe_source(inspected.read_bytes(), allow_token_paste=allow_token_paste):
                raise ValueError(
                    f"line directives, token pasting or volatile builtins require review: {marker}"
                )
            scanned.add(inspected)
        markers.append(marker)
    if not markers:
        raise ValueError("compiler produced no verifiable line markers")
    return markers


def capture_msvc_context(
    project_root: Path,
    compilation_database: Path,
    source: Path,
    *,
    output: str,
    execution_backend: str | None = None,
    timeout: int = 120,
    expected_digest: str | None = None,
    allow_token_paste: bool = False,
) -> dict[str, Any]:
    """Run the selected CMake TU through its pinned compiler's ``/P`` mode.

    The caller must serialize compiler work. The result captures expanded source
    and compiler line markers, not a complete macro table or a proof of linked
    providers. Unreviewed switches, host includes and incomplete inputs fail.
    """
    if any(
        path_identity(p.absolute())["links"] for p in (project_root, compilation_database, source)
    ):
        raise ValueError("project, source and compilation database paths must not contain symlinks")
    root = project_root.resolve()
    database = compilation_database.resolve()
    source = source.resolve()
    if not source.is_relative_to(root) or not database.is_relative_to(root):
        raise ValueError("source and compilation database must belong to the project")
    # Resolve once so the gate, the header extraction and the compiler run
    # all agree on one runtime: None inherits REBREW_CONTAINER_RUNTIME (with
    # the docker default in container_runtime), and an explicit nerdctl is
    # as valid here as it is in run_toolchain.
    from rebrew.utils import container_runtime

    resolved_backend = container_runtime(execution_backend)
    if resolved_backend in {"", "unshare"}:
        raise ValueError("preprocessing requires a verified Docker or Podman image filesystem")
    raw_database = database.read_bytes()
    entries = json.loads(raw_database)
    selected = [
        e
        for e in entries
        if (Path(e["directory"]) / e["file"]).resolve() == source and e.get("output") == output
    ]
    if len(selected) != 1:
        raise ValueError("select exactly one source and build output in the compilation database")
    profile, flags = _command(selected[0], root, source)
    if allow_token_paste and not os.environ.get("SOURCE_DATE_EPOCH"):
        raise ValueError("token-paste capture requires an explicit SOURCE_DATE_EPOCH")
    if any(
        _unsafe_source(flag.encode("utf-8"), allow_token_paste=allow_token_paste) for flag in flags
    ):
        raise ValueError("volatile or token-pasting compiler macro requires review")
    spec = get_toolchain(profile)
    if spec.family != "msvc" or spec.runtime != "wine" or not spec.image or not spec.tool_root:
        raise ValueError("preprocessing requires an image-backed MSVC/Wine toolchain")
    environment = {"SOURCE_DATE_EPOCH": os.environ.get("SOURCE_DATE_EPOCH")}
    with ImageHeaders(runtime=resolved_backend) as images:
        sdk_root = images.get(profile)
        image_id = images.trees[profile]["id"]
        sdk_files = dict(images.trees[profile]["manifest"])
        sdk_include = str(images.trees[profile]["include"])
        before, selected_files, proof = _closure(
            root, source, flags, sdk_root, allow_token_paste=allow_token_paste
        )
        with tempfile.TemporaryDirectory(prefix="rebrew-preprocess-") as temporary:
            temporary_root = Path(temporary)
            workdir = temporary_root / "work"
            staged = temporary_root / "project"
            workdir.mkdir()
            staged.mkdir()
            from rebrew.compiler.compile import extract_include_dirs

            for directory in extract_include_dirs(flags):
                (staged / Path(directory).relative_to(root)).mkdir(parents=True, exist_ok=True)
            for original, data in selected_files.items():
                destination = staged / original.relative_to(root)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                destination.chmod(int(before["mode:" + str(original)], 8))
                mtime = int(before["mtime:" + str(original)])
                os.utime(destination, ns=(mtime, mtime))
                if destination.stat().st_mtime_ns != mtime:
                    raise ValueError("staged preprocessing timestamp could not be preserved")
            driver_flags = []
            for flag in flags:
                if flag.startswith("/I/"):
                    driver_flags.append("/IZ:" + flag[2:].replace("/", "\\"))
                elif flag.startswith("/") and Path(flag).is_dir():
                    driver_flags.append("Z:" + flag.replace("/", "\\"))
                else:
                    driver_flags.append(flag)
            wine_source = "Z:" + str(source).replace("/", "\\")
            clocked = environment["SOURCE_DATE_EPOCH"] is not None
            executable = str(Path(spec.tool_root) / "CL.EXE")
            runner = replace(
                spec, image_entrypoint="/usr/local/bin/rebrew-clock" if clocked else "/usr/bin/wine"
            )
            result = run_toolchain(
                runner,
                (["wine"] if clocked else []) + [executable, *driver_flags, "/P", wine_source],
                workdir=workdir,
                mounts=[(str(staged), str(root))],
                image_id=image_id,
                execution_backend=resolved_backend,
                timeout=timeout,
            )
            artifact = workdir / (source.stem + ".i")
            if result.returncode != 0 or not artifact.is_file():
                raise ValueError(f"MSVC preprocessing failed: {result.stdout}\n{result.stderr}")
            if _MSVC_IGNORED_OPT_RE.search(result.stdout + "\n" + result.stderr):
                raise ValueError("MSVC ignored or rejected an input option during preprocessing")
            expanded = artifact.read_bytes()
            markers = _reported_inputs(
                expanded,
                root=root,
                staged=staged,
                before=before,
                sdk_root=sdk_root,
                sdk_include=sdk_include,
                sdk_files=sdk_files,
                closure_paths=set(proof["paths"]),
                allow_token_paste=allow_token_paste,
            )
        after, _, after_proof = _closure(
            root, source, flags, sdk_root, allow_token_paste=allow_token_paste
        )
        if after != before or after_proof != proof or database.read_bytes() != raw_database:
            raise ValueError("preprocessing inputs changed during compiler execution")
        normalized_proof = images.normalize(proof)
        images.verify()
    if environment != {"SOURCE_DATE_EPOCH": os.environ.get("SOURCE_DATE_EPOCH")}:
        raise ValueError("preprocessing environment changed during compiler execution")
    digest_inputs = {
        "database": hashlib.sha256(raw_database).hexdigest(),
        "source": str(source),
        "output": output,
        "profile": profile,
        "image_id": image_id,
        "flags": flags,
        "environment": environment,
        "allow_token_paste": allow_token_paste,
        "sdk_files": sdk_files,
        "files": before,
        "include_closure": normalized_proof,
        "expanded_sha256": hashlib.sha256(expanded).hexdigest(),
    }
    digest = hashlib.sha256(json.dumps(digest_inputs, sort_keys=True).encode()).hexdigest()
    if expected_digest is not None and expected_digest != digest:
        raise ValueError("preprocessed context changed; review a new capture")
    return {
        **digest_inputs,
        "line_markers": markers,
        "expanded": expanded,
        "input_digest": digest,
        "macro_table_complete": False,
        "provider_evidence": False,
        "compile_database_freshness_proven": False,
        "line_markers_authenticate_origin": False,
        "complete_project_tree_snapshotted": False,
        "conservative_include_closure_complete": True,
        "original_tu_equivalence_proven": False,
    }


__all__ = ["capture_msvc_context"]
