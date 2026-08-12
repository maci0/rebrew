"""Compile dispatch — each job runs inside the matching toolchain container.

The container is invoked exactly like the Dockerfile documents::

    docker run --rm -v "$PWD":/work -w /work rebrew/msvc:6.0-win32 /c f.c

(ENTRYPOINT is the compiler wrapper; the source file is mounted as the work
dir and the produced ``.obj``/``.o``/``.exe`` is copied into the artifact
store.)

No docker-py dependency: the docker CLI is invoked directly (the service
container mounts the docker socket).
"""

from __future__ import annotations

import subprocess
import tempfile
import uuid
from pathlib import Path

from .models import CompileRequest, CompileResult

#: Where compiled artifacts land (relative to the service root).  Gitignored.
ARTIFACT_DIR = Path(__file__).resolve().parents[1] / "artifacts"

_OBJ_GLOBS = ("*.obj", "*.o", "*.exe", "*.ne")

_COMPILE_TIMEOUT_S = 120


class CompileError(RuntimeError):
    """The toolchain container could not produce an artifact."""


def _artifact_store() -> Path:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    return ARTIFACT_DIR


def compile_job(req: CompileRequest, image: str) -> CompileResult:
    """Run one compile in the toolchain container and store the artifact."""
    job_id = uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="recompile_") as td:
        workdir = Path(td)
        src = workdir / req.filename
        src.write_text(req.source, encoding="utf-8")

        cmd = ["docker", "run", "--rm", "-v", f"{workdir}:/work", "-w", "/work", image]
        cmd += req.flags
        cmd += [req.filename]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_COMPILE_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            return CompileResult(
                id=job_id,
                compiler=req.compiler,
                status="error",
                log=f"compile timed out after {_COMPILE_TIMEOUT_S}s",
            )
        except OSError as exc:
            return CompileResult(
                id=job_id,
                compiler=req.compiler,
                status="error",
                log=f"docker unavailable: {exc}",
            )

        log = proc.stdout + proc.stderr

        # Find the produced artifact (the wrapper emits one .obj/.o/.exe).
        artifact = None
        for glob in _OBJ_GLOBS:
            hits = list(workdir.glob(glob))
            if hits:
                artifact = hits[0]
                break

        if artifact is None or not artifact.exists():
            return CompileResult(
                id=job_id,
                compiler=req.compiler,
                status="error",
                log=log or f"toolchain produced no artifact (exit {proc.returncode})",
            )

        store = _artifact_store()
        ext = artifact.suffix
        dest = store / f"{job_id}{ext}"
        dest.write_bytes(artifact.read_bytes())

        return CompileResult(
            id=job_id,
            compiler=req.compiler,
            status="ok",
            artifact_url=f"/api/v1/artifacts/{job_id}{ext}",
            compiler_version=_compiler_version(log),
            log=log,
        )


def _compiler_version(log: str) -> str | None:
    """Best-effort: the CL banner (e.g. 'Version 12.00.8168') or the wcc/DCC
    banner line."""
    for line in log.splitlines():
        low = line.lower()
        if "version" in low and any(
            k in low for k in ("compiler", "cl.exe", "wcc", "delphi", "copyright")
        ):
            return line.strip()
    return None
