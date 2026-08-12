"""recompile.online — FastAPI application.

Routes:
    GET  /api/v1/compilers        — available toolchains (from the rebrew registry)
    POST /api/v1/compile          — {compiler, source, flags} → CompileResult
    GET  /api/v1/artifacts/{name} — the compiled artifact bytes
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from .compilers import list_compilers, resolve_image
from .executor import ARTIFACT_DIR, compile_job
from .models import CompileRequest, CompileResult, CompilerInfo

app = FastAPI(
    title="recompile.online",
    version="0.1.0",
    description=(
        "Compiler-as-a-service over the rebrew toolchain zoo — compile C with "
        "vintage toolchains (MSVC 6.0 SP3/SP6, VC4/5/7, Watcom, Delphi 1.0) "
        "inside their pinned containers, byte-reproducibly."
    ),
)


@app.get("/api/v1/compilers", response_model=list[CompilerInfo])
def list_toolchains() -> list[CompilerInfo]:
    """Every toolchain with a runnable container image."""
    return list_compilers()


@app.post("/api/v1/compile", response_model=CompileResult)
def compile_source(req: CompileRequest) -> CompileResult:
    """Compile *req.source* with the requested toolchain container."""
    image = resolve_image(req.compiler)
    if image is None:
        raise HTTPException(
            status_code=400,
            detail=f"compiler '{req.compiler}' is host-only or unknown — see /api/v1/compilers",
        )
    return compile_job(req, image)


@app.get("/api/v1/artifacts/{artifact_name}")
def get_artifact(artifact_name: str) -> FileResponse:
    """Serve a compiled artifact by its id (e.g. ``a1b2c3d4e5f6.obj``)."""
    root = ARTIFACT_DIR.resolve()
    path = (root / artifact_name).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise HTTPException(status_code=404, detail="artifact not found")
    return FileResponse(path, filename=artifact_name)


def main() -> None:
    """Run the API server (uvicorn)."""
    import uvicorn

    uvicorn.run("recompile.app:app", host="0.0.0.0", port=8000)
