"""Pydantic request/response models for the recompile API."""

from pydantic import BaseModel, Field


class CompileRequest(BaseModel):
    """A compile job: source text + a toolchain id + optional flags."""

    compiler: str = Field(..., description="Toolchain id from /api/v1/compilers")
    source: str = Field(..., description="C source text")
    flags: list[str] = Field(
        default_factory=list, description="Compiler flags, e.g. ['/O1', '/Gd']"
    )
    filename: str = Field(
        default="input.c", description="Source basename (drives the artifact name)"
    )


class CompilerInfo(BaseModel):
    """One available toolchain."""

    id: str
    family: str
    version: str
    target: str
    runtime: str
    flags_style: str
    obj_ext: str
    description: str


class CompileResult(BaseModel):
    """Outcome of a compile job."""

    id: str
    compiler: str
    status: str  # ok | error
    artifact_url: str | None = None
    compiler_version: str | None = None
    warnings: list[str] = Field(default_factory=list)
    log: str = ""
