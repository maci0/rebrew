"""Toolchain catalog — derived from the rebrew toolchain registry.

The version and target are parsed from the docker image tag
(``rebrew/msvc:6.0-win32`` → version ``6.0``, target ``win32``) so the API
surface stays in sync with the actual images.
"""

from __future__ import annotations

import re

from rebrew.toolchain import TOOLCHAINS

from .models import CompilerInfo

_TAG_RE = re.compile(r"^rebrew/(?P<family>[a-z]+):(?P<version>[0-9.]+)-(?P<target>win\d+)$")


def list_compilers() -> list[CompilerInfo]:
    """Every toolchain that has a runnable image (host-only ones are listed
    but marked by ``image=None`` at the source; here they are skipped until
    they get containers)."""
    out: list[CompilerInfo] = []
    for tool_id, spec in TOOLCHAINS.items():
        if not spec.image:
            continue
        m = _TAG_RE.match(spec.image)
        family = m.group("family") if m else spec.image.split("/")[0]
        version = m.group("version") if m else ""
        target = m.group("target") if m else ""
        out.append(
            CompilerInfo(
                id=tool_id,
                family=family,
                version=version,
                target=target,
                runtime=spec.runtime,
                flags_style=spec.flags_style,
                obj_ext=spec.obj_ext,
                description=spec.description,
            )
        )
    return out


def resolve_image(compiler_id: str) -> str | None:
    """The docker image tag for a toolchain id, or None if host-only."""
    spec = TOOLCHAINS.get(compiler_id)
    return spec.image if spec is not None else None
