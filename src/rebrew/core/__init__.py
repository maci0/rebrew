"""Core subsystem — matching and toolchain utilities."""

from rebrew.core.matching import smart_reloc_compare
from rebrew.core.toolchain import msvc_env_from_config

__all__ = ["msvc_env_from_config", "smart_reloc_compare"]
