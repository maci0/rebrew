"""Core subsystem — matching and toolchain utilities."""

from rebrew.core.matching import build_iat_region as build_iat_region
from rebrew.core.matching import build_name_to_va as build_name_to_va
from rebrew.core.matching import smart_reloc_compare as smart_reloc_compare
from rebrew.core.toolchain import msvc_env_from_config as msvc_env_from_config
from rebrew.core.toolchain import resolve_runner_path as resolve_runner_path

__all__ = [
    "build_iat_region",
    "build_name_to_va",
    "msvc_env_from_config",
    "resolve_runner_path",
    "smart_reloc_compare",
]
