"""lint_cflags.py — redundant CFLAGS analysis (W029).

Finds preset/function CFLAGS that restate a default or an inherited value and
can be dropped from the metadata.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console

from rebrew.config import ProjectConfig
from rebrew.utils import atomic_write_text

console = Console(stderr=True)


def _cflags_key(cflags: str) -> frozenset[str]:
    """Normalize a CFLAGS string for redundancy comparison (W029).

    Flag ORDER carries no meaning for MSVC (/O2 /Gd == /Gd /O2), so compare
    as token sets — a lower-level entry only counts as redundant when its
    whole flag set is what the higher level would already supply.
    """
    return frozenset(cflags.split())


def _inline_equals_store(found_key: str, inline_value: str, store_value: str) -> bool:
    """Whether an inline annotation duplicates its metadata-store value.

    CFLAGS compares order-insensitively (``/O2 /Gd`` == ``/Gd /O2``); every
    other key compares stripped strings.  A differing inline copy is left
    alone — deleting it would destroy information a human may rely on.
    """
    if found_key == "CFLAGS":
        return _cflags_key(inline_value.strip()) == _cflags_key(store_value.strip())
    return inline_value.strip() == store_value.strip()


@dataclass(frozen=True)
class RedundantPreset:
    """A ``compiler.cflags_presets.<MODULE>`` entry that only repeats project cflags."""

    module: str
    cflags: str
    inherited: str

    def message(self) -> str:
        """Human-readable W029 text for this preset."""
        return f"cflags_presets.{self.module} = '{self.cflags}' (= project cflags)"


@dataclass(frozen=True)
class RedundantFunctionCflags:
    """A per-function ``cflags`` entry that only repeats the inherited ladder."""

    module: str
    va: int
    cflags: str
    inherited: str

    def message(self) -> str:
        """Human-readable W029 text for this function."""
        return (
            f"{self.module} 0x{self.va:x}: cflags '{self.cflags}' (= inherited '{self.inherited}')"
        )


def check_redundant_cflags(
    cfg: ProjectConfig | None,
    preloaded_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
) -> tuple[list[RedundantPreset], list[RedundantFunctionCflags]]:
    """Collect redundant cflags entries for W029 (module presets + per-function).

    Returns ``(preset_redundant, function_redundant)`` as structured hits so
    ``--fix`` can drop them without parsing warning text.  Pure metadata +
    config logic — no .c file I/O.  Order-invariant flag comparison via
    ``_cflags_key``.

    The level ladder is: per-function cflags (rebrew-functions.toml) →
    module preset (``compiler.cflags_presets.<MODULE>``) → project
    ``compiler.cflags``.
    """
    if cfg is None:
        return [], []
    from rebrew.cli import resolve_cflags
    from rebrew.metadata import load_metadata as _load_meta

    project_cflags = str(getattr(cfg, "cflags", "") or "")
    project_key = _cflags_key(project_cflags)
    presets: dict[str, str] = getattr(cfg, "cflags_presets", {}) or {}

    preset_redundant: list[RedundantPreset] = []
    for mod, preset_cflags in sorted(presets.items()):
        if project_key and _cflags_key(str(preset_cflags)) == project_key:
            preset_redundant.append(
                RedundantPreset(
                    module=str(mod),
                    cflags=str(preset_cflags),
                    inherited=project_cflags,
                )
            )

    metadata = (
        preloaded_metadata if preloaded_metadata is not None else _load_meta(cfg.metadata_dir)
    )
    fn_redundant: list[RedundantFunctionCflags] = []
    for (module, va), meta in sorted(metadata.items(), key=lambda kv: kv[0][1]):
        fn_cflags = str(meta.get("cflags") or "").strip()
        if not fn_cflags:
            continue
        inherited = resolve_cflags(cfg, None, module)
        if _cflags_key(fn_cflags) == _cflags_key(inherited):
            fn_redundant.append(
                RedundantFunctionCflags(module=module, va=va, cflags=fn_cflags, inherited=inherited)
            )
    return preset_redundant, fn_redundant


def _drop_redundant_presets(
    cfg: ProjectConfig,
    hits: list[RedundantPreset],
    *,
    dry_run: bool,
) -> int:
    """Remove W029-redundant ``cflags_presets`` keys from ``rebrew-project.toml``.

    Only drops a module's keys when the remaining fallback is still project
    cflags (so a target override that merely undoes a different global
    preset is left alone).  Returns the number of modules dropped.  Missing
    or unreadable project TOML is a no-op (tests mock config without a file).
    """
    if not hits:
        return 0
    toml_path = Path(cfg.root) / "rebrew-project.toml"
    if not toml_path.exists():
        return 0
    import tomlkit

    try:
        doc = tomlkit.parse(toml_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        console.print(f"[yellow]warning:[/yellow] could not update {toml_path}: {exc}")
        return 0

    def _find(table: Any, mod_upper: str) -> tuple[Any, Any]:
        if table is None:
            return None, None
        presets = table.get("cflags_presets")
        if presets is None:
            return None, None
        for key in list(presets.keys()):
            if str(key).upper() == mod_upper:
                return presets, key
        return None, None

    def _drop(presets: Any, key: Any, table: Any) -> None:
        del presets[key]
        if len(presets) == 0:
            del table["cflags_presets"]

    target_compiler: Any = None
    target_name = str(getattr(cfg, "target_name", "") or "")
    if target_name:
        targets = doc.get("targets")
        if targets is not None and target_name in targets:
            tgt = targets[target_name]
            target_compiler = tgt.get("compiler") if tgt is not None else None
    global_compiler = doc.get("compiler")

    dropped = 0
    for hit in hits:
        expected = _cflags_key(hit.cflags)
        mod = hit.module.upper()
        t_presets, t_key = _find(target_compiler, mod)
        g_presets, g_key = _find(global_compiler, mod)
        t_val = _cflags_key(str(t_presets[t_key])) if t_key is not None else None
        g_val = _cflags_key(str(g_presets[g_key])) if g_key is not None else None
        remaining = None
        if t_val is not None and t_val != expected:
            remaining = t_val
        elif g_val is not None and g_val != expected:
            remaining = g_val
        if remaining is not None:
            continue
        changed = False
        if t_key is not None and t_val == expected:
            _drop(t_presets, t_key, target_compiler)
            changed = True
        if g_key is not None and g_val == expected:
            _drop(g_presets, g_key, global_compiler)
            changed = True
        if changed:
            dropped += 1

    if dropped and not dry_run:
        atomic_write_text(toml_path, tomlkit.dumps(doc), encoding="utf-8")
    return dropped
