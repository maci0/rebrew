"""rebrew cache: Manage the compile result cache."""

import typer

from rebrew.cli import (
    TargetOption,
    confirm_abort,
    console,
    error_exit,
    json_print,
    require_config,
)
from rebrew.compile_cache import (
    DEFAULT_CACHE_BACKEND,
    DEFAULT_CACHE_SIZE_LIMIT_MIB,
    get_compile_cache,
)
from rebrew.utils import BYTES_PER_MIB

#: Re-exported for callers that render the CLI's own default (the JSON report
#: exposes ``size_limit_mib``): mypy's implicit-reexport rule needs the name in
#: ``__all__`` before a test may read it off this module.
__all__ = [
    "DEFAULT_CACHE_BACKEND",
    "DEFAULT_CACHE_SIZE_LIMIT_MIB",
    "app",
    "clear",
    "main_entry",
    "stats",
]


app = typer.Typer(
    help="Manage the compile result cache (.rebrew/compile_cache/).",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew cache stats · · · · · · Show cache size and entry count\n\n"
        "  rebrew cache clear · · · · · · Delete all cached .obj files\n\n"
        "  rebrew cache clear --force · · · Delete without a confirmation prompt\n\n"
        "[dim]The compile cache stores .obj bytes keyed by (source + flags + compiler), "
        "skipping docker/compiler startup on cache hit (hundreds of ms savings). "
        "The store is pluggable: \\[cache] backend in rebrew-project.toml selects it "
        "(default diskcache at {project_root}/.rebrew/compile_cache/).[/dim]"
    ),
)


@app.command(
    epilog="Examples:\n\n  rebrew cache stats --json\n\nCache entries are compiler results keyed by source, flags, and compiler identity."
)
def stats(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Show compile cache statistics."""
    cfg = require_config(target=target, json_mode=json_output)

    backend = getattr(cfg, "cache_backend", DEFAULT_CACHE_BACKEND)
    cache_dir = cfg.root / ".rebrew" / "compile_cache"
    size_limit = getattr(cfg, "cache_size_limit", DEFAULT_CACHE_SIZE_LIMIT_MIB * BYTES_PER_MIB)
    if backend == "diskcache" and not cache_dir.exists():
        if json_output:
            # Same key set as the present-cache payload below, so a consumer
            # indexes one shape either way.  The limit is the configured one
            # (a cache that does not exist yet still has a budget), and the
            # counters are zero because no lookup has run.
            json_print(
                {
                    "exists": False,
                    "backend": backend,
                    "cache_dir": str(cache_dir),
                    "entries": 0,
                    "volume_bytes": 0,
                    "volume_mib": 0,
                    "size_limit_mib": round(size_limit / BYTES_PER_MIB, 2),
                    "session_hits": 0,
                    "session_misses": 0,
                    "session_hit_rate_pct": 0.0,
                }
            )
        else:
            console.print("No compile cache found (not yet created).")
        return

    cache = get_compile_cache(cfg.root, backend, size_limit)
    try:
        info = cache.stats()
        if json_output:
            json_print({"exists": True, "backend": backend, "cache_dir": str(cache_dir), **info})
        else:
            console.print(f"Cache backend:  {backend}")
            console.print(f"Cache directory: {cache_dir}")
            console.print(f"Entries:         {info['entries']}")
            console.print(f"Disk usage:      {info['volume_mib']} MiB")
            console.print(f"Size limit:      {info['size_limit_mib']} MiB")
            # The session counters are per-process: a shared or remote store
            # cannot attribute them, so a backend omits them rather than
            # counting someone else's lookups (see CacheBackend).
            hits = int(info.get("session_hits", 0))
            misses = int(info.get("session_misses", 0))
            if hits + misses > 0:
                console.print(
                    f"Session:         {hits} hits, {misses} misses"
                    f" ({info.get('session_hit_rate_pct', 0.0)}% hit rate)"
                )
            else:
                console.print("Session:         no lookups this session")
    finally:
        cache.close()


@app.command(
    epilog="Examples:\n\n  rebrew cache clear --force\n\nCache entries are compiler results keyed by source, flags, and compiler identity."
)
def clear(
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Delete all cached .obj files."""
    cfg = require_config(target=target, json_mode=json_output)

    backend = getattr(cfg, "cache_backend", DEFAULT_CACHE_BACKEND)
    cache_dir = cfg.root / ".rebrew" / "compile_cache"
    if backend == "diskcache" and not cache_dir.exists():
        if json_output:
            json_print(
                {
                    "cleared": 0,
                    "cache_dir": str(cache_dir),
                    "backend": backend,
                    "message": "No compile cache found",
                }
            )
        else:
            console.print("No compile cache found (nothing to clear).")
        return

    if json_output and not force:
        error_exit(
            "--json cannot prompt for confirmation; pass --force to clear the cache",
            json_mode=True,
        )

    cache = get_compile_cache(
        cfg.root,
        backend,
        getattr(cfg, "cache_size_limit", DEFAULT_CACHE_SIZE_LIMIT_MIB * BYTES_PER_MIB),
    )
    try:
        count = cache.count
        if not force and not json_output:
            console.print(f"About to delete {count} cached entries from {cache_dir}")
            # Prompt on stderr. stdout is the pipe; a prompt there disappears
            # when stdout is redirected and the command still blocks on stdin.
            confirm_abort(f"Delete {count} cached compile results?")
        cache.clear()
        if json_output:
            json_print({"cleared": count, "cache_dir": str(cache_dir), "backend": backend})
        else:
            console.print(f"Cleared {count} cached entries from {cache_dir}")
    finally:
        cache.close()


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)


if __name__ == "__main__":
    main_entry()
