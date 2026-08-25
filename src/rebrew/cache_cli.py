"""rebrew cache: Manage the compile result cache."""

import typer
from rich.console import Console

from rebrew.cli import TargetOption, error_exit, json_print, require_config
from rebrew.compile_cache import get_compile_cache

console = Console(stderr=True)

app = typer.Typer(
    help="Manage the compile result cache (.rebrew/compile_cache/).",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew cache stats · · · · · · Show cache size and entry count\n\n"
        "  rebrew cache clear · · · · · · Delete all cached .obj files\n\n"
        "  rebrew cache clear --target x · Clear cache for a specific project root\n\n"
        "[dim]The compile cache stores .obj bytes keyed by (source + flags + compiler), "
        "skipping Wine/wibo subprocess startup on cache hit (200-500ms savings). "
        "The store is pluggable: [cache] backend in rebrew-project.toml selects it "
        "(default diskcache at {project_root}/.rebrew/compile_cache/).[/dim]"
    ),
)


@app.command()
def stats(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Show compile cache statistics."""
    cfg = require_config(target=target, json_mode=json_output)

    backend = getattr(cfg, "cache_backend", "diskcache")
    cache_dir = cfg.root / ".rebrew" / "compile_cache"
    if backend == "diskcache" and not cache_dir.exists():
        if json_output:
            json_print({"exists": False, "entries": 0, "volume_mb": 0})
        else:
            console.print("No compile cache found (not yet created).")
        return

    cache = get_compile_cache(cfg.root, backend)
    try:
        info = cache.stats()
        if json_output:
            json_print({"exists": True, "backend": backend, "cache_dir": str(cache_dir), **info})
        else:
            console.print(f"Cache backend:  {backend}")
            console.print(f"Cache directory: {cache_dir}")
            console.print(f"Entries:         {info['entries']}")
            console.print(f"Disk usage:      {info['volume_mb']} MB")
            console.print(f"Size limit:      {info['size_limit_mb']} MB")
            hits = int(info["session_hits"])
            misses = int(info["session_misses"])
            if hits + misses > 0:
                console.print(
                    f"Session:         {hits} hits, {misses} misses"
                    f" ({info['session_hit_rate_pct']}% hit rate)"
                )
            else:
                console.print("Session:         no lookups this session")
    finally:
        cache.close()


@app.command()
def clear(
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Delete all cached .obj files."""
    cfg = require_config(target=target, json_mode=json_output)

    backend = getattr(cfg, "cache_backend", "diskcache")
    cache_dir = cfg.root / ".rebrew" / "compile_cache"
    if backend == "diskcache" and not cache_dir.exists():
        if json_output:
            json_print({"cleared": 0, "message": "No compile cache found"})
        else:
            console.print("No compile cache found (nothing to clear).")
        return

    if json_output and not force:
        error_exit(
            "--json cannot prompt for confirmation; pass --force to clear the cache",
            json_mode=True,
        )

    cache = get_compile_cache(cfg.root, backend)
    try:
        count = cache.count
        if not force and not json_output:
            console.print(f"About to delete {count} cached entries from {cache_dir}")
            typer.confirm(f"Delete {count} cached compile results?", abort=True)
        cache.clear()
        if json_output:
            json_print({"cleared": count, "cache_dir": str(cache_dir), "backend": backend})
        else:
            console.print(f"Cleared {count} cached entries from {cache_dir}")
    finally:
        cache.close()


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
