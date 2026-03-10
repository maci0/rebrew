"""rebrew cache: Manage the compile result cache."""

import typer
from rich.console import Console

from rebrew.cli import TargetOption, json_print, require_config
from rebrew.compile_cache import CompileCache

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
        "Location: {project_root}/.rebrew/compile_cache/[/dim]"
    ),
)


@app.command()
def stats(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Show compile cache statistics."""
    cfg = require_config(target=target)

    cache_dir = cfg.root / ".rebrew" / "compile_cache"
    if not cache_dir.exists():
        if json_output:
            json_print({"exists": False, "entries": 0, "volume_mb": 0})
        else:
            console.print("No compile cache found (not yet created).")
        return

    cache = CompileCache(cache_dir)
    try:
        info = cache.stats()
        if json_output:
            json_print({"exists": True, "cache_dir": str(cache_dir), **info})
        else:
            console.print(f"Cache directory: {cache_dir}")
            console.print(f"Entries:         {info['entries']}")
            console.print(f"Disk usage:      {info['volume_mb']} MB")
            console.print(f"Size limit:      {info['size_limit_mb']} MB")
    finally:
        cache.close()


@app.command()
def clear(
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Delete all cached .obj files."""
    cfg = require_config(target=target)

    cache_dir = cfg.root / ".rebrew" / "compile_cache"
    if not cache_dir.exists():
        if json_output:
            json_print({"cleared": 0, "message": "No compile cache found"})
        else:
            console.print("No compile cache found (nothing to clear).")
        return

    cache = CompileCache(cache_dir)
    try:
        count = cache.count
        if not force and not json_output:
            console.print(f"About to delete {count} cached entries from {cache_dir}")
            typer.confirm("Continue?", abort=True)
        cache.clear()
        if json_output:
            json_print({"cleared": count, "cache_dir": str(cache_dir)})
        else:
            console.print(f"Cleared {count} cached entries from {cache_dir}")
    finally:
        cache.close()


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
