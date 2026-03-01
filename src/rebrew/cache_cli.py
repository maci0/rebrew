"""rebrew cache: Manage the compile result cache."""

import typer
from rich.console import Console

from rebrew.cli import TargetOption, get_config
from rebrew.compile_cache import CompileCache

console = Console(stderr=True)

app = typer.Typer(
    help="Manage the compile result cache (.rebrew/compile_cache/).",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew cache stats                Show cache size and entry count

rebrew cache clear                Delete all cached .obj files

rebrew cache clear --target x     Clear cache for a specific project root

[dim]The compile cache stores .obj bytes keyed by (source + flags + compiler),
skipping Wine/wibo subprocess startup on cache hit (200-500ms savings).
Location: {project_root}/.rebrew/compile_cache/[/dim]""",
)


@app.command()
def stats(
    target: str | None = TargetOption,
) -> None:
    """Show compile cache statistics."""
    try:
        cfg = get_config(target=target)
    except (FileNotFoundError, KeyError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    cache_dir = cfg.root / ".rebrew" / "compile_cache"
    if not cache_dir.exists():
        typer.echo("No compile cache found (not yet created).")
        return

    cache = CompileCache(cache_dir)
    try:
        info = cache.stats()
        typer.echo(f"Cache directory: {cache_dir}")
        typer.echo(f"Entries:         {info['entries']}")
        typer.echo(f"Disk usage:      {info['volume_mb']} MB")
        typer.echo(f"Size limit:      {info['size_limit_mb']} MB")
    finally:
        cache.close()


@app.command()
def clear(
    target: str | None = TargetOption,
) -> None:
    """Delete all cached .obj files."""
    try:
        cfg = get_config(target=target)
    except (FileNotFoundError, KeyError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    cache_dir = cfg.root / ".rebrew" / "compile_cache"
    if not cache_dir.exists():
        typer.echo("No compile cache found (nothing to clear).")
        return

    cache = CompileCache(cache_dir)
    try:
        count = cache.count
        cache.clear()
        typer.echo(f"Cleared {count} cached entries from {cache_dir}")
    finally:
        cache.close()


def main_entry() -> None:
    app()
