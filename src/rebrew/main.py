import sys

import typer

app = typer.Typer(help="Compiler-in-the-loop decompilation workbench")

# Import subcommands
from rebrew.asm import app as asm_app
from rebrew.batch import app as batch_app
from rebrew.builddb import app as build_db_app
from rebrew.catalog import app as catalog_app
from rebrew.cfg import app as cfg_app
from rebrew.ga import app as ga_app
from rebrew.init import app as init_app
from rebrew.lint import app as lint_app
from rebrew.match import app as match_app
from rebrew.next import app as next_app
from rebrew.skeleton import app as skeleton_app
from rebrew.sync import app as sync_app
from rebrew.test import app as test_app
from rebrew.verify import app as verify_app

# Register subcommands
app.add_typer(test_app, name="test", help="Quick compile-and-compare for reversed functions.")
app.add_typer(verify_app, name="verify", help="Validate compiled bytes against original DLL.")
app.add_typer(next_app, name="next", help="Find the next best functions to work on.")
app.add_typer(skeleton_app, name="skeleton", help="Generate skeleton C files for matching.")
app.add_typer(catalog_app, name="catalog", help="Build JSON coverage catalogs for the web UI.")
app.add_typer(sync_app, name="sync", help="Sync GHIDRA annotations with rebrew.")
app.add_typer(lint_app, name="lint", help="Lint C annotations.")
app.add_typer(batch_app, name="batch", help="Batch extract assembly or functions.")
app.add_typer(match_app, name="match", help="GA engine for binary matching (diff, flag-sweep, GA).")
app.add_typer(ga_app, name="ga", help="Batch GA runner for STUB functions.")
app.add_typer(asm_app, name="asm", help="Disassemble original bytes.")
app.add_typer(build_db_app, name="build-db", help="Build SQLite coverage database.")
app.add_typer(init_app, name="init", help="Initialize a new rebrew project.")
app.add_typer(cfg_app, name="cfg", help="Read and edit rebrew.toml programmatically.")

def main():
    app()

if __name__ == "__main__":
    sys.exit(main())
