"""app — the umbrella ``rebrew`` CLI composition layer.

`main.py` is the console-script entry point, `builtins.py` declares every
packaged command as a ``CliComponent`` row grouped by domain, and `plugin.py`
is the component/context runtime that mounts them and third-party
``rebrew.commands`` / ``rebrew.multicommands`` entry points.

Import submodules by name (``rebrew.app.main``, …); this package exports no
public names of its own.
"""

__all__: list[str] = []
