"""binsync — BinSync state I/O.

`state.py` reads a declib artifact directory, `serial.py` wraps the artifact
dump/load layer, `export.py` and `importer.py` move annotations between rebrew
metadata and a BinSync state dir, `diff.py` reports divergence, `init.py`
creates the git envelope, `overlay.py` maps a related target's names across
VAs, and `cli.py` is the `rebrew binsync` umbrella.
"""
