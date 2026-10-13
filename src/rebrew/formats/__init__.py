"""formats — executable, object and archive file parsers.

`binary_loader.py` loads a target image into the `binary_model.py` types
(PE/ELF/Mach-O through LIEF, NE through `ne_loader.py`); the PE, OMF, LZEXE,
import-table, relocation and static-archive modules read the formats LIEF
does not cover or that rebrew patches byte for byte.

Import submodules by name (``rebrew.formats.binary_loader``, …); this package
exports no public names of its own.
"""

__all__: list[str] = []
