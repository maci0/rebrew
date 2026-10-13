"""metadata — source annotations and the locked metadata stores.

`functions.py` owns ``rebrew-functions.toml`` and `data.py` owns
``rebrew-data.toml``; both write through `document.py`'s qualified-key and
lock helpers. `model.py` is the typed view of a function entry,
`annotation.py` merges source markers with the stored fields, and
`marker_migration.py` / `source_provenance.py` move markers and evidence
into the stores.

Import submodules by name (``rebrew.metadata.functions``, …); this package
exports no public names of its own.
"""

__all__: list[str] = []
