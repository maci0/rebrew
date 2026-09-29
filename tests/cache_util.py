"""Builders for the on-disk verify stores, shared by the tests that fake them.

The verify cache and the ``--compare`` baseline are clear-text TOML documents
(``rebrew.verify_cache``); a test that hand-builds one has to serialize it the
way the store does, or it proves nothing about what the store reads back.
"""

from __future__ import annotations

from typing import Any

import tomlkit

from rebrew.verify_cache import toml_document


def cache_text(doc: dict[str, Any]) -> str:
    """Serialize a verify-cache or baseline document the way the store does."""
    return tomlkit.dumps(toml_document(doc))
