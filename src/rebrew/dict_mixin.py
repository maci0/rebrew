"""dict_mixin.py - Shared serialization mixin for dataclasses.

Provides a generic to_dict() implementation via dataclasses.asdict()
so that trivial dataclasses don't need hand-written serialization.
"""

import dataclasses
from typing import Any


class DictMixin:
    """Mixin adding a generic ``to_dict()`` to any ``@dataclass``.

    Uses ``dataclasses.asdict()`` under the hood.  Dataclasses with custom
    serialization logic (e.g. field renaming, computed fields) should keep
    their own ``to_dict()`` instead of using this mixin.
    """

    def to_dict(self) -> dict[str, Any]:
        """Serialize all fields to a plain dict (recursive)."""
        return dataclasses.asdict(self)
