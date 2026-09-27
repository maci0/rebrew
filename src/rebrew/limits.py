"""limits.py — the "no bound measured" sentinels shared by the size and delta filters.

Both live here so a module that only needs to recognise an unset bound does not
have to import the tool that offers the bound.  ``rebrew.skeleton`` and
``rebrew.match_batch`` own the ``--max-size`` / ``--max-delta`` options, and
``rebrew.match_run`` compares against these while driving a batch; keeping the
constants in a leaf module lets the driver stay out of the command modules.

The two numbers match by accident, not by meaning: one is a function extent in
bytes and the other is a byte delta.  They are separate constants so a change
to one bound cannot silently move the other.
"""

from __future__ import annotations

#: "No upper bound" for the ``--max-size`` family of filters.  Deliberately
#: well above any real function extent, so ``size <= max_size`` is always true
#: when the option is left at its default; callers that need to recognize
#: "unset" compare against this instead of hardcoding the number.
NO_MAX_SIZE = 9999

#: "No byte delta measured" for the ``--max-delta`` filter.  A STUB, a PROVEN
#: function, or a NEAR_MATCHING with no ``blocker_delta`` carries no delta, and
#: ``--max-delta`` must not filter it out.
NO_DELTA = 9999
