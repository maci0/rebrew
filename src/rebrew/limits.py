"""limits.py — the "no bound measured" sentinels shared by size and delta filtering.

Both live here so a module that only needs to recognise an unset value does not
have to import the tool that offers the bound.  ``rebrew.skeleton`` and
``rebrew.match`` expose ``--max-size``; the batch parsers and drivers in
``rebrew.match_batch`` / ``rebrew.match_run`` compare a stub's size and delta
against these sentinels.  Keeping the constants in a leaf module lets those
callers stay out of the command modules.

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

#: "No byte delta measured" sentinel carried by a STUB, a PROVEN function, or
#: a NEAR_MATCHING with no ``blocker_delta``.  Callers compare against it to
#: omit a meaningless delta from terminal and JSON output rather than print
#: ``Δ9999B``; a ``max_delta`` filter also treats it as over threshold.
NO_DELTA = 9999
