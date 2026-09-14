"""Function status vocabulary shared by the coverage consumers."""

# Single source of truth lives in rebrew.metadata (KNOWN_STATUSES,
# MATCHED_STATUSES); this module re-exports it for the workspace package so
# coverage consumers import from one place without depending on the metadata
# writers.  Reportal's portal status set is a superset: it also carries
# "MATCHED", the aggregate display label, so portal statuses are not
# interchangeable with this tuple.
from rebrew.metadata import KNOWN_STATUSES as KNOWN_STATUSES
from rebrew.metadata import MATCHED_STATUSES as MATCHED_STATUSES
