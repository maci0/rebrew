"""Function status vocabulary shared by the coverage consumers."""

#: Statuses that count as matched work (byte-identical or proven-equivalent),
#: in canonical display order.  Mirrors rebrew.metadata.MATCHED_STATUSES
#: verbatim.  reportal's portal status set is a superset: it also carries
#: "MATCHED", the aggregate display label, so portal statuses are not
#: interchangeable with this tuple.
MATCHED_STATUSES: tuple[str, ...] = ("EXACT", "RELOC", "PROVEN")
