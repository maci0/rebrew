"""Property-based fuzz tests for the llvm-pdbutil text parsers.

The ``pdb_info`` parsers read ``llvm-pdbutil`` output for an arbitrary PDB.
"""

from __future__ import annotations

import string

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.pdb_info import _parse_compile3, _parse_procs

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_ident = st.text(alphabet=string.ascii_letters + string.digits + "_", min_size=1, max_size=24)
_hexnum = st.integers(min_value=0, max_value=0xFFFFFFFF).map(hex)


# ---------------------------------------------------------------------------
# pdb_info llvm-pdbutil text parsers
# ---------------------------------------------------------------------------


@st.composite
def _proc_dump(draw: st.DrawFn) -> tuple[str, list[str]]:
    """A synthetic llvm-pdbutil symbol dump and the proc names it holds."""
    names = draw(st.lists(_ident, max_size=12))
    lines: list[str] = []
    for i, name in enumerate(names):
        kind = draw(st.sampled_from(["GPROC32", "LPROC32", "GPROC32_ID", "LPROC32_ID"]))
        if draw(st.booleans()):
            lines.append(f" {i * 100} | S_{kind} [size = {draw(st.integers(0, 999))}] `{name}`")
        else:
            lines.append(f" {i * 100} | S_{kind} [size = {draw(st.integers(0, 999))}]")
            lines.append(
                f"        type = 0x1001, debug start = {draw(_hexnum)}, debug end = {draw(_hexnum)}"
            )
            lines.append(f"        flags = none, name = '{name}'")
        if draw(st.booleans()):
            lines.append("  S_END [size = 4]")
    return "\n".join(lines) + "\n", names


class TestPdbInfoFuzz:
    @settings(max_examples=300, deadline=None)
    @given(st.text(max_size=600))
    def test_parse_procs_arbitrary_text(self, text: str) -> None:
        procs = _parse_procs(text)
        assert len(procs) <= 500
        for entry in procs:
            assert isinstance(entry["name"], str) and entry["name"]

    @settings(max_examples=200, deadline=None)
    @given(_proc_dump())
    def test_parse_procs_recovers_names_in_order(self, dump: tuple[str, list[str]]) -> None:
        text, names = dump
        assert [e["name"] for e in _parse_procs(text)] == names

    @settings(max_examples=300, deadline=None)
    @given(st.text(max_size=600))
    def test_parse_compile3_arbitrary_text(self, text: str) -> None:
        frontend, backend, flags = _parse_compile3(text)
        assert "\n" not in frontend and "\n" not in backend
        for tok in flags:
            assert tok and "|" not in tok and not any(c.isspace() for c in tok)

    @given(
        st.lists(
            st.text(alphabet=string.ascii_letters + string.digits + "/-", min_size=1, max_size=8),
            min_size=1,
            max_size=6,
        ),
        st.sampled_from([" ", " | "]),
    )
    def test_parse_compile3_flag_round_trip(self, flags: list[str], sep: str) -> None:
        if [f.lower() for f in flags] == ["none"]:
            flags = ["/O2"]
        text = (
            " 1 | S_COMPILE3 [size = 60]\n"
            "        frontend = 13.10.3077, backend = 13.10.3077\n"
            f"        flags = {sep.join(flags)}\n"
            " 2 | S_GPROC32 [size = 4]\n"
        )
        assert _parse_compile3(text) == ("13.10.3077", "13.10.3077", flags)
