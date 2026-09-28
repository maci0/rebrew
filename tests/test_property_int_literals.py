"""Property-based fuzz tests for the shared integer-literal parsers.

:func:`rebrew.utils.parse_int_literal` and
:func:`rebrew.utils.parse_c_integer_literal` are the coercion every integer
from outside rebrew passes through: disassembly operands, config range
bounds, array bounds in C annotations, symbol addresses, and the CLI's
``--va``.  The text reaching them is untrusted, so the properties below
pin what a caller may rely on:

* a malformed literal raises ``ValueError`` and nothing else, so
  ``cli.parse_va`` fails loud and the ``asm``/``matcher`` callers that
  catch ``ValueError`` keep working;
* only ASCII digits of the literal's own base are accepted, so a value
  spelled with ``int()``'s extras (embedded underscore, a Unicode decimal
  digit, a sign inside the digits) is rejected rather than read as a
  different number;
* the base rules hold: a ``0x`` prefix is hex in both parsers, ``010`` is
  ten for :func:`parse_int_literal` and eight for
  :func:`parse_c_integer_literal``, and a ``u``/``l`` suffix is inert.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from rebrew.utils import parse_c_integer_literal, parse_int_literal


@dataclass(frozen=True)
class _Literal:
    """One well-formed literal: its value, the base, and the digit text."""

    value: int
    base: int
    digits: str


def _format_base(value: int, base: int) -> str:
    """Spell *value* in *base* with ASCII digits, no prefix."""
    digits = "0123456789abcdef"
    if value == 0:
        return "0"
    out = ""
    while value:
        value, remainder = divmod(value, base)
        out = digits[remainder] + out
    return out


#: Every character ``int()`` tolerates that is not an ASCII digit: grouping
#: underscores, signs, and non-ASCII decimal digit sets
#: (Arabic-Indic, Extended Arabic-Indic, Devanagari).
_LENIENT = "_+-٠۰۱۲۳۴۵۶۷۸۹०१२३४५६८९"

_TEXT = st.text(max_size=12)
_HEX_DIGITS = st.text(alphabet="0123456789abcdefABCDEF", min_size=1, max_size=8)
_DEC_DIGITS = st.text(alphabet="0123456789", min_size=1, max_size=8)
_OCTAL_DIGITS = st.text(alphabet="01234567", min_size=1, max_size=8)
_SIGN = st.sampled_from(["", "-", "+"])
_SUFFIX = st.sampled_from(["", "u", "U", "l", "L", "ul", "UL", "llu"])
_BASES = st.sampled_from([8, 10, 16])
_JUNK_TEXT = st.text(alphabet=_LENIENT, min_size=1, max_size=6)
#: A value, the base its digits are spelled in, and those digits.  Built from
#: the value so every base is exercised with digits that are valid in it.
_LITERALS = st.tuples(
    st.integers(min_value=0, max_value=2**32 - 1),
    _BASES,
).map(lambda pair: _Literal(value=pair[0], base=pair[1], digits=_format_base(pair[0], pair[1])))


def _digit_body(text: str) -> str | None:
    """The ASCII digit body of *text*, or ``None`` if it is not spelled in digits."""
    body = text.strip()
    while body and body[-1] in "uUlL":
        body = body[:-1]
    body = body.lstrip("+-").strip()
    if body[:2].lower() == "0x":
        body = body[2:]
    if not body or not body.isascii():
        return None
    if not all(ch in "0123456789abcdefABCDEF" for ch in body):
        return None
    return body


def _is_accepted(text: str, parse: Callable[[str], int]) -> bool:
    try:
        parse(text)
    except ValueError:
        return False
    return True


class TestParseIntLiteral:
    @given(text=_TEXT, base=_BASES)
    @settings(max_examples=300)
    def test_only_value_error(self, text: str, base: int) -> None:
        """A malformed literal is a ``ValueError``, never a ``TypeError``."""
        with contextlib.suppress(ValueError):
            parse_int_literal(text, base=base)

    @given(text=_JUNK_TEXT, base=_BASES)
    @settings(max_examples=300)
    def test_rejects_int_leniency(self, text: str, base: int) -> None:
        """``"1_0"`` and ``"١٢"`` are not integers in any base.

        ``int()`` reads both, so without the rejection a config value or a
        disassembly operand resolves to a number no writer meant.
        """
        assert _digit_body(text) is None
        assert not _is_accepted(text, lambda t: parse_int_literal(t, base=base))

    @given(case=_LITERALS, sign=_SIGN)
    @settings(max_examples=200)
    def test_sign_mirrors(self, case: _Literal, sign: str) -> None:
        """``-x`` is ``-(x)`` and ``+x`` is ``x``, in every base."""
        expected = -case.value if sign == "-" else case.value
        assert parse_int_literal(sign + case.digits, base=case.base) == expected

    @given(case=_LITERALS, pad=st.sampled_from(["", " ", "\t", "  "]))
    @settings(max_examples=200)
    def test_whitespace_is_inert(self, case: _Literal, pad: str) -> None:
        assert parse_int_literal(pad + case.digits + pad, base=case.base) == case.value

    @given(digits=_DEC_DIGITS)
    @settings(max_examples=100)
    def test_decimal_base_ignores_leading_zero(self, digits: str) -> None:
        """``010`` is ten for :func:`parse_int_literal`, never eight."""
        assume(digits[0] != "0")
        assert parse_int_literal("0" + digits) == int(digits)

    @given(digits=_HEX_DIGITS, pad=st.sampled_from(["", " ", "\t"]))
    @settings(max_examples=200)
    def test_hex_prefix_wins(self, digits: str, pad: str) -> None:
        """A ``0x`` prefix selects base 16 whatever *base* says."""
        assert parse_int_literal(f"{pad}0x{digits}", base=10) == int(digits, 16)
        assert parse_int_literal(f"{pad}0X{digits}", base=8) == int(digits, 16)

    @given(case=_LITERALS)
    @settings(max_examples=200)
    def test_value_equals_int_of_its_own_digits(self, case: _Literal) -> None:
        """The parsed value is exactly the base-*base* reading of the digits."""
        assert parse_int_literal(case.digits, base=case.base) == case.value


class TestParseCIntegerLiteral:
    @given(text=_TEXT)
    @settings(max_examples=300)
    def test_only_value_error(self, text: str) -> None:
        with contextlib.suppress(ValueError):
            parse_c_integer_literal(text)

    @given(text=_JUNK_TEXT)
    @settings(max_examples=300)
    def test_rejects_int_leniency(self, text: str) -> None:
        """An array bound nobody wrote is not a bound.

        ``int()`` reads ``"1_0"`` as ten and ``"١٢"`` as twelve; a bound
        dropped that way sizes the array wrong instead of failing the
        annotation.
        """
        assert _digit_body(text) is None
        assert not _is_accepted(text, parse_c_integer_literal)

    @given(digits=st.text(alphabet="123456789", min_size=1, max_size=8), sign=_SIGN, suffix=_SUFFIX)
    @settings(max_examples=200)
    def test_sign_and_suffix(self, digits: str, sign: str, suffix: str) -> None:
        """A sign mirrors the value and a ``u``/``l`` suffix is inert.

        The digits never start with a zero, so the constant is decimal
        rather than octal; the octal form is covered separately.
        """
        unsigned = int(digits)
        expected = -unsigned if sign == "-" else unsigned
        assert parse_c_integer_literal(f"{sign}{digits}{suffix}") == expected

    @given(digits=_OCTAL_DIGITS)
    @settings(max_examples=200)
    def test_leading_zero_is_octal(self, digits: str) -> None:
        """``010`` is eight here, never ten."""
        assume(digits[0] != "0")
        assert parse_c_integer_literal("0" + digits) == int(digits, 8)

    @given(digits=st.text(alphabet="89", min_size=1, max_size=8))
    @settings(max_examples=200)
    def test_non_octal_leading_zero_falls_back_to_decimal(self, digits: str) -> None:
        """``08`` is the padded decimal, the value C's own bound would take."""
        assert parse_c_integer_literal("0" + digits) == int(digits)

    @given(digits=_HEX_DIGITS, sign=_SIGN, suffix=_SUFFIX)
    @settings(max_examples=200)
    def test_hex_form(self, digits: str, sign: str, suffix: str) -> None:
        """``0x`` is hex, with an optional sign and suffix."""
        unsigned = int(digits, 16)
        expected = -unsigned if sign == "-" else unsigned
        assert parse_c_integer_literal(f"{sign}0x{digits}{suffix}") == expected

    @given(digits=_HEX_DIGITS)
    @settings(max_examples=200)
    def test_hex_agrees_with_parse_int_literal(self, digits: str) -> None:
        """The two parsers read one hex constant identically."""
        assert parse_c_integer_literal(f"0x{digits}") == parse_int_literal(f"0x{digits}")
