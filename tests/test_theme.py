"""Contrast and separation invariants for :mod:`rebrew.theme`.

The token set is the only place the HTML surfaces choose a colour, so these
gates are what keep a palette change from trading accessibility for identity.
"""

import re
from collections.abc import Mapping
from typing import NamedTuple

from rebrew.status_style import STATUS_HEX
from rebrew.theme import TOKENS

#: WCAG 2.2 contrast floors: 1.4.3 for text, 1.4.11 for a boundary or state
#: indicator that carries meaning without words.
TEXT_FLOOR = 4.5
NONTEXT_FLOOR = 3.0

#: Text colours, against every surface they are painted on.
_TEXT_ROLES = {
    "ink": ("surface", "sunken"),
    "muted": ("surface", "sunken"),
    "faint": ("surface", "sunken"),
    "accent": ("surface", "sunken"),
    "accent-hi": ("surface", "sunken"),
    "surface": ("ink",),
    "nav": ("ink",),
    "note-ink": ("note-bg",),
}

#: Borders and the focus ring, which 1.4.11 holds to the non-text floor.
_NONTEXT_ROLES = {
    "line": ("surface", "sunken"),
    "line-hi": ("surface", "sunken"),
    "accent": ("surface", "sunken"),
}


class _Pair(NamedTuple):
    role: str
    on: str
    foreground: str
    background: str


def _channel(value: int) -> float:
    c = value / 255
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _luminance(hex_color: str) -> float:
    """WCAG relative luminance of a ``#rgb`` / ``#rrggbb`` literal."""
    digits = hex_color.lstrip("#")
    if len(digits) == 3:
        digits = "".join(d * 2 for d in digits)
    r, g, b = (int(digits[i : i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def _contrast(foreground: str, background: str) -> float:
    hi, lo = sorted((_luminance(foreground), _luminance(background)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _pairs(roles: Mapping[str, tuple[str, ...]]) -> list[_Pair]:
    return [
        _Pair(role, on, TOKENS[role], TOKENS[on])
        for role, backgrounds in roles.items()
        for on in backgrounds
    ]


class TestTokenContrast:
    """Every painted pair clears the WCAG floor for the role it carries."""

    def test_text_pairs_clear_the_text_floor(self) -> None:
        for pair in _pairs(_TEXT_ROLES):
            ratio = _contrast(pair.foreground, pair.background)
            assert ratio >= TEXT_FLOOR, (
                f"{pair.role} on {pair.on} ({pair.foreground} / {pair.background})"
                f" is {ratio:.2f}:1, under {TEXT_FLOOR}:1"
            )

    def test_border_and_focus_pairs_clear_the_nontext_floor(self) -> None:
        for pair in _pairs(_NONTEXT_ROLES):
            ratio = _contrast(pair.foreground, pair.background)
            assert ratio >= NONTEXT_FLOOR, (
                f"{pair.role} on {pair.on} ({pair.foreground} / {pair.background})"
                f" is {ratio:.2f}:1, under {NONTEXT_FLOOR}:1"
            )


class TestFavicon:
    """The mark is a self-contained data URI that decodes to the shipped SVG."""

    def test_decodes_to_valid_svg_using_the_ink_token(self) -> None:
        import urllib.parse

        from rebrew.theme import FAVICON

        assert FAVICON.startswith("data:image/svg+xml,")
        svg = urllib.parse.unquote(FAVICON.removeprefix("data:image/svg+xml,"))
        # A half-encoded or double-encoded URI leaves an escape behind, and an
        # unencoded '#' would truncate the data URI at the fill colour.
        assert "%" not in svg
        assert svg.startswith("<svg ") and svg.endswith("</svg>")
        assert f'fill="{TOKENS["ink"]}"' in svg

    def test_needs_no_attribute_quoting_from_a_surface(self) -> None:
        """Both surfaces wrap attributes differently, and neither may break."""
        from rebrew.theme import FAVICON

        assert not set("\"'<>& ") & set(FAVICON)


class TestTokenSeparation:
    """The token set is disjoint from the status vocabulary, and ordered."""

    def test_no_chrome_colour_is_a_status_colour(self) -> None:
        """Chrome must not paint a verdict.

        A border, link or focus ring in a status hue reads as that status on a
        row it has nothing to do with. DISPATCH is excluded because it is
        *defined* as the ink token: a jump table is structure, not a verdict.
        """
        statuses = {color.lower() for name, color in STATUS_HEX.items() if name != "DISPATCH"}
        chrome = {
            role: value
            for role, value in TOKENS.items()
            if re.fullmatch(r"#[0-9a-fA-F]{3,8}", value)
        }
        collisions = {role: value for role, value in chrome.items() if value.lower() in statuses}
        assert not collisions, f"chrome reuses a status colour: {collisions}"

    def test_hover_states_step_further_from_the_surface(self) -> None:
        """A hover reads as the same role, one step louder."""
        surface = _luminance(TOKENS["surface"])
        for role, hover in (("accent", "accent-hi"), ("line", "line-hi")):
            assert _luminance(TOKENS[hover]) < _luminance(TOKENS[role]), (
                f"{hover} is not darker than {role}"
            )
            assert _luminance(TOKENS[role]) <= surface
