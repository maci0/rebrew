"""Contrast and separation invariants for :mod:`rebrew.theme`.

The token set is the only place the HTML surfaces choose a colour, so these
gates are what keep a palette change from trading accessibility for identity.
"""

import itertools
import math
import re
from collections.abc import Mapping
from typing import NamedTuple

from rebrew.status_style import STATUS_HEX
from rebrew.theme import TOKENS

#: WCAG 2.2 contrast floors: 1.4.3 for text, 1.4.11 for a boundary or state
#: indicator that carries meaning without words.
TEXT_FLOOR = 4.5
NONTEXT_FLOOR = 3.0

#: Text colours, against every surface they are painted on.  ``hover`` and
#: ``pressed`` are surfaces for a row or a button the pointer is on, so body
#: text and borders are painted on them too, not only on the two resting
#: backgrounds.
_TEXT_ROLES = {
    "ink": ("surface", "sunken", "hover", "pressed"),
    "muted": ("surface", "sunken"),
    "faint": ("surface", "sunken"),
    "accent": ("surface", "sunken"),
    "accent-hi": ("surface", "sunken"),
    "surface": ("ink",),
    "nav": ("ink",),
    "note-ink": ("note-bg",),
}

#: Borders and the focus ring, which 1.4.11 holds to the non-text floor.
#: ``accent-soft`` is the report's focus outline on the dark header, where the
#: accent itself has no contrast left to spend.
_NONTEXT_ROLES = {
    "line": ("surface", "sunken", "hover", "pressed"),
    "line-hi": ("surface", "sunken"),
    "accent": ("surface", "sunken"),
    "accent-soft": ("ink",),
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
    """The mark is a standalone SVG document both surfaces serve as a file."""

    def test_is_a_complete_svg_document_using_the_ink_token(self) -> None:
        from rebrew.theme import FAVICON_SVG

        assert FAVICON_SVG.startswith("<svg ") and FAVICON_SVG.endswith("</svg>")
        assert f'fill="{TOKENS["ink"]}"' in FAVICON_SVG


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


class TestTokenCoverage:
    """Every colour a surface can paint is held to a floor by the tables above."""

    def test_every_hex_token_is_covered_by_a_role_table(self) -> None:
        """A new colour cannot ship unpinned.

        The role tables enumerate painted pairs by hand, so a token added
        without one is a colour the gate has never measured — the failure mode
        the tables exist to prevent.  A token is covered when it is painted as
        a foreground (a key) or as a background something is painted on.
        ``ring`` and ``veil`` are alpha composites rather than colours: the
        halo behind an active card, and the veil under a loading message, each
        paired with a border or an ink that carries the state on its own.
        """
        foregrounds = set(_TEXT_ROLES) | set(_NONTEXT_ROLES)
        backgrounds = {
            on for ons in (*_TEXT_ROLES.values(), *_NONTEXT_ROLES.values()) for on in ons
        }
        unpinned = {
            name
            for name, value in TOKENS.items()
            if re.fullmatch(r"#[0-9a-fA-F]{3,8}", value)
            and name not in foregrounds
            and name not in backgrounds
        }
        assert not unpinned, f"colour tokens with no contrast floor: {sorted(unpinned)}"


#: The neutral ladder, darkest first: a stub is written down, an unknown is
#: not. The marks are meant to be a step apart, not to be told apart by hue,
#: so the separation gate below leaves them out.
_STATUS_LADDER = ("STUB", "SKIP", "UNKNOWN")

#: CIE76 distance under which two loud marks read as the same swatch.
STATUS_SEPARATION_FLOOR = 18.0

#: Distance a mark must keep from the accent, which is reserved for links and
#: focus rings. RELOC was a sky blue 35 away before the retune, which is the
#: same neighbourhood a reader cannot act on.
STATUS_ACCENT_FLOOR = 50.0


def _lab(hex_color: str) -> tuple[float, float, float]:
    """CIE L*a*b* of a ``#rgb`` / ``#rrggbb`` literal."""
    digits = hex_color.lstrip("#")
    if len(digits) == 3:
        digits = "".join(d * 2 for d in digits)
    r, g, b = (_channel(int(digits[i : i + 2], 16)) for i in (0, 2, 4))
    x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047
    y = 0.2126 * r + 0.7152 * g + 0.0722 * b
    z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883

    def f(t: float) -> float:
        return t ** (1 / 3) if t > 216 / 24389 else (841 / 108) * t + 4 / 29

    fx, fy, fz = f(x), f(y), f(z)
    return (116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz))


def _delta_e(left: str, right: str) -> float:
    squares = [(a - b) ** 2 for a, b in zip(_lab(left), _lab(right), strict=True)]
    return math.sqrt(sum(squares))


class TestStatusMarks:
    """The status vocabulary is painted as body text and as a graph fill."""

    def test_marks_clear_the_text_floor_on_both_surfaces(self) -> None:
        """A mark is body text in the report table and the dashboard cards."""
        for name, color in STATUS_HEX.items():
            for role in ("surface", "sunken"):
                ratio = _contrast(color, TOKENS[role])
                assert ratio >= TEXT_FLOOR, (
                    f"{name} on {role} ({color} / {TOKENS[role]}) is {ratio:.2f}:1"
                )

    def test_white_on_a_fill_clears_the_text_floor(self) -> None:
        """The call graph writes its label in white on the mark."""
        for name, color in STATUS_HEX.items():
            ratio = _contrast(TOKENS["surface"], color)
            assert ratio >= TEXT_FLOOR, (
                f"{name} as a fill ({color}) carries white text at {ratio:.2f}:1"
            )

    def test_loud_marks_are_not_the_same_swatch(self) -> None:
        """Two verdicts that read alike are one verdict on a colour-blind read.

        Compared per distinct colour, not per status: the six machine verdicts
        share the error red on purpose, and the stylesheets group them.
        """
        loud = {
            color
            for name, color in STATUS_HEX.items()
            if name not in _STATUS_LADDER and name != "DISPATCH"
        }
        for left, right in itertools.combinations(sorted(loud), 2):
            distance = _delta_e(left, right)
            assert distance >= STATUS_SEPARATION_FLOOR, (
                f"{left} and {right} sit {distance:.1f} deltaE apart"
            )

    def test_no_mark_lands_in_the_accent_hue(self) -> None:
        """A verdict in the link blue reads as something to click."""
        for name, color in STATUS_HEX.items():
            distance = _delta_e(color, TOKENS["accent"])
            assert distance >= STATUS_ACCENT_FLOOR, (
                f"{name} ({color}) is {distance:.1f} deltaE from the accent"
            )

    def test_the_neutral_marks_are_an_ordered_ladder(self) -> None:
        """STUB, SKIP and UNKNOWN are steps of one grey, not three greys."""
        for darker, lighter in itertools.pairwise(_STATUS_LADDER):
            assert _luminance(STATUS_HEX[darker]) < _luminance(STATUS_HEX[lighter]), (
                f"{darker} ({STATUS_HEX[darker]}) is not darker than "
                f"{lighter} ({STATUS_HEX[lighter]})"
            )

    def test_the_ladder_marks_are_neutral_not_hued(self) -> None:
        """A parked row must not borrow the hue of a verdict.

        Measured as the red/green channels against blue: a warm neutral runs
        positive, a cool slate runs negative, and the chrome neutrals are warm.
        """
        for name in _STATUS_LADDER:
            digits = STATUS_HEX[name].lstrip("#")
            r, g, b = (int(digits[i : i + 2], 16) for i in (0, 2, 4))
            assert (r + g) / 2 > b, f"{name} ({STATUS_HEX[name]}) is cool, not warm"
