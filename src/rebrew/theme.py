"""Chrome design tokens shared by the HTML surfaces (report pages, dashboard)
and the exported call graph.

Plain tool chrome: a system font stack, one link/focus blue, one 6px radius.
Deliberately not a component-library palette, and small on purpose: these
surfaces are read for addresses and bytes, so nothing here competes with the
data. A role named here is rendered the same way by every surface that uses it,
so the report and the dashboard read as one tool.

The neutrals are warm rather than ``#1a1a1a``/``#f5f5f5``. The mascot
(``docs/mascot.png``) is a brass machine in a leather harness under phosphor
green, and a cold grey page beside it reads as a different product. The accent
blue is the one cold value and it stays: the status marks own green, teal,
amber and red, and a link or focus ring in one of those hues would read as a
verdict on a row it says nothing about. The same rule runs the other way, so
``tests/test_theme`` also holds every status mark away from ``accent``: a
matched row in the link blue reads as something to click. ``tests/test_theme``
holds every text pair to 4.5:1 and every border and focus pair to 3:1 against
every background these tokens ship on — the two page surfaces plus the hover
and pressed a row or button is painted on — and fails on a colour token added
without one, so the temperature costs no contrast.

``ink`` on ``surface`` is also the title band both HTML surfaces open with: the
report's ``header`` and the dashboard's heading, on the same padding, so the
dashboard and a report read as one tool opened side by side.

Status marks are ``status_style.STATUS_HEX``, the same values
the call graph uses, and are not repeated here; the graph's node stroke, label
colour, label font and edge colour read the ``ink``, ``surface``, ``mono`` and
``line`` tokens here instead of their own literals, so a graph exported beside
its report is painted the same chrome. Mermaid has no stylesheet to inherit
from, so the graph carries these values in an init directive and Graphviz takes
them as graph attributes (``depgraph.render_mermaid`` / ``render_dot``).

Both stylesheets write ``var(--rb-<name>)`` and pass the result through
:func:`inline`, so a surface ships one self-contained file. Resolving here
rather than shipping a ``:root`` block keeps the dashboard shell inside its
congestion-window budget (``tests/test_dashboard.py``), and the dashboard and
the report then cannot drift apart.
"""

import re

#: Semantic name -> value for the shared chrome.
TOKENS: dict[str, str] = {
    # text
    "ink": "#2a201a",
    "muted": "#3b322b",
    "faint": "#544940",
    "nav": "#cdc6bd",
    "note-ink": "#9a3412",
    # surfaces
    "surface": "#fff",
    "sunken": "#f7f4ef",
    "hover": "#faf8f4",
    "pressed": "#efeae2",
    "veil": "rgba(255,255,255,.7)",
    "note-bg": "#fff7ed",
    # lines
    "line": "#767676",
    "line-hi": "#444",
    # interaction
    "accent": "#005fcc",
    "accent-hi": "#003e85",
    "accent-soft": "#9dc4f5",
    "ring": "rgba(0,95,204,.25)",
    # type
    "sans": "system-ui, sans-serif",
    "mono": 'ui-monospace, "Cascadia Code", Consolas, monospace',
    # One ladder, 24/20/18 for display and 15/14/13 for text, so a level
    # reads as a step rather than as a default.
    "size-title": "1.5rem",
    "size-value": "1.25rem",
    "size-heading": "1.125rem",
    "size-note": "0.9375rem",
    "size-cell": "0.875rem",
    "size-caption": "0.8125rem",
    "size-code": "0.8125rem",
    # shape
    "radius": "6px",
}

#: The rebrew mark: the mascot's ``0x`` mug, in phosphor green on the harness
#: leather (the ``ink`` token, so the tab and the page cannot drift apart).
#: One source for both surfaces.  Both link it rather than inlining it: the
#: dashboard as a same-origin route, the report as a ``favicon.svg`` beside the
#: pages, so neither document carries 443 bytes of percent-encoded payload the
#: browser cannot cache or compress.
FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
    '<rect width="16" height="16" rx="3" fill="' + TOKENS["ink"] + '"/>'
    '<text x="8.2" y="12.1" font-family="monospace" font-size="12" font-weight="bold"'
    ' text-anchor="middle" letter-spacing="-0.6" fill="#7ee0a3">0x</text></svg>'
)

_VAR = re.compile(r"var\(--rb-([a-z-]+)\)")


def inline(css: str) -> str:
    """Resolve every ``var(--rb-<name>)`` in *css* to its token value."""
    return _VAR.sub(lambda m: TOKENS[m[1]], css)
