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
verdict on a row it says nothing about. ``tests/test_theme`` holds every text
pair to 4.5:1 and every border and focus pair to 3:1 on the two surfaces these
tokens ship on, so the temperature costs no contrast.

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
#: Inline as a data URI because both surfaces ship one self-contained file and
#: forbid every off-site load, and because an inline mark still stops the
#: per-load ``/favicon.ico`` 404 a blank ``data:,`` icon was there to stop.
#: Percent-encoded, so the value needs no attribute quoting from either
#: surface.
FAVICON = (
    "data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22"
    "%20viewBox%3D%220%200%2016%2016%22%3E%3Crect%20width%3D%2216%22%20height%3D%2216%22"
    "%20rx%3D%223%22%20fill%3D%22" + TOKENS["ink"].replace("#", "%23") + "%22%2F%3E%3Ctext%20"
    "x%3D%228.2%22%20y%3D%2212.1%22%20font-family%3D%22monospace%22%20font-size%3D%2212%22"
    "%20font-weight%3D%22bold%22%20text-anchor%3D%22middle%22%20letter-spacing%3D%22-0.6%22"
    "%20fill%3D%22%237ee0a3%22%3E0x%3C%2Ftext%3E%3C%2Fsvg%3E"
)

_VAR = re.compile(r"var\(--rb-([a-z-]+)\)")


def inline(css: str) -> str:
    """Resolve every ``var(--rb-<name>)`` in *css* to its token value."""
    return _VAR.sub(lambda m: TOKENS[m[1]], css)
