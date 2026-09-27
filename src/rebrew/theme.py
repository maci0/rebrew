"""Chrome design tokens shared by the HTML surfaces (report pages, dashboard)
and the exported call graph.

Plain tool chrome: a system font stack, one link/focus blue, grey borders,
one 6px radius. Deliberately not a component-library palette, and small on
purpose: these surfaces are read for addresses and bytes, so nothing here
competes with the data. A role named here is rendered the same way by every
surface that uses it, so the report and the dashboard read as one tool.
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
    "ink": "#1a1a1a",
    "muted": "#333",
    "faint": "#4a4a4a",
    "nav": "#c8c8c8",
    "note-ink": "#9a3412",
    # surfaces
    "surface": "#fff",
    "sunken": "#f5f5f5",
    "hover": "#f9f9f9",
    "pressed": "#f0f0f0",
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

_VAR = re.compile(r"var\(--rb-([a-z-]+)\)")


def inline(css: str) -> str:
    """Resolve every ``var(--rb-<name>)`` in *css* to its token value."""
    return _VAR.sub(lambda m: TOKENS[m[1]], css)
