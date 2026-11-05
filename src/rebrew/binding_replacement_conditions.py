"""Conservative target-selected structural views for binding reviews."""

from __future__ import annotations

import re

from rebrew.c_conditionals import conditional_fragments, structural_variants
from rebrew.c_parser import mask_msvc_syntax, mask_va_arg_types, parse_c_source


def target_structural_view(text: str, macros: dict[str, bool]) -> tuple[bytes, list[str]]:
    """Select explicitly known simple fragment guards without changing offsets.

    This is not a preprocessor. Callers must establish that the supplied macro
    state is complete and unaffected by flags, includes, or source directives.
    Unsupported guards, unknown macros, and unavailable combinations refuse.
    """
    raw = mask_va_arg_types(mask_msvc_syntax(text)).encode("utf-8", errors="surrogateescape")
    fragments, _ = conditional_fragments(raw, parse_c_source)
    if not fragments:
        raise ValueError("no supported conditional structural fragments")
    choices: list[int] = []
    names: list[str] = []
    for fragment in fragments:
        directives = [raw[start:end].decode("ascii").strip() for start, end in fragment.directives]
        if len(directives) != 3 or directives[1:] != ["#else", "#endif"]:
            raise ValueError("unsupported conditional branch chain")
        match = re.fullmatch(r"#\s*(ifdef|ifndef)\s+([A-Za-z_]\w*)", directives[0])
        if match is None or len(fragment.branches) != 2:
            raise ValueError("unsupported conditional guard")
        operator, name = match.groups()
        if name not in macros:
            raise ValueError(f"unknown macro state: {name}")
        value = macros[name] if operator == "ifdef" else not macros[name]
        choices.append(0 if value else 1)
        names.append(name)
    for name in names:
        pattern = rf"(?m)^\s*#\s*(?:define|undef)\s+{re.escape(name)}\b"
        if re.search(pattern, text):
            raise ValueError(f"source changes macro state: {name}")
    for candidate in structural_variants(raw, fragments):
        valid = True
        for fragment, choice in zip(fragments, choices, strict=True):
            start, end = fragment.branches[choice]
            if candidate[start:end] != raw[start:end] or not raw[start:end].strip():
                valid = False
                break
            for index, (start, end) in enumerate(fragment.branches):
                if index != choice and candidate[start:end].strip():
                    valid = False
                    break
        if valid:
            tree, _ = parse_c_source(candidate)
            if tree.root_node.has_error:
                raise ValueError("target structural view has syntax errors")
            return candidate, names
    raise ValueError("target guard combination is not represented by structural variants")
