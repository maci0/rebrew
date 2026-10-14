"""Same-coordinate structural views for conditional C brace fragments.

This does not evaluate macros. It selects structurally equivalent branches for
AST parsing, and supplies each alternative so inventories retain source facts.
"""

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

_DIRECTIVE = re.compile(rb"^[ \t]*#[ \t]*([A-Za-z_][A-Za-z_0-9]*)", re.M)
_MASK = bytes(byte if byte in (10, 13) else 32 for byte in range(256))


@dataclass
class _Frame:
    start: int
    depth: int
    branch_start: int
    branches: list[tuple[int, int]] = field(default_factory=list)
    ends: list[int] = field(default_factory=list)
    directives: list[tuple[int, int]] = field(default_factory=list)
    has_else: bool = False
    consistent: bool = True


@dataclass
class ConditionalFragment:
    start: int
    end: int
    branches: list[tuple[int, int]]
    directives: list[tuple[int, int]]


def conditional_fragments(
    raw: bytes, parse: Callable[[bytes], tuple[Any, bytes]]
) -> tuple[list[ConditionalFragment], list[tuple[int, int]]]:
    """Find equal, nonzero brace effects using AST-selected lexical exclusions."""
    if b"#" not in raw:
        return [], []
    # Removing only directive hashes leaves quotes, comments and continuations
    # intact, even when the original grammar swallowed a branch as preproc_arg.
    probe = bytearray(raw)
    for match in _DIRECTIVE.finditer(raw):
        position = raw.index(b"#", match.start(), match.end())
        probe[position] = 32
    tree, _ = parse(bytes(probe))
    lexical = bytearray(raw)
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type in {"comment", "string_literal", "char_literal"}:
            lexical[node.start_byte : node.end_byte] = raw[
                node.start_byte : node.end_byte
            ].translate(_MASK)
        else:
            pending.extend(node.named_children)

    directives: list[tuple[int, int, bytes]] = []
    consumed = 0
    for match in _DIRECTIVE.finditer(lexical):
        if match.start() < consumed:
            continue
        end = raw.find(b"\n", match.end())
        end = len(raw) if end < 0 else end + 1
        while raw[match.start() : end].rstrip(b"\r\n").endswith(b"\\") and end < len(raw):
            following = raw.find(b"\n", end)
            end = len(raw) if following < 0 else following + 1
        consumed = end
        directives.append((match.start(), end, match[1]))
        lexical[match.start() : end] = raw[match.start() : end].translate(_MASK)

    events = [(match.start(), match.end(), match[0]) for match in re.finditer(rb"[{}]", lexical)]
    events.extend(directives)
    events.sort()
    stack: list[_Frame] = []
    regions: list[tuple[int, int]] = []
    fragments: list[ConditionalFragment] = []
    depth = 0
    for start, end, kind in events:
        if kind == b"{":
            depth += 1
        elif kind == b"}":
            depth -= 1
        elif kind in {b"if", b"ifdef", b"ifndef"}:
            stack.append(_Frame(start, depth, end, directives=[(start, end)]))
        elif kind in {b"elif", b"else"} and stack:
            frame = stack[-1]
            frame.branches.append((frame.branch_start, start))
            frame.ends.append(depth)
            frame.directives.append((start, end))
            frame.branch_start = end
            frame.has_else |= kind == b"else"
            depth = frame.depth
        elif kind == b"endif" and stack:
            frame = stack.pop()
            frame.branches.append((frame.branch_start, start))
            frame.ends.append(depth)
            frame.directives.append((start, end))
            regions.append((frame.start, end))
            endings = frame.ends if frame.has_else else [*frame.ends, frame.depth]
            consistent = frame.consistent and len(set(endings)) == 1
            if consistent and endings[0] != frame.depth:
                fragments.append(
                    ConditionalFragment(frame.start, end, frame.branches, frame.directives)
                )
            if stack:
                stack[-1].consistent &= consistent
            depth = frame.ends[0]
    return sorted(fragments, key=lambda group: group.start), sorted(regions)


def structural_variants(raw: bytes, fragments: list[ConditionalFragment]) -> Iterator[bytes]:
    """Yield a baseline and each branch, with ancestor selections made explicit.

    The number of parses is linear in the branch inventory, not its Cartesian
    product. Every byte offset and newline remains a coordinate of *raw*.
    """
    choices = [(-1, 0)] + [
        (index, branch)
        for index, group in enumerate(fragments)
        for branch in range(len(group.branches))
    ]
    seen: set[tuple[int, ...]] = set()
    for selected, branch in choices:
        picks = [0] * len(fragments)
        if selected >= 0:
            picks[selected] = branch
            position = fragments[selected].start
            for index, group in enumerate(fragments):
                for alternative, (start, end) in enumerate(group.branches):
                    if start <= position < end:
                        picks[index] = alternative
                        break
        key = tuple(picks)
        if key in seen:
            continue
        seen.add(key)
        result = bytearray(raw)
        for index, group in enumerate(fragments):
            ranges = [*group.directives]
            ranges.extend(
                span
                for alternative, span in enumerate(group.branches)
                if alternative != picks[index]
            )
            for start, end in ranges:
                result[start:end] = raw[start:end].translate(_MASK)
        yield bytes(result)
