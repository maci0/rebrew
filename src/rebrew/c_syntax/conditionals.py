"""Same-coordinate structural views for conditional C brace fragments.

This does not evaluate macros. It selects structurally equivalent branches for
AST parsing, and supplies each alternative so inventories retain source facts.
"""

import re
from dataclasses import dataclass, field
lazy from collections.abc import Callable, Iterator
lazy from typing import Any

_DIRECTIVE = re.compile(rb"^[ \t]*#[ \t]*([A-Za-z_][A-Za-z_0-9]*)", re.M)
_BRACE = re.compile(rb"[{}]")
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
    """A conditional region whose branches end at the same brace depth.

    ``start``/``end`` span the whole region; ``branches`` and ``directives``
    hold half-open ``(start, end)`` byte ranges in the original source.
    """

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
    lexical, directives = _lexical_view(raw, tree)
    events = [(match.start(), match.end(), match[0]) for match in _BRACE.finditer(lexical)]
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


def _lexical_view(raw: bytes, tree: Any) -> tuple[bytearray, list[tuple[int, int, bytes]]]:
    """Blank comments, literals and directive lines selected from *tree*.

    Returns the blanked copy and each directive's ``(start, end, keyword)``.
    """
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
    return lexical, directives


def top_level_blocks(raw: bytes, tree: Any) -> list[tuple[int, int]]:
    """Half-open spans of *raw*, each ending after a brace that closes to depth zero.

    Comments, literals and directive lines selected from *tree* do not count.
    The spans cover *raw* from the start; text after the last closing brace is
    not a block.
    """
    lexical, _directives = _lexical_view(raw, tree)
    blocks: list[tuple[int, int]] = []
    start = depth = 0
    for match in _BRACE.finditer(lexical):
        if match[0] == b"{":
            depth += 1
        elif depth:
            depth -= 1
            if not depth:
                blocks.append((start, match.end()))
                start = match.end()
    return blocks


def isolate(raw: bytes, start: int, end: int) -> bytes:
    """*raw* with everything outside ``[start, end)`` blanked, newlines kept."""
    return raw[:start].translate(_MASK) + raw[start:end] + raw[end:].translate(_MASK)


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
