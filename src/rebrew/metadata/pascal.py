"""Lexical source positions for Delphi routine anchors; no ABI or type inference."""

lazy import re

#: Hoisted token/ident patterns: compiled once at module load rather than per
#: ``finditer``/``fullmatch`` call.  The per-byte scan below previously built
#: 1-2 byte slices (``source[i:i+1]``) per byte plus a pattern per token.
_TOKEN_RE = re.compile(rb"[A-Za-z_][A-Za-z_0-9]*|[^\s]")
_IDENT_RE = re.compile(rb"[A-Za-z_][A-Za-z_0-9]*")
_QUOTE = 0x27  # ord("'")


def pascal_syntax(
    source: bytes,
) -> tuple[bytearray, list[tuple[int, int]], dict[int, list[tuple[str, str, str]]]]:
    """Mask strings/comments and index implementation routine headings.

    Interface and class prototypes are not implementations. Forward/external
    declarations have no source body. Compiler directives remain barriers, so
    a conditional between an address and its routine cannot silently bind it.
    """
    masked = bytearray(source)
    comments: list[tuple[int, int]] = []
    i = 0
    n = len(source)
    while i < n:
        start = i
        if source[i] == _QUOTE:
            i += 1
            while i < n:
                if source[i] == _QUOTE:
                    i += 1
                    if i >= n or source[i] != _QUOTE:
                        break
                i += 1
        elif source[i : i + 1] == b"{" or source[i : i + 2] in (b"(*", b"//"):
            opening = b"{" if source[i : i + 1] == b"{" else source[i : i + 2]
            closing = {b"{": b"}", b"(*": b"*)", b"//": b"\n"}[opening]
            end = source.find(closing, i + len(opening))
            if end < 0 and opening != b"//":
                raise ValueError("unterminated Delphi comment")
            i = len(source) if end < 0 else end + (0 if opening == b"//" else len(closing))
            comments.append((start, i))
            if source[start + len(opening) : start + len(opening) + 1] == b"$":
                continue
        else:
            i += 1
            continue
        for j in range(start, i):
            if masked[j] not in (10, 13):
                masked[j] = 32

    tokens = list(_TOKEN_RE.finditer(masked))
    words = [token[0].lower() for token in tokens]
    implementation = words.index(b"implementation") if b"implementation" in words else -1
    is_unit = bool(words and words[0] == b"unit")
    declarations: dict[int, list[tuple[str, str, str]]] = {}
    for idx, word in enumerate(words):
        if word not in (b"procedure", b"function", b"constructor", b"destructor"):
            continue
        if is_unit and (implementation < 0 or idx < implementation):
            continue
        j = idx + 1
        name: list[bytes] = []
        if j >= len(tokens) or not _IDENT_RE.fullmatch(tokens[j][0]):
            continue
        name.append(tokens[j][0])
        j += 1
        while j + 1 < len(tokens) and words[j] == b".":
            name.extend((b".", tokens[j + 1][0]))
            j += 2
        depth = 0
        while j < len(tokens):
            if words[j] == b"(":
                depth += 1
            elif words[j] == b")":
                depth -= 1
            elif words[j] == b";" and depth == 0:
                break
            j += 1
        while (
            j + 2 < len(tokens)
            and words[j + 1]
            in (
                b"far",
                b"near",
                b"cdecl",
                b"pascal",
                b"register",
                b"stdcall",
                b"export",
            )
            and words[j + 2] == b";"
        ):
            j += 2
        if j + 1 >= len(tokens) or words[j + 1] not in (
            b"begin",
            b"asm",
            b"var",
            b"const",
            b"type",
            b"label",
            b"procedure",
            b"function",
        ):
            continue
        line = source.count(b"\n", 0, tokens[idx].start()) + 1
        declarations.setdefault(line, []).append((b"".join(name).decode("ascii"), "FUNCTION", ""))
    return masked, comments, declarations
