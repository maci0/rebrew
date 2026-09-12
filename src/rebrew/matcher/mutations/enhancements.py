"""enhancements.py — MSVC6 codegen-insight and register-pressure operators.

Phase 5 commutative/block-register/type-retyping/zero-clearing mutations,
Enhancements 2-4, the Phase 6 binary-cleanup set, and Category 7 register
pressure manipulation.
"""

from __future__ import annotations

import random
import re

import tree_sitter as ts

from rebrew.matcher.ast_engine import _C_LANGUAGE, parse_c_ast
from rebrew.matcher.mutations.queries import (
    _QUERY_ASSIGN_ZERO,
    _QUERY_LOCAL_DECL,
    _LazyQuery,
)
from rebrew.matcher.mutations.runtime import (
    _capture,
    _commute_operands,
    _cursor,
    _find_function_body_insert_pos,
    _first_caps,
)

# --- Queries for Phase 5 mutations ---

_QUERY_COMMUTE_BIT_OR = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "|" @op
        right: (_) @right) @expr
""",
)

_QUERY_COMMUTE_BIT_AND = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "&" @op
        right: (_) @right) @expr
""",
)

_QUERY_COMMUTE_BIT_XOR = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "^" @op
        right: (_) @right) @expr
""",
)

_QUERY_COMMUTE_ADD_GENERAL = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "+" @op
        right: (_) @right) @expr
""",
)

_QUERY_COMMUTE_MUL_GENERAL = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "*" @op
        right: (_) @right) @expr
""",
)

_QUERY_BITAND_ZERO = _LazyQuery(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression
            left: (identifier) @var
            operator: "&="
            right: (number_literal) @val
            (#eq? @val "0")
        )
    ) @expr
""",
)


def mut_commute_bit_or(s: str, rng: random.Random) -> str | None:
    """Swap operands of bitwise OR: ``a | b`` → ``b | a``.

    MSVC6 evaluates sub-expressions left-to-right, so swapping
    ``|`` operands changes temporary register allocation order.
    """
    return _commute_operands(s, rng, _QUERY_COMMUTE_BIT_OR, b"|")


def mut_commute_bit_and(s: str, rng: random.Random) -> str | None:
    """Swap operands of bitwise AND: ``a & b`` → ``b & a``."""
    return _commute_operands(s, rng, _QUERY_COMMUTE_BIT_AND, b"&")


def mut_commute_bit_xor(s: str, rng: random.Random) -> str | None:
    """Swap operands of bitwise XOR: ``a ^ b`` → ``b ^ a``."""
    return _commute_operands(s, rng, _QUERY_COMMUTE_BIT_XOR, b"^")


def mut_commute_add_general(s: str, rng: random.Random) -> str | None:
    """Swap operands of addition with arbitrary sub-expressions.

    Unlike the identifier-only commutes, this handles
    complex AST nodes like ``(w >> 8) + (w << 8)``.
    """
    return _commute_operands(s, rng, _QUERY_COMMUTE_ADD_GENERAL, b"+")


def mut_commute_mul_general(s: str, rng: random.Random) -> str | None:
    """Swap operands of multiplication with arbitrary sub-expressions."""
    return _commute_operands(s, rng, _QUERY_COMMUTE_MUL_GENERAL, b"*")


# --- Enhancement 2: C89 Block-Scoped Register Injection ---


def mut_inject_block_register(s: str, rng: random.Random) -> str | None:
    """Wrap a statement range in ``{ register int _reg_N; ... }``.

    MSVC6 changes its prologue and delayed-push strategy depending on
    exactly where a register variable is declared.  Wrapping a loop or
    a run of statements in an anonymous block with a ``register`` dummy
    delays the register assignment and rotates ESI/EDI/EBX allocation.

    This is C89-safe: the declaration is at the top of the new block.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    # Strategy 1: wrap a loop body in a register block
    q_loop = _LazyQuery(
        _C_LANGUAGE,
        """
        [
            (while_statement body: (compound_statement) @body) @stmt
            (for_statement body: (compound_statement) @body) @stmt
            (do_statement body: (compound_statement) @body) @stmt
        ]
    """,
    )
    cursor = _cursor(q_loop)
    loop_matches = cursor.matches(tree.root_node)

    # Strategy 2: wrap 2-4 adjacent expression_statements in a block
    q_adj = _LazyQuery(
        _C_LANGUAGE,
        """
        (compound_statement
            (expression_statement) @s1
            .
            (expression_statement) @s2
        )
    """,
    )
    cursor2 = _cursor(q_adj)
    adj_matches = cursor2.matches(tree.root_node)

    candidates: list[tuple[str, dict[str, ts.Node]]] = []
    for m in loop_matches:
        caps = _first_caps(m[1])
        candidates.append(("loop", caps))
    for m in adj_matches:
        caps = _first_caps(m[1])
        candidates.append(("adj", caps))

    if not candidates:
        return None

    reg_id = rng.randint(0, 99)
    reg_name = f"_reg_{reg_id}".encode()
    if reg_name in b_source:
        return None

    kind, caps = rng.choice(candidates)

    if kind == "loop":
        body_node = caps["body"]
        inner = b_source[body_node.start_byte + 1 : body_node.end_byte - 1]
        replacement = b"{\n        register int " + reg_name + b";" + inner + b"\n    }"
        result = b_source[: body_node.start_byte] + replacement + b_source[body_node.end_byte :]
    else:
        s1 = caps["s1"]
        s2 = caps["s2"]
        s1_text = b_source[s1.start_byte : s1.end_byte]
        s2_text = b_source[s2.start_byte : s2.end_byte]
        replacement = (
            b"{\n        register int "
            + reg_name
            + b";\n        "
            + s1_text
            + b"\n        "
            + s2_text
            + b"\n    }"
        )
        result = b_source[: s1.start_byte] + replacement + b_source[s2.end_byte :]

    return result.decode("utf-8")


# --- Enhancement 3: Equivalent-Size Local Type Retyping ---

# Cycle through same-size types to influence MSVC6 register weighting.
# int, char*, DWORD, long are all 4 bytes on 32-bit MSVC6.
_EQUIV_TYPE_CYCLE: dict[bytes, bytes] = {
    b"int": b"DWORD",
    b"DWORD": b"long",
    b"long": b"char *",
    b"char *": b"int",
    b"unsigned int": b"ULONG",
    b"ULONG": b"unsigned int",
}


def mut_retype_local_equiv(s: str, rng: random.Random) -> str | None:
    """Cycle a local variable's type between same-size alternatives.

    Changing ``unsigned int count`` to ``char* count`` manipulates the
    type-size rules just enough to shift MSVC6's internal register
    weighting, potentially forcing a variable into a different register.

    Cycle: int → DWORD → long → char* → int
    Also: unsigned int ↔ ULONG
    """
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_LOCAL_DECL)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid: list[tuple[ts.Node, bytes]] = []
    for match in matches:
        caps = match[1]
        type_node = _capture(caps, "type")
        if isinstance(type_node, list):
            type_node = type_node[0]
        if not type_node:
            continue

        # For pointer types, tree-sitter puts the declarator inside
        # a pointer_declarator — we handle only simple types here.
        type_text = b_source[type_node.start_byte : type_node.end_byte].strip()

        # Also check for "register int" → strip qualifier to match cycle
        bare_type = type_text
        for prefix in (b"register ", b"volatile "):
            if bare_type.startswith(prefix):
                bare_type = bare_type[len(prefix) :]

        if bare_type in _EQUIV_TYPE_CYCLE:
            valid.append((type_node, type_text))

    if not valid:
        return None

    node, old_text = rng.choice(valid)

    # Strip qualifiers, cycle the bare type, re-add qualifiers
    prefix = b""
    bare = old_text
    for qual in (b"register ", b"volatile "):
        if bare.startswith(qual):
            prefix = qual
            bare = bare[len(qual) :]
            break

    new_bare = _EQUIV_TYPE_CYCLE.get(bare)
    if not new_bare:
        return None

    new_type = prefix + new_bare
    result = b_source[: node.start_byte] + new_type + b_source[node.end_byte :]
    result_str = result.decode("utf-8")
    return result_str if result_str != s else None


# --- Enhancement 4: Zero-to-Bitand Transform ---


def mut_zero_to_bitand(s: str, rng: random.Random) -> str | None:
    """Transform ``var = 0;`` into ``var &= 0;`` or vice versa.

    MSVC6 sometimes generates ``and [mem], reg`` to clear a variable
    when it knows a register is already zero from an adjacent check.
    Using ``var &= 0`` instead of ``var = 0`` can trigger the
    ``and`` instruction form instead of ``mov [mem], 0``.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    candidates: list[tuple[dict[str, ts.Node], bytes, str]] = []

    # Forward: var = 0 → var &= 0
    zero_cursor = _cursor(_QUERY_ASSIGN_ZERO)
    for m in zero_cursor.matches(tree.root_node):
        caps = _first_caps(m[1])
        # Skip if inside a for-loop initializer
        parent = caps["expr"].parent
        if parent and parent.type == "for_statement":
            continue
        var = b_source[caps["var"].start_byte : caps["var"].end_byte]
        if b"." in var or b"->" in var or b"[" in var:
            continue
        candidates.append((caps, var + b" &= 0;", "expr"))

    # Reverse: var &= 0 → var = 0
    bitand_cursor = _cursor(_QUERY_BITAND_ZERO)
    for m in bitand_cursor.matches(tree.root_node):
        caps = _first_caps(m[1])
        var = b_source[caps["var"].start_byte : caps["var"].end_byte]
        candidates.append((caps, var + b" = 0;", "expr"))

    if not candidates:
        return None

    caps, replacement, target_key = rng.choice(candidates)
    target = caps[target_key]
    result = b_source[: target.start_byte] + replacement + b_source[target.end_byte :]
    return result.decode("utf-8")


# ---------------------------------------------------------------------------
# Phase 6: MSVC6 high-impact targeted mutations (2026-03)
# ---------------------------------------------------------------------------

# --- Queries for Phase 6 ---

_QUERY_IF_ELSE_FULL = _LazyQuery(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression
            (binary_expression
                left: (_) @left
                operator: _ @op
                right: (_) @right
            ) @bin
        ) @cond
        consequence: (_) @cons
        alternative: (else_clause (_) @alt)
    ) @stmt
""",
)

_QUERY_NESTED_CALL_ARG = _LazyQuery(
    _C_LANGUAGE,
    """
    (call_expression
        function: (_) @outer_fn
        arguments: (argument_list
            (call_expression
                function: (_) @inner_fn
                arguments: (argument_list) @inner_args
            ) @inner_call
        ) @args
    ) @stmt
""",
)

_QUERY_COMPLEX_ARG = _LazyQuery(
    _C_LANGUAGE,
    """
    (call_expression
        function: (_) @fn
        arguments: (argument_list
            (binary_expression) @arg
        ) @args
    ) @stmt
""",
)

_QUERY_DUMMY_STACK_VARS = _LazyQuery(
    _C_LANGUAGE, "(function_definition body: (compound_statement) @body)"
)
_QUERY_INJECT_DUMMY_REGISTERS = _LazyQuery(
    _C_LANGUAGE, "(function_definition body: (compound_statement) @body)"
)
_QUERY_HOIST_REPEATED_DEREF = _LazyQuery(
    _C_LANGUAGE, "(function_definition body: (compound_statement) @body)"
)


# Operator inversion map for De Morgan-aware if/else inversion.
# NOTE: && ↔ || are deliberately absent — inverting them requires negating
# the operands too (if (a && b) → if (!a || !b)), which this mutator does
# not do.  Mapping them directly flips the branch outcome (verified wrong
# for a=1, b=1), so those operators are left untouched here.
_INVERT_OP: dict[bytes, bytes] = {
    b"==": b"!=",
    b"!=": b"==",
    b"<": b">=",
    b">=": b"<",
    b">": b"<=",
    b"<=": b">",
}


def mut_invert_if_else(s: str, rng: random.Random) -> str | None:
    """Invert if/else with proper operator negation (De Morgan-aware).

    Unlike :func:`mut_swap_if_else` which wraps in ``!()``,  this
    mutator directly inverts the comparison operator::

        if (a == b) { A } else { B }  →  if (a != b) { B } else { A }

    MSVC6 emits ``je`` vs ``jne`` depending on the condition polarity.
    Swapping the operator *and* the bodies produces semantically
    identical code but forces the opposite branch prediction layout
    and jump instruction.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    cursor = _cursor(_QUERY_IF_ELSE_FULL)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])

    op_node = caps["op"]
    op_text = b_source[op_node.start_byte : op_node.end_byte]
    inverted_op = _INVERT_OP.get(op_text)
    if not inverted_op:
        return None

    left = b_source[caps["left"].start_byte : caps["left"].end_byte]
    right = b_source[caps["right"].start_byte : caps["right"].end_byte]
    cons = b_source[caps["cons"].start_byte : caps["cons"].end_byte]
    alt = b_source[caps["alt"].start_byte : caps["alt"].end_byte]

    # Brace both arms: a bare `else if` without its own trailing else would
    # otherwise re-bind the final else to the inner if (dangling else),
    # flipping branch outcomes.
    def _braced(body: bytes) -> bytes:
        if body.startswith(b"{") and body.endswith(b"}"):
            return body
        return b"{ " + body + b" }"

    stmt_node = caps["stmt"]
    replacement = (
        b"if ("
        + left
        + b" "
        + inverted_op
        + b" "
        + right
        + b") "
        + _braced(alt)
        + b" else "
        + _braced(cons)
    )
    result = b_source[: stmt_node.start_byte] + replacement + b_source[stmt_node.end_byte :]
    return result.decode("utf-8")


# Stack-frame padding sizes that trip MSVC6 push/sub-esp thresholds.
# 4-byte increments test individual register pushes vs sub esp.
# Larger sizes (16, 32, 64) test alloca-style frame expansion.
_STACK_PAD_SIZES = [4, 8, 12, 16, 20, 24, 32, 48, 64]


def mut_dummy_stack_vars(s: str, rng: random.Random) -> str | None:
    """Inject volatile stack padding to trigger MSVC6 frame strategy changes.

    MSVC6 decides between ``push reg`` (small frame) and ``sub esp, N``
    (larger frame) based on the total size of local variables.  By
    injecting sized ``volatile`` locals we can cross the threshold that
    flips the strategy.

    Unlike :func:`mut_inject_dummy_var` (single ``int``), this injects
    a ``volatile`` local of a specific, randomly-chosen byte size to
    precisely target the push/sub-esp boundary.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    q = _QUERY_DUMMY_STACK_VARS
    cursor = _cursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])
    body_node = caps["body"]

    pad_id = rng.randint(0, 99)
    pad_name = f"_spad_{pad_id}".encode()
    if pad_name in b_source:
        return None

    size = rng.choice(_STACK_PAD_SIZES)
    insert_pos = body_node.start_byte + 1

    if size == 4:
        decl = b"\n    volatile int " + pad_name + b" = 0;"
    else:
        decl = (
            b"\n    volatile char "
            + pad_name
            + f"[{size}]".encode()
            + b"; "
            + pad_name
            + b"[0] = 0;"
        )

    result = b_source[:insert_pos] + decl + b_source[insert_pos:]
    return result.decode("utf-8")


# --- Category 7: Register Pressure Manipulation ---


def mut_inject_dummy_registers(s: str, rng: random.Random) -> str | None:
    """Inject ``register int`` declarations to consume volatile registers.

    MSVC6 honours the ``register`` keyword and will allocate the
    requested variables into the volatile registers (eax, ecx, edx)
    first.  By injecting 1-3 dummy ``register int`` locals at the top
    of a function body we force subsequent real variables into
    callee-saved registers (esi, edi, ebx), which changes the
    prologue/epilogue push/pop sequence and overall code layout.

    The count is randomised (1-3) so the GA can explore different
    register pressure levels.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    q = _QUERY_INJECT_DUMMY_REGISTERS
    cursor = _cursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])
    body_node = caps["body"]

    count = rng.randint(1, 3)
    decls: list[bytes] = []
    for _ in range(count):
        reg_id = rng.randint(0, 99)
        name = f"_dummy_reg_{reg_id}".encode()
        if name in b_source:
            return None
        # Guard against duplicates within the batch itself.
        if name in b"".join(decls):
            return None
        decls.append(b"\n    register int " + name + b" = 0;")

    insert_pos = body_node.start_byte + 1
    payload = b"".join(decls)
    result = b_source[:insert_pos] + payload + b_source[insert_pos:]
    return result.decode("utf-8")


def mut_extract_complex_args(s: str, rng: random.Random) -> str | None:
    """Extract nested calls or complex expressions from function arguments.

    When MSVC6 sees ``foo(a, bar(b))``, it folds the inner call's result
    directly into the ``push`` sequence for the outer call.  This can
    produce interleaved ``lea``/``mov``/``push`` patterns that differ
    from the target.

    Extracting into a temp var forces explicit right-to-left evaluation::

        foo(a, bar(b))  →  int _t42 = bar(b); foo(a, _t42);

    Targets both nested function calls and binary-expression arguments
    (e.g. ``ptr + offset``).
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    candidates: list[tuple[ts.Node, ts.Node, bytes]] = []

    # Strategy 1: nested function calls in arguments
    nc_cursor = _cursor(_QUERY_NESTED_CALL_ARG)
    for m in nc_cursor.matches(tree.root_node):
        caps = _first_caps(m[1])
        call_node = caps["stmt"]  # the OUTER call expression
        inner_call_node = caps["inner_call"]
        inner_text = b_source[inner_call_node.start_byte : inner_call_node.end_byte]
        candidates.append((call_node, inner_call_node, inner_text))

    # Strategy 2: binary expressions as arguments (ptr arithmetic, shifts, etc.)
    ca_cursor = _cursor(_QUERY_COMPLEX_ARG)
    for m in ca_cursor.matches(tree.root_node):
        caps = _first_caps(m[1])
        call_node = caps["stmt"]
        arg_node = caps["arg"]
        # Only extract if not trivially simple
        arg_text = b_source[arg_node.start_byte : arg_node.end_byte]
        if len(arg_text) > 6:  # skip trivial like "a + 1"
            candidates.append((call_node, arg_node, arg_text))

    if not candidates:
        return None

    call_node, extract_node, extract_text = rng.choice(candidates)

    # The query captures the call expression, but the temp assignment must be
    # inserted BEFORE the enclosing statement — splicing at the call start
    # turns `return g(a, h(b, c));` into `return _t = h(b, c); g(a, _t);`,
    # changing the return value and killing the outer call.  Only expression
    # and return statements are handled (same shapes the older
    # the older extract-args mutator supported); everything else is skipped.
    stmt = call_node
    while stmt.parent is not None:
        parent = stmt.parent
        if parent.type in ("expression_statement", "return_statement"):
            stmt = parent
            break
        if parent.type == "compound_statement":
            break
        stmt = parent
    if stmt.type not in ("expression_statement", "return_statement"):
        return None

    var_id = rng.randint(0, 999)
    var_name = f"_t{var_id}".encode()
    if var_name in b_source:
        return None

    # C89: hoist declaration to function body top
    insert_pos = _find_function_body_insert_pos(b_source, stmt.start_byte)
    if insert_pos is None:
        return None

    hoisted_decl = b"\n    int " + var_name + b";"
    inline_assign = var_name + b" = " + extract_text + b";\n    "

    # Insert hoisted decl at function body top
    out = b_source[:insert_pos] + hoisted_decl + b_source[insert_pos:]
    # Adjust offsets by the hoisted decl length
    offset = len(hoisted_decl)
    s_start = stmt.start_byte + offset
    s_end = stmt.end_byte + offset
    e_start = extract_node.start_byte + offset
    e_end = extract_node.end_byte + offset

    new_stmt = out[s_start:e_start] + var_name + out[e_end:s_end]
    result = out[:s_start] + inline_assign + new_stmt + out[s_end:]

    return result.decode("utf-8")


def mut_hoist_repeated_deref(s: str, rng: random.Random) -> str | None:
    """Hoist a repeated absolute-pointer deref into a kept-live local.

    ``*(T *)0x415880`` used N times compiles to N memory re-reads; assigning
    it to a local once keeps the pointer live, which is the MSVC6 codegen
    for a global-pointer variable tested by truthiness (``mov eax,[mem];
    test eax,eax``).  Campaign finding: the register-only NEAR_MATCHING gap
    on smygb 0x401370 (100% mnemonic match, 21 register diffs) needs exactly
    this shape change — a shared ``p`` local reused across blocks keeps one
    register, while the target keeps the object pointer live in another.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    q = _QUERY_HOIST_REPEATED_DEREF
    cursor = _cursor(q)
    matches = list(cursor.matches(tree.root_node))
    if not matches:
        return None
    match = rng.choice(matches)
    caps = _first_caps(match[1])
    body_node = caps["body"]
    body_start, body_end = body_node.start_byte, body_node.end_byte
    # AST offsets are UTF-8 byte positions: slice the BYTES, not the str.  The
    # old str slice mis-aligned by one index per multibyte char before the body
    # (a single `é` in a comment), garbling or skipping the splice.
    body_bytes = b_source[body_start:body_end]

    deref_re = re.compile(rb"\*\s*\(\s*[^)]*\*\s*\)\s*0x[0-9a-fA-F]+")
    occurrences = list(deref_re.finditer(body_bytes))
    if len(occurrences) < 2:
        return None
    # Group by the absolute address; the address with the most repeats wins.
    by_addr: dict[bytes, list[re.Match[bytes]]] = {}
    for m in occurrences:
        addr_m = re.search(rb"0x[0-9a-fA-F]+$", m.group(0))
        if addr_m is None:
            continue
        by_addr.setdefault(addr_m.group(0), []).append(m)
    addr, ms = max(by_addr.items(), key=lambda kv: len(kv[1]))
    if len(ms) < 2:
        return None
    first_expr = ms[0].group(0)
    local_name = f"_ptr{rng.randint(0, 99)}"
    decl = b"void *" + local_name.encode() + b" = " + first_expr + b";"
    # Replace EVERY occurrence (including the first) with the local name —
    # the declaration above carries the original expression.
    new_body = body_bytes
    for m in reversed(ms):
        new_body = new_body[: m.start()] + local_name.encode() + new_body[m.end() :]
    # Insert the declaration right after the opening '{'.
    insert_at = new_body.find(b"{") + 1
    if insert_at <= 0:
        return None
    new_body = new_body[:insert_at] + b"\n    " + decl + new_body[insert_at:]
    return (b_source[:body_start] + new_body + b_source[body_end:]).decode("utf-8")


#: Function-level pragmas that affect a single function's codegen — they
#: stay with the function body across preamble/body splits so the pragma
#: mutations can find, add, and remove them (a removed pragma must not
#: linger in the preamble, where the mutation layer never sees it).
