"""structural.py — MSVC6-targeted structural mutation operators.

Control-flow/branch inversion, stack-frame manipulation, instruction folding,
zero-extension/register clearing, and register-pressure fuzzing.
"""

from __future__ import annotations

import random

import tree_sitter as ts

from rebrew.matcher.ast_engine import _C_LANGUAGE, parse_c_ast
from rebrew.matcher.mutations.queries import (
    _QUERY_ADD_VOLATILE_INTERMEDIATE,
    _QUERY_BYTE_CAST,
    _QUERY_BYTE_TYPE_DECL,
    _QUERY_DEREF_PTR_ADD,
    _QUERY_IF_STMT,
    _QUERY_INJECT_DUMMY_ARRAY,
    _QUERY_INJECT_DUMMY_VAR,
    _QUERY_REGISTER_DECL,
    _QUERY_SCOPE_VARIABLE,
    _QUERY_SUBSCRIPT_EXPR,
    _QUERY_SUBSCRIPT_SCALED,
    _QUERY_WHILE_LOOP,
    _LazyQuery,
)
from rebrew.matcher.mutations.runtime import (
    _apply_query_once,
    _capture,
    _cursor,
    _find_function_body_insert_pos,
    _first_caps,
)

# ---------------------------------------------------------------------------
# MSVC6-targeted structural mutations (2026-03 batch)
# ---------------------------------------------------------------------------


# --- Category 1: Control Flow & Branch Inversion ---


def mut_while_to_goto_loop(s: str, rng: random.Random) -> str | None:
    """Rewrite while(cond) { body } to goto-based loop with explicit jumps.

    Forces MSVC6 to emit different branch/fall-through layouts.
    Output:
        loop_N:
          if (!(cond)) goto end_N;
          body
          goto loop_N;
        end_N:
              ;
    """
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_WHILE_LOOP)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])

    cond = b_source[caps["cond"].start_byte : caps["cond"].end_byte]
    body_node = caps["body"]
    # Brace-stripping below assumes a compound body; a single-statement
    # body (while (c) x++;) would have its first/last characters cut off
    # (x++; → ++), emitting uncompilable code.
    if body_node.type != "compound_statement":
        return None
    body = b_source[body_node.start_byte : body_node.end_byte]

    # Strip outer parens from cond
    cond_inner = cond
    if cond_inner.startswith(b"(") and cond_inner.endswith(b")"):
        cond_inner = cond_inner[1:-1]

    # Use a unique suffix to avoid label collisions
    label_id = rng.randint(0, 999)
    loop_label = f"_loop_{label_id}".encode()
    end_label = f"_end_{label_id}".encode()

    # Check for label collisions in existing source
    if loop_label in b_source or end_label in b_source:
        return None

    inner = body[1:-1]  # strip { }

    replacement = (
        loop_label
        + b":\n    "
        + b"if (!("
        + cond_inner.strip()
        + b")) goto "
        + end_label
        + b";\n    "
        + inner.strip()
        + b"\n    "
        + b"goto "
        + loop_label
        + b";\n    "
        + end_label
        + b": ;"
    )

    result = b_source[: caps["stmt"].start_byte] + replacement + b_source[caps["stmt"].end_byte :]
    return result.decode("utf-8")


# --- Category 2: Stack Frame Manipulation ---


def mut_inject_dummy_var(s: str, rng: random.Random) -> str | None:
    """Inject an unused local variable to change stack frame allocation.

    Adding locals can switch MSVC6 between push ecx (small frame)
    and sub esp, N (larger frame).
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    # Find function body compound statements
    q = _QUERY_INJECT_DUMMY_VAR
    cursor = _cursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])
    body_node = caps["body"]

    dummy_id = rng.randint(0, 99)
    dummy_name = f"_dummy_{dummy_id}".encode()
    if dummy_name in b_source:
        return None

    # Insert after opening brace
    insert_pos = body_node.start_byte + 1
    decl = b"\n    int " + dummy_name + b";"
    result = b_source[:insert_pos] + decl + b_source[insert_pos:]
    return result.decode("utf-8")


def mut_inject_dummy_array(s: str, rng: random.Random) -> str | None:
    """Inject an unused char array to push past stack alignment thresholds.

    MSVC6 changes stack allocation strategy at certain byte boundaries.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    q = _QUERY_INJECT_DUMMY_ARRAY
    cursor = _cursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])
    body_node = caps["body"]

    pad_id = rng.randint(0, 99)
    pad_name = f"_pad_{pad_id}".encode()
    if pad_name in b_source:
        return None

    size = rng.choice([4, 8, 12, 16])
    insert_pos = body_node.start_byte + 1
    decl = f"\n    char {pad_name.decode()}[{size}];".encode()
    result = b_source[:insert_pos] + decl + b_source[insert_pos:]
    return result.decode("utf-8")


def mut_scope_variable(s: str, rng: random.Random) -> str | None:
    """Move a local variable declaration into a nested block scope.

    MSVC6 allocates stack space differently for block-scoped variables.
    Wraps the declaration + its first usage in a bare { } block.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    # Find declarations inside the function body (top-level compound_statement)
    q = _QUERY_SCOPE_VARIABLE
    cursor = _cursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])

    d1 = caps["d1"]
    next_stmt = caps["next_stmt"]

    d1_text = b_source[d1.start_byte : d1.end_byte]
    next_text = b_source[next_stmt.start_byte : next_stmt.end_byte]

    # Wrap both in a bare block
    replacement = b"{\n        " + d1_text + b"\n        " + next_text + b"\n    }"

    result = b_source[: d1.start_byte] + replacement + b_source[next_stmt.end_byte :]
    return result.decode("utf-8")


# --- Category 3: Instruction Folding (lea vs. Arithmetic) ---


def mut_array_to_ptr_arith(s: str, rng: random.Random) -> str | None:
    """Rewrite p[i] to *(p + i).

    Changes whether MSVC6 uses lea for address computation or explicit
    add/shl instructions.
    """
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        arr = b_source[captures["arr"].start_byte : captures["arr"].end_byte]
        idx = b_source[captures["idx"].start_byte : captures["idx"].end_byte]
        return b"*((" + arr + b") + (" + idx + b"))"

    res = _apply_query_once(b_source, _QUERY_SUBSCRIPT_EXPR, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None


def mut_ptr_arith_to_array(s: str, rng: random.Random) -> str | None:
    """Rewrite *(p + i) to p[i] (inverse of mut_array_to_ptr_arith)."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        ptr = b_source[captures["ptr"].start_byte : captures["ptr"].end_byte]
        idx = b_source[captures["idx"].start_byte : captures["idx"].end_byte]
        return ptr + b"[" + idx + b"]"

    res = _apply_query_once(b_source, _QUERY_DEREF_PTR_ADD, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None


def mut_decouple_index_math(s: str, rng: random.Random) -> str | None:
    """Decouple scaled array index to break lea folding.

    Rewrites ``p[i * N]`` to ``int _off_72; p[(_off_72 = i * N, _off_72)]``
    (declaration hoisted to the function top per C89).  The temp is
    genuinely declared and the parenthesized comma-expression preserves the
    index value, so the candidate compiles and stays semantically identical
    — MSVC6 just computes the offset separately instead of folding it into
    a lea.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_SUBSCRIPT_SCALED)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    _, captures = rng.choice(matches)
    caps = _first_caps(captures)
    expr = caps["expr"]

    arr = b_source[caps["arr"].start_byte : caps["arr"].end_byte]
    idx_left = b_source[caps["idx_left"].start_byte : caps["idx_left"].end_byte]
    idx_right = b_source[caps["idx_right"].start_byte : caps["idx_right"].end_byte]

    off_id = rng.randint(0, 99)
    off_name = f"_off_{off_id}".encode()
    if off_name in b_source:
        return None

    insert_pos = _find_function_body_insert_pos(b_source, expr.start_byte)
    if insert_pos is None:
        return None

    hoisted_decl = b"\n    int " + off_name + b";"
    # (off = i * N, off) — valid C comma-expression with the same value as
    # i * N, computed before the subscript is evaluated.
    new_expr = (
        arr + b"[(" + off_name + b" = " + idx_left + b" * " + idx_right + b", " + off_name + b")]"
    )

    out = b_source[:insert_pos] + hoisted_decl + b_source[insert_pos:]
    offset = len(hoisted_decl)
    e_start = expr.start_byte + offset
    e_end = expr.end_byte + offset
    result = out[:e_start] + new_expr + out[e_end:]
    return result.decode("utf-8")


# --- Category 4: Zero-Extension & Register Clearing ---


def mut_preinit_byte_load(s: str, rng: random.Random) -> str | None:
    """Pre-initialize byte-width variable to trigger xor reg, reg pattern.

    Rewrites: char c = *p;  -->  int c = 0; c = *p;
    MSVC6 emits xor eax, eax + mov al, [mem] instead of movzx.
    """
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_BYTE_TYPE_DECL)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])

    var = b_source[caps["var"].start_byte : caps["var"].end_byte]
    init_expr = b_source[caps["init"].start_byte : caps["init"].end_byte]

    # Widen type to int and split into decl + assign with zero pre-init
    replacement = b"int " + var + b" = 0;\n    " + var + b" = " + init_expr + b";"

    stmt = caps["stmt"]
    result = b_source[: stmt.start_byte] + replacement + b_source[stmt.end_byte :]
    return result.decode("utf-8")


def mut_cast_to_bitmask(s: str, rng: random.Random) -> str | None:
    """Rewrite type casts to explicit bitmask operations.

    (WORD)x  --> (x & 0xFFFF)
    (BYTE)x  --> (x & 0xFF)
    Affects movzx vs. and-masking codegen in MSVC6.
    """
    b_source = s.encode("utf-8")

    _MASK_MAP = {
        b"WORD": b"0xFFFF",
        b"unsigned short": b"0xFFFF",
        b"BYTE": b"0xFF",
        b"unsigned char": b"0xFF",
    }

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        type_text = b_source[captures["type"].start_byte : captures["type"].end_byte]
        val = b_source[captures["val"].start_byte : captures["val"].end_byte]
        mask = _MASK_MAP.get(type_text.strip())
        if mask is None:
            return b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        return b"((" + val + b") & " + mask + b")"

    res = _apply_query_once(b_source, _QUERY_BYTE_CAST, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None


# --- Category 5: Register Pressure Fuzzing ---


def mut_swap_register_keywords(s: str, rng: random.Random) -> str | None:
    """Swap register keyword between two local variable declarations.

    In MSVC6, the order of register-annotated declarations directly maps
    to register allocation (first=ESI, second=EDI, third=EBX).
    Moving register from one var to another changes allocation.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    # Find ALL declarations
    q_all = _LazyQuery(_C_LANGUAGE, "(declaration) @decl")
    cursor_all = _cursor(q_all)
    all_decls = cursor_all.matches(tree.root_node)

    if len(all_decls) < 2:
        return None

    # Separate into register and non-register declarations
    reg_decls = []
    non_reg_decls = []
    for m in all_decls:
        caps = _first_caps(m[1])
        decl_node = caps["decl"]
        text = b_source[decl_node.start_byte : decl_node.end_byte]
        if b"register " in text:
            reg_decls.append(decl_node)
        elif text.strip().startswith(
            (
                b"int ",
                b"char ",
                b"short ",
                b"long ",
                b"unsigned ",
                b"signed ",
                b"DWORD ",
                b"BOOL ",
                b"BYTE ",
                b"WORD ",
            )
        ):
            non_reg_decls.append(decl_node)

    if not reg_decls or not non_reg_decls:
        return None

    # Pick one register decl and one non-register decl
    reg_node = rng.choice(reg_decls)
    non_reg_node = rng.choice(non_reg_decls)

    reg_text = b_source[reg_node.start_byte : reg_node.end_byte]
    non_reg_text = b_source[non_reg_node.start_byte : non_reg_node.end_byte]

    # Remove register from the register decl, add it to the non-register decl
    new_reg_text = reg_text.replace(b"register ", b"", 1)
    new_non_reg_text = b"register " + non_reg_text

    # Apply replacements in order (later position first to preserve offsets)
    if reg_node.start_byte > non_reg_node.start_byte:
        result = (
            b_source[: non_reg_node.start_byte]
            + new_non_reg_text
            + b_source[non_reg_node.end_byte : reg_node.start_byte]
            + new_reg_text
            + b_source[reg_node.end_byte :]
        )
    else:
        result = (
            b_source[: reg_node.start_byte]
            + new_reg_text
            + b_source[reg_node.end_byte : non_reg_node.start_byte]
            + new_non_reg_text
            + b_source[non_reg_node.end_byte :]
        )

    return result.decode("utf-8")


def mut_add_volatile_intermediate(s: str, rng: random.Random) -> str | None:
    """Wrap an assignment RHS in a volatile temporary to force stack spill.

    x = a + b;  -->  volatile int _t_N;  (hoisted to function top)
                     _t_N = a + b; x = _t_N;  (inline)

    C89-safe: declaration is hoisted to the function body top.
    Forces MSVC6 to spill the intermediate to the stack, freeing up
    registers for the main computation path.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    q = _QUERY_ADD_VOLATILE_INTERMEDIATE
    cursor = _cursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])

    var = b_source[caps["var"].start_byte : caps["var"].end_byte]
    rhs = b_source[caps["rhs"].start_byte : caps["rhs"].end_byte]
    stmt = caps["stmt"]

    tmp_id = rng.randint(0, 99)
    tmp_name = f"_t_{tmp_id}".encode()
    if tmp_name in b_source:
        return None

    # C89: hoist declaration to function body top
    insert_pos = _find_function_body_insert_pos(b_source, stmt.start_byte)
    if insert_pos is None:
        return None

    hoisted_decl = b"\n    volatile int " + tmp_name + b";"
    inline_replacement = tmp_name + b" = " + rhs + b";\n    " + var + b" = " + tmp_name + b";"

    out = b_source[:insert_pos] + hoisted_decl + b_source[insert_pos:]
    offset = len(hoisted_decl)
    stmt_start = stmt.start_byte + offset
    stmt_end = stmt.end_byte + offset

    result = out[:stmt_start] + inline_replacement + out[stmt_end:]
    return result.decode("utf-8")


def mut_reorder_register_vars(s: str, rng: random.Random) -> str | None:
    """Reorder register-annotated variable declarations.

    MSVC6 assigns registers in declaration order:
      first register var → ESI, second → EDI, third → EBX.
    Permuting them directly controls register allocation.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    cursor = _cursor(_QUERY_REGISTER_DECL)
    matches = cursor.matches(tree.root_node)

    # Collect all register declarations
    reg_nodes: list[ts.Node] = []
    for m in matches:
        caps = _first_caps(m[1])
        reg_nodes.append(caps["stmt"])

    if len(reg_nodes) < 2:
        return None

    # Pick two adjacent register declarations and swap them
    idx = rng.randint(0, len(reg_nodes) - 2)
    n1 = reg_nodes[idx]
    n2 = reg_nodes[idx + 1]

    n1_text = b_source[n1.start_byte : n1.end_byte]
    n2_text = b_source[n2.start_byte : n2.end_byte]
    mid_text = b_source[n1.end_byte : n2.start_byte]
    if mid_text.strip():
        # Statements between the two declarations (e.g. a use of n1's
        # variable: `register int a = 0; use(a); register int b = 0;`)
        # would leave the moved declaration after the use — undeclared
        # identifier, a guaranteed wasted compile.  Only swap ADJACENT
        # declarations.
        return None

    result = b_source[: n1.start_byte] + n2_text + mid_text + n1_text + b_source[n2.end_byte :]
    return result.decode("utf-8")


# ---------------------------------------------------------------------------
# Switch statement mutations (MSVC6 comparison chain codegen)
# ---------------------------------------------------------------------------

_QUERY_SWITCH_STMT = _LazyQuery(
    _C_LANGUAGE,
    """
    (switch_statement
        condition: (parenthesized_expression) @cond
        body: (compound_statement) @body) @stmt
""",
)


def mut_reorder_switch_cases(s: str, rng: random.Random) -> str | None:
    """Swap two case clauses within a switch statement.

    MSVC6 generates comparison chains for sparse case values (e.g. Windows
    message IDs) in **source order**.  Reordering cases directly changes
    the cmp/je/jne branch tree layout.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_SWITCH_STMT)
    matches = cursor.matches(tree.root_node)
    if not matches:
        return None

    _, caps = rng.choice(matches)
    body_node = caps["body"][0]

    # Collect case_statement children (skip default for reordering)
    case_nodes = [
        c
        for c in body_node.children
        if c.type == "case_statement" and c.children and c.children[0].type == "case"
    ]
    if len(case_nodes) < 2:
        return None

    # Pick two random distinct cases and swap them
    i, j = rng.sample(range(len(case_nodes)), 2)
    n1 = case_nodes[i]
    n2 = case_nodes[j]
    # Ensure n1 comes before n2 in the source
    if n1.start_byte > n2.start_byte:
        n1, n2 = n2, n1

    n1_text = b_source[n1.start_byte : n1.end_byte]
    n2_text = b_source[n2.start_byte : n2.end_byte]

    result = (
        b_source[: n1.start_byte]
        + n2_text
        + b_source[n1.end_byte : n2.start_byte]
        + n1_text
        + b_source[n2.end_byte :]
    )
    return result.decode("utf-8")


def mut_switch_to_if_chain(s: str, rng: random.Random) -> str | None:
    """Convert a switch/case statement to an if/else if chain.

    MSVC6 generates fundamentally different code for if/else if vs switch:
    switch uses a comparison chain with subtraction-based dispatch;
    if/else if uses direct comparisons.  This mutation explores that
    alternate codegen path.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_SWITCH_STMT)
    matches = cursor.matches(tree.root_node)
    if not matches:
        return None

    _, caps = rng.choice(matches)
    stmt_node = caps["stmt"][0]
    cond_node = caps["cond"][0]
    body_node = caps["body"][0]

    # Extract the condition expression (strip parens)
    cond_text = b_source[cond_node.start_byte + 1 : cond_node.end_byte - 1].strip()

    # Collect case statements with their values and bodies
    branches: list[tuple[bytes | None, bytes]] = []  # (value_or_None_for_default, body)
    for child in body_node.children:
        if child.type != "case_statement":
            continue
        is_default = child.children and child.children[0].type == "default"
        if is_default:
            # Collect body statements after the colon
            body_parts = []
            past_colon = False
            for sub in child.children:
                if sub.type == ":":
                    past_colon = True
                    continue
                if past_colon and sub.type != "break_statement":
                    body_parts.append(b_source[sub.start_byte : sub.end_byte])
            body_text = b"\n        ".join(body_parts) if body_parts else b"/* empty */"
            branches.append((None, body_text))
        else:
            # Extract case value (between 'case' and ':')
            value_node = None
            for sub in child.children:
                if sub.type == "case":
                    continue
                if sub.type == ":":
                    break
                value_node = sub
            if value_node is None:
                continue
            case_val = b_source[value_node.start_byte : value_node.end_byte].strip()
            # Collect body statements after the colon
            body_parts = []
            past_colon = False
            for sub in child.children:
                if sub.type == ":":
                    past_colon = True
                    continue
                if past_colon and sub.type != "break_statement":
                    body_parts.append(b_source[sub.start_byte : sub.end_byte])
            body_text = b"\n        ".join(body_parts) if body_parts else b"/* empty */"
            branches.append((case_val, body_text))

    if not branches:
        return None

    # Build if/else if chain
    parts: list[bytes] = []
    default_body: bytes | None = None
    first = True
    for val, body in branches:
        if val is None:
            default_body = body
            continue
        if first:
            parts.append(b"if (" + cond_text + b" == " + val + b") {\n        " + body + b"\n    }")
            first = False
        else:
            parts.append(
                b" else if (" + cond_text + b" == " + val + b") {\n        " + body + b"\n    }"
            )

    if default_body is not None:
        parts.append(b" else {\n        " + default_body + b"\n    }")

    if not parts:
        return None

    replacement = b"".join(parts)
    result = b_source[: stmt_node.start_byte] + replacement + b_source[stmt_node.end_byte :]
    return result.decode("utf-8")


def mut_split_switch(s: str, rng: random.Random) -> str | None:
    """Split a switch into two nested switches guarded by a range check.

    Rewrites ``switch(x) { case A: ...; case B: ...; case C: ...; }``
    into ``if (x <= B) { switch(x) { case A: ...; case B: ...; } }
    else { switch(x) { case C: ...; } }``

    This forces a two-level dispatch which can match binaries where the
    original code used nested message handling or where MSVC6 internally
    split the comparison tree at a different pivot.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_SWITCH_STMT)
    matches = cursor.matches(tree.root_node)
    if not matches:
        return None

    _, caps = rng.choice(matches)
    stmt_node = caps["stmt"][0]
    cond_node = caps["cond"][0]
    body_node = caps["body"][0]

    cond_text = b_source[cond_node.start_byte + 1 : cond_node.end_byte - 1].strip()

    # Collect non-default case nodes with their original text
    case_nodes = []
    default_text: bytes | None = None
    for child in body_node.children:
        if child.type != "case_statement":
            continue
        is_default = child.children and child.children[0].type == "default"
        if is_default:
            default_text = b_source[child.start_byte : child.end_byte]
        else:
            case_nodes.append(child)

    # Need at least 3 cases to make splitting worthwhile
    if len(case_nodes) < 3:
        return None

    # Pick a split point (not the first or last)
    split_idx = rng.randint(1, len(case_nodes) - 1)
    left_cases = case_nodes[:split_idx]
    right_cases = case_nodes[split_idx:]

    # Extract the pivot value from the last left case
    pivot_node = left_cases[-1]
    pivot_val = None
    for sub in pivot_node.children:
        if sub.type == "case":
            continue
        if sub.type == ":":
            break
        pivot_val = b_source[sub.start_byte : sub.end_byte].strip()
    if pivot_val is None:
        return None

    # Build two switches
    left_body = b"\n    ".join(b_source[c.start_byte : c.end_byte] for c in left_cases)
    right_body = b"\n    ".join(b_source[c.start_byte : c.end_byte] for c in right_cases)

    # Add default to the right switch (or left, randomly)
    if default_text is not None:
        if rng.random() < 0.5:
            left_body += b"\n    " + default_text
        else:
            right_body += b"\n    " + default_text

    replacement = (
        b"if (" + cond_text + b" <= " + pivot_val + b") {\n"
        b"    switch (" + cond_text + b") {\n    " + left_body + b"\n    }\n"
        b"} else {\n"
        b"    switch (" + cond_text + b") {\n    " + right_body + b"\n    }\n"
        b"}"
    )

    result = b_source[: stmt_node.start_byte] + replacement + b_source[stmt_node.end_byte :]
    return result.decode("utf-8")


def mut_move_switch_default(s: str, rng: random.Random) -> str | None:
    """Move the default clause to the top or bottom of a switch body.

    Default position affects fallthrough and the 'else' branch of
    MSVC6's comparison chain.  Moving it changes whether the default
    path is the first or last jne target.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_SWITCH_STMT)
    matches = cursor.matches(tree.root_node)
    if not matches:
        return None

    _, caps = rng.choice(matches)
    body_node = caps["body"][0]

    # Find default and non-default case nodes
    default_node: ts.Node | None = None
    case_nodes: list[ts.Node] = []
    for child in body_node.children:
        if child.type != "case_statement":
            continue
        is_default = child.children and child.children[0].type == "default"
        if is_default:
            default_node = child
        else:
            case_nodes.append(child)

    if default_node is None or not case_nodes:
        return None

    # Check if default is already at desired position
    # Move to top if currently at bottom, bottom if at top/middle
    all_cases = [c for c in body_node.children if c.type == "case_statement"]
    default_idx = all_cases.index(default_node)
    new_order = case_nodes + [default_node] if default_idx == 0 else [default_node] + case_nodes

    # Reconstruct the body with reordered cases
    open_brace = b_source[body_node.start_byte : body_node.start_byte + 1]
    close_brace = b_source[body_node.end_byte - 1 : body_node.end_byte]
    # Use the indentation from the first case statement
    indent = b"\n    "
    new_body = open_brace + indent
    new_body += indent.join(b_source[c.start_byte : c.end_byte] for c in new_order)
    new_body += b"\n" + close_brace

    result = b_source[: body_node.start_byte] + new_body + b_source[body_node.end_byte :]
    return result.decode("utf-8")


# ---------------------------------------------------------------------------
# Advanced Control Flow & Switch Edge Cases (MSVC6 blocks)
# ---------------------------------------------------------------------------


def mut_if_chain_to_switch(s: str, rng: random.Random) -> str | None:
    """Convert an if/else-if equality chain into a switch statement."""
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_IF_STMT)
    matches = cursor.matches(tree.root_node)

    valid_chains = []

    for match in matches:
        if_node = _capture(match, "if_stmt")
        if isinstance(if_node, list):
            if_node = if_node[0]
        if not if_node:
            continue

        if if_node.parent and if_node.parent.type == "else_clause":
            continue

        chain_var = None
        cases = []
        current_if = if_node
        default_body = None

        valid = True
        while current_if:
            if current_if.type != "if_statement":
                default_body = b_source[current_if.start_byte : current_if.end_byte]
                break

            cond = current_if.child_by_field_name("condition")
            if not cond or cond.type != "parenthesized_expression":
                valid = False
                break
            bin_expr = cond.child(1)
            if not bin_expr or bin_expr.type != "binary_expression":
                valid = False
                break
            op = bin_expr.child_by_field_name("operator")
            if not op or b_source[op.start_byte : op.end_byte] != b"==":
                valid = False
                break
            left = bin_expr.child_by_field_name("left")
            right = bin_expr.child_by_field_name("right")
            if not left or left.type != "identifier":
                valid = False
                break

            var_name = b_source[left.start_byte : left.end_byte]
            val_text = b_source[right.start_byte : right.end_byte]

            if chain_var is None:
                chain_var = var_name
            elif chain_var != var_name:
                valid = False
                break

            consequence = current_if.child_by_field_name("consequence")
            cases.append((val_text, consequence))

            alt = current_if.child_by_field_name("alternative")
            if not alt:
                break

            next_stmt = alt.child(1)
            if not next_stmt:
                break
            current_if = next_stmt

        if valid and len(cases) >= 2 and chain_var:
            valid_chains.append((if_node, chain_var, cases, default_body))

    if not valid_chains:
        return None

    target_if, chain_var, cases, default_body = rng.choice(valid_chains)

    out = b"switch (" + chain_var + b") {\n"
    for val, body_node in cases:
        body_text = b_source[body_node.start_byte : body_node.end_byte]
        if body_node.type == "compound_statement":
            inner = body_text[1:-1].strip()
            out += b"    case " + val + b": {\n        " + inner + b"\n        break;\n    }\n"
        else:
            out += b"    case " + val + b":\n        " + body_text + b"\n        break;\n"

    if default_body:
        if default_body.startswith(b"{"):
            inner = default_body[1:-1].strip()
            out += b"    default: {\n        " + inner + b"\n        break;\n    }\n"
        else:
            out += b"    default:\n        " + default_body + b"\n        break;\n"

    out += b"}"

    end_byte = target_if.end_byte
    start = target_if.start_byte
    return (b_source[:start] + out + b_source[end_byte:]).decode("utf-8")


def mut_switch_add_explicit_default(s: str, rng: random.Random) -> str | None:
    """Add an explicit default case to a switch that lacks one."""
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_SWITCH_STMT)
    matches = cursor.matches(tree.root_node)

    valid_switches = []
    for match in matches:
        switch = _capture(match, "stmt")
        if isinstance(switch, list):
            switch = switch[0]
        if not switch:
            continue

        body = switch.child_by_field_name("body")
        if not body or body.type != "compound_statement":
            continue

        has_default = False
        cases = []
        for child in body.children:
            if child.type == "case_statement":
                # Check if this case is actually a default
                if any(c.type == "default" for c in child.children):
                    has_default = True
                    break
                else:
                    cases.append(child)

        if not has_default and cases:
            valid_switches.append(body)

    if not valid_switches:
        return None

    target_body = rng.choice(valid_switches)
    end_idx = target_body.end_byte - 1

    stmt = rng.choice([b"break;", b"return;"])
    injection = b"\n    default:\n        " + stmt + b"\n"

    return (b_source[:end_idx] + injection + b_source[end_idx:]).decode("utf-8")


def mut_wrap_in_else(s: str, rng: random.Random) -> str | None:
    """Wrap statements after an early-exit if into an else block."""
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_IF_STMT)
    matches = cursor.matches(tree.root_node)

    valid_ifs = []

    def contains_early_exit(node: ts.Node) -> bool:
        if node.type in (
            "return_statement",
            "goto_statement",
            "break_statement",
            "continue_statement",
        ):
            return True
        if node.type == "compound_statement":
            for child in node.children:
                if contains_early_exit(child):
                    return True
        return False

    for match in matches:
        if_stmt = _capture(match, "if_stmt")
        if isinstance(if_stmt, list):
            if_stmt = if_stmt[0]
        if not if_stmt:
            continue

        if if_stmt.child_by_field_name("alternative"):
            continue

        conseq = if_stmt.child_by_field_name("consequence")
        if not conseq:
            continue

        if not contains_early_exit(conseq):
            continue

        sibling = if_stmt.next_named_sibling
        if not sibling:
            continue

        valid_ifs.append((if_stmt, sibling))

    if not valid_ifs:
        return None

    target_if, target_sibling = rng.choice(valid_ifs)

    parent = target_if.parent
    if not parent or parent.type != "compound_statement":
        return None

    start_byte = target_if.end_byte
    last_child = parent.children[-2]
    end_byte = last_child.end_byte

    if start_byte >= end_byte:
        return None

    rest_of_block = b_source[start_byte:end_byte].strip()
    if not rest_of_block:
        return None

    replacement = b" else {\n    " + rest_of_block + b"\n}"

    return (b_source[:start_byte] + replacement + b_source[end_byte:]).decode("utf-8")


def mut_switch_break_to_return(s: str, rng: random.Random) -> str | None:
    """Replace switch break statements with the trailing return statement."""
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_SWITCH_STMT)
    matches = cursor.matches(tree.root_node)

    valid_targets = []

    for match in matches:
        switch = _capture(match, "stmt")
        if isinstance(switch, list):
            switch = switch[0]
        if not switch:
            continue

        sibling = switch.next_named_sibling
        if not sibling or sibling.type != "return_statement":
            continue

        ret_text = b_source[sibling.start_byte : sibling.end_byte]

        body = switch.child_by_field_name("body")
        if not body or body.type != "compound_statement":
            continue

        break_nodes: list[ts.Node] = []

        def find_breaks(n: ts.Node, bn: list[ts.Node]) -> None:
            if n.type == "break_statement":
                bn.append(n)
            elif n.type not in (
                "switch_statement",
                "while_statement",
                "for_statement",
                "do_statement",
            ):
                for c in n.children:
                    find_breaks(c, bn)

        find_breaks(body, break_nodes)

        if break_nodes:
            valid_targets.append((switch, ret_text, break_nodes, sibling))

    if not valid_targets:
        return None

    switch, ret_text, breaks, ret_node = rng.choice(valid_targets)

    out = b_source
    breaks.sort(key=lambda n: n.start_byte, reverse=True)

    for b_node in breaks:
        out = out[: b_node.start_byte] + ret_text + out[b_node.end_byte :]

    return out.decode("utf-8")
