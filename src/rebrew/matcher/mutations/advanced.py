"""advanced.py — advanced logical and manual-decomp mutation operators.

Phase 3 logical/evaluation rewrites, Phase 4 hand-written decomp insights, the
loop-break group, the if/else-call-to-ternary group, and the common-tail
hoist/sink pair.
"""

from __future__ import annotations

import random
import re

from rebrew.matcher.ast_engine import _C_LANGUAGE, parse_c_ast
from rebrew.matcher.mutations.queries import (
    _QUERY_BIN_COND_IF,
    _QUERY_LOCAL_DECL,
    _QUERY_NESTED_IF_P3,
    _QUERY_SINK_COMMON_TAIL,
    _QUERY_TERNARY_ARG_TO_IF_ELSE_CALL,
    _QUERY_WHILE_LOOP,
    _LazyQuery,
)
from rebrew.matcher.mutations.runtime import (
    _capture,
    _cursor,
    _find_function_body_insert_pos,
    _first_caps,
)

# --- Phase 3: Advanced Logical & Evaluation Mutations ---


def mut_split_and_condition(s: str, rng: random.Random) -> str | None:
    """Split an if(a && b) into nested if(a) { if(b) ... } blocks."""
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_BIN_COND_IF)
    matches = cursor.matches(tree.root_node)

    valid_ifs = []
    for match in matches:
        stmt = _capture(match, "stmt")
        if isinstance(stmt, list):
            stmt = stmt[0]
        if not stmt:
            continue

        # Must not have else clause for simple split
        if stmt.child_by_field_name("alternative"):
            continue

        bin_node = _capture(match, "bin")
        if isinstance(bin_node, list):
            bin_node = bin_node[0]

        left = _capture(match, "left")
        if isinstance(left, list):
            left = left[0]
        right = _capture(match, "right")
        if isinstance(right, list):
            right = right[0]

        if not left or not right:
            continue
        op_text = b_source[left.end_byte : right.start_byte].strip()
        if op_text != b"&&":
            continue

        body = _capture(match, "body")
        if isinstance(body, list):
            body = body[-1]

        valid_ifs.append((stmt, left, right, body))

    if not valid_ifs:
        return None

    stmt, left, right, body = rng.choice(valid_ifs)

    left_str = b_source[left.start_byte : left.end_byte]
    right_str = b_source[right.start_byte : right.end_byte]
    body_str = b_source[body.start_byte : body.end_byte]

    new_stmt = b"if (" + left_str + b") {\n        if (" + right_str + b") " + body_str + b"\n    }"

    return (b_source[: stmt.start_byte] + new_stmt + b_source[stmt.end_byte :]).decode("utf-8")


def mut_split_or_condition(s: str, rng: random.Random) -> str | None:
    """Split if(a || b) into separate if(a) ... else if(b) ... blocks."""
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_BIN_COND_IF)
    matches = cursor.matches(tree.root_node)

    valid_ifs = []
    for match in matches:
        stmt = _capture(match, "stmt")
        if isinstance(stmt, list):
            stmt = stmt[0]
        if not stmt:
            continue

        if stmt.child_by_field_name("alternative"):
            continue

        bin_node = _capture(match, "bin")
        if isinstance(bin_node, list):
            bin_node = bin_node[0]

        left = _capture(match, "left")
        if isinstance(left, list):
            left = left[0]
        right = _capture(match, "right")
        if isinstance(right, list):
            right = right[0]

        if not left or not right:
            continue
        op_text = b_source[left.end_byte : right.start_byte].strip()
        if op_text != b"||":
            continue

        body = _capture(match, "body")
        if isinstance(body, list):
            body = body[-1]

        valid_ifs.append((stmt, left, right, body))

    if not valid_ifs:
        return None

    stmt, left, right, body = rng.choice(valid_ifs)

    left_str = b_source[left.start_byte : left.end_byte]
    right_str = b_source[right.start_byte : right.end_byte]
    body_str = b_source[body.start_byte : body.end_byte]

    new_stmt = (
        b"if (" + left_str + b") " + body_str + b"\n    else if (" + right_str + b") " + body_str
    )

    return (b_source[: stmt.start_byte] + new_stmt + b_source[stmt.end_byte :]).decode("utf-8")


def mut_merge_nested_ifs(s: str, rng: random.Random) -> str | None:
    """Merge nested if(a) { if(b) } into a single if(a && b) condition."""
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_NESTED_IF_P3)
    matches = cursor.matches(tree.root_node)

    valid_ifs = []
    for match in matches:
        stmt = _capture(match, "stmt")
        if isinstance(stmt, list):
            stmt = stmt[0]
        if not stmt:
            continue

        if stmt.child_by_field_name("alternative"):
            continue

        inner_if = _capture(match, "inner_if")
        if isinstance(inner_if, list):
            inner_if = inner_if[-1]
        if inner_if.child_by_field_name("alternative"):
            continue

        cond1 = _capture(match, "cond1")
        if isinstance(cond1, list):
            cond1 = cond1[0]
        cond2 = _capture(match, "cond2")
        if isinstance(cond2, list):
            cond2 = cond2[0]

        body = _capture(match, "body")
        if isinstance(body, list):
            body = body[-1]

        outer_body = _capture(match, "outer_body")
        if isinstance(outer_body, list):
            outer_body = outer_body[0]

        # Ensure the outer_body only contains the inner_if statement
        block_nodes = [c for c in outer_body.children if c.type != "{" and c.type != "}"]
        if len(block_nodes) != 1:
            continue

        valid_ifs.append((stmt, cond1, cond2, body))

    if not valid_ifs:
        return None

    stmt, cond1, cond2, body = rng.choice(valid_ifs)

    # We want without the surrounding parens if we are going to wrap it
    cond1_str = b_source[cond1.start_byte + 1 : cond1.end_byte - 1]
    cond2_str = b_source[cond2.start_byte + 1 : cond2.end_byte - 1]
    body_str = b_source[body.start_byte : body.end_byte]

    new_stmt = b"if ((" + cond1_str + b") && (" + cond2_str + b")) " + body_str

    return (b_source[: stmt.start_byte] + new_stmt + b_source[stmt.end_byte :]).decode("utf-8")


def mut_extract_condition_to_var(s: str, rng: random.Random) -> str | None:
    """Hoist an if-condition into a temporary variable assignment."""
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_BIN_COND_IF)
    matches = cursor.matches(tree.root_node)

    valid_ifs = []
    for match in matches:
        stmt = _capture(match, "stmt")
        if isinstance(stmt, list):
            stmt = stmt[0]
        if not stmt:
            continue

        bin_node = _capture(match, "bin")
        if isinstance(bin_node, list):
            bin_node = bin_node[0]

        left = _capture(match, "left")
        if isinstance(left, list):
            left = left[0]
        right = _capture(match, "right")
        if isinstance(right, list):
            right = right[0]

        if not left or not right:
            continue
        op_text = b_source[left.end_byte : right.start_byte].strip()
        if op_text not in (b"==", b"!=", b"<", b">", b"<=", b">="):
            continue

        valid_ifs.append((stmt, bin_node))

    if not valid_ifs:
        return None

    stmt, bin_node = rng.choice(valid_ifs)
    cond_str = b_source[bin_node.start_byte : bin_node.end_byte]

    var_id = rng.randint(0, 999)
    var_name = f"_cond_{var_id}".encode()

    # C89: hoist declaration to function body top, keep assignment inline
    insert_pos = _find_function_body_insert_pos(b_source, stmt.start_byte)
    if insert_pos is None:
        return None

    hoisted_decl = b"\n    int " + var_name + b";"
    inline_assign = var_name + b" = (" + cond_str + b");\n    "

    # Insert hoisted declaration
    out = b_source[:insert_pos] + hoisted_decl + b_source[insert_pos:]
    offset = len(hoisted_decl)

    # Adjust byte positions for the insertion
    stmt_start = stmt.start_byte + offset
    stmt_end = stmt.end_byte + offset
    bin_start = bin_node.start_byte + offset
    bin_end = bin_node.end_byte + offset

    # Replace the binary expression with the variable
    new_stmt_str = out[stmt_start:bin_start] + var_name + out[bin_end:stmt_end]

    return (out[:stmt_start] + inline_assign + new_stmt_str + out[stmt_end:]).decode("utf-8")


def mut_loop_condition_extraction(s: str, rng: random.Random) -> str | None:
    """Rewrite while(cond) as while(1) { if(!cond) break; ... }."""
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_WHILE_LOOP)
    matches = cursor.matches(tree.root_node)

    valid_loops = []
    for match in matches:
        stmt = _capture(match, "stmt")
        if isinstance(stmt, list):
            stmt = stmt[0]
        if not stmt:
            continue

        cond = _capture(match, "cond")
        if isinstance(cond, list):
            cond = cond[0]

        body = _capture(match, "body")
        if isinstance(body, list):
            body = body[-1]

        valid_loops.append((stmt, cond, body))

    if not valid_loops:
        return None

    stmt, cond, body = rng.choice(valid_loops)

    cond_str = b_source[cond.start_byte + 1 : cond.end_byte - 1]

    if body.type == "compound_statement":
        inner_body = b_source[body.start_byte + 1 : body.end_byte - 1].strip()
        new_loop = (
            b"while (1) {\n        if (!("
            + cond_str
            + b")) break;\n        "
            + inner_body
            + b"\n    }"
        )
    else:
        body_str = b_source[body.start_byte : body.end_byte]
        new_loop = (
            b"while (1) {\n        if (!("
            + cond_str
            + b")) break;\n        "
            + body_str
            + b"\n    }"
        )

    return (b_source[: stmt.start_byte] + new_loop + b_source[stmt.end_byte :]).decode("utf-8")


# ---------------------------------------------------------------------------
# New MSVC6-targeted mutators (2026-03 GA improvements batch)
# ---------------------------------------------------------------------------


# Type widening/narrowing tables — MSVC6 generates different MOV widths
_TYPE_WIDEN_MAP: dict[bytes, bytes] = {
    b"short": b"int",
    b"int": b"short",
    b"BYTE": b"DWORD",
    b"DWORD": b"BYTE",
    b"WORD": b"DWORD",
}


def mut_widen_local_type(s: str, rng: random.Random) -> str | None:
    """Toggle local variable type width: short↔int, BYTE↔DWORD, WORD↔DWORD.

    MSVC6 generates different MOV sizes (MOVSX, MOVZX, MOV EAX vs MOV AL)
    depending on the declared type width.
    """
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_LOCAL_DECL)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid = []
    for match in matches:
        caps = match[1]
        type_node = _capture(caps, "type")
        if isinstance(type_node, list):
            type_node = type_node[0]
        if not type_node:
            continue
        type_text = b_source[type_node.start_byte : type_node.end_byte].strip()
        if type_text in _TYPE_WIDEN_MAP:
            valid.append((type_node, type_text))

    if not valid:
        return None

    node, old_type = rng.choice(valid)
    new_type = _TYPE_WIDEN_MAP[old_type]
    res = b_source[: node.start_byte] + new_type + b_source[node.end_byte :]
    result = res.decode("utf-8")
    return result if result != s else None


_DLLIMPORT_RE = re.compile(
    rb"__declspec\s*\(\s*dllimport\s*\)\s*",
)
_EXTERN_DECL_RE = re.compile(
    rb"^(extern\s+)((?:int|void|BOOL|DWORD|HANDLE|HRESULT|UINT|LRESULT|"
    rb"char|short|long|unsigned|FARPROC|LPVOID)\s+\w+\s*\()",
    re.MULTILINE,
)


def mut_toggle_dllimport(s: str, rng: random.Random) -> str | None:
    """Add or remove __declspec(dllimport) on extern function declarations.

    Changes IAT calling sequences: dllimport produces direct CALL [addr]
    to the IAT, while without it the linker inserts a thunk stub.
    """
    b_source = s.encode("utf-8")

    # Try to remove existing dllimport first
    dllimport_matches = list(_DLLIMPORT_RE.finditer(b_source))
    if dllimport_matches:
        m = rng.choice(dllimport_matches)
        res = b_source[: m.start()] + b_source[m.end() :]
        result = res.decode("utf-8")
        return result if result != s else None

    # Try to add dllimport to an extern declaration
    extern_matches = list(_EXTERN_DECL_RE.finditer(b_source))
    if extern_matches:
        m = rng.choice(extern_matches)
        res = (
            b_source[: m.start(1)]
            + m.group(1)
            + b"__declspec(dllimport) "
            + m.group(2)
            + b_source[m.end(2) :]
        )
        result = res.decode("utf-8")
        return result if result != s else None

    return None


_MEMCPY_RE = re.compile(
    rb"memcpy\s*\(\s*([^,]+),\s*([^,]+),\s*(\d+)\s*\)\s*;",
)


def mut_memcpy_to_loop(s: str, rng: random.Random) -> str | None:
    """Convert memcpy(dst, src, N) to an explicit byte-copy loop.

    MSVC6 inlines memcpy() to REP MOVSD/MOVSB while explicit loops
    generate different codegen (typically LEA + indexed MOV).
    """
    b_source = s.encode("utf-8")
    matches = list(_MEMCPY_RE.finditer(b_source))
    if not matches:
        return None

    m = rng.choice(matches)
    dst = m.group(1).strip()
    src = m.group(2).strip()
    n = m.group(3).strip()
    idx = rng.randint(0, 999)
    var = f"_ci_{idx}".encode()

    # C89-safe: we need the loop var declared at function top
    insert_pos = _find_function_body_insert_pos(b_source, m.start())
    if insert_pos is None:
        return None

    hoisted_decl = b"\n    int " + var + b";"
    loop = (
        b"for ("
        + var
        + b" = 0; "
        + var
        + b" < "
        + n
        + b"; "
        + var
        + b"++) ((char*)"
        + dst
        + b")["
        + var
        + b"] = ((char*)"
        + src
        + b")["
        + var
        + b"];"
    )

    # Insert hoisted decl
    out = b_source[:insert_pos] + hoisted_decl + b_source[insert_pos:]
    offset = len(hoisted_decl)

    # Replace memcpy call
    res = out[: m.start() + offset] + loop + out[m.end() + offset :]
    return res.decode("utf-8")


_BYTE_COPY_LOOP_RE = re.compile(
    rb"for\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*<\s*(\d+)\s*;\s*\1\s*\+\+\s*\)"
    rb"\s*\(\(char\s*\*\)\s*(\w+)\)\s*\[\s*\1\s*\]\s*=\s*\(\(char\s*\*\)\s*(\w+)\)\s*\[\s*\1\s*\]\s*;",
)


def mut_loop_to_memcpy(s: str, rng: random.Random) -> str | None:
    """Convert explicit byte-copy loop to memcpy().

    Inverse of mut_memcpy_to_loop.  memcpy() inlines to REP MOVS
    on MSVC6, which uses different register allocation.
    """
    b_source = s.encode("utf-8")
    matches = list(_BYTE_COPY_LOOP_RE.finditer(b_source))
    if not matches:
        return None

    m = rng.choice(matches)
    dst = m.group(3)
    src = m.group(4)
    n = m.group(2)
    replacement = b"memcpy(" + dst + b", " + src + b", " + n + b");"
    res = b_source[: m.start()] + replacement + b_source[m.end() :]
    return res.decode("utf-8")


_QUERY_FLOAT_BINOP = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        operator: _ @op
        right: (_) @right) @expr
""",
)

# Float-context hints: variable/function names or types
_FLOAT_HINTS = re.compile(
    rb"(?:float|double|FLOAT|DOUBLE|flt|dbl|_f_|_d_|"
    rb"sin|cos|tan|sqrt|pow|fabs|ceil|floor|log|exp|atan)",
    re.IGNORECASE,
)


def mut_commute_float_operands(s: str, rng: random.Random) -> str | None:
    """Swap operands in float multiplication/addition.

    Changes FPU load order: fld a; fmul b  vs  fld b; fmul a.
    Identical math, different bytes.  Only targets expressions that
    look like they involve floating-point variables.
    """
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_FLOAT_BINOP)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid = []
    for match in matches:
        caps = match[1]
        op_node = _capture(caps, "op")
        if isinstance(op_node, list):
            op_node = op_node[0]
        if not op_node:
            continue
        op_text = b_source[op_node.start_byte : op_node.end_byte]
        if op_text not in (b"*", b"+"):
            continue

        left = _capture(caps, "left")
        right = _capture(caps, "right")
        if isinstance(left, list):
            left = left[0]
        if isinstance(right, list):
            right = right[0]
        if not left or not right:
            continue

        left_text = b_source[left.start_byte : left.end_byte]
        right_text = b_source[right.start_byte : right.end_byte]

        # Only swap if it looks float-related
        context = b_source[max(0, left.start_byte - 30) : right.end_byte + 30]
        if not _FLOAT_HINTS.search(context):
            continue

        # Don't swap if already identical
        if left_text == right_text:
            continue

        valid.append((left, right))

    if not valid:
        return None

    left, right = rng.choice(valid)
    left_text = b_source[left.start_byte : left.end_byte]
    right_text = b_source[right.start_byte : right.end_byte]

    # Swap left and right operands
    res = (
        b_source[: left.start_byte]
        + right_text
        + b_source[left.end_byte : right.start_byte]
        + left_text
        + b_source[right.end_byte :]
    )
    result = res.decode("utf-8")
    return result if result != s else None


# --- Phase 4: Manual decomp insight mutations ---


_QUERY_FUNC_PARAM = _LazyQuery(
    _C_LANGUAGE,
    """
    (function_definition
        declarator: (function_declarator
            parameters: (parameter_list
                (parameter_declaration) @param)))
""",
)


def mut_register_param(s: str, rng: random.Random) -> str | None:
    """Add 'register' keyword to a function parameter declaration.

    MSVC6 treats register-qualified parameters differently from locals:
    forces the parameter into a callee-saved register (ESI/EDI) and can
    suppress ``push ebp`` frame setup entirely.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_FUNC_PARAM)
    matches = cursor.matches(tree.root_node)

    # Collect params that don't already have 'register'
    valid = []
    for match in matches:
        caps = _first_caps(match[1])
        param = caps["param"]
        text = b_source[param.start_byte : param.end_byte]
        if b"register" not in text and b"..." not in text:
            valid.append(param)

    if not valid:
        return None

    param = rng.choice(valid)
    text = b_source[param.start_byte : param.end_byte]
    result = b_source[: param.start_byte] + b"register " + text + b_source[param.end_byte :]
    return result.decode("utf-8")


def mut_unregister_param(s: str, rng: random.Random) -> str | None:
    """Remove 'register' keyword from a function parameter declaration."""
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_FUNC_PARAM)
    matches = cursor.matches(tree.root_node)

    valid = []
    for match in matches:
        caps = _first_caps(match[1])
        param = caps["param"]
        text = b_source[param.start_byte : param.end_byte]
        if b"register " in text:
            valid.append(param)

    if not valid:
        return None

    param = rng.choice(valid)
    text = b_source[param.start_byte : param.end_byte]
    new_text = text.replace(b"register ", b"", 1)
    result = b_source[: param.start_byte] + new_text + b_source[param.end_byte :]
    return result.decode("utf-8")


# --- Loop break mutations ---


_QUERY_BREAK_IN_LOOP = _LazyQuery(
    _C_LANGUAGE,
    """
    [
        (while_statement body: (compound_statement (break_statement) @brk))
        (do_statement body: (compound_statement (break_statement) @brk))
        (for_statement body: (compound_statement (break_statement) @brk))
    ]
""",
)

_QUERY_LOOP_BODY = _LazyQuery(
    _C_LANGUAGE,
    """
    [
        (while_statement body: (compound_statement) @body)
        (do_statement body: (compound_statement) @body)
        (for_statement body: (compound_statement) @body)
    ]
""",
)


def mut_remove_loop_break(s: str, rng: random.Random) -> str | None:
    """Remove a break statement from a loop body.

    MSVC6 generates different branch layouts for loops with explicit
    break vs fall-through behavior.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_BREAK_IN_LOOP)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])
    brk = caps["brk"]

    # Remove the break statement and any trailing whitespace/newline
    end = brk.end_byte
    while end < len(b_source) and b_source[end : end + 1] in (b" ", b"\t", b"\n", b"\r"):
        end += 1

    result = b_source[: brk.start_byte] + b_source[end:]
    res = result.decode("utf-8")
    return res if res != s else None


def mut_add_loop_break(s: str, rng: random.Random) -> str | None:
    """Add a break statement at the end of a loop body.

    Inserts ``break;`` as the last statement inside a loop's compound body.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_LOOP_BODY)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])
    body = caps["body"]

    # Don't add if there's already a break as the last statement
    children = [c for c in body.children if c.type not in ("{", "}")]
    if children and children[-1].type == "break_statement":
        return None

    # Insert before the closing brace
    close_brace = body.end_byte - 1
    indent = b"\n    "
    result = b_source[:close_brace] + indent + b"break;" + indent[:-4] + b_source[close_brace:]
    return result.decode("utf-8")


# --- If/else call to ternary arg ---


_QUERY_IF_ELSE_CALL = _LazyQuery(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond
        consequence: [
            (expression_statement (call_expression function: (_) @fn1 arguments: (argument_list) @args1))
            (compound_statement (expression_statement (call_expression function: (_) @fn1 arguments: (argument_list) @args1)))
        ]
        alternative: (else_clause [
            (expression_statement (call_expression function: (_) @fn2 arguments: (argument_list) @args2))
            (compound_statement (expression_statement (call_expression function: (_) @fn2 arguments: (argument_list) @args2)))
        ])
    ) @expr
""",
)


def mut_if_else_call_to_ternary_arg(s: str, rng: random.Random) -> str | None:
    """Collapse if/else with same function call differing by one arg into ternary.

    Changes: if (c) { Fn(a, X); } else { Fn(a, Y); }
         ->  Fn(a, c ? X : Y);

    Reduces AST use-count, which can change MSVC6 register allocation.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_IF_ELSE_CALL)
    matches = cursor.matches(tree.root_node)

    valid = []
    for match in matches:
        caps = _first_caps(match[1])
        fn1 = b_source[caps["fn1"].start_byte : caps["fn1"].end_byte]
        fn2 = b_source[caps["fn2"].start_byte : caps["fn2"].end_byte]
        if fn1 != fn2:
            continue

        # Get arg lists — check they have equal count and differ in exactly one position
        args1_node = caps["args1"]
        args2_node = caps["args2"]
        a1_children = [c for c in args1_node.children if c.type not in ("(", ")", ",")]
        a2_children = [c for c in args2_node.children if c.type not in ("(", ")", ",")]
        if len(a1_children) != len(a2_children) or len(a1_children) == 0:
            continue

        diff_indices = []
        for i, (c1, c2) in enumerate(zip(a1_children, a2_children, strict=True)):
            t1 = b_source[c1.start_byte : c1.end_byte]
            t2 = b_source[c2.start_byte : c2.end_byte]
            if t1 != t2:
                diff_indices.append(i)

        if len(diff_indices) != 1:
            continue

        valid.append((caps, a1_children, a2_children, diff_indices[0], fn1))

    if not valid:
        return None

    caps, a1_children, a2_children, diff_idx, fn_name = rng.choice(valid)
    cond = b_source[caps["cond"].start_byte : caps["cond"].end_byte]

    # Build the merged arg list: same args + ternary at the differing position
    merged_args = []
    for i, c1 in enumerate(a1_children):
        if i == diff_idx:
            true_val = b_source[c1.start_byte : c1.end_byte]
            false_val = b_source[a2_children[i].start_byte : a2_children[i].end_byte]
            merged_args.append(cond + b" ? " + true_val + b" : " + false_val)
        else:
            merged_args.append(b_source[c1.start_byte : c1.end_byte])

    replacement = fn_name + b"(" + b", ".join(merged_args) + b");"
    result = b_source[: caps["expr"].start_byte] + replacement + b_source[caps["expr"].end_byte :]
    return result.decode("utf-8")


def mut_ternary_arg_to_if_else_call(s: str, rng: random.Random) -> str | None:
    """Split a function call with a ternary argument into if/else calls.

    Changes: Fn(a, c ? X : Y);
         ->  if (c) { Fn(a, X); } else { Fn(a, Y); }
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    # Find call expressions that have a conditional_expression in their argument list
    q = _QUERY_TERNARY_ARG_TO_IF_ELSE_CALL
    cursor = _cursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])

    fn = b_source[caps["fn"].start_byte : caps["fn"].end_byte]
    cond = b_source[caps["cond"].start_byte : caps["cond"].end_byte]
    val_true = b_source[caps["val_true"].start_byte : caps["val_true"].end_byte]
    val_false = b_source[caps["val_false"].start_byte : caps["val_false"].end_byte]
    ternary_node = caps["ternary"]
    call_node = caps["call"]

    # Rebuild the arg list with the true value and the false value
    args_node = call_node.child_by_field_name("arguments")
    if not args_node:
        return None

    arg_children = [c for c in args_node.children if c.type not in ("(", ")", ",")]

    # Build if-branch args and else-branch args
    if_args = []
    else_args = []
    for c in arg_children:
        if c.id == ternary_node.id:
            if_args.append(val_true)
            else_args.append(val_false)
        else:
            arg_text = b_source[c.start_byte : c.end_byte]
            if_args.append(arg_text)
            else_args.append(arg_text)

    if_call = fn + b"(" + b", ".join(if_args) + b");"
    else_call = fn + b"(" + b", ".join(else_args) + b");"

    replacement = (
        b"if ("
        + cond
        + b") {\n        "
        + if_call
        + b"\n    } else {\n        "
        + else_call
        + b"\n    }"
    )

    stmt = caps["stmt"]
    result = b_source[: stmt.start_byte] + replacement + b_source[stmt.end_byte :]
    return result.decode("utf-8")


# --- Hoist/sink common tail from if/else branches ---


_QUERY_IF_ELSE_COMPOUND = _LazyQuery(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond
        consequence: (compound_statement) @if_body
        alternative: (else_clause
            (compound_statement) @else_body)
    ) @stmt
""",
)


def mut_hoist_common_tail(s: str, rng: random.Random) -> str | None:
    """Hoist the last identical statement from both if/else branches.

    When both branches end with the same statement (byte-equal), removes
    it from both and places it after the if/else.  This lets the compiler
    merge return paths.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_IF_ELSE_COMPOUND)
    matches = cursor.matches(tree.root_node)

    valid = []
    for match in matches:
        caps = _first_caps(match[1])
        if_body = caps["if_body"]
        else_body = caps["else_body"]

        # Get actual statement children (skip braces)
        if_stmts = [c for c in if_body.children if c.type not in ("{", "}")]
        else_stmts = [c for c in else_body.children if c.type not in ("{", "}")]
        if not if_stmts or not else_stmts:
            continue

        last_if = if_stmts[-1]
        last_else = else_stmts[-1]
        t_if = b_source[last_if.start_byte : last_if.end_byte]
        t_else = b_source[last_else.start_byte : last_else.end_byte]

        if t_if == t_else:
            valid.append((caps, last_if, last_else, t_if))

    if not valid:
        return None

    caps, last_if, last_else, common_text = rng.choice(valid)
    stmt = caps["stmt"]
    if_body = caps["if_body"]
    else_body = caps["else_body"]

    # Remove last statement from else branch first (higher offsets first)
    result = b_source[:]
    # Calculate what the if/else looks like after removing the tails
    # Work from the end of the source backwards to keep offsets valid

    # Remove from else branch (comes after if branch in source)
    # Find whitespace before the statement to remove cleanly
    else_rm_start = last_else.start_byte
    while else_rm_start > else_body.start_byte and b_source[else_rm_start - 1 : else_rm_start] in (
        b" ",
        b"\t",
        b"\n",
        b"\r",
    ):
        else_rm_start -= 1
    result = result[:else_rm_start] + result[last_else.end_byte :]

    # Offset adjustments for the removal
    else_removed = last_else.end_byte - else_rm_start

    # Remove from if branch (adjust offset for previous removal if else comes after)
    if_rm_start = last_if.start_byte
    while if_rm_start > if_body.start_byte and result[if_rm_start - 1 : if_rm_start] in (
        b" ",
        b"\t",
        b"\n",
        b"\r",
    ):
        if_rm_start -= 1

    # If the if branch is before the else branch in source (always), no adjustment needed for if removal
    # But we already removed from else, so if if_rm_start < else_rm_start, the if region is untouched
    if if_rm_start < else_rm_start:
        result = result[:if_rm_start] + result[last_if.end_byte :]
        # The stmt end also shifts
        adj_stmt_end = stmt.end_byte - else_removed - (last_if.end_byte - if_rm_start)
    else:
        # If branch is after else (unusual), offset was already shifted
        adjusted_start = if_rm_start - else_removed
        adjusted_end = last_if.end_byte - else_removed
        result = result[:adjusted_start] + result[adjusted_end:]
        adj_stmt_end = stmt.end_byte - else_removed - (adjusted_end - adjusted_start)

    # Insert the common statement after the if/else
    result = result[:adj_stmt_end] + b"\n    " + common_text + result[adj_stmt_end:]
    return result.decode("utf-8")


def mut_sink_common_tail(s: str, rng: random.Random) -> str | None:
    """Sink a post-if/else statement into both branches as the last statement.

    Takes a statement immediately following an if/else and duplicates it
    as the last statement in both branches.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    # Find if/else followed by a sibling statement
    q = _QUERY_SINK_COMMON_TAIL
    cursor = _cursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])
    if_body = caps["if_body"]
    else_body = caps["else_body"]
    next_stmt = caps["next_stmt"]

    stmt_text = b_source[next_stmt.start_byte : next_stmt.end_byte]

    # Insert into if branch (before closing brace)
    if_close = if_body.end_byte - 1
    result = b_source[:if_close] + b"    " + stmt_text + b"\n    " + b_source[if_close:]

    # Offset for the insertion
    inserted_len = 4 + len(stmt_text) + 5  # "    " + text + "\n    "

    # Insert into else branch (before closing brace, adjusted for previous insert)
    else_close = else_body.end_byte - 1 + inserted_len
    result = result[:else_close] + b"    " + stmt_text + b"\n    " + result[else_close:]

    # Remove the original next_stmt (adjusted for both insertions)
    total_inserted = inserted_len * 2
    orig_start = next_stmt.start_byte + total_inserted
    orig_end = next_stmt.end_byte + total_inserted
    # Remove leading whitespace too
    rm_start = orig_start
    while rm_start > 0 and result[rm_start - 1 : rm_start] in (b" ", b"\t", b"\n", b"\r"):
        rm_start -= 1
    result = result[:rm_start] + result[orig_end:]

    return result.decode("utf-8")
