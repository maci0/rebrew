"""basic.py — the core mutation operators.

The general-purpose C mutation set (Phase 1/2): operator/operand swaps,
comparison rewrites, declaration and statement reordering, loop/branch
reshaping, and expression-level rewrites.
"""

from __future__ import annotations

import random
import re
from typing import Any

import tree_sitter as ts

from rebrew.matcher.ast_engine import parse_c_ast, replace_node
from rebrew.matcher.mutations.queries import (
    _QUERY_ACCUM,
    _QUERY_ADJACENT_DECL,
    _QUERY_ADJACENT_EXPR_STMTS,
    _QUERY_ARRAY_INDEX,
    _QUERY_ASSIGN_ZERO,
    _QUERY_BARE_CHAR_TYPE,
    _QUERY_BITAND,
    _QUERY_CALL_ASSIGN,
    _QUERY_CALL_CONV,
    _QUERY_CMP_BOUNDARY,
    _QUERY_COMBINE_PTR_ARITH,
    _QUERY_COMPOUND_ASSIGN,
    _QUERY_CONST_ADD_FOLD,
    _QUERY_CONST_ADD_UNFOLD,
    _QUERY_DECLARATION,
    _QUERY_DEMORGAN_NOT_AND,
    _QUERY_DEMORGAN_NOT_OR,
    _QUERY_DO_WHILE,
    _QUERY_DOUBLE_NOT,
    _QUERY_EARLY_RETURN,
    _QUERY_ELSE_IF,
    _QUERY_EQ_ZERO,
    _QUERY_EXPANDED_COMPOUND,
    _QUERY_FLIP_LT_GE,
    _QUERY_FOR_COUNT_UP,
    _QUERY_FOR_LOOP,
    _QUERY_GOTO_RET_FALSE,
    _QUERY_HOIST_RETURN,
    _QUERY_IDENTIFIER,
    _QUERY_IF_ASSIGN_ELSE,
    _QUERY_IF_BODY_RETURN,
    _QUERY_IF_ELSE,
    _QUERY_IF_FALSE_BITAND,
    _QUERY_INSERT_NOOP_BLOCK,
    _QUERY_INT_PARAM,
    _QUERY_INTRODUCE_LOCAL_ALIAS,
    _QUERY_MERGE_DECL,
    _QUERY_NEGATE_CONDITION,
    _QUERY_NO_CALL_CONV,
    _QUERY_NUMBER_LITERAL,
    _QUERY_PARAM_ORDER,
    _QUERY_POST_DECREMENT,
    _QUERY_POST_INCREMENT,
    _QUERY_PTR_ARROW,
    _QUERY_PTR_PARAM,
    _QUERY_REASSOCIATE,
    _QUERY_REMOVE_CAST,
    _QUERY_REORDER_DECLARATIONS,
    _QUERY_RETURN_FALSE,
    _QUERY_RETURN_TYPE,
    _QUERY_RHS_IDENT,
    _QUERY_SIZED_CHAR_TYPE,
    _QUERY_SPLIT_DECL,
    _QUERY_SPLIT_PTR_ARITH,
    _QUERY_SWAP_AND,
    _QUERY_SWAP_EQ,
    _QUERY_SWAP_NE,
    _QUERY_SWAP_OR,
    _QUERY_TEMP_VAR,
    _QUERY_TERNARY,
    _QUERY_VOLATILE_ACCESS,
    _QUERY_WHILE,
    _QUERY_XOR_SELF,
    _LazyQuery,
)
from rebrew.matcher.mutations.runtime import (
    _RE_FUNC_PRAGMA,
    _RE_GUARD_CLAUSE,
    _RE_RET_FALSE_LABEL,
    _RE_RET_FALSE_LABEL_NL,
    _RE_SINK_RETURN,
    _apply_query_once,
    _capture,
    _commute_operands,
    _cursor,
    _find_function_body_insert_pos,
    _first_caps,
    brace_block,
)

# --- Mutations ---


def mut_flip_eq_zero(s: str, rng: random.Random) -> str | None:
    """Rewrite x == 0 / x != 0 into boolean-not forms."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        op = b_source[captures["op"].start_byte : captures["op"].end_byte]

        if op == b"==":
            return b"!" + left
        else:
            return b"!!" + left

    res = _apply_query_once(b_source, _QUERY_EQ_ZERO, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_flip_lt_ge(s: str, rng: random.Random) -> str | None:
    """Rewrite ``a < b`` into the equivalent negated ``!(a >= b)`` form."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        return b"!(" + left + b" >= " + right + b")"

    res = _apply_query_once(b_source, _QUERY_FLIP_LT_GE, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_add_redundant_parens(s: str, rng: random.Random) -> str | None:
    """Wrap a random identifier in redundant parentheses.

    AST makes this safe vs wrapping keywords like 'return'.  The declared name
    of a function definition is skipped: wrapping it (`int (f)(int x) { ... }`)
    is legal C, but `quick_validate`'s cheap function-start gate rejects it, so
    the mutant could never reach the compiler.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    q = _QUERY_IDENTIFIER
    cursor = _cursor(q._get() if isinstance(q, _LazyQuery) else q)
    candidates: list[ts.Node] = []
    for _pattern_index, captures in cursor.matches(tree.root_node):
        node = _capture(_first_caps(captures), "expr")
        if node is None or node.parent is None:
            continue
        if node.parent.type == "function_declarator":
            continue
        candidates.append(node)
    if not candidates:
        return None
    node = rng.choice(candidates)
    return replace_node(
        b_source, node, b"(" + b_source[node.start_byte : node.end_byte] + b")"
    ).decode("utf-8")


def mut_swap_eq_operands(s: str, rng: random.Random) -> str | None:
    """Swap A == b to b == a."""
    return _commute_operands(s, rng, _QUERY_SWAP_EQ, b"==")


def mut_swap_ne_operands(s: str, rng: random.Random) -> str | None:
    """Swap A != b to b != a."""
    return _commute_operands(s, rng, _QUERY_SWAP_NE, b"!=")


def mut_reassociate_add(s: str, rng: random.Random) -> str | None:
    """Reassociate ``(a + b) + c`` into ``a + (b + c)``."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        a = b_source[captures["a"].start_byte : captures["a"].end_byte]
        b = b_source[captures["b"].start_byte : captures["b"].end_byte]
        c = b_source[captures["c"].start_byte : captures["c"].end_byte]
        return a + b" + (" + b + b" + " + c + b")"

    res = _apply_query_once(b_source, _QUERY_REASSOCIATE, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_swap_or_operands(s: str, rng: random.Random) -> str | None:
    """Swap A || b to b || a (changes short-circuit order, affects codegen)."""
    return _commute_operands(s, rng, _QUERY_SWAP_OR, b"||")


def mut_swap_and_operands(s: str, rng: random.Random) -> str | None:
    """Swap A && b to b && a."""
    return _commute_operands(s, rng, _QUERY_SWAP_AND, b"&&")


def mut_toggle_bool_not(s: str, rng: random.Random) -> str | None:
    """Remove one ``!!identifier`` sequence."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        ident = b_source[captures["ident"].start_byte : captures["ident"].end_byte]
        return ident

    res = _apply_query_once(b_source, _QUERY_DOUBLE_NOT, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_return_to_goto(s: str, rng: random.Random) -> str | None:
    """Replace 'return FALSE;' or 'return 0;' with 'goto ret_false;' and add label."""
    if "ret_false:" in s:
        return None  # already has the label

    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(
        _QUERY_RETURN_FALSE._get()
        if isinstance(_QUERY_RETURN_FALSE, _LazyQuery)
        else _QUERY_RETURN_FALSE
    )
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])
    ret_node = caps["expr"]

    goto_pos = ret_node.start_byte
    result = b_source[:goto_pos] + b"goto ret_false;" + b_source[ret_node.end_byte :]

    # Anchor the label to a FALSE-returning statement AFTER the goto.  A
    # raw-text regex can match inside string literals/comments (leaving the
    # goto referencing a label that does not exist — compile error) or land
    # before an arbitrary later `return 1;` (wrong value on the error path).
    label_pos = None
    tree2 = parse_c_ast(result)
    cursor2 = _cursor(
        _QUERY_RETURN_FALSE._get()
        if isinstance(_QUERY_RETURN_FALSE, _LazyQuery)
        else _QUERY_RETURN_FALSE
    )
    for m2 in cursor2.matches(tree2.root_node):
        caps2 = _first_caps(m2[1])
        node = caps2["expr"]
        if node.start_byte > goto_pos:
            label_pos = node.start_byte
            break

    if label_pos is not None:
        result = result[:label_pos] + b"ret_false:\n" + result[label_pos:]
    else:
        # Fallback: append before the enclosing function's closing brace —
        # C labels are function-scoped, so a bare rfind("}") could land in a
        # sibling function.
        fn = tree2.root_node.descendant_for_byte_range(goto_pos, goto_pos)
        while fn is not None and fn.type != "function_definition":
            fn = fn.parent
        if fn is None:
            return None
        body = fn.child_by_field_name("body")
        if body is None:
            return None
        brace_pos = body.end_byte - 1
        result = result[:brace_pos] + b"ret_false:\n    return 0;\n" + result[brace_pos:]

    return result.decode("utf-8")


def mut_goto_to_return(s: str, rng: random.Random) -> str | None:
    """Reverse: replace 'goto ret_false;' with 'return 0;'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        return b"return 0;"

    res = _apply_query_once(b_source, _QUERY_GOTO_RET_FALSE, _repl, rng)
    if not res:
        return None

    result = res.decode("utf-8")

    # Remove the label if no more gotos reference it
    if "goto ret_false" not in result:
        result = _RE_RET_FALSE_LABEL_NL.sub("", result)
        result = _RE_RET_FALSE_LABEL.sub("", result)

    return result


def mut_swap_if_else(s: str, rng: random.Random) -> str | None:
    """Swap if/else bodies and negate the condition."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        cond_node = captures["cond"]
        cons_node = captures["cons"]
        alt_node = captures["alt"]  # this is the statement inside `else_clause`

        cond = b_source[cond_node.start_byte : cond_node.end_byte]
        cons = b_source[cons_node.start_byte : cons_node.end_byte]
        alt = b_source[alt_node.start_byte : alt_node.end_byte]

        # Strip outer parens from cond if present to negate safely
        cond_inner = cond[1:-1] if cond.startswith(b"(") and cond.endswith(b")") else cond

        # Simple negation - in real scenarios, prefer mut_flip_lt_ge and others
        negated_cond = b"!(" + cond_inner + b")"

        # Brace both arms: a bare `else if` without its own trailing else
        # would re-bind the final else to the inner if (dangling else),
        # flipping branch outcomes.
        return b"if (" + negated_cond + b") " + brace_block(alt) + b" else " + brace_block(cons)

    res = _apply_query_once(b_source, _QUERY_IF_ELSE, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_add_cast(s: str, rng: random.Random) -> str | None:
    """Wrap an expression in (int) or (unsigned int) cast."""
    b_source = s.encode("utf-8")
    casts = [b"(int)", b"(unsigned int)"]
    cast = rng.choice(casts)

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        ident_node = captures["expr"]
        ident = b_source[ident_node.start_byte : ident_node.end_byte]

        # Don't cast type keywords. Even though tree-sitter distinguishes
        # identifiers from keywords, it's safer to have a small blocklist.
        if ident in (
            b"BOOL",
            b"int",
            b"DWORD",
            b"HANDLE",
            b"LPVOID",
            b"void",
            b"return",
            b"if",
            b"else",
            b"while",
            b"for",
            b"goto",
            b"volatile",
        ):
            return ident

        return cast + ident

    res = _apply_query_once(b_source, _QUERY_RHS_IDENT, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None


def mut_remove_cast(s: str, rng: random.Random) -> str | None:
    """Remove a (TYPE) cast."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        val = b_source[captures["val"].start_byte : captures["val"].end_byte]
        return val

    res = _apply_query_once(b_source, _QUERY_REMOVE_CAST, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_toggle_volatile(s: str, rng: random.Random) -> str | None:
    """Add or remove 'volatile' on a local variable declaration."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        decl = b_source[captures["expr"].start_byte : captures["expr"].end_byte]

        # Try removing volatile first
        if b"volatile " in decl and rng.random() < 0.5:
            return decl.replace(b"volatile ", b"")

        # Try adding volatile
        if b"volatile" not in decl:
            # simple trick: inject after the type
            # but we can just prepend it
            return b"volatile " + decl

        return decl

    res = _apply_query_once(b_source, _QUERY_DECLARATION, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None


def mut_volatile_access(s: str, rng: random.Random) -> str | None:
    """Add or remove ``volatile`` on a pointer-cast dereference.

    Declaration-level ``volatile`` (:func:`mut_toggle_volatile`) qualifies
    every access to the variable; MSVC6 keys the memory-operand fold and the
    store ordering off the qualifier on the *access*, so a qualified lvalue is
    a lever of its own.  ``*(float*)p = x;`` becomes ``*(volatile float*)p =
    x;`` (the store stops sinking past the computation producing ``x``), and a
    load cast gains or loses the same qualifier.

    Only an existing cast is requalified, so no pointee type has to be
    invented.
    """
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        ty = b_source[captures["ty"].start_byte : captures["ty"].end_byte]
        expr = b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        if b"volatile" in ty:
            return expr.replace(b"volatile ", b"", 1)
        return expr.replace(ty, b"volatile " + ty, 1)

    res = _apply_query_once(b_source, _QUERY_VOLATILE_ACCESS, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None


def mut_add_register_keyword(s: str, rng: random.Random) -> str | None:
    """Add 'register' keyword to a local variable declaration."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        decl = b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        if b"register" not in decl:
            return b"register " + decl
        return decl

    res = _apply_query_once(b_source, _QUERY_DECLARATION, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None


def mut_remove_register_keyword(s: str, rng: random.Random) -> str | None:
    """Remove 'register' keyword from a local variable declaration."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        decl = b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        if b"register " in decl:
            return decl.replace(b"register ", b"")
        return decl

    res = _apply_query_once(b_source, _QUERY_DECLARATION, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None


def mut_if_false_to_bitand(s: str, rng: random.Random) -> str | None:
    """Convert 'if (!expr) var = FALSE;' to 'var &= expr;'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        cond = b_source[captures["cond"].start_byte : captures["cond"].end_byte]
        var = b_source[captures["var"].start_byte : captures["var"].end_byte]

        return var + b" &= " + cond + b";"

    res = _apply_query_once(b_source, _QUERY_IF_FALSE_BITAND, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_reorder_elseif(s: str, rng: random.Random) -> str | None:
    """Swap two branches in an else-if chain.

    ``if (a) A else if (b) B else C`` → ``if (b && !(a)) B else if (a) A else C``.
    The second branch must be guarded with ``!(a)`` (a plain swap runs B when
    both hold, changing the result) and any trailing ``else`` must be
    preserved (a bare swap silently dropped it).
    """
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        cond1 = b_source[captures["cond1"].start_byte : captures["cond1"].end_byte]
        cons1 = b_source[captures["cons1"].start_byte : captures["cons1"].end_byte]
        cond2 = b_source[captures["cond2"].start_byte : captures["cond2"].end_byte]
        cons2 = b_source[captures["cons2"].start_byte : captures["cons2"].end_byte]

        replacement = (
            b"if ("
            + cond2[1:-1]
            + b" && !"
            + cond1
            + b") "
            + cons2
            + b" else if "
            + cond1
            + b" "
            + cons1
        )
        tail = captures.get("tail")
        if tail is not None:
            tail_text = b_source[tail.start_byte : tail.end_byte]
            replacement += b" else " + tail_text
        return replacement

    res = _apply_query_once(b_source, _QUERY_ELSE_IF, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_bitand_to_if_false(s: str, rng: random.Random) -> str | None:
    """Reverse of mut_if_false_to_bitand: convert 'var &= expr;' to 'if (!expr) var = 0;'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        var = b_source[captures["var"].start_byte : captures["var"].end_byte]
        expr = b_source[captures["expr"].start_byte : captures["expr"].end_byte]

        return b"if (!(" + expr + b"))\n            " + var + b" = 0;"

    res = _apply_query_once(b_source, _QUERY_BITAND, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_introduce_temp_for_call(s: str, rng: random.Random) -> str | None:
    """Introduce a temp variable for a function call result.

    C89-safe: hoists 'BOOL tmp;' to the top of the function body.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_CALL_ASSIGN)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    _, captures = rng.choice(matches)
    single_captures = _first_caps(captures)

    target_node = _capture(single_captures, "expr")
    if not target_node:
        return None

    var = b_source[single_captures["var"].start_byte : single_captures["var"].end_byte]
    call = b_source[single_captures["call"].start_byte : single_captures["call"].end_byte]

    # Inline replacement: tmp = call(); var = tmp;
    inline_repl = b"tmp = " + call + b";\n    " + var + b" = tmp;"

    if re.search(rb"\btmp\b", b_source):
        # 'tmp' already declared somewhere — just use it, no hoisting needed
        res = replace_node(b_source, target_node, inline_repl)
        return res.decode("utf-8") if res else None

    # C89: hoist 'BOOL tmp;' to function body top
    insert_pos = _find_function_body_insert_pos(b_source, target_node.start_byte)
    if insert_pos is None:
        # Fallback: can't find function body, skip
        return None

    hoisted_decl = b"\n    BOOL tmp;"
    out = b_source[:insert_pos] + hoisted_decl + b_source[insert_pos:]
    offset = len(hoisted_decl)

    # Apply inline replacement at the shifted position
    new_start = target_node.start_byte + offset
    new_end = target_node.end_byte + offset
    result = out[:new_start] + inline_repl + out[new_end:]
    return result.decode("utf-8")


def mut_remove_temp_var(s: str, rng: random.Random) -> str | None:
    """Remove a temp variable usage: 'tmp = expr; var = tmp;' -> 'var = expr;'."""
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_TEMP_VAR)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    captures = _first_caps(match[1])

    stmt1 = captures["stmt1"]
    stmt2 = captures["stmt2"]

    var = b_source[captures["var"].start_byte : captures["var"].end_byte]
    expr = b_source[captures["stmt"].start_byte : captures["stmt"].end_byte]

    replacement = var + b" = " + expr + b";"

    res = b_source[: stmt1.start_byte] + replacement + b_source[stmt2.end_byte :]
    return res.decode("utf-8")


def mut_toggle_signedness(s: str, rng: random.Random) -> str | None:
    """Toggle signed/unsigned on a local variable declaration."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        decl = b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        if b"unsigned " in decl:
            return decl.replace(b"unsigned ", b"")
        else:
            return b"unsigned " + decl

    res = _apply_query_once(b_source, _QUERY_DECLARATION, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None


def mut_swap_adjacent_declarations(s: str, rng: random.Random) -> str | None:
    """Swap two adjacent variable declarations."""
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_ADJACENT_DECL)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    captures = _first_caps(match[1])

    d1 = captures["d1"]
    d2 = captures["d2"]

    d1_text = b_source[d1.start_byte : d1.end_byte]
    d2_text = b_source[d2.start_byte : d2.end_byte]
    mid_text = b_source[d1.end_byte : d2.start_byte]

    replacement = d2_text + mid_text + d1_text
    res = b_source[: d1.start_byte] + replacement + b_source[d2.end_byte :]
    return res.decode("utf-8")


def mut_split_declaration_init(s: str, rng: random.Random) -> str | None:
    """Split 'TYPE var = expr;' into 'TYPE var; var = expr;'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        type_ = b_source[captures["type"].start_byte : captures["type"].end_byte]
        var = b_source[captures["var"].start_byte : captures["var"].end_byte]
        expr = b_source[captures["expr"].start_byte : captures["expr"].end_byte]

        return type_ + b" " + var + b";\n    " + var + b" = " + expr + b";"

    res = _apply_query_once(b_source, _QUERY_SPLIT_DECL, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_merge_declaration_init(s: str, rng: random.Random) -> str | None:
    """Merge 'TYPE var; ... var = expr;' into 'TYPE var = expr;'."""
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_MERGE_DECL)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    captures = _first_caps(match[1])

    d1 = captures["d1"]
    d2 = captures["d2"]

    type_ = b_source[captures["type"].start_byte : captures["type"].end_byte]
    var = b_source[captures["var"].start_byte : captures["var"].end_byte]
    expr = b_source[captures["init_expr"].start_byte : captures["init_expr"].end_byte]

    replacement = type_ + b" " + var + b" = " + expr + b";"
    res = b_source[: d1.start_byte] + replacement + b_source[d2.end_byte :]
    return res.decode("utf-8")


def mut_while_to_dowhile(s: str, rng: random.Random) -> str | None:
    """Convert 'while (cond) { body }' to 'if (cond) { do { body } while (cond); }'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        cond = b_source[captures["cond"].start_byte : captures["cond"].end_byte]
        body = b_source[captures["body"].start_byte : captures["body"].end_byte]
        return b"if " + cond + b" {\n    do " + body + b" while " + cond + b";\n    }"

    res = _apply_query_once(b_source, _QUERY_WHILE, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_dowhile_to_while(s: str, rng: random.Random) -> str | None:
    """Convert 'do { body } while (cond);' to 'while (cond) { body }'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        cond = b_source[captures["cond"].start_byte : captures["cond"].end_byte]
        body = b_source[captures["body"].start_byte : captures["body"].end_byte]
        return b"while " + cond + b" " + body

    res = _apply_query_once(b_source, _QUERY_DO_WHILE, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_early_return_to_accum(s: str, rng: random.Random) -> str | None:
    """Convert 'if (!expr) return 0;' to 'ret &= expr;' accumulator pattern."""
    b_source = s.encode("utf-8")
    if (
        b"ret;" not in b_source
        and b"retcode;" not in b_source
        and b"ret\n" not in b_source
        and b"retcode\n" not in b_source
        and b"ret=" not in b_source
        and b"retcode=" not in b_source
        and b"ret =" not in b_source
        and b"retcode =" not in b_source
    ):
        return None

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        expr = b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        var = b"retcode" if b"retcode" in b_source else b"ret"
        return var + b" &= " + expr + b";"

    res = _apply_query_once(b_source, _QUERY_EARLY_RETURN, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_accum_to_early_return(s: str, rng: random.Random) -> str | None:
    """Convert 'ret &= expr;' to 'if (!expr) return 0;'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        expr = b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        return b"if (!(" + expr + b"))\n        return 0;"

    res = _apply_query_once(b_source, _QUERY_ACCUM, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_pointer_to_int_param(s: str, rng: random.Random) -> str | None:
    """Change a pointer parameter to int or vice versa."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        var = b_source[captures["var"].start_byte : captures["var"].end_byte]
        return b"int " + var

    res = _apply_query_once(b_source, _QUERY_PTR_PARAM, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_int_to_pointer_param(s: str, rng: random.Random) -> str | None:
    """Change an int parameter to char* (for pointer-based access)."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        var = b_source[captures["var"].start_byte : captures["var"].end_byte]
        return b"char *" + var

    res = _apply_query_once(b_source, _QUERY_INT_PARAM, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_duplicate_loop_body(s: str, rng: random.Random) -> str | None:
    """Duplicate loop body (manual loop unrolling by 2x)."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        cond = b_source[captures["cond"].start_byte : captures["cond"].end_byte]
        body = b_source[captures["body"].start_byte : captures["body"].end_byte]

        inner = body[1:-1].strip()
        if not inner:
            raise ValueError
        return b"while " + cond + b" {\n    " + inner + b"\n    " + inner + b"\n}"

    try:
        res = _apply_query_once(b_source, _QUERY_WHILE, _repl, rng)
        return res.decode("utf-8") if res else None
    except ValueError:
        return None


def mut_fold_constant_add(s: str, rng: random.Random) -> str | None:
    """Fold two consecutive constant additions into a single statement."""
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_CONST_ADD_FOLD)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid_matches = []
    for match in matches:
        captures = _first_caps(match[1])
        if captures["stmt1"].next_named_sibling == captures["stmt2"]:
            try:
                n1 = int(
                    b_source[captures["n1"].start_byte : captures["n1"].end_byte].decode("utf-8")
                )
                n2 = int(
                    b_source[captures["n2"].start_byte : captures["n2"].end_byte].decode("utf-8")
                )
                valid_matches.append((captures, n1, n2))
            except ValueError:
                pass

    if not valid_matches:
        return None

    captures, n1, n2 = rng.choice(valid_matches)
    v1 = b_source[captures["v1"].start_byte : captures["v1"].end_byte]

    new_sum = str(n1 + n2).encode("utf-8")
    replacement = v1 + b" = " + v1 + b" + " + new_sum + b";"

    start = captures["stmt1"].start_byte
    end = captures["stmt2"].end_byte
    return (b_source[:start] + replacement + b_source[end:]).decode("utf-8")


def _parse_int_literal(raw: str) -> int | None:
    """Parse a C integer literal (decimal / hex / octal, optional u/l/U/L
    suffix) — None for floats, chars, or other non-integers."""
    body = raw.strip()
    if not body:
        return None
    if body[0] == "'":  # char literal
        return None
    # strip integer suffixes
    while body and body[-1] in "uUlL":
        body = body[:-1]
    if not body:
        return None
    try:
        if body.lower().startswith("0x"):
            return int(body, 16)
        if len(body) > 1 and body.startswith("0"):
            return int(body, 8)
        return int(body, 10)
    except ValueError:
        return None


def mut_tweak_integer_literal(s: str, rng: random.Random) -> str | None:
    """Tweak a numeric literal by a small delta (field offsets, sizes, magic
    numbers, enum values).

    Without this the GA can never FIX a wrong constant: structural
    mutations leave ``+ 0x70`` stuck when the target wants ``+ 0x6c``, so a
    function whose only defect is a wrong offset plateaus at its seed score
    forever.  Deltas are biased small (±1/±2/±4/±8/±0x10) — the off-by-N
    mistakes decompilation actually makes.  The literal's radix (hex vs
    decimal) is preserved.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_NUMBER_LITERAL)

    valid: list[tuple[Any, str, int]] = []
    for match in cursor.matches(tree.root_node):
        lit = _first_caps(match[1]).get("lit")
        if lit is None:
            continue
        raw = b_source[lit.start_byte : lit.end_byte].decode("utf-8")
        value = _parse_int_literal(raw)
        if value is None:
            continue
        valid.append((lit, raw, value))

    if not valid:
        return None

    lit, raw, value = rng.choice(valid)
    delta = rng.choice([1, -1, 2, -2, 4, -4, 8, -8, 0x10, -0x10])
    new_value = value + delta
    if new_value < 0 or new_value == value:
        return None
    new_raw = hex(new_value) if raw.lower().startswith("0x") else str(new_value)
    return (b_source[: lit.start_byte] + new_raw.encode("utf-8") + b_source[lit.end_byte :]).decode(
        "utf-8"
    )


#: Ancestor node types where C requires a constant expression, so a literal
#: inside them cannot be replaced by a variable.
_REQUIRES_CONSTANT_EXPR = frozenset(
    {
        "case_statement",
        "enumerator",
        "array_declarator",
        "bitfield_clause",
        "preproc_def",
        "preproc_if",
        "preproc_ifdef",
        "preproc_elif",
    }
)


def _literal_requires_constant_expression(lit: ts.Node) -> bool:
    """True when *lit* sits where replacing it with a variable is invalid.

    Covers the constant-expression contexts (case label, enumerator, array
    bound, bitfield width, preprocessor condition), ``static`` storage
    initializers, and file scope where there is no function body to declare a
    local in.
    """
    parent = lit.parent
    while parent is not None:
        if parent.type in _REQUIRES_CONSTANT_EXPR:
            return True
        if parent.type == "declaration":
            # `static` is a keyword token in some grammar revisions and a
            # `storage_class_specifier` node in others; match the text either
            # way.
            for child in parent.children:
                if child.text == b"static" or child.type == "storage_class_specifier":
                    return True
        if parent.type == "function_definition":
            return False
        parent = parent.parent
    return True


def mut_materialize_constant(s: str, rng: random.Random) -> str | None:
    """Hoist an integer literal into a named local.

    MSVC6 folds a literal into an immediate operand, but loads a named
    variable into a register first: ``unsigned char marker = 0xff; ... marker``
    produces ``or edx,-1`` plus byte compares where the bare ``0xff`` folds
    into ``cmp byte ptr [mem], 0xff``.  The variable's *name* and width are the
    lever, not its value.

    The local is declared at the enclosing function's body top (C89:
    declarations first) and its width follows the literal's magnitude: at most
    0xff ``unsigned char``, at most 0xffff ``unsigned short``, otherwise
    ``int``.  Literals where C requires a constant expression are skipped.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = _cursor(_QUERY_NUMBER_LITERAL)

    valid: list[ts.Node] = []
    for match in cursor.matches(tree.root_node):
        lit = _first_caps(match[1]).get("lit")
        if lit is None:
            continue
        value = _parse_int_literal(b_source[lit.start_byte : lit.end_byte].decode("utf-8"))
        # 0 and 1 are structural (`i = 0`), not magic constants, and the
        # widest int cannot hold a larger literal.
        if value is None or value in (0, 1) or abs(value) > 0x7FFFFFFF:
            continue
        if _literal_requires_constant_expression(lit):
            continue
        valid.append(lit)

    if not valid:
        return None

    lit_node = rng.choice(valid)
    name = f"_mk_{rng.randint(0, 99)}".encode()
    if name in b_source:
        return None
    body_pos = _find_function_body_insert_pos(b_source, lit_node.start_byte)
    if body_pos is None:
        return None

    raw = b_source[lit_node.start_byte : lit_node.end_byte]
    magnitude = abs(_parse_int_literal(raw.decode("utf-8")) or 0)
    if magnitude <= 0xFF:
        ctype = b"unsigned char"
    elif magnitude <= 0xFFFF:
        ctype = b"unsigned short"
    else:
        ctype = b"int"
    decl = b"\n    " + ctype + b" " + name + b" = " + raw + b";"

    # Replace first, then insert: the insertion point precedes the literal, so
    # the replacement cannot shift it.
    result = b_source[: lit_node.start_byte] + name + b_source[lit_node.end_byte :]
    result = result[:body_pos] + decl + result[body_pos:]
    return result.decode("utf-8")


def mut_unfold_constant_add(s: str, rng: random.Random) -> str | None:
    """Expand a constant addition into repeated increment-by-one statements."""
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_CONST_ADD_UNFOLD)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid_matches = []
    for match in matches:
        captures = _first_caps(match[1])
        try:
            n = int(b_source[captures["n"].start_byte : captures["n"].end_byte].decode("utf-8"))
            if 1 < n <= 16:
                valid_matches.append((captures, n))
        except ValueError:
            pass

    if not valid_matches:
        return None

    captures, n = rng.choice(valid_matches)
    v1 = b_source[captures["v1"].start_byte : captures["v1"].end_byte]

    incs = b"; ".join([v1 + b" = " + v1 + b" + 1" for _ in range(n)]) + b";"

    start = captures["stmt"].start_byte
    end = captures["stmt"].end_byte
    return (b_source[:start] + incs + b_source[end:]).decode("utf-8")


def mut_change_array_index_order(s: str, rng: random.Random) -> str | None:
    """Swap array and index in a subscript expression (arr[i] to i[arr])."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        arr = b_source[captures["arr"].start_byte : captures["arr"].end_byte]
        idx = b_source[captures["idx"].start_byte : captures["idx"].end_byte]
        return idx + b"[" + arr + b"]"

    res = _apply_query_once(b_source, _QUERY_ARRAY_INDEX, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_struct_vs_ptr_access(s: str, rng: random.Random) -> str | None:
    """Convert ptr->field arrow access to (*ptr).field dereference form."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        ptr = b_source[captures["ptr"].start_byte : captures["ptr"].end_byte]
        field = b_source[captures["field"].start_byte : captures["field"].end_byte]
        return b"(*" + ptr + b")." + field

    res = _apply_query_once(b_source, _QUERY_PTR_ARROW, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_change_return_type(s: str, rng: random.Random) -> str | None:
    """Replace the function return type with a random integer type."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        current = b_source[captures["expr"].start_byte : captures["expr"].end_byte].decode("utf-8")
        types = ["int", "char", "short", "long"]
        candidates = [t for t in types if t != current]
        if not candidates:
            return current.encode("utf-8")
        new_type = rng.choice(candidates).encode("utf-8")
        return new_type

    res = _apply_query_once(b_source, _QUERY_RETURN_TYPE, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_combine_ptr_arith(s: str, rng: random.Random) -> str | None:
    """Combine two consecutive pointer arithmetic additions into one."""
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_COMBINE_PTR_ARITH)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid_matches: list[tuple[dict[str, ts.Node], int, int]] = []
    for match in matches:
        captures = _first_caps(match[1])
        try:
            n1 = int(b_source[captures["n1"].start_byte : captures["n1"].end_byte].decode("utf-8"))
            n2 = int(b_source[captures["n2"].start_byte : captures["n2"].end_byte].decode("utf-8"))
            s1 = captures["stmt1"]
            s2 = captures["stmt2"]
            between = b_source[s1.end_byte : s2.start_byte].strip()
            if not between:
                valid_matches.append((captures, n1, n2))
        except ValueError:
            pass

    if not valid_matches:
        return None

    captures, n1, n2 = rng.choice(valid_matches)
    v1 = b_source[captures["v1"].start_byte : captures["v1"].end_byte]
    new_sum = str(n1 + n2).encode("utf-8")
    replacement = v1 + b" = " + v1 + b" + " + new_sum + b";"
    start = captures["stmt1"].start_byte
    end = captures["stmt2"].end_byte
    return (b_source[:start] + replacement + b_source[end:]).decode("utf-8")


def mut_split_ptr_arith(s: str, rng: random.Random) -> str | None:
    """Split a single pointer addition into two smaller additions."""
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_SPLIT_PTR_ARITH)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid_matches: list[tuple[dict[str, ts.Node], int]] = []
    for match in matches:
        if not match[1]:
            continue
        captures = _first_caps(match[1])
        if "n1" not in captures or "v1" not in captures:
            continue
        try:
            n = int(b_source[captures["n1"].start_byte : captures["n1"].end_byte].decode("utf-8"))
            if n > 1:
                valid_matches.append((captures, n))
        except ValueError:
            pass

    if not valid_matches:
        return None

    captures, n = rng.choice(valid_matches)
    v1 = b_source[captures["v1"].start_byte : captures["v1"].end_byte]
    n1 = n // 2
    n2 = n - n1
    replacement = (
        v1
        + b" = "
        + v1
        + b" + "
        + str(n1).encode("utf-8")
        + b"; "
        + v1
        + b" = "
        + v1
        + b" + "
        + str(n2).encode("utf-8")
        + b";"
    )
    start = captures["stmt"].start_byte
    end = captures["stmt"].end_byte
    return (b_source[:start] + replacement + b_source[end:]).decode("utf-8")


def mut_change_param_order(s: str, rng: random.Random) -> str | None:
    """Swap two parameters in a function definition's parameter list."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        params = captures["expr"]
        children = [c for c in params.children if c.type != "," and c.type != "(" and c.type != ")"]
        if len(children) < 2:
            return b_source[params.start_byte : params.end_byte]
        i, j = rng.sample(range(len(children)), 2)
        params_text = [b_source[c.start_byte : c.end_byte] for c in children]
        params_text[i], params_text[j] = params_text[j], params_text[i]
        return b"(" + b", ".join(params_text) + b")"

    res = _apply_query_once(b_source, _QUERY_PARAM_ORDER, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_toggle_calling_convention(s: str, rng: random.Random) -> str | None:
    """Toggle between __cdecl and __stdcall calling conventions."""
    b_source = s.encode("utf-8")

    def _repl_existing(captures: dict[str, ts.Node]) -> bytes:
        conv = b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        if conv == b"__cdecl":
            return b"__stdcall"
        elif conv == b"__stdcall":
            return b"__cdecl"
        return conv

    res = _apply_query_once(b_source, _QUERY_CALL_CONV, _repl_existing, rng)
    if res is not None:
        return res.decode("utf-8")

    # No existing convention — insert one after the return type.  The query
    # captures the TYPE node as `expr` (see _QUERY_NO_CALL_CONV): splicing the
    # whole function_definition destroyed the body.
    def _repl_insert(captures: dict[str, ts.Node]) -> bytes:
        t = b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        conv = rng.choice([b"__cdecl", b"__stdcall"])
        return t + b" " + conv

    res = _apply_query_once(b_source, _QUERY_NO_CALL_CONV, _repl_insert, rng)
    return res.decode("utf-8") if res is not None else None


def mut_toggle_char_signedness(s: str, rng: random.Random) -> str | None:
    """Cycle char type signedness: char -> unsigned -> signed -> char."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        t = b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        mapping = {
            b"char": b"unsigned char",
            b"unsigned char": b"signed char",
            b"signed char": b"char",
        }
        return mapping.get(t, t)

    res = _apply_query_once(b_source, _QUERY_SIZED_CHAR_TYPE, _repl, rng)
    if res is None:
        res = _apply_query_once(b_source, _QUERY_BARE_CHAR_TYPE, _repl, rng)
    if res is None or res == b_source:
        return None
    return res.decode("utf-8")


def mut_comparison_boundary(s: str, rng: random.Random) -> str | None:
    """Adjust comparison boundary by toggling between > 0 and >= 1 forms."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        op = b_source[captures["op"].start_byte : captures["op"].end_byte]
        num_str = b_source[captures["num"].start_byte : captures["num"].end_byte]
        try:
            num = int(num_str.decode("utf-8"))
        except ValueError:
            return b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        if op == b">" and num == 0:
            return left + b" >= 1"
        elif op == b">=" and num == 1:
            return left + b" > 0"
        elif op == b"<" and num == 1:
            return left + b" <= 0"
        elif op == b"<=" and num == 0:
            return left + b" < 1"
        return b_source[captures["expr"].start_byte : captures["expr"].end_byte]

    res = _apply_query_once(b_source, _QUERY_CMP_BOUNDARY, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_insert_noop_block(s: str, rng: random.Random) -> str | None:
    """Insert a no-op block `if (0) {}` before a random statement in a compound body."""
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    # Find all statements inside compound_statements
    q = _QUERY_INSERT_NOOP_BLOCK
    cursor = _cursor(q)
    matches = cursor.matches(tree.root_node)
    if not matches:
        return None
    match = rng.choice(matches)
    captures = _first_caps(match[1])
    stmt_node = captures["stmt"]
    noop = b"if (0) {} "
    start = stmt_node.start_byte
    return (b_source[:start] + noop + b_source[start:]).decode("utf-8")


def mut_introduce_local_alias(s: str, rng: random.Random) -> str | None:
    """Introduce a local alias for an identifier used in an expression statement."""
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    q = _QUERY_INTRODUCE_LOCAL_ALIAS
    cursor = _cursor(q)
    matches = cursor.matches(tree.root_node)
    if not matches:
        return None
    match = rng.choice(matches)
    captures = _first_caps(match[1])
    var_node = captures["var"]
    stmt_node = captures["stmt"]
    var_name = b_source[var_node.start_byte : var_node.end_byte]
    alias = b"_alias_" + var_name
    decl = b"int " + alias + b" = " + var_name + b"; "
    # Replace the var usage with the alias
    result = (
        b_source[: stmt_node.start_byte]
        + decl
        + b_source[stmt_node.start_byte : var_node.start_byte]
        + alias
        + b_source[var_node.end_byte :]
    )
    return result.decode("utf-8")


def mut_reorder_declarations(s: str, rng: random.Random) -> str | None:
    """Swap two adjacent declarations in a compound statement."""
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    q = _QUERY_REORDER_DECLARATIONS
    cursor = _cursor(q)
    matches = cursor.matches(tree.root_node)
    if not matches:
        return None
    match = rng.choice(matches)
    captures = _first_caps(match[1])
    d1 = captures["d1"]
    d2 = captures["d2"]
    d1_text = b_source[d1.start_byte : d1.end_byte]
    d2_text = b_source[d2.start_byte : d2.end_byte]
    result = (
        b_source[: d1.start_byte]
        + d2_text
        + b_source[d1.end_byte : d2.start_byte]
        + d1_text
        + b_source[d2.end_byte :]
    )
    return result.decode("utf-8")


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

_RE_FUNC_START = re.compile(
    r"^[a-zA-Z_][a-zA-Z0-9_*\s]*\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(",
    re.MULTILINE,
)
_RE_VALIDATE_LABEL = re.compile(r"^\s*([a-zA-Z_]\w*)\s*:", re.MULTILINE)
_LABEL_IGNORE = frozenset({"case", "default", "public", "private", "protected"})
_TYPE_KEYWORDS_RE = (
    r"(?:BOOL|int|DWORD|HANDLE|LPVOID|void|char|short|long|float|double|"
    r"unsigned|signed|const|volatile|register|UINT|ULONG|BYTE|WORD)"
)
_RE_VALIDATE_DOUBLE_TYPE = re.compile(r"\b(" + _TYPE_KEYWORDS_RE + r")\s+\1\b")


def _split_preamble_body(source: str) -> tuple[str, str]:
    """Split source into preamble (includes, typedefs, externs) and function body."""
    lines = source.splitlines()
    preamble: list[str] = []
    body: list[str] = []
    in_body = False
    brace_count = 0

    for line in lines:
        if not in_body:
            if _RE_FUNC_PRAGMA.match(line):
                # Function-level pragmas (optimize/intrinsic/function/
                # check_stack) belong WITH the function, not the file
                # preamble: pragma mutations must see and toggle them, and a
                # removed pragma must not linger in the preamble.
                in_body = True
                body.append(line)
            elif _RE_FUNC_START.match(line) and ("{" in line or ";" not in line):
                # A ;-terminated match with no brace is a prototype
                # (declaration), not a definition — treating it as the body
                # start stranded every include/typedef below it in the body,
                # so mutating the real function dropped the preamble's
                # declarations on the floor.  A brace marks a definition;
                # neither mark means a multi-line signature (old behavior:
                # body starts here).
                in_body = True
                body.append(line)
                brace_count += line.count("{") - line.count("}")
            else:
                preamble.append(line)
        else:
            body.append(line)
            brace_count += line.count("{") - line.count("}")

    return "\n".join(preamble), "\n".join(body)


def quick_validate(source: str) -> bool:
    """Fast check for obvious syntax errors that would waste a compilation round."""
    if source.count("{") != source.count("}"):
        return False
    if source.count("(") != source.count(")"):
        return False
    if not _RE_FUNC_START.search(source):
        return False
    try:
        return _quick_validate_ast_checks(source)
    except Exception:
        # Parse failure: fall back to the whole-source scan.  A duplicate
        # check scoped per function needs the AST; without it, identical
        # labels in sibling functions would reject everything.
        seen: set[str] = set()
        for m in _RE_VALIDATE_LABEL.finditer(source):
            seen_label = m.group(1)
            if seen_label in _LABEL_IGNORE:
                continue
            if seen_label in seen:
                return False
            seen.add(seen_label)
    return not _RE_VALIDATE_DOUBLE_TYPE.search(source)


def _block_has_C89_declaration_order(block: ts.Node) -> bool:
    """True when every declaration in *block* precedes every statement.

    C89 requires block-scope declarations before the first statement, so a
    declaration after one is a hard error for MSVC6 (``error C2143: missing
    ';' before 'type'``).  Most mutations that move declarations around can
    produce it, and the compiler is the only other place it would be caught,
    at the cost of a full compile.  ``type_definition`` counts as a
    declaration; comments are skipped.
    """
    seen_statement = False
    for node in block.children:
        # Braces and punctuation are unnamed nodes; only a named node is a
        # statement.  Counting the opening `{` as one rejected every block
        # that declares a local.
        if not node.is_named or node.type == "comment":
            continue
        if node.type in ("declaration", "type_definition"):
            if seen_statement:
                return False
        else:
            seen_statement = True
    return True


def _quick_validate_ast_checks(source: str) -> bool:
    """True when the parsed functions have no duplicate label and no C89
    declaration-order violation.

    Scoped per ``function_definition``: sibling functions legitimately reuse
    label names (the GA mutates multi-function files), so a global scan
    discarded every mutant of such a file.  Raises on parse failure — the
    caller falls back to the whole-source scan.
    """
    from rebrew.matcher.ast_engine import parse_c_ast

    tree = parse_c_ast(source.encode("utf-8"))
    for child in tree.root_node.children:
        if child.type != "function_definition":
            continue
        labels: set[bytes] = set()
        stack = [child]
        while stack:
            node = stack.pop()
            if node.type == "labeled_statement":
                label_node = node.child_by_field_name("label")
                if label_node is not None and label_node.text is not None:
                    label: bytes = label_node.text
                    if label in labels:
                        return False
                    labels.add(label)
            if node.type == "compound_statement" and not _block_has_C89_declaration_order(node):
                return False
            stack.extend(node.children)
    return not _RE_VALIDATE_DOUBLE_TYPE.search(source)


def compute_population_diversity(pop: list[str]) -> float:
    """Compute diversity of the population (0.0 to 1.0)."""
    if not pop or len(pop) < 2:
        return 0.0
    return len(set(pop)) / len(pop)


def _early_exit_return(b_source: bytes, ref_byte: int) -> bytes:
    """Early-exit return statement matching the enclosing function's return type.

    *ref_byte* locates the mutated statement; the enclosing
    ``function_definition`` is resolved by walking up from it, so a file with
    several functions uses the right one (the old first-function scan took the
    wrong return type whenever the match was not in the first function).

    ``void`` takes a bare ``return;`` (``return 0;`` would not compile);
    a pointer return takes ``return NULL;`` (``NULL`` is available — seeds
    include windows.h); anything else keeps ``return 0;``.
    """
    tree = parse_c_ast(b_source)
    node = tree.root_node.descendant_for_byte_range(ref_byte, ref_byte)
    while node is not None and node.type != "function_definition":
        node = node.parent
    if node is None:
        return b"return 0;"
    type_node = node.child_by_field_name("type")
    declarator = node.child_by_field_name("declarator")
    decl_text = b_source[declarator.start_byte : declarator.end_byte] if declarator else b""
    type_text = b_source[type_node.start_byte : type_node.end_byte] if type_node else b""
    if type_text.strip() == b"void":
        return b"return;"
    if b"*" in decl_text:
        return b"return NULL;"
    return b"return 0;"


def crossover(parent1: str, parent2: str, rng: random.Random) -> str:
    """Line-level crossover of two parent sources."""
    p1_pre, p1_body = _split_preamble_body(parent1)
    _, p2_body = _split_preamble_body(parent2)
    lines1 = p1_body.splitlines()
    lines2 = p2_body.splitlines()
    if not lines1 or not lines2:
        return parent1
    min_len = min(len(lines1), len(lines2))
    if min_len < 2:
        return parent1
    split_idx = rng.randint(1, min_len - 1)
    child_body = "\n".join(lines1[:split_idx] + lines2[split_idx:])
    child = p1_pre + "\n" + child_body
    if quick_validate(child):
        return child
    return parent1


# ---------------------------------------------------------------------------
# Structural code-layout mutations (AST rewrites of former regex mutations)
# ---------------------------------------------------------------------------


def mut_extract_else_body(s: str, rng: random.Random) -> str | None:
    """Convert if/else to negated-condition early exit.

    Changes:  if (c) { A } else { B }  ->  if (!(c)) { B; <early return>; } A
    where <early return> matches the function type (``return;`` for void,
    ``return NULL;`` for pointers, ``return 0;`` otherwise).
    """
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_IF_BODY_RETURN)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])

    cond = b_source[caps["cond"].start_byte + 1 : caps["cond"].end_byte - 1]
    if_body = b_source[caps["if_body"].start_byte + 1 : caps["if_body"].end_byte - 1]
    else_body = b_source[caps["else_body"].start_byte + 1 : caps["else_body"].end_byte - 1]

    # Negate condition
    cond_stripped = cond.strip()
    if cond_stripped.startswith(b"!") and not cond_stripped.startswith(b"!="):
        neg_cond = cond_stripped[1:].strip()
        if neg_cond.startswith(b"(") and neg_cond.endswith(b")"):
            neg_cond = neg_cond[1:-1]
    else:
        neg_cond = b"!(" + cond_stripped + b")"

    replacement = (
        b"if ("
        + neg_cond
        + b") {"
        + else_body
        + b"\n        "
        + _early_exit_return(b_source, caps["expr"].start_byte)
        + b"\n    }"
        + if_body
    )
    result = b_source[: caps["expr"].start_byte] + replacement + b_source[caps["expr"].end_byte :]
    return result.decode("utf-8")


def mut_for_to_while(s: str, rng: random.Random) -> str | None:
    """Convert for loop to while loop.

    Changes:  for (i=0; i<n; i++) { body }  ->  i=0; while (i<n) { body i++; }
    """
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_FOR_LOOP)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])

    init = b_source[caps["init"].start_byte : caps["init"].end_byte] if "init" in caps else b""
    cond = b_source[caps["cond"].start_byte : caps["cond"].end_byte] if "cond" in caps else b""
    update = (
        b_source[caps["update"].start_byte : caps["update"].end_byte] if "update" in caps else b""
    )
    body = b_source[caps["body"].start_byte : caps["body"].end_byte]

    if not cond:
        return None

    # Build while loop
    parts = []
    if init:
        init_text = init.strip()
        if not init_text.endswith(b";"):
            init_text += b";"
        parts.append(init_text + b"\n    ")

    inner = body[1:-1]  # strip { }
    if update:
        inner = inner.rstrip() + b"\n        " + update + b";\n    "

    parts.append(b"while (" + cond + b") {" + inner + b"}")

    replacement = b"".join(parts)
    result = b_source[: caps["stmt"].start_byte] + replacement + b_source[caps["stmt"].end_byte :]
    return result.decode("utf-8")


def mut_while_to_for(s: str, rng: random.Random) -> str | None:
    """Convert while loop to for loop.

    Changes:  while (cond) { body }  ->  for (; cond; ) { body }
    """
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        cond = b_source[captures["cond"].start_byte : captures["cond"].end_byte]
        body = b_source[captures["body"].start_byte : captures["body"].end_byte]
        # Strip parens from condition
        cond_inner = cond
        if cond_inner.startswith(b"(") and cond_inner.endswith(b")"):
            cond_inner = cond_inner[1:-1]
        return b"for (; " + cond_inner.strip() + b"; ) " + body

    res = _apply_query_once(b_source, _QUERY_WHILE, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_if_to_ternary(s: str, rng: random.Random) -> str | None:
    """Convert if/else assignment to ternary expression.

    Changes:  if (c) x = a; else x = b;  ->  x = (c) ? a : b;
    """
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_IF_ASSIGN_ELSE)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    # Filter: both assignments must target the same variable
    valid = []
    for match in matches:
        caps = _first_caps(match[1])
        var1 = b_source[caps["var1"].start_byte : caps["var1"].end_byte]
        var2 = b_source[caps["var2"].start_byte : caps["var2"].end_byte]
        if var1 == var2:
            valid.append(caps)

    if not valid:
        return None

    caps = rng.choice(valid)
    cond = b_source[caps["cond"].start_byte : caps["cond"].end_byte]
    var = b_source[caps["var1"].start_byte : caps["var1"].end_byte]
    val_true = b_source[caps["val1"].start_byte : caps["val1"].end_byte]
    val_false = b_source[caps["val2"].start_byte : caps["val2"].end_byte]

    replacement = var + b" = " + cond + b" ? " + val_true + b" : " + val_false + b";"
    result = b_source[: caps["expr"].start_byte] + replacement + b_source[caps["expr"].end_byte :]
    return result.decode("utf-8")


def mut_ternary_to_if(s: str, rng: random.Random) -> str | None:
    """Convert ternary expression to if/else assignment.

    Changes:  x = c ? a : b;  ->  if (c) x = a; else x = b;
    """
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_TERNARY)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])

    var = b_source[caps["var"].start_byte : caps["var"].end_byte]
    cond = b_source[caps["cond"].start_byte : caps["cond"].end_byte]
    val_true = b_source[caps["val_true"].start_byte : caps["val_true"].end_byte]
    val_false = b_source[caps["val_false"].start_byte : caps["val_false"].end_byte]

    replacement = (
        b"if ("
        + cond
        + b")\n        "
        + var
        + b" = "
        + val_true
        + b";\n    else\n        "
        + var
        + b" = "
        + val_false
        + b";"
    )
    result = b_source[: caps["expr"].start_byte] + replacement + b_source[caps["expr"].end_byte :]
    return result.decode("utf-8")


def mut_hoist_return(s: str, rng: random.Random) -> str | None:
    """Extract branch returns to a labeled goto accumulator.

    Changes:  return expr;  ->  ret = expr; goto end;
    (and adds 'end: return ret;' before the function's closing brace)
    """
    b_source = s.encode("utf-8")
    if b"end:" in b_source:
        return None

    tree = parse_c_ast(b_source)
    q = _QUERY_HOIST_RETURN
    cursor = _cursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])
    val = b_source[caps["val"].start_byte : caps["val"].end_byte]
    stmt = caps["stmt"]

    # Only safe when the return is the FINAL statement of the function body —
    # `goto end` placed before the function's closing brace would otherwise
    # skip any code that follows the return's enclosing block.
    parent = stmt.parent
    if parent is None or parent.type != "compound_statement":
        return None
    if parent.parent is None or parent.parent.type != "function_definition":
        return None
    body_stmts = [c for c in parent.named_children if c.type != "comment"]
    if not body_stmts or body_stmts[-1] != stmt:
        return None

    # Word-boundary check: the old `b"ret" in b_source` matched inside
    # "return", so ret_var was always "retval" — and it was never declared,
    # so every candidate failed to compile (dead mutator).
    ret_var = b"retval"
    if re.search(rb"\bretval\b", b_source):
        return None

    insert_pos = _find_function_body_insert_pos(b_source, stmt.start_byte)
    if insert_pos is None:
        return None

    hoisted = b"\n    int " + ret_var + b";"
    out = b_source[:insert_pos] + hoisted + b_source[insert_pos:]
    offset = len(hoisted)
    s_start = stmt.start_byte + offset
    s_end = stmt.end_byte + offset

    replacement = ret_var + b" = " + val + b";\n    goto end;"
    result = out[:s_start] + replacement + out[s_end:]

    # The label must close the SAME function.  ``result.rfind(b"}")`` landed on
    # the file's last brace (a sibling function or struct further down),
    # leaving this function's ``goto end;`` dangling (compile error).  ``parent``
    # is the validated enclosing body, so its closing brace is the right anchor;
    # shift it by the hoisted declaration and the replacement's length delta.
    brace_pos = parent.end_byte + offset - 1 + (len(replacement) - (s_end - s_start))
    result = result[:brace_pos] + b"\nend:\n    return " + ret_var + b";\n" + result[brace_pos:]

    return result.decode("utf-8")


def mut_sink_return(s: str, rng: random.Random) -> str | None:
    """Collapse ret=expr; goto end; back to return expr.

    Inverse of mut_hoist_return.
    """
    b_source = s.encode("utf-8")
    if b"goto end;" not in b_source:
        return None

    # Use regex since this is a multi-statement pattern
    all_m = list(_RE_SINK_RETURN.finditer(b_source))
    if not all_m:
        return None

    m = rng.choice(all_m)
    expr = m.group(2)
    replacement = b"return " + expr + b";"
    result = b_source[: m.start()] + replacement + b_source[m.end() :]

    # Remove end label if no more gotos
    if b"goto end;" not in result:
        result = re.sub(rb"\nend:\n\s*return\s+\w+;\n", b"\n", result)

    return result.decode("utf-8")


def mut_swap_adjacent_stmts(s: str, rng: random.Random) -> str | None:
    """Swap two adjacent non-dependent assignment statements."""
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_ADJACENT_EXPR_STMTS)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    # Filter: only swap assignment statements, check no dependencies
    valid = []
    for match in matches:
        caps = _first_caps(match[1])
        s1 = caps["s1"]
        s2 = caps["s2"]
        s1_text = b_source[s1.start_byte : s1.end_byte]
        s2_text = b_source[s2.start_byte : s2.end_byte]
        # Both must be assignments
        if b"=" not in s1_text or b"=" not in s2_text:
            continue
        # Quick dependency check
        lhs1 = s1_text.split(b"=")[0].strip()
        lhs2 = s2_text.split(b"=")[0].strip()
        if lhs1 in s2_text or lhs2 in s1_text:
            continue
        valid.append(caps)

    if not valid:
        return None

    caps = rng.choice(valid)
    s1 = caps["s1"]
    s2 = caps["s2"]
    s1_text = b_source[s1.start_byte : s1.end_byte]
    s2_text = b_source[s2.start_byte : s2.end_byte]
    mid = b_source[s1.end_byte : s2.start_byte]

    result = b_source[: s1.start_byte] + s2_text + mid + s1_text + b_source[s2.end_byte :]
    return result.decode("utf-8")


def mut_guard_clause(s: str, rng: random.Random) -> str | None:
    """Extract guard clause.

    Changes: if(c){body;return x;} return y -> if(!c) return y; body; return x;
    """
    b_source = s.encode("utf-8")
    # Use regex for this complex multi-statement pattern
    all_m = list(_RE_GUARD_CLAUSE.finditer(b_source))
    if not all_m:
        return None

    m = rng.choice(all_m)
    indent = m.group(1)
    cond = m.group(2).strip()
    body = m.group(3).strip()
    ret_true = m.group(4).strip()
    ret_false = m.group(5).strip()

    if cond.startswith(b"!"):
        neg = cond[1:].strip().lstrip(b"(").rstrip(b")")
    else:
        neg = b"!(" + cond + b")"

    replacement = (
        indent
        + b"if ("
        + neg
        + b") return "
        + ret_false
        + b";\n"
        + indent
        + body
        + b"\n"
        + indent
        + b"return "
        + ret_true
        + b";"
    )
    result = b_source[: m.start()] + replacement + b_source[m.end() :]
    return result.decode("utf-8")


def mut_invert_loop_direction(s: str, rng: random.Random) -> str | None:
    """Reverse loop iteration: for(i=0;i<n;i++) -> for(i=n-1;i>=0;i--)."""
    b_source = s.encode("utf-8")
    cursor = _cursor(_QUERY_FOR_COUNT_UP)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])

    var = b_source[caps["var"].start_byte : caps["var"].end_byte]
    limit = b_source[caps["limit"].start_byte : caps["limit"].end_byte]
    body = b_source[caps["body"].start_byte : caps["body"].end_byte]

    replacement = (
        b"for (" + var + b" = " + limit + b" - 1; " + var + b" >= 0; " + var + b"--) " + body
    )
    result = b_source[: caps["stmt"].start_byte] + replacement + b_source[caps["stmt"].end_byte :]
    return result.decode("utf-8")


def mut_compound_assign_toggle(s: str, rng: random.Random) -> str | None:
    """Toggle between x = x + n and x += n."""
    b_source = s.encode("utf-8")

    # Try expanding compound (x += n -> x = x + n)
    expand_cursor = _cursor(_QUERY_COMPOUND_ASSIGN)
    tree = parse_c_ast(b_source)
    expand_matches = [(m, "expand") for m in expand_cursor.matches(tree.root_node)]

    # Try shortening expanded (x = x + n -> x += n)
    short_cursor = _cursor(_QUERY_EXPANDED_COMPOUND)
    short_matches = []
    for m in short_cursor.matches(tree.root_node):
        caps = _first_caps(m[1])
        var = b_source[caps["var"].start_byte : caps["var"].end_byte]
        var2 = b_source[caps["var2"].start_byte : caps["var2"].end_byte]
        if var == var2:
            short_matches.append((m, "shorten"))

    all_matches = expand_matches + short_matches
    if not all_matches:
        return None

    match, direction = rng.choice(all_matches)
    caps = _first_caps(match[1])

    var = b_source[caps["var"].start_byte : caps["var"].end_byte]
    op = b_source[caps["op"].start_byte : caps["op"].end_byte]
    rhs = b_source[caps["rhs"].start_byte : caps["rhs"].end_byte]

    if direction == "expand":
        # x += n -> x = x + n
        base_op = op.rstrip(b"=").strip()
        if not base_op:
            base_op = b"+"
        # Safety: reject subtraction with multi-term RHS
        if base_op == b"-" and (b"+" in rhs or b"-" in rhs):
            return None
        replacement = var + b" = " + var + b" " + base_op + b" " + rhs + b";"
    else:
        # x = x + n -> x += n
        base_op = b_source[caps["op"].start_byte : caps["op"].end_byte]
        if base_op == b"-" and (b"+" in rhs or b"-" in rhs):
            return None
        replacement = var + b" " + base_op + b"= " + rhs + b";"

    target = _capture(caps, "expr") or _capture(caps, "stmt")
    if target is None:
        return None
    result = b_source[: target.start_byte] + replacement + b_source[target.end_byte :]
    return result.decode("utf-8")


def mut_demorgan(s: str, rng: random.Random) -> str | None:
    """Apply De Morgan's law: !(a && b) <-> (!a || !b)."""
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    and_cursor = _cursor(_QUERY_DEMORGAN_NOT_AND)
    and_matches = [(m, "and") for m in and_cursor.matches(tree.root_node)]

    or_cursor = _cursor(_QUERY_DEMORGAN_NOT_OR)
    or_matches = [(m, "or") for m in or_cursor.matches(tree.root_node)]

    all_matches = and_matches + or_matches
    if not all_matches:
        return None

    match, kind = rng.choice(all_matches)
    caps = _first_caps(match[1])

    a = b_source[caps["a"].start_byte : caps["a"].end_byte]
    b = b_source[caps["b"].start_byte : caps["b"].end_byte]

    if kind == "and":
        replacement = b"(!" + a + b" || !" + b + b")"
    else:
        replacement = b"(!" + a + b" && !" + b + b")"

    expr = caps["expr"]
    result = b_source[: expr.start_byte] + replacement + b_source[expr.end_byte :]
    return result.decode("utf-8")


def mut_postpre_increment(s: str, rng: random.Random) -> str | None:
    """Toggle i++ <-> ++i and i-- <-> --i."""
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    candidates: list[tuple[dict[str, ts.Node], bytes]] = []

    for q in [_QUERY_POST_INCREMENT, _QUERY_POST_DECREMENT]:
        cursor = _cursor(q)
        for m in cursor.matches(tree.root_node):
            caps = _first_caps(m[1])
            expr_node = caps["expr"]
            var = b_source[caps["var"].start_byte : caps["var"].end_byte]
            text = b_source[expr_node.start_byte : expr_node.end_byte]
            # Determine if post or pre and the operator
            if text.endswith(b"++"):
                candidates.append((caps, b"++" + var))
            elif text.endswith(b"--"):
                candidates.append((caps, b"--" + var))
            elif text.startswith(b"++"):
                candidates.append((caps, var + b"++"))
            elif text.startswith(b"--"):
                candidates.append((caps, var + b"--"))

    if not candidates:
        return None

    caps, replacement = rng.choice(candidates)
    expr = caps["expr"]
    result = b_source[: expr.start_byte] + replacement + b_source[expr.end_byte :]
    return result.decode("utf-8")


def mut_xor_zero_toggle(s: str, rng: random.Random) -> str | None:
    """Toggle x = 0 <-> x ^= x."""
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    candidates: list[tuple[dict[str, ts.Node], bytes, str]] = []

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
        candidates.append((caps, var + b" ^= " + var + b";", "expr"))

    xor_cursor = _cursor(_QUERY_XOR_SELF)
    for m in xor_cursor.matches(tree.root_node):
        caps = _first_caps(m[1])
        var = b_source[caps["var"].start_byte : caps["var"].end_byte]
        candidates.append((caps, var + b" = 0;", "expr"))

    if not candidates:
        return None

    caps, replacement, target_key = rng.choice(candidates)
    target = caps[target_key]
    result = b_source[: target.start_byte] + replacement + b_source[target.end_byte :]
    return result.decode("utf-8")


def mut_negate_condition(s: str, rng: random.Random) -> str | None:
    """Wrap if-condition in negation: if (a > b) -> if (!(a > b))."""
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    q = _QUERY_NEGATE_CONDITION
    cursor = _cursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = _first_caps(match[1])
    cond_node = caps["cond"]
    cond = b_source[cond_node.start_byte + 1 : cond_node.end_byte - 1].strip()

    # Toggle negation
    if cond.startswith(b"!(") and cond.endswith(b")"):
        new_cond = cond[2:-1]
    elif cond.startswith(b"!") and not cond.startswith(b"!="):
        new_cond = cond[1:].strip()
    else:
        new_cond = b"!(" + cond + b")"

    replacement = b"(" + new_cond + b")"
    result = b_source[: cond_node.start_byte] + replacement + b_source[cond_node.end_byte :]
    return result.decode("utf-8")
