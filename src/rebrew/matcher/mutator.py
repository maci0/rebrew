"""mutator.py – Unified C source mutation engine for GA-based binary matching.

Provides mutation functions that transform C89 source code to explore
the MSVC6 code generation space.  Uses tree-sitter AST for all mutations.
"""

import random
import re
from collections.abc import Callable
from typing import Literal, overload

import tree_sitter as ts

from rebrew.matcher.ast_engine import _C_LANGUAGE, ASTMutator, parse_c_ast

# --- Query Definitions ---
# We define tree-sitter queries here for performance

_QUERY_COMMUTE_ADD = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        "+" @op
        right: (identifier) @right) @expr
""",
)

_QUERY_COMMUTE_MUL = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        "*" @op
        right: (identifier) @right) @expr
""",
)

_QUERY_EQ_ZERO = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        ["==" "!="] @op
        right: (number_literal) @right
        (#eq? @right "0")) @expr
""",
)

_QUERY_FLIP_LT_GE = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        "<"
        right: (identifier) @right) @expr
""",
)

_QUERY_IDENTIFIER = ts.Query(
    _C_LANGUAGE,
    """
    (identifier) @expr
""",
)

_QUERY_SWAP_EQ = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        "=="
        right: (identifier) @right) @expr
""",
)

_QUERY_SWAP_NE = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        "!="
        right: (identifier) @right) @expr
""",
)

_QUERY_REASSOCIATE = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (parenthesized_expression (binary_expression left: (_) @a "+" right: (_) @b))
        "+"
        right: (_) @c) @expr
""",
)

_QUERY_SWAP_OR = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "||"
        right: (_) @right) @expr
""",
)

_QUERY_SWAP_AND = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "&&"
        right: (_) @right) @expr
""",
)

_QUERY_DOUBLE_NOT = ts.Query(
    _C_LANGUAGE,
    """
    (unary_expression
        operator: "!"
        argument: (unary_expression
            operator: "!"
            argument: (identifier) @ident)) @expr
""",
)

_QUERY_GOTO_RET_FALSE = ts.Query(
    _C_LANGUAGE,
    """
    (goto_statement
        (statement_identifier) @lbl
        (#eq? @lbl "ret_false")) @expr
""",
)

_QUERY_IF_ELSE = ts.Query(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond
        consequence: (_) @cons
        alternative: (else_clause (_) @alt)) @expr
""",
)

_QUERY_RHS_IDENT = ts.Query(
    _C_LANGUAGE,
    """
    [
        (assignment_expression right: (identifier) @expr)
        (init_declarator value: (identifier) @expr)
        (return_statement (identifier) @expr)
        (argument_list (identifier) @expr)
    ]
""",
)

_QUERY_REMOVE_CAST = ts.Query(
    _C_LANGUAGE,
    """
    (cast_expression
        type: (type_descriptor) @type
        value: (_) @val
        (#match? @type "^(DWORD|int|BOOL|unsigned int)$")) @expr
""",
)

_QUERY_DECLARATION = ts.Query(
    _C_LANGUAGE,
    """
    (declaration) @expr
""",
)

_QUERY_IF_FALSE_BITAND = ts.Query(
    _C_LANGUAGE,
    """
    [
      (if_statement
          condition: (parenthesized_expression (unary_expression operator: "!" argument: (_) @cond))
          consequence: (expression_statement (assignment_expression left: (identifier) @var right: (number_literal) @false_val (#match? @false_val "^0|FALSE$")))) @expr

      (if_statement
          condition: (parenthesized_expression (unary_expression operator: "!" argument: (_) @cond))
          consequence: (compound_statement (expression_statement (assignment_expression left: (identifier) @var right: (number_literal) @false_val (#match? @false_val "^0|FALSE$"))))) @expr
    ]
""",
)

_QUERY_ELSE_IF = ts.Query(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond1
        consequence: (_) @cons1
        alternative: (else_clause
            (if_statement
                condition: (parenthesized_expression) @cond2
                consequence: (_) @cons2
            )
        )
    ) @expr
""",
)

_QUERY_BITAND = ts.Query(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression left: (identifier) @var operator: "&=" right: (_) @expr)
    ) @stmt
""",
)

_QUERY_CALL_ASSIGN = ts.Query(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression left: (identifier) @var right: (call_expression) @call)
    ) @expr
""",
)

_QUERY_TEMP_VAR = ts.Query(
    _C_LANGUAGE,
    """
    (compound_statement
        (expression_statement (assignment_expression left: (identifier) @tmp right: (_) @stmt)) @stmt1
        .
        (expression_statement (assignment_expression left: (identifier) @var right: (identifier) @tmp2 (#eq? @tmp @tmp2))) @stmt2
    )
""",
)

_QUERY_ADJACENT_DECL = ts.Query(
    _C_LANGUAGE,
    """
    (compound_statement
        (declaration) @d1
        .
        (declaration) @d2
    )
""",
)

_QUERY_SPLIT_DECL = ts.Query(
    _C_LANGUAGE,
    """
    (declaration
        type: (_) @type
        declarator: (init_declarator
            declarator: (identifier) @var
            value: (_) @expr
        )
    ) @stmt
""",
)

_QUERY_MERGE_DECL = ts.Query(
    _C_LANGUAGE,
    """
    (compound_statement
        (declaration type: (_) @type declarator: (identifier) @decl) @d1
        .
        (expression_statement (assignment_expression left: (identifier) @var right: (_) @init_expr (#eq? @decl @var))) @d2
    )
""",
)

_QUERY_WHILE = ts.Query(
    _C_LANGUAGE,
    """
    (while_statement
        condition: (parenthesized_expression) @cond
        body: (compound_statement) @body
    ) @stmt
""",
)

_QUERY_DO_WHILE = ts.Query(
    _C_LANGUAGE,
    """
    (do_statement
        body: (compound_statement) @body
        condition: (parenthesized_expression) @cond
    ) @stmt
""",
)

_QUERY_EARLY_RETURN = ts.Query(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression (unary_expression operator: "!" argument: (_) @expr))
        consequence: [
            (return_statement (number_literal) @ret_val (#match? @ret_val "^0$"))
            (compound_statement (return_statement (number_literal) @ret_val (#match? @ret_val "^0$")))
        ]
    ) @stmt
""",
)

_QUERY_ACCUM = ts.Query(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression left: (identifier) @var operator: "&=" right: (_) @expr (#match? @var "^(ret|retcode|result)$"))
    ) @stmt
""",
)

_QUERY_PTR_PARAM = ts.Query(
    _C_LANGUAGE,
    """
    (parameter_declaration type: (_) @type declarator: (pointer_declarator declarator: (identifier) @var) @ptr_decl) @stmt
""",
)

_QUERY_INT_PARAM = ts.Query(
    _C_LANGUAGE,
    """
    (parameter_declaration type: (primitive_type) @type declarator: (identifier) @var (#eq? @type "int")) @expr
""",
)

_QUERY_CONST_ADD_FOLD = ts.Query(
    _C_LANGUAGE,
    """
    (compound_statement
        (expression_statement (assignment_expression left: (identifier) @v1 operator: "=" right: (binary_expression left: (identifier) @v2 operator: "+" right: (number_literal) @n1 (#eq? @v1 @v2)))) @stmt1
        .
        (expression_statement (assignment_expression left: (identifier) @v3 operator: "=" right: (binary_expression left: (identifier) @v4 operator: "+" right: (number_literal) @n2 (#eq? @v3 @v4) (#eq? @v1 @v3)))) @stmt2
    )
""",
)

_QUERY_CONST_ADD_UNFOLD = ts.Query(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression left: (identifier) @v1 operator: "=" right: (binary_expression left: (identifier) @v2 operator: "+" right: (number_literal) @n (#eq? @v1 @v2)))
    ) @stmt
""",
)

_QUERY_ARRAY_INDEX = ts.Query(
    _C_LANGUAGE,
    """
    (subscript_expression argument: (_) @arr index: (_) @idx) @expr
""",
)

_QUERY_PTR_ARROW = ts.Query(
    _C_LANGUAGE,
    """
    (field_expression argument: (_) @ptr "->" field: (field_identifier) @field) @expr
""",
)

_QUERY_RETURN_TYPE = ts.Query(
    _C_LANGUAGE,
    """
    (function_definition type: (primitive_type) @expr declarator: (_))
""",
)

_QUERY_PTR_PARAM = ts.Query(
    _C_LANGUAGE,
    """
    (parameter_declaration type: (primitive_type) @type declarator: (pointer_declarator declarator: (identifier) @var)) @stmt
""",
)

_QUERY_NESTED_IF_P3 = ts.Query(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond1
        consequence: (compound_statement
            (if_statement
                condition: (parenthesized_expression) @cond2
                consequence: (_) @body) @inner_if) @outer_body) @stmt
""",
)


_QUERY_CALL_ARG = ts.Query(
    _C_LANGUAGE,
    """
    (expression_statement
        (call_expression
            arguments: (argument_list
                (_) @arg)) @call) @stmt
""",
)


def mut_extract_args_to_temps(s: str, rng: random.Random) -> str | None:
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)
    cursor = ts.QueryCursor(_QUERY_CALL_ARG)
    matches = cursor.matches(tree.root_node)

    valid_args = []
    for match in matches:
        # get nodes
        nodes = {k: (v[0] if isinstance(v, list) else v) for k, v in match[1].items()}
        stmt = nodes.get("stmt")
        arg = nodes.get("arg")
        if not stmt or not arg:
            continue

        # Check if arg is complex (not a literal or identifier)
        if arg.type in ("identifier", "number_literal", "string_literal", "char_literal"):
            continue

        valid_args.append((stmt, arg))

    if not valid_args:
        return None

    stmt, arg = rng.choice(valid_args)

    arg_str = b_source[arg.start_byte : arg.end_byte]

    var_id = rng.randint(0, 999)
    var_name = f"_tmp_{var_id}".encode()

    # C89: hoist declaration to function body top, keep assignment inline
    insert_pos = _find_function_body_insert_pos(b_source, stmt.start_byte)
    if insert_pos is None:
        return None

    hoisted_decl = b"\n    int " + var_name + b";"
    inline_assign = var_name + b" = " + arg_str + b";\n    "
    new_stmt_str = (
        b_source[stmt.start_byte : arg.start_byte]
        + var_name
        + b_source[arg.end_byte : stmt.end_byte]
    )

    # Insert hoisted decl first (adjusting offsets for the insertion)
    out = b_source[:insert_pos] + hoisted_decl + b_source[insert_pos:]
    # Adjust byte offsets by the length of the hoisted decl
    offset = len(hoisted_decl)
    stmt_start = stmt.start_byte + offset
    stmt_end = stmt.end_byte + offset
    arg_start = arg.start_byte + offset
    arg_end = arg.end_byte + offset
    new_stmt_str = out[stmt_start:arg_start] + var_name + out[arg_end:stmt_end]

    return (out[:stmt_start] + inline_assign + new_stmt_str + out[stmt_end:]).decode("utf-8")


_QUERY_WHILE_LOOP = ts.Query(
    _C_LANGUAGE,
    """
    (while_statement condition: (_) @cond body: (compound_statement) @body) @stmt
""",
)

_QUERY_SPLIT_CMP_CHAIN = ts.Query(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression
            (binary_expression left: (_) @left operator: "&&" right: (_) @right)
        )
        consequence: (compound_statement) @body
    ) @stmt
""",
)

_QUERY_MERGE_CMP_CHAIN = ts.Query(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond1
        consequence: (compound_statement
            (if_statement
                condition: (parenthesized_expression) @cond2
                consequence: (compound_statement) @body
            )
        ) @stmt2
    ) @stmt
""",
)

_QUERY_COMBINE_PTR_ARITH = ts.Query(
    _C_LANGUAGE,
    """
    (compound_statement
        (expression_statement (assignment_expression left: (identifier) @v1 right: (binary_expression left: (identifier) @v2 operator: "+" right: (number_literal) @n1))) @stmt1
        (expression_statement (assignment_expression left: (identifier) @v3 right: (binary_expression left: (identifier) @v4 operator: "+" right: (number_literal) @n2))) @stmt2
        (#eq? @v1 @v2)
        (#eq? @v2 @v3)
        (#eq? @v3 @v4)
    )
""",
)

_QUERY_SPLIT_PTR_ARITH = ts.Query(
    _C_LANGUAGE,
    """
    (expression_statement (assignment_expression left: (identifier) @v1 right: (binary_expression left: (identifier) @v2 operator: "+" right: (number_literal) @n1))) @stmt
    (#eq? @v1 @v2)
""",
)

_QUERY_PARAM_ORDER = ts.Query(
    _C_LANGUAGE,
    """
    (function_definition declarator: (function_declarator parameters: (parameter_list) @expr))
""",
)

_QUERY_CALL_CONV = ts.Query(
    _C_LANGUAGE,
    """
    (function_definition (ms_call_modifier) @expr)
""",
)

_QUERY_NO_CALL_CONV = ts.Query(
    _C_LANGUAGE,
    """
    (function_definition type: (_) @type declarator: (function_declarator declarator: (identifier) @name)) @stmt
""",
)

_QUERY_CHAR_TYPE = ts.Query(
    _C_LANGUAGE,
    """
    (primitive_type) @expr
""",
)

_QUERY_CMP_BOUNDARY = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression left: (_) @left operator: [">" ">=" "<" "<="] @op right: (number_literal) @num) @expr
""",
)

# Note: Tree-sitter might see some macros or types differently.
_QUERY_RETURN_FALSE = ts.Query(
    _C_LANGUAGE,
    """
    (return_statement
        (number_literal) @val
        (#match? @val "^0|FALSE$")) @expr
""",
)  # But for typical C code generated/decompiled, these work well.


# ---------------------------------------------------------------------------
# Queries for structural/code-layout mutations (formerly regex-only)
# ---------------------------------------------------------------------------

_QUERY_NESTED_IF = ts.Query(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @outer_cond
        consequence: (compound_statement
            (if_statement
                condition: (parenthesized_expression) @inner_cond
                consequence: (compound_statement) @inner_body
            ) @inner_if
        ) @outer_body
    ) @expr
""",
)

_QUERY_FOR_LOOP = ts.Query(
    _C_LANGUAGE,
    """
    (for_statement
        initializer: (_)? @init
        condition: (_)? @cond
        update: (_)? @update
        body: (compound_statement) @body
    ) @stmt
""",
)

_QUERY_IF_ASSIGN_ELSE = ts.Query(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond
        consequence: [
            (expression_statement (assignment_expression left: (identifier) @var1 right: (_) @val1))
            (compound_statement (expression_statement (assignment_expression left: (identifier) @var1 right: (_) @val1)))
        ]
        alternative: (else_clause [
            (expression_statement (assignment_expression left: (identifier) @var2 right: (_) @val2))
            (compound_statement (expression_statement (assignment_expression left: (identifier) @var2 right: (_) @val2)))
        ])
    ) @expr
""",
)

_QUERY_TERNARY = ts.Query(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression
            left: (identifier) @var
            right: (conditional_expression
                condition: (_) @cond
                consequence: (_) @val_true
                alternative: (_) @val_false
            )
        )
    ) @expr
""",
)

_QUERY_ADJACENT_EXPR_STMTS = ts.Query(
    _C_LANGUAGE,
    """
    (compound_statement
        (expression_statement) @s1
        .
        (expression_statement) @s2
    )
""",
)

_QUERY_COMPOUND_ASSIGN = ts.Query(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression
            left: (identifier) @var
            operator: ["+=" "-=" "*=" "|=" "&=" "^="] @op
            right: (_) @rhs
        )
    ) @expr
""",
)

_QUERY_EXPANDED_COMPOUND = ts.Query(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression
            left: (identifier) @var
            operator: "="
            right: (binary_expression
                left: (identifier) @var2
                operator: ["+" "-" "*" "|" "&" "^"] @op
                right: (_) @rhs
            )
        )
    ) @expr
""",
)

_QUERY_DEMORGAN_NOT_AND = ts.Query(
    _C_LANGUAGE,
    """
    (unary_expression
        operator: "!"
        argument: (parenthesized_expression
            (binary_expression
                left: (_) @a
                operator: "&&"
                right: (_) @b
            )
        )
    ) @expr
""",
)

_QUERY_DEMORGAN_NOT_OR = ts.Query(
    _C_LANGUAGE,
    """
    (unary_expression
        operator: "!"
        argument: (parenthesized_expression
            (binary_expression
                left: (_) @a
                operator: "||"
                right: (_) @b
            )
        )
    ) @expr
""",
)

_QUERY_POST_INCREMENT = ts.Query(
    _C_LANGUAGE,
    """
    (update_expression argument: (identifier) @var operator: "++") @expr
""",
)

_QUERY_POST_DECREMENT = ts.Query(
    _C_LANGUAGE,
    """
    (update_expression argument: (identifier) @var operator: "--") @expr
""",
)

_QUERY_ASSIGN_ZERO = ts.Query(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression
            left: (identifier) @var
            operator: "="
            right: (number_literal) @val
            (#eq? @val "0")
        )
    ) @expr
""",
)

_QUERY_XOR_SELF = ts.Query(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression
            left: (identifier) @var
            operator: "^="
            right: (identifier) @var2
            (#eq? @var @var2)
        )
    ) @expr
""",
)

_QUERY_FOR_COUNT_UP = ts.Query(
    _C_LANGUAGE,
    """
    (for_statement
        initializer: (assignment_expression
            left: (identifier) @var
            right: (number_literal) @zero
            (#eq? @zero "0")
        )
        condition: (binary_expression
            left: (identifier) @var2
            operator: "<"
            right: (_) @limit
            (#eq? @var @var2)
        )
        update: (update_expression
            argument: (identifier) @var3
            operator: "++"
            (#eq? @var @var3)
        )
        body: (compound_statement) @body
    ) @stmt
""",
)

_QUERY_IF_BODY_RETURN = ts.Query(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond
        consequence: (compound_statement) @if_body
        alternative: (else_clause
            (compound_statement) @else_body
        )
    ) @expr
""",
)


def _find_function_body_insert_pos(source: bytes, ref_byte: int) -> int | None:
    """Find the insert position for a declaration at the top of the enclosing function body.

    Walks up the tree-sitter AST from *ref_byte* to find the enclosing
    ``function_definition`` → ``compound_statement`` and returns the byte
    offset right after the opening ``{``.  Returns *None* if no enclosing
    function body is found.

    This is used to hoist variable declarations so that they comply with
    C89 scoping rules (all declarations before any statements).
    """
    tree = parse_c_ast(source)
    # Find the deepest node at ref_byte and walk up to find function body
    node = tree.root_node.descendant_for_byte_range(ref_byte, ref_byte)
    while node is not None:
        if node.type == "compound_statement":
            parent = node.parent
            if parent is not None and parent.type == "function_definition":
                # Return position right after the opening brace
                return node.start_byte + 1
        node = node.parent
    return None


def _apply_query_once(
    source: bytes,
    query: ts.Query,
    repl: Callable[[dict[str, ts.Node]], bytes],
    rng: random.Random,
) -> bytes | None:
    """Apply an AST query and replace one matched occurrence."""
    tree = parse_c_ast(source)
    cursor = ts.QueryCursor(query)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    # Match is a tuple of (pattern_index, dict_of_captures)
    # We want a random match
    _, captures = rng.choice(matches)

    # captures is a dict mapping capture name (e.g. "expr") to a list of Nodes
    # We assume one node per capture name in our queries
    single_captures = {k: v[0] for k, v in captures.items()}

    target_node = single_captures.get("stmt") or single_captures.get("expr")
    if not target_node:
        return None

    replacement = repl(single_captures)

    return ASTMutator.replace_node(source, target_node, replacement)


# --- Mutations ---


def mut_commute_simple_add(s: str, rng: random.Random) -> str | None:
    """Swap operands of simple identifier addition."""
    return _commute_operands(s, rng, _QUERY_COMMUTE_ADD, b"+")


def mut_commute_simple_mul(s: str, rng: random.Random) -> str | None:
    """Swap operands of simple identifier multiplication."""
    return _commute_operands(s, rng, _QUERY_COMMUTE_MUL, b"*")


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

    AST makes this safe vs wrapping keywords like 'return'.
    """
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        ident = b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        return b"(" + ident + b")"

    res = _apply_query_once(b_source, _QUERY_IDENTIFIER, _repl, rng)
    return res.decode("utf-8") if res else None


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

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        return b"goto ret_false;"

    res = _apply_query_once(b_source, _QUERY_RETURN_FALSE, _repl, rng)
    if not res:
        return None

    result = res.decode("utf-8")

    # Needs to add ret_false: before the last return statement
    # We will use regex for the fallback label injection for now since it operates on the whole block
    import re

    _RE_FINAL_RET = re.compile(
        r"(\s+return[^;]+;[ \t]*\n[ \t]*\}(?:\s*|//.*)*)$(?![\s\S]*\})", re.MULTILINE
    )
    final_ret = _RE_FINAL_RET.search(result)
    if final_ret:
        pos = final_ret.start(1)
        result = result[:pos] + "\nret_false:\n" + result[pos:]
    else:
        # Fallback: add before closing brace
        last_brace = result.rfind("}")
        if last_brace >= 0:
            result = result[:last_brace] + "ret_false:\n    return 0;\n" + result[last_brace:]

    return result


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
        import re

        result = re.sub(r"^[ \t]*ret_false:[ \t]*\n", "", result, flags=re.MULTILINE)
        result = re.sub(r"^[ \t]*ret_false:[ \t]*", "", result, flags=re.MULTILINE)

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

        return b"if (" + negated_cond + b") " + alt + b" else " + cons

    res = _apply_query_once(b_source, _QUERY_IF_ELSE, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_add_cast(s: str, rng: random.Random) -> str | None:
    """Wrap an expression in (BOOL) or (int) cast."""
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
    """Swap two branches in an else-if chain."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        cond1 = b_source[captures["cond1"].start_byte : captures["cond1"].end_byte]
        cons1 = b_source[captures["cons1"].start_byte : captures["cons1"].end_byte]
        cond2 = b_source[captures["cond2"].start_byte : captures["cond2"].end_byte]
        cons2 = b_source[captures["cons2"].start_byte : captures["cons2"].end_byte]

        return b"if " + cond2 + b" " + cons2 + b" else if " + cond1 + b" " + cons1

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
    cursor = ts.QueryCursor(_QUERY_CALL_ASSIGN)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    _, captures = rng.choice(matches)
    single_captures = {k: v[0] for k, v in captures.items()}

    target_node = single_captures.get("expr")
    if not target_node:
        return None

    var = b_source[single_captures["var"].start_byte : single_captures["var"].end_byte]
    call = b_source[single_captures["call"].start_byte : single_captures["call"].end_byte]

    # Inline replacement: tmp = call(); var = tmp;
    inline_repl = b"tmp = " + call + b";\n    " + var + b" = tmp;"

    if b"tmp" in b_source:
        # 'tmp' already declared somewhere — just use it, no hoisting needed
        res = ASTMutator.replace_node(b_source, target_node, inline_repl)
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
    cursor = ts.QueryCursor(_QUERY_TEMP_VAR)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    captures = {k: v[0] for k, v in match[1].items()}

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
    cursor = ts.QueryCursor(_QUERY_ADJACENT_DECL)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    captures = {k: v[0] for k, v in match[1].items()}

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
    cursor = ts.QueryCursor(_QUERY_MERGE_DECL)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    captures = {k: v[0] for k, v in match[1].items()}

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
            raise ValueError()
        return b"while " + cond + b" {\n    " + inner + b"\n    " + inner + b"\n}"

    try:
        res = _apply_query_once(b_source, _QUERY_WHILE, _repl, rng)
        return res.decode("utf-8") if res else None
    except ValueError:
        return None


def mut_fold_constant_add(s: str, rng: random.Random) -> str | None:
    b_source = s.encode("utf-8")
    cursor = ts.QueryCursor(_QUERY_CONST_ADD_FOLD)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid_matches = []
    for match in matches:
        captures = {k: v[0] for k, v in match[1].items()}
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


def mut_unfold_constant_add(s: str, rng: random.Random) -> str | None:
    b_source = s.encode("utf-8")
    cursor = ts.QueryCursor(_QUERY_CONST_ADD_UNFOLD)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid_matches = []
    for match in matches:
        captures = {k: v[0] for k, v in match[1].items()}
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
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        arr = b_source[captures["arr"].start_byte : captures["arr"].end_byte]
        idx = b_source[captures["idx"].start_byte : captures["idx"].end_byte]
        return idx + b"[" + arr + b"]"

    res = _apply_query_once(b_source, _QUERY_ARRAY_INDEX, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_struct_vs_ptr_access(s: str, rng: random.Random) -> str | None:
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        ptr = b_source[captures["ptr"].start_byte : captures["ptr"].end_byte]
        field = b_source[captures["field"].start_byte : captures["field"].end_byte]
        return b"(*" + ptr + b")." + field

    res = _apply_query_once(b_source, _QUERY_PTR_ARROW, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_change_return_type(s: str, rng: random.Random) -> str | None:
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


def mut_split_cmp_chain(s: str, rng: random.Random) -> str | None:
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        body = b_source[captures["body"].start_byte : captures["body"].end_byte]
        return b"if (" + left + b") { if (" + right + b") " + body + b" }"

    res = _apply_query_once(b_source, _QUERY_SPLIT_CMP_CHAIN, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_merge_cmp_chain(s: str, rng: random.Random) -> str | None:
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        cond1 = b_source[captures["cond1"].start_byte + 1 : captures["cond1"].end_byte - 1]
        cond2 = b_source[captures["cond2"].start_byte + 1 : captures["cond2"].end_byte - 1]
        body = b_source[captures["body"].start_byte : captures["body"].end_byte]
        return b"if ((" + cond1 + b") && (" + cond2 + b")) " + body

    res = _apply_query_once(b_source, _QUERY_MERGE_CMP_CHAIN, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_combine_ptr_arith(s: str, rng: random.Random) -> str | None:
    b_source = s.encode("utf-8")
    cursor = ts.QueryCursor(_QUERY_COMBINE_PTR_ARITH)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid_matches: list[tuple[dict[str, ts.Node], int, int]] = []
    for match in matches:
        captures = {k: v[0] for k, v in match[1].items()}
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
    b_source = s.encode("utf-8")
    cursor = ts.QueryCursor(_QUERY_SPLIT_PTR_ARITH)

    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid_matches: list[tuple[dict[str, ts.Node], int]] = []
    for match in matches:
        if not match[1]:
            continue
        captures = {k: v[0] for k, v in match[1].items()}
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

    # No existing convention — insert one before the type
    def _repl_insert(captures: dict[str, ts.Node]) -> bytes:
        t = b_source[captures["type"].start_byte : captures["type"].end_byte]
        conv = rng.choice([b"__cdecl", b"__stdcall"])
        return t + b" " + conv

    res = _apply_query_once(b_source, _QUERY_NO_CALL_CONV, _repl_insert, rng)
    return res.decode("utf-8") if res is not None else None


def mut_toggle_char_signedness(s: str, rng: random.Random) -> str | None:
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        t = b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        mapping = {
            b"char": b"unsigned char",
            b"unsigned char": b"signed char",
            b"signed char": b"char",
        }
        return mapping.get(t, t)

    res = _apply_query_once(b_source, _QUERY_CHAR_TYPE, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_comparison_boundary(s: str, rng: random.Random) -> str | None:
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
    q = ts.Query(
        _C_LANGUAGE,
        """(compound_statement [(expression_statement) (declaration) (return_statement)] @stmt)""",
    )
    cursor = ts.QueryCursor(q)
    matches = cursor.matches(tree.root_node)
    if not matches:
        return None
    match = rng.choice(matches)
    captures = {k: v[0] for k, v in match[1].items()}
    stmt_node = captures["stmt"]
    noop = b"if (0) {} "
    start = stmt_node.start_byte
    return (b_source[:start] + noop + b_source[start:]).decode("utf-8")


def mut_introduce_local_alias(s: str, rng: random.Random) -> str | None:
    """Introduce a local alias for an identifier used in an expression statement."""
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    q = ts.Query(
        _C_LANGUAGE,
        """(expression_statement (assignment_expression right: (identifier) @var)) @stmt""",
    )
    cursor = ts.QueryCursor(q)
    matches = cursor.matches(tree.root_node)
    if not matches:
        return None
    match = rng.choice(matches)
    captures = {k: v[0] for k, v in match[1].items()}
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
    q = ts.Query(
        _C_LANGUAGE,
        """
        (compound_statement (declaration) @d1 (declaration) @d2)
    """,
    )
    cursor = ts.QueryCursor(q)
    matches = cursor.matches(tree.root_node)
    if not matches:
        return None
    match = rng.choice(matches)
    captures = {k: v[0] for k, v in match[1].items()}
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
            if _RE_FUNC_START.match(line):
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
    labels: set[str] = set()
    for m in _RE_VALIDATE_LABEL.finditer(source):
        label = m.group(1)
        if label in _LABEL_IGNORE:
            continue
        if label in labels:
            return False
        labels.add(label)
    return not _RE_VALIDATE_DOUBLE_TYPE.search(source)


def compute_population_diversity(pop: list[str]) -> float:
    """Compute diversity of the population (0.0 to 1.0)."""
    if not pop or len(pop) < 2:
        return 0.0
    return len(set(pop)) / len(pop)


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


def mut_flatten_nested_if(s: str, rng: random.Random) -> str | None:
    """Flatten nested if into && chain.

    Changes:  if (a) { if (b) { body } }  ->  if (a && b) { body }
    """
    b_source = s.encode("utf-8")
    cursor = ts.QueryCursor(_QUERY_NESTED_IF)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    # Filter: outer body must contain ONLY the inner if (no other stmts)
    valid = []
    for match in matches:
        caps = {k: v[0] for k, v in match[1].items()}
        outer_body = caps["outer_body"]
        # Count named children that are actual statements (not just braces)
        stmts = [c for c in outer_body.named_children]
        if len(stmts) == 1 and stmts[0].type == "if_statement":
            valid.append(caps)

    if not valid:
        return None

    caps = rng.choice(valid)
    outer_cond = b_source[caps["outer_cond"].start_byte + 1 : caps["outer_cond"].end_byte - 1]
    inner_cond = b_source[caps["inner_cond"].start_byte + 1 : caps["inner_cond"].end_byte - 1]
    inner_body = b_source[caps["inner_body"].start_byte : caps["inner_body"].end_byte]

    replacement = b"if (" + outer_cond.strip() + b" && " + inner_cond.strip() + b") " + inner_body
    result = b_source[: caps["expr"].start_byte] + replacement + b_source[caps["expr"].end_byte :]
    return result.decode("utf-8")


def mut_extract_else_body(s: str, rng: random.Random) -> str | None:
    """Convert if/else to negated-condition early exit.

    Changes:  if (c) { A } else { B }  ->  if (!(c)) { B; return 0; } A
    """
    b_source = s.encode("utf-8")
    cursor = ts.QueryCursor(_QUERY_IF_BODY_RETURN)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}

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

    replacement = b"if (" + neg_cond + b") {" + else_body + b"\n        return 0;\n    }" + if_body
    result = b_source[: caps["expr"].start_byte] + replacement + b_source[caps["expr"].end_byte :]
    return result.decode("utf-8")


def mut_for_to_while(s: str, rng: random.Random) -> str | None:
    """Convert for loop to while loop.

    Changes:  for (i=0; i<n; i++) { body }  ->  i=0; while (i<n) { body i++; }
    """
    b_source = s.encode("utf-8")
    cursor = ts.QueryCursor(_QUERY_FOR_LOOP)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}

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
    cursor = ts.QueryCursor(_QUERY_IF_ASSIGN_ELSE)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    # Filter: both assignments must target the same variable
    valid = []
    for match in matches:
        caps = {k: v[0] for k, v in match[1].items()}
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
    cursor = ts.QueryCursor(_QUERY_TERNARY)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}

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
    q = ts.Query(_C_LANGUAGE, "(return_statement (_) @val) @stmt")
    cursor = ts.QueryCursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}
    val = b_source[caps["val"].start_byte : caps["val"].end_byte]
    stmt = caps["stmt"]

    ret_var = b"ret" if b"retcode" not in b_source else b"retval"
    if ret_var in b_source:
        ret_var = b"retval"
    if ret_var in b_source:
        return None

    replacement = ret_var + b" = " + val + b";\n    goto end;"
    result = b_source[: stmt.start_byte] + replacement + b_source[stmt.end_byte :]

    # Add end label before the last closing brace
    last_brace = result.rfind(b"}")
    if last_brace >= 0:
        result = (
            result[:last_brace] + b"\nend:\n    return " + ret_var + b";\n" + result[last_brace:]
        )

    return result.decode("utf-8")


def mut_sink_return(s: str, rng: random.Random) -> str | None:
    """Collapse ret=expr; goto end; back to return expr.

    Inverse of mut_hoist_return.
    """
    b_source = s.encode("utf-8")
    if b"goto end;" not in b_source:
        return None

    # Use regex since this is a multi-statement pattern
    pat = re.compile(rb"(\w+)\s*=\s*([^;]+);\s*\n\s*goto\s+end\s*;")
    all_m = list(pat.finditer(b_source))
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
    cursor = ts.QueryCursor(_QUERY_ADJACENT_EXPR_STMTS)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    # Filter: only swap assignment statements, check no dependencies
    valid = []
    for match in matches:
        caps = {k: v[0] for k, v in match[1].items()}
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
    pat = re.compile(
        rb"([ \t]*)if\s*\(([^)]+)\)\s*\{([^}]+)return\s+([^;]+);\s*\}\s*\n\s*\1return\s+([^;]+);"
    )
    all_m = list(pat.finditer(b_source))
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
    cursor = ts.QueryCursor(_QUERY_FOR_COUNT_UP)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}

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
    expand_cursor = ts.QueryCursor(_QUERY_COMPOUND_ASSIGN)
    tree = parse_c_ast(b_source)
    expand_matches = [(m, "expand") for m in expand_cursor.matches(tree.root_node)]

    # Try shortening expanded (x = x + n -> x += n)
    short_cursor = ts.QueryCursor(_QUERY_EXPANDED_COMPOUND)
    short_matches = []
    for m in short_cursor.matches(tree.root_node):
        caps = {k: v[0] for k, v in m[1].items()}
        var = b_source[caps["var"].start_byte : caps["var"].end_byte]
        var2 = b_source[caps["var2"].start_byte : caps["var2"].end_byte]
        if var == var2:
            short_matches.append((m, "shorten"))

    all_matches = expand_matches + short_matches
    if not all_matches:
        return None

    match, direction = rng.choice(all_matches)
    caps = {k: v[0] for k, v in match[1].items()}

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

    target = caps.get("expr") or caps.get("stmt")
    if target is None:
        return None
    result = b_source[: target.start_byte] + replacement + b_source[target.end_byte :]
    return result.decode("utf-8")


def mut_demorgan(s: str, rng: random.Random) -> str | None:
    """Apply De Morgan's law: !(a && b) <-> (!a || !b)."""
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    and_cursor = ts.QueryCursor(_QUERY_DEMORGAN_NOT_AND)
    and_matches = [(m, "and") for m in and_cursor.matches(tree.root_node)]

    or_cursor = ts.QueryCursor(_QUERY_DEMORGAN_NOT_OR)
    or_matches = [(m, "or") for m in or_cursor.matches(tree.root_node)]

    all_matches = and_matches + or_matches
    if not all_matches:
        return None

    match, kind = rng.choice(all_matches)
    caps = {k: v[0] for k, v in match[1].items()}

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
        cursor = ts.QueryCursor(q)
        for m in cursor.matches(tree.root_node):
            caps = {k: v[0] for k, v in m[1].items()}
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

    zero_cursor = ts.QueryCursor(_QUERY_ASSIGN_ZERO)
    for m in zero_cursor.matches(tree.root_node):
        caps = {k: v[0] for k, v in m[1].items()}
        # Skip if inside a for-loop initializer
        parent = caps["expr"].parent
        if parent and parent.type == "for_statement":
            continue
        var = b_source[caps["var"].start_byte : caps["var"].end_byte]
        if b"." in var or b"->" in var or b"[" in var:
            continue
        candidates.append((caps, var + b" ^= " + var + b";", "expr"))

    xor_cursor = ts.QueryCursor(_QUERY_XOR_SELF)
    for m in xor_cursor.matches(tree.root_node):
        caps = {k: v[0] for k, v in m[1].items()}
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

    q = ts.Query(_C_LANGUAGE, "(if_statement condition: (parenthesized_expression) @cond) @stmt")
    cursor = ts.QueryCursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}
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


# ---------------------------------------------------------------------------
# MSVC6-targeted structural mutations (2026-03 batch)
# ---------------------------------------------------------------------------

_QUERY_IF_STMT = ts.Query(_C_LANGUAGE, "(if_statement) @if_stmt")

# --- Queries for new mutations ---

_QUERY_SUBSCRIPT_EXPR = ts.Query(
    _C_LANGUAGE,
    """
    (subscript_expression argument: (_) @arr index: (_) @idx) @expr
""",
)

_QUERY_BIN_COND_IF = ts.Query(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression (binary_expression
            left: (_) @left
            right: (_) @right) @bin)
        consequence: (_) @body) @stmt
""",
)

_QUERY_NESTED_IF_P3 = ts.Query(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond1
        consequence: (compound_statement
            (if_statement
                condition: (parenthesized_expression) @cond2
                consequence: (_) @body) @inner_if) @outer_body) @stmt
""",
)

_QUERY_NESTED_IF_P3 = ts.Query(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond1
        consequence: (compound_statement
            (if_statement
                condition: (parenthesized_expression) @cond2
                consequence: (_) @body) @inner_if) @outer_body) @stmt
""",
)


_QUERY_WHILE_LOOP = ts.Query(
    _C_LANGUAGE,
    """
    (while_statement
        condition: (parenthesized_expression) @cond
        body: (_) @body) @stmt
""",
)

_QUERY_DEREF_PTR_ADD = ts.Query(
    _C_LANGUAGE,
    """
    (pointer_expression
        operator: "*"
        argument: (parenthesized_expression
            (binary_expression left: (_) @ptr operator: "+" right: (_) @idx)
        )
    ) @expr
""",
)

_QUERY_SUBSCRIPT_SCALED = ts.Query(
    _C_LANGUAGE,
    """
    (subscript_expression
        argument: (_) @arr
        index: (binary_expression left: (_) @idx_left operator: "*" right: (_) @idx_right)
    ) @expr
""",
)

_QUERY_BYTE_TYPE_DECL = ts.Query(
    _C_LANGUAGE,
    """
    (declaration
        type: (primitive_type) @type
        declarator: (init_declarator
            declarator: (identifier) @var
            value: (_) @init
        )
        (#match? @type "^(char|BYTE|unsigned char|signed char)$")
    ) @stmt
""",
)

_QUERY_BYTE_CAST = ts.Query(
    _C_LANGUAGE,
    """
    (cast_expression
        type: (type_descriptor) @type
        value: (_) @val
        (#match? @type "^(WORD|BYTE|unsigned short|unsigned char)$")
    ) @expr
""",
)

_QUERY_REGISTER_DECL = ts.Query(
    _C_LANGUAGE,
    """
    (declaration
        (storage_class_specifier) @sc
        (#eq? @sc "register")
    ) @stmt
""",
)


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
    cursor = ts.QueryCursor(_QUERY_WHILE_LOOP)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}

    cond = b_source[caps["cond"].start_byte : caps["cond"].end_byte]
    body = b_source[caps["body"].start_byte : caps["body"].end_byte]

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
    q = ts.Query(_C_LANGUAGE, "(function_definition body: (compound_statement) @body)")
    cursor = ts.QueryCursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}
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

    q = ts.Query(_C_LANGUAGE, "(function_definition body: (compound_statement) @body)")
    cursor = ts.QueryCursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}
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
    q = ts.Query(
        _C_LANGUAGE,
        """
        (function_definition body: (compound_statement
            (declaration type: (_) @type declarator: (_) @decl) @d1
            .
            (expression_statement) @next_stmt
        ))
    """,
    )
    cursor = ts.QueryCursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}

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

    Rewrite p[i * N] to { int _off = i * N; p[_off]; }
    This forces MSVC6 to compute the offset separately instead of
    folding it into a lea instruction.
    """
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        arr = b_source[captures["arr"].start_byte : captures["arr"].end_byte]
        idx_left = b_source[captures["idx_left"].start_byte : captures["idx_left"].end_byte]
        idx_right = b_source[captures["idx_right"].start_byte : captures["idx_right"].end_byte]

        off_id = random.randint(0, 99)
        off_name = f"_off_{off_id}".encode()
        if off_name in b_source:
            return b_source[captures["expr"].start_byte : captures["expr"].end_byte]

        return (
            off_name + b" = " + idx_left + b" * " + idx_right + b", " + arr + b"[" + off_name + b"]"
        )

    res = _apply_query_once(b_source, _QUERY_SUBSCRIPT_SCALED, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None


# --- Category 4: Zero-Extension & Register Clearing ---


def mut_preinit_byte_load(s: str, rng: random.Random) -> str | None:
    """Pre-initialize byte-width variable to trigger xor reg, reg pattern.

    Rewrites: char c = *p;  -->  int c = 0; c = *p;
    MSVC6 emits xor eax, eax + mov al, [mem] instead of movzx.
    """
    b_source = s.encode("utf-8")
    cursor = ts.QueryCursor(_QUERY_BYTE_TYPE_DECL)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}

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
    q_all = ts.Query(_C_LANGUAGE, "(declaration) @decl")
    cursor_all = ts.QueryCursor(q_all)
    all_decls = cursor_all.matches(tree.root_node)

    if len(all_decls) < 2:
        return None

    # Separate into register and non-register declarations
    reg_decls = []
    non_reg_decls = []
    for m in all_decls:
        caps = {k: v[0] for k, v in m[1].items()}
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

    q = ts.Query(
        _C_LANGUAGE,
        """
        (expression_statement
            (assignment_expression
                left: (identifier) @var
                operator: "="
                right: (binary_expression) @rhs
            )
        ) @stmt
    """,
    )
    cursor = ts.QueryCursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}

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

    cursor = ts.QueryCursor(_QUERY_REGISTER_DECL)
    matches = cursor.matches(tree.root_node)

    # Collect all register declarations
    reg_nodes: list[ts.Node] = []
    for m in matches:
        caps = {k: v[0] for k, v in m[1].items()}
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

    result = b_source[: n1.start_byte] + n2_text + mid_text + n1_text + b_source[n2.end_byte :]
    return result.decode("utf-8")


# ---------------------------------------------------------------------------
# Switch statement mutations (MSVC6 comparison chain codegen)
# ---------------------------------------------------------------------------

_QUERY_SWITCH_STMT = ts.Query(
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
    cursor = ts.QueryCursor(_QUERY_SWITCH_STMT)
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
    cursor = ts.QueryCursor(_QUERY_SWITCH_STMT)
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
    cursor = ts.QueryCursor(_QUERY_SWITCH_STMT)
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
    cursor = ts.QueryCursor(_QUERY_SWITCH_STMT)
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
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = ts.QueryCursor(_QUERY_IF_STMT)
    matches = cursor.matches(tree.root_node)

    valid_chains = []

    for match in matches:
        if_node = match[1].get("if_stmt")
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
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = ts.QueryCursor(_QUERY_SWITCH_STMT)
    matches = cursor.matches(tree.root_node)

    valid_switches = []
    for match in matches:
        switch = match[1].get("stmt")
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
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = ts.QueryCursor(_QUERY_IF_STMT)
    matches = cursor.matches(tree.root_node)

    valid_ifs = []

    def contains_early_exit(node) -> bool:
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
        if_stmt = match[1].get("if_stmt")
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
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = ts.QueryCursor(_QUERY_SWITCH_STMT)
    matches = cursor.matches(tree.root_node)

    valid_targets = []

    for match in matches:
        switch = match[1].get("stmt")
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

        break_nodes = []

        def find_breaks(n, bn) -> None:
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


# --- Phase 3: Advanced Logical & Evaluation Mutations ---


def mut_split_and_condition(s: str, rng: random.Random) -> str | None:
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = ts.QueryCursor(_QUERY_BIN_COND_IF)
    matches = cursor.matches(tree.root_node)

    valid_ifs = []
    for match in matches:
        stmt = match[1].get("stmt")
        if isinstance(stmt, list):
            stmt = stmt[0]
        if not stmt:
            continue

        # Must not have else clause for simple split
        if stmt.child_by_field_name("alternative"):
            continue

        bin_node = match[1].get("bin")
        if isinstance(bin_node, list):
            bin_node = bin_node[0]

        left = match[1].get("left")
        if isinstance(left, list):
            left = left[0]
        right = match[1].get("right")
        if isinstance(right, list):
            right = right[0]

        if not left or not right:
            continue
        op_text = b_source[left.end_byte : right.start_byte].strip()
        if op_text != b"&&":
            continue

        body = match[1].get("body")
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
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = ts.QueryCursor(_QUERY_BIN_COND_IF)
    matches = cursor.matches(tree.root_node)

    valid_ifs = []
    for match in matches:
        stmt = match[1].get("stmt")
        if isinstance(stmt, list):
            stmt = stmt[0]
        if not stmt:
            continue

        if stmt.child_by_field_name("alternative"):
            continue

        bin_node = match[1].get("bin")
        if isinstance(bin_node, list):
            bin_node = bin_node[0]

        left = match[1].get("left")
        if isinstance(left, list):
            left = left[0]
        right = match[1].get("right")
        if isinstance(right, list):
            right = right[0]

        if not left or not right:
            continue
        op_text = b_source[left.end_byte : right.start_byte].strip()
        if op_text != b"||":
            continue

        body = match[1].get("body")
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
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = ts.QueryCursor(_QUERY_NESTED_IF_P3)
    matches = cursor.matches(tree.root_node)

    valid_ifs = []
    for match in matches:
        stmt = match[1].get("stmt")
        if isinstance(stmt, list):
            stmt = stmt[0]
        if not stmt:
            continue

        if stmt.child_by_field_name("alternative"):
            continue

        inner_if = match[1].get("inner_if")
        if isinstance(inner_if, list):
            inner_if = inner_if[-1]
        if inner_if.child_by_field_name("alternative"):
            continue

        cond1 = match[1].get("cond1")
        if isinstance(cond1, list):
            cond1 = cond1[0]
        cond2 = match[1].get("cond2")
        if isinstance(cond2, list):
            cond2 = cond2[0]

        body = match[1].get("body")
        if isinstance(body, list):
            body = body[-1]

        outer_body = match[1].get("outer_body")
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
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = ts.QueryCursor(_QUERY_BIN_COND_IF)
    matches = cursor.matches(tree.root_node)

    valid_ifs = []
    for match in matches:
        stmt = match[1].get("stmt")
        if isinstance(stmt, list):
            stmt = stmt[0]
        if not stmt:
            continue

        bin_node = match[1].get("bin")
        if isinstance(bin_node, list):
            bin_node = bin_node[0]

        left = match[1].get("left")
        if isinstance(left, list):
            left = left[0]
        right = match[1].get("right")
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
    b_source = s.encode("utf-8")

    tree = parse_c_ast(b_source)
    cursor = ts.QueryCursor(_QUERY_WHILE_LOOP)
    matches = cursor.matches(tree.root_node)

    valid_loops = []
    for match in matches:
        stmt = match[1].get("stmt")
        if isinstance(stmt, list):
            stmt = stmt[0]
        if not stmt:
            continue

        cond = match[1].get("cond")
        if isinstance(cond, list):
            cond = cond[0]

        body = match[1].get("body")
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

_QUERY_LOCAL_DECL = ts.Query(
    _C_LANGUAGE,
    """
    (declaration type: (_) @type declarator: (_) @decl) @stmt
""",
)


def mut_widen_local_type(s: str, rng: random.Random) -> str | None:
    """Toggle local variable type width: short↔int, BYTE↔DWORD, WORD↔DWORD.

    MSVC6 generates different MOV sizes (MOVSX, MOVZX, MOV EAX vs MOV AL)
    depending on the declared type width.
    """
    b_source = s.encode("utf-8")
    cursor = ts.QueryCursor(_QUERY_LOCAL_DECL)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid = []
    for match in matches:
        caps = match[1]
        type_node = caps.get("type")
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


_QUERY_FLOAT_BINOP = ts.Query(
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
    cursor = ts.QueryCursor(_QUERY_FLOAT_BINOP)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid = []
    for match in matches:
        caps = match[1]
        op_node = caps.get("op")
        if isinstance(op_node, list):
            op_node = op_node[0]
        if not op_node:
            continue
        op_text = b_source[op_node.start_byte : op_node.end_byte]
        if op_text not in (b"*", b"+"):
            continue

        left = caps.get("left")
        right = caps.get("right")
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


_QUERY_FUNC_PARAM = ts.Query(
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
    cursor = ts.QueryCursor(_QUERY_FUNC_PARAM)
    matches = cursor.matches(tree.root_node)

    # Collect params that don't already have 'register'
    valid = []
    for match in matches:
        caps = {k: v[0] for k, v in match[1].items()}
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
    cursor = ts.QueryCursor(_QUERY_FUNC_PARAM)
    matches = cursor.matches(tree.root_node)

    valid = []
    for match in matches:
        caps = {k: v[0] for k, v in match[1].items()}
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


_QUERY_BREAK_IN_LOOP = ts.Query(
    _C_LANGUAGE,
    """
    [
        (while_statement body: (compound_statement (break_statement) @brk))
        (do_statement body: (compound_statement (break_statement) @brk))
        (for_statement body: (compound_statement (break_statement) @brk))
    ]
""",
)

_QUERY_LOOP_BODY = ts.Query(
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
    cursor = ts.QueryCursor(_QUERY_BREAK_IN_LOOP)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}
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
    cursor = ts.QueryCursor(_QUERY_LOOP_BODY)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}
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


_QUERY_IF_ELSE_CALL = ts.Query(
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
    cursor = ts.QueryCursor(_QUERY_IF_ELSE_CALL)
    matches = cursor.matches(tree.root_node)

    valid = []
    for match in matches:
        caps = {k: v[0] for k, v in match[1].items()}
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
    q = ts.Query(
        _C_LANGUAGE,
        """
        (expression_statement
            (call_expression
                function: (_) @fn
                arguments: (argument_list
                    (conditional_expression
                        condition: (_) @cond
                        consequence: (_) @val_true
                        alternative: (_) @val_false) @ternary)
            ) @call
        ) @stmt
    """,
    )
    cursor = ts.QueryCursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}

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


_QUERY_IF_ELSE_COMPOUND = ts.Query(
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
    cursor = ts.QueryCursor(_QUERY_IF_ELSE_COMPOUND)
    matches = cursor.matches(tree.root_node)

    valid = []
    for match in matches:
        caps = {k: v[0] for k, v in match[1].items()}
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
    q = ts.Query(
        _C_LANGUAGE,
        """
        (compound_statement
            (if_statement
                condition: (parenthesized_expression) @cond
                consequence: (compound_statement) @if_body
                alternative: (else_clause
                    (compound_statement) @else_body)
            ) @if_stmt
            .
            [
                (expression_statement)
                (return_statement)
            ] @next_stmt
        )
    """,
    )
    cursor = ts.QueryCursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}
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


# ---------------------------------------------------------------------------
# Phase 5: MSVC6 codegen insights (commutative ops, block registers, type
# retyping, zero-clearing via bitand)
# ---------------------------------------------------------------------------

# --- Queries for Phase 5 mutations ---

_QUERY_COMMUTE_BIT_OR = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "|" @op
        right: (_) @right) @expr
""",
)

_QUERY_COMMUTE_BIT_AND = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "&" @op
        right: (_) @right) @expr
""",
)

_QUERY_COMMUTE_BIT_XOR = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "^" @op
        right: (_) @right) @expr
""",
)

_QUERY_COMMUTE_ADD_GENERAL = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "+" @op
        right: (_) @right) @expr
""",
)

_QUERY_COMMUTE_MUL_GENERAL = ts.Query(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "*" @op
        right: (_) @right) @expr
""",
)

_QUERY_BITAND_ZERO = ts.Query(
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


def _commute_operands(s: str, rng: random.Random, query: ts.Query, op_str: bytes) -> str | None:
    """Generic commutative operand swap for the given binary operator query."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        if left == right:
            return b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        return right + b" " + op_str + b" " + left

    res = _apply_query_once(b_source, query, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None


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

    Unlike ``mut_commute_simple_add`` (identifiers only), this handles
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
    q_loop = ts.Query(
        _C_LANGUAGE,
        """
        [
            (while_statement body: (compound_statement) @body) @stmt
            (for_statement body: (compound_statement) @body) @stmt
            (do_statement body: (compound_statement) @body) @stmt
        ]
    """,
    )
    cursor = ts.QueryCursor(q_loop)
    loop_matches = cursor.matches(tree.root_node)

    # Strategy 2: wrap 2-4 adjacent expression_statements in a block
    q_adj = ts.Query(
        _C_LANGUAGE,
        """
        (compound_statement
            (expression_statement) @s1
            .
            (expression_statement) @s2
        )
    """,
    )
    cursor2 = ts.QueryCursor(q_adj)
    adj_matches = cursor2.matches(tree.root_node)

    candidates: list[tuple[str, dict[str, ts.Node]]] = []
    for m in loop_matches:
        caps = {k: v[0] for k, v in m[1].items()}
        candidates.append(("loop", caps))
    for m in adj_matches:
        caps = {k: v[0] for k, v in m[1].items()}
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
    cursor = ts.QueryCursor(_QUERY_LOCAL_DECL)
    tree = parse_c_ast(b_source)
    matches = cursor.matches(tree.root_node)

    valid: list[tuple[ts.Node, bytes]] = []
    for match in matches:
        caps = match[1]
        type_node = caps.get("type")
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
    zero_cursor = ts.QueryCursor(_QUERY_ASSIGN_ZERO)
    for m in zero_cursor.matches(tree.root_node):
        caps = {k: v[0] for k, v in m[1].items()}
        # Skip if inside a for-loop initializer
        parent = caps["expr"].parent
        if parent and parent.type == "for_statement":
            continue
        var = b_source[caps["var"].start_byte : caps["var"].end_byte]
        if b"." in var or b"->" in var or b"[" in var:
            continue
        candidates.append((caps, var + b" &= 0;", "expr"))

    # Reverse: var &= 0 → var = 0
    bitand_cursor = ts.QueryCursor(_QUERY_BITAND_ZERO)
    for m in bitand_cursor.matches(tree.root_node):
        caps = {k: v[0] for k, v in m[1].items()}
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

_QUERY_FUNC_DEF = ts.Query(
    _C_LANGUAGE,
    """
    (function_definition
        type: (_) @ret_type
        declarator: (_) @decl
        body: (compound_statement) @body
    ) @func
""",
)

_QUERY_IF_ELSE_FULL = ts.Query(
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

_QUERY_DO_WHILE_FULL = ts.Query(
    _C_LANGUAGE,
    """
    (do_statement
        body: (compound_statement) @body
        condition: (parenthesized_expression) @cond
    ) @stmt
""",
)

_QUERY_NESTED_CALL_ARG = ts.Query(
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

_QUERY_COMPLEX_ARG = ts.Query(
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


def mut_pragma_optimize(s: str, rng: random.Random) -> str | None:
    """Inject ``#pragma optimize`` around function definitions.

    MSVC6's global register allocator (the ``g`` flag) aggressively
    coalesces variables into shared registers.  Disabling it with
    ``#pragma optimize("g", off)`` forces strict local allocation,
    making ``register`` keywords reliable and preventing unwanted CSE.

    Also randomly tests ``"y"`` (frame-pointer omission) and ``""``
    (full optimisation reset) for wider codegen exploration.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    cursor = ts.QueryCursor(_QUERY_FUNC_DEF)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}
    func_node = caps["func"]

    # Don't inject if already present
    before = b_source[max(0, func_node.start_byte - 80) : func_node.start_byte]
    if b"#pragma optimize" in before:
        return None

    # Choose a pragma variant
    variant = rng.choice(
        [
            (b'#pragma optimize("g", off)', b'#pragma optimize("", on)'),
            (b'#pragma optimize("y", off)', b'#pragma optimize("", on)'),
            (b'#pragma optimize("gy", off)', b'#pragma optimize("", on)'),
            (b'#pragma optimize("", off)', b'#pragma optimize("", on)'),
        ]
    )

    prefix = variant[0] + b"\n"
    suffix = b"\n" + variant[1]

    result = (
        b_source[: func_node.start_byte]
        + prefix
        + b_source[func_node.start_byte : func_node.end_byte]
        + suffix
        + b_source[func_node.end_byte :]
    )
    return result.decode("utf-8")


def mut_pragma_optimize_remove(s: str, rng: random.Random) -> str | None:
    """Remove ``#pragma optimize`` directives surrounding a function.

    Reverse of :func:`mut_pragma_optimize`.  Strips both the ``off``
    line before and the ``on`` line after the function.
    """
    b_source = s.encode("utf-8")

    # Find and remove #pragma optimize("...", off) lines
    pragma_off_re = re.compile(rb"#pragma optimize\([^)]+,\s*off\)\s*\n")
    pragma_on_re = re.compile(rb"\n#pragma optimize\([^)]+,\s*on\)")

    m_off = pragma_off_re.search(b_source)
    if not m_off:
        return None

    result = b_source[: m_off.start()] + b_source[m_off.end() :]

    m_on = pragma_on_re.search(result)
    if m_on:
        result = result[: m_on.start()] + result[m_on.end() :]

    result_str = result.decode("utf-8")
    return result_str if result_str != s else None


# Operator inversion map for De Morgan-aware if/else inversion
_INVERT_OP: dict[bytes, bytes] = {
    b"==": b"!=",
    b"!=": b"==",
    b"<": b">=",
    b">=": b"<",
    b">": b"<=",
    b"<=": b">",
    b"&&": b"||",
    b"||": b"&&",
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

    cursor = ts.QueryCursor(_QUERY_IF_ELSE_FULL)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}

    op_node = caps["op"]
    op_text = b_source[op_node.start_byte : op_node.end_byte]
    inverted_op = _INVERT_OP.get(op_text)
    if not inverted_op:
        return None

    left = b_source[caps["left"].start_byte : caps["left"].end_byte]
    right = b_source[caps["right"].start_byte : caps["right"].end_byte]
    cons = b_source[caps["cons"].start_byte : caps["cons"].end_byte]
    alt = b_source[caps["alt"].start_byte : caps["alt"].end_byte]

    stmt_node = caps["stmt"]
    replacement = (
        b"if (" + left + b" " + inverted_op + b" " + right + b") " + alt + b" else " + cons
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

    q = ts.Query(_C_LANGUAGE, "(function_definition body: (compound_statement) @body)")
    cursor = ts.QueryCursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}
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

    q = ts.Query(_C_LANGUAGE, "(function_definition body: (compound_statement) @body)")
    cursor = ts.QueryCursor(q)
    matches = cursor.matches(tree.root_node)

    if not matches:
        return None

    match = rng.choice(matches)
    caps = {k: v[0] for k, v in match[1].items()}
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


def mut_loop_convert(s: str, rng: random.Random) -> str | None:
    """Rotate loop forms: while ↔ do-while-under-if ↔ for.

    MSVC6 generates different jump layouts and register lifetimes
    depending on the C loop construct used.  This mutator converts
    between the three semantically equivalent forms:

    * ``while (cond) { body }``
    * ``if (cond) { do { body } while (cond); }``
    * ``for (; cond; ) { body }``

    Unlike the existing :func:`mut_while_to_dowhile`,
    :func:`mut_for_to_while`, and :func:`mut_while_to_for` which are
    individually selected, this mutator randomly picks one of the
    conversions in a single GA slot, increasing the chance of finding
    loop-rotation matches.
    """
    b_source = s.encode("utf-8")
    tree = parse_c_ast(b_source)

    candidates: list[tuple[str, dict[str, ts.Node]]] = []

    # Collect while loops
    w_cursor = ts.QueryCursor(_QUERY_WHILE_LOOP)
    for m in w_cursor.matches(tree.root_node):
        caps = {k: v[0] for k, v in m[1].items()}
        candidates.append(("while", caps))

    # Collect do-while loops
    dw_cursor = ts.QueryCursor(_QUERY_DO_WHILE_FULL)
    for m in dw_cursor.matches(tree.root_node):
        caps = {k: v[0] for k, v in m[1].items()}
        candidates.append(("dowhile", caps))

    # Collect for loops
    f_cursor = ts.QueryCursor(_QUERY_FOR_LOOP)
    for m in f_cursor.matches(tree.root_node):
        caps = {k: v[0] for k, v in m[1].items()}
        # Only convert simple for(; cond ;) loops (no init/update)
        has_init = (
            "init" in caps
            and (caps["init"][0] if isinstance(caps["init"], list) else caps["init"]).end_byte
            > (caps["init"][0] if isinstance(caps["init"], list) else caps["init"]).start_byte
        )
        has_update = (
            "update" in caps
            and (caps["update"][0] if isinstance(caps["update"], list) else caps["update"]).end_byte
            > (caps["update"][0] if isinstance(caps["update"], list) else caps["update"]).start_byte
        )
        if not has_init and not has_update:
            candidates.append(("for_simple", caps))

    if not candidates:
        return None

    kind, caps = rng.choice(candidates)

    if kind == "while":
        cond = b_source[caps["cond"].start_byte : caps["cond"].end_byte]
        body = b_source[caps["body"].start_byte : caps["body"].end_byte]
        stmt = caps["stmt"]

        target_form = rng.choice(["dowhile", "for"])
        if target_form == "dowhile":
            # while (cond) { body } → if (cond) { do { body } while (cond); }
            replacement = b"if " + cond + b" {\n    do " + body + b" while " + cond + b";\n    }"
        else:
            # while (cond) { body } → for (; cond_inner; ) { body }
            cond_inner = cond
            if cond_inner.startswith(b"(") and cond_inner.endswith(b")"):
                cond_inner = cond_inner[1:-1]
            replacement = b"for (; " + cond_inner.strip() + b"; ) " + body

        result = b_source[: stmt.start_byte] + replacement + b_source[stmt.end_byte :]
        return result.decode("utf-8")

    if kind == "dowhile":
        cond = b_source[caps["cond"].start_byte : caps["cond"].end_byte]
        body = b_source[caps["body"].start_byte : caps["body"].end_byte]
        stmt = caps["stmt"]

        target_form = rng.choice(["while", "for"])
        if target_form == "while":
            replacement = b"while " + cond + b" " + body
        else:
            cond_inner = cond
            if cond_inner.startswith(b"(") and cond_inner.endswith(b")"):
                cond_inner = cond_inner[1:-1]
            replacement = b"for (; " + cond_inner.strip() + b"; ) " + body

        result = b_source[: stmt.start_byte] + replacement + b_source[stmt.end_byte :]
        return result.decode("utf-8")

    if kind == "for_simple":
        # for (; cond; ) { body } → while (cond) { body }
        cond_node = caps["cond"][0] if isinstance(caps["cond"], list) else caps["cond"]
        body_node = caps["body"][0] if isinstance(caps["body"], list) else caps["body"]
        stmt_node = caps["stmt"][0] if isinstance(caps["stmt"], list) else caps["stmt"]

        cond = b_source[cond_node.start_byte : cond_node.end_byte]
        body = b_source[body_node.start_byte : body_node.end_byte]

        replacement = b"while (" + cond + b") " + body
        result = b_source[: stmt_node.start_byte] + replacement + b_source[stmt_node.end_byte :]
        return result.decode("utf-8")

    return None


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
    nc_cursor = ts.QueryCursor(_QUERY_NESTED_CALL_ARG)
    for m in nc_cursor.matches(tree.root_node):
        caps = {k: v[0] for k, v in m[1].items()}
        stmt_node = caps["stmt"]
        inner_call_node = caps["inner_call"]
        inner_text = b_source[inner_call_node.start_byte : inner_call_node.end_byte]
        candidates.append((stmt_node, inner_call_node, inner_text))

    # Strategy 2: binary expressions as arguments (ptr arithmetic, shifts, etc.)
    ca_cursor = ts.QueryCursor(_QUERY_COMPLEX_ARG)
    for m in ca_cursor.matches(tree.root_node):
        caps = {k: v[0] for k, v in m[1].items()}
        stmt_node = caps["stmt"]
        arg_node = caps["arg"]
        # Only extract if not trivially simple
        arg_text = b_source[arg_node.start_byte : arg_node.end_byte]
        if len(arg_text) > 6:  # skip trivial like "a + 1"
            candidates.append((stmt_node, arg_node, arg_text))

    if not candidates:
        return None

    stmt_node, extract_node, extract_text = rng.choice(candidates)

    var_id = rng.randint(0, 999)
    var_name = f"_t{var_id}".encode()
    if var_name in b_source:
        return None

    # C89: hoist declaration to function body top
    insert_pos = _find_function_body_insert_pos(b_source, stmt_node.start_byte)
    if insert_pos is None:
        return None

    hoisted_decl = b"\n    int " + var_name + b";"
    inline_assign = var_name + b" = " + extract_text + b";\n    "

    # Replace the extracted expression with the temp var in the original call
    new_stmt = (
        b_source[stmt_node.start_byte : extract_node.start_byte]
        + var_name
        + b_source[extract_node.end_byte : stmt_node.end_byte]
    )

    # Insert hoisted decl at function body top
    out = b_source[:insert_pos] + hoisted_decl + b_source[insert_pos:]
    # Adjust offsets by the hoisted decl length
    offset = len(hoisted_decl)
    s_start = stmt_node.start_byte + offset
    s_end = stmt_node.end_byte + offset
    e_start = extract_node.start_byte + offset
    e_end = extract_node.end_byte + offset

    new_stmt = out[s_start:e_start] + var_name + out[e_end:s_end]
    result = out[:s_start] + inline_assign + new_stmt + out[s_end:]

    return result.decode("utf-8")


ALL_MUTATIONS = [
    mut_commute_simple_add,
    mut_commute_simple_mul,
    mut_flip_eq_zero,
    mut_flip_lt_ge,
    mut_add_redundant_parens,
    mut_swap_eq_operands,
    mut_swap_ne_operands,
    mut_reassociate_add,
    mut_swap_or_operands,
    mut_swap_and_operands,
    mut_toggle_bool_not,
    mut_return_to_goto,
    mut_goto_to_return,
    mut_swap_if_else,
    mut_add_cast,
    mut_remove_cast,
    mut_toggle_volatile,
    mut_add_register_keyword,
    mut_remove_register_keyword,
    mut_if_false_to_bitand,
    mut_reorder_elseif,
    mut_bitand_to_if_false,
    mut_introduce_temp_for_call,
    mut_remove_temp_var,
    mut_toggle_signedness,
    mut_swap_adjacent_declarations,
    mut_split_declaration_init,
    mut_merge_declaration_init,
    mut_while_to_dowhile,
    mut_dowhile_to_while,
    mut_early_return_to_accum,
    mut_accum_to_early_return,
    mut_pointer_to_int_param,
    mut_int_to_pointer_param,
    mut_duplicate_loop_body,
    mut_fold_constant_add,
    mut_unfold_constant_add,
    mut_change_array_index_order,
    mut_struct_vs_ptr_access,
    mut_change_return_type,
    mut_split_cmp_chain,
    mut_merge_cmp_chain,
    mut_combine_ptr_arith,
    mut_split_ptr_arith,
    mut_change_param_order,
    mut_toggle_calling_convention,
    mut_toggle_char_signedness,
    mut_comparison_boundary,
    mut_insert_noop_block,
    mut_introduce_local_alias,
    mut_reorder_declarations,
    mut_flatten_nested_if,
    mut_extract_else_body,
    mut_for_to_while,
    mut_while_to_for,
    mut_if_to_ternary,
    mut_ternary_to_if,
    mut_hoist_return,
    mut_sink_return,
    mut_swap_adjacent_stmts,
    mut_guard_clause,
    mut_invert_loop_direction,
    mut_compound_assign_toggle,
    mut_demorgan,
    mut_postpre_increment,
    mut_xor_zero_toggle,
    mut_negate_condition,
    # --- MSVC6-targeted structural mutations (2026-03 batch) ---
    mut_while_to_goto_loop,
    mut_inject_dummy_var,
    mut_inject_dummy_array,
    mut_scope_variable,
    mut_array_to_ptr_arith,
    mut_ptr_arith_to_array,
    mut_decouple_index_math,
    mut_preinit_byte_load,
    mut_cast_to_bitmask,
    mut_swap_register_keywords,
    mut_add_volatile_intermediate,
    mut_reorder_register_vars,
    # --- Switch statement mutations (MSVC6 comparison chain codegen) ---
    mut_reorder_switch_cases,
    mut_switch_to_if_chain,
    mut_split_switch,
    mut_move_switch_default,
    # --- Advanced Control Flow & Switch Edge Cases (MSVC6 blocks) ---
    mut_if_chain_to_switch,
    mut_switch_add_explicit_default,
    mut_wrap_in_else,
    mut_switch_break_to_return,
    # --- Phase 3: Advanced Logical & Evaluation Mutations ---
    mut_split_and_condition,
    mut_merge_nested_ifs,
    mut_split_or_condition,
    mut_extract_condition_to_var,
    mut_loop_condition_extraction,
    mut_extract_args_to_temps,
    # --- MSVC6 type width & codegen mutations (2026-03 GA improvements) ---
    mut_widen_local_type,
    mut_toggle_dllimport,
    mut_memcpy_to_loop,
    mut_loop_to_memcpy,
    mut_commute_float_operands,
    # --- Phase 4: Manual decomp insight mutations ---
    mut_register_param,
    mut_unregister_param,
    mut_remove_loop_break,
    mut_add_loop_break,
    mut_if_else_call_to_ternary_arg,
    mut_ternary_arg_to_if_else_call,
    mut_hoist_common_tail,
    mut_sink_common_tail,
    # --- Phase 5: MSVC6 codegen insights (commutative, block registers, type retyping, bitand) ---
    mut_commute_bit_or,
    mut_commute_bit_and,
    mut_commute_bit_xor,
    mut_commute_add_general,
    mut_commute_mul_general,
    mut_inject_block_register,
    mut_retype_local_equiv,
    mut_zero_to_bitand,
    # --- Phase 6: MSVC6 codegen quirks (pragma, branch layout, stack padding, loop rotation) ---
    mut_pragma_optimize,
    mut_pragma_optimize_remove,
    mut_invert_if_else,
    mut_dummy_stack_vars,
    mut_inject_dummy_registers,
    mut_loop_convert,
    mut_extract_complex_args,
]

__all__ = [
    "ALL_MUTATIONS",
    "compute_population_diversity",
    "crossover",
    "mutate_code",
    "quick_validate",
    *[m.__name__ for m in ALL_MUTATIONS],
]


@overload
def mutate_code(
    source: str,
    rng: random.Random,
    track_mutation: Literal[False] = False,
    mutation_weights: dict[str, float] | None = None,
) -> str: ...


@overload
def mutate_code(
    source: str,
    rng: random.Random,
    track_mutation: Literal[True],
    mutation_weights: dict[str, float] | None = None,
) -> tuple[str, str]: ...


def mutate_code(
    source: str,
    rng: random.Random,
    track_mutation: bool = False,
    mutation_weights: dict[str, float] | None = None,
) -> str | tuple[str, str]:
    """Apply a random mutation to the source code.

    When *mutation_weights* is provided, it maps mutation function names
    (e.g. ``"mut_swap_if_else"``) to relative weights.  Mutations not
    listed default to weight 1.0.
    """
    preamble, body = _split_preamble_body(source)

    weights: list[float] | None = None
    if mutation_weights:
        weights = [mutation_weights.get(m.__name__, 1.0) for m in ALL_MUTATIONS]
        if not any(w > 0 for w in weights):
            weights = None

    for _ in range(10):
        if weights:
            mut_func = rng.choices(ALL_MUTATIONS, weights=weights, k=1)[0]
        else:
            mut_func = rng.choice(ALL_MUTATIONS)
        new_body = mut_func(body, rng)
        if new_body and new_body != body:
            new_source = preamble + "\n" + new_body
            if quick_validate(new_source):
                if track_mutation:
                    return new_source, mut_func.__name__
                return new_source

    if track_mutation:
        return source, "none"
    return source
