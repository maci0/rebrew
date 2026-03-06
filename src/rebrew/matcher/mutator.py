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
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        return right + b" + " + left

    res = _apply_query_once(b_source, _QUERY_COMMUTE_ADD, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_commute_simple_mul(s: str, rng: random.Random) -> str | None:
    """Swap operands of simple identifier multiplication."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        return right + b" * " + left

    res = _apply_query_once(b_source, _QUERY_COMMUTE_MUL, _repl, rng)
    return res.decode("utf-8") if res else None


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
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        return right + b" == " + left

    res = _apply_query_once(b_source, _QUERY_SWAP_EQ, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_swap_ne_operands(s: str, rng: random.Random) -> str | None:
    """Swap A != b to b != a."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        return right + b" != " + left

    res = _apply_query_once(b_source, _QUERY_SWAP_NE, _repl, rng)
    return res.decode("utf-8") if res else None


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
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        if left == right:
            return b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        return right + b" || " + left

    res = _apply_query_once(b_source, _QUERY_SWAP_OR, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None


def mut_swap_and_operands(s: str, rng: random.Random) -> str | None:
    """Swap A && b to b && a."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        if left == right:
            return b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        return right + b" && " + left

    res = _apply_query_once(b_source, _QUERY_SWAP_AND, _repl, rng)
    if not res:
        return None
    res_str = res.decode("utf-8")
    return res_str if res_str != s else None


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
    """Introduce a temp variable for a function call result."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        var = b_source[captures["var"].start_byte : captures["var"].end_byte]
        call = b_source[captures["call"].start_byte : captures["call"].end_byte]

        if b"tmp" in b_source:
            return b"tmp = " + call + b";\n    " + var + b" = tmp;"
        else:
            return b"BOOL tmp = " + call + b";\n    " + var + b" = tmp;"

    res = _apply_query_once(b_source, _QUERY_CALL_ASSIGN, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_remove_temp_var(s: str, rng: random.Random) -> str | None:
    """Remove a temp variable usage: 'tmp = expr; var = tmp;' -> 'var = expr;'."""
    b_source = s.encode("utf-8")
    cursor = ts.QueryCursor(_QUERY_TEMP_VAR)
    from rebrew.matcher.ast_engine import parse_c_ast

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
    from rebrew.matcher.ast_engine import parse_c_ast

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
    from rebrew.matcher.ast_engine import parse_c_ast

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
    from rebrew.matcher.ast_engine import parse_c_ast

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
    from rebrew.matcher.ast_engine import parse_c_ast

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
    from rebrew.matcher.ast_engine import parse_c_ast

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
    from rebrew.matcher.ast_engine import parse_c_ast

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
    from rebrew.matcher.ast_engine import parse_c_ast

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
    from rebrew.matcher.ast_engine import parse_c_ast

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
    from rebrew.matcher.ast_engine import parse_c_ast

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
