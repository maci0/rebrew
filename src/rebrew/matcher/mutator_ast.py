"""mutator_ast.py - AST-based C source mutations.

Provides AST-aware equivalents of the regex-based mutators from mutator.py.
"""

import random
from collections.abc import Callable

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


def _apply_query_once(
    source: bytes,
    query: ts.Query,
    repl: Callable[[dict[str, ts.Node]], bytes],
    rng: random.Random,
) -> bytes | None:
    """Helper to apply an AST query and replace one matched occurrence."""
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


def mut_ast_commute_simple_add(s: str, rng: random.Random) -> str | None:
    """Swap operands of simple identifier addition."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        return right + b" + " + left

    res = _apply_query_once(b_source, _QUERY_COMMUTE_ADD, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_commute_simple_mul(s: str, rng: random.Random) -> str | None:
    """Swap operands of simple identifier multiplication."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        return right + b" * " + left

    res = _apply_query_once(b_source, _QUERY_COMMUTE_MUL, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_flip_eq_zero(s: str, rng: random.Random) -> str | None:
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


def mut_ast_flip_lt_ge(s: str, rng: random.Random) -> str | None:
    """Rewrite ``a < b`` into the equivalent negated ``!(a >= b)`` form."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        return b"!(" + left + b" >= " + right + b")"

    res = _apply_query_once(b_source, _QUERY_FLIP_LT_GE, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_add_redundant_parens(s: str, rng: random.Random) -> str | None:
    """Wrap a random identifier in redundant parentheses.
    AST makes this safe vs wrapping keywords like 'return'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        ident = b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        return b"(" + ident + b")"

    res = _apply_query_once(b_source, _QUERY_IDENTIFIER, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_swap_eq_operands(s: str, rng: random.Random) -> str | None:
    """a == b -> b == a"""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        return right + b" == " + left

    res = _apply_query_once(b_source, _QUERY_SWAP_EQ, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_swap_ne_operands(s: str, rng: random.Random) -> str | None:
    """a != b -> b != a"""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        return right + b" != " + left

    res = _apply_query_once(b_source, _QUERY_SWAP_NE, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_reassociate_add(s: str, rng: random.Random) -> str | None:
    """Reassociate ``(a + b) + c`` into ``a + (b + c)``."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        a = b_source[captures["a"].start_byte : captures["a"].end_byte]
        b = b_source[captures["b"].start_byte : captures["b"].end_byte]
        c = b_source[captures["c"].start_byte : captures["c"].end_byte]
        return a + b" + (" + b + b" + " + c + b")"

    res = _apply_query_once(b_source, _QUERY_REASSOCIATE, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_swap_or_operands(s: str, rng: random.Random) -> str | None:
    """a || b -> b || a  (changes short-circuit order, affects codegen)"""
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


def mut_ast_swap_and_operands(s: str, rng: random.Random) -> str | None:
    """a && b -> b && a"""
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


def mut_ast_toggle_bool_not(s: str, rng: random.Random) -> str | None:
    """Remove one ``!!identifier`` sequence."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        ident = b_source[captures["ident"].start_byte : captures["ident"].end_byte]
        return ident

    res = _apply_query_once(b_source, _QUERY_DOUBLE_NOT, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_return_to_goto(s: str, rng: random.Random) -> str | None:
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


def mut_ast_goto_to_return(s: str, rng: random.Random) -> str | None:
    """Reverse: replace 'goto ret_false;' with 'return 0;'"""
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


def mut_ast_swap_if_else(s: str, rng: random.Random) -> str | None:
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

        # Simple negation - in real scenarios, prefer mut_ast_flip_lt_ge and others
        negated_cond = b"!(" + cond_inner + b")"

        return b"if (" + negated_cond + b") " + alt + b" else " + cons

    res = _apply_query_once(b_source, _QUERY_IF_ELSE, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_add_cast(s: str, rng: random.Random) -> str | None:
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


def mut_ast_remove_cast(s: str, rng: random.Random) -> str | None:
    """Remove a (TYPE) cast."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        val = b_source[captures["val"].start_byte : captures["val"].end_byte]
        return val

    res = _apply_query_once(b_source, _QUERY_REMOVE_CAST, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_toggle_volatile(s: str, rng: random.Random) -> str | None:
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


def mut_ast_add_register_keyword(s: str, rng: random.Random) -> str | None:
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


def mut_ast_remove_register_keyword(s: str, rng: random.Random) -> str | None:
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


def mut_ast_if_false_to_bitand(s: str, rng: random.Random) -> str | None:
    """Convert 'if (!expr) var = FALSE;' to 'var &= expr;'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        cond = b_source[captures["cond"].start_byte : captures["cond"].end_byte]
        var = b_source[captures["var"].start_byte : captures["var"].end_byte]

        return var + b" &= " + cond + b";"

    res = _apply_query_once(b_source, _QUERY_IF_FALSE_BITAND, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_reorder_elseif(s: str, rng: random.Random) -> str | None:
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


def mut_ast_bitand_to_if_false(s: str, rng: random.Random) -> str | None:
    """Reverse of mut_if_false_to_bitand: convert 'var &= expr;' to 'if (!expr) var = 0;'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        var = b_source[captures["var"].start_byte : captures["var"].end_byte]
        expr = b_source[captures["expr"].start_byte : captures["expr"].end_byte]

        return b"if (!(" + expr + b"))\n            " + var + b" = 0;"

    res = _apply_query_once(b_source, _QUERY_BITAND, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_introduce_temp_for_call(s: str, rng: random.Random) -> str | None:
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


def mut_ast_remove_temp_var(s: str, rng: random.Random) -> str | None:
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


def mut_ast_toggle_signedness(s: str, rng: random.Random) -> str | None:
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


def mut_ast_swap_adjacent_declarations(s: str, rng: random.Random) -> str | None:
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


def mut_ast_split_declaration_init(s: str, rng: random.Random) -> str | None:
    """Split 'TYPE var = expr;' into 'TYPE var; var = expr;'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        type_ = b_source[captures["type"].start_byte : captures["type"].end_byte]
        var = b_source[captures["var"].start_byte : captures["var"].end_byte]
        expr = b_source[captures["expr"].start_byte : captures["expr"].end_byte]

        return type_ + b" " + var + b";\n    " + var + b" = " + expr + b";"

    res = _apply_query_once(b_source, _QUERY_SPLIT_DECL, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_merge_declaration_init(s: str, rng: random.Random) -> str | None:
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


def mut_ast_while_to_dowhile(s: str, rng: random.Random) -> str | None:
    """Convert 'while (cond) { body }' to 'if (cond) { do { body } while (cond); }'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        cond = b_source[captures["cond"].start_byte : captures["cond"].end_byte]
        body = b_source[captures["body"].start_byte : captures["body"].end_byte]
        return b"if " + cond + b" {\n    do " + body + b" while " + cond + b";\n    }"

    res = _apply_query_once(b_source, _QUERY_WHILE, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_dowhile_to_while(s: str, rng: random.Random) -> str | None:
    """Convert 'do { body } while (cond);' to 'while (cond) { body }'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        cond = b_source[captures["cond"].start_byte : captures["cond"].end_byte]
        body = b_source[captures["body"].start_byte : captures["body"].end_byte]
        return b"while " + cond + b" " + body

    res = _apply_query_once(b_source, _QUERY_DO_WHILE, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_early_return_to_accum(s: str, rng: random.Random) -> str | None:
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


def mut_ast_accum_to_early_return(s: str, rng: random.Random) -> str | None:
    """Convert 'ret &= expr;' to 'if (!expr) return 0;'."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        expr = b_source[captures["expr"].start_byte : captures["expr"].end_byte]
        return b"if (!(" + expr + b"))\n        return 0;"

    res = _apply_query_once(b_source, _QUERY_ACCUM, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_pointer_to_int_param(s: str, rng: random.Random) -> str | None:
    """Change a pointer parameter to int or vice versa."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        var = b_source[captures["var"].start_byte : captures["var"].end_byte]
        return b"int " + var

    res = _apply_query_once(b_source, _QUERY_PTR_PARAM, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_int_to_pointer_param(s: str, rng: random.Random) -> str | None:
    """Change an int parameter to char* (for pointer-based access)."""
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        var = b_source[captures["var"].start_byte : captures["var"].end_byte]
        return b"char *" + var

    res = _apply_query_once(b_source, _QUERY_INT_PARAM, _repl, rng)
    return res.decode("utf-8") if res else None


def mut_ast_duplicate_loop_body(s: str, rng: random.Random) -> str | None:
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


def mut_ast_fold_constant_add(s: str, rng: random.Random) -> str | None:
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


def mut_ast_unfold_constant_add(s: str, rng: random.Random) -> str | None:
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


def mut_ast_change_array_index_order(s: str, rng: random.Random) -> str | None:
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        arr = b_source[captures["arr"].start_byte : captures["arr"].end_byte]
        idx = b_source[captures["idx"].start_byte : captures["idx"].end_byte]
        return idx + b"[" + arr + b"]"

    res = _apply_query_once(b_source, _QUERY_ARRAY_INDEX, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_ast_struct_vs_ptr_access(s: str, rng: random.Random) -> str | None:
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        ptr = b_source[captures["ptr"].start_byte : captures["ptr"].end_byte]
        field = b_source[captures["field"].start_byte : captures["field"].end_byte]
        return b"(*" + ptr + b")." + field

    res = _apply_query_once(b_source, _QUERY_PTR_ARROW, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_ast_change_return_type(s: str, rng: random.Random) -> str | None:
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


def mut_ast_split_cmp_chain(s: str, rng: random.Random) -> str | None:
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        left = b_source[captures["left"].start_byte : captures["left"].end_byte]
        right = b_source[captures["right"].start_byte : captures["right"].end_byte]
        body = b_source[captures["body"].start_byte : captures["body"].end_byte]
        return b"if (" + left + b") { if (" + right + b") " + body + b" }"

    res = _apply_query_once(b_source, _QUERY_SPLIT_CMP_CHAIN, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_ast_merge_cmp_chain(s: str, rng: random.Random) -> str | None:
    b_source = s.encode("utf-8")

    def _repl(captures: dict[str, ts.Node]) -> bytes:
        cond1 = b_source[captures["cond1"].start_byte + 1 : captures["cond1"].end_byte - 1]
        cond2 = b_source[captures["cond2"].start_byte + 1 : captures["cond2"].end_byte - 1]
        body = b_source[captures["body"].start_byte : captures["body"].end_byte]
        return b"if ((" + cond1 + b") && (" + cond2 + b")) " + body

    res = _apply_query_once(b_source, _QUERY_MERGE_CMP_CHAIN, _repl, rng)
    return res.decode("utf-8") if res is not None else None


def mut_ast_combine_ptr_arith(s: str, rng: random.Random) -> str | None:
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


def mut_ast_split_ptr_arith(s: str, rng: random.Random) -> str | None:
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


def mut_ast_change_param_order(s: str, rng: random.Random) -> str | None:
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


def mut_ast_toggle_calling_convention(s: str, rng: random.Random) -> str | None:
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


def mut_ast_toggle_char_signedness(s: str, rng: random.Random) -> str | None:
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


def mut_ast_comparison_boundary(s: str, rng: random.Random) -> str | None:
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


def mut_ast_insert_noop_block(s: str, rng: random.Random) -> str | None:
    """Insert a no-op block `if (0) {}` before a random statement in a compound body."""
    b_source = s.encode("utf-8")
    from rebrew.matcher.ast_engine import parse_c_ast

    tree = parse_c_ast(b_source)
    # Find all expression_statements inside compound_statements
    q = ts.Query(_C_LANGUAGE, """(compound_statement (expression_statement) @stmt)""")
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


def mut_ast_introduce_local_alias(s: str, rng: random.Random) -> str | None:
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


def mut_ast_reorder_declarations(s: str, rng: random.Random) -> str | None:
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
