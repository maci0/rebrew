"""queries.py — the shared tree-sitter query library for GA mutations.

The lazily compiled queries the mutation operators run against the seed's C
AST.  _LazyQuery defers compilation so a run that never mutates does not pay
for the tree-sitter queries at import.
"""

from __future__ import annotations

from typing import Any

import tree_sitter as ts

from rebrew.matcher.ast_engine import _C_LANGUAGE


class _LazyQuery:
    """Defer tree-sitter query compilation until first use.

    This GA-only module defines ~98 queries; compiling them at import cost
    ~50ms of EVERY CLI invocation (status/todo/cfg/--help never use them).
    """

    __slots__ = ("_lang", "_source", "_query")

    def __init__(self, lang: ts.Language, source: str) -> None:
        self._lang = lang
        self._source = source
        self._query: ts.Query | None = None

    def _get(self) -> Any:
        """Return the compiled query, compiling on first use.

        Typed ``Any`` because the tree-sitter type stubs do not declare
        ``captures``/``matches`` on ``Query`` even though
        they exist at runtime.
        """
        if self._query is None:
            self._query = ts.Query(self._lang, self._source)
        return self._query

    def captures(self, *args: object, **kwargs: object) -> Any:
        return self._get().captures(*args, **kwargs)

    def matches(self, *args: object, **kwargs: object) -> Any:
        return self._get().matches(*args, **kwargs)


_QUERY_EQ_ZERO = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        ["==" "!="] @op
        right: (number_literal) @right
        (#eq? @right "0")) @expr
""",
)

_QUERY_FLIP_LT_GE = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        "<"
        right: (identifier) @right) @expr
""",
)

_QUERY_IDENTIFIER = _LazyQuery(
    _C_LANGUAGE,
    """
    (identifier) @expr
""",
)

_QUERY_SWAP_EQ = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        "=="
        right: (identifier) @right) @expr
""",
)

_QUERY_SWAP_NE = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        "!="
        right: (identifier) @right) @expr
""",
)

_QUERY_REASSOCIATE = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (parenthesized_expression (binary_expression left: (_) @a "+" right: (_) @b))
        "+"
        right: (_) @c) @expr
""",
)

_QUERY_SWAP_OR = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "||"
        right: (_) @right) @expr
""",
)

_QUERY_SWAP_AND = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "&&"
        right: (_) @right) @expr
""",
)

_QUERY_DOUBLE_NOT = _LazyQuery(
    _C_LANGUAGE,
    """
    (unary_expression
        operator: "!"
        argument: (unary_expression
            operator: "!"
            argument: (identifier) @ident)) @expr
""",
)

_QUERY_GOTO_RET_FALSE = _LazyQuery(
    _C_LANGUAGE,
    """
    (goto_statement
        (statement_identifier) @lbl
        (#eq? @lbl "ret_false")) @expr
""",
)

_QUERY_IF_ELSE = _LazyQuery(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond
        consequence: (_) @cons
        alternative: (else_clause (_) @alt)) @expr
""",
)

_QUERY_RHS_IDENT = _LazyQuery(
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

_QUERY_REMOVE_CAST = _LazyQuery(
    _C_LANGUAGE,
    """
    (cast_expression
        type: (type_descriptor) @type
        value: (_) @val
        (#match? @type "^(DWORD|int|BOOL|unsigned int)$")) @expr
""",
)

_QUERY_DECLARATION = _LazyQuery(
    _C_LANGUAGE,
    """
    (declaration) @expr
""",
)

# Anchored "zero in any C spelling" (0, 00, 0x0, 0L, 0UL).  A bare ``^0`` is a
# Rust-regex alternation ``(^0)|(FALSE$)``: unanchored ``^0`` matches EVERY
# ``0x…`` literal (0x100 is not false), so the mutations below rewrote non-zero
# values.
_RE_C_ZERO_LITERAL = r"^0[xX]?0*[uUlL]*$"

_QUERY_IF_FALSE_BITAND = _LazyQuery(
    _C_LANGUAGE,
    f"""
    [
      (if_statement
          condition: (parenthesized_expression (unary_expression operator: "!" argument: (_) @cond))
          consequence: (expression_statement (assignment_expression left: (identifier) @var right: (number_literal) @false_val (#match? @false_val "{_RE_C_ZERO_LITERAL}")))) @expr

      (if_statement
          condition: (parenthesized_expression (unary_expression operator: "!" argument: (_) @cond))
          consequence: (compound_statement (expression_statement (assignment_expression left: (identifier) @var right: (number_literal) @false_val (#match? @false_val "{_RE_C_ZERO_LITERAL}"))))) @expr
    ]
""",
)

_QUERY_ELSE_IF = _LazyQuery(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond1
        consequence: (_) @cons1
        alternative: (else_clause
            (if_statement
                condition: (parenthesized_expression) @cond2
                consequence: (_) @cons2
                alternative: (else_clause (_) @tail)?
            )
        )
    ) @expr
""",
)

_QUERY_BITAND = _LazyQuery(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression left: (identifier) @var operator: "&=" right: (_) @expr)
    ) @stmt
""",
)

_QUERY_CALL_ASSIGN = _LazyQuery(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression left: (identifier) @var right: (call_expression) @call)
    ) @expr
""",
)

_QUERY_TEMP_VAR = _LazyQuery(
    _C_LANGUAGE,
    """
    (compound_statement
        (expression_statement (assignment_expression left: (identifier) @tmp right: (_) @stmt)) @stmt1
        .
        (expression_statement (assignment_expression left: (identifier) @var right: (identifier) @tmp2 (#eq? @tmp @tmp2))) @stmt2
    )
""",
)

_QUERY_ADJACENT_DECL = _LazyQuery(
    _C_LANGUAGE,
    """
    (compound_statement
        (declaration) @d1
        .
        (declaration) @d2
    )
""",
)

_QUERY_SPLIT_DECL = _LazyQuery(
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

_QUERY_MERGE_DECL = _LazyQuery(
    _C_LANGUAGE,
    """
    (compound_statement
        (declaration type: (_) @type declarator: (identifier) @decl) @d1
        .
        (expression_statement (assignment_expression left: (identifier) @var right: (_) @init_expr (#eq? @decl @var))) @d2
    )
""",
)

_QUERY_WHILE = _LazyQuery(
    _C_LANGUAGE,
    """
    (while_statement
        condition: (parenthesized_expression) @cond
        body: (compound_statement) @body
    ) @stmt
""",
)

_QUERY_DO_WHILE = _LazyQuery(
    _C_LANGUAGE,
    """
    (do_statement
        body: (compound_statement) @body
        condition: (parenthesized_expression) @cond
    ) @stmt
""",
)

_QUERY_EARLY_RETURN = _LazyQuery(
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

_QUERY_ACCUM = _LazyQuery(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression left: (identifier) @var operator: "&=" right: (_) @expr (#match? @var "^(ret|retcode|result)$"))
    ) @stmt
""",
)

_QUERY_INT_PARAM = _LazyQuery(
    _C_LANGUAGE,
    """
    (parameter_declaration type: (primitive_type) @type declarator: (identifier) @var (#eq? @type "int")) @expr
""",
)

_QUERY_CONST_ADD_FOLD = _LazyQuery(
    _C_LANGUAGE,
    """
    (compound_statement
        (expression_statement (assignment_expression left: (identifier) @v1 operator: "=" right: (binary_expression left: (identifier) @v2 operator: "+" right: (number_literal) @n1 (#eq? @v1 @v2)))) @stmt1
        .
        (expression_statement (assignment_expression left: (identifier) @v3 operator: "=" right: (binary_expression left: (identifier) @v4 operator: "+" right: (number_literal) @n2 (#eq? @v3 @v4) (#eq? @v1 @v3)))) @stmt2
    )
""",
)

_QUERY_NUMBER_LITERAL = _LazyQuery(_C_LANGUAGE, "(number_literal) @lit")

_QUERY_CONST_ADD_UNFOLD = _LazyQuery(
    _C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression left: (identifier) @v1 operator: "=" right: (binary_expression left: (identifier) @v2 operator: "+" right: (number_literal) @n (#eq? @v1 @v2)))
    ) @stmt
""",
)

_QUERY_ARRAY_INDEX = _LazyQuery(
    _C_LANGUAGE,
    """
    (subscript_expression argument: (_) @arr index: (_) @idx) @expr
""",
)

_QUERY_PTR_ARROW = _LazyQuery(
    _C_LANGUAGE,
    """
    (field_expression argument: (_) @ptr "->" field: (field_identifier) @field) @expr
""",
)

_QUERY_RETURN_TYPE = _LazyQuery(
    _C_LANGUAGE,
    """
    (function_definition type: (primitive_type) @expr declarator: (_))
""",
)

_QUERY_PTR_PARAM = _LazyQuery(
    _C_LANGUAGE,
    """
    (parameter_declaration type: (primitive_type) @type declarator: (pointer_declarator declarator: (identifier) @var)) @stmt
""",
)

_QUERY_NESTED_IF_P3 = _LazyQuery(
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


_QUERY_COMBINE_PTR_ARITH = _LazyQuery(
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

_QUERY_SPLIT_PTR_ARITH = _LazyQuery(
    _C_LANGUAGE,
    """
    (expression_statement (assignment_expression left: (identifier) @v1 right: (binary_expression left: (identifier) @v2 operator: "+" right: (number_literal) @n1))) @stmt
    (#eq? @v1 @v2)
""",
)

_QUERY_PARAM_ORDER = _LazyQuery(
    _C_LANGUAGE,
    """
    (function_definition declarator: (function_declarator parameters: (parameter_list) @expr))
""",
)

_QUERY_CALL_CONV = _LazyQuery(
    _C_LANGUAGE,
    """
    (function_definition (ms_call_modifier) @expr)
""",
)

_QUERY_NO_CALL_CONV = _LazyQuery(
    _C_LANGUAGE,
    """
    (function_definition type: (_) @expr declarator: (function_declarator declarator: (identifier)))
""",
)
# NOTE: the type node is captured as ``@expr``, not ``@stmt``.
# ``_apply_query_once`` splices over ``stmt``/``expr``, so naming the whole
# ``function_definition`` here replaced the entire body with `int __cdecl`
# (the insertion branch of ``mut_toggle_calling_convention`` produced garbage).

_QUERY_SIZED_CHAR_TYPE = _LazyQuery(
    _C_LANGUAGE,
    """
    (sized_type_specifier
        type: (primitive_type) @base
        (#eq? @base "char")) @expr
""",
)

_QUERY_BARE_CHAR_TYPE = _LazyQuery(
    _C_LANGUAGE,
    """
    (primitive_type) @expr
    (#eq? @expr "char")
""",
)

_QUERY_CMP_BOUNDARY = _LazyQuery(
    _C_LANGUAGE,
    """
    (binary_expression left: (_) @left operator: [">" ">=" "<" "<="] @op right: (number_literal) @num) @expr
""",
)

# Note: Tree-sitter might see some macros or types differently.
# ``mut_return_to_goto`` rewrites the matched statement to ``goto ret_false;``
# and the label's tail to ``return 0;``, so a non-zero ``0x…`` literal matched
# by the old unanchored ``^0`` silently changed the returned value.
_QUERY_RETURN_FALSE = _LazyQuery(
    _C_LANGUAGE,
    f"""
    (return_statement
        (number_literal) @val
        (#match? @val "{_RE_C_ZERO_LITERAL}")) @expr
""",
)  # But for typical C code generated/decompiled, these work well.


# ---------------------------------------------------------------------------
# Queries for structural/code-layout mutations (formerly regex-only)
# ---------------------------------------------------------------------------

_QUERY_FOR_LOOP = _LazyQuery(
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

_QUERY_IF_ASSIGN_ELSE = _LazyQuery(
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

_QUERY_TERNARY = _LazyQuery(
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

_QUERY_ADJACENT_EXPR_STMTS = _LazyQuery(
    _C_LANGUAGE,
    """
    (compound_statement
        (expression_statement) @s1
        .
        (expression_statement) @s2
    )
""",
)

_QUERY_COMPOUND_ASSIGN = _LazyQuery(
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

_QUERY_EXPANDED_COMPOUND = _LazyQuery(
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

_QUERY_DEMORGAN_NOT_AND = _LazyQuery(
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

_QUERY_DEMORGAN_NOT_OR = _LazyQuery(
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

_QUERY_POST_INCREMENT = _LazyQuery(
    _C_LANGUAGE,
    """
    (update_expression argument: (identifier) @var operator: "++") @expr
""",
)

_QUERY_POST_DECREMENT = _LazyQuery(
    _C_LANGUAGE,
    """
    (update_expression argument: (identifier) @var operator: "--") @expr
""",
)

_QUERY_ASSIGN_ZERO = _LazyQuery(
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

_QUERY_XOR_SELF = _LazyQuery(
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

_QUERY_FOR_COUNT_UP = _LazyQuery(
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

_QUERY_IF_BODY_RETURN = _LazyQuery(
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


_QUERY_IF_STMT = _LazyQuery(_C_LANGUAGE, "(if_statement) @if_stmt")

# --- Queries for new mutations ---

_QUERY_SUBSCRIPT_EXPR = _QUERY_ARRAY_INDEX

_QUERY_BIN_COND_IF = _LazyQuery(
    _C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression (binary_expression
            left: (_) @left
            right: (_) @right) @bin)
        consequence: (_) @body) @stmt
""",
)

_QUERY_WHILE_LOOP = _LazyQuery(
    _C_LANGUAGE,
    """
    (while_statement
        condition: (parenthesized_expression) @cond
        body: (_) @body) @stmt
""",
)

_QUERY_DEREF_PTR_ADD = _LazyQuery(
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

_QUERY_SUBSCRIPT_SCALED = _LazyQuery(
    _C_LANGUAGE,
    """
    (subscript_expression
        argument: (_) @arr
        index: (binary_expression left: (_) @idx_left operator: "*" right: (_) @idx_right)
    ) @expr
""",
)

_QUERY_BYTE_TYPE_DECL = _LazyQuery(
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

_QUERY_BYTE_CAST = _LazyQuery(
    _C_LANGUAGE,
    """
    (cast_expression
        type: (type_descriptor) @type
        value: (_) @val
        (#match? @type "^(WORD|BYTE|unsigned short|unsigned char)$")
    ) @expr
""",
)

_QUERY_REGISTER_DECL = _LazyQuery(
    _C_LANGUAGE,
    """
    (declaration
        (storage_class_specifier) @sc
        (#eq? @sc "register")
    ) @stmt
""",
)


_QUERY_INJECT_DUMMY_VAR = _LazyQuery(
    _C_LANGUAGE, "(function_definition body: (compound_statement) @body)"
)
_QUERY_INJECT_DUMMY_ARRAY = _LazyQuery(
    _C_LANGUAGE, "(function_definition body: (compound_statement) @body)"
)
_QUERY_SCOPE_VARIABLE = _LazyQuery(
    _C_LANGUAGE,
    "\n        (function_definition body: (compound_statement\n            (declaration type: (_) @type declarator: (_) @decl) @d1\n            .\n            (expression_statement) @next_stmt\n        ))\n    ",
)
_QUERY_ADD_VOLATILE_INTERMEDIATE = _LazyQuery(
    _C_LANGUAGE,
    '\n        (expression_statement\n            (assignment_expression\n                left: (identifier) @var\n                operator: "="\n                right: (binary_expression) @rhs\n            )\n        ) @stmt\n    ',
)


_QUERY_TERNARY_ARG_TO_IF_ELSE_CALL = _LazyQuery(
    _C_LANGUAGE,
    "\n        (expression_statement\n            (call_expression\n                function: (_) @fn\n                arguments: (argument_list\n                    (conditional_expression\n                        condition: (_) @cond\n                        consequence: (_) @val_true\n                        alternative: (_) @val_false) @ternary)\n            ) @call\n        ) @stmt\n    ",
)
_QUERY_SINK_COMMON_TAIL = _LazyQuery(
    _C_LANGUAGE,
    "\n        (compound_statement\n            (if_statement\n                condition: (parenthesized_expression) @cond\n                consequence: (compound_statement) @if_body\n                alternative: (else_clause\n                    (compound_statement) @else_body)\n            ) @if_stmt\n            .\n            [\n                (expression_statement)\n                (return_statement)\n            ] @next_stmt\n        )\n    ",
)


_QUERY_LOCAL_DECL = _LazyQuery(
    _C_LANGUAGE,
    """
    (declaration type: (_) @type declarator: (_) @decl) @stmt
""",
)
