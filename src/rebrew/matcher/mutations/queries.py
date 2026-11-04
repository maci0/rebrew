"""queries.py — the shared tree-sitter query library for GA mutations.

The lazily compiled queries the mutation operators run against the seed's C
AST.  ``LazyQuery`` defers compilation so a run that never mutates does not pay
for the tree-sitter queries at import.
"""

from __future__ import annotations

lazy import threading
lazy from typing import Any

lazy import tree_sitter as ts

from rebrew.matcher.ast_engine import C_LANGUAGE


class LazyQuery:
    """Defer tree-sitter query compilation until first use.

    This GA-only module defines ~98 queries; compiling them at import cost
    ~50ms of EVERY CLI invocation (status/todo/cfg/--help never use them).

    Module-level instances are shared across ``match batch -j N`` stub
    workers; first-use compilation is guarded so two threads cannot both
    observe ``_query is None`` and race the assignment (tree-sitter's
    ``Query`` constructor can release the GIL).
    """

    __slots__ = ("_lang", "_lock", "_query", "_source")

    def __init__(self, lang: ts.Language, source: str) -> None:
        self._lang = lang
        self._source = source
        self._query: ts.Query | None = None
        self._lock = threading.Lock()

    def _get(self) -> Any:
        """Return the compiled query, compiling on first use.

        Typed ``Any`` because the tree-sitter type stubs do not declare
        ``captures``/``matches`` on ``Query`` even though
        they exist at runtime.
        """
        # Fast path: already compiled (common after the first mutation).
        cached = self._query
        if cached is not None:
            return cached
        with self._lock:
            if self._query is None:
                self._query = ts.Query(self._lang, self._source)
            return self._query


QUERY_EQ_ZERO = LazyQuery(
    C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        ["==" "!="] @op
        right: (number_literal) @right
        (#eq? @right "0")) @expr
""",
)

QUERY_FLIP_LT_GE = LazyQuery(
    C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        "<"
        right: (identifier) @right) @expr
""",
)

QUERY_IDENTIFIER = LazyQuery(
    C_LANGUAGE,
    """
    (identifier) @expr
""",
)

QUERY_SWAP_EQ = LazyQuery(
    C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        "=="
        right: (identifier) @right) @expr
""",
)

QUERY_SWAP_NE = LazyQuery(
    C_LANGUAGE,
    """
    (binary_expression
        left: (identifier) @left
        "!="
        right: (identifier) @right) @expr
""",
)

QUERY_REASSOCIATE = LazyQuery(
    C_LANGUAGE,
    """
    (binary_expression
        left: (parenthesized_expression (binary_expression left: (_) @a "+" right: (_) @b))
        "+"
        right: (_) @c) @expr
""",
)

QUERY_SWAP_OR = LazyQuery(
    C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "||"
        right: (_) @right) @expr
""",
)

QUERY_SWAP_AND = LazyQuery(
    C_LANGUAGE,
    """
    (binary_expression
        left: (_) @left
        "&&"
        right: (_) @right) @expr
""",
)

QUERY_DOUBLE_NOT = LazyQuery(
    C_LANGUAGE,
    """
    (unary_expression
        operator: "!"
        argument: (unary_expression
            operator: "!"
            argument: (identifier) @ident)) @expr
""",
)

QUERY_GOTO_RET_FALSE = LazyQuery(
    C_LANGUAGE,
    """
    (goto_statement
        (statement_identifier) @lbl
        (#eq? @lbl "ret_false")) @expr
""",
)

QUERY_IF_ELSE = LazyQuery(
    C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond
        consequence: (_) @cons
        alternative: (else_clause (_) @alt)) @expr
""",
)

QUERY_RHS_IDENT = LazyQuery(
    C_LANGUAGE,
    """
    [
        (assignment_expression right: (identifier) @expr)
        (init_declarator value: (identifier) @expr)
        (return_statement (identifier) @expr)
        (argument_list (identifier) @expr)
    ]
""",
)

QUERY_REMOVE_CAST = LazyQuery(
    C_LANGUAGE,
    """
    (cast_expression
        type: (type_descriptor) @type
        value: (_) @val
        (#match? @type "^(DWORD|int|BOOL|unsigned int)$")) @expr
""",
)

QUERY_DECLARATION = LazyQuery(
    C_LANGUAGE,
    """
    (declaration) @expr
""",
)

# Anchored "zero in any C spelling" (0, 00, 0x0, 0L, 0UL).  A bare ``^0`` is a
# Rust-regex alternation ``(^0)|(FALSE$)``: unanchored ``^0`` matches EVERY
# ``0x…`` literal (0x100 is not false), so the mutations below rewrote non-zero
# values.
_RE_C_ZERO_LITERAL = r"^0[xX]?0*[uUlL]*$"

QUERY_IF_FALSE_BITAND = LazyQuery(
    C_LANGUAGE,
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

QUERY_ELSE_IF = LazyQuery(
    C_LANGUAGE,
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

QUERY_BITAND = LazyQuery(
    C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression left: (identifier) @var operator: "&=" right: (_) @expr)
    ) @stmt
""",
)

QUERY_CALL_ASSIGN = LazyQuery(
    C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression left: (identifier) @var right: (call_expression) @call)
    ) @expr
""",
)

QUERY_TEMP_VAR = LazyQuery(
    C_LANGUAGE,
    """
    (compound_statement
        (expression_statement (assignment_expression left: (identifier) @tmp right: (_) @stmt)) @stmt1
        .
        (expression_statement (assignment_expression left: (identifier) @var right: (identifier) @tmp2 (#eq? @tmp @tmp2))) @stmt2
    )
""",
)

QUERY_ADJACENT_DECL = LazyQuery(
    C_LANGUAGE,
    """
    (compound_statement
        (declaration) @d1
        .
        (declaration) @d2
    )
""",
)

QUERY_SPLIT_DECL = LazyQuery(
    C_LANGUAGE,
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

QUERY_MERGE_DECL = LazyQuery(
    C_LANGUAGE,
    """
    (compound_statement
        (declaration type: (_) @type declarator: (identifier) @decl) @d1
        .
        (expression_statement (assignment_expression left: (identifier) @var right: (_) @init_expr (#eq? @decl @var))) @d2
    )
""",
)

QUERY_WHILE = LazyQuery(
    C_LANGUAGE,
    """
    (while_statement
        condition: (parenthesized_expression) @cond
        body: (compound_statement) @body
    ) @stmt
""",
)

QUERY_DO_WHILE = LazyQuery(
    C_LANGUAGE,
    """
    (do_statement
        body: (compound_statement) @body
        condition: (parenthesized_expression) @cond
    ) @stmt
""",
)

QUERY_EARLY_RETURN = LazyQuery(
    C_LANGUAGE,
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

QUERY_ACCUM = LazyQuery(
    C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression left: (identifier) @var operator: "&=" right: (_) @expr (#match? @var "^(ret|retcode|result)$"))
    ) @stmt
""",
)

QUERY_INT_PARAM = LazyQuery(
    C_LANGUAGE,
    """
    (parameter_declaration type: (primitive_type) @type declarator: (identifier) @var (#eq? @type "int")) @expr
""",
)

QUERY_CONST_ADD_FOLD = LazyQuery(
    C_LANGUAGE,
    """
    (compound_statement
        (expression_statement (assignment_expression left: (identifier) @v1 operator: "=" right: (binary_expression left: (identifier) @v2 operator: "+" right: (number_literal) @n1 (#eq? @v1 @v2)))) @stmt1
        .
        (expression_statement (assignment_expression left: (identifier) @v3 operator: "=" right: (binary_expression left: (identifier) @v4 operator: "+" right: (number_literal) @n2 (#eq? @v3 @v4) (#eq? @v1 @v3)))) @stmt2
    )
""",
)

QUERY_NUMBER_LITERAL = LazyQuery(C_LANGUAGE, "(number_literal) @lit")

#: A pointer-cast dereference (``*(T*)p``): the per-access qualifier site.
#: MSVC6 keys the memory-operand fold and the store ordering off the qualifier
#: on the access, so a cast-qualified lvalue is a lever of its own, separate
#: from the declaration-level ``volatile`` of `mut_toggle_volatile`.
QUERY_VOLATILE_ACCESS = LazyQuery(
    C_LANGUAGE,
    "(pointer_expression argument: (cast_expression (type_descriptor) @ty)) @expr",
)

QUERY_CONST_ADD_UNFOLD = LazyQuery(
    C_LANGUAGE,
    """
    (expression_statement
        (assignment_expression left: (identifier) @v1 operator: "=" right: (binary_expression left: (identifier) @v2 operator: "+" right: (number_literal) @n (#eq? @v1 @v2)))
    ) @stmt
""",
)

QUERY_ARRAY_INDEX = LazyQuery(
    C_LANGUAGE,
    """
    (subscript_expression argument: (_) @arr index: (_) @idx) @expr
""",
)

QUERY_PTR_ARROW = LazyQuery(
    C_LANGUAGE,
    """
    (field_expression argument: (_) @ptr "->" field: (field_identifier) @field) @expr
""",
)

QUERY_RETURN_TYPE = LazyQuery(
    C_LANGUAGE,
    """
    (function_definition type: (primitive_type) @expr declarator: (_))
""",
)

QUERY_PTR_PARAM = LazyQuery(
    C_LANGUAGE,
    """
    (parameter_declaration type: (primitive_type) @type declarator: (pointer_declarator declarator: (identifier) @var)) @stmt
""",
)

QUERY_NESTED_IF_P3 = LazyQuery(
    C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression) @cond1
        consequence: (compound_statement
            (if_statement
                condition: (parenthesized_expression) @cond2
                consequence: (_) @body) @inner_if) @outer_body) @stmt
""",
)


QUERY_COMBINE_PTR_ARITH = LazyQuery(
    C_LANGUAGE,
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

QUERY_SPLIT_PTR_ARITH = LazyQuery(
    C_LANGUAGE,
    """
    (expression_statement (assignment_expression left: (identifier) @v1 right: (binary_expression left: (identifier) @v2 operator: "+" right: (number_literal) @n1))) @stmt
    (#eq? @v1 @v2)
""",
)

QUERY_PARAM_ORDER = LazyQuery(
    C_LANGUAGE,
    """
    (function_definition declarator: (function_declarator parameters: (parameter_list) @expr))
""",
)

QUERY_CALL_CONV = LazyQuery(
    C_LANGUAGE,
    """
    (function_definition (ms_call_modifier) @expr)
""",
)

QUERY_NO_CALL_CONV = LazyQuery(
    C_LANGUAGE,
    """
    (function_definition type: (_) @expr declarator: (function_declarator declarator: (identifier)))
""",
)
# NOTE: the type node is captured as ``@expr``, not ``@stmt``.
# ``apply_query_once`` splices over ``stmt``/``expr``, so naming the whole
# ``function_definition`` here replaced the entire body with `int __cdecl`
# (the insertion branch of ``mut_toggle_calling_convention`` produced garbage).

QUERY_SIZED_CHAR_TYPE = LazyQuery(
    C_LANGUAGE,
    """
    (sized_type_specifier
        type: (primitive_type) @base
        (#eq? @base "char")) @expr
""",
)

QUERY_BARE_CHAR_TYPE = LazyQuery(
    C_LANGUAGE,
    """
    (primitive_type) @expr
    (#eq? @expr "char")
""",
)

QUERY_CMP_BOUNDARY = LazyQuery(
    C_LANGUAGE,
    """
    (binary_expression left: (_) @left operator: [">" ">=" "<" "<="] @op right: (number_literal) @num) @expr
""",
)

# ``mut_return_to_goto`` rewrites the matched statement to ``goto ret_false;``
# and the label's tail to ``return 0;``, so only the exact zero literal can
# match: a non-zero ``0x…`` would silently change the returned value.
QUERY_RETURN_FALSE = LazyQuery(
    C_LANGUAGE,
    f"""
    (return_statement
        (number_literal) @val
        (#match? @val "{_RE_C_ZERO_LITERAL}")) @expr
""",
)


# ---------------------------------------------------------------------------
# Queries for structural/code-layout mutations (formerly regex-only)
# ---------------------------------------------------------------------------

QUERY_FOR_LOOP = LazyQuery(
    C_LANGUAGE,
    """
    (for_statement
        initializer: (_)? @init
        condition: (_)? @cond
        update: (_)? @update
        body: (compound_statement) @body
    ) @stmt
""",
)

QUERY_IF_ASSIGN_ELSE = LazyQuery(
    C_LANGUAGE,
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

QUERY_TERNARY = LazyQuery(
    C_LANGUAGE,
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

QUERY_ADJACENT_EXPR_STMTS = LazyQuery(
    C_LANGUAGE,
    """
    (compound_statement
        (expression_statement) @s1
        .
        (expression_statement) @s2
    )
""",
)

QUERY_COMPOUND_ASSIGN = LazyQuery(
    C_LANGUAGE,
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

QUERY_EXPANDED_COMPOUND = LazyQuery(
    C_LANGUAGE,
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

QUERY_DEMORGAN_NOT_AND = LazyQuery(
    C_LANGUAGE,
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

QUERY_DEMORGAN_NOT_OR = LazyQuery(
    C_LANGUAGE,
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

QUERY_POST_INCREMENT = LazyQuery(
    C_LANGUAGE,
    """
    (update_expression argument: (identifier) @var operator: "++") @expr
""",
)

QUERY_POST_DECREMENT = LazyQuery(
    C_LANGUAGE,
    """
    (update_expression argument: (identifier) @var operator: "--") @expr
""",
)

QUERY_ASSIGN_ZERO = LazyQuery(
    C_LANGUAGE,
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

QUERY_XOR_SELF = LazyQuery(
    C_LANGUAGE,
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

QUERY_FOR_COUNT_UP = LazyQuery(
    C_LANGUAGE,
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

QUERY_IF_BODY_RETURN = LazyQuery(
    C_LANGUAGE,
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


QUERY_IF_STMT = LazyQuery(C_LANGUAGE, "(if_statement) @if_stmt")

# --- Queries for new mutations ---

QUERY_BIN_COND_IF = LazyQuery(
    C_LANGUAGE,
    """
    (if_statement
        condition: (parenthesized_expression (binary_expression
            left: (_) @left
            right: (_) @right) @bin)
        consequence: (_) @body) @stmt
""",
)

QUERY_WHILE_LOOP = LazyQuery(
    C_LANGUAGE,
    """
    (while_statement
        condition: (parenthesized_expression) @cond
        body: (_) @body) @stmt
""",
)

QUERY_DEREF_PTR_ADD = LazyQuery(
    C_LANGUAGE,
    """
    (pointer_expression
        operator: "*"
        argument: (parenthesized_expression
            (binary_expression left: (_) @ptr operator: "+" right: (_) @idx)
        )
    ) @expr
""",
)

QUERY_SUBSCRIPT_SCALED = LazyQuery(
    C_LANGUAGE,
    """
    (subscript_expression
        argument: (_) @arr
        index: (binary_expression left: (_) @idx_left operator: "*" right: (_) @idx_right)
    ) @expr
""",
)

QUERY_BYTE_TYPE_DECL = LazyQuery(
    C_LANGUAGE,
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

QUERY_BYTE_CAST = LazyQuery(
    C_LANGUAGE,
    """
    (cast_expression
        type: (type_descriptor) @type
        value: (_) @val
        (#match? @type "^(WORD|BYTE|unsigned short|unsigned char)$")
    ) @expr
""",
)

QUERY_REGISTER_DECL = LazyQuery(
    C_LANGUAGE,
    """
    (declaration
        (storage_class_specifier) @sc
        (#eq? @sc "register")
    ) @stmt
""",
)


#: Shared tree-sitter query: a function's entire body block.
QUERY_BODY = "(function_definition body: (compound_statement) @body)"

QUERY_INJECT_DUMMY_VAR = LazyQuery(C_LANGUAGE, QUERY_BODY)
QUERY_INJECT_DUMMY_ARRAY = LazyQuery(C_LANGUAGE, QUERY_BODY)
QUERY_SCOPE_VARIABLE = LazyQuery(
    C_LANGUAGE,
    "\n        (function_definition body: (compound_statement\n            (declaration type: (_) @type declarator: (_) @decl) @d1\n            .\n            (expression_statement) @next_stmt\n        ))\n    ",
)
QUERY_ADD_VOLATILE_INTERMEDIATE = LazyQuery(
    C_LANGUAGE,
    '\n        (expression_statement\n            (assignment_expression\n                left: (identifier) @var\n                operator: "="\n                right: (binary_expression) @rhs\n            )\n        ) @stmt\n    ',
)


QUERY_TERNARY_ARG_TO_IF_ELSE_CALL = LazyQuery(
    C_LANGUAGE,
    "\n        (expression_statement\n            (call_expression\n                function: (_) @fn\n                arguments: (argument_list\n                    (conditional_expression\n                        condition: (_) @cond\n                        consequence: (_) @val_true\n                        alternative: (_) @val_false) @ternary)\n            ) @call\n        ) @stmt\n    ",
)
QUERY_SINK_COMMON_TAIL = LazyQuery(
    C_LANGUAGE,
    "\n        (compound_statement\n            (if_statement\n                condition: (parenthesized_expression) @cond\n                consequence: (compound_statement) @if_body\n                alternative: (else_clause\n                    (compound_statement) @else_body)\n            ) @if_stmt\n            .\n            [\n                (expression_statement)\n                (return_statement)\n            ] @next_stmt\n        )\n    ",
)


QUERY_LOCAL_DECL = LazyQuery(
    C_LANGUAGE,
    """
    (declaration type: (_) @type declarator: (_) @decl) @stmt
""",
)


#: Statements only: inserting `if (0) {}` ahead of a *declaration* puts a
#: statement before the block's declarations, which C89 (and MSVC6) rejects.
QUERY_INSERT_NOOP_BLOCK = LazyQuery(
    C_LANGUAGE,
    "(compound_statement [(expression_statement) (return_statement)] @stmt)",
)
QUERY_INTRODUCE_LOCAL_ALIAS = LazyQuery(
    C_LANGUAGE, "(expression_statement (assignment_expression right: (identifier) @var)) @stmt"
)


QUERY_REORDER_DECLARATIONS = LazyQuery(
    C_LANGUAGE, "\n        (compound_statement (declaration) @d1 (declaration) @d2)\n    "
)
QUERY_HOIST_RETURN = LazyQuery(C_LANGUAGE, "(return_statement (_) @val) @stmt")
QUERY_NEGATE_CONDITION = LazyQuery(
    C_LANGUAGE, "(if_statement condition: (parenthesized_expression) @cond) @stmt"
)

# --- Lever queries: C shapes a real 2002 MSVC6 build keys its codegen off ---

#: Every conditional, so the caller can keep the equal-arm ones.  Narrowed in
#: Python because "both arms are the same constant" is a text comparison.
QUERY_CONDITIONAL = LazyQuery(C_LANGUAGE, "(conditional_expression) @cond")

#: A negated comparison, ``-(a != b)``: MSVC6 compiles it to the setne form
#: where the ternary spelling gets the fused ``sbb`` (7 bytes shorter).
QUERY_NEGATED_COMPARISON = LazyQuery(
    C_LANGUAGE,
    "(unary_expression argument: (parenthesized_expression (binary_expression) @cmp)) @un",
)

#: An initialized declaration, the shape a pointer walk into a local copy takes.
QUERY_INIT_DECLARATION = LazyQuery(
    C_LANGUAGE,
    "(declaration (init_declarator declarator: (_) @declarator value: (_) @init) @decl) @stmt",
)

#: A byte-typed local (with or without an initializer): the value a dead
#: parameter slot can home instead of spilling a fresh dword.
QUERY_BYTE_LOCAL_DECL = LazyQuery(
    C_LANGUAGE,
    """
    (declaration
        type: [(primitive_type) (sized_type_specifier)] @type
        declarator: [
            (identifier) @name
            (init_declarator
                declarator: (identifier) @name
                value: (_) @init
            )
        ]
    ) @stmt
""",
)

#: A call through a plain function name: the site whose caller-side prototype
#: view a function-pointer cast can change.
QUERY_PLAIN_CALL = LazyQuery(
    C_LANGUAGE,
    "(call_expression function: (identifier) @fn arguments: (argument_list) @args) @call",
)
