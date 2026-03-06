"""mutator.py – C source mutation engine for GA-based binary matching.

Provides 67 mutation functions that transform C89 source code to explore
the MSVC6 code generation space. Each mutation targets a specific compiler
behavior (register allocation, instruction selection, calling conventions,
and code layout / control flow structure).
"""

import random
import re
from collections.abc import Callable
from typing import Literal, overload

# ---------------------------------------------------------------------------
# Pre-compiled regex patterns (module-level for performance)
# ---------------------------------------------------------------------------

_RE_FUNC_START = re.compile(
    r"^[a-zA-Z_][a-zA-Z0-9_*\s]*\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(",
    re.MULTILINE,
)
_RE_COMMUTE_ADD = re.compile(r"\b([A-Za-z_]\w*)\s*\+\s*([A-Za-z_]\w*)\b")
_RE_COMMUTE_MUL = re.compile(r"\b([A-Za-z_]\w*)\s*\*\s*([A-Za-z_]\w*)\b")
_RE_FLIP_EQ_ZERO = re.compile(r"\b([A-Za-z_]\w*)\s*(==|!=)\s*0\b")
_RE_FLIP_LT_GE = re.compile(r"\b([A-Za-z_]\w*)\s*<\s*([A-Za-z_]\w*)\b")
_C_KEYWORDS = frozenset(
    {
        "auto",
        "break",
        "case",
        "char",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "float",
        "for",
        "goto",
        "if",
        "int",
        "long",
        "register",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "typedef",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while",
        "BOOL",
        "DWORD",
        "HANDLE",
        "LPVOID",
        "LPCSTR",
        "LPSTR",
        "HRESULT",
        "UINT",
        "ULONG",
        "BYTE",
        "WORD",
        "SIZE_T",
        "WPARAM",
        "LPARAM",
        "LRESULT",
        "TRUE",
        "FALSE",
        "NULL",
        "include",
        "define",
        "ifdef",
        "ifndef",
        "endif",
        "pragma",
    }
)
_RE_ADD_PARENS = re.compile(r"\b([A-Za-z_]\w*)\b")
_RE_REASSOCIATE = re.compile(
    r"\(\s*([A-Za-z_]\w*)\s*\+\s*([A-Za-z_]\w*)\s*\)\s*\+\s*([A-Za-z_]\w*)"
)
_RE_DOUBLE_NOT = re.compile(r"!!\s*([A-Za-z_]\w*)")
_RE_SWAP_EQ = re.compile(r"(\b\w+\b)\s*==\s*(\b\w+\b)")
_RE_SWAP_NE = re.compile(r"(\b\w+\b)\s*!=\s*(\b\w+\b)")
_RE_SWAP_OR = re.compile(r"([^|&\n]+?)\s*\|\|\s*([^|&\n;)]+)")
_RE_SWAP_AND = re.compile(r"([^|&\n]+?)\s*&&\s*([^|&\n;)]+)")
_RE_RETURN_FALSE = re.compile(r"\breturn\s+(?:FALSE|0)\s*;")
_RE_GOTO_RET_FALSE = re.compile(r"\bgoto\s+ret_false\s*;")
_RE_FINAL_RET = re.compile(r"(\n)([ \t]*return\s+\w+\s*;\s*\n\})")
_RE_RET_FALSE_LABEL = re.compile(r"\n\s*ret_false:\s*\n\s*return\s+0\s*;\s*\n")
_RE_RET_FALSE_LABEL_BARE = re.compile(r"\n\s*ret_false:\s*\n")
_RE_LOCAL_PARAMS = re.compile(r"\b(?:HANDLE|DWORD|LPVOID|int|BOOL)\s+(\w+)")
_RE_BRACE_AFTER_PAREN = re.compile(r"\)\s*\{")
_RE_DECL_LINE = re.compile(r"^([ \t]+)((?:BOOL|int|DWORD|HANDLE|LPVOID)\s+\w+)\s*;$", re.MULTILINE)
_RE_INIT_LINE = re.compile(
    r"^([ \t]+(?:BOOL|int|DWORD|HANDLE|LPVOID)\s+\w+)\s*=\s*[^;]+;$", re.MULTILINE
)
_RE_IF_COND = re.compile(r"\bif\s*\(([^{]*?)\)\s*\{")
_RE_ELSEIF_CHAIN = re.compile(r"(\bif\s*\([^{]*?\)\s*\{)")
_RE_CAST_TARGET = re.compile(r"(?<=[=(,!])\s*(\b[A-Za-z_]\w*\b)(?!\s*\()")
_RE_REMOVE_CAST = re.compile(r"\((?:BOOL|int|DWORD|HANDLE|LPVOID)\)(\w+)")
_RE_VOLATILE = re.compile(r"\bvolatile\s+")
_RE_ADD_VOLATILE = re.compile(r"^([ \t]+)((?:BOOL|int|DWORD|HANDLE|LPVOID)\s+\w+)", re.MULTILINE)
_RE_ADD_REGISTER = re.compile(r"^([ \t]+)((?:BOOL|int|DWORD|HANDLE|LPVOID)\s+\w+)", re.MULTILINE)
_RE_REMOVE_REGISTER = re.compile(r"\bregister\s+")
_RE_IF_FALSE_BITAND = re.compile(
    r"if\s*\(\s*!\s*(\w+\s*\([^)]*(?:\([^)]*\)[^)]*)*\))\s*\)\s*\n?\s*(\w+)\s*=\s*(?:FALSE|0)\s*;"
)
_RE_BITAND_TO_IF = re.compile(r"(\w+)\s*&=\s*(\w+\s*\([^)]*(?:\([^)]*\)[^)]*)*\))\s*;")
_RE_VAR_ASSIGN_CALL = re.compile(r"(\w+)\s*=\s*(\w+\s*\([^;]+\))\s*;")
_RE_BOOL_TMP_DECL = re.compile(r"\b(?:BOOL|int)\s+tmp\b")
_RE_TEMP_VAR = re.compile(r"tmp\s*=\s*([^;]+);\s*\n\s*(\w+)\s*=\s*tmp\s*;")
_RE_UNSIGNED_REMOVE = re.compile(r"\bunsigned\s+(int|long|short|char)\b")
_RE_UNSIGNED_ADD = re.compile(r"(?<!\bunsigned\s)(?<!\bsigned\s)\b(int|long|short)\s+(\w+)\s*[;=,]")
_TYPE_PAT_STR = (
    r"(?:const\s+)?(?:unsigned\s+)?(?:volatile\s+)?"
    r"(?:BOOL|int|DWORD|HANDLE|LPVOID|HLOCAL|void|char|short|long|float|double|"
    r"UINT|ULONG|BYTE|WORD|SIZE_T|CRITICAL_SECTION|ushort|uint|undefined\d?)"
)
_RE_DECL_SWAP = re.compile(
    r"^([ \t]+)(" + _TYPE_PAT_STR + r")\s+\**\w+(?:\s*\[[^\]]*\])?\s*(?:=\s*[^;]+)?;\s*$"
)
_TYPE_KW = (
    r"(?:BOOL|int|DWORD|HANDLE|LPVOID|char|short|long|float|double|"
    r"UINT|ULONG|BYTE|WORD)"
)
_RE_SPLIT_DECL = re.compile(
    r"^([ \t]+)((?:const\s+)?(?:unsigned\s+)?(?:volatile\s+)?"
    + _TYPE_KW
    + r"\s+\**(\w+))\s*=\s*([^;]+);",
    re.MULTILINE,
)
_RE_MERGE_DECL = re.compile(
    r"^([ \t]+)((?:unsigned\s+)?(?:volatile\s+)?" + _TYPE_KW + r")\s+(\w+)\s*;\s*\n"
    r"\1\3\s*=\s*([^;]+);",
    re.MULTILINE,
)
_RE_WHILE_LOOP = re.compile(r"\bwhile\s*\(")
_RE_DO_WHILE = re.compile(r"\bdo\s*\{")
_RE_DO_WHILE_COND = re.compile(r"while\s*\((.+)\)\s*;")  # .+ allows nested parens like func()
_RE_EARLY_RETURN = re.compile(
    r"if\s*\(\s*!\s*(\w+\s*\([^)]*(?:\([^)]*\)[^)]*)*\))\s*\)\s*\n?\s*return\s+(?:FALSE|0)\s*;"
)
_RE_ACCUM = re.compile(r"(\w+)\s*&=\s*(\w+\s*\([^)]*(?:\([^)]*\)[^)]*)*\))\s*;")
_RE_RETCODE_VAR = re.compile(r"\bret(?:code)?\b")
_RE_PTR_PARAM = re.compile(r"\b(char|void|int|short|long|unsigned\s+char)\s*\*\s*(\w+)")
_RE_INT_PARAM = re.compile(r"(?<=[(,])\s*int\s+(\w+)")
_RE_CONST_ADD = re.compile(r"(\w+)\s*=\s*\1\s*\+\s*(\d+);\s*(\1)\s*=\s*\3\s*\+\s*(\d+);")
_RE_SINGLE_ADD = re.compile(r"(\w+)\s*=\s*\1\s*\+\s*(\d+);")
_RE_ARRAY_INDEX = re.compile(r"(\w+)\s*\[\s*(\w+)\s*\]")
_RE_PTR_ARROW = re.compile(r"(\w+)\s*->\s*(\w+)")
_RE_CMP_CHAIN_3 = re.compile(r"if\s*\(([^=!&|]+)\s*&&\s*([^=!&|]+)\s*&&\s*([^)]+)\)", re.MULTILINE)
_RE_CMP_CHAIN_2 = re.compile(r"if\s*\(([^=!&|]+)\s*&&\s*([^)]+)\)")
_RE_MERGE_IF = re.compile(r"if\s*\(([^)]+)\)\s*\{\s*\}\s*if\s*\(([^)]+)\)\s*\{\s*\}")
_RE_PTR_ARITH_DOUBLE = _RE_CONST_ADD  # Same pattern: fold two consecutive adds
_RE_PTR_ARITH_SINGLE = _RE_SINGLE_ADD  # Same pattern: split a single add
_RE_RETURN_TYPE = re.compile(r"^(int|char|short|long)\s+(\*?\s*\w+)\s*\([^)]*\)\s*\{", re.MULTILINE)
_RE_FUNC_SIG = re.compile(r"^(\w+(?:[ \t]+\w+)+)[ \t]*\(([^)]+)\)[ \t]*\{", re.MULTILINE)
# Validation patterns (used by quick_validate)
_RE_VALIDATE_LABEL = re.compile(r"^\s*([a-zA-Z_]\w*)\s*:", re.MULTILINE)
_LABEL_IGNORE = frozenset({"case", "default", "public", "private", "protected"})
_TYPE_KEYWORDS = (
    r"(?:BOOL|int|DWORD|HANDLE|LPVOID|void|char|short|long|float|double|"
    r"unsigned|signed|const|volatile|register|UINT|ULONG|BYTE|WORD)"
)
_RE_VALIDATE_DOUBLE_TYPE = re.compile(r"\b(" + _TYPE_KEYWORDS + r")\s+\1\b")


def _split_preamble_body(source: str) -> tuple[str, str]:
    """Split source into preamble (includes, typedefs, externs) and function body."""
    lines = source.splitlines()
    preamble = []
    body = []
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
            if brace_count == 0 and "}" in line:
                # We might have trailing stuff, but usually it's just one function
                pass

    return "\n".join(preamble), "\n".join(body)


def quick_validate(source: str) -> bool:
    """Fast check for obvious syntax errors that would waste a compilation round.

    Checks:
    - Balanced braces and parentheses
    - At least one function definition present
    - No duplicate goto labels (e.g. two ``ret_false:`` labels)
    - No adjacent duplicate type keywords (e.g. ``int int``)
    """
    if source.count("{") != source.count("}"):
        return False
    if source.count("(") != source.count(")"):
        return False

    # Must contain at least one function definition
    if not _RE_FUNC_START.search(source):
        return False

    # Detect duplicate goto labels (common mutation artifact)
    labels: set[str] = set()
    for m in _RE_VALIDATE_LABEL.finditer(source):
        label = m.group(1)
        if label in _LABEL_IGNORE:
            continue
        if label in labels:
            return False
        labels.add(label)

    # Detect adjacent duplicate type keywords (e.g. "int int x;")
    return not _RE_VALIDATE_DOUBLE_TYPE.search(source)


def compute_population_diversity(pop: list[str]) -> float:
    """Compute diversity of the population (0.0 to 1.0)."""
    if not pop or len(pop) < 2:
        return 0.0

    unique_sources = set(pop)
    return len(unique_sources) / len(pop)


def crossover(parent1: str, parent2: str, rng: random.Random) -> str:
    """Line-level crossover of two parent sources."""
    p1_pre, p1_body = _split_preamble_body(parent1)
    _, p2_body = _split_preamble_body(parent2)

    lines1 = p1_body.splitlines()
    lines2 = p2_body.splitlines()

    if not lines1 or not lines2:
        return parent1

    # Need at least 2 lines in both parents to have a meaningful split point
    min_len = min(len(lines1), len(lines2))
    if min_len < 2:
        return parent1

    split_idx = rng.randint(1, min_len - 1)

    child_body = "\n".join(lines1[:split_idx] + lines2[split_idx:])
    child = p1_pre + "\n" + child_body

    if quick_validate(child):
        return child
    return parent1


# --- Mutations ---


def _sub_once(
    pat: str | re.Pattern[str],
    repl: str | Callable[[re.Match[str]], str],
    s: str,
    rng: random.Random,
) -> str | None:
    """Helper to randomly replace one occurrence of a pattern."""
    matches = list(pat.finditer(s) if isinstance(pat, re.Pattern) else re.finditer(pat, s))
    if not matches:
        return None
    m = rng.choice(matches)
    replacement: str = repl if isinstance(repl, str) else repl(m)
    return s[: m.start()] + replacement + s[m.end() :]


def mut_commute_simple_add(s: str, rng: random.Random) -> str | None:
    """Swap operands of simple identifier addition expressions."""
    # x + y  -> y + x  (identifiers only)
    return _sub_once(_RE_COMMUTE_ADD, lambda m: f"{m.group(2)} + {m.group(1)}", s, rng)


def mut_commute_simple_mul(s: str, rng: random.Random) -> str | None:
    """Swap operands of simple identifier multiplication expressions."""
    return _sub_once(_RE_COMMUTE_MUL, lambda m: f"{m.group(2)} * {m.group(1)}", s, rng)


def mut_flip_eq_zero(s: str, rng: random.Random) -> str | None:
    """Rewrite ``x == 0``/``x != 0`` into boolean-not forms."""

    # x == 0 -> !x , x != 0 -> !!x
    def repl(m: re.Match[str]) -> str:
        x, op = m.group(1), m.group(2)
        return f"!{x}" if op == "==" else f"!!{x}"

    return _sub_once(_RE_FLIP_EQ_ZERO, repl, s, rng)


def mut_flip_lt_ge(s: str, rng: random.Random) -> str | None:
    """Rewrite ``a < b`` into the equivalent negated ``>=`` form."""
    # a < b -> !(a >= b)
    return _sub_once(_RE_FLIP_LT_GE, lambda m: f"!({m.group(1)} >= {m.group(2)})", s, rng)


def mut_add_redundant_parens(s: str, rng: random.Random) -> str | None:
    """Wrap a random non-keyword identifier in redundant parentheses."""
    matches = [m for m in _RE_ADD_PARENS.finditer(s) if m.group(1) not in _C_KEYWORDS]
    if not matches:
        return None
    m = rng.choice(matches)
    return s[: m.start()] + f"({m.group(1)})" + s[m.end() :]


def mut_reassociate_add(s: str, rng: random.Random) -> str | None:
    """Reassociate ``(a + b) + c`` into ``a + (b + c)``."""
    # (a + b) + c -> a + (b + c)
    return _sub_once(
        _RE_REASSOCIATE, lambda m: f"{m.group(1)} + ({m.group(2)} + {m.group(3)})", s, rng
    )


def mut_insert_noop_block(s: str, rng: random.Random) -> str | None:
    """Insert a no-op volatile block at a random line boundary."""
    # Insert a no-op volatile read, tends to affect optimization, use sparingly.
    insertion = "\n    { volatile int __noop = 0; (void)__noop; }\n"
    lines = s.splitlines(True)
    if len(lines) < 3:
        return None
    idx = rng.randrange(0, len(lines))
    return "".join(lines[:idx] + [insertion] + lines[idx:])


def mut_toggle_bool_not(s: str, rng: random.Random) -> str | None:
    """Remove one ``!!identifier`` sequence."""
    # !!x -> x, and x -> !!x for identifiers in boolean contexts is unsafe.
    # Here only remove !! on identifiers.
    return _sub_once(_RE_DOUBLE_NOT, lambda m: f"{m.group(1)}", s, rng)


def mut_swap_eq_operands(s: str, rng: random.Random) -> str | None:
    """a == b -> b == a"""
    return _sub_once(_RE_SWAP_EQ, lambda m: f"{m.group(2)} == {m.group(1)}", s, rng)


def mut_swap_ne_operands(s: str, rng: random.Random) -> str | None:
    """a != b -> b != a"""
    return _sub_once(_RE_SWAP_NE, lambda m: f"{m.group(2)} != {m.group(1)}", s, rng)


def mut_swap_or_operands(s: str, rng: random.Random) -> str | None:
    """a || b -> b || a  (changes short-circuit order, affects codegen)"""
    matches = list(_RE_SWAP_OR.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    a_text = m.group(1).strip()
    b_text = m.group(2).strip()
    if a_text == b_text:
        return None
    start, end = m.span()
    return s[:start] + f"{b_text} || {a_text}" + s[end:]


def mut_swap_and_operands(s: str, rng: random.Random) -> str | None:
    """a && b -> b && a"""
    matches = list(_RE_SWAP_AND.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    a_text = m.group(1).strip()
    b_text = m.group(2).strip()
    if a_text == b_text:
        return None
    start, end = m.span()
    return s[:start] + f"{b_text} && {a_text}" + s[end:]


def mut_return_to_goto(s: str, rng: random.Random) -> str | None:
    """Replace 'return FALSE;' or 'return 0;' with 'goto ret_false;' and add label."""
    if "ret_false:" in s:
        return None  # already has the label
    matches = list(_RE_RETURN_FALSE.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    start, end = m.span()
    result = s[:start] + "goto ret_false;" + s[end:]
    # Add label before the final return statement
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
    """Reverse: replace 'goto ret_false;' with 'return FALSE;'"""
    matches = list(_RE_GOTO_RET_FALSE.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    start, end = m.span()
    result = s[:start] + "return 0;" + s[end:]
    # Remove the label if no more gotos reference it
    if "goto ret_false" not in result:
        result = _RE_RET_FALSE_LABEL.sub("\n", result)
        result = _RE_RET_FALSE_LABEL_BARE.sub("\n", result)
    return result


def mut_introduce_local_alias(s: str, rng: random.Random) -> str | None:
    """Create a local variable aliasing a parameter and replace some uses."""
    # Find parameter names in __stdcall function signatures
    params = _RE_LOCAL_PARAMS.findall(s)
    params = [
        p for p in params if len(p) > 1 and p not in ("WINAPI", "BOOL", "HANDLE", "DWORD", "LPVOID")
    ]
    if not params:
        return None
    param = rng.choice(params)
    alias = "_" + param[0]  # e.g., hDllHandle -> _h
    if alias in s:
        return None  # already aliased

    # Find the type of the parameter
    type_match = re.search(r"\b(HANDLE|DWORD|LPVOID|int|BOOL)\s+" + re.escape(param) + r"\b", s)
    if not type_match:
        return None
    ptype = type_match.group(1)

    # Insert alias declaration after opening brace of function body
    brace_match = _RE_BRACE_AFTER_PAREN.search(s)
    if not brace_match:
        return None
    insert_pos = brace_match.end()
    decl = f"\n    {ptype} {alias} = {param};"
    result = s[:insert_pos] + decl + s[insert_pos:]

    # Replace some (not all) subsequent uses of param with alias
    # Only replace in the function body (after the declaration)
    body_start = insert_pos + len(decl)
    body = result[body_start:]
    occurrences = list(re.finditer(r"\b" + re.escape(param) + r"\b", body))
    if not occurrences:
        return result
    # Replace a random subset
    to_replace = rng.sample(occurrences, k=rng.randint(1, len(occurrences)))
    to_replace.sort(key=lambda m: m.start(), reverse=True)
    for occ in to_replace:
        body = body[: occ.start()] + alias + body[occ.end() :]
    return result[:body_start] + body


def mut_reorder_declarations(s: str, rng: random.Random) -> str | None:
    """Move a local variable declaration or add an initializer."""
    matches = list(_RE_DECL_LINE.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    decl_line = m.group(0)
    indent = m.group(1)
    decl_core = m.group(2)

    choice = rng.randint(0, 1)
    if choice == 0:
        # Add "= 0" initializer
        if "= " in decl_line:
            return None
        new_line = f"{indent}{decl_core} = 0;"
        return s[: m.start()] + new_line + s[m.end() :]
    else:
        # Remove initializer if present
        init_matches = list(_RE_INIT_LINE.finditer(s))
        if not init_matches:
            return None
        im = rng.choice(init_matches)
        return s[: im.start()] + im.group(1) + ";" + s[im.end() :]


def _find_matching_char(s: str, open_pos: int, open_ch: str, close_ch: str) -> int | None:
    """Find closing delimiter matching the opener at *open_pos*.

    Returns the index **after** the closing delimiter, or ``None`` if
    unbalanced.  Works for ``{}`` and ``()``.
    """
    if open_pos >= len(s) or s[open_pos] != open_ch:
        return None
    depth = 1
    i = open_pos + 1
    while i < len(s) and depth > 0:
        if s[i] == open_ch:
            depth += 1
        elif s[i] == close_ch:
            depth -= 1
        i += 1
    return i if depth == 0 else None


def _find_matching_brace(s: str, open_pos: int) -> int | None:
    """Find closing brace matching the opening brace at open_pos."""
    return _find_matching_char(s, open_pos, "{", "}")


def mut_swap_if_else(s: str, rng: random.Random) -> str | None:
    """Negate condition and swap if/else bodies."""
    matches = list(_RE_IF_COND.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    cond = m.group(1).strip()
    if_brace_start = s.find("{", m.start())
    if if_brace_start == -1:
        return None
    if_brace_end = _find_matching_brace(s, if_brace_start)
    if if_brace_end is None:
        return None

    # Check for else clause
    rest = s[if_brace_end:].lstrip()
    if not rest.startswith("else"):
        return None
    else_start = s.find("else", if_brace_end)
    if else_start == -1:
        return None
    after_else = s[else_start + 4 :].lstrip()
    if not after_else.startswith("{"):
        return None
    else_brace_start = s.find("{", else_start + 4)
    if else_brace_start == -1:
        return None
    else_brace_end = _find_matching_brace(s, else_brace_start)
    if else_brace_end is None:
        return None

    if_body = s[if_brace_start + 1 : if_brace_end - 1]
    else_body = s[else_brace_start + 1 : else_brace_end - 1]

    # Negate condition
    if cond.startswith("!") and not cond.startswith("!!"):
        neg_cond = cond[1:].strip()
        if neg_cond.startswith("(") and neg_cond.endswith(")"):
            neg_cond = neg_cond[1:-1]
    else:
        neg_cond = f"!({cond})"

    result = (
        s[: m.start()] + f"if ({neg_cond}) {{{else_body}}} else {{{if_body}}}" + s[else_brace_end:]
    )
    return result


def mut_reorder_elseif(s: str, rng: random.Random) -> str | None:
    """Swap two branches in an else-if chain."""
    matches = list(_RE_ELSEIF_CHAIN.finditer(s))
    if len(matches) < 2:
        return None

    # Find adjacent if/else-if pairs
    for m in matches:
        brace_start = s.find("{", m.start())
        if brace_start == -1:
            continue
        brace_end = _find_matching_brace(s, brace_start)
        if brace_end is None:
            continue
        rest = s[brace_end:].lstrip()
        if rest.startswith("else if"):
            else_if_start = s.find("else if", brace_end)
            if else_if_start == -1:
                continue
            # Extract the else-if condition and body
            ei_match = re.match(r"else\s+if\s*\(([^{]*?)\)\s*\{", s[else_if_start:])
            if not ei_match:
                continue
            ei_brace_start = s.find("{", else_if_start + ei_match.start())
            if ei_brace_start == -1:
                continue
            ei_brace_end = _find_matching_brace(s, ei_brace_start)
            if ei_brace_end is None:
                continue

            # Extract first branch cond + body
            cond1_match = re.match(r"if\s*\(([^{]*?)\)\s*\{", s[m.start() :])
            if not cond1_match:
                continue
            cond1 = cond1_match.group(1).strip()
            body1 = s[brace_start + 1 : brace_end - 1]
            cond2 = ei_match.group(1).strip()
            body2 = s[ei_brace_start + 1 : ei_brace_end - 1]

            # Swap the two branches
            result = (
                s[: m.start()]
                + f"if ({cond2}) {{{body2}}}\n    else if ({cond1}) {{{body1}}}"
                + s[ei_brace_end:]
            )
            return result
    return None


def mut_add_cast(s: str, rng: random.Random) -> str | None:
    """Wrap an expression in (BOOL) or (int) cast."""
    casts = ["(int)", "(unsigned int)"]
    cast = rng.choice(casts)
    matches = list(_RE_CAST_TARGET.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    ident = m.group(1)
    # Don't cast type keywords
    if ident in (
        "BOOL",
        "int",
        "DWORD",
        "HANDLE",
        "LPVOID",
        "void",
        "return",
        "if",
        "else",
        "while",
        "for",
        "goto",
        "volatile",
    ):
        return None
    start, end = m.span(1)
    return s[:start] + f"{cast}{ident}" + s[end:]


def mut_remove_cast(s: str, rng: random.Random) -> str | None:
    """Remove a (TYPE) cast."""
    return _sub_once(_RE_REMOVE_CAST, lambda m: m.group(1), s, rng)


def mut_toggle_volatile(s: str, rng: random.Random) -> str | None:
    """Add or remove 'volatile' on a local variable declaration."""
    # Try removing volatile first
    vol_matches = list(_RE_VOLATILE.finditer(s))
    if vol_matches and rng.random() < 0.5:
        m = rng.choice(vol_matches)
        return s[: m.start()] + s[m.end() :]
    # Try adding volatile
    matches = list(_RE_ADD_VOLATILE.finditer(s))
    matches = [m for m in matches if "volatile" not in s[m.start() : m.end() + 20]]
    if not matches:
        return None
    m = rng.choice(matches)
    return s[: m.start()] + m.group(1) + "volatile " + m.group(2) + s[m.end() :]


def mut_add_register_keyword(s: str, rng: random.Random) -> str | None:
    """Add 'register' keyword to a local variable declaration.
    Note: MSVC6 largely ignores register hints, but the keyword
    can sometimes affect variable ordering in the symbol table."""
    matches = list(_RE_ADD_REGISTER.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    if "register" in s[m.start() : m.end() + 20]:
        return None
    return s[: m.start()] + m.group(1) + "register " + m.group(2) + s[m.end() :]


def mut_remove_register_keyword(s: str, rng: random.Random) -> str | None:
    """Remove 'register' keyword from a declaration."""
    matches = list(_RE_REMOVE_REGISTER.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    return s[: m.start()] + s[m.end() :]


def mut_if_false_to_bitand(s: str, rng: random.Random) -> str | None:
    """Convert 'if (!expr) var = FALSE;' to 'var &= expr;'.

    This can produce `and [mem], reg` instead of `test/jne/mov` pattern,
    which is how MSVC6 sometimes optimizes this idiom.
    """
    matches = list(_RE_IF_FALSE_BITAND.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    call_expr = m.group(1)
    var_name = m.group(2)
    replacement = f"{var_name} &= {call_expr};"
    return s[: m.start()] + replacement + s[m.end() :]


def mut_bitand_to_if_false(s: str, rng: random.Random) -> str | None:
    """Reverse of mut_if_false_to_bitand: convert 'var &= expr;' to 'if (!expr) var = FALSE;'."""
    matches = list(_RE_BITAND_TO_IF.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    var_name = m.group(1)
    call_expr = m.group(2)
    replacement = f"if (!{call_expr})\n            {var_name} = 0;"
    return s[: m.start()] + replacement + s[m.end() :]


def mut_introduce_temp_for_call(s: str, rng: random.Random) -> str | None:
    """Introduce a temp variable for a function call result.

    Transforms: var = FuncCall(...);
    Into:       tmp = FuncCall(...); var = tmp;

    This can help the compiler keep the result in a register for subsequent tests.
    """
    matches = list(_RE_VAR_ASSIGN_CALL.finditer(s))
    # Filter to only function calls (must have parens), not already using tmp
    matches = [m for m in matches if "(" in m.group(2) and "tmp" not in m.group(0)]
    if not matches:
        return None
    m = rng.choice(matches)
    var_name = m.group(1)
    call_expr = m.group(2)
    # Check if tmp is already declared
    if _RE_BOOL_TMP_DECL.search(s):
        replacement = f"tmp = {call_expr};\n    {var_name} = tmp;"
    else:
        replacement = f"BOOL tmp = {call_expr};\n    {var_name} = tmp;"
    return s[: m.start()] + replacement + s[m.end() :]


def mut_remove_temp_var(s: str, rng: random.Random) -> str | None:
    """Remove a temp variable usage: 'tmp = expr; var = tmp;' -> 'var = expr;'."""
    matches = list(_RE_TEMP_VAR.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    expr = m.group(1)
    var_name = m.group(2)
    return s[: m.start()] + f"{var_name} = {expr};" + s[m.end() :]


# -------------------------
# Register-allocation-aware mutations
# These target MSVC6's register allocator: variable declaration order,
# signed/unsigned types, expression structure, and control flow all
# influence which variables go into EAX/ECX/EDX vs ESI/EDI/EBX.
# -------------------------


def mut_toggle_signedness(s: str, rng: random.Random) -> str | None:
    """Toggle signed/unsigned on a local variable declaration.

    MSVC6 generates different instructions for signed vs unsigned:
    - movsx vs movzx for extension
    - sar vs shr for right shift
    - jl/jge vs jb/jae for comparisons
    These changes alter register pressure and allocation order.
    """
    matches = list(_RE_UNSIGNED_REMOVE.finditer(s))
    matches_add = list(_RE_UNSIGNED_ADD.finditer(s))

    candidates = []
    if matches:
        candidates.append(("remove", matches))
    if matches_add:
        candidates.append(("add", matches_add))
    if not candidates:
        return None

    action, ms = rng.choice(candidates)
    m = rng.choice(ms)
    if action == "remove":
        return s[: m.start()] + m.group(1) + s[m.end() :]
    else:
        return s[: m.start()] + "unsigned " + m.group(0) + s[m.end() :]


def mut_swap_adjacent_declarations(s: str, rng: random.Random) -> str | None:
    """Swap two adjacent variable declarations at function start.

    MSVC6 register allocator is sensitive to declaration order when
    multiple variables have similar liveness. Swapping declarations
    can change which variable gets EAX vs ECX vs EDX.
    """

    lines = s.split("\n")
    decl_indices = []
    for i, line in enumerate(lines):
        if _RE_DECL_SWAP.match(line):
            decl_indices.append(i)

    pairs = []
    for i in range(len(decl_indices) - 1):
        if decl_indices[i + 1] == decl_indices[i] + 1:
            pairs.append((decl_indices[i], decl_indices[i + 1]))
    if not pairs:
        return None

    a_idx, b_idx = rng.choice(pairs)
    lines[a_idx], lines[b_idx] = lines[b_idx], lines[a_idx]
    return "\n".join(lines)


def mut_split_declaration_init(s: str, rng: random.Random) -> str | None:
    """Split 'TYPE var = expr;' into 'TYPE var; var = expr;'.

    Separating declaration from initialization changes when the compiler
    considers the variable 'live', which affects register allocation.
    """
    matches = list(_RE_SPLIT_DECL.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    indent = m.group(1)
    decl = m.group(2)
    var = m.group(3)
    init_expr = m.group(4).strip()
    replacement = f"{indent}{decl};\n{indent}{var} = {init_expr};"
    return s[: m.start()] + replacement + s[m.end() :]


def mut_merge_declaration_init(s: str, rng: random.Random) -> str | None:
    """Merge 'TYPE var; ... var = expr;' into 'TYPE var = expr;'.

    Reverse of mut_split_declaration_init. Merging shortens the live range
    gap, which can free a register for other variables.
    """

    matches = list(_RE_MERGE_DECL.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    indent = m.group(1)
    type_decl = m.group(2)
    var = m.group(3)
    init_expr = m.group(4).strip()
    replacement = f"{indent}{type_decl} {var} = {init_expr};"
    return s[: m.start()] + replacement + s[m.end() :]


def mut_while_to_dowhile(s: str, rng: random.Random) -> str | None:
    """Convert 'while (cond) { body }' to 'if (cond) { do { body } while (cond); }'.

    MSVC6 performs loop rotation differently for while vs do-while.
    A do-while avoids the duplicated condition check at loop top.
    """
    matches = list(_RE_WHILE_LOOP.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    # Find balanced closing paren for the condition
    paren_start = m.end() - 1  # index of '('
    paren_end = _find_matching_char(s, paren_start, "(", ")")
    if paren_end is None:
        return None
    cond = s[paren_start + 1 : paren_end - 1]

    # Find opening brace after condition
    rest_after_paren = s[paren_end:].lstrip()
    if not rest_after_paren.startswith("{"):
        return None
    brace_start = s.index("{", paren_end)
    close = _find_matching_brace(s, brace_start)
    if close is None:
        return None
    body = s[brace_start + 1 : close - 1]
    before = s[: m.start()]
    after = s[close:]
    replacement = f"if ({cond}) {{\n    do {{{body}}} while ({cond});\n    }}"
    return before + replacement + after


def mut_dowhile_to_while(s: str, rng: random.Random) -> str | None:
    """Convert 'do { body } while (cond);' to 'while (cond) { body }'.

    Reverse of mut_while_to_dowhile. Changes loop rotation behavior.
    """
    matches = list(_RE_DO_WHILE.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    brace_start = m.end() - 1
    close = _find_matching_brace(s, brace_start)
    if close is None:
        return None
    body = s[brace_start + 1 : close - 1]
    # Find 'while (cond);' after closing brace
    after_close_raw = s[close:]
    after_close = after_close_raw.lstrip()
    wm = _RE_DO_WHILE_COND.match(after_close)
    if not wm:
        return None
    cond = wm.group(1)
    before = s[: m.start()]
    whitespace_skip = len(after_close_raw) - len(after_close)
    rest = s[close + whitespace_skip + wm.end() :]
    replacement = f"while ({cond}) {{{body}}}"
    return before + replacement + rest


def mut_early_return_to_accum(s: str, rng: random.Random) -> str | None:
    """Convert 'if (!expr) return 0;' to 'ret &= expr;' accumulator pattern.

    This extends the live range of a return-value variable, creating register
    pressure that forces the compiler to spill other variables to stack,
    changing the overall register allocation.
    """
    matches = list(_RE_EARLY_RETURN.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    call_expr = m.group(1)
    # Check if 'ret' or 'retcode' already exists
    if _RE_RETCODE_VAR.search(s):
        var = "retcode" if "retcode" in s else "ret"
        replacement = f"{var} &= {call_expr};"
    else:
        return None
    return s[: m.start()] + replacement + s[m.end() :]


def mut_accum_to_early_return(s: str, rng: random.Random) -> str | None:
    """Convert 'ret &= expr;' to 'if (!expr) return 0;'.

    Reverse of mut_early_return_to_accum.
    """
    matches = list(_RE_ACCUM.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    var_name = m.group(1)
    if var_name not in ("ret", "retcode", "result"):
        return None
    call_expr = m.group(2)
    replacement = f"if (!{call_expr})\n        return 0;"
    return s[: m.start()] + replacement + s[m.end() :]


def mut_pointer_to_int_param(s: str, rng: random.Random) -> str | None:
    """Change a pointer parameter to int or vice versa.

    MSVC6 generates different address computation instructions for
    pointer arithmetic vs integer + cast, affecting register usage.
    """
    matches = list(_RE_PTR_PARAM.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    # Don't change extern/typedef declarations
    line_start = s.rfind("\n", 0, m.start()) + 1
    line = s[line_start : m.start()]
    if "extern" in line or "typedef" in line:
        return None
    var_name = m.group(2)
    # Replace 'TYPE *name' with 'int name'
    return s[: m.start()] + "int " + var_name + s[m.end() :]


def mut_int_to_pointer_param(s: str, rng: random.Random) -> str | None:
    """Change an int parameter to char* (for pointer-based access).

    Reverse of mut_pointer_to_int_param. Using char* changes how the
    compiler generates field access (lea vs add).
    """
    matches = list(_RE_INT_PARAM.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    var_name = m.group(1)
    return s[: m.start()] + " char *" + var_name + s[m.end() :]


def mut_duplicate_loop_body(s: str, rng: random.Random) -> str | None:
    """Duplicate loop body (manual loop unrolling by 2x).

    Changes:
    while(condition) { body; }
    ->
    while(condition) { body; body; }
    This affects register pressure and loop overhead.
    """
    matches = list(_RE_WHILE_LOOP.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    # Find balanced condition parens
    paren_start = m.end() - 1
    paren_end = _find_matching_char(s, paren_start, "(", ")")
    if paren_end is None:
        return None
    cond = s[paren_start + 1 : paren_end - 1]
    # Find balanced body braces
    rest_after_paren = s[paren_end:].lstrip()
    if not rest_after_paren.startswith("{"):
        return None
    brace_start = s.index("{", paren_end)
    brace_end = _find_matching_brace(s, brace_start)
    if brace_end is None:
        return None
    body = s[brace_start + 1 : brace_end - 1]
    # Duplicate body
    new_body = body + "\n" + body.strip()
    new_while = f"while ({cond}) {{{new_body}}}"
    return s[: m.start()] + new_while + s[brace_end:]


def mut_fold_constant_add(s: str, rng: random.Random) -> str | None:
    """Fold multiple +1 or +N into a single addition.

    Changes: x = x + 1; x = x + 1; -> x = x + 2;
    This affects how many add instructions are generated.
    """

    matches = list(_RE_CONST_ADD.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    var = m.group(1)
    n1 = int(m.group(2))
    n2 = int(m.group(4))
    new = f"{var} = {var} + {n1 + n2};"
    return s[: m.start()] + new + s[m.end() :]


def mut_unfold_constant_add(s: str, rng: random.Random) -> str | None:
    """Unfold addition into multiple increments.

    Changes: x = x + 2; -> x = x + 1; x = x + 1;
    This adds more add instructions for register pressure.
    """

    matches = list(_RE_SINGLE_ADD.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    var = m.group(1)
    n = int(m.group(2))
    if n <= 1 or n > 16:
        return None
    # Split into n increments of 1
    incs = "; ".join([f"{var} = {var} + 1" for _ in range(n)]) + ";"
    return s[: m.start()] + incs + s[m.end() :]


def mut_change_array_index_order(s: str, rng: random.Random) -> str | None:
    """Change array[i] to i[array] (equivalent but different codegen).

    Both compile to same code but can affect MSVC register allocation.
    """

    matches = list(_RE_ARRAY_INDEX.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    arr = m.group(1)
    idx = m.group(2)
    new = f"{idx}[{arr}]"
    return s[: m.start()] + new + s[m.end() :]


def mut_struct_vs_ptr_access(s: str, rng: random.Random) -> str | None:
    """Change ptr->field to (*ptr).field (equivalent semantics, different codegen).

    This affects how MSVC generates field access code.
    """

    matches = list(_RE_PTR_ARROW.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    ptr = m.group(1)
    field = m.group(2)
    new = f"(*{ptr}).{field}"
    return s[: m.start()] + new + s[m.end() :]


def mut_split_cmp_chain(s: str, rng: random.Random) -> str | None:
    """Split chained && into nested if statements.

    Changes: if (a && b) { body } -> if (a) { if (b) { body } }
    This preserves semantics while changing control flow and register usage.
    """
    matches = list(_RE_CMP_CHAIN_3.finditer(s))
    if not matches:
        matches = list(_RE_CMP_CHAIN_2.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    # Find the body braces following the if(...)
    rest = s[m.end() :].lstrip()
    if not rest.startswith("{"):
        return None
    brace_start = s.index("{", m.end())
    brace_end = _find_matching_brace(s, brace_start)
    if brace_end is None:
        return None
    body = s[brace_start + 1 : brace_end - 1]

    # Extract the condition text between "if (" and the closing ")"
    cond_text = m.group(0)
    inner = cond_text[cond_text.index("(") + 1 : cond_text.rindex(")")]
    parts = [p.strip() for p in re.split(r"\s*&&\s*", inner)]
    if len(parts) < 2:
        return None

    # Build nested ifs with balanced braces:
    # if (a && b) { body }  ->  if (a) { if (b) { body } }
    # if (a && b && c) { body }  ->  if (a) { if (b) { if (c) { body } } }
    inner_block = "{" + body + "}"
    for i in range(len(parts) - 1, -1, -1):
        inner_block = f"if ({parts[i]}) {inner_block}"
        if i > 0:
            inner_block = "{ " + inner_block + " }"
    result = s[: m.start()] + inner_block + s[brace_end:]
    return result


def mut_merge_cmp_chain(s: str, rng: random.Random) -> str | None:
    """Merge separate if statements into chained comparison.

    Changes: if (a == b) {} if (b == c) {} -> if (a == b && b == c) {}
    Opposite of split_cmp_chain.
    """

    matches = list(_RE_MERGE_IF.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    cond1 = m.group(1)
    cond2 = m.group(2)
    new = f"if ({cond1} && {cond2}) {{}}"
    return s[: m.start()] + new + s[m.end() :]


def mut_combine_ptr_arith(s: str, rng: random.Random) -> str | None:
    """Combine separate pointer arithmetic into single expression.

    Changes: p = p + n; p = p + m; -> p = p + (n + m);
    Affects number of add instructions generated.
    """

    matches = list(_RE_PTR_ARITH_DOUBLE.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    var = m.group(1)
    n1 = int(m.group(2))
    n2 = int(m.group(4))
    new = f"{var} = {var} + {n1 + n2};"
    return s[: m.start()] + new + s[m.end() :]


def mut_split_ptr_arith(s: str, rng: random.Random) -> str | None:
    """Split combined pointer arithmetic into separate statements.

    Changes: p = p + n; -> p = p + n1; p = p + n2; where n1+n2=n
    Adds more add instructions for register pressure.
    """

    matches = list(_RE_PTR_ARITH_SINGLE.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    var = m.group(1)
    n = int(m.group(2))
    if n <= 1:
        return None
    # Split into two parts
    n1 = n // 2
    n2 = n - n1
    new = f"{var} = {var} + {n1}; {var} = {var} + {n2};"
    return s[: m.start()] + new + s[m.end() :]


def mut_change_return_type(s: str, rng: random.Random) -> str | None:
    """Change return type between int/char/short for register pressure.

    Different return types generate different register usage (al vs ax vs eax).
    """

    matches = list(_RE_RETURN_TYPE.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    types = ["int", "char", "short", "long"]
    current = m.group(1)
    new_type = rng.choice([t for t in types if t != current])
    # Replace only the return type, preserving everything after it
    return s[: m.start()] + new_type + s[m.start() + len(m.group(1)) :]


def mut_change_param_order(s: str, rng: random.Random) -> str | None:
    """Reorder function parameters to affect register allocation.

    MSVC passes parameters in different registers based on position.
    """

    match = _RE_FUNC_SIG.search(s)
    if not match:
        return None
    params = [p.strip() for p in match.group(2).split(",")]
    if len(params) < 2:
        return None
    # Swap two random params
    i, j = rng.sample(range(len(params)), 2)
    params[i], params[j] = params[j], params[i]
    new_sig = match.group(1) + "(" + ", ".join(params) + ") {"
    return s[: match.start()] + new_sig + s[match.end() :]


# Calling convention patterns
_RE_FUNC_DEF_CONV = re.compile(
    r"^([a-zA-Z_][a-zA-Z0-9_*\s]*)\s+(__cdecl|__stdcall)\s+([a-zA-Z_][a-zA-Z0-9_]*\s*\()",
    re.MULTILINE,
)
# Char signedness
_RE_UNSIGNED_CHAR = re.compile(r"\bunsigned\s+char\b")
_RE_SIGNED_CHAR = re.compile(r"\bsigned\s+char\b")
_RE_BARE_CHAR = re.compile(r"(?<!unsigned )(?<!unsigned\t)(?<!signed )(?<!signed\t)\bchar\b")
# Comparison boundary
_RE_GE_ONE = re.compile(r"(\b\w+)\s*>=\s*1\b")
_RE_GT_ZERO = re.compile(r"(\b\w+)\s*>\s*0\b")
_RE_LE_ZERO = re.compile(r"(\b\w+)\s*<=\s*0\b")
_RE_LT_ONE = re.compile(r"(\b\w+)\s*<\s*1\b")


def mut_toggle_calling_convention(s: str, rng: random.Random) -> str | None:
    """Toggle between __cdecl and __stdcall calling conventions.

    MSVC6 generates different prologue/epilogue code for each convention.
    __cdecl: caller cleans stack; __stdcall: callee cleans stack (ret N).
    """
    m = _RE_FUNC_DEF_CONV.search(s)
    if m:
        old_conv = m.group(2)
        new_conv = "__stdcall" if old_conv == "__cdecl" else "__cdecl"
        return s[: m.start(2)] + new_conv + s[m.end(2) :]

    # No explicit convention — try adding one
    match = _RE_FUNC_SIG.search(s)
    if not match:
        return None
    conv = rng.choice(["__cdecl", "__stdcall"])
    # Insert convention between return type and function name
    # group(1) captures "rettype funcname" — split on last whitespace
    sig = match.group(1)
    last_space = sig.rfind(" ")
    if last_space < 0:
        return None
    return (
        s[: match.start(1)]
        + sig[:last_space]
        + " "
        + conv
        + " "
        + sig[last_space + 1 :]
        + s[match.end(1) :]
    )


def mut_toggle_char_signedness(s: str, rng: random.Random) -> str | None:
    """Toggle char signedness: char -> unsigned char -> signed char -> char.

    MSVC6 treats char as signed by default, but explicit signedness
    affects sign-extension in generated code (movsx vs movzx).
    """
    # Collect all replacement candidates
    candidates: list[tuple[re.Match[str], str, bool]] = []  # (match, replacement, is_line_based)
    for m in _RE_UNSIGNED_CHAR.finditer(s):
        candidates.append((m, "signed char", False))
    for m in _RE_SIGNED_CHAR.finditer(s):
        candidates.append((m, "char", False))
    # Bare char → unsigned char (only in declaration-like lines)
    for m in _RE_BARE_CHAR.finditer(s):
        candidates.append((m, "unsigned char", False))

    if not candidates:
        return None
    m, replacement, _ = rng.choice(candidates)
    result = s[: m.start()] + replacement + s[m.end() :]
    # Guard against double-keyword artifacts like "unsigned unsigned char"
    if "unsigned unsigned" in result or "signed signed" in result:
        return None
    return result


def mut_comparison_boundary(s: str, rng: random.Random) -> str | None:
    """Toggle comparison boundary: >= 1 <-> > 0, <= 0 <-> < 1.

    These generate different x86 comparison encodings (cmp+jge vs cmp+jg)
    which can cause byte-level mismatches even with identical logic.
    """
    # Collect all matches across all four patterns with their replacements
    candidates: list[tuple[re.Match[str], str]] = []
    for m in _RE_GE_ONE.finditer(s):
        candidates.append((m, m.group(1) + " > 0"))
    for m in _RE_GT_ZERO.finditer(s):
        candidates.append((m, m.group(1) + " >= 1"))
    for m in _RE_LE_ZERO.finditer(s):
        candidates.append((m, m.group(1) + " < 1"))
    for m in _RE_LT_ONE.finditer(s):
        candidates.append((m, m.group(1) + " <= 0"))

    if not candidates:
        return None
    m, replacement = rng.choice(candidates)
    return s[: m.start()] + replacement + s[m.end() :]


# -------------------------
# Code layout mutations
# These target structural code patterns that cause MSVC6's codegen to
# produce different branch layouts, loop entry code, and register
# live ranges.
# -------------------------

_RE_NESTED_IF = re.compile(r"\bif\s*\(")
_RE_FOR_LOOP = re.compile(r"\bfor\s*\(")
# Simple if/else single-assignment: if (c) x = a; else x = b;
_RE_IF_ASSIGN_ELSE = re.compile(
    r"if\s*\(([^)]+)\)\s*\n?\s*(\w+)\s*=\s*([^;]+);\s*\n?\s*else\s*\n?\s*\2\s*=\s*([^;]+);",
)
# Ternary assignment: x = c ? a : b;
_RE_TERNARY_ASSIGN = re.compile(
    r"(\w+)\s*=\s*\(?\s*([^?;]+?)\s*\)?\s*\?\s*([^:;]+?)\s*:\s*([^;]+?)\s*;",
)
# Hoist: return <expr>; at the end of a branch
_RE_BRANCH_RETURN = re.compile(r"([ \t]+)return\s+([^;]+);(\s*\n\s*\})", re.MULTILINE)
# Sink: ret = <expr>; goto end;
_RE_RET_GOTO_END = re.compile(r"([ \t]+)(\w+)\s*=\s*([^;]+);\s*\n\s*\1goto\s+end\s*;")


def mut_flatten_nested_if(s: str, rng: random.Random) -> str | None:
    """Flatten nested if into && chain.

    Changes:  if (a) { if (b) { body } }  →  if (a && b) { body }
    Complementary with existing mut_split_cmp_chain (which goes the other way).
    This version handles deeper nesting patterns that split_cmp_chain misses.
    """
    matches = list(_RE_NESTED_IF.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)

    # Find balanced condition parens for outer if
    paren_start = m.end() - 1
    paren_end = _find_matching_char(s, paren_start, "(", ")")
    if paren_end is None:
        return None
    outer_cond = s[paren_start + 1 : paren_end - 1].strip()

    # Find outer body braces
    rest = s[paren_end:].lstrip()
    if not rest.startswith("{"):
        return None
    brace_start = s.index("{", paren_end)
    brace_end = _find_matching_brace(s, brace_start)
    if brace_end is None:
        return None

    # Check that body is just another if (possibly with whitespace)
    inner_body = s[brace_start + 1 : brace_end - 1].strip()
    inner_match = re.match(r"if\s*\(", inner_body)
    if not inner_match:
        return None

    # Parse the inner if condition
    inner_paren_start = inner_match.end() - 1
    inner_paren_end = _find_matching_char(inner_body, inner_paren_start, "(", ")")
    if inner_paren_end is None:
        return None
    inner_cond = inner_body[inner_paren_start + 1 : inner_paren_end - 1].strip()

    # Get inner body (must have braces)
    inner_rest = inner_body[inner_paren_end:].lstrip()
    if not inner_rest.startswith("{"):
        return None
    inner_brace_start = inner_body.index("{", inner_paren_end)
    inner_brace_end = _find_matching_brace(inner_body, inner_brace_start)
    if inner_brace_end is None:
        return None

    # After the inner if's closing brace, there should be nothing else
    trailing = inner_body[inner_brace_end:].strip()
    if trailing:
        return None  # There's more code — can't safely flatten

    inner_block = inner_body[inner_brace_start:inner_brace_end]
    replacement = f"if ({outer_cond} && {inner_cond}) {inner_block}"
    return s[: m.start()] + replacement + s[brace_end:]


def mut_extract_else_body(s: str, rng: random.Random) -> str | None:
    """Convert if/else to negated-condition early exit.

    Changes:  if (c) { A } else { B }  →  if (!(c)) { B; return 0; } A
    MSVC6 generates different branch layouts for these two patterns,
    affecting jump distances and register liveness.
    """
    # Find if statements that have else clauses
    matches = list(_RE_NESTED_IF.finditer(s))
    if not matches:
        return None
    rng.shuffle(matches)

    for m in matches:
        paren_start = m.end() - 1
        paren_end = _find_matching_char(s, paren_start, "(", ")")
        if paren_end is None:
            continue
        cond = s[paren_start + 1 : paren_end - 1].strip()

        # Find if-body braces
        rest = s[paren_end:].lstrip()
        if not rest.startswith("{"):
            continue
        brace_start = s.index("{", paren_end)
        brace_end = _find_matching_brace(s, brace_start)
        if brace_end is None:
            continue
        if_body = s[brace_start + 1 : brace_end - 1]

        # Check for else clause
        after_if = s[brace_end:].lstrip()
        offset_to_else = len(s[brace_end:]) - len(after_if)
        if not after_if.startswith("else"):
            continue
        else_start = brace_end + offset_to_else + 4  # skip "else"
        after_else = s[else_start:].lstrip()

        # Don't match 'else if' — only 'else {' blocks
        if after_else.startswith("if"):
            continue
        if not after_else.startswith("{"):
            continue

        else_brace_start = s.index("{", else_start)
        else_brace_end = _find_matching_brace(s, else_brace_start)
        if else_brace_end is None:
            continue
        else_body = s[else_brace_start + 1 : else_brace_end - 1]

        # Build negated condition early-exit form
        if cond.startswith("!"):
            neg_cond = cond[1:].strip()
            if neg_cond.startswith("(") and neg_cond.endswith(")"):
                neg_cond = neg_cond[1:-1]
        else:
            neg_cond = f"!({cond})"
        replacement = f"if ({neg_cond}) {{{else_body}\n        return 0;\n    }}{if_body}"
        return s[: m.start()] + replacement + s[else_brace_end:]

    return None


def mut_for_to_while(s: str, rng: random.Random) -> str | None:
    """Convert for loop to while loop.

    Changes:  for (i=0; i<n; i++) { body }
           →  i=0; while (i<n) { body i++; }
    MSVC6 generates different loop entry code for for vs while loops.
    """
    matches = list(_RE_FOR_LOOP.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)

    paren_start = m.end() - 1
    paren_end = _find_matching_char(s, paren_start, "(", ")")
    if paren_end is None:
        return None
    header = s[paren_start + 1 : paren_end - 1]

    # Split on semicolons — must have exactly 2
    parts = header.split(";")
    if len(parts) != 3:
        return None
    init, cond, inc = [p.strip() for p in parts]
    if not cond:
        return None

    # Find body braces
    rest = s[paren_end:].lstrip()
    if not rest.startswith("{"):
        return None
    brace_start = s.index("{", paren_end)
    brace_end = _find_matching_brace(s, brace_start)
    if brace_end is None:
        return None
    body = s[brace_start + 1 : brace_end - 1]

    # Build while loop
    init_stmt = f"{init};\n    " if init else ""
    inc_stmt = f"\n        {inc};" if inc else ""
    replacement = f"{init_stmt}while ({cond}) {{{body}{inc_stmt}\n    }}"
    return s[: m.start()] + replacement + s[brace_end:]


def mut_while_to_for(s: str, rng: random.Random) -> str | None:
    """Convert while loop to for loop.

    Changes:  while (cond) { body }  →  for (; cond; ) { body }
    Inverse of mut_for_to_while. MSVC6 generates different entry code.
    """
    matches = list(_RE_WHILE_LOOP.finditer(s))
    # Filter out do-while patterns
    filtered = []
    for m in matches:
        before = s[: m.start()].rstrip()
        if before.endswith("do") or before.endswith("}"):
            continue  # This is a do-while condition, skip
        filtered.append(m)
    if not filtered:
        return None
    m = rng.choice(filtered)

    paren_start = m.end() - 1
    paren_end = _find_matching_char(s, paren_start, "(", ")")
    if paren_end is None:
        return None
    cond = s[paren_start + 1 : paren_end - 1].strip()

    # Find body braces
    rest = s[paren_end:].lstrip()
    if not rest.startswith("{"):
        return None
    brace_start = s.index("{", paren_end)
    brace_end = _find_matching_brace(s, brace_start)
    if brace_end is None:
        return None
    body = s[brace_start + 1 : brace_end - 1]

    replacement = f"for (; {cond}; ) {{{body}}}"
    return s[: m.start()] + replacement + s[brace_end:]


def mut_if_to_ternary(s: str, rng: random.Random) -> str | None:
    """Convert if/else assignment to ternary expression.

    Changes:  if (c) x = a; else x = b;  →  x = (c) ? a : b;
    The ternary form often generates cmovcc instead of a conditional jump,
    changing the instruction stream entirely.
    """
    matches = list(_RE_IF_ASSIGN_ELSE.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    cond = m.group(1).strip()
    var = m.group(2)
    val_true = m.group(3).strip()
    val_false = m.group(4).strip()
    replacement = f"{var} = ({cond}) ? {val_true} : {val_false};"
    return s[: m.start()] + replacement + s[m.end() :]


def mut_ternary_to_if(s: str, rng: random.Random) -> str | None:
    """Convert ternary expression to if/else assignment.

    Changes:  x = c ? a : b;  →  if (c) x = a; else x = b;
    Inverse of mut_if_to_ternary. Uses conditional jumps instead of cmov.
    """
    matches = list(_RE_TERNARY_ASSIGN.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    var = m.group(1).strip()
    cond = m.group(2).strip()
    val_true = m.group(3).strip()
    val_false = m.group(4).strip()
    # Don't convert if this looks like a declaration (has type keyword before var)
    before = s[: m.start()].rstrip()
    if (
        before
        and before.split()[-1:][0:1]
        and before.split()[-1]
        in (
            "int",
            "char",
            "short",
            "long",
            "BOOL",
            "DWORD",
            "UINT",
            "BYTE",
            "WORD",
            "unsigned",
            "signed",
            "const",
            "volatile",
        )
    ):
        return None
    replacement = (
        f"if ({cond})\n        {var} = {val_true};\n    else\n        {var} = {val_false};"
    )
    return s[: m.start()] + replacement + s[m.end() :]


def mut_hoist_return(s: str, rng: random.Random) -> str | None:
    """Extract branch returns to a labeled goto accumulator.

    Changes:  return expr;  →  ret = expr; goto end;
    (and adds 'end: return ret;' before the enclosing function's closing brace)
    This extends the live range of the ret variable, creating register
    pressure that forces different register allocation.
    """
    matches = list(_RE_BRANCH_RETURN.finditer(s))
    if not matches:
        return None

    # Skip if end label already exists
    if re.search(r"\bend\s*:", s):
        return None

    m = rng.choice(matches)
    indent = m.group(1)
    expr = m.group(2).strip()
    trailing = m.group(3)

    # Check if ret variable already used
    ret_var = "ret" if "retcode" not in s else "retval"
    if re.search(rf"\b{ret_var}\b", s):
        ret_var = "retval"
    if re.search(rf"\b{ret_var}\b", s):
        return None  # Can't find a free variable name

    replacement = f"{indent}{ret_var} = {expr};\n{indent}goto end;{trailing}"
    result = s[: m.start()] + replacement + s[m.end() :]

    # Find the enclosing function's closing brace by tracking depth
    # from the replacement position outward.
    pos = m.start()
    depth = 0
    func_close = -1
    for i in range(pos, len(result)):
        if result[i] == "{":
            depth += 1
        elif result[i] == "}":
            depth -= 1
            if depth <= 0:
                func_close = i
                break
    if func_close < 0:
        return None
    result = result[:func_close] + f"\nend:\n    return {ret_var};\n" + result[func_close:]
    return result


def mut_sink_return(s: str, rng: random.Random) -> str | None:
    """Collapse ret=expr; goto end; back to return expr;

    Inverse of mut_hoist_return. Reduces register live ranges.
    """
    matches = list(_RE_RET_GOTO_END.finditer(s))
    if not matches:
        return None

    m = rng.choice(matches)
    indent = m.group(1)
    expr = m.group(3).strip()
    replacement = f"{indent}return {expr};"
    result = s[: m.start()] + replacement + s[m.end() :]

    # Remove the end label and its return if no more gotos reference it
    if "goto end;" not in result:
        result = re.sub(r"\nend:\n\s*return\s+\w+;\n", "\n", result)

    return result


# -------------------------
# Structural codegen mutations (batch 2)
# These target expression rewriting and statement ordering patterns
# that cause MSVC6 to emit different instruction sequences.
# -------------------------

# Adjacent statement pattern: two simple assignment or call statements
# Matches both simple (x = ...) and compound (x += ...) assignments
_RE_ADJACENT_STMTS = re.compile(
    r"([ \t]+)(\w+\s*(?:[+\-*|&^])?=[^;]+;)\s*\n(\1)(\w+\s*(?:[+\-*|&^])?=[^;]+;)",
)
# Guard clause: if (cond) { body; return expr; }\n return other;
_RE_GUARD_IF_RETURN = re.compile(
    r"([ \t]*)if\s*\(([^)]+)\)\s*\{([^}]+)return\s+([^;]+);\s*\}\s*\n\s*\1return\s+([^;]+);",
)
# For loop with init;cond;incr
_RE_FOR_COUNT_UP = re.compile(
    r"for\s*\(\s*(\w+)\s*=\s*0\s*;\s*\1\s*<\s*([^;]+);\s*\1\+\+\s*\)",
)
# Compound assignment: x = x OP y
_RE_COMPOUND_EXPAND = re.compile(
    r"(\b\w+)\s*=\s*\1\s*([+\-*|&^])\s*([^;]+);",
)
# Compound shorthand: x OP= y
_RE_COMPOUND_SHORT = re.compile(
    r"(\b\w+)\s*([+\-*|&^])=\s*([^;]+);",
)
# De Morgan: !(a && b) or !(a || b)
_RE_DEMORGAN_AND = re.compile(r"!\s*\(([^)]+?)\s*&&\s*([^)]+?)\)")
_RE_DEMORGAN_OR = re.compile(r"!\s*\(([^)]+?)\s*\|\|\s*([^)]+?)\)")
# Post/pre increment
_RE_POST_INC = re.compile(r"(\b[a-zA-Z_]\w*)\+\+")
_RE_PRE_INC = re.compile(r"\+\+(\b[a-zA-Z_]\w*)")
_RE_POST_DEC = re.compile(r"(\b[a-zA-Z_]\w*)--")
_RE_PRE_DEC = re.compile(r"--(\b[a-zA-Z_]\w*)")
# x = 0 (simple zero assignment)
_RE_ASSIGN_ZERO = re.compile(r"(\b\w+)\s*=\s*0\s*;")
_RE_XOR_SELF = re.compile(r"(\b\w+)\s*\^=\s*\1\s*;")
# Negate condition: if (expr) — NOT a simple regex, requires balanced parens
# So we use _find_matching_char at runtime instead of a static regex.


def mut_swap_adjacent_stmts(s: str, rng: random.Random) -> str | None:
    """Swap two adjacent non-dependent assignment statements.

    Affects register allocation order and instruction scheduling.
    """
    matches = list(_RE_ADJACENT_STMTS.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    indent = m.group(1)
    stmt_a = m.group(2)
    stmt_b = m.group(4)
    # Quick dependency check: skip if one statement's LHS appears in the other
    lhs_a = stmt_a.split("=")[0].strip()
    lhs_b = stmt_b.split("=")[0].strip()
    # Use word boundary to avoid false positives (e.g. "a" in "bar")
    if re.search(r"\b" + re.escape(lhs_a) + r"\b", stmt_b):
        return None
    if re.search(r"\b" + re.escape(lhs_b) + r"\b", stmt_a):
        return None
    replacement = f"{indent}{stmt_b}\n{indent}{stmt_a}"
    return s[: m.start()] + replacement + s[m.end() :]


def mut_guard_clause(s: str, rng: random.Random) -> str | None:
    """Extract guard clause: if(c){body;return x;} return y → if(!c) return y; body; return x;

    Changes branch prediction layout and fall-through path.
    """
    matches = list(_RE_GUARD_IF_RETURN.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    indent = m.group(1)
    cond = m.group(2).strip()
    body = m.group(3).strip()
    ret_true = m.group(4).strip()
    ret_false = m.group(5).strip()
    # Negate condition simply
    neg_cond = cond[1:].strip().lstrip("(").rstrip(")") if cond.startswith("!") else f"!({cond})"
    replacement = (
        f"{indent}if ({neg_cond}) return {ret_false};\n{indent}{body}\n{indent}return {ret_true};"
    )
    return s[: m.start()] + replacement + s[m.end() :]


def mut_invert_loop_direction(s: str, rng: random.Random) -> str | None:
    """Reverse loop iteration: for(i=0;i<n;i++) → for(i=n-1;i>=0;i--).

    Affects loop entry/exit code and comparison instruction selection.
    """
    matches = list(_RE_FOR_COUNT_UP.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    var = m.group(1)
    limit = m.group(2).strip()
    replacement = f"for ({var} = {limit} - 1; {var} >= 0; {var}--)"
    return s[: m.start()] + replacement + s[m.end() :]


def mut_compound_assign_toggle(s: str, rng: random.Random) -> str | None:
    """Toggle between x = x + n and x += n (and other operators).

    MSVC6 sometimes generates different code for these equivalent forms.
    """
    # Try expanding compound first, then shortening
    expand_matches = [(m, "expand") for m in _RE_COMPOUND_SHORT.finditer(s)]
    short_matches = [(m, "shorten") for m in _RE_COMPOUND_EXPAND.finditer(s)]
    all_matches = expand_matches + short_matches
    if not all_matches:
        return None
    m, direction = rng.choice(all_matches)
    if direction == "expand":
        var = m.group(1)
        op = m.group(2)
        expr = m.group(3).strip()
        replacement = f"{var} = {var} {op} {expr};"
    else:
        var = m.group(1)
        op = m.group(2)
        expr = m.group(3).strip()
        replacement = f"{var} {op}= {expr};"
    return s[: m.start()] + replacement + s[m.end() :]


def mut_demorgan(s: str, rng: random.Random) -> str | None:
    """Apply De Morgan's law: !(a && b) ↔ (!a || !b).

    Forces different branch structure in the compiled output.
    Only applies to exactly two operands (rejects chained operators).
    """
    and_matches = [(m, "and") for m in _RE_DEMORGAN_AND.finditer(s)]
    or_matches = [(m, "or") for m in _RE_DEMORGAN_OR.finditer(s)]
    all_matches = and_matches + or_matches
    if not all_matches:
        return None
    m, kind = rng.choice(all_matches)
    a = m.group(1).strip()
    b = m.group(2).strip()
    # Reject if either operand contains the same logical operator (chained ops)
    # e.g. !(a && b && c) — partial application creates wrong precedence
    if kind == "and" and ("&&" in a or "&&" in b):
        return None
    if kind == "or" and ("||" in a or "||" in b):
        return None
    replacement = f"(!{a} || !{b})" if kind == "and" else f"(!{a} && !{b})"
    return s[: m.start()] + replacement + s[m.end() :]


def mut_postpre_increment(s: str, rng: random.Random) -> str | None:
    """Toggle i++ ↔ ++i and i-- ↔ --i.

    Can affect codegen for complex expressions where evaluation order
    interacts with register allocation.
    """
    candidates: list[tuple[re.Match[str], str]] = []
    for m in _RE_POST_INC.finditer(s):
        candidates.append((m, f"++{m.group(1)}"))
    for m in _RE_PRE_INC.finditer(s):
        candidates.append((m, f"{m.group(1)}++"))
    for m in _RE_POST_DEC.finditer(s):
        candidates.append((m, f"--{m.group(1)}"))
    for m in _RE_PRE_DEC.finditer(s):
        candidates.append((m, f"{m.group(1)}--"))
    if not candidates:
        return None
    m, replacement = rng.choice(candidates)
    return s[: m.start()] + replacement + s[m.end() :]


def mut_xor_zero_toggle(s: str, rng: random.Random) -> str | None:
    """Toggle x = 0 ↔ x ^= x.

    Classic zero-extend pattern: MSVC6 uses xor reg,reg vs mov reg,0
    depending on source form. This can cause byte-level mismatches.
    """
    zero_matches = [(m, "to_xor") for m in _RE_ASSIGN_ZERO.finditer(s)]
    xor_matches = [(m, "to_zero") for m in _RE_XOR_SELF.finditer(s)]
    all_matches = zero_matches + xor_matches
    if not all_matches:
        return None
    m, direction = rng.choice(all_matches)
    var = m.group(1)
    # Skip if the variable looks like a struct field or array element
    if "." in var or "->" in var or "[" in var:
        return None
    # Check what precedes the match — reject struct access (p->len, s.val)
    prefix = s[: m.start()]
    stripped_prefix = prefix.rstrip()
    if stripped_prefix.endswith((".", ">")):
        return None
    # CRITICAL: reject for-loop initializers — for (i = 0; ...) → for (i ^= i; ...) is wrong
    # because i ^= i assumes i is already initialized with a value
    if re.search(r"\bfor\s*\([^;]*$", prefix):
        return None
    replacement = f"{var} ^= {var};" if direction == "to_xor" else f"{var} = 0;"
    return s[: m.start()] + replacement + s[m.end() :]


def mut_negate_condition(s: str, rng: random.Random) -> str | None:
    """Wrap if-condition in negation: if (a > b) → if (!(a > b)).

    Forces different conditional jump instruction (jle vs jg, etc.).
    Only adds negation; does NOT swap bodies (use mut_swap_if_else for that).
    """
    # Find all if-conditions using balanced paren matching
    candidates: list[tuple[int, int, str]] = []
    for m in re.finditer(r"\bif\s*\(", s):
        paren_start = m.end() - 1  # position of '('
        paren_end = _find_matching_char(s, paren_start, "(", ")")
        if paren_end is None:
            continue
        cond = s[paren_start + 1 : paren_end - 1].strip()
        if cond:
            candidates.append((m.start(), paren_end, cond))
    if not candidates:
        return None
    start, end, cond = rng.choice(candidates)
    # Toggle: if already negated, remove negation; otherwise add it
    if cond.startswith("!(") and cond.endswith(")"):
        new_cond = cond[2:-1]
    elif cond.startswith("!") and not cond.startswith("!="):
        new_cond = cond[1:].strip()
    else:
        new_cond = f"!({cond})"
    replacement = f"if ({new_cond})"
    return s[:start] + replacement + s[end:]


ALL_MUTATIONS = [
    mut_commute_simple_add,
    mut_commute_simple_mul,
    mut_flip_eq_zero,
    mut_flip_lt_ge,
    mut_add_redundant_parens,
    mut_reassociate_add,
    mut_insert_noop_block,
    mut_toggle_bool_not,
    mut_swap_eq_operands,
    mut_swap_ne_operands,
    mut_swap_or_operands,
    mut_swap_and_operands,
    mut_return_to_goto,
    mut_goto_to_return,
    mut_introduce_local_alias,
    mut_reorder_declarations,
    mut_swap_if_else,
    mut_reorder_elseif,
    mut_add_cast,
    mut_remove_cast,
    mut_toggle_volatile,
    mut_add_register_keyword,
    mut_remove_register_keyword,
    mut_if_false_to_bitand,
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
    mut_split_cmp_chain,
    mut_merge_cmp_chain,
    mut_combine_ptr_arith,
    mut_split_ptr_arith,
    mut_change_return_type,
    mut_change_param_order,
    mut_toggle_calling_convention,
    mut_toggle_char_signedness,
    mut_comparison_boundary,
    # Code layout mutations (structural codegen)
    mut_flatten_nested_if,
    mut_extract_else_body,
    mut_for_to_while,
    mut_while_to_for,
    mut_if_to_ternary,
    mut_ternary_to_if,
    mut_hoist_return,
    mut_sink_return,
    # Structural codegen mutations (batch 2)
    mut_swap_adjacent_stmts,
    mut_guard_clause,
    mut_invert_loop_direction,
    mut_compound_assign_toggle,
    mut_demorgan,
    mut_postpre_increment,
    mut_xor_zero_toggle,
    mut_negate_condition,
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

    # Build weighted selection list
    weights: list[float] | None = None
    if mutation_weights:
        weights = [mutation_weights.get(m.__name__, 1.0) for m in ALL_MUTATIONS]
        # Fall back to uniform if all weights are zero
        if not any(w > 0 for w in weights):
            weights = None
    else:
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
