import random
import re
from typing import Any


def _split_preamble_body(source: str) -> tuple[str, str]:
    """Split source into preamble (includes, typedefs, externs) and function body."""
    lines = source.splitlines()
    preamble = []
    body = []
    in_body = False
    brace_count = 0

    for line in lines:
        if not in_body:
            if re.match(r"^[a-zA-Z_][a-zA-Z0-9_*\s]*\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(", line):
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

def _quick_validate(source: str) -> bool:
    """Fast check for obvious syntax errors (unbalanced braces/parens)."""
    if source.count("{") != source.count("}"):
        return False
    if source.count("(") != source.count(")"):
        return False
    return True

def compute_population_diversity(pop: list[str]) -> float:
    """Compute diversity of the population (0.0 to 1.0)."""
    if not pop or len(pop) < 2:
        return 0.0

    unique_sources = set(pop)
    return len(unique_sources) / len(pop)

def crossover(parent1: str, parent2: str, rng: random.Random) -> str:
    """Line-level crossover of two parent sources."""
    p1_pre, p1_body = _split_preamble_body(parent1)
    p2_pre, p2_body = _split_preamble_body(parent2)

    lines1 = p1_body.splitlines()
    lines2 = p2_body.splitlines()

    if not lines1 or not lines2:
        return parent1

    # Find a safe split point (not inside a statement)
    # This is a naive implementation. A real AST-based crossover is better.
    split_idx = rng.randint(1, min(len(lines1), len(lines2)) - 1)

    child_body = "\n".join(lines1[:split_idx] + lines2[split_idx:])
    child = p1_pre + "\n" + child_body

    if _quick_validate(child):
        return child
    return parent1

# --- Mutations ---

def mut_commute_simple_add(s: str, rng: random.Random) -> str | None:
    # x + y  -> y + x  (identifiers only)
    pat = r"\b([A-Za-z_]\w*)\s*\+\s*([A-Za-z_]\w*)\b"
    return _sub_once(pat, lambda m: f"{m.group(2)} + {m.group(1)}", s, rng)


def mut_commute_simple_mul(s: str, rng: random.Random) -> str | None:
    pat = r"\b([A-Za-z_]\w*)\s*\*\s*([A-Za-z_]\w*)\b"
    return _sub_once(pat, lambda m: f"{m.group(2)} * {m.group(1)}", s, rng)


def mut_flip_eq_zero(s: str, rng: random.Random) -> str | None:
    # x == 0 -> !x , x != 0 -> !!x
    pat = r"\b([A-Za-z_]\w*)\s*(==|!=)\s*0\b"

    def repl(m):
        x, op = m.group(1), m.group(2)
        return f"!{x}" if op == "==" else f"!!{x}"

    return _sub_once(pat, repl, s, rng)


def mut_flip_lt_ge(s: str, rng: random.Random) -> str | None:
    # a < b -> !(a >= b)
    pat = r"\b([A-Za-z_]\w*)\s*<\s*([A-Za-z_]\w*)\b"
    return _sub_once(pat, lambda m: f"!({m.group(1)} >= {m.group(2)})", s, rng)


def mut_add_redundant_parens(s: str, rng: random.Random) -> str | None:
    pat = r"\b([A-Za-z_]\w*)\b"
    return _sub_once(pat, lambda m: f"({m.group(1)})", s, rng)


def mut_reassociate_add(s: str, rng: random.Random) -> str | None:
    # (a + b) + c -> a + (b + c)
    pat = r"\(\s*([A-Za-z_]\w*)\s*\+\s*([A-Za-z_]\w*)\s*\)\s*\+\s*([A-Za-z_]\w*)"
    return _sub_once(
        pat, lambda m: f"{m.group(1)} + ({m.group(2)} + {m.group(3)})", s, rng
    )


def mut_insert_noop_block(s: str, rng: random.Random) -> str | None:
    # Insert a no-op volatile read, tends to affect optimization, use sparingly.
    insertion = "\n    { volatile int __noop = 0; (void)__noop; }\n"
    lines = s.splitlines(True)
    if len(lines) < 3:
        return None
    idx = rng.randrange(0, len(lines))
    return "".join(lines[:idx] + [insertion] + lines[idx:])


def mut_toggle_bool_not(s: str, rng: random.Random) -> str | None:
    # !!x -> x, and x -> !!x for identifiers in boolean contexts is unsafe.
    # Here only remove !! on identifiers.
    pat = r"!!\s*([A-Za-z_]\w*)"
    return _sub_once(pat, lambda m: f"{m.group(1)}", s, rng)


def mut_swap_eq_operands(s: str, rng: random.Random) -> str | None:
    """a == b -> b == a"""
    pat = r"(\b\w+\b)\s*==\s*(\b\w+\b)"
    return _sub_once(pat, lambda m: f"{m.group(2)} == {m.group(1)}", s, rng)


def mut_swap_ne_operands(s: str, rng: random.Random) -> str | None:
    """a != b -> b != a"""
    pat = r"(\b\w+\b)\s*!=\s*(\b\w+\b)"
    return _sub_once(pat, lambda m: f"{m.group(2)} != {m.group(1)}", s, rng)


def mut_swap_or_operands(s: str, rng: random.Random) -> str | None:
    """a || b -> b || a  (changes short-circuit order, affects codegen)"""
    pat = r"([^|&\n]+?)\s*\|\|\s*([^|&\n;)]+)"
    matches = list(re.finditer(pat, s))
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
    pat = r"([^|&\n]+?)\s*&&\s*([^|&\n;)]+)"
    matches = list(re.finditer(pat, s))
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
    pat = r"\breturn\s+(?:FALSE|0)\s*;"
    matches = list(re.finditer(pat, s))
    if not matches:
        return None
    m = rng.choice(matches)
    start, end = m.span()
    result = s[:start] + "goto ret_false;" + s[end:]
    # Add label before the final return statement
    final_ret = re.search(r"(\n)([ \t]*return\s+\w+\s*;\s*\n\})", result)
    if final_ret:
        pos = final_ret.start(1)
        result = result[:pos] + "\nret_false:\n" + result[pos:]
    else:
        # Fallback: add before closing brace
        last_brace = result.rfind("}")
        if last_brace >= 0:
            result = (
                result[:last_brace]
                + "ret_false:\n    return 0;\n"
                + result[last_brace:]
            )
    return result


def mut_goto_to_return(s: str, rng: random.Random) -> str | None:
    """Reverse: replace 'goto ret_false;' with 'return FALSE;'"""
    pat = r"\bgoto\s+ret_false\s*;"
    matches = list(re.finditer(pat, s))
    if not matches:
        return None
    m = rng.choice(matches)
    start, end = m.span()
    result = s[:start] + "return FALSE;" + s[end:]
    # Remove the label if no more gotos reference it
    if "goto ret_false" not in result:
        result = re.sub(r"\n\s*ret_false:\s*\n\s*return\s+0\s*;\s*\n", "\n", result)
        result = re.sub(r"\n\s*ret_false:\s*\n", "\n", result)
    return result


def mut_introduce_local_alias(s: str, rng: random.Random) -> str | None:
    """Create a local variable aliasing a parameter and replace some uses."""
    # Find parameter names in __stdcall function signatures
    params = re.findall(r"\b(?:HANDLE|DWORD|LPVOID|int|BOOL)\s+(\w+)", s)
    params = [
        p
        for p in params
        if len(p) > 1 and p not in ("WINAPI", "BOOL", "HANDLE", "DWORD", "LPVOID")
    ]
    if not params:
        return None
    param = rng.choice(params)
    alias = "_" + param[0]  # e.g., hDllHandle -> _h
    if alias in s:
        return None  # already aliased

    # Find the type of the parameter
    type_match = re.search(
        r"\b(HANDLE|DWORD|LPVOID|int|BOOL)\s+" + re.escape(param) + r"\b", s
    )
    if not type_match:
        return None
    ptype = type_match.group(1)

    # Insert alias declaration after opening brace of function body
    brace_match = re.search(r"\)\s*\{", s)
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
    to_replace = rng.sample(
        occurrences, k=min(rng.randint(1, len(occurrences)), len(occurrences))
    )
    to_replace.sort(key=lambda m: m.start(), reverse=True)
    for occ in to_replace:
        body = body[: occ.start()] + alias + body[occ.end() :]
    return result[:body_start] + body


def mut_reorder_declarations(s: str, rng: random.Random) -> str | None:
    """Move a local variable declaration or add an initializer."""
    # Find declarations like "TYPE varname;" at the start of function body
    pat = r"^([ \t]+)((?:BOOL|int|DWORD|HANDLE|LPVOID)\s+\w+)\s*;$"
    matches = list(re.finditer(pat, s, re.MULTILINE))
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
        init_pat = r"^([ \t]+(?:BOOL|int|DWORD|HANDLE|LPVOID)\s+\w+)\s*=\s*\w+\s*;$"
        init_matches = list(re.finditer(init_pat, s, re.MULTILINE))
        if not init_matches:
            return None
        im = rng.choice(init_matches)
        return s[: im.start()] + im.group(1) + ";" + s[im.end() :]


def _find_matching_brace(s: str, open_pos: int) -> int | None:
    """Find closing brace matching the opening brace at open_pos."""
    if open_pos >= len(s) or s[open_pos] != "{":
        return None
    depth = 1
    i = open_pos + 1
    while i < len(s) and depth > 0:
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
        i += 1
    return i if depth == 0 else None


def mut_swap_if_else(s: str, rng: random.Random) -> str | None:
    """Negate condition and swap if/else bodies."""
    pat = r"\bif\s*\(([^{]*?)\)\s*\{"
    matches = list(re.finditer(pat, s))
    if not matches:
        return None
    m = rng.choice(matches)
    cond = m.group(1).strip()
    if_brace_start = s.index("{", m.start())
    if_brace_end = _find_matching_brace(s, if_brace_start)
    if if_brace_end is None:
        return None

    # Check for else clause
    rest = s[if_brace_end:].lstrip()
    if not rest.startswith("else"):
        return None
    else_start = s.index("else", if_brace_end)
    after_else = s[else_start + 4 :].lstrip()
    if not after_else.startswith("{"):
        return None
    else_brace_start = s.index("{", else_start + 4)
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
        s[: m.start()]
        + f"if ({neg_cond}) {{{else_body}}} else {{{if_body}}}"
        + s[else_brace_end:]
    )
    return result


def mut_reorder_elseif(s: str, rng: random.Random) -> str | None:
    """Swap two branches in an else-if chain."""
    # Find if(...){...} else if(...){...} patterns
    pat = r"(\bif\s*\([^{]*?\)\s*\{)"
    matches = list(re.finditer(pat, s))
    if len(matches) < 2:
        return None

    # Find adjacent if/else-if pairs
    for m in matches:
        brace_start = s.index("{", m.start())
        brace_end = _find_matching_brace(s, brace_start)
        if brace_end is None:
            continue
        rest = s[brace_end:].lstrip()
        if rest.startswith("else if"):
            else_if_start = s.index("else if", brace_end)
            # Extract the else-if condition and body
            ei_match = re.match(r"else\s+if\s*\(([^{]*?)\)\s*\{", s[else_if_start:])
            if not ei_match:
                continue
            ei_brace_start = s.index("{", else_if_start + ei_match.start())
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
    casts = ["(BOOL)", "(int)", "(DWORD)"]
    cast = rng.choice(casts)
    # Find identifiers in expression contexts (after = or in function args)
    pat = r"(?<=[=(,!])\s*(\b[A-Za-z_]\w*\b)(?!\s*\()"
    matches = list(re.finditer(pat, s))
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
    pat = r"\((?:BOOL|int|DWORD|HANDLE|LPVOID)\)(\w+)"
    return _sub_once(pat, lambda m: m.group(1), s, rng)


def mut_toggle_volatile(s: str, rng: random.Random) -> str | None:
    """Add or remove 'volatile' on a local variable declaration."""
    # Try removing volatile first
    vol_pat = r"\bvolatile\s+"
    vol_matches = list(re.finditer(vol_pat, s))
    if vol_matches and rng.random() < 0.5:
        m = rng.choice(vol_matches)
        return s[: m.start()] + s[m.end() :]
    # Try adding volatile
    pat = r"^([ \t]+)((?:BOOL|int|DWORD|HANDLE|LPVOID)\s+\w+)"
    matches = list(re.finditer(pat, s, re.MULTILINE))
    matches = [m for m in matches if "volatile" not in s[m.start() : m.end() + 20]]
    if not matches:
        return None
    m = rng.choice(matches)
    return s[: m.start()] + m.group(1) + "volatile " + m.group(2) + s[m.end() :]


def mut_add_register_keyword(s: str, rng: random.Random) -> str | None:
    """Add 'register' keyword to a local variable declaration.
    Note: MSVC6 largely ignores register hints, but the keyword
    can sometimes affect variable ordering in the symbol table."""
    pat = r"^([ \t]+)((?:BOOL|int|DWORD|HANDLE|LPVOID)\s+\w+)"
    matches = list(re.finditer(pat, s, re.MULTILINE))
    if not matches:
        return None
    m = rng.choice(matches)
    if "register" in s[m.start() : m.end() + 20]:
        return None
    return s[: m.start()] + m.group(1) + "register " + m.group(2) + s[m.end() :]


def mut_remove_register_keyword(s: str, rng: random.Random) -> str | None:
    """Remove 'register' keyword from a declaration."""
    pat = r"\bregister\s+"
    matches = list(re.finditer(pat, s))
    if not matches:
        return None
    m = rng.choice(matches)
    return s[: m.start()] + s[m.end() :]


def mut_if_false_to_bitand(s: str, rng: random.Random) -> str | None:
    """Convert 'if (!expr) var = FALSE;' to 'var &= expr;'.

    This can produce `and [mem], reg` instead of `test/jne/mov` pattern,
    which is how MSVC6 sometimes optimizes this idiom.
    """
    # Match: if (!CALL(...)) VAR = FALSE;
    pat = r"if\s*\(\s*!\s*(\w+\s*\([^)]*\))\s*\)\s*\n?\s*(\w+)\s*=\s*(?:FALSE|0)\s*;"
    matches = list(re.finditer(pat, s))
    if not matches:
        return None
    m = rng.choice(matches)
    call_expr = m.group(1)
    var_name = m.group(2)
    replacement = "%s &= %s;" % (var_name, call_expr)
    return s[: m.start()] + replacement + s[m.end() :]


def mut_bitand_to_if_false(s: str, rng: random.Random) -> str | None:
    """Reverse of mut_if_false_to_bitand: convert 'var &= expr;' to 'if (!expr) var = FALSE;'."""
    pat = r"(\w+)\s*&=\s*(\w+\s*\([^)]*\))\s*;"
    matches = list(re.finditer(pat, s))
    if not matches:
        return None
    m = rng.choice(matches)
    var_name = m.group(1)
    call_expr = m.group(2)
    replacement = "if (!%s)\n            %s = FALSE;" % (call_expr, var_name)
    return s[: m.start()] + replacement + s[m.end() :]


def mut_introduce_temp_for_call(s: str, rng: random.Random) -> str | None:
    """Introduce a temp variable for a function call result.

    Transforms: var = FuncCall(...);
    Into:       tmp = FuncCall(...); var = tmp;

    This can help the compiler keep the result in a register for subsequent tests.
    """
    # Match: VAR = CALL(args);  (but not var &= or var |= etc.)
    pat = r"(\w+)\s*=\s*(\w+\s*\([^;]+\))\s*;"
    matches = list(re.finditer(pat, s))
    # Filter to only function calls (must have parens), not already using tmp
    matches = [m for m in matches if "(" in m.group(2) and "tmp" not in m.group(0)]
    if not matches:
        return None
    m = rng.choice(matches)
    var_name = m.group(1)
    call_expr = m.group(2)
    # Check if tmp is already declared
    if re.search(r"\b(?:BOOL|int)\s+tmp\b", s):
        replacement = "tmp = %s;\n    %s = tmp;" % (call_expr, var_name)
    else:
        replacement = "tmp = %s;\n    %s = tmp;" % (call_expr, var_name)
    return s[: m.start()] + replacement + s[m.end() :]


def mut_remove_temp_var(s: str, rng: random.Random) -> str | None:
    """Remove a temp variable usage: 'tmp = expr; var = tmp;' -> 'var = expr;'."""
    pat = r"tmp\s*=\s*([^;]+);\s*\n\s*(\w+)\s*=\s*tmp\s*;"
    matches = list(re.finditer(pat, s))
    if not matches:
        return None
    m = rng.choice(matches)
    expr = m.group(1)
    var_name = m.group(2)
    return s[: m.start()] + "%s = %s;" % (var_name, expr) + s[m.end() :]


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
    pat_remove = r"\bunsigned\s+(int|long|short|char)\b"
    matches = list(re.finditer(pat_remove, s))
    pat_add = r"(?<!\bunsigned\s)(?<!\bsigned\s)\b(int|long|short)\s+(\w+)\s*[;=,]"
    matches_add = list(re.finditer(pat_add, s))

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
        return (
            s[: m.start()] + "unsigned " + m.group(0) + s[m.end() + len(m.group(0)) :]
        )


def mut_swap_adjacent_declarations(s: str, rng: random.Random) -> str | None:
    """Swap two adjacent variable declarations at function start.

    MSVC6 register allocator is sensitive to declaration order when
    multiple variables have similar liveness. Swapping declarations
    can change which variable gets EAX vs ECX vs EDX.
    """

    type_pat = (
        r"(?:const\s+)?(?:unsigned\s+)?(?:volatile\s+)?"
        r"(?:BOOL|int|DWORD|HANDLE|LPVOID|HLOCAL|void|char|short|long|float|double|"
        r"UINT|ULONG|BYTE|WORD|SIZE_T|CRITICAL_SECTION|ushort|uint|undefined\d?)"
    )
    pat = (
        r"^([ \t]+)(" + type_pat + r")\s+\**\w+(?:\s*\[[^\]]*\])?\s*(?:=\s*[^;]+)?;\s*$"
    )
    lines = s.split("\n")
    decl_indices = []
    for i, line in enumerate(lines):
        if re.match(pat, line):
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
    pat = (
        r"^([ \t]+)((?:const\s+)?(?:unsigned\s+)?(?:volatile\s+)?"
        r"(?:BOOL|int|DWORD|HANDLE|LPVOID|char|short|long|float|double|"
        r"UINT|ULONG|BYTE|WORD)\s+\**(\w+))\s*=\s*([^;]+);"
    )
    matches = list(re.finditer(pat, s, re.MULTILINE))
    if not matches:
        return None
    m = rng.choice(matches)
    indent = m.group(1)
    decl = m.group(2)
    var = m.group(3)
    init_expr = m.group(4).strip()
    replacement = "%s%s;\n%s%s = %s;" % (indent, decl, indent, var, init_expr)
    return s[: m.start()] + replacement + s[m.end() :]


def mut_merge_declaration_init(s: str, rng: random.Random) -> str | None:
    """Merge 'TYPE var; ... var = expr;' into 'TYPE var = expr;'.

    Reverse of mut_split_declaration_init. Merging shortens the live range
    gap, which can free a register for other variables.
    """

    type_kw = (
        r"(?:BOOL|int|DWORD|HANDLE|LPVOID|char|short|long|float|double|"
        r"UINT|ULONG|BYTE|WORD)"
    )
    pat = (
        r"^([ \t]+)((?:unsigned\s+)?(?:volatile\s+)?" + type_kw + r")\s+(\w+)\s*;\s*\n"
        r"([ \t]+)\3\s*=\s*([^;]+);"
    )
    matches = list(re.finditer(pat, s, re.MULTILINE))
    if not matches:
        return None
    m = rng.choice(matches)
    indent = m.group(1)
    type_decl = m.group(2)
    var = m.group(3)
    init_expr = m.group(5).strip()
    replacement = "%s%s %s = %s;" % (indent, type_decl, var, init_expr)
    return s[: m.start()] + replacement + s[m.end() :]


def mut_while_to_dowhile(s: str, rng: random.Random) -> str | None:
    """Convert 'while (cond) { body }' to 'if (cond) { do { body } while (cond); }'.

    MSVC6 performs loop rotation differently for while vs do-while.
    A do-while avoids the duplicated condition check at loop top.
    """
    pat = r"while\s*\(([^)]+)\)\s*\{"
    matches = list(re.finditer(pat, s))
    if not matches:
        return None
    m = rng.choice(matches)
    cond = m.group(1)

    brace_start = m.end() - 1
    close = _find_matching_brace(s, brace_start)
    if close is None:
        return None
    body = s[brace_start + 1 : close]
    before = s[: m.start()]
    after = s[close + 1 :]
    replacement = "if (%s) {\n    do {%s} while (%s);\n    }" % (cond, body, cond)
    return before + replacement + after


def mut_dowhile_to_while(s: str, rng: random.Random) -> str | None:
    """Convert 'do { body } while (cond);' to 'while (cond) { body }'.

    Reverse of mut_while_to_dowhile. Changes loop rotation behavior.
    """
    pat = r"\bdo\s*\{"
    matches = list(re.finditer(pat, s))
    if not matches:
        return None
    m = rng.choice(matches)
    brace_start = m.end() - 1
    close = _find_matching_brace(s, brace_start)
    if close is None:
        return None
    body = s[brace_start + 1 : close]
    # Find 'while (cond);' after closing brace
    after_close = s[close + 1 :].lstrip()
    wm = re.match(r"while\s*\(([^)]+)\)\s*;", after_close)
    if not wm:
        return None
    cond = wm.group(1)
    before = s[: m.start()]
    rest = s[close + 1 + len(s[close + 1 :]) - len(after_close) + wm.end() :]
    replacement = "while (%s) {%s}" % (cond, body)
    return before + replacement + rest


def mut_early_return_to_accum(s: str, rng: random.Random) -> str | None:
    """Convert 'if (!expr) return 0;' to 'ret &= expr;' accumulator pattern.

    This extends the live range of a return-value variable, creating register
    pressure that forces the compiler to spill other variables to stack,
    changing the overall register allocation.
    """
    pat = r"if\s*\(\s*!\s*(\w+\s*\([^)]*\))\s*\)\s*\n?\s*return\s+(?:FALSE|0)\s*;"
    matches = list(re.finditer(pat, s))
    if not matches:
        return None
    m = rng.choice(matches)
    call_expr = m.group(1)
    # Check if 'ret' or 'retcode' already exists
    if re.search(r"\bret(?:code)?\b", s):
        var = "retcode" if "retcode" in s else "ret"
        replacement = "%s &= %s;" % (var, call_expr)
    else:
        replacement = "if (!%s) return 0;" % call_expr  # no change
        return None
    return s[: m.start()] + replacement + s[m.end() :]


def mut_accum_to_early_return(s: str, rng: random.Random) -> str | None:
    """Convert 'ret &= expr;' to 'if (!expr) return 0;'.

    Reverse of mut_early_return_to_accum.
    """
    pat = r"(\w+)\s*&=\s*(\w+\s*\([^)]*\))\s*;"
    matches = list(re.finditer(pat, s))
    if not matches:
        return None
    m = rng.choice(matches)
    var_name = m.group(1)
    if var_name not in ("ret", "retcode", "result"):
        return None
    call_expr = m.group(2)
    replacement = "if (!%s)\n        return 0;" % call_expr
    return s[: m.start()] + replacement + s[m.end() :]


def mut_pointer_to_int_param(s: str, rng: random.Random) -> str | None:
    """Change a pointer parameter to int or vice versa.

    MSVC6 generates different address computation instructions for
    pointer arithmetic vs integer + cast, affecting register usage.
    """
    # Find pointer params: TYPE *name or TYPE* name
    pat_ptr = r"\b(char|void|int|short|long|unsigned\s+char)\s*\*\s*(\w+)"
    matches = list(re.finditer(pat_ptr, s))
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
    # Find 'int name' in function signatures (after '(' or ',')
    pat = r"(?<=[(,])\s*int\s+(\w+)"
    matches = list(re.finditer(pat, s))
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
    import re

    # Find while loops
    while_pat = re.compile(
        r"\bwhile\s*\(([^)]+)\)\s*\{([^}]+)\}", re.MULTILINE | re.DOTALL
    )
    matches = list(while_pat.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    cond = m.group(1)
    body = m.group(2)
    # Duplicate body
    new_body = body + "\n" + body.strip()
    new_while = f"while ({cond}) {{{new_body}}}"
    return s[: m.start()] + new_while + s[m.end() :]


def mut_fold_constant_add(s: str, rng: random.Random) -> str | None:
    """Fold multiple +1 or +N into a single addition.

    Changes: x = x + 1; x = x + 1; -> x = x + 2;
    This affects how many add instructions are generated.
    """
    import re

    # Find repeated increments of same var: var = var + N
    pat = re.compile(r"(\w+)\s*=\s*\1\s*\+\s*(\d+);\s*(\1)\s*=\s*\3\s*\+\s*(\d+);")
    matches = list(pat.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    var = m.group(1)
    n1 = int(m.group(2))
    n2 = int(m.group(4))
    old = m.group(0)
    new = f"{var} = {var} + {n1 + n2};"
    return s[: m.start()] + new + s[m.end() :]


def mut_unfold_constant_add(s: str, rng: random.Random) -> str | None:
    """Unfold addition into multiple increments.

    Changes: x = x + 2; -> x = x + 1; x = x + 1;
    This adds more add instructions for register pressure.
    """
    import re

    # Find x = x + N where N > 1
    pat = re.compile(r"(\w+)\s*=\s*\1\s*\+\s*(\d+);")
    matches = list(pat.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    var = m.group(1)
    n = int(m.group(2))
    if n <= 1:
        return None
    # Split into n increments of 1
    incs = "; ".join([f"{var} = {var} + 1" for _ in range(n)])
    old = m.group(0)
    return s[: m.start()] + incs + s[m.end() :]


def mut_change_array_index_order(s: str, rng: random.Random) -> str | None:
    """Change array[i] to i[array] (equivalent but different codegen).

    Both compile to same code but can affect MSVC register allocation.
    """
    import re

    # Find array[index] patterns
    pat = re.compile(r"(\w+)\s*\[\s*(\w+)\s*\]")
    matches = list(pat.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    arr = m.group(1)
    idx = m.group(2)
    old = m.group(0)
    new = f"{idx}[{arr}]"
    return s[: m.start()] + new + s[m.end() :]


def mut_struct_vs_ptr_access(s: str, rng: random.Random) -> str | None:
    """Change ptr->field to (*ptr).field (equivalent semantics, different codegen).

    This affects how MSVC generates field access code.
    """
    import re

    # Find ptr->field
    pat = re.compile(r"(\w+)\s*->\s*(\w+)")
    matches = list(pat.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    ptr = m.group(1)
    field = m.group(2)
    old = m.group(0)
    new = f"(*{ptr}).{field}"
    return s[: m.start()] + new + s[m.end() :]


def mut_split_cmp_chain(s: str, rng: random.Random) -> str | None:
    """Split chained comparisons into separate if statements.

    Changes: if (a == b && b == c) -> if (a == b) if (b == c)
    This changes control flow and register usage.
    """
    import re

    # Find if with && chain
    pat = re.compile(
        r"if\s*\(([^=!&|]+)\s*&&\s*([^=!&|]+)\s*&&\s*([^)]+)\)", re.MULTILINE
    )
    matches = list(pat.finditer(s))
    if not matches:
        # Try 2-way &&
        pat = re.compile(r"if\s*\(([^=!&|]+)\s*&&\s*([^)]+)\)")
        matches = list(pat.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    cond = m.group(0)
    inner = (
        m.group(1)
        if m.lastindex == 1
        else m.group(2)
        if m.lastindex == 2
        else m.group(3)
    )
    parts = [
        p.strip()
        for p in re.split(r"\s*&&\s*", m.group(0).replace("if (", "").replace(")", ""))
    ]
    if len(parts) < 2:
        return None
    new_ifs = "; ".join([f"if ({p}) {{}}" for p in parts])
    return s[: m.start()] + new_ifs + s[m.end() :]


def mut_merge_cmp_chain(s: str, rng: random.Random) -> str | None:
    """Merge separate if statements into chained comparison.

    Changes: if (a == b) {} if (b == c) {} -> if (a == b && b == c) {}
    Opposite of split_cmp_chain.
    """
    import re

    # Find adjacent if statements
    if_pat = re.compile(r"if\s*\(([^)]+)\)\s*\{\s*\}\s*if\s*\(([^)]+)\)\s*\{\s*\}")
    matches = list(if_pat.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    cond1 = m.group(1)
    cond2 = m.group(2)
    old = m.group(0)
    new = f"if ({cond1} && {cond2}) {{}}"
    return s[: m.start()] + new + s[m.end() :]


def mut_combine_ptr_arith(s: str, rng: random.Random) -> str | None:
    """Combine separate pointer arithmetic into single expression.

    Changes: p = p + n; p = p + m; -> p = p + (n + m);
    Affects number of add instructions generated.
    """
    import re

    pat = re.compile(r"(\w+)\s*=\s*\1\s*\+\s*(\d+);\s*(\1)\s*=\s*\3\s*\+\s*(\d+);")
    matches = list(pat.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    var = m.group(1)
    n1 = int(m.group(2))
    n2 = int(m.group(4))
    old = m.group(0)
    new = f"{var} = {var} + {n1 + n2};"
    return s[: m.start()] + new + s[m.end() :]


def mut_split_ptr_arith(s: str, rng: random.Random) -> str | None:
    """Split combined pointer arithmetic into separate statements.

    Changes: p = p + n; -> p = p + n1; p = p + n2; where n1+n2=n
    Adds more add instructions for register pressure.
    """
    import re

    pat = re.compile(r"(\w+)\s*=\s*\1\s*\+\s*(\d+);")
    matches = list(pat.finditer(s))
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
    old = m.group(0)
    new = f"{var} = {var} + {n1}; {var} = {var} + {n2};"
    return s[: m.start()] + new + s[m.end() :]


def mut_change_return_type(s: str, rng: random.Random) -> str | None:
    """Change return type between int/char/short for register pressure.

    Different return types generate different register usage (al vs ax vs eax).
    """
    import re

    # Find function return type
    pat = re.compile(
        r"^(int|char|short|long)\s+(\*?\s*\w+)\s*\([^)]*\)\s*\{", re.MULTILINE
    )
    matches = list(pat.finditer(s))
    if not matches:
        return None
    m = rng.choice(matches)
    types = ["int", "char", "short", "long"]
    current = m.group(1)
    new_type = rng.choice([t for t in types if t != current])
    old = m.group(0)
    new = f"{new_type} {m.group(2)} {{"
    return s[: m.start()] + new + s[m.end() :]


def mut_change_param_order(s: str, rng: random.Random) -> str | None:
    """Reorder function parameters to affect register allocation.

    MSVC passes parameters in different registers based on position.
    """
    import re

    # Find function signature
    pat = re.compile(r"^(\w+\s+\w+)\s*\(([^)]+)\)\s*\{", re.MULTILINE | re.DOTALL)
    match = pat.search(s)
    if not match:
        return None
    params = [p.strip() for p in match.group(2).split(",")]
    if len(params) < 2:
        return None
    # Swap two random params
    i, j = rng.sample(range(len(params)), 2)
    params[i], params[j] = params[j], params[i]
    old = match.group(0)

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
]

def mutate_code(
    source: str,
    rng: random.Random,
    track_mutation: bool = False,
    mutation_weights: dict[str, float] | None = None,
) -> Any:
    """Apply a random mutation to the source code."""
    preamble, body = _split_preamble_body(source)

    valid_mutations = [m for m in ALL_MUTATIONS if m is not None]

    for _ in range(10):
        mut_func = rng.choice(valid_mutations)
        new_body = mut_func(body, rng)
        if new_body and new_body != body:
            new_source = preamble + "\n" + new_body
            if _quick_validate(new_source):
                if track_mutation:
                    return new_source, mut_func.__name__
                return new_source

    if track_mutation:
        return source, "none"
    return source
