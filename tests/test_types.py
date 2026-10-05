"""Unit tests for the shared parsed type model."""

from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.types import StructDef, parse_structs


class TestParseStructs:
    def test_flat_struct_offsets(self) -> None:
        structs = parse_structs("typedef struct { int x; char y; short z; } Foo;")
        foo = structs["Foo"]
        assert isinstance(foo, StructDef)
        assert foo.fields == [("x", "int", 0), ("y", "char", 4), ("z", "short", 6)]
        assert foo.size == 8

    def test_pointer_and_array(self) -> None:
        structs = parse_structs("typedef struct { int *p; char buf[8]; } Bar;")
        bar = structs["Bar"]
        assert bar.fields == [("p", "int *", 0), ("buf", "char[8]", 4)]
        assert bar.size == 12

    def test_array_of_pointers_keeps_every_element(self) -> None:
        """``char *rows[4]`` is four pointers.

        The ``[4]`` was glued onto the name and the field was sized as one
        pointer, so ``tail`` sat at offset 4.
        """
        s = parse_structs("typedef struct { char c; char *rows[4]; int tail; } S;")["S"]
        assert s.complete
        assert s.fields == [
            ("c", "char", 0),
            ("rows", "char *[4]", 4),
            ("tail", "int", 20),
        ]
        assert s.size == 24

    def test_parenthesized_array_of_pointers_keeps_every_element(self) -> None:
        """``int (*table[4])`` is four pointers. The parentheses do not change it.

        Wrapping the suffix as ``(*[4])`` made the type unknown, so ``tail``
        was dropped. ``int (*row)[4]`` stays one pointer.
        """
        s = parse_structs("typedef struct { char c; int (*table[4]); int tail; } S;")["S"]
        assert s.complete
        assert s.fields == [
            ("c", "char", 0),
            ("table", "int *[4]", 4),
            ("tail", "int", 20),
        ]
        assert s.size == 24

    def test_pointer_to_array_field_is_one_pointer(self) -> None:
        """``char (*row)[4]`` is a pointer. The bound is the array it addresses.

        The field used to end the struct, so ``tail`` was dropped.
        """
        from rebrew.types import type_size

        assert type_size("char (*)[4]") == 4
        assert type_size("char (**)[4]") == 4
        s = parse_structs("typedef struct { char c; char (*row)[4]; int tail; } S;")["S"]
        assert s.complete
        assert s.fields == [
            ("c", "char", 0),
            ("row", "char (*)[4]", 4),
            ("tail", "int", 8),
        ]
        assert s.size == 12

    def test_array_of_pointers_to_array_is_not_a_grid(self) -> None:
        """``int (*table[2])[3]`` is two pointers. The outer bound is the pointee.

        The parentheses were dropped, so the field was ``int *[2][3]``
        (24 bytes) and ``tail`` sat at offset 28. ``char (*row)[4]`` stays
        one pointer. ``int (*plain[4])`` stays four pointers.
        """
        s = parse_structs("typedef struct { char c; int (*table[2])[3]; int tail; } S;")["S"]
        assert s.complete
        assert s.fields == [
            ("c", "char", 0),
            ("table", "int (*[2])[3]", 4),
            ("tail", "int", 12),
        ]
        assert s.size == 16
        rows = parse_structs("typedef struct { char c; char (**rows[2])[4]; int tail; } R;")["R"]
        assert rows.complete
        assert rows.fields == [
            ("c", "char", 0),
            ("rows", "char (**[2])[4]", 4),
            ("tail", "int", 12),
        ]
        assert rows.size == 16

    def test_multidimensional_array_fields(self) -> None:
        structs = parse_structs(
            "typedef struct { char tag; float m[4][4]; double grid[2][3][4]; int tail; } Matrix;"
        )
        matrix = structs["Matrix"]
        assert matrix.complete
        assert matrix.fields == [
            ("tag", "char", 0),
            ("m", "float[4][4]", 4),
            ("grid", "double[2][3][4]", 72),
            ("tail", "int", 264),
        ]
        assert matrix.size == 272

    def test_named_struct_tag(self) -> None:
        structs = parse_structs("struct Baz { int a; int b; };")
        assert structs["Baz"].size == 8

    def test_forward_reference_resolves(self) -> None:
        """A field typed as a struct declared LATER still gets its size."""
        structs = parse_structs(
            "typedef struct { Inner inner; int tail; } Outer;\n"
            "typedef struct { int a; int b; } Inner;"
        )
        outer = structs["Outer"]
        assert outer.complete
        assert [f[2] for f in outer.fields] == [0, 8]
        assert outer.size == 12

    def test_unknown_returns_empty(self) -> None:
        assert parse_structs("int x;") == {}
        assert parse_structs("") == {}


# ---------------------------------------------------------------------------
# Hypothesis fuzz — parse_structs on untrusted C text
# ---------------------------------------------------------------------------

_C_ID = st.from_regex(r"[A-Za-z_][A-Za-z0-9_]{0,12}", fullmatch=True)
_C_TYPE = st.sampled_from(
    ["char", "short", "int", "long", "float", "double", "void *", "int *", "char *"]
)


@st.composite
def _struct_source(draw: st.DrawFn) -> str:
    """Near-valid typedef/struct soup so tree-sitter + layout paths run."""
    n = draw(st.integers(min_value=0, max_value=4))
    chunks: list[str] = []
    for _ in range(n):
        name = draw(_C_ID)
        nfields = draw(st.integers(min_value=0, max_value=5))
        fields: list[str] = []
        for _ in range(nfields):
            kind = draw(st.sampled_from(["scalar", "array", "ptr", "junk"]))
            fname = draw(_C_ID)
            if kind == "scalar":
                fields.append(f"{draw(_C_TYPE)} {fname};")
            elif kind == "array":
                n_el = draw(st.integers(min_value=-2, max_value=16))
                fields.append(f"char {fname}[{n_el}];")
            elif kind == "ptr":
                fields.append(f"int *{fname};")
            else:
                fields.append(draw(st.text(max_size=24)))
        body = " ".join(fields)
        if draw(st.booleans()):
            chunks.append(f"typedef struct {{ {body} }} {name};")
        else:
            chunks.append(f"struct {name} {{ {body} }};")
        if draw(st.booleans()):
            chunks.append(draw(st.text(max_size=40)))
    if not chunks:
        return draw(st.text(max_size=200))
    return "\n".join(chunks)


def _assert_struct_map_shape(structs: dict[str, StructDef]) -> None:
    for name, sdef in structs.items():
        assert isinstance(name, str) and name
        assert isinstance(sdef, StructDef)
        assert sdef.name == name
        assert sdef.size >= 0
        assert isinstance(sdef.complete, bool)
        prev_offset = -1
        for field_name, spelling, offset in sdef.fields:
            assert isinstance(field_name, str) and field_name
            assert isinstance(spelling, str) and spelling
            assert isinstance(offset, int) and offset >= 0
            # Offsets are non-decreasing; zero-width fields (e.g. ``T x[0]``)
            # may share an offset with the next field.
            assert offset >= prev_offset
            assert offset <= sdef.size
            prev_offset = offset


@settings(max_examples=150, deadline=None)
@given(st.text(max_size=400))
def test_parse_structs_random_text_no_crash(text: str) -> None:
    """Arbitrary text: parse_structs returns a shaped map — never raises."""
    _assert_struct_map_shape(parse_structs(text))


@settings(max_examples=150, deadline=None)
@given(_struct_source())
def test_parse_structs_structured_source_invariants(src: str) -> None:
    """Structure-aware C fragments exercise typedef/tag/array/pointer layout
    without crashing; successful defs keep monotonic non-overlapping offsets."""
    _assert_struct_map_shape(parse_structs(src))


class TestStructSizes:
    def test_known_type_sizes(self) -> None:
        from rebrew.types import type_size

        assert type_size("int") == 4
        assert type_size("char") == 1
        assert type_size("short") == 2
        assert type_size("long") == 4
        assert type_size("float") == 4
        assert type_size("double") == 8
        assert type_size("void *") == 4
        assert type_size("char[16]") == 16
        assert type_size("int[4]") == 16
        assert type_size("unsigned short[2][4]") == 16

    def test_unknown_type_is_none(self) -> None:
        from rebrew.types import type_size

        assert type_size("struct Unknown") is None
        assert type_size("") is None

    def test_negative_array_size_is_none(self) -> None:
        # ``char pad[-2]; int x;`` used to lay both fields at offset 0.
        from rebrew.types import type_size

        assert type_size("char[-2]") is None
        assert type_size("int[-1]") is None

    def test_void_field_type_is_none(self) -> None:
        from rebrew.types import type_size

        assert type_size("void") is None
        assert type_size("void *") == 4  # pointers still size

    def test_negative_array_does_not_overlap_next_field(self) -> None:
        structs = parse_structs("typedef struct { char pad[-2]; int x; } Bad;")
        bad = structs["Bad"]
        assert bad.complete is False
        assert bad.fields == []  # parse stops before the invalid field

    def test_array_of_double_aligns_to_eight(self) -> None:
        """An array aligns by its element: ``double arr[2]`` is 8-aligned."""
        s = parse_structs("typedef struct { char c; double arr[2]; } S;")["S"]
        assert [f[2] for f in s.fields] == [0, 8]
        assert s.size == 24

    def test_long_long_is_eight_and_aligned(self) -> None:
        """MSVC ``long long`` and ``__int64`` are 8 bytes, aligned to 8.

        An unknown size used to stop the struct, so the following field
        was dropped and ``char c; long long x;`` did not pad ``x`` to 8.
        """
        from rebrew.types import type_size

        assert type_size("long long") == 8
        assert type_size("unsigned long long") == 8
        assert type_size("long long int") == 8
        assert type_size("__int64") == 8
        assert type_size("unsigned __int64") == 8
        s = parse_structs("typedef struct { char c; long long x; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [
            ("c", 0),
            ("x", 8),
            ("tail", 16),
        ]
        assert s.size == 24
        wide = parse_structs("typedef struct { char c; __int64 x; } W;")["W"]
        assert wide.complete
        assert [(name, off) for name, _spelling, off in wide.fields] == [("c", 0), ("x", 8)]
        assert wide.size == 16

    def test_long_double_and_multiword_ints(self) -> None:
        """``long double`` is 8 and aligned like ``double``. ``short int`` is
        ``short`` and ``long int`` is ``long``. An unknown size stopped the
        struct on the ``char``."""
        from rebrew.types import type_size

        assert type_size("long double") == 8
        assert type_size("short int") == 2
        assert type_size("unsigned short int") == 2
        assert type_size("long int") == 4
        s = parse_structs("typedef struct { char c; long double x; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [
            ("c", 0),
            ("x", 8),
            ("tail", 16),
        ]
        assert s.size == 24

    def test_div_and_mod_array_bounds(self) -> None:
        """Integer ``/`` and ``%`` fold in an array bound. ``1 / 0`` is not a bound."""
        from rebrew.types import type_size

        assert type_size("char[8 / 2]") == 4
        assert type_size("int[7 / 2]") == 12
        assert type_size("char[10 % 3]") == 1
        assert type_size("char[1 / 0]") is None
        assert type_size("char[1 << 4]") == 16
        assert type_size("char[8 >> 1]") == 4
        assert type_size("char[1 << 31]") is None
        s = parse_structs("typedef struct { char expr[8 / 2]; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [("expr", 0), ("tail", 4)]
        assert s.size == 8

    def test_signed_intermediate_array_bounds(self) -> None:
        """A negative constant may appear inside a nonnegative bound.

        ``4 + -2`` is a plus of the literals ``4`` and ``-2``. Dropping the
        negative before the addition made the bound unknown, so the struct
        stopped. Division and remainder are toward zero, so ``(-5) / 2 + 3``
        is 1. A negative final bound and a shift of a negative stay unknown.
        """
        from rebrew.types import type_size

        assert type_size("char[4 + -2]") == 2
        assert type_size("char[2 * -1 + 4]") == 2
        assert type_size("char[-(1 - 3)]") == 2
        assert type_size("char[(-2) * (-2)]") == 4
        assert type_size("char[(-5) / 2 + 3]") == 1
        assert type_size("char[(-5) % 2 + 2]") == 1
        assert type_size("char[+(1 + 1)]") == 2
        assert type_size("char[(-1) << 1]") is None
        assert type_size("char[1 << -1]") is None
        assert type_size("char[1 - 3]") is None
        assert type_size("char[-2]") is None
        s = parse_structs("typedef struct { char expr[4 + -2]; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [("expr", 0), ("tail", 4)]
        assert s.size == 8

    def test_bitwise_array_bounds(self) -> None:
        """Nonnegative ``&``, ``|``, and ``^`` fold in an array bound.

        ``15 & 7`` is 7. A negative operand and ``~`` stay unknown: signed
        bitwise is not two's complement here.
        """
        from rebrew.types import type_size

        assert type_size("char[15 & 7]") == 7
        assert type_size("char[15 | 16]") == 31
        assert type_size("char[255 ^ 15]") == 240
        assert type_size("int[15 & 7]") == 28
        assert type_size("char[1 | 2 & 4]") == 1
        assert type_size("char[(-1) & 7]") is None
        assert type_size("char[~0]") is None
        s = parse_structs("typedef struct { char expr[15 & 7]; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [("expr", 0), ("tail", 8)]
        assert s.size == 12

    def test_integer_cast_array_bounds(self) -> None:
        """A cast that does not change the value is the bound.

        ``(int)(2 + 2)`` is 4 and ``4 + (int)-2`` is 2. A cast that would
        truncate (``(char)256``) or reinterpret a negative as unsigned
        (``(unsigned)-1``) stays unknown.
        """
        from rebrew.types import type_size

        assert type_size("char[(int)(2 + 2)]") == 4
        assert type_size("char[(unsigned)4]") == 4
        assert type_size("char[4 + (int)-2]") == 2
        assert type_size("char[(char)4]") == 4
        assert type_size("char[(signed char)4]") == 4
        assert type_size("char[(unsigned char)200]") == 200
        assert type_size("char[(char)256]") is None
        assert type_size("char[(unsigned)-1]") is None
        assert type_size("char[(const int)4]") == 4
        assert type_size("char[(int *)4]") is None
        s = parse_structs("typedef struct { char expr[(int)(2 + 2)]; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [("expr", 0), ("tail", 4)]
        assert s.size == 8

    def test_ternary_array_bounds(self) -> None:
        """A constant ``?:`` picks the live arm. Both arms must fold.

        ``1 ? 4 : 2`` is 4 and ``0 ? 8 : 2`` is 2. A name in either arm
        stays unknown, including the arm that C would not evaluate.
        """
        from rebrew.types import type_size

        assert type_size("char[1 ? 4 : 2]") == 4
        assert type_size("char[0 ? 8 : 2]") == 2
        assert type_size("char[-1 ? 3 : 9]") == 3
        assert type_size("char[1 ? 4 : n]") is None
        assert type_size("char[0 ? n : 2]") is None
        s = parse_structs("typedef struct { char expr[0 ? 8 : 2]; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [("expr", 0), ("tail", 4)]
        assert s.size == 8

    def test_comma_operator_array_bounds(self) -> None:
        """The comma operator's value is its rightmost operand.

        ``(2, 3)`` is 3 and ``(2, 3, 4)`` is 4. Every operand must fold,
        so a name or ``1 / 0`` on the left stays unknown.
        """
        from rebrew.types import type_size

        assert type_size("char[(2, 3)]") == 3
        assert type_size("char[(2, 3, 4)]") == 4
        assert type_size("char[(2, n)]") is None
        assert type_size("char[(1 / 0, 4)]") is None
        s = parse_structs("typedef struct { char expr[(0, 2)]; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [("expr", 0), ("tail", 4)]
        assert s.size == 8

    def test_sizeof_array_bounds(self) -> None:
        """``sizeof`` of a known 32-bit type is a bound.

        ``sizeof(int)`` is 4 and ``sizeof(char) * 4`` is 4. An unknown
        type and ``sizeof`` of an expression stay unknown.
        """
        from rebrew.types import type_size

        assert type_size("char[sizeof(int)]") == 4
        assert type_size("char[sizeof(char) * 4]") == 4
        assert type_size("char[sizeof(long long)]") == 8
        assert type_size("char[sizeof(long double)]") == 8
        assert type_size("char[sizeof(unsigned short)]") == 2
        assert type_size("char[sizeof(const int)]") == 4
        assert type_size("char[sizeof(int *)]") == 4
        assert type_size("char[sizeof(int[2])]") == 8
        assert type_size("char[sizeof(Foo)]") is None
        assert type_size("char[sizeof(2)]") is None
        s = parse_structs("typedef struct { char expr[sizeof(short)]; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [("expr", 0), ("tail", 4)]
        assert s.size == 8

    def test_comparison_array_bounds(self) -> None:
        """A constant comparison is 0 or 1, so it can choose a ternary arm.

        ``1 < 2 ? 4 : 8`` is 4. ``2 > 1`` is 1.
        """
        from rebrew.types import type_size

        assert type_size("char[1 < 2]") == 1
        assert type_size("char[1 > 2]") == 0
        assert type_size("char[2 <= 2]") == 1
        assert type_size("char[2 >= 3]") == 0
        assert type_size("char[2 == 2]") == 1
        assert type_size("char[2 != 2]") == 0
        assert type_size("char[-1 < 0]") == 1
        assert type_size("char[1 < 2 ? 4 : 8]") == 4
        assert type_size("char[1 > 2 ? 4 : 8]") == 8
        s = parse_structs("typedef struct { char expr[2 > 1]; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [("expr", 0), ("tail", 4)]
        assert s.size == 8

    def test_logical_array_bounds(self) -> None:
        """``&&``, ``||``, and ``!`` fold to 0 or 1, not to the operand.

        ``1 && 2`` is 1. ``0 || 3`` is 1. ``!0`` is 1. An unknown operand
        stays unknown.
        """
        from rebrew.types import type_size

        assert type_size("char[1 && 2]") == 1
        assert type_size("char[1 && 0]") == 0
        assert type_size("char[0 || 3]") == 1
        assert type_size("char[0 || 0]") == 0
        assert type_size("char[!0]") == 1
        assert type_size("char[!2]") == 0
        assert type_size("char[!-1]") == 0
        assert type_size("char[1 && 2 ? 4 : 8]") == 4
        assert type_size("char[0 && n]") is None
        s = parse_structs("typedef struct { char expr[0 || 1]; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [("expr", 0), ("tail", 4)]
        assert s.size == 8

    def test_character_constant_array_bounds(self) -> None:
        """A character constant is an integer bound.

        ``'A'`` is 65, ``'\\n'`` is 10, and ``'\\x10'`` is 16. A
        multi-character literal stays unknown.
        """
        from rebrew.types import type_size

        assert type_size("char['A']") == 65
        assert type_size("char['\\n']") == 10
        assert type_size("char['\\x10']") == 16
        assert type_size("char['\\0']") == 0
        assert type_size("char[L'A']") == 65
        assert type_size("char['AB']") is None
        s = parse_structs("typedef struct { char expr['\\n']; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [("expr", 0), ("tail", 12)]
        assert s.size == 16

    def test_sizeof_string_array_bounds(self) -> None:
        """``sizeof`` of a string counts the bytes plus the terminating NUL.

        ``sizeof("hi")`` is 3 and ``sizeof("")`` is 1. Adjacent strings
        are one literal.
        """
        from rebrew.types import type_size

        assert type_size('char[sizeof("hi")]') == 3
        assert type_size('char[sizeof("")]') == 1
        assert type_size('char[sizeof("hi\\n")]') == 4
        assert type_size('char[sizeof("a" "b")]') == 3
        assert type_size('char[sizeof "hi"]') == 3
        # 32-bit MSVC wchar_t is 2. The L prefix used to be ignored, so this was 3.
        assert type_size('char[sizeof(L"hi")]') == 6
        assert type_size('char[sizeof(L"")]') == 2
        assert type_size('char[sizeof(u"hi")]') == 6
        assert type_size('char[sizeof(U"hi")]') == 12
        assert type_size('char[sizeof(u8"hi")]') == 3
        assert type_size('char[sizeof("a" L"b")]') is None
        s = parse_structs('typedef struct { char expr[sizeof("hi")]; int tail; } S;')["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [("expr", 0), ("tail", 4)]
        assert s.size == 8

    def test_wchar_t_is_two_bytes(self) -> None:
        """32-bit MSVC ``wchar_t`` is 2 bytes, the same width as ``L""``.

        ``sizeof(wchar_t)`` and a ``wchar_t`` field used to be unknown, so
        the struct stopped and the following ``int`` was dropped.
        """
        from rebrew.types import type_size

        assert type_size("wchar_t") == 2
        assert type_size("char[sizeof(wchar_t)]") == 2
        assert type_size("wchar_t[3]") == 6
        s = parse_structs("typedef struct { wchar_t c; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [("c", 0), ("tail", 4)]
        assert s.size == 8

    def test_sizeof_character_constant(self) -> None:
        """A C character constant has type ``int`` on 32-bit MSVC.

        ``sizeof('A')`` is 4. ``sizeof(L'A')`` is 2 (``wchar_t``),
        ``sizeof(u'A')`` is 2, and ``sizeof(U'A')`` is 4. A
        multi-character literal is still an ``int``.
        """
        from rebrew.types import type_size

        assert type_size("char[sizeof('A')]") == 4
        assert type_size("char[sizeof 'A']") == 4
        assert type_size("char[sizeof(L'A')]") == 2
        assert type_size("char[sizeof(u'A')]") == 2
        assert type_size("char[sizeof(U'A')]") == 4
        assert type_size("char[sizeof(u8'A')]") == 1
        assert type_size("char[sizeof('AB')]") == 4

    def test_bool_is_one_byte(self) -> None:
        """32-bit MSVC ``bool`` is 1 byte.

        ``sizeof(bool)`` and a ``bool`` field used to be unknown, so the
        struct stopped and the following ``int`` was dropped.
        """
        from rebrew.types import type_size

        assert type_size("bool") == 1
        assert type_size("char[sizeof(bool)]") == 1
        assert type_size("bool[4]") == 4
        s = parse_structs("typedef struct { bool flag; int tail; } S;")["S"]
        assert s.complete
        assert [(name, off) for name, _spelling, off in s.fields] == [("flag", 0), ("tail", 4)]
        assert s.size == 8

    def test_sizeof_identifier_array(self) -> None:
        """``sizeof(wchar_t[3])`` is 6.

        ``wchar_t`` is not a tree-sitter keyword, so ``wchar_t[3]`` was a
        subscript and the bound stayed unknown. ``const wchar_t[3]`` already
        parsed as a type. An unknown name stays unknown.
        """
        from rebrew.types import type_size

        assert type_size("char[sizeof(wchar_t[3])]") == 6
        assert type_size("char[sizeof(wchar_t[2][3])]") == 12
        assert type_size("char[sizeof(wchar_t[2 + 1])]") == 6
        assert type_size("char[sizeof(n[3])]") is None

    def test_sizeof_pointer_to_array_is_not_the_object(self) -> None:
        """``sizeof(char (*)[4])`` is 4. ``sizeof(char *[2])`` is 8.

        ``(*)`` inside the bound sized ``int[sizeof(char (*)[4])]`` as one
        pointer. ``char *[2]`` stayed unknown, so the next field was dropped.
        """
        from rebrew.types import type_size

        assert type_size("int[sizeof(char (*)[4])]") == 16
        assert type_size("char[sizeof(char (**)[4])]") == 4
        assert type_size("char[sizeof(char *[2])]") == 8
        assert type_size("short[sizeof(int *[2][3])]") == 48
        assert type_size("char (*)[4]") == 4
        s = parse_structs("typedef struct { char gap[sizeof(char *[2])]; int tail; } Rows;")["Rows"]
        assert s.complete
        assert s.fields == [("gap", "char[sizeof(char *[2])]", 0), ("tail", "int", 8)]
        assert s.size == 12

    def test_array_of_int_still_aligns_to_four(self) -> None:
        s = parse_structs("typedef struct { char c; int arr[2]; } S;")["S"]
        assert [f[2] for f in s.fields] == [0, 4]
        assert s.size == 12

    def test_c_constant_array_bounds(self) -> None:
        """Hex, octal, and a constant expression are C bounds.

        ``int()`` read ``0x10`` as not a number, ``010`` as ten, and
        ``2 + 2`` as not a number, so the struct stopped at that field.
        """
        from rebrew.types import type_size

        assert type_size("char[0x10]") == 16
        assert type_size("char[010]") == 8
        assert type_size("char[2 + 2]") == 4
        foo = parse_structs(
            "typedef struct { char gap[0x10]; char oct[010]; char expr[2 + 2]; int tail; } Foo;"
        )["Foo"]
        assert foo.complete
        assert [f[0] for f in foo.fields] == ["gap", "oct", "expr", "tail"]
        assert [f[2] for f in foo.fields] == [0, 16, 24, 28]
        assert foo.size == 32


class TestCheckStruct:
    def test_clean_declaration(self) -> None:
        from rebrew.types import check_struct, parse_structs

        structs = parse_structs("typedef struct { int x; char y; } Foo;")
        assert check_struct(structs["Foo"], {0: 4, 4: 1}) == []

    def test_missing_offset(self) -> None:
        from rebrew.types import check_struct, parse_structs

        structs = parse_structs("typedef struct { int x; } Foo;")
        findings = check_struct(structs["Foo"], {0: 4, 8: 4})
        assert findings == [{"offset": 8, "evidenced_width": 4, "issue": "missing"}]

    def test_narrow_field(self) -> None:
        from rebrew.types import check_struct, parse_structs

        structs = parse_structs("typedef struct { char x; } Foo;")
        findings = check_struct(structs["Foo"], {0: 4})
        assert findings == [{"offset": 0, "evidenced_width": 4, "issue": "width", "field": "x"}]

    def test_nested_struct_field_span_resolved(self) -> None:
        """A read inside a nested-struct field is not reported as missing when
        the known-structs map supplies its size."""
        from rebrew.types import check_struct, parse_structs

        structs = parse_structs(
            "typedef struct { int a; int b; } Inner;\n"
            "typedef struct { char c; Inner inner; int tail; } Outer;"
        )
        # Without the map the "Inner" span is zero-width and this read is
        # reported missing.
        assert check_struct(structs["Outer"], {4: 4}, known_structs=structs) == []


class TestCollectEvidence:
    def test_named_evidence_merged(self, tmp_path: Path) -> None:
        from rebrew.types_cli import collect_evidence

        dec = tmp_path / "f.dec.c"
        dec.write_text(
            "void f(Player *p) {\n  p->field_0 = 1;\n  int x = *(int *)(p + 4);\n}\n",
            encoding="utf-8",
        )
        ev = collect_evidence([dec])
        assert ev == {"Player": {0: 4, 4: 4}}


class TestRewriteParamType:
    def test_rewrites_indexed_param(self) -> None:
        from rebrew.types import rewrite_param_type

        src = "int __cdecl foo(int a, void *p) { return a; }\n"
        out = rewrite_param_type(src, "foo", 1, "Player *")
        assert out == "int __cdecl foo(int a, Player *p) { return a; }\n"

    def test_missing_function_returns_none(self) -> None:
        from rebrew.types import rewrite_param_type

        assert rewrite_param_type("int foo(void) { return 0; }\n", "bar", 0, "int") is None

    def test_bad_index_returns_none(self) -> None:
        from rebrew.types import rewrite_param_type

        assert rewrite_param_type("int foo(int a) { return a; }\n", "foo", 3, "int") is None

    def test_legacy_bytes_round_trip(self, tmp_path: Path) -> None:
        from rebrew.types import rewrite_param_type
        from rebrew.utils import read_compile_source

        path = tmp_path / "f.c"
        path.write_bytes(b'char *s = "Caf\xe9";\nint foo(int a, void *p) { return a; }\n')
        out = rewrite_param_type(read_compile_source(path), "foo", 1, "Player *")
        assert out is not None
        assert out.encode("utf-8", errors="surrogateescape") == (
            b'char *s = "Caf\xe9";\nint foo(int a, Player *p) { return a; }\n'
        )


class TestApplyTypeCli:
    def _cfg(self, tmp_path: Path):
        from types import SimpleNamespace

        return SimpleNamespace(
            root=tmp_path,
            reversed_dir=tmp_path / "src",
            metadata_dir=tmp_path,
            source_ext=".c",
            marker="SERVER",
        )

    def test_apply_rewrites_param(self, tmp_path: Path, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.types_cli import app

        src = tmp_path / "src"
        src.mkdir()
        f = src / "foo.c"
        f.write_text("int __cdecl foo(int a, void *p) { return a; }\n", encoding="utf-8")
        monkeypatch.setattr("rebrew.types_cli.require_config", lambda **kw: self._cfg(tmp_path))
        res = CliRunner().invoke(app, ["apply", "foo", "--param", "1", "--type", "Player *"])
        assert res.exit_code == 0, res.output
        assert "Player *p" in f.read_text(encoding="utf-8")

    def test_apply_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.types_cli import app

        src = tmp_path / "src"
        src.mkdir()
        f = src / "foo.c"
        before = "int __cdecl foo(int a, void *p) { return a; }\n"
        f.write_text(before, encoding="utf-8")
        monkeypatch.setattr("rebrew.types_cli.require_config", lambda **kw: self._cfg(tmp_path))
        res = CliRunner().invoke(
            app, ["apply", "foo", "--param", "1", "--type", "Player *", "--dry-run"]
        )
        assert res.exit_code == 0, res.output
        assert f.read_text(encoding="utf-8") == before
