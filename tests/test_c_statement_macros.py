"""A body the grammar cannot parse must not consume the definitions after it."""

from rebrew.c_parser import function_definition_spans, function_signatures
from rebrew.metadata.source_provenance import function_definition_hashes
from rebrew.source_binding import has_unique_source_definition

# Reduced from zlib 1.1.3 infblock.c: a statement macro used without a
# semicolon before a conditional expression leaves the body unclosed.
SOURCE = """int broken(s, r)
int *s;
int r;
{
  {
      {
        {
          {
            LEAVE
          }
          c = c == 16 ? s[i - 1] : 0;
          do {
          } while (--j);
        }
      }
      LEAVE
  }
}


int after(s)
int *s;
{
  return *s == 2;
}
"""


def test_definition_after_an_unparsable_body_is_found() -> None:
    assert function_signatures(SOURCE)["after"] == "int after(s) int *s;"
    raw = SOURCE.encode()
    assert ("after", raw.index(b"int after"), len(raw.rstrip())) in function_definition_spans(
        SOURCE
    )


def test_definition_after_an_unparsable_body_has_one_hash() -> None:
    assert "after" in function_definition_hashes(SOURCE)
    assert has_unique_source_definition(SOURCE, "after")
    assert "broken" not in function_definition_hashes(SOURCE)


def test_clean_source_is_unchanged() -> None:
    clean = "int one(void)\n{\n  return 1;\n}\nint two(void)\n{\n  return 2;\n}\n"
    assert set(function_signatures(clean)) == {"one", "two"}
    assert set(function_definition_hashes(clean)) == {"one", "two"}
