"""Address anchors locate syntax while metadata owns classification and state."""

import pytest

from rebrew.metadata.anchors import add_address_anchor, parse_address_anchors


class TestAddressAnchors:
    def test_functions_variables_constants_and_shared_targets(self) -> None:
        source = (
            "// ADDRESS: SERVER 0x10001000\n// ADDRESS: CLIENT 0x401000\n"
            "int\nf(int x) { return x; }\n"
            "/* ADDRESS: SERVER 0x10002000 */\nint g;\n"
            '// ADDRESS: CLIENT 0x402000\nstatic const char message[] = "hello";\n'
            "// ADDRESS: SERVER 0x10003000\nextern int (*callback)(void);\n"
        )
        anchors = parse_address_anchors(source)
        assert [(a.module, a.va, a.name, a.kind) for a in anchors] == [
            ("SERVER", 0x10001000, "f", "FUNCTION"),
            ("CLIENT", 0x401000, "f", "FUNCTION"),
            ("SERVER", 0x10002000, "g", "DATA"),
            ("CLIENT", 0x402000, "message", "DATA"),
            ("SERVER", 0x10003000, "callback", "DATA"),
        ]
        assert anchors[0].definition_line == anchors[1].definition_line == 3

    @pytest.mark.parametrize(
        "source",
        [
            "// ADDRESS: S 0x1000\n",
            "// ADDRESS: S nope\nint x;\n",
            "// ADDRESS: S 0x1000\nint a, b;\n",
            '// ADDRESS: S 0x1000\n#include "x.h"\nint x;\n',
            "// ADDRESS: S 0x1000\nf();\nint x;\n",
            "int x; // ADDRESS: S 0x1000\nint y;\n",
        ],
    )
    def test_refuses_malformed_or_ambiguous_binding(self, source: str) -> None:
        with pytest.raises(ValueError, match="line 1:"):
            parse_address_anchors(source)

    def test_strings_and_disabled_comment_text_are_not_anchors(self) -> None:
        assert parse_address_anchors('char *s = "// ADDRESS: S 0x1000";\n') == []
        assert parse_address_anchors("/* disabled\n// ADDRESS: S 0x1000\n*/\nint x;") == []

    def test_writer_stacks_targets_and_preserves_crlf(self) -> None:
        source = "int f(void) { return 1; }\r\n"
        first = add_address_anchor(source, "S", 0x1000, "f")
        both = add_address_anchor(first, "C", 0x2000, "f")
        assert "\n" not in both.replace("\r\n", "")
        assert [a.module for a in parse_address_anchors(both)] == ["S", "C"]
        assert add_address_anchor(both, "S", 0x1000, "f") == both


class TestAnchorCache:
    def test_cached_results_are_isolated_and_edits_revalidated(self) -> None:
        source = "// ADDRESS: CACHE 0x1000\nint cache_identity;\n"
        first = parse_address_anchors(source)
        first.clear()
        assert parse_address_anchors(source)[0].name == "cache_identity"
        changed = source.replace("cache_identity", "changed_identity")
        assert parse_address_anchors(changed)[0].name == "changed_identity"
        with pytest.raises(ValueError, match="exactly one"):
            parse_address_anchors(source.replace("int cache_identity;", "int a, b;"))

    def test_cache_retention_is_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.metadata import anchors

        monkeypatch.setattr(anchors, "_ANCHOR_CACHE", anchors.OrderedDict())
        monkeypatch.setattr(anchors, "_ANCHOR_CACHE_CHARS", 0)
        monkeypatch.setattr(anchors, "_ANCHOR_CACHE_MAX_CHARS", 100)
        monkeypatch.setattr(anchors, "_ANCHOR_CACHE_MAX_ENTRIES", 2)
        for i in range(10):
            parse_address_anchors(f"// ADDRESS: CACHE 0x{i:04x}\nint value_{i};\n")
            assert len(anchors._ANCHOR_CACHE) <= 2
            assert anchors._ANCHOR_CACHE_CHARS <= 100
        oversized = "// ADDRESS: CACHE 0x1000\nint value;\n" + " " * 101
        assert parse_address_anchors(oversized)[0].name == "value"
        assert oversized not in anchors._ANCHOR_CACHE
