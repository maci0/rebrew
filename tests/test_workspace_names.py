"""Tests for the placeholder-name rule in ``rebrew.workspace.names``."""

from __future__ import annotations

import re

import pytest

from rebrew.workspace.names import PLACEHOLDER_NAME_PATTERN, is_placeholder_name

#: Generated labels: one per alternative of the pattern, plus the decorated
#: and rebrew-generated spellings each consumer relied on before the rules
#: were merged (BinSync import, lint W023, the dependency graph).
PLACEHOLDERS = [
    "",
    "fcn",
    "fn",
    "fun",
    "FUN_00401000",
    "FUN_main_thing",
    "DAT_10002000",
    "thunk_FUN_00401000",
    "thunk_CreateWindowA",
    "switchdataD_00402000",
    "func_10001000",
    "func_1000ABCD",
    "_func_10001000",
    "func_10001000@@12",
    "FUN_00401000@@0",
    "@func_10001000@4",
    "_func_10001000@8",
    "sub_401000",
    "sub_401000@8",
    "fcn_00401000",
    "fcn.00401000",
    "g_1234",
    "g_DEADBEEF",
    "fn_0x00009999",
    "fn_0x1000_placeholder",
]

#: Chosen names, including near misses of every alternative.
CHOSEN = [
    "Foo",
    "real_name",
    "func_hook",
    "sub_menu",
    "fcn_init",
    "fcn.init",
    "SUB_401000",
    "Fun_401000",
    "FUNC_00401000",
    "nullsub_1",
    "loc_401000",
    "j_strcpy",
    "unk_401000",
    "401000",
    "g_foo",
    "g_123",
    "g_123456789",
    "fn_0x",
    "fn_main",
    "fcnx",
    " FUN_1",
    "FUN_1\n",
]


class TestIsPlaceholderName:
    @pytest.mark.parametrize("name", PLACEHOLDERS)
    def test_generated_labels_are_placeholders(self, name: str) -> None:
        assert is_placeholder_name(name)

    @pytest.mark.parametrize("name", CHOSEN)
    def test_chosen_names_are_not(self, name: str) -> None:
        assert not is_placeholder_name(name)

    def test_published_pattern_is_the_rule(self) -> None:
        """A client compiling the published string gets the same answers."""
        compiled = re.compile(PLACEHOLDER_NAME_PATTERN)
        for name in PLACEHOLDERS + CHOSEN:
            assert (compiled.fullmatch(name) is not None) == is_placeholder_name(name), name
        assert PLACEHOLDER_NAME_PATTERN.startswith("^")
        assert PLACEHOLDER_NAME_PATTERN.endswith("$")
