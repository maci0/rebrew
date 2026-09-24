"""Tests for the single module-marker resolver (``rebrew.config.module_marker``).

The marker is the ``MODULE`` half of every ``MODULE.0xVA`` metadata key.  Before
this resolver existed, nine call sites derived it differently (raw ``.upper()``,
lower-case target name, hardcoded ``"SERVER"`` / ``"GAME"``), so one function
could be written under four different keys.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from rebrew.config import module_marker
from rebrew.utils import parse_metadata_key, qualified_key


class TestModuleMarker:
    def test_explicit_marker_wins(self) -> None:
        cfg = SimpleNamespace(marker="SERVER", target_name="client.dll")
        assert module_marker(cfg) == "SERVER"

    def test_derives_from_target_name(self) -> None:
        cfg = SimpleNamespace(marker="", target_name="server")
        assert module_marker(cfg) == "SERVER"

    def test_strips_non_identifier_chars(self) -> None:
        # Matches load_config's own derivation: a raw ``.upper()`` would yield
        # "SERVER.DLL", which matches no ``// FUNCTION: MODULE 0xVA`` line.
        cfg = SimpleNamespace(marker="", target_name="server.dll")
        assert module_marker(cfg) == "SERVERDLL"

    def test_unresolvable_is_empty_not_fabricated(self) -> None:
        cfg = SimpleNamespace(marker="", target_name="")
        assert module_marker(cfg) == ""

    def test_missing_attributes_do_not_raise(self) -> None:
        assert module_marker(SimpleNamespace()) == ""

    def test_none_values_treated_as_unset(self) -> None:
        cfg = SimpleNamespace(marker=None, target_name=None)
        assert module_marker(cfg) == ""


class TestMarkerKeyRoundTrip:
    """Why an empty marker must never reach a store writer."""

    def test_resolved_marker_round_trips_through_a_metadata_key(self) -> None:
        cfg = SimpleNamespace(marker="", target_name="server.dll")
        module = module_marker(cfg)
        assert parse_metadata_key(qualified_key(module, 0x1000)) == (module, 0x1000)

    def test_empty_module_renders_a_key_the_loader_drops(self) -> None:
        # qualified_key("") emits a bare ``0xVA`` table; parse_metadata_key only
        # accepts ``MODULE.0xVA``, so such a write is silently unreadable.
        # The store writers reject it (see below) rather than losing the data.
        assert parse_metadata_key(qualified_key("", 0x1000)) is None

    def test_function_store_rejects_an_empty_module(self, tmp_path: object) -> None:
        from rebrew.metadata import update_field

        with pytest.raises(ValueError, match="non-empty module"):
            update_field(tmp_path, 0x1000, "note", "x", module="")  # type: ignore[arg-type]

    def test_data_store_rejects_an_empty_module(self, tmp_path: object) -> None:
        from rebrew.data_metadata import set_data_field

        with pytest.raises(ValueError, match="non-empty module"):
            set_data_field(tmp_path, 0x1000, "name", "g_x", module="")  # type: ignore[arg-type]


class TestTunableDefaults:
    """One named constant per tunable: dataclass, loader, and getattr fallbacks agree."""

    def test_compile_timeout_single_source(self) -> None:
        from rebrew.config import DEFAULT_COMPILE_TIMEOUT, ProjectConfig

        assert ProjectConfig.compile_timeout == DEFAULT_COMPILE_TIMEOUT

    def test_lint_max_line_length_single_source(self) -> None:
        from rebrew.config import DEFAULT_LINT_MAX_LINE_LENGTH, ProjectConfig

        assert ProjectConfig.lint_max_line_length == DEFAULT_LINT_MAX_LINE_LENGTH
