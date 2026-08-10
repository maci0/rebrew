"""Tests for the typer direct-call OptionInfo-leak convention.

Direct Python calls to a typer callback (the unit-test convention) leak
``typer.models.OptionInfo`` as the value of *omitted* params — truthy, not a
Path, not the declared default.  Two real bugs came from this: a truthy
``--sweep-toolchain`` leaking into ``match``'s watch re-test, and ``rebrew
init`` crashing on a leaked ``--link-tools-from``.  These tests pin the
convention documented in docs/DEVELOPMENT.md:

- callbacks called directly guard new options with ``option_default()``;
- closures re-entering a callback forward every CLI param explicitly.
"""

from __future__ import annotations

from pathlib import Path

from typer.models import OptionInfo

from rebrew.cli import option_default


class TestOptionDefault:
    def test_optioninfo_becomes_default(self) -> None:
        leaked = OptionInfo(default=None)
        assert option_default(leaked, None) is None
        assert option_default(leaked, Path("/tmp/x")) == Path("/tmp/x")

    def test_real_values_pass_through(self) -> None:
        assert option_default(None, Path("/tmp/x")) is None  # not a leak
        assert option_default(Path("/tmp/y"), None) == Path("/tmp/y")
        assert option_default(False, True) is False
        assert option_default("value", "default") == "value"

    def test_truthiness_of_leak_is_why_the_helper_exists(self) -> None:
        """An OptionInfo is truthy — the exact trap (if x is not None: ...)."""
        leaked = OptionInfo(default=False)
        assert bool(leaked) is True


class TestConventionEnforced:
    def test_init_guards_new_option_with_helper(self) -> None:
        """init.py is the canonical example — the guard must use the helper."""
        import rebrew.init as init_mod

        source = Path(init_mod.__file__).read_text(encoding="utf-8")
        assert "option_default(toolchain_dir, None)" in source

    def test_match_retest_forwards_sweep_params(self, monkeypatch) -> None:
        """watch-mode _retest must forward the batch/sweep params explicitly —
        an omitted one leaks as a truthy OptionInfo instead of its default."""
        from types import SimpleNamespace

        from rebrew import match

        captured: dict = {}

        def _fake_main(**kwargs) -> None:  # type: ignore[no-untyped-def]
            captured.update(kwargs)

        monkeypatch.setattr(match, "main", _fake_main)
        monkeypatch.setattr(
            "rebrew.utils.watch_files",
            lambda paths, retest: retest(),  # fire the re-test immediately
        )
        monkeypatch.setattr("rebrew.match.require_config", lambda **kw: SimpleNamespace())

        # Minimal single-function watch run: the retest closure must carry
        # every CLI param, including the recently-added batch/sweep ones.
        # The fixture .c does not exist, but _retest only forwards kwargs —
        # the assertion is on the forwarded set, before any file work.
        params = SimpleNamespace(
            cfg=SimpleNamespace(metadata_dir=Path("/tmp"), reversed_dir=Path("/tmp")),
            cl="cl",
            inc=[],
            cflags="/O2",
            symbol="_f",
            msvc_env={},
            cc=None,
            timeout=30,
            va_int=0x1000,
            target_bytes=b"",
            seed_c=Path("/tmp/f.c"),
        )
        monkeypatch.setattr(match, "resolve_build_params", lambda *a, **k: params)

        # Build the watch closure without invoking the CLI.
        from typer.testing import CliRunner

        result = CliRunner().invoke(match.app, ["--watch", "/tmp/f.c"])
        assert result.exit_code in (0, 1), result.output
        for key in ("sweep_toolchain", "sweep_then_ga", "skip_recent_hours"):
            assert key in captured, f"_retest did not forward {key} (OptionInfo leak)"
        assert captured["sweep_toolchain"] is False
        assert captured["watch"] is False
