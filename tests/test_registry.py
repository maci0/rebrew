"""Tests for declarative component registration (rebrew.registry).

Covers entry-point discovery, import failure reporting, the single-source
conflict policy, and each registry's merge path (toolchains, decompiler
backends, GA mutations, CLI commands).
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from rebrew.registry import (
    RegistryError,
    entry_point_registrations,
    import_registration,
    merge_into,
    merge_provider_dict,
)


def _fake_entry_points(**groups: list[tuple[str, str]]) -> Any:
    """A stand-in for ``importlib.metadata.entry_points()`` (a callable).

    ``group -> [(name, value), ...]`` — each value is ``module`` or
    ``module:attr``, exactly the shape of a setuptools entry point."""

    def _entry_points() -> SimpleNamespace:
        def _select(group: str) -> list[SimpleNamespace]:
            return [SimpleNamespace(name=n, value=v) for n, v in groups.get(group, ())]

        return SimpleNamespace(select=_select)

    return _entry_points


def _install_fake_module(name: str, **attrs: Any) -> types.ModuleType:
    """Insert an importable fake module into sys.modules (importlib hits it)."""
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    sys.modules[name] = mod
    return mod


class TestEntryPointRegistrations:
    def test_parses_module_and_attr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{"rebrew.toolchains": [("a", "rebrew.diagnose"), ("b", "rebrew.diagnose:main")]}
            ),
        )
        regs = entry_point_registrations("rebrew.toolchains")
        assert [(r.name, r.target) for r in regs] == [
            ("a", "rebrew.diagnose"),
            ("b", "rebrew.diagnose:main"),
        ]
        assert all(r.origin == "entry-point" for r in regs)

    def test_bad_value_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.commands": [("bad", ":nope")]}),
        )
        with pytest.raises(RegistryError, match="expected 'module' or 'module:attr'"):
            entry_point_registrations("rebrew.commands")


class TestImportRegistration:
    def test_imports_module(self) -> None:
        reg = entry_point_registrations("rebrew.commands") or SimpleNamespace(
            name="x", module="rebrew.diagnose", attr="", group="g", origin="entry-point"
        )
        obj = import_registration(reg)
        assert obj.__name__ == "rebrew.diagnose"

    def test_imports_attr(self) -> None:
        from rebrew.diagnose import main as diagnose_main

        reg = SimpleNamespace(
            name="x", module="rebrew.diagnose", attr="main", group="g", origin="entry-point"
        )
        assert import_registration(reg) is diagnose_main

    def test_missing_module_raises(self) -> None:
        reg = SimpleNamespace(
            name="x", module="rebrew.no_such_module", attr="", group="g", origin="entry-point"
        )
        with pytest.raises(RegistryError, match="module 'rebrew.no_such_module' not importable"):
            import_registration(reg)

    def test_missing_attr_raises(self) -> None:
        reg = SimpleNamespace(
            name="x", module="rebrew.diagnose", attr="nope", group="g", origin="entry-point"
        )
        with pytest.raises(RegistryError, match="has no attribute 'nope'"):
            import_registration(reg)


class TestMerge:
    def test_merge_into_conflict_raises(self) -> None:
        registry = {"a": 1}
        with pytest.raises(RegistryError, match="duplicate"):
            merge_into(registry, "a", 2, "data-file x.toml", group="toolchains")

    def test_merge_provider_dict_ok(self) -> None:
        registry: dict[str, int] = {}
        merge_provider_dict(registry, lambda: {"a": 1, "b": 2}, "entry-point", group="g")
        assert registry == {"a": 1, "b": 2}

    def test_merge_provider_dict_conflict_raises(self) -> None:
        registry = {"a": 1}
        with pytest.raises(RegistryError, match="duplicate"):
            merge_provider_dict(registry, lambda: {"a": 2}, "entry-point", group="g")

    def test_merge_provider_dict_non_dict_raises(self) -> None:
        with pytest.raises(RegistryError, match="expected dict"):
            merge_provider_dict({}, lambda: [1], "entry-point", group="g")

    def test_merge_provider_dict_raising_provider_raises(self) -> None:
        def _boom() -> dict[str, Any]:
            raise RuntimeError("kaboom")

        with pytest.raises(RegistryError, match="kaboom"):
            merge_provider_dict({}, _boom, "entry-point", group="g")


class TestToolchainRegistry:
    def test_overlay_adds_toolchain(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("REBREW_TOOLCHAIN_OVERLAY_DIR", str(tmp_path))
        (tmp_path / "custom.toml").write_text(
            '[mytc]\nimage = "rebrew/custom:1.0-win32"\nbinary = "mycc"\n'
            'flags_style = "posix"\nobj_ext = ".o"\ndescription = "custom"\n',
            encoding="utf-8",
        )
        from rebrew.toolchain import build_toolchain_registry

        registry = build_toolchain_registry()
        assert "msvc6" in registry  # built-ins intact
        spec = registry["mytc"]
        assert spec.image == "rebrew/custom:1.0-win32"
        assert spec.flags_style == "posix"
        assert spec.obj_ext == ".o"

    def test_overlay_conflict_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("REBREW_TOOLCHAIN_OVERLAY_DIR", str(tmp_path))
        (tmp_path / "dup.toml").write_text('[msvc6]\nbinary = "cl"\n', encoding="utf-8")
        from rebrew.toolchain import build_toolchain_registry

        with pytest.raises(RegistryError, match="duplicate.*msvc6"):
            build_toolchain_registry()

    def test_overlay_unknown_field_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("REBREW_TOOLCHAIN_OVERLAY_DIR", str(tmp_path))
        (tmp_path / "bad.toml").write_text('[mytc]\ncompiler = "cl"\n', encoding="utf-8")
        from rebrew.toolchain import build_toolchain_registry

        with pytest.raises(RegistryError, match="unknown field"):
            build_toolchain_registry()

    def test_overlay_dir_missing_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("REBREW_TOOLCHAIN_OVERLAY_DIR", str(tmp_path / "nope"))
        from rebrew.toolchain import build_toolchain_registry

        with pytest.raises(Exception, match="is not a directory"):
            build_toolchain_registry()

    def test_entry_point_provider_adds_toolchain(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.toolchain import ToolchainSpec, build_toolchain_registry

        monkeypatch.delenv("REBREW_TOOLCHAIN_OVERLAY_DIR", raising=False)
        _install_fake_module(
            "tc_provider_test",
            provider=lambda: {"plugtc": ToolchainSpec(name="plugtc", image=None, binary="pcc")},
        )
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.toolchains": [("plugtc", "tc_provider_test:provider")]}),
        )
        registry = build_toolchain_registry()
        assert registry["plugtc"].binary == "pcc"

    def test_entry_point_provider_conflict_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.toolchain import ToolchainSpec, build_toolchain_registry

        monkeypatch.delenv("REBREW_TOOLCHAIN_OVERLAY_DIR", raising=False)
        _install_fake_module(
            "tc_provider_conflict",
            provider=lambda: {"msvc6": ToolchainSpec(name="msvc6", image=None, binary="cl")},
        )
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{"rebrew.toolchains": [("msvc6", "tc_provider_conflict:provider")]}
            ),
        )
        with pytest.raises(RegistryError, match="duplicate.*msvc6"):
            build_toolchain_registry()


class TestDecompilerRegistry:
    def test_entry_point_backend_added(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.decompiler import _merge_entry_point_backends

        def _fake_backend(binary: Path, va: int, root: Path, **_kwargs: Any) -> str | None:
            return None

        _install_fake_module("backend_provider_test", backend=_fake_backend)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{"rebrew.decompiler_backends": [("plugdec", "backend_provider_test:backend")]}
            ),
        )
        merged, _auto = _merge_entry_point_backends()
        assert "plugdec" in merged
        assert merged["plugdec"] is _fake_backend
        assert "r2ghidra" in merged  # packaged backends intact

    def test_entry_point_conflict_skipped_with_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        from rebrew.decompiler import _merge_entry_point_backends

        def _fake_backend(binary: Path, va: int, root: Path, **_kwargs: Any) -> str | None:
            return None

        _install_fake_module("backend_provider_dup", backend=_fake_backend)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{"rebrew.decompiler_backends": [("r2ghidra", "backend_provider_dup:backend")]}
            ),
        )
        with caplog.at_level("WARNING", logger="rebrew.decompiler"):
            merged, _auto = _merge_entry_point_backends()
        assert "r2ghidra" in merged  # packaged backend survives
        assert any("duplicate" in r.message for r in caplog.records)


class TestMutationRegistry:
    def test_entry_point_mutation_added(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.matcher.mutator import _merge_entry_point_mutations

        def _mut_plugin(s: str, rng: Any) -> str | None:
            return None

        _install_fake_module("mutation_provider_test", mut_fn=_mut_plugin)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{"rebrew.mutations": [("mut_plugin_op", "mutation_provider_test:mut_fn")]}
            ),
        )
        merged = _merge_entry_point_mutations()
        assert any(m is _mut_plugin for m in merged)
        assert len(merged) > 100  # packaged operators still present

    def test_entry_point_conflict_skipped_with_warning(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        from rebrew.matcher.mutator import _merge_entry_point_mutations

        def _mut_plugin(s: str, rng: Any) -> str | None:
            return None

        _install_fake_module("mutation_provider_dup", mut_fn=_mut_plugin)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{
                    "rebrew.mutations": [
                        ("mut_hoist_repeated_deref", "mutation_provider_dup:mut_fn")
                    ]
                }
            ),
        )
        with caplog.at_level("WARNING", logger="rebrew.matcher.mutator"):
            merged = _merge_entry_point_mutations()
        assert not any(m is _mut_plugin for m in merged)  # skipped
        assert len(merged) > 100  # packaged operators intact
        assert any("duplicate" in r.message for r in caplog.records)

    def test_module_without_attr_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.matcher.mutator import _merge_entry_point_mutations

        _install_fake_module("mutation_provider_mod")
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.mutations": [("mut_x", "mutation_provider_mod")]}),
        )
        merged = _merge_entry_point_mutations()
        assert not any(m.__name__ == "mut_x" for m in merged)


class TestCliRegistry:
    def test_discovered_single_command_registered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.main

        fresh = typer.Typer()
        monkeypatch.setattr(rebrew.main, "app", fresh)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.commands": [("diagtest", "rebrew.diagnose")]}),
        )
        rebrew.main._register_discovered_commands()
        names = [c.name for c in fresh.registered_commands]
        assert "diagtest" in names

    def test_discovered_multi_command_registered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.main

        fresh = typer.Typer()
        monkeypatch.setattr(rebrew.main, "app", fresh)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.multicommands": [("libtest", "rebrew.library")]}),
        )
        rebrew.main._register_discovered_commands()
        names = [g.name for g in fresh.registered_groups]
        assert "libtest" in names

    def test_attr_form_registered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.main

        fresh = typer.Typer()
        monkeypatch.setattr(rebrew.main, "app", fresh)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.commands": [("diagattr", "rebrew.diagnose:main")]}),
        )
        rebrew.main._register_discovered_commands()
        assert "diagattr" in [c.name for c in fresh.registered_commands]

    def test_stub_fallback_for_broken_plugin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.main

        fresh = typer.Typer()
        monkeypatch.setattr(rebrew.main, "app", fresh)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.commands": [("broken", "rebrew.no_such_module")]}),
        )
        rebrew.main._register_discovered_commands()
        names = [c.name for c in fresh.registered_commands]
        assert "broken" in names
        result = CliRunner().invoke(fresh, ["broken"])
        assert result.exit_code == 2  # EXIT_ERROR — stub reports the missing dep

    def test_duplicate_vs_builtin_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.main

        fresh = typer.Typer()
        monkeypatch.setattr(rebrew.main, "app", fresh)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.commands": [("test", "rebrew.diagnose")]}),
        )
        with pytest.raises(RegistryError, match="duplicate CLI command 'test'"):
            rebrew.main._register_discovered_commands()


class TestFlagSetRegistry:
    def _patch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _provider() -> dict[str, object]:
            from rebrew.matcher.flags import FlagSet

            return {
                "mytc": (
                    [FlagSet(id="my_opt", flags=("-O1", "-O2"))],
                    {"quick": ["my_opt"], "full": None},
                )
            }

        _install_fake_module("flag_provider_test", provider=_provider)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.flag_sets": [("p", "flag_provider_test:provider")]}),
        )

    def test_plugin_flag_set_merged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.matcher import compiler

        self._patch(monkeypatch)
        flags, tiers = compiler._merged_flag_sets()
        assert "mytc" in flags and "mytc" in tiers
        assert "msvc6" in flags and "watcom" in tiers  # packaged intact

    def test_plugin_sweep_uses_plugin_axes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.matcher import compiler

        self._patch(monkeypatch)
        flags, tiers = compiler._merged_flag_sets()
        monkeypatch.setattr(compiler, "_FLAGS_MAP", flags)
        monkeypatch.setattr(compiler, "_TIERS_MAP", tiers)
        combos = compiler.generate_flag_combinations(tier="quick", profile="mytc")
        assert "-O1" in combos and "-O2" in combos
        assert not any("/O2" in c for c in combos)  # not the MSVC axes

    def test_bad_provider_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.matcher import compiler

        _install_fake_module("flag_provider_bad", provider=lambda: [1, 2])
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.flag_sets": [("p", "flag_provider_bad:provider")]}),
        )
        flags, tiers = compiler._merged_flag_sets()
        assert "msvc6" in flags  # packaged axes intact


class TestLibraryPresetRegistry:
    def _patch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _provider() -> dict[str, dict[str, str]]:
            return {"my-runtime": {"toolchain": "mytc", "cflags": "-O2"}}

        _install_fake_module("preset_provider_test", provider=_provider)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{"rebrew.library_presets": [("p", "preset_provider_test:provider")]}
            ),
        )

    def test_plugin_preset_applies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.metadata as metadata

        self._patch(monkeypatch)
        all_presets = metadata._merged_library_presets()
        assert "my-runtime" in all_presets
        assert "msvcrt-static" in all_presets  # packaged intact
        # wire the merged registry in, then confirm resolution uses it
        monkeypatch.setattr(metadata, "_LIBRARY_PRESETS_ALL", all_presets)
        merged, presets = metadata.apply_library_presets({"library": "my-runtime"})
        assert presets == ("my-runtime",)
        assert merged["toolchain"] == "mytc"
        assert merged["cflags"] == "-O2"
        merged2, _ = metadata.apply_library_presets({"library": "msvcrt-static"})
        assert merged2["toolchain"] == "msvc6"

    def test_plugin_preset_recognized_by_library_cli(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.metadata as metadata

        self._patch(monkeypatch)
        monkeypatch.setattr(metadata, "_LIBRARY_PRESETS_ALL", metadata._merged_library_presets())
        from rebrew.library import app as library_app

        # --preset my-runtime must not be rejected as unknown
        result = CliRunner().invoke(library_app, ["set", "--preset", "my-runtime", str(tmp_path)])
        assert result.exit_code == 0


class TestToolchainDetectorRegistry:
    def _patch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _provider() -> dict[str, list[str]]:
            return {"msvc": ["mytc"], "delphi": ["mytc"]}

        _install_fake_module("detector_provider_test", provider=_provider)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{"rebrew.toolchain_detectors": [("p", "detector_provider_test:provider")]}
            ),
        )

    def test_plugin_family_alignment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.toolchain_detect as td

        self._patch(monkeypatch)
        compat = td._merged_profile_compat()
        assert "mytc" in compat["msvc"]
        assert compat["delphi"] == {"mytc"}  # un-matchable family opened
        monkeypatch.setattr(td, "_PROFILE_COMPAT_ALL", compat)
        info = td.ToolchainInfo(
            family="msvc", arch="x86_32", msvc_version="6.0", suggested_profiles=None
        )
        aligned, _ = td.profile_matches_detection("mytc", info)
        assert aligned

    def test_bad_provider_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.toolchain_detect import _merged_profile_compat

        _install_fake_module("detector_provider_bad", provider=lambda: {"msvc": "nope"})
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{"rebrew.toolchain_detectors": [("p", "detector_provider_bad:provider")]}
            ),
        )
        compat = _merged_profile_compat()
        assert "msvc6" in compat["msvc"]  # packaged family table intact


class TestPluginToolchainConfig:
    """A plugin toolchain must be selectable and routed like a packaged one."""

    def _project(self, tmp_path: Path, profile: str) -> Path:
        (tmp_path / "rebrew-project.toml").write_text(
            f'[project]\nroot = "{tmp_path}"\ndefault_target = "T"\n'
            f'[targets.T]\nbinary = "{tmp_path}/t.exe"\n'
            f'[compiler]\nprofile = "{profile}"\n',
            encoding="utf-8",
        )
        return tmp_path

    def _overlay(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        overlay = tmp_path / "overlay"
        overlay.mkdir(exist_ok=True)
        (overlay / "mytc.toml").write_text(
            '[mytc]\nbinary = "mycc"\nflags_style = "posix"\nobj_ext = ".o"\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("REBREW_TOOLCHAIN_OVERLAY_DIR", str(overlay))

    def test_plugin_profile_not_rewritten(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.config import load_config

        self._overlay(tmp_path, monkeypatch)
        # TOOLCHAINS is a module-level snapshot built at first import; rebuild
        # it with the overlay, as a process started with the env set would have.
        import rebrew.toolchain as toolchain

        monkeypatch.setattr(toolchain, "TOOLCHAINS", toolchain.build_toolchain_registry())
        root = self._project(tmp_path, "mytc")
        cfg = load_config(root=root)
        assert cfg.compiler_profile == "mytc"
        assert cfg.posix_style is True
        assert cfg.base_cflags == ""

    def test_plugin_profile_without_overlay_falls_back(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.config import load_config

        monkeypatch.delenv("REBREW_TOOLCHAIN_OVERLAY_DIR", raising=False)
        root = self._project(tmp_path, "not-a-real-toolchain")
        cfg = load_config(root=root)
        assert cfg.compiler_profile == "msvc6"  # unknown → historic fallback


class TestBinaryDetectorRegistry:
    def _patch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.toolchain_detect import ToolchainInfo

        def _detect(path: Path) -> ToolchainInfo | None:
            if path.name == "junk.bin":
                return ToolchainInfo(
                    family="acme-c",
                    confidence="high",
                    version_hint="Acme C 2.0",
                    evidence=["acme magic"],
                    detected_by="plugin",
                )
            return None

        _install_fake_module("detector_fn_test", detect=_detect)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{"rebrew.binary_detectors": [("acme", "detector_fn_test:detect")]}
            ),
        )

    def test_plugin_detects_novel_family(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.toolchain_detect as td

        self._patch(monkeypatch)
        monkeypatch.setattr(td, "_PLUGIN_DETECTORS", td._discover_binary_detectors())
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 64)
        info = td.detect_toolchain(junk)
        assert info.family == "acme-c"
        assert info.detected_by == "plugin-acme"
        assert info.confidence == "high"
        # a binary the packaged backends recognize is untouched by plugins
        monkeypatch.setattr(td, "_PLUGIN_DETECTORS", [])
        assert td.detect_toolchain(junk).family == "unknown"

    def test_non_callable_detector_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.toolchain_detect as td

        _install_fake_module("detector_fn_bad", detect="not-callable")
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.binary_detectors": [("bad", "detector_fn_bad:detect")]}),
        )
        assert td._discover_binary_detectors() == []


class TestSixteenBitAlignment:
    """A bits=16 plugin toolchain joins the arch-alignment set."""

    def test_bits16_plugin_allowed_on_x86_16(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.toolchain as toolchain
        import rebrew.toolchain_detect as td

        overlay = tmp_path / "overlay"
        overlay.mkdir()
        (overlay / "mytc16.toml").write_text(
            '[mytc16]\nbinary = "acme"\nbits = 16\n', encoding="utf-8"
        )
        monkeypatch.setenv("REBREW_TOOLCHAIN_OVERLAY_DIR", str(overlay))
        monkeypatch.setattr(toolchain, "TOOLCHAINS", toolchain.build_toolchain_registry())

        assert "mytc16" in td._bitness16_profiles()
        assert "tc16" in td._bitness16_profiles()  # packaged set intact

        compat = dict(td._PROFILE_COMPAT_ALL)
        compat.setdefault("acme-c", set()).add("mytc16")
        monkeypatch.setattr(td, "_PROFILE_COMPAT_ALL", compat)

        info16 = td.ToolchainInfo(family="acme-c", arch="x86_16")
        aligned, _ = td.profile_matches_detection("mytc16", info16)
        assert aligned

    def test_bits16_plugin_rejected_on_32bit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.toolchain as toolchain
        import rebrew.toolchain_detect as td

        overlay = tmp_path / "overlay"
        overlay.mkdir()
        (overlay / "mytc16.toml").write_text(
            '[mytc16]\nbinary = "acme"\nbits = 16\n', encoding="utf-8"
        )
        monkeypatch.setenv("REBREW_TOOLCHAIN_OVERLAY_DIR", str(overlay))
        monkeypatch.setattr(toolchain, "TOOLCHAINS", toolchain.build_toolchain_registry())

        info32 = td.ToolchainInfo(
            family="msvc", arch="x86_32", msvc_version="6.0", suggested_profiles=None
        )
        aligned, _ = td.profile_matches_detection("mytc16", info32)
        assert not aligned


class TestMsvcVersionRegistry:
    def _patch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _provider() -> dict[str, list[str]]:
            return {"build:8168": ["mytc"], "linker:12.0": ["mytc"]}

        _install_fake_module("msvc_ver_provider", provider=_provider)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.msvc_versions": [("p", "msvc_ver_provider:provider")]}),
        )

    def test_plugin_version_entries_merge(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.toolchain_detect as td

        self._patch(monkeypatch)
        rich, eras = td._merged_msvc_version_tables()
        # plugin appended after packaged profiles (packaged order preserved)
        assert "mytc" in rich[8168]
        assert rich[8168][0] == "msvc6"
        assert "mytc" in eras[(12, 0)]
        assert eras[(12, 0)][0] == "msvc6"
        assert rich[3077] == ("msvc710",)  # msvc7 is a deprecated alias of msvc710

    def test_bad_key_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.toolchain_detect as td

        _install_fake_module("msvc_ver_bad", provider=lambda: {"8168": ["mytc"]})
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.msvc_versions": [("p", "msvc_ver_bad:provider")]}),
        )
        rich, eras = td._merged_msvc_version_tables()
        assert rich[8168]  # packaged build table intact

    def test_empty_profiles_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.toolchain_detect as td

        _install_fake_module("msvc_ver_empty", provider=lambda: {"build:8168": []})
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.msvc_versions": [("p", "msvc_ver_empty:provider")]}),
        )
        rich, eras = td._merged_msvc_version_tables()
        assert rich[8168]  # packaged build table intact

    def test_plugin_passes_version_exact_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.toolchain_detect as td

        self._patch(monkeypatch)
        rich, _ = td._merged_msvc_version_tables()
        monkeypatch.setattr(td, "_RICH_BUILD_PROFILES_ALL", rich)
        compat = dict(td._PROFILE_COMPAT_ALL)
        compat["msvc"] = set(compat["msvc"]) | {"mytc"}  # family alignment
        monkeypatch.setattr(td, "_PROFILE_COMPAT_ALL", compat)
        info = td.ToolchainInfo(
            family="msvc", msvc_version="6.0", suggested_profiles=list(rich[8168])
        )
        aligned, _ = td.profile_matches_detection("mytc", info)
        assert aligned


class TestBinaryLoaderRegistry:
    def _patch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.binary_loader import BinaryInfo

        def _load(path: Path, fmt: str) -> BinaryInfo | None:
            if path.name == "junk.bin":
                return BinaryInfo(path=path, format="plugin")
            return None

        _install_fake_module("loader_plugin_test", load=_load)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.binary_loaders": [("plug", "loader_plugin_test:load")]}),
        )

    def test_plugin_loads_unparseable_binary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.binary_loader as bl

        self._patch(monkeypatch)
        monkeypatch.setattr(bl, "_PLUGIN_LOADERS", bl._discover_binary_loaders())
        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 64)
        info = bl.load_binary(junk)
        assert info.format == "plugin"

    def test_no_plugin_loader_still_raises(self, tmp_path: Path) -> None:
        import rebrew.binary_loader as bl

        junk = tmp_path / "junk.bin"
        junk.write_bytes(b"\x00" * 64)
        with pytest.raises(ValueError, match="unknown format"):
            bl.load_binary(junk)

    def test_non_callable_loader_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.binary_loader as bl

        _install_fake_module("loader_plugin_bad", load="nope")
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.binary_loaders": [("bad", "loader_plugin_bad:load")]}),
        )
        assert bl._discover_binary_loaders() == []


class TestPluginHelpPanel:
    def test_discovered_command_in_plugins_panel(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.main

        fresh = typer.Typer()
        monkeypatch.setattr(rebrew.main, "app", fresh)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.commands": [("diagtest", "rebrew.diagnose")]}),
        )
        rebrew.main._register_discovered_commands()
        cmd = next(c for c in fresh.registered_commands if c.name == "diagtest")
        assert cmd.rich_help_panel == "Plugins"


class TestCacheBackendRegistry:
    """The compile-cache store is a pluggable component (rebrew.cache_backends)."""

    class _MemoryBackend:
        """A trivial in-memory CacheBackend for tests."""

        def __init__(self, cache_dir: Path, size_limit: int = 0) -> None:
            self.hits = 0
            self.misses = 0
            self._store: dict[str, bytes] = {}

        def get(self, key: str) -> bytes | None:
            if key in self._store:
                self.hits += 1
                return self._store[key]
            self.misses += 1
            return None

        def put(self, key: str, obj_bytes: bytes) -> None:
            self._store[key] = obj_bytes

        @property
        def volume(self) -> int:
            return sum(len(v) for v in self._store.values())

        @property
        def count(self) -> int:
            return len(self._store)

        def clear(self) -> None:
            self._store.clear()

        def close(self) -> None:
            return None

        def stats(self) -> dict[str, int | float]:
            return {"entries": self.count, "volume_mb": 0.0, "size_limit_mb": 0}

    def _patch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _factory(
            cache_dir: Path, size_limit: int = 0
        ) -> TestCacheBackendRegistry._MemoryBackend:
            return self._MemoryBackend(cache_dir, size_limit)

        _install_fake_module("cache_backend_test", factory=_factory)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{"rebrew.cache_backends": [("mem", "cache_backend_test:factory")]}
            ),
        )

    def test_plugin_backend_discovered(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.compile_cache as cc

        self._patch(monkeypatch)
        backends = cc._discover_cache_backends()
        assert "mem" in backends
        assert "diskcache" in backends  # packaged default intact
        monkeypatch.setattr(cc, "_CACHE_BACKENDS", backends)
        cache = cc.get_compile_cache(Path("/tmp"), "mem")
        cache.put("k", b"obj")
        assert cache.get("k") == b"obj"
        assert cache.count == 1

    def test_plugin_conflict_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.compile_cache as cc

        _install_fake_module("cache_backend_dup", factory=lambda *a, **k: None)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{"rebrew.cache_backends": [("diskcache", "cache_backend_dup:factory")]}
            ),
        )
        backends = cc._discover_cache_backends()
        assert backends["diskcache"] is cc.CompileCache  # packaged backend survives

    def test_unknown_backend_errors(self, tmp_path: Path) -> None:
        import rebrew.compile_cache as cc

        with pytest.raises(ValueError, match="unknown cache backend"):
            cc.get_compile_cache(tmp_path, "nope")

    def test_config_selects_backend(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.compile_cache as cc
        from rebrew.config import load_config

        self._patch(monkeypatch)
        monkeypatch.setattr(cc, "_CACHE_BACKENDS", cc._discover_cache_backends())
        (tmp_path / "rebrew-project.toml").write_text(
            f'[project]\nroot = "{tmp_path}"\ndefault_target = "T"\n'
            f'[targets.T]\nbinary = "{tmp_path}/t.exe"\n[cache]\nbackend = "mem"\n',
            encoding="utf-8",
        )
        cfg = load_config(root=tmp_path)
        assert cfg.cache_backend == "mem"
        cache = cc.get_compile_cache(tmp_path, cfg.cache_backend)
        assert type(cache).__name__ == "_MemoryBackend"


class TestToolchainOrigin:
    """list_toolchains reports where each toolchain came from."""

    def test_origins_recorded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.toolchain as toolchain

        overlay = tmp_path / "overlay"
        overlay.mkdir()
        (overlay / "mytc.toml").write_text('[mytc]\nbinary = "mycc"\n', encoding="utf-8")
        monkeypatch.setenv("REBREW_TOOLCHAIN_OVERLAY_DIR", str(overlay))
        monkeypatch.setattr(toolchain, "TOOLCHAINS", toolchain.build_toolchain_registry())
        assert toolchain.TOOLCHAIN_ORIGINS["msvc6"] == "packaged"
        assert toolchain.TOOLCHAIN_ORIGINS["mytc"] == f"data-file {overlay / 'mytc.toml'}"
        rows = {r["name"]: r for r in toolchain.list_toolchains()}
        assert rows["mytc"]["origin"] == f"data-file {overlay / 'mytc.toml'}"
        assert rows["msvc6"]["origin"] == "packaged"


class TestDoctorCacheCheck:
    def test_valid_backend_passes(self) -> None:
        from rebrew.doctor import check_cache_backend

        result = check_cache_backend(SimpleNamespace(cache_backend="diskcache"))
        assert result.status == "pass"

    def test_unknown_backend_fails(self) -> None:
        from rebrew.doctor import check_cache_backend

        result = check_cache_backend(SimpleNamespace(cache_backend="nope"))
        assert result.status == "fail"
        assert "not a registered backend" in result.message


class TestInitSkillsOverlay:
    def test_init_renders_user_skills(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew import init
        from rebrew.skills import REBREW_SKILLS_DIR_ENV

        user = tmp_path / "user-skills"
        (user / "my-skill").mkdir(parents=True)
        (user / "my-skill" / "SKILL.md").write_text(
            "---\nname: my-skill\ndescription: Community skill.\n---\n# For <target>\n",
            encoding="utf-8",
        )
        monkeypatch.setenv(REBREW_SKILLS_DIR_ENV, str(user))
        dest = tmp_path / "proj"
        dest.mkdir()
        init._copy_agent_skills(dest, "BENCH")
        rendered = dest / ".agents" / "skills" / "my-skill" / "SKILL.md"
        assert rendered.is_file()
        assert "<target>" not in rendered.read_text(encoding="utf-8")  # substituted
        # packaged skills still rendered
        assert (dest / ".agents" / "skills" / "rebrew-workflow" / "SKILL.md").is_file()

    def test_init_user_skill_overrides_packaged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew import init
        from rebrew.skills import REBREW_SKILLS_DIR_ENV

        user = tmp_path / "user-skills"
        (user / "override").mkdir(parents=True)
        (user / "override" / "SKILL.md").write_text(
            "---\nname: rebrew-workflow\ndescription: Override.\n---\n# overridden <target>\n",
            encoding="utf-8",
        )
        monkeypatch.setenv(REBREW_SKILLS_DIR_ENV, str(user))
        dest = tmp_path / "proj"
        dest.mkdir()
        init._copy_agent_skills(dest, "BENCH")
        rendered = dest / ".agents" / "skills" / "rebrew-workflow" / "SKILL.md"
        assert "overridden" in rendered.read_text(encoding="utf-8")


class TestRealEntryPointMetadata:
    """Discovery through real importlib.metadata dist-info — no monkeypatch.

    The rest of the suite fakes ``entry_points()``; this test builds an
    installed-style distribution (a ``*.dist-info`` dir with an
    ``entry_points.txt`` + a module on sys.path) and exercises the actual
    discovery path, proving the mechanism works against real metadata."""

    def test_mutation_discovered_via_real_dist_info(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        dist = tmp_path / "rebrew_plugin_demo-0.1.dist-info"
        dist.mkdir(parents=True)
        (dist / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: rebrew-plugin-demo\nVersion: 0.1\n",
            encoding="utf-8",
        )
        (dist / "entry_points.txt").write_text(
            "[rebrew.mutations]\nmut_demo = rebrew_plugin_demo:mut_demo\n",
            encoding="utf-8",
        )
        (tmp_path / "rebrew_plugin_demo.py").write_text(
            "def mut_demo(s, rng):\n    return None\n",
            encoding="utf-8",
        )
        monkeypatch.syspath_prepend(str(tmp_path))

        from rebrew.matcher.mutator import _merge_entry_point_mutations

        merged = _merge_entry_point_mutations()
        assert any(m.__name__ == "mut_demo" for m in merged)

    def test_command_discovered_via_real_dist_info(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.main

        dist = tmp_path / "rebrew_plugin_cmd-0.1.dist-info"
        dist.mkdir(parents=True)
        (dist / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: rebrew-plugin-cmd\nVersion: 0.1\n",
            encoding="utf-8",
        )
        (dist / "entry_points.txt").write_text(
            "[rebrew.commands]\ndemo-cmd = rebrew.diagnose\n",
            encoding="utf-8",
        )
        monkeypatch.syspath_prepend(str(tmp_path))

        fresh = typer.Typer()
        monkeypatch.setattr(rebrew.main, "app", fresh)
        rebrew.main._register_discovered_commands()
        assert "demo-cmd" in [c.name for c in fresh.registered_commands]


class TestLegacyProfileAliases:
    """msvc6.3/msvc6.6 migrate to their modern registry names at config load."""

    @pytest.mark.parametrize(
        ("legacy", "modern"),
        [("msvc6.3", "msvc600sp3"), ("msvc6.6", "msvc600sp6")],
    )
    def test_legacy_alias_migrates(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, legacy: str, modern: str
    ) -> None:
        import warnings

        from rebrew.config import load_config

        (tmp_path / "rebrew-project.toml").write_text(
            f'[project]\nroot = "{tmp_path}"\ndefault_target = "T"\n'
            f'[targets.T]\nbinary = "{tmp_path}/t.exe"\n'
            f'[compiler]\nprofile = "{legacy}"\n',
            encoding="utf-8",
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cfg = load_config(root=tmp_path)
        assert cfg.compiler_profile == modern

    def test_unknown_profile_still_falls_back(self, tmp_path: Path) -> None:
        import warnings

        from rebrew.config import load_config

        (tmp_path / "rebrew-project.toml").write_text(
            f'[project]\nroot = "{tmp_path}"\ndefault_target = "T"\n'
            f'[targets.T]\nbinary = "{tmp_path}/t.exe"\n'
            f'[compiler]\nprofile = "not-a-real-toolchain"\n',
            encoding="utf-8",
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cfg = load_config(root=tmp_path)
        assert cfg.compiler_profile == "msvc6"


class TestDecompilerAutoProbe:
    """A plugin backend opts into --auto probing via __rebrew_auto_probe__."""

    def _patch(self, monkeypatch: pytest.MonkeyPatch, marked: bool) -> None:
        def _fake_backend(binary: Path, va: int, root: Path, **_kwargs: Any) -> str | None:
            return None

        if marked:
            _fake_backend.__rebrew_auto_probe__ = True  # type: ignore[attr-defined]
        _install_fake_module("backend_auto_test", backend=_fake_backend)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{"rebrew.decompiler_backends": [("auto-dec", "backend_auto_test:backend")]}
            ),
        )

    def test_marked_backend_joins_auto_probe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.decompiler import _merge_entry_point_backends

        self._patch(monkeypatch, marked=True)
        _map, auto = _merge_entry_point_backends()
        assert "auto-dec" in auto
        assert auto[:3] == ("r2ghidra", "r2dec", "kuna")  # curated order first

    def test_unmarked_backend_stays_name_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.decompiler import _merge_entry_point_backends

        self._patch(monkeypatch, marked=False)
        _map, auto = _merge_entry_point_backends()
        assert "auto-dec" not in auto
        assert "auto-dec" in _map  # still selectable by name


class TestEntryPointProvenance:
    """Entry-point toolchains record their provider module in the origin."""

    def test_origin_names_provider_module(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.toolchain as toolchain
        from rebrew.toolchain import ToolchainSpec

        monkeypatch.delenv("REBREW_TOOLCHAIN_OVERLAY_DIR", raising=False)
        _install_fake_module(
            "prov_module_test",
            provider=lambda: {"plugtc": ToolchainSpec(name="plugtc", image=None, binary="pcc")},
        )
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(**{"rebrew.toolchains": [("plugtc", "prov_module_test:provider")]}),
        )
        monkeypatch.setattr(toolchain, "TOOLCHAINS", toolchain.build_toolchain_registry())
        assert toolchain.TOOLCHAIN_ORIGINS["plugtc"] == "entry-point:prov_module_test"


class TestSkillsDirWarning:
    def test_missing_skills_dir_warns_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        from rebrew.skills import REBREW_SKILLS_DIR_ENV, _list_skills

        monkeypatch.setenv(REBREW_SKILLS_DIR_ENV, str(tmp_path / "nope"))
        with caplog.at_level("WARNING", logger="rebrew.skills"):
            _list_skills()
            _list_skills()  # second call must not re-warn
        assert sum("is not a directory" in r.message for r in caplog.records) == 1


class TestNativeElfToolchains:
    """gcc/clang are native PATH specs — an ELF profile must actually compile."""

    def test_gcc_clang_in_registry(self) -> None:
        from rebrew.toolchain import TOOLCHAINS

        for name in ("gcc", "clang"):
            spec = TOOLCHAINS.get(name)
            assert spec is not None
            assert spec.image is None
            assert spec.runtime == "native"
            assert spec.flags_style == "posix"
            assert spec.obj_ext == ".o"

    @pytest.mark.parametrize("profile", ["gcc", "clang"])
    def test_elf_profile_compiles(self, tmp_path: Path, profile: str) -> None:
        import warnings

        from rebrew.compile import compile_to_obj
        from rebrew.config import load_config

        (tmp_path / "rebrew-project.toml").write_text(
            f'[project]\nroot = "{tmp_path}"\ndefault_target = "T"\n'
            f'[targets.T]\nbinary = "{tmp_path}/t.elf"\nformat = "elf"\n'
            f'[compiler]\nprofile = "{profile}"\n',
            encoding="utf-8",
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cfg = load_config(root=tmp_path)
        src = tmp_path / "f.c"
        src.write_text("int f(int a){return a+1;}\n", encoding="utf-8")
        obj, err = compile_to_obj(cfg, src, "", tmp_path, obj_name="f.o")
        assert obj is not None, err


class TestRefreshAll:
    """refresh_all() re-runs discovery and refreshes every registry snapshot."""

    def test_refresh_all_counts(self) -> None:
        from rebrew.registry import refresh_all

        counts = refresh_all()
        assert counts["toolchains"] >= 39
        assert counts["decompiler_backends"] >= 4
        assert counts["mutations"] > 100
        assert counts["cache_backends"] >= 1
        assert counts["library_presets"] >= 5

    def test_refresh_picks_up_installed_plugin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.compile_cache as cc
        from rebrew.registry import refresh_all

        self._patch_plugin(monkeypatch)
        assert "mem2" not in cc._CACHE_BACKENDS
        counts = refresh_all()
        assert counts["cache_backends"] >= 2
        assert "mem2" in cc._CACHE_BACKENDS  # snapshot refreshed in place

    def _patch_plugin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _factory(cache_dir: Path, size_limit: int = 0) -> object:
            return None

        _install_fake_module("cache_backend_refresh", factory=_factory)
        monkeypatch.setattr(
            "rebrew.registry.entry_points",
            _fake_entry_points(
                **{"rebrew.cache_backends": [("mem2", "cache_backend_refresh:factory")]}
            ),
        )


class TestNativeCacheKey:
    """Native specs must key the compile cache by their binary, not the
    config's MSVC compiler_command (gcc vs clang would otherwise collide)."""

    def test_gcc_and_clang_get_distinct_ids(self, tmp_path: Path) -> None:
        import warnings

        from rebrew.compile_cache import compile_cache_key
        from rebrew.config import load_config

        def _id(profile: str) -> str:
            (tmp_path / "rebrew-project.toml").write_text(
                f'[project]\nroot = "{tmp_path}"\ndefault_target = "T"\n'
                f'[targets.T]\nbinary = "{tmp_path}/t.elf"\nformat = "elf"\n'
                f'[compiler]\nprofile = "{profile}"\n',
                encoding="utf-8",
            )
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                cfg = load_config(root=tmp_path)
            from rebrew.toolchain import TOOLCHAINS

            spec = TOOLCHAINS[cfg.compiler_profile]
            return f"native:{spec.binary}"

        k_gcc = compile_cache_key("int f(){}", "f.c", [], [], _id("gcc"))
        k_clang = compile_cache_key("int f(){}", "f.c", [], [], _id("clang"))
        assert k_gcc != k_clang
        assert "wine" not in _id("gcc")  # not the MSVC default


class TestSkillNameSanitization:
    """A skill's frontmatter name must never escape the skills directory."""

    def test_install_sanitizes_traversal_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.skills import REBREW_SKILLS_DIR_ENV, app

        user_dir = tmp_path / "skills"
        user_dir.mkdir()
        monkeypatch.setenv(REBREW_SKILLS_DIR_ENV, str(user_dir))

        evil = tmp_path / "evil"
        evil.mkdir()
        (evil / "SKILL.md").write_text(
            "---\nname: ../../escape\ndescription: malicious.\n---\n# Evil\n",
            encoding="utf-8",
        )
        r = CliRunner().invoke(app, ["install", str(evil), "--json"])
        assert r.exit_code == 0
        assert not (tmp_path / "escape").exists()  # nothing escaped the overlay
        assert (user_dir / "..-..-escape").is_dir()  # folded into the dir

    def test_safe_name_helper(self) -> None:
        from rebrew.skills import _safe_skill_name

        assert _safe_skill_name("../../evil") == "..-..-evil"
        assert _safe_skill_name("/abs/path") == "abs-path"
        assert _safe_skill_name("rebrew-workflow") == "rebrew-workflow"
        assert _safe_skill_name("!!!") == ""


class TestFlagDataSyncPreservation:
    """A sync run must not wipe the hand-maintained flag families."""

    def test_splice_preserves_tail(self, tmp_path: Path) -> None:
        from tools.sync_decomp_flags import splice_preserved_tail

        generated = '"""Auto-generated..."""\n\nCOMMON_MSVC_FLAGS = []\n'
        existing = (
            '"""Auto-generated..."""\nCOMMON_MSVC_FLAGS = []\n'
            "# --- Hand-maintained flag families below ---\n"
            "WATCOM_FLAGS = []\nGCC_FLAGS = []\n"
        )
        p = tmp_path / "flag_data.py"
        p.write_text(existing, encoding="utf-8")
        out = splice_preserved_tail(generated, p)
        assert "WATCOM_FLAGS" in out and "GCC_FLAGS" in out
        assert "COMMON_MSVC_FLAGS = []" in out

    def test_splice_no_existing_file(self, tmp_path: Path) -> None:
        from tools.sync_decomp_flags import splice_preserved_tail

        generated = '"""gen"""\n'
        out = splice_preserved_tail(generated, tmp_path / "missing.py")
        assert out == generated
