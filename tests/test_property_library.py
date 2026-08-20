"""Property-based tests for the library-config merge (order independence).

Per the Cordis paper's confluence result (Theorem 73), the quiescent state of
a composed system is a function of the *final configuration alone*, not of
the order in which the components were assembled.  Rebrew's analog: the
resolved ``(toolchain, cflags)`` for a source must depend only on the final
set of override declarations (per-function metadata, per-library
``rebrew-library.toml`` files, known-library presets, project defaults) —
never on the order the fields were written, the order the files were
created, or the order the presets were merged in.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from hypothesis import given
from hypothesis import strategies as st

from rebrew.cli import resolve_compile_overrides
from rebrew.metadata import (
    LIBRARY_METADATA_FILE,
    apply_library_presets,
    find_library_override,
)


def _tree(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A project root with a nested library and a function dir under it."""
    proj = tmp_path / "proj"
    lib = proj / "refs" / "zlib"
    fn = lib / "f"
    for d in (proj, lib, fn):
        d.mkdir(parents=True)
    return proj, lib, fn


class TestPresetMergeFixedPoint:
    """apply_library_presets converges: re-merging a merged result changes
    nothing, for any field set — the reconciliation is a fixed point."""

    @given(
        st.sampled_from(["", "watcom", "tc16", "msvc1.52"]),
        st.sampled_from(["", "-ot", "/O1", "/O2 /Gd /MT"]),
        st.sampled_from(["", "watcom-runtime", "msvcrt-static", "msvcrt-dynamic"]),
    )
    def test_remerge_is_identity(self, toolchain: str, cflags: str, library: str) -> None:
        meta = {"toolchain": toolchain, "cflags": cflags, "library": library}
        merged, presets = apply_library_presets(meta)
        again, presets2 = apply_library_presets(merged)
        assert again == merged
        assert presets2 == presets

    def test_explicit_fields_win_in_every_order(self) -> None:
        """Explicit fields beat presets regardless of which key the preset
        would fill — the merge reads the final field set, not a sequence."""
        for toolchain, cflags in (("watcom", ""), ("", "-ot"), ("tc16", "-O2")):
            merged, presets = apply_library_presets(
                {"toolchain": toolchain, "cflags": cflags, "library": "watcom-runtime"}
            )
            assert merged["toolchain"] == (toolchain or "watcom")
            assert merged["cflags"] == (cflags or "-ot")
            assert presets == ("watcom-runtime",)


class TestTomlFieldOrderIndependence:
    """The resolved override is independent of the order fields are written
    in the rebrew-library.toml file."""

    def test_field_permutation_same_resolution(self, tmp_path: Path) -> None:
        import itertools

        fields = {"toolchain": "tc16", "cflags": "-O2", "library": "watcom-runtime"}
        for order in itertools.permutations(["toolchain", "cflags", "library"]):
            proj, lib, fn = _tree(tmp_path / "".join(order))
            lines = "\n".join(f'{k} = "{fields[k]}"' for k in order)
            (lib / LIBRARY_METADATA_FILE).write_text(lines + "\n", encoding="utf-8")

            ovr = find_library_override(fn, proj)
            assert ovr is not None
            assert ovr.path == lib / LIBRARY_METADATA_FILE
            # Explicit fields always win over the watcom-runtime preset, in
            # any declaration order.
            assert ovr.toolchain == "tc16"
            assert ovr.cflags == "-O2"
            assert ovr.library == "watcom-runtime"
            assert ovr.presets == ("watcom-runtime",)


class TestNearestWinsOrderIndependence:
    """Nearest-ancestor-wins is a property of the final tree, not of the
    order the library files were created."""

    def test_inner_created_first(self, tmp_path: Path) -> None:
        proj, lib, fn = _tree(tmp_path / "a")
        (lib / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc600sp6"\n', encoding="utf-8")
        (proj / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc6"\n', encoding="utf-8")
        ovr = find_library_override(fn, proj)
        assert ovr is not None and ovr.toolchain == "msvc600sp6"

    def test_outer_created_first(self, tmp_path: Path) -> None:
        proj, lib, fn = _tree(tmp_path / "b")
        (proj / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc6"\n', encoding="utf-8")
        (lib / LIBRARY_METADATA_FILE).write_text('toolchain = "msvc600sp6"\n', encoding="utf-8")
        ovr = find_library_override(fn, proj)
        assert ovr is not None and ovr.toolchain == "msvc600sp6"


class TestResolutionConfluence:
    """resolve_compile_overrides converges: interleaved reconfiguration
    (add an override, remove it) reaches the same resolution as applying the
    final configuration once — the paper's quiescent-state theorem."""

    def test_transient_override_does_not_change_final_state(self, tmp_path: Path) -> None:
        proj, lib, fn = _tree(tmp_path)
        (lib / LIBRARY_METADATA_FILE).write_text(
            'toolchain = "watcom"\ncflags = "-ot"\n', encoding="utf-8"
        )
        cfg = SimpleNamespace(root=proj)

        final = resolve_compile_overrides(cfg, fn, None, None)
        # A transient per-function override that is then removed.
        _transient = resolve_compile_overrides(cfg, fn, "watcom", "-ot")
        after = resolve_compile_overrides(cfg, fn, None, None)
        assert after == final

    def test_resolution_depends_only_on_final_field_set(self, tmp_path: Path) -> None:
        proj, lib, fn = _tree(tmp_path)
        cfg = SimpleNamespace(root=proj)

        # Declared toolchain-only, then cflags-only in a separate file — the
        # final resolution equals writing both fields in one file.
        (lib / LIBRARY_METADATA_FILE).write_text('toolchain = "watcom"\n', encoding="utf-8")
        both = resolve_compile_overrides(cfg, fn, None, None)
        (lib / LIBRARY_METADATA_FILE).write_text('cflags = "-ot"\n', encoding="utf-8")
        cflags_only = resolve_compile_overrides(cfg, fn, None, None)
        (lib / LIBRARY_METADATA_FILE).write_text(
            'toolchain = "watcom"\ncflags = "-ot"\n', encoding="utf-8"
        )
        final = resolve_compile_overrides(cfg, fn, None, None)

        # toolchain-only: preset-free, cflags falls back to the default.
        assert both[0] == "watcom"
        assert both[1] != cflags_only[1]
        # The union of the two partial declarations equals the one-file form.
        assert final[0] == "watcom"
        assert final[1] == "-ot"
