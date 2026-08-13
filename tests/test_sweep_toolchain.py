"""Tests for rebrew.match — the --sweep-toolchain toolchain-version sweep."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from rebrew.match import _run_single_toolchain_sweep


class _FakeRes:
    def __init__(self, obj: bytes):
        self.ok = True
        self.obj_bytes = obj
        self.reloc_offsets = []


def _make_params() -> SimpleNamespace:
    return SimpleNamespace(
        cfg=SimpleNamespace(compiler_profile="msvc6", compile_timeout=60),
        seed_c=Path("seed.c"),
        seed_src="int f(void){return 1;}",
        cl="wine cl",
        inc="/inc",
        cflags="/O1",
        symbol="_f",
        target_bytes=b"\x55\x8b\xec\x5d\xc3",
        va_int=0x401000,
        target_size=5,
        msvc_env={},
        cc=None,
    )


def test_vendored_enumeration_includes_msvc400() -> None:
    """The sweep's MSVC version list covers the full vendored 4.0→7.0 line,
    including the now-vendored 4.0 (uppercase BIN/INCLUDE layout) — the
    detector can suggest any of these profiles, so the sweep must be able
    to try each."""
    from rebrew.match import _MSVC_TOOLCHAIN_PATHS

    profiles = [p for p, _cl, _inc in _MSVC_TOOLCHAIN_PATHS]
    assert "msvc-4.0-win32" in profiles
    assert "msvc-4.2-win32" in profiles
    assert "msvc-5.0-win32" in profiles
    # 4.0's tree is all-caps (BIN/INCLUDE) — the sweep path must match it.
    cl = next(cl for p, cl, _i in _MSVC_TOOLCHAIN_PATHS if p == "msvc-4.0-win32")
    assert "4.0-win32/BIN/CL.EXE" in cl
    inc = next(i for p, _c, i in _MSVC_TOOLCHAIN_PATHS if p == "msvc-4.0-win32")
    assert "4.0-win32/INCLUDE" in inc


def test_toolchain_sweep_orders_best_first(monkeypatch, capsys) -> None:
    # Two vendored toolchains: "good" compiles byte-identical, "bad" does not.
    good = b"\x55\x8b\xec\x5d\xc3"
    bad = b"\x90\x90\x90\x90\x90"
    monkeypatch.setattr(
        "rebrew.match._vendored_msvc_toolchains",
        lambda cfg, cl, inc: [("good", "wine good", "/good"), ("bad", "wine bad", "/bad")],
    )
    calls: dict[str, bytes] = {}

    def _fake_build(src, cl_cmd, inc_dir, cflags, symbol, **kw):  # noqa: ARG001
        calls[cl_cmd] = good if "good" in cl_cmd else bad
        return _FakeRes(calls[cl_cmd])

    monkeypatch.setattr("rebrew.match.build_candidate_obj_only", _fake_build)
    monkeypatch.setattr(
        "rebrew.match.score_candidate",
        lambda t, obj, rel: SimpleNamespace(total=0.0 if obj == good else 50.0),
    )
    monkeypatch.setattr(
        "rebrew.match.smart_reloc_compare",
        lambda obj, tgt, rel, name_to_va=None, section_va=None, iat_region=None: (
            obj == tgt,
            len(obj),
            len(tgt),
            [],
            [],
        ),
    )

    _run_single_toolchain_sweep(_make_params(), json_output=True)
    out = json.loads(capsys.readouterr().out)
    assert out["sweep"] == "toolchain"
    assert out["best"] == "good"
    assert out["results"][0]["toolchain"] == "good"
    assert out["results"][0]["matched"] is True
    assert out["results"][1]["toolchain"] == "bad"


def test_toolchain_flag_sweep_reports_per_toolchain(monkeypatch, capsys) -> None:
    """--sweep-toolchain --flag-sweep-only combines both dimensions: each
    toolchain gets its own flag sweep and the best flags are reported."""
    import json

    from rebrew.match import _run_single_toolchain_flag_sweep

    monkeypatch.setattr(
        "rebrew.match._vendored_msvc_toolchains",
        lambda cfg, cl, inc: [("good", "wine good", "/good"), ("bad", "wine bad", "/bad")],
    )

    def _fake_flag_sweep(src, target, cl_cmd, inc_dir, cflags, symbol, jobs, tier=None, **kw):  # noqa: ARG001
        if "good" in cl_cmd:
            return [(0.0, "/O1")]
        return [(42.0, "")]

    monkeypatch.setattr("rebrew.match.flag_sweep", _fake_flag_sweep)

    _run_single_toolchain_flag_sweep(_make_params(), tier="quick", jobs=2, json_output=True)
    out = json.loads(capsys.readouterr().out)
    assert out["sweep"] == "toolchain+flags"
    assert out["best"] == "good"
    by_name = {r["toolchain"]: r for r in out["results"]}
    assert by_name["good"]["exact"] is True
    assert by_name["good"]["flags"] == "/O1"
    assert by_name["bad"]["exact"] is False
    assert by_name["bad"]["best_score"] == 42.0


def test_flag_combos_msvc_line_share_msvc6_flags() -> None:
    """msvc400/msvc420/msvc5/6.3/6.6 all fall back to the msvc6 flag set in
    the sweep (they are MSVC-style compilers) — a future profile-specific
    flag set must not silently diverge the sweep for the expanded line."""
    from rebrew.matcher.compiler import generate_flag_combinations

    base = generate_flag_combinations(tier="quick", profile="msvc6")
    for prof in ("msvc400", "msvc420", "msvc5", "msvc6.3", "msvc6.6", "msvc7"):
        combos = generate_flag_combinations(tier="quick", profile=prof)
        assert combos == base, prof
        nonempty = [c for c in combos if c]
        assert nonempty and all("/" in c for c in nonempty), prof  # MSVC-style
