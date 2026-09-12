"""Tests for rebrew.match — the --sweep-toolchain toolchain-version sweep."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from rebrew.match_sweep import _run_single_toolchain_sweep


class _FakeRes:
    def __init__(self, obj: bytes):
        self.ok = True
        self.obj_bytes = obj
        self.reloc_offsets = []


def _make_params() -> SimpleNamespace:
    return SimpleNamespace(
        cfg=SimpleNamespace(compiler_profile="msvc-6.0", compile_timeout=60),
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
    """The sweep's MSVC list covers the full image-backed registry line
    (every msvc profile with a cl image) — the detector can suggest any of
    these profiles, so the sweep must be able to try each."""
    from rebrew.match_sweep import _vendored_msvc_toolchains

    toolchains = _vendored_msvc_toolchains(SimpleNamespace(compiler_profile="msvc-6.0"))
    profiles = [p for p, _cl, _inc in toolchains]
    assert "msvc-4.0" in profiles
    assert "msvc-4.2" in profiles
    assert "msvc-6.0" in profiles
    assert "msvc-6.0-sp6" in profiles
    assert "msvc-1.52" not in profiles  # 16-bit DOSBox, not a cl sweep target
    assert profiles[0] == "msvc-6.0"  # configured profile first
    # docker-only: the cl_cmd/inc_dir are inert for image-backed profiles
    assert all(cl == "" and inc == "" for _p, cl, inc in toolchains[1:])


def test_sweep_filter_matches() -> None:
    """Filter semantics: exact profile, profile prefix, version substring,
    arch substring."""
    from rebrew.match_sweep import _sweep_filter_matches

    assert _sweep_filter_matches("msvc-6.0-sp6", "6.0-sp6-win32", ["msvc-6.0-sp6"])
    assert _sweep_filter_matches("msvc-2.0", "2.0-win32", ["msvc-2"])  # prefix
    assert _sweep_filter_matches("msvc-6.0-sp1", "6.0-sp1-win32", ["6.0"])
    assert _sweep_filter_matches("msvc-1.52", "1.52-win16", ["win16"])
    assert _sweep_filter_matches("msvc-6.0", "6.0-win32", ["6.0"])
    assert not _sweep_filter_matches("msvc-10.0", "10.0-win32", ["msvc-2"])
    assert not _sweep_filter_matches("msvc-4.0", "4.0-win32", ["5.0"])


def test_vendored_enumeration_respects_only_exclude() -> None:
    """--sweep-toolchains / --sweep-exclude-toolchains narrow the registry enumeration."""
    from rebrew.match_sweep import _vendored_msvc_toolchains

    all_ = _vendored_msvc_toolchains(SimpleNamespace(compiler_profile="msvc-6.0"))
    profiles = [p for p, _cl, _inc in all_]
    assert "msvc-2.0" in profiles and "msvc-10.0" in profiles

    only = _vendored_msvc_toolchains(SimpleNamespace(compiler_profile="msvc-6.0"), only="6.0")
    only_p = [p for p, _cl, _inc in only]
    assert "msvc-6.0" in only_p and "msvc-6.0-sp6" in only_p
    assert "msvc-2.0" not in only_p and "msvc-10.0" not in only_p

    excl = _vendored_msvc_toolchains(
        SimpleNamespace(compiler_profile="msvc-6.0"), exclude="2.0,4.0"
    )
    excl_p = [p for p, _cl, _inc in excl]
    assert "msvc-2.0" not in excl_p and "msvc-4.0" not in excl_p
    assert "msvc-6.0" in excl_p

    # the configured profile is the baseline when it survives the filters,
    # and is never listed twice
    only_sp6 = _vendored_msvc_toolchains(
        SimpleNamespace(compiler_profile="msvc-6.0-sp6"), only="6.0-sp6"
    )
    assert only_sp6[0][0] == "msvc-6.0-sp6"

    # "--sweep-toolchains 4.0" means ONLY 4.0: the configured msvc-6.0 baseline
    # must not be swept anyway (help: "Sweep only these toolchains").
    only_400 = _vendored_msvc_toolchains(SimpleNamespace(compiler_profile="msvc-6.0"), only="4.0")
    only_400_p = [p for p, _cl, _inc in only_400]
    assert only_400_p and all(p.startswith("msvc-4") for p in only_400_p), only_400_p

    # No duplicates: the unfiltered enumeration includes the configured
    # profile once, not once from the loop plus once as the baseline.
    assert len(profiles) == len(set(profiles))


def test_toolchain_sweep_orders_best_first(monkeypatch, capsys) -> None:
    # Two vendored toolchains: "good" compiles byte-identical, "bad" does not.
    good = b"\x55\x8b\xec\x5d\xc3"
    bad = b"\x90\x90\x90\x90\x90"
    monkeypatch.setattr(
        "rebrew.match_sweep._vendored_msvc_toolchains",
        lambda cfg, cl, inc, *a, **k: [("good", "wine good", "/good"), ("bad", "wine bad", "/bad")],
    )
    monkeypatch.setattr("rebrew.coff_reloc.build_name_to_va", lambda cfg: {"_f": 0x1000})
    calls: dict[str, bytes] = {}

    def _fake_build(src, cl_cmd, inc_dir, cflags, symbol, **kw):
        calls[cl_cmd] = good if "good" in cl_cmd else bad
        return _FakeRes(calls[cl_cmd])

    monkeypatch.setattr("rebrew.match_sweep.build_candidate_obj_only", _fake_build)
    monkeypatch.setattr(
        "rebrew.match_sweep.score_candidate",
        lambda t, obj, rel, **kw: SimpleNamespace(total=0.0 if obj == good else 50.0),
    )
    monkeypatch.setattr(
        "rebrew.match_sweep.smart_reloc_compare",
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
    """--flag-sweep-toolchains --flag-sweep-only combines both dimensions: each
    toolchain gets its own flag sweep and the best flags are reported."""
    import json

    from rebrew.match_sweep import _run_single_toolchain_flag_sweep

    monkeypatch.setattr(
        "rebrew.match_sweep._vendored_msvc_toolchains",
        lambda cfg, cl, inc, *a, **k: [("good", "wine good", "/good"), ("bad", "wine bad", "/bad")],
    )

    def _fake_flag_sweep(src, target, cl_cmd, inc_dir, cflags, symbol, jobs, tier=None, **kw):
        if "good" in cl_cmd:
            return [(0.0, "/O1")]
        return [(42.0, "")]

    monkeypatch.setattr("rebrew.match_sweep.flag_sweep", _fake_flag_sweep)

    _run_single_toolchain_flag_sweep(_make_params(), tier="quick", jobs=2, json_output=True)
    out = json.loads(capsys.readouterr().out)
    assert out["sweep"] == "toolchain+flags"
    assert out["best"] == "good"
    by_name = {r["toolchain"]: r for r in out["results"]}
    assert by_name["good"]["exact"] is True
    assert by_name["good"]["flags"] == "/O1"
    assert by_name["bad"]["exact"] is False
    assert by_name["bad"]["best_score"] == 42.0


def test_flag_combos_msvc_line_share_msvc_6_0_flags() -> None:
    """msvc-4.0/msvc-4.2/msvc-5.0/6.3/6.6 all fall back to the msvc-6.0 flag set in
    the sweep (they are MSVC-style compilers) — a future profile-specific
    flag set must not silently diverge the sweep for the expanded line."""
    from rebrew.matcher.compiler import generate_flag_combinations

    base = generate_flag_combinations(tier="quick", profile="msvc-6.0")
    for prof in ("msvc-4.0", "msvc-4.2", "msvc-5.0", "msvc-6.0-sp3", "msvc-6.0-sp6", "msvc-7.0"):
        combos = generate_flag_combinations(tier="quick", profile=prof)
        assert combos == base, prof
        nonempty = [c for c in combos if c]
        assert nonempty and all("/" in c for c in nonempty), prof  # MSVC-style
