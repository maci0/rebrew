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
        lambda obj, tgt, rel, name_to_va=None, section_va=None: (
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
