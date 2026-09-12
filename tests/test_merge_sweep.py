"""Tests for :mod:`rebrew.merge_sweep` -- TU-partition search.

The search itself runs through :func:`search_partitions` with a stub scorer,
so merge/split acceptance, tie-breaks, determinism, memoization, and the
compile cap are explicit without a compiler.  The CLI layer is covered via
``--dry-run`` (no binary needed beyond config) and ``--audit`` with the
compile path stubbed out.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from typer.testing import CliRunner

from rebrew.merge_sweep import (
    _apply_merge,
    _apply_split,
    _merge_candidates,
    _partition_key,
    _rank_key,
    _split_candidates,
    app,
    search_partitions,
)

runner = CliRunner()

A = 0x10001000
B = 0x10002000
C = 0x10003000
D = 0x10004000


def _score_of(values: dict[tuple[tuple[int, ...], ...], int], cost: int = 1) -> Any:
    def score(partition: list[list[int]]) -> tuple[int, int]:
        return values[_partition_key(partition)], cost

    return score


class TestPartitionKey:
    def test_order_insensitive_within_cluster(self) -> None:
        assert _partition_key([[B, A]]) == _partition_key([[A, B]])

    def test_cluster_order_matters(self) -> None:
        assert _partition_key([[A], [B]]) != _partition_key([[B], [A]])


class TestMergeCandidates:
    def test_call_edge_qualifies_pair(self) -> None:
        part = [[A], [B]]
        cands = _merge_candidates(part, {A: {B}}, {})
        assert [(left, right, reason) for left, right, reason in cands] == [(0, 1, "call")]

    def test_reverse_call_edge_qualifies_pair(self) -> None:
        assert _merge_candidates([[A], [B]], {B: {A}}, {}) != []

    def test_shared_string_qualifies_pair(self) -> None:
        cands = _merge_candidates([[A], [B]], {}, {A: {0x2000}, B: {0x2000}})
        assert [c[2] for c in cands] == ["string"]

    def test_both_reasons_combine(self) -> None:
        cands = _merge_candidates([[A], [B]], {A: {B}}, {A: {0x2000}, B: {0x2000}})
        assert [c[2] for c in cands] == ["call+string"]

    def test_unrelated_pair_has_no_candidate(self) -> None:
        assert _merge_candidates([[A], [B]], {}, {}) == []

    def test_only_adjacent_pairs_considered(self) -> None:
        part = [[A], [B], [C]]
        cands = _merge_candidates(part, {A: {C}}, {})
        assert cands == []


class TestSplitCandidates:
    def test_large_gap_splits(self) -> None:
        part = [[A, B]]
        assert _split_candidates(part, {(A, B): "large_nonpadding"}) == [(0, 1)]

    def test_padding_gap_does_not_split(self) -> None:
        assert _split_candidates([[A, B]], {(A, B): "padding"}) == []
        assert _split_candidates([[A, B]], {(A, B): "small_nonpadding"}) == []

    def test_split_positions_are_ordered(self) -> None:
        part = [[A, B, C]]
        gaps = {(A, B): "large_nonpadding", (B, C): "large_nonpadding"}
        assert _split_candidates(part, gaps) == [(0, 1), (0, 2)]


class TestApply:
    def test_merge_joins_and_sorts(self) -> None:
        assert _apply_merge([[B], [A], [C]], 0, 1) == [[A, B], [C]]

    def test_split_divides_cluster(self) -> None:
        assert _apply_split([[A, B, C]], 0, 2) == [[A, B], [C]]


class TestRankKey:
    def test_higher_score_ranks_first(self) -> None:
        assert _rank_key([[A, B]], 10) > _rank_key([[A], [B]], 9)

    def test_tie_prefers_fewer_clusters(self) -> None:
        assert _rank_key([[A, B]], 9) > _rank_key([[A], [B]], 9)

    def test_tie_on_count_prefers_lower_va(self) -> None:
        assert _rank_key([[A], [B]], 9) > _rank_key([[B], [C]], 9)


class TestSearchPartitions:
    def test_merge_accepted_on_improvement(self) -> None:
        initial = [[A], [B]]
        values = {
            ((A,), (B,)): 10,
            ((A, B),): 14,
        }
        final, best, moves, compiles = search_partitions(
            initial, _score_of(values), {A: {B}}, {}, {}
        )
        assert final == [[A, B]]
        assert best == 14
        assert len(moves) == 1
        assert moves[0]["kind"] == "merge"
        assert moves[0]["reason"] == "call"

    def test_merge_rejected_without_improvement(self) -> None:
        initial = [[A], [B]]
        values = {((A,), (B,)): 10, ((A, B),): 9}
        final, best, moves, _ = search_partitions(initial, _score_of(values), {A: {B}}, {}, {})
        assert final == [[A], [B]]
        assert best == 10
        assert moves == []

    def test_split_accepted_on_tie(self) -> None:
        initial = [[A, B]]
        values = {((A, B),): 10, ((A,), (B,)): 10}
        final, best, moves, _ = search_partitions(
            initial, _score_of(values), {}, {}, {(A, B): "large_nonpadding"}
        )
        assert final == [[A], [B]]
        assert best == 10
        assert [m["kind"] for m in moves] == ["split"]

    def test_merge_then_split_to_fixpoint(self) -> None:
        initial = [[A], [B, C]]
        values = {
            ((A,), (B, C)): 10,
            ((A, B, C),): 12,
            ((A, B), (C,)): 15,
        }
        final, best, moves, _ = search_partitions(
            initial,
            _score_of(values),
            {A: {B}},
            {},
            {(B, C): "large_nonpadding", (A, B): "padding"},
        )
        assert final == [[A, B], [C]]
        assert best == 15
        assert [m["kind"] for m in moves] == ["merge", "split"]

    def test_memoizes_scores_per_partition_key(self) -> None:
        initial = [[A], [B]]
        calls = 0

        def score(partition: list[list[int]]) -> tuple[int, int]:
            nonlocal calls
            calls += 1
            return (10 if len(partition) == 2 else 9), 1

        _, _, _, _ = search_partitions(initial, score, {A: {B}}, {}, {})
        # initial + merged candidate; a revisit would add more calls
        assert calls == 2

    def test_budget_counts_real_invocations(self) -> None:
        """The cap charges compiler invocations, not partitions scored."""
        initial = [[A], [B]]

        def pricey(partition: list[list[int]]) -> tuple[int, int]:
            return 10, 3  # one partition costs 3 compiler runs

        _, _, _, compiles = search_partitions(initial, pricey, {A: {B}}, {}, {}, max_compiles=4)
        # initial (3) fits; the merged candidate (+3 = 6) exceeds 4
        assert compiles == 6

    def test_max_compiles_caps_search(self) -> None:
        initial = [[A], [B], [C]]
        values = {
            ((A,), (B,), (C,)): 10,
            ((A, B), (C,)): 11,
            ((A,), (B, C)): 12,
        }
        _, _, moves, compiles = search_partitions(
            initial, _score_of(values), {A: {B}, B: {C}}, {}, {}, max_compiles=2
        )
        # initial + first candidate fit the cap; scoring the second
        # candidate aborts the search before any move is accepted.
        assert compiles == 3  # attempted invocations, including the aborting one
        assert moves == []

    def test_on_accept_receives_every_move(self) -> None:
        initial = [[A], [B]]
        values = {((A,), (B,)): 10, ((A, B),): 14}
        seen: list[dict[str, Any]] = []
        search_partitions(initial, _score_of(values), {A: {B}}, {}, {}, on_accept=seen.append)
        assert len(seen) == 1
        assert seen[0]["after"] == 14

    def test_deterministic_under_reordered_inputs(self) -> None:
        values = {((A,), (B,)): 10, ((A, B),): 14}
        first = search_partitions([[A], [B]], _score_of(values), {B: {A}}, {}, {})
        second = search_partitions([[A], [B]], _score_of(values), {B: {A}}, {}, {})
        assert first[0] == second[0]
        assert first[2] == second[2]


def _make_cfg(tmp_path: Path) -> Any:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    return SimpleNamespace(
        marker="SERVER",
        source_ext=".c",
        reversed_dir=src_dir,
        metadata_dir=tmp_path,
        root=tmp_path,
        target_binary=tmp_path / "target.exe",
        function_list=tmp_path / "functions.txt",
        padding_bytes=[0xCC, 0x90],
        text_va=0x10000000,
        text_size=0x10000,
    )


def _write_source(path: Path, va: int, symbol: str) -> None:
    name = symbol.lstrip("_")
    path.write_text(
        f"// FUNCTION: SERVER 0x{va:08x}\n"
        f"// SYMBOL: {symbol}\n"
        f"// SIZE: 10\n"
        "\n"
        f"int {name}(void) {{ return 0; }}\n",
        encoding="utf-8",
    )


def _patch_cli(monkeypatch: Any, cfg: Any) -> None:
    monkeypatch.setattr(
        "rebrew.merge_sweep.require_config", lambda target=None, json_mode=False: cfg
    )
    monkeypatch.setattr(
        "rebrew.merge_sweep.load_binary",
        lambda path: SimpleNamespace(text_va=0x10000000, text_size=0x10000),
    )
    monkeypatch.setattr(
        "rebrew.merge_sweep.parse_function_list",
        lambda path: [
            {"va": A, "size": 10, "name": "func_a"},
            {"va": B, "size": 10, "name": "func_b"},
        ],
    )
    monkeypatch.setattr(
        "rebrew.merge_sweep.build_function_registry",
        lambda funcs, cfg_arg, ghidra_path=None, bin_path=None: {
            A: {"canonical_size": 10},
            B: {"canonical_size": 10},
        },
    )
    monkeypatch.setattr(
        "rebrew.merge_sweep._initial_partition", lambda registry, info, cfg_arg: [[A], [B]]
    )
    monkeypatch.setattr(
        "rebrew.merge_sweep._function_call_map", lambda registry, info, cfg_arg: {A: {B}}
    )
    monkeypatch.setattr("rebrew.merge_sweep._function_strings", lambda info: {})
    monkeypatch.setattr("rebrew.merge_sweep._gap_classes", lambda vas, registry, info, cfg_arg: {})


class TestDryRunCli:
    def test_dry_run_shows_partition_and_candidates(self, tmp_path: Path, monkeypatch: Any) -> None:
        cfg = _make_cfg(tmp_path)
        cfg.target_binary.write_bytes(b"x")
        cfg.function_list.write_text("x\n", encoding="utf-8")
        _write_source(cfg.reversed_dir / "a.c", A, "_func_a")
        _write_source(cfg.reversed_dir / "b.c", B, "_func_b")
        _patch_cli(monkeypatch, cfg)

        result = runner.invoke(app, ["--dry-run"])
        assert result.exit_code == 0, result.output
        assert "merge candidate" in result.output
        assert "0x10001000" in result.output

    def test_dry_run_json_payload(self, tmp_path: Path, monkeypatch: Any) -> None:
        cfg = _make_cfg(tmp_path)
        cfg.target_binary.write_bytes(b"x")
        cfg.function_list.write_text("x\n", encoding="utf-8")
        _write_source(cfg.reversed_dir / "a.c", A, "_func_a")
        _write_source(cfg.reversed_dir / "b.c", B, "_func_b")
        _patch_cli(monkeypatch, cfg)

        result = runner.invoke(app, ["--dry-run", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["dry_run"] is True
        assert payload["clusters"] == 2
        assert len(payload["merge_candidates"]) == 1
        assert payload["merge_candidates"][0]["reason"] == "call"


class TestAuditCli:
    def test_audit_log_written_on_search(self, tmp_path: Path, monkeypatch: Any) -> None:
        import rebrew.merge_sweep as ms

        cfg = _make_cfg(tmp_path)
        cfg.target_binary.write_bytes(b"x")
        cfg.function_list.write_text("x\n", encoding="utf-8")
        _write_source(cfg.reversed_dir / "a.c", A, "_func_a")
        _write_source(cfg.reversed_dir / "b.c", B, "_func_b")
        _patch_cli(monkeypatch, cfg)
        monkeypatch.setattr("rebrew.merge_sweep.build_name_to_va", lambda cfg_arg: {})

        values = {((A,), (B,)): 10, ((A, B),): 14}

        def fake_scorer(
            cfg_arg: Any, annotations: dict[int, Any], name_to_va: dict[str, int]
        ) -> Any:
            return lambda partition: (values[_partition_key(partition)], 1)

        monkeypatch.setattr(ms, "_PartitionScorer", fake_scorer)
        audit_path = tmp_path / "audit.json"

        result = runner.invoke(app, ["--passes", "1", "--audit", str(audit_path)])
        assert result.exit_code == 0, result.output
        log = json.loads(audit_path.read_text(encoding="utf-8"))
        assert len(log) == 1
        assert log[0]["kind"] == "merge"
        assert log[0]["before"] == 10
        assert log[0]["after"] == 14

    def test_json_output_carries_partition(self, tmp_path: Path, monkeypatch: Any) -> None:
        import rebrew.merge_sweep as ms

        cfg = _make_cfg(tmp_path)
        cfg.target_binary.write_bytes(b"x")
        cfg.function_list.write_text("x\n", encoding="utf-8")
        _write_source(cfg.reversed_dir / "a.c", A, "_func_a")
        _write_source(cfg.reversed_dir / "b.c", B, "_func_b")
        _patch_cli(monkeypatch, cfg)
        monkeypatch.setattr("rebrew.merge_sweep.build_name_to_va", lambda cfg_arg: {})
        values = {((A,), (B,)): 10, ((A, B),): 9}
        monkeypatch.setattr(
            ms,
            "_PartitionScorer",
            lambda cfg_arg, annotations, name_to_va: (
                lambda partition: (values[_partition_key(partition)], 1)
            ),
        )

        result = runner.invoke(app, ["--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert payload["moves"] == 0
        assert payload["clusters"] == 2


def _make_ann(va: int, filename: str, symbol: str, size: int = 10) -> SimpleNamespace:
    return SimpleNamespace(
        va=va,
        filepath=filename,
        symbol=symbol,
        name=symbol.lstrip("_"),
        size=size,
        toolchain="",
        cflags="",
        module="SERVER",
    )


def _scorer_cfg(tmp_path: Path) -> SimpleNamespace:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    return SimpleNamespace(
        marker="SERVER",
        source_ext=".c",
        reversed_dir=src,
        metadata_dir=tmp_path,
        root=tmp_path,
        target_binary=tmp_path / "target.exe",
        function_list=tmp_path / "functions.txt",
        padding_bytes=[0xCC, 0x90],
        text_va=0x10000000,
        text_size=0x10000,
        cflags="",
        cflags_explicit=False,
        cflags_presets={},
        compiler_profile="",
        posix_style=False,
    )


class TestPartitionScorer:
    def _patch_compile(self, monkeypatch: Any, calls: list[dict[str, Any]], size: int = 10) -> None:
        import rebrew.coff_reloc
        import rebrew.compile
        import rebrew.matcher
        import rebrew.merge_sweep as ms

        def fake_compile(
            cfg: Any, src: Any, cflags: list[str], workdir: Any, **kw: Any
        ) -> tuple[str, str]:
            calls.append({"cflags": list(cflags), "toolchain": kw.get("toolchain")})
            obj = Path(workdir) / "tu.obj"
            obj.write_bytes(b"OBJ")
            return str(obj), ""

        monkeypatch.setattr(rebrew.compile, "compile_to_obj", fake_compile)
        monkeypatch.setattr(
            rebrew.matcher,
            "parse_obj_symbol_and_relocs",
            lambda obj_path, symbol: (b"\x90" * size, {}, []),
        )
        monkeypatch.setattr(
            rebrew.coff_reloc,
            "smart_reloc_compare",
            lambda o, t, r, **kw: (True, len(t), len(t), [], []),
        )
        monkeypatch.setattr(rebrew.coff_reloc, "build_iat_region", lambda cfg_arg: set())
        monkeypatch.setattr(ms, "extract_raw_bytes", lambda binary, va, n: bytes([0x90]) * n)

    def test_cluster_compiles_once_for_all_members(self, tmp_path: Path, monkeypatch: Any) -> None:
        import rebrew.merge_sweep as ms

        cfg = _scorer_cfg(tmp_path)
        _write_source(cfg.reversed_dir / "a.c", A, "_func_a")
        _write_source(cfg.reversed_dir / "b.c", B, "_func_b")
        annotations = {A: _make_ann(A, "a.c", "_func_a"), B: _make_ann(B, "b.c", "_func_b")}
        calls: list[dict[str, Any]] = []
        self._patch_compile(monkeypatch, calls)

        scorer = ms._PartitionScorer(cfg, annotations, {})
        matched, invokes = scorer([[A, B]])
        assert invokes == 1  # one TU compile, not one per function
        assert len(calls) == 1
        assert matched == 20  # both members scored from the one build

    def test_overrides_resolve_against_real_source_dir(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A rebrew-libraries.toml beside the real sources shapes the TU
        compile; the temp staging dir carries no override file."""
        import rebrew.merge_sweep as ms

        cfg = _scorer_cfg(tmp_path)
        _write_source(cfg.reversed_dir / "a.c", A, "_func_a")
        (cfg.reversed_dir / "rebrew-libraries.toml").write_text(
            'toolchain = "msvc6"\ncflags = "/O2 /Gd /MT"\n', encoding="utf-8"
        )
        annotations = {A: _make_ann(A, "a.c", "_func_a")}
        calls: list[dict[str, Any]] = []
        self._patch_compile(monkeypatch, calls)

        scorer = ms._PartitionScorer(cfg, annotations, {})
        matched, invokes = scorer([[A]])
        assert invokes == 1
        assert matched == 10
        assert calls[0]["toolchain"] == "msvc6"
        assert calls[0]["cflags"] == ["/O2", "/Gd", "/MT"]
