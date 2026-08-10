"""Tests for rebrew llm_seed — optional LLM-assisted GA seed generation.

All tests are mocked: no real network calls.  The contract is that a
configured endpoint's C-code response is validated with tree-sitter and
injected into the GA's initial population, and that everything degrades
gracefully (empty list, no crash) when the endpoint is missing or fails.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.llm_seed import (
    _parse_response,
    _valid_c_source,
    extract_seeds,
    llm_config,
    request_seeds,
)


def _cfg(endpoint: str = "", api_key: str = "") -> SimpleNamespace:
    return SimpleNamespace(llm_endpoint=endpoint, llm_api_key=api_key)


class TestLlmConfig:
    def test_no_config_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("REBREW_LLM_ENDPOINT", raising=False)
        monkeypatch.delenv("REBREW_LLM_API_KEY", raising=False)
        assert llm_config(_cfg()) is None

    def test_config_wins_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("REBREW_LLM_ENDPOINT", "https://env.example/v1")
        cfg = _cfg(endpoint="https://cfg.example/v1", api_key="cfg-key")
        conf = llm_config(cfg)
        assert conf == {"endpoint": "https://cfg.example/v1", "api_key": "cfg-key"}

    def test_env_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("REBREW_LLM_ENDPOINT", "https://env.example/v1")
        monkeypatch.setenv("REBREW_LLM_API_KEY", "env-key")
        assert llm_config(_cfg()) == {
            "endpoint": "https://env.example/v1",
            "api_key": "env-key",
        }


class TestExtractSeeds:
    def test_fenced_c_blocks(self) -> None:
        text = (
            "Here are alternatives:\n"
            "```c\nint f(void) { return 1; }\n```\n"
            "and another\n"
            "```c\nint g(void) { return 2; }\n```\n"
        )
        assert extract_seeds(text) == [
            "int f(void) { return 1; }",
            "int g(void) { return 2; }",
        ]

    def test_no_blocks_returns_empty(self) -> None:
        assert extract_seeds("no code here") == []

    def test_empty_blocks_skipped(self) -> None:
        assert extract_seeds("```c\n\n```") == []


class TestValidCSource:
    def test_valid_function(self) -> None:
        assert _valid_c_source("int f(void) { return 0; }")

    def test_garbage_rejected(self) -> None:
        assert not _valid_c_source("not c at all {{{")
        assert not _valid_c_source("")


class TestParseResponse:
    def test_openai_shape(self) -> None:
        data = {"choices": [{"message": {"content": "```c\nint f(void){return 0;}\n```"}}]}
        assert "int f(void){return 0;}" in _parse_response(data)

    def test_content_parts(self) -> None:
        data = {"choices": [{"message": {"content": [{"text": "part1 "}, {"text": "part2"}]}}]}
        assert _parse_response(data) == "part1 part2"

    def test_plain_string(self) -> None:
        assert _parse_response("plain") == "plain"


class _FakeClient:
    """A canned httpx-like client."""

    def __init__(self, payload: dict | str) -> None:
        self.payload = payload
        self.last_payload: dict | None = None

    def post(self, url, json=None, headers=None, timeout=None):  # type: ignore[no-untyped-def]
        self.last_payload = json
        return _FakeResponse(self.payload)


class _FakeResponse:
    def __init__(self, payload: dict | str) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict | str:
        return self.payload


class TestRequestSeeds:
    def test_returns_validated_seeds(self) -> None:
        client = _FakeClient(
            {
                "choices": [
                    {
                        "message": {
                            "content": (
                                "```c\nint f(void) { return 0; }\n```\n"
                                "```c\nthis is not valid c ```\n"
                            )
                        }
                    }
                ]
            }
        )
        seeds = request_seeds(_cfg("https://llm/v1", "k"), "int f(void){return 0;}", client=client)
        assert seeds == ["int f(void) { return 0; }"]  # garbage block dropped
        assert client.last_payload is not None
        assert "f(void)" in client.last_payload["messages"][0]["content"]

    def test_no_endpoint_returns_empty(self) -> None:
        assert request_seeds(_cfg(), "int f(void){return 0;}") == []

    def test_failing_request_returns_empty(self) -> None:
        class _Broken:
            def post(self, *a, **k):  # type: ignore[no-untyped-def]
                raise OSError("connection refused")

        assert (
            request_seeds(_cfg("https://llm/v1"), "int f(void){return 0;}", client=_Broken()) == []
        )


class TestMatchGlue:
    def test_llm_seeds_injected_into_ga(self, tmp_path: Path, monkeypatch) -> None:
        """match --llm-seed appends validated LLM snippets to the GA seeds."""
        from types import SimpleNamespace as NS

        from rebrew import match as match_mod

        captured: dict[str, object] = {}

        class _FakeGA:
            def __init__(self, *a, **k):  # type: ignore[no-untyped-def]
                captured["extra_seeds"] = k.get("extra_seeds")
                captured["target"] = k.get("target_bytes")

            def run(self) -> tuple[str, float]:  # type: ignore[no-untyped-def]
                return "int f(void){return 0;}", 0.0

            def close(self) -> None:
                return None

        monkeypatch.setattr(match_mod, "BinaryMatchingGA", _FakeGA)
        monkeypatch.setattr(
            "rebrew.llm_seed.request_seeds",
            lambda cfg, source: ["int f(void) { return 42; }"],
        )

        p = NS(
            cfg=NS(
                root=tmp_path,
                compile_timeout=30,
                posix_style=False,
                llm_endpoint="https://llm/v1",
                llm_api_key="k",
            ),
            seed_src="int f(void){return 0;}",
            seed_c=tmp_path / "f.c",
            target_bytes=b"\x55\x8b\xec\x5d\xc3",
            cl="cl",
            inc=[],
            cflags="/O2",
            symbol="_f",
            msvc_env={},
            cc=None,
            timeout=30,
            va_int=0x1000,
            target_size=5,
        )
        match_mod._run_single_ga(
            p,
            str(tmp_path / "out"),
            1,
            4,
            1,
            False,
            None,
            None,
            1,
            False,
            None,
            False,
            llm_seed=True,
        )
        assert "int f(void) { return 42; }" in captured["extra_seeds"]

    def test_llm_seed_without_endpoint_warns_not_crashes(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        from types import SimpleNamespace as NS

        from rebrew import match as match_mod

        monkeypatch.setattr(
            "rebrew.llm_seed.llm_config",
            lambda cfg: None,  # no endpoint
        )
        calls: list[object] = []

        class _FakeGA:
            def __init__(self, *a, **k):  # type: ignore[no-untyped-def]
                calls.append(k.get("extra_seeds"))

            def run(self) -> tuple[str, float]:  # type: ignore[no-untyped-def]
                return "int f(void){return 0;}", 0.0

            def close(self) -> None:
                return None

        monkeypatch.setattr(match_mod, "BinaryMatchingGA", _FakeGA)
        p = NS(
            cfg=NS(root=tmp_path, compile_timeout=30, posix_style=False),
            seed_src="int f(void){return 0;}",
            seed_c=tmp_path / "f.c",
            target_bytes=b"\xc3",
            cl="cl",
            inc=[],
            cflags="/O2",
            symbol="_f",
            msvc_env={},
            cc=None,
            timeout=30,
            va_int=0x1000,
            target_size=5,
        )
        match_mod._run_single_ga(
            p,
            str(tmp_path / "out"),
            1,
            4,
            1,
            False,
            None,
            None,
            1,
            False,
            None,
            False,
            llm_seed=True,
        )
        assert "no LLM endpoint" in capsys.readouterr().err
        assert calls == [None]  # GA ran unchanged, no seeds


class TestLlmSeedDryRun:
    """H10: match --llm-seed --dry-run previews the prompt without a GA run."""

    def test_dry_run_shows_prompt_and_skips_ga(self, tmp_path: Path, monkeypatch, capsys) -> None:
        from types import SimpleNamespace as NS

        from rebrew import match as match_mod

        calls: list[object] = []

        class _FakeGA:
            def __init__(self, *a, **k):  # type: ignore[no-untyped-def]
                calls.append(1)

            def run(self) -> tuple[str, float]:  # type: ignore[no-untyped-def]
                raise AssertionError("GA must not run in dry-run mode")

            def close(self) -> None:
                return None

        monkeypatch.setattr(match_mod, "BinaryMatchingGA", _FakeGA)
        monkeypatch.setattr(
            "rebrew.llm_seed.request_seeds",
            lambda cfg, source: ["int f(void) { return 42; }"],
        )
        p = NS(
            cfg=NS(
                root=tmp_path,
                compile_timeout=30,
                posix_style=False,
                llm_endpoint="https://llm/v1",
                llm_api_key="k",
            ),
            seed_src="int f(void){return 0;}",
            seed_c=tmp_path / "f.c",
            target_bytes=b"\xc3",
            cl="cl",
            inc=[],
            cflags="/O2",
            symbol="_f",
            msvc_env={},
            cc=None,
            timeout=30,
            va_int=0x1000,
            target_size=5,
        )
        match_mod._run_single_ga(
            p,
            str(tmp_path / "out"),
            1,
            4,
            1,
            False,
            None,
            None,
            1,
            False,
            None,
            False,
            llm_seed=True,
            dry_run=True,
        )
        assert calls == []  # GA never constructed
        out = capsys.readouterr().err
        assert "LLM seed prompt (dry-run)" in out
        assert "1 validated seed(s) would be added" in out

    def test_dry_run_without_llm_seed_still_rejected(self, tmp_path: Path, monkeypatch) -> None:
        """--dry-run alone in single mode keeps its batch-only error."""
        from types import SimpleNamespace as NS

        from typer.testing import CliRunner

        from rebrew.match import app

        cfg = NS(
            root=tmp_path,
            reversed_dir=tmp_path,
            metadata_dir=tmp_path,
            marker="S",
            source_ext=".c",
            target_name="S",
            target_binary=tmp_path / "x",
        )
        monkeypatch.setattr("rebrew.match.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.match.resolve_source_arg", lambda cfg, s: s)
        result = CliRunner().invoke(app, ["--dry-run", "f.c"])
        assert result.exit_code == 2  # EXIT_ERROR
        assert "batch mode only" in result.output
