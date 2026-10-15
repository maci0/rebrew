"""Regression checks for project document/address lookup."""

from pathlib import Path

import pytest
from cli_json import cli_payload
from typer.testing import CliRunner

from rebrew.app.main import app
from rebrew.findings import find_documented_addresses


class TestFindings:
    def test_range_heading_context_and_nested_docs(self, tmp_path: Path) -> None:
        docs = tmp_path / "docs" / "nested"
        docs.mkdir(parents=True)
        (docs / "probes.md").write_text(
            "# Probe history\nfirst 0x10\n## Failed shape\nbefore\n"
            "0X0020 and 0x20 also 0x25\nafter\n0x30 beyond\n"
        )
        hits = find_documented_addresses(tmp_path, [0x21], window=1, context=1)
        assert len(hits) == 1
        assert hits[0]["doc"] == "docs/nested/probes.md"
        assert hits[0]["line"] == 5
        assert hits[0]["va"] == ["0x20"]
        assert hits[0]["section"] == "Failed shape"
        assert [row["line"] for row in hits[0]["context"]] == [4, 5, 6]
        assert len(find_documented_addresses(tmp_path, [0x10, 0x25])) == 2

    def test_explicit_document_and_missing_document(self, tmp_path: Path) -> None:
        path = tmp_path / "goal.md"
        path.write_text("0x1000 measured\n")
        assert find_documented_addresses(tmp_path, [0x1000]) == []
        assert len(find_documented_addresses(tmp_path, [0x1000], documents=[Path("goal.md")])) == 1
        with pytest.raises(FileNotFoundError):
            find_documented_addresses(tmp_path, [0x1000], documents=[Path("missing.md")])

    def test_json_through_cli(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "goal.md").write_text("# Test\n0x1000 [measured]\n")
        monkeypatch.setattr("rebrew.findings.require_root", lambda root=None, **_kw: tmp_path)
        result = CliRunner().invoke(
            app, ["source", "findings", "0x1000", "--doc", "goal.md", "--json"]
        )
        assert result.exit_code == 0, result.output
        assert cli_payload(result)["hits"][0]["text"] == "0x1000 [measured]"

    @pytest.mark.parametrize("field", ["window", "context"])
    def test_rejects_negative_limits(self, tmp_path: Path, field: str) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            find_documented_addresses(tmp_path, [1], **{field: -1})
