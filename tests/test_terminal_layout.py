"""Terminal reports preserve complete values at ordinary terminal widths."""

from __future__ import annotations

from io import StringIO

import pytest
from rich.cells import cell_len
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rebrew.utils import TerminalTable


def _render(renderable: object, width: int) -> str:
    buffer = StringIO()
    Console(file=buffer, width=width, height=24, color_system=None, highlight=False).print(
        renderable
    )
    output = buffer.getvalue()
    assert all(cell_len(line) <= width for line in output.splitlines())
    return output


class TestTerminalTable:
    @pytest.mark.parametrize("width", [60, 80, 100, 120])
    @pytest.mark.parametrize("panel", [False, True])
    def test_crowded_table_keeps_verdicts_and_numbers(self, width: int, panel: bool) -> None:
        table = TerminalTable(title="Results", caption="Stored verdicts")
        table.add_column("VA", width=12, no_wrap=True)
        table.add_column("Symbol", width=40, no_wrap=True)
        table.add_column("Status", width=16, no_wrap=True)
        table.add_column("Match %", width=8, no_wrap=True, justify="right")
        table.add_column("Bytes", width=12, no_wrap=True, justify="right")
        for name in ("日本語_function", "another_function"):
            table.add_row("0x00401000", name, "NEAR_MATCHING", "99.9%", "123456789B")
        output = _render(Panel(table) if panel else table, width)
        for value in (
            "Results",
            "Stored verdicts",
            "0x00401000",
            "日本語_function",
            "another_function",
            "NEAR_MATCHING",
            "99.9%",
            "123456789B",
        ):
            assert value in output
        assert "…" not in output

    def test_fitting_table_keeps_rich_layout(self) -> None:
        tables = []
        for cls in (Table, TerminalTable):
            table = cls(title="Results")
            table.add_column("Status")
            table.add_column("Count", justify="right")
            table.add_row("EXACT", "123")
            tables.append(table)
        assert _render(tables[0], 80) == _render(tables[1], 80)

    def test_empty_table_keeps_headers_and_footer(self) -> None:
        table = TerminalTable(show_footer=True)
        table.add_column("Symbol", width=80, footer="Total")
        table.add_column("Bytes", width=80, footer="123456789B")
        output = _render(table, 60)
        for value in ("Symbol", "Bytes", "Total", "123456789B"):
            assert value in output

    def test_fixed_column_does_not_clip_large_number(self) -> None:
        table = TerminalTable()
        table.add_column("Bytes", width=4, no_wrap=True, overflow="ellipsis")
        table.add_row("123456789B")
        assert "123456789B" in _render(table, 120)

    def test_resize_does_not_mutate_columns(self) -> None:
        table = TerminalTable()
        table.add_column("Symbol", width=45)
        table.add_column("Status", width=25, no_wrap=True)
        table.add_row("function_name", "INTERNAL_ERROR")
        wide = _render(table, 120)
        assert "INTERNAL_ERROR" in _render(table, 60)
        assert _render(table, 120) == wide

    def test_wrapped_unicode_and_markup_keep_all_content(self) -> None:
        table = TerminalTable()
        table.add_column("Name", width=80)
        table.add_column("Status", no_wrap=True)
        table.add_row("[cyan]" + "名" * 45 + "[/cyan]", "SIZE_MISMATCH")
        output = _render(table, 60)
        assert output.count("名") == 45
        assert "[cyan]" not in output
        assert "SIZE_MISMATCH" in output


class TestReports:
    @pytest.mark.parametrize("width", [60, 80, 100, 120])
    def test_error_wraps_message_and_keeps_hint_on_its_own_line(
        self, monkeypatch: pytest.MonkeyPatch, width: int
    ) -> None:
        import typer

        import rebrew.cli as cli

        buffer = StringIO()
        monkeypatch.setattr(
            cli,
            "console",
            Console(file=buffer, width=width, height=24, color_system=None, force_terminal=True),
        )
        hint = "Pass --yes to skip the prompt."
        with pytest.raises(typer.Exit):
            cli.error_exit("Could not load " + "/long-directory" * 12, hint=hint)
        output = buffer.getvalue()
        assert all(cell_len(line) <= width for line in output.splitlines())
        assert output.splitlines()[-1] == hint
        assert output.count("/") == 12

    @pytest.mark.parametrize("width", [60, 80, 100, 120])
    def test_verification_keeps_measured_values(
        self, monkeypatch: pytest.MonkeyPatch, width: int
    ) -> None:
        import rebrew.verify as verify

        buffer = StringIO()
        monkeypatch.setattr(
            verify, "console", Console(file=buffer, width=width, height=24, color_system=None)
        )
        verify.render_verify_summary(
            [
                {
                    "va": "0x00401000",
                    "name": "function_name",
                    "size": 123456,
                    "status": "NEAR_MATCHING",
                    "match_percent": 99.99,
                    "delta": 12345,
                    "similarity": 98.7,
                },
            ]
        )
        output = buffer.getvalue()
        assert all(cell_len(line) <= width for line in output.splitlines())
        for value in ("0x00401000", "123456B", "NEAR_MATCHING", "99.9%", "12345B", "98.7%"):
            assert value in output

    @pytest.mark.parametrize("width", [60, 80, 100, 120])
    def test_instruction_diff_stays_within_width(self, width: int) -> None:
        from rebrew.matcher.scoring import print_diff_summary

        lines: list[str] = []
        print_diff_summary(
            {
                "summary": {},
                "instructions": [
                    {
                        "match": "**",
                        "target": {"bytes": "83ec10", "disasm": "sub esp, 0x10"},
                        "candidate": {"bytes": "83ec20", "disasm": "sub esp, 0x20"},
                    },
                ],
            },
            width=width,
            write=lines.append,
        )
        table = "\n".join(lines[1 : lines.index("== : exact match")])
        assert all(cell_len(line) <= width for line in table.splitlines())
        for value in ("83ec10", "83ec20", "sub esp, 0x10", "sub esp, 0x20", "**"):
            assert value in table
