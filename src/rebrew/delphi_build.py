"""Build complete Delphi 1.0 programs and consistent segment maps."""

import shutil
from pathlib import Path

import typer

from rebrew.cli import TargetOption, console, error_exit, json_print, require_config
from rebrew.compiler.delphi16 import Delphi16Error, compile_ne
from rebrew.utils import safe_shlex_split

app = typer.Typer(
    help="Compile a complete Delphi 1.0 Pascal program through its Docker image.",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew build delphi src/main/HOLIDAY.DPR --dcc-args '-$S-'\n\n"
        "  rebrew build delphi hello.dpr -o hello.exe --map hello.map --json\n\n"
        "Source units always rebuild; a map uses the same compiler invocation and switches."
    ),
)


@app.callback(invoke_without_command=True)
def main(
    source: Path = typer.Argument(..., help="Pascal program source (.DPR or .PAS)"),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Executable output (default: the target's bin_dir)"
    ),
    map_output: Path | None = typer.Option(
        None, "--map", help="Also write a fresh compiler segment map"
    ),
    dcc_args: str = typer.Option(
        "", "--dcc-args", help="Additional DCC switches after configured compiler flags"
    ),
    cfg_file: Path | None = typer.Option(None, "--cfg", help="DCC.CFG to stage verbatim"),
    units: Path | None = typer.Option(
        None, "--units", help="Replace the image's RTL/VCL unit directory"
    ),
    workdir: Path | None = typer.Option(
        None, "--work-dir", help="Retain fresh compilation directories below this path"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Build a Pascal program; no function verdicts or managed stores are written."""
    cfg = require_config(target=target, json_mode=json_output)
    if cfg.compiler_profile != "delphi-1.0":
        error_exit("select a target configured with the delphi-1.0 profile", json_mode=json_output)
    if not source.is_file():
        error_exit(f"source not found: {source}", json_mode=json_output)
    output = output if output is not None else cfg.bin_dir / f"{source.stem.upper()}.EXE"
    destinations = [output, *([map_output] if map_output is not None else [])]
    if any(path.resolve() == cfg.target_binary.resolve() for path in destinations):
        error_exit(
            "build outputs must not replace the configured reference binary", json_mode=json_output
        )
    if map_output is not None and map_output.resolve() == output.resolve():
        error_exit("executable and map need distinct output paths", json_mode=json_output)
    try:
        flags = (
            safe_shlex_split(cfg.base_cflags)
            + safe_shlex_split(cfg.cflags)
            + safe_shlex_split(dcc_args)
        )
        result = compile_ne(
            source,
            workdir,
            timeout=cfg.compile_timeout,
            units_dir=units,
            extra_args=flags,
            dcc_cfg=cfg_file.read_bytes() if cfg_file is not None else None,
            map_file=map_output is not None,
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(result.exe_path, output)
        if map_output is not None and result.map_path is not None:
            map_output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(result.map_path, map_output)
        log_path = output.with_suffix(".dcc.log")
        log_path.write_text(result.log, encoding="utf-8")
    except (OSError, ValueError, Delphi16Error) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(
            {
                "output": str(output),
                "map": str(map_output) if map_output is not None else None,
                "log_path": str(log_path),
                "log": result.log,
                "function_count": len(result.funcs),
                "toolchain": cfg.compiler_profile,
                "compiler_args": result.compiler_args,
            }
        )
        return
    console.print(result.log.rstrip(), markup=False)
    console.print(f"Built {output} ({output.stat().st_size:,} bytes)", markup=False)
    if map_output is not None:
        console.print(f"Wrote {map_output}", markup=False)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
