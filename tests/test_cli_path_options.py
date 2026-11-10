"""String path parameters keep str values and shell file completion; options read <path> in help."""

import importlib
from typing import Any
lazy from pathlib import Path

import pytest
import typer
from typer.core import TyperOption
from typer.main import get_command


class TestStringPathParameters:
    @pytest.mark.parametrize(
        "module, operation, names",
        [
            ("test", None, ("target_bin",)),
            ("verify", None, ("file", "output_path", "batch_dir")),
            ("skeleton", None, ("output", "append")),
            ("depgraph", None, ("output",)),
            ("gen_flirt_pat", None, ("lib_path", "output")),
            ("discover", None, ("output",)),
            ("rehome", None, ("from_file", "to_file")),
            ("merge", None, ("sources", "output")),
            ("match", "run", ("inc", "lib", "out_dir", "extra_seed", "collect_pairs")),
            ("match", "batch", ("collect_pairs",)),
            ("match", "flags", ("inc",)),
            ("test", None, ("batch_dir",)),
            ("intake", None, ("binary",)),
            ("cfg", "target add", ("binary",)),
            ("toolchain_cli", "detect", ("binary",)),
            ("pdb_info", "show", ("binary",)),
            ("pdb_info", "import-cflags", ("binary",)),
            ("library", "show", ("directory",)),
            ("library", "list", ("root",)),
            ("library", "set", ("directory",)),
            ("library", "remove", ("directory",)),
            ("residue", None, ("built", "baseline", "new_baseline")),
            ("merge_sweep", None, ("audit",)),
        ],
    )
    def test_paths_keep_strings_and_offer_native_path_completion(
        self, tmp_path: Path, module: str, operation: str | None, names: tuple[str, ...]
    ) -> None:
        command: Any = get_command(importlib.import_module(f"rebrew.{module}").app)
        if operation is not None:
            for name in operation.split():
                command = command.commands[name]
        params = {param.name: param for param in command.params}
        context = typer._click.core.Context(command)
        for name in names:
            param = params[name]
            candidate = str(tmp_path / "new path")
            many = param.multiple or param.nargs == -1
            value = param.process_value(context, [candidate] if many else candidate)
            # A string return keeps direct Python callers and structured JSON fields stable.
            assert (list(value) if many else [value]) == [candidate], (module, operation, name)
            assert all(type(item) is str for item in (value if many else [value]))
            # No completion items: the shell completes file names.
            assert param.shell_complete(context, "x") == []
            # An option's help names its value a path; an argument's shows its name.
            if isinstance(param, TyperOption):
                assert param.display_type_rich(context) == "<path>", (module, operation, name)
