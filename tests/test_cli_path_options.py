"""Path-valued CLI parameters provide native completion without changing APIs."""

import importlib
from pathlib import Path
from typing import Any

import pytest
from typer.main import get_command
from typer.models import TyperPath


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
        for name in names:
            param = params[name]
            assert isinstance(param.type, TyperPath), (module, operation, name)
            # This is Typer's native path/completion type, with a string return
            # so direct Python callers and structured JSON fields stay stable.
            assert param.type.name == "path"
            candidate = str(tmp_path / "new path")
            value = param.type.convert(candidate, param, None)
            assert type(value) is str
            assert value == candidate
