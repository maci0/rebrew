"""Render rebrew's listings of every function of x86 binaries, as the ops answer them.

The backend renders x86 listings in process and claims they equal rebrew's;
its listing comparison test reads what this writes.  Each binary is analysed
through ``rebrew.analyse`` in a scratch workspace and every function of the
analysis is listed through ``rebrew.disassemble`` in ``nasm`` (32-bit
x86 only, as the op answers), ``asm`` and ``hex``.  Writes one JSON document to OUTPUT::

    {"renderer": ...,
     "binaries": [{"path", "sha256", "arch",
                   "functions": [{"va", "size", "name", "nasm", "asm", "hex"}]}]}

``path`` is the binary's path as given.  A format's value is the text, or
``{"refused": detail}``; a binary ``rebrew.analyse`` refuses (no function
discovered) has its ``refused`` detail and no functions.  SCRATCH_DIR must lie
outside any rebrew project, whose configuration the analysis would find.

Usage: uv run python tools/listing_corpus.py SCRATCH_DIR OUTPUT BINARY...
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rebrew.asm import listing_renderer
from rebrew.ops import WorkerConfig, dispatch

#: The formats the backend renders in process, and the arch rebrew lists as NASM source.
FORMATS = ("nasm", "asm", "hex")
NASM_ARCHES = frozenset({"x86_32"})


def _call(config: WorkerConfig, op: str, request: dict[str, Any]) -> tuple[int, Any]:
    status, body = dispatch(config, op, json.dumps(request).encode())
    return status, json.loads(body)


def render(scratch: Path, binary: Path) -> dict[str, Any]:
    """The listings of every function of *binary* (see the module docstring)."""
    data = binary.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    filestore, workspace = scratch / "files", scratch / "workspace"
    for directory in (filestore, workspace):
        shutil.rmtree(directory, ignore_errors=True)
    (filestore / "binaries").mkdir(parents=True)
    workspace.mkdir()
    (filestore / "binaries" / digest).write_bytes(data)
    config = WorkerConfig(filestore.resolve(), workspace.resolve())
    request = {
        "binary_id": 1,
        "sha256": digest,
        "name": binary.name,
        "file_key": f"binaries/{digest}",
    }
    out: dict[str, Any] = {"path": str(binary), "sha256": digest}
    status, reply = _call(config, "rebrew.analyse", request)
    if status != 200:
        return {**out, "refused": reply["detail"], "functions": []}
    project = Path(reply["project"])
    (target,) = reply["targets"]
    functions = []
    for fn in sorted(target["functions"], key=lambda f: f["va"]):
        row: dict[str, Any] = {"va": fn["va"], "size": fn["size"], "name": fn["name"]}
        for fmt in FORMATS:
            if fmt == "nasm" and target["arch"] not in NASM_ARCHES:
                continue
            status, listing = _call(
                config,
                "rebrew.disassemble",
                {"project_dir": str(project), "va": fn["va"], "size": fn["size"], "format": fmt},
            )
            row[fmt] = listing["text"] if status == 200 else {"refused": listing["detail"]}
        functions.append(row)
    return {**out, "arch": target["arch"], "functions": functions}


def main(argv: list[str]) -> None:
    """Write the document of the binaries named on the command line."""
    if len(argv) < 3:
        raise SystemExit(__doc__)
    scratch, output = Path(argv[0]), Path(argv[1])
    binaries = [render(scratch, Path(name)) for name in argv[2:]]
    doc = {"renderer": listing_renderer(), "binaries": binaries}
    output.write_text(json.dumps(doc, indent=1) + "\n")
    for b in binaries:
        print(f"{b['path']}: {b.get('arch', b.get('refused'))}, {len(b['functions'])} functions")


if __name__ == "__main__":
    main(sys.argv[1:])
