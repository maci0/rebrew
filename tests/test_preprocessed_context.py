"""Pinned compiler preprocessing captures actual target output, without publishing state."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.compiler import preprocessed_context as capture


def _fixture(root: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, list]:
    src = root / "src"
    src.mkdir()
    (src / "common.h").write_text("#define VALUE 1\n")
    source = src / "unit.c"
    source.write_text('#include "common.h"\nint f(void) { return VALUE; }\n')
    build = root / "build"
    build.mkdir()
    database = build / "compile_commands.json"
    entries = []
    for target in ("TL", "GOLD"):
        entries.append(
            {
                "directory": str(build),
                "file": str(source),
                "output": f"{target}.obj",
                "arguments": [
                    "rebrew",
                    "build",
                    "driver",
                    "cl",
                    "--",
                    "/REBREW_TOOLCHAIN:msvc-6.0-sp5-pp",
                    "/nologo",
                    "/D",
                    target,
                    f"/I{src}",
                    "/DVALUE=1",
                    "/UVALUE",
                    "/DVALUE=2",
                    "/MT",
                    "/Gd",
                    f"/Fo{target}.obj",
                    "-c",
                    str(source),
                ],
            }
        )
    database.write_text(json.dumps(entries))
    calls = []

    class Images:
        def __init__(self) -> None:
            self.trees = {}

        def __enter__(self) -> Images:
            return self

        def __exit__(self, *args: object) -> None:
            pass

        def get(self, profile: str) -> Path:
            self.trees[profile] = {"id": "sha256:" + "a" * 64}
            return root

        def verify(self) -> None:
            pass

    def run(spec: object, flags: list[str], **kwargs: object) -> SimpleNamespace:
        calls.append((flags, kwargs))
        marker = str(source).replace("/", "\\").replace("\\", "\\\\")
        target = "GOLD" if "GOLD" in flags else "TL"
        (Path(kwargs["workdir"]) / "unit.i").write_bytes(
            f'#line 1 "Z:{marker}"\nint {target}(void) {{return 2;}}\n'.encode()
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(capture, "ImageHeaders", Images)
    monkeypatch.setattr(capture, "run_toolchain", run)
    return source, database, calls


def test_capture_preserves_target_flag_order_and_expansion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, calls = _fixture(tmp_path, monkeypatch)
    a = capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
    b = capture.capture_msvc_context(tmp_path, db, source, output="GOLD.obj")
    assert b"int TL(" in a["expanded"] and b"int GOLD(" in b["expanded"]
    assert a["input_digest"] != b["input_digest"]
    flags, options = calls[0]
    assert flags.index("/DVALUE=1") < flags.index("/UVALUE") < flags.index("/DVALUE=2")
    assert flags[-2:] == ["/P", "Z:" + str(source).replace("/", "\\")]
    assert options["image_id"] == "sha256:" + "a" * 64
    assert not a["macro_table_complete"] and not a["provider_evidence"]


@pytest.mark.parametrize("mutation", ["source", "header", "new_shadow", "database"])
def test_capture_refuses_changed_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    original = capture.run_toolchain

    def changed(*args: object, **kwargs: object) -> object:
        result = original(*args, **kwargs)
        target = {
            "source": source,
            "header": source.parent / "common.h",
            "new_shadow": source.parent / "new.h",
            "database": db,
        }[mutation]
        target.write_text("changed\n")
        return result

    monkeypatch.setattr(capture, "run_toolchain", changed)
    with pytest.raises(ValueError, match="inputs changed"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


def test_capture_refuses_compiler_failure_and_ambiguous_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="select exactly one"):
        capture.capture_msvc_context(tmp_path, db, source, output="missing.obj")
    monkeypatch.setattr(
        capture,
        "run_toolchain",
        lambda *a, **kw: SimpleNamespace(returncode=1, stdout="", stderr="fatal error"),
    )
    with pytest.raises(ValueError, match="fatal error"):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")


@pytest.mark.parametrize("bad", ["@flags.rsp", "/FIhidden.h", "/I/outside"])
def test_capture_refuses_unpinned_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    source, db, _ = _fixture(tmp_path, monkeypatch)
    entries = json.loads(db.read_text())
    entries[0]["arguments"].insert(-1, bad)
    db.write_text(json.dumps(entries))
    with pytest.raises(ValueError):
        capture.capture_msvc_context(tmp_path, db, source, output="TL.obj")
