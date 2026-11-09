"""kuna decompiles a 16-bit NE function through its segment as a raw image (kuna v1.993+)."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from bin_util import make_ne
from test_ne_relocations import CODE, CODE_FLAGS, DATA_FLAGS, FIXUPS

import rebrew.decompiler as dc
from rebrew.formats.binary_loader import UnsupportedBinaryFormat
from rebrew.ops import WorkerConfig, dispatch

RAW_TARGET = "x86:LE:16:Protected Mode"
#: Flat addresses ((segment - 1) << 16 | offset) of the functions at offsets 0 and 0x20 of segment 1.
CALLER_VA = 0x0
CALLEE_VA = 0x20
KUNA_160_UNKNOWN_OPTION = "error: unknown option --raw-image\n"


def _ne_file(tmp_path: Path) -> Path:
    path = tmp_path / "caller.exe"
    path.write_bytes(
        make_ne(
            segments=[(CODE, CODE_FLAGS, FIXUPS), (b"\x00" * 0x130, DATA_FLAGS)], modules=["KERNEL"]
        )
    )
    return path


class _Run:
    def __init__(self, returncode: int, stdout: str, stderr: str = "") -> None:
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _fake_kuna(monkeypatch: pytest.MonkeyPatch, result: _Run) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []

    def run(cmd: list[str], **kwargs: Any) -> _Run:
        image = Path(cmd[2])
        seen.append({"cmd": cmd, "image": image.read_bytes() if image.exists() else b""})
        return result

    monkeypatch.setattr(dc.shutil, "which", lambda name: "/usr/bin/kuna")
    monkeypatch.setattr(dc, "run_process_group", run)
    return seen


def test_an_ne_function_is_decompiled_from_its_segment_as_a_raw_16_bit_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _fake_kuna(
        monkeypatch,
        _Run(0, "void sub_20(void)\n{\n  sub_0();\n  sub_20();\n  sub_ffff();\n}\n"),
    )
    code = dc.fetch_kuna(_ne_file(tmp_path), CALLEE_VA, tmp_path)
    assert code is not None
    cmd = seen[0]["cmd"]
    assert cmd[1] == "decompile" and cmd[3:] == [
        "0x20",
        "--addr",
        "--raw-image",
        "--target",
        RAW_TARGET,
        "--base",
        "0x0",
    ]
    # the slice is the segment (relocated), not the file
    assert seen[0]["image"].startswith(CODE[:3])
    assert len(seen[0]["image"]) > len(CODE)
    # kuna's slice offsets are renamed to the backend's flat addresses
    assert code.startswith("void sub_0020(void)")
    assert "sub_0000();" in code and "sub_ffff();" in code
    assert "3 relocations applied" in code


def test_an_address_outside_the_segment_is_not_decompiled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _fake_kuna(monkeypatch, _Run(0, "x"))
    with pytest.warns(UserWarning, match="outside"):
        assert dc.fetch_kuna(_ne_file(tmp_path), 0x7000, tmp_path) is None
    assert seen == []


def test_kuna_without_raw_image_is_an_unsupported_format_not_a_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_kuna(monkeypatch, _Run(1, "", KUNA_160_UNKNOWN_OPTION))
    with pytest.raises(UnsupportedBinaryFormat, match="--raw-image"):
        dc.fetch_kuna(_ne_file(tmp_path), CALLER_VA, tmp_path)
    assert dc.fetch_decompilation("auto", _ne_file(tmp_path), CALLER_VA, tmp_path)[0] is None


def test_a_flat_binary_still_runs_kuna_on_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ" + bytes(62))
    seen = _fake_kuna(monkeypatch, _Run(0, "void sub_401000(void)\n{\n}\n"))
    assert dc.fetch_kuna(binary, 0x401000, tmp_path) == "void sub_401000(void)\n{\n}"
    assert seen[0]["cmd"][2:] == [str(binary), "0x401000", "--addr"]


def _ne_worker(tmp_path: Path) -> tuple[WorkerConfig, str, str]:
    """A worker that has analysed the NE fixture: ``(config, project_dir, sha256)``."""
    data = _ne_file(tmp_path).read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    (tmp_path / "files" / "binaries").mkdir(parents=True)
    (tmp_path / "files" / "binaries" / sha256).write_bytes(data)
    (tmp_path / "workspace").mkdir()
    config = WorkerConfig((tmp_path / "files").resolve(), (tmp_path / "workspace").resolve())
    request = {"binary_id": 1, "sha256": sha256, "name": "ne.exe", "file_key": f"binaries/{sha256}"}
    status, body = dispatch(config, "rebrew.analyse", json.dumps(request).encode())
    assert status == 200, body
    return config, json.loads(body)["project"], sha256


def _decompile(
    config: WorkerConfig, project: str, sha256: str, va: int
) -> tuple[int, dict[str, Any]]:
    """The request the backend sends for a function: ProjectDir, SHA256, VA, Backend, Named."""
    request = {
        "project_dir": project,
        "sha256": sha256,
        "va": va,
        "backend": "kuna",
        "named": False,
    }
    status, body = dispatch(config, "rebrew.decompile", json.dumps(request).encode())
    return status, json.loads(body)


def test_the_backend_decompile_request_for_an_ne_function(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, project, sha256 = _ne_worker(tmp_path)
    _fake_kuna(monkeypatch, _Run(0, "void sub_0(void)\n{\n  sub_20();\n}\n"))
    status, reply = _decompile(config, project, sha256, CALLER_VA)
    assert status == 200, reply
    assert reply["backend"] == "kuna"
    assert reply["code"].startswith("void sub_0000(void)\n{\n  sub_0020();\n}")


def test_the_backend_gets_unsupported_binary_format_from_a_kuna_without_raw_image(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, project, sha256 = _ne_worker(tmp_path)
    _fake_kuna(monkeypatch, _Run(1, "", KUNA_160_UNKNOWN_OPTION))
    status, reply = _decompile(config, project, sha256, CALLER_VA)
    assert (status, reply["error"]) == (422, "unsupported-binary-format")
    assert "--raw-image" in reply["detail"]


def _kuna_raw_image_support() -> bool | None:
    """None without kuna on PATH; else whether its ``decompile`` takes ``--raw-image``."""
    kuna = shutil.which("kuna")
    if kuna is None:
        return None
    help_text = subprocess.run(
        [kuna, "decompile", "--help"], capture_output=True, text=True, check=False
    )
    return "--raw-image" in help_text.stdout + help_text.stderr


@pytest.mark.skipif(
    _kuna_raw_image_support() is not True, reason="requires kuna v1.993+ (--raw-image) on PATH"
)
def test_real_kuna_decompiles_an_ne_function_with_its_far_calls_named(tmp_path: Path) -> None:
    code, backend = dc.fetch_decompilation("kuna", _ne_file(tmp_path), CALLER_VA, tmp_path)
    assert backend == "kuna" and code is not None
    assert code.startswith("void sub_0000(short a0,short a1)"), code  # 16-bit registers, flat name
    assert "KERNEL_176(" in code  # the import
    assert "sub_10123(" in code  # segment 2, offset 0x123
    assert "sub_0020(" in code  # the callee in the same segment
    assert "sub_ffff" not in code
    assert "NE segment 1: 3 relocations applied" in code


@pytest.mark.skipif(
    _kuna_raw_image_support() is not False, reason="requires a kuna without --raw-image on PATH"
)
def test_real_old_kuna_is_a_typed_unsupported_outcome(tmp_path: Path) -> None:
    with pytest.raises(UnsupportedBinaryFormat, match="--raw-image"):
        dc.fetch_kuna(_ne_file(tmp_path), CALLER_VA, tmp_path)
