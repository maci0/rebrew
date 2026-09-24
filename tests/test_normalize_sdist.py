"""Tests for tools/normalize_sdist.py (deterministic sdist tar metadata)."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "normalize_sdist.py"
EPOCH = 1_700_000_000


def _write_sdist(path: Path, *, mode: int, uid: int, mtime: int, reverse: bool) -> None:
    files = [("pkg-1.0/b.py", b"print('b')\n"), ("pkg-1.0/a.sh", b"#!/bin/sh\n")]
    if reverse:
        files.reverse()
    with tarfile.open(path, "w:gz") as tar:
        root = tarfile.TarInfo("pkg-1.0")
        root.type = tarfile.DIRTYPE
        root.mode, root.uid, root.mtime, root.uname = 0o700, uid, mtime, "someone"
        tar.addfile(root)
        for name, data in files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o700 if name.endswith(".sh") else mode
            info.uid, info.gid, info.mtime, info.uname = uid, uid, mtime, "someone"
            tar.addfile(info, io.BytesIO(data))


def _run(*paths: Path, epoch: str | None = str(EPOCH)) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "SOURCE_DATE_EPOCH"}
    if epoch is not None:
        env["SOURCE_DATE_EPOCH"] = epoch
    return subprocess.run(
        [sys.executable, str(SCRIPT), *map(str, paths)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


class TestNormalizeSdist:
    def test_divergent_checkouts_yield_identical_bytes(self, tmp_path: Path) -> None:
        first, second = tmp_path / "one.tar.gz", tmp_path / "two.tar.gz"
        _write_sdist(first, mode=0o600, uid=1000, mtime=1, reverse=False)
        _write_sdist(second, mode=0o664, uid=501, mtime=2_000_000_000, reverse=True)
        assert first.read_bytes() != second.read_bytes()

        result = _run(first, second)

        assert result.returncode == 0, result.stderr
        assert first.read_bytes() == second.read_bytes()

    def test_metadata_normalized_and_contents_kept(self, tmp_path: Path) -> None:
        sdist = tmp_path / "pkg.tar.gz"
        _write_sdist(sdist, mode=0o600, uid=1000, mtime=1, reverse=True)

        assert _run(sdist).returncode == 0

        with tarfile.open(sdist, "r:gz") as tar:
            members = tar.getmembers()
            names = [m.name for m in members]
            assert names == ["pkg-1.0", "pkg-1.0/a.sh", "pkg-1.0/b.py"]
            modes = {m.name: m.mode for m in members}
            assert modes == {"pkg-1.0": 0o755, "pkg-1.0/a.sh": 0o644, "pkg-1.0/b.py": 0o644}
            assert {(m.mtime, m.uid, m.gid, m.uname, m.gname) for m in members} == {
                (EPOCH, 0, 0, "", "")
            }
            payload = tar.extractfile("pkg-1.0/b.py")
            assert payload is not None
            assert payload.read() == b"print('b')\n"
        # gzip header MTIME (bytes 4..8) must be zero, not the build time.
        assert sdist.read_bytes()[4:8] == b"\0\0\0\0"

    def test_missing_epoch_fails_loud(self, tmp_path: Path) -> None:
        sdist = tmp_path / "pkg.tar.gz"
        _write_sdist(sdist, mode=0o644, uid=0, mtime=1, reverse=False)
        before = sdist.read_bytes()

        result = _run(sdist, epoch=None)

        assert result.returncode != 0
        assert "SOURCE_DATE_EPOCH" in result.stderr
        assert sdist.read_bytes() == before
