"""Tests for tools/normalize_sdist.py (deterministic sdist tar metadata)."""

from __future__ import annotations

import io
import os
import stat
import subprocess
import sys
import tarfile
import zipfile
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
        encoding="utf-8",
        errors="replace",
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


def _write_wheel(
    path: Path,
    *,
    mode: int,
    date: tuple[int, int, int, int, int, int],
    reverse: bool,
) -> None:
    files = [("rebrew/b.py", b"print('b')\n"), ("rebrew/a.py", b"print('a')\n")]
    if reverse:
        files.reverse()
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo(filename="rebrew/", date_time=date)
        info.external_attr = (stat.S_IFDIR | 0o700) << 16
        zf.writestr(info, b"")
        for name, data in files:
            info = zipfile.ZipInfo(filename=name, date_time=date)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFREG | mode) << 16
            zf.writestr(info, data)


class TestNormalizeWheel:
    def test_divergent_modes_and_order_yield_identical_bytes(self, tmp_path: Path) -> None:
        first, second = tmp_path / "one.whl", tmp_path / "two.whl"
        _write_wheel(first, mode=0o644, date=(2020, 1, 2, 3, 4, 6), reverse=False)
        _write_wheel(second, mode=0o664, date=(2024, 6, 1, 12, 30, 8), reverse=True)
        assert first.read_bytes() != second.read_bytes()

        result = _run(first, second)

        assert result.returncode == 0, result.stderr
        assert first.read_bytes() == second.read_bytes()
        again = _run(first)
        assert again.returncode == 0, again.stderr
        assert first.read_bytes() == second.read_bytes()

    def test_metadata_normalized_and_contents_kept(self, tmp_path: Path) -> None:
        wheel = tmp_path / "pkg.whl"
        _write_wheel(wheel, mode=0o600, date=(2020, 1, 2, 3, 4, 6), reverse=True)

        assert _run(wheel).returncode == 0

        with zipfile.ZipFile(wheel) as zf:
            names = zf.namelist()
            assert names == ["rebrew/", "rebrew/a.py", "rebrew/b.py"]
            modes = {(info.external_attr >> 16) & 0o777 for info in zf.infolist()}
            assert modes == {0o755, 0o644}
            assert zf.read("rebrew/b.py") == b"print('b')\n"
            dates = {info.date_time for info in zf.infolist()}
            assert dates == {(2023, 11, 14, 22, 13, 20)}

    def test_epoch_zero_clamps_to_zip_floor(self, tmp_path: Path) -> None:
        wheel = tmp_path / "pkg.whl"
        _write_wheel(wheel, mode=0o644, date=(2020, 1, 2, 3, 4, 6), reverse=False)

        assert _run(wheel, epoch="0").returncode == 0

        with zipfile.ZipFile(wheel) as zf:
            assert {info.date_time for info in zf.infolist()} == {(1980, 1, 1, 0, 0, 0)}

    def test_odd_second_epoch_floors_to_the_zip_field_resolution(self, tmp_path: Path) -> None:
        wheel = tmp_path / "pkg.whl"
        _write_wheel(wheel, mode=0o644, date=(2020, 1, 2, 3, 4, 6), reverse=False)

        assert _run(wheel, epoch=str(EPOCH + 1)).returncode == 0

        # The DOS time field holds seconds in pairs, so the odd second the
        # sdist records exactly is unreachable in a zip.  What is stored is
        # the even second below it, which a reader gets back verbatim.
        with zipfile.ZipFile(wheel) as zf:
            assert {info.date_time for info in zf.infolist()} == {(2023, 11, 14, 22, 13, 20)}

    def test_far_future_epoch_clamps_to_the_zip_ceiling(self, tmp_path: Path) -> None:
        wheel = tmp_path / "pkg.whl"
        _write_wheel(wheel, mode=0o644, date=(2020, 1, 2, 3, 4, 6), reverse=False)

        assert _run(wheel, epoch=str(4_000_000_000_000)).returncode == 0

        with zipfile.ZipFile(wheel) as zf:
            assert {info.date_time for info in zf.infolist()} == {(2107, 12, 31, 23, 59, 58)}

    def test_missing_epoch_fails_loud(self, tmp_path: Path) -> None:
        wheel = tmp_path / "pkg.whl"
        _write_wheel(wheel, mode=0o644, date=(2020, 1, 2, 3, 4, 6), reverse=False)
        before = wheel.read_bytes()

        result = _run(wheel, epoch=None)

        assert result.returncode != 0
        assert "SOURCE_DATE_EPOCH" in result.stderr
        assert wheel.read_bytes() == before

    def test_unknown_suffix_fails_loud(self, tmp_path: Path) -> None:
        other = tmp_path / "pkg.zip"
        other.write_bytes(b"not a wheel")

        result = _run(other)

        assert result.returncode != 0
        assert "expected a .tar.gz sdist or a .whl" in result.stderr


class TestArchiveOnDiskMode:
    """The rewritten archive itself, not just the modes recorded inside it.

    Both normalizers write through a sibling mkstemp file and rename it over
    the artifact.  mkstemp creates 0600 and the rename carries that onto the
    result, so the wheel used to ship 0600 while the sdist followed the
    caller's umask, contradicting the umask 022 ``make build`` pins and the
    umask=022 line in dist/rebrew.buildinfo.
    """

    @staticmethod
    def _mode(path: Path) -> int:
        return stat.S_IMODE(path.stat().st_mode)

    def test_wheel_is_readable_after_normalize(self, tmp_path: Path) -> None:
        wheel = tmp_path / "pkg.whl"
        _write_wheel(wheel, mode=0o644, date=(2020, 1, 2, 3, 4, 6), reverse=False)

        assert _run(wheel).returncode == 0

        assert self._mode(wheel) == 0o644

    def test_sdist_is_readable_after_normalize(self, tmp_path: Path) -> None:
        sdist = tmp_path / "pkg.tar.gz"
        _write_sdist(sdist, mode=0o644, uid=0, mtime=1, reverse=False)

        assert _run(sdist).returncode == 0

        assert self._mode(sdist) == 0o644
