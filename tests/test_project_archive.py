"""Tests for ``rebrew.project_archive.unpack_project_archive`` bounds and formats."""

from __future__ import annotations

import io
import tarfile
import tracemalloc
import zipfile
lazy from pathlib import Path

import pytest

from rebrew.project_archive import ProjectArchiveError, unpack_project_archive

_PROJECT = {"rebrew-project.toml": b"[project]\n", "src/a.c": b"int a;\n"}


def _tar(members: dict[str, bytes], mode: str = "w", fmt: int = tarfile.PAX_FORMAT) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode, format=fmt) as archive:  # type: ignore[call-overload]
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _unpack(tmp_path: Path, data: bytes) -> Path:
    archive = tmp_path / "upload"
    archive.write_bytes(data)
    into = tmp_path / "into"
    into.mkdir()
    return unpack_project_archive(archive, into)


class TestFormats:
    @pytest.mark.parametrize("mode", ["w", "w:gz", "w:bz2", "w:xz", "w:zst"])
    def test_tar_compressions_unpack(self, tmp_path: Path, mode: str) -> None:
        root = _unpack(tmp_path, _tar(_PROJECT, mode))
        assert root == tmp_path / "into"
        assert (root / "src" / "a.c").read_bytes() == b"int a;\n"

    def test_files_larger_than_the_header_allowance_unpack(self, tmp_path: Path) -> None:
        files = {
            f"src/{size}.bin": bytes(range(256)) * (size // 256) for size in (0, 512, 300 << 10)
        }
        files |= {"src/odd.bin": b"x" * 511, "src/one.bin": b"y"}
        root = _unpack(tmp_path, _tar({**_PROJECT, **files}, "w:gz"))
        for name, data in files.items():
            assert (root / name).read_bytes() == data

    def test_zip_unpacks(self, tmp_path: Path) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, data in _PROJECT.items():
                archive.writestr(name, data)
        root = _unpack(tmp_path, buffer.getvalue())
        assert (root / "rebrew-project.toml").read_bytes() == b"[project]\n"

    def test_neither_tar_nor_zip_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ProjectArchiveError, match="neither a tar nor a zip"):
            _unpack(tmp_path, b"not an archive" * 100)


class TestHeaderBound:
    @pytest.mark.parametrize("fmt", [tarfile.GNU_FORMAT, tarfile.PAX_FORMAT], ids=["gnu", "pax"])
    def test_huge_name_header_is_refused_without_buffering_it(
        self, tmp_path: Path, fmt: int
    ) -> None:
        # A 4 MiB name compresses to a few KiB; tarfile reads a name header whole.
        # It comes first so the trace holds no earlier member's copy buffer.
        name_bytes = 4 << 20
        data = _tar({"a" * name_bytes: b"", **_PROJECT}, "w:gz", fmt)
        assert len(data) < 64 << 10
        # Resolve the module's lazy imports first so the trace sees only the unpack.
        (tmp_path / "warm").mkdir()
        _unpack(tmp_path / "warm", _tar(_PROJECT, "w:gz", fmt))
        tracemalloc.start()
        try:
            with pytest.raises(ProjectArchiveError, match="header"):
                _unpack(tmp_path, data)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert peak < name_bytes // 4


class TestNameBound:
    @pytest.mark.parametrize(
        "name",
        [
            "x" * 256,
            "é" * 128,  # 128 characters, 256 UTF-8 bytes
            "/".join(["d" * 200] * 6),
        ],
    )
    def test_overlong_name_is_refused(self, tmp_path: Path, name: str) -> None:
        with pytest.raises(ProjectArchiveError, match="longer than"):
            _unpack(tmp_path, _tar({**_PROJECT, name: b"x"}))

    def test_name_at_the_part_bound_unpacks(self, tmp_path: Path) -> None:
        root = _unpack(tmp_path, _tar({**_PROJECT, "x" * 255: b"x"}))
        assert (root / ("x" * 255)).read_bytes() == b"x"
