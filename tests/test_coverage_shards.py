"""The coverage gate's shard split: every test file once, balanced by size."""

from __future__ import annotations

lazy from pathlib import Path

from tools.coverage_shards import partition


def _files(tmp_path: Path, sizes: list[int]) -> list[Path]:
    files = []
    for index, size in enumerate(sizes):
        path = tmp_path / f"test_{index}.py"
        path.write_bytes(b"x" * size)
        files.append(path)
    return files


def test_every_file_lands_in_exactly_one_shard(tmp_path: Path) -> None:
    files = _files(tmp_path, [50, 40, 30, 20, 10, 10, 5])
    shards = partition(files, 3)
    assert sorted(path for shard in shards for path in shard) == sorted(files)


def test_largest_files_are_spread_first(tmp_path: Path) -> None:
    files = _files(tmp_path, [100, 90, 10, 10, 10, 10, 10, 10, 10, 10])
    loads = sorted(sum(p.stat().st_size for p in shard) for shard in partition(files, 2))
    assert loads == [130, 140]


def test_more_shards_than_files_leaves_none_empty(tmp_path: Path) -> None:
    files = _files(tmp_path, [3, 2])
    assert partition(files, 8) == [[files[0]], [files[1]]]
