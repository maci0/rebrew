"""Tests for capturing and validating earlier include search misses."""

import os
from pathlib import Path
lazy from collections.abc import Sequence

import pytest

from rebrew.compiler import cache


class TestIncludeShadowProbes:
    @pytest.mark.parametrize("escaping", [False, True])
    def test_shadow_capture_walks_through_winner_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, escaping: bool
    ) -> None:
        tmp_path = tmp_path.resolve()
        early, late = tmp_path / "early" / "src", tmp_path / "late" / "src"
        early.mkdir(parents=True)
        late.mkdir(parents=True)
        header = (late.parent if escaping else late) / "api.h"
        header.write_text("int value;\n")
        name = "../api.h" if escaping else "api.h"
        walked: list[Path] = []
        walk = cache._walk_include_path_checked

        def counted(
            directory: Path, parts: Sequence[str], *, lexical: list[tuple[str, str]] | None
        ) -> Path | None:
            walked.append(directory)
            return walk(directory, parts, lexical=lexical)

        monkeypatch.setattr(cache, "_walk_include_path_checked", counted)
        shadows: list[tuple[str, str, tuple[str, ...]]] = []
        paths, fallback, _, consistent = cache.scan_include_closure(
            f"#include <{name}>\n", None, (str(early), str(late)), shadow=shadows
        )
        assert paths == (str(header),) and not fallback and consistent
        assert walked == [early, late]
        assert shadows[0] == ("escape" if escaping else "find", name, (str(early),))

    @pytest.mark.skipif(os.name != "posix", reason="Uses symlinks")
    def test_earlier_alias_to_same_header_changes_cached_quote_base(self, tmp_path: Path) -> None:
        tmp_path = tmp_path.resolve()
        early = tmp_path / "early" / "deep" / "nested"
        late = tmp_path / "late" / "deep" / "nested"
        early.mkdir(parents=True)
        late.mkdir(parents=True)
        header = late / "api.h"
        header.write_text('#include "child.h"\n')
        dirs = [str(tmp_path / "early"), str(tmp_path / "late")]
        source = "#include <deep/nested/api.h>\n"
        old_time = 1_000_000_000
        os.utime(early, ns=(old_time, old_time))
        root_stats = [Path(d).stat().st_mtime_ns for d in dirs]
        before = cache.header_dependency_hash(source, None, dirs)

        (early / "api.h").symlink_to(header)
        child = early / "child.h"
        child.write_text("int new_child;\n")
        os.utime(early, ns=(old_time, old_time))

        assert early.stat().st_mtime_ns == old_time
        assert [Path(d).stat().st_mtime_ns for d in dirs] == root_stats
        after = cache.header_dependency_hash(source, None, dirs)
        assert after != before
        paths, fallback, _, consistent = cache.scan_include_closure(source, None, tuple(dirs))
        assert paths == tuple(sorted((str(child), str(header))))
        assert not fallback and consistent
        child.write_text("int updated_child;\n")
        assert cache.header_dependency_hash(source, None, dirs) != after
