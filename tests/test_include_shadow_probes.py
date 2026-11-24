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


class TestPersistentIncludeClosures:
    @pytest.mark.parametrize("change", ["version", "resolver", "truncated", "corrupt", "config"])
    def test_cache_misses_for_foreign_inputs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
    ) -> None:
        from unittest.mock import patch

        early, late = tmp_path / "early", tmp_path / "late"
        early.mkdir()
        late.mkdir()
        (early / "api.h").write_text("int early;\n")
        (late / "api.h").write_text("int late;\n")
        path = tmp_path / "closures.json"
        source = "#include <api.h>\n"
        dirs = [str(early), str(late)]
        with cache.include_closure_cache(path):
            before = cache.header_dependency_hash(source, None, dirs)
        raw = path.read_bytes()

        if change == "version":
            path.write_bytes(b"old-version\n" + raw.split(b"\n", 1)[1])
        elif change == "resolver":
            # A development install keeps its release number when the resolver changes.
            edited = tmp_path / "cache.py"
            edited.write_bytes(Path(cache.__file__).read_bytes() + b"\n# edited\n")
            monkeypatch.setattr(cache, "__file__", str(edited))
        elif change == "truncated":
            path.write_bytes(raw[:-1])
        elif change == "corrupt":
            # Still valid JSON, with a missing winner proof.
            path.write_bytes(raw.replace(b'"winner"', b'"missing"', 1))
        else:
            dirs.reverse()

        monkeypatch.setattr(cache, "_INCLUDE_CLOSURE_MEMO", {})
        monkeypatch.setattr(cache, "_include_closure_memo_chars", 0)
        with (
            patch.object(cache, "scan_include_closure", wraps=cache.scan_include_closure) as scan,
            cache.include_closure_cache(path),
        ):
            after = cache.header_dependency_hash(source, None, dirs)
        assert scan.call_count == 2
        assert (after != before) == (change == "config")

    @pytest.mark.skipif(os.name != "posix", reason="Uses symlinks")
    @pytest.mark.parametrize(
        "change",
        [
            "shadow",
            "rename",
            "retarget",
            "dir-retarget",
            "contents",
            "missing",
            "escape",
            "collision",
        ],
    )
    def test_revalidates_in_fresh_process(self, tmp_path: Path, change: str) -> None:
        import subprocess
        import sys

        early = tmp_path / "early" / "deep" / "nested"
        late = tmp_path / "late" / "deep" / "nested"
        early.mkdir(parents=True)
        late.mkdir(parents=True)
        api = late / "api.h"
        api.write_text('#include "old.h"\n#include "unavailable.h"\n')
        (late / "old.h").write_text("int old_value;\n")
        (late / "new.h").write_text("int new_value;\n")
        alternate = tmp_path / "alternate.h"
        alternate.write_text("int alternate;\n")
        alias = late / "alias.h"
        alias.symlink_to(api.name)
        source = "#include <deep/nested/alias.h>\n#include <deep/nested/optional.h>\n"
        if change == "dir-retarget":
            early.rmdir()
            empty = tmp_path / "empty"
            empty.mkdir()
            early.symlink_to(empty, target_is_directory=True)
        if change == "escape":
            source = "#include <../optional.h>\n"
        script = tmp_path / "fingerprint.py"
        script.write_text(
            """import sys
from pathlib import Path
from unittest.mock import patch

from rebrew.compiler import cache

root = Path(sys.argv[1])
mode = sys.argv[2]
source = sys.argv[3]
dirs = [str(root / "early"), str(root / "late")]
with patch.object(cache, "scan_include_closure", wraps=cache.scan_include_closure) as scan:
    if mode == "fresh":
        print(cache.header_dependency_hash(source, None, dirs))
    else:
        with cache.include_closure_cache(root / "closures.json"):
            print(cache.header_dependency_hash(source, None, dirs))
    print(scan.call_count)
"""
        )

        def run(mode: str) -> tuple[str, int]:
            digest, scans = subprocess.check_output(
                [sys.executable, str(script), str(tmp_path), mode, source], text=True
            ).splitlines()
            return digest, int(scans)

        before, scans = run("write")
        assert scans == 2
        assert run("hit") == (before, 0)
        directory = {
            "shadow": early,
            "rename": late.parent,
            "dir-retarget": early.parent,
            "missing": early,
            "escape": tmp_path,
            "collision": early,
        }.get(change, late)
        original = directory.stat()
        if change == "shadow":
            (early / "alias.h").symlink_to(api)
            (early / "old.h").write_text("int shadow;\n")
        elif change == "rename":
            late.rename(late.with_name("NESTED"))
            if late.exists():
                pytest.skip("case-sensitive paths required")
        elif change == "retarget":
            alias.unlink()
            alias.symlink_to(alternate)
        elif change == "dir-retarget":
            backing = tmp_path / "backing"
            backing.mkdir()
            (backing / "alias.h").symlink_to(api)
            (backing / "old.h").write_text("int new_parent;\n")
            early.unlink()
            early.symlink_to(backing, target_is_directory=True)
        elif change == "contents":
            header_stat = api.stat()
            api.write_text('#include "new.h"\n#include "unavailable.h"\n')
            os.utime(api, ns=(header_stat.st_atime_ns, header_stat.st_mtime_ns))
        elif change == "missing":
            (early / "optional.h").write_text("int found;\n")
        elif change == "collision":
            (early / "alias.h").symlink_to(alternate)
            (late / "unavailable.h").touch()
            if (late / "UNAVAILABLE.H").exists():
                pytest.skip("case-sensitive paths required")
            (late / "UNAVAILABLE.H").touch()
        else:
            (tmp_path / "optional.h").write_text("int escaped;\n")
        os.utime(directory, ns=(original.st_atime_ns, original.st_mtime_ns))

        after, scans = run("fresh")
        assert scans == 2
        assert after != before
        assert run("changed") == (after, 2)
        assert run("hit") == (after, 0)
