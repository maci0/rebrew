"""Vendored trees must reproduce their pinned originals and ordered patches."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.vendor import VendorError, app, vendor_trees

PRISTINE = "int f(void)\n{\n    return 1;\n}\n"
PATCH = """--- a/f.c
+++ b/f.c
@@ -1,4 +1,4 @@
 int f(void)
 {
-    return 1;
+    return 2;
 }
"""


def _tree(root: Path, name: str = "lib") -> Path:
    original = root / f"{name}-1"
    original.mkdir()
    (original / "f.c").write_text(PRISTINE)
    manifest = root / f"{name}.toml"
    manifest.write_text(
        f'name = "{name}"\nversion = "1"\nurl = "https://example.invalid/lib.tar.gz"\n'
        f'sha256 = "{"0" * 64}"\npristine = "{name}-1"\nchecksums = "{name}.sha256"\n'
        f'output = "{name}"\nfiles = ["f.c"]\npatches = ["{name}.patch"]\n'
    )
    digest = hashlib.sha256(PRISTINE.encode()).hexdigest()
    (root / f"{name}.sha256").write_text(f"{digest}  {name}-1/f.c\n")
    (root / f"{name}.patch").write_text(PATCH)
    vendor_trees(root, [manifest], write=True)
    return manifest


def _replace(manifest: Path, before: str, after: str) -> None:
    text = manifest.read_text()
    assert before in text
    manifest.write_text(text.replace(before, after))


class TestVendor:
    def test_sync_and_check_cli(self, tmp_path: Path) -> None:
        manifest = _tree(tmp_path)
        assert "return 2;" in (tmp_path / "lib/f.c").read_text()
        result = CliRunner().invoke(app, ["--root", str(tmp_path), "--json", str(manifest)])
        assert result.exit_code == 0, result.output
        report = json.loads(result.stdout)["libraries"][0]
        assert report["mode"] == "check" and report["files"] == report["patches"] == 1
        (tmp_path / "lib/extra.c").write_text("extra")
        (tmp_path / "lib/f.c").write_text("edited")
        result = CliRunner().invoke(app, ["--root", str(tmp_path), "--apply", str(manifest)])
        assert result.exit_code == 0, result.output
        assert not (tmp_path / "lib/extra.c").exists()
        assert "return 2;" in (tmp_path / "lib/f.c").read_text()

    @pytest.mark.parametrize("change", ["edited", "extra", "missing"])
    def test_output_drift(self, tmp_path: Path, change: str) -> None:
        manifest = _tree(tmp_path)
        if change == "edited":
            (tmp_path / "lib/f.c").write_text(PRISTINE)
        elif change == "extra":
            (tmp_path / "lib/extra.c").write_text("")
        else:
            (tmp_path / "lib/f.c").unlink()
        before = {p: p.read_bytes() for p in (tmp_path / "lib").rglob("*") if p.is_file()}
        result = CliRunner().invoke(app, ["--root", str(tmp_path), "--json", str(manifest)])
        assert result.exit_code == 1 and "error" in json.loads(result.stdout)
        assert before == {p: p.read_bytes() for p in (tmp_path / "lib").rglob("*") if p.is_file()}

    @pytest.mark.parametrize("change", ["modified", "extra", "missing", "unpinned"])
    def test_pristine_drift(self, tmp_path: Path, change: str) -> None:
        manifest = _tree(tmp_path)
        if change == "modified":
            (tmp_path / "lib-1/f.c").write_text("changed")
        elif change == "extra":
            (tmp_path / "lib-1/extra.c").write_text("")
        elif change == "missing":
            (tmp_path / "lib-1/f.c").unlink()
        else:
            (tmp_path / "lib.sha256").write_text("")
        with pytest.raises(VendorError):
            vendor_trees(tmp_path, [manifest], write=True)
        assert "return 2;" in (tmp_path / "lib/f.c").read_text()

    def test_bad_patch_stages_all_before_writing(self, tmp_path: Path) -> None:
        first = _tree(tmp_path)
        second = _tree(tmp_path, "second")
        (tmp_path / "lib/f.c").write_text("preserve local edits")
        (tmp_path / "second.patch").write_text(PATCH.replace("-    return 1;", "-    return 9;"))
        with pytest.raises(VendorError, match="does not apply"):
            vendor_trees(tmp_path, [first, second], write=True)
        assert (tmp_path / "lib/f.c").read_text() == "preserve local edits"

    @pytest.mark.parametrize("kind", ["extra", "deleted"])
    def test_patch_cannot_change_file_inventory(self, tmp_path: Path, kind: str) -> None:
        manifest = _tree(tmp_path)
        patch = "--- /dev/null\n+++ b/extra.c\n@@ -0,0 +1 @@\n+extra\n"
        if kind == "deleted":
            patch = "--- a/f.c\n+++ /dev/null\n@@ -1,4 +0,0 @@\n" + "".join(
                f"-{line}\n" for line in PRISTINE.splitlines()
            )
        (tmp_path / "lib.patch").write_text(patch)
        with pytest.raises(VendorError, match="exactly the listed files"):
            vendor_trees(tmp_path, [manifest], write=True)
        assert "return 2;" in (tmp_path / "lib/f.c").read_text()

    @pytest.mark.parametrize(
        ("before", "after"),
        [
            ('files = ["f.c"]', 'files = "f.c"'),
            ('files = ["f.c"]', "files = [4]"),
            ('files = ["f.c"]', "files = []"),
            ('files = ["f.c"]', 'files = ["f.c", "f.c"]'),
            ('files = ["f.c"]', 'files = ["../f.c"]'),
            ('output = "lib"', 'output = "../escape"'),
            ('patches = ["lib.patch"]', 'patches = ["../escape.patch"]'),
            ('name = "lib"', "name = 1"),
            (f'sha256 = "{"0" * 64}"', 'sha256 = "bad"'),
        ],
    )
    def test_manifest_validation(self, tmp_path: Path, before: str, after: str) -> None:
        manifest = _tree(tmp_path)
        _replace(manifest, before, after)
        with pytest.raises(VendorError):
            vendor_trees(tmp_path, [manifest], write=True)

    @pytest.mark.parametrize("record", ["bad", "g" * 64 + "  lib-1/f.c", "0" * 64 + "  ../f.c"])
    def test_bad_checksums(self, tmp_path: Path, record: str) -> None:
        manifest = _tree(tmp_path)
        (tmp_path / "lib.sha256").write_text(record + "\n")
        with pytest.raises(VendorError):
            vendor_trees(tmp_path, [manifest], write=True)

    def test_duplicate_checksum(self, tmp_path: Path) -> None:
        manifest = _tree(tmp_path)
        checksum = tmp_path / "lib.sha256"
        checksum.write_text(checksum.read_text() * 2)
        with pytest.raises(VendorError, match="duplicate checksum"):
            vendor_trees(tmp_path, [manifest])

    @pytest.mark.parametrize("output", ["lib-1", "lib-1/subdir", "second", "."])
    def test_protect_inputs_and_other_outputs(self, tmp_path: Path, output: str) -> None:
        manifest = _tree(tmp_path)
        second = _tree(tmp_path, "second")
        _replace(manifest, 'output = "lib"', f'output = "{output}"')
        with pytest.raises(VendorError):
            vendor_trees(tmp_path, [manifest, second], write=True)
        assert (tmp_path / "lib-1/f.c").read_text() == PRISTINE

    @pytest.mark.parametrize("path", ["lib/f.c", "lib-1/f.c", "lib.patch"])
    def test_symlinks_rejected(self, tmp_path: Path, path: str) -> None:
        manifest = _tree(tmp_path)
        victim = tmp_path / "victim"
        victim.write_text("preserve")
        linked = tmp_path / path
        linked.unlink()
        linked.symlink_to(victim)
        with pytest.raises(VendorError, match="symlinks"):
            vendor_trees(tmp_path, [manifest], write=True)
        assert victim.read_text() == "preserve"

    def test_no_patch_needed(self, tmp_path: Path) -> None:
        manifest = _tree(tmp_path)
        _replace(manifest, 'patches = ["lib.patch"]', "patches = []")
        vendor_trees(tmp_path, [manifest], write=True)
        assert (tmp_path / "lib/f.c").read_text() == PRISTINE

    def test_explicit_root_and_relative_manifest(self, tmp_path: Path) -> None:
        _tree(tmp_path)
        result = CliRunner().invoke(app, ["--root", str(tmp_path), "lib.toml"])
        assert result.exit_code == 0, result.output
        assert "lib: 1 patches, check ok" in result.output

    def test_io_failure_has_json_error(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(app, ["--root", str(tmp_path), "--json", "missing.toml"])
        assert result.exit_code == 2 and "error" in json.loads(result.stdout)

    def test_nested_files_and_shared_checksums(self, tmp_path: Path) -> None:
        manifest = _tree(tmp_path)
        original = tmp_path / "lib-1"
        (original / "include").mkdir()
        (original / "include/f.h").write_text("int f(void);\n")
        digest = hashlib.sha256((original / "include/f.h").read_bytes()).hexdigest()
        checksum = tmp_path / "lib.sha256"
        checksum.write_text(checksum.read_text() + f"{digest}  lib-1/include/f.h\n")
        _replace(manifest, 'files = ["f.c"]', 'files = ["f.c", "include/f.h"]')
        second = tmp_path / "headers.toml"
        second.write_text(manifest.read_text().replace('output = "lib"', 'output = "headers"'))
        vendor_trees(tmp_path, [manifest, second], write=True)
        assert (tmp_path / "lib/include/f.h").read_bytes() == (
            tmp_path / "headers/include/f.h"
        ).read_bytes()
        vendor_trees(tmp_path, [manifest, second])

    def test_missing_patch_tool_reports_infrastructure_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        manifest = _tree(tmp_path)

        def unavailable(*args: object, **kwargs: object) -> None:
            raise FileNotFoundError("GNU patch is missing")

        monkeypatch.setattr("rebrew.vendor.subprocess.run", unavailable)
        result = CliRunner().invoke(app, ["--root", str(tmp_path), "--json", str(manifest)])
        assert result.exit_code == 2 and "GNU patch" in json.loads(result.stdout)["error"]

    def test_output_must_be_a_directory(self, tmp_path: Path) -> None:
        manifest = _tree(tmp_path)
        _replace(manifest, 'output = "lib"', 'output = "lib.patch"')
        with pytest.raises(VendorError):
            vendor_trees(tmp_path, [manifest], write=True)
        assert (tmp_path / "lib.patch").read_text() == PATCH
