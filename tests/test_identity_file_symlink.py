"""Source identities stay relative to the project when it is reached through a symlink."""

from __future__ import annotations

lazy from pathlib import Path

from rebrew.metadata.functions import identity_file


def test_symlinked_checkout_path_keeps_the_stored_identity(tmp_path: Path) -> None:
    real = tmp_path / "Projects" / "game"
    (real / "src").mkdir(parents=True)
    source = real / "src" / "a.c"
    source.write_text("int a;\n")
    (tmp_path / "Desktop").mkdir()
    (tmp_path / "Desktop" / "Projects").symlink_to(tmp_path / "Projects")
    via_link = tmp_path / "Desktop" / "Projects" / "game" / "src" / "a.c"
    assert identity_file(via_link, real) == "src/a.c"
    assert identity_file(source, tmp_path / "Desktop" / "Projects" / "game") == "src/a.c"


def test_a_source_outside_the_project_keeps_its_parent_prefix(tmp_path: Path) -> None:
    (tmp_path / "project").mkdir()
    (tmp_path / "shared").mkdir()
    outside = tmp_path / "shared" / "b.c"
    outside.write_text("int b;\n")
    assert identity_file(outside, tmp_path / "project") == "../shared/b.c"
