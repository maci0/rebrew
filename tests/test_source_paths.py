"""Moved sources retain their original quoted-header providers."""

from pathlib import Path

from rebrew.source_paths import rebase_includes


def test_real_directives_move_without_touching_comments_or_strings(tmp_path: Path) -> None:
    (tmp_path / "local.h").write_text("int provider;\n")
    destination = tmp_path / "fragments"
    destination.mkdir()
    text = (
        '/* café\r\n#include "./local.h"\r\n*/\r\n'
        'const char *example = "#include \\"local.h\\"";\r\n'
        '#ifdef VERSION\r\n# include "local.h" /* provider */\r\n#endif\r\n'
        '#include <stdio.h>\r\n#include "missing.h"\r\n'
    )
    result = rebase_includes(text, tmp_path, destination)
    assert result == text.replace('# include "local.h"', '# include "../local.h"')
    assert (destination / "../local.h").resolve() == (tmp_path / "local.h").resolve()


def test_existing_parent_relative_headers_keep_the_same_provider(tmp_path: Path) -> None:
    original = tmp_path / "original"
    original.mkdir()
    destination = tmp_path / "new" / "nested"
    destination.mkdir(parents=True)
    header = tmp_path / "shared.h"
    header.write_text("int shared;\n")
    result = rebase_includes('#include "../shared.h"\n', original, destination)
    assert result == '#include "../../shared.h"\n'
