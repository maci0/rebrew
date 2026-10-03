"""Static archive iteration and stock-library cache paths shared by analysis tools."""

from collections.abc import Iterator
from pathlib import Path


def parse_archive(lib_path: str) -> Iterator[tuple[str, bytes]]:
    """Parse an ar archive (.lib / .a) and yield (member_name, obj_data).

    The ``!<arch>`` layout is shared by MSVC COFF .lib files and GNU/IDO
    ELF .a archives; the special ``/`` (symbol index) and ``//`` (long-name
    table) members are skipped. COFF NUL-terminated and GNU ``/\n``-terminated
    long names are resolved before yielding their object bodies.
    """
    data = Path(lib_path).read_bytes()

    if not data.startswith(b"!<arch>\n"):
        raise ValueError(f"{lib_path} is not a valid archive")

    pos = 8
    long_names = b""
    while pos < len(data):
        if pos % 2 == 1:
            pos += 1
        if pos + 60 > len(data):
            break

        header = data[pos : pos + 60]
        name_field = header[0:16].rstrip(b" ")
        try:
            size = int(header[48:58].strip())
        except ValueError:
            break

        pos += 60
        member_data = data[pos : pos + size]
        pos += size

        raw_name = name_field.decode("ascii", errors="replace")
        if raw_name == "//":
            long_names = member_data
            continue
        name = raw_name.rstrip("/")
        if not name:
            continue
        if name.startswith("/") and name[1:].isdigit():
            offset = int(name[1:])
            if offset >= len(long_names):
                raise ValueError(f"{lib_path}: invalid long-name offset {offset}")
            tail = long_names[offset:]
            endings = [end for delimiter in (b"\0", b"/\n") if (end := tail.find(delimiter)) >= 0]
            if not endings or min(endings) == 0:
                raise ValueError(f"{lib_path}: invalid long name at offset {offset}")
            name = tail[: min(endings)].decode("ascii", errors="replace")

        yield name, member_data


def stock_lib_cache(root: Path, name: str, profile: str) -> Path:
    """Where a stock archive is cached: ``.scratch/<profile>_<stem>_stock<suffix>``.

    The profile is part of the path because the archive's bytes come out of
    that toolchain's image, and nothing downstream can tell one image's
    ``LIBCMT.LIB`` from another's: a path keyed on the name alone kept the
    first profile's extraction forever (``ensure_stock_lib`` accepts any
    existing file), so a later profile read the wrong archive — ``todo``
    filtered its work list against another toolchain's library code, and
    ``assert_library_is_stock`` compared the image's copy against a file from
    a different image.
    """
    return root / ".scratch" / f"{profile}_{Path(name).stem.lower()}_stock{Path(name).suffix}"
