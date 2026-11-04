"""Static archive iteration and stock-library cache paths shared by analysis tools."""

import re
lazy from collections.abc import Iterator
lazy from pathlib import Path

_LONG_NAME_END = re.compile(b"\0|/\n")


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
        if size < 0:
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
            ending = _LONG_NAME_END.search(long_names, offset)
            if ending is None or ending.start() == offset:
                raise ValueError(f"{lib_path}: invalid long name at offset {offset}")
            name = long_names[offset : ending.start()].decode("ascii", errors="replace")

        yield name, member_data


def stock_lib_cache(root: Path, name: str, profile: str) -> Path:
    """Where a stock archive is cached: ``.scratch/<profile>_<stem>_stock<suffix>``.

    The profile is part of the path because the archive's bytes come out of
    that toolchain's image, and nothing downstream can tell one image's
    ``LIBCMT.LIB`` from another's: a path keyed on the name alone kept the
    first profile's extraction forever, so a later profile read the wrong
    archive — ``todo`` filtered its work list against another toolchain's
    library code, and ``assert_library_is_stock`` compared the image's copy
    against a file from a different image.
    """
    return root / ".scratch" / f"{profile}_{Path(name).stem.lower()}_stock{Path(name).suffix}"


def stock_lib_valid(path: Path) -> bool:
    """True when *path* is a structurally complete ``ar`` archive.

    A cached extraction is reused by every later run, so a copy interrupted
    mid-transfer, a truncated file, or a hand-edited archive must not be
    treated as the toolchain's library: indexing a short archive drops the
    members that identify library code, and those functions are then
    recommended as game code.  Walk the member headers without reading the
    members and reject a file that ends inside one.
    """
    try:
        file_size = path.stat().st_size
        with path.open("rb") as stream:
            if stream.read(8) != b"!<arch>\n":
                return False
            position = 8
            members = 0
            while position < file_size:
                if position % 2:
                    position += 1
                if position >= file_size:
                    # The final member had odd length; ar pads it with one
                    # byte, which is alignment rather than another header.
                    break
                if position + 60 > file_size:
                    return False
                stream.seek(position)
                header = stream.read(60)
                if len(header) != 60:
                    return False
                try:
                    member_size = int(header[48:58].strip())
                except ValueError:
                    return False
                if member_size < 0:
                    return False
                position += 60
                if position + member_size > file_size:
                    return False
                position += member_size
                members += 1
            return members > 0 or file_size == 8
    except OSError:
        return False
