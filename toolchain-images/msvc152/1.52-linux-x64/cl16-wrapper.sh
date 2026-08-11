#!/bin/sh
# cl16 wrapper — stage the vendored MSVC 1.52 tree into a fresh DOSBox
# C: drive and run CL.EXE headless.
#
# Invoke:  cl16 <source.c> [flags...]
#
# Design notes:
# - CL 1.52 is a 16-bit Phar Lap DOS program: it cannot open long
#   filenames (DOSBox 8.3-truncates them, C1083).  The source is
#   staged under the fixed short name SRC.C, and the produced object
#   is copied back to /work as <source-stem>.OBJ so callers get a
#   predictable name (DOSBox FAT-uppercases on write).
# - All args after the source are forwarded to CL verbatim, so the GA
#   flag sweep (/O1, /Gs, ...) actually reaches the compiler.
# - INCLUDE/LIB point at the vendored tree baked into the image.
set -e
src="$1"
shift || true
flags="$@"
stem=$(basename "$src")
stem="${stem%.*}"

sandbox=$(mktemp -d /tmp/cl16.XXXXXX)
trap 'rm -rf "$sandbox"' EXIT

cp -r /opt/msvc152/. "$sandbox"/
cp "$src" "$sandbox/SRC.C" 2>/dev/null || {
    echo "cl16: cannot read source file '$src'" >&2
    exit 1
}

printf '[sdl]\nfullscreen=false\n[cpu]\ncycles=fixed 30000\n[autoexec]\nmount c %s\nC:\ncd \\\nset INCLUDE=C:\\INCLUDE\nset LIB=C:\\LIB\nC:\\BIN\\CL.EXE /nologo /c %s SRC.C > C:\\clout.txt\nexit\n' \
    "$sandbox" "$flags" > "$sandbox/cl16.conf"

SDL_VIDEODRIVER=dummy dosbox -conf "$sandbox/cl16.conf" -noconsole >/dev/null 2>&1 || true

cp "$sandbox"/CLOUT.TXT /work/clout.txt 2>/dev/null || true
if [ -f "$sandbox/SRC.OBJ" ]; then
    cp "$sandbox/SRC.OBJ" "/work/${stem}.OBJ"
    exit 0
fi

echo "cl16: CL produced no object for ${stem} (log in /work/clout.txt)" >&2
cat "$sandbox/CLOUT.TXT" 2>/dev/null >&2 || true
exit 1
