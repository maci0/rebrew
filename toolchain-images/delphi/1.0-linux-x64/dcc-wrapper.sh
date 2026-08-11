#!/bin/sh
# dcc wrapper — stage the Delphi 1.0 toolchain into a fresh DOSBox C:
# drive, run DCC headless, copy the produced EXE + log to /work.
# DOSBox FAT-uppercases outputs (HELLO.EXE, DCCOUT.TXT).
# DCC is a 16-bit DOS program: a long source basename would be
# 8.3-truncated in DOSBox ("Error 15: File not found"), so the source is
# staged under the fixed short name SRC.DPR and the produced SRC.EXE is
# copied back under the original basename's stem so callers get a
# predictable output name.
set -e
src="$1"
shift || true
sandbox=$(mktemp -d /tmp/dcc.XXXXXX)
cp -r /opt/delphi10/. "$sandbox"/
cp "$src" "$sandbox/SRC.DPR" 2>/dev/null || { echo "dcc: cannot read source '$src'" >&2; exit 1; }
printf '/m\n/cw\n/rC:\\DELPHI\\LIB\n/uC:\\DELPHI\\LIB\n/iC:\\DELPHI\\LIB\n' > "$sandbox/DCC.CFG"
cat > "$sandbox/dcc.conf" <<EOF
[sdl]
fullscreen=false

[cpu]
cycles=fixed 30000

[autoexec]
mount c $sandbox
C:
cd \\
C:\\DCC.EXE SRC.DPR > C:\\dccout.txt
exit
EOF
SDL_VIDEODRIVER=dummy dosbox -conf "$sandbox/dcc.conf" -noconsole >/dev/null 2>&1 || true
cp "$sandbox"/DCCOUT.TXT /work/dccout.txt 2>/dev/null || true
if [ -f "$sandbox/SRC.EXE" ]; then
    stem=$(basename "$src")
    stem="${stem%.*}"
    cp "$sandbox/SRC.EXE" "/work/${stem}.EXE"
else
    echo "dcc: DCC produced no executable (log: /work/dccout.txt)" >&2
    cat "$sandbox/DCCOUT.TXT" 2>/dev/null >&2 || true
    exit 1
fi
rm -rf "$sandbox"
