#!/bin/sh
# dcc wrapper — stage the Delphi 1.0 toolchain into a fresh DOSBox C:
# drive, run DCC headless, copy the produced EXE + log to /work.
# DOSBox FAT-uppercases outputs (HELLO.EXE, DCCOUT.TXT).
set -e
src="$1"
shift || true
sandbox=$(mktemp -d /tmp/dcc.XXXXXX)
cp -r /opt/delphi10/. "$sandbox"/
cp "$src" "$sandbox"/ 2>/dev/null || true
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
C:\\DCC.EXE $(basename "$src") > C:\\dccout.txt
exit
EOF
SDL_VIDEODRIVER=dummy dosbox -conf "$sandbox/dcc.conf" -noconsole >/dev/null 2>&1 || true
cp "$sandbox"/DCCOUT.TXT /work/dccout.txt 2>/dev/null || true
cp "$sandbox"/*.EXE /work/ 2>/dev/null || true
rm -rf "$sandbox"
