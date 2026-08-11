# MSVC 1.52 — 16-bit compiler (Phar Lap TNT CL under DOSBox).
#
# The image encapsulates the DOSBox sandbox: BIN/INCLUDE/LIB are baked in
# and the `cl16` wrapper stages them into a fresh C: drive, runs
# CL.EXE /c headless, and writes the .OBJ back to the mounted /work.
#
# Build:  docker build -t rebrew/msvc:1.52-linux-x64 toolchain-images/msvc/1.52-linux-x64
# Invoke: docker run --rm -v "$PWD":/work -w /work rebrew/msvc:1.52-linux-x64 /c test.c  (ENTRYPOINT is the cl16 wrapper)

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends dosbox \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Vendored MSVC 1.52 command-line tree (archive.org en_vc152_202512).
COPY msvc152/ /opt/msvc152/

# The `cl16` wrapper: stage BIN/INCLUDE/LIB into a fresh DOSBox C: drive,
# run CL /c headless with the caller's flags, copy the .OBJ + log back to
# /work.  The source is staged under a short 8.3-safe name because CL 1.52
# (16-bit) cannot open long filenames inside DOSBox (see cl16-wrapper.sh).
COPY cl16-wrapper.sh /usr/local/bin/cl16
RUN chmod +x /usr/local/bin/cl16

ENV SDL_VIDEODRIVER=dummy

ENTRYPOINT ["/usr/local/bin/cl16"]
