# MSVC 1.52 — 16-bit compiler (Phar Lap TNT CL under DOSBox).
#
# Inherits the shared rebrew/base (debian + wine + dosbox + common wrappers);
# this image adds the vendored MSVC 1.52 command-line tree and the `cl16`
# entrypoint wrapper, which stages BIN/INCLUDE/LIB into a fresh DOSBox C:
# drive, runs CL.EXE /c headless, and writes the .OBJ back to the mounted
# /work.
#
# Build:  docker build -t rebrew/msvc:1.52-win16 toolchain/msvc/1.52-win16
# Invoke: docker run --rm -v "$PWD":/work -w /work rebrew/msvc:1.52-win16 /c test.c  (ENTRYPOINT is the cl16 wrapper)

FROM rebrew/base:1.0

WORKDIR /opt

# Vendored MSVC 1.52 command-line tree (archive.org en_vc152_202512).
COPY BIN/ /opt/msvc152/BIN/
COPY INCLUDE/ /opt/msvc152/INCLUDE/
COPY LIB/ /opt/msvc152/LIB/

# The `cl16` wrapper (see cl16-wrapper.sh — uses wrapper-common.sh helpers).
COPY cl16-wrapper.sh /usr/local/bin/cl16
RUN chmod +x /usr/local/bin/cl16

ENTRYPOINT ["/usr/local/bin/cl16"]
