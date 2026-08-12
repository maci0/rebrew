# Open Watcom 2.0 (C) — x86 32-bit codegen compiler (native Linux).
#
# Inherits the shared rebrew/base (debian + wine + dosbox + common wrappers);
# this image adds the Open Watcom 2.0 snapshot (CI tarball — the official
# self-extracting installer SIGFPEs on modern glibc, known issue) and uses
# wcc386 directly as the entrypoint.
#
# Build:  docker build -t rebrew/watcom:2.0-win32 toolchain/watcom/2.0-win32
# Invoke: docker run --rm -v "$PWD":/work -w /work rebrew/watcom:2.0-win32 -c -o out.o f.c  (ENTRYPOINT is wcc386)

FROM rebrew/base:1.0

WORKDIR /opt

COPY binl/ /opt/watcom/binl/
COPY h/ /opt/watcom/h/
COPY lib386/ /opt/watcom/lib386/

# wcc386 (32-bit x86, native) — rebrew's entrypoint.  Emits OMF objects by
# default (8086 relocatable); the OMF parser is the enabling follow-up.
ENV WATCOM=/opt/watcom \
    INCLUDE=/opt/watcom/h \
    PATH=/opt/watcom/binl:$PATH

ENTRYPOINT ["/opt/watcom/binl/wcc386"]
