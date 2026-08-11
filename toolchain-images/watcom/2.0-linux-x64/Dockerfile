# Open Watcom 2.0 (C) — x86 32-bit codegen compiler (native Linux).
#
# Uses the CI snapshot tarball: the official self-extracting installer
# SIGFPEs on modern glibc (known issue), but `ow-snapshot.tar.xz` from the
# Last-CI-build release is a plain archive that extracts cleanly.
#
# Build:  docker build -t rebrew/watcom:2.0-linux-x64 toolchain-images/watcom/2.0-linux-x64
# Invoke: docker run --rm -v "$PWD":/work -w /work rebrew/watcom:2.0-linux-x64 wcc386 ...

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

RUN curl -sL -o /tmp/ow.tar.xz \
        "https://github.com/open-watcom/open-watcom-v2/releases/download/Last-CI-build/ow-snapshot.tar.xz" \
    && mkdir -p /opt/watcom \
    && tar xJf /tmp/ow.tar.xz -C /opt/watcom --strip-components=1 \
    && rm /tmp/ow.tar.xz \
    && ls /opt/watcom/binl/wcc386

# wcc386 (32-bit x86, native) — rebrew's entrypoint.  Emits OMF objects by
# default (8086 relocatable); the OMF parser is the enabling follow-up.
ENV WATCOM=/opt/watcom \
    INCLUDE=/opt/watcom/h \
    PATH=/opt/watcom/binl:$PATH

ENTRYPOINT ["/opt/watcom/binl/wcc386"]
