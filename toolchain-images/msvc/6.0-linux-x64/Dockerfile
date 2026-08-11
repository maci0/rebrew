# MSVC 6.0 — 32-bit PE compiler under wine (the flagship toolchain).
#
# The OmniBlade decomp.me msvcwin9x release carries the MSVC 6.0
# command-line toolchain (5 MB tarball); the image adds wine and exposes a
# `cl` wrapper that translates POSIX-ish argv into wine + MSVC calls.
#
# Build:  docker build -t rebrew/msvc:6.0-linux-x64 toolchain-images/msvc/6.0-linux-x64
# Invoke: docker run --rm -v "$PWD":/work -w /work rebrew/msvc:6.0-linux-x64 /c f.c  (ENTRYPOINT is the cl wrapper)

FROM debian:bookworm-slim

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates wine wine32 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# MSVC 6.0 command-line toolchain (Bin/Include/Lib — top-level in the tarball).
RUN curl -sL -o /tmp/msvc6.tar.gz \
        "https://github.com/OmniBlade/decomp.me/releases/download/msvcwin9x/msvc6.0.tar.gz" \
    && mkdir -p /opt/msvc6.0 \
    && tar xzf /tmp/msvc6.tar.gz -C /opt/msvc6.0 \
    && rm /tmp/msvc6.tar.gz \
    && ls /opt/msvc6.0/Bin/CL.EXE

# The `cl` wrapper: translate the MSVC-style argv (already msvc-shaped from
# rebrew) into `wine /opt/msvc6.0/bin/CL.EXE <args>` inside the mounted /work.
RUN printf '#!/bin/sh\nexec wine /opt/msvc6.0/bin/CL.EXE "$@"\n' > /usr/local/bin/cl \
    && chmod +x /usr/local/bin/cl

ENV WINEDEBUG=-all \
    WINEPREFIX=/opt/wineprefix

ENTRYPOINT ["/usr/local/bin/cl"]
