# MSVC 6.0 — 32-bit PE compiler under wine (the flagship toolchain).
#
# Inherits the shared rebrew/base; this image adds the MSVC 6.0
# command-line toolchain (OmniBlade msvcwin9x tarball, sha256-pinned) and
# the `cl` entrypoint wrapper.  Fully self-contained: no host files.
#
# Build:  docker build -t rebrew/msvc:6.0-win32 toolchain/msvc/6.0-win32
# Invoke: docker run --rm -v "$PWD":/work -w /work rebrew/msvc:6.0-win32 /c f.c  (ENTRYPOINT is the cl wrapper)

FROM rebrew/base:1.0

WORKDIR /opt

# MSVC 6.0 command-line toolchain (Bin/Include/Lib — top-level in the tarball).
RUN curl -sL -o /tmp/msvc6.tar.gz \
        "https://github.com/OmniBlade/decomp.me/releases/download/msvcwin9x/msvc6.0.tar.gz" \
    && echo "5c81e9c2ab0ac5545022c1418a23392cb514db950cf6dcb1f48327270403fcd3  /tmp/msvc6.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/msvc6.0 \
    && tar xzf /tmp/msvc6.tar.gz -C /opt/msvc6.0 \
    && rm /tmp/msvc6.tar.gz \
    && ls /opt/msvc6.0/Bin/CL.EXE

# The `cl` wrapper: validate the source (common helper), then translate the
# MSVC-style argv into `wine /opt/msvc6.0/bin/CL.EXE <args>` inside the
# mounted /work.
RUN printf '%s\n' \
        '#!/bin/sh' \
        '. /usr/local/lib/rebrew/wrapper-common.sh' \
        'rebrew_pick_source "$@"' \
        'exec wine /opt/msvc6.0/bin/CL.EXE "$@"' \
        > /usr/local/bin/cl \
    && chmod +x /usr/local/bin/cl

ENTRYPOINT ["/usr/local/bin/cl"]
