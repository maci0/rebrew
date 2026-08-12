# rebrew/base — the shared OS + wine layer for every toolchain image.
#
# All toolchain Dockerfiles inherit FROM this image, so the OS, wine,
# dosbox and download tooling are built once and cached; each toolchain
# image only adds its compiler + an entrypoint wrapper.
#
# Build:  docker build -t rebrew/base:1.0 toolchain/base
# Invoke: (base has no entrypoint — toolchain images set their own)
#
# Contents:
#   - wine + wine32 (32-bit PE compilers under wine, e.g. MSVC 6.0)
#   - dosbox (16-bit DOS compilers, e.g. MSVC 1.52, Delphi 1.0)
#   - dumb-init (signal handling for the compile containers)
#   - curl / ca-certificates / xz-utils (tarball-based toolchains)
#   - /usr/local/lib/rebrew/wrapper-common.sh (shared wrapper helpers)
#   - common env: WINEDEBUG=-all, WINEPREFIX=/opt/wineprefix,
#     SDL_VIDEODRIVER=dummy (headless)

FROM debian:bookworm-slim

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        wine wine32 dosbox dumb-init curl ca-certificates xz-utils \
    && rm -rf /var/lib/apt/lists/*

ENV WINEDEBUG=-all \
    WINEPREFIX=/opt/wineprefix \
    SDL_VIDEODRIVER=dummy

COPY wrapper-common.sh /usr/local/lib/rebrew/wrapper-common.sh
RUN chmod +x /usr/local/lib/rebrew/wrapper-common.sh
