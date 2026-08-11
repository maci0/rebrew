# Borland Delphi 1.0 — 16-bit NE compiler (DOS DPMI app under DOSBox).
#
# The image encapsulates the DOSBox sandbox: DCC.EXE + DELPHI.DSL +
# DPMI16BI.OVL + RTM.EXE + the RTL/VCL units are baked in, and the `dcc`
# wrapper (dcc-wrapper.sh) stages them into a fresh C: drive (a non-tmpfs
# sandbox — DOSBox 0.74-3 breaks on tmpfs) and runs DCC headless, writing
# the .EXE back to the mounted /work.
#
# Build:  docker build -t rebrew/delphi:1.0-linux-x64 toolchain-images/delphi/1.0-linux-x64
# Invoke: docker run --rm -v "$PWD":/work -w /work rebrew/delphi:1.0-linux-x64 dcc hello.dpr

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends dosbox \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Vendored Delphi 1.0 toolchain: DCC.EXE (DOS DPMI), the required
# DELPHI.DSL symbol table, DPMI16BI.OVL + RTM.EXE (DPMI runtime), and the
# RTL/VCL units (UNITS.PAK + LIB.PAK output).  The staged binaries are
# gitignored; re-vendor from tools/DELPHI10 + the wine C: DELPHI/LIB.
COPY delphi10/ /opt/delphi10/
COPY delphi-lib/ /opt/delphi10/DELPHI/LIB/
COPY dcc-wrapper.sh /usr/local/bin/dcc

RUN chmod +x /usr/local/bin/dcc

ENV SDL_VIDEODRIVER=dummy

ENTRYPOINT ["/usr/local/bin/dcc"]
