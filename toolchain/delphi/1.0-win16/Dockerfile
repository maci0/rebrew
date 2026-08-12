# Borland Delphi 1.0 — 16-bit NE compiler (DOS DPMI app under DOSBox).
#
# Inherits the shared rebrew/base (debian + wine + dosbox + common wrappers);
# this image adds the vendored Delphi 1.0 toolchain (DCC.EXE + DELPHI.DSL +
# DPMI16BI.OVL + RTM.EXE + the RTL/VCL units) and the `dcc` entrypoint
# wrapper, which stages them into a fresh C: drive (a non-tmpfs sandbox —
# DOSBox 0.74-3 breaks on tmpfs) and runs DCC headless, writing the .EXE
# back to the mounted /work.
#
# Build:  docker build -t rebrew/delphi:1.0-win16 toolchain/delphi/1.0-win16
# Invoke: docker run --rm -v "$PWD":/work -w /work rebrew/delphi:1.0-win16 hello.dpr  (ENTRYPOINT is the dcc wrapper)

FROM rebrew/base:1.0

WORKDIR /opt

# Vendored Delphi 1.0 toolchain: DCC.EXE (DOS DPMI), the required
# DELPHI.DSL symbol table, DPMI16BI.OVL + RTM.EXE (DPMI runtime), and the
# RTL/VCL units (UNITS.PAK + LIB.PAK output).  The staged binaries are
# gitignored; re-vendor from tools/DELPHI10 + the wine C: DELPHI/LIB.
COPY DCC.EXE DELPHI.DSL DPMI16BI.OVL RTM.EXE /opt/delphi10/
COPY delphi-lib/ /opt/delphi10/DELPHI/LIB/
COPY dcc-wrapper.sh /usr/local/bin/dcc

RUN chmod +x /usr/local/bin/dcc

ENTRYPOINT ["/usr/local/bin/dcc"]
