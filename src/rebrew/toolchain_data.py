"""toolchain_data.py — the packaged toolchain registry and source pins.

Profiles in config.py map to these by name; the runner builds the public
TOOLCHAINS from BUILTIN_TOOLCHAINS plus entry-point providers and the
project overlay.
"""

from __future__ import annotations

from rebrew.toolchain_paths import vendored_path
from rebrew.toolchain_spec import ToolchainSource, ToolchainSpec

#: Pinned sources for assembling each toolchain (used by ``rebrew toolchain
#: vendor`` and mirrored in the Dockerfiles).  Same sha256 as the images
#: download, so host trees and containers are byte-identical.
SOURCES: dict[str, ToolchainSource] = {
    "msvc-6.0": ToolchainSource(
        # archaic-msvc/msvc600 — the flagship MSVC 6.0 base (VC98/Bin/CL.EXE,
        # 12.00.8168).  Byte-reproducible with the old decomp.me msvc6.0
        # source (masked-object sha256 identical), now pinned to the
        # archaic-msvc org per the "get everything from archaic-msvc" rule.
        url="https://codeload.github.com/archaic-msvc/msvc600/tar.gz/refs/heads/master",
        sha256="19b72020c8225f91d7345b16aa0acf1b31a4608ae1299693021491e7338d0ee8",
        commit="34d4fc4004e880b8d5c44ae5babd7229eeaad993",
        layout="tar-strip1",
        host_dir="msvc/6.0-win32",
    ),
    "msvc-2.0": ToolchainSource(
        # archaic-msvc/msvc200 — VC 2.0 (1994), the first 32-bit compiler; bin/cl.exe.
        url="https://codeload.github.com/archaic-msvc/msvc200/tar.gz/refs/heads/master",
        sha256="0b058f103fe6b615987a85d518d7fd23389fab67c9df3cadfae22f5a70d5d000",
        commit="6bf022c590fdea0526dc94975f3d91add444ac1a",
        layout="tar-strip1",
        host_dir="msvc/2.0-win32",
    ),
    "msvc-4.1": ToolchainSource(
        # archaic-msvc/msvc410 — VC 4.1 (1996); bin/CL.EXE (10.10.6038).
        url="https://codeload.github.com/archaic-msvc/msvc410/tar.gz/refs/heads/master",
        sha256="21486aecd108397bdced6e2cf6a5170a3cc30280a3eba97a4a8f92985a9cc5c4",
        commit="373f5e621ac8fb7b219873b37334ef1d0a2149e6",
        layout="tar-strip1",
        host_dir="msvc/4.1-win32",
    ),
    "msvc-5.0-sp1": ToolchainSource(
        # archaic-msvc/msvc500sp1 — VC 5.0 SP1 (CL.EXE identical to base 11.00.7022).
        url="https://codeload.github.com/archaic-msvc/msvc500sp1/tar.gz/refs/heads/master",
        sha256="f41e9e5a05bd7a4da97fdcc9d168aaac7898e5bfec11791c630735a7da13d303",
        commit="401174749393c9991a6b91425a795e04e8bdeedb",
        layout="tar-strip1",
        host_dir="msvc/5.0-sp1-win32",
    ),
    "msvc-5.0-sp2": ToolchainSource(
        # archaic-msvc/msvc500sp2 — VC 5.0 SP2.
        url="https://codeload.github.com/archaic-msvc/msvc500sp2/tar.gz/refs/heads/master",
        sha256="551137506a6a98ca890bfe20df7d5833bc475cf7e2279d959eccce0485525c8e",
        commit="4ebf02022705b4c9e9108d3ed3f286ed80ba2ed9",
        layout="tar-strip1",
        host_dir="msvc/5.0-sp2-win32",
    ),
    "msvc-5.0-sp3": ToolchainSource(
        # archaic-msvc/msvc500sp3 — VC 5.0 SP3.
        url="https://codeload.github.com/archaic-msvc/msvc500sp3/tar.gz/refs/heads/master",
        sha256="cdba2878eaacd07cb289b73f08250e2c39596fc9b31a2ad7a4fd887879be1e38",
        commit="259a03f0bc863de5baf657ec064cb60cb20a2cdc",
        layout="tar-strip1",
        host_dir="msvc/5.0-sp3-win32",
    ),
    "msvc-6.0-sp1": ToolchainSource(
        # archaic-toolchains/msvc600_sp1 — VC 6.0 SP1 (1998).  The full RTM
        # product tree (archaic-msvc msvc600 + VS6 Enterprise CD1 CRT/debug/
        # redist) plus the files SP1 is documented to have fixed (strftime.c,
        # MFC sources) taken in cumulative state from the official SP2 payload
        # the standalone SP1 payload (VSE600SP1.EXE) is not preserved in any
        # public archive.  CL.EXE 12.00.8168 (the RTM..SP3 driver, byte-identical
        # to the base 6.0 compiler).
        url="https://codeload.github.com/archaic-toolchains/msvc600_sp1/tar.gz/refs/heads/main",
        sha256="2c3d1a6d2e7d6248f1bcb5e46a54cd2bea94704df032056abef53828b0b79888",
        commit="6d9787482473ca46a1e6fb70be020755951eb16a",
        layout="tar-strip1",
        host_dir="msvc/6.0-sp1-win32",
    ),
    "msvc-6.0-sp2": ToolchainSource(
        # archaic-toolchains/msvc600_sp2 — VC 6.0 SP2 (1999).  The full RTM
        # tree plus the entire official SP2 payload (crt/src, debug, lib,
        # mfc/src, mfc/lib from the MSDN Disc 18 VS6SP2 CABs) and the SP2
        # redistributable runtimes.  SP2 changed no compiler binaries and no
        # headers — CL.EXE stays 12.00.8168 (byte-identical to the base).
        url="https://codeload.github.com/archaic-toolchains/msvc600_sp2/tar.gz/refs/heads/main",
        sha256="088cd189ce0ae3c7ff96a71bb3f364a397b2fe6c19e6a8f252cc575be3783574",
        commit="79157a87dec5e5ff014178f817f27a70098fd862",
        layout="tar-strip1",
        host_dir="msvc/6.0-sp2-win32",
    ),
    "msvc-6.0-sp4": ToolchainSource(
        # archaic-toolchains/msvc600_sp4 — VC 6.0 SP4 (2000) full tree with
        # Bin: the archaic-msvc msvc600_sp4 headers/libs plus the decomp.me
        # msvc6.4 Bin (CL.EXE 12.00.8804 — the SP4+ driver; sha-verified
        # byte-identical to the official SP4 CD's cl/c1/c1xx/link/cvtres).
        url="https://codeload.github.com/archaic-toolchains/msvc600_sp4/tar.gz/refs/heads/main",
        sha256="7aeb03f65858000bb6988a64cc066a4a2aec9fc591400db400ffe6fc99ae2dbc",
        commit="0ca69bae9e3ca739c5ce38c8cf39ffc51582080d",
        layout="tar-strip1",
        host_dir="msvc/6.0-sp4-win32",
    ),
    "msvc-6.0-sp3": ToolchainSource(
        # OmniBlade decomp.me msvc6.3 — VC 6.0 SP3 (CL.EXE 12.00.8168, the
        # RTM..SP3 build; identical to the flagship msvc-6.0 compiler).  The
        # archaic-msvc msvc600_sp3 repo carries no Bin/, so the decomp.me
        # mirror (which matches the vendored tree byte-for-byte) is pinned.
        url="https://github.com/OmniBlade/decomp.me/releases/download/msvcwin9x/msvc6.3.tar.gz",
        sha256="84f73e718b3671bfd5de3b7764622b07633b572ee826ca3b77602d224c128608",
        layout="tar",
        host_dir="msvc/6.0-sp3-win32",
    ),
    "msvc-6.0-sp5": ToolchainSource(
        # archaic-msvc/msvc600_sp5 — VC 6.0 SP5 full product tree (VC98/Bin,
        # CL.EXE 12.00.8804).  The archaic sp3/sp4 repos carry no Bin/, and
        # decomp.me's msvc6.4/6.5 mislabel the SP6 compiler, so SP5 is the
        # earliest real SP with its own preserved compiler binary.
        url="https://codeload.github.com/archaic-msvc/msvc600_sp5/tar.gz/refs/heads/master",
        sha256="a95a9c17cbcbe0d97a3e80ef9596f12404eb28f36bab24e89aabcbe37acbbef6",
        commit="b0b07e29108e2695eb0274c2a377a7b7d7326150",
        layout="tar-strip1",
        host_dir="msvc/6.0-sp5-win32",
    ),
    "msvc-6.0-sp5-pp": ToolchainSource(
        # archaic-msvc/msvc600_sp5_vcpp — VC 6.0 SP5 with the Visual C++ 6.0
        # Processor Pack already applied (extracted tree, so no installer
        # runs).  The pack replaces the code generator (c2.dll 13.00.9044.0),
        # adds MASM 6.15 (ml.exe), and ships the MMX/SSE/SSE2 intrinsic
        # headers (mmintrin.h, xmmintrin.h, emmintrin.h, ...).  cl.exe itself
        # is unchanged (12.00.8804) and there is no /arch option: SSE/SSE2
        # code is written with the pack's intrinsics.  The pack is SP5-only:
        # SP6 removes it.
        url="https://codeload.github.com/archaic-msvc/msvc600_sp5_vcpp/tar.gz/refs/heads/master",
        sha256="1bbf177489054698fd5d29bf042692efdb5bec8719f9dc889b9b1c618c645991",
        commit="762e9382c751613c341daa766f0e22cdeb07152c",
        layout="tar-strip1",
        host_dir="msvc/6.0-sp5-pp-win32",
    ),
    "msvc-6.0-sp6": ToolchainSource(
        # archaic-msvc/msvc600_sp6 — VC 6.0 SP6 full product tree
        # (VC98/Bin/CL.EXE, 12.00.8804 — the same compiler the SP4 CD and
        # SP5 carry).  The repo stashes mspdb60.dll under Common/MSDev98/Bin
        # (the vendor + Dockerfile relocate it — CL imports it in-dir).
        url="https://codeload.github.com/archaic-msvc/msvc600_sp6/tar.gz/refs/heads/master",
        sha256="7c2aa3dd4c56b8054cc1ae0e00cd976005dd5b9b43ea8c33b22798a15c9c15c3",
        commit="1f4223a77122220d28e8670788b3f9fd6bb2c4d1",
        layout="tar-strip1",
        host_dir="msvc/6.0-sp6-win32",
    ),
    "msvc-7.0": ToolchainSource(
        # archaic-msvc/msvc710 — the legacy "msvc-7.0" profile's compiler is
        # cl.exe 13.10.3077 (the .NET 2003 build); archaic-msvc carries it
        # in msvc710 (Vc7/bin layout).  The vendored 7.0-win32 host tree
        # keeps its flat Bin/ layout (established config); the image builds
        # from the archaic source.
        url="https://codeload.github.com/archaic-msvc/msvc710/tar.gz/refs/heads/master",
        sha256="618e876bc06431498fa98e71a408d822a5fad979219ce3253318d099a6917b27",
        commit="2932d76fe417b0bc49010b26d4be2e5b743cc4be",
        layout="tar-strip1",
        host_dir="msvc/7.0-win32",
    ),
    "msvc-7.0-rtm": ToolchainSource(
        # archaic-msvc/msvc700 — the true VC 7.0 (2002) compiler (13.00.9466;
        # 7.0-SP1 shipped the identical binary).  Vc7/bin/cl.exe layout; the
        # canonical 7.0-win32 dir stays with the established msvc-7.0 profile.
        url="https://codeload.github.com/archaic-msvc/msvc700/tar.gz/refs/heads/master",
        sha256="5f75462fb6134ad56c3ae28cf8b1e3b2869578d4171568b7a1fcdfb0bf97830b",
        commit="97fe4cdeaeb0bb934591d4b05eb52c2e8ab3e34b",
        layout="tar-strip1",
        host_dir="msvc/7.0-rtm-win32",
    ),
    "msvc-7.0-sp1": ToolchainSource(
        # archaic-msvc/msvc700_sp1 — VC 7.0 SP1 (same 13.00.9466 compiler,
        # updated headers/libs).
        url="https://codeload.github.com/archaic-msvc/msvc700_sp1/tar.gz/refs/heads/master",
        sha256="bc1300625c89e855e1c0160b43c6fe2576ad68426483bd73c3cde2682165ba8a",
        commit="8bd9502d74274667de198247a459d63dbd431068",
        layout="tar-strip1",
        host_dir="msvc/7.0-sp1-win32",
    ),
    "msvc-7.1": ToolchainSource(
        # archaic-msvc/msvc710 — VC 7.1 (.NET 2003; cl.exe 13.10.3077, the
        # same build the legacy msvc-7.0 profile carries).  Vc7/bin/cl.exe.
        url="https://codeload.github.com/archaic-msvc/msvc710/tar.gz/refs/heads/master",
        sha256="618e876bc06431498fa98e71a408d822a5fad979219ce3253318d099a6917b27",
        commit="2932d76fe417b0bc49010b26d4be2e5b743cc4be",
        layout="tar-strip1",
        host_dir="msvc/7.1-win32",
    ),
    "msvc-7.1-sp1": ToolchainSource(
        # archaic-msvc/msvc710_sp1 — VC 7.1 SP1 (cl.exe 13.10.6030).
        url="https://codeload.github.com/archaic-msvc/msvc710_sp1/tar.gz/refs/heads/master",
        sha256="44246ff2980d715c2d05eaed505344a0b87850a04606482c13ba4832ddf5ec70",
        commit="cf62606064633dd8441aa2feffe34792099cc366",
        layout="tar-strip1",
        host_dir="msvc/7.1-sp1-win32",
    ),
    "msvc-8.0": ToolchainSource(
        # archaic-msvc/msvc800 — VC 8.0 (2005; cl.exe 14.00.50727).  VC/bin.
        url="https://codeload.github.com/archaic-msvc/msvc800/tar.gz/refs/heads/master",
        sha256="ab819164ebd9e9d367c1178a86eb9c3337b1a8d85d1357322a3252b63ad64453",
        commit="00ddaf58d09788f0b12e475dae5fb5674dd32578",
        layout="tar-strip1",
        host_dir="msvc/8.0-win32",
    ),
    "msvc-8.0-sp1": ToolchainSource(
        # archaic-msvc/msvc800_sp1 — VC 8.0 SP1 (cl.exe 14.00.50727.762).
        url="https://codeload.github.com/archaic-msvc/msvc800_sp1/tar.gz/refs/heads/master",
        sha256="9b53b515d79839c7404944c29cdae862d3a8c1ff0d0a27a202bfc37a31f587c5",
        commit="4b1bafba636f67eb76f548f0f0e7f38864091a4a",
        layout="tar-strip1",
        host_dir="msvc/8.0-sp1-win32",
    ),
    "msvc-9.0": ToolchainSource(
        # archaic-msvc/msvc900 — VC 9.0 (2008; cl.exe 15.00.21022).  VC/bin;
        # the repo carries no SP1 tarball (VC 2008 SP1's 15.00.30729 compiler
        # is not preserved publicly) — the base 9.0 profile is the matchable
        # target for VS2008-era binaries.
        url="https://codeload.github.com/archaic-msvc/msvc900/tar.gz/refs/heads/master",
        sha256="9121d184d9cb88c13b95d3d2e770c8d8ae9d2531a5d8ea90c53a14f765e3f904",
        commit="c9d710cef9a3dec08d7d2dca78a3b494335a5baa",
        layout="tar-strip1",
        host_dir="msvc/9.0-win32",
    ),
    "msvc-9.0-sp1": ToolchainSource(
        # archaic-toolchains/msvc900_sp1 — VC 9.0 SP1 (2008): the msvc-9.0 base
        # plus the 15.00.30729.01 compiler (cl/c1/c1xx/c2/link/mspdb80,
        # Professional-edition series) and 122 SP1 headers/libs, extracted
        # from the official VS2008 SP1 DVD (VS90sp1-KB945140-X86-ENU.msp).
        # Closes the "VC 2008 SP1 compiler has no public tarball" gap.
        url="https://codeload.github.com/archaic-toolchains/msvc900_sp1/tar.gz/refs/heads/main",
        sha256="33a66c779da39ab40518f24b75656f1f93cb1837a3d65a9b79188f41c2f2bd97",
        commit="cebb3c9740c92de36937a401a3a3141358c8ac29",
        layout="tar-strip1",
        host_dir="msvc/9.0-sp1-win32",
    ),
    "msvc-11.0": ToolchainSource(
        # archaic-msvc/msvc1100 — VC 11.0 / VS 2012 (cl.exe 17.00.50522.1).
        # VC/bin + Windows Kits + a wine/ runner dir; the newest compiler the
        # archaic-msvc org carries.
        url="https://codeload.github.com/archaic-msvc/msvc1100/tar.gz/refs/heads/master",
        sha256="adba1882eb076cb774b7a5d0f2b1067544da7cd2f0bf0b12f284361516cbc825",
        commit="89087a636aea5e6f9450ee7e840ea71e08740ee1",
        layout="tar-strip1",
        host_dir="msvc/11.0-win32",
    ),
    "msvc-10.0": ToolchainSource(
        # archaic-msvc/msvc1000 — VC 10.0 (2010; cl.exe 16.00.30319).  VC/bin.
        url="https://codeload.github.com/archaic-msvc/msvc1000/tar.gz/refs/heads/master",
        sha256="5f0b4486eb68e0069bb11506bcc8834710ac92ac1e7f311b3e4400a9d5d9409f",
        commit="f8977e2cacbe6cab4f9e73eb2c05695a88519bfe",
        layout="tar-strip1",
        host_dir="msvc/10.0-win32",
    ),
    "msvc-10.0-sp1": ToolchainSource(
        # archaic-msvc/msvc1000_sp1 — VC 10.0 SP1 (cl.exe 16.00.40219).
        url="https://codeload.github.com/archaic-msvc/msvc1000_sp1/tar.gz/refs/heads/master",
        sha256="2e5fbb9b71ed8cb2673594484d6a8fad7484c809ecefffaf3319e0164af6f89b",
        commit="09a53c11f781ec9ab5e66772ba720b9d85e4c2a4",
        layout="tar-strip1",
        host_dir="msvc/10.0-sp1-win32",
    ),
    "msvc-1.5": ToolchainSource(
        # Committed tree extracted from the archive.org en_vc152 item
        # (VC 1.5, 1993, 16-bit) — RAR SFX extracts cleanly for 1.5 (the
        # 1.52 SFX corrupts), so the verified tree is vendored under the
        # rebrew-toolchains checkout (msvc15.tar.xz next to its Dockerfile).
        in_repo="msvc/1.5-win16/msvc15.tar.xz",
        layout="tar",
        host_dir="msvc/1.5-win16",
    ),
    "msvc-1.0": ToolchainSource(
        # Assembled from the WinWorldPC "Microsoft Visual C++ 1.0
        # Professional" 3.5" floppy set (20×1.44MB, SZDD-compressed payload;
        # 7z-extracted + renamed), then vendored under the rebrew-toolchains
        # checkout as msvc10.tar.xz.  CL.EXE is a Phar Lap TNT DOS-extender
        # (PE32) like 1.5/1.52 — runs headless under DOSBox and produces
        # 16-bit OMF (verified).
        in_repo="msvc/1.0-win16/msvc10.tar.xz",
        layout="tar",
        host_dir="msvc/1.0-win16",
    ),
    "msvc-1.52": ToolchainSource(
        in_repo="msvc/1.52-win16/msvc152.tar.xz",
        layout="tar",
        host_dir="msvc/1.52-win16",
    ),
    "delphi-1.0": ToolchainSource(
        in_repo="delphi/1.0-win16/delphi10.tar.xz",
        layout="tar",
        host_dir="delphi/1.0-win16",
    ),
    "ido-5.3": ToolchainSource(
        # decompals/ido-static-recomp v1.2 — statically recompiled SGI IDO 5.3
        # (MIPS-II big-endian, N64).  Native Linux x86_64 binaries; the same
        # sha256 the rebrew/ido:5.3-linux image downloads at build time.
        url="https://github.com/decompals/ido-static-recomp/releases/download/v1.2/ido-5.3-recomp-linux.tar.gz",
        sha256="ab5c741561f80913d58c8b074771f23941a3edd312505a8ebed6d1dfeb65e506",
        layout="tar",
        host_dir="ido/5.3-linux",
    ),
    "ido-7.1": ToolchainSource(
        # decompals/ido-static-recomp v1.2 — statically recompiled SGI IDO 7.1
        # (MIPS-II big-endian, N64).  Native Linux x86_64 binaries; the same
        # sha256 the rebrew/ido:7.1-linux image downloads at build time.
        url="https://github.com/decompals/ido-static-recomp/releases/download/v1.2/ido-7.1-recomp-linux.tar.gz",
        sha256="0d411696e178fcca34c31c3bf02011b928d7fd9c1fa7f8bf45070e0781b58e15",
        layout="tar",
        host_dir="ido/7.1-linux",
    ),
    "clang-18.1.8": ToolchainSource(
        # LLVM's official prebuilt x86_64 Linux release (llvmorg-18.1.8 — the
        # only x86_64 Linux asset that release published).  Native ELF
        # binaries; the same sha256 the rebrew/clang:18.1.8-linux-x64 image
        # downloads at build time.
        url="https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04.tar.xz",
        sha256="54ec30358afcc9fb8aa74307db3046f5187f9fb89fb37064cdde906e062ebf36",
        layout="tar-strip1",
        host_dir="clang/18.1.8-linux-x64",
    ),
    "clang-16.0.4": ToolchainSource(
        # llvmorg-16.0.4 — the newest 16.x release with an x86_64 Linux
        # asset (16.0.5/16.0.6 shipped aarch64 and powerpc64le only).
        url="https://github.com/llvm/llvm-project/releases/download/llvmorg-16.0.4/clang+llvm-16.0.4-x86_64-linux-gnu-ubuntu-22.04.tar.xz",
        sha256="fd464333bd55b482eb7385f2f4e18248eb43129a3cda4c0920ad9ac3c12bdacf",
        layout="tar-strip1",
        host_dir="clang/16.0.4-linux-x64",
    ),
    "gcc-14.2.0": ToolchainSource(
        # GNU GCC 14.2.0 release tarball; the image builds C-only from it.
        url="https://ftp.gnu.org/gnu/gcc/gcc-14.2.0/gcc-14.2.0.tar.xz",
        sha256="a7b39bc69cbf9e25826c5a60ab26477001f7c08d85cec04bc0e29cabed6f3cc9",
        layout="tar-strip1",
        host_dir="gcc/14.2.0-linux-x64",
    ),
    "gcc-12.3.0": ToolchainSource(
        # GNU GCC 12.3.0 release tarball; the image builds C-only from it.
        url="https://ftp.gnu.org/gnu/gcc/gcc-12.3.0/gcc-12.3.0.tar.xz",
        sha256="949a5d4f99e786421a93b532b22ffab5578de7321369975b91aec97adfda8c3b",
        layout="tar-strip1",
        host_dir="gcc/12.3.0-linux-x64",
    ),
    "mingw-16.2.0": ToolchainSource(
        # niXman/mingw-builds-binaries — the i686-w64-mingw32 target, Windows
        # host (the driver is a PE32 binary the image runs under wine); the
        # archive wraps its tree in mingw32/.
        url="https://github.com/niXman/mingw-builds-binaries/releases/download/16.2.0-rt_v14-rev1/i686-16.2.0-release-posix-dwarf-msvcrt-rt_v14-rev1.7z",
        sha256="9773342cba88efe50e6f3ddd021ac6f1d9ac1957301705fe64def22f501f0dd4",
        layout="7z-strip1",
        host_dir="mingw/16.2.0-win32",
    ),
    "mingw-14.2.0": ToolchainSource(
        url="https://github.com/niXman/mingw-builds-binaries/releases/download/14.2.0-rt_v12-rev2/i686-14.2.0-release-posix-dwarf-msvcrt-rt_v12-rev2.7z",
        sha256="895d22c902e22d4b7b1c1b4160d1b3d70bbd6fc653b04f46b7736ef0ef5e4bc2",
        layout="7z-strip1",
        host_dir="mingw/14.2.0-win32",
    ),
    "watcom-2.0-win16": ToolchainSource(
        # Open Watcom 2.0 snapshot, dated 2026-09-01.  The Last-CI-build tag
        # the `watcom` pin uses is republished on every CI run, so its
        # recorded sha256 no longer resolves upstream; the dated release is
        # immutable and this image rebuilds reproducibly from it.
        url="https://github.com/open-watcom/open-watcom-v2/releases/download/2026-09-01-Build/ow-snapshot.tar.xz",
        sha256="bac354f3c75ffa49ff8d70a44e475de7e7c1823fff04b80c14787bd0792c9bdf",
        layout="tar-strip1",
        host_dir="watcom/2.0-win16",
    ),
    "borland-5.5": ToolchainSource(
        url="https://archive.org/download/BorlandC55/Borland%20C%2B%2B%205.5.zip",
        sha256="12affb942db2b9823292697faaa6f465b18c381ba347f9f4bf8efae6ff34cca1",
        layout="zip-installshield",
        host_dir="borland/5.5-win32",
    ),
    "borland-2.0": ToolchainSource(
        in_repo="borland/2.0-win16/tc20.tar.xz",
        # Assembled from the archive.org turboc20 item (floppy disk images:
        # TCC.EXE 2.0/TLINK.EXE/CPP.EXE + runtime libs + headers), then
        # vendored under the rebrew-toolchains checkout for deterministic
        # builds.
        layout="tar",
        host_dir="borland/2.0-win16",
    ),
    "borland-3.1": ToolchainSource(
        in_repo="borland/3.1-win16/tc31.tar.xz",
        # Original download (sha256-verified once, then vendored under the
        # rebrew-toolchains checkout for deterministic builds): archive.org
        # item turboc3.1_202112 (TC.zip), sha256
        # 9cf53cd5d229633c2cf60c6fe2b24dba43b40a0ff2ca71e90279fa8649b622e4.
        layout="tar",
        host_dir="borland/3.1-win16",
    ),
    "watcom-2.0-win32": ToolchainSource(
        # The rolling `Last-CI-build` tag is republished on every CI run, so a
        # recorded sha256 stops resolving upstream; the dated release is
        # immutable and this image rebuilds reproducibly from it (the same
        # snapshot the 16-bit image uses).
        url="https://github.com/open-watcom/open-watcom-v2/releases/download/2026-09-01-Build/ow-snapshot.tar.xz",
        sha256="bac354f3c75ffa49ff8d70a44e475de7e7c1823fff04b80c14787bd0792c9bdf",
        commit="",
        layout="tar-strip1",
        host_dir="watcom/2.0-win32",
    ),
    "msvc-4.2": ToolchainSource(
        # archaic-msvc snapshot — the vendored toolchain/msvc/4.2-win32 tree
        # is a byte-identical extraction of this repo tarball (verified: file
        # list + CL.EXE match).  Previously vendored but NOT pinned, so a
        # fresh clone could not reproduce it via `rebrew toolchain vendor`.
        url="https://codeload.github.com/archaic-msvc/msvc420/tar.gz/refs/heads/master",
        sha256="651db241202416be7e870ff8d98928179b94515068e7895008b8a82cb0b7001c",
        commit="b42c244f0a83ba15ba2ffb62b0dc240d7b2dea50",
        layout="tar-strip1",
        host_dir="msvc/4.2-win32",
    ),
    "msvc-5.0": ToolchainSource(
        # archaic-msvc snapshot — vendored toolchain/msvc/5.0-win32 is a
        # byte-identical extraction (verified).  Same sha256 the doctor hint
        # for the 5.0 layout already pointed at (codeload archaic-msvc/msvc500).
        url="https://codeload.github.com/archaic-msvc/msvc500/tar.gz/refs/heads/master",
        sha256="46745771c0805310212415450f097134f3871d1786434e86c080e0b8cb9a38fb",
        commit="8abf95ce980161ad87b0b02402269cce76988953",
        layout="tar-strip1",
        host_dir="msvc/5.0-win32",
    ),
    "msvc-4.0": ToolchainSource(
        # itsmattkc/MSVC400 — the classic MSVC 4.0 (1995) tree; BIN/CL.EXE
        # at the repo root.  Completes the msvc4x/5/6/7 profile set (config,
        # init, and the detector already knew msvc-4.0; only the toolchain
        # registry lacked it).
        url="https://codeload.github.com/itsmattkc/MSVC400/tar.gz/refs/heads/master",
        sha256="c076ab51bb5a52c805c85603d565ac406beec1a0accf3829127369294f1aff11",
        commit="821e942fd95bd16d01649401de7943ef87ae9f54",
        layout="tar-strip1",
        host_dir="msvc/4.0-win32",
    ),
}


#: Packaged (built-in) toolchain registry — the base every discovered
#: toolchain merges on top of.  The public :data:`TOOLCHAINS` is built from
#: this plus entry-point providers and the project-level TOML overlay; keep
#: the distinction so "packaged specs" and "user components" never blur.
BUILTIN_TOOLCHAINS: dict[str, ToolchainSpec] = {
    "msvc-4.0": ToolchainSpec(
        name="msvc-4.0",
        image="rebrew/msvc:4.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc4.0/BIN",
        host_path=vendored_path("msvc/4.0-win32")
        if vendored_path("msvc/4.0-win32").exists()
        else None,
        description="MSVC 4.0 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-4.2": ToolchainSpec(
        name="msvc-4.2",
        image="rebrew/msvc:4.2-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc4.2/bin",
        host_path=vendored_path("msvc/4.2-win32")
        if vendored_path("msvc/4.2-win32").exists()
        else None,
        description="MSVC 4.2 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-5.0": ToolchainSpec(
        name="msvc-5.0",
        image="rebrew/msvc:5.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc5.0/bin",
        host_path=vendored_path("msvc/5.0-win32")
        if vendored_path("msvc/5.0-win32").exists()
        else None,
        description="MSVC 5.0 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-6.0": ToolchainSpec(
        name="msvc-6.0",
        image="rebrew/msvc:6.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc6.0/VC98/Bin",
        host_path=vendored_path("msvc/6.0-win32")
        if vendored_path("msvc/6.0-win32").exists()
        else None,
        description="MSVC 6.0 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "delphi-1.0": ToolchainSpec(
        name="delphi-1.0",
        image="rebrew/delphi:1.0-win16",
        binary="DCC.EXE",
        image_binary=None,  # the image ENTRYPOINT is the dcc wrapper
        runtime="dosbox",
        bits=16,  # 16-bit target (arch-alignment check)
        flags_style="msvc",
        obj_ext=".exe",  # DCC emits a linked NE, not an object
        host_path=vendored_path("delphi/1.0-win16"),
        description="Borland Delphi 1.0 (16-bit NE) — DOSBox",
    ),
    "mingw-16.2.0": ToolchainSpec(
        name="mingw-16.2.0",
        image="rebrew/mingw:16.2.0-win32",
        binary="i686-w64-mingw32-gcc",
        image_binary=None,  # the image ENTRYPOINT is the mingw-16.2.0 wrapper
        runtime="wine",  # the mingw-builds driver is a Windows PE binary
        flags_style="posix",
        obj_ext=".obj",  # PE/COFF object for the i686-w64-mingw32 target
        description="MinGW-w64 GCC 16.2.0 (PE/x86_32) — docker image (wine inside)",
    ),
    "mingw-14.2.0": ToolchainSpec(
        name="mingw-14.2.0",
        image="rebrew/mingw:14.2.0-win32",
        binary="i686-w64-mingw32-gcc",
        image_binary=None,  # the image ENTRYPOINT is the mingw-16.2.0 wrapper
        runtime="wine",  # the mingw-builds driver is a Windows PE binary
        flags_style="posix",
        obj_ext=".obj",  # PE/COFF object for the i686-w64-mingw32 target
        description="MinGW-w64 GCC 14.2.0 (PE/x86_32) — docker image (wine inside)",
    ),
    "gcc-14.2.0": ToolchainSpec(
        name="gcc-14.2.0",
        image="rebrew/gcc:14.2.0-linux-x64",
        binary="gcc",
        image_binary=None,  # the image ENTRYPOINT is the gcc wrapper
        runtime="native",  # the compiler runs natively in the image
        flags_style="posix",
        obj_ext=".o",  # ELF x86_64 object
        description="GCC 14.2.0 (ELF/x86_64) — docker image (native, built from source)",
    ),
    "gcc-12.3.0": ToolchainSpec(
        name="gcc-12.3.0",
        image="rebrew/gcc:12.3.0-linux-x64",
        binary="gcc",
        image_binary=None,  # the image ENTRYPOINT is the gcc wrapper
        runtime="native",  # the compiler runs natively in the image
        flags_style="posix",
        obj_ext=".o",  # ELF x86_64 object
        description="GCC 12.3.0 (ELF/x86_64) — docker image (native, built from source)",
    ),
    "clang-18.1.8": ToolchainSpec(
        name="clang-18.1.8",
        image="rebrew/clang:18.1.8-linux-x64",
        binary="clang",
        image_binary=None,  # the image ENTRYPOINT is the clang wrapper
        runtime="native",  # the compiler runs natively in the image
        flags_style="posix",
        obj_ext=".o",  # ELF x86_64 object
        description="Clang 18.1.8 (ELF/x86_64) — docker image (native, LLVM release build)",
    ),
    "clang-16.0.4": ToolchainSpec(
        name="clang-16.0.4",
        image="rebrew/clang:16.0.4-linux-x64",
        binary="clang",
        image_binary=None,  # the image ENTRYPOINT is the clang wrapper
        runtime="native",  # the compiler runs natively in the image
        flags_style="posix",
        obj_ext=".o",  # ELF x86_64 object
        description="Clang 16.0.4 (ELF/x86_64) — docker image (native, LLVM release build)",
    ),
    "ido-5.3": ToolchainSpec(
        name="ido-5.3",
        image="rebrew/ido:5.3-linux",
        binary="cc",
        runtime="native",  # ido-static-recomp binaries run natively on Linux
        flags_style="posix",
        obj_ext=".o",  # ELF MIPS object
        description="IDO 5.3 reimplementation (MIPS-II BE, N64) — docker image (native Linux)",
    ),
    "ido-7.1": ToolchainSpec(
        name="ido-7.1",
        image="rebrew/ido:7.1-linux",
        binary="cc",
        runtime="native",  # ido-static-recomp binaries run natively on Linux
        flags_style="posix",
        obj_ext=".o",  # ELF MIPS object
        description="IDO 7.1 reimplementation (MIPS-II BE, N64) — docker image (native Linux)",
    ),
    "watcom-2.0-win32": ToolchainSpec(
        name="watcom-2.0-win32",
        image="rebrew/watcom:2.0-win32",
        binary="wcc386",
        image_binary=None,  # the image ENTRYPOINT is wcc386
        runtime="native",
        flags_style="posix",
        arg_style="watcom",
        obj_ext=".o",  # wcc386 emits OMF (8086 relocatable) — see OMF note
        host_path=vendored_path("watcom/2.0-win32")
        if vendored_path("watcom/2.0-win32").exists()
        else None,
        host_bin="binl",
        description="Open Watcom 2.0 (x86 32-bit) — docker image (native Linux wcc386)",
    ),
    "msvc-1.52": ToolchainSpec(
        name="msvc-1.52",
        image="rebrew/msvc:1.52-win16",
        binary="CL.EXE",
        image_binary=None,  # the image ENTRYPOINT is the cl16 wrapper
        runtime="dosbox",
        bits=16,  # 16-bit target (arch-alignment check)
        flags_style="msvc",
        arg_style="dos",
        obj_ext=".obj",  # 16-bit OMF — see docs/OMF_NOTES.md
        host_path=vendored_path("msvc/1.52-win16")
        if vendored_path("msvc/1.52-win16").exists()
        else None,
        description="MSVC 1.52 (16-bit, Windows 3.x) — DOSBox via rebrew.msvc16",
    ),
    "msvc-2.0": ToolchainSpec(
        name="msvc-2.0",
        image="rebrew/msvc:2.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc2.0/bin",
        host_path=vendored_path("msvc/2.0-win32")
        if vendored_path("msvc/2.0-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 2.0 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-4.1": ToolchainSpec(
        name="msvc-4.1",
        image="rebrew/msvc:4.1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc4.1/bin",
        host_path=vendored_path("msvc/4.1-win32")
        if vendored_path("msvc/4.1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 4.1 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-5.0-sp1": ToolchainSpec(
        name="msvc-5.0-sp1",
        image="rebrew/msvc:5.0-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc5.0-sp1/bin",
        host_path=vendored_path("msvc/5.0-sp1-win32")
        if vendored_path("msvc/5.0-sp1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 5.0 SP1 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-5.0-sp2": ToolchainSpec(
        name="msvc-5.0-sp2",
        image="rebrew/msvc:5.0-sp2-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc5.0-sp2/bin",
        host_path=vendored_path("msvc/5.0-sp2-win32")
        if vendored_path("msvc/5.0-sp2-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 5.0 SP2 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-5.0-sp3": ToolchainSpec(
        name="msvc-5.0-sp3",
        image="rebrew/msvc:5.0-sp3-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc5.0-sp3/bin",
        host_path=vendored_path("msvc/5.0-sp3-win32")
        if vendored_path("msvc/5.0-sp3-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 5.0 SP3 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-6.0-sp3": ToolchainSpec(
        name="msvc-6.0-sp3",
        image="rebrew/msvc:6.0-sp3-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc6.0-sp3/VC98/Bin",
        host_path=vendored_path("msvc/6.0-sp3-win32")
        if vendored_path("msvc/6.0-sp3-win32").exists()
        else None,
        host_bin="Bin",
        description="MSVC 6.0 SP3 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-6.0-sp1": ToolchainSpec(
        name="msvc-6.0-sp1",
        image="rebrew/msvc:6.0-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc6.0-sp1/VC98/bin",
        host_path=vendored_path("msvc/6.0-sp1-win32")
        if vendored_path("msvc/6.0-sp1-win32").exists()
        else None,
        host_bin="Bin",
        description="MSVC 6.0 SP1 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-6.0-sp2": ToolchainSpec(
        name="msvc-6.0-sp2",
        image="rebrew/msvc:6.0-sp2-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc6.0-sp2/VC98/bin",
        host_path=vendored_path("msvc/6.0-sp2-win32")
        if vendored_path("msvc/6.0-sp2-win32").exists()
        else None,
        host_bin="Bin",
        description="MSVC 6.0 SP2 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-6.0-sp4": ToolchainSpec(
        name="msvc-6.0-sp4",
        image="rebrew/msvc:6.0-sp4-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc6.0-sp4/VC98/bin",
        host_path=vendored_path("msvc/6.0-sp4-win32")
        if vendored_path("msvc/6.0-sp4-win32").exists()
        else None,
        host_bin="Bin",
        description="MSVC 6.0 SP4 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-6.0-sp5": ToolchainSpec(
        name="msvc-6.0-sp5",
        image="rebrew/msvc:6.0-sp5-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc6.0-sp5/VC98/Bin",
        host_path=vendored_path("msvc/6.0-sp5-win32")
        if vendored_path("msvc/6.0-sp5-win32").exists()
        else None,
        host_bin="Bin",
        description="MSVC 6.0 SP5 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-6.0-sp5-pp": ToolchainSpec(
        name="msvc-6.0-sp5-pp",
        image="rebrew/msvc:6.0-sp5-pp-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc6.0-sp5-pp/VC98/Bin",
        host_path=vendored_path("msvc/6.0-sp5-pp-win32")
        if vendored_path("msvc/6.0-sp5-pp-win32").exists()
        else None,
        host_bin="Bin",
        description=(
            "MSVC 6.0 SP5 + VC6 Processor Pack (32-bit PE, C89, SSE/SSE2 intrinsics) "
            "— docker image (wine inside)"
        ),
    ),
    "msvc-6.0-sp6": ToolchainSpec(
        name="msvc-6.0-sp6",
        image="rebrew/msvc:6.0-sp6-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc6.0-sp6/VC98/Bin",
        host_path=vendored_path("msvc/6.0-sp6-win32")
        if vendored_path("msvc/6.0-sp6-win32").exists()
        else None,
        host_bin="Bin",
        description="MSVC 6.0 SP6 (32-bit PE, C89) — docker image (wine inside)",
    ),
    "msvc-7.0": ToolchainSpec(
        name="msvc-7.0",
        image="rebrew/msvc:7.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc7.0/Vc7/bin",
        host_path=vendored_path("msvc/7.0-win32")
        if vendored_path("msvc/7.0-win32").exists()
        else None,
        host_bin="Bin",
        description="MSVC 7.0 (32-bit PE, C89) — docker image (wine inside) (13.10.3077 build)",
    ),
    "msvc-7.0-rtm": ToolchainSpec(
        name="msvc-7.0-rtm",
        image="rebrew/msvc:7.0-rtm-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc7.0-rtm/Vc7/bin",
        host_path=vendored_path("msvc/7.0-rtm-win32")
        if vendored_path("msvc/7.0-rtm-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 7.0 RTM (32-bit PE, C89, 13.00.9466) — docker image (wine inside)",
    ),
    "msvc-7.0-sp1": ToolchainSpec(
        name="msvc-7.0-sp1",
        image="rebrew/msvc:7.0-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc7.0-sp1/Vc7/bin",
        host_path=vendored_path("msvc/7.0-sp1-win32")
        if vendored_path("msvc/7.0-sp1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 7.0 SP1 (32-bit PE, C89, 13.00.9466) — docker image (wine inside)",
    ),
    "msvc-7.1": ToolchainSpec(
        name="msvc-7.1",
        image="rebrew/msvc:7.1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc7.1/Vc7/bin",
        host_path=vendored_path("msvc/7.1-win32")
        if vendored_path("msvc/7.1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 7.1 (32-bit PE, C89, 13.10.3077) — docker image (wine inside)",
    ),
    "msvc-7.1-sp1": ToolchainSpec(
        name="msvc-7.1-sp1",
        image="rebrew/msvc:7.1-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc7.1-sp1/Vc7/bin",
        host_path=vendored_path("msvc/7.1-sp1-win32")
        if vendored_path("msvc/7.1-sp1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 7.1 SP1 (32-bit PE, C89, 13.10.6030) — docker image (wine inside)",
    ),
    "msvc-8.0": ToolchainSpec(
        name="msvc-8.0",
        image="rebrew/msvc:8.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc8.0/VC/bin",
        host_path=vendored_path("msvc/8.0-win32")
        if vendored_path("msvc/8.0-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 8.0 (32-bit PE, C89, 14.00.50727) — docker image (wine inside)",
    ),
    "msvc-8.0-sp1": ToolchainSpec(
        name="msvc-8.0-sp1",
        image="rebrew/msvc:8.0-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc8.0-sp1/VC/bin",
        host_path=vendored_path("msvc/8.0-sp1-win32")
        if vendored_path("msvc/8.0-sp1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 8.0 SP1 (32-bit PE, C89, 14.00.50727.762) — docker image (wine inside)",
    ),
    "msvc-9.0": ToolchainSpec(
        name="msvc-9.0",
        image="rebrew/msvc:9.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc9.0/VC/bin",
        host_path=vendored_path("msvc/9.0-win32")
        if vendored_path("msvc/9.0-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 9.0 (32-bit PE, C89, 15.00.21022) — docker image (wine inside)",
    ),
    "msvc-9.0-sp1": ToolchainSpec(
        name="msvc-9.0-sp1",
        image="rebrew/msvc:9.0-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc9.0-sp1/VC/bin",
        host_path=vendored_path("msvc/9.0-sp1-win32")
        if vendored_path("msvc/9.0-sp1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 9.0 SP1 (32-bit PE, C89, 15.00.30729) — docker image (wine inside)",
    ),
    "msvc-11.0": ToolchainSpec(
        name="msvc-11.0",
        image="rebrew/msvc:11.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc11.0/VC/bin",
        host_path=vendored_path("msvc/11.0-win32")
        if vendored_path("msvc/11.0-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 11.0 (32-bit PE, C++, 17.00.50522) — docker image (wine inside)",
    ),
    "msvc-10.0": ToolchainSpec(
        name="msvc-10.0",
        image="rebrew/msvc:10.0-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc10.0/VC/bin",
        host_path=vendored_path("msvc/10.0-win32")
        if vendored_path("msvc/10.0-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 10.0 (32-bit PE, C89, 16.00.30319) — docker image (wine inside)",
    ),
    "msvc-10.0-sp1": ToolchainSpec(
        name="msvc-10.0-sp1",
        image="rebrew/msvc:10.0-sp1-win32",
        binary="cl",
        runtime="wine",
        flags_style="msvc",
        obj_ext=".obj",
        tool_root="/opt/msvc10.0-sp1/VC/bin",
        host_path=vendored_path("msvc/10.0-sp1-win32")
        if vendored_path("msvc/10.0-sp1-win32").exists()
        else None,
        host_bin="bin",
        description="MSVC 10.0 SP1 (32-bit PE, C89, 16.00.40219) — docker image (wine inside)",
    ),
    "msvc-1.5": ToolchainSpec(
        name="msvc-1.5",
        image="rebrew/msvc:1.5-win16",
        binary="CL.EXE",
        image_binary=None,  # the image ENTRYPOINT is the cl15 wrapper
        runtime="dosbox",
        bits=16,  # 16-bit target (arch-alignment check)
        flags_style="msvc",
        arg_style="dos",
        obj_ext=".obj",  # 16-bit OMF — parses via rebrew.omf16
        host_path=vendored_path("msvc/1.5-win16")
        if vendored_path("msvc/1.5-win16").exists()
        else None,
        host_bin="BIN",
        description="MSVC 1.5 (16-bit, Windows 3.x) — DOSBox via rebrew.msvc16 (version=1.5-win16)",
    ),
    "msvc-1.0": ToolchainSpec(
        name="msvc-1.0",
        image="rebrew/msvc:1.0-win16",
        binary="CL.EXE",
        image_binary=None,  # the image ENTRYPOINT is the cl10 wrapper
        runtime="dosbox",
        bits=16,  # 16-bit target (arch-alignment check)
        flags_style="msvc",
        arg_style="dos",
        obj_ext=".obj",  # 16-bit OMF — parses via rebrew.omf16
        host_path=vendored_path("msvc/1.0-win16")
        if vendored_path("msvc/1.0-win16").exists()
        else None,
        host_bin="BIN",
        description="MSVC 1.0 (16-bit, Windows 3.x) — DOSBox via rebrew.msvc16 (version=1.0-win16)",
    ),
    "borland-2.0": ToolchainSpec(
        name="borland-2.0",
        image="rebrew/borland:2.0-win16",
        binary="TCC.EXE",
        runtime="dosbox",
        bits=16,  # 16-bit target (arch-alignment check)
        flags_style="posix",
        arg_style="dos",
        obj_ext=".obj",  # Borland 16-bit OMF — parses via rebrew.omf16
        host_path=vendored_path("borland/2.0-win16")
        if vendored_path("borland/2.0-win16").exists()
        else None,
        host_bin="BIN",
        description="Turbo C 2.0 (16-bit DOS) — DOSBox via rebrew.tc16 (version=2.0)",
    ),
    "borland-3.1": ToolchainSpec(
        name="borland-3.1",
        image="rebrew/borland:3.1-win16",
        binary="TCC.EXE",
        runtime="dosbox",
        bits=16,  # 16-bit target (arch-alignment check)
        flags_style="posix",
        arg_style="dos",
        obj_ext=".obj",  # Borland 16-bit OMF — parses via rebrew.omf16
        host_path=vendored_path("borland/3.1-win16")
        if vendored_path("borland/3.1-win16").exists()
        else None,
        host_bin="BIN",
        description="Turbo C++ 3.1 (16-bit DOS) — DOSBox via rebrew.tc16",
    ),
    "borland-5.5": ToolchainSpec(
        name="borland-5.5",
        image="rebrew/borland:5.5-win32",
        binary="bcc32.exe",
        runtime="wine",
        flags_style="posix",
        arg_style="borland",
        obj_ext=".obj",
        tool_root="/opt/bcc55/Bin",
        host_path=vendored_path("borland/5.5-win32")
        if vendored_path("borland/5.5-win32").exists()
        else None,
        description="Borland C++ 5.5 (32-bit PE, C89) — docker image (wine inside) (free command-line tools)",
    ),
    "watcom-2.0-win16": ToolchainSpec(
        name="watcom-2.0-win16",
        image="rebrew/watcom:2.0-win16",
        binary="wcc",
        image_binary=None,  # the image ENTRYPOINT is the wcc wrapper
        runtime="native",  # the compiler runs natively in the image
        bits=16,  # 16-bit target (arch-alignment check)
        flags_style="posix",
        arg_style="watcom",
        obj_ext=".obj",  # 16-bit OMF — parses via omf16/objconv
        description="Open Watcom 2.0 wcc (16-bit DOS, OMF) — docker image (native Linux)",
    ),
}
