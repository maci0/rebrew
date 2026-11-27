"""smoke.py — Golden smoke verification and container build helpers for toolchains."""

from __future__ import annotations

from typing import Any
lazy import io
lazy import subprocess
lazy from collections.abc import Callable
lazy from pathlib import Path

lazy from rebrew.utils import container_runtime, run_process_group

__all__ = [
    "ARCH_FAMILY",
    "BUILD_LOG_TAIL",
    "COFF_TARGETS",
    "DOCKER_BUILD_TIMEOUT_S",
    "ELF_ARCHES",
    "SDE",
    "SMOKE_DPR",
    "SMOKE_GOLDEN",
    "SMOKE_SOURCE",
    "SMOKE_TIMEOUT_S",
    "build_failure",
    "declared_target",
    "docker_build",
    "masked_obj_sha256",
    "object_target",
    "run_smoke_container",
]

#: Golden object hashes — the byte-exact output each toolchain image must
#: produce for the fixed smoke source (reproducibility evidence: the same
#: source + toolchain → the same object, every build).
SMOKE_SOURCE = "int add(int a, int b) { return a + b; }\n"
SMOKE_DPR = "program hello;\nbegin\nend.\n"
# Fix source mtime for compilers that embed file metadata. Runtime object
# timestamps are separately masked by each golden entry; VC6's COFF stamp
# comes from the build clock, as do __DATE__ and __TIME__ expansions.
SDE = 1767225600  # 2026-01-01 00:00:00 UTC
SMOKE_GOLDEN: dict[
    str, tuple[list[str], str, str, str, tuple[int, int] | list[tuple[int, int]] | None]
] = {
    # name -> (flags, out, golden, src, timestamp-mask (zeroed before hashing) | None)
    "vbcc-0.9h-p2-amiga": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "48f2ad73a8dc116b00716e1ae549d87a55b864eab61abaf10067231e2f4ef457",
        "t.c",
        None,
    ),
    "ack-6.2-7afa32a-linux386": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "d38c79ff5289a211e0e139386749fe515bfc6aa882eac6adbf009ec4831b94cd",
        "t.c",
        None,
    ),
    "cc65-2.19-c64": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "cd6327c8f1df20a0e3646d4d5f3310a11e428b9d3e76dc225a6e45c3f8caf08c",
        "t.c",
        [(100, 105), (109, 113)],
    ),
    "devkita64-16.1.0-1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "fcfe06d67999c350c10031b51dc3aa0a28871a079371fd3caa01656d29198931",
        "t.c",
        None,
    ),
    "devkitarm-16.1.0-1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "5960b15f41c57b5d1da5518b8a577ea79534957c81d16ce99f8b67b0684ffe74",
        "t.c",
        None,
    ),
    "devkitppc-16.2.0-1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0920bdb95b1d37add629127dcb5e211237ba87235c4e12ce00426af98c475397",
        "t.c",
        None,
    ),
    "gbdk-4.5.0-sm83": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ce8d8ac10dec653c82b32e09524af6360788a0571d962799445c2fc7a4cb7736",
        "t.c",
        None,
    ),
    "ia16-gcc-6.3.0-20260612": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "490bec31d3e6a980d56018204dbcacbc75f50c967bc38de56ab4073451cd659e",
        "t.c",
        None,
    ),
    "llvm-mos-23.3.0-c64": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "f5aabe4da2aa14b748abda9627b21d59269df85b0055a58ea602e555bdb46716",
        "t.c",
        None,
    ),
    "llvm-mos-23.3.0-nes": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "f5aabe4da2aa14b748abda9627b21d59269df85b0055a58ea602e555bdb46716",
        "t.c",
        None,
    ),
    "mintelf-gcc-15.2.0": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a92c7c383df829ca78c5eaa1f9a53273411f332766a76295b676d2d6a11afbe4",
        "t.c",
        None,
    ),
    "quickc-2.50": (
        ["t.c"],
        "t.OBJ",
        "534f38edeeb0a1cc83dd486e53573e49804ce401878f454f362e7a06de4eb150",
        "t.c",
        None,
    ),
    "retro68-16.0.0-0cbd3cb-m68k": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "f4c033bac716a8a1a95779e4ed28b8523c7c75816c7182cee208bcd8ef59a5e0",
        "t.c",
        None,
    ),
    "sdcc-4.6.0-8051": (
        ["-c", "t.c", "-o", "t.rel"],
        "t.rel",
        "bc04dbede8b0b518ea562469e13e53fd1597637d22580cff158a94c76ce27e72",
        "t.c",
        None,
    ),
    "sdcc-4.6.0-sm83": (
        ["-c", "t.c", "-o", "t.rel"],
        "t.rel",
        "909f7e07ededd3dd3ab8d10c867b101b48d67fdcf54019eaa8ce2faf5f47b675",
        "t.c",
        None,
    ),
    "sdcc-4.6.0-stm8": (
        ["-c", "t.c", "-o", "t.rel"],
        "t.rel",
        "76e1aacffa95b73484fc3de2af5ea6f4bdde77334c53928e074cc493faf92c94",
        "t.c",
        None,
    ),
    "sdcc-4.6.0-z80": (
        ["-c", "t.c", "-o", "t.rel"],
        "t.rel",
        "2291b832befc653769c2e0a2d9ee0d4e16e65bad92a5ba0a7b52439d9a501f85",
        "t.c",
        None,
    ),
    "watcom-2.0-20261001-win16": (
        ["-zq", "-fo=t.obj", "t.c"],
        "t.obj",
        "85244b6c95dc68fc7de450a4ef422c0bf4ab3a13a882b3cbb5d0e346bb9b01c4",
        "t.c",
        None,
    ),
    "watcom-2.0-20261001-win32": (
        ["-zq", "-fo=t.obj", "t.c"],
        "t.obj",
        "44a6354f779f2c504384019c6786ec1831ca7b5cc20721e1a678295753f08220",
        "t.c",
        None,
    ),
    "z88dk-2.4-sccz80": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "537b6a984a3243ad2b3d5aae1fb9131c8b2083363ddaf003a7fb0083e19f413f",
        "t.c",
        None,
    ),
    "agbcc": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "28b39640a87fdcc99a7ba1b84080e9929b5fdb029f7724e87365973781b8a027",
        "t.c",
        None,
    ),
    "agbcc-arm-gba": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "1602655a2bc8014b0302f8c2e05dbc19e7ddac88f66bc49912dbfcde60f96582",
        "t.c",
        None,
    ),
    "agbcc-fe8j": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "28b39640a87fdcc99a7ba1b84080e9929b5fdb029f7724e87365973781b8a027",
        "t.c",
        None,
    ),
    "agbcc-old-gba": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "28b39640a87fdcc99a7ba1b84080e9929b5fdb029f7724e87365973781b8a027",
        "t.c",
        None,
    ),
    "agbccpp": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "8125fea1732862be679d41fb855feafbb97d1b4c1e87ec49e342b25d28756685",
        "t.c",
        None,
    ),
    "armcc-4.0-771": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "4d8a39cb71bd88f7dcaaf579038bb19b2faad1362497c7fa9c4f4fc89cbeaed9",
        "t.c",
        None,
    ),
    "armcc-4.0-821": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "571c53a6f9b065268f4e6a9f84bdb872a6d433a4d49ff2465e18c7c745398772",
        "t.c",
        None,
    ),
    "armcc-4.0-865": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "eb8f92549944cc22bab347136759b3b897fe0a8527f2dc2cfa7e1dfb40f4f356",
        "t.c",
        None,
    ),
    "armcc-4.0-902": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "e2d4173b8c59cf94125c1cb9e494d4203b5e20e260c74e03970484fef19015ba",
        "t.c",
        None,
    ),
    "armcc-4.1-1049": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0047d90dc83ecfc2a5c1f64eda6e77a292e2c6d8cbbcb7c03afda55996ae121e",
        "t.c",
        None,
    ),
    "armcc-4.1-1440": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "e4762d01794120d951006370079e9f35cda8323111c23d94d661878c2e7c51e4",
        "t.c",
        None,
    ),
    "armcc-4.1-1454": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "f428922a7febfa7c396e5a66be22e118ad0e50913ab7ba992bb2a1af27573ea5",
        "t.c",
        None,
    ),
    "armcc-4.1-561": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "2fa66c35b731ec1491f0287d25bc599af01afdd12d1f68be82625adb9606406f",
        "t.c",
        None,
    ),
    "armcc-4.1-713": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "8a665486d22cfa0e0980876d41606ac8b10f05c816bea7d4ea644328608fbf11",
        "t.c",
        None,
    ),
    "armcc-4.1-791": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "9a21b977094c2379820c59f2293d4b1b7f9aff00e6b011613ede251b2b87841d",
        "t.c",
        None,
    ),
    "armcc-4.1-844": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "2b94aa749162fc1e4bf5b361281c49db2d978295358a4f7ad587a74a25fce2c6",
        "t.c",
        None,
    ),
    "armcc-4.1-894": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0c4dbf1c758f29da8c2991af66cbbf662b9956fc9aa6cbd9cf9d61d1e6053234",
        "t.c",
        None,
    ),
    "armcc-4.1-921": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "273f98be821a36499984de1be4d79b8547f016c78412055198516d044d248db5",
        "t.c",
        None,
    ),
    "armcc-5.04-82": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "f131c3195142a536bb927476cbb5db2d2d81f8b045b24618b059510e0a557d3e",
        "t.c",
        None,
    ),
    "bootlin-m68k-glibc-2026.08-1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "4e22bb378bef32571255d08debb2954005440caafadfc296dbfe2ba59ddcec00",
        "t.c",
        None,
    ),
    "borland-2.0-decompme": (
        ["t.c"],
        "t.OBJ",
        "4014d10c9e106017d90a0da89afba4382fde16cfc212708dbf237630f675b718",
        "t.c",
        [(48, 52), (58, 59), (201, 206)],
    ),
    "borland-3.1-decompme": (
        ["t.c"],
        "t.OBJ",
        "c267d84bb109d7c56bed3ee2719279ccdb807b461b1cc7f2e66e2eff71bb2f78",
        "t.c",
        [(50, 54), (60, 61), (213, 218)],
    ),
    "borland-5.6": (
        ["-c", "t.c"],
        "t.obj",
        "b1875401454ec46636a0cae798f815a55641acfb06284a086ac7f139c4a39f06",
        "t.c",
        None,
    ),
    "clang-3.9.1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "d4ab9b75a3eb750d459561e8123f7364d62cacacd6e5736727fd8b7b56f71eea",
        "t.c",
        None,
    ),
    "clang-4.0.1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ff2e852978a86a69eef5c93e853e8963785326bbb8d74401ac1b8dcef35e0581",
        "t.c",
        None,
    ),
    "clang-8.0.0": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "06d602f78e3d452ee7326b5108530833cf1761ee5ca58df88fa2449bd8450f8e",
        "t.c",
        None,
    ),
    "clang-9.0.0": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "353e7f58814394b7a1e0adce01e75f2f77d5e952bc7bf17eb7d6a2db7a5805b6",
        "t.c",
        None,
    ),
    "djgpp-12.2.0": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a98c1f815c62d9dfe3ce61d514f20d7565d5889000bb3221816db272917cb701",
        "t.c",
        (4, 8),
    ),
    "ee-gcc-2.9-990721": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "e021ffa82bce669644fc4908ad71b9ef7e183672c0ef128a8662333ac2928971",
        "t.c",
        None,
    ),
    "ee-gcc-2.9-991111": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "e021ffa82bce669644fc4908ad71b9ef7e183672c0ef128a8662333ac2928971",
        "t.c",
        None,
    ),
    "ee-gcc-2.9-991111-01": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "e021ffa82bce669644fc4908ad71b9ef7e183672c0ef128a8662333ac2928971",
        "t.c",
        None,
    ),
    "ee-gcc-2.9-991111-01-dtls13010": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "e190654865d7ddd61886c33adbfde849ec0236a121e5b95879f14ff9a4ca6059",
        "t.c",
        None,
    ),
    "ee-gcc-2.9-991111a": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "e021ffa82bce669644fc4908ad71b9ef7e183672c0ef128a8662333ac2928971",
        "t.c",
        None,
    ),
    "ee-gcc-2.9-991111b-r4": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "39db592a8c5231000f3abea8354abe78ba6f8cd5ddf615e9343e5a4e69165158",
        "t.c",
        None,
    ),
    "ee-gcc-2.95.2-273a": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "1882a59278087a8d07a95c37321f0eae4abfcee507dadf1e5ce6f0d6c3ff6f07",
        "t.c",
        None,
    ),
    "ee-gcc-2.95.2-274": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "1882a59278087a8d07a95c37321f0eae4abfcee507dadf1e5ce6f0d6c3ff6f07",
        "t.c",
        None,
    ),
    "ee-gcc-2.95.3-107": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "1882a59278087a8d07a95c37321f0eae4abfcee507dadf1e5ce6f0d6c3ff6f07",
        "t.c",
        None,
    ),
    "ee-gcc-2.95.3-114": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "1882a59278087a8d07a95c37321f0eae4abfcee507dadf1e5ce6f0d6c3ff6f07",
        "t.c",
        None,
    ),
    "ee-gcc-2.95.3-136": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "1882a59278087a8d07a95c37321f0eae4abfcee507dadf1e5ce6f0d6c3ff6f07",
        "t.c",
        None,
    ),
    "ee-gcc-2.96": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "d41160ea3e68ff8539cc0b9967a1f1023b1cf0bed5366bff7d7ab85a50cc7aee",
        "t.c",
        None,
    ),
    "ee-gcc-3.2-030210-beta2": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "be771f0b36562a131cf16ce5b793e11b8fe86b6d11989cef1a5d77bdf53cc943",
        "t.c",
        None,
    ),
    "ee-gcc-3.2-030926": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "3e23bc3cb6c355ca3114c0d58f9c09f9146aab1790c2f204b86dc87a1805ede8",
        "t.c",
        None,
    ),
    "ee-gcc-3.2-040921": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "3e23bc3cb6c355ca3114c0d58f9c09f9146aab1790c2f204b86dc87a1805ede8",
        "t.c",
        None,
    ),
    "gcc-2.5.7-mipsel": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "f24abb3edbf67080374c34e52f7cc9b1f2e18053b5e5ea69185507204eee444d",
        "t.c",
        None,
    ),
    "gcc-2.5.7-psx": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "fdc522953d68de5c0673c0e3f81f6b8d96a75339e04d2aba66b538ab9852719d",
        "t.c",
        None,
    ),
    "gcc-2.6.0-mipsel": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ae226a98deb005edc5c34470657dc388b74faaabfb05e03de9f9156b840fd8ac",
        "t.c",
        None,
    ),
    "gcc-2.6.0-psx": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "98afa59d7bb81f126c199d6cbd1970b74611898a5420f8e0a089b005d0fa82df",
        "t.c",
        None,
    ),
    "gcc-2.6.3-mipsel": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.6.3-ps1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.7.0-mipsel": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.7.1-mipsel": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.7.2-cdk": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.7.2-kmc": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "38761c9dba459f44133eab2b26b1d1f8cf34427dba2156b6ee6269cd451ab682",
        "t.c",
        None,
    ),
    "gcc-2.7.2-mipsel": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.7.2-psx": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.7.2-sn0001": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "e52ab2f65b0d3ed1743695d378a035da910ea24a0f1a9200056977be78b0d7d9",
        "t.c",
        None,
    ),
    "gcc-2.7.2-sn0001-cxx": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "923ecdfb236d16d1df78acbf46f3d09920bd853b6290497fdd4eb5d4654cce4a",
        "t.c",
        None,
    ),
    "gcc-2.7.2-sn0004": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "3fc3e9c218a07db822e874789b21823e3adf240e276e620f090c596595e82f1d",
        "t.c",
        None,
    ),
    "gcc-2.7.2-sn0006": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "e52ab2f65b0d3ed1743695d378a035da910ea24a0f1a9200056977be78b0d7d9",
        "t.c",
        None,
    ),
    "gcc-2.7.2-sn0006-cxx": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "923ecdfb236d16d1df78acbf46f3d09920bd853b6290497fdd4eb5d4654cce4a",
        "t.c",
        None,
    ),
    "gcc-2.7.2-snew": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0093d54345f2de568bc220a10514393685314e7a1f6433f46615ac873b9ad315",
        "t.c",
        None,
    ),
    "gcc-2.7.2.1-mipsel": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.7.2.2-mipsel": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.7.2.3-mipsel": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.8.0-mipsel": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.8.0-psx": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.8.1-mipsel": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.8.1-pm": (
        ["-pipe", "-c", "t.c", "-o", "t.o"],
        "t.o",
        "fcffde9d2d7ce25515e4355d8ab96d6be06cab98ccef0b32e41f144c20a90f3b",
        "t.c",
        None,
    ),
    "gcc-2.8.1-psx": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.8.1-sn": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "e52ab2f65b0d3ed1743695d378a035da910ea24a0f1a9200056977be78b0d7d9",
        "t.c",
        None,
    ),
    "gcc-2.8.1-sn-cxx": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "923ecdfb236d16d1df78acbf46f3d09920bd853b6290497fdd4eb5d4654cce4a",
        "t.c",
        None,
    ),
    "gcc-2.8.1-snew-cxx": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "b5f29ab77cd18940d1efd16986d9e9fef3f2c17546b0666873490c26b4b16d18",
        "t.c",
        None,
    ),
    "gcc-2.91.66-mipsel": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.91.66-psx": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.95.2-mipsel": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "4e82b9bdba766f2735c2e3207f4335460dd31e718890b8fd001030a0352a7e8f",
        "t.c",
        None,
    ),
    "gcc-2.95.2-ps1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "gcc-2.96": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "b5aada8f5c1b34afdbbc4a2beee103fb9210c6050f42816e776a5508beb5d2a0",
        "t.c",
        None,
    ),
    "gcc-3.1-1041": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0173cd6440a7b1241d1a143720c13dba32a5c17ecf90382f82e49d7370d6b29d",
        "t.c",
        None,
    ),
    "gcc-3.2-rh8": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "dd7686a51f8ede6f3a082efbbf8a16a3e43be6172ac6227e8e4b157136660b4f",
        "t.c",
        None,
    ),
    "gcc-4.0.0-5026": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "7d455259f44e9082b9e990395ad675146076e5d334a1becb6d83792adea776c6",
        "t.c",
        None,
    ),
    "gcc-4.0.1-5363": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "7d455259f44e9082b9e990395ad675146076e5d334a1becb6d83792adea776c6",
        "t.c",
        None,
    ),
    "gcc-4.0.1-5370": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "7d455259f44e9082b9e990395ad675146076e5d334a1becb6d83792adea776c6",
        "t.c",
        None,
    ),
    "gcc-4.4.0-mips64-elf": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ed06347a819bcd0315e874eb66c65ec3b8e276ba44149c0fe59dac154031b12a",
        "t.c",
        None,
    ),
    "gcc-egcs-1.1.2-4": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "b7d0f38966d83b1229835d14ef60ed30efe5bff0092d5b0b1b70095c261dcb27",
        "t.c",
        None,
    ),
    "gcc-egcs-1.1.2-4c": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "560cc2438b2625fbb7ab4a255390637f4e4e831754426b9481894171a83b3ccf",
        "t.c",
        None,
    ),
    "ghs-5.3.22": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "f506998c657a567a1d5c900b3015ecbc0a59dfdb8a62f999b6d7529993fcc194",
        "t.c",
        None,
    ),
    "icc-5.0.1-010525z": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "6fcadfe99935cff5fb7e24d8f42af5745ea5efae8d93efabd21ec3affe0c5d5f",
        "t.c",
        (4, 8),
    ),
    "ido-4.1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0b491122de659ee3725c21aff8476e18372cabacda3061d2df8b3984505a54e0",
        "t.c",
        None,
    ),
    "ido-5.2": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "063e6ff78b13504844a7c1c6ed7639ea9e4d7850c9172b2ce98bb1b696c846b6",
        "t.c",
        None,
    ),
    "ido-5.3-cxx": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "dcc869d99c31f15beb6f553d9cb59373f8f5d5e8b1a5ace92c4655367a070683",
        "t.c",
        None,
    ),
    "ido-5.3-irix": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ca1c35d2a8b09732a72548ff32d20879f005295069894b054244c451aee26f67",
        "t.c",
        None,
    ),
    "ido-5.3-linux": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ca1c35d2a8b09732a72548ff32d20879f005295069894b054244c451aee26f67",
        "t.c",
        None,
    ),
    "ido-6.0": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "e0ff0808d960e8a6e958f719065ebc583a8bc2dc8b315efdacf260115cda26be",
        "t.c",
        None,
    ),
    "ido-7.1-cxx": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a933832b85b5602310dda2001d17a8f8a6c62a1831142ade5ffb657f7f35082a",
        "t.c",
        None,
    ),
    "ido-7.1-linux": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "4dbfd49bab0cee26de68339472e9ec43ce14d21a4ff601feddd4ca79e8b6c444",
        "t.c",
        None,
    ),
    "ido-mipspro-744": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "80d839d3767f3ef7bc3ebdb61cb7cca2adc204ea799fa18905d80387d0673720",
        "t.c",
        None,
    ),
    "iop-gcc-2.8.1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bc6f6c0ba899638cdf4f4a5f7b25df0ae634724bf93f5e70141ebf0d1d146747",
        "t.c",
        None,
    ),
    "iop-gcc-2.95.2-102": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bc6f6c0ba899638cdf4f4a5f7b25df0ae634724bf93f5e70141ebf0d1d146747",
        "t.c",
        None,
    ),
    "msc-5.1": (
        ["t.c"],
        "t.OBJ",
        "f0b8dcfd793499b4d6b7afac4743d3b81cd4f35d360e05f6a12165b3a81583c5",
        "t.c",
        None,
    ),
    "msc-6.0": (
        ["t.c"],
        "t.OBJ",
        "a10772c278d7f4cd3a363eaf473ff53ef0f8c6ab4f8c66838b6f2cd18a73e655",
        "t.c",
        None,
    ),
    "msvc-12.0-u4": (
        ["/nologo", "/c", "t.c", "/Fot.obj"],
        "t.obj",
        "a742e2747fb2afa813c05a9dd3567c6727a4dd2017030840fd3794cb295ac434",
        "t.c",
        (4, 8),
    ),
    "msvc-6.0-sp5-crt": (
        ["/nologo", "/c", "t.c", "/Fot.obj"],
        "t.obj",
        "547b88f827c13e9273f46b1a72415002289fac62d0f65dc0ef9289dbc5a3e546",
        "t.c",
        (4, 8),
    ),
    "msvc-8.0-portable": (
        ["/nologo", "/c", "t.c", "/Fot.obj"],
        "t.obj",
        "c6d82406d884675a4be4910786da9350baa8b9e4ad1fb60de94abaa4e2e5bee2",
        "t.c",
        (4, 8),
    ),
    "msvc-ppc-14.00.2110": (
        ["/nologo", "/c", "t.c", "/Fot.obj"],
        "t.obj",
        "325629cfe217f38840e28ebf1b3093fd962bd5f40243055210d67f94fed13ef8",
        "t.c",
        (4, 8),
    ),
    "msvc-ppc-16.00.11886": (
        ["/nologo", "/c", "t.c", "/Fot.obj"],
        "t.obj",
        "3427c30e122a1e792fd3143181184efb6a34dcc0ada6c057676ef39e39f98f0f",
        "t.c",
        (4, 8),
    ),
    "mwcc-2.3.3-144": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "92e4d4e5c3e0d1aa9e272ee73a35f445512b1475679b07d78bc4971eb818b42b",
        "t.c",
        None,
    ),
    "mwcc-2.3.3-159": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "92e4d4e5c3e0d1aa9e272ee73a35f445512b1475679b07d78bc4971eb818b42b",
        "t.c",
        None,
    ),
    "mwcc-2.3.3-159p1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "92e4d4e5c3e0d1aa9e272ee73a35f445512b1475679b07d78bc4971eb818b42b",
        "t.c",
        None,
    ),
    "mwcc-2.3.3-163": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "92e4d4e5c3e0d1aa9e272ee73a35f445512b1475679b07d78bc4971eb818b42b",
        "t.c",
        None,
    ),
    "mwcc-2.3.3-163e": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "86703bd9957cf727e1c6eaeabb64da9f9d5ea3e9960bb1829327b7d024164a9f",
        "t.c",
        None,
    ),
    "mwcc-2.3.3-163n": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "92e4d4e5c3e0d1aa9e272ee73a35f445512b1475679b07d78bc4971eb818b42b",
        "t.c",
        None,
    ),
    "mwcc-2.4.2-53": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "43444755ccbda0c817c6cb97a190d5f40ba7c91443971fcd93625bb75200c76c",
        "t.c",
        None,
    ),
    "mwcc-2.4.2-81": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "43444755ccbda0c817c6cb97a190d5f40ba7c91443971fcd93625bb75200c76c",
        "t.c",
        None,
    ),
    "mwcc-2.4.2-81r": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "43444755ccbda0c817c6cb97a190d5f40ba7c91443971fcd93625bb75200c76c",
        "t.c",
        None,
    ),
    "mwcc-2.4.7-105": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "69339ea7e678adb727ed9028e943676e90a0f46129ac2934640c62ac73cb0cbd",
        "t.c",
        None,
    ),
    "mwcc-2.4.7-107": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "69339ea7e678adb727ed9028e943676e90a0f46129ac2934640c62ac73cb0cbd",
        "t.c",
        None,
    ),
    "mwcc-2.4.7-108": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "2ddd511ff1dbbfbcac33477c5793f1d32fe9add282b0625a82185ce65acb426e",
        "t.c",
        None,
    ),
    "mwcc-2.4.7-92": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "69339ea7e678adb727ed9028e943676e90a0f46129ac2934640c62ac73cb0cbd",
        "t.c",
        None,
    ),
    "mwcc-2.4.7-92p1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "69339ea7e678adb727ed9028e943676e90a0f46129ac2934640c62ac73cb0cbd",
        "t.c",
        None,
    ),
    "mwcc-4.1-51213": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0102e0218c566de8d0f01ccfcc7316909c59f639754eb022461306d2d81f12b8",
        "t.c",
        None,
    ),
    "mwcc-4.1-60126": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0102e0218c566de8d0f01ccfcc7316909c59f639754eb022461306d2d81f12b8",
        "t.c",
        None,
    ),
    "mwcc-4.1-60209": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0102e0218c566de8d0f01ccfcc7316909c59f639754eb022461306d2d81f12b8",
        "t.c",
        None,
    ),
    "mwcc-4.1-60831": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a64b72996370cf1c34c734548344ff0c17c4117278ee9e9b406bfadb76581437",
        "t.c",
        None,
    ),
    "mwcc-4.2-127": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a64b72996370cf1c34c734548344ff0c17c4117278ee9e9b406bfadb76581437",
        "t.c",
        None,
    ),
    "mwcc-4.2-140": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a64b72996370cf1c34c734548344ff0c17c4117278ee9e9b406bfadb76581437",
        "t.c",
        None,
    ),
    "mwcc-4.2-142": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a64b72996370cf1c34c734548344ff0c17c4117278ee9e9b406bfadb76581437",
        "t.c",
        None,
    ),
    "mwcc-4.2-60308": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0102e0218c566de8d0f01ccfcc7316909c59f639754eb022461306d2d81f12b8",
        "t.c",
        None,
    ),
    "mwcc-4.2-60422": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a64b72996370cf1c34c734548344ff0c17c4117278ee9e9b406bfadb76581437",
        "t.c",
        None,
    ),
    "mwcc-4.3-145": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a64b72996370cf1c34c734548344ff0c17c4117278ee9e9b406bfadb76581437",
        "t.c",
        None,
    ),
    "mwcc-4.3-151": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a64b72996370cf1c34c734548344ff0c17c4117278ee9e9b406bfadb76581437",
        "t.c",
        None,
    ),
    "mwcc-4.3-172": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a64b72996370cf1c34c734548344ff0c17c4117278ee9e9b406bfadb76581437",
        "t.c",
        None,
    ),
    "mwcc-4.3-188": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a64b72996370cf1c34c734548344ff0c17c4117278ee9e9b406bfadb76581437",
        "t.c",
        None,
    ),
    "mwcc-4.3-202": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a64b72996370cf1c34c734548344ff0c17c4117278ee9e9b406bfadb76581437",
        "t.c",
        None,
    ),
    "mwcc-4.3-213": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a64b72996370cf1c34c734548344ff0c17c4117278ee9e9b406bfadb76581437",
        "t.c",
        None,
    ),
    "mwccarm-2.0-56": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "fdf8266028c0139a334e1c4c2b4eae98aa44637572aa4512a32a547c9bc49ae9",
        "t.c",
        None,
    ),
    "mwccarm-2.0-72": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "26a091da28d1b064f09c9ef52415a268e3012a9a7b7f00b9ef4bb0349588bfbe",
        "t.c",
        None,
    ),
    "mwccarm-2.0-79": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "dcf944c8bfd04ae467543d71a1e08e8ce1cfad040393e0a2aa2ae573b63f43dc",
        "t.c",
        None,
    ),
    "mwccarm-2.0-82": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "9db96cf54039ddda13d40b59fe252dac47f6c2728b5c186ff1967bb40ad2f083",
        "t.c",
        None,
    ),
    "mwccarm-2.0-84": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "d916b87c3adaba30fabb6fcf66d2dfb4144ec2f80d80b72eb5c0ed7276f28dcc",
        "t.c",
        None,
    ),
    "mwccarm-2.0-87": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a6c232cf85217def86b14a5c0ef149786015919c8c16497117fd4fb5d0a1bbb9",
        "t.c",
        None,
    ),
    "mwccarm-3.0-114": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0e5fc412ca3e27f9bf2351aa5cfe82be6912fb7dd09e8875dfe9564ca2adae92",
        "t.c",
        None,
    ),
    "mwccarm-3.0-123": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "3ac1c93f73c3838f2c943402bddfdda050d7b768d9f506cd205bd99408cf51cb",
        "t.c",
        None,
    ),
    "mwccarm-3.0-126": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "4e7b7bebb57237d0cc18ac7aae3d8b5ab5b58cb24a3eaeaa6e01266503d12142",
        "t.c",
        None,
    ),
    "mwccarm-3.0-131": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "2fcdce0515afb9e34027bee8a787f4be4960f1880058fa8f10629bd805596af7",
        "t.c",
        None,
    ),
    "mwccarm-3.0-133": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "b4a9fd468db740817d35a5d21a056b71ebf0ec5fe2cdcb88bceb956d6776cdd5",
        "t.c",
        None,
    ),
    "mwccarm-3.0-134": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "4734e6194d1c0643b07c56ff7bd1c1fe5649695066dfd39a8125fd7e5976aa13",
        "t.c",
        None,
    ),
    "mwccarm-3.0-136": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "68eb373a5623aa4069880f65937c80bd5421bf7900f12945871949191faad49f",
        "t.c",
        None,
    ),
    "mwccarm-3.0-137": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "60612d5a621fed23a85754651469ed04e71b3bee5ea115dc0ffae8d21d5cf94b",
        "t.c",
        None,
    ),
    "mwccarm-3.0-138": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "4dcfda5f4075bca2a8e94b548f1b28df0072b0e690bb3e12bee2165eaf1ef419",
        "t.c",
        None,
    ),
    "mwccarm-3.0-139": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "eaeaf6f1aea930b6d7cd3197954343b9ace30a8ff7b9f0dad04fc99fff159505",
        "t.c",
        None,
    ),
    "mwccarm-4.0-1018": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a99e7fc00d3252810a959a895008b717bb439acd1a17bc69b7b4a7cfdaa5f4c6",
        "t.c",
        None,
    ),
    "mwccarm-4.0-1024": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "d8240b9bf957db2393bd20248e7766f45736ee115926f919489f8ef6e6968d27",
        "t.c",
        None,
    ),
    "mwccarm-4.0-1026": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "265d83e285e69daec3aeea9cc8c607a1937a5d283e23422c68cd3b741b4afa36",
        "t.c",
        None,
    ),
    "mwccarm-4.0-1027": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a376048c2b81a7adb378e6e77eca967a2dfe637ddb988daceb44dec56653f34c",
        "t.c",
        None,
    ),
    "mwccarm-4.0-1028": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a8228589bc27a7836f1aa2f928b50402015a6ed9a2120cc875ad2b924be16eeb",
        "t.c",
        None,
    ),
    "mwccarm-4.0-1034": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "9cf2e8d12eae7086449dcfb2f38341d44bcd3ce5bdfa99788016e70a2ffc8ea0",
        "t.c",
        None,
    ),
    "mwccarm-4.0-1036": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "f39fda0d28e2888aa1b89a28b3cecbaa03c5bae9e402b64ca69f133820f8f31c",
        "t.c",
        None,
    ),
    "mwccarm-4.0-1051": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "1cbef06ef3a133d1e7c43e8b3483e720d6c16ad570d52ca0160b861021b168d2",
        "t.c",
        None,
    ),
    "mwccpsp-3.0.1-121": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "8cb1217ecf5796977f2436b5cfce241afbe8b4d2b1a4b28ec77661e0d74b47b6",
        "t.c",
        None,
    ),
    "mwccpsp-3.0.1-134": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "8cb1217ecf5796977f2436b5cfce241afbe8b4d2b1a4b28ec77661e0d74b47b6",
        "t.c",
        None,
    ),
    "mwccpsp-3.0.1-139": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bb43657b6e93cc46397a37c34ac0df88f3e9f611c35fb4e79596c4afdfc21dcb",
        "t.c",
        None,
    ),
    "mwccpsp-3.0.1-147": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bb43657b6e93cc46397a37c34ac0df88f3e9f611c35fb4e79596c4afdfc21dcb",
        "t.c",
        None,
    ),
    "mwccpsp-3.0.1-151": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bb43657b6e93cc46397a37c34ac0df88f3e9f611c35fb4e79596c4afdfc21dcb",
        "t.c",
        None,
    ),
    "mwccpsp-3.0.1-180": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bb43657b6e93cc46397a37c34ac0df88f3e9f611c35fb4e79596c4afdfc21dcb",
        "t.c",
        None,
    ),
    "mwccpsp-3.0.1-192": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bb43657b6e93cc46397a37c34ac0df88f3e9f611c35fb4e79596c4afdfc21dcb",
        "t.c",
        None,
    ),
    "mwccpsp-3.0.1-201": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bb43657b6e93cc46397a37c34ac0df88f3e9f611c35fb4e79596c4afdfc21dcb",
        "t.c",
        None,
    ),
    "mwccpsp-3.0.1-205": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bb43657b6e93cc46397a37c34ac0df88f3e9f611c35fb4e79596c4afdfc21dcb",
        "t.c",
        None,
    ),
    "mwccpsp-3.0.1-210": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bb43657b6e93cc46397a37c34ac0df88f3e9f611c35fb4e79596c4afdfc21dcb",
        "t.c",
        None,
    ),
    "mwccpsp-3.0.1-219": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bb43657b6e93cc46397a37c34ac0df88f3e9f611c35fb4e79596c4afdfc21dcb",
        "t.c",
        None,
    ),
    "mwcps2-2.3-991202": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "066f7b8999578eeb3c313b21ef3c5653948ff6a2bd6058bc6a2175bb5a66ac93",
        "t.c",
        None,
    ),
    "mwcps2-2.3.3-000906": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "7f45ac7f9ef92db50f0f493249704130ac22c20b7e660edc3a7e63058fd8ca73",
        "t.c",
        None,
    ),
    "mwcps2-2.4-001213": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "9c6908d96a24c4b7b9f2ca27998be2eaf6bbbabe5da92d158cefd8f6ace8f1de",
        "t.c",
        None,
    ),
    "mwcps2-3.0-011126": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "9c6908d96a24c4b7b9f2ca27998be2eaf6bbbabe5da92d158cefd8f6ace8f1de",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1-020123": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "9c6908d96a24c4b7b9f2ca27998be2eaf6bbbabe5da92d158cefd8f6ace8f1de",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1b103-040528": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1b119-040914": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1b145-050209": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1b151-050317": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1b198-051011": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1b205-051227": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1b210-060308": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1b44-030325": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1b51-030512": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1b74-030811": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1b75-030916": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1b87-031208": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0.1b95-040309": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0.3": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "9c6908d96a24c4b7b9f2ca27998be2eaf6bbbabe5da92d158cefd8f6ace8f1de",
        "t.c",
        None,
    ),
    "mwcps2-3.0b22-020926": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "9c6908d96a24c4b7b9f2ca27998be2eaf6bbbabe5da92d158cefd8f6ace8f1de",
        "t.c",
        None,
    ),
    "mwcps2-3.0b38-030307": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0b50-030527": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "mwcps2-3.0b52-030722": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "88d010b262db0eb56907224a2cfa94eb2c4c2acdbcd83c95cdb95bd842869760",
        "t.c",
        None,
    ),
    "ndk-r8e-4.4.3": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "cb3fd414c7e5b95487dda8af6afbeaf8bc988ebaa634c38d9e1b75dfdc666701",
        "t.c",
        None,
    ),
    "ndk-r8e-4.7": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "9a38fab979a8b0a3990f4122817673ee0be0886c687d50733b7fdd62719e97c3",
        "t.c",
        None,
    ),
    "prodg-3.5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "f1a32839c9ac9cec393ae99d04502565e31dd2e03793d828e801c23bb8365ccc",
        "t.c",
        None,
    ),
    "prodg-3.5b140": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "f1a32839c9ac9cec393ae99d04502565e31dd2e03793d828e801c23bb8365ccc",
        "t.c",
        None,
    ),
    "prodg-3.7": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "f1a32839c9ac9cec393ae99d04502565e31dd2e03793d828e801c23bb8365ccc",
        "t.c",
        None,
    ),
    "prodg-3.8.1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "9810daee7c9913f2ceceb39a2e5f86fe24221e898c3652009ed955452639c2db",
        "t.c",
        None,
    ),
    "prodg-3.9.3": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "9810daee7c9913f2ceceb39a2e5f86fe24221e898c3652009ed955452639c2db",
        "t.c",
        None,
    ),
    "ps2dev-2.0.0-ee": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "2959ee51aae42e62dc8843e3cf36fd8c79df689d5e414ef5116e618e73c1439f",
        "t.c",
        None,
    ),
    "ps2dev-2.0.0-iop": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "f1c9e2dd37504e83252c9533b0cb98f5e110dafa9b760771b4f3cdc63131789e",
        "t.c",
        None,
    ),
    "psp-gcc-1.3.1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0b03c07a8df16ead4d8848f309c20cdc3d4d524165f28f36dcddd323f0232fae",
        "t.c",
        None,
    ),
    "pspdev-20261001": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "b08894496bb020fc6a21cb9d32037321496665b52da1871c3f0c57d3096a9605",
        "t.c",
        None,
    ),
    "pspsnc-1.2.7503.0": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ed9fd59d331ea7092f5fc51e8b49bb070c7144ef2f851e8b6aa1a0869e1317d0",
        "t.c",
        None,
    ),
    "psyq-2.6.3-221": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "7cd2617fda85c1472b60cabc4df2a3d3baa70018dbcb6ff9c8021a577f7797fa",
        "t.c",
        None,
    ),
    "psyq-3.3": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "7cd2617fda85c1472b60cabc4df2a3d3baa70018dbcb6ff9c8021a577f7797fa",
        "t.c",
        None,
    ),
    "psyq-3.5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "7cd2617fda85c1472b60cabc4df2a3d3baa70018dbcb6ff9c8021a577f7797fa",
        "t.c",
        None,
    ),
    "psyq-3.6": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "7cd2617fda85c1472b60cabc4df2a3d3baa70018dbcb6ff9c8021a577f7797fa",
        "t.c",
        None,
    ),
    "psyq-4.0": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "7cd2617fda85c1472b60cabc4df2a3d3baa70018dbcb6ff9c8021a577f7797fa",
        "t.c",
        None,
    ),
    "psyq-4.1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "7cd2617fda85c1472b60cabc4df2a3d3baa70018dbcb6ff9c8021a577f7797fa",
        "t.c",
        None,
    ),
    "psyq-4.3": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "7cd2617fda85c1472b60cabc4df2a3d3baa70018dbcb6ff9c8021a577f7797fa",
        "t.c",
        None,
    ),
    "psyq-4.4": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "7cd2617fda85c1472b60cabc4df2a3d3baa70018dbcb6ff9c8021a577f7797fa",
        "t.c",
        None,
    ),
    "psyq-4.5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "ee7b003d8782abb0bd677e5a2f26451515fdb8ac8f5f907d255ea04eed9d82c3",
        "t.c",
        None,
    ),
    "psyq-4.6": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bd5adb2a378c4a8730a4af4e211db53715f4041b321fa46c2e4d2b15367d0a7a",
        "t.c",
        None,
    ),
    "saturn-cygnus-2.7-96Q3": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "16d2ecc9c1eb3647bdefb3e0937f140f765c1cd275e0726317201f9f51f74f84",
        "t.c",
        None,
    ),
    "saturn-cygnus-2.7-96Q3-native64": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "558a5925b6fc035067e0d2b30119a87c791955a0b99ca2a89a3b8b7a5aa44f97",
        "t.c",
        None,
    ),
    "shc-5.0r10": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "06fd6fbba9f05ccbc0dc10b4018017b0dd5fc120e7304c89fa366a804ab083e6",
        "t.c",
        (114, 126),
    ),
    "shc-5.0r26": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "06fd6fbba9f05ccbc0dc10b4018017b0dd5fc120e7304c89fa366a804ab083e6",
        "t.c",
        (114, 126),
    ),
    "shc-5.0r28": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "06fd6fbba9f05ccbc0dc10b4018017b0dd5fc120e7304c89fa366a804ab083e6",
        "t.c",
        (114, 126),
    ),
    "shc-5.0r31": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "06fd6fbba9f05ccbc0dc10b4018017b0dd5fc120e7304c89fa366a804ab083e6",
        "t.c",
        (114, 126),
    ),
    "shc-5.0r32": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "06fd6fbba9f05ccbc0dc10b4018017b0dd5fc120e7304c89fa366a804ab083e6",
        "t.c",
        (114, 126),
    ),
    "shc-5.1r01": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "06fd6fbba9f05ccbc0dc10b4018017b0dd5fc120e7304c89fa366a804ab083e6",
        "t.c",
        (114, 126),
    ),
    "shc-5.1r03": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "06fd6fbba9f05ccbc0dc10b4018017b0dd5fc120e7304c89fa366a804ab083e6",
        "t.c",
        (114, 126),
    ),
    "shc-5.1r04": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "06fd6fbba9f05ccbc0dc10b4018017b0dd5fc120e7304c89fa366a804ab083e6",
        "t.c",
        (114, 126),
    ),
    "shc-5.1r08": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "06fd6fbba9f05ccbc0dc10b4018017b0dd5fc120e7304c89fa366a804ab083e6",
        "t.c",
        (114, 126),
    ),
    "shc-5.1r11": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "06fd6fbba9f05ccbc0dc10b4018017b0dd5fc120e7304c89fa366a804ab083e6",
        "t.c",
        (114, 126),
    ),
    "shc-5.1r13": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "06fd6fbba9f05ccbc0dc10b4018017b0dd5fc120e7304c89fa366a804ab083e6",
        "t.c",
        (114, 126),
    ),
    "watcom-10.0a": (
        ["-zq", "-fo=t.obj", "t.c"],
        "t.obj",
        "67a686686dcb5b20f1bca4f2b9f68fc9cf74118057f6d6f3d85f4d155c9d70a4",
        "t.c",
        None,
    ),
    "watcom-10.0a-cxx": (
        ["-zq", "-fo=t.obj", "t.c"],
        "t.obj",
        "669c2bc80ac513e710f0c6a4eaedaafc08bcf86a4fa3233974782b8a93394d4c",
        "t.c",
        None,
    ),
    "watcom-10.5": (
        ["-zq", "-fo=t.obj", "t.c"],
        "t.obj",
        "67a686686dcb5b20f1bca4f2b9f68fc9cf74118057f6d6f3d85f4d155c9d70a4",
        "t.c",
        None,
    ),
    "watcom-10.5-cxx": (
        ["-zq", "-fo=t.obj", "t.c"],
        "t.obj",
        "669c2bc80ac513e710f0c6a4eaedaafc08bcf86a4fa3233974782b8a93394d4c",
        "t.c",
        None,
    ),
    "watcom-10.5a": (
        ["-zq", "-fo=t.obj", "t.c"],
        "t.obj",
        "67a686686dcb5b20f1bca4f2b9f68fc9cf74118057f6d6f3d85f4d155c9d70a4",
        "t.c",
        None,
    ),
    "watcom-10.5a-cxx": (
        ["-zq", "-fo=t.obj", "t.c"],
        "t.obj",
        "669c2bc80ac513e710f0c6a4eaedaafc08bcf86a4fa3233974782b8a93394d4c",
        "t.c",
        None,
    ),
    "watcom-10.6": (
        ["-zq", "-fo=t.obj", "t.c"],
        "t.obj",
        "67a686686dcb5b20f1bca4f2b9f68fc9cf74118057f6d6f3d85f4d155c9d70a4",
        "t.c",
        None,
    ),
    "watcom-10.6-cxx": (
        ["-zq", "-fo=t.obj", "t.c"],
        "t.obj",
        "669c2bc80ac513e710f0c6a4eaedaafc08bcf86a4fa3233974782b8a93394d4c",
        "t.c",
        None,
    ),
    "watcom-11.0": (
        ["-zq", "-fo=t.obj", "t.c"],
        "t.obj",
        "93c466082e01fe5aeba77a9188e420537785fe7714c3660d0926243d681b6441",
        "t.c",
        None,
    ),
    "watcom-11.0-cxx": (
        ["-zq", "-fo=t.obj", "t.c"],
        "t.obj",
        "a58dfc6a47da3fca0ab6b02f4076844cf0d6aeb9ef1c4a4b12f817081d9da416",
        "t.c",
        None,
    ),
    "saturn-cygnus-2.7-96Q3-daze-0.3.0": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "dfdd1315fd8c59af00a397741de78aef9a262b432e6eef27d60240c2e3015a31",
        "t.c",
        None,
    ),
    "gcc-2.5.7-mipsel-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "896860f5b9e1aa31e101495dbfd36292f370f90494519b7816a33312f9e1a3fb",
        "t.c",
        None,
    ),
    "gcc-2.5.7-psx-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "51c03f4b559b4c696c9957589a3ff237b798d012968256ade86e538bd8b25950",
        "t.c",
        None,
    ),
    "gcc-2.6.0-mipsel-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a7b7ef9592dd3000f965ceb5110741790069d40360363dd76dc3cb42a31f9300",
        "t.c",
        None,
    ),
    "gcc-2.6.0-psx-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "df4ffc57299e4eed8f353ff46c6be2bef541049ba8184cd236f6acce5301622b",
        "t.c",
        None,
    ),
    "gcc-2.6.3-mipsel-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.6.3-ps1-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.7.0-mipsel-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.7.1-mipsel-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.7.2-cdk-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.7.2-mipsel-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.7.2-psx-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.7.2.1-mipsel-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.7.2.2-mipsel-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.7.2.3-mipsel-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.8.0-mipsel-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.8.0-psx-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.8.1-mipsel-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.8.1-psx-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.91.66-mipsel-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.91.66-psx-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "gcc-2.95.2-mipsel-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "c86b3101e6b08dbfe684ff5fdc814fa7396dfc1ec7222a00002a7731ee851883",
        "t.c",
        None,
    ),
    "gcc-2.95.2-ps1-maspsx-4ffa8b5": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "bf686f1e8b1f7f5d187865c70779bcdb826c9010651afb3e8bb197b16576acdf",
        "t.c",
        None,
    ),
    "psyq-2.6.3-221-daze-0.3.0": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "83d08a9413740ebee6e44006edcad38280ef4cc68f2a3e92df0aa9c108fd9d47",
        "t.c",
        None,
    ),
    "psyq-3.3-daze-0.3.0": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "83d08a9413740ebee6e44006edcad38280ef4cc68f2a3e92df0aa9c108fd9d47",
        "t.c",
        None,
    ),
    "psyq-3.5-daze-0.3.0": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "83d08a9413740ebee6e44006edcad38280ef4cc68f2a3e92df0aa9c108fd9d47",
        "t.c",
        None,
    ),
    "psyq-3.6-daze-0.3.0": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "83d08a9413740ebee6e44006edcad38280ef4cc68f2a3e92df0aa9c108fd9d47",
        "t.c",
        None,
    ),
    "gcc-16.2.0": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "a0a9d4089b71967b3f3c99057278a17c281e53b3db9c0cf44b0299a48a16b406",
        "t.c",
        None,
    ),
    "clang-23.1.4": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "b94fd7ca880452fbe456860b2551e3a05270fc9f14f0f33f3a8094993d58410d",
        "t.c",
        None,
    ),
    "mwcc-4.1-51213p1": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0102e0218c566de8d0f01ccfcc7316909c59f639754eb022461306d2d81f12b8",
        "t.c",
        None,
    ),
    "saturn-cygnus-2.7-96Q3-native": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "558a5925b6fc035067e0d2b30119a87c791955a0b99ca2a89a3b8b7a5aa44f97",
        "t.c",
        None,
    ),
    "shc-5.0r32-sh2": (
        ["-c", "t.c", "-o", "t.o"],
        "t.o",
        "0d7c909d9ece6a352509b3d583edb0609314b2115e47f7ca7b4604d03d6e47f0",
        "t.c",
        (114, 126),  # ROF source date copied into the ELF .comment section
    ),
    "msvc-4.0": (
        ["/c", "t.c"],
        "t.obj",
        "d420f2d9626c270866ba1d1d718a19cd39a59d07c8fe9d2999bde3ffd4bd9f4a",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — identical masked object to msvc-4.2 (same
    # compiler lineage; cross-validates both goldens)
    "msvc-4.2": (
        ["/c", "t.c"],
        "t.obj",
        "d420f2d9626c270866ba1d1d718a19cd39a59d07c8fe9d2999bde3ffd4bd9f4a",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp
    "msvc-5.0": (
        ["/c", "t.c"],
        "t.obj",
        "3fdf875c176b0abc8614f7208053d0b53193e73466f0c52c3cabc80a065dc897",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp
    "msvc-6.0": (
        ["/c", "t.c"],
        "t.obj",
        "4b50f0dbba945a5bc80f9e40ed05bcfb06505fff2204a4b567192c7e5fb1e224",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp
    "msvc-6.0-win9x": (
        ["/c", "t.c"],
        "t.obj",
        "4b50f0dbba945a5bc80f9e40ed05bcfb06505fff2204a4b567192c7e5fb1e224",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp (same smoke codegen as msvc-6.0; images differ in hosted tree)
    "msvc-2.0": (
        ["/c", "t.c"],
        "t.obj",
        "3df39750075ba99bba6f9418a9cb399eedfe48149132bb6a49f2045239cad25f",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp
    "msvc-4.1": (
        ["/c", "t.c"],
        "t.obj",
        "d420f2d9626c270866ba1d1d718a19cd39a59d07c8fe9d2999bde3ffd4bd9f4a",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — identical masked object to msvc-4.0/msvc-4.2
    "msvc-5.0-sp1": (
        ["/c", "t.c"],
        "t.obj",
        "3fdf875c176b0abc8614f7208053d0b53193e73466f0c52c3cabc80a065dc897",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — identical masked object to msvc-5.0 (same CL)
    "msvc-5.0-sp2": (
        ["/c", "t.c"],
        "t.obj",
        "3fdf875c176b0abc8614f7208053d0b53193e73466f0c52c3cabc80a065dc897",
        "t.c",
        (4, 8),
    ),
    "msvc-5.0-sp3": (
        ["/c", "t.c"],
        "t.obj",
        "3fdf875c176b0abc8614f7208053d0b53193e73466f0c52c3cabc80a065dc897",
        "t.c",
        (4, 8),
    ),
    "msvc-6.0-sp1": (
        ["/c", "t.c"],
        "t.obj",
        "4b50f0dbba945a5bc80f9e40ed05bcfb06505fff2204a4b567192c7e5fb1e224",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — identical masked object to msvc-6.0 (same CL+C1)
    "msvc-6.0-sp2": (
        ["/c", "t.c"],
        "t.obj",
        "4b50f0dbba945a5bc80f9e40ed05bcfb06505fff2204a4b567192c7e5fb1e224",
        "t.c",
        (4, 8),
    ),
    "msvc-6.0-sp3": (
        ["/c", "t.c"],
        "t.obj",
        "7e4ff03b2845d2268b2c0d27d35e63cea41d2e44320e821f6f6438da41873774",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — comp.id differs from msvc-6.0 (SP3 passes)
    "msvc-6.0-sp4": (
        ["/c", "t.c"],
        "t.obj",
        "e9427fee0356ef5f8f569e2450a75b753e5fc28070b5d31916516992bbb20687",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — same C1 as sp5 but distinct comp.id (image path)
    "msvc-6.0-sp5": (
        ["/c", "t.c"],
        "t.obj",
        "547b88f827c13e9273f46b1a72415002289fac62d0f65dc0ef9289dbc5a3e546",
        "t.c",
        (4, 8),
    ),
    "msvc-6.0-sp5-pp": (
        ["/c", "t.c"],
        "t.obj",
        "202f30ec9d86ab587d0c319cbcc488cf0b5cefd8a9d190ad5effecd6e31d455a",
        "t.c",
        (4, 8),
    ),
    "msvc-6.0-sp6": (
        ["/c", "t.c"],
        "t.obj",
        "7ec66aebd67075b5e1482d9ee05f4a53134925a4e6a79101446e9a7b31eb3994",
        "t.c",
        (4, 8),
    ),
    "msvc-7.0": (
        ["/c", "t.c"],
        "t.obj",
        "9e42bfe45c02ff046d13ce6c32b7fc1d422b30bf225ff4b64f659a16cadd9f4b",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — identical masked object to msvc-7.0-rtm (same CL)
    "msvc-7.0-rtm": (
        ["/c", "t.c"],
        "t.obj",
        "9e42bfe45c02ff046d13ce6c32b7fc1d422b30bf225ff4b64f659a16cadd9f4b",
        "t.c",
        (4, 8),
    ),
    "msvc-7.0-sp1": (
        ["/c", "t.c"],
        "t.obj",
        "138377065cf5e3ac2f7afd6252f9f39e18996cbb5f0e8cf2956ab20fb42d0af7",
        "t.c",
        (4, 8),
    ),
    "msvc-7.1": (
        ["/c", "t.c"],
        "t.obj",
        "77c906d5556114c01e11cb6d6afa1beed3e0b0dea6f9f04351ce6775f9303071",
        "t.c",
        (4, 8),
    ),
    "msvc-7.1-sp1": (
        ["/c", "t.c"],
        "t.obj",
        "edf732bc642630021456f567636c08dac2ee2ef5a5cc6f69b646fcc0dc3377bf",
        "t.c",
        (4, 8),
    ),
    "msvc-8.0": (
        ["/c", "t.c"],
        "t.obj",
        "c6d82406d884675a4be4910786da9350baa8b9e4ad1fb60de94abaa4e2e5bee2",
        "t.c",
        (4, 8),
    ),  # identical masked object to msvc-8.0-sp1 (same CL)
    "msvc-8.0-sp1": (
        ["/c", "t.c"],
        "t.obj",
        "c6d82406d884675a4be4910786da9350baa8b9e4ad1fb60de94abaa4e2e5bee2",
        "t.c",
        (4, 8),
    ),
    "msvc-9.0-sp1": (
        ["/c", "t.c"],
        "t.obj",
        "c11006fdd4ae42814472be29f400b8147bd3d42e4f976de9248727bb7459b8d8",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — 15.00.30729 SP1 compiler
    "msvc-11.0": (
        ["/c", "t.c"],
        "t.obj",
        "90f064ea1bd8f8b76e7df38a8d3bfc0905b68f9b523d219e575bf3bda9e20bd5",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — 17.00.50522 VS2012 compiler
    "msvc-9.0": (
        ["/c", "t.c"],
        "t.obj",
        "8fed9b3cbb029773d2a5ec6aeb7a9643cee319005554a127a814c2862f1a80d4",
        "t.c",
        (4, 8),
    ),
    "msvc-10.0": (
        ["/c", "t.c"],
        "t.obj",
        "df2bfe3ec2234bb4525ae45136b7fe47b0e7f3af353662e13e8ae156b984ea0e",
        "t.c",
        (4, 8),
    ),
    "msvc-10.0-sp1": (
        ["/c", "t.c"],
        "t.obj",
        "778fe81a9d24c919e7f19026f5ff4ef5f08435cbda4e33659435fd0ca96351be",
        "t.c",
        (4, 8),
    ),
    "msvc-1.5": (
        ["/c", "t.c"],
        "t.OBJ",
        "d3bf67158b4d52bd24cb7b137e803491080cf221ffcd6b5dc9dafb885ab36dc2",
        "t.c",
        None,
    ),  # identical OMF to msvc-1.52 (same 16-bit codegen)
    "msvc-1.0": (
        ["/c", "t.c"],
        "t.OBJ",
        "d3bf67158b4d52bd24cb7b137e803491080cf221ffcd6b5dc9dafb885ab36dc2",
        "t.c",
        None,
    ),  # identical OMF to msvc-1.52/msvc-1.5 (same 16-bit codegen)
    "msvc-1.52": (
        ["/c", "t.c"],
        "t.OBJ",
        "d3bf67158b4d52bd24cb7b137e803491080cf221ffcd6b5dc9dafb885ab36dc2",
        "t.c",
        None,
    ),
    "borland-5.5": (
        ["-c", "t.c"],
        "t.obj",
        "76f45489734e9e2d58ed42d999f570204755566d135e757d27a754c194fdc8f1",
        "t.c",
        None,
    ),
    "watcom-2.0-win32": (
        ["-fo=w.o", "t.c"],
        "w.o",
        "44a6354f779f2c504384019c6786ec1831ca7b5cc20721e1a678295753f08220",
        "t.c",
        None,
    ),
    "watcom-2.0-win16": (
        ["-fo=w.o", "t.c"],
        "w.o",
        "85244b6c95dc68fc7de450a4ef422c0bf4ab3a13a882b3cbb5d0e346bb9b01c4",
        "t.c",
        None,  # wcc embeds the source path (fixed /tmp/rebrew-smoke) but no
        # timestamp — fixed-workdir runs are byte-identical.
    ),
    "delphi-1.0": (
        ["hello.dpr"],
        "hello.EXE",
        "fb91f2e3eefd4a139454bf578682bd62a47ef3dd6ced7b9c487a142a9a56e1e2",
        "hello.dpr",
        None,
    ),
    "borland-3.1": (
        ["t.c"],
        "t.OBJ",
        "2fc719cfdfa0ba7c61667505f41f8bbccf22cf716614ff53056073f40a48cd85",
        "t.c",
        [
            (48, 60),
            (201, 207),
        ],  # Borland COMENT run-timestamp (sub-second ticks) + record checksums
    ),
    "borland-2.0": (
        ["t.c"],
        "t.OBJ",
        "f98ba8e6702ab607a6cfd24627f862735e1a9c5738489377eab55896d66f985a",
        "t.c",
        [
            (47, 51),
            (57, 58),
        ],  # Borland COMENT run-timestamp (sub-second ticks) + record checksum
    ),
    "ido-5.3": (
        ["-c", "-O2", "-o", "t.o", "t.c"],
        "t.o",
        "23d42a2d1b2bf56d013a803db6d0d458c693e48f932d1859ad9ec5df881018a6",
        "t.c",
        None,  # ELF object — no timestamp; src path/mtime are fixed by the gate
    ),
    "ido-7.1": (
        ["-c", "-O2", "-o", "t.o", "t.c"],
        "t.o",
        "6af67c000618e1acb476b58ff8dae30e727934ad78e819bc87305d7e2ebc8672",
        "t.c",
        None,  # ELF object — no timestamp; src path/mtime are fixed by the gate
    ),
    "gcc-14.2.0": (
        ["-c", "-O2", "-o", "t.o", "t.c"],
        "t.o",
        "37e63745119ab217e65378fd5b5ab5c5aa22fcece3f4d397b7f10f6c0b9e62f6",
        "t.c",
        None,  # ELF object — no timestamp; src path/mtime are fixed by the gate
    ),
    "gcc-12.3.0": (
        ["-c", "-O2", "-o", "t.o", "t.c"],
        "t.o",
        "b80235b3ec4b75d3f9a5d32db64660911d6f1ce9e2c9e67319b378095987d198",
        "t.c",
        None,  # ELF object — no timestamp; src path/mtime are fixed by the gate
    ),
    "clang-18.1.8": (
        ["-c", "-O2", "-o", "t.o", "t.c"],
        "t.o",
        "fed0b5f644dcc6dff27e0e2178987cfa49d17c4ee4c785ddbafe7c5f0d5f4067",
        "t.c",
        None,  # ELF object — no timestamp; src path/mtime are fixed by the gate
    ),
    "clang-16.0.4": (
        ["-c", "-O2", "-o", "t.o", "t.c"],
        "t.o",
        "f2a7e6e5310741bc84b99c9c3674f9909510c867c8349686d0467dcaf07b1ea7",
        "t.c",
        None,  # ELF object — no timestamp; src path/mtime are fixed by the gate
    ),
    "mingw-16.2.0": (
        ["-c", "-O2", "-o", "t.o", "t.c"],
        "t.o",
        "385f1a688e6490af5978106aa59169cc4d434fd8ee60eb2547d7bdfb34689981",
        "t.c",
        (4, 8),  # COFF TimeDateStamp
    ),
    "mingw-14.2.0": (
        ["-c", "-O2", "-o", "t.o", "t.c"],
        "t.o",
        "bd6533f8062fefa16fcf2e52fad761feabbf1c54f0583a64d3c5004a049c140d",
        "t.c",
        (4, 8),  # COFF TimeDateStamp
    ),
}


SMOKE_TIMEOUT_S = 300

#: A docker build of one toolchain image, base plus toolchain, is the long
#: pole of `rebrew toolchain build`.
DOCKER_BUILD_TIMEOUT_S = 3600

#: Tail of a captured docker log kept in a failure message.
BUILD_LOG_TAIL = 300


def docker_build(
    tag: str,
    context: Path,
    *,
    stream: bool,
    run_fn: Callable[..., subprocess.CompletedProcess[Any]] | None = None,
    runtime_fn: Callable[[], str] | None = None,
) -> tuple[int, str]:
    """``docker build -t *tag* *context*``; return ``(returncode, log_tail)``.

    A toolchain build runs for minutes to an hour, and docker's own
    layer-by-layer output is the only progress signal it emits, so
    *stream* lets it reach the terminal live.  ``--json`` turns streaming off:
    docker writes that log to stdout, which would land in the middle of the
    JSON document, so it is captured and only its tail survives a failure.

    Group-killed, like every other docker spawn in the tree: a plain
    ``subprocess.run`` timeout or a Ctrl+C SIGKILLs only the docker CLI and
    leaves the build it started holding a build slot under the daemon, so the
    next ``rebrew toolchain build`` of the same image races it.
    """
    run_proc = run_fn if run_fn is not None else run_process_group
    get_runtime = runtime_fn if runtime_fn is not None else container_runtime
    argv = [get_runtime(), "build", "-t", tag, str(context)]
    if stream:
        r = run_proc(argv, timeout=DOCKER_BUILD_TIMEOUT_S)
        return r.returncode, ""
    r = run_proc(
        argv,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=DOCKER_BUILD_TIMEOUT_S,
    )
    return r.returncode, (r.stdout + r.stderr)[-BUILD_LOG_TAIL:].strip()


def build_failure(returncode: int, log_tail: str) -> str:
    """The failure clause of a build error, naming the log when one was kept."""
    if log_tail:
        return f"{log_tail} (exit {returncode})"
    return f"exit {returncode}"


#: COFF machine types the smoke check reads: (architecture, bits).  The
#: architecture names are recompile-toolchains' ``arch`` vocabulary.
COFF_TARGETS: dict[int, tuple[str, int]] = {
    0x014C: ("x86", 32),
    0x8664: ("x86_64", 64),
    0x0200: ("ia64", 64),
    0x01C0: ("arm", 32),
    0x01C2: ("arm", 32),
    0x01C4: ("arm", 32),
    0xAA64: ("aarch64", 64),
    0x0162: ("mips", 32),
    0x0166: ("mips", 32),
    0x0168: ("mips", 32),
    0x0169: ("mips", 32),
    0x0266: ("mips", 32),
    0x0366: ("mips", 32),
    0x0466: ("mips", 32),
    0x01F0: ("powerpc", 32),
    0x01F1: ("powerpc", 32),
    0x01A2: ("sh", 32),
    0x01A3: ("sh", 32),
    0x01A6: ("sh", 32),
    0x0268: ("m68k", 32),
}

#: ELF machines the smoke check reads, by LIEF ``ELF.ARCH`` name; the bits are
#: the file's class.
ELF_ARCHES: dict[str, str] = {
    "I386": "x86",
    "X86_64": "x86_64",
    "AARCH64": "aarch64",
    "ARM": "arm",
    "MIPS": "mips",
    "MIPS_RS3_LE": "mips",
    "PPC": "powerpc",
    "PPC64": "powerpc",
    "SH": "sh",
    "M68K": "m68k",
}

#: recompile-toolchains ``arch`` values that name one machine family the object
#: header cannot tell apart.
ARCH_FAMILY = {"sh2": "sh", "sh4": "sh"}


def object_target(obj: Path) -> tuple[str, int] | None:
    """The (architecture, bits) an ELF or COFF object was compiled for; ``None`` for another format."""
    import lief

    from rebrew.formats.coff import load_coff

    data = obj.read_bytes()
    if data[:4] == b"\x7fELF":
        elf = lief.ELF.parse(io.BytesIO(data))
        if elf is None:
            return None
        arch = ELF_ARCHES.get(elf.header.machine_type.name)
        bits = 64 if elf.header.identity_class == lief.ELF.Header.CLASS.ELF64 else 32
        return None if arch is None else (arch, bits)
    coff = load_coff(data)
    if coff is None:
        return None
    return COFF_TARGETS.get(int(coff[0].header.machine.value))


def declared_target(spec: Any) -> tuple[str, int] | None:
    """The (architecture, bits) *spec* declares: its catalogue row's ``arch`` and ``bits``.

    The registry's own ``bits`` wins over the row's where it sets one.  ``None``
    when either is unknown, or for a 16-bit x86 target (its OMF and MZ objects
    carry no machine field).
    """
    from rebrew.compiler.toolchain_data import toolchains_manifest

    row = next((r for r in toolchains_manifest()["toolchains"] if r["id"] == spec.name), None)
    arch = row.get("arch") if row is not None else None
    bits = spec.bits if spec.bits is not None else (row.get("bits") if row is not None else None)
    if not isinstance(arch, str) or not isinstance(bits, int) or arch == "x86_16":
        return None
    return ARCH_FAMILY.get(arch, arch), bits


def run_smoke_container(
    image: str,
    name_prefix: str,
    workdir: Path,
    flags: list[str],
    *,
    kvm: bool = False,
    run_fn: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    runtime_fn: Callable[[], str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Compile *flags* in *image* with *workdir* mounted at /work, offline.

    The container gets a unique name (a fixed name collided under parallel
    runs); group-killed on timeout (a killed docker CLI leaves the container
    under dockerd).  Re-raises :class:`subprocess.TimeoutExpired`.
    """
    import uuid

    from rebrew.compiler.toolchain import bind_mount, docker_hardening_args

    run_proc = run_fn if run_fn is not None else run_process_group
    get_runtime = runtime_fn if runtime_fn is not None else container_runtime
    container = f"{name_prefix}-{uuid.uuid4().hex[:12]}"
    return run_proc(
        [
            get_runtime(),
            "run",
            "--rm",
            *docker_hardening_args(kvm=kvm),
            "--name",
            container,
            "-v",
            bind_mount(workdir, "/work"),
            "-w",
            "/work",
            image,
            *flags,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=SMOKE_TIMEOUT_S,
    )


def masked_obj_sha256(obj: Path, mask: tuple[int, int] | list[tuple[int, int]] | None) -> str:
    """sha256 of *obj* with the masked byte ranges zeroed (golden hashing)."""
    import hashlib

    raw = obj.read_bytes()
    if mask is not None:
        ranges = mask if isinstance(mask, list) else [mask]
        masked = bytearray(raw)
        for start, end in ranges:
            masked[start:end] = b"\x00" * (end - start)
        raw = bytes(masked)
    return hashlib.sha256(raw).hexdigest()
