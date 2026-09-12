# SDK Media Provenance

Where to obtain DirectX and Windows Platform SDK media for byte-matching
projects, with verifiable provenance.  An SDK header tree is a compile
input: struct layouts, `_inline` helpers, macros, and interface vtables in
`ddraw.h` / `d3d.h` / `d3d8.h` decide the emitted bytes, so the header
version must match the original build.  These media are the source trees a
future SDK layer would vendor; rebrew has no SDK layer today.

All checksums below were read from the archive.org metadata API
(`https://archive.org/metadata/<identifier>`) on 2026-09-11.  Sizes are in
bytes.  Download URLs are `https://archive.org/download/<identifier>/<file>`.

## 1. DirectX SDKs (archive.org `directxsdks`)

The `directxsdks` collection is a curated preservation set of official
Microsoft DirectX SDK releases, from the 1995 Game SDK through the June 2010
SDK.  Provenance: uploaded by `wobakj@web.de`, listed under the
`vintagesoftware` collection ("The Vintage Software Collection", maintained
by `jscott@archive.org`), no explicit license set on any item.  The
underlying Microsoft EULA still governs use; the archive is a preservation
mirror, not a grant of rights.

| Release date | Title | File | Size | MD5 | SHA1 |
|---|---|---|---|---|---|
| 1995-12-09 | Microsoft DirectX 1.0 SDK (Game SDK) | [`GAMESDK.rar`](https://archive.org/download/gamesdk/GAMESDK.rar) | 13331158 | `81be7a3e056500d4b7e685c27cf3c959` | `45656249c02c08fbc7a6ba48a3f62c69f82d207b` |
| 1996-06-12 | Microsoft DirectX 2.0 SDK | [`DIRECTX2.rar`](https://archive.org/download/directx2sdk/DIRECTX2.rar) | 27443949 | `4587a231354480930f46b1b37f3d475b` | `ec34c0001e6deccc5a73a212b9d14f04eb2fa383` |
| 1996-10-25 | Microsoft DirectX 3.0 SDK | [`DIRECTX3.rar`](https://archive.org/download/directx3sdk/DIRECTX3.rar) | 68623698 | `6533615dd9fac741848288a29911e887` | `11b777e71afaba9cdad6e3f90c6959dd1fe15c9a` |
| 1996-12-20 | Microsoft DirectX 3.0a SDK | [`DIRECTX3A.EXE`](https://archive.org/download/directx3asdk/DIRECTX3A.EXE) | 55532209 | `50e268dad40bb1ac8600f29703fe49a0` | `df671514a0c7c9b3037b06bbedac2a78dc327867` |
| 1997-08-07 | Microsoft DirectX 5.0 SDK | [`idx5sdk.exe`](https://archive.org/download/idx5sdk/idx5sdk.exe) | 33018416 | `f00938648587bd0f23739f00b89f1ba4` | `b14370372307360a9e8de2ebd8fcd13173fd3b4a` |
| 1998-12-12 | Microsoft DirectX 6.0 SDK | [`DIRECTX6_SDK.EXE`](https://archive.org/download/directx6sdk/DIRECTX6_SDK.EXE) | 218620051 | `b0b541fcdf244ee22153d3adc27b7eb1` | `3bdcf0925c09afc648ad2196104214402df408d7` |
| 1999-01-11 | Microsoft DirectX 6.1 SDK | [`dx61sdkimage.exe`](https://archive.org/download/dx61sdkimage/dx61sdkimage.exe) | 75224112 | `c43d0071c84244858d40a94ed9a37ceb` | `6944788e4927ee5c2345fe73ae9d531f9657ab0e` |
| 1999-09-10 | Microsoft DirectX 7.0 SDK | [`dx7sdk-7001.exe`](https://archive.org/download/dx7sdk-7001/dx7sdk-7001.exe) | 128891648 | `6bf1801d83fe5e4f27c172c372b7d282` | `3e65a4409df2043540b4a8c70b697a198366589c` |
| 1999-12-17 | Microsoft DirectX 7.0a SDK | [`dx7adxf.exe`](https://archive.org/download/dx7adxf/dx7adxf.exe) | 128089312 | `e55086ddcef274fbfe47fc3199ae4386` | `b5213a87726de09621a0b7b47a1107793527e542` |
| 2000-11-05 | Microsoft DirectX 8.0 SDK | [`dx8sdk.exe`](https://archive.org/download/dx8sdk/dx8sdk.exe) | 144441256 | `9106e17618a531ca9ec2533984fd1c78` | `79935e264d969941ed74c37392f54e6bd1cc399c` |
| 2001-01-26 | Microsoft DirectX 8.0a SDK | (file removed) | n/a | n/a | n/a |
| 2001-11-03 | Microsoft DirectX 8.1 SDK full | [`dx81sdk_full.exe`](https://archive.org/download/dx81sdk_full/dx81sdk_full.exe) | 173778784 | `28533018267fa278bb1c603a67d86d2f` | `61b5733209205e942f37431ee40da712e1f50e6a` |
| 2002-07-24 | Microsoft DirectX 8.1b SDK | [`DX81b_SDK.exe`](https://archive.org/download/dx81b_sdk/DX81b_SDK.exe) | 174848584 | `0ef4637b05b77ae8f75d58e17f0e7d6d` | `221c60334da54e8e670741e7090e51255ad0284c` |
| 2002-12-19 | Microsoft DirectX 9.0 SDK | [`dx9sdk.exe`](https://archive.org/download/dx9sdk/dx9sdk.exe) | 233197112 | `ca95dc68b0b97439ba74767d3fa34201` | `267880280b82bae7d399fc2e15f9eaf182328380` |
| 2003-05-20 | Microsoft DirectX 9.0a SDK | [`dx90asdk.exe`](https://archive.org/download/dx90asdk/dx90asdk.exe) | 228726880 | `b71a17780f6a52adbee1185fb8968155` | `75992f4c2f3b2f8d7677f388eb746c21f95ff6fd` |
| 2003-07-17 | Microsoft DirectX 9.0b SDK | [`dx90bsdk.exe`](https://archive.org/download/dx90bsdk/dx90bsdk.exe) | 228594272 | `14b2e2a987f5b1c67241f392bf4d90df` | `d4e0c9dfcdb40a45532e153e7b4ed55fb31da9b9` |
| 2003-10-03 | Microsoft DirectX 9.0 Update SDK (Summer 2003) | [`dx90updatesdk.exe`](https://archive.org/download/dx90updatesdk/dx90updatesdk.exe) | 190991976 | `ed328da4033e18124801265ee91f690e` | `38a7581d727503f0401cfd2a3bf084418e7eda44` |
| 2004-07-30 | Microsoft DirectX SDK Summer 2004 | [`dxsdk_sum2004.exe`](https://archive.org/download/dxsdk_sum2004/dxsdk_sum2004.exe) | 239008008 | `dc2645e3a811268ca2b11fcae3ef241b` | `73d875b97591f48707c38ec0dbc63982ff45c661` |
| 2004-10-07 | Microsoft DirectX SDK October 2004 | [`dxsdk_oct2004.exe`](https://archive.org/download/dxsdk_oct2004/dxsdk_oct2004.exe) | 229290240 | `7400addc1ef83cc8a813040e192168ca` | `8097bb69676a20e55a98a67d960a8b6edc89dff9` |
| 2004-12-09 | Microsoft DirectX SDK December 2004 | [`dxsdk_dec2004.exe`](https://archive.org/download/dxsdk_dec2004/dxsdk_dec2004.exe) | 233784600 | `08b5995a06ac6bdd31687045defc4436` | `69f7a521a787c3a914c2dee9489a29235caa7d15` |
| 2005-02-09 | Microsoft DirectX SDK February 2005 | [`dxsdk_feb2005.exe`](https://archive.org/download/dxsdk_feb2005/dxsdk_feb2005.exe) | 162084600 | `5567292509090710430b9f50fb82d59e` | `2a6c60da4c9f4de09e1dbbe06075964f326e86b8` |
| 2005-03-30 | Microsoft DirectX SDK April 2005 | [`dxsdk_apr2005.exe`](https://archive.org/download/dxsdk_apr2005/dxsdk_apr2005.exe) | 159694584 | `5d16634b0b42e219a3f1893b50a543e6` | `ec4dd48826a399c6ce041745f14b90356d8c5cd1` |
| 2005-06-03 | Microsoft DirectX SDK June 2005 | [`dxsdk_jun2005.exe`](https://archive.org/download/dxsdk_jun2005/dxsdk_jun2005.exe) | 166456568 | `a6d85680b78b6c3b29a42574f233d677` | `120068d272d5a272050141dd870276c1f43e0b03` |
| 2005-07-27 | Microsoft DirectX SDK August 2005 | [`dxsdk_aug2005.exe`](https://archive.org/download/dxsdk_aug2005/dxsdk_aug2005.exe) | 178255104 | `053c7a32ce3d7982eb1191863d4e2ddb` | `67b14c622f80481c433414837d43b6ed5b97f4d8` |
| 2005-10-11 | Microsoft DirectX SDK October 2005 | [`dxsdk_oct2005.exe`](https://archive.org/download/dxsdk_oct2005/dxsdk_oct2005.exe) | 217123072 | `90ef5ee5ee39fa631e21241e159a2c82` | `20869b69bd80b9d4e90de1097ee943a65560eb05` |
| 2005-12-07 | Microsoft DirectX SDK December 2005 | [`dxsdk_dec2005.exe`](https://archive.org/download/dxsdk_dec2005/dxsdk_dec2005.exe) | 334163688 | `79983cadc9e8cd7a16d5c9bcd8c5ce46` | `1dca39b63e5f1371ee47fccf3fbb755ab69a7891` |
| 2006-02-08 | Microsoft DirectX SDK February 2006 | [`dxsdk_feb2006.exe`](https://archive.org/download/dxsdk_feb2006/dxsdk_feb2006.exe) | 353500904 | `642f3f253d17c3070ce5f43b0211720c` | `c7d6182451e62ad9f4d76a47382e67cb24b2a11f` |
| 2006-04-04 | Microsoft DirectX SDK April 2006 | [`dxsdk_apr2006.exe`](https://archive.org/download/dxsdk_apr2006/dxsdk_apr2006.exe) | 409118432 | `375f6b26608985842be364d2e8996954` | `67b6a521ad5f4ac1a96a406243c67f877f337bf8` |
| 2006-06-07 | Microsoft DirectX SDK June 2006 | [`dxsdk_jun2006.exe`](https://archive.org/download/dxsdk_jun2006/dxsdk_jun2006.exe) | 464796456 | `96717f5a4a27dbb20ea9c9bd099305f2` | `ecaeb2f0be25d7a3daef25836ce576adbc430895` |
| 2006-08-22 | Microsoft DirectX SDK August 2006 | [`dxsdk_aug2006.exe`](https://archive.org/download/dxsdk_aug2006/dxsdk_aug2006.exe) | 531144000 | `27fc23264588ba44c6e21ed7c53c0355` | `1e9cdbef391ebfbf781e6c87a375138d8c195c57` |
| 2006-10-06 | Microsoft DirectX SDK October 2006 | [`dxsdk_oct2006.exe`](https://archive.org/download/dxsdk_oct2006/dxsdk_oct2006.exe) | 534465344 | `5c810426994df33eb22c13ef68e94259` | `8231d6e0f2794bebb16fb132646746be934d0011` |
| 2006-12-12 | Microsoft DirectX SDK December 2006 | [`dxsdk_dec2006.exe`](https://archive.org/download/dxsdk_dec2006/dxsdk_dec2006.exe) | 469765944 | `f5ffeec75e11ff9c91cb8233c96ecc24` | `edf78c88d03b251182990bd49c4cb7dcc1c9c388` |
| 2007-01-30 | Microsoft DirectX SDK February 2007 | [`dxsdk_feb2007.exe`](https://archive.org/download/dxsdk_feb2007/dxsdk_feb2007.exe) | 453010816 | `53d0a4c3ab14bdad12c804f3171bea87` | `1a446ae20300b49ac3adcc3afe2aab3f5e639b99` |
| 2007-04-05 | Microsoft DirectX SDK April 2007 | [`dxsdk_apr2007.exe`](https://archive.org/download/dxsdk_apr2007/dxsdk_apr2007.exe) | 462460792 | `3e4baca6a181105dfe77e1e759744d06` | `bbf4ddc394d630a22e139ff1cdb518ac626c6dfd` |
| 2007-06-25 | Microsoft DirectX SDK June 2007 | [`dxsdk_jun2007.exe`](https://archive.org/download/dxsdk_jun2007/dxsdk_jun2007.exe) | 476689272 | `b9f1bb466b657a072ef136196c71cee6` | `12f540b35945bfebb492ea67747a0ab60aefb192` |
| 2007-07-23 | Microsoft DirectX SDK August 2007 | [`dxsdk_aug2007.exe`](https://archive.org/download/dxsdk_aug2007/dxsdk_aug2007.exe) | 491582328 | `e866e58a5cbfc98b3880261b5ae78529` | `c812c18e2972bdb1d9cbb544be9ced9370a4656f` |
| 2007-10-24 | Microsoft DirectX SDK November 2007 | [`dxsdk_november2007.exe`](https://archive.org/download/dxsdk_november2007/dxsdk_november2007.exe) | 448582184 | `3c9210874cf36173d386a894300a0bf3` | `bf900a1a2e54f189cf310b6429d1fbdb00636c16` |
| 2008-03-07 | Microsoft DirectX SDK March 2008 | [`dxsdk_march2008.exe`](https://archive.org/download/dxsdk_march2008/dxsdk_march2008.exe) | 463616544 | `fb474f7181acf72769c513509d021deb` | `b5805adf1f768d06500cfd5bb67b613371ef279c` |
| 2008-05-31 | Microsoft DirectX SDK June 2008 | [`DXSDK_Jun08.exe`](https://archive.org/download/dxsdk_jun08/DXSDK_Jun08.exe) | 480213464 | `4dd249ab7c8e4132c07c5fd450ff33ff` | `3ee61216a34e00f58fb467e3d8f12c10ce813203` |
| 2008-07-31 | Microsoft DirectX SDK August 2008 | [`DXSDK_Aug08.exe`](https://archive.org/download/dxsdk_aug08/DXSDK_Aug08.exe) | 486051200 | `65b699a914860a906e6f997734de8a82` | `b565ddea4990ab25c61750192e6327e356307593` |
| 2008-10-27 | Microsoft DirectX SDK November 2008 | [`DXSDK_Nov08.exe`](https://archive.org/download/dxsdk_nov08/DXSDK_Nov08.exe) | 506698928 | `38c6525744336058f7033433ee1ad217` | `dad25120571544449faf52806a5b3077654a69ea` |
| 2009-03-17 | Microsoft DirectX SDK March 2009 | [`DXSDK_Mar09.exe`](https://archive.org/download/dxsdk_mar09/DXSDK_Mar09.exe) | 539195824 | `123831c60571791f7527d50d0490e99d` | `c656abf19240841ad61f9fe6ebb77c0823b93146` |
| 2009-09-05 | Microsoft DirectX SDK August 2009 | [`DXSDK_Aug09.exe`](https://archive.org/download/dxsdk_aug09/DXSDK_Aug09.exe) | 580228040 | `66e5379ecf46b014688779621bcc677c` | `5b9b969ed7b6cf5534bb7350e44c09b3573b0e71` |
| 2010-02-05 | Microsoft DirectX SDK February 2010 | [`DXSDK_Feb10.exe`](https://archive.org/download/dxsdk_feb10/DXSDK_Feb10.exe) | 581591568 | `15e4c96dcc44aa60380a2dbbaa103a63` | `c1c66499b2e5c5530b07285af4c090c33af4a4f8` |
| 2010-06-02 | Microsoft DirectX SDK June 2010 | [`DXSDK_Jun10.exe`](https://archive.org/download/dxsdk_jun10/DXSDK_Jun10.exe) | 599452800 | `a7fa610b1791d873162b9e33007a6777` | `8fe98c00fde0f524760bb9021f438bd7d9304a69` |

## 2. Other components in the collection

DDKs, Media SDKs, Extras, symbols, and MusicProducer tools.  Some SDK
headers live only in an Extras package (the DirectShow and Direct3D extras
for DirectX 9.0), so these are not optional for full coverage.

| Release date | Title | File | Size | MD5 | SHA1 |
|---|---|---|---|---|---|
| 1997-09-09 | Microsoft DirectX 5.0 SDK fix | [`dx5fix.exe`](https://archive.org/download/dx5fix/dx5fix.exe) | 148584 | `7f1339a41b659958d003652c54180ca1` | `d11babda00d4805f212c8b5510c0021a156aaa51` |
| 1997-10-08 | Microsoft DirectX 5.0 DDK | [`dx5ddk.exe`](https://archive.org/download/dx5ddk/dx5ddk.exe) | 7496120 | `b69d318fd39f0dfe0181e69db62fbccc` | `8917ede213bc17048f4951b8d8bf3f4f03299aaf` |
| 1997-12-05 | Microsoft DirectX Media 5.1 SDK | [`DX51.rar`](https://archive.org/download/dxm51sdk/DX51.rar) | 25814723 | `c2501a196217a8a433f76209f747a5b5` | `bcee029e49b398e2355ad74a860b037ac645ee6d` |
| 1999-12-13 | Microsoft DirectX Media 6.0 SDK | [`dxmweb.exe`](https://archive.org/download/dxmweb/dxmweb.exe) | 94866608 | `6320b2fa14cf3406b54fe5caae94fb3e` | `437739c6cba60bb3921814d8e38925588e9c5d11` |
| 2000-02-12 | Microsoft DirectX 7.0 DDK | [`dx7ddk.exe`](https://archive.org/download/dx7ddk/dx7ddk.exe) | 5250504 | `c7150aba5646f0981b33f4f7a54cfb1c` | `b64c8f73ff3313f0b551333d4696f86a7246c47f` |
| 2001-11-02 | Microsoft DirectX 8.1 SDK Extras DirectShow | [`DX81SDK_extras_DShow.exe`](https://archive.org/download/dx81sdk_extras_dshow/DX81SDK_extras_DShow.exe) | 421240 | `ebecfea619bdafbd39590fba76d54185` | `021160504832480534e605158f5861a6ed1b4617` |
| 2001-11-03 | Microsoft DirectX 8.1 MusicProducer | [`DX81MusicProducer.exe`](https://archive.org/download/dx81musicproducer/DX81MusicProducer.exe) | 10339192 | `0c2dbb13c2747c36591769c170eb2613` | `d88a1ffe1f0f2b27e9f081b27aa77ebbf1d70938` |
| 2001-11-03 | Microsoft DirectX 8.1 MusicProducer Content | [`DX81MusicProducer_Content.exe`](https://archive.org/download/dx81musicproducer_content/DX81MusicProducer_Content.exe) | 22368152 | `6c20a6890c4b5d47e7b0f586b50dec34` | `56b5423770a083c10ec58f869d954cb51f2207cb` |
| 2001-11-21 | Microsoft DirectX 8.1 SDK Extras | [`dx81sdk_extras.exe`](https://archive.org/download/dx81sdk_extras/dx81sdk_extras.exe) | 40151904 | `c26ff5c6e755f1c75345ddac190d3318` | `fb841ff45e2bf78bc9a531f3004d172fb37ddd55` |
| 2002-12-17 | Microsoft DirectX 9.0 SDK Extras Direct3D | [`dx90_sdk_extras_direct3d.exe`](https://archive.org/download/dx90_sdk_extras_direct3d/dx90_sdk_extras_direct3d.exe) | 1466488 | `55f595c3316416aab68a7a4069554f30` | `6a26f6d3095ef5dd8eb8b65ffdb8f495c9178d55` |
| 2002-12-17 | Microsoft DirectX 9.0 SDK Extras DirectShow | [`dx90_sdkextras_directshow.exe`](https://archive.org/download/dx90_sdkextras_directshow/dx90_sdkextras_directshow.exe) | 1311872 | `068971a553ccf761379e0b06d0cd4f96` | `a241c43c9045b2907502f58f9a8e13a5f6080526` |
| 2003-08-05 | Microsoft DirectX 9.0 VisualStudio 2003 full | [`dx90_vs2003_full.exe`](https://archive.org/download/dx90_vs2003_full/dx90_vs2003_full.exe) | 19315296 | `1a32053ea03d12ced5b762ae887f0822` | `26c6968d7c7cbf3b99dd8f24573215ca57e43343` |
| 2003-09-19 | Microsoft DirectX 9.0 Update (Summer 2003) Extras | [`dx90update_extras.exe`](https://archive.org/download/dx90update_extras/dx90update_extras.exe) | 133661808 | `038a4902d8f47082deac242584d780d4` | `86eee764eac5d5a0f0864d6ba10d4061184f86ef` |
| 2003-10-07 | Microsoft DirectX 9.0 Update (Summer 2003) managed | [`dx90update_managed.exe`](https://archive.org/download/dx90update_managed/dx90update_managed.exe) | 15579696 | `9abf2409f25be053225f3ce3b7584907` | `51a0edf2859177445279993efb5238b9b157fe52` |
| 2004-07-30 | Microsoft DirectX SDK Summer 2004 Extras | [`dxsdk_sum2004_extras.exe`](https://archive.org/download/dxsdk_sum2004_extras/dxsdk_sum2004_extras.exe) | 44218632 | `9d18b048f329a102aa223473a0549440` | `d80a806dd26aaed931e0d174168ada93bb04e839` |
| 2004-10-07 | Microsoft DirectX SDK October 2004 Extras | [`dxsdk_oct2004_extras.exe`](https://archive.org/download/dxsdk_oct2004_extras/dxsdk_oct2004_extras.exe) | 66817792 | `c700fa404c0e28f879c640327fdc0036` | `bcb41b7ab17ebe674e68e0c4998d66f52d11300e` |
| 2004-12-13 | Microsoft DirectX SDK December 2004 Extras | [`dxsdk_dec2004_extras.exe`](https://archive.org/download/dxsdk_dec2004_extras/dxsdk_dec2004_extras.exe) | 36831528 | `42a42c199661c54c8fea855fb62dc592` | `474bc15ebbae84609b3c0e4fd66ed193b1329bb4` |
| 2005-02-09 | Microsoft DirectX SDK February 2005 Extras | [`dxsdk_feb2005_extras.exe`](https://archive.org/download/dxsdk_feb2005_extras/dxsdk_feb2005_extras.exe) | 37361416 | `1dd5634251f1edb45086d3e8b41b9a91` | `c0aceecfb7fe57bcad1996baffa4ae482dc8f708` |
| 2006-02-07 | Microsoft DirectX SDK February 2006 symbols | [`dxsdk_feb2006_symbols.exe`](https://archive.org/download/dxsdk_feb2006_symbols/dxsdk_feb2006_symbols.exe) | 38914808 | `9dd293f8dd5b8a883e1abb242c131394` | `a70329410ddbbece2b6e38dbeb4887d9c4643bc6` |

## 3. Verified media contents

The Game SDK archive (`gamesdk`, DirectX 1.0) was downloaded and listed to
confirm the class of media carries real SDK trees.  MD5 matched the
metadata (`81be7a3e056500d4b7e685c27cf3c959`), and it contains
`GAMESDK/SDK/INC/DDRAW.H`, `DSOUND.H`, `DPLAY.H`, `DSETUP.H`,
`FASTFILE.H` plus `GAMESDK/SDK/LIB/{DDRAW,DSOUND,DPLAY,DSETUP,FASTFILE}.LIB`.
The other items are self-extracting installers, RAR sets, or ISOs; their
internal trees were not independently extracted here.

Detection note: several of these installers trip archive.org's malware
scanner.  `dx8a_sdk` (DirectX 8.0a) had its file removed under "suspected
malware", so that release is not downloadable from the collection.

## 4. Official Microsoft source (June 2010)

The last DirectX SDK is still served by Microsoft Download Center (id 6812):

- Page: `https://www.microsoft.com/en-us/download/details.aspx?id=6812`
- File: `https://download.microsoft.com/download/a/e/7/ae743f1f-632b-4809-87a9-aa1bb3458e31/DXSDK_Jun10.exe`
- `Content-Length: 599455936`, `Last-Modified: 2025-02-14`

The archive.org `dxsdk_jun10` copy is 599452800 bytes, 3136 bytes smaller.
The two are not byte-identical, so pin the source you actually use.  This is
the only DirectX SDK Microsoft still hosts; everything older is
preservation-only.

## 5. Header-only mirrors (decomp.me precedent)

decomp.me layers SDK headers onto a bare compiler image as a "library":
`site/backend/libraries/libraries.yaml` maps `win32 -> directx -> version`
to a GitHub branch, `download.py` unpacks it to
`LIBRARY_BASE_PATH/<platform>/<name>/<version>/`, and
`compiler_wrapper.py` appends `library_include_flag + include_path` for each
selected library.  MSVC uses `/IZ:`, the wine drive prefix.  There is no lib
path: `Library.get_include_path` returns only `include/`, and decomp.me never
links.  Headers alone are sufficient for object-level comparison.

The two mirrors it uses are header-only, with no declared license:

| Repo | Branch | Pinned commit | Covers |
|---|---|---|---|
| `roblabla/directx-headers` | `5.0` | `2ebd637827f50d0dab3c8cb2e9742bb3aafc7e75` | DirectX 5.0 headers (`ddraw.h`, `d3d.h`, `dinput.h`, `dsound.h`) |
| `roblabla/directx-headers` | `main` | `0d3e6f1fd1c9ca49988a9af201063db455dd8c01` | DirectX 8-era headers (`d3d8.h`, `d3dx8*.h`, DirectShow, DirectMusic) |
| `ifarbod/dxsdk9` | `master` | `c9cb2823cd1fc7d3b7c09b14e827cedf42d00400` | DirectX 9 (June 2010) headers, no `.lib` |

`libraries.yaml` labels these `5.0`, `8.0`, and `9.0`.  No 6.0 or 7.0 entry
exists.  Both repos are unpinned upstream forks of SDK headers; verify
against the original media before relying on byte equality.

## 6. License-clean compile-only headers

Reimplemented headers let a function compile without an official SDK, but
they are not byte-equivalent to the original SDK headers, so they cannot be
expected to reproduce the original codegen.

- `microsoft/DirectX-Headers`, MIT.  Official, but covers DirectX 12 /
  D3D12 / DirectXMath only, nothing for the DirectX 5-9 era.
- Wine (`wine-mirror/wine`): reimplemented `ddraw.h`, `d3d.h`, `dsound.h`,
  `dinput.h` under LGPL-2.1+ (GitHub reports the multi-license tree as
  `NOASSERTION`).
- ReactOS (`reactos/reactos`): LGPL/GPL-style reimplementations.
- MinGW-w64 (`mingw-w64/mingw-w64`): permissive mix, ships `d3d9.h`,
  `dsound.h`, `dinput.h`, no DirectX 3-7 headers.

Use these to make a decompile compile.  Use the original SDK media in
sections 1 and 2 to match bytes.

## 7. Windows Platform SDK media

The same layering need applies to the Platform SDK (`winnt.h`,
`winbase.h`, `commctrl.h`), which changes struct packing and `WINVER`
gates.  Verified archive.org items:

| Date | Title | File | Size | MD5 | SHA1 |
|---|---|---|---|---|---|
| 2001-06 | Platform SDK June 2001 (`en_platform_sdk_june_2001`) | [`en_platform_sdk_june_2001.exe`](https://archive.org/download/en_platform_sdk_june_2001/en_platform_sdk_june_2001.exe) | 338875255 | `2796cd52a966dbfeccee6278535be707` | `2a2cbaddec91972060e48b576e74f9ed780d0e0a` |
| 2001-09 | MSDN Disc 0727.5, bundles DirectX 8.0a SDK (`msdn-disc0727.5-september-2001-x08-45038`) | [`1_platsdk_tools.iso`](https://archive.org/download/msdn-disc0727.5-september-2001-x08-45038/1_platsdk_tools.iso) | 2704539648 | `729484ff932d1fd80102827a2f66085f` | `0969a81b7e02452a0ef2c6a19a33c42465639301` |
| 2004-08-01 | Platform SDK for Windows XP SP2 (`xpsp2sdk`) | [`XP SP2 SDK.iso`](https://archive.org/download/xpsp2sdk/XP%20SP2%20SDK.iso) | 248590336 | `16bf333ed70d1aae0d9cfefbbd220476` | `6cfe1a272da4fd71fe5882fc7c1215c55008c318` |

The MSDN disc is the fallback for DirectX 8.0a after the `dx8a_sdk` removal.
Two further items (`psdk-full.-1` "Platform SDK Feb 2003" and
`psdk-2600.2180` "Platform SDK 2600.2180") expose only an `Extract.exe`
stub, so their payloads were not retrievable.

## 8. Reproducing the verification

```bash
curl -sS "https://archive.org/metadata/<identifier>" \
  | jq -r '.files[] | select(.name|test("\\.(iso|exe|zip|rar|7z|img)$";"i")) | "\(.name) \(.size) \(.md5) \(.sha1)"'
```

The collection listing itself:

```bash
curl -sS 'https://archive.org/advancedsearch.php?q=collection%3Adirectxsdks&fl%5B%5D=identifier&rows=200&output=json'
```

## 9. Relation to rebrew

rebrew has no SDK layer: `ProjectConfig.compiler_includes` is a single path
and the image supplies one `INCLUDE`/`LIB` pair.  These media are the trees
such a layer would vendor.  If an SDK layer is built, pin the extracted
header tree by sha256 (matching the `sources.json` discipline), not just the
installer, because installers differ between the Microsoft and archive.org
copies and an installer hash does not fix the header contents.
