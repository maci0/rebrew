"""crypto_scan.py: Name-and-constant crypto detector for a target binary.

Two independent signals:

- **Constant tables**: the fixed algorithm constants of AES / SHA-256 /
  SHA-1 / MD5 are searched in the binary's data sections.  A 256-byte S-box
  or round-constant table is a strong indicator on its own; the initial-hash
  words are short but exact.
- **Names**: imported APIs (Windows CryptoAPI/CNG, OpenSSL, common hash and
  cipher libraries) and the project's own function names are matched against
  curated pattern sets.  An import is a high-confidence hit; a function name
  is medium because a name can be a wrapper or an unrelated coincidence.

Neither signal is proof of cryptographic *use*: a statically linked library
that is never called still leaves tables in the image, and a name can be a
thin forwarding wrapper.  The scan narrows where to look.

Usage:
    rebrew crypto-scan [binary]
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal

import typer
from rich.console import Console
from rich.table import Table

from rebrew.cli import EXIT_ERROR, TargetOption, error_exit, json_print, require_config

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Constant tables (fixed algorithm constants, embedded as literals)
# ---------------------------------------------------------------------------

#: AES forward S-box (FIPS-197, 256 bytes).
_AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)

#: AES inverse S-box (FIPS-197, 256 bytes).
_AES_INV_SBOX = bytes.fromhex(
    "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb"
    "547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd125"
    "72f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d84"
    "90d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b"
    "3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e"
    "47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af4"
    "1fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cef"
    "a0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d"
)


def _words_from_hex(text: str) -> tuple[int, ...]:
    """Decode a big-endian hex string into consecutive uint32 values."""
    return tuple(int(text[index : index + 8], 16) for index in range(0, len(text), 8))


#: SHA-256 round constants K (FIPS 180-4, 64 uint32).
_SHA256_K = _words_from_hex(
    "428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5"
    "d807aa9812835b01243185be550c7dc372be5d7480deb1fe9bdc06a7c19bf174"
    "e49b69c1efbe47860fc19dc6240ca1cc2de92c6f4a7484aa5cb0a9dc76f988da"
    "983e5152a831c66db00327c8bf597fc7c6e00bf3d5a7914706ca635114292967"
    "27b70a852e1b21384d2c6dfc53380d13650a7354766a0abb81c2c92e92722c85"
    "a2bfe8a1a81a664bc24b8b70c76c51a3d192e819d6990624f40e3585106aa070"
    "19a4c1161e376c082748774c34b0bcb5391c0cb34ed8aa4a5b9cca4f682e6ff3"
    "748f82ee78a5636f84c878148cc7020890befffaa4506cebbef9a3f7c67178f2"
)

#: SHA-256 initial hash value H (FIPS 180-4, 8 uint32).
_SHA256_H = _words_from_hex("6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19")

#: SHA-1 initial hash value H (FIPS 180-1, 5 uint32).
_SHA1_H = _words_from_hex("67452301efcdab8998badcfe10325476c3d2e1f0")

#: MD5 sine-derived T table (RFC 1321, 64 uint32).
_MD5_T = _words_from_hex(
    "d76aa478e8c7b756242070dbc1bdceeef57c0faf4787c62aa8304613fd469501"
    "698098d88b44f7afffff5bb1895cd7be6b901122fd987193a679438e49b40821"
    "f61e2562c040b340265e5a51e9b6c7aad62f105d02441453d8a1e681e7d3fbc8"
    "21e1cde6c33707d6f4d50d87455a14eda9e3e905fcefa3f8676f02d98d2a4c8a"
    "fffa39428771f6816d9d6122fde5380ca4beea444bdecfa9f6bb4b60bebfbc70"
    "289b7ec6eaa127fad4ef308504881d05d9d4d039e6db99e51fa27cf8c4ac5665"
    "f4292244432aff97ab9423a7fc93a039655b59c38f0ccc92ffeff47d85845dd1"
    "6fa87e4ffe2ce6e0a30143144e0811a1f7537e82bd3af2352ad7d2bbeb86d391"
)

#: Byte-wide tables searched as-is.
_BYTE_TABLES: tuple[tuple[str, bytes], ...] = (
    ("AES S-box", _AES_SBOX),
    ("AES inverse S-box", _AES_INV_SBOX),
)

#: Word-wide tables, stored as uint32 values; a target may carry either
#: endianness, so both encodings are searched.
_WORD_TABLES: tuple[tuple[str, tuple[int, ...]], ...] = (
    ("SHA-256 round constants K", _SHA256_K),
    ("SHA-256 initial hash H", _SHA256_H),
    ("SHA-1 initial hash H", _SHA1_H),
    ("MD5 T table", _MD5_T),
)

_WORD_ENCODINGS: tuple[Literal["little", "big"], ...] = ("little", "big")

#: Sections that hold code, never constant tables.
_CODE_SECTIONS: frozenset[str] = frozenset({".text", ".code", ".init", ".fini"})

#: Confidence labels.  An import or constant table is ``high``; a function
#: name is ``medium`` because a name can be a wrapper or a coincidence.
_HIGH_CONFIDENCE = "high"
_MEDIUM_CONFIDENCE = "medium"

#: Confidence levels, most confident first; drives sort order and the
#: ``by_confidence`` summary keys.
_CONFIDENCE_LEVELS: tuple[str, ...] = (_HIGH_CONFIDENCE, _MEDIUM_CONFIDENCE)

#: ``(group label, pattern)`` pairs for name detection.  A pattern with ``*``
#: is anchored at both ends (``Crypt*`` = names starting with ``Crypt``); a
#: pattern without one is a case-insensitive substring test.
_NAME_PATTERNS: tuple[tuple[str, str], ...] = (
    ("Windows CryptoAPI/CNG", "Crypt*"),
    ("Windows CryptoAPI/CNG", "BCrypt*"),
    ("Windows CryptoAPI/CNG", "NCrypt*"),
    ("OpenSSL", "EVP_*"),
    ("OpenSSL", "RSA_*"),
    ("OpenSSL", "AES_*"),
    ("OpenSSL", "DES_*"),
    ("OpenSSL", "SHA*"),
    ("OpenSSL", "MD5*"),
    ("OpenSSL", "HMAC*"),
    ("Common crypto", "ChaCha*"),
    ("Common crypto", "Poly1305*"),
    ("Common crypto", "Salsa20*"),
    ("Common crypto", "Blowfish*"),
    ("Common crypto", "libsodium"),
    ("Common crypto", "mbedtls_*"),
    ("Common crypto", "wolfSSL*"),
    ("Common crypto", "CRC32"),
)


def _pack_words(words: tuple[int, ...], endian: Literal["little", "big"]) -> bytes:
    """Encode *words* as consecutive 4-byte integers in *endian* order."""
    return b"".join(word.to_bytes(4, endian) for word in words)


def _build_needles() -> tuple[tuple[str, bytes], ...]:
    """Every ``(table name, needle bytes)`` pair to search for."""
    needles: list[tuple[str, bytes]] = list(_BYTE_TABLES)
    for name, words in _WORD_TABLES:
        for endian in _WORD_ENCODINGS:
            needles.append((name, _pack_words(words, endian)))
    return tuple(needles)


_TABLE_NEEDLES: tuple[tuple[str, bytes], ...] = _build_needles()


# ---------------------------------------------------------------------------
# Constant-table detection
# ---------------------------------------------------------------------------


def _overlaps(intervals: list[tuple[int, int]], start: int, end: int) -> bool:
    """True when ``[start, end)`` overlaps any recorded interval."""
    return any(
        start < existing_end and existing_start < end for existing_start, existing_end in intervals
    )


def constant_findings(sections: Sequence[tuple[str, int, bytes]]) -> list[dict[str, Any]]:
    """Find embedded crypto constant tables in *sections*.

    Each entry is ``(section name, section VA, raw section bytes)``.  For
    every table the raw bytes are searched directly (and, for the uint32
    tables, in both little- and big-endian encodings); a hit reports the
    table's absolute VA.  Overlapping hits of the same table in the same
    section are collapsed to the first.  Empty input yields ``[]``.
    """
    out: list[dict[str, Any]] = []
    for section_name, section_va, blob in sections:
        covered: dict[str, list[tuple[int, int]]] = {}
        for name, needle in _TABLE_NEEDLES:
            if not needle or len(needle) > len(blob):
                continue
            start = 0
            while True:
                offset = blob.find(needle, start)
                if offset < 0:
                    break
                end = offset + len(needle)
                if not _overlaps(covered.setdefault(name, []), offset, end):
                    covered[name].append((offset, end))
                    out.append(
                        {
                            "kind": "constant",
                            "name": name,
                            "va": section_va + offset,
                            "section": section_name,
                            "confidence": _HIGH_CONFIDENCE,
                        }
                    )
                start = end
    out.sort(key=lambda finding: (finding["va"], finding["name"]))
    return out


# ---------------------------------------------------------------------------
# Name detection
# ---------------------------------------------------------------------------


def _pattern_matches(pattern: str, candidate: str) -> bool:
    """Match a curated *pattern* against *candidate*, case-insensitively."""
    lowered = candidate.lower()
    pattern = pattern.lower()
    if "*" not in pattern:
        return pattern in lowered
    parts = [re.escape(part) for part in pattern.split("*")]
    return re.fullmatch(".*".join(parts), lowered) is not None


def _match_pattern(name: str) -> tuple[str, str] | None:
    """Return ``(group, pattern)`` for the first pattern matching *name*."""
    for group, pattern in _NAME_PATTERNS:
        if _pattern_matches(pattern, name):
            return group, pattern
    return None


def name_findings(
    imports: Sequence[dict[str, Any]], function_names: Sequence[str]
) -> list[dict[str, Any]]:
    """Match import names and project function names against the pattern sets.

    Import hits carry ``confidence: "high"``; function-name hits carry
    ``"medium"``.  Duplicate names within a source are reported once, and a
    function name that an import already reported is skipped so a symbol is
    never listed twice at two confidences.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in imports:
        name = str(record.get("name") or "")
        if not name or name in seen:
            continue
        match = _match_pattern(name)
        if match is None:
            continue
        group, pattern = match
        seen.add(name)
        out.append(
            {
                "kind": "import",
                "name": name,
                "detail": f"{group} ({pattern})",
                "confidence": _HIGH_CONFIDENCE,
            }
        )
    for name in function_names:
        if not name or name in seen:
            continue
        match = _match_pattern(name)
        if match is None:
            continue
        group, pattern = match
        seen.add(name)
        out.append(
            {
                "kind": "name",
                "name": name,
                "detail": f"{group} ({pattern})",
                "confidence": _MEDIUM_CONFIDENCE,
            }
        )
    return out


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


def _data_sections(info: Any) -> list[tuple[str, int, bytes]]:
    """File-backed data sections as ``(name, va, bytes)`` for constant search.

    Code sections are skipped; a section with no file-backed bytes (BSS) is
    skipped.  Bytes are clamped to the file length.
    """
    raw = info.data
    out: list[tuple[str, int, bytes]] = []
    for name, section in info.sections.items():
        if name in _CODE_SECTIONS or name.endswith(".__text"):
            continue
        start = section.file_offset
        end = min(start + section.raw_size, len(raw))
        if start < 0 or start >= end:
            continue
        out.append((name, section.va, raw[start:end]))
    return out


def crypto_scan(
    binary_path: str | Path, function_names: Sequence[str] | None = None
) -> dict[str, Any]:
    """Scan *binary_path* for crypto constants, imports, and function names.

    Returns ``{"binary", "findings", "count", "by_confidence"}``; findings
    are sorted by confidence then name.  No findings is a valid result.
    Raises ``FileNotFoundError`` when the path does not exist.
    """
    path = Path(binary_path)
    if not path.exists():
        raise FileNotFoundError(f"Binary not found: {path}")

    from rebrew.binary_loader import load_binary
    from rebrew.imports import parse_imports

    try:
        info = load_binary(path)
    except (OSError, ValueError) as exc:
        raise ValueError(f"Cannot parse binary {path}: {exc}") from exc

    findings = constant_findings(_data_sections(info))
    findings.extend(name_findings(parse_imports(path), list(function_names or [])))
    findings.sort(key=lambda finding: (finding["confidence"], finding["name"]))

    by_confidence = dict.fromkeys(_CONFIDENCE_LEVELS, 0)
    for finding in findings:
        by_confidence[finding["confidence"]] += 1
    return {
        "binary": str(path),
        "findings": findings,
        "count": len(findings),
        "by_confidence": by_confidence,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _project_function_names(cfg: Any) -> list[str]:
    """Function names from the project's function list, or ``[]``.

    Best-effort: a missing or unreadable list leaves the name signal with
    no project input rather than failing the scan.
    """
    try:
        from rebrew.catalog import cached_function_list

        functions = cached_function_list(cfg)
    except (ImportError, AttributeError, OSError, ValueError, KeyError):
        return []
    return [str(entry["name"]) for entry in functions if entry.get("name")]


def _detail_text(finding: dict[str, Any]) -> str:
    """Human-table detail for a finding: address+section for constants."""
    if finding["kind"] == "constant":
        return f"0x{finding['va']:08x} in {finding['section']}"
    return str(finding.get("detail", ""))


app = typer.Typer(
    help="Detect crypto in a binary: constant tables, crypto imports, and function names.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew crypto-scan · · · · · · · · Scan the project's target binary\n\n"
        "  rebrew crypto-scan original/game.exe Scan a specific binary\n\n"
        "  rebrew crypto-scan game.exe --json · Machine-readable findings\n\n"
        "[bold]What it detects:[/bold]\n\n"
        "  Constant tables · · · · AES S-box / inverse, SHA-256 K and H,\n\n"
        "                          SHA-1 H, MD5 T (both endiannesses)\n\n"
        "  Imports · · · · · · · · · Crypt* / BCrypt* / NCrypt*, EVP_* / RSA_*,\n\n"
        "                          SHA* / MD5* / HMAC*, libsodium, mbedtls_*, ...\n\n"
        "  Function names · · · · · Project functions matching those patterns\n\n"
        "[dim]An import is high confidence; a function name is medium.  A\n"
        "finding is an indicator, not proof the code is called.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    binary: Path | None = typer.Argument(None, help="Binary path (default: project target)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Detect crypto constant tables, crypto imports, and crypto-named functions."""
    cfg: Any = None
    if binary is None:
        cfg = require_config(target=target, json_mode=json_output)
        binary = cfg.target_binary
        if not binary.exists():
            error_exit(f"target binary missing: {binary}", json_mode=json_output, code=EXIT_ERROR)
    else:
        try:
            from rebrew.config import load_config

            cfg = load_config(target=target)
        except (FileNotFoundError, OSError, KeyError, ValueError):
            cfg = None
    if not binary.exists():
        error_exit(f"binary not found: {binary}", json_mode=json_output)

    function_names = _project_function_names(cfg) if cfg is not None else []
    try:
        result = crypto_scan(binary, function_names)
    except (OSError, ValueError) as exc:
        error_exit(f"cannot scan {binary}: {exc}", json_mode=json_output, code=EXIT_ERROR)

    if json_output:
        json_print(result)
        return

    findings = result["findings"]
    if not findings:
        console.print(f"[yellow]No crypto indicators found in {binary}.[/]")
        return
    console.print(f"[bold]{result['count']}[/] crypto indicator(s) in [bold]{binary}[/]:")
    table = Table()
    table.add_column("Confidence", style="bold")
    table.add_column("Kind")
    table.add_column("Name")
    table.add_column("Detail", overflow="fold")
    for finding in findings:
        confidence = str(finding["confidence"])
        color = "red" if confidence == _HIGH_CONFIDENCE else "yellow"
        table.add_row(
            f"[{color}]{confidence}[/]",
            str(finding["kind"]),
            str(finding["name"]),
            _detail_text(finding),
        )
    console.print(table)


def main_entry() -> None:
    """Run the Typer CLI application."""
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
