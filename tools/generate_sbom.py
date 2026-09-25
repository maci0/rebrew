"""generate_sbom.py – Emit a CycloneDX 1.5 SBOM from the committed uv.lock.

Offline-only: reads ``uv.lock`` (and the project's own version from
``src/rebrew/__init__.py``).  No network, no advisory DB, no package
install.  Consumers and vuln scanners get a release inventory without
re-resolving PyPI.

Usage::

    uv run --no-project --offline python tools/generate_sbom.py
    uv run --no-project --offline python tools/generate_sbom.py -o dist/rebrew.cdx.json
    make sbom
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_LOCK = _REPO_ROOT / "uv.lock"
_INIT = _REPO_ROOT / "src" / "rebrew" / "__init__.py"
_VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.M)


def _project_version() -> str:
    text = _INIT.read_text(encoding="utf-8")
    match = _VERSION_RE.search(text)
    if match is None:
        raise SystemExit(f"no __version__ in {_INIT}")
    return match.group(1)


def _parse_lock(text: str) -> list[dict[str, Any]]:
    """Parse uv.lock package stanzas into CycloneDX component dicts.

    ``tomllib`` is not used: a line-oriented parse is enough for name,
    version, source kind, and artifact hashes (uv.lock's inline tables are
    awkward to round-trip and we do not need the rest of each stanza).
    """
    components: list[dict[str, Any]] = []
    name: str | None = None
    version: str | None = None
    source_kind = "registry"
    source_extra = ""
    hashes: list[str] = []

    def flush() -> None:
        nonlocal name, version, source_kind, source_extra, hashes
        if name is None or version is None:
            name = version = None
            source_kind = "registry"
            source_extra = ""
            hashes = []
            return
        if name in {"rebrew"}:
            # The editable self-package is the SBOM metadata.component, not a
            # listed dependency.
            name = version = None
            source_kind = "registry"
            source_extra = ""
            hashes = []
            return
        purl = _purl(name, version, source_kind, source_extra)
        component: dict[str, Any] = {
            "type": "library",
            "name": name,
            "version": version,
            "bom-ref": purl,
            "purl": purl,
        }
        if hashes:
            # Prefer a single sha256; CycloneDX accepts multiple.
            component["hashes"] = [
                {"alg": "SHA-256", "content": h.removeprefix("sha256:")}
                for h in sorted(hashes)
                if h.startswith("sha256:")
            ]
        components.append(component)
        name = version = None
        source_kind = "registry"
        source_extra = ""
        hashes = []

    for raw in text.splitlines():
        line = raw.strip()
        if line == "[[package]]":
            flush()
            continue
        if line.startswith("name = "):
            name = line.split("=", 1)[1].strip().strip('"')
            continue
        if line.startswith("version = ") and version is None:
            version = line.split("=", 1)[1].strip().strip('"')
            continue
        if line.startswith("source = "):
            if "git =" in line:
                source_kind = "git"
                m = re.search(r'git = "([^"]+)"', line)
                source_extra = m.group(1) if m else ""
            elif "directory =" in line or "editable =" in line:
                source_kind = "path"
                m = re.search(r'(?:directory|editable) = "([^"]+)"', line)
                source_extra = m.group(1) if m else ""
            else:
                source_kind = "registry"
                source_extra = ""
            continue
        if "hash = " in line:
            m = re.search(r'hash = "(sha256:[0-9a-f]+)"', line)
            if m and m.group(1) not in hashes:
                hashes.append(m.group(1))
    flush()
    components.sort(key=lambda c: (c["name"], c["version"], c.get("bom-ref", "")))
    return components


def _purl(name: str, version: str, kind: str, extra: str) -> str:
    # Package URLs use underscores→hyphens for the PyPI namespace name form.
    dist = name.lower().replace("_", "-")
    if kind == "git":
        # Preserve the commit when uv embedded it after '#'.
        rev = ""
        if "#" in extra:
            rev = extra.rsplit("#", 1)[-1]
        base = extra.split("?", 1)[0].split("#", 1)[0]
        if rev:
            return f"pkg:generic/{dist}@{version}?vcs_url={base}&commit={rev}"
        return f"pkg:generic/{dist}@{version}?vcs_url={base}"
    if kind == "path":
        return f"pkg:generic/{dist}@{version}?file_name={extra}"
    return f"pkg:pypi/{dist}@{version}"


def build_bom(lock_text: str, project_version: str) -> dict[str, Any]:
    components = _parse_lock(lock_text)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "library",
                "name": "rebrew",
                "version": project_version,
                "bom-ref": f"pkg:pypi/rebrew@{project_version}",
                "purl": f"pkg:pypi/rebrew@{project_version}",
            },
        },
        "components": components,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Write JSON here (default: stdout)",
    )
    parser.add_argument(
        "--lock",
        type=Path,
        default=_LOCK,
        help="Path to uv.lock (default: repo root)",
    )
    args = parser.parse_args(argv)
    if not args.lock.is_file():
        print(f"error: lockfile not found: {args.lock}", file=sys.stderr)
        return 1
    bom = build_bom(args.lock.read_text(encoding="utf-8"), _project_version())
    payload = json.dumps(bom, indent=2, sort_keys=False) + "\n"
    if args.output is None:
        sys.stdout.write(payload)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        print(f"wrote {args.output} ({len(bom['components'])} components)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
