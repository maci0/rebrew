"""generate_sbom.py – Emit a CycloneDX 1.5 SBOM from the committed uv.lock.

Offline-only: reads ``uv.lock`` (and the project's own version from
``src/rebrew/__init__.py``).  No network, no advisory DB, no package
install.  Consumers and vuln scanners get a release inventory without
re-resolving PyPI.  The rebrew component's purl is the GitHub repository
(``pkg:github/maci0/rebrew@v<version>``); dependency components keep
``pkg:pypi`` when the lock fetched them from the index.

Every emitted document passes ``validate_bom``; a lock that parsed to a near
empty inventory exits 1 rather than writing a BOM a scanner reads as clean.

Licenses come from ``tools/licenses.py`` (each pinned artifact's own declared
string), not from the network, so a component without a recorded grant fails
the run instead of reaching a scanner as a blank field.

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
import tomllib
from pathlib import Path
from typing import Any

# `make sbom` runs this file directly under `uv --no-project`, so the repo root
# is not on sys.path the way pytest puts it there.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.licenses import PATH_OR_GIT_LICENSES, REGISTRY_LICENSES

_REPO_ROOT = Path(__file__).resolve().parent.parent
_LOCK = _REPO_ROOT / "uv.lock"
_INIT = _REPO_ROOT / "src" / "rebrew" / "__init__.py"
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.M)

# A declared grant goes in ``expression`` when every id in it is an SPDX
# identifier, and in ``name`` when it is the trove text or prose an artifact
# actually ships.  Normalizing a classifier to an id the upstream never wrote
# would put a license claim in a release artifact.  "BSD" (sympy) and "GPLv3"
# (resembl) are both single bare tokens and neither is an SPDX id, so the set
# of known ids is what decides the form, not the shape of the string.  An id
# this table has not recorded yet falls back to ``name``: that form quotes the
# declaration instead of asserting a claim, which is the side to err on.
_SPDX_IDS = frozenset(
    {
        "0BSD",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "CC0-1.0",
        "GPL-2.0-or-later",
        "GPL-3.0-only",
        "MIT",
        "MIT-0",
        "MPL-2.0",
        "NOASSERTION",
        "OLDAP-2.8",
        "PSF-2.0",
        "Zlib",
    }
)
_EXPRESSION_JOINER_RE = re.compile(r"\s+(?:AND|OR|WITH)\s+")


def _license_field(source_kind: str, name: str, version: str) -> dict[str, Any]:
    """The CycloneDX ``licenses`` entry for one locked distribution."""
    if source_kind == "registry":
        declared = REGISTRY_LICENSES.get(f"{name}=={version}")
    else:
        declared = PATH_OR_GIT_LICENSES.get(name)
    if declared is None:
        raise ValueError(
            f"no recorded license for {name}=={version} ({source_kind}): add the grant "
            f"it declares to tools/licenses.py, and NOTICE if it is not permissive"
        )
    tokens = _EXPRESSION_JOINER_RE.split(declared)
    if all(token in _SPDX_IDS for token in tokens):
        return {"expression": declared}
    return {"license": {"name": declared}}


# Copyleft dependencies pinned in uv.lock.  Expressions were read from the
# locked artifacts: m2c aa869da ``License-Expression: GPL-3.0-only``, pyvex
# 9.3.4 ``License-Expression: BSD-2-Clause AND GPL-2.0-or-later``, and the
# MPL-2.0 packages below.  resembl states the trove text ``GPLv3`` (which
# reads as GPL-3.0-only), so the emitted component carries that name rather
# than an expression upstream never wrote.  certifi 2026.7.22 and hypothesis
# 6.168.0 declare ``MPL-2.0`` and every resolve pulls them in; tqdm 4.70.1
# declares ``License-Expression: MPL-2.0 AND MIT`` and arrives with the
# ``binsync`` extra (declib's progress bars).  See NOTICE.
# Permissive dependencies keep the license metadata inside their own wheels.
#
# ``tests/test_packaging.py`` fails when the resolved environment holds a
# copyleft distribution missing from this table, so a lock bump cannot drop
# the attribution silently.  Only the names are load-bearing: the emitted
# license always comes from ``tools/licenses.py``.
_COPYLEFT_EXPRESSIONS = {
    "resembl": "GPLv3",
    "m2c": "GPL-3.0-only",
    "pyvex": "BSD-2-Clause AND GPL-2.0-or-later",
    "certifi": "MPL-2.0",
    "hypothesis": "MPL-2.0",
    "tqdm": "MPL-2.0 AND MIT",
}
#: License families that oblige downstream consumers beyond the MIT grant the
#: wheel ships under: NOTICE attribution, source availability, or a
#: reciprocal-license clause on derived work.  Used only to decide which
#: distributions the SBOM must name explicitly; the emitted expression always
#: comes from ``_COPYLEFT_EXPRESSIONS``.
_COPYLEFT_FAMILIES = re.compile(r"AGPL|GPL|LGPL|MPL|CDDL|CECILL|EUPL|OSL|SSPL")


def canonicalize(name: str) -> str:
    """PEP 503 name normalization, so ``Tree_Sitter`` and ``tree-sitter`` agree."""
    return re.sub(r"[-_.]+", "-", name).lower()


def copyleft_names_in_environment() -> list[tuple[str, str]]:
    """Installed distributions whose own license metadata is copyleft.

    ``uv.lock`` carries no license field, so the SBOM's copyleft expressions
    can only be audited against the resolved environment.  Returns
    ``(canonical name, declared license)`` pairs sorted by name; PEP 639
    ``License-Expression`` wins over the legacy free-text ``License`` header.

    The SBOM generator stays offline and lock-driven, so this is a
    verification helper for tests rather than part of ``build_bom``.
    """
    import importlib.metadata as importlib_metadata

    found: dict[str, str] = {}
    for dist in importlib_metadata.distributions():
        name = (dist.metadata["Name"] or "").strip()
        if not name:
            continue
        meta = dist.metadata
        declared = (meta.get("License-Expression") or meta.get("License") or "").strip()
        # A multi-line License header is the full licence text, not a field.
        if "\n" in declared or not _COPYLEFT_FAMILIES.search(declared):
            continue
        found[canonicalize(name)] = declared
    return sorted(found.items())


def _project_version() -> str:
    text = _INIT.read_text(encoding="utf-8")
    match = _VERSION_RE.search(text)
    if match is None:
        raise SystemExit(f"no __version__ in {_INIT}")
    return match.group(1)


def _license_id(data: dict[str, Any]) -> str:
    """SPDX id from ``[project].license`` (PEP 639 string form)."""
    lic = data["project"]["license"]
    if not isinstance(lic, str) or not lic.strip():
        raise SystemExit("pyproject.toml [project].license must be an SPDX id string")
    return lic.strip()


# CycloneDX externalReference types for the project URL table.  Homepage and
# Repository may share a URL; the type is what differs.
_URL_REF_TYPES = (
    ("Repository", "vcs"),
    ("Homepage", "website"),
    ("Issues", "issue-tracker"),
    ("Changelog", "release-notes"),
    ("Security", "advisories"),
)


def _project_component(version: str) -> dict[str, Any]:
    """The SBOM root component for this GitHub repository.

    Install is the git URL in the README.  Release tags are ``v{version}``
    (the packaging tag contract), so the purl is
    ``pkg:github/<owner>/<repo>@v<version>`` from ``project.urls.Repository``.
    """
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    urls = data["project"]["urls"]
    repo = str(urls["Repository"]).rstrip("/")
    prefix = "https://github.com/"
    path = repo.removeprefix(prefix)
    if not repo.startswith(prefix) or path.count("/") != 1 or not path:
        raise SystemExit(f"project.urls.Repository is not a GitHub repo URL: {repo}")
    purl = f"pkg:github/{path}@v{version}"
    refs: list[dict[str, str]] = []
    for key, ref_type in _URL_REF_TYPES:
        url = urls.get(key)
        if isinstance(url, str) and url:
            refs.append({"type": ref_type, "url": url})
    return {
        "type": "library",
        "name": "rebrew",
        "version": version,
        "bom-ref": purl,
        "purl": purl,
        "licenses": [{"license": {"id": _license_id(data)}}],
        "externalReferences": refs,
    }


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
        if name == "rebrew":
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
        component["licenses"] = [_license_field(source_kind, name, version)]
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


# A BOM that parses but inventories nothing is worse than no BOM: a scanner
# reads it as a clean bill of health.  Every emitted document goes through
# this, so `make sbom` and the package job share one contract.
MIN_COMPONENTS = 10


def validate_bom(bom: dict[str, Any]) -> None:
    """Raise ValueError unless ``bom`` is a scannable CycloneDX document.

    Checks the format header, the spec version, a non-trivial component list,
    and a license on every component.  Deliberately structural: field-level
    schema validation belongs to the CycloneDX validator, not to this
    generator.
    """
    if bom.get("bomFormat") != "CycloneDX":
        raise ValueError(f"bomFormat is {bom.get('bomFormat')!r}, expected 'CycloneDX'")
    if bom.get("specVersion") != "1.5":
        raise ValueError(f"specVersion is {bom.get('specVersion')!r}, expected '1.5'")
    if "component" not in bom.get("metadata", {}):
        raise ValueError("metadata.component is missing: the document describes no subject")
    components = bom.get("components")
    if not isinstance(components, list) or len(components) < MIN_COMPONENTS:
        found = len(components) if isinstance(components, list) else "absent"
        raise ValueError(
            f"components lists {found} entries, expected at least {MIN_COMPONENTS}: "
            f"the lock parsed short, so the inventory would read as complete"
        )
    unlicensed = sorted(c.get("name", "?") for c in components if not c.get("licenses"))
    if unlicensed:
        raise ValueError(f"components without a license: {unlicensed}")


def build_bom(lock_text: str, project_version: str) -> dict[str, Any]:
    components = _parse_lock(lock_text)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": _project_component(project_version),
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
    try:
        bom = build_bom(args.lock.read_text(encoding="utf-8"), _project_version())
        validate_bom(bom)
    except ValueError as exc:
        print(f"error: generated SBOM is not scannable: {exc}", file=sys.stderr)
        return 1
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
