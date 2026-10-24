"""Declared license of every distribution the committed ``uv.lock`` pins.

Provenance: each value is the license string the pinned artifact declares in
its own ``METADATA`` — ``License-Expression`` when present, else ``License``,
else the first ``Classifier: License ::`` line.  Nothing here is interpreted
or upgraded to a different grant: a trove classifier such as
``OSI Approved :: BSD License`` does not say which BSD, and guessing would
put a license claim in a release artifact that upstream never made.

``generate_sbom.py`` reads this table so the CycloneDX inventory carries a
license for every component instead of leaving 109 of 112 blank, and
``tests/test_packaging.py`` fails when the lock and this table disagree, so a
``uv lock --upgrade`` cannot ship an unrecorded grant.

``NOASSERTION`` marks a package whose metadata did not name a grant this table
could record verbatim: ``colorama`` sits behind a ``sys_platform == 'win32'``
marker and this project is Linux-only, so it never installs, and ``pyxdia``
puts the whole MIT text in a multi-line ``License`` field and ships no trove
classifier, leaving no single-line field to quote.  It is the SPDX value for
"not determined" and is a claim about this table, not about the package.
"""

from __future__ import annotations

# Non-registry sources have no version-independent identity: a path checkout
# and a commit-pinned git dependency are recorded by name.
PATH_OR_GIT_LICENSES = {
    "m2c": "GPL-3.0-only",
    # resembl 3.6.1 declares License-Expression: GPL-3.0-only (PEP 639).
    # There is no free-text License field on that artifact.
    "resembl": "GPL-3.0-only",
}

# ``name==version`` -> the artifact's own declared license string.
REGISTRY_LICENSES: dict[str, str] = {
    "angr==10.0.5": "BSD-2-Clause",
    "angr-data==0.2.0": "BSD-2-Clause",
    "annotated-doc==0.0.5": "MIT",
    "annotated-types==0.8.0": "MIT",
    "anyio==4.15.1": "MIT",
    "archinfo==10.0.5": "BSD-2-Clause",
    "arpy==1.1.1": "Simplified BSD",
    "asn1crypto==1.5.1": "MIT",
    "ast-serialize==0.13.1": "MIT",
    "bitarray==3.12.3": "PSF-2.0",
    "bitstring==4.4.0": "MIT",
    "cachetools==7.2.4": "MIT",
    "capstone==5.0.9": "OSI Approved :: BSD License",
    "cart==1.2.3": "MIT",
    "certifi==2026.10.23": "MPL-2.0",
    "cffi==2.1.1": "MIT-0",
    "cfgv==3.5.0": "MIT",
    "cle==10.0.5": "BSD-2-Clause",
    "click==8.5.0": "BSD-3-Clause",
    "colorama==0.4.6": "NOASSERTION",
    "cxxheaderparser==2.2.0": "BSD-3-Clause",
    "declib==4.5.0": "BSD-2-Clause",
    "diskcache==5.6.3": "Apache 2.0",
    "distlib==0.4.4": "PSF-2.0",
    "execnet==2.1.2": "MIT",
    "filelock==4.2.4": "MIT",
    "future==1.0.0": "MIT",
    "gitdb==4.0.12": "BSD License",
    "gitpython==3.2.1": "BSD-3-Clause",
    "graphviz==0.20.3": "MIT",
    "h11==0.16.0": "MIT",
    "httpcore==1.0.9": "BSD-3-Clause",
    "httpx==0.28.1": "BSD-3-Clause",
    "hypothesis==6.170.9": "MPL-2.0",
    "identify==2.6.20": "MIT",
    "idna==3.20": "BSD-3-Clause",
    "iniconfig==2.3.1": "MIT",
    "jpype1==1.7.1": "Apache-2.0",
    "librt==0.16.0": "MIT",
    "lief==1.0.0": "Apache License 2.0",
    "lmdb==3.0.0": "OLDAP-2.8",
    "markdown-it-py==4.2.0": "OSI Approved :: MIT License",
    "mdurl==0.1.2": "OSI Approved :: MIT License",
    "minidump==0.0.24": "OSI Approved :: MIT License",
    "msgspec==0.22.0": "BSD-3-Clause",
    "mulpyplexer==0.9": "BSD",
    "mypy==2.4.0": "MIT",
    "mypy-extensions==1.1.0": "MIT",
    "networkx==3.7": "BSD-3-Clause",
    "nodeenv==1.11.0": "BSD",
    "numpy==2.5.4": "BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0",
    "packaging==26.3": "Apache-2.0 OR BSD-2-Clause",
    "pathspec==1.1.1": "OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
    "pefile==2024.8.26": "MIT",
    "platformdirs==4.13.5": "MIT",
    "pluggy==1.7.0": "MIT",
    "ply==3.11": "BSD",
    "pg8000==1.31.5": "BSD 3-Clause License",
    "pre-commit==4.7.0": "MIT",
    "prompt-toolkit==3.0.53": "OSI Approved :: BSD License",
    "protobuf==7.36.2": "3-Clause BSD License",
    "psutil==7.2.2": "BSD-3-Clause",
    "pycparser==3.11": "BSD-3-Clause",
    "pycryptodome==4.2.0": "BSD-2-Clause AND Unlicense AND MIT",
    "pydantic==2.14.1": "MIT",
    "pydantic-core==2.50.1": "MIT",
    "pydemumble==0.1.3": "OSI Approved :: BSD License",
    "pyelftools==0.33": "Public domain",
    "pyghidra==3.2.0": "Apache-2.0",
    "pygments==2.21.0": "BSD-2-Clause",
    "pymysql==1.2.3": "MIT",
    "pypcode==4.0.1": "BSD-2-Clause AND Apache-2.0 AND Zlib",
    "pytest==9.1.1": "MIT",
    "pytest-xdist==3.8.0": "MIT",
    "python-dateutil==3.0.0": "Dual License",
    # Multi-line License field (the full MIT text, which the docstring's
    # fallback rule skips); the trove classifier is the declared grant.
    "python-discovery==1.6.4": "OSI Approved :: MIT License",
    "python-flirt==0.10.2": "License :: OSI Approved :: Apache Software License",
    "pyvex==10.0.5": "BSD-2-Clause AND GPL-2.0-or-later",
    "pyxbe==1.0.4": "MIT",
    "pyxdia==0.1.1": "NOASSERTION",  # full MIT text in a multi-line License field, no classifier
    "pyyaml==6.0.3": "MIT",
    "rapidfuzz==3.14.6": "MIT",
    "rich==15.0.0": "MIT",
    "ruff==0.17.2": "MIT",
    "scramp==1.4.18": "MIT-0",
    "setuptools==84.2.1": "MIT",
    "shellingham==1.5.4": "ISC License",
    "six==1.17.0": "MIT",
    "skills-ref==0.1.1": "Apache-2.0",
    "slipcover==1.1.0": "OSI Approved :: Apache Software License",
    "smmap==5.0.3": "BSD-3-Clause",
    "sortedcontainers==2.4.0": "Apache 2.0",
    "sqlalchemy==2.1.6": "MIT",
    "sqlmodel==0.0.48": "MIT",
    "strictyaml==1.7.3": "MIT",
    "tabulate==0.10.0": "MIT",
    "tibs==0.5.7": "The MIT License",
    "toml==0.10.2": "MIT",
    "tomli-w==1.2.0": "OSI Approved :: MIT License",
    "tomlkit==0.15.2": "MIT",
    "tqdm==4.70.1": "MPL-2.0 AND MIT",
    "tree-sitter==0.26.0": "OSI Approved :: MIT License",
    "tree-sitter-c==0.24.2": "MIT",
    "typer==0.27.3": "MIT",
    "tzdata==2026.5": "Apache-2.0",
    "typing-extensions==4.16.0": "PSF-2.0",
    "typing-inspection==0.4.4": "MIT",
    "uefi-firmware==1.16": "BSD-3-Clause",
    "virtualenv==21.14.13": "MIT",
    "wcwidth==0.9.3": "License :: OSI Approved :: MIT License",
    "z3-solver==5.3.1.0": "MIT License",
    "zstandard==0.25.0": "BSD-3-Clause",
}
