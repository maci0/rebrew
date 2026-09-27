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

``NOASSERTION`` marks a package whose metadata was not readable in-tree
(``colorama`` is behind a ``sys_platform == 'win32'`` marker and this project
is Linux-only, so it never installs).  It is the SPDX value for "not
determined" and is a claim about this table, not about the package.
"""

from __future__ import annotations

# Non-registry sources have no version-independent identity: a path checkout
# and a commit-pinned git dependency are recorded by name.
PATH_OR_GIT_LICENSES = {
    "m2c": "GPL-3.0-only",
    # resembl states the trove text "GPLv3", not an SPDX id.  It reads as
    # GPL-3.0-only (no later-version clause), but the SBOM records the string
    # the artifact declares and the reader does the mapping.
    "resembl": "GPLv3",
}

# ``name==version`` -> the artifact's own declared license string.
REGISTRY_LICENSES: dict[str, str] = {
    "angr==9.3.4": "BSD-2-Clause",
    "angr-data==0.1.0.post1": "BSD-2-Clause",
    "annotated-doc==0.0.5": "MIT",
    "annotated-types==0.8.0": "MIT",
    "anyio==4.15.1": "MIT",
    "archinfo==9.3.4": "BSD-2-Clause",
    "arpy==1.1.1": "Simplified BSD",
    "asn1crypto==1.5.1": "MIT",
    "ast-serialize==0.11.2": "MIT",
    "bitarray==3.11.0": "PSF-2.0",
    "bitstring==4.4.0": "MIT",
    "cachetools==7.1.8": "MIT",
    "capstone==5.0.9": "OSI Approved :: BSD License",
    "cart==1.2.3": "MIT",
    "certifi==2026.7.22": "MPL-2.0",
    "cffi==2.1.1": "MIT-0",
    "cfgv==3.5.0": "MIT",
    "claripy==9.3.4": "BSD-2-Clause",
    "cle==9.3.4": "BSD-2-Clause",
    "click==8.5.0": "BSD-3-Clause",
    "colorama==0.4.6": "NOASSERTION",
    "cxxheaderparser==2.0.0": "BSD-3-Clause",
    "declib==4.5.0": "BSD-2-Clause",
    "diskcache==5.6.3": "Apache 2.0",
    "distlib==0.4.3": "PSF-2.0",
    "filelock==3.32.6": "MIT",
    "future==1.0.0": "MIT",
    "gitdb==4.0.12": "BSD License",
    "gitpython==3.1.62": "BSD-3-Clause",
    "graphviz==0.20.3": "MIT",
    "greenlet==3.5.6": "MIT AND PSF-2.0",
    "h11==0.16.0": "MIT",
    "httpcore==1.0.9": "BSD-3-Clause",
    "httpx==0.28.1": "BSD-3-Clause",
    "hypothesis==6.168.0": "MPL-2.0",
    "identify==2.6.19": "MIT",
    "idna==3.19": "BSD-3-Clause",
    "iniconfig==2.3.0": "MIT",
    "jpype1==1.5.2": "License :: OSI Approved :: Apache Software License",
    "librt==0.15.0": "MIT",
    "lief==1.0.0": "Apache License 2.0",
    "lmdb==2.1.1": "OLDAP-2.8",
    "markdown-it-py==4.2.0": "OSI Approved :: MIT License",
    "mdurl==0.1.2": "OSI Approved :: MIT License",
    "minidump==0.0.24": "OSI Approved :: MIT License",
    "mpmath==1.3.0": "BSD",
    "msgspec==0.21.1": "BSD-3-Clause",
    "mulpyplexer==0.9": "BSD",
    "mypy==2.3.1": "MIT",
    "mypy-extensions==1.1.0": "MIT",
    "networkx==3.6.1": "BSD-3-Clause",
    "nodeenv==1.10.0": "BSD",
    "numpy==2.5.3": "BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0",
    "packaging==26.3": "Apache-2.0 OR BSD-2-Clause",
    "pathspec==1.1.1": "OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
    "pefile==2024.8.26": "MIT",
    "platformdirs==4.11.8": "MIT",
    "pluggy==1.6.0": "MIT",
    "ply==3.11": "BSD",
    "pg8000==1.31.5": "BSD 3-Clause License",
    "pre-commit==4.6.2": "MIT",
    "prompt-toolkit==3.0.53": "OSI Approved :: BSD License",
    "protobuf==7.36.1": "3-Clause BSD License",
    "psutil==7.2.2": "BSD-3-Clause",
    "pycparser==3.0": "BSD-3-Clause",
    "pycryptodome==3.23.0": "BSD, Public Domain",
    "pydantic==2.13.5": "MIT",
    "pydantic-core==2.46.5": "MIT",
    "pydemumble==0.1.3": "OSI Approved :: BSD License",
    "pyelftools==0.33": "Public domain",
    "pyghidra==3.1.0": "Apache-2.0",
    "pygments==2.21.0": "BSD-2-Clause",
    "pymysql==1.2.3": "MIT",
    "pypcode==4.0.0": "BSD-2-Clause AND Apache-2.0 AND Zlib",
    "pytest==9.1.1": "MIT",
    "python-dateutil==2.9.0.post0": "Dual License",
    "python-discovery==1.6.0": "Permission is hereby granted, free of charge, to any person obtaining a",
    "python-flirt==0.10.0": "OSI Approved :: Apache Software License",
    "pyvex==9.3.4": "BSD-2-Clause AND GPL-2.0-or-later",
    "pyxbe==1.0.4": "MIT",
    "pyxdia==0.1.1": "Copyright 2024 Matt Borgerson",
    "pyyaml==6.0.3": "MIT",
    "rapidfuzz==3.14.6": "MIT",
    "rich==15.0.0": "MIT",
    "ruff==0.16.7": "MIT",
    "scramp==1.4.17": "MIT No Attribution",
    "setuptools==84.0.0": "MIT",
    "shellingham==1.5.4": "ISC License",
    "six==1.17.0": "MIT",
    "skills-ref==0.1.1": "Apache-2.0",
    "slipcover==1.1.0": "OSI Approved :: Apache Software License",
    "smmap==5.0.3": "BSD-3-Clause",
    "sortedcontainers==2.4.0": "Apache 2.0",
    "sqlalchemy==2.0.53": "MIT",
    "sqlmodel==0.0.42": "MIT",
    "strictyaml==1.7.3": "MIT",
    "sympy==1.14.0": "BSD",
    "tabulate==0.10.0": "MIT",
    "tibs==0.5.7": "The MIT License",
    "toml==0.10.2": "MIT",
    "tomli-w==1.2.0": "OSI Approved :: MIT License",
    "tomlkit==0.15.1": "MIT",
    "tqdm==4.70.1": "MPL-2.0 AND MIT",
    "tree-sitter==0.26.0": "OSI Approved :: MIT License",
    "tree-sitter-c==0.24.2": "MIT",
    "typer==0.27.2": "MIT",
    "typing-extensions==4.16.0": "PSF-2.0",
    "typing-inspection==0.4.4": "MIT",
    "uefi-firmware==1.16": "BSD-3-Clause",
    "virtualenv==21.7.9": "MIT",
    "wcwidth==0.8.3": "MIT",
    "z3-solver==4.13.0.0": "MIT License",
    "zstandard==0.25.0": "BSD-3-Clause",
}
