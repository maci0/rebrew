# Security Policy

## Supported versions

Rebrew is published as **Beta** (`Development Status :: 4 - Beta` in
[`pyproject.toml`](pyproject.toml)). There is no separate LTS track in this
repository: security fixes land on the default branch (`main`) and in the
next release cut from that branch. Older tags are not guaranteed to receive
backports.

## Reporting a vulnerability

Email the package author listed in [`pyproject.toml`](pyproject.toml):

**Marcel W. Wysocki** — `maci.stgn@gmail.com`

Please include enough detail to reproduce the issue (affected command or
module path, rebrew version or commit, and whether a local project or
dependency is required). Do not open a public GitHub issue for unfixed
vulnerabilities.

This repository does not define an SLA, bug bounty, or encrypted-reporting
channel. Acknowledgement and fix timing depend on maintainer availability.

## Security model (summary)

Rebrew is a **local** compiler-in-the-loop reversing workbench (CLI). It is
not a multi-tenant network service. The living attack-surface and trust-boundary
document is:

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)

Operators should treat project source, configured HTTP endpoints
(recompile, LLM, ReVa MCP, decomp.me), GitHub release and toolchain-media
downloads (wibo, SDK tarballs), docker/podman images (`REBREW_CONTAINER_RUNTIME`),
cmake bridge wineprefix / profile pins (`REBREW_WINEPREFIX`, `REBREW_TOOLCHAIN`),
and installed Python entry-point plugins as part of the trust boundary.

## Claims this policy does **not** make

- No claim of authentication or authorization on `rebrew dashboard` (default
  bind is loopback; binding to non-loopback addresses exposes a read-only
  HTTP API without credentials).
- No claim that docker toolchain or cmake-bridge execution is a hardened
  sandbox against a hostile project tree or malicious image. Local container
  runs use `--network=none` (no egress); that does not imply escape resistance.
- No claim that optional wibo / toolchain-media downloads are attested beyond
  the in-code host allow-list and hash checks described in
  [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Wibo integrity uses the live
  GitHub release `digest`; it does not consume `GH_TOKEN`/`GITHUB_TOKEN`
  (those tokens are used only by toolchain pin-check/update HTTP to GitHub).
- No claim that dependency CVEs are absent; pin rationale lives in
  `pyproject.toml` comments and the changelog.
- No claim that library helpers which invoke host DOSBox
  (`rebrew.msvc16` / `tc16` / `delphi16`) are covered by the docker-only
  compile guarantee on the shipped CLI compile path.
