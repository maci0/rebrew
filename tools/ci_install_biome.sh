#!/usr/bin/env bash
# Install the Biome CLI for a CI job, retrying transient release-download
# failures.
#
# The pre-commit biome hook exits 0 when the binary is absent, so without
# this helper the dashboard-JS gate never runs in CI: a job goes green
# having never checked the dashboard .mjs files. Same posture as
# tools/ci_install_vnu.sh (retry a flaky mirror, verify a fetched artifact
# against a pin).
#
# The pin is both the version in the URL and the binary's sha256: a
# republished or tampered binary fails the check instead of changing what
# the gate validates. `BIOME_VERSION` is a second assertion on the same
# bytes, so the failure names the version the pin expects rather than a
# digest mismatch with nothing to compare it against. The URL itself is
# version-pinned (not the moving `latest` tag): a digest pin alone still
# lets a republished asset under a new version silently swap the tool the
# gate runs, and a `latest` download is not reproducible — two runs on
# different days can fetch different bytes and neither names which.
#
# Biome ships as a standalone single-file binary (biome-linux-x64); no
# Node.js or npm is needed. The previous `npm install -g
# @biomejs/biome@<version>` resolved the version-only pin fresh on every
# run: npm fetched the JS wrapper plus every platform's binary package
# (~800 MB) with no integrity check and no lockfile, so a republished or
# compromised platform package changed what the gate ran without any pin
# moving. This helper fetches exactly one binary and verifies it.
#
# Usage: bin_dir="$(bash tools/ci_install_biome.sh [dest])"
# Prints the directory holding the `biome` binary for the caller to put
# on PATH. Exits 1 when the download or either pin check fails, naming
# what was expected.
set -euo pipefail

BIOME_VERSION="2.6.6"
BIOME_SHA256="69ca8e9ff548091b2bfbd178d6f73142b483a5257b07854de702c68fb7f8c06b"
BIOME_URL="https://github.com/biomejs/biome/releases/download/%40biomejs/biome%40${BIOME_VERSION}/biome-linux-x64"

MAX_ATTEMPTS=3
RETRY_BASE_DELAY_SECONDS=5

dest="${1:-${REBREW_BIOME_DIR:-${HOME}/.cache/rebrew/biome}}"
bin_dir="${dest}"

# Already installed and matching the pin: nothing to download.
if [[ -x "${bin_dir}/biome" ]]; then
  have="$("${bin_dir}/biome" --version 2>/dev/null | sed 's/.*Version: //' || true)"
  if [[ "${have}" == "${BIOME_VERSION}"* ]]; then
    echo "${bin_dir}"
    exit 0
  fi
  echo "replacing biome ${have:-unknown} at ${dest} (pin: ${BIOME_VERSION})" >&2
  rm -rf -- "${dest}"
fi

# Name a missing prerequisite instead of retrying it: every attempt fails
# identically without curl, and the loop would report a mirror diagnosis
# for a host that cannot fetch at all.  Same preflight shape as
# tools/ci_apt_install.sh's apt-get check and the git check in
# tools/ci_clone_resembl.sh.
if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: curl not on PATH, so biome cannot be installed" >&2
  echo "This helper is for Debian/Ubuntu runners (CI pins ubuntu-24.04)." >&2
  exit 1
fi

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Download into a sibling of dest and rename over it only after both pin
# checks pass, so a failed run leaves the previous install (if any) and
# never a half-written binary that a later job would treat as installed.
staging="${dest}.incoming.$$"
archive="${staging}.bin"
mkdir -p -- "$(dirname -- "${dest}")"
cleanup() {
  rm -f -- "${archive}"
  rm -rf -- "${staging}"
}
trap cleanup EXIT

attempt=0
while [[ ${attempt} -lt ${MAX_ATTEMPTS} ]]; do
  attempt=$((attempt + 1))
  if curl --proto '=https' --tlsv1.2 -sSfL --retry 2 -o "${archive}" "${BIOME_URL}"; then
    got="$(sha256_of "${archive}")"
    if [[ "${got}" != "${BIOME_SHA256}" ]]; then
      echo "biome binary sha256 ${got}, expected ${BIOME_SHA256}" >&2
      echo "Upstream republished the ${BIOME_VERSION} release asset; update BIOME_VERSION" >&2
      echo "and BIOME_SHA256 in tools/ci_install_biome.sh together." >&2
      exit 1
    fi
    mkdir -p -- "${staging}"
    mv -- "${archive}" "${staging}/biome"
    chmod +x "${staging}/biome"
    have="$("${staging}/biome" --version 2>/dev/null | sed 's/.*Version: //' || true)"
    if [[ "${have}" != "${BIOME_VERSION}"* ]]; then
      echo "biome reports '${have:-unknown}', expected ${BIOME_VERSION}" >&2
      echo "The binary digest matched but the tool is not the pinned one;" >&2
      echo "re-check BIOME_VERSION before trusting this gate." >&2
      exit 1
    fi
    rm -rf -- "${dest}"
    mv -- "${staging}" "${dest}"
    echo "${bin_dir}"
    exit 0
  fi
  if [[ ${attempt} -eq ${MAX_ATTEMPTS} ]]; then
    echo "biome download (${BIOME_URL}) failed after ${attempt} attempts" >&2
    exit 1
  fi
  sleep $((attempt * RETRY_BASE_DELAY_SECONDS))
done
