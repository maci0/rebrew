#!/usr/bin/env bash
# Install the W3C Nu HTML validator for a CI job, retrying transient
# release-download failures.
#
# tests/html_validate.py drives `vnu` over the dashboard shell and the
# generated report pages and skips when it is absent, so without this
# helper the two tests that assert the markup parses never run in CI:
# a job goes green having never opened the HTML. Same posture as
# tools/ci_apt_install.sh (retry a flaky mirror) and
# tools/ci_clone_resembl.sh (verify a fetched artifact against a pin).
#
# The validator ships as a release asset under a single moving `latest`
# tag, so the pin is the archive's sha256 rather than a version in the
# URL: a republished or tampered archive fails the check instead of
# changing what the gate validates. `VNU_VERSION` is a second assertion
# on the same bytes, so the failure names the version the pin expects
# rather than a digest mismatch with nothing to compare it against.
#
# The archive bundles its own JRE, so the job needs no `java` install
# (same reasoning as the nasm/node assertions in ci.yml).
#
# Usage: bin_dir="$(bash tools/ci_install_vnu.sh [dest])"
# Prints the directory holding the `vnu` launcher for the caller to put
# on PATH. Exits 1 when the download or either pin check fails, naming
# what was expected.
set -euo pipefail

VNU_VERSION="26.9.27"
VNU_SHA256="e9dcc2d00c432b6f8cab72431656c49c1e9e7d57c31ced097e329b916de799f5"
VNU_URL="https://github.com/validator/validator/releases/download/latest/vnu.linux.zip"

MAX_ATTEMPTS=3
RETRY_BASE_DELAY_SECONDS=5

dest="${1:-${REBREW_VNU_DIR:-${HOME}/.cache/rebrew/vnu}}"
bin_dir="${dest}/vnu-runtime-image/bin"

# Already installed and matching the pin: nothing to download.
if [[ -x "${bin_dir}/vnu" ]]; then
  have="$("${bin_dir}/vnu" --version 2>/dev/null || true)"
  if [[ "${have}" == "${VNU_VERSION}"* ]]; then
    echo "${bin_dir}"
    exit 0
  fi
  echo "replacing vnu ${have:-unknown} at ${dest} (pin: ${VNU_VERSION})" >&2
  rm -rf -- "${dest}"
fi

# Name a missing prerequisite instead of retrying it: every attempt fails
# identically without curl or unzip, and the loop would report a mirror
# diagnosis for a host that cannot fetch at all.  Same preflight shape as
# tools/ci_apt_install.sh's apt-get check and the git check in
# tools/ci_clone_resembl.sh.
for tool in curl unzip; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "ERROR: ${tool} not on PATH, so vnu cannot be installed" >&2
    echo "This helper is for Debian/Ubuntu runners (CI pins ubuntu-24.04)." >&2
    exit 1
  fi
done

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Download into a sibling of dest and rename over it only after both pin
# checks pass, so a failed run leaves the previous install (if any) and
# never a half-extracted tree that a later job would treat as installed.
staging="${dest}.incoming.$$"
archive="${staging}.zip"
cleanup() {
  rm -f -- "${archive}"
  rm -rf -- "${staging}"
}
trap cleanup EXIT

attempt=0
while [[ ${attempt} -lt ${MAX_ATTEMPTS} ]]; do
  attempt=$((attempt + 1))
  if curl -sSfL --retry 2 -o "${archive}" "${VNU_URL}"; then
    got="$(sha256_of "${archive}")"
    if [[ "${got}" != "${VNU_SHA256}" ]]; then
      echo "vnu archive sha256 ${got}, expected ${VNU_SHA256}" >&2
      echo "Upstream republished the 'latest' release asset; update VNU_VERSION" >&2
      echo "and VNU_SHA256 in tools/ci_install_vnu.sh together." >&2
      exit 1
    fi
    mkdir -p -- "${staging}"
    unzip -q -o "${archive}" -d "${staging}"
    rm -f -- "${archive}"
    rm -rf -- "${dest}"
    mv -- "${staging}" "${dest}"
    have="$("${bin_dir}/vnu" --version 2>/dev/null || true)"
    if [[ "${have}" != "${VNU_VERSION}"* ]]; then
      echo "vnu reports '${have:-unknown}', expected ${VNU_VERSION}" >&2
      echo "The archive digest matched but the validator is not the pinned one;" >&2
      echo "re-check VNU_VERSION before trusting this gate." >&2
      exit 1
    fi
    echo "${bin_dir}"
    exit 0
  fi
  if [[ ${attempt} -eq ${MAX_ATTEMPTS} ]]; then
    echo "vnu download (${VNU_URL}) failed after ${attempt} attempts" >&2
    exit 1
  fi
  sleep $((attempt * RETRY_BASE_DELAY_SECONDS))
done
