#!/usr/bin/env bash
# Install host packages in a CI job, retrying transient apt mirror failures.
#
# One helper for every apt step (nasm for assembly tests, patch for vendoring,
# build-essential, pkg-config and libjson-c-dev for native runner tests,
# ant and default-jdk for JPype source builds,
# plus shellcheck and yamllint for pre-commit, jq for the nightly drift result gate):
# apt mirrors
# flake under load, and a job that dies on the first 503 retries nothing.
# Retries match tools/ci_clone_resembl.sh.
#
# Usage: bash tools/ci_apt_install.sh <package>...
# Available tools and native development capabilities are left alone (a runner
# image that ships them needs no apt round trip). Exits 1 when update/install
# fails after MAX_ATTEMPTS tries, or a required capability stays unavailable.
set -euo pipefail

MAX_ATTEMPTS=3
RETRY_BASE_DELAY_SECONDS=5

if [[ $# -eq 0 ]]; then
  echo "usage: $(basename "$0") <package>..." >&2
  exit 2
fi

# Name the missing prerequisite instead of retrying it.  A runner without
# apt-get fails every `retry` call identically, so the loop burns its backoff
# and exits with "apt-get update failed after 3 attempts", which reads as a
# dead mirror rather than a host that cannot install at all.  Same preflight
# shape as the Makefile's ensure-uv / ensure-nasm.
if ! command -v apt-get >/dev/null 2>&1; then
  echo "ERROR: apt-get not on PATH, so $* cannot be installed" >&2
  echo "This helper is for Debian/Ubuntu runners (CI pins ubuntu-24.04)." >&2
  exit 1
fi

# Likewise for the privilege escalation the non-root path needs: `sudo -n`
# fails rather than prompting, but the message would be sudo's, not ours.
if [[ "${EUID}" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
  echo "ERROR: not root and no sudo on PATH, so apt-get cannot be run as root" >&2
  echo "Run this as root, or on a runner whose user has passwordless sudo." >&2
  exit 1
fi

# GitHub runners call this as a non-root user; a local container may not.
# `sudo -n`: there is no TTY in CI, so a runner whose sudo wants a password
# blocks on the prompt until the job timeout instead of reporting why.  -n
# turns that into an immediate failure the retry loop cannot paper over.
run_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    sudo -n "$@"
  fi
}

# Retry a command, sleeping longer after each failure. Echoes a final error
# naming the operation so a flaky mirror is not reported as a build break.
retry() {
  local what="$1"
  shift
  local attempt
  for attempt in $(seq 1 "${MAX_ATTEMPTS}"); do
    if "$@"; then
      return 0
    fi
    if [[ "${attempt}" -eq "${MAX_ATTEMPTS}" ]]; then
      echo "${what} failed after ${attempt} attempts" >&2
      return 1
    fi
    sleep $((attempt * RETRY_BASE_DELAY_SECONDS))
  done
}

# Development packages provide build capabilities rather than a namesake executable.
package_available() {
  case "$1" in
    build-essential) command -v cc >/dev/null 2>&1 && command -v make >/dev/null 2>&1 ;;
    default-jdk) command -v javac >/dev/null 2>&1 && command -v java >/dev/null 2>&1 ;;
    libjson-c-dev) command -v pkg-config >/dev/null 2>&1 && pkg-config --exists json-c ;;
    *) command -v "$1" >/dev/null 2>&1 ;;
  esac
}

missing=()
for pkg in "$@"; do
  # This predicate intentionally returns false for an unavailable capability.
  # shellcheck disable=SC2310
  if ! package_available "${pkg}"; then
    missing+=("${pkg}")
  fi
done
if [[ ${#missing[@]} -eq 0 ]]; then
  echo "already available: $*"
  exit 0
fi

# Log the Ubuntu archive snapshot the mirror serves so a second run on a
# different day that resolves different package versions can be told apart.
# apt is the one build input that floats: every other CI pin (Go, bun, uv,
# Python) is a fixed version, while `apt-get install <name>` tracks the
# mirror's current build.  The snapshot URI is not pinned (mirrors vary),
# but recording it in the log makes the drift visible in the job output.
snapshot="$(awk '/^deb / && /ubuntu\.com/ {print $2; exit}' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true)"
if [[ -n "${snapshot}" ]]; then
  echo "apt snapshot: ${snapshot} (floating; package versions may drift between runs)"
fi
retry "apt-get update" run_root apt-get update -qq
retry "apt-get install ${missing[*]}" run_root env DEBIAN_FRONTEND=noninteractive \
  apt-get install -y --no-install-recommends "${missing[@]}"

# Record what was actually installed, so a rebuild that resolves different
# package versions can be told apart from the run that shipped.  dpkg-query
# reads the installed set; a package apt installed but dpkg does not report
# fails the helper rather than shipping an unrecorded tool.
# shellcheck disable=SC2016,SC2310
if command -v dpkg-query >/dev/null 2>&1; then
  run_root dpkg-query -W -f='${Package}=${Version}\n' "${missing[@]}" || {
    echo "installed but dpkg-query cannot report versions for: ${missing[*]}" >&2
    exit 1
  }
fi

for pkg in "${missing[@]}"; do
  # This predicate intentionally returns false for an unavailable capability.
  # shellcheck disable=SC2310
  if ! package_available "${pkg}"; then
    echo "apt-get reported success but ${pkg} is still unavailable" >&2
    exit 1
  fi
done
echo "installed: ${missing[*]}"
