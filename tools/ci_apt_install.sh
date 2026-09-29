#!/usr/bin/env bash
# Install host packages in a CI job, retrying transient apt mirror failures.
#
# One helper for every apt step (nasm for the asm round-trip tests, shellcheck
# and yamllint for the pre-commit gate, jq for the nightly drift result gate):
# apt mirrors
# flake under load, and a job that dies on the first 503 retries nothing.
# Retries match tools/ci_clone_resembl.sh.
#
# Usage: bash tools/ci_apt_install.sh <package>...
# Packages already on PATH are left alone (a runner image that ships one needs
# no apt round trip). Exits 1 when an update or install still fails after
# MAX_ATTEMPTS tries, naming the package.
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

missing=()
for pkg in "$@"; do
  if ! command -v "${pkg}" >/dev/null 2>&1; then
    missing+=("${pkg}")
  fi
done
if [[ ${#missing[@]} -eq 0 ]]; then
  echo "already on PATH: $*"
  exit 0
fi

retry "apt-get update" run_root apt-get update -qq
retry "apt-get install ${missing[*]}" run_root env DEBIAN_FRONTEND=noninteractive \
  apt-get install -y --no-install-recommends "${missing[@]}"

for pkg in "${missing[@]}"; do
  if ! command -v "${pkg}" >/dev/null 2>&1; then
    echo "apt-get reported success but ${pkg} is still not on PATH" >&2
    exit 1
  fi
done
echo "installed: ${missing[*]}"
