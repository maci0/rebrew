#!/usr/bin/env bash
# Clone the sibling resembl path-dep for CI (and local mirrors of that layout).
#
# [tool.uv.sources] resolves resembl from ../resembl; actions/checkout cannot
# write outside GITHUB_WORKSPACE, so workflows call this instead.  Retries
# match the apt-get install step: GitHub/codeload flakes should not fail the
# job on the first transient error.
#
# Requires RESEMBL_REF in the environment (workflow env / Makefile pin).
set -euo pipefail

ref="${RESEMBL_REF:?RESEMBL_REF is required (e.g. v2.0.0)}"
dest="${1:-../resembl}"

for attempt in 1 2 3; do
  rm -rf "${dest}"
  if git clone --depth 1 --branch "${ref}" \
      https://github.com/maci0/resembl.git "${dest}"; then
    exit 0
  fi
  if [[ "${attempt}" -eq 3 ]]; then
    echo "git clone resembl (${ref} -> ${dest}) failed after ${attempt} attempts" >&2
    exit 1
  fi
  sleep $((attempt * 5))
done
