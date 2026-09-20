#!/usr/bin/env bash
# Clone the sibling resembl path-dep for CI (and local mirrors of that layout).
#
# [tool.uv.sources] resolves resembl from ../resembl; actions/checkout cannot
# write outside GITHUB_WORKSPACE, so workflows call this instead.  Retries
# match the apt-get install step: GitHub/codeload flakes should not fail the
# job on the first transient error.
#
# Requires RESEMBL_REF in the environment (workflow env / Makefile pin).
# When GH_TOKEN or GITHUB_TOKEN is set (workflows map secrets.GITHUB_TOKEN),
# clone with an Authorization header so the token never lands in the remote
# URL and GitHub applies authenticated git rate limits.
set -euo pipefail

ref="${RESEMBL_REF:?RESEMBL_REF is required (e.g. v2.0.0)}"
dest="${1:-../resembl}"

# Refuse callers that would rm -rf something other than a resembl checkout
# (e.g. dest=/ or dest=.).
if [[ "$(basename "${dest}")" != "resembl" ]]; then
  echo "refusing dest whose basename is not 'resembl': ${dest}" >&2
  exit 1
fi
case "${dest}" in
  / | "" | . | ..)
    echo "refusing dangerous dest: ${dest}" >&2
    exit 1
    ;;
esac

# Never block the job on an interactive credential prompt (no TTY in CI).
export GIT_TERMINAL_PROMPT=0

auth_args=()
token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [[ -n "${token}" ]]; then
  # basic = base64("x-access-token:<token>"); tr strips the 76-col wrap base64
  # may add on some platforms (no -w0 on macOS/BSD).
  basic="$(printf 'x-access-token:%s' "${token}" | base64 | tr -d '\n')"
  auth_args=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic ${basic}")
fi

for attempt in 1 2 3; do
  rm -rf "${dest}"
  if git "${auth_args[@]}" clone --depth 1 --branch "${ref}" \
      https://github.com/maci0/resembl.git "${dest}"; then
    exit 0
  fi
  if [[ "${attempt}" -eq 3 ]]; then
    echo "git clone resembl (${ref} -> ${dest}) failed after ${attempt} attempts" >&2
    exit 1
  fi
  sleep $((attempt * 5))
done
