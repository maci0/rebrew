#!/usr/bin/env bash
# Clone the sibling resembl path-dep for CI (and local mirrors of that layout).
#
# [tool.uv.sources] resolves resembl from ../resembl; actions/checkout cannot
# write outside GITHUB_WORKSPACE, so workflows call this instead.  Retries
# match the apt-get install step: GitHub/codeload flakes should not fail the
# job on the first transient error.
#
# Requires RESEMBL_REF and RESEMBL_SHA in the environment (uv-env action
# inputs).  The clone fails unless the tag resolves to RESEMBL_SHA: tags are
# mutable, so a retargeted tag must not silently change the path dependency.
# When GH_TOKEN or GITHUB_TOKEN is set (workflows map secrets.GITHUB_TOKEN
# onto this step only — not workflow-wide),
# clone with an Authorization header so the token never lands in the remote
# URL and GitHub applies authenticated git rate limits.  The header is written
# to a temp gitconfig created under umask 077 (GIT_CONFIG_GLOBAL) so the secret
# does not appear on the git process argv (visible via ps / audit logs) or in
# a file that is briefly world-readable.  The variables are unset before git
# runs, so the child does not inherit them via the environment.
# The tag SHA is checked only after clone.  Hooks, fsmonitor, ext:: remotes,
# and LFS smudge are disabled so that checkout cannot run a program from the
# tree being verified.  A rejected or failed clone never touches dest: the
# attempt lands in a sibling staging directory that is renamed over dest only
# after the SHA check passes, so a local mirror keeps the checkout it had.
set -euo pipefail

ref="${RESEMBL_REF:?RESEMBL_REF is required (e.g. v3.0.0)}"
want_sha="${RESEMBL_SHA:?RESEMBL_SHA is required (the commit RESEMBL_REF must resolve to)}"
dest="${1:-../resembl}"

# Same policy as tools/ci_apt_install.sh, which states the same two values.
# A job that dies on the first transient codeload error retries nothing, and
# the apt helper's docstring points here for the mirror, so the two must not
# drift apart silently.
MAX_ATTEMPTS=3
RETRY_BASE_DELAY_SECONDS=5

# Refuse callers that would rm -rf something other than a resembl checkout
# (e.g. dest=/ or dest=.).  Before the git preflight below: a bad dest is
# refused whatever the host has installed.
if [[ "$(basename "${dest}")" != "resembl" ]]; then
  echo "refusing dest whose basename is not 'resembl': ${dest}" >&2
  exit 1
fi
case "${dest}" in
  / | "" | . | ..)
    echo "refusing dangerous dest: ${dest}" >&2
    exit 1
    ;;
  *)
    ;;
esac

# A host without git fails every attempt identically, so the loop burns its
# backoff and exits with "git clone resembl failed after 3 attempts": a mirror
# diagnosis for what is a missing binary.  Name it before the loop, the way
# tools/ci_apt_install.sh names a missing apt-get.
if ! command -v git >/dev/null 2>&1; then
  echo "ERROR: git not on PATH, so ${RESEMBL_REF} cannot be cloned into ${dest}" >&2
  echo "Run 'make setup' after installing git, or clone the sibling checkout by hand." >&2
  exit 1
fi

# Never block the job on an interactive credential prompt (no TTY in CI).
export GIT_TERMINAL_PROMPT=0
# git-lfs smudge runs during clone, before the SHA check below.
export GIT_LFS_SKIP_SMUDGE=1

# -c outranks repo config and the clone template.  core.hooksPath=/dev/null
# is not a directory, so git runs no hooks.
git_safe=(
  -c core.fsmonitor=
  -c core.hooksPath=/dev/null
  -c protocol.ext.allow=never
  -c core.sshCommand=ssh
  -c gpg.program=gpg
  -c filter.lfs.smudge=
  -c filter.lfs.process=
  -c filter.lfs.required=false
)

# Each attempt clones into this sibling of dest, never into dest itself: a run
# that exhausts its retries must not leave a local mirror without the checkout
# it already had.  Same parent directory, so the accepted clone is a rename.
staging="$(dirname -- "${dest}")/.resembl.clone.$$"

git_config_tmp=""
cleanup() {
  if [[ -n "${git_config_tmp}" && -f "${git_config_tmp}" ]]; then
    rm -f -- "${git_config_tmp}"
  fi
  rm -rf -- "${staging}"
}
trap cleanup EXIT

token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
# Drop the raw token before any child.  /proc/<pid>/environ would otherwise
# show it to every process git starts.
unset GH_TOKEN GITHUB_TOKEN
if [[ -n "${token}" ]]; then
  # basic = base64("x-access-token:<token>"); tr strips the 76-col wrap base64
  # may add on some platforms (no -w0 on macOS/BSD).
  basic="$(printf 'x-access-token:%s' "${token}" | base64 | tr -d '\n')"
  # umask before mktemp.  A chmod afterwards would leave a window where the
  # new file is 0644 and a reader can open it.
  old_umask="$(umask)"
  umask 077
  git_config_tmp="$(mktemp)"
  umask "${old_umask}"
  chmod 600 "${git_config_tmp}"
  # GIT_CONFIG_GLOBAL points git at this file; argv stays free of the token.
  printf '%s\n' \
    '[http "https://github.com/"]' \
    "	extraheader = AUTHORIZATION: basic ${basic}" \
    >"${git_config_tmp}"
  export GIT_CONFIG_GLOBAL="${git_config_tmp}"
  unset basic
fi
unset token

for ((attempt = 1; attempt <= MAX_ATTEMPTS; attempt++)); do
  rm -rf -- "${staging}"
  if git "${git_safe[@]}" clone --depth 1 --branch "${ref}" -- \
      https://github.com/maci0/resembl.git "${staging}"; then
    got_sha="$(git "${git_safe[@]}" -C "${staging}" rev-parse HEAD)"
    if [[ "${got_sha}" != "${want_sha}" ]]; then
      echo "resembl ${ref} resolves to ${got_sha}, expected ${want_sha}" >&2
      exit 1
    fi
    rm -rf -- "${dest}"
    mv -- "${staging}" "${dest}"
    exit 0
  fi
  rm -rf -- "${staging}"
  if [[ "${attempt}" -eq "${MAX_ATTEMPTS}" ]]; then
    echo "git clone resembl (${ref} -> ${dest}) failed after ${attempt} attempts" >&2
    exit 1
  fi
  sleep $((attempt * RETRY_BASE_DELAY_SECONDS))
done
