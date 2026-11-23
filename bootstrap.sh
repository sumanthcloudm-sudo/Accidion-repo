#!/usr/bin/env bash
# Retrieve and verify a GitHub kit archive, then scan the caller's project.
set +x
set -euo pipefail
umask 077

fail() {
  printf 'Accidion bootstrap: %s\n' "$1" >&2
  exit 2
}

usage() {
  printf '%s\n' 'Usage: bootstrap.sh [--public | --release-asset] [--repository OWNER/REPO] --commit FULL_SHA --archive-sha256 SHA256 [-- scanner-options]'
}

project="$(pwd -P)"
(( BASH_VERSINFO[0] > 3 || (BASH_VERSINFO[0] == 3 && BASH_VERSINFO[1] >= 2) )) ||
  fail "Bash 3.2 or newer is required."
repo=
commit=
archive_sha=
release_asset=false
public=false
while (( $# )); do
  case "$1" in
    --repository|--commit|--archive-sha256)
      (( $# >= 2 )) || fail "Missing value for $1."
      case "$1" in
        --repository) repo=$2 ;;
        --commit) commit=$2 ;;
        --archive-sha256) archive_sha=$2 ;;
      esac
      shift 2 ;;
    --) shift; break ;;
    --release-asset) release_asset=true; shift ;;
    --public) public=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "Separate scanner options with --." ;;
  esac
done
if $public && $release_asset; then fail "Public archive mode and private release asset mode are mutually exclusive."; fi
for arg in "$@"; do
  case "$arg" in --project-path|--project-path=*) fail "Run from the application directory to select the scan target." ;; esac
done

for tool in uname curl tar gzip mktemp mkdir rm dirname; do
  command -v "$tool" >/dev/null || fail "$tool is required before installation can start."
done
case "$(uname -s)" in
  MINGW*|MSYS*) system=windows ;;
  Darwin) system=macos ;;
  Linux) system=linux ;;
  *) fail "Unsupported operating system." ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) fail "Unsupported processor architecture." ;;
esac

if [[ -z $repo ]] && $public; then
  repo=sumanthcloudm-sudo/Accidion-repo
elif [[ -z $repo ]] && command -v git >/dev/null; then
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  git_root="$(git -C "$script_dir" rev-parse --show-toplevel 2>/dev/null || true)"
  # Use origin only if this script is at the kit checkout root, never the caller's project origin.
  if [[ -n $git_root && $script_dir -ef $git_root && -f $script_dir/security-scan.sh && -f $script_dir/starter_kit.py ]]; then
    origin="$(git -C "$script_dir" remote get-url private 2>/dev/null ||
      git -C "$script_dir" remote get-url origin 2>/dev/null || true)"
    case "$origin" in
      https://github.com/*) repo=${origin#https://github.com/} ;;
      git@github.com:*) repo=${origin#git@github.com:} ;;
      ssh://git@github.com/*) repo=${origin#ssh://git@github.com/} ;;
    esac
    repo=${repo%/}
    repo=${repo%.git}
  fi
fi
[[ $repo =~ ^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
  fail "Confirm the GitHub repository and pass --repository OWNER/REPO."
[[ $commit =~ ^[a-f0-9]{40}$ && $archive_sha =~ ^[a-f0-9]{64}$ ]] ||
  fail "Supply an approved full lowercase commit SHA and archive SHA-256."

version="$(curl -q --version)" || fail "Cannot validate curl."
[[ $version =~ ^curl[[:space:]]+([0-9]+)\.([0-9]+)\.([0-9]+) ]] || fail "Cannot determine curl version."
major=$((10#${BASH_REMATCH[1]}))
minor=$((10#${BASH_REMATCH[2]}))
patch=$((10#${BASH_REMATCH[3]}))
(( major > 7 || (major == 7 && (minor > 83 || (minor == 83 && patch >= 1))) )) ||
  fail "curl 7.83.1 or newer is required for authenticated redirects."
if command -v sha256sum >/dev/null; then
  hash=(sha256sum)
elif command -v shasum >/dev/null; then
  hash=(shasum -a 256)
else
  fail "sha256sum or shasum is required to verify the archive."
fi

temp_parent=
for candidate in "${TMPDIR:-/tmp}" /tmp "${HOME:-/tmp}"; do
  parent="$(cd -- "$candidate" 2>/dev/null && pwd -P)" || continue
  case "$parent/" in "${project%/}/"*) continue ;; esac
  if [[ -w $parent ]]; then temp_parent=$parent; break; fi
done
[[ -n $temp_parent ]] || fail "No writable temporary directory outside the application."

api="https://api.github.com/repos/$repo"
curl_args=(--silent --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180)
token=
if ! $public; then
  token=${GH_TOKEN:-${GITHUB_TOKEN:-}}
  if [[ -z $token ]] && command -v gh >/dev/null; then
    token="$(gh auth token --hostname github.com 2>/dev/null || true)"
  fi
  [[ $token =~ ^[A-Za-z0-9_-]+$ ]] || fail "Use an approved GitHub CLI login or provide a read-only GH_TOKEN."
fi
unset GH_TOKEN GITHUB_TOKEN
status="$(curl -q "${curl_args[@]}" --output /dev/null --write-out '%{http_code}' "$api")" ||
  fail "GitHub is unreachable. Check corporate network or proxy settings."
if $public; then
  [[ $status == 200 ]] || fail "Expected an anonymously accessible public repository."
else
  [[ $status == 404 ]] || fail "Expected a private repository. Confirm the repository and GitHub access."
fi

work="$(mktemp -d "$temp_parent/accidion-kit.XXXXXXXX")" || fail "Could not create a private temporary directory."
trap 'rm -rf -- "$work"' EXIT
mkdir -- "$work/kit"
printf 'Accidion bootstrap: %s/%s, retrieving reviewed revision %s\n' "$system" "$arch" "$commit"
if $public; then
  curl -q "${curl_args[@]}" --fail --location --max-redirs 3 --retry 2 \
    --output "$work/kit.tar.gz" "$api/tarball/$commit" ||
    fail "Pinned public archive download failed. Check the commit and network policy."
elif $release_asset; then
  command -v gh >/dev/null || fail "An approved GitHub CLI installation is required for release asset retrieval."
  GH_TOKEN="$token" gh release download "kit-$commit" --repo "$repo" --pattern 'accidion-kit.tar.gz' \
    --output - </dev/null > "$work/kit.tar.gz" 2>/dev/null ||
    fail "Pinned release asset download failed. Check read access, SSO and release publication."
elif ! printf 'header = "Authorization: Bearer %s"\n' "$token" |
  curl -q --config - "${curl_args[@]}" --fail --location --max-redirs 3 --retry 2 \
    --output "$work/kit.tar.gz" "$api/tarball/$commit"; then
  fail "Pinned archive download failed. Check read permission, SSO, the commit, and network policy."
fi
unset token
digest="$("${hash[@]}" < "$work/kit.tar.gz")" || fail "Could not compute the archive SHA-256."
[[ ${digest%% *} == "$archive_sha" ]] || fail "Archive SHA-256 mismatch. Obtain the reviewed release digest."
tar -xzf "$work/kit.tar.gz" --strip-components=1 -C "$work/kit" || fail "Could not extract the verified archive."
for path in bootstrap.sh security-scan.sh starter_kit.py starter_install.py starter_findings.py \
            accidion-dependencies.gradle .gitleaks.toml semgrep.yml .checkov.yml; do
  [[ -f $work/kit/$path && ! -L $work/kit/$path ]] || fail "Verified archive is missing a regular $path."
done
ACCIDION_KIT_COMMIT="$commit" ACCIDION_KIT_ARCHIVE_SHA256="$archive_sha" \
  "$BASH" "$work/kit/security-scan.sh" "$@" --project-path "$project"
