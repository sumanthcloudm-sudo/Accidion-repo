bash -s -- OWNER/PRIVATE_REPO FULL_COMMIT_SHA BOOTSTRAP_SHA256 KIT_ARCHIVE_SHA256 <<'ACCIDION'
set +x
set -euo pipefail
umask 077
repo=$1 commit=$2 bootstrap_sha=$3 archive_sha=$4
shift 4
fail() { printf 'Accidion bootstrap: %s\n' "$1" >&2; exit 2; }
[[ $repo =~ ^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*$ &&
   $commit =~ ^[a-f0-9]{40}$ && $bootstrap_sha =~ ^[a-f0-9]{64}$ &&
   $archive_sha =~ ^[a-f0-9]{64}$ ]] || fail "Supply the repository, full commit and both reviewed digests."
for tool in curl mktemp rm; do
  command -v "$tool" >/dev/null || fail "An approved $tool installation is required."
done
if command -v sha256sum >/dev/null; then hash=(sha256sum)
elif command -v shasum >/dev/null; then hash=(shasum -a 256)
else fail "sha256sum or shasum is required."; fi
app="$(pwd -P)"
token=${GH_TOKEN:-${GITHUB_TOKEN:-}}
if [[ -z $token ]] && command -v gh >/dev/null; then
  token="$(gh auth token --hostname github.com 2>/dev/null || true)"
fi
[[ $token =~ ^[A-Za-z0-9_-]+$ ]] || fail "Authenticate with GitHub CLI or supply an approved read-only GH_TOKEN."
unset GH_TOKEN GITHUB_TOKEN
api="https://api.github.com/repos/$repo"
curl_args=(--silent --proto '=https' --connect-timeout 15 --max-time 60)
status="$(curl -q "${curl_args[@]}" -o /dev/null -w '%{http_code}' "$api")" ||
  fail "Could not reach GitHub."
[[ $status == 404 ]] || fail "Expected a private repository. Check its visibility and permissions."
parent=
for candidate in "${TMPDIR:-/tmp}" /tmp "${HOME:-/tmp}"; do
  resolved="$(cd -- "$candidate" 2>/dev/null && pwd -P)" || continue
  case "$resolved/" in "${app%/}/"*) continue ;; esac
  if [[ -w $resolved ]]; then parent=$resolved; break; fi
done
[[ -n $parent ]] || fail "No writable temporary directory outside the application."
work="$(mktemp -d "$parent/accidion-entry.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
if ! printf 'header = "Authorization: Bearer %s"\n' "$token" |
  curl -q --config - "${curl_args[@]}" --fail -H 'Accept: application/vnd.github.raw+json' \
    -o "$work/bootstrap.sh" "$api/contents/bootstrap.sh?ref=$commit"; then
  fail "Pinned bootstrap download failed. Check GitHub read access, SSO and the commit."
fi
digest="$("${hash[@]}" < "$work/bootstrap.sh")"
[[ ${digest%% *} == "$bootstrap_sha" ]] || fail "Bootstrap SHA-256 mismatch."
GH_TOKEN="$token" bash "$work/bootstrap.sh" --repository "$repo" --commit "$commit" \
  --archive-sha256 "$archive_sha" -- "$@"
ACCIDION
