bash -c '
set +x
set -euo pipefail
umask 077
repo=$1 rev=$2 bootstrap_sha=$3 archive_sha=$4
shift 4
[[ $repo =~ ^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9._-]*$ &&
   $rev =~ ^[a-f0-9]{40}$ && $bootstrap_sha =~ ^[a-f0-9]{64}$ && $archive_sha =~ ^[a-f0-9]{64}$ ]] ||
  { echo "Supply the private repository slug, reviewed commit and both SHA-256 digests." >&2; exit 2; }
[[ "$(gh repo view "$repo" --json isPrivate --jq .isPrivate)" == true ]] ||
  { echo "Private repository access is required. Check GitHub login and SSO." >&2; exit 2; }
app="$(pwd -P)"
parent=
for candidate in "${TMPDIR:-/tmp}" /tmp "${HOME:-/tmp}"; do
  path="$(cd -- "$candidate" 2>/dev/null && pwd -P)" || continue
  case "$path/" in "${app%/}/"*) continue ;; esac
  if [[ -w $path ]]; then parent=$path; break; fi
done
[[ -n $parent ]] || { echo "No writable temporary directory outside the application." >&2; exit 2; }
work="$(mktemp -d "$parent/accidion-entry.XXXXXXXX")"
trap "rm -rf -- \"\$work\"" EXIT
gh api --hostname github.com -H "Accept: application/vnd.github.raw+json" \
  "repos/$repo/contents/bootstrap.sh?ref=$rev" > "$work/bootstrap.sh"
if command -v sha256sum >/dev/null; then digest="$(sha256sum < "$work/bootstrap.sh")"
else digest="$(shasum -a 256 < "$work/bootstrap.sh")"; fi
[[ ${digest%% *} == "$bootstrap_sha" ]] || { echo "Bootstrap SHA-256 mismatch." >&2; exit 2; }
bash "$work/bootstrap.sh" --repository "$repo" --commit "$rev" --archive-sha256 "$archive_sha" --release-asset -- "$@"
' accidion OWNER/PRIVATE_REPO FULL_COMMIT_SHA BOOTSTRAP_SHA256 KIT_ARCHIVE_SHA256
