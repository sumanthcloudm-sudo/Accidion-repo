bash -c '
set +x
set -euo pipefail
umask 077
rev=$1 bootstrap_sha=$2 archive_sha=$3
shift 3
[[ $rev =~ ^[a-f0-9]{40}$ && $bootstrap_sha =~ ^[a-f0-9]{64}$ && $archive_sha =~ ^[a-f0-9]{64}$ ]] ||
  { echo "Supply the reviewed commit and both SHA-256 digests." >&2; exit 2; }
app="$(pwd -P)"
parent=
for candidate in "${TMPDIR:-/tmp}" /tmp "${HOME:-/tmp}"; do
  path="$(cd -- "$candidate" 2>/dev/null && pwd -P)" || continue
  case "$path/" in "${app%/}/"*) continue ;; esac
  if [[ -w $path ]]; then parent=$path; break; fi
done
[[ -n $parent ]] || { echo "No writable temporary directory outside the application." >&2; exit 2; }
work="$(mktemp -d "$parent/accidion-public.XXXXXXXX")"
cleanup_download() {
  local status=$? attempt
  trap - EXIT
  for attempt in 1 2 3 4 5; do
    if rm -rf -- "$work" 2>/dev/null; then
      exit "$status"
    fi
    if [[ $attempt != 5 ]]; then sleep 1 || break; fi
  done
  printf "Warning: could not remove temporary Accidion files at %s (launcher exit %s).\n" "$work" "$status" >&2
  exit "$status"
}
trap cleanup_download EXIT
repo=sumanthcloudm-sudo/Accidion-repo
credential_token() {
  local saved line
  command -v git >/dev/null || return 1
  saved="$(
    unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR
    printf "protocol=https\nhost=github.com\npath=%s.git\n\n" "$repo" |
      GIT_TERMINAL_PROMPT=0 GCM_INTERACTIVE=Never GIT_ASKPASS=false \
      GIT_CEILING_DIRECTORIES="${work%/*}" git -C "$work" credential fill 2>/dev/null
  )" || return 1
  while IFS= read -r line; do
    case "$line" in password=*) printf "%s\n" "${line#password=}"; return ;; esac
  done <<< "$saved"
  return 1
}
token=${GH_TOKEN:-${GITHUB_TOKEN:-}}
if [[ -z $token ]] && command -v gh >/dev/null; then
  token="$(gh auth token --hostname github.com 2>/dev/null || true)"
fi
if [[ -z $token ]]; then token="$(credential_token || true)"; fi
[[ $token =~ ^[A-Za-z0-9_-]+$ ]] ||
  { echo "Provide an approved GH_TOKEN, GitHub CLI login, or cached Git credential-manager entry." >&2; exit 2; }
unset GH_TOKEN GITHUB_TOKEN
if ! printf "header = \"Authorization: Bearer %s\"\n" "$token" |
  curl -q --config - --fail --silent --proto "=https" --connect-timeout 15 --max-time 60 \
    -H "Accept: application/vnd.github.raw+json" \
    "https://api.github.com/repos/$repo/contents/bootstrap.sh?ref=$rev" \
    --output "$work/bootstrap.sh"; then
  echo "Authenticated launcher download failed. Check the credential, access, SSO and revision." >&2
  exit 2
fi
if command -v sha256sum >/dev/null; then digest="$(sha256sum < "$work/bootstrap.sh")"
else digest="$(shasum -a 256 < "$work/bootstrap.sh")"; fi
[[ ${digest%% *} == "$bootstrap_sha" ]] || { echo "Bootstrap SHA-256 mismatch." >&2; exit 2; }
GH_TOKEN="$token" "$BASH" "$work/bootstrap.sh" --public --commit "$rev" --archive-sha256 "$archive_sha" -- "$@"
' accidion-public FULL_COMMIT_SHA BOOTSTRAP_SHA256 KIT_ARCHIVE_SHA256
