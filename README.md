# Accidion DevSecOps Starter Kit

Run the kit from an existing Java project. The bootstrap downloads the approved kit revision and passes the application directory to the scanner workflow through its current working directory.

## Run from the public GitHub repository

From your Java application's directory, open Git Bash on Windows or Bash on macOS or Linux. The workflow needs Bash 3.2 or later, curl 7.83.1 or later, tar with gzip, sha256sum or shasum, HTTPS access to GitHub, and a writable temporary directory outside your project. Authenticate with an approved GitHub user token before running the command. Supply GH_TOKEN through your credential vault, sign in using gh auth login --hostname github.com, or use a previously configured secure Git credential manager with a cached github.com login. Git is required at this stage only for the credential-helper option. Paste the complete Bash command with the three values from the reviewed release handoff. Append --dry-run to preview discovery without installations or scans.

Use a read-only GitHub user token accepted by GitHub's authenticated-user endpoint, with the minimum repository access required by your organization. Complete any required SSO authorization. Keep tokens out of shell history, scripts, Git remote URLs, reports, and chat. The launcher reads cached credentials without prompting, sends the authorization header through standard input, and removes GitHub token variables before running scanners. Configure an OS-backed credential manager, such as Git Credential Manager, through your approved onboarding process. [GitHub user-token requirements](https://docs.github.com/en/rest/users/users#get-the-authenticated-user) · [Git credential helpers](https://git-scm.com/docs/gitcredentials)

~~~bash
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
trap "rm -rf -- \"\$work\"" EXIT
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
~~~

The release handoff contains the full reviewed commit SHA, the SHA-256 of the launcher downloaded through the authenticated Contents API, and the SHA-256 of the exact authenticated tarball response, following its HTTPS redirect. Distribute these through a trusted channel after review. A digest mismatch stops execution or extraction. The launcher requires authentication for this workflow. Repository-level access restrictions require a private GitHub repository.

The kit creates fresh JSON reports under $HOME/.accidion/reports/<application-name>/scan-<UTC-date-time>-<id>/. The scan uses your application's files and dependencies. Successful applicable stages produce their individual outputs, with the Syft inventory kept separate. The summary captures scan counts, issue names, severity, paths and line ranges where available, descriptions, impact, remediation, and failure or skip reasons. Use --report-dir for a different parent outside the application.

## One command from your Java project (private distribution)

Ask your administrator for read access to your organization's private Accidion distribution repository and complete any required SSO authorization. Install GitHub CLI through your approved channel and sign in once with gh auth login --hostname github.com, or have your credential manager inject an approved read-only GH_TOKEN. Open Windows Git Bash or Bash on macOS or Linux in your Java application directory. Paste the complete command below with the four values supplied in the approved release handoff. Append --dry-run to verify retrieval and project discovery without installing or scanning.

~~~bash
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
~~~

### Release packaging

After review, build the release asset from the exact approved commit using git archive --format=tar.gz --prefix=accidion-kit/ --output=accidion-kit.tar.gz FULL_COMMIT_SHA. Publish that exact asset as accidion-kit.tar.gz on the private release tagged kit-FULL_COMMIT_SHA. Publish the full commit SHA, the SHA-256 of bootstrap.sh as stored in that commit, and the SHA-256 of the exact uploaded asset through the approved internal channel. Keep the asset unchanged for that release. The bootstrap verifies both digests before allowing execution. [GitHub CLI release downloads](https://cli.github.com/manual/gh_release_download)

### Alternate pinned archive download without GitHub CLI

With an approved token injected by your credential manager, use the command below when GitHub CLI is unavailable. Supply the SHA-256 of GitHub's generated tarball response for the pinned commit. This digest is different from the uploaded release asset's digest.

~~~bash
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
~~~

### Bootstrap architecture and authentication

- **Initial requirements** are Bash 3.2 or later, curl 7.83.1 or later, tar with gzip support, standard utilities, and sha256sum or shasum. Use Git Bash on Windows. Bash, the downloader, and the hash verifier must be provisioned through an approved channel before the command. The kit can provision Git and other applicable software after retrieval. A writable temporary directory outside the application and HTTPS access to GitHub's API and archive service are required. [curl redirect behavior](https://curl.se/docs/manpage.html)
- **Private access** uses an approved GitHub CLI login on github.com, or a read-only GH_TOKEN (GITHUB_TOKEN is also accepted). Authorize access through your organization's SSO if required. Supply tokens through the approved credential store or secret injection. The command passes the credential to curl via standard input, disables the local curl configuration, and removes the GitHub token from the scanner environment. GitHub SSH credentials alone are insufficient for this HTTPS archive workflow.
- **Verification** happens twice. The command retrieves bootstrap.sh through the Contents API at the full commit and verifies its SHA-256 before executing it. The bootstrap records the application directory, detects the host and architecture, checks prerequisites, retrieves the complete archive for that commit, and verifies the archive SHA-256 before extraction. It checks for the required kit files and invokes security-scan.sh with the original application path. The summary records the commit and archive digest. [GitHub Contents API](https://docs.github.com/en/rest/repos/contents)
- **Release updates** require a new reviewed pin and matching digests. Compute the bootstrap digest from the exact Contents API response and the archive digest from the exact authenticated tarball response for that commit. Distribute both through the approved internal channel. GitHub can change archive compression while preserving file content. If a digest changes, administrators must reverify and redistribute the approved digest before rerunning. [GitHub archive stability](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives)
- **Local maintenance** can invoke bash /path/to/bootstrap.sh --commit FULL_COMMIT_SHA --archive-sha256 KIT_ARCHIVE_SHA256 --release-asset -- --dry-run from an application directory. The script uses the kit checkout's private remote, falling back to its origin when no private remote is configured. Pass --repository OWNER/REPO to select a destination explicitly.

## Obtain a local copy for development

Ask your DevSecOps administrator for the private repository URL and read access. Authenticate using your organization's approved GitHub method. Use Git Bash on Windows and a Bash terminal on macOS or Linux.

~~~bash
git clone https://github.com/OWNER/PRIVATE_REPO.git "$HOME/devsecops/Accidion-repo"
git -C "$HOME/devsecops/Accidion-repo" pull --ff-only
~~~

If Git is unavailable, download and extract the complete kit ZIP from the authenticated private repository. Use the approved branch or release for your team. Keep the launcher, Python modules, Gradle init script, and scanner configurations together. A new ZIP can be extracted into a separate directory when updating.

## Prerequisites and installation

- **Launcher** requires Bash and standard shell utilities. Git for Windows supplies Bash and Git. Start from Git Bash on Windows. The launcher accepts x86-64 and ARM64, subject to upstream package availability. Python 3.10 or later is required. Python 3.12 is the recommended starting point for the scanner wheels.
- **Windows 10/11** uses Git Bash and native Windows Python. When available, WinGet can provision supported missing prerequisites. The kit locates Windows system utilities from the operating system and does not require a manual PATH edit.
- **macOS Intel and Apple Silicon** use the same Bash command and an existing approved Homebrew installation for missing system prerequisites. The kit selects packages for the architecture of the running interpreter. Use a native shell and interpreter when your organization requires native ARM64 executables.
- **Linux Ubuntu and Debian** use APT. **Fedora** uses DNF. **RHEL-compatible distributions** use DNF or YUM and can bootstrap Python 3.12 when it is available from approved repositories. Package operations require existing privileges. Docker on an RPM-based distribution requires the engine package to be available in an already configured repository. [RHEL Python package suites](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/installing_and_using_dynamic_programming_languages/assembly_installing-and-using-python_installing-and-using-dynamic-programming-languages)
- **Permissions and package availability** vary by system and architecture. The kit reuses compatible installations, checks the upstream asset name and digest for the detected platform, and records unavailable native packages or wheel installation failures in the same JSON summary on all platforms. The kit does not invoke privilege elevation, change Docker group membership, modify package repositories, or accept WinGet agreements. If policy blocks installation, have IT provision an approved compatible executable and then use --no-install.
- **Java and builds** need a JDK with javac, version 11 or newer for Dependency-Check, and a JDK compatible with the target application's build and wrapper. Set JAVA_HOME to your approved compatible JDK if needed. Use the project's Maven or Gradle wrapper for an install-enabled scan. Otherwise the kit looks for a compatible CLI and can download a pinned Maven or Gradle distribution.
- **Docker** is only needed with the image options. A supported package manager can install a missing Docker CLI, but Docker Desktop or Engine must be running and the account must already have approved daemon access. Configuring services or restarting the machine is an administrative step.
- **Network access** may be needed for approved OS repositories, GitHub release metadata and assets, Python package indexes, Apache Maven and Gradle distributions, application artifact repositories, and vulnerability feeds. Follow corporate proxy, certificate, registry and repository settings. Keep SSH keys, tokens and local build credentials in approved credential stores.

The installer checks executable versions and reuses those that meet the minimums in starter_install.py. It verifies pinned archive downloads against upstream digest metadata or published checksums and installs them in a user-local cache. It installs pinned Semgrep and Checkov packages into separate virtual environments with pip. Pip respects the configured index and certificate settings. Python transitive packages are resolved by pip from compatible wheels and are not hash-locked by the kit. On ARM64, a missing native scanner asset or wheel can require an approved preinstalled executable.

Upstream sources for scanner packages and release information. [Gitleaks](https://github.com/gitleaks/gitleaks/releases) · [Semgrep](https://pypi.org/project/semgrep/) · [Dependency-Check](https://github.com/dependency-check/DependencyCheck/releases) · [Syft](https://github.com/anchore/syft/releases) · [Grype](https://github.com/anchore/grype/releases) · [Checkov](https://pypi.org/project/checkov/)

Use --no-install when software must be provided by IT. This disables provisioning by the kit and uses an existing build CLI in place of project wrappers, whose version probes could provision a distribution. Scanners and build tools can still access configured repositories, pull dependencies or refresh their vulnerability data. This option does not make the scan offline.

## Run against an application

~~~bash
KIT="$HOME/devsecops/Accidion-repo"
APP="$HOME/projects/e-commerce"

bash "$KIT/security-scan.sh" --project-path "$APP" --dry-run
bash "$KIT/security-scan.sh" --project-path "$APP" --setup-only
bash "$KIT/security-scan.sh" --project-path "$APP" --no-install
bash "$KIT/security-scan.sh" --project-path "$APP"
~~~

- **Dry run** prints the platform, discovery counts, candidate build roots and scan plan. It creates no reports and starts no installers or scanner processes. Without Python it prints a bootstrap status instead of project discovery.
- **Setup only** installs or verifies all six scanners and applicable prerequisites and writes an installation summary. It defers project wrapper execution and scanner runs.
- **Default run** installs missing applicable tools, resolves dependencies and runs the applicable scans. Run it only on a project you trust. Wrapper scripts, Maven plugins, Gradle build files and explicitly selected Docker builds execute project-controlled code.
- **Containers** are optional. Grype scans the Syft SBOM, and Checkov checks discovered Dockerfiles. Select one of these options to also have Grype check OS and application packages in a container image.

~~~bash
bash "$KIT/security-scan.sh" --project-path "$APP" --image ecommerce:local
bash "$KIT/security-scan.sh" --project-path "$APP" --build-image
~~~

The local image option uses an existing Docker image. The build option uses a root Dockerfile or the only discovered Dockerfile and uses its parent as build context. For repositories with multiple Dockerfiles or a different build context, build the desired image normally and pass its tag. App-specific Docker build arguments are handled by that normal build.

## Architecture

1. security-scan.sh detects the host, bootstraps Python if needed, and preserves the caller's working directory.
2. starter_kit.py discovers Java sources, Maven and Gradle builds, existing JAR/WAR/EAR files, Dockerfiles and common infrastructure files. Maven copies resolved dependencies into a per-run working directory. Gradle uses a kit-supplied init script to collect standard compile and runtime configurations. The kit also scans existing Java archives, including files under target and build. It does not run an application build to create missing archives.
3. starter_install.py validates tools and reuses or provisions compatible versions. Applicable scanners run sequentially in this order. Gitleaks scans the project tree, Semgrep applies the local Java and SQL rules, Dependency-Check scans resolved dependencies and archives, Syft builds the CycloneDX inventory, Grype checks the SBOM and any requested container image, and Checkov scans discovered Terraform, Dockerfile, Kubernetes, CloudFormation, ARM and Bicep candidates. The default Gitleaks scope is filesystem content. Review and extend the Semgrep rules if your organization requires broader SAST coverage.
4. The kit creates a private run directory for reports and diagnostics. A failed scanner is recorded and independent scanners continue. If dependency resolution fails, a partial Java dependency scan is not reported as successful.

Discovery covers conventional Maven reactors and Gradle builds with standard Java configurations. Separate builds nested under another root, custom configurations, composite builds and builds with unusual resolution logic may need a more specific project path or prebuilt archives. Check the dry-run build roots and the resulting inventory.

## Reports

Reports go to a unique timestamped directory under $HOME/.accidion/reports/<application-name>/ by default. The kit uses the Maven name or artifact ID, Gradle root name, or directory name, then converts it to a safe lowercase folder name. Set ACCIDION_HOME to relocate report and cache defaults, or --report-dir to override the report parent. These directories must be outside the scanned project. The run directory uses owner-only permissions on POSIX and restricted ACL inheritance on Windows. Git Bash users do not need to edit PATH for the Windows ACL check. Use a private, ACL-capable volume and keep reports and run.log out of Git and shared storage.

OWASP Dependency-Check stores its database in ACCIDION_HOME/dependency-check-data. Grype defaults to ACCIDION_HOME/grype-db and honors an approved GRYPE_DB_CACHE_DIR override. Both paths persist across runs, including with --no-install. Scanners still apply their normal feed freshness and update policy. A first run or stale cache can take longer. The summary records each cache path and whether it already had content before that scanner ran. [Grype database configuration](https://oss.anchore.com/docs/reference/grype/configuration/)

| File | Contents |
|---|---|
| gitleaks-report.json | Filesystem secret findings with secret and match values removed |
| semgrep-report.json | Static analysis findings and diagnostics |
| dependency-check-report.json | Java dependency vulnerability analysis |
| syft-sbom.json | CycloneDX component inventory |
| grype-report.json | Vulnerabilities in the SBOM by default, or in the selected container |
| grype-sbom-report.json | Additional native package vulnerability report when both SBOM and container scans run |
| checkov-report.json | Checks and findings for discovered infrastructure inputs |
| security-summary.json | Application name, project path, pinned kit commit, timestamps, platform, tool versions, installation and scan status, report paths, counts and numbered issues |
| run.log | Private diagnostics from installers, build tools and scanners |

Individual reports retain scanner-native structures with sensitive fields masked. Gitleaks runs first and its exact detected values are used to scrub published reports, diagnostics and terminal issue text. The kit also removes source excerpts and other sensitive payloads from known native fields, masks common credential formats, and strips query parameters from normalized reference links. Unredacted scanner output exists temporarily inside the private run directory and is removed during normal cleanup. An interrupted process can leave that temporary output behind. Treat all reports as sensitive because repository details and values the scanners did not detect can still appear.

A valid partial report remains available when a scanner fails. Skips and failures without output have a null report path. SBOM components are counted separately. Severity uses the scanner's own scale, so Semgrep's ERROR and a vulnerability scanner's HIGH remain distinct. When evidence is missing, the issue contains a null or UNKNOWN value and an explanation in evidence_limitations. Numbering is continuous in scan order, and the terminal prints every issue. Findings repeated by different scanners or reported for both a package and an image remain individually visible.

### Example issue in security-summary.json

This fixture illustrates the schema. The values do not represent an application scan.

~~~json
{
  "issue_number": 1,
  "issue_id": "47b77dc43f19ca8a3de563f1",
  "issue_name": "Potential SQL Injection from Query Concatenation",
  "scanner_name": "Semgrep",
  "vulnerability_category": "SQL Injection",
  "severity": "ERROR",
  "source_file": "src/main/java/example/Search.java",
  "affected_filename": "Search.java",
  "relative_file_path": "src/main/java/example/Search.java",
  "start_line": 42,
  "end_line": 43,
  "issue_description": "SQL injection risk due to unsafe query concatenation",
  "root_cause": "The rule detected a string constructed by concatenating an input expression.",
  "security_impact": "If input is attacker-controlled and reaches a SQL execution sink, it can change the query.",
  "recommended_remediation": "Use a parameterized query with bound values and verify that the string reaches a database sink.",
  "rule_id": "java-sql-injection",
  "cwe_id": ["CWE-89"],
  "cve_id": null,
  "affected_dependency": null,
  "installed_version": null,
  "fixed_version": null,
  "reference_links": [],
  "evidence_limitations": {
    "cve_id": "No CVE was supplied with this finding.",
    "affected_dependency": "No affected package was identified for this finding.",
    "installed_version": "No installed version was reported.",
    "fixed_version": "No fixed version was reported. Consult the referenced advisory or vendor.",
    "reference_links": "No usable reference URL was supplied."
  }
}
~~~

Use totalFindings, findingsBySeverity and findingsByScanner for triage, then use issues and the referenced native report for evidence. Use sbomComponentCount to track inventory separately. For a credential finding, verify validity and rotate or revoke it before removing the source exposure. For a dependency finding, verify the installed coordinate and the advisory's supported fix, update the direct dependency or its transitive parent, and rerun. For source and infrastructure findings, confirm the source location and rule context before applying the recommended change. The kit does not edit the application.

### Example scanner and inventory totals

This excerpt uses synthetic counts. The full summary also contains each scanner's status and report location and the complete issues array.

~~~json
{
  "applicationName": "Example Java App",
  "totalFindings": 2,
  "findingsBySeverity": {"ERROR": 1, "HIGH": 1},
  "findingsByScanner": {
    "gitleaks": 0,
    "semgrep": 1,
    "dependency-check": 0,
    "syft": 0,
    "grype": 1,
    "checkov": 0
  },
  "sbomComponentCount": 3
}
~~~

A completed run exits with 0 when required operations succeeded, 1 for recorded required installation or scan failures, or 2 for usage or startup errors. Findings alone do not change the exit status.

## Troubleshooting

| Symptom | What to check |
|---|---|
| Bootstrap expects a private repository | Confirm the GitHub slug and its visibility. Use an approved private destination. |
| Pinned download fails | Check authenticated read access, SSO, the reviewed commit, and network access to GitHub's API and archive service. |
| Bootstrap or archive SHA-256 mismatch | Get the approved release pins and digests from your administrator. Execution stops before the affected download is run or extracted. |
| Credential missing or rejected | Check vault injection, GitHub CLI sign-in, or the cached Git credential-manager entry for github.com. Verify token expiration, repository access, and required SSO authorization. |
| Native and summary counts differ | Check the scanner's nativeFindingCount, findingCount, status, and reason in security-summary.json. The individual report retains the evidence for inspection. |
| Tool missing or blocked by endpoint protection | Review the installation reason and private log. Ask IT for an approved compatible installation and retry with --no-install. |
| Python venv or pip cannot install a scanner | Check the Python version, package-index policy and compatible wheel availability. On Linux, ask IT to provision Python's venv support if necessary. |
| Dependency resolution fails | Check JAVA_HOME, wrapper compatibility, repository authentication, and the build configuration. Test from the affected module. |
| Dependency-Check or Grype cannot download vulnerability data | Check proxy rules, feed connectivity, and rate limits. Check the log for the failed service. |
| Docker installed but image scan fails | Start the approved Docker service or Desktop and verify daemon access. Use an existing local image or omit image options to use the SBOM path. |
| Reports cannot be created | Choose a writable location outside the project, on a filesystem that supports user-only permissions. |
| Windows executable just installed is unavailable | Open a new Git Bash terminal to refresh PATH, then retry. |

## Local validation

To validate the Accidion sample already in this repository, run this single command from the repository root. The scan target is src, so bootstrap code, tests, workspace caches, and the root reports folder are outside the target.

~~~bash
ACCIDION_HOME="$(pwd -P)/.accidion" bash ./security-scan.sh --project-path ./src --report-dir ./reports
~~~

Each run creates reports/<application-name>/scan-<UTC-date-time>-<id>/ in the checkout. The workspace .accidion and reports directories are ignored by Git. The source scan also excludes the named generated JSON artifacts, including the legacy Dependency-Check report under src/target.

The summary provides affected_filename and relative_file_path alongside source_file. For example, a dependency scanner may report a JAR filename without identifying where it appears in the project's source. In that case the relative path and line numbers remain null. OpenTofu .tofu and .tofu.json files are detected and listed as unsupported inputs for the current Checkov integration. Terraform-compatible .tf and .tf.json files remain supported. [Checkov native OpenTofu extension support](https://github.com/bridgecrewio/checkov/pull/7401)

~~~bash
bash -n security-scan.sh
python -B -m unittest discover -s tests -v
bash ./security-scan.sh --dry-run
~~~

The suite runs the actual Bash launcher against a temporary Java project and exercises native report-directory permissions. Separate tests mock the network, installers, and scanners to validate package selection, scan order, report reconciliation, and redaction without running security scans.

Run the same local checks on each supported host. A native dry run verifies detection and discovery, while mocked scans exercise report generation without calling the security tools. For a restricted workspace, set TMPDIR, TMP, and TEMP to an ignored workspace directory before running the launcher and scanner tests.

The kit completed a live scanner run on Windows x86-64 using Git Bash. The final Windows and Ubuntu WSL checks covered the launcher, report-directory creation, and mocked scanner behavior. Native macOS and standalone Linux end-to-end validation are pending.
