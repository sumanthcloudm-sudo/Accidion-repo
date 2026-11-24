# Accidion — Java Application Security Scanner

Accidion scans a completed Java application and creates JSON security reports. It is intended to help developers find security issues before a pull request or release.

**Target environment: Ubuntu Linux.** These instructions cover Ubuntu only. Windows, macOS and other Linux distributions are outside the documented workflow.

## What you need

Before running Accidion, make sure you have:

- Ubuntu with Bash.
- Git.
- Python 3.10 or newer, including the matching `venv` support.
- A JDK compatible with your application. OWASP Dependency-Check requires Java 11 or newer.
- Internet access to approved package repositories and vulnerability databases.
- Permission to read your application and write to your home directory.

Your Java application should already build and pass its normal tests.

### Why these prerequisites matter

| Requirement | Why Accidion needs it |
| --- | --- |
| Bash | Runs the `security-scan.sh` launcher |
| Git | Clones the toolkit |
| Python 3.10+ and venv | Runs the scanner orchestration and creates its isolated tool environment |
| JDK | Supports Java dependency analysis and Java build tools |
| Network access | Downloads approved scanner packages and vulnerability databases |
| Writable home directory | Stores tools, caches and private JSON reports |

Accidion does **not** run `sudo` or bypass Ubuntu permissions. If a system package is missing and your account cannot install it, ask your administrator to install it. Do not run the complete scan as root.

## Quick start

### 1. Install or verify prerequisites

Check what is already available:

```bash
git --version
python3 --version
java -version
```

If Git, Python or the matching Python virtual-environment package is missing, ask your Ubuntu administrator to install the required packages. The JDK version must also be compatible with your application; Java 11 or newer is required by Dependency-Check.

### 2. Clone Accidion once

```bash
mkdir -p "$HOME/devsecops"
git clone https://github.com/sumanthcloudm-sudo/Accidion-repo.git "$HOME/devsecops/Accidion-repo"
```

Keep the Accidion folder separate from your Java application. Use a repository revision approved by your team.

### 3. Open your Java application folder

Replace the example path with the real path to your application:

```bash
cd "$HOME/projects/my-java-app"
```

Run the scan from the application root so Accidion can discover its source files and build files.

### 4. Run the scan

```bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh"
```

That is the normal developer command. Accidion discovers the project, checks applicable tools, installs or reuses compatible tools where permitted, runs the scans sequentially and writes JSON reports.

If you want to stay in another directory, pass the application path explicitly:

```bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --project-path "$HOME/projects/my-java-app"
```

## What gets scanned

| Tool | What it checks | When it applies |
| --- | --- | --- |
| Gitleaks | Exposed secrets and credentials | Every scan |
| Semgrep | Source-code security patterns | When Java application inputs are found |
| OWASP Dependency-Check | Known vulnerabilities in Java dependencies | When Maven/Gradle build files or Java archives are found |
| Syft | Software component inventory (SBOM) | When Java application inputs are found |
| Grype | Known vulnerabilities in the generated SBOM; optional container image scan | When an SBOM or selected image is available |
| Checkov | Infrastructure-as-Code and Dockerfile configuration | When supported infrastructure files or Dockerfiles are found |

A scanner may be skipped when the application does not contain its supported input. A skipped scanner is not a successful scan. Review the scan summary and any failed or skipped scanner status.

## Where reports are saved

By default, reports are written outside your application:

```text
$HOME/.accidion/reports/<application-name>/<scan-run>/
```

The terminal prints the exact directory for each run.

Important JSON files include:

- `security-summary.json` — consolidated findings from the available scanners.
- `gitleaks-report.json` — secret scan results.
- `semgrep-report.json` — source-code scan results.
- `dependency-check-report.json` — Java dependency vulnerability results.
- `syft-sbom.json` — software component inventory.
- `grype-report.json` — package or image vulnerability results.
- `checkov-report.json` — infrastructure scan results.

Some individual reports are created only when the corresponding scanner runs and produces output. A run log is also kept in the run directory for troubleshooting.

Reports can contain sensitive project and vulnerability information. Keep them in approved, access-controlled storage and do not commit them to your application repository.

## Understand and fix findings

1. Open `security-summary.json` from the report directory printed in the terminal.
2. Find the issue name, scanner, severity, source file and line number, when available.
3. Open the affected file in your editor and verify the finding.
4. Apply the recommended fix and check related code or dependencies.
5. Build and test your application again.
6. Run the same Accidion command again and review the new summary.

Not every scanner provides a source line number. Dependency and inventory findings may identify a package rather than a line of code. A severity of `UNKNOWN` still needs review.

**A successful scan does not mean that the application has zero vulnerabilities.** Review findings and scanner failures before accepting the result.

## Optional commands

Run these from your Java application directory.

Preview which files and scanners Accidion detects, without installing tools or writing reports:

```bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --dry-run
```

Verify or install the toolkit's scanners without running scans:

```bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --setup-only
```

Use already-installed tools and disable kit-managed installation:

```bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --no-install
```

The launcher also supports `--report-dir PATH` to choose a private report parent outside the application.

## Optional Docker image scan

Docker is not required for the normal source and dependency scan. For an existing local image:

```bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --image my-app:latest
```

To build and scan a discovered Dockerfile:

```bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --build-image
```

Docker must be installed, running and accessible to your account. Image scanning is an additional check; it does not replace source-code or dependency scanning.

## Troubleshooting

| Message or symptom | What to check |
| --- | --- |
| Python 3.10+ is required | Install a supported Python version and its matching `venv` package |
| Permission or package installation failure | Ask your Ubuntu administrator to provision the missing prerequisite; do not run the full scan as root |
| Java or build-tool failure | Check the JDK version, project wrapper and application build |
| Dependency scan finds no dependencies | Confirm the project contains a supported Maven/Gradle build file or Java archive and that dependency resolution succeeds |
| Vulnerability database download fails | Check approved network, proxy and firewall access |
| Scanner is skipped | Check whether the application contains files supported by that scanner |
| Report cannot be written | Check home-directory permissions and available disk space |
| Docker scan fails | Check Docker installation, daemon status, image name and account access |

The first run may take longer because tools, application dependencies and vulnerability databases may need to be downloaded. Later runs can reuse compatible tools and cached data.

## Scope and limitations

- The documented developer workflow targets Ubuntu.
- Accidion does not automatically modify or repair application source code.
- Scanner coverage depends on the files discovered and the scanner's supported formats.
- Tool installation and database updates depend on approved network access and permissions.
- Maven dependency-tree information may be available when dependency resolution succeeds; it does not by itself prove runtime exploitability or provide complete direct/transitive source-line mapping.
- Review failed and skipped scanners as well as findings. Do not treat missing output as a clean result.

## More information

- [Developer Guide](DEVELOPER-GUIDE.md) — detailed workflow, security rules, scanner behavior and troubleshooting.
- [Sample Reports](sample-reports/README.md) — examples of report output.

---

**Normal workflow:** build and test your Java application → run one Accidion command → review the JSON summary → fix issues → build, test and scan again.
