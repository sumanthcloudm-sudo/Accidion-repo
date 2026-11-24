# Accidion Developer Guide

For developers who have completed a Java application and want to identify and remediate security issues before delivery. No prior experience with security scanners is required.

## 1. What Accidion does

Accidion discovers application source, build files, Java archives and supported infrastructure files, installs or reuses applicable tools, runs security checks and generates local JSON reports. It does not automatically fix code or certify that an application is secure.

## 2. Quick start: clone once, scan with one command

Open Git Bash on Windows or Bash on Linux/macOS. Git must already be available for cloning. Keep the kit outside your application.

```bash
mkdir -p "$HOME/devsecops"
git clone https://github.com/sumanthcloudm-sudo/Accidion-repo.git "$HOME/devsecops/Accidion-repo"
cd "$HOME/projects/my-java-app"
bash "$HOME/devsecops/Accidion-repo/security-scan.sh"
```

Replace the example application path with your actual path. Run the clone only once. For subsequent scans, enter your application directory and repeat the last command. Use an organization-approved kit revision; review changes before updating it. The local checkout launcher is distinct from the authenticated, digest-pinned public download workflow described in the [README](README.md#run-from-the-public-github-repository). That workflow requires an approved GitHub credential and the three reviewed release values; obtain them from your administrator rather than inventing them.

## 3. Example application layout

```text
my-java-app/
  pom.xml
  src/main/java/com/example/App.java
  src/main/resources/application.properties
  Dockerfile
  infrastructure/main.tf
```

Only include files relevant to your application. A Gradle build is also supported. Do not create insecure files in production just to test scanners.

## 4. Prerequisites

- Bash, Git for cloning, a writable home directory and approved network access.
- Python 3.10 or newer (3.12 recommended); native Windows Python on Windows.
- A compatible JDK with javac (at least Java 11 for Dependency-Check, and compatible with the application's build).
- Approved Maven/Gradle repositories and credentials where needed.
- Docker only for optional image scanning; a running daemon and existing authorized access are needed.
- Supported launcher architectures: x86-64 and ARM64, subject to available packages and wheels.

System package installation is conditional on existing permissions and approved package sources. Do not bypass organizational controls.

## 5. Windows 10/11

Install Git for Windows through your approved channel and open **Git Bash**, not Command Prompt or PowerShell. Example:

```bash
git --version
mkdir -p "$HOME/devsecops"
git clone https://github.com/sumanthcloudm-sudo/Accidion-repo.git "$HOME/devsecops/Accidion-repo"
cd "/c/Users/YOUR_USERNAME/projects/my-java-app"
bash "$HOME/devsecops/Accidion-repo/security-scan.sh"
```

Replace YOUR_USERNAME and the project path. WinGet can install supported missing prerequisites where policy permits. Native Python is required. For WSL, use the Linux instructions and Linux tools instead.

## 6. Ubuntu (including WSL)

Open an Ubuntu Bash terminal. Where permitted, have an administrator provision missing system packages; for example, on Ubuntu with a compatible Python version:

```bash
sudo apt-get update
sudo apt-get install -y git python3 python3-venv
```

The kit itself does not invoke sudo. Run the scanner as your normal developer account:

```bash
mkdir -p "$HOME/devsecops"
git clone https://github.com/sumanthcloudm-sudo/Accidion-repo.git "$HOME/devsecops/Accidion-repo"
cd "$HOME/projects/my-java-app"
bash "$HOME/devsecops/Accidion-repo/security-scan.sh"
```

## 7. Standalone Linux

Debian/Ubuntu use APT; Fedora uses DNF; RHEL-compatible systems use DNF/YUM and may require Python 3.12 packages from approved repositories. Ask IT to provision Git, Python, a compatible JDK and other missing system packages as needed. Existing root privileges are required for automatic Linux system-package operations on this branch. Do not run the entire scan as root merely to install prerequisites.

```bash
mkdir -p "$HOME/devsecops"
git clone https://github.com/sumanthcloudm-sudo/Accidion-repo.git "$HOME/devsecops/Accidion-repo"
cd "$HOME/projects/my-java-app"
bash "$HOME/devsecops/Accidion-repo/security-scan.sh"
```

## 8. macOS

Open Terminal and use Bash. Install Git and approved Homebrew if needed. Homebrew can provision supported missing prerequisites. Both Intel and Apple Silicon are recognized, subject to compatible distributions.

```bash
mkdir -p "$HOME/devsecops"
git clone https://github.com/sumanthcloudm-sudo/Accidion-repo.git "$HOME/devsecops/Accidion-repo"
cd "$HOME/projects/my-java-app"
bash "$HOME/devsecops/Accidion-repo/security-scan.sh"
```

Native macOS and standalone Linux end-to-end validation is not established by the previous public guide; these instructions describe implemented platform paths, not a new live test.

## 9. Automatic installation and reuse

The launcher locates compatible Python and can provision it through supported package managers. The Python runner checks Git, applicable Java/build tools and scanners. Compatible installations are reused; pinned downloads and Python environments are managed locally. Missing packages, denied permissions, unsupported wheels and unavailable tools can cause a recorded failure. The kit does not elevate privileges, configure Docker groups or bypass policy. Use approved installations supplied by IT where necessary.

## 10. Scan options

Run from the application directory:

```bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --dry-run
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --setup-only
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --no-install
```

Dry run previews discovery without installing, scanning or writing reports (if Python is missing it cannot discover files). Setup-only prepares tools without scanning. No-install disables kit-managed installation; builds and vulnerability databases may still require network access. These modes are mutually exclusive.

## 11. Java dependency resolution

The runner discovers pom.xml, Gradle build/settings files, Java source and JAR/WAR/EAR artifacts. It prefers the project wrapper for installation-enabled scans when available. Maven resolves dependencies using maven-dependency-plugin 3.8.1 copy-dependencies; Gradle uses the supplied init script. Resolved files are held in temporary work storage and used for dependency scanning and inventory. Build failures, inaccessible repositories or incompatible JDKs can prevent those stages from succeeding. Review build scripts and wrappers before scanning untrusted projects because build tools execute project-controlled logic.

## 12. Security tool overview

| Tool | Purpose | Configuration |
| --- | --- | --- |
| Gitleaks | Secrets in working-directory files | [.gitleaks.toml](.gitleaks.toml) |
| Semgrep | Source and selected manifest patterns | [semgrep.yml](semgrep.yml) |
| OWASP Dependency-Check | Known Java dependency vulnerabilities | Runner arguments in [starter_kit.py](starter_kit.py) |
| Syft | CycloneDX JSON component inventory | Runner arguments |
| Grype | Known package and optional image vulnerabilities | Runner arguments |
| Checkov | Infrastructure policies | [.checkov.yml](.checkov.yml) |

The examples below are illustrative **partial normalized issue objects** from the structure of security-summary.json, not actual scan output or a guarantee that the example triggers every scanner version. The full schema is in starter_findings.py.

## 13. Gitleaks: secret scanning

The public configuration extends the built-in Gitleaks rules and adds two custom rules: `hardcoded-password` and `hardcoded-token`. Built-in rules include credential patterns such as API tokens and private keys. The built-in count depends on the scanner version. Generated scanner JSON is allowlisted. The runner scans the working directory, not full Git history.

Example insecure properties (placeholder only): `password=EXAMPLE_ONLY`. Replace hardcoded credentials with an approved secret-store integration or runtime configuration. Revoke or rotate real exposed credentials and follow your incident response process; deleting the line alone is insufficient.

```json
{
  "scanner_name": "Gitleaks",
  "issue_name": "Hardcoded password detected",
  "rule_id": "hardcoded-password",
  "severity": "UNKNOWN",
  "source_file": "src/main/resources/application.properties",
  "start_line": 7,
  "end_line": 7,
  "recommended_remediation": "Verify, revoke or rotate valid credentials and use an approved secret store."
}
```

The runner redacts detected secrets and sensitive fields before publishing reports. Treat even redacted output as sensitive.

## 14. Semgrep: source security

The public configuration contains exactly five custom rules, all configured with ERROR severity.

| Rule ID | Scope and meaning |
| --- | --- |
| java-sql-injection | Java string assignment with concatenation; potential SQL injection, CWE-89 |
| insecure-dynamic-sql | EXEC(@variable) in SQL files; CWE-89 |
| vulnerable-log4j | log4j-core 2.14.1 in pom.xml; CVE-2021-44228 |
| vulnerable-jackson | jackson-databind 2.9.8 in pom.xml |
| vulnerable-commons-collections | commons-collections 3.2.1 in pom.xml |

These are pattern checks, not comprehensive Java SAST or proof of exploitability. The Java rule may match non-SQL concatenation; inspect the input and database sink. This public configuration does not include a dedicated command-injection rule.

Insecure Java example: `String query = "SELECT * FROM users WHERE name = " + input;`

Prefer bound parameters, for example:

```java
PreparedStatement stmt = connection.prepareStatement(
    "SELECT * FROM users WHERE name = ?");
stmt.setString(1, input);
```

For the dynamic SQL rule use static queries or properly bound parameters with sp_executesql. For the three manifest rules, upgrade to supported patched dependencies and verify resolved versions.

```json
{
  "scanner_name": "Semgrep",
  "issue_name": "Potential SQL Injection from Query Concatenation",
  "rule_id": "java-sql-injection",
  "severity": "ERROR",
  "source_file": "src/main/java/com/example/App.java",
  "start_line": 20,
  "end_line": 20,
  "cwe_id": ["CWE-89"],
  "recommended_remediation": "Use a parameterized query with bound values and verify the database sink."
}
```

## 15. OWASP Dependency-Check

Matches Java dependency evidence against known vulnerabilities. It scans resolved dependencies and discovered Java archives, including transitive dependencies. The vulnerability database changes over time; there is no fixed custom rule count. A finding can be a false match and must be verified against the actual library and advisory.

```json
{
  "scanner_name": "OWASP Dependency-Check",
  "issue_name": "Vulnerable Java dependency",
  "severity": "CRITICAL",
  "rule_id": "CVE-2021-44228",
  "cve_id": ["CVE-2021-44228"],
  "affected_dependency": "org.apache.logging.log4j:log4j-core",
  "installed_version": "2.14.1",
  "fixed_version": null,
  "start_line": null,
  "end_line": null,
  "recommended_remediation": "Confirm the match and upgrade to a vendor-supported patched release."
}
```

Update the dependency in pom.xml or Gradle configuration. For a transitive dependency update the parent or use an approved version constraint. Use the appropriate build command, such as mvn dependency:tree when Maven is available, to verify the effective dependency. Consult the vendor advisory for a supported fix; do not assume a missing fixed_version means no fix exists.

## 16. Syft: SBOM generation

Syft inventories components in CycloneDX JSON. The runner inventories the application and merges resolved dependency inventory when applicable. Syft is not a vulnerability scanner; a component count is not a finding count.

Illustrative partial SBOM:

```json
{
  "bomFormat": "CycloneDX",
  "components": [
    {
      "type": "library",
      "group": "org.apache.logging.log4j",
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    }
  ]
}
```

Check component names and versions against expected dependencies; use Grype and Dependency-Check for vulnerability evidence.

## 17. Grype: package and container vulnerabilities

By default Grype scans the Java SBOM when applicable. It matches package versions to its evolving vulnerability database. Container scanning is optional, not a default Docker build.

```json
{
  "scanner_name": "Grype",
  "issue_name": "Vulnerable package",
  "severity": "CRITICAL",
  "rule_id": "CVE-2021-44228",
  "cve_id": ["CVE-2021-44228"],
  "affected_dependency": "log4j-core",
  "installed_version": "2.14.1",
  "fixed_version": ["2.17.1"],
  "start_line": null,
  "scan_target": "sbom",
  "recommended_remediation": "Review the advisory, upgrade to a compatible supported patched release and rescan."
}
```

The fix version is illustrative historical evidence, not a recommendation to install that old version today. Follow the current vendor advisory and your supported Java version.

For a local image or a discovered Dockerfile, choose one of these commands, only when Docker is running and you have approved access:

```bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --image my-app:local
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --build-image
```

Review Dockerfiles before building. Upgrade vulnerable application packages or the base image, rebuild and rescan.

## 18. Checkov: infrastructure security

The six configured frameworks are terraform, dockerfile, kubernetes, cloudformation, arm and bicep. Built-in policy counts and IDs depend on the installed Checkov version. The runner scans discovered infrastructure candidates using the local configuration and disables policy downloads. Native .tofu and .tofu.json coverage is not available.

Example: a Dockerfile that runs as root may violate built-in policy CKV_DOCKER_3. Configure an appropriate non-root USER and ensure application file permissions support it. Other policy categories include access control, encryption and network exposure, depending on supported resources.

```json
{
  "scanner_name": "Checkov",
  "issue_name": "Ensure that a user for the container has been created",
  "rule_id": "CKV_DOCKER_3",
  "severity": "UNKNOWN",
  "source_file": "Dockerfile",
  "start_line": 1,
  "end_line": 5,
  "recommended_remediation": "Configure a non-root container user and validate permissions."
}
```

Use the actual reported check ID and guidance. Missing severity is reported as UNKNOWN, not LOW.

## 19. Where to find reports

Normal runs create a fresh private per-run directory under:

```text
~/.accidion/reports/<application-name>/scan-<UTC-timestamp>-<id>/
```

The application name is sanitized for use as a directory. The terminal prints the exact report directory. List runs using:

```bash
ls -lt "$HOME/.accidion/reports"
```

Open the printed directory in VS Code or your file explorer. On Windows Git Bash, the home directory normally corresponds to the Windows user profile. WSL uses its Linux home. ACCIDION_HOME can override the default base; --report-dir selects another parent outside the scanned application.

## 20. Report inventory

| File | Contents |
| --- | --- |
| security-summary.json | Overall status and normalized issues; open first |
| gitleaks-report.json | Redacted secret findings |
| semgrep-report.json | Static rule matches and errors |
| dependency-check-report.json | Java dependency evidence and vulnerabilities |
| syft-sbom.json | CycloneDX inventory |
| grype-report.json | Package or selected image vulnerability matches |
| checkov-report.json | Infrastructure checks |
| run.log | Redacted diagnostic log |

Only successful or available scanner artifacts are written; a skipped/failed scanner may have no file. An image scan alongside a Java SBOM scan can additionally produce grype-sbom-report.json. Reports are not automatically exported into the application's repository.

## 21. Understand the summary

Read scanners status (success, skipped or failed), reason, findingCount, totalFindings, findingsBySeverity, installations and issues. Native counts and normalized counts may differ if parsing fails; investigate the corresponding report.

| Issue field | Meaning |
| --- | --- |
| issue_number, issue_id | Run sequence number and evidence-derived identifier |
| issue_name, scanner_name | What was detected and by which tool |
| vulnerability_category, severity | Classification and scanner-reported severity |
| source_file, affected_filename, relative_file_path | Available source location |
| start_line, end_line | Available source line range |
| issue_description, root_cause, security_impact | Available evidence and possible impact |
| recommended_remediation | Suggested action |
| rule_id, cwe_id, cve_id | Rule, weakness and vulnerability identifiers |
| affected_dependency, installed_version, fixed_version | Package and version evidence |
| reference_links, evidence_limitations | References and reasons evidence is absent |

CWE identifies a weakness category; CVE identifies a published vulnerability. Null means unavailable evidence, not absence of risk. Dependency and Grype findings may have no code line numbers. Severity vocabularies differ between scanners.

## 22. Fix vulnerabilities in VS Code

Open your application folder. Read the latest security-summary.json and check failed or skipped stages before trusting its coverage. For each finding, locate relative_file_path or source_file and use Ctrl+P (Cmd+P on macOS) to open it. Use Ctrl+G (or the Go to Line command) for the reported start_line when available. Review the underlying code and references, apply the appropriate fix and test the application. For dependency findings, inspect the build manifest and resolved dependency tree. For infrastructure findings, inspect the resource and check guidance. Prioritize exposed credentials and serious exploitable findings according to team policy.

## 23. Rescan and interpret exit status

From the same application directory:

```bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh"
```

Compare the newest summary against the previous run, including scanner status and coverage. Exit 0 means the runner completed without recorded execution failures; it does not mean zero vulnerabilities. Exit 1 indicates recorded tool/stage failures and exit 2 can indicate launcher, argument or other setup errors. A skipped scanner does not establish that the skipped area is secure.

## 24. First run, subsequent runs and troubleshooting

The first scan may take longer because tools, application dependencies and vulnerability databases must be downloaded. Later runs can reuse compatible tools and caches, but databases may refresh. Do not assume a fixed duration or finding count.

| Problem | Action |
| --- | --- |
| Python missing | Obtain approved Python 3.10+ and venv support; Linux system install requires existing privileges. |
| Java/Maven/Gradle failure | Check JDK compatibility, wrapper, artifact repository access and build errors. |
| Network or database update failure | Check approved proxy, certificates, repository and feed access; inspect run.log. |
| Tool blocked by policy | Ask IT for an approved compatible installation; use --no-install when provisioned. |
| Checkov skipped | Confirm supported infrastructure files are present. |
| Docker failure | Ensure daemon is running, image exists or Dockerfile is suitable, and access is authorized. |
| Report directory error | Choose a writable location outside the application. |
| Authenticated bootstrap failure | Check approved credential, SSO, reviewed commit and digests. Never bypass a digest mismatch. |
| Windows temporary cleanup warning | A retained directory may be locked; inspect the preserved scan status and remove it only after the lock clears. Use a reviewed launcher with the cleanup fix. |

Do not send tokens, raw secrets, source code or sensitive reports to unauthorized recipients.

## 25. Developer completion checklist

- [ ] Application builds and tests pass.
- [ ] Approved Accidion checkout is outside the application.
- [ ] Scan executed against the intended application directory.
- [ ] Latest summary reviewed for failed/skipped stages and coverage.
- [ ] Findings triaged; real exposed secrets rotated.
- [ ] Code, dependencies and infrastructure issues remediated or formally accepted according to policy.
- [ ] Application rebuilt/tested and rescanned.
- [ ] Latest reports reviewed and retained through approved channels.

For implementation details see the [README](README.md). This guide describes the public checkout workflow and its current configurations. It does not claim validation of every OS, architecture, rule, or live scan.
