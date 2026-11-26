# Accidion Developer Guide

This guide is for a developer who wants to scan an existing application for security findings. The examples use a Java application.

Accidion is designed to run from **Windows (Git Bash), Linux (Bash), or macOS (Bash)**. Native end-to-end verification is not complete on every platform; tool availability and installation depend on the OS, architecture, permissions, and network access.

## 1. Purpose of the security scripts

Copy the approved [standalone launcher](dist/security-scan.sh) into the application directory. The launcher extracts its embedded components to a temporary directory outside the application.

When you run the launcher against your own application, Accidion:

1. Uses your current working directory as the **application root**, unless you provide a different path.
2. Discovers supported files inside that root, such as Java source, `pom.xml`, Gradle build files, JAR/WAR/EAR archives, Dockerfiles, and supported infrastructure files.
3. Detects the operating system and CPU architecture.
4. Verifies or, where supported and permitted, installs required tools; existing compatible tools and cached data may be reused.
5. Runs applicable scanners and records success, failure, skipped checks and unavailable tools.
6. Creates private JSON reports, a consolidated findings summary, and a diagnostic log.

**Accidion automatically discovers Java application components in the current working directory (or the configured application root) and executes the applicable security scanners.**

| Security tool | What it checks |
| --- | --- |
| Gitleaks | Potential exposed secrets and credentials |
| Semgrep | Source-code patterns and static security rules |
| OWASP Dependency-Check | Known vulnerabilities in applicable Java dependencies |
| Syft | Software Bill of Materials (SBOM) and component inventory |
| Grype | Known package vulnerabilities; optionally a Docker image |
| Checkov | Supported infrastructure-as-code and Dockerfile policies |

Detection does not mean automatic remediation. Developers review findings, update their **own application**, test it, and rescan.

### Supporting scripts

| File | Purpose |
| --- | --- |
| `security-scan.sh` | Entry point, platform detection and input configuration |
| `starter_kit.py` | Project discovery, scanner execution and report generation |
| `starter_install.py` | Tool verification and permitted provisioning |
| `starter_findings.py` | Consolidated findings and remediation guidance |
| `security-scan.properties` | Optional application root, output path and scanner settings |

## 2. Security scanning launcher: security-scan.sh

**Main launcher:** [dist/security-scan.sh](dist/security-scan.sh)

Copy this file as `security-scan.sh`. It contains the supporting scripts and default scanner configuration.

Basic usage, from **your Java application root**:

```bash
bash security-scan.sh
```

That command runs the default selection of scanners (`all`). Accidion checks which scanners apply to your files; it can skip non-applicable checks.

You can also specify the application explicitly from another directory:

```bash
bash security-scan.sh --project-path "/path/to/my-java-app"
```

The first normal scan creates `security-scan.properties` in the selected
application with defaults for the current directory, the private report
location, all applicable scanners, and no container scan. Later scans reuse
that file and preserve your edits. Help, preview and setup-only runs leave it
alone.

| Property | Meaning |
| --- | --- |
| `PROJECT_ROOT` | Application directory. Default `.` |
| `OUTPUT_DIR` | Private report parent. An empty value uses the default |
| `SCANNERS` | `all` or comma-separated scanner names |
| `DOCKER_IMAGE` | Existing local Docker image |
| `BUILD_IMAGE` | `true` to build and scan a discovered Dockerfile. Default `false` |

Use `--config PATH` for an existing alternate file. Relative property paths
start from the file's directory. CLI flags override property values. Use
`bash security-scan.sh --config "../team scan.properties" --dry-run` to preview
the effective scanner selection. Keep credentials in your approved secret
store. Configure required scanners in the protected CI environment with
`ACCIDION_REQUIRED_SCANNERS`.

For scanner errors, consult the private `run.log` and the status in
`security-summary.json`. On a cold Dependency-Check run, allow time to populate
the NVD database. Use a permitted NVD API key or HTTPS mirror and reuse the cache.
If Dependency-Check is waiting on a lock after an interrupted run, confirm the
updater has stopped before using a fresh private cache.

### Scanner execution commands — choose one per run

After copying the standalone launcher, enter your Java application root containing `pom.xml`. Accidion automatically discovers Maven and applicable application files. Choose one command below based on what you want to scan. These examples assume default properties unless overridden by the command. Run only the command you need today; there is no requirement to run every scanner each time. All commands use Bash/Git Bash on the developer's laptop, from the application root.

#### Complete security scan

When: before integration or release. Where: application root. Reports: all applicable scanner reports, summary and log. Docker image scanning is opt-in.

```bash
bash security-scan.sh --scanner all
```

#### Gitleaks — secret scanning

When: before committing or after configuration changes. Where: application root. Report: `gitleaks-report.json`.

```bash
bash security-scan.sh --scanner gitleaks
```

#### Semgrep — source-code security

When: after source-code changes. Where: application root. Report: `semgrep-report.json`.

```bash
bash security-scan.sh --scanner semgrep
```

#### OWASP Dependency-Check — Maven dependency security

When: after changing Maven dependencies or when only dependency findings are needed. Where: Maven root containing `pom.xml`. Accidion detects Maven and attempts dependency resolution. Report: `dependency-check-report.json`; Maven dependency-tree JSON may also be produced.

```bash
bash security-scan.sh --scanner dependency-check
```

#### Syft — SBOM generation

When: a component inventory is needed. Where: application root. Report: `syft-sbom.json` (CycloneDX JSON, not a vulnerability list).

```bash
bash security-scan.sh --scanner syft
```

#### Grype — package vulnerability scanning

When: application package vulnerabilities need checking. Where: application root. Report: `grype-report.json`; Syft runs as a prerequisite when needed and may generate `syft-sbom.json`.

```bash
bash security-scan.sh --scanner grype
```

#### Checkov — infrastructure security

When: infrastructure or Dockerfile changes. Where: application root with supported files. Report: `checkov-report.json` if applicable.

```bash
bash security-scan.sh --scanner checkov
```

#### Multiple scanners

When: only a subset of checks is needed. Where: application root. Reports: the selected scanner outputs and any required prerequisite outputs.

```bash
bash security-scan.sh --scanner gitleaks,semgrep
```

#### Docker image only

Run from the application root with Docker installed, running and accessible. Only Grype scans the image. Report: `grype-report.json`.

List local images:

```bash
docker images
```

Scan an existing image (replace the name and tag):

```bash
bash security-scan.sh --scanner grype --image my-app:latest
```

Build and scan using the application Dockerfile:

```bash
bash security-scan.sh --scanner grype --build-image
```

#### Complete scan including Docker

Run from the application root to scan both the application and its image.

Scan all applicable targets including an existing image:

```bash
bash security-scan.sh --scanner all --image my-app:latest
```

Build the image and run the complete scan:

```bash
bash security-scan.sh --scanner all --build-image
```

Reports: applicable application reports and image findings, with `grype-sbom-report.json` when package findings are produced. Docker is optional for normal Java scans.

For additional options, use `bash security-scan.sh --help`.

## 3. Steps to run Accidion on your own Java application

### Step 1 — Develop, build, and test your Java application

For example, your laptop may already contain:

```text
my-java-app/
  pom.xml
  src/
    main/
      java/
  Dockerfile                 # optional
  infrastructure/            # optional
```

Your application can use Maven or Gradle. Finish its normal build and tests before scanning. For Maven, open the application root and run `mvn clean verify` if Maven and the appropriate JDK are installed. Your real source and build files remain in **your own application directory**.

### Step 2 — Check prerequisites on your laptop

- **Windows:** open **Git Bash**. Use a supported native Windows Python installation.
- **Linux:** open **Bash**.
- **macOS:** open **Bash**.
- **All platforms:** Use a writable cache directory outside the application and approved network access for first-run downloads.
- **Automatic tool setup:** Accidion automatically detects and attempts to install missing Python and security scanning tools on supported operating systems.
- **Java builds/dependency checks:** use an appropriate JDK (Java 11 or newer for Dependency-Check), Maven/Gradle as applicable, and reachable approved dependency repositories.
- **Docker:** optional, only for image scanning.

Accidion may provision some missing prerequisites/tools on supported systems, but it does not bypass administrator permissions, system security policy, or network restrictions. If an essential prerequisite cannot be provisioned, obtain an approved installation.

### Step 3 — Copy the standalone launcher

Copy the approved [dist/security-scan.sh](dist/security-scan.sh) to the application directory and keep the filename `security-scan.sh`.

### Step 4 — Enter your Java application's root directory

The next command is an **example**, not an automatic location.

For Windows Git Bash:

```bash
cd "/c/Users/yourname/projects/my-java-app"
```

For Linux or macOS:

```bash
cd "$HOME/projects/my-java-app"
```

Verify the current folder using:

```bash
pwd
ls
```

For Maven, look for `pom.xml`.

**Replace the example path with the actual path to your Java application.** The folder you enter is what Accidion scans. If you do not want to change directories, use `--project-path` instead.

### Step 5 — Run one security scanning command

From your Java application root, choose **one** of the following commands.

Complete scan (default properties):

```bash
bash security-scan.sh
```

Maven dependency scan only:

```bash
bash security-scan.sh --scanner dependency-check
```

Existing Docker image only (replace the image name and tag):

```bash
bash security-scan.sh --scanner grype --image my-app:latest
```

For other individual scanners or combinations, use Section 2.

Accidion discovers the applicable project files, checks required tools, runs applicable scanners, and prints progress and the **exact report directory**.

If you first want to see what Accidion detects without running scans:

```bash
bash security-scan.sh --dry-run
```

The first full run may download tools, Java dependencies, or vulnerability databases. Missing prerequisites, unsupported scanner packages, build problems, and blocked downloads can cause scans to fail or be skipped. Read the reported statuses rather than assuming every tool ran.

### Step 6 — Fix findings in your Java application and rescan

Open the new `security-summary.json`, review the scanner statuses and findings, then open the reported files in your own Java application. Fix confirmed vulnerabilities, rebuild, rerun tests, and repeat the **same** security-scan command.

**Next time:** open a terminal, enter your application root, and repeat Step 5.

## 4. Application properties and report paths

**Configuration file:** `security-scan.properties`, created in the application directory on the first normal scan.

The default scans the selected application and writes reports to the private default directory. Change the file to set recurring values.

Defaults generated by the standalone launcher:

```properties
PROJECT_ROOT=.
OUTPUT_DIR=
SCANNERS=all
DOCKER_IMAGE=
BUILD_IMAGE=false
```

| Property | Purpose | Default behavior |
| --- | --- | --- |
| `PROJECT_ROOT` | Path to the developer's Java application | Current directory |
| `OUTPUT_DIR` | Parent directory for private scan reports | `~/.accidion/reports/` |
| `SCANNERS` | `all` or comma-separated scanner names | `all` |
| `DOCKER_IMAGE` | Existing authorized local Docker image name | Empty; no explicit image requested |
| `BUILD_IMAGE` | Build and scan a Docker image | `false` |

Example for a Linux developer who wants fixed paths (macOS typically uses `/Users/yourname` instead of `/home/yourname`):

```properties
PROJECT_ROOT=/home/yourname/projects/my-java-app
OUTPUT_DIR=/home/yourname/security-reports
SCANNERS=all
DOCKER_IMAGE=
BUILD_IMAGE=false
```

Replace those paths with the actual application and report paths. On Windows, use the paths appropriate to Git Bash/your filesystem instead; do not copy Linux paths to Windows. **The report directory must be outside your application directory** to avoid accidentally scanning or committing sensitive results.

To configure Maven-only scanning as a recurring default, use `SCANNERS=dependency-check`, `DOCKER_IMAGE=` and `BUILD_IMAGE=false`. For Docker-only scanning, use `SCANNERS=grype`, `DOCKER_IMAGE=my-app:latest` and `BUILD_IMAGE=false`. Run the same launcher after saving. For occasional scanner selection, keep default properties and use command-line flags instead. Clear configured Docker properties before switching to a scanner that does not include Grype.

Alternatively, keep properties at their defaults and pass values directly:

```bash
bash security-scan.sh --project-path "/path/to/my-java-app" --report-dir "/path/to/private-reports"
```

The launcher reads properties at startup and applies explicit command-line overrides. Use `--config PATH` to read an existing alternative. Keep reports outside the application.

## 5. Security reports: where to find them and how to read them

After a scan, Accidion prints the **exact report location**. By default, reports are saved privately on the developer's laptop under:

```text
~/.accidion/reports/<application-name>/scan-<timestamp>-<id>/
```

A new scan creates a separate run directory. Your application source is **not automatically modified**, and scan reports are **not automatically committed to your Java application's Git repository**.

| Report file | What the developer learns |
| --- | --- |
| `security-summary.json` | **Start here.** Application name, scanner statuses, detected findings, severity, source location when available, remediation guidance and evidence |
| `gitleaks-report.json` | Potential exposed secrets |
| `semgrep-report.json` | Static-code rule findings and scanner errors |
| `dependency-check-report.json` | Dependency vulnerabilities and available CVE evidence |
| `syft-sbom.json` | Component inventory (SBOM); not a vulnerability list |
| `grype-report.json` | Known vulnerable packages or image components |
| `checkov-report.json` | Supported infrastructure policy failures |
| `run.log` | Redacted execution diagnostics and scanner/build errors |

An image scan alongside package scanning can also produce `grype-sbom-report.json`; a Maven scan may produce a dependency-tree JSON file. **Only reports produced by applicable, completed stages may be present.** A missing file may indicate an unselected, skipped, or failed scanner.

### Complete versus individual scanner reports

Every completed scan normally generates `security-summary.json` and `run.log`. Native scanner reports are generated only for executed stages that produce output. Unselected stages do not generate their native reports.

| Scan selection | Expected native scanner reports (in addition to summary and log) |
| --- | --- |
| `--scanner all` | All applicable scanner outputs: Gitleaks, Semgrep, Dependency-Check, Syft, Grype and Checkov |
| `--scanner dependency-check` | `dependency-check-report.json` (and possible Maven dependency-tree JSON) |
| `--scanner gitleaks` | `gitleaks-report.json` |
| `--scanner semgrep` | `semgrep-report.json` |
| `--scanner syft` | `syft-sbom.json` |
| `--scanner grype` | `grype-report.json` and required Syft SBOM when applicable |
| `--scanner checkov` | `checkov-report.json` when applicable |
| `--scanner grype --image my-app:latest` | `grype-report.json` for the image only |
| `--scanner grype --build-image` | `grype-report.json` for the built image |
| `--scanner gitleaks,semgrep` | Gitleaks and Semgrep reports |
| `--scanner all --image my-app:latest` | Applicable scanner outputs plus image findings and possible `grype-sbom-report.json` |

Reports are generated based on the selected and applicable scanners. Some scanners may require additional prerequisite reports. Review `security-summary.json` to identify completed, skipped or failed scans.

### How a developer uses the findings

1. Open `security-summary.json` in VS Code or another JSON viewer.
2. Check each scanner's `status` and reason. A skipped or failed scanner is **not** evidence of a clean scan.
3. Review `issues`, especially `scanner_name`, `issue_name`, `severity`, `source_file` or `relative_file_path`, `start_line` when available, `affected_dependency`, and `recommended_remediation`.
4. Open the actual source file, manifest, or infrastructure file in **your application**. Dependency findings may identify a package instead of a line number.
5. Fix the problem, rebuild and test the application, and run the scan again.

Do not publish reports containing sensitive project information or credentials. Scanner results may require manual triage and approved risk decisions. A completed scan or a process exit code of zero does **not** prove your application has zero vulnerabilities.

---

**Developer workflow in one sentence:** Build and test your own Java application → copy the standalone launcher → enter that application's root → run `security-scan.sh` → review private JSON findings → fix your application → rescan.
