# Accidion Security Starter Kit

## Purpose

Accidion Security Starter Kit automates application security
scanning, installation of missing security tools, vulnerability
identification, and JSON report generation.

## Supported platforms

- Windows AMD64 with Git Bash and native CPython
- Ubuntu and compatible Linux distributions on AMD64 or ARM64
- macOS Intel and Apple Silicon with Bash 3.2 or newer

Scanner and Python wheel availability varies by OS, architecture and Linux
distribution. Windows ARM64 support depends on available upstream assets.
The GitHub Actions matrix targets Windows AMD64, Linux AMD64 and ARM64, and
macOS Intel and Apple Silicon. The pinned Semgrep release has wheels for macOS
Apple Silicon and Windows AMD64. On macOS Intel and Windows ARM64, use a
compatible approved Semgrep installation when available. The workflow's
`live_scanners` input enables live scanner testing.

## Security Tools

| Tool | Purpose |
|---|---|
| Gitleaks | Secret and credential scanning |
| Semgrep | Static application security testing |
| OWASP Dependency-Check | Dependency vulnerability scanning |
| Syft | Software Bill of Materials generation |
| Grype | Package and container vulnerability scanning |
| Checkov | Infrastructure and Dockerfile security |

## Quick Start

Copy the approved [standalone security-scan.sh](security-scan.sh) into
your application directory. In that directory, open Bash (Git Bash on Windows)
and run:

```bash
bash security-scan.sh
```

You can also run the central launcher by absolute path while your shell is in
the application root. Git Bash accepts drive-letter paths such as
`C:/tools/Accidion-repo/security-scan.sh`.

```bash
bash "/path/to/Accidion-repo/security-scan.sh"
```

Python 3.10+ is required and the launcher can attempt user-local setup.
Accidion reuses compatible tools and provisions missing tools where permitted.
Java dependency scans may need a JDK and Maven or Gradle. Docker and a running
daemon are required only for explicit image scans.

Use an approved network and package manager for first-run downloads. Accidion
does not invoke `sudo`. Use `--no-install` for environments that supply their own
tools and `--dry-run` to preview discovery. Run `bash security-scan.sh --help`
for available flags.

### Application properties

The first normal scan creates `security-scan.properties` in the application
directory when there is no file there. Edit the file to set recurring defaults.
The launcher preserves an existing file. Help, dry runs and setup-only runs
leave it alone. Dry runs load the standalone payload in memory.

```properties
# Security scan configuration
PROJECT_ROOT=.
OUTPUT_DIR=
SCANNERS=all
DOCKER_IMAGE=
BUILD_IMAGE=false
```

Paths in properties are relative to the properties file. An empty `OUTPUT_DIR`
uses the private report directory under `ACCIDION_HOME` or `~/.accidion`.
`SCANNERS` accepts `all` or a comma-separated list of scanner names.
`DOCKER_IMAGE` names a local image. Set `BUILD_IMAGE=true` to build and scan
the discovered Dockerfile. Keep passwords, tokens and API keys in the
approved secret store.

```bash
bash security-scan.sh --config "/path/to/team-scan.properties" --dry-run
bash security-scan.sh --scanner gitleaks,semgrep --report-dir "../private reports"
```

Explicit CLI values override properties, which override built-in defaults.
`--config` uses the named existing file in place of the implicit file.
`--project-path` selects the application and its implicit properties file
when no `--config` is provided. An explicit Docker option overrides both
Docker properties.

For a managed CI gate, set `ACCIDION_REQUIRED_SCANNERS` in the protected job
environment, use a trusted copy of the launcher, and pin `--project-path` to
the checkout under review. Each required scanner must
complete successfully. Requests to omit a required scanner or use a preview,
help or setup-only run fail the gate. Projects can still configure local scans
without that managed policy.

Syft and Grype discover Java, Python, JavaScript, TypeScript projects with
supported package manifests, .NET, Go and several other ecosystems. Coverage
depends on the installed scanner and manifest or lockfile. The included Semgrep
rules target Java and SQL. Dependency-Check resolves Java dependencies.

### Complete Security Scan

```bash
bash security-scan.sh --scanner all
```

All applicable security scanners are executed.

### Individual Scanner Execution

**Gitleaks - Secret Scanning**

```bash
bash security-scan.sh --scanner gitleaks
```

**Semgrep - Code Security**

```bash
bash security-scan.sh --scanner semgrep
```

**OWASP Dependency-Check - Dependency Security**

```bash
bash security-scan.sh --scanner dependency-check
```

**Syft - SBOM Generation**

```bash
bash security-scan.sh --scanner syft
```

**Grype - Package Vulnerability Scanning**

```bash
bash security-scan.sh --scanner grype
```

Syft is automatically executed when required for package scanning.

**Checkov - Infrastructure Security**

```bash
bash security-scan.sh --scanner checkov
```

### Multiple Scanner Execution

```bash
bash security-scan.sh --scanner gitleaks,semgrep
```

Developers can select any combination of supported scanners.

### Docker-Only Security Scanning

Scan an existing Docker image:

```bash
docker images
bash security-scan.sh --scanner grype --image my-app:latest
```

Replace my-app:latest with the actual image name and tag.

Build and scan a Docker image:

```bash
bash security-scan.sh --scanner grype --build-image
```

Only Grype executes in Docker-only scanning.
The remaining five scanners are skipped.

### Complete Security Scan with Docker

```bash
bash security-scan.sh --scanner all --build-image
```

To include an existing Docker image:

```bash
bash security-scan.sh --scanner all --image my-app:latest
```

### Automatic Execution

The launcher automatically:

1. Detects the operating system and architecture.
2. Reads the scanning configuration.
3. Provisions missing Python where supported.
4. Installs missing applicable security tools.
5. Executes selected security scanners.
6. Generates JSON reports and remediation guidance.

## Configuration (Optional)

Developers can save reusable preferences in
`security-scan.properties`.

```properties
PROJECT_ROOT=.
OUTPUT_DIR=
SCANNERS=all
DOCKER_IMAGE=
BUILD_IMAGE=false
```

| Property | Purpose |
|---|---|
| PROJECT_ROOT | Application directory |
| OUTPUT_DIR | Security report directory |
| SCANNERS | Security scanners to execute |
| DOCKER_IMAGE | Existing Docker image |
| BUILD_IMAGE | Build and scan Docker image |

Configuration changes are not required when using command-line arguments.

Report directories are created automatically and must be outside
the application directory.

## Security Reports

Full scans automatically create and refresh `<application-root>/reports/`.
Open `reports/security-summary.json` in IntelliJ IDEA or VS Code to review
scanner statuses and findings. The folder contains sanitized JSON from
successful scanners. A failed, unavailable, skipped or unselected scanner
has a status in the summary and no project JSON. The next full scan recreates
missing reports and leaves unrelated files in the folder alone.

Accidion protects its generated files with local Git exclusions and excludes
the report folder from scan inputs. A tracked report path, unsafe destination,
or Git rules that prevent local exclusion cause an explicit error. Dry runs
and setup-only runs leave the application report folder alone.

Each run keeps its private diagnostics in the configured output directory
or the default location:

```text
~/.accidion/reports/<application-name>/<scan-directory>/
```

Depending on the selected scanners, the following reports are generated:

- gitleaks-report.json
- semgrep-report.json
- dependency-check-report.json
- syft-sbom.json
- grype-report.json
- checkov-report.json
- security-summary.json

The private run also contains `run.log`, available partial scanner output and
Maven dependency-tree diagnostics. Combined container and package scans can
also export `grype-sbom-report.json`.

Successful scanner execution does not mean the application
is free of vulnerabilities. Developers must review the findings
and address identified security issues.

## Troubleshooting

- A Windows Semgrep certificate-store error can affect scanning even when
  the version probe succeeds. Use the approved Windows certificate store or
  organizational CA configuration. The runner can try Semgrep's upstream
  Python CLI compatibility mode.
- The launcher can invoke Checkov through its installed Python module if the
  Windows console launcher is broken. If Syft cannot generate an SBOM, Grype
  attempts a directory scan. Resolved Java dependency coverage stays marked
  incomplete when that fallback cannot cover it.
- If a scanner is `unavailable`, check report installation status and `run.log`
  for a tool version, package manager, permission, certificate or network
  error. Follow your organization's proxy and CA configuration for Bash,
  Python/pip, Java and the scanner. Tools may need separate proxy settings.
- `--report-dir PATH` selects a writable report parent outside the application.
  `ACCIDION_HOME` selects the private tools and database cache location and
  defaults to `~/.accidion`. Keep reports private. Review the four scanner
  statuses in `security-summary.json` before interpreting findings counts.
- The first Dependency-Check run can spend substantial time populating the NVD
  database. Reuse the same cache. Set `NVD_API_KEY` through your approved secret
  manager to use NVD's authenticated rate limits. The key is passed via a private
  temporary properties file. Managed environments can set `ACCIDION_NVD_MIRROR`
  to an approved HTTPS mirror such as `https://mirror.example/nvdcve-{0}.json.gz`.
  The report includes Dependency-Check command time
  and separate report-processing timings. If an interrupted update leaves
  Dependency-Check waiting on a database lock, confirm the updater has stopped
  and retry with a fresh private cache. Treat a lock as active until verified.
- Set `ACCIDION_SCAN_TIMEOUT` to a positive number of seconds to change the
  per-scanner command timeout (default 3600). `--no-install` permits scanner
  database updates and dependency resolution.

## Build the standalone distribution

From the toolkit repository, run `python scripts/build_standalone.py` with
Python 3.10+. Add `--check` to verify that the tracked output matches the source.

## Documentation

Refer to the [DevOps Security Scanning Guide](Devops%20Security%20Scanning.md)
for detailed execution steps, configuration and report interpretation.
