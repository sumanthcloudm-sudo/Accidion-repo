# Accidion DevSecOps Security Scanning Guide

## 1. Purpose of the security scripts

Accidion scans an application for exposed secrets, source-code issues, vulnerable dependencies and packages, and infrastructure misconfigurations. It also generates a software bill of materials (SBOM) when supported package inputs are present.

The launcher detects the operating system and CPU architecture, checks for prerequisites such as Python, and attempts to install missing prerequisites and applicable scanners where supported. It can reuse compatible tools and cached vulnerability data. Installation depends on package availability, permissions, and network access.

Accidion discovers inputs in the application directory, including source files, build files and archives, package manifests and lockfiles, Dockerfiles, and supported infrastructure definitions. Package discovery includes supported inputs for Java, JavaScript and TypeScript, Python, Go, .NET, Rust, Ruby, and PHP. Coverage varies by scanner. For example, the bundled Semgrep rules cover Java and SQL, and OWASP Dependency-Check runs for Maven or Gradle build files or Java archives. The scan writes JSON reports and a consolidated summary with scanner statuses and findings.

## 2. Provide security-scan.sh

[Open the local script in IntelliJ IDEA](./security-scan.sh) · [View on GitHub](https://github.com/sumanthcloudm-sudo/Accidion-repo/blob/standalone-cross-platform/security-scan.sh) · [Download raw script](https://raw.githubusercontent.com/sumanthcloudm-sudo/Accidion-repo/refs/heads/standalone-cross-platform/security-scan.sh)

Developers only need this standalone script from the Accidion repository. It includes the supporting scripts and default scanner configurations. The optional properties file is created automatically on the first normal scan if it is missing.

## 3. Steps to run the security scan

1. Download `security-scan.sh`.
2. Copy it into the application root directory.
3. Open the terminal in the application root directory.
4. Execute:

   ```bash
   bash security-scan.sh
   ```

5. Review the generated security reports. Start with `reports/security-summary.json`.

Use Git Bash on Windows and Bash on Linux or macOS. The launcher recognizes x86-64 and ARM64. Individual scanner availability varies by platform and architecture.

The launcher needs Python 3.10 or later and attempts to provision it if missing. Use a writable tool cache and private report directory outside the application, and allow network access for first-run tool and vulnerability database downloads. Dependency checks on Maven or Gradle projects may need a compatible JDK, the corresponding build tool or wrapper, and access to dependency repositories. Docker is optional. For image scans, the Docker CLI and a running, accessible Docker daemon are required.

## 4. Properties file configuration

Keep one `security-scan.properties` file in the application root where you start the launcher. For a custom application path, edit this same file in the directory from which you launch the scan. The launcher reads it at startup and resolves relative paths from the properties file's directory.

| Property | What it controls | Default |
|---|---|---|
| `PROJECT_ROOT` | Directory to scan. Use an absolute path or a path relative to the properties file. | `.`, the directory containing the properties file |
| `OUTPUT_DIR` | Parent directory for private scan history and diagnostics. Choose a writable path outside the scanned application. The project JSON export still goes to the scanned application's `reports/` directory. | Blank, which uses `~/.accidion/reports/` with the default Accidion home |
| `SCANNERS` | Scanner selection. Use `all` or a comma-separated list of `gitleaks`, `semgrep`, `dependency-check`, `syft`, `grype`, and `checkov`. Accidion can add Syft when Grype needs an application SBOM. | `all`, which runs applicable scanners |
| `DOCKER_IMAGE` | Existing local Docker image to scan with Grype, such as `my-app:latest`. Include Grype in the selection or use `all`. | Blank, so no existing image is requested |
| `BUILD_IMAGE` | Set to `true` to build an image locally and scan it with Grype. Accidion needs a root `Dockerfile` or exactly one discovered Dockerfile. Leave `DOCKER_IMAGE` blank when building. | `false` |

Choose one example, save the values in the same properties file, and run the same command for all four examples:

```bash
bash security-scan.sh
```

### Example 1: Scan the current application

```properties
PROJECT_ROOT=.
OUTPUT_DIR=
SCANNERS=all
DOCKER_IMAGE=
BUILD_IMAGE=false
```

### Example 2: Scan using custom application and output paths

```properties
PROJECT_ROOT=/home/developer/my-application
OUTPUT_DIR=/home/developer/security-reports
SCANNERS=all
DOCKER_IMAGE=
BUILD_IMAGE=false
```

### Example 3: Scan selected security scanners

```properties
PROJECT_ROOT=.
OUTPUT_DIR=
SCANNERS=gitleaks,semgrep,dependency-check
DOCKER_IMAGE=
BUILD_IMAGE=false
```

### Example 4: Scan an existing Docker image

```properties
PROJECT_ROOT=.
OUTPUT_DIR=
SCANNERS=all
DOCKER_IMAGE=my-app:latest
BUILD_IMAGE=false
```

This example runs applicable application checks and scans the local image with Grype.

## 5. Explain the security reports

Open `reports/security-summary.json` in the scanned application root. The `reports/` folder contains sanitized JSON exports from successful scanners. Accidion also prints the private run location, which defaults to `~/.accidion/reports/<application-name>/scan-<timestamp>-<id>/`. Set `OUTPUT_DIR` to change the private report parent. Each private run directory contains `run.log` and any available diagnostics, which can include partial scanner output.

| Scanner | Report | What it contains |
|---|---|---|
| Gitleaks | `gitleaks-report.json` | Potential secrets and credentials in application files, with rule and file location details. |
| Semgrep | `semgrep-report.json` | Static analysis findings from bundled Java and SQL rules, with affected files and lines where available. |
| OWASP Dependency-Check | `dependency-check-report.json` | Known vulnerabilities in dependencies identified from applicable builds and archives, with affected dependencies and available CVE details. |
| Syft | `syft-sbom.json` | CycloneDX JSON inventory of detected components and versions. |
| Grype | `grype-report.json` | Known vulnerabilities in packages from the application SBOM or a requested Docker image. When both are scanned, application package results may also appear in `grype-sbom-report.json`. |
| Checkov | `checkov-report.json` | Policy check results for supported infrastructure definitions and Dockerfiles, including failed checks and affected resources or files. |
| Consolidated summary | `security-summary.json` | Scanner statuses and reasons, finding counts by scanner and severity, and issues with available evidence and remediation guidance. |

Check each scanner's status first. A status of `success` means the scanner completed and can still have findings. A `skipped`, `unavailable`, or `failed` status explains why coverage is missing. A scanner may be skipped because it was outside the configured selection or because it had no applicable inputs. For example, Checkov needs supported infrastructure files or Dockerfiles, and Grype needs supported package inputs or a requested Docker image. Native OpenTofu files (`.tofu` and `.tofu.json`) do not enable Checkov coverage in this launcher.

Review the summary's `issues` for severity, affected files and lines, affected dependencies or components, and recommended remediation. Package findings may identify a component and version without a source line. Open the scanner report for additional evidence, then fix confirmed issues and rerun the scan.
