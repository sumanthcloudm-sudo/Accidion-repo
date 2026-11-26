# Accidion Java DevSecOps Security Starter Kit

Scan a Java project for exposed secrets, vulnerable dependencies, unsafe code and infrastructure settings. The kit also inventories software components and can check a local Docker image.

Use it with Core Java, Spring Boot, microservices, Maven, Gradle, multi-module builds and Docker-based Java applications. Run it in Windows Git Bash (x64), Linux Bash (x64 or ARM64 on supported distributions), or macOS Bash 3.2 or newer (Intel or Apple Silicon). Windows ARM64 has limited scanner availability.

## Prerequisites

- Use the JDK and build tools your project requires. The scanner's JDK check requires Java 11 or newer when applicable. Maven and Gradle wrappers are supported.
- Use Python 3.10 or newer, with native Windows CPython on Git Bash. The launcher can attempt to install Python and missing tools where supported.
- Allow access to approved download and dependency repositories, and provide writable private storage outside the application. For image scans, use a Docker CLI with access to a running daemon.

## Quick start

1. Build the application and run its tests with your project's normal build command.
2. Open the standalone `security-scan.sh`. [Open the local script in IntelliJ IDEA](./security-scan.sh) · [View on GitHub](https://github.com/sumanthcloudm-sudo/Accidion-repo/blob/standalone-cross-platform/security-scan.sh) · [Download raw script](https://raw.githubusercontent.com/sumanthcloudm-sudo/Accidion-repo/refs/heads/standalone-cross-platform/security-scan.sh)
3. Copy the file into your Java application root. Open Bash in that directory, using Git Bash on Windows.
4. Run the scan.

   ```bash
   bash security-scan.sh
   ```

5. Open `reports/security-summary.json`. Check which scanners ran, fix confirmed findings, rebuild, test and repeat the same command.

The launcher contains its Python scripts and scanner configurations. It detects the platform, discovers application inputs, attempts to resolve Java dependencies when needed and writes JSON reports.

## Default configuration

The first normal run creates `security-scan.properties` in the application root if it is missing. Edit that one file for subsequent scans.

```properties
PROJECT_ROOT=.
OUTPUT_DIR=
SCANNERS=all
DOCKER_IMAGE=
BUILD_IMAGE=false
```

All six scanners are selected by default. Stages without applicable inputs may be skipped. Set `OUTPUT_DIR` to change the private report parent. The application-local JSON export stays in the scanned application's `reports/` directory.

## Scanners and JSON reports

| Scanner | Purpose | JSON report |
| --- | --- | --- |
| Gitleaks | Detect exposed secrets | `gitleaks-report.json` |
| Semgrep | Find unsafe source-code patterns | `semgrep-report.json` |
| OWASP Dependency-Check | Find known Java dependency vulnerabilities | `dependency-check-report.json` |
| Syft | Generate a software bill of materials (SBOM) | `syft-sbom.json` |
| Grype | Find package and container vulnerabilities | `grype-report.json`, plus `grype-sbom-report.json` for combined image and package scans when produced |
| Checkov | Check infrastructure and Dockerfile policies | `checkov-report.json` |

The application receives `reports/security-summary.json` and sanitized reports from successful stages that produced output. Each run retains its summary, available outputs and diagnostic log in private storage under `~/.accidion/reports/<application-name>/scan-<timestamp>-<id>/` by default. A successful scanner can still report vulnerabilities. Syft counts inventory components separately from findings.

See the [Java Developer Security Guide](JAVA-DEVELOPER-SECURITY-GUIDE.md) for configuration examples, report interpretation, platform limitations and troubleshooting.
