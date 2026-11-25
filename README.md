# Accidion Security Starter Kit

## Purpose

Accidion Security Starter Kit automates application security
scanning, installation of missing security tools, vulnerability
identification, and JSON report generation.

## Supported Platforms

- Ubuntu Linux (Bash)

Other platforms require separate validation.

Automatic installation depends on platform compatibility,
network access, and installation permissions.

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

### Prerequisites

- Git and Bash
- Internet access to download missing tools and vulnerability databases
- Required installation and report directory permissions
- Java JDK, Maven or Gradle when required by the application
- Docker installed and running for Docker image scanning

### Clone the Repository

```bash
git clone https://github.com/sumanthcloudm-sudo/Accidion-repo.git
cd Accidion-repo
```

Specify your application directory when scanning an external project:

```bash
bash security-scan.sh --project-path "/path/to/my-app"
```

Without a configured application path, the current working directory is scanned.

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
PROJECT_ROOT=
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

Reports are generated in the configured output directory
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
- run.log

Successful scanner execution does not mean the application
is free of vulnerabilities. Developers must review the findings
and address identified security issues.

## Documentation

Refer to the [DevOps Security Scanning Guide](Devops%20Security%20Scanning.md)
for detailed execution steps, configuration and report interpretation.
