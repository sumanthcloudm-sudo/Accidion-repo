# Accidion DevOps Security Scanning Guide

## 1. Purpose of Security Scripts

Accidion Security Starter Kit provides automated security scanning,
vulnerability detection, software inventory generation, and security
reporting for developer applications.

The toolkit automatically provisions missing security tools and
provides remediation guidance for identified security findings.

### Script Responsibilities

| File | Purpose |
|---|---|
| security-scan.sh | Main launcher for security scanning |
| python-bootstrap.sh | Automatically installs managed Python when required |
| starter_install.py | Detects and installs missing security tools |
| starter_kit.py | Executes scanners and generates reports |
| starter_findings.py | Consolidates findings and provides remediation guidance |
| security-scan.properties | Accepts application and report output paths |

### Security Tools

| Tool | Security Category | Purpose |
|---|---|---|
| Gitleaks | Secret Scanning | Detect hardcoded passwords, tokens and credentials |
| Semgrep | SAST | Identify insecure source code patterns |
| OWASP Dependency-Check | SCA | Identify vulnerable application dependencies |
| Syft | SBOM | Generate software component inventory |
| Grype | Vulnerability Scanning | Identify package and container vulnerabilities |
| Checkov | IaC Security | Detect infrastructure and Dockerfile misconfigurations |

## 2. Security Scanning Launcher

The security scanning entry point is `security-scan.sh`.

```bash
bash security-scan.sh
```

The launcher automatically:

1. Detects the operating system and architecture.
2. Reads the security scanning properties.
3. Detects and installs compatible Python if missing.
4. Identifies the application technology and build system.
5. Detects and installs missing applicable security tools.
6. Executes applicable security scans.
7. Consolidates findings and remediation guidance.
8. Generates JSON security reports.

Existing compatible Python and security tool installations
are reused automatically.

## 3. Steps to Run Security Scanning

### Prerequisites

| Requirement | Purpose |
|---|---|
| Git | Clone the security starter kit |
| Bash | Execute the security scanning launcher |
| Internet access | Download missing tools and vulnerability databases |
| Installation permissions | Allow automatic tool provisioning |

Java JDK and other build prerequisites may be required depending
on the application technology.

Docker is required only for scanning options that need a local
container build or Docker image access.

### Supported Platforms

- Windows using Git Bash
- Linux using Bash
- macOS using Bash

Windows scanning has been validated. Native Linux and macOS
validation is pending.

### Step 1: Clone the Security Starter Kit

```bash
git clone https://github.com/sumanthcloudm-sudo/Accidion-repo.git
cd Accidion-repo
```

### Step 2: Select the Application

Specify the application directory using --project-path or
optionally configure PROJECT_ROOT in security-scan.properties.

If neither is specified, the current working directory is scanned.

### Step 3: Execute Security Scanning

Choose the security scan based on your application requirements.

#### Complete Security Scan

```bash
bash security-scan.sh --scanner all
```

#### Gitleaks - Secret Scanning

```bash
bash security-scan.sh --scanner gitleaks
```

#### Semgrep - Code Security

```bash
bash security-scan.sh --scanner semgrep
```

#### OWASP Dependency-Check - Dependency Security

```bash
bash security-scan.sh --scanner dependency-check
```

#### Syft - SBOM Generation

```bash
bash security-scan.sh --scanner syft
```

#### Grype - Package Vulnerability Scanning

```bash
bash security-scan.sh --scanner grype
```

Syft is automatically selected when required for package scanning.

#### Checkov - Infrastructure Security

```bash
bash security-scan.sh --scanner checkov
```

#### Multiple Security Scanners

```bash
bash security-scan.sh --scanner gitleaks,semgrep
```

Developers can select any combination of scanner names.

#### Docker-Only Security Scanning

Scan an existing Docker image:

```bash
bash security-scan.sh --scanner grype --image my-app:latest
```

Build and scan a Docker image:

```bash
bash security-scan.sh --scanner grype --build-image
```

Only Grype executes in Docker-only scanning.
Docker must be installed and running.

#### Complete Security Scan with Docker

```bash
bash security-scan.sh --scanner all --build-image
```

Missing required tools are automatically installed where
supported and permitted.

The first execution may take longer because tools and
vulnerability databases need to be downloaded.

Subsequent executions reuse existing tools and cached databases.

### Optional Commands

| Command | Purpose |
|---|---|
| bash security-scan.sh --dry-run | Preview scanning configuration |
| bash security-scan.sh --setup-only | Provision tools without scanning |
| bash security-scan.sh --no-install | Run without installing missing tools |
| bash security-scan.sh --details | Display detailed security findings |
| bash security-scan.sh --verbose | Display verbose execution information |
| bash security-scan.sh --help | Display available options |

## 4. Security Scanning Properties (Optional)

Developers can save reusable scanning preferences in
`security-scan.properties`. Configuration is optional.

### Default Configuration

```properties
PROJECT_ROOT=
OUTPUT_DIR=
SCANNERS=all
DOCKER_IMAGE=
BUILD_IMAGE=false
```

| Property | Description | Default |
|---|---|---|
| PROJECT_ROOT | Application directory | Current working directory |
| OUTPUT_DIR | Report output directory | ~/.accidion/reports/ |
| SCANNERS | Security scanners to execute | all |
| DOCKER_IMAGE | Existing Docker image | Empty |
| BUILD_IMAGE | Build and scan Docker image | false |

### Sample Configuration

Developers can optionally configure application and report paths in `security-scan.properties`.

| Operating System | PROJECT_ROOT | OUTPUT_DIR |
|---|---|---|
| Windows | C:/Projects/my-app | C:/SecurityReports |
| Linux | /home/developer/my-app | /home/developer/reports |
| macOS | /Users/developer/my-app | /Users/developer/reports |

Use absolute paths appropriate for your operating system.

Configuration is optional. Empty values use the default locations.

Report directories are created automatically and must be outside the application directory.


If OUTPUT_DIR is configured, reports are generated under
the specified output directory.

## 5. Security Reports

### Generated Reports

| Report File | Description |
|---|---|
| security-summary.json | Consolidated scanner results and security findings |
| gitleaks-report.json | Detected secrets and credentials |
| semgrep-report.json | Source code security findings |
| dependency-check-report.json | Dependency vulnerabilities and CVE details |
| syft-sbom.json | Software Bill of Materials in CycloneDX format |
| grype-report.json | Package or container vulnerability findings |
| checkov-report.json | Infrastructure and Dockerfile security findings |
| run.log | Scanner execution and troubleshooting information |

Reports are generated for applicable scanners. Failed or skipped
scanners may not generate individual reports.

### Sample Security Finding

```text
Issue Name       : SQL Injection
Scanner          : Semgrep
Severity         : HIGH
Source File      : src/main/Manager.java
Line Number      : 10
Technology       : Java

Security Risk:
Untrusted input may modify the executed SQL query.

Recommended Fix:
Use JDBC PreparedStatement with parameterized queries.

Verification:
Test the corrected query and rerun security scanning.
```

### Severity Classification

| Severity | Description |
|---|---|
| CRITICAL | Highest-priority security findings |
| HIGH | Significant security findings |
| MEDIUM | Moderate security findings |
| LOW | Lower-severity security findings |
| UNKNOWN | Severity unavailable; requires manual review |

### Scanner Execution Status

| Status | Description |
|---|---|
| Success | Scanner execution completed |
| Failed | Scanner execution encountered an error |
| Skipped | Scanner was not applicable or was not executed |

Successful scanner execution does not mean that the application
is free of vulnerabilities.

Developers should review the findings, apply appropriate remediation,
and rerun security scanning to verify the fixes.

Security reports may contain sensitive application information
and must be stored in approved locations.
