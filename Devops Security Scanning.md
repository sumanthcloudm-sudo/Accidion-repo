# Accidion Developer Guide

This guide is for a developer who has **already developed a Java application on their own laptop** and wants to scan that application for security findings using Accidion.

Accidion is designed to run from **Windows (Git Bash), Linux (Bash), or macOS (Bash)**. Native end-to-end verification is not complete on every platform; tool availability and installation depend on the OS, architecture, permissions, and network access.

## 1. Purpose of the security scripts

Accidion is a separate security toolkit. **Do not copy Accidion into your Java application or replace your application's code.**

When you run the launcher against your own application, Accidion:

1. Uses your current working directory as the **application root**, unless you provide a different path.
2. Discovers supported files inside that root, such as Java source, \`pom.xml\`, Gradle build files, JAR/WAR/EAR archives, Dockerfiles, and supported infrastructure files.
3. Detects the operating system and CPU architecture.
4. Verifies or, where supported and permitted, installs required tools; existing compatible tools and cached data may be reused.
5. Runs the selected **applicable** scanners and records skipped or failed checks.
6. Creates private JSON reports, a consolidated findings summary, and a diagnostic log.

**Automatic detection means detecting supported files within the application directory you selected.** Accidion does **not** search your entire laptop, automatically choose among unrelated projects, or guarantee that every scanner is applicable.

| Security tool | What it checks |
| --- | --- |
| Gitleaks | Potential exposed secrets and credentials |
| Semgrep | Source-code patterns and static security rules |
| OWASP Dependency-Check | Known vulnerabilities in applicable Java dependencies |
| Syft | Software Bill of Materials (SBOM) and component inventory |
| Grype | Known package vulnerabilities; optionally a Docker image |
| Checkov | Supported infrastructure-as-code and Dockerfile policies |

Detection does not mean automatic remediation. Developers review findings, update their **own application**, test it, and rescan.

## 2. Security scanning launcher: security-scan.sh

**Main launcher:** [security-scan.sh](security-scan.sh)

The actual \`security-scan.sh\` is included in the Accidion GitHub repository. You do **not** need to create another script or paste the launcher into your Java project. The launcher uses the other files shipped with the kit.

Basic usage, from **your Java application root**:

\`\`\`bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh"
\`\`\`

That command runs the default selection of scanners (\`all\`). Accidion checks which scanners apply to your files; it can skip non-applicable checks.

You can also specify the application explicitly from another directory:

\`\`\`bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --project-path "/path/to/my-java-app"
\`\`\`

Useful options:

| Option | Purpose |
| --- | --- |
| \`--scanner all\` | Run all applicable scanner types (default) |
| \`--scanner gitleaks,semgrep\` | Run a selected combination |
| \`--project-path PATH\` | Select the application root instead of the current directory |
| \`--report-dir PATH\` | Select a private report parent directory **outside** the application |
| \`--dry-run\` | Preview project discovery without a security scan |
| \`--setup-only\` | Prepare applicable tools without scanning |
| \`--no-install\` | Do not install missing kit-managed tools |
| \`--details\` | Display more finding evidence in the terminal |
| \`--verbose\` | Display scanner and dependency-resolution diagnostics |
| \`--image IMAGE\` | Include scanning an existing local Docker image |
| \`--build-image\` | Build and scan an application Docker image if a suitable Dockerfile exists |
| \`--help\` | Show launcher options |

Docker image scanning requires Docker to be installed, running, and accessible. Use only images you are authorized to scan.

## 3. Steps to run Accidion on your own Java application

### Step 1 — Develop, build, and test your Java application

For example, your laptop may already contain:

\`\`\`text
my-java-app/
  pom.xml
  src/
    main/
      java/
  Dockerfile                 # optional
  infrastructure/            # optional
\`\`\`

Your application can use Maven or Gradle. Finish its normal build and tests before scanning. Your real source and build files remain in **your own application directory**.

### Step 2 — Check prerequisites on your laptop

- **Windows:** open **Git Bash**. Use a supported native Windows Python installation.
- **Linux:** open **Bash**.
- **macOS:** open **Bash**.
- **All platforms:** Git, a writable home directory, and approved network access are needed for cloning and first-run downloads.
- **Python:** 3.10 or newer and compatible environment support are required by the runner.
- **Java builds/dependency checks:** use an appropriate JDK (Java 11 or newer for Dependency-Check), Maven/Gradle as applicable, and reachable approved dependency repositories.
- **Docker:** optional, only for image scanning.

Accidion may provision some missing prerequisites/tools on supported systems, but it does not bypass administrator permissions, system security policy, or network restrictions. If an essential prerequisite cannot be provisioned, obtain an approved installation.

### Step 3 — Clone the Accidion kit once

Run these commands in Git Bash or Bash:

\`\`\`bash
mkdir -p "$HOME/devsecops"
git clone https://github.com/sumanthcloudm-sudo/Accidion-repo.git "$HOME/devsecops/Accidion-repo"
\`\`\`

This is a **one-time clone**. Keep it separate from your Java application. In a team environment, use the organization-approved version/revision of the kit.

### Step 4 — Enter your Java application's root directory

The next command is an **example**, not an automatic location.

For Windows Git Bash:

\`\`\`bash
cd "/c/Users/yourname/projects/my-java-app"
\`\`\`

For Linux or macOS:

\`\`\`bash
cd "$HOME/projects/my-java-app"
\`\`\`

**Replace the example path with the actual path to your Java application.** The folder you enter is what Accidion scans. If you do not want to change directories, use \`--project-path\` instead.

### Step 5 — Run one security scanning command

From your Java application root:

\`\`\`bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh"
\`\`\`

Accidion discovers the applicable project files, checks required tools, runs applicable scanners, and prints progress and the **exact report directory**.

If you first want to see what Accidion detects without running scans:

\`\`\`bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --dry-run
\`\`\`

The first full run may download tools, Java dependencies, or vulnerability databases. Missing prerequisites, unsupported scanner packages, build problems, and blocked downloads can cause scans to fail or be skipped. Read the reported statuses rather than assuming every tool ran.

### Step 6 — Fix findings in your Java application and rescan

Open the new \`security-summary.json\`, review the scanner statuses and findings, then open the reported files in your own Java application. Fix confirmed vulnerabilities, rebuild, rerun tests, and repeat the **same** security-scan command.

**Next time:** do **not** clone the kit again. Open a terminal, enter your application's root, and repeat Step 5.

## 4. Optional properties file: application root and output path

**Configuration file:** [security-scan.properties](security-scan.properties), inside the **Accidion kit directory**.

The file is optional. If left blank, the launcher scans the **current working directory** and writes reports under a private default directory. You do not need to change the properties file for normal use.

Default properties shipped with the kit:

\`\`\`properties
PROJECT_ROOT=
OUTPUT_DIR=
SCANNERS=all
DOCKER_IMAGE=
BUILD_IMAGE=false
\`\`\`

| Property | Purpose | Default behavior |
| --- | --- | --- |
| \`PROJECT_ROOT\` | Path to the developer's Java application | Current directory |
| \`OUTPUT_DIR\` | Parent directory for private scan reports | \`~/.accidion/reports/\` |
| \`SCANNERS\` | \`all\` or comma-separated scanner names | \`all\` |
| \`DOCKER_IMAGE\` | Existing authorized local Docker image name | Empty; no explicit image requested |
| \`BUILD_IMAGE\` | Build and scan a Docker image | \`false\` |

Example for a Linux or macOS developer who wants fixed paths:

\`\`\`properties
PROJECT_ROOT=/home/yourname/projects/my-java-app
OUTPUT_DIR=/home/yourname/security-reports
SCANNERS=all
DOCKER_IMAGE=
BUILD_IMAGE=false
\`\`\`

Replace those paths with the actual application and report paths. On Windows, use the paths appropriate to Git Bash/your filesystem instead; do not copy Linux paths to Windows. **The report directory must be outside your application directory** to avoid accidentally scanning or committing sensitive results.

Alternatively, keep properties at their defaults and pass values directly:

\`\`\`bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh" --project-path "/path/to/my-java-app" --report-dir "/path/to/private-reports"
\`\`\`

Explicit command-line options take precedence over corresponding properties. The kit's properties file is read when the launcher starts; it is not a file you put inside every developer application.

## 5. Security reports: where to find them and how to read them

After a scan, Accidion prints the **exact report location**. By default, reports are saved privately on the developer's laptop under:

\`\`\`text
~/.accidion/reports/<application-name>/scan-<timestamp>-<id>/
\`\`\`

A new scan creates a separate run directory. Your application source is **not automatically modified**, and scan reports are **not automatically committed to your Java application's Git repository**.

| Report file | What the developer learns |
| --- | --- |
| \`security-summary.json\` | **Start here.** Application name, scanner statuses, detected findings, severity, source location when available, remediation guidance and evidence |
| \`gitleaks-report.json\` | Potential exposed secrets |
| \`semgrep-report.json\` | Static-code rule findings and scanner errors |
| \`dependency-check-report.json\` | Dependency vulnerabilities and available CVE evidence |
| \`syft-sbom.json\` | Component inventory (SBOM); not a vulnerability list |
| \`grype-report.json\` | Known vulnerable packages or image components |
| \`checkov-report.json\` | Supported infrastructure policy failures |
| \`run.log\` | Redacted execution diagnostics and scanner/build errors |

An image scan alongside package scanning can also produce \`grype-sbom-report.json\`; a Maven scan may produce a dependency-tree JSON file. **Only reports produced by applicable, completed stages may be present.** A missing file may indicate an unselected, skipped, or failed scanner.

### How a developer uses the findings

1. Open \`security-summary.json\` in VS Code or another JSON viewer.
2. Check each scanner's \`status\` and reason. A skipped or failed scanner is **not** evidence of a clean scan.
3. Review \`issues\`, especially \`scanner_name\`, \`issue_name\`, \`severity\`, \`source_file\` or \`relative_file_path\`, \`start_line\` when available, \`affected_dependency\`, and \`recommended_remediation\`.
4. Open the actual source file, manifest, or infrastructure file in **your application**. Dependency findings may identify a package instead of a line number.
5. Fix the problem, rebuild and test the application, and run the scan again.

Do not publish reports containing sensitive project information or credentials. Scanner results may require manual triage and approved risk decisions. A completed scan or a process exit code of zero does **not** prove your application has zero vulnerabilities.

---

**Developer workflow in one sentence:** Build and test your own Java application → clone Accidion once → enter that application's root → run \`security-scan.sh\` → review private JSON findings → fix your application → rescan.
