# Accidion Starter Kit developer guide

## 1. Overview

Accidion scans an existing Java application for exposed secrets, insecure code, vulnerable dependencies, and infrastructure misconfigurations. It also creates a software bill of materials (SBOM), an inventory of the components in your application.

Run the kit from your application directory. It installs missing tools where permitted and saves the results as JSON so you can review findings, make fixes, and compare subsequent scans.

### Quick Start

1. Open **Git Bash** on Windows or **Bash** on Ubuntu, standalone Linux, or macOS. On macOS, open Terminal and enter `bash`.
2. Follow [Get the reviewed kit](#get-the-reviewed-kit) to clone Accidion into `$HOME/devsecops/Accidion-repo` and check out the full reviewed commit SHA supplied by your release owner or team handover. Keeping the kit separate from your application is the recommended workflow.
3. Replace the example path with your existing Java Maven application directory, then run the launcher from that directory.

   ~~~bash
   cd "$HOME/projects/orders-service" &&
     bash "$HOME/devsecops/Accidion-repo/security-scan.sh"
   ~~~

4. The kit installs missing supported tools automatically where permissions allow. When the scan finishes, open `reports/security-summary.json` in your application directory to see which scans ran and what they found.

## 2. Prerequisites

| Platform | Have ready before you run | What the kit can install |
|---|---|---|
| **Windows** | Git for Windows with **Git Bash**. Use an approved WinGet installation if you need automatic system setup. | Native Windows Python and a JDK through WinGet, plus managed build tools and scanners. |
| **Ubuntu** | **Bash**, approved APT repositories, and an account allowed to use sudo for missing system packages. Run the scan as your normal user. | Python, the matching Python venv package, a JDK, and Git through APT, plus managed build tools and scanners. |
| **Other Linux** | **Bash**. On Debian, Fedora, and supported RHEL-family distributions, have your administrator supply missing system prerequisites for a normal developer account. | Managed build tools and scanners. System package installation through APT, DNF, or YUM requires existing root privileges. |
| **macOS** | **Bash**. Use an existing approved Homebrew installation if you need automatic system setup. | Python, Git, and a JDK through Homebrew, plus managed build tools and scanners. |

The scan needs Python **3.10 or newer** with virtual environment support and Git. For Java dependency analysis, use a **JDK 11 or newer** with `javac` that also meets your application’s build requirements. If your package manager is unavailable or restricted, have IT provide these tools. The kit can supply Maven when needed. Docker is required only for optional image scans.

Allow write access to the project’s `reports/` directory and to your home directory for private reports and tool caches. Installation, dependency resolution, and vulnerability database updates can require access to approved software and artifact repositories.

**Verified coverage.** Windows x86-64 with Git Bash has regression and earlier live-scan coverage. Ubuntu **24.04.5 LTS on x86-64 under WSL 2** completed two live runs. Both exited 0, all six scanners succeeded, and all seven JSON files were validated. The second run reused installed tools and both vulnerability databases. Python and Git were already present, so installation from an absent state was covered by mocks. Live coverage here does not extend to Ubuntu 22.04, standalone Linux, ARM64, or native macOS.

## 3. Getting Started

### Get the reviewed kit

Use the release approved by your team. The public source is available in the [Accidion Starter Kit repository](https://github.com/sumanthcloudm-sudo/Accidion-repo).

Cloning the public repository over HTTPS requires Git. GitHub sign-in is optional for public cloning. The authentication steps below apply when you choose the authenticated release launcher or need access to a private repository.

**Recommended local workflow.** Ask the release owner for the full, 40-character reviewed commit SHA, or get it from your team’s approved release handover. Have it ready before running the commands below. When prompted, paste that full SHA. If you haven’t received it, ask the release owner before running the kit.

~~~bash
mkdir -p "$HOME/devsecops"
git clone https://github.com/sumanthcloudm-sudo/Accidion-repo.git "$HOME/devsecops/Accidion-repo" &&
  read -r -p 'Reviewed full commit SHA: ' reviewed_commit &&
  [[ "$reviewed_commit" =~ ^[0-9a-f]{40}$ ]] &&
  git -C "$HOME/devsecops/Accidion-repo" checkout --detach "$reviewed_commit"
~~~

If your team supplies a complete approved ZIP instead, extract it into `$HOME/devsecops/Accidion-repo` with `security-scan.sh` directly inside that folder. For a private checkout, use the repository and access instructions in your team’s handover.

For an **authenticated release**, open Bash in your Java application directory. The release launcher requires Bash 3.2+, curl 7.83.1+, tar with gzip, `sha256sum` or `shasum`, HTTPS access to GitHub, and a writable temporary directory outside the application. If your release uses GitHub CLI, sign in and complete any required organization SSO.

~~~bash
gh auth login --hostname github.com
gh auth status --hostname github.com
~~~

Run the matching [public release command](README.md#run-from-the-public-github-repository), [private release-asset command](README.md#one-command-from-your-java-project-private-distribution), or [private archive command without GitHub CLI](README.md#alternate-pinned-archive-download-without-github-cli). The public launcher also accepts an approved token supplied through your credential store or a cached Git credential-manager login.

Use the full commit SHA and both SHA-256 digests from the release handover. The launcher verifies its own download and the kit archive before running the scan. If a value is missing or verification fails, ask the release owner for the matching handover. Keep tokens out of command history, scripts, and reports.

### How to Execute security-scan.sh

#### Step 1 — Open the terminal

- **Windows** — Open Git Bash.
- **Ubuntu** — Open a Bash terminal.
- **Standalone Linux** — Open a Bash terminal.
- **macOS** — Open Terminal, type `bash`, and press Enter.

#### Step 2 — Navigate to your Java application

~~~bash
cd ~/projects/orders-service
~~~

`orders-service` is an example application name. Replace `~/projects/orders-service` with the actual path to your Java project. If `cd` reports an error, correct the path before continuing.

#### Step 3 — Verify the application files

~~~bash
pwd
ls
~~~

`pwd` shows your current directory, and `ls` lists its contents. Check that you see the expected project files, such as `pom.xml` and `src/`. A typical Maven project looks like this:

~~~text
orders-service/
├── pom.xml
├── src/
│   ├── main/java/com/example/orders/OrderService.java
│   └── test/java/com/example/orders/OrderServiceTest.java
└── reports/  # Created by a normal scan that reaches report export
~~~

#### Step 4 — Execute the security scan

Choose the command that matches where you saved the kit. By default, the scan targets your **current working directory**, so stay in the application directory for either method.

**Recommended — Keep the kit separate.** From your Java Maven application directory, run the launcher from the checkout created above:

~~~bash
bash "$HOME/devsecops/Accidion-repo/security-scan.sh"
~~~

If you saved the kit elsewhere, adjust the launcher path in the command.

**Alternative — Keep the complete kit inside the application.** This method requires the launcher and all companion files, including the Python modules and scanner configurations, together in the application directory.

~~~bash
bash security-scan.sh
~~~

#### Step 5 — Let the kit install tools and scan

The kit detects your operating system and checks its prerequisites. It reuses compatible tools and installs missing supported tools where permissions allow. For a Maven project, it resolves the Java dependencies. It runs Gitleaks, Semgrep, OWASP Dependency-Check, Syft, Grype, and Checkov as applicable and generates JSON reports.

Let the kit handle scanner installation. Run the script as your normal developer account and reserve `sudo` for individual package operations where authorized. If your organization blocks an installation, ask IT to provide the missing prerequisite.

#### Step 6 — Verify the generated reports

~~~bash
ls -lh reports/
~~~

Open `reports/security-summary.json` first. It tells you which scanners ran, whether they succeeded, and what they found. The individual JSON reports contain details from each scanner, such as affected files, dependency versions, or the software inventory. Use the current summary to confirm which reports were produced by your run. See [Understanding Security Reports](#6-understanding-security-reports) for the report layout and status meanings.

#### Step 7 — Fix vulnerabilities and rescan

Review the findings, fix the issues that apply to your project, and run the same command from Step 4 again. Open the new summary and check that the relevant scanners completed and the findings you addressed are resolved.

## 4. How Automatic Security Scanning Works

~~~mermaid
flowchart LR
    A[Check prerequisites] --> B[Install missing tools]
    B --> C[Resolve Java dependencies]
    C --> D[Run applicable scans]
    D --> E[Save JSON reports]
~~~

On the first run, the kit finds your Java project, checks for compatible tools, and installs what is missing where permissions allow. It uses the Maven wrapper when available or supplies Maven if needed. It resolves dependencies so scanners can examine the libraries your application uses. Java dependency resolution runs when the dependency and inventory stages need it.

Later runs reuse compatible tools and keep the vulnerability databases between scans. Scanners can still refresh their data. The first run can take longer because it downloads tools and initializes those databases.

## 5. Security Tools

| Tool | Purpose | What it scans | JSON report |
|---|---|---|---|
| **Gitleaks** | Finds exposed credentials | Files in the current project tree | `gitleaks-report.json` |
| **Semgrep** | Finds unsafe code patterns | Project files using the kit’s Java and SQL rules | `semgrep-report.json` |
| **OWASP Dependency-Check** | Finds known Java dependency vulnerabilities | Resolved libraries and existing Java archives | `dependency-check-report.json` |
| **Syft** | Creates a CycloneDX SBOM | Application packages and resolved dependencies | `syft-sbom.json` |
| **Grype** | Finds known package vulnerabilities | The Syft SBOM and an optional Docker image | `grype-report.json` |
| **Checkov** | Finds infrastructure misconfigurations | Supported files such as Terraform, Kubernetes manifests, and Dockerfiles | `checkov-report.json` |

The kit selects scanners based on the files it finds. Gitleaks checks the working tree by default. Use your team’s separate secret-audit process if Git history is in scope.

## 6. Understanding Security Reports

A normal run exports the JSON files it generates into your project. A run with all six scanners typically produces this layout:

~~~text
<your-project>/
└── reports/
    ├── security-summary.json
    ├── gitleaks-report.json
    ├── semgrep-report.json
    ├── dependency-check-report.json
    ├── syft-sbom.json
    ├── grype-report.json
    └── checkov-report.json
~~~

The kit also stores a private copy and `run.log` under `$HOME/.accidion/reports/<application-name>/scan-<UTC-timestamp>-<id>/`. Open the current `security-summary.json` first. It shows which tools ran, what they found, and where to find the private reports and log. If a scanner was skipped or failed before writing a report, a same-named file in the project export can be from an older run. Use the current summary to confirm provenance.

- **Scanner status.** `success` means the scanner completed. `skipped` includes a reason, such as no applicable infrastructure files. `failed` means a tool or scan had a problem. Review the reason and log, even if the scanner produced partial JSON.
- **Severity and findings.** Start with exposed credentials and findings that are severe and relevant to your application. Severity comes from the originating scanner, so a dependency scanner’s `HIGH` and a Semgrep rule’s `ERROR` use different scales. `UNKNOWN` means the scanner supplied no severity. Inspect the file, line, package, or resource and any recommended fix.
- **Exit status.** `0` means the requested operation completed without a required installation or scanner failure. A scan can exit 0 and still report vulnerabilities. `1` means a required tool or scanner failed. `2` indicates a usage, launcher, or top-level error.

Treat reports, logs, and SBOMs as sensitive. Keep them out of version control and share them only through approved channels.

## 7. Fix Vulnerabilities and Rescan

1. **Check coverage.** Resolve unexpected scanner failures or skips before relying on the results.
2. **Fix the source of the finding.** Revoke or rotate exposed credentials and remove them from application files. Correct unsafe code, such as by using parameterized SQL. Upgrade vulnerable dependencies to a compatible fixed release. For a transitive dependency, update the library that brings it in or apply an approved version constraint. Correct infrastructure findings in the relevant templates or Dockerfiles.
3. **Verify the fix.** Run your normal application tests, then repeat the scan command from [Getting Started](#3-getting-started). Compare the new summary with the previous private run and confirm that the relevant scanner completed and the finding is resolved.

Run the kit on projects you trust. Maven wrappers and build logic can execute project code, as can an explicitly requested Docker build.

## 8. Advanced Options

Append an option to your usual launcher command.

| Option | Purpose |
|---|---|
| `--project-path PATH` | Scan a specific directory. Defaults to the current directory. |
| `--dry-run` | Preview discovery without installing tools, running scanners, or writing reports. If Python is missing, the preview reports that prerequisite. |
| `--setup-only` | Install or verify tools and write a private setup summary without running scanners. |
| `--no-install` | Use compatible existing tools and a build CLI. Dependency downloads and vulnerability data updates can still use the network. |
| `--report-dir PATH` | Move the private report parent outside the project. Normal project JSON export still uses `reports/`. |
| `--image IMAGE` | Scan an existing local Docker image. |
| `--build-image` | Build and scan the image from the root Dockerfile or the only discovered Dockerfile. |
| `-h` or `--help` | Show launcher usage. |

Choose at most one of `--dry-run`, `--setup-only`, and `--no-install`. Choose at most one image option. Docker image options require approved access to a running Docker daemon.

## 9. Troubleshooting

| Problem | What to do |
|---|---|
| Download or authentication fails | Check GitHub access, SSO, and `curl --version`. For a checksum mismatch, request the exact command and digests for the approved release. |
| Installation is denied or a tool is missing | Read the package or tool name in the error. Confirm the approved package manager or ask IT to provision the prerequisite. Use `--no-install` once the required tools are present. Avoid running the entire scan with sudo. |
| Semgrep or Checkov cannot install | Check the selected Python version, venv support, configured package index, and wheel availability for your architecture. Consult the private log for the failing package. |
| Maven dependency resolution fails | Check that the correct POM was discovered and the compatible JDK is selected. Review the private log for the missing artifact or repository error. Confirm Maven settings, mirror access, and credentials. |
| Downloads fail behind a proxy | Check your approved proxy, certificate, and repository settings. Ask IT to confirm access to the package source or vulnerability feed. |
| Dependency-Check takes a long time | Check the terminal and private log for update progress. In the verified Ubuntu run, the first NVD database download took about 25 minutes. Keep the existing cache for subsequent runs. |
| A vulnerability database fails to update | Check the private log for network or proxy errors and confirm that the database cache is writable. Restore access to the approved feed and rerun the scan. |
| A report is absent or appears stale | Check the latest summary for a skipped or failed scanner. Verify project write access and run a normal scan to export JSON. |
| Windows prints a temporary directory cleanup warning | Check the reported exit status and summary. Use the current reviewed release, and wait for the directory handle to be released before removing the retained directory. |
