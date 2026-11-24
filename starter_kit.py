"""Discover and scan an existing Java project, with private per-run JSON reports."""
import argparse
import csv
from collections import Counter
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

from starter_install import Installer, detect, refresh_windows_path, run
from starter_findings import NAMES, NORMALIZE, Redactor, capture_secrets, issue_identifier

KIT = Path(__file__).resolve().parent
REPORTS = {
    "gitleaks": "gitleaks-report.json", "semgrep": "semgrep-report.json",
    "dependency-check": "dependency-check-report.json", "syft": "syft-sbom.json",
    "grype": "grype-report.json", "checkov": "checkov-report.json",
}
GENERATED_JSON = (*REPORTS.values(), "grype-sbom-report.json", "security-summary.json")
IGNORED = {".git", ".gradle", ".venv", "venv", "node_modules", ".terraform",
           ".cache", "__pycache__", ".pytest_cache", "reports"}
INFRA = (".tf", ".tf.json", ".bicep")
IAC_MARKERS = re.compile(r'(?m)^\s*(?:apiVersion|AWSTemplateFormatVersion|Resources)\s*:|'
                         r'"(?:apiVersion|AWSTemplateFormatVersion|Resources|[$]schema)"\s*:')


def infrastructure_file(path):
    if path.name.lower().endswith(INFRA):
        return True
    if path.suffix.lower() not in {".json", ".yaml", ".yml", ".template"}:
        return False
    with path.open(encoding="utf-8-sig", errors="replace") as source:
        return bool(IAC_MARKERS.search(source.read(256 * 1024)))


def discover(project):
    files = {kind: [] for kind in ("java", "maven", "gradle", "jars", "dockerfiles", "iac", "opentofu")}

    def raise_walk_error(error):
        raise error

    for directory, dirs, names in os.walk(project, onerror=raise_walk_error):
        base = Path(directory)
        dirs[:] = sorted(d for d in dirs if d not in IGNORED and not (base / d).is_symlink())
        generated = bool(set(base.relative_to(project).parts) & {"build", "target"})
        for name in sorted(names):
            path = base / name
            if path.is_symlink() or not path.is_file():
                continue
            lower = name.lower()
            if lower.endswith((".jar", ".war", ".ear")):
                if name not in {"gradle-wrapper.jar", "maven-wrapper.jar"}:
                    files["jars"].append(path)
            elif generated:
                continue
            elif lower.endswith(".java"):
                files["java"].append(path)
            elif name == "pom.xml":
                files["maven"].append(path)
            elif name in {"settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts"}:
                files["gradle"].append(path)
            elif lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile"):
                files["dockerfiles"].append(path)
            elif lower.endswith((".tofu", ".tofu.json")):
                files["opentofu"].append(path)
            elif infrastructure_file(path):
                files["iac"].append(path)
    return files


def build_roots(files, family):
    candidates = sorted({p.parent for p in files[family]}, key=lambda p: (len(p.parts), str(p)))
    roots = []
    for parent in candidates:
        if not any(parent.is_relative_to(root) for root in roots):
            roots.append(parent)
    return roots


def application_name(project, roots):
    maven = roots["maven"]
    candidates = [project] if project in maven else maven if len(maven) == 1 else []
    for root in candidates:
        try:
            pom = ElementTree.parse(root / "pom.xml").getroot()
        except (OSError, ElementTree.ParseError):
            continue
        for field in ("name", "artifactId"):
            if value := (pom.findtext(f"{{*}}{field}") or "").strip():
                return value
    gradle = roots["gradle"]
    candidates = [project] if project in gradle else gradle if len(gradle) == 1 else []
    for root in candidates:
        for name in ("settings.gradle", "settings.gradle.kts"):
            try:
                with (root / name).open(encoding="utf-8", errors="replace") as settings:
                    match = re.search(r"""(?m)^\s*rootProject\.name\s*=\s*(['"])([^'"\r\n]+)\1""",
                                      settings.read(256 * 1024))
            except OSError:
                continue
            if match:
                return match[2]
    return project.name


def wrapper_for(root, family, system):
    name = ("mvnw.cmd" if family == "maven" else "gradlew.bat") if system == "windows" else (
        "mvnw" if family == "maven" else "gradlew"
    )
    path = root / name
    if path.is_file() and not path.is_symlink():
        return [str(path)] if system == "windows" else ["bash", str(path)]
    return None


def write_json(path, content):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(content, output, indent=2, ensure_ascii=False)
        output.write("\n")
    temporary.replace(path)


def report_application_directory(name):
    label = re.sub(r"[^A-Za-z0-9_-]+", "-", name).strip("-_").lower()[:80].rstrip("-_")
    if re.fullmatch(r"con|prn|aux|nul|com[0-9]|lpt[0-9]", label):
        label = f"app-{label}"
    return label or "application"


def private_run_path(parent):
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = Path(tempfile.mkdtemp(prefix=f"scan-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-", dir=parent))
    if os.name == "nt":
        try:
            system = Path(os.environ["SystemRoot"]) / "System32"
            identity = run([system / "whoami.exe", "/user", "/fo", "csv", "/nh"], capture=True, timeout=30)
            sid = next(csv.reader(identity.splitlines()))[-1]
            if not sid.startswith("S-1-"):
                raise RuntimeError("Could not confirm the current Windows account SID")
            run([system / "icacls.exe", path, "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F"],
                capture=True, timeout=30)
        except Exception:
            path.rmdir()
            raise
    else:
        path.chmod(0o700)
    return path


def native_finding_count(name, report):
    if name == "gitleaks":
        return len(report or [])
    if name == "semgrep":
        return len(report["results"])
    if name == "dependency-check":
        return sum(len(item.get("vulnerabilities") or []) for item in report["dependencies"])
    if name == "grype":
        return len(report["matches"])
    if name == "checkov":
        return sum(len(scan["results"].get("failed_checks") or [])
                   for scan in (report if isinstance(report, list) else [report]))
    return 0  # Syft reports inventory.


def report_error(name, report):
    if name == "semgrep" and report.get("errors"):
        return "Semgrep reported scan errors. See the individual report."
    if name == "checkov" and any(scan["summary"].get("parsing_errors")
                                for scan in (report if isinstance(report, list) else [report])):
        return "Checkov reported parsing errors. See the individual report."
    return None


def terminal_issue(issue):
    def safe(value):
        return "".join(character if character.isprintable() else " " for character in str(value))

    line = issue["start_line"] or "unknown"
    if issue["start_line"] and issue["end_line"] and issue["start_line"] != issue["end_line"]:
        line = f"{issue['start_line']}-{issue['end_line']}"
    print(f"Issue {issue['issue_number']}: {safe(issue['issue_name'])}\n"
          f"  Tool: {issue['scanner_name']} | Severity: {safe(issue['severity'])}\n"
          f"  Source: {safe(issue['source_file'] or 'unknown')} | Line: {line}\n"
          f"  Recommended fix: {safe(issue['recommended_remediation'])}", flush=True)


def select_dockerfile(files, project):
    dockerfiles = files["dockerfiles"]
    root = [p for p in dockerfiles if p.parent == project and p.name == "Dockerfile"]
    if len(root) == 1:
        return root[0]
    return dockerfiles[0] if len(dockerfiles) == 1 else None


def resolve_dependencies(project, builds, out, log):
    for index, (family, root, tool) in enumerate(builds):
        if not tool:
            raise RuntimeError(f"No usable {family} build tool for {root.relative_to(project)}")
        target = out / str(index)
        target.mkdir()
        if family == "maven":
            args = [*tool, "-B", "-f", root / "pom.xml",
                    "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies",
                    "-Dmdep.useRepositoryLayout=true",
                    f"-DoutputDirectory={target}"]
        else:
            args = [*tool, "--no-daemon", "--no-configuration-cache", "--console=plain", "--init-script",
                    KIT / "accidion-dependencies.gradle", f"-PaccidionDependencyDirectory={target}",
                    "accidionCollectDependencies"]
        run(args, cwd=root, log=log)


def args_for(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-path", type=Path, default=Path.cwd())
    parser.add_argument("--report-dir", type=Path, help="Parent report directory outside the scan target")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--dry-run", action="store_true")
    modes.add_argument("--setup-only", action="store_true")
    parser.add_argument("--no-install", action="store_true")
    images = parser.add_mutually_exclusive_group()
    images.add_argument("--image", help="Scan a locally available Docker image")
    images.add_argument("--build-image", action="store_true", help="Build the discovered Dockerfile locally")
    return parser.parse_args(argv)


def execute(options, system, arch):
    os.umask(0o077)
    project = options.project_path.resolve(strict=True)
    if not project.is_dir():
        raise ValueError("Project path must be a directory")
    files = discover(project)
    roots = {family: build_roots(files, family) for family in ("maven", "gradle")}
    app_name = application_name(project, roots)
    application_directory = report_application_directory(app_name)
    dockerfile = select_dockerfile(files, project)
    image_requested = bool(options.image or (options.build_image and dockerfile))
    java_app = bool(files["java"] or files["jars"] or files["maven"] or files["gradle"])
    java_needed = bool(files["jars"] or files["maven"] or files["gradle"])
    applicability = {
        "gitleaks": None,
        "semgrep": None if java_app else "No Java application inputs",
        "dependency-check": None if java_needed else "No Maven/Gradle build files or Java archives",
        "syft": None if java_app else "No Java application inputs",
        "grype": None if java_app or options.image or options.build_image else "No Java SBOM or container target",
        "checkov": None if files["iac"] or files["dockerfiles"] else (
            "OpenTofu files found, but native .tofu/.tofu.json coverage is unavailable"
            if files["opentofu"] else "No supported infrastructure candidates"),
    }
    discovery = {key: len(items) for key, items in files.items()}
    if options.dry_run:
        print(json.dumps({"platform": system, "architecture": arch, "project": str(project),
                          "applicationName": app_name, "reportApplicationDirectory": application_directory,
                          "discovery": discovery, "buildRoots": {
                              k: [str(p.relative_to(project)) for p in v] for k, v in roots.items()},
                          "installMissing": not options.no_install,
                          "scanContainer": image_requested, "scanners": applicability}, indent=2))
        return 0

    home = Path(os.environ.get("ACCIDION_HOME", Path.home() / ".accidion")).resolve()
    report_parent = (options.report_dir or home / "reports").resolve()
    application_reports = (report_parent / application_directory).resolve()
    cache = (home / "tools").resolve()
    if (report_parent.is_relative_to(project) or cache.is_relative_to(project)
            or application_reports.is_relative_to(project) or application_reports.parent != report_parent):
        raise ValueError("Report and tool directories must be outside the project being scanned")
    report_dir = private_run_path(application_reports)
    started = datetime.now(timezone.utc)
    redactor = Redactor()
    statuses = {}
    issues = []
    issue_ids = Counter()
    vulnerability_caches = {}

    def vulnerability_cache(scanner, location):
        path = location.expanduser().resolve()
        if path.is_relative_to(project):
            raise ValueError("Vulnerability cache must be outside the scanned project")
        if scanner not in vulnerability_caches:
            vulnerability_caches[scanner] = {
                "path": str(path), "presentBeforeScan": path.is_dir() and any(path.iterdir()),
            }
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    with tempfile.TemporaryFile(mode="w+", dir=report_dir, encoding="utf-8", errors="replace") as log:
        installer = Installer(system, arch, cache, not options.no_install, log)
        installer.records["python"] = {
            "status": "installed" if os.getenv("ACCIDION_PYTHON_BOOTSTRAPPED") else "reused",
            "version": ".".join(map(str, sys.version_info[:3])),
        }
        refresh_windows_path()
        installer.ensure("git")
        java = installer.ensure("java") if java_needed or options.setup_only else None
        builds = []
        for family, directories in roots.items():
            name = "mvn" if family == "maven" else "gradle"
            for root in directories:
                wrapper = wrapper_for(root, family, system)
                # Wrapper version probes can provision a distro. Setup-only and no-install
                # never invoke wrappers as part of preflight.
                if wrapper and (options.setup_only or options.no_install):
                    if options.setup_only:
                        installer.records[f"{name}:{root.relative_to(project)}"] = {"status": "deferred", "reason": "Project wrapper is verified during an installation-enabled scan"}
                        continue
                    wrapper = None
                tool = installer.ensure(name, wrapper=wrapper, cwd=root) if java else None
                if java:
                    installer.records[f"{name}:{root.relative_to(project)}"] = installer.records.pop(name)
                builds.append((family, root, tool))
        docker = installer.ensure("docker") if image_requested else None
        tools = {}
        for name, reason in applicability.items():
            if reason and not options.setup_only:
                installer.records[name] = {"status": "skipped", "reason": reason}
                tools[name] = None
            else:
                tools[name] = installer.ensure(name)
        log.flush()

        def execute_scan(name, action, skip=None):
            label = NAMES.get(name, "Syft")
            installation = installer.records[name]
            entry = {"status": "skipped", "reason": skip, "report": None,
                     "version": installation.get("version"), "installationStatus": installation["status"],
                     "findingCount": None, "nativeFindingCount": None, "findings": []}
            statuses[name] = entry
            if name == "checkov" and files["opentofu"]:
                entry["unsupportedInputs"] = [
                    str(path.relative_to(project)) for path in files["opentofu"]
                ]
            if skip:
                print(f"{label}: skipped ({skip})", flush=True)
                return
            if not tools[name]:
                entry.update(status="failed", reason=installation.get("reason"))
                print(f"{label}: failed to provide a compatible executable", flush=True)
                return
            raw_output = work / REPORTS[name]
            problems = []
            print(f"{label}: running", flush=True)
            try:
                action(tools[name], raw_output)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
                problems.append(str(error))
            image_selected = bool(options.image or options.build_image)
            artifacts = [(raw_output, "container" if image_selected else "sbom")]
            if name == "grype" and image_selected and java_app:
                artifacts.insert(0, (work / "grype-sbom-report.json", "sbom"))
                entry["additionalReports"] = []
            for native, target in artifacts:
                try:
                    with native.open(encoding="utf-8-sig") as source:
                        report = json.load(source)
                    if name == "gitleaks":
                        redactor.add(capture_secrets(report))
                    output = report_dir / native.name
                    write_json(output, redactor.data(report, native=True))
                    if native == raw_output:
                        entry["report"] = str(output)
                    else:
                        entry["additionalReports"].append(str(output))
                    native_count = native_finding_count(name, report)
                    entry["nativeFindingCount"] = (entry["nativeFindingCount"] or 0) + native_count
                    if name == "syft":
                        if report.get("bomFormat") != "CycloneDX":
                            raise ValueError("Expected a CycloneDX SBOM")
                        entry["inventoryCount"] = len(report.get("components", []))
                    else:
                        for item in NORMALIZE[name](report, project):
                            item = redactor.data(item)
                            item["issue_id"] = issue_identifier(item)
                            if name == "grype":
                                item["scan_target"] = target
                                item["issue_id"] += f"-{target}"
                            issue_ids[item["issue_id"]] += 1
                            occurrence = issue_ids[item["issue_id"]]
                            if occurrence > 1:
                                item["issue_id"] += f"-{occurrence}"
                            item["issue_number"] = len(issues) + 1
                            issues.append(item)
                            entry["findings"].append(item)
                            terminal_issue(item)
                    if reason := report_error(name, report):
                        problems.append(reason)
                except FileNotFoundError:
                    problems.append(f"Scanner did not write {native.name}")
                except (OSError, ValueError, TypeError, AttributeError, KeyError, RuntimeError) as error:
                    problems.append(f"Could not interpret {native.name}: {error}")
            if entry["report"] or entry.get("additionalReports"):
                entry["findingCount"] = len(entry["findings"])
                if entry["nativeFindingCount"] != entry["findingCount"]:
                    problems.append(f"Native findings ({entry['nativeFindingCount']}) differ from normalized "
                                    f"findings ({entry['findingCount']}); inspect the individual report")
            entry.update(status="failed" if problems else "success",
                         reason=redactor.text("; ".join(problems)) if problems else None)
            if name == "syft":
                inventory = entry.get("inventoryCount", "unavailable")
                print(f"{label}: {entry['status']} | SBOM components: {inventory}", flush=True)
            else:
                print(f"{label}: {entry['status']} | {len(entry['findings'])} issues", flush=True)
            log.flush()

        def invoke(cmd, *args, accepted=(0,), env=None):
            print(f"\n--- {Path(cmd[0]).name} ---", file=log, flush=True)
            run([*cmd, *args], cwd=project, log=log, accepted=accepted, env=env)

        with tempfile.TemporaryDirectory(prefix="work-", dir=report_dir) as directory:
            work = Path(directory)
            deps = work / "dependencies"
            deps.mkdir()
            resolution_error = None
            resolved_dependencies = False

            def prepare_dependencies():
                nonlocal resolution_error, resolved_dependencies
                if resolved_dependencies:
                    return
                resolved_dependencies = True
                try:
                    resolve_dependencies(project, builds, deps, log)
                except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                    resolution_error = str(error)

            def dependency_check(cmd, out):
                if not java:
                    raise RuntimeError("A compatible JDK is unavailable")

                prepare_dependencies()

                if resolution_error:
                    raise RuntimeError(
                        f"Dependency resolution failed: {resolution_error}"
                    )

                database = vulnerability_cache(
                    "dependency-check",
                    home / "dependency-check-data"
                )

                args = [
                    "--project", project.name,
                    "--format", "JSON",
                    "--out", out.parent,
                    "--data", database,
                    "--scan", deps,
                    "--disableOssIndex"
                ]

                for artifact in files["jars"]:
                    args.extend(("--scan", artifact))

                invoke(cmd, *args)

                report = json.loads(
                    out.read_text(encoding="utf-8")
                )

                if not report.get("dependencies"):
                    raise RuntimeError(
                        "Dependency-Check detected no dependencies."
                    )

            def syft(cmd, out):
                # Inventory the resolved dependencies independently of the original project
                # so package-manager dependencies and existing application artifacts are represented.
                prepare_dependencies()
                if resolution_error:
                    raise RuntimeError(f"Dependency resolution failed: {resolution_error}")
                excludes = [flag for file in GENERATED_JSON for flag in ("--exclude", f"**/{file}")]
                invoke(cmd, "scan", f"dir:{project}", "--exclude", "**/.git/**", *excludes,
                       "-o", f"cyclonedx-json={out}")
                if not builds:
                    return
                resolved = work / "resolved-sbom.json"
                invoke(cmd, "scan", f"dir:{deps}", "-o", f"cyclonedx-json={resolved}")
                report = json.loads(out.read_text(encoding="utf-8"))
                extra = json.loads(resolved.read_text(encoding="utf-8"))
                components = {row.get("bom-ref") or row.get("purl"): row for row in report.get("components", [])}
                for row in extra.get("components", []):
                    components.setdefault(row.get("bom-ref") or row.get("purl"), row)
                report["components"] = list(components.values())
                references = {}
                for item in (*report.get("dependencies", []), *extra.get("dependencies", [])):
                    references.setdefault(item["ref"], set()).update(item.get("dependsOn", []))
                # Anchor the dependency graph from the second directory at the project BOM root.
                main_ref = report.get("metadata", {}).get("component", {}).get("bom-ref")
                extra_ref = extra.get("metadata", {}).get("component", {}).get("bom-ref")
                if main_ref and extra_ref and main_ref != extra_ref:
                    references.setdefault(main_ref, set()).update(references.pop(extra_ref, set()))
                    for targets in references.values():
                        if extra_ref in targets:
                            targets.remove(extra_ref)
                            targets.add(main_ref)
                report["dependencies"] = [{"ref": ref, "dependsOn": sorted(targets)}
                                          for ref, targets in references.items()]
                write_json(out, report)

            def run_grype(cmd, target, out):
                database = vulnerability_cache("grype", Path(os.environ.get("GRYPE_DB_CACHE_DIR") or home / "grype-db"))
                invoke(cmd, target, "-o", "json", "--file", out,
                       env={**os.environ, "GRYPE_DB_CACHE_DIR": str(database)})

            def grype_sbom(cmd, out):
                if statuses["syft"]["status"] != "success":
                    raise RuntimeError("A successful Syft SBOM is required for package scanning")
                run_grype(cmd, f"sbom:{work / REPORTS['syft']}", out)

            def grype_image(cmd, out):
                if options.build_image and not dockerfile:
                    raise RuntimeError("Select a project with one Dockerfile or a root Dockerfile, or supply --image")
                if not docker:
                    raise RuntimeError("Docker CLI is unavailable")
                invoke(docker, "info", "--format", "{{.ServerVersion}}")
                archive = work / "image.tar"
                image = options.image or f"accidion-scan:{report_dir.name.lower()}"
                built = False
                try:
                    if options.build_image:
                        invoke(docker, "build", "-f", dockerfile, "-t", image, dockerfile.parent)
                        built = True
                    invoke(docker, "image", "save", "-o", archive, image)
                    run_grype(cmd, f"docker-archive:{archive}", out)
                finally:
                    if built:
                        invoke(docker, "image", "rm", image)

            def grype(cmd, out):
                if not image_requested and not options.build_image:
                    grype_sbom(cmd, out)
                    return
                errors = []
                if java_app:
                    try:
                        grype_sbom(cmd, work / "grype-sbom-report.json")
                    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                        errors.append(f"Package scan: {error}")
                try:
                    grype_image(cmd, out)
                except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                    errors.append(f"Image scan: {error}")
                if errors:
                    raise RuntimeError("; ".join(errors))

            def checkov(cmd, out):
                checkov_dir = work / "checkov"
                checkov_dir.mkdir()
                raw = checkov_dir / "results_json.json"
                try:
                    invoke(cmd, "--config-file", KIT / ".checkov.yml", "--skip-download", "--file",
                           *files["iac"], *files["dockerfiles"], "--output", "json",
                           "--output-file-path", checkov_dir, "--soft-fail")
                finally:
                    if raw.is_file():
                        shutil.move(raw, out)

            setup = "Setup-only mode" if options.setup_only else None
            execute_scan("gitleaks", lambda cmd, out: invoke(
                cmd, "dir", project, "--config", KIT / ".gitleaks.toml",
                "--report-format", "json", "--report-path", out, "--redact=0", "--exit-code", "0"), setup)
            execute_scan("semgrep", lambda cmd, out: invoke(
                cmd, "scan", "--config", KIT / "semgrep.yml", "--metrics=off", "--disable-version-check",
                *(f"--exclude={filename}" for filename in GENERATED_JSON),
                "--json", "--output", out, project), setup or applicability["semgrep"])
            execute_scan("dependency-check", dependency_check, setup or applicability["dependency-check"])
            execute_scan("syft", syft, setup or applicability["syft"])
            execute_scan("grype", grype, setup or applicability["grype"])
            execute_scan("checkov", checkov, setup or applicability["checkov"])

        log.seek(0)
        (report_dir / "run.log").write_text(redactor.text(log.read()), encoding="utf-8")

    summary = {"schemaVersion": 2, "applicationName": app_name, "scanStartedAt": started.isoformat(),
               "generatedAt": datetime.now(timezone.utc).isoformat(), "platform": system, "architecture": arch,
               "kitCommit": os.environ.get("ACCIDION_KIT_COMMIT"),
               "kitArchiveSha256": os.environ.get("ACCIDION_KIT_ARCHIVE_SHA256"),
               "project": str(project), "mode": "setup-only" if options.setup_only else "scan",
               "discovery": discovery, "installations": installer.records, "scanners": statuses,
               "vulnerabilityCaches": vulnerability_caches,
               "toolVersions": {name: entry.get("version") for name, entry in installer.records.items()},
               "totalFindings": len(issues), "findingsBySeverity": dict(Counter(x["severity"] for x in issues)),
               "findingsByScanner": {name: len(entry["findings"]) for name, entry in statuses.items()},
               "sbomComponentCount": statuses["syft"].get("inventoryCount"), "issues": issues,
               "log": str(report_dir / "run.log")}
    write_json(report_dir / "security-summary.json", redactor.data(summary))
    print(f"{len(issues)} issues. Report directory: {redactor.text(str(report_dir))}", flush=True)
    failures = {"unavailable", "installation_failed"}
    required = set(REPORTS) if options.setup_only else {
        name for name, entry in statuses.items() if entry["status"] != "skipped"
    }
    return int(any(record["status"] in failures for name, record in installer.records.items()
                   if name in required or name not in REPORTS)
               or any(entry["status"] == "failed" for entry in statuses.values()))


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    try:
        return execute(args_for(), *detect())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Starter kit failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
