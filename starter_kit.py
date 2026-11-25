"""Discover and scan an existing Java project, with private per-run JSON reports."""
import argparse
import csv
from collections import Counter, defaultdict
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

from starter_install import Installer, detect, refresh_windows_path, run
from starter_findings import (
    NAMES, NORMALIZE, SEVERITIES, Redactor, capture_secrets, find_maven_declaration, issue_identifier,
    project_source, source_label, terminal_field, terminal_summary,
)

KIT = Path(__file__).resolve().parent
TOOLKIT_FILES = ("starter_kit.py", "starter_install.py", "starter_findings.py",
                 ".gitleaks.toml", "semgrep.yml", ".checkov.yml", "accidion-dependencies.gradle")
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


def select_dockerfile(files, project):
    dockerfiles = files["dockerfiles"]
    root = [p for p in dockerfiles if p.parent == project and p.name == "Dockerfile"]
    if len(root) == 1:
        return root[0]
    return dockerfiles[0] if len(dockerfiles) == 1 else None


def resolve_dependencies(project, builds, out, log, diagnostic):
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
        if family == "maven":
            tree_file = target / "maven-dependency-tree.json"

            tree_args = [
                *tool, "-B", "-f", root / "pom.xml",
                "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree",
                "-DoutputType=json", "-DappendOutput=true",
                f"-DoutputFile={tree_file.resolve()}"
            ]

        else:
            tree_args = [*args[:-1], "accidionDependencyPaths"]

        try:
            run(tree_args, cwd=root, log=log)
        except Exception as error:
            diagnostic(f"{family} dependency paths unavailable ({type(error).__name__})")


def maven_trees(path):
    data = path.read_text(encoding="utf-8").strip()
    decoder = json.JSONDecoder()
    while data:
        tree, offset = decoder.raw_decode(data)
        yield tree
        data = data[offset:].lstrip()


def gradle_source_label(project, source, coordinate):
    # Version catalogs and computed declarations fall back to the build file.
    literal = re.compile(r"\s*\w+\s*(?:\(\s*|\s+)['\"]" + re.escape(coordinate) + r"(?=[:'\"])")
    try:
        lines = (project / source).read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError):
        return source
    matches = [number for number, content in enumerate(lines, 1) if literal.match(content)]
    return source_label(source, matches[0]) if len(matches) == 1 else source


def dependency_contexts(project, builds, deps, diagnostic, poms):
    modules = defaultdict(list)
    for pom in poms:
        try:
            root = ElementTree.parse(pom).getroot()
            group = root.findtext("{*}groupId") or root.findtext("{*}parent/{*}groupId")
            modules[group, root.findtext("{*}artifactId")].append(pom)
        except (OSError, ElementTree.ParseError):
            continue
    contexts = defaultdict(set)
    declarations = {}
    for index, (family, root, _) in enumerate(builds):
        target = deps / str(index)
        try:
            if family == "gradle":
                file = deps.parent / f"gradle-dependency-paths-{index}.json"
                for row in json.loads(file.read_text(encoding="utf-8")):
                    if source := project_source(root / row["source"], project):
                        key = source, row["direct"]
                        if key not in declarations:
                            declarations[key] = gradle_source_label(project, *key)
                        contexts[row["component"], row["version"]].add(
                            (row["kind"], row["direct"], row["directVersion"], declarations[key]))
                continue

            tree = target / "maven-dependency-tree.json"
            for data in maven_trees(tree):
                candidates = [pom for pom in modules[data.get("groupId"), data.get("artifactId")]
                              if pom.is_relative_to(root)]
                pom = candidates[0] if len(candidates) == 1 else root / "pom.xml"
                for direct in data.get("children") or []:
                    coordinate = f"{direct['groupId']}:{direct['artifactId']}"
                    version = direct["version"]
                    key = pom, coordinate, version
                    if key not in declarations:
                        _, start, end = find_maven_declaration(
                            pom.parent, coordinate, version, declaration_pom=pom)
                        declarations[key] = source_label(pom.relative_to(project).as_posix(), start, end)
                    nodes = [(direct, "Direct")]
                    while nodes:
                        node, kind = nodes.pop()
                        component = f"{node['groupId']}:{node['artifactId']}"
                        contexts[component, node["version"]].add((kind, coordinate, version, declarations[key]))
                        nodes.extend((child, "Transitive") for child in node.get("children") or [])
        except (OSError, ValueError, TypeError, AttributeError, KeyError) as error:
            diagnostic(f"{family} dependency path evidence unavailable ({type(error).__name__})")
    return {key: sorted(values) for key, values in contexts.items()}


def enrich_maven_finding(issue, project, report_dir):
    coordinate = issue.get("maven_coordinate")

    if not coordinate:
        component = issue.get("affected_dependency") or ""
        if component.count(":") == 1:
            coordinate = component

    version = issue.get("installed_version")

    if not coordinate or not version:
        return

    if coordinate.count(":") == 2:
        coordinate = coordinate.rsplit(":", 1)[0]

    paths = []

    def walk(node, chain):
        group = node.get("groupId")
        artifact = node.get("artifactId")
        installed = node.get("version")

        current = {
            "coordinate": f"{group}:{artifact}",
            "version": installed
        }

        chain = chain + [current]

        if len(chain) > 1:
            if current["coordinate"] == coordinate and installed == version:
                if chain not in paths:
                    paths.append(chain)

        for child in node.get("children") or []:
            walk(child, chain)

    for tree in sorted(report_dir.glob("maven-dependency-tree-*.json")):
        try:
            data = json.loads(tree.read_text(encoding="utf-8"))
            walk(data, [])
        except (OSError, ValueError, TypeError, AttributeError):
            continue

    if not paths:
        return

    issue["dependency_chains"] = [
        " -> ".join(
            f'{node["coordinate"]}:{node["version"]}'
            for node in chain
        )
        for chain in paths
    ]

    types = {
        "Direct" if len(chain) == 2 else "Transitive"
        for chain in paths
    }

    issue["dependency_type"] = (
        next(iter(types)) if len(types) == 1
        else "Direct and Transitive"
    )

    if len(paths) != 1:
        return

    chain = paths[0]

    if len(chain) <= 2:
        return

    parent = chain[-2]
    direct = chain[1]

    issue["parent_dependency"] = parent["coordinate"]
    issue["parent_version"] = parent["version"]
    issue["direct_dependency"] = direct["coordinate"]
    issue["direct_dependency_version"] = direct["version"]

    source, start, end = find_maven_declaration(
        project, direct["coordinate"], direct["version"]
    )

    if source and start and end:
        issue["direct_dependency_source_file"] = source
        issue["direct_dependency_start_line"] = start
        issue["direct_dependency_end_line"] = end

    issue["dependency_remediation"] = (
        f'Review and update {direct["coordinate"]} '
        "to a compatible version that resolves the vulnerable "
        "transitive dependency. Verify the resolved version, "
        "rebuild, test and rerun the security scan."
    )


def scanner_selection(value):
    names = [name.strip().lower() for name in value.split(",")]

    invalid = [name for name in names
               if name != "all" and name not in REPORTS]

    if invalid:
        raise argparse.ArgumentTypeError(
            "Invalid scanner selection: " + ", ".join(invalid)
        )

    if "all" in names:
        if len(set(names)) != 1:
            raise argparse.ArgumentTypeError(
                "Use all by itself or select individual scanners"
            )
        return tuple(REPORTS)

    return tuple(dict.fromkeys(names))


def args_for(argv=None):
    def nonempty(value):
        if not value.strip():
            raise argparse.ArgumentTypeError("requires a non-empty value")
        return value

    def directory_path(value):
        return Path(nonempty(value))

    parser = argparse.ArgumentParser(prog="security-scan.sh", description=__doc__,
                                     allow_abbrev=False, add_help=False)
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message and exit")
    parser.add_argument("--project-path", type=directory_path, default=Path.cwd(),
                        help="Application directory (default: current directory)")
    parser.add_argument("--report-dir", type=directory_path, help="Private report parent outside the application")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--dry-run", action="store_true", help="Preview without installing tools or writing reports")
    modes.add_argument("--setup-only", action="store_true", help="Verify or install tools without running scans")
    parser.add_argument("--no-install", action="store_true", help="Use existing tools. Can be combined with either mode")
    images = parser.add_mutually_exclusive_group()
    images.add_argument("--image", type=nonempty, help="Scan a locally available Docker image")
    images.add_argument("--build-image", action="store_true", help="Build the discovered Dockerfile locally")
    parser.add_argument("--details", action="store_true", help="Show all findings and per-scanner evidence")
    parser.add_argument("--verbose", action="store_true", help="Show scanner and dependency-resolution diagnostics")
    parser.add_argument(
        "--scanner",
        type=scanner_selection,
        default=tuple(REPORTS),
        help="Select all or comma-separated scanner names"
    )
    options = parser.parse_args(argv)
    if options.help:
        parser.print_help()
        parser.exit()
    return options


def validate_report_directory(path, label):
    for parent in (path, *path.parents):
        if parent.exists():
            if not parent.is_dir():
                raise ValueError(f"{label} must be a directory: {parent}")
            if not os.access(parent, os.W_OK | os.X_OK):
                raise ValueError(f"{label} requires a writable directory: {parent}")
            return


def execute(options, system, arch):
    os.umask(0o077)
    for filename in TOOLKIT_FILES:
        path = KIT / filename
        if not path.is_file() or not os.access(path, os.R_OK):
            raise ValueError(f"Required toolkit file is missing or unreadable: {path}. "
                             "Restore the complete kit and retry.")
    project = options.project_path.resolve()
    if not project.is_dir():
        raise ValueError(f"Application path must be an accessible directory: {project}")
    files = discover(project)
    roots = {family: build_roots(files, family) for family in ("maven", "gradle")}
    app_name = application_name(project, roots)
    application_directory = report_application_directory(app_name)
    dockerfile = select_dockerfile(files, project)
    if options.build_image and not dockerfile:
        raise ValueError("--build-image requires a root Dockerfile or exactly one discovered Dockerfile. "
                         "Select the application directory or pass --image IMAGE.")
    image_requested = bool(options.image or options.build_image)
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
    selected = set(getattr(options, "scanner", REPORTS))
    prerequisites = set()

    if image_requested and "grype" not in selected:
        raise ValueError("Docker image scanning requires Grype")

    complete_scan = selected == set(REPORTS)

    scan_package_grype = (
        "grype" in selected
        and java_app
        and (not image_requested or complete_scan)
    )

    if scan_package_grype and "syft" not in selected:
        prerequisites.add("syft")

    active_scanners = selected | prerequisites

    for name in REPORTS:
        if name not in active_scanners:
            applicability[name] = "Scanner not selected"

    provision_scanners = {
        name for name in active_scanners
        if applicability[name] is None
        or (complete_scan and options.setup_only)
    }

    dependency_work = bool(
        provision_scanners & {"dependency-check", "syft"}
    )

    home = Path(os.environ.get("ACCIDION_HOME", Path.home() / ".accidion")).resolve()
    report_parent = (options.report_dir or home / "reports").resolve()
    application_reports = (report_parent / application_directory).resolve()
    cache = (home / "tools").resolve()
    if report_parent.is_relative_to(project):
        raise ValueError(f"Private report directory must be outside the application: {report_parent}")
    if application_reports.is_relative_to(project) or application_reports.parent != report_parent:
        raise ValueError(f"Application report directory must stay under the private report parent: {application_reports}")
    if cache.is_relative_to(project):
        raise ValueError(f"Tool cache must be outside the application: {cache}")
    validate_report_directory(application_reports, "Private report path")

    discovery = {key: len(items) for key, items in files.items()}
    if options.dry_run:
        print(json.dumps({"platform": system, "architecture": arch, "project": str(project),
                          "applicationName": app_name, "reportApplicationDirectory": application_directory,
                          "discovery": discovery, "buildRoots": {
                              k: [str(p.relative_to(project)) for p in v] for k, v in roots.items()},
                          "installMissing": not options.no_install,
                          "scanContainer": image_requested,
                          "selectedScanners": sorted(selected),
                          "prerequisiteScanners": sorted(prerequisites),
                          "scanners": applicability}, indent=2))
        return 0

    report_dir = private_run_path(application_reports)
    total_started = time.perf_counter()
    started = datetime.now(timezone.utc)
    scan_clock = time.monotonic()
    redactor = Redactor()
    statuses = {}
    issues = []
    terminal_metadata = []
    contexts = {}
    diagnostics = []

    def emit(message):
        # Preserve spacing between sections and flatten controls in scanner evidence.
        prefix = "\n" if message.startswith("\n") else ""
        safe = "".join(char if char.isprintable() else " " for char in redactor.text(message.lstrip("\n")))
        print(prefix + safe, flush=True)

    emit("=== Accidion Security Scan ===" if not options.setup_only else "=== Accidion Setup ===")
    terminal_field(emit, "Application", app_name)
    terminal_field(emit, "Project directory", project)
    operating_system = {"windows": "Windows", "linux": "Linux", "macos": "macOS"}.get(system, system)
    terminal_field(emit, "Operating system", f"{operating_system} ({arch})")
    build_systems = [name for family, name in (("maven", "Maven"), ("gradle", "Gradle")) if roots[family]]
    terminal_field(emit, "Build system", ", ".join(build_systems) or "None detected")
    terminal_field(emit, "Started (UTC)", started.strftime("%Y-%m-%d %H:%M:%S"))
    applicable = [NAMES.get(name, "Syft") for name, reason in applicability.items() if reason is None]
    terminal_field(emit, "Applicable scanners", ", ".join(applicable) or "None")
    emit("")

    def progress(label, status, duration=0, count=None, unit="finding", reason=None):
        quantity = str(count) if count is not None else "unavailable"
        result = ("Scanning in progress" if status == "running"
                  else f"{quantity} {unit if count == 1 else unit + 's'}")
        suffix = f" | {reason}" if reason else ""
        emit(f"{label}: {status} | {duration:.2f}s | {result}{suffix}")

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
        java = installer.ensure("java") if (
            dependency_work and (java_needed or options.setup_only)
        ) else None
        builds = []
        for family, directories in (
            roots.items() if dependency_work else ()
        ):
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
            if name not in provision_scanners:
                installer.records[name] = {"status": "skipped", "reason": reason}
                tools[name] = None
            else:
                tools[name] = installer.ensure(name)
        log.flush()

        def execute_scan(name, action, skip=None):
            scan_started = time.monotonic()
            label = NAMES.get(name, "Syft")
            installation = installer.records[name]
            entry = {"status": "skipped", "reason": skip, "report": None,
                     "version": installation.get("version"), "installationStatus": installation["status"],
                     "findingCount": None, "nativeFindingCount": None, "findings": []}
            statuses[name] = entry
            entry["selected"] = name in selected
            entry["prerequisite"] = name in prerequisites

            if name not in active_scanners:
                entry["reason"] = "Scanner not selected"
                progress(label, "skipped", reason=entry["reason"])
                return
            if name == "checkov" and files["opentofu"]:
                entry["unsupportedInputs"] = [
                    str(path.relative_to(project)) for path in files["opentofu"]
                ]
            unit = "component" if name == "syft" else "finding"
            skip = skip or applicability[name]
            entry["reason"] = skip

            if skip:
                progress(label, "skipped", unit=unit, reason=skip)
                return
            if not tools[name]:
                entry.update(status="failed", reason=installation.get("reason"))
                progress(label, "failed", unit=unit, reason="Tool unavailable; review installation in the report")
                return
            raw_output = work / REPORTS[name]
            problems = []
            scanner_started = time.perf_counter()
            entry["startedAt"] = datetime.now(timezone.utc).isoformat()
            progress(label, "running", unit=unit)
            try:
                action(tools[name], raw_output)
            except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
                problems.append(str(error))
            image_selected = bool(options.image or options.build_image)
            artifacts = [(raw_output, "container" if image_selected else "sbom")]
            if name == "grype" and image_selected and scan_package_grype:
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
                        kwargs = {"terminal": True} if name in {"dependency-check", "grype"} else {}
                        for item in NORMALIZE[name](report, project, **kwargs):
                            evidence = item.pop("_terminal", {})
                            if name in ("dependency-check", "grype"):
                                enrich_maven_finding(item, project, report_dir)
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
                            terminal_metadata.append(evidence)
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
            entry["completedAt"] = datetime.now(timezone.utc).isoformat()
            entry["durationSeconds"] = round(time.perf_counter() - scanner_started, 2)
            count = entry.get("inventoryCount") if name == "syft" else entry["findingCount"]
            progress(label, entry["status"], entry["durationSeconds"], count, unit,
                     "Review scanner report and run.log" if problems else None)
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
                    resolve_dependencies(project, builds, deps, log, diagnostics.append)

                    for tree in sorted(deps.rglob("maven-dependency-tree.json")):
                        try:
                            tree_data = list(maven_trees(tree))[-1]
                            tree_report = report_dir / (
                                "maven-dependency-tree-"
                                + tree.parent.name + ".json"
                            )
                            write_json(tree_report, redactor.data(tree_data))
                            diagnostics.append("Maven dependency tree report generated")
                        except (OSError, ValueError, IndexError) as exc:
                            diagnostics.append(f"Maven dependency tree export failed ({type(exc).__name__})")
                except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                    resolution_error = str(error)

            def dependency_check(cmd, out):
                if not java:
                    raise RuntimeError("A compatible JDK is unavailable")
                prepare_dependencies()
                if resolution_error:
                    raise RuntimeError(f"Dependency resolution failed: {resolution_error}")
                database = vulnerability_cache("dependency-check", home / "dependency-check-data")
                args = ["--project", project.name, "--format", "JSON", "--out", out.parent,
                        "--data", database, "--scan", deps]
                for artifact in files["jars"]:
                    args.extend(("--scan", artifact))
                invoke(cmd, *args)

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
                if scan_package_grype:
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
            if java_needed and resolved_dependencies:
                contexts = dependency_contexts(project, builds, deps, diagnostics.append, files["maven"])

        log.seek(0)
        (report_dir / "run.log").write_text(redactor.text(log.read()), encoding="utf-8")

    summary = {"schemaVersion": 2, "applicationName": app_name, "scanStartedAt": started.isoformat(),
               "generatedAt": datetime.now(timezone.utc).isoformat(),
               "durationSeconds": round(time.monotonic() - scan_clock, 2),
               "platform": system, "architecture": arch,
               "kitCommit": os.environ.get("ACCIDION_KIT_COMMIT"),
               "kitArchiveSha256": os.environ.get("ACCIDION_KIT_ARCHIVE_SHA256"),
               "project": str(project), "mode": "setup-only" if options.setup_only else "scan",
               "selectedScanners": sorted(selected),
               "prerequisiteScanners": sorted(prerequisites),
               "unselectedScanners": sorted(set(REPORTS) - active_scanners),
               "discovery": discovery,
               "installations": installer.records,
               "scanners": statuses,
               "vulnerabilityCaches": vulnerability_caches,
               "toolVersions": {name: entry.get("version") for name, entry in installer.records.items()},
               "totalFindings": len(issues), "findingsBySeverity": dict(Counter(x["severity"] for x in issues)),
               "findingsByScanner": {name: len(entry["findings"]) for name, entry in statuses.items()},
               "sbomComponentCount": statuses["syft"].get("inventoryCount"), "issues": issues,
               "log": str(report_dir / "run.log")}
    summary["totalDurationSeconds"] = round(time.perf_counter() - total_started, 2)
    write_json(report_dir / "security-summary.json", redactor.data(summary))
    failures = {"unavailable", "installation_failed"}
    required = provision_scanners if options.setup_only else {
        name for name, entry in statuses.items() if entry["status"] != "skipped"
    }
    failed = (any(record["status"] in failures for name, record in installer.records.items()
                   if name in required or name not in REPORTS)
              or any(entry["status"] == "failed" for entry in statuses.values()))
    inventory = None
    if sbom_path := statuses["syft"]["report"]:
        try:
            inventory = json.loads(Path(sbom_path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    counts, remediation_count, grouped = terminal_summary(
        issues, terminal_metadata, project, contexts, emit, details=options.details,
        statuses=statuses, inventory=inventory,
    )
    emit("\n=== Security Summary ===")
    emit(f"Scanner execution: {'failed' if failed else 'completed'} ({summary['totalDurationSeconds']:.2f}s)")
    executions = Counter(entry["status"] for entry in statuses.values())
    emit("Scanner status: " + " | ".join(f"{executions[state]} {state}" for state in ("success", "failed", "skipped")))
    validation = "findings require review" if issues else "no findings reported by completed scans"
    if options.setup_only:
        validation = "not run (setup only)"
    elif failed:
        validation = "incomplete coverage; " + validation
    emit(f"Security validation: {validation}")
    emit("Severity (grouped findings, deduplicated across scanners): " + " | ".join(f"{level} {counts[level]}" for level in SEVERITIES))
    if counts["UNKNOWN"]:
        emit("UNKNOWN means the scanner supplied no recognized severity. Review these findings for impact.")
    raw = sum(entry["nativeFindingCount"] or 0 for entry in statuses.values())
    emit(f"Raw findings reported: {raw}")
    emit(f"Grouped findings across scanner sections: {grouped}")
    emit(f"Unique remediations across scanners: {remediation_count}")
    if options.verbose:
        emit("\nDiagnostics")
        for name, record in installer.records.items():
            version = f" ({record['version']})" if record.get("version") else ""
            emit(f"  {name}: {record['status']}{version}")
        for name, entry in statuses.items():
            emit(f"  {name}: native findings {entry['nativeFindingCount']}; "
                 f"report {Path(entry['report']).name if entry['report'] else 'unavailable'}")
        for message in diagnostics:
            emit(f"  {message}")
        emit("  Scanner diagnostics: run.log and individual JSON reports")
    emit(f"\nReports: {report_dir}")
    filenames = sorted(path.name for path in report_dir.glob("*.json"))
    emit("  JSON reports: " + ", ".join(filenames))
    emit("  Log: run.log")
    return int(failed)


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
