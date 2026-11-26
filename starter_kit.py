"""Discover and scan an existing Java project, with private per-run JSON reports."""
import argparse
import csv
from collections import Counter, defaultdict
from contextlib import ExitStack
import functools
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree

from starter_install import CommandTimeout, Installer, detect, recover_dependency_check_lock, refresh_windows_path, run
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
           ".cache", "__pycache__", ".pytest_cache"}
MANIFESTS = {
    "package.json": "javascript", "package-lock.json": "javascript", "yarn.lock": "javascript",
    "pnpm-lock.yaml": "javascript", "tsconfig.json": "typescript",
    "pyproject.toml": "python", "pipfile.lock": "python", "poetry.lock": "python", "uv.lock": "python",
    "go.mod": "go", "go.sum": "go", "packages.lock.json": "dotnet", "packages.config": "dotnet",
    "cargo.toml": "rust", "cargo.lock": "rust", "gemfile.lock": "ruby", "composer.lock": "php",
}
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
    files = {kind: [] for kind in ("java", "maven", "gradle", "jars", "dockerfiles", "iac", "opentofu", "sql",
                                     *sorted(set(MANIFESTS.values())))}

    def raise_walk_error(error):
        raise error

    for directory, dirs, names in os.walk(project, onerror=raise_walk_error):
        base = Path(directory)
        dirs[:] = sorted(d for d in dirs if d not in IGNORED and d.casefold() != "reports"
                         and not (base / d).is_symlink())
        generated = bool(set(base.relative_to(project).parts) & {"build", "target"})
        for name in sorted(names):
            path = base / name
            if name in GENERATED_JSON or path.is_symlink() or not path.is_file():
                continue
            lower = name.lower()
            if lower.endswith((".jar", ".war", ".ear")):
                if name not in {"gradle-wrapper.jar", "maven-wrapper.jar"}:
                    files["jars"].append(path)
            elif generated:
                continue
            elif lower in MANIFESTS:
                files[MANIFESTS[lower]].append(path)
            elif lower.startswith("requirements") and lower.endswith(".txt"):
                files["python"].append(path)
            elif lower.endswith((".csproj", ".fsproj", ".vbproj", ".deps.json")):
                files["dotnet"].append(path)
            elif lower.endswith(".sql"):
                files["sql"].append(path)
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


def resolve_dependencies(project, builds, out, log, diagnostic, *, timeout=3600):
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
        run(args, cwd=root, log=log, timeout=timeout)
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
            run(tree_args, cwd=root, log=log, timeout=timeout)
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


def maven_declaration_lookup():
    @functools.cache
    def find_poms(root):
        return tuple(root.rglob("pom.xml"))

    return functools.cache(functools.partial(find_maven_declaration, find_poms=find_poms))


def dependency_contexts(project, builds, deps, diagnostic, poms, *,
                        maven_reports=None, declaration_lookup=find_maven_declaration):
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
            trees = maven_trees(tree) if maven_reports is None else maven_reports.get(tree)
            if trees is None:
                diagnostic(f"{family} dependency path evidence unavailable (FileNotFoundError)")
                continue
            for data in trees:
                candidates = [pom for pom in modules[data.get("groupId"), data.get("artifactId")]
                              if pom.is_relative_to(root)]
                pom = candidates[0] if len(candidates) == 1 else root / "pom.xml"
                for direct in data.get("children") or []:
                    coordinate = f"{direct['groupId']}:{direct['artifactId']}"
                    version = direct["version"]
                    key = pom, coordinate, version
                    if key not in declarations:
                        _, start, end = declaration_lookup(
                            pom.parent, coordinate, version, declaration_pom=pom)
                        declarations[key] = source_label(pom.relative_to(project).as_posix(), start, end)
                    nodes = [(direct, "Direct")]
                    while nodes:
                        node, kind = nodes.pop()
                        component = f"{node['groupId']}:{node['artifactId']}"
                        contexts[component, node["version"]].add((kind, coordinate, version, declarations[key]))
                        nodes.extend((child, "Transitive") for child in node.get("children") or [])
            if maven_reports is not None and trees.error is not None:
                diagnostic(f"{family} dependency path evidence unavailable ({trees.error})")
        except (OSError, ValueError, TypeError, AttributeError, KeyError) as error:
            diagnostic(f"{family} dependency path evidence unavailable ({type(error).__name__})")
    return {key: sorted(values) for key, values in contexts.items()}


class MavenTreeReport:
    """Retain parsed trees for terminal evidence, including any prefix before an error."""

    def __init__(self, path):
        self.trees = []
        self.error = None
        try:
            self.trees.extend(maven_trees(path))
        except (OSError, ValueError, TypeError, AttributeError) as error:
            self.error = type(error).__name__

    def __iter__(self):
        return iter(self.trees)


def index_maven_dependencies(trees):
    paths = defaultdict(dict)
    for tree in trees:
        pending = [(tree, ())]
        while pending:
            node, ancestors = pending.pop()
            try:
                coordinate = f"{node.get('groupId')}:{node.get('artifactId')}"
                version = node.get("version")
                chain = (*ancestors, (coordinate, version))
                if ancestors:
                    paths[coordinate, version][chain] = None
                pending.extend((child, chain) for child in reversed(node.get("children") or []))
            except (TypeError, AttributeError):
                # Keep paths visited before malformed data, as the report walk did.
                break
    return paths


def enrich_maven_finding(issue, project, dependency_index, declaration_lookup=find_maven_declaration):
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

    paths = dependency_index.get((coordinate, version))
    if not paths:
        return

    issue["dependency_chains"] = [
        " -> ".join(f"{component}:{installed}" for component, installed in chain)
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

    chain = next(iter(paths))

    if len(chain) <= 2:
        return

    parent, parent_version = chain[-2]
    direct, direct_version = chain[1]

    issue["parent_dependency"] = parent
    issue["parent_version"] = parent_version
    issue["direct_dependency"] = direct
    issue["direct_dependency_version"] = direct_version

    source, start, end = declaration_lookup(project, direct, direct_version)

    if source and start and end:
        issue["direct_dependency_source_file"] = source
        issue["direct_dependency_start_line"] = start
        issue["direct_dependency_end_line"] = end

    issue["dependency_remediation"] = (
        f"Review and update {direct} "
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


def safe_report_path(path, expected_type):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (not expected_type(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise ValueError(f"Unsafe report path: {path}")
    return info


def protect_project_reports(project):
    git = shutil.which("git")
    if not git:
        if any(os.path.lexists(parent / ".git") for parent in (project, *project.parents)):
            raise ValueError("Git is required to protect project reports from accidental commits")
        return

    def git_call(*args, allowed=(0,), input=None):
        result = subprocess.run([git, "-C", project, *args], input=input, capture_output=True)
        if result.returncode not in allowed:
            raise ValueError(result.stderr.decode(errors="replace").strip() or f"git {args[0]} failed")
        return result

    if git_call("rev-parse", "--is-inside-work-tree", allowed=(0, 128)).stdout.strip() != b"true":
        if any(os.path.lexists(parent / ".git") for parent in (project, *project.parents)):
            raise ValueError("Git could not verify the application worktree")
        return
    paths = [f"reports/{name}" for name in GENERATED_JSON]
    pathspecs = [f":(icase,literal){path}" for path in paths]
    if git_call("ls-files", "-z", "--", *pathspecs).stdout:
        raise ValueError("A generated report path is tracked by Git. Remove it from the index before scanning")
    prefix = git_call("rev-parse", "--show-prefix").stdout.removesuffix(b"\n").removesuffix(b"\r")
    if b"\n" in prefix or b"\r" in prefix:
        raise ValueError("Cannot write literal Git exclusions for an application path containing a line break")
    exclude = project / os.fsdecode(git_call("rev-parse", "--git-path", "info/exclude")
                                    .stdout.removesuffix(b"\n").removesuffix(b"\r"))
    safe_report_path(exclude.parent, stat.S_ISDIR)
    exclude.parent.mkdir(exist_ok=True)
    info = safe_report_path(exclude, stat.S_ISREG)
    if info and info.st_nlink != 1:
        raise ValueError(f"Unsafe Git exclusion file: {exclude}")
    rules = {path.encode(): path.encode() for path in paths}
    rules[b"reports/.accidion-export-probe/report.json"] = b"reports/.accidion-export-*/"

    def ignored_paths(paths):
        result = git_call("check-ignore", "-z", "--stdin", allowed=(0, 1),
                          input=b"".join(path + b"\0" for path in paths))
        return set(result.stdout.split(b"\0"))

    missing = rules.keys() - ignored_paths(rules)
    if missing:
        with exclude.open("a+b") as output:
            output.seek(0)
            existing = set(output.read().splitlines())
            directory = re.sub(rb"([\\*?\[\] ])", rb"\\\1", prefix)
            new_rules = [b"/" + directory + rules[path] for path in sorted(missing)]
            lines = [rule for rule in new_rules if rule not in existing]
            if lines:
                output.write(b"\n" + b"\n".join(lines) + b"\n")
        if not missing.issubset(ignored_paths(missing)):
            raise ValueError("Git ignore rules override the local report exclusions")


def prepare_project_reports(project, home, stack):
    # Keep the kernel lock outside the worktree and release it even on scan errors.
    key = hashlib.sha256(os.fsencode(os.path.normcase(project))).hexdigest()
    locks = home / "report-locks"
    locks.mkdir(parents=True, exist_ok=True)
    safe_report_path(locks, stat.S_ISDIR)
    lock_path = locks / key
    safe_report_path(lock_path, stat.S_ISREG)
    lock = stack.enter_context(lock_path.open("ab"))
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        raise ValueError(f"Could not lock project reports for {project}: {error}") from error

    destination = project / "reports"
    safe_report_path(destination, stat.S_ISDIR)
    if os.path.lexists(destination / ".git"):
        raise ValueError(f"Project reports cannot be written to a separate Git repository: {destination}")
    protect_project_reports(project)
    destination.mkdir(exist_ok=True)
    identity = safe_report_path(destination, stat.S_ISDIR)
    outputs = [destination / name for name in GENERATED_JSON]
    for output in outputs:
        safe_report_path(output, stat.S_ISREG)
    for output in reversed(outputs):
        output.unlink(missing_ok=True)
    return destination, identity


def export_project_reports(destination, identity, report_dir, statuses):
    current = safe_report_path(destination, stat.S_ISDIR)
    if current is None or not os.path.samestat(identity, current):
        raise ValueError(f"Project report directory changed during the scan: {destination}")
    scanner_reports = [
        Path(path).name
        for entry in statuses.values() if entry["status"] == "success"
        for path in (entry["report"], *entry.get("additionalReports", ())) if path
    ]
    # Stage every sanitized JSON file before publication and publish the summary last.
    with tempfile.TemporaryDirectory(prefix=".accidion-export-", dir=destination) as directory:
        staging = Path(directory)
        names = [*scanner_reports, "security-summary.json"]
        for name in names:
            shutil.copyfile(report_dir / name, staging / name)
        for name in names:
            safe_report_path(destination / name, stat.S_ISREG)
        for name in names:
            (staging / name).replace(destination / name)


def execute(options, system, arch, *, in_memory_preview=False):
    with ExitStack() as stack:
        return execute_with_reports(options, system, arch, stack, in_memory_preview=in_memory_preview)


def execute_with_reports(options, system, arch, stack, *, in_memory_preview=False):
    os.umask(0o077)
    for filename in (() if in_memory_preview and options.dry_run else TOOLKIT_FILES):
        path = KIT / filename
        if not path.is_file() or not os.access(path, os.R_OK):
            raise ValueError(f"Required toolkit file is missing or unreadable: {path}. "
                             "Restore the complete kit and retry.")
    project = options.project_path.resolve()
    if not project.is_dir():
        raise ValueError(f"Application path must be an accessible directory: {project}")
    timeout = int(os.getenv("ACCIDION_SCAN_TIMEOUT", "3600"))
    if timeout < 1:
        raise ValueError("ACCIDION_SCAN_TIMEOUT must be a positive number of seconds")
    nvd_mirror = os.getenv("ACCIDION_NVD_MIRROR")
    if nvd_mirror:
        mirror = urlsplit(nvd_mirror)
        if (mirror.scheme != "https" or not mirror.hostname or mirror.username is not None
                or mirror.query or mirror.fragment or "{0}" not in mirror.path
                or any(character.isspace() for character in nvd_mirror)):
            raise ValueError("ACCIDION_NVD_MIRROR requires an HTTPS NVD feed URL template with {0} and no credentials")
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
    package_app = java_app or any(files[technology] for technology in MANIFESTS.values())
    scan_exclusions = []
    launcher = os.environ.get("ACCIDION_STANDALONE_LAUNCHER")
    toolkit = [KIT / name for name in (*TOOLKIT_FILES, "security-scan.sh", "python-bootstrap.sh",
                                       "scripts/security-scan.template.sh")]
    if launcher:
        toolkit.append(Path(launcher).resolve())
    for path in toolkit:
        if path.is_relative_to(project):
            scan_exclusions.append(path.relative_to(project))

    applicability = {
        "gitleaks": None,
        "semgrep": None if java_app or files["sql"] else "No inputs for bundled Java and SQL rules",
        "dependency-check": None if java_needed else "No Maven/Gradle build files or Java archives",
        "syft": None if package_app else "No supported package manifests or Java inputs",
        "grype": None if package_app or image_requested else "No supported package manifests or container target",
        "checkov": None if files["iac"] or files["dockerfiles"] else (
            "OpenTofu files found, but native .tofu/.tofu.json coverage is unavailable"
            if files["opentofu"] else "No supported infrastructure candidates"),
    }
    selected = set(getattr(options, "scanner", REPORTS))
    required = os.getenv("ACCIDION_REQUIRED_SCANNERS")
    policy = set(scanner_selection(required)) if required else set()
    if policy and (options.setup_only or options.dry_run):
        raise ValueError("Configured policy requires a full scan execution")
    if not policy.issubset(selected):
        raise ValueError("Scanner selection omits scanners required by ACCIDION_REQUIRED_SCANNERS")
    prerequisites = set()

    if image_requested and "grype" not in selected:
        raise ValueError("Docker image scanning requires Grype")

    complete_scan = selected == set(REPORTS)

    scan_package_grype = (
        "grype" in selected
        and package_app
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

    if not options.setup_only:
        try:
            destination, report_identity = prepare_project_reports(project, home, stack)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise ValueError(f"Project report export could not be prepared: {error}") from error
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

    declaration_lookup = maven_declaration_lookup()
    maven_index = {}
    maven_reports = {}
    maven_index_duration = None
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

    with (
        tempfile.TemporaryDirectory(prefix="scanner-state-", dir=report_dir) as scanner_state,
        tempfile.TemporaryFile(mode="w+", dir=report_dir, encoding="utf-8", errors="replace") as log,
    ):
        installer = Installer(system, arch, cache, not options.no_install, log)
        installer.scratch_env = {key: scanner_state for key in ("TMPDIR", "TEMP", "TMP")}
        # Semgrep's Windows RPC transport uses the native temp path. Keep it short
        # while placing Python's scratch directory and Semgrep state with the report.
        installer.semgrep_env = {
            "TMPDIR": scanner_state,
            "SEMGREP_LOG_FILE": str(Path(scanner_state) / "semgrep.log"),
            "SEMGREP_SETTINGS_FILE": str(Path(scanner_state) / "settings.yml"),
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        }
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
        for name, record in installer.records.items():
            if record["status"] in {"unavailable", "installation_failed"}:
                print(f"{name}: {record['reason']}", file=log)
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
                entry.update(status="unavailable", reason=installation.get("reason"))
                progress(label, "unavailable", unit=unit, reason=redactor.text(entry["reason"]) if entry["reason"]
                         else "Tool unavailable; review installation in the report")
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
            entry["reportProcessing"] = []
            for native, target in artifacts:
                processing = {"artifact": native.name}
                entry["reportProcessing"].append(processing)
                processing_started = time.perf_counter()
                try:
                    emit(f"{label} | Loading {native.name}")
                    stage_started = time.perf_counter()
                    with native.open(encoding="utf-8-sig") as source:
                        report = json.load(source)
                    processing["loadSeconds"] = round(time.perf_counter() - stage_started, 3)
                    emit(f"{label} | Sanitizing {native.name}")
                    stage_started = time.perf_counter()
                    if name == "gitleaks":
                        redactor.add(capture_secrets(report))
                    output = report_dir / native.name
                    write_json(output, redactor.data(report, native=True))
                    processing["sanitizeAndWriteSeconds"] = round(time.perf_counter() - stage_started, 3)
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
                        maven_enrichment = name in {"dependency-check", "grype"}
                        kwargs = {"terminal": True, "declaration_lookup": declaration_lookup} if maven_enrichment else {}
                        emit(f"{label} | Normalizing {native_count} findings")
                        if maven_enrichment:
                            emit(f"{label} | Enriching Maven dependency evidence during normalization")
                        stage_started = time.perf_counter()
                        enrichment_seconds = 0
                        next_update = stage_started + 5
                        processed = 0
                        for processed, item in enumerate(NORMALIZE[name](report, project, **kwargs), 1):
                            evidence = item.pop("_terminal", {})
                            if maven_enrichment:
                                enrichment_started = time.perf_counter()
                                enrich_maven_finding(item, project, maven_index, declaration_lookup)
                                enrichment_seconds += time.perf_counter() - enrichment_started
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
                            now = time.perf_counter()
                            if processed % 1000 == 0 or now >= next_update:
                                emit(f"{label} | Processed {processed}/{native_count} findings in {now - stage_started:.2f}s")
                                next_update = now + 5
                        elapsed = time.perf_counter() - stage_started
                        processing["normalizeSeconds"] = round(elapsed - enrichment_seconds, 3)
                        if maven_enrichment:
                            processing["mavenEnrichmentSeconds"] = round(enrichment_seconds, 3)
                        emit(f"{label} | Processed {processed}/{native_count} findings in {elapsed:.2f}s")
                    if reason := report_error(name, report):
                        problems.append(reason)
                except FileNotFoundError:
                    problems.append(f"Scanner did not write {native.name}")
                except (OSError, ValueError, TypeError, AttributeError, KeyError, RuntimeError) as error:
                    problems.append(f"Could not interpret {native.name}: {error}")
                finally:
                    processing["totalSeconds"] = round(time.perf_counter() - processing_started, 3)
                    emit(f"{label} | Report processing took {processing['totalSeconds']:.3f}s")
            if entry["report"] or entry.get("additionalReports"):
                observed = len(entry["findings"])
                entry["findingCount"] = observed if not problems or observed else None
                if entry["nativeFindingCount"] is not None and entry["nativeFindingCount"] != observed:
                    problems.append(f"Native findings ({entry['nativeFindingCount']}) differ from normalized "
                                    f"findings ({observed}); inspect the individual report")
            if problems and entry["nativeFindingCount"] == 0:
                entry["nativeFindingCount"] = None
                entry["findingCount"] = None
            entry.update(status="failed" if problems else "success",
                         reason=redactor.text("; ".join(problems)) if problems else None)
            entry["completedAt"] = datetime.now(timezone.utc).isoformat()
            entry["durationSeconds"] = round(time.perf_counter() - scanner_started, 2)
            count = entry.get("inventoryCount") if name == "syft" else entry["findingCount"]
            progress(label, entry["status"], entry["durationSeconds"], count, unit,
                     redactor.text(problems[0]) if problems else None)
            if problems:
                print(f"{label}: {entry['reason']}", file=log)
            log.flush()

        def invoke(cmd, *args, accepted=(0,), env=None):
            print(f"\n--- {Path(cmd[0]).name} ---", file=log, flush=True)
            scanner_env = {**os.environ, **(env if env is not None else installer.scratch_env)}
            run([*cmd, *args], cwd=project, log=log, accepted=accepted, env=scanner_env, timeout=timeout)

        with tempfile.TemporaryDirectory(prefix="work-", dir=report_dir) as directory:
            work = Path(directory)
            deps = work / "dependencies"
            deps.mkdir()
            resolution_error = None
            dependency_resolution_seconds = None
            resolved_dependencies = False

            def prepare_dependencies():
                nonlocal resolution_error, resolved_dependencies, maven_index, maven_index_duration, dependency_resolution_seconds
                if resolved_dependencies:
                    return
                resolved_dependencies = True
                resolution_started = time.perf_counter()
                try:
                    resolve_dependencies(project, builds, deps, log, diagnostics.append, timeout=timeout)
                except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                    resolution_error = str(error)
                finally:
                    dependency_resolution_seconds = round(time.perf_counter() - resolution_started, 3)

                tree_paths = sorted(deps.rglob("maven-dependency-tree.json"))
                if tree_paths:
                    started = time.perf_counter()
                    emit(f"Maven | Loading {len(tree_paths)} dependency tree report(s)")
                    exported = {}
                    for tree in tree_paths:
                        parsed = maven_reports[tree] = MavenTreeReport(tree)
                        if resolution_error is not None:
                            continue
                        try:
                            if parsed.error:
                                diagnostics.append(f"Maven dependency tree export failed ({parsed.error})")
                                continue
                            # Preserve the existing exported tree and enrichment scope.
                            data = redactor.data(parsed.trees[-1])
                            tree_report = report_dir / f"maven-dependency-tree-{tree.parent.name}.json"
                            write_json(tree_report, data)
                            exported[tree_report] = data
                            diagnostics.append("Maven dependency tree report generated")
                        except (OSError, ValueError, IndexError) as exc:
                            diagnostics.append(f"Maven dependency tree export failed ({type(exc).__name__})")
                    emit(f"Maven | Prepared dependency tree reports in {time.perf_counter() - started:.3f}s")
                    emit("Maven | Indexing dependency chains")
                    started = time.perf_counter()
                    maven_index = index_maven_dependencies(exported[path] for path in sorted(exported))
                    maven_index_duration = round(time.perf_counter() - started, 3)
                    emit(f"Maven | Indexed {len(maven_index)} dependency versions in {maven_index_duration:.3f}s")

            def dependency_check(cmd, out):
                if not java:
                    raise RuntimeError("A compatible JDK is unavailable")
                prepare_dependencies()
                if resolution_error:
                    raise RuntimeError(f"Dependency resolution failed: {resolution_error}")
                database = vulnerability_cache("dependency-check", home / "dependency-check-data")
                args = ["--project", project.name, "--format", "JSON", "--out", out.parent,
                        "--data", database, "--scan", deps,
                        "--exclude", "**/maven-dependency-tree.json",
                        "--exclude", "**/gradle-dependency-paths-*.json"]
                for artifact in files["jars"]:
                    args.extend(("--scan", artifact))
                if nvd_mirror:
                    args.extend(("--nvdDatafeed", nvd_mirror))
                if key := os.getenv("NVD_API_KEY"):
                    if not re.fullmatch(r"[a-zA-Z0-9-]+", key):
                        raise ValueError("NVD_API_KEY contains unexpected characters")
                    redactor.add([key])
                    properties = work / "dependency-check.properties"
                    properties.write_text(f"nvd.api.key={key}\n", encoding="ascii")
                    args.extend(("--propertyfile", properties))
                command_started = time.perf_counter()
                if recover_dependency_check_lock(database):
                    print("Dependency-Check | Removed an orphaned update lock before scanning", file=log)
                try:
                    invoke(cmd, *args)
                except (CommandTimeout, KeyboardInterrupt):
                    if recover_dependency_check_lock(database, wait_for_release=True):
                        print("Dependency-Check | Removed an orphaned update lock after scanning", file=log)
                    raise
                finally:
                    statuses["dependency-check"]["commandSeconds"] = round(time.perf_counter() - command_started, 3)

            excludes = ["--exclude", "**/.git/**", "--exclude", "./reports/**"]
            for filename in GENERATED_JSON:
                excludes.extend(("--exclude", f"**/{filename}"))
            for path in scan_exclusions:
                excludes.extend(("--exclude", "./" + path.as_posix()))

            def syft(cmd, out):
                # Inventory the resolved dependencies independently of the original project
                # so package-manager dependencies and existing application artifacts are represented.
                prepare_dependencies()
                invoke(cmd, "scan", f"dir:{project}", *excludes,
                       "-o", f"cyclonedx-json={out}")
                if resolution_error:
                    raise RuntimeError(f"SBOM only covers files in the project; dependency resolution failed: {resolution_error}")
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

            def run_grype(cmd, target, out, *extra):
                database = vulnerability_cache("grype", Path(os.environ.get("GRYPE_DB_CACHE_DIR") or home / "grype-db"))
                # SQLite hydration can require gigabytes of temporary space. Use the
                # cache filesystem so a small report or system temp filesystem is irrelevant.
                with tempfile.TemporaryDirectory(prefix="grype-scratch-", dir=database) as scratch:
                    env = dict.fromkeys(("TMPDIR", "TEMP", "TMP", "SQLITE_TMPDIR"), scratch)
                    invoke(cmd, target, "-o", "json", "--file", out, *extra,
                           env={**env, "GRYPE_DB_CACHE_DIR": str(database)})

            def grype_sbom(cmd, out):
                syft_status = statuses["syft"]
                if syft_status["status"] == "success" and syft_status.get("inventoryCount") is not None:
                    run_grype(cmd, f"sbom:{work / REPORTS['syft']}", out)
                    return
                statuses["grype"]["packageScanMode"] = "direct-directory"
                run_grype(cmd, f"dir:{project}", out, *excludes)
                if builds:
                    raise RuntimeError("Grype directory scan completed with partial Java coverage. "
                                       "A complete Syft SBOM is required for resolved build dependencies.")

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
            def gitleaks(cmd, out):
                config = KIT / ".gitleaks.toml"
                if scan_exclusions or not options.setup_only:
                    # Match both native Windows separators and portable relative paths.
                    patterns = [r"(?:^|[\\/])" + r"[\\/]".join(map(re.escape, path.parts)) + "$"
                                for path in scan_exclusions]
                    patterns.append(r"(?:^|[\\/])reports[\\/]")
                    content = config.read_text(encoding="utf-8")
                    content = content.replace("paths = [", "paths = [" + ", ".join(
                        json.dumps(pattern, ensure_ascii=False) for pattern in patterns) + ", ", 1)
                    config = work / ".gitleaks.toml"
                    config.write_text(content, encoding="utf-8")
                invoke(cmd, "dir", project, "--config", config, "--report-format", "json",
                       "--report-path", out, "--redact=0", "--exit-code", "0")

            execute_scan("gitleaks", gitleaks, setup)
            execute_scan("semgrep", lambda cmd, out: invoke(
                cmd, "scan", "--config", KIT / "semgrep.yml", "--metrics=off", "--disable-version-check",
                "--exclude=/reports/",
                *(f"--exclude={filename}" for filename in GENERATED_JSON),
                *(f"--exclude=/{path.as_posix()}" for path in scan_exclusions),
                "--json", "--output", out, project, env=installer.semgrep_env), setup or applicability["semgrep"])
            execute_scan("dependency-check", dependency_check, setup or applicability["dependency-check"])
            execute_scan("syft", syft, setup or applicability["syft"])
            execute_scan("grype", grype, setup or applicability["grype"])
            execute_scan("checkov", checkov, setup or applicability["checkov"])
            if java_needed and resolved_dependencies:
                contexts = dependency_contexts(
                    project, builds, deps, diagnostics.append, files["maven"],
                    maven_reports=maven_reports, declaration_lookup=declaration_lookup,
                )

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
               "mavenIndexDurationSeconds": maven_index_duration,
               "toolVersions": {name: entry.get("version") for name, entry in installer.records.items()},
               "totalFindings": len(issues), "findingsBySeverity": dict(Counter(x["severity"] for x in issues)),
               "requiredScanners": sorted(policy),
               "dependencyResolutionSeconds": dependency_resolution_seconds,
               "findingsByScanner": {name: entry["findingCount"] for name, entry in statuses.items()},
               "sbomComponentCount": statuses["syft"].get("inventoryCount"), "issues": issues,
               "log": str(report_dir / "run.log")}
    summary["totalDurationSeconds"] = round(time.perf_counter() - total_started, 2)
    write_json(report_dir / "security-summary.json", redactor.data(summary))
    export_failed = False
    if not options.setup_only:
        try:
            export_project_reports(destination, report_identity, report_dir, statuses)
        except (OSError, ValueError) as error:
            print(f"Project report export failed: {error}. Private reports: {report_dir}", file=sys.stderr)
            export_failed = True
    failures = {"unavailable", "installation_failed"}
    required = provision_scanners if options.setup_only else {
        name for name, entry in statuses.items() if entry["status"] != "skipped"
    }
    failed = (any(record["status"] in failures for name, record in installer.records.items()
                   if name in required or name not in REPORTS)
              or any(entry["status"] == "failed" for entry in statuses.values()))
    if not options.setup_only:
        unmet = sorted(name for name in policy if statuses[name]["status"] != "success")
        if unmet:
            emit("Required scanners did not complete successfully: " + ", ".join(unmet))
            failed = True
    inventory = None
    if sbom_path := statuses["syft"]["report"]:
        try:
            inventory = json.loads(Path(sbom_path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    counts, review = terminal_summary(
        issues, terminal_metadata, project, contexts, emit, details=options.details,
        statuses=statuses, inventory=inventory, declaration_lookup=declaration_lookup,
    )
    emit("\n=== Security Summary ===")
    emit(f"Scanner execution: {'failed' if failed else 'completed'} ({summary['totalDurationSeconds']:.2f}s)")
    executions = Counter(entry["status"] for entry in statuses.values())
    emit("Scanner status: " + " | ".join(f"{executions[state]} {state}" for state in ("success", "failed", "skipped", "unavailable")))
    validation = "findings require review" if issues else "no findings reported by completed scans"
    if options.setup_only:
        validation = "not run (setup only)"
    elif failed:
        validation = "incomplete coverage; " + validation
    emit(f"Security validation: {validation}")
    emit("Severity (unique findings across scanners): " + " | ".join(f"{level} {counts[level]}" for level in SEVERITIES))
    if counts["UNKNOWN"]:
        emit("UNKNOWN means the scanner supplied no recognized severity. Review these findings for impact.")
    raw = sum(entry["nativeFindingCount"] or 0 for entry in statuses.values())
    emit(f"Raw findings reported: {raw}")
    emit(f"Unique findings across scanners: {sum(counts.values())}")
    emit(f"Unique dependency vulnerability findings: {review['dependency']}")
    emit(f"Unique source findings: {review['source']}")
    emit(f"Dependency findings with unverified package or advisory identity: {review['unverified']}")
    emit(f"Findings reported by multiple scanners: {review['overlap']}")
    emit(f"Unique findings with severity conflicts: {review['severity_conflicts']}")
    emit(f"Review groups across scanners: {review['groups']}")
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
    if not options.setup_only and not export_failed:
        emit(f"Application JSON reports: {destination}")
    if export_failed:
        return 2
    return int(failed)


def main(*, in_memory_preview=False):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    try:
        return execute(args_for(), *detect(), in_memory_preview=in_memory_preview)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Starter kit failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
