"""Discover and scan an existing Java project, with private per-run JSON reports."""
import argparse
import base64
import csv
from collections import Counter, defaultdict
from contextlib import ExitStack
import functools
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from urllib.parse import quote, urlsplit
from xml.etree import ElementTree

from starter_install import CommandTimeout, Installer, detect, recover_dependency_check_lock, refresh_windows_path, run
from starter_findings import (
    NAMES, NORMALIZE, SEVERITIES, Redactor, capture_secrets, evidence_digest, find_maven_declaration, issue_identifier,
    brief, dependency_remediation, project_source, source_label, source_remediation, technology, terminal_field,
    terminal_groups, terminal_package, terminal_severity, terminal_summary, verification_commands,
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
DASHBOARD = "security-dashboard.html"
GENERATED_REPORTS = (*GENERATED_JSON, DASHBOARD)
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


def deduplicated_findings(issues, metadata):
    groups, counts = terminal_groups(issues, metadata)
    unique_findings = [
        {"severity": min((terminal_severity(row) for row in rows), key=SEVERITIES.index),
         "advisoryIds": sorted(aliases),
         "issueIds": [row["issue_id"] for row in rows]}
        for _, findings in groups for rows, aliases in findings
    ]
    return {"uniqueFindingCount": len(unique_findings),
            "uniqueFindingsBySeverity": dict(counts),
            "uniqueFindings": unique_findings}


def review_fingerprint(group, issues_by_id, evidence_by_id, project):
    observations = []
    for issue_id in group["issueIds"]:
        issue = issues_by_id[issue_id]
        evidence = evidence_by_id[issue_id]
        observation = {key: value for key, value in issue.items()
                       if key not in {"issue_id", "issue_number"}}
        if issue["scanner_name"] == NAMES["semgrep"]:
            source = project_source(issue["relative_file_path"], project)
            if not source:
                return None
            try:
                contents = (project / source).read_text(encoding="utf-8")
                rules = (KIT / "semgrep.yml").read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                return None
            observation["rule_id"] = issue["rule_id"].rsplit(".", 1)[-1]
            observation["reviewEvidence"] = evidence_digest([contents, rules])
        else:
            if not evidence.get("reviewEvidence"):
                return None
            observation["reviewEvidence"] = evidence["reviewEvidence"]
            observation["packagePurl"] = evidence.get("package")
            observation["advisoryAliases"] = evidence.get("aliases", [])
        observations.append(evidence_digest(observation))
    # Changes to any observation, including newly corroborating evidence, require review.
    return evidence_digest([group["severity"], group["advisoryIds"], sorted(set(observations))])


def trusted_review_verifier():
    # The managed verifier is installed by the operating-system administrator.
    # No worktree file, environment setting or PATH entry can select it.
    if os.name == "nt":
        import ctypes
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
        if not 0 < length < len(buffer):
            return None
        system = Path(buffer.value)
        directory = system / "Accidion"
        verifier = directory / "VerifyFindingReviews.exe"
        powershell = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        try:
            if any(safe_report_path(path, stat.S_ISDIR) is None for path in (system, directory)):
                return None
            if safe_report_path(verifier, stat.S_ISREG) is None:
                return None
            if safe_report_path(powershell, stat.S_ISREG) is None:
                return None
            paths = ",".join("'" + str(path).replace("'", "''") + "'"
                             for path in (system, directory, verifier))
            acl_check = r"""
$ErrorActionPreference = 'Stop'
$trusted = @('S-1-5-18', 'S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$write = [int][System.Security.AccessControl.FileSystemRights]::Write
$write = $write -bor [int][System.Security.AccessControl.FileSystemRights]::Delete
$write = $write -bor [int][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
$write = $write -bor [int][System.Security.AccessControl.FileSystemRights]::ChangePermissions
$write = $write -bor [int][System.Security.AccessControl.FileSystemRights]::TakeOwnership
$write = $write -bor 0x50000000
$sid = [System.Security.Principal.SecurityIdentifier]
foreach ($path in @(__PATHS__)) {
    if ([System.IO.Directory]::Exists($path)) {
        $acl = [System.IO.Directory]::GetAccessControl($path)
    } else {
        $acl = [System.IO.File]::GetAccessControl($path)
    }
    if ($acl.GetOwner($sid).Value -notin $trusted) { exit 1 }
    $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $raw.DiscretionaryAcl) { exit 1 }
    foreach ($ace in $raw.DiscretionaryAcl) {
        if ($ace -isnot [System.Security.AccessControl.CommonAce]) { exit 1 }
        if ($ace.AceQualifier -eq 'AccessAllowed' -and
            ($ace.AccessMask -band $write) -and
            $ace.SecurityIdentifier.Value -notin $trusted) { exit 1 }
    }
}
exit 0
""".replace("__PATHS__", paths)
            subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", acl_check],
                           capture_output=True, check=True, timeout=10, cwd=system,
                           env={"SystemRoot": str(system.parent), "WINDIR": str(system.parent)})
            return verifier
        except (OSError, ValueError, subprocess.SubprocessError):
            return None

    try:
        directory = Path("/etc").resolve(strict=True) / "accidion"
        verifier = directory / "verify-finding-reviews"
        if safe_report_path(directory, stat.S_ISDIR) is None or safe_report_path(verifier, stat.S_ISREG) is None:
            return None
        if not os.access(verifier, os.X_OK):
            return None
        for path in (verifier, *verifier.parents):
            info = path.stat()
            if info.st_uid != 0 or info.st_mode & 0o022:
                return None
        return verifier
    except (OSError, ValueError, RuntimeError):
        return None


def verified_review_approvals(project, digests, now):
    if not digests:
        return {}, "not_needed"
    verifier = trusted_review_verifier()
    if verifier is None:
        return {}, "unavailable"
    # The verifier independently resolves this project in its trusted application
    # registry and returns only decisions authenticated for that application.
    request = {"schemaVersion": 1, "projectPath": str(project),
               "reviewDigests": sorted(digests)}
    try:
        environment = {}
        if os.name == "nt":
            windows = str(verifier.parents[2])
            environment = {"SystemRoot": windows, "WINDIR": windows}
        result = subprocess.run([verifier], input=json.dumps(request), encoding="utf-8",
                                capture_output=True, check=True, timeout=15,
                                cwd=verifier.parent, env=environment)
        response = json.loads(result.stdout)
        application = response["applicationId"]
        if (response["schemaVersion"] != 1 or response["projectPath"] != request["projectPath"]
                or not isinstance(application, str) or not application.strip()
                or not isinstance(response["approvals"], dict)):
            return {}, "invalid"
        approvals = {}
        for digest, decision in response["approvals"].items():
            if digest not in digests or decision["applicationId"] != application:
                continue
            reviewer = decision["securityReviewer"]
            approved = datetime.fromisoformat(decision["approvedAt"])
            expires = datetime.fromisoformat(decision["expiresAt"])
            if isinstance(reviewer, str) and reviewer.strip() and approved <= now < expires:
                approvals[digest] = {"applicationId": application, "securityReviewer": reviewer,
                                     "approvedAt": decision["approvedAt"], "expiresAt": decision["expiresAt"],
                                     "reviewDigest": digest}
        return approvals, "verified"
    except (OSError, UnicodeError, KeyError, TypeError, ValueError, subprocess.SubprocessError):
        return {}, "invalid"


def load_finding_reviews(path):
    cases = {}
    suspected = set()
    try:
        if safe_report_path(path, stat.S_ISREG) is None:
            return cases, suspected, "missing"
        data = json.loads(path.read_text(encoding="utf-8"))
        if data["schemaVersion"] != 1:
            raise ValueError("Unsupported finding review schema")
        for case in data["cases"]:
            evidence = {key: case[key] for key in ("id", "reason", "advisoryReferences", "findings")}
            if (not all(isinstance(evidence[key], str) and evidence[key].strip() for key in ("id", "reason"))
                    or not isinstance(evidence["advisoryReferences"], list)
                    or not evidence["advisoryReferences"]
                    or not all(isinstance(url, str) and url.strip() for url in evidence["advisoryReferences"])
                    or not isinstance(evidence["findings"], list) or not evidence["findings"]):
                raise ValueError("Incomplete finding review evidence")
            digest = evidence_digest(evidence)
            for finding in evidence["findings"]:
                fingerprint = finding["fingerprint"]
                if (not re.fullmatch(r"[a-f0-9]{64}", fingerprint) or fingerprint in cases
                        or not isinstance(finding["subject"], str) or not finding["subject"].strip()):
                    raise ValueError("Invalid or duplicate review finding")
                cases[fingerprint] = {
                    "caseId": evidence["id"], "reason": evidence["reason"],
                    "advisoryReferences": evidence["advisoryReferences"],
                    "evidence": finding, "reviewDigest": digest,
                    "approvalStatus": "pending", "approval": None,
                }
        if (not isinstance(data["suspectedFingerprints"], list)
                or not all(re.fullmatch(r"[a-f0-9]{64}", value) for value in data["suspectedFingerprints"])):
            raise ValueError("Invalid suspected finding fingerprints")
        suspected = set(data["suspectedFingerprints"])
        if suspected.intersection(cases):
            raise ValueError("Overlapping review dispositions")
    except (OSError, UnicodeError, KeyError, TypeError, ValueError):
        return {}, set(), "invalid"
    return cases, suspected, "loaded"


def finding_dispositions(groups, issues, metadata, project, review_path, now):
    cases, suspected, review_status = load_finding_reviews(review_path)
    approvals, verification_status = verified_review_approvals(
        project, {case["reviewDigest"] for case in cases.values()}, now
    )
    issues_by_id = {issue["issue_id"]: issue for issue in issues}
    evidence_by_id = {issue["issue_id"]: evidence for issue, evidence in zip(issues, metadata, strict=True)}
    actionable = Counter(dict.fromkeys(SEVERITIES, 0))
    false_positive = actionable.copy()
    pending = suspected_count = 0
    fingerprints = [
        review_fingerprint(group, issues_by_id, evidence_by_id, project) if cases or suspected else None
        for group in groups
    ]
    occurrences = Counter(fingerprints)
    for group, fingerprint in zip(groups, fingerprints, strict=True):
        review = cases.get(fingerprint) if occurrences[fingerprint] == 1 else None
        if review:
            approval = approvals.get(review["reviewDigest"])
            if approval:
                review = {**review, "approvalStatus": "approved", "approval": approval}
            group["review"] = review
        if review and review["approvalStatus"] == "approved":
            group["disposition"] = "confirmed_false_positive"
            false_positive[group["severity"]] += 1
            continue
        is_suspected = fingerprint in suspected
        group["disposition"] = "pending_review" if review or is_suspected else "actionable"
        if is_suspected:
            group["review"] = {"approvalStatus": "pending", "suspectedFalsePositive": True,
                               "evidence": {"fingerprint": fingerprint}}
        pending += group["disposition"] == "pending_review"
        suspected_count += is_suspected
        actionable[group["severity"]] += 1
    return {
        "findingReviewStatus": review_status,
        "findingApprovalVerificationStatus": verification_status,
        "observedFindingCount": len(groups),
        "actionableFindingCount": sum(actionable.values()),
        "confirmedFalsePositiveCount": sum(false_positive.values()),
        "suspectedFalsePositiveCount": suspected_count,
        "pendingReviewCount": pending,
        "actionableFindingsBySeverity": dict(actionable),
        "falsePositiveFindingsBySeverity": dict(false_positive),
    }


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
    failures = []
    for index, (family, root, tool) in enumerate(builds):
        try:
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
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            failure = f"{family} dependency resolution failed for {root.relative_to(project)}: {error}"
            diagnostic(failure)
            failures.append(failure)
    if failures:
        raise RuntimeError("; ".join(failures))


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
    paths = [f"reports/{name}" for name in GENERATED_REPORTS]
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
    outputs = [destination / name for name in GENERATED_REPORTS]
    for output in outputs:
        safe_report_path(output, stat.S_ISREG)
    for output in reversed(outputs):
        output.unlink(missing_ok=True)
    return destination, identity


def export_project_reports(destination, identity, report_dir, statuses, *, project_identity=None):
    project = destination.parent
    if project_identity is not None:
        current_project = safe_report_path(project, stat.S_ISDIR)
        if (current_project is None or not os.path.samestat(project_identity, current_project)
                or project.resolve(strict=True) != project):
            raise ValueError(f"Application directory changed during the scan: {project}")
        # Recheck tracked paths in case the Git index changed during the scan.
        protect_project_reports(project)

    current = safe_report_path(destination, stat.S_ISDIR)
    if current is None and project_identity is not None:
        # The caller still holds the original project lock. Only recover an absent
        # directory in the same application, never adopt a replacement directory.
        destination.mkdir(mode=0o700)
        current = safe_report_path(destination, stat.S_ISDIR)
        identity = current
    if current is None or not os.path.samestat(identity, current):
        raise ValueError(f"Project report directory changed during the scan: {destination}")
    if os.path.lexists(destination / ".git"):
        raise ValueError(f"Project reports cannot be written to a separate Git repository: {destination}")
    scanner_reports = [
        Path(path).name
        for entry in statuses.values() if entry["status"] == "success"
        for path in (entry["report"], *entry.get("additionalReports", ())) if path
    ]
    # Stage every sanitized report before publication and publish the summary last.
    with tempfile.TemporaryDirectory(prefix=".accidion-export-", dir=destination) as directory:
        staging = Path(directory)
        names = [*scanner_reports]
        if safe_report_path(report_dir / DASHBOARD, stat.S_ISREG) is not None:
            names.append(DASHBOARD)
        names.append("security-summary.json")
        for name in names:
            shutil.copyfile(report_dir / name, staging / name)
        current = safe_report_path(destination, stat.S_ISDIR)
        if current is None or not os.path.samestat(identity, current):
            raise ValueError(f"Project report directory changed while staging reports: {destination}")
        for name in names:
            safe_report_path(destination / name, stat.S_ISREG)
        for name in names:
            (staging / name).replace(destination / name)


def execute(options, system, arch, *, in_memory_preview=False):
    with ExitStack() as stack:
        return execute_with_reports(options, system, arch, stack, in_memory_preview=in_memory_preview)


def scanner_progress_message(label, status, duration=0, count=None, unit="finding", reason=None):
    if status == "running":
        result = "Scanning in progress"
    elif count is None:
        result = reason or "No results available"
    else:
        result = f"{count} {unit if count == 1 else unit + 's'}"
        if reason:
            result += f" | {reason}"
    return f"{label}: {status} | {duration:.2f}s | {result}"


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
    if not nvd_mirror:
        nvd_mirror = os.getenv("ACCIDION_NVD_DATAFEED_URL")
        if nvd_mirror is None and not os.getenv("NVD_API_KEY"):
            nvd_mirror = "https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/nvdcve-{0}.json.gz"
    if nvd_mirror:
        mirror = urlsplit(nvd_mirror)
        if (mirror.scheme != "https" or not mirror.hostname or mirror.username is not None
                or mirror.query or mirror.fragment or mirror.path.count("{0}") != 1
                or any(character.isspace() for character in nvd_mirror)):
            raise ValueError("The NVD feed requires an HTTPS URL template with exactly one {0} and no credentials")
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
            project_identity = safe_report_path(project, stat.S_ISDIR)
            destination, report_identity = prepare_project_reports(project, home, stack)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise ValueError(f"Project report export could not be prepared: {error}") from error
    report_dir = private_run_path(application_reports)
    total_started = time.perf_counter()
    started = datetime.now(timezone.utc)
    scan_clock = time.monotonic()
    redactor = Redactor()
    live_log = report_dir / "run.log"
    live_log.touch()
    statuses = {}
    issues = []
    terminal_metadata = []
    contexts = {}
    diagnostics = []

    def emit(message, *, quiet=False):
        # Preserve spacing between sections and flatten controls in scanner evidence.
        prefix = "\n" if message.startswith("\n") else ""
        safe = "".join(char if char.isprintable() else " " for char in redactor.text(message.lstrip("\n")))
        if not quiet or options.verbose:
            print(prefix + safe, flush=True)
        with live_log.open("a", encoding="utf-8") as output:
            output.write(prefix + safe + "\n")

    def diagnostic(message):
        emit(message, quiet=True)

    emit("=== Accidion Security Scan ===" if not options.setup_only else "=== Accidion Setup ===")
    terminal_field(diagnostic, "Application", app_name)
    terminal_field(diagnostic, "Project directory", project)
    operating_system = {"windows": "Windows", "linux": "Linux", "macos": "macOS"}.get(system, system)
    terminal_field(diagnostic, "Operating system", f"{operating_system} ({arch})")
    build_systems = [name for family, name in (("maven", "Maven"), ("gradle", "Gradle")) if roots[family]]
    terminal_field(diagnostic, "Build system", ", ".join(build_systems) or "None detected")
    terminal_field(diagnostic, "Started (UTC)", started.strftime("%Y-%m-%d %H:%M:%S"))
    applicable = [NAMES.get(name, "Syft") for name, reason in applicability.items() if reason is None]
    terminal_field(diagnostic, "Applicable scanners", ", ".join(applicable) or "None")
    diagnostic("")

    def progress(label, status, duration=0, count=None, unit="finding", reason=None):
        long_reason = reason and not options.verbose and len(reason) > 220
        if long_reason:
            diagnostic(scanner_progress_message(label, status, duration, count, unit, reason))
        emit(scanner_progress_message(label, status, duration, count, unit,
                                      brief(reason, 220) if long_reason else reason), quiet=status == "running")

    issue_ids = Counter()
    declaration_lookup = maven_declaration_lookup()
    maven_index = {}
    maven_reports = {}
    maven_index_duration = None
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
                    diagnostic(f"{label} | Loading {native.name}")
                    stage_started = time.perf_counter()
                    with native.open(encoding="utf-8-sig") as source:
                        report = json.load(source)
                    processing["loadSeconds"] = round(time.perf_counter() - stage_started, 3)
                    diagnostic(f"{label} | Sanitizing {native.name}")
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
                        diagnostic(f"{label} | Normalizing {native_count} findings")
                        if maven_enrichment:
                            diagnostic(f"{label} | Enriching Maven dependency evidence during normalization")
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
                                diagnostic(f"{label} | Processed {processed}/{native_count} findings in {now - stage_started:.2f}s")
                                next_update = now + 5
                        elapsed = time.perf_counter() - stage_started
                        processing["normalizeSeconds"] = round(elapsed - enrichment_seconds, 3)
                        if maven_enrichment:
                            processing["mavenEnrichmentSeconds"] = round(enrichment_seconds, 3)
                        diagnostic(f"{label} | Processed {processed}/{native_count} findings in {elapsed:.2f}s")
                    if reason := report_error(name, report):
                        problems.append(reason)
                except FileNotFoundError:
                    problems.append(f"Scanner did not write {native.name}")
                except (OSError, ValueError, TypeError, AttributeError, KeyError, RuntimeError) as error:
                    problems.append(f"Could not interpret {native.name}: {error}")
                finally:
                    processing["totalSeconds"] = round(time.perf_counter() - processing_started, 3)
                    diagnostic(f"{label} | Report processing took {processing['totalSeconds']:.3f}s")
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
                    diagnostic("Preparing Maven/Gradle dependencies...")
                    resolve_dependencies(project, builds, deps, log, diagnostics.append, timeout=timeout)
                    diagnostic("Dependency resolution completed.")
                except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                    resolution_error = str(error)
                finally:
                    dependency_resolution_seconds = round(time.perf_counter() - resolution_started, 3)

                tree_paths = sorted(deps.rglob("maven-dependency-tree.json"))
                if tree_paths:
                    started = time.perf_counter()
                    diagnostic(f"Maven | Loading {len(tree_paths)} dependency tree report(s)")
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
                    diagnostic(f"Maven | Prepared dependency tree reports in {time.perf_counter() - started:.3f}s")
                    diagnostic("Maven | Indexing dependency chains")
                    started = time.perf_counter()
                    maven_index = index_maven_dependencies(exported[path] for path in sorted(exported))
                    maven_index_duration = round(time.perf_counter() - started, 3)
                    diagnostic(f"Maven | Indexed {len(maven_index)} dependency versions in {maven_index_duration:.3f}s")

            def dependency_check(cmd, out):
                if not java:
                    raise RuntimeError("A compatible JDK is unavailable")
                prepare_dependencies()
                if resolution_error:
                    raise RuntimeError(f"Dependency resolution failed: {resolution_error}")
                diagnostic("OWASP Dependency-Check: preparing vulnerability database...")
                database = vulnerability_cache("dependency-check", home / "dependency-check-data")
                args = ["--project", project.name, "--format", "JSON", "--out", out.parent,
                        "--data", database, "--scan", deps,
                        "--exclude", "**/maven-dependency-tree.json",
                        "--exclude", "**/gradle-dependency-paths-*.json"]
                for artifact in files["jars"]:
                    args.extend(("--scan", artifact))
                if nvd_mirror:
                    diagnostics.append("OWASP Dependency-Check uses a configured NVD JSON 2.0 feed")
                    args.extend(("--nvdDatafeed", nvd_mirror))
                if key := os.getenv("NVD_API_KEY"):
                    if not re.fullmatch(r"[a-zA-Z0-9-]+", key):
                        raise ValueError("NVD_API_KEY contains unexpected characters")
                    redactor.add([key])
                    properties = work / "dependency-check.properties"
                    properties.write_text(f"nvd.api.key={key}\n", encoding="ascii")
                    args.extend(("--propertyfile", properties))
                diagnostic("OWASP Dependency-Check: starting database update and dependency analysis...")
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

        for message in diagnostics:
            print(message, file=log)
        log.seek(0)
        with live_log.open("a", encoding="utf-8") as output:
            output.write("\n=== Scanner diagnostics ===\n")
            output.write(redactor.text(log.read()))

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
    summary.update(deduplicated_findings(issues, terminal_metadata))
    review_path = (Path(launcher).resolve().parent if launcher else project) / "security-finding-reviews.json"
    summary.update(finding_dispositions(summary["uniqueFindings"], issues, terminal_metadata,
                                        project, review_path, datetime.now(timezone.utc)))
    summary["totalDurationSeconds"] = round(time.perf_counter() - total_started, 2)
    write_json(report_dir / "security-summary.json", redactor.data(summary))
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
    dashboard_failed = False
    if not options.setup_only:
        try:
            write_dashboard(report_dir / DASHBOARD, summary, terminal_metadata, inventory, project,
                            files, contexts, declaration_lookup, failed, redactor)
        except (OSError, ValueError, TypeError, KeyError, RuntimeError) as error:
            print(f"Security dashboard generation failed: {redactor.text(str(error))}", file=sys.stderr)
            dashboard_failed = True
    export_failed = False
    if not options.setup_only:
        try:
            export_project_reports(destination, report_identity, report_dir, statuses,
                                   project_identity=project_identity)
        except (OSError, ValueError) as error:
            print(f"Project report export failed: {error}. Private reports: {report_dir}", file=sys.stderr)
            export_failed = True
    if options.verbose:
        emit("\nDiagnostics")
        for name, record in installer.records.items():
            emit(f"  {name}: {record['status']} {record.get('version') or ''}".rstrip())
        for message in diagnostics:
            emit(f"  {message}")
    if options.details or options.verbose:
        counts, review = terminal_summary(
            issues, terminal_metadata, project, contexts, emit, details=options.details,
            statuses=statuses, inventory=inventory, declaration_lookup=declaration_lookup,
        )
        emit("\n=== Security Summary ===")
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
    else:
        emit("")
    emit(f"Scanner execution: {'failed' if failed else 'completed'} ({summary['totalDurationSeconds']:.2f}s)")
    if not options.setup_only and not export_failed:
        emit(f"Application JSON reports: {destination}")
        if not dashboard_failed:
            emit(f"Application security dashboard: {destination / DASHBOARD}")
            emit(open_dashboard_in_chrome(destination / DASHBOARD, system))
    elif not export_failed:
        emit(f"Private reports: {report_dir}")
    emit(f"Diagnostic log: {report_dir / 'run.log'}")
    if export_failed or dashboard_failed:
        return 2
    return int(failed)


def windows_chrome():
    import winreg

    location = r"Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, location) as key:
                executable = Path(os.path.expandvars(winreg.QueryValue(key, None)))
            if executable.name.casefold() == "chrome.exe" and executable.is_file():
                return executable
        except (OSError, ValueError, TypeError):
            continue
    for name in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        if root := os.environ.get(name):
            executable = Path(root) / "Google" / "Chrome" / "Application" / "chrome.exe"
            if executable.is_file():
                return executable
    return None


def windows_desktop_available():
    import ctypes
    from ctypes import wintypes

    class WindowStationFlags(ctypes.Structure):
        _fields_ = [("inherit", wintypes.BOOL), ("reserved", wintypes.BOOL), ("flags", wintypes.DWORD)]

    user32 = ctypes.windll.user32
    station = user32.GetProcessWindowStation
    station.restype = wintypes.HANDLE
    get_info = user32.GetUserObjectInformationW
    get_info.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                         ctypes.POINTER(wintypes.DWORD))
    info = WindowStationFlags()
    needed = wintypes.DWORD()
    return bool(get_info(station(), 1, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(needed))
                and info.flags & 1)


def wsl_chrome():
    executable = shutil.which("chrome.exe")
    if executable:
        return Path(executable)
    cmd = shutil.which("cmd.exe")
    if not cmd:
        windows_cmd = run(["wslpath", "-u", r"C:\Windows\System32\cmd.exe"], capture=True, timeout=3).strip()
        if not Path(windows_cmd).is_file():
            return None
        cmd = windows_cmd
    # CMD only receives fixed environment-variable names. Project filenames are
    # translated and passed directly to Chrome as a single file URL argument.
    for variable in ("ProgramFiles", "LOCALAPPDATA"):
        result = subprocess.run([cmd, "/d", "/u", "/c", "set", variable], capture_output=True, timeout=3)
        if result.returncode:
            continue
        for line in result.stdout.decode("utf-16-le").splitlines():
            name, _, directory = line.partition("=")
            if name.casefold() not in {"programfiles", "programfiles(x86)", "localappdata"}:
                continue
            windows_path = str(PureWindowsPath(directory) / "Google" / "Chrome" / "Application" / "chrome.exe")
            local = Path(run(["wslpath", "-u", windows_path], capture=True, timeout=3).strip())
            if local.is_file():
                return local
    return None


def open_dashboard_in_chrome(path, system):
    if any(os.environ.get(name, "").lower() not in {"", "0", "false", "no"}
           for name in ("CI", "GITHUB_ACTIONS", "TF_BUILD")):
        return "Chrome: skipped (CI)"
    try:
        path = path.resolve(strict=True)
        application = path.parent.parent
        wsl = system == "linux" and (os.getenv("WSL_INTEROP") or os.getenv("WSL_DISTRO_NAME")
                                      or "microsoft" in platform.release().lower())
        if system == "macos":
            console_uid = Path("/dev/console").stat().st_uid
            if not console_uid or console_uid != os.getuid():
                return "Chrome: skipped (no desktop session)"
            subprocess.run(["/usr/bin/open", "-a", "Google Chrome", path.as_uri()],
                           stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=5)
            return "Chrome: dashboard open requested"
        if system == "windows":
            if not windows_desktop_available():
                return "Chrome: skipped (no desktop session)"
            executable = windows_chrome()
            url = path.as_uri()
        elif wsl:
            executable = wsl_chrome()
            if not executable:
                return "Chrome: Windows Google Chrome not found"
            windows_path = PureWindowsPath(run(["wslpath", "-w", path], capture=True, timeout=3).strip())
            if not windows_path.is_absolute():
                raise ValueError("WSL did not return an absolute Windows path")
            translated = windows_path.as_posix()
            prefix = "file:" if translated.startswith("//") else "file:///"
            url = prefix + quote(translated, safe="/:$")
        else:
            if not (os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY")):
                return "Chrome: skipped (no desktop session)"
            executable = next((Path(found) for name in ("google-chrome", "google-chrome-stable")
                               if (found := shutil.which(name))), None)
            url = path.as_uri()
        if not executable:
            return "Chrome: Google Chrome not found"
        executable = executable.resolve(strict=True)
        if executable.is_relative_to(application):
            return "Chrome: ignored an executable inside the application"
        detached = ({"creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP}
                    if system == "windows" else {"start_new_session": True})
        browser = subprocess.Popen([executable, url], cwd=executable.parent, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **detached)
        try:
            if browser.wait(timeout=0.15):
                return "Chrome: launch failed"
        except subprocess.TimeoutExpired:
            pass  # Chrome runs independently of the scan.
        return "Chrome: dashboard open requested"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        return "Chrome: could not open Google Chrome"


def dashboard_maven_modules(poms):
    modules = defaultdict(list)
    for pom in poms:
        try:
            root = ElementTree.parse(pom).getroot()
        except (OSError, ElementTree.ParseError):
            continue
        group = root.findtext("{*}groupId") or root.findtext("{*}parent/{*}groupId")
        artifact = root.findtext("{*}artifactId")
        version = root.findtext("{*}version") or root.findtext("{*}parent/{*}version")
        if all((group, artifact, version)):
            modules[":".join(part.strip() for part in (group, artifact, version))].append(pom)
    return {coordinate: paths[0] for coordinate, paths in modules.items() if len(paths) == 1}


def dashboard_data(summary, metadata, inventory, project, files, contexts, declaration_lookup, failed):
    issues = summary["issues"]
    evidence = {row["issue_id"]: value for row, value in zip(issues, metadata, strict=True)}
    by_id = {row["issue_id"]: row for row in issues}
    module_roots = {file.parent for kind in ("maven", "gradle") for file in files[kind]}
    maven_modules = dashboard_maven_modules(files["maven"])
    recipes, descriptions, chains, limitations, finding_text = [], [], [], [], []
    recipe_indices, description_indices, chain_indices, limitation_indices, text_indices = {}, {}, {}, {}, {}
    reported_project = str(summary["project"]).replace("\\", "/").rstrip("/")

    @functools.lru_cache(maxsize=None)
    def application_source(path):
        if not path:
            return None
        relative = project_source(path, project)
        normalized = path.replace("\\", "/")
        if relative is None and normalized.startswith(reported_project + "/"):
            relative = project_source(normalized[len(reported_project) + 1:], project)
        return relative

    @functools.lru_cache(maxsize=None)
    def module_for(path):
        relative = application_source(path)
        if relative:
            parent = next((folder for folder in (project / relative).parents if folder in module_roots), None)
            if parent:
                return parent.relative_to(project).as_posix()
        return "Unavailable"

    @functools.lru_cache(maxsize=None)
    def saved_dependency_context(chain, component, version):
        nodes = chain.split(" -> ")
        pom = maven_modules.get(nodes[0])
        if not pom or len(nodes) < 2 or nodes[-1] != f"{component}:{version}":
            return None
        parent, _, parent_version = nodes[1].rpartition(":")
        if not parent or not parent_version:
            return None
        _, start, end = declaration_lookup(pom.parent, parent, parent_version, declaration_pom=pom)
        location = source_label(pom.relative_to(project).as_posix(), start, end)
        return ("Direct" if len(nodes) == 2 else "Transitive", parent, parent_version, location)

    def intern(value, items, indices):
        key = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        if key not in indices:
            indices[key] = len(items)
            items.append(value)
        return indices[key]

    def source_for(row):
        path, start, end = evidence[row["issue_id"]].get("sourceLocation", (None, None, None))
        reported = path or row["relative_file_path"] or row["source_file"]
        display = application_source(reported) or reported
        return display, start or row["start_line"], end or row["end_line"]

    records = []
    for group in summary["uniqueFindings"]:
        rows = [by_id[issue_id] for issue_id in group["issueIds"]]
        primary = rows[0]
        package = None
        dependency_contexts_for_group = {}
        component = version = relationship = None
        parents = []
        dependency = primary["scanner_name"] in {NAMES["dependency-check"], NAMES["grype"]}
        locations = list(dict.fromkeys(location for row in rows
                                       if (location := source_for(row))[0]))
        if dependency:
            package = terminal_package(primary, evidence[primary["issue_id"]].get("package"))
            package = package or ("reported", primary["affected_dependency"] or "Unknown package",
                                  primary["installed_version"], primary.get("scan_target"), primary["scanner_name"])
            key = package[1:3]
            context = contexts.get(key, ())
            if not context and package[0] == "maven" and any(row.get("scan_target") != "container" for row in rows):
                context = sorted({match for row in rows for chain in row["dependency_chains"] or []
                                  if (match := saved_dependency_context(chain, *key))})
            dependency_contexts_for_group = {key: context}
            component, related_locations, relationship, parents, version, steps, verification = (
                dependency_remediation(package, rows, project, dependency_contexts_for_group, declaration_lookup))
            locations = list(dict.fromkeys([*locations, *related_locations]))
            title = primary["issue_name"]
            problem = primary["issue_description"]
            risk = primary["security_impact"]
        else:
            title, problem, risk, steps, verification = source_remediation(primary)

        # Scanner paths may point to extracted archives. Only verified application files
        # may contribute working directories and build commands.
        command_locations = [(relative, start, end) for path, start, end in locations
                             if (relative := application_source(path))]
        if dependency:
            command_locations.extend(
                (path, row.get("direct_dependency_start_line"), row.get("direct_dependency_end_line"))
                for row in rows if (path := application_source(row.get("direct_dependency_source_file")))
            )
        commands = list(verification_commands(project, command_locations, package, primary["rule_id"]))
        recipe = intern({
            "steps": [step.replace("advisory IDs and links in --details", "advisory IDs and links below")
                      for step in steps if step],
            "verify": verification, "commands": commands,
        }, recipes, recipe_indices)

        modules = {module_for(path) for path, _, _ in locations}
        scopes = set()
        observations = []
        declarations = set()
        package_locations = set()
        for row in rows:
            proof = evidence[row["issue_id"]]
            path, start, end = source_for(row)
            module = module_for(path)
            package_paths = [item for item in proof.get("locations", []) if isinstance(item, str) and item]
            if dependency and path and technology(path) not in {"Maven", "Gradle"}:
                package_paths.append(path)
                path, start, end = None, None, None
            package_paths = list(dict.fromkeys(package_paths))
            if dependency:
                package_locations.update(package_paths)
            parent = ":".join(filter(None, (row["direct_dependency"], row["direct_dependency_version"]))) \
                if row.get("direct_dependency") else ":".join(filter(None, (row["parent_dependency"], row["parent_version"])))
            if not parent and row["dependency_type"] == "Direct":
                parent = "Direct dependency"
            if dependency and module != "Unavailable":
                scopes.add((module, parent or "Parent unavailable"))
            if dependency and (parent_path := application_source(row.get("direct_dependency_source_file"))):
                declarations.add(("Transitive", parent, parent_path, row.get("direct_dependency_start_line"),
                                  row.get("direct_dependency_end_line"), module_for(parent_path)))
            description = intern({key: row[key] for key in (
                "issue_description", "root_cause", "security_impact", "recommended_remediation"
            )}, descriptions, description_indices)
            observations.append({
                "id": row["issue_id"], "number": row["issue_number"], "name": row["issue_name"],
                "scanner": row["scanner_name"], "severity": row["severity"], "rule": row["rule_id"],
                "cves": row["cve_id"], "cwes": row["cwe_id"], "file": path, "artifact": row["affected_filename"],
                "start": start, "end": end, "module": module, "packageLocations": package_paths,
                "dependency": dependency,
                "technology": technology(path) or ("Container image" if row.get("scan_target") == "container" else None),
                "installed": row["installed_version"], "fixed": row["fixed_version"], "fixState": proof.get("fix_state"),
                "relationship": row["dependency_type"], "parent": parent,
                "chains": intern(row["dependency_chains"] or [], chains, chain_indices),
                "references": row["reference_links"] or [], "locations": proof.get("locations", []),
                "resource": proof.get("resource"), "purl": proof.get("package"), "target": row.get("scan_target"),
                "description": description, "limitations": intern(row["evidence_limitations"], limitations, limitation_indices),
            })

        if package and package[0] == "maven":
            for relation, parent, parent_version, source in dependency_contexts_for_group.get((package[1], version), ()):
                match = re.fullmatch(r"(.+?):([1-9]\d*)(?:-([1-9]\d*))?", source)
                path = match[1] if match else source
                start = int(match[2]) if match else None
                end = int(match[3]) if match and match[3] else None
                module = module_for(path)
                label = ("Direct dependency" if relation == "Direct"
                         else ":".join(filter(None, (parent, parent_version))))
                scopes.add((module, label or "Parent unavailable"))
                if relative := application_source(path):
                    declarations.add((relation, ":".join(filter(None, (parent, parent_version))),
                                      relative, start, end, module))
        if dependency:
            locations = [item for item in locations if technology(item[0]) in {"Maven", "Gradle"}]
            declared_ranges = {(path, start, end or start) for _, _, path, start, end, _ in declarations}
            locations = [(path, start, end) for path, start, end in locations
                         if (path, start, end or start) not in declared_ranges]
        modules.update(module for module, _ in scopes)
        modules.update(entry[-1] for entry in declarations)
        modules = sorted(modules - {"Unavailable"}) or ["Unavailable"]
        if dependency and not scopes:
            scopes.add(("Unavailable", "Parent unavailable"))
        records.append({
            "title": title, "text": intern([problem, risk], finding_text, text_indices), "severity": group["severity"],
            "scanners": sorted({row["scanner_name"] for row in rows}),
            "ids": group["advisoryIds"] or sorted({row["rule_id"] for row in rows if row["rule_id"]}),
            "package": component, "version": version, "relationship": relationship, "parents": parents,
            "modules": modules, "scopes": sorted(scopes), "locations": locations,
            "declarations": sorted(declarations, key=lambda item: (item[2], item[3] or 0, item[0], item[1] or "")),
            "packageLocations": sorted(package_locations),
            "transitive": "Transitive" in (relationship or "")
                          or any("Transitive" in (row["dependency_type"] or "") for row in rows),
            "technologies": sorted({kind for path, _, _ in locations if (kind := technology(path))}
                                   | {row["technology"] for row in observations if row["technology"]})
                            or (["Java package (Maven)"] if package and package[0] == "maven" else []),
            "disposition": group.get("disposition", "actionable"), "review": group.get("review"),
            "recipe": recipe, "observations": observations,
        })

    counts = {
        "original": summary["totalFindings"], "observed": len(records),
        "actionable": summary["actionableFindingCount"], "pending": summary["pendingReviewCount"],
        "falsePositives": summary["confirmedFalsePositiveCount"], "suspected": summary["suspectedFalsePositiveCount"],
        "actionableSeverity": summary["actionableFindingsBySeverity"],
        "observedSeverity": summary["uniqueFindingsBySeverity"],
        "inventory": summary["sbomComponentCount"],
    }
    return {
        "application": summary["applicationName"], "execution": "Failed or incomplete" if failed else "Completed",
        "generated": summary["generatedAt"], "counts": counts, "findings": records,
        "recipes": recipes, "descriptions": descriptions, "chains": chains, "limitations": limitations,
        "findingText": finding_text, "reviewVerification": summary.get("findingApprovalVerificationStatus"),
        "scanners": [{"name": NAMES.get(name, "Syft"), "status": entry["status"],
                      "reason": entry["reason"], "count": entry["findingCount"]}
                     for name, entry in summary["scanners"].items()],
        "inventory": [
            [*(row.get(key) for key in ("name", "version", "type", "purl")),
             list(dict.fromkeys(prop["value"] for prop in row.get("properties") or []
                                if re.fullmatch(r"syft:location:\d+:(?:path|accessPath)", prop.get("name") or "")
                                and isinstance(prop.get("value"), str) and prop["value"]))]
            for row in (inventory or {}).get("components", [])
        ],
    }


def write_dashboard(path, summary, metadata, inventory, project, files, contexts, declaration_lookup, failed, redactor):
    data = dashboard_data(summary, metadata, inventory, project, files, contexts, declaration_lookup, failed)
    # Escape HTML raw-text delimiters in inert JSON. The UI treats every value as text.
    payload = json.dumps(redactor.data(data), ensure_ascii=True, separators=(",", ":"))
    payload = payload.replace("<", r"\u003c").replace(">", r"\u003e").replace("&", r"\u0026")
    script_hash = base64.b64encode(hashlib.sha256(DASHBOARD_SCRIPT.encode("utf-8")).digest()).decode("ascii")
    page = DASHBOARD_HTML.replace("SCRIPT_HASH", script_hash).replace("DASHBOARD_SCRIPT", DASHBOARD_SCRIPT)
    temporary = path.with_suffix(".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as output:
        header, footer = page.split("DASHBOARD_DATA", 1)
        output.write(header)
        output.write(payload)
        output.write(footer)
    temporary.replace(path)




DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-SCRIPT_HASH'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>Security remediation | Accidion</title>
<style>
:root{color-scheme:light;--ink:#162331;--muted:#516275;--line:#d8e1e7;--surface:#fff;--page:#f1f5f7;--brand:#08665d;--nav:#12282b;--radius:12px}
*{box-sizing:border-box}body{margin:0;background:var(--page);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--brand);text-underline-offset:3px}a:hover{text-decoration-thickness:2px}button,input,select{font:inherit}
button{cursor:pointer;border:1px solid var(--line);border-radius:7px;background:white;color:var(--ink);padding:.36rem .7rem}button:hover:enabled{border-color:var(--brand);background:#eaf8f4}button:disabled{opacity:.45;cursor:default}
:focus-visible{outline:3px solid #0c8778;outline-offset:3px}header{background:var(--nav);color:white}header a{color:#bdeee4}h1,h2,h3,h4,p{margin:0 0 .65rem}h1{font-size:clamp(1.85rem,4vw,3rem);letter-spacing:-.04em;line-height:1.1}h2{font-size:1.45rem;letter-spacing:-.02em}h3{font-size:1.1rem}h4{font-size:1rem}
.shell{max-width:1240px;margin:auto;padding:1.1rem clamp(1rem,3vw,2.5rem)}.top,.row,.pager{display:flex;gap:.9rem;align-items:center;justify-content:space-between;flex-wrap:wrap}.brand{font-weight:750;letter-spacing:.02em}nav{display:flex;gap:1.15rem;flex-wrap:wrap}.hero{padding-top:1.4rem;padding-bottom:1.7rem}.hero p{color:#bbd8d6;margin-bottom:0}.status{border:1px solid #638e87;border-radius:999px;padding:.2rem .75rem;font-size:.86rem;color:#e2f6f2;white-space:nowrap}
main section{scroll-margin-top:1rem;margin:1.5rem 0 2rem}.muted,.hint{color:var(--muted)}.hint{font-size:.9rem;margin:.25rem 0 .7rem}.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:1rem 1.15rem}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:.75rem;margin-bottom:.8rem}.metric strong{display:block;font-size:1.65rem;letter-spacing:-.03em;font-variant-numeric:tabular-nums}.metric span{font-size:.88rem;color:var(--muted)}
.severities{display:flex;gap:.55rem;flex-wrap:wrap;margin:.55rem 0}.badge{display:inline-block;font-size:.77rem;font-weight:750;color:#304556;background:#e8edf2;padding:.17rem .52rem;border-radius:6px;white-space:nowrap}.critical{background:#f5dceb;color:#781448}.high{background:#ffe4df;color:#8a2a1f}.medium{background:#ffefcf;color:#714706}.low{background:#dbf2e9;color:#16574a}.badge + .badge{margin-left:.25rem}
.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.7rem;margin:.8rem 0 1rem}.filters label{display:grid;gap:.24rem;font-weight:650;font-size:.86rem}.filters label:first-child{grid-column:span 2}input,select{width:100%;min-width:0;background:#fff;color:var(--ink);border:1px solid #b9c8d1;border-radius:7px;padding:.45rem .55rem}label.inventory-search{display:block;max-width:30rem}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:9px}table{width:100%;border-collapse:collapse;text-align:left;background:white}th,td{vertical-align:top;padding:.55rem .7rem;border-bottom:1px solid var(--line);overflow-wrap:anywhere}th{background:#eaf0f3;font-size:.84rem;white-space:nowrap}tbody tr:last-child td{border-bottom:0}td:nth-child(2),td:nth-child(3){min-width:8rem}td small{display:block;color:var(--muted)}.pager{margin:.7rem 0 .25rem}.pager div{display:flex;align-items:center;gap:.55rem}.pager p{margin:0;color:var(--muted);font-size:.9rem}
summary{cursor:pointer;font-weight:700;overflow-wrap:anywhere}summary:hover{color:var(--brand)}details.finding{background:#fff;border:1px solid var(--line);border-radius:9px;margin:.55rem 0;padding:.68rem .85rem}details.finding[open]{border-color:#91bcb5}.finding-title{display:inline-block;vertical-align:middle;max-width:calc(100% - 2rem)}.finding-title b{display:block;line-height:1.3}.finding-title small{display:block;color:var(--muted);font-weight:450;margin-top:.15rem}.detail{border-top:1px solid var(--line);margin-top:.7rem;padding-top:.75rem}.detail p,.detail li,dd{overflow-wrap:anywhere}.detail details{border-left:2px solid var(--line);padding:.32rem .65rem;margin:.5rem 0}
dl{display:grid;grid-template-columns:minmax(9rem,15rem) minmax(0,1fr);gap:.25rem .75rem;margin:.6rem 0 .9rem}dt{font-weight:650;color:var(--muted)}dd{margin:0;white-space:pre-wrap}ol,ul{padding-left:1.4rem}.commands{background:#edf4f5;border-radius:8px;padding:.55rem .7rem;margin:.45rem 0;overflow-wrap:anywhere}code{font-family:ui-monospace,Consolas,monospace}.command-copy{margin-left:auto}.by-scanner{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:.65rem}.by-scanner p{margin-bottom:0}
[hidden]{display:none!important}@media(max-width:650px){.filters label:first-child{grid-column:auto}dl{grid-template-columns:1fr}dd{margin-bottom:.4rem}nav{font-size:.88rem}}
</style>
</head>
<body>
<header>
  <div class="shell top"><span class="brand">Accidion Security</span><nav aria-label="Report sections"><a href="#overview">Overview</a><a href="#priority">Fix first</a><a href="#findings">Findings</a><a href="#scanners">Scanner guidance</a><a id="inventory-nav" href="#inventory">Inventory</a></nav></div>
  <div class="shell hero"><div class="row"><h1 id="application">Security remediation</h1><span id="execution" class="status"></span></div><p id="generated"></p></div>
</header>
<main class="shell">
  <noscript><p class="card">JavaScript is required to display this offline report. The original findings are available in <a href="security-summary.json">security-summary.json</a>.</p></noscript>
  <section id="overview" aria-labelledby="overview-title">
    <h2 id="overview-title">Security overview</h2>
    <div id="metrics" class="metrics"></div>
    <div class="card"><h3>Actionable severity</h3><div id="severity" class="severities"></div><p id="observed-severity" class="hint" hidden></p><p id="overview-note" class="hint"></p><a href="security-summary.json">Open original JSON summary</a></div>
  </section>
  <section class="card row" aria-label="Scanner views">
    <label>Scanner view <select id="scanner-view"></select></label>
    <div class="row"><button id="previous-scanner" type="button">Previous Scanner</button>
      <button id="next-scanner" type="button">Next Scanner</button></div>
    <p id="scanner-view-status" class="muted" role="status"></p>
  </section>
  <section id="priority" aria-labelledby="priority-title">
    <h2 id="priority-title">What should I fix first?</h2>
    <div class="card">
      <p class="hint">Start with actionable CRITICAL and HIGH findings. Review requests remain actionable. A finding can affect several modules, so work-item counts can overlap.</p>
      <div class="table-wrap"><table><thead><tr><th scope="col">Remediation work</th><th scope="col">Module</th><th scope="col">Direct parent</th><th scope="col">Severity</th><th scope="col">Details</th></tr></thead><tbody id="priority-rows"></tbody></table></div>
      <div id="priority-pages" class="pager"></div>
    </div>
  </section>
  <section id="findings" aria-labelledby="findings-title">
    <div class="row"><h2 id="findings-title">Developer remediation details</h2><button id="reset" type="button">Clear filters</button></div>
    <div class="card">
      <div class="filters">
        <label>Search findings<input id="search" type="search" placeholder="Issue, advisory, file or rule"></label>
        <label>Severity<select id="severity-filter"></select></label>
        <label id="scanner-filter-field">Scanner<select id="scanner-filter"></select></label>
        <label>Application module<select id="module-filter"></select></label>
        <label>Package<select id="package-filter"></select></label>
        <label>Disposition<select id="disposition-filter"></select></label>
      </div>
      <div id="priority-selection" class="hint" hidden></div>
      <div id="finding-pages" class="pager"></div>
      <div id="finding-rows"></div>
    </div>
  </section>
  <section id="scanners" aria-labelledby="scanners-title"><h2 id="scanners-title">Scanner guidance</h2><div id="scanner-cards" class="by-scanner"></div></section>
  <section id="inventory" aria-labelledby="inventory-title">
    <h2 id="inventory-title">Software inventory</h2>
    <div class="card"><p class="hint">Syft inventories software components. Inventory entries are separate from vulnerability findings.</p>
      <label class="inventory-search">Search components<input id="inventory-search" type="search" placeholder="Name, version, type or package URL"></label>
      <div id="inventory-pages" class="pager"></div>
      <div class="table-wrap"><table><thead><tr><th scope="col">Component</th><th scope="col">Version</th><th scope="col">Type</th><th scope="col">Package URL</th><th scope="col">Package location</th></tr></thead><tbody id="inventory-rows"></tbody></table></div>
    </div>
  </section>
</main>
<script type="application/json" id="report-data">DASHBOARD_DATA</script>
<script>DASHBOARD_SCRIPT</script>
</body>
</html>
"""

DASHBOARD_SCRIPT = r""""use strict";
const data = JSON.parse(document.getElementById("report-data").textContent);
document.getElementById("report-data").remove();
const count = data.counts;
const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const labels = {actionable: "Actionable", pending_review: "Pending review", confirmed_false_positive: "Confirmed false positive"};
const byId = id => document.getElementById(id);
const available = value => value != null && value !== "" && (!Array.isArray(value) || value.length > 0);
const shown = value => available(value) ? (Array.isArray(value) ? value.join(", ") : String(value)) : "Unavailable";
const amount = value => value == null ? "Unavailable" : new Intl.NumberFormat().format(value);
const unique = values => [...new Set(values.filter(available))];
const ordered = values => unique(values).sort((a, b) => a.localeCompare(b, undefined, {numeric: true}));
function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}
function button(text, handler, container) {
  const element = node("button", text);
  element.type = "button";
  element.addEventListener("click", handler);
  container.append(element);
  return element;
}
function badge(severity, text = severity) {
  return node("span", text, "badge " + (severities.includes(severity) ? severity.toLowerCase() : ""));
}
function fields(container, entries) {
  const list = node("dl");
  for (const [label, value] of entries) list.append(node("dt", label), node("dd", shown(value)));
  container.append(list);
}
function sectionText(container, heading, text) {
  container.append(node("h4", heading), node("p", shown(text)));
}
function details(container, title, build) {
  const element = node("details");
  element.append(node("summary", title));
  element.addEventListener("toggle", () => {
    if (!element.open || element.dataset.loaded) return;
    element.dataset.loaded = "true";
    build(element);
  });
  container.append(element);
  return element;
}
function links(container, values) {
  const list = node("ul");
  for (const value of unique(values)) {
    const item = node("li");
    let url;
    try { url = new URL(value); } catch {}
    if (url && ["https:", "http:"].includes(url.protocol) && !url.username && !url.password) {
      const link = node("a", value);
      link.href = url.href;
      link.rel = "noopener noreferrer";
      item.append(link);
    } else {
      item.textContent = value;
    }
    list.append(item);
  }
  container.append(list.children.length ? list : node("p", "Unavailable", "muted"));
}
function page(container, state, length, label, render, size = 25) {
  const pages = Math.max(1, Math.ceil(length / size));
  state.index = Math.min(state.index, pages - 1);
  const from = state.index * size;
  const to = Math.min(from + size, length);
  container.replaceChildren();
  const text = node("p", length ? amount(from + 1) + "\u2013" + amount(to) + " of " + amount(length) + " " + label : "No " + label + " found.");
  text.setAttribute("role", "status");
  container.append(text);
  if (pages > 1) {
    const actions = node("div");
    function move(step) {
      state.index += step;
      render();
      const buttons = container.querySelectorAll("button");
      const preferred = buttons[step < 0 ? 0 : 1];
      const other = buttons[step < 0 ? 1 : 0];
      if (preferred) (preferred.disabled ? other : preferred).focus();
    }
    button("Previous", () => move(-1), actions).disabled = state.index === 0;
    button("Next", () => move(1), actions).disabled = state.index + 1 >= pages;
    container.append(actions);
  }
  return [from, to];
}
const title = shown(data.application);
byId("application").textContent = title;
document.title = title + " | Security remediation";
byId("execution").textContent = data.execution;
byId("generated").textContent = "Security remediation report \u00b7 " + shown(data.generated);
for (const [label, value] of [
  ["Actionable findings", count.actionable], ["Unique observed findings", count.observed],
  ["Original observations", count.original], ["Duplicate observations", count.original - count.observed],
  ["Pending review", count.pending], ["SBOM components", count.inventory],
]) {
  const card = node("div", undefined, "card metric");
  card.append(node("strong", amount(value)), node("span", label));
  byId("metrics").append(card);
}
for (const severity of severities) {
  byId("severity").append(badge(severity, severity + " " + amount(count.actionableSeverity[severity] ?? 0)));
}
const observedSeverity = byId("observed-severity");
if (count.observed !== count.actionable) {
  observedSeverity.hidden = false;
  observedSeverity.textContent = "Observed severity: " + severities
    .map(severity => severity + " " + amount(count.observedSeverity[severity] ?? 0)).join(" | ");
}
const reduction = count.original ? ((count.original - count.observed) * 100 / count.original).toFixed(2) : "0.00";
byId("overview-note").textContent = "Deduplication reduced observations by " + reduction + "%. " +
  amount(count.falsePositives) + " confirmed false positives are excluded from the actionable count. " +
  amount(count.suspected) + " suspected false positives remain actionable.";
const scannerGuides = {
  Gitleaks: "Treat a possible credential as sensitive. Confirm ownership and validity, rotate or revoke as needed, remove it from source, and store its replacement in an approved secret store.",
  Semgrep: "Start at the reported file and line. Trace the matched code and verify whether the inputs can produce the reported behavior.",
  "OWASP Dependency-Check": "Use the reported Maven declaration, dependency chain and advisory scope to decide whether to update the direct dependency or the parent that supplies it.",
  Syft: "Use the inventory to confirm what was resolved and packaged. Syft inventory entries are listed separately below.",
  Grype: "Compare the reported installed version and package identity with the advisory. Treat scanner-reported fixes as candidates until their applicability is verified.",
  Checkov: "Inspect the reported resource and control in the configuration file. Validate the proposed setting with the platform tooling before rescanning.",
};
for (const scanner of data.scanners) {
  const card = node("article", undefined, "card");
  card.append(node("h3", scanner.name), node("p", scanner.status + " \u00b7 " +
    (scanner.name === "Syft" ? amount(count.inventory) + " components" : amount(scanner.count) + " observations"), "hint"));
  if (scanner.reason) card.append(node("p", scanner.reason, "hint"));
  card.append(node("p", scannerGuides[scanner.name] || ""));
  byId("scanner-cards").append(card);
}

const findings = data.findings;
const scannerViews = data.scanners.map(scanner => scanner.name);
let scannerView = "";
function inScannerView(finding) {
  return !scannerView || finding.scanners.includes(scannerView);
}
function visibleObservations(finding) {
  return scannerView ? finding.observations.filter(item => item.scanner === scannerView) : finding.observations;
}

const searchText = findings.map(f => [f.title, f.package, f.version, ...f.ids, ...f.scanners, ...f.modules,
  ...f.observations.flatMap(o => [o.id, o.name, o.file, o.artifact, o.rule, o.resource, o.parent, ...(o.cves || [])])]
  .join(" ").toLowerCase());
function options(id, values, all, translate = value => value) {
  const filter = byId(id);
  for (const value of ["", ...values]) {
    const option = node("option", value ? translate(value) : all);
    option.value = value;
    filter.append(option);
  }
}
options("severity-filter", severities, "All severities");
options("scanner-view", scannerViews, "All scanners");
options("scanner-filter", ordered(findings.flatMap(f => f.scanners)), "All scanners");
options("module-filter", ordered(findings.flatMap(f => f.modules)), "All modules");
options("package-filter", ordered(findings.map(f => f.package)), "All packages");
options("disposition-filter", Object.keys(labels), "All dispositions", value => labels[value]);
const filters = ["search", "severity-filter", "scanner-filter", "module-filter", "package-filter", "disposition-filter"].map(byId);
let selectedWork = null;
const findingPage = {index: 0};
let activeRecipe = null;

const noSourceLocation = "Source location not reported by scanner";
const transitiveLocation = "Transitive dependency - see parent declaration";
function sourceLocation(path, start, end) {
  if (!path) return noSourceLocation;
  if (!Number.isInteger(start) || start < 1) return path + " | " + noSourceLocation;
  const range = Number.isInteger(end) && end > start ? start + "\u2013" + end : String(start);
  return path + " | Line " + range;
}
function showLocations(container, finding) {
  if (finding.transitive) container.append(node("p", transitiveLocation));
  const list = node("ul");
  for (const [path, start, end] of finding.locations) list.append(node("li", sourceLocation(path, start, end)));
  for (const [relation, parent, path, start, end, module] of finding.declarations) {
    const label = relation === "Transitive" ? "Parent declaration" : "Dependency declaration";
    list.append(node("li", label + " | " + shown(parent) + " | " + sourceLocation(path, start, end)
      + " | Module " + shown(module)));
  }
  if (list.children.length) container.append(list);
  if (finding.packageLocations.length) fields(container, [["Package locations", finding.packageLocations.join("\n")]]);
  if (!list.children.length && (finding.transitive || !finding.packageLocations.length)) {
    container.append(node("p", noSourceLocation, "muted"));
  }
  const hasLine = finding.locations.some(([, line]) => Number.isInteger(line) && line > 0)
    || finding.declarations.some(([, , , line]) => Number.isInteger(line) && line > 0);
  if (!hasLine && (list.children.length || finding.transitive || !finding.packageLocations.length)) {
    container.append(node("p", "Use the original scanner evidence and the fix verification guidance to confirm the affected file or package.", "hint"));
  }
}
async function copyCommand(command, control) {
  try {
    if (!navigator.clipboard) throw new Error("Clipboard unavailable");
    await navigator.clipboard.writeText(command);
  } catch {
    const text = node("textarea");
    text.value = command;
    text.readOnly = true;
    control.parentNode.append(text);
    text.select();
    let copied = false;
    try { copied = document.execCommand("copy"); } catch {}
    if (copied) text.remove();
    control.textContent = copied ? "Copied" : "Select and copy";
    if (copied) control.focus();
    return;
  }
  control.textContent = "Copied";
}
function recipe(container, value) {
  if (value.steps.length) {
    const list = node("ol");
    for (const step of value.steps) list.append(node("li", step));
    container.append(list);
  } else {
    container.append(node("p", "Fix steps unavailable.", "muted"));
  }
  sectionText(container, "How to verify the fix", value.verify);
  if (!value.commands.length) {
    container.append(node("p", "Working directory and verification command unavailable.", "muted"));
  }
  for (const [directory, command] of value.commands) {
    const box = node("div", undefined, "commands");
    box.append(node("p", "Working directory: " + directory));
    const row = node("div", undefined, "row");
    row.append(node("code", command));
    const copy = button("Copy command", () => copyCommand(command, copy), row);
    copy.className = "command-copy";
    box.append(row);
    if (/<[^>]+>/.test(command)) box.append(node("p", "Replace any placeholder before running this command.", "hint"));
    container.append(box);
  }
}
function observation(container, o) {
  const text = data.descriptions[o.description];
  fields(container, [
    ["Original finding", "#" + o.number + " \u00b7 " + o.id], ["Issue name", o.name], ["Scanner", o.scanner], ["Reported severity", o.severity],
    ["Rule or advisory ID", o.rule], ["Related CVEs", o.cves], ["CWEs", o.cwes], ["Application module", o.module],
    ["Technology", o.technology],
    ...(!o.dependency || o.file || !o.packageLocations.length
      ? [["Source location", !o.start && (o.relationship || "").includes("Transitive")
          ? transitiveLocation : sourceLocation(o.file, o.start, o.end)]] : []),
    ...(o.dependency && o.packageLocations.length ? [["Package location", o.packageLocations.join("\n")]] : []),
    ...(!o.dependency && o.locations.length ? [["Scanner locations", o.locations]] : []),
    ["Affected artifact", o.artifact], ["Infrastructure resource", o.resource], ["Scan target", o.target], ["Package URL", o.purl],
    ["Installed version", o.installed], ["Scanner-reported fixed versions", o.fixed], ["Reported fix state", o.fixState],
    ["Dependency type", o.relationship], ["Parent dependency", o.parent], ["Dependency chains", data.chains[o.chains].join("\n")],
  ]);
  sectionText(container, "Scanner finding", text.issue_description);
  sectionText(container, "Root cause", text.root_cause);
  sectionText(container, "Reported security impact", text.security_impact);
  sectionText(container, "Scanner remediation", text.recommended_remediation);
  if (Object.keys(data.limitations[o.limitations]).length) {
    details(container, "Evidence limitations", content => fields(content, Object.entries(data.limitations[o.limitations]).map(([key, value]) => [key.replaceAll("_", " "), value])));
  }
  container.append(node("h4", "Advisory references"));
  links(container, o.references);
}
function finding(container, f) {
  const element = node("details", undefined, "finding");
  const summary = node("summary");
  const titleBox = node("span", undefined, "finding-title");
  const observations = visibleObservations(f);
  const selected = scannerView ? observations[0] : null;
  titleBox.append(node("b", selected ? selected.name : f.title), node("small", [scannerView || f.scanners.join(", "), f.ids.join(", "), f.package].filter(available).join(" \u00b7 ")));
  summary.append(badge(f.severity), badge("", labels[f.disposition]), document.createTextNode(" "), titleBox);
  element.append(summary);
  element.addEventListener("toggle", () => {
    if (!element.open || element.dataset.loaded) return;
    element.dataset.loaded = "true";
    const body = node("div", undefined, "detail");
    const scannerEvidence = selected && f.package ? data.descriptions[selected.description] : null;
    const [problem, risk] = scannerEvidence ? [scannerEvidence.issue_description, scannerEvidence.security_impact]
      : data.findingText[f.text];
    sectionText(body, "What is the problem?", problem);
    sectionText(body, "Why is it dangerous?", risk);
    fields(body, [
      ["Application modules", f.modules], ["Technology", f.technologies],
      ["Package", f.package], ["Installed version", f.version], ["Dependency type", f.relationship],
      ["Parent dependencies", f.parents], ["Verified fixed version", "Unavailable in the scan evidence"],
      ["Scanner-reported fixed versions", ordered(observations.flatMap(o => o.fixed || []))],
      ["False-positive review status", f.review ? f.review.approvalStatus : "No review recorded"],
    ]);
    if (f.review) {
      const approval = f.review.approval;
      if (f.review.reason) sectionText(body, "Review reason", f.review.reason);
      if (approval) fields(body, [["Verified reviewer", approval.securityReviewer], ["Approved until", approval.expiresAt]]);
      if (f.review.advisoryReferences?.length) {
        body.append(node("h4", "Review references"));
        links(body, f.review.advisoryReferences);
      }
    }
    body.append(node("h4", "Affected source and related build files"));
    showLocations(body, f);
    const guidance = node("div", undefined, "detail");
    guidance.hidden = true;
    const toggle = button("Show fix steps and verification", () => {
      if (!guidance.hidden) {
        guidance.hidden = true;
        toggle.textContent = "Show fix steps and verification";
        toggle.setAttribute("aria-expanded", "false");
        activeRecipe = null;
        return;
      }
      if (activeRecipe) activeRecipe.control.click();
      if (!guidance.children.length) recipe(guidance, data.recipes[f.recipe]);
      guidance.hidden = false;
      toggle.textContent = "Hide fix steps and verification";
      toggle.setAttribute("aria-expanded", "true");
      activeRecipe = {control: toggle};
    }, body);
    toggle.setAttribute("aria-expanded", "false");
    body.append(guidance);
    if (scannerView && observations.length < f.observations.length) {
      body.append(node("p", "Additional scanner evidence is available in the All scanners view.", "hint"));
    }
    const evidence = node("h4", "Original scanner evidence (" + amount(observations.length) + ")");
    body.append(evidence);
    for (const o of observations) {
      details(body, "#" + o.number + " \u00b7 " + o.scanner + " \u00b7 " + shown(o.rule), child => observation(child, o));
    }
    element.append(body);
  });
  container.append(element);
}
function renderFindings() {
  const rows = byId("finding-rows");
  rows.replaceChildren();
  activeRecipe = null;
  const [query, severity, scanner, module, packageName, disposition] = filters.map(input => input.value);
  const terms = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
  const indices = selectedWork ? selectedWork.indices : findings.map((_, index) => index);
  const matching = indices.filter(index => {
    const f = findings[index];
    return inScannerView(f) && (!severity || f.severity === severity) && (!scanner || f.scanners.includes(scanner)) &&
      (!module || f.modules.includes(module)) && (!packageName || f.package === packageName) &&
      (!disposition || f.disposition === disposition) && terms.every(term => searchText[index].includes(term));
  });
  const [from, to] = page(byId("finding-pages"), findingPage, matching.length, "findings", renderFindings);
  for (const index of matching.slice(from, to)) finding(rows, findings[index]);
}
function resetFindings(work) {
  for (const input of filters) input.value = "";
  selectedWork = work;
  const note = byId("priority-selection");
  note.hidden = !work;
  note.textContent = work ? "Showing priority work for " + work.title + " \u00b7 " + work.module + " \u00b7 " + work.parent : "";
  findingPage.index = 0;
  renderFindings();
}
byId("reset").addEventListener("click", () => resetFindings(null));
let timer;
filters.forEach(input => input.addEventListener(input.tagName === "INPUT" ? "input" : "change", () => {
  clearTimeout(timer);
  timer = setTimeout(() => { findingPage.index = 0; renderFindings(); }, input.tagName === "INPUT" ? 120 : 0);
}));
renderFindings();

const workItems = new Map();
findings.forEach((f, index) => {
  if (f.disposition === "confirmed_false_positive" || !["CRITICAL", "HIGH"].includes(f.severity)) return;
  const scopes = f.scopes.length ? f.scopes : f.modules.map(module => [module, "Not applicable"]);
  const subject = f.package ? f.package : f.title;
  for (const [module, parent] of scopes) {
    const key = JSON.stringify([subject, f.version, module, parent, f.package ? null : f.ids]);
    if (!workItems.has(key)) workItems.set(key, {title: subject, version: f.version, module, parent, critical: 0, high: 0, indices: []});
    const work = workItems.get(key);
    work[f.severity.toLowerCase()] += 1;
    work.indices.push(index);
  }
});
const priority = [...workItems.values()];
const priorityPage = {index: 0};
function renderPriority() {
  const rows = byId("priority-rows");
  rows.replaceChildren();
  const visibleWork = priority.map(work => {
    const indices = work.indices.filter(index => inScannerView(findings[index]));
    const critical = indices.filter(index => findings[index].severity === "CRITICAL").length;
    return {...work, indices, critical, high: indices.length - critical};
  }).filter(work => work.indices.length).sort((a, b) => b.critical - a.critical || b.high - a.high || a.title.localeCompare(b.title));
  const [from, to] = page(byId("priority-pages"), priorityPage, visibleWork.length, "work items", renderPriority, 12);
  for (const work of visibleWork.slice(from, to)) {
    const row = node("tr");
    const titleCell = node("td");
    titleCell.append(node("strong", work.title));
    if (work.version) titleCell.append(node("small", "Installed " + work.version));
    const severityCell = node("td");
    if (work.critical) severityCell.append(badge("CRITICAL", work.critical + " CRITICAL"));
    if (work.high) severityCell.append(badge("HIGH", work.high + " HIGH"));
    const open = node("td");
    button("View " + amount(work.indices.length) + " findings", () => {
      resetFindings(work);
      byId("findings").scrollIntoView();
      byId("search").focus({preventScroll: true});
    }, open);
    row.append(titleCell, node("td", work.module), node("td", work.parent), severityCell, open);
    rows.append(row);
  }
}
renderPriority();

const inventoryPage = {index: 0};
function renderInventory() {
  const search = byId("inventory-search").value.toLowerCase().trim();
  const matches = data.inventory.filter(row => row.join(" ").toLowerCase().includes(search));
  const [from, to] = page(byId("inventory-pages"), inventoryPage, matches.length, "components", renderInventory, 25);
  const rows = byId("inventory-rows");
  rows.replaceChildren();
  for (const component of matches.slice(from, to)) {
    const row = node("tr");
    for (const field of component.slice(0, 4)) row.append(node("td", shown(field)));
    row.append(node("td", component[4].length ? component[4].join("\n") : "Package location not reported by Syft"));
    rows.append(row);
  }
}
byId("inventory-search").addEventListener("input", () => { inventoryPage.index = 0; renderInventory(); });
renderInventory();

function selectScanner(name) {
  scannerView = name;
  const position = scannerViews.indexOf(name);
  byId("scanner-view").value = name;
  byId("previous-scanner").disabled = position <= 0;
  byId("next-scanner").disabled = position + 1 >= scannerViews.length;
  byId("priority").hidden = name === "Syft";
  byId("findings").hidden = name === "Syft";
  byId("inventory").hidden = Boolean(name && name !== "Syft");
  byId("scanner-filter-field").hidden = Boolean(name);
  byId("findings-title").textContent = name ? name + " findings" : "Developer remediation details";
  const scanner = data.scanners.find(item => item.name === name);
  byId("scanner-view-status").textContent = scanner ? scanner.name + ": " + scanner.status
    + (name === "Syft" ? " | " + amount(count.inventory) + " inventory components"
       : " | " + amount(findings.filter(inScannerView).length) + " unique findings") : "";
  priorityPage.index = 0;
  resetFindings(null);
  renderPriority();
}
byId("scanner-view").addEventListener("change", event => selectScanner(event.target.value));
byId("previous-scanner").addEventListener("click", () => selectScanner(scannerViews[scannerViews.indexOf(scannerView) - 1]));
byId("next-scanner").addEventListener("click", () => selectScanner(scannerViews[scannerViews.indexOf(scannerView) + 1]));
byId("inventory-nav").addEventListener("click", () => selectScanner("Syft"));
selectScanner("");"""


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
