"""Map scanner evidence to a common issue schema and scrub published output."""
import hashlib
import os
import re
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import quote, unquote, urlsplit

NAMES = {
    "gitleaks": "Gitleaks", "semgrep": "Semgrep", "dependency-check": "OWASP Dependency-Check",
    "grype": "Grype", "checkov": "Checkov",
}
HIDDEN_FIELDS = {
    "Secret", "Match", "Message", "Author", "Email", "lines", "metavars", "code_block",
    "fixed_definition", "evaluations", "entity_tags", "connected_node", "span", "long_msg", "short_msg",
}
PEM = re.compile(r"-----BEGIN [^\r\n-]*PRIVATE KEY-----[\s\S]*?-----END [^\r\n-]*PRIVATE KEY-----")
TOKENS = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|[Aa][Kk][Ii][Aa][A-Z0-9]{16})\b")
CREDENTIAL = re.compile(
    r"""(?i)(\b(?:password|token|api[-_ ]?key|authorization)(?:["']?\s*[:=]\s*|\s+Bearer\s+))"""
    r"""(?:"[^"\r\n]*"|'[^'\r\n]*'|(?:Bearer\s+)?[^\s,;'"><]+)"""
)
SENSITIVE_KEY = re.compile(r"(?i)^(?:password|token|api[-_ ]?key|authorization|secret|"
                           r"(?:access|refresh)[-_ ]?token|(?:private|secret)[-_ ]?key)$")
URL_USER = re.compile(r"(https?://)[^/\s@]+@", re.IGNORECASE)
CWE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
GHSA = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE)
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def capture_secrets(report):
    return {item["Secret"] for item in (report or [])
            if isinstance(item.get("Secret"), str) and item["Secret"] not in {"", "REDACTED", "[REDACTED]"}}


def conceal(value):
    if isinstance(value, list):
        return [conceal(item) for item in value]
    if isinstance(value, dict):
        return {key: conceal(item) for key, item in value.items()}
    return "[REDACTED]" if isinstance(value, str) and value else value


class Redactor:
    def __init__(self):
        self.secrets = set()
        self.pattern = None

    def add(self, secrets):
        self.secrets.update(value for secret in secrets for value in (secret, quote(secret, safe="")))
        if self.secrets:
            literals = sorted(self.secrets, key=lambda item: (-len(item), item))
            self.pattern = re.compile("|".join(map(re.escape, literals)))

    def text(self, value):
        if self.pattern:
            value = self.pattern.sub("[REDACTED]", value)
        value = PEM.sub("[REDACTED]", value)
        value = TOKENS.sub("[REDACTED]", value)
        value = URL_USER.sub(r"\1[REDACTED]@", value)
        return CREDENTIAL.sub(r"\1[REDACTED]", value)

    def data(self, value, native=False, dynamic_keys=False):
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.data(item, native, dynamic_keys) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                safe_key = self.text(key) if dynamic_keys else key
                if safe_key in result:
                    safe_key = next(f"{safe_key}-{i}" for i in range(2, len(value) + 2)
                                    if f"{safe_key}-{i}" not in result)
                result[safe_key] = (
                    "[REDACTED]" if native and SENSITIVE_KEY.fullmatch(key) and item is not None
                    else conceal(self.data(item, dynamic_keys=True)) if native and key in HIDDEN_FIELDS
                    else self.data(item, native, dynamic_keys)
                )
            return result
        return value


def first_text(*values):
    return next((item.strip() for item in values if isinstance(item, str) and item.strip()), None)


def list_of(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def identifiers(pattern, values):
    return list(dict.fromkeys(match.group().upper() for value in list_of(values)
                              if isinstance(value, str) for match in pattern.finditer(value)))


def references(*values):
    links = []
    for value in values:
        for item in list_of(value):
            link = item.get("url") if isinstance(item, dict) else item
            if not isinstance(link, str):
                continue
            try:
                parsed = urlsplit(link)
                if parsed.scheme in {"https", "http"} and parsed.hostname and not parsed.username:
                    # Drop query and fragment parameters, which sometimes contain credentials.
                    links.append(parsed._replace(query="", fragment="").geturl())
            except ValueError:
                continue
    return list(dict.fromkeys(links))


def rule_title(identifier):
    if not identifier:
        return None
    title = re.sub(r"[_-]+", " ", str(identifier).rsplit(".", 1)[-1]).strip().title()
    return re.sub(r"\b(Api|Aws|Cve|Gcp|Http|Jwt|Sql|Ssh|Tls|Url|Xss)\b",
                  lambda match: match[0].upper(), title)


def location(path, project, *, local_only=False):
    if not isinstance(path, str) or not path:
        return None
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            return candidate.relative_to(project).as_posix()
        except ValueError:
            return None if local_only else path
    return None if local_only else path.replace("\\", "/")


def line(value):
    return value if type(value) is int and value > 0 else None


def dependency_evidence(item):
    for package in item.get("packages", []):
        purl = package.get("id", "")
        match = re.match(r"pkg:maven/([^/]+)/([^@?]+)(?:@([^?]+))?", purl)
        if match:
            group, artifact, version = (unquote(part) if part else None for part in match.groups())
            return f"{group}:{artifact}", version
    return first_text(item.get("fileName")), None


def new_issue(scanner, **evidence):
    issue = dict.fromkeys((
        "issue_number", "issue_id", "issue_name", "scanner_name", "vulnerability_category", "severity",
        "source_file", "affected_filename", "relative_file_path",
        "start_line", "end_line", "issue_description", "root_cause", "security_impact",
        "recommended_remediation", "rule_id", "cwe_id", "cve_id", "affected_dependency",
        "installed_version", "fixed_version", "maven_coordinate", "dependency_type",
        "parent_dependency", "parent_version", "dependency_chains", "reference_links",
    ))
    issue.update(scanner_name=NAMES[scanner], **evidence)
    if source := issue["source_file"]:
        path = PurePosixPath(source.replace("\\", "/"))
        issue["affected_filename"] = issue["affected_filename"] or path.name or None
        if not path.is_absolute() and not PureWindowsPath(source).drive and ".." not in path.parts:
            issue["relative_file_path"] = path.as_posix()
    issue["severity"] = first_text(issue["severity"]).upper() if first_text(issue["severity"]) else "UNKNOWN"
    missing = {
        "issue_description": "No detailed description was supplied.",
        "rule_id": "The scanner did not supply an identifier for this match.",
        "source_file": "Scanner evidence did not identify a project source file.",
        "affected_filename": "The scanner did not identify an affected filename.",
        "relative_file_path": "The scanner did not identify a path relative to the project.",
        "start_line": "Scanner evidence did not supply a start line in the project file.",
        "end_line": "Scanner evidence did not supply an end line in the project file.",
        "root_cause": "The report did not establish a root cause.",
        "security_impact": "The report did not establish the impact for the affected application.",
        "cwe_id": "No CWE was supplied with this finding.",
        "cve_id": "No CVE was supplied with this finding.",
        "affected_dependency": "No affected package was identified for this finding.",
        "installed_version": "No installed version was reported.",
        "fixed_version": "No fixed version was reported. Consult the referenced advisory or vendor.",
    }
    issue["evidence_limitations"] = {field: reason for field, reason in missing.items() if issue[field] is None}
    if issue["severity"] == "UNKNOWN":
        issue["evidence_limitations"]["severity"] = "The scanner did not assign a severity."
    if not issue["reference_links"]:
        issue["evidence_limitations"]["reference_links"] = "No usable reference URL was supplied."
    return issue


def issue_identifier(issue):
    material = "\x1f".join(str(issue[key]) for key in (
        "scanner_name", "rule_id", "issue_name", "source_file", "start_line", "end_line",
        "affected_dependency", "installed_version", "issue_description",
    ))
    return hashlib.sha256(material.encode()).hexdigest()[:24]


GITLEAKS_GUIDANCE = {
    "generic-api-key": (
        "Hardcoded API key",
        "A potential API key was detected in source code.",
        "A valid exposed API key may allow unauthorized API access."
    ),
    "hardcoded-password": (
        "Hardcoded password",
        "A potential password was detected in source code.",
        "A valid exposed password may allow unauthorized account access."
    ),
    "hardcoded-token": (
        "Hardcoded authentication token",
        "A potential authentication token was detected in source code.",
        "A valid exposed token may allow unauthorized access to protected resources."
    ),
    "private-key": (
        "Exposed private key",
        "Private key material was detected in the project.",
        "A valid exposed private key may enable impersonation or unauthorized authentication."
    ),
}


def gitleaks_issues(report, project):
    for row in report or []:
        rule = row.get("RuleID")
        description = first_text(row.get("Description"))
        guidance = GITLEAKS_GUIDANCE.get(rule)
        yield new_issue("gitleaks", issue_name=guidance[0] if guidance else description or rule_title(rule) or "Potential credential exposure",
                        vulnerability_category="Secret exposure", severity=row.get("Severity"),
                        source_file=location(row.get("File"), project), start_line=line(row.get("StartLine")),
                        end_line=line(row.get("EndLine")), issue_description=description,
                        root_cause=guidance[1] if guidance else "Gitleaks matched a credential detection rule at this location.",
                        security_impact=guidance[2] if guidance else "If valid, the exposed credential may allow unauthorized access.",
                        recommended_remediation="Verify whether the value is active. Revoke or rotate it if valid, remove it from source, and retrieve it from an approved secret store.",
                        rule_id=rule, reference_links=references(row.get("References")))


SEMGREP_GUIDANCE = {
    "CWE-89": (
        "SQL Injection",
        "Untrusted input may be included in a SQL query.",
        "Attackers may access or modify database records.",
        "Use PreparedStatement and parameterized SQL queries."
    ),
    "CWE-78": (
        "OS Command Injection",
        "Untrusted input may reach an operating system command.",
        "Attackers may execute unauthorized system commands.",
        "Avoid shell execution and validate command arguments using an allowlist."
    ),
    "CWE-22": (
        "Path Traversal",
        "Untrusted input may influence a filesystem path.",
        "Attackers may access files outside the intended directory.",
        "Normalize and validate paths against an approved base directory."
    ),
    "CWE-502": (
        "Insecure Deserialization",
        "Untrusted serialized data may be processed without sufficient restrictions.",
        "Attackers may manipulate application behavior or execute arbitrary code.",
        "Avoid deserializing untrusted objects and enforce strict type restrictions."
    ),
    "CWE-79": (
        "Cross-Site Scripting (XSS)",
        "Untrusted input may reach HTML output without appropriate encoding.",
        "Attackers may execute malicious scripts in a user's browser.",
        "Apply context-aware output encoding and safe templating."
    ),
    "CWE-327": (
        "Weak or Risky Cryptography",
        "A potentially insecure cryptographic algorithm is used.",
        "Sensitive information may receive insufficient protection.",
        "Replace prohibited algorithms with approved modern cryptographic alternatives."
    ),
    "CWE-918": (
        "Server-Side Request Forgery (SSRF)",
        "Untrusted input may control a server-side request destination.",
        "Attackers may access internal services or restricted resources.",
        "Allowlist request destinations and restrict access to internal network addresses."
    ),
    "CWE- hardcoded": ()
}
SEMGREP_GUIDANCE.pop("CWE- hardcoded")


def semgrep_issues(report, project):
    for row in report["results"]:
        extra = row.get("extra") or {}
        meta = extra.get("metadata") or {}
        rule = row.get("check_id")
        classes = list_of(meta.get("vulnerability_class"))
        matched_cwes = identifiers(CWE, meta.get("cwe")) or []
        guidance = next(
            (details for cwe, details in SEMGREP_GUIDANCE.items()
             if cwe in matched_cwes),
            None
        )
        cves = identifiers(CVE, [*list_of(meta.get("cve")), extra.get("message", "")])
        yield new_issue("semgrep", issue_name=(guidance[0] if guidance else None) or first_text(meta.get("issue_name"), meta.get("shortDescription"),
                                                       *classes, rule_title(rule), extra.get("message"))
                        or "Semgrep security rule match",
                        vulnerability_category=first_text(*classes, meta.get("subcategory"), meta.get("category"))
                        or "Source code security",
                        severity=extra.get("severity"), source_file=location(row.get("path"), project),
                        start_line=line((row.get("start") or {}).get("line")),
                        end_line=line((row.get("end") or {}).get("line")),
                        issue_description=first_text(extra.get("message")),
                        root_cause=first_text(meta.get("root_cause")) or (guidance[1] if guidance else None),
                        security_impact=first_text(meta.get("security_impact")) or (guidance[2] if guidance else None),
                        recommended_remediation=first_text(meta.get("recommended_remediation"), meta.get("remediation"))
                        or (guidance[3] if guidance else None)
                        or "Review the matched code and rule references. Apply the rule-specific secure pattern and rerun the scan.",
                        rule_id=rule, cwe_id=identifiers(CWE, meta.get("cwe")) or None, cve_id=cves or None,
                        affected_dependency=first_text(meta.get("affected_dependency")),
                        installed_version=first_text(meta.get("installed_version")),
                        fixed_version=first_text(meta.get("fixed_version")),
                        reference_links=references(meta.get("references"), meta.get("source")))


def find_maven_declaration(project, component, version, *, declaration_pom=None,
                           direct_only=False, find_poms=None):
    from pathlib import Path
    from xml.parsers import expat

    if not component or ":" not in component or not version:
        return None, None, None

    group, artifact = component.split(":", 1)
    root = Path(project)
    matches = []

    if declaration_pom:
        poms = (declaration_pom,)
    else:
        poms = find_poms(root) if find_poms else root.rglob("pom.xml")
    for pom in poms:
        if any(part in {".git", "target", ".venv", ".accidion"}
               for part in pom.relative_to(root).parts):
            continue

        parser = expat.ParserCreate(namespace_separator="}")
        stack = []
        records = []
        current = None
        field = None

        def start(name, attrs):
            nonlocal current, field
            tag = name.split("}")[-1]
            stack.append(tag)

            if tag == "dependency" and stack in (
                ["project", "dependencies", "dependency"],
                ["project", "dependencyManagement", "dependencies", "dependency"],
            ):
                current = {"start": parser.CurrentLineNumber, "managed": "dependencyManagement" in stack}
            elif current is not None and len(stack) > 1:
                if stack[-2] == "dependency" and tag in (
                    "groupId", "artifactId", "version"
                ):
                    field = tag
                    current[field] = ""

        def data(value):
            if current is not None and field:
                current[field] += value

        def end(name):
            nonlocal current, field
            tag = name.split("}")[-1]

            if field == tag:
                field = None

            if tag == "dependency" and current is not None:
                current["end"] = parser.CurrentLineNumber
                records.append(current)
                current = None

            stack.pop()

        parser.StartElementHandler = start
        parser.CharacterDataHandler = data
        parser.EndElementHandler = end

        try:
            parser.Parse(pom.read_bytes(), True)
        except (OSError, expat.ExpatError):
            continue

        import re
        import xml.etree.ElementTree as ET

        properties = {}

        try:
            xml_root = ET.parse(pom).getroot()
            for node in xml_root:
                if node.tag.split("}")[-1] == "properties":
                    for prop in node:
                        properties[prop.tag.split("}")[-1]] = (
                            prop.text or ""
                        ).strip()
        except (OSError, ET.ParseError):
            continue

        def resolve_version(value):
            seen = set()

            while value not in seen:
                seen.add(value)
                match = re.fullmatch(r"\$\{([^}]+)\}", value)

                if not match:
                    return value

                key = match.group(1)

                if key not in properties:
                    return None

                value = properties[key]

            return None

        for record in records:
            if (
                record.get("groupId", "").strip() == group
                and record.get("artifactId", "").strip() == artifact
                and (
                    resolve_version(record.get("version", "").strip()) == version
                    or declaration_pom and not record.get("version")
                )
                and (not (declaration_pom or direct_only) or not record["managed"])
            ):
                matches.append((
                    pom.relative_to(root).as_posix(),
                    record["start"],
                    record["end"]
                ))

    if len(matches) == 1:
        return matches[0]

    return None, None, None


def dependency_issues(report, project, *, terminal=False, declaration_lookup=find_maven_declaration):
    for item in report["dependencies"]:
        component, version = dependency_evidence(item)
        pom_file, start_line, end_line = declaration_lookup(
            project, component, version
        )
        for vuln in item.get("vulnerabilities") or []:
            identifier = first_text(vuln.get("name"))
            title = first_text(vuln.get("title"))
            label = " — ".join(filter(None, (identifier, component)))
            description = first_text(vuln.get("description"))

            issue_name = title or " — ".join(
                filter(None, ("Vulnerable Java dependency", identifier, component))
            )

            root_cause = (
                f"Dependency-Check associated {component or 'a Java dependency'}"
                f" version {version or 'not reported'}"
                f" with vulnerability {identifier or 'not identified'}."
            )

            security_impact = description or (
                "The dependency may expose the application to a known vulnerability. "
                "Review the advisory to determine application-specific impact."
            )

            remediation = (
                f"Verify the vulnerability match for {component or 'the affected dependency'}. "
                f"Review the advisory for {identifier or 'the reported vulnerability'} "
                "and upgrade to a supported patched version. "
                "For transitive dependencies, update the parent dependency "
                "or apply an approved dependencyManagement override. "
                "Rebuild, test and rerun the security scan."
            )
            issue = new_issue("dependency-check", issue_name=issue_name,
                            root_cause=root_cause,
                            security_impact=security_impact,
                            vulnerability_category="Java dependency vulnerability", severity=vuln.get("severity"),
                            source_file=pom_file or location(item.get("filePath"), project, local_only=True),
                            start_line=start_line,
                            end_line=end_line,
                            affected_filename=first_text(item.get("fileName")),
                            issue_description=first_text(vuln.get("description")),
                            recommended_remediation=remediation,
                            rule_id=identifier, cwe_id=identifiers(CWE, vuln.get("cwes")) or None,
                            cve_id=identifiers(CVE, identifier) or None, affected_dependency=component,
                            installed_version=version, reference_links=references(vuln.get("references")))
            if terminal:
                issue["_terminal"] = {
                    "package": next((package["id"] for package in item.get("packages", [])
                                     if package.get("id", "").startswith("pkg:maven/")), None),
                    "aliases": advisory_ids(identifier, issue["reference_links"]),
                    "title": title,
                }
            yield issue


def grype_issues(report, _project, *, terminal=False, declaration_lookup=find_maven_declaration):
    for row in report["matches"]:
        vuln = row["vulnerability"]
        artifact = row.get("artifact") or {}
        identifier, component = first_text(vuln.get("id")), first_text(artifact.get("name"))
        label = " — ".join(filter(None, (identifier, component)))
        versions = (vuln.get("fix") or {}).get("versions") or []
        description = first_text(vuln.get("description"))
        installed = first_text(artifact.get("version"))

        issue_name = first_text(vuln.get("title"), vuln.get("description")) or " — ".join(
            filter(None, ("Vulnerable package", identifier, component))
        )

        root_cause = (
            f"Grype matched {component or 'an installed package'} "
            f"version {installed or 'not reported'} "
            f"with vulnerability {identifier or 'not identified'}."
        )

        security_impact = description or (
            "The affected package may expose the application or container "
            "to a known vulnerability. Review the advisory for details."
        )
        remediation = (
            f"Verify the vulnerability match for {component or 'the affected package'}. "
            f"Upgrade to a compatible reported fixed version: {', '.join(versions)}. "
            "Update the dependency or container base image as applicable, "
            "rebuild, test and rescan."
            if versions else
            f"Review the advisory for {identifier or 'the reported vulnerability'} "
            f"affecting {component or 'the installed package'}. "
            "If no patch is available, evaluate a supported replacement "
            "or approved mitigation."
        )
        metadata = artifact.get("metadata") or {}
        group = first_text(metadata.get("pomGroupID"))
        artifact_id = first_text(metadata.get("pomArtifactID"), component)

        pom_file, start_line, end_line = None, None, None

        if artifact.get("type") == "java-archive" and group and artifact_id:
            pom_file, start_line, end_line = declaration_lookup(
                _project, f"{group}:{artifact_id}", installed
            )

        package_paths = []
        for item in artifact.get("locations") or []:
            path = first_text(item.get("path"))
            if path:
                package_paths.append(path)

        if pom_file and package_paths:
            if not any(
                path.replace(chr(92), "/").lstrip("/") == pom_file
                for path in package_paths
            ):
                pom_file, start_line, end_line = None, None, None

        affected_file = pom_file or (
            package_paths[0] if len(set(package_paths)) == 1 else None
        )

        issue = new_issue("grype", issue_name=issue_name,
                        source_file=affected_file,
                        start_line=start_line,
                        end_line=end_line,
                        root_cause=root_cause,
                        security_impact=security_impact,
                        vulnerability_category="Package vulnerability", severity=vuln.get("severity"),
                        issue_description=first_text(vuln.get("description")), recommended_remediation=remediation,
                        rule_id=identifier, cwe_id=identifiers(CWE, vuln.get("cwes")) or None,
                        cve_id=identifiers(CVE, [identifier, *(entry.get("id") for entry in row.get("relatedVulnerabilities") or [])]) or None,
                        affected_dependency=component, installed_version=first_text(artifact.get("version")),
                        maven_coordinate=(
                            f"{group}:{artifact_id}:{installed}"
                            if artifact.get("type") == "java-archive"
                            and group and artifact_id and installed else None
                        ),
                        fixed_version=versions or None, reference_links=references(vuln.get("urls"), vuln.get("dataSource")))

        if terminal:
            issue["_terminal"] = {
                "package": first_text(artifact.get("purl")) or (
                    f"pkg:maven/{group}/{artifact_id}@{installed}"
                    if artifact.get("type") == "java-archive" and group and artifact_id and installed else None
                ),
                "title": first_text(vuln.get("title")),
                "fix_state": first_text((vuln.get("fix") or {}).get("state")),
                "aliases": advisory_ids(identifier, [
                    *(entry.get("id") for entry in row.get("relatedVulnerabilities") or []),
                    *issue["reference_links"],
                ]),
            }
        yield issue


CHECKOV_GUIDANCE = {
    "CKV_AWS_24": (
        "Unrestricted public SSH access",
        "Inbound SSH access is allowed from any IPv4 address.",
        "Exposes the resource to unauthorized SSH connection attempts.",
        "Restrict inbound port 22 to approved IP addresses or trusted networks."
    ),
    "CKV_AWS_25": (
        "Unrestricted public RDP access",
        "Inbound RDP access is allowed from any IPv4 address.",
        "Exposes remote desktop services to unauthorized connection attempts.",
        "Restrict inbound port 3389 to approved IP addresses or trusted networks."
    ),
    "CKV_AWS_53": (
        "S3 public ACL protection disabled",
        "The bucket does not block public access control lists.",
        "Public ACLs may expose sensitive stored data.",
        "Enable block_public_acls in the S3 public access block configuration."
    ),
    "CKV_AWS_23": (
        "Missing security group rule description",
        "A security group or rule has no required description.",
        "Makes network access rules harder to review and maintain.",
        "Add meaningful descriptions explaining the purpose of each applicable rule."
    ),
}


def checkov_issues(report, project):
    for scan in list_of(report):
        for row in scan["results"].get("failed_checks") or []:
            lines = list_of(row.get("file_line_range"))
            rule = row.get("check_id")
            guidance = CHECKOV_GUIDANCE.get(rule)
            path = row.get("file_abs_path") or row.get("repo_file_path")
            yield new_issue("checkov", issue_name=(guidance[0] if guidance else first_text(row.get("check_name")) or rule_title(rule) or "Infrastructure check failed"),
                            root_cause=guidance[1] if guidance else None,
                            security_impact=guidance[2] if guidance else None,
                            vulnerability_category=first_text(row.get("bc_category"), scan.get("check_type"))
                            or "Infrastructure misconfiguration",
                            severity=row.get("severity"), source_file=location(path, project) or row.get("file_path"),
                            start_line=line(lines[0]) if lines else None,
                            end_line=line(lines[-1]) if len(lines) > 1 else None,
                            issue_description=first_text(row.get("description"), row.get("short_description"), row.get("check_name")),
                            recommended_remediation=(guidance[3] if guidance else None) or first_text(row.get("remediation"))
                            or (f"Update the affected resource to meet this control: {row['check_name']}."
                                if row.get("check_name") else
                                "Update the affected infrastructure resource using the check guidance and rerun Checkov."),
                            rule_id=rule, reference_links=references(row.get("guideline")))


NORMALIZE = {
    "gitleaks": gitleaks_issues, "semgrep": semgrep_issues, "dependency-check": dependency_issues,
    "grype": grype_issues, "checkov": checkov_issues,
}

# Terminal presentation uses separate evidence so the published JSON stays unchanged.
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def advisory_ids(primary, evidence):
    ids = identifiers(CVE, primary) + identifiers(GHSA, primary)
    if len(ids) != 1:
        return ids[:1]
    alias_pattern = GHSA if ids[0].startswith("CVE-") else CVE
    aliases = identifiers(alias_pattern, evidence)
    if len(aliases) == 1:
        ids.extend(aliases)
    return [f"GHSA-{item[5:].lower()}" if item.startswith("GHSA-") else item for item in ids]


def terminal_package(issue, purl):
    version = issue["installed_version"]
    if not purl or not version:
        return None
    base, _, qualifiers = purl.partition("?")
    if base.startswith("pkg:maven/"):
        coordinate = unquote(base.removeprefix("pkg:maven/").split("@", 1)[0]).replace("/", ":")
        variants = [part for part in qualifiers.split("&")
                    if part.startswith("classifier=") or part.startswith("type=") and part not in {"type=jar", "type=pom"}]
        return "maven", coordinate, version, tuple(sorted(variants))
    return "package", purl, version, ()


def terminal_severity(issue):
    value = issue["severity"]
    if issue["scanner_name"] == "Semgrep":
        value = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(value, value)
    return value if value in SEVERITIES else "UNKNOWN"


def terminal_groups(issues, metadata):
    packages = defaultdict(list)
    sources = defaultdict(list)
    identities = [terminal_package(issue, evidence.get("package"))
                  for issue, evidence in zip(issues, metadata)]
    maven = defaultdict(set)
    for package in identities:
        if package and package[0] == "maven":
            maven[package[1:3]].add(package)
    for index, (issue, evidence, package) in enumerate(zip(issues, metadata, identities)):
        component = issue["affected_dependency"]
        version = issue["installed_version"]
        if not package and component:
            candidates = maven[component, version] if issue["scanner_name"] == "Semgrep" else set()
            if len(candidates) == 1:
                package = next(iter(candidates))
            else:
                # Group similar remediation while keeping each unverified package match as evidence.
                package = ("reported", component, version, issue.get("scan_target"), issue["scanner_name"])
        aliases = set(evidence.get("aliases", ()))
        if package and issue["scanner_name"] == "Semgrep":
            aliases.update(issue["cve_id"] or [])
        if package:
            packages[package].append((issue, aliases))
        else:
            path = issue["relative_file_path"] or issue["source_file"]
            rule = issue["rule_id"] or issue["issue_name"]
            start, end = issue["start_line"], issue["end_line"]
            location_key = (path, start, end or start) if path and rule and start else index
            key = (issue["scanner_name"], rule, location_key)
            sources[key].append(issue)

    groups = [(None, [(rows, set())]) for rows in sources.values()]

    def rank(finding):
        return min(SEVERITIES.index(terminal_severity(issue)) for issue in finding[0])

    for package, rows in packages.items():
        # Index by advisory and merge overlapping clusters, even when a bridge arrives late.
        findings = {}
        owners = {}
        for index, (issue, aliases) in enumerate(rows):
            evidence = [issue]
            for previous in sorted({owners[alias] for alias in aliases if alias in owners
                                    and package[0] != "reported"}):
                merged, previous_aliases = findings.pop(previous)
                evidence.extend(merged)
                aliases.update(previous_aliases)
            findings[index] = (evidence, aliases)
            owners.update(dict.fromkeys(aliases, index))
        groups.append((package, list(findings.values())))

    for _, findings in groups:
        findings.sort(key=rank)
    groups.sort(key=lambda group: rank(group[1][0]))
    counts = Counter(SEVERITIES[rank(finding)] for _, findings in groups for finding in findings)
    return groups, counts


def source_label(path, start=None, end=None):
    if not start:
        return path
    return f"{path}:{start}-{end}" if end and end != start else f"{path}:{start}"


def project_source(path, project):
    if not path:
        return None
    path = Path(path)
    if not path.is_absolute():
        path = project / path
    try:
        resolved = path.resolve()
        relative = resolved.relative_to(project)
        return relative.as_posix() if resolved.is_file() else None
    except (OSError, ValueError):
        return None


SCANNER_SECTIONS = (
    ("gitleaks", "Secret Scanning"), ("semgrep", "Code Security"),
    ("dependency-check", "Dependency Security"), ("syft", "Software Inventory"),
    ("grype", "Package Vulnerability Scanning"), ("checkov", "Infrastructure Security"),
)

TECHNOLOGIES = {
    ".java": "Java", ".kt": "Kotlin", ".sql": "SQL", ".tf": "Terraform", ".tf.json": "Terraform",
    ".gradle": "Gradle", ".gradle.kts": "Gradle", ".bicep": "Bicep", ".py": "Python",
    ".yaml": "YAML", ".yml": "YAML", ".json": "JSON", ".xml": "XML", ".env": "Environment configuration",
    ".properties": "Properties", ".sh": "Shell",
}


def technology(path):
    name = PurePosixPath(path or "").name.lower()
    if name == "pom.xml":
        return "Maven"
    if name in {"libs.versions.toml", "gradle.lockfile"}:
        return "Gradle"
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        return "Docker"
    return next((value for suffix, value in TECHNOLOGIES.items() if name.endswith(suffix)), None)


def terminal_locations(rows):
    return list(dict.fromkeys(
        (row["relative_file_path"] or row["source_file"], row["start_line"], row["end_line"])
        for row in rows if row["relative_file_path"] or row["source_file"]
    ))


def brief(value, limit=200):
    text = " ".join(value.split())
    return text if len(text) <= limit else text[:limit - 3].rsplit(" ", 1)[0] + "..."


S3_PUBLIC_ACCESS_FLAGS = {
    "CKV_AWS_53": "block_public_acls",
    "CKV_AWS_54": "block_public_policy",
    "CKV_AWS_55": "ignore_public_acls",
    "CKV_AWS_56": "restrict_public_buckets",
}

S3_TERRAFORM_GUIDANCE = {
    "CKV2_AWS_6": (
        "The bucket has no explicit public access block in this configuration.",
        "A future ACL or bucket policy could expose objects outside the intended accounts.",
        ("Attach aws_s3_bucket_public_access_block to this bucket.",
         "Set block_public_acls, ignore_public_acls, block_public_policy, and restrict_public_buckets to true."),
    ),
    "CKV_AWS_18": (
        "The bucket has no server access logging configuration.",
        "It may be harder to investigate suspicious requests and trace access.",
        ("Add aws_s3_bucket_logging with a dedicated log destination and prefix.",
         "Allow S3 log delivery to write to the destination. Verify logs arrive after a test request."),
    ),
    "CKV_AWS_19": (
        "The scan found no explicit encryption-at-rest configuration.",
        "New objects may use a key different from the one required by your data policy.",
        ("Attach aws_s3_bucket_server_side_encryption_configuration and set the encryption algorithm required by policy.",
         "Upload a test object and verify its encryption settings. Review existing objects separately."),
    ),
    "CKV_AWS_145": (
        "The configuration does not select KMS encryption by default.",
        "Objects may be written without the required KMS key policy and key-use audit controls.",
        ('Set sse_algorithm = "aws:kms" in aws_s3_bucket_server_side_encryption_configuration.',
         "Select an approved KMS key, grant necessary access, and verify a test upload uses it."),
    ),
    "CKV_AWS_21": (
        "Bucket versioning is not enabled in the configuration.",
        "Accidental deletes or overwrites may leave no earlier version to restore.",
        ('Attach aws_s3_bucket_versioning with status = "Enabled".',
         "Upload two versions of a test object and confirm the earlier version can be restored."),
    ),
    "CKV2_AWS_61": (
        "The bucket has no lifecycle configuration.",
        "Objects and old versions can outlast intended retention, or be managed inconsistently.",
        ("Add aws_s3_bucket_lifecycle_configuration with rules limited to the intended object prefixes or tags.",
         "Review transition and expiration times against retention requirements before enabling the rules."),
    ),
    "CKV_AWS_300": (
        "The lifecycle configuration does not expire incomplete multipart uploads.",
        "Abandoned upload parts can accumulate and consume storage.",
        ("Add abort_incomplete_multipart_upload to the applicable lifecycle rule.",
         "Set days_after_initiation to a value that permits legitimate long uploads."),
    ),
    "CKV_AWS_144": (
        "The configuration has no cross-region replication rule.",
        "A regional disruption may leave the workload without an up-to-date copy in another region.",
        ("Enable versioning on both buckets and configure aws_s3_bucket_replication_configuration for an approved destination region.",
         "Scope the replication IAM role and key access to the required objects. Upload a test object and verify delivery."),
    ),
    "CKV2_AWS_62": (
        "The bucket has no event notification configuration.",
        "Workflows that depend on object events may miss uploads or deletes.",
        ("Add aws_s3_bucket_notification for the required events and an approved Lambda, SQS, SNS, or EventBridge destination.",
         "Grant delivery permissions and verify that a test object event reaches the intended consumer."),
    ),
}


def infrastructure_guidance(issue, tech):
    rule = issue["rule_id"]
    if rule in {"CKV_DOCKER_3", "CKV_DOCKER_8"}:
        return ("The Dockerfile does not declare a non-root runtime user.",
                "A compromised process running as root has more privileges inside the container.",
                ("Create or select an unprivileged user in the final stage and grant access to required paths.",
                 "Set USER to that account before the application starts."),
                "Rebuild and confirm the running process has a nonzero UID, then rescan.")
    if rule == "CKV_DOCKER_2":
        return ("The final Dockerfile stage does not declare an active health check.",
                "A process can remain running while the service has stopped responding.",
                ("Add a HEALTHCHECK in the final stage using a command the image actually contains.",
                 "Probe service readiness and set timeouts and retries that allow for normal startup."),
                "Run the rebuilt image, confirm a healthy status, and test that a failed probe is reported.")
    if rule == "CKV2_AWS_5":
        return ("Checkov did not find a resource attached to this security group.",
                "An unused group can leave stale rules that expose a workload if the group is reused.",
                ("Check the plan and AWS console for existing attachments, including workloads managed outside this Terraform stack.",
                 "Remove the group from configuration if it is unused. If required, reference its ID in the intended resource's security group setting and limit its rules to that workload."),
                "Check the plan for unintended detachments or deletions. If retained, verify the intended attachment and rerun Checkov.")
    if rule == "CKV_AWS_382":
        return ("The security group permits unrestricted outbound traffic.",
                "A compromised workload could contact arbitrary external destinations.",
                ("Identify the outbound destinations and ports the workload requires.",
                 "Replace the unrestricted egress rule with rules limited to those destinations and ports."),
                "Review the planned rule changes, test required outbound connections, and rescan.")
    if tech == "Terraform":
        validate = "Review the affected resource changes in the plan and rescan."
        if flag := S3_PUBLIC_ACCESS_FLAGS.get(rule):
            return (f"The bucket public access configuration does not enable {flag}.",
                    "ACLs or bucket policies can grant access outside the intended accounts.",
                    (f"Set {flag} = true in aws_s3_bucket_public_access_block for this bucket.",
                     "Verify that required application principals retain their intended access."), validate)
        if rule in {"CKV_AWS_20", "CKV_AWS_57"}:
            access = "read" if rule == "CKV_AWS_20" else "write"
            return (f"The bucket ACL grants overly broad {access} access.",
                    f"Unintended principals may gain {access} access to objects.",
                    ("Remove the broad ACL grant from the bucket or aws_s3_bucket_acl configuration.",
                     "Grant access only to the required principals through the bucket policy."), validate)
        if guidance := S3_TERRAFORM_GUIDANCE.get(rule):
            return (*guidance, validate)
    guidance = CHECKOV_GUIDANCE.get(rule)
    if guidance:
        validate = ("Review the plan for the affected resource before rescanning." if tech == "Terraform"
                    else "Validate the configuration and rescan.")
        steps = (guidance[3],)
        if tech == "Terraform" and rule in {"CKV_AWS_24", "CKV_AWS_25"}:
            steps = (guidance[3], "Replace wildcard CIDRs in the affected ingress block with the approved CIDRs.")
        if tech == "Terraform" and rule == "CKV_AWS_23":
            steps = ("Add a description to the flagged security group or rule in the Terraform resource.",
                     "Record the rule's purpose and the traffic it is intended to allow.")
        return guidance[1], guidance[2], steps, validate
    validate = {"Terraform": "Review the plan for the affected resource, then rescan.",
                "Docker": "Rebuild the image, test its runtime behavior, and rescan."}
    return (issue["root_cause"] or issue["issue_description"] or "The rule failed for the reported resource.",
            issue["security_impact"] or "The report does not describe the consequence of this policy failure.",
            (issue["recommended_remediation"] or f"Identify the resource setting that fails {rule or 'the reported check'}.",),
            validate.get(tech, "Validate the affected resource with its platform tooling and rescan."))


def source_remediation(issue):
    scanner = issue["scanner_name"]
    path = issue["relative_file_path"] or issue["source_file"]
    tech = technology(path)
    title = issue["issue_name"]
    if scanner == "Gitleaks":
        guidance = GITLEAKS_GUIDANCE.get(issue["rule_id"])
        fixture = set(re.split(r"[/_.-]", (path or "").lower())) & {"test", "tests", "fixture", "fixtures", "example", "sample", "mock"}
        assessment = ("Possible test credential based on the path. Validity is unverified." if fixture
                      else "Potential credential. Validity is unverified.")
        return (guidance[0] if guidance else "Potential credential exposure",
                assessment, "If valid, the exposed credential could grant unauthorized access.",
                ("Ask the credential owner to confirm whether it is active. Revoke or rotate it if active or uncertain.",
                 "Remove it from source. Load active credentials from an approved secret store, or use a confirmed inert fixture."),
                "Check revocation if applicable, test with the replacement, and rescan.")
    if scanner == "Semgrep":
        cwes = issue["cwe_id"] or []
        guidance = next((SEMGREP_GUIDANCE[cwe] for cwe in cwes if cwe in SEMGREP_GUIDANCE), None)
        if "CWE-89" in cwes or issue["rule_id"] in {"java-sql-injection", "insecure-dynamic-sql"}:
            risk = "If untrusted input changes the executed query, it could read or modify database records."
            if tech == "SQL":
                steps = ("Replace dynamic SQL with a static query where possible.",
                         "For SQL Server, bind values with sp_executesql. If identifiers must vary, restrict them to an allowlist.")
            elif tech == "Java":
                steps = ("Trace the constructed query to its execution point.",
                         "Use JDBC PreparedStatement placeholders and bind input values separately from the SQL.")
            else:
                steps = ("Trace input to the query execution point.",
                         "Separate statement text from data using the database interface's parameter binding.")
            return title, issue["root_cause"] or "Input may become part of the SQL statement.", risk, steps, (
                "Test that inputs containing SQL syntax are treated as data, then rescan.")
        return (title, issue["root_cause"] or issue["issue_description"] or "The scanner matched the reported rule.",
                guidance[2] if guidance else issue["security_impact"] or "The rule match does not establish a specific impact.",
                (guidance[3] if guidance else issue["recommended_remediation"],),
                "Add a regression test for the flagged behavior and rescan.")
    return (title, *infrastructure_guidance(issue, tech))


def dependency_remediation(package, rows, project, contexts, declaration_lookup=find_maven_declaration):
    kind, component, version, variant = package[:4]
    if kind == "package":
        identity = component.rpartition("@")[0] or component
        component = f"{rows[0]['affected_dependency'] or identity} ({identity})"
    elif kind == "maven" and variant:
        component = f"{component} ({', '.join(variant)})"

    container = any(row.get("scan_target") == "container" for row in rows)
    project_dependency = any(row.get("scan_target") != "container" for row in rows)
    context = contexts.get((package[1], version), ()) if kind == "maven" and project_dependency else ()
    maven_source = any(technology(row["source_file"]) == "Maven" for row in rows)
    if not context and (kind == "maven" or maven_source) and project_dependency:
        path, start, end = declaration_lookup(project, package[1], version, direct_only=True)
        if path:
            context = [("Direct", package[1], version, source_label(path, start, end))]

    locations = []
    for _, _, _, source in context:
        path, separator, lines = source.rpartition(":")
        start, _, end = lines.partition("-")
        locations.append((path, int(start), int(end or start)) if separator and start.isdigit()
                         and (not end or end.isdigit()) else (source, None, None))
    locations.extend(terminal_locations([row for row in rows if row["scanner_name"] == "Semgrep"]))
    if not context:
        locations.extend((path, row["start_line"], row["end_line"])
                         for row in rows if (path := project_source(row["source_file"], project))
                         and technology(path) in {"Maven", "Gradle"})
    tools = {technology(path) for path, _, _ in locations}
    paths = {relation for relation, *_ in context}
    parents = [f"{parent}:{parent_version}" if parent_version else parent
               for relation, parent, parent_version, _ in context if relation == "Transitive"]
    steps = ["Use the advisory IDs and links in --details to check affected versions and choose a compatible release."]
    if "Direct" in paths or project_dependency and not paths:
        if "Maven" in tools:
            steps.append("For a direct Maven dependency, update the version, property, or imported BOM that controls it.")
        if "Gradle" in tools:
            steps.append("For a direct Gradle dependency, update its declaration or version catalog and refresh dependency locks if used.")
    if "Transitive" in paths:
        steps.append("Upgrade the listed direct parent so it resolves the affected library to the selected release.")
    if project_dependency and not paths:
        steps.append("Use the build's dependency tree to locate the dependency and identify whether to update it or its parent.")
    if container:
        steps.append("Update the package in the Dockerfile or select a rebuilt base image with the corrected package.")
    verify = "Confirm the resolved version against each advisory, then rebuild, test, and rescan."
    if container:
        verify += " Check the rebuilt image with Grype."
    return (component, list(dict.fromkeys(locations)),
            " / ".join(sorted(paths)) or ("Container package" if container and not project_dependency else "Unresolved"),
            list(dict.fromkeys(parents)), version, steps, verify)


def verification_commands(project, locations, package, rule):
    checks = {}
    for source, _, _ in locations:
        path = Path(source)
        if path.is_absolute() or ".." in path.parts:
            continue
        folder = path.parent
        tech = technology(source)
        if tech == "Terraform":
            checks[folder.as_posix(), "terraform validate"] = None
            plan_dir = folder.as_posix()
            if plan_dir != ".":
                plan_dir += " if standalone, otherwise run from its Terraform calling root"
            checks[plan_dir, "terraform plan"] = None
        elif package and tech == "Maven":
            coordinate = package[1]
            if re.fullmatch(r"[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+", coordinate):
                checks[folder.as_posix(), f"mvn dependency:tree -Dincludes={coordinate}"] = None
        elif package and tech == "Gradle":
            artifact = package[1].rsplit(":", 1)[-1]
            if not re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9_.-]*", artifact):
                continue
            launcher = "gradle"
            wrapper = "gradlew.bat" if os.name == "nt" else "gradlew"
            for distance, directory in enumerate((folder, *folder.parents)):
                if (project / directory / wrapper).is_file():
                    launcher = "../" * distance + wrapper if distance else f"./{wrapper}"
                    break
            checks[folder.as_posix(), f"{launcher} dependencyInsight --dependency {artifact} "
                   "--configuration runtimeClasspath"] = None
        elif tech == "Docker":
            command = {
                "CKV_DOCKER_2": "docker inspect --format '{{.State.Health.Status}}' <container>",
                "CKV_DOCKER_3": "docker exec <container> id -u",
                "CKV_DOCKER_8": "docker exec <container> id -u",
            }.get(rule)
            if command:
                checks[folder.as_posix(), command] = None
    return checks


def dependency_title(component, rows, metadata):
    titles = {title for row in rows if (title := first_text(
        metadata[id(row)].get("title"), row["issue_name"] if row["scanner_name"] == "Semgrep" else None
    )) and len(title) <= 115}
    if len(titles) == 1:
        return next(iter(titles))
    return f"Vulnerable package: {component}"


def dependency_fix_evidence(findings, metadata):
    versions = set()
    availability = Counter()
    for evidence, _ in findings:
        candidates = {version for row in evidence for version in list_of(row["fixed_version"]) if first_text(version)}
        versions.update(candidates)
        states = {metadata[id(row)].get("fix_state") for row in evidence}
        reported_fix = bool(candidates) or "fixed" in states
        unavailable = "not-fixed" in states or "wont-fix" in states
        if reported_fix and unavailable:
            label = "conflicting reports"
        elif reported_fix:
            label = "fix reported"
        elif "wont-fix" in states:
            label = "marked won't fix"
        elif unavailable:
            label = "reported unfixed"
        else:
            label = "availability unknown"
        availability[label] += 1
    return sorted(versions), ", ".join(f"{count} {label}" for label, count in availability.items())


def dependency_risks(findings):
    risks = []
    for evidence, _ in findings:
        known = {cwe for row in evidence for cwe in row["cwe_id"] or []}
        impacts = [SEMGREP_GUIDANCE[cwe][2] for cwe in sorted(known) if cwe in SEMGREP_GUIDANCE]
        if impacts:
            risks.extend(f"If the affected code is reachable: {impact[0].lower()}{impact[1:]}" for impact in impacts)
            continue
        for row in evidence:
            description = row["issue_description"] or ""
            sentences = re.split(r"(?<=[!?])\s+|(?<=\.)\s+(?=[A-Z])", " ".join(description.split()))
            impact = next((text for text in sentences if len(text) <= 140 and re.search(
                r"\b(?:attackers?|allows?|exposes?|bypass|denial of service|disclos\w*|execut\w*|escalat\w*)\b",
                text, re.IGNORECASE)), None)
            if impact:
                risks.append(impact)
                break
    risks = list(dict.fromkeys(risks))
    if len(risks) > 2:
        return [*risks[:2], "See --details for the remaining advisory evidence."]
    return risks or ["The report provides no concise impact statement. See --details for the advisory evidence."]


def terminal_evidence(findings, emit, metadata):
    for evidence, aliases in findings:
        if aliases:
            emit(f"  Advisory: {', '.join(sorted(aliases))}")
        for issue in sorted(evidence, key=lambda row: row["issue_number"] or 0):
            target = f" / {issue['scan_target']}" if issue.get("scan_target") else ""
            emit(f"    Report finding #{issue['issue_number']} | {issue['scanner_name']}{target} | "
                 f"{issue['severity']} | {issue['rule_id'] or 'rule unavailable'}")
            path = issue["relative_file_path"] or issue["affected_filename"]
            if path:
                emit(f"      Source file: {path}")
                if issue["start_line"]:
                    emit(f"      Line number(s): {source_label('', issue['start_line'], issue['end_line'])[1:]}")
            extra_ids = sorted(set(issue["cve_id"] or []) - aliases - {issue["rule_id"]})
            if extra_ids:
                emit(f"      Related advisories: {', '.join(extra_ids)}")
            if issue["fixed_version"]:
                emit(f"      Reported fixed versions: {', '.join(list_of(issue['fixed_version']))}")
            if state := metadata[id(issue)].get("fix_state"):
                emit(f"      Reported fix state: {state}")
            for field in ("issue_description", "root_cause", "security_impact", "recommended_remediation"):
                if issue[field]:
                    emit(f"      {issue[field]}")
            for link in issue["reference_links"] or []:
                emit(f"      {link}")


ISSUE_LABEL_WIDTH = 19


def terminal_field(emit, label, value):
    emit(f"  {label:<{ISSUE_LABEL_WIDTH}} {value}")


def terminal_inventory(report, emit):
    if not isinstance(report, dict) or report.get("bomFormat") != "CycloneDX":
        return
    components = [row for row in list_of(report.get("components")) if isinstance(row, dict)]
    terminal_field(emit, "Format", report.get("bomFormat") or "Unavailable")
    terminal_field(emit, "Components", len(components))
    counts = Counter(
        (first_text(row.get("type")) or "Unspecified",
         row["purl"][4:].split("/", 1)[0] if str(row.get("purl")).startswith("pkg:") else "Unspecified")
        for row in components
    )
    if counts:
        kind_width = max(len("Type"), *(len(kind) for kind, _ in counts))
        ecosystem_width = max(len("Ecosystem"), *(len(ecosystem) for _, ecosystem in counts))
        emit(f"  {'Type':<{kind_width}}  {'Ecosystem':<{ecosystem_width}}  Components")
        emit(f"  {'-' * kind_width}  {'-' * ecosystem_width}  ----------")
        for (kind, ecosystem), count in sorted(counts.items()):
            emit(f"  {kind:<{kind_width}}  {ecosystem:<{ecosystem_width}}  {count:>10}")
    examples = [f"{row['name']} {row.get('version') or ''}".strip() for row in components
                if isinstance(row.get("name"), str)]
    if examples:
        terminal_field(emit, "Component examples", ", ".join(examples[:3]))


def terminal_issue(number, scanner, package, findings, project, contexts, emit, details, metadata,
                   declaration_lookup=find_maven_declaration):
    rows = [issue for evidence, _ in findings for issue in evidence]
    primary = rows[0]
    if package:
        component, locations, dependency_type, parents, version, steps, verification = (
            dependency_remediation(package, rows, project, contexts, declaration_lookup)
        )
        title = dependency_title(component, rows, metadata)
        risks = dependency_risks(findings)
        problem = "This scanner matched the installed version against one or more vulnerability records."
    else:
        title, problem, risk, steps, verification = source_remediation(primary)
        risks = [risk]
        locations = terminal_locations(rows)

    severity = min((terminal_severity(issue) for issue in rows), key=SEVERITIES.index)
    original = sorted({f"{row['scanner_name']} {row['severity']}" for row in rows
                       if row["severity"] != severity})
    aliases = {alias for _, ids in findings for alias in ids}
    aliases.update(alias for row in rows for alias in row["cve_id"] or [])
    identifiers = sorted(aliases) or sorted({row["rule_id"] for row in rows if row["rule_id"]})
    emit(f"\nIssue {number}")
    terminal_field(emit, "Issue name", title)
    terminal_field(emit, "Scanner", scanner)
    terminal_field(emit, "Severity", severity)
    if original:
        terminal_field(emit, "Reported severity", ", ".join(original))
    by_file = defaultdict(list)
    for path, start, end in locations:
        by_file[path].append(source_label("", start, end).removeprefix(":") or "Unavailable")
    for path, lines in (by_file or {"Unavailable": ["Unavailable"]}).items():
        terminal_field(emit, "Source file", path)
        terminal_field(emit, "Line number(s)", ", ".join(dict.fromkeys(lines)))
    technologies = sorted({tech for path in by_file if (tech := technology(path))})
    if any(row.get("scan_target") == "container" for row in rows) and "Docker" not in technologies:
        technologies.append("Container image")
    terminal_field(emit, "Technology", ", ".join(technologies) or
                   ("Java package" if package and package[0] == "maven" else "Unavailable"))
    if identifiers:
        label = "Advisory ID" if aliases else "Rule ID"
        remaining = f" (+{len(identifiers) - 1} in --details)" if len(identifiers) > 1 else ""
        terminal_field(emit, label, identifiers[0] + remaining)
    else:
        terminal_field(emit, "Rule ID / CVE", "Unavailable")
    if package:
        terminal_field(emit, "Dependency", component)
        terminal_field(emit, "Installed version", version or "Unavailable")
        versions, availability = dependency_fix_evidence(findings, metadata)
        reported = ", ".join(versions[:5]) or "Not reported"
        if len(versions) > 5:
            reported += f" (+{len(versions) - 5} in --details)"
        terminal_field(emit, "Reported fixes", reported)
        terminal_field(emit, "Advisory fix status", availability)
        terminal_field(emit, "Dependency type", dependency_type)
        if parents:
            terminal_field(emit, "Direct parent(s)", ", ".join(parents))
    terminal_field(emit, "Problem", brief(problem))
    for index, risk in enumerate(risks):
        terminal_field(emit, "Security risk" if index == 0 else "", brief(risk))
    for index, step in enumerate(filter(None, steps), 1):
        terminal_field(emit, "How to fix" if index == 1 else "", f"{index}. {brief(step)}")
    terminal_field(emit, "Verification", verification)
    for directory, command in verification_commands(project, locations, package, primary["rule_id"]):
        terminal_field(emit, "Working directory", directory if directory != "." else ". (project directory)")
        terminal_field(emit, "Command", command)
    if details:
        terminal_evidence(findings, emit, metadata)


def terminal_summary(issues, metadata, project, contexts, emit, *,
                     details=False, statuses=None, inventory=None, declaration_lookup=find_maven_declaration):
    unique_groups, counts = terminal_groups(issues, metadata)
    evidence_by_issue = {id(issue): row for issue, row in zip(issues, metadata)}
    by_scanner = defaultdict(list)
    for issue, evidence in zip(issues, metadata):
        by_scanner[issue["scanner_name"]].append((issue, evidence))
    grouped_total = 0
    for key, title in SCANNER_SECTIONS:
        label = NAMES.get(key, "Syft")
        heading = f"=== {label} - {title} ==="
        emit(f"\n{heading}")
        emit("-" * len(heading))
        entry = statuses[key] if statuses is not None else None
        if entry is not None:
            duration = f"{entry.get('durationSeconds', 0):.2f}s"
            terminal_field(emit, "Execution", f"{entry['status']} | {duration}")
            if entry["report"]:
                terminal_field(emit, "JSON report", Path(entry["report"]).name)
        if key == "syft":
            terminal_inventory(inventory, emit)
            continue

        rows = by_scanner[label]
        findings, evidence = zip(*rows) if rows else ((), ())
        groups, scanner_counts = terminal_groups(findings, evidence)
        grouped = sum(scanner_counts.values())
        grouped_total += grouped
        native = entry["nativeFindingCount"] if entry is not None else len(rows)
        terminal_field(emit, "Raw findings", native if native is not None else "Unavailable")
        if native is not None or groups:
            terminal_field(emit, "Grouped findings", grouped)
            terminal_field(emit, "Issues to review", len(groups))
        for number, (package, findings) in enumerate(groups, 1):
            terminal_issue(number, label, package, findings, project, contexts, emit, details, evidence_by_issue,
                           declaration_lookup)
    return counts, len(unique_groups), grouped_total
