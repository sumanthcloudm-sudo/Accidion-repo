"""Map scanner evidence to a common issue schema and scrub published output."""
import hashlib
import re
from pathlib import Path
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
        "source_file", "start_line", "end_line", "issue_description", "root_cause", "security_impact",
        "recommended_remediation", "rule_id", "cwe_id", "cve_id", "affected_dependency",
        "installed_version", "fixed_version", "reference_links",
    ))
    issue.update(scanner_name=NAMES[scanner], **evidence)
    issue["severity"] = first_text(issue["severity"]).upper() if first_text(issue["severity"]) else "UNKNOWN"
    missing = {
        "issue_description": "No detailed description was supplied.",
        "rule_id": "The scanner did not supply an identifier for this match.",
        "source_file": "Scanner evidence did not identify a project source file.",
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


def gitleaks_issues(report, project):
    for row in report or []:
        rule = row.get("RuleID")
        description = first_text(row.get("Description"))
        yield new_issue("gitleaks", issue_name=description or rule_title(rule) or "Detected secret",
                        vulnerability_category="Secret exposure", severity=row.get("Severity"),
                        source_file=location(row.get("File"), project), start_line=line(row.get("StartLine")),
                        end_line=line(row.get("EndLine")), issue_description=description,
                        root_cause="Gitleaks matched a credential detection rule at this location.",
                        recommended_remediation="Verify whether the value is active. Revoke or rotate it if valid, remove it from source, and retrieve it from an approved secret store.",
                        rule_id=rule, reference_links=references(row.get("References")))


def semgrep_issues(report, project):
    for row in report["results"]:
        extra = row.get("extra") or {}
        meta = extra.get("metadata") or {}
        rule = row.get("check_id")
        classes = list_of(meta.get("vulnerability_class"))
        cves = identifiers(CVE, [*list_of(meta.get("cve")), extra.get("message", "")])
        yield new_issue("semgrep", issue_name=first_text(meta.get("issue_name"), meta.get("shortDescription"),
                                                       *classes, rule_title(rule), extra.get("message"))
                        or "Semgrep security rule match",
                        vulnerability_category=first_text(*classes, meta.get("subcategory"), meta.get("category"))
                        or "Source code security",
                        severity=extra.get("severity"), source_file=location(row.get("path"), project),
                        start_line=line((row.get("start") or {}).get("line")),
                        end_line=line((row.get("end") or {}).get("line")),
                        issue_description=first_text(extra.get("message")),
                        root_cause=first_text(meta.get("root_cause")),
                        security_impact=first_text(meta.get("security_impact")),
                        recommended_remediation=first_text(meta.get("recommended_remediation"), meta.get("remediation"))
                        or "Review the matched code and rule references. Apply the rule-specific secure pattern and rerun the scan.",
                        rule_id=rule, cwe_id=identifiers(CWE, meta.get("cwe")) or None, cve_id=cves or None,
                        affected_dependency=first_text(meta.get("affected_dependency")),
                        installed_version=first_text(meta.get("installed_version")),
                        fixed_version=first_text(meta.get("fixed_version")),
                        reference_links=references(meta.get("references"), meta.get("source")))


def dependency_issues(report, project):
    for item in report["dependencies"]:
        component, version = dependency_evidence(item)
        for vuln in item.get("vulnerabilities") or []:
            identifier = first_text(vuln.get("name"))
            title = first_text(vuln.get("title"))
            label = " — ".join(filter(None, (identifier, component)))
            yield new_issue("dependency-check", issue_name=title or f"Vulnerable Java dependency{f' — {label}' if label else ''}",
                            vulnerability_category="Java dependency vulnerability", severity=vuln.get("severity"),
                            source_file=location(item.get("filePath"), project, local_only=True),
                            issue_description=first_text(vuln.get("description")),
                            recommended_remediation="Confirm the dependency match, then upgrade to a vendor-supported patched release. For transitive dependencies, update or constrain the parent dependency.",
                            rule_id=identifier, cwe_id=identifiers(CWE, vuln.get("cwes")) or None,
                            cve_id=identifiers(CVE, identifier) or None, affected_dependency=component,
                            installed_version=version, reference_links=references(vuln.get("references")))


def grype_issues(report, _project):
    for row in report["matches"]:
        vuln = row["vulnerability"]
        artifact = row.get("artifact") or {}
        identifier, component = first_text(vuln.get("id")), first_text(artifact.get("name"))
        label = " — ".join(filter(None, (identifier, component)))
        versions = (vuln.get("fix") or {}).get("versions") or []
        remediation = (f"Upgrade to a compatible reported fix ({', '.join(versions)}), then rebuild and rescan."
                       if versions else "Review the advisory for a patch. If none is available, evaluate a supported replacement or mitigation.")
        yield new_issue("grype", issue_name=first_text(vuln.get("title")) or f"Vulnerable package{f' — {label}' if label else ''}",
                        vulnerability_category="Package vulnerability", severity=vuln.get("severity"),
                        issue_description=first_text(vuln.get("description")), recommended_remediation=remediation,
                        rule_id=identifier, cwe_id=identifiers(CWE, vuln.get("cwes")) or None,
                        cve_id=identifiers(CVE, [identifier, *(entry.get("id") for entry in row.get("relatedVulnerabilities") or [])]) or None,
                        affected_dependency=component, installed_version=first_text(artifact.get("version")),
                        fixed_version=versions or None, reference_links=references(vuln.get("urls"), vuln.get("dataSource")))


def checkov_issues(report, project):
    for scan in list_of(report):
        for row in scan["results"].get("failed_checks") or []:
            lines = list_of(row.get("file_line_range"))
            rule = row.get("check_id")
            path = row.get("file_abs_path") or row.get("repo_file_path")
            yield new_issue("checkov", issue_name=first_text(row.get("check_name")) or rule_title(rule) or "Infrastructure check failed",
                            vulnerability_category=first_text(row.get("bc_category"), scan.get("check_type"))
                            or "Infrastructure misconfiguration",
                            severity=row.get("severity"), source_file=location(path, project) or row.get("file_path"),
                            start_line=line(lines[0]) if lines else None,
                            end_line=line(lines[-1]) if len(lines) > 1 else None,
                            issue_description=first_text(row.get("description"), row.get("short_description"), row.get("check_name")),
                            recommended_remediation=first_text(row.get("remediation"))
                            or (f"Update the affected resource to meet this control: {row['check_name']}."
                                if row.get("check_name") else
                                "Update the affected infrastructure resource using the check guidance and rerun Checkov."),
                            rule_id=rule, reference_links=references(row.get("guideline")))


NORMALIZE = {
    "gitleaks": gitleaks_issues, "semgrep": semgrep_issues, "dependency-check": dependency_issues,
    "grype": grype_issues, "checkov": checkov_issues,
}
