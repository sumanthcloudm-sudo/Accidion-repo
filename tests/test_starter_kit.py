import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import starter_install
import starter_kit as kit


class StarterKitTests(unittest.TestCase):
    SECRET = "fixture-secret-only-947285"
    def test_platforms_and_assets(self):
        for system, machine, expected in [
            ("Windows", "AMD64", ("windows", "amd64")),
            ("Darwin", "x86_64", ("macos", "amd64")),
            ("Darwin", "arm64", ("macos", "arm64")),
            ("Linux", "aarch64", ("linux", "arm64")),
        ]:
            with self.subTest(system=system, machine=machine):
                self.assertEqual(starter_install.detect(system, machine), expected)
        self.assertEqual(starter_install.release_asset("syft", "1", "windows", "amd64"),
                         "syft_1_windows_amd64.zip")
        self.assertEqual(starter_install.release_asset("gitleaks", "8", "macos", "arm64"),
                         "gitleaks_8_darwin_arm64.tar.gz")
        self.assertIn("Git.Git", starter_install.package_command("windows", "git", lambda _: True))
        self.assertIn("temurin@21", starter_install.package_command("macos", "java", lambda _: True))
        with patch.object(starter_install.os, "geteuid", create=True, return_value=0):
            self.assertEqual(starter_install.package_command("linux", "git", lambda _: True)[0], "apt-get")
        with patch.object(starter_install.os, "geteuid", create=True, return_value=1000):
            with self.assertRaises(PermissionError):
                starter_install.package_command("linux", "git", lambda _: True)
        with self.assertRaises(ValueError):
            starter_install.detect("FreeBSD", "amd64")

    def test_installer_reuses_or_installs_and_reports_failures(self):
        installer = starter_install.Installer("linux", "amd64", Path("mock"), True, None)
        with patch.object(starter_install.shutil, "which", return_value="/approved/gitleaks"), \
             patch.object(installer, "version", return_value="8.30.1"), \
             patch.object(installer, "install") as install:
            self.assertEqual(installer.ensure("gitleaks"), ["/approved/gitleaks"])
            install.assert_not_called()
        with patch.object(starter_install.shutil, "which", return_value=None), \
             patch.object(installer, "managed", return_value=None), \
             patch.object(installer, "version", return_value="8.30.1"), \
             patch.object(installer, "install", return_value=["/managed/gitleaks"]):
            self.assertEqual(installer.ensure("gitleaks"), ["/managed/gitleaks"])
            self.assertEqual(installer.records["gitleaks"]["status"], "installed")
        with patch.object(starter_install.shutil, "which", return_value=None), \
             patch.object(installer, "managed", return_value=None), \
             patch.object(installer, "install", side_effect=PermissionError("blocked")):
            self.assertIsNone(installer.ensure("gitleaks"))
            self.assertEqual(installer.records["gitleaks"]["status"], "installation_failed")

    @staticmethod
    def populate(project):
        paths = ["src/Main.java", "pom.xml", "module/pom.xml", "mvnw", "mvnw.cmd",
                 "sidecar/build.gradle.kts", "sidecar/gradlew", "sidecar/gradlew.bat",
                 "target/app.jar", "Dockerfile", "deploy/main.tf", ".git/Hidden.java"]
        for name in paths:
            path = project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        (project / "pom.xml").write_text('<project xmlns="http://maven.apache.org/POM/4.0.0">'
                                             '<name>External Java App</name></project>')
        (project / "deploy/service.yaml").write_text("apiVersion: v1\nkind: Service\n")
        (project / "settings.json").write_text("{}")

    @staticmethod
    def mock_run(cmd, **kwargs):
        name = str(cmd[0])
        args = [str(x) for x in cmd]
        if name in {"mvn", "gradle", "docker"}:
            if "save" in args:
                Path(args[args.index("-o") + 1]).touch()
            return ""
        if name == "gitleaks":
            out = Path(args[args.index("--report-path") + 1])
            data = [{"RuleID": "generic-api-key", "Description": "Hardcoded API Key",
                     "Secret": StarterKitTests.SECRET, "Match": f'apiKey="{StarterKitTests.SECRET}"',
                     "File": "src/Main.java", "StartLine": index, "EndLine": index}
                    for index in range(1, 7)]
            print(StarterKitTests.SECRET, file=kwargs["log"])
        elif name == "semgrep":
            out = Path(args[args.index("--output") + 1])
            data = {"results": [{"check_id": "java-sql-injection", "path": "src/Main.java",
                                 "start": {"line": 12}, "end": {"line": 14},
                                 "extra": {"severity": "ERROR", "message": StarterKitTests.SECRET,
                                           "lines": "Source code", "metadata": {
                                               "issue_name": "SQL Injection", "cwe": "CWE-89",
                                               "remediation": "Bind query parameters."}}}], "errors": []}
        elif name == "dependency-check":
            out = Path(args[args.index("--out") + 1]) / kit.REPORTS[name]
            data = {"dependencies": [{"fileName": "test.jar", "packages": [{"id": "pkg:maven/test/test@1.0"}],
                                      "vulnerabilities": [{"name": "CVE-2025-12345", "severity": "HIGH"}]}]}
        elif name == "syft":
            out = Path(args[-1].split("=", 1)[1])
            data = {"bomFormat": "CycloneDX", "components": [{"name": "test", "bom-ref": "test"}]}
        elif name == "grype":
            out = Path(args[args.index("--file") + 1])
            data = {"matches": [{"vulnerability": {"id": "CVE-2025-12346", "severity": "Critical",
                                                    "fix": {"versions": ["2.0"]}},
                                 "artifact": {"name": "package", "version": "1.0"}}]}
        elif name == "checkov":
            out = Path(args[args.index("--output-file-path") + 1]) / "results_json.json"
            data = {"summary": {"parsing_errors": 0}, "results": {"failed_checks": [{
                "check_id": "CKV_DOCKER_3", "check_name": "Container Running as Root",
                "repo_file_path": "Dockerfile", "file_line_range": [1, 4], "code_block": [[1, "FROM base"]]}]}}
        else:
            raise AssertionError(f"Unexpected subprocess: {name}")
        out.write_text(json.dumps(data), encoding="utf-8")
        return ""

    def test_external_project_and_report_pipeline_on_simulated_platforms(self):
        for system, arch in [("windows", "amd64"), ("macos", "arm64"),
                             ("macos", "amd64"), ("linux", "amd64")]:
            with self.subTest(system=system, arch=arch), tempfile.TemporaryDirectory() as root:
                project = Path(root) / "external app"
                self.populate(project)
                discovered = kit.discover(project)
                self.assertEqual(len(discovered["java"]), 1)
                self.assertEqual(len(discovered["jars"]), 1)
                self.assertEqual(len(discovered["iac"]), 2)
                self.assertEqual(kit.build_roots(discovered, "maven"), [project])
                self.assertEqual(kit.build_roots(discovered, "gradle"), [project / "sidecar"])
                calls = []

                def ensure(installer, name, wrapper=None, cwd=None):
                    calls.append((name, wrapper))
                    installer.records[name] = {"status": "reused", "version": "123.4"}
                    return [name]

                home = Path(root) / "kit-data"
                with patch.dict(os.environ, {"ACCIDION_HOME": str(home), "ACCIDION_KIT_COMMIT": "1" * 40,
                                             "ACCIDION_KIT_ARCHIVE_SHA256": "2" * 64}), \
                     patch.object(kit.Installer, "ensure", ensure), \
                     patch.object(kit, "run", side_effect=self.mock_run) as runner, \
                     patch.object(kit, "private_run_path", side_effect=lambda parent: self.fake_private(parent)), \
                     patch.object(kit, "refresh_windows_path"), \
                     contextlib.redirect_stdout(io.StringIO()) as terminal:
                    options = kit.args_for(["--project-path", str(project), "--dry-run"])
                    self.assertEqual(kit.execute(options, system, arch), 0)
                    self.assertFalse(home.exists())
                    runner.assert_not_called()
                    options = kit.args_for(["--project-path", str(project), "--setup-only"])
                    self.assertEqual(kit.execute(options, system, arch), 0)
                    runner.assert_not_called()
                    options = kit.args_for(["--project-path", str(project), "--build-image"])
                    self.assertEqual(kit.execute(options, system, arch), 0)
                actual_order = [call.args[0][0] for call in runner.call_args_list
                                if call.args[0][0] in kit.REPORTS]
                self.assertEqual(actual_order, ["gitleaks", "semgrep", "dependency-check",
                                                "syft", "syft", "grype", "grype", "checkov"])
                reports = sorted((home / "reports").iterdir())[-1]
                self.assertEqual(set(p.name for p in reports.glob("*.json")),
                                 set(kit.REPORTS.values()) | {"security-summary.json", "grype-sbom-report.json"})
                summary = json.loads((reports / "security-summary.json").read_text())
                self.assertEqual(summary["applicationName"], "External Java App")
                self.assertEqual(summary["kitCommit"], "1" * 40)
                self.assertEqual(summary["kitArchiveSha256"], "2" * 64)
                self.assertTrue(all(s["status"] == "success" for s in summary["scanners"].values()))
                self.assertEqual(summary["scanners"]["syft"]["inventoryCount"], 1)
                self.assertEqual(summary["scanners"]["syft"]["findings"], [])
                self.assertEqual(summary["scanners"]["grype"]["findings"][0]["severity"], "CRITICAL")
                self.assertEqual(summary["sbomComponentCount"], 1)
                self.assertEqual(summary["totalFindings"], 11)
                self.assertEqual(summary["findingsByScanner"]["gitleaks"], 6)
                issues = summary["issues"]
                self.assertEqual([item["issue_number"] for item in issues], list(range(1, 12)))
                self.assertEqual(len({item["issue_id"] for item in issues}), 11)
                self.assertEqual(issues[0]["issue_name"], "Hardcoded API Key")
                self.assertEqual(issues[6]["issue_name"], "SQL Injection")
                self.assertEqual(issues[6]["source_file"], "src/Main.java")
                self.assertEqual((issues[6]["start_line"], issues[6]["end_line"]), (12, 14))
                self.assertEqual(issues[6]["cwe_id"], ["CWE-89"])
                self.assertEqual(issues[7]["installed_version"], "1.0")
                self.assertIsNone(issues[7]["fixed_version"])
                self.assertIn("fixed_version", issues[7]["evidence_limitations"])
                self.assertEqual(issues[8]["fixed_version"], ["2.0"])
                self.assertEqual([x["scan_target"] for x in issues[8:10]], ["sbom", "container"])
                self.assertEqual(issues[10]["issue_name"], "Container Running as Root")
                self.assertEqual(issues[10]["source_file"], "Dockerfile")
                for path in reports.iterdir():
                    self.assertNotIn(self.SECRET, path.read_text(encoding="utf-8"))
                self.assertNotIn(self.SECRET, terminal.getvalue())
                self.assertIn("Issue 11: Container Running as Root", terminal.getvalue())
                original = json.loads((reports / "gitleaks-report.json").read_text())
                self.assertEqual(original[0]["Secret"], "[REDACTED]")
                self.assertEqual(original[0]["StartLine"], 1)
                self.assertEqual(len(list((home / "reports").iterdir())), 2)
                wrappers = [wrapper for name, wrapper in calls if name in {"mvn", "gradle"}]
                self.assertTrue(wrappers)
                self.assertTrue(all((len(cmd) == 1) == (system == "windows") for cmd in wrappers))

    @staticmethod
    def fake_private(parent):
        parent.mkdir(parents=True, exist_ok=True)
        path = parent / str(len(list(parent.iterdir())))
        path.mkdir()
        return path

    def test_failed_scanner_does_not_prevent_other_applicable_scans(self):
        with tempfile.TemporaryDirectory() as root:
            project = Path(root) / "app"
            project.mkdir()
            (project / "App.java").touch()
            home = Path(root) / "data"

            def ensure(installer, name, **kwargs):
                installer.records[name] = {"status": "reused", "version": "123.4"}
                return [name]

            def mock_run(args, **kwargs):
                if args[0] == "semgrep":
                    self.mock_run(args, **kwargs)
                    raise RuntimeError("simulated network or permission failure")
                return self.mock_run(args, **kwargs)

            with patch.dict(os.environ, {"ACCIDION_HOME": str(home)}), \
                 patch.object(kit.Installer, "ensure", ensure), \
                 patch.object(kit, "run", side_effect=mock_run), \
                 patch.object(kit, "refresh_windows_path"), \
                 patch.object(kit, "private_run_path", side_effect=self.fake_private), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(kit.execute(kit.args_for(["--project-path", str(project)]), "linux", "amd64"), 1)
            summary = json.loads((home / "reports/0/security-summary.json").read_text())
            self.assertEqual(summary["scanners"]["semgrep"]["status"], "failed")
            self.assertEqual(summary["scanners"]["semgrep"]["findingCount"], 1)
            self.assertIn("simulated network or permission failure", summary["scanners"]["semgrep"]["reason"])
            self.assertTrue((home / "reports/0/semgrep-report.json").exists())
            self.assertEqual(summary["scanners"]["grype"]["status"], "success")
            self.assertEqual(summary["scanners"]["checkov"]["status"], "skipped")
            self.assertEqual(summary["installations"]["checkov"]["status"], "skipped")

class BootstrapTests(unittest.TestCase):
    pin = "0123456789abcdef" * 2 + "01234567"
    repo = "example-team/private-kit"
    token = "test_mock_token"

    def setUp(self):
        self.bash = (Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
                     if os.name == "nt" else shutil.which("bash"))
        if not self.bash or not Path(self.bash).is_file():
            self.skipTest("Bash or Git Bash unavailable")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.app = self.root / "Java Application"
        self.app.mkdir()
        (self.app / "App.java").touch()
        mock = self.root / "bin"
        mock.mkdir()
        fixture = self.root / "fixture"
        fixture.mkdir()
        self.bootstrap = kit.KIT / "bootstrap.sh"
        for name in ("bootstrap.sh", "starter_kit.py", "starter_install.py", "starter_findings.py",
                     "accidion-dependencies.gradle", ".gitleaks.toml", "semgrep.yml", ".checkov.yml"):
            shutil.copyfile(kit.KIT / name, fixture / name)
        (fixture / "security-scan.sh").write_text(
            '#!/usr/bin/env bash\nset -eu\n'
            '[[ $1 == --dry-run && $2 == --project-path && $3 -ef . && -f App.java ]]\n'
            '[[ -z "${GH_TOKEN+x}${GITHUB_TOKEN+x}" && -f "$(dirname "$0")/kit-marker" ]]\n'
            'case "$0" in "$3/"*) exit 9 ;; esac\n'
            'printf "scanner:%s:%s\\n" "$ACCIDION_KIT_COMMIT" "$ACCIDION_KIT_ARCHIVE_SHA256"\n',
            newline="\n",
        )
        (fixture / "kit-marker").touch()
        archive = self.root / "fixture.tar.gz"
        with tarfile.open(archive, "w:gz") as output:
            output.add(fixture, arcname=f"team-private-kit-{self.pin}")
        self.bootstrap_sha = hashlib.sha256(self.bootstrap.read_bytes()).hexdigest()
        self.archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
        self.mock_script(mock / "curl",
            '#!/usr/bin/env bash\nset -eu\n'
            'if [[ " $* " == *" --version "* ]]; then printf "curl %s\\n" "$MOCK_CURL_VERSION"; exit; fi\n'
            'if [[ " $* " == *" -w "* || " $* " == *" --write-out "* ]]; then printf "%s" "$MOCK_HTTP_CODE"; exit; fi\n'
            '[[ " $* " != *"$MOCK_TOKEN"* && -z "${GH_TOKEN+x}${GITHUB_TOKEN+x}" ]]\n'
            'read -r auth\n[[ $auth == "header = \\"Authorization: Bearer $MOCK_TOKEN\\"" ]]\n'
            'case " $* " in\n'
            '  *"/contents/bootstrap.sh?ref=$MOCK_PIN "*) input=$MOCK_BOOTSTRAP ;;\n'
            '  *"/tarball/$MOCK_PIN "*) [[ ${MOCK_ARCHIVE_FAIL:-0} == 0 ]] || exit 22; input=$MOCK_ARCHIVE ;;\n'
            '  *) exit 11 ;;\nesac\n'
            'while [[ "$1" != --output && "$1" != -o ]]; do shift; done\n'
            'cp -- "$input" "$2"\n')
        self.mock_script(mock / "uname",
            '#!/usr/bin/env bash\ncase "$1" in -s) echo "$MOCK_OS" ;; -m) echo "$MOCK_ARCH" ;; esac\n')
        self.mock_script(mock / "gh",
            '#!/usr/bin/env bash\nset -eu\n'
            'case "$1" in\n'
            '  auth) [[ ${MOCK_GH_LOGIN:-0} == 1 ]]; printf "%s\\n" "$MOCK_TOKEN" ;;\n'
            '  repo) [[ " $* " == *" $MOCK_REPO "* && $MOCK_HTTP_CODE == 404 ]]; echo true ;;\n'
            '  api) [[ " $* " == *"repos/$MOCK_REPO/contents/bootstrap.sh?ref=$MOCK_PIN " ]]; cat -- "$MOCK_BOOTSTRAP" ;;\n'
            '  release) [[ " $* " == *" kit-$MOCK_PIN "* && " $* " == *" $MOCK_REPO "* &&'
            ' " $* " == *" accidion-kit.tar.gz "* && $GH_TOKEN == "$MOCK_TOKEN" ]]; cat -- "$MOCK_ARCHIVE" ;;\n'
            '  *) exit 12 ;;\nesac\n')
        self.mock_script(mock / "git",
            '#!/usr/bin/env bash\nset -eu\n'
            '[[ $1 == -C && $2 -ef "$MOCK_KIT" ]] || exit 3\n'
            'case "$3" in rev-parse) printf "%s\\n" "$MOCK_KIT" ;;\n'
            '    remote) printf "%s\\n" "$MOCK_ORIGIN" ;; *) exit 4 ;; esac\n')
        self.env = {**os.environ, "GH_TOKEN": self.token, "GITHUB_TOKEN": "", "MOCK_TOKEN": self.token,
                    "MOCK_PIN": self.pin, "MOCK_HTTP_CODE": "404", "MOCK_CURL_VERSION": "8.12.0",
                    "MOCK_OS": "MINGW64_NT", "MOCK_ARCH": "x86_64", "MOCK_BIN": self.posix(mock),
                    "MOCK_ARCHIVE": self.posix(archive), "MOCK_BOOTSTRAP": self.posix(self.bootstrap),
                    "TMPDIR": self.posix(self.app), "MOCK_KIT": self.posix(kit.KIT),
                    "MOCK_ORIGIN": f"git@github.com:{self.repo}.git", "MOCK_REPO": self.repo}
        guide = (kit.KIT / "README.md").read_text(encoding="utf-8")
        block = next(part for part in guide.split("~~~bash\n") if part.startswith("bash -s -- OWNER/PRIVATE_REPO"))
        pins = "OWNER/PRIVATE_REPO FULL_COMMIT_SHA BOOTSTRAP_SHA256 KIT_ARCHIVE_SHA256"
        self.command = block.split("\n~~~", 1)[0].replace(
            pins, f"{self.repo} {self.pin} {self.bootstrap_sha} {self.archive_sha} --dry-run", 1
        )
        release = next(part for part in guide.split("~~~bash\n") if part.startswith("bash -c"))
        self.release_command = release.split("\n~~~", 1)[0].replace(
            pins,
            f"{self.repo} {self.pin} {self.bootstrap_sha} {self.archive_sha} --dry-run", 1,
        )

    @staticmethod
    def posix(path):
        return path.as_posix() if os.name != "nt" else "/" + path.drive[0].lower() + path.as_posix()[2:]

    @staticmethod
    def mock_script(path, body):
        path.write_text(body, newline="\n")
        path.chmod(0o700)

    def shell(self, command, **environment):
        prefix = 'export PATH="$MOCK_BIN:$PATH"\n'
        result = subprocess.run([self.bash, "-c", prefix + command], cwd=self.app,
                                env={**self.env, **environment}, timeout=30, text=True, capture_output=True)
        self.assertNotIn(self.token, result.stderr + result.stdout)
        return result

    def test_documented_bootstrap_downloads_both_pins_and_preserves_target(self):
        for system, machine, expected in [
            ("MINGW64_NT", "x86_64", "windows/amd64"),
            ("Darwin", "x86_64", "macos/amd64"),
            ("Darwin", "arm64", "macos/arm64"),
            ("Linux", "aarch64", "linux/arm64"),
        ]:
            with self.subTest(system=system, machine=machine):
                result = self.shell(self.command, MOCK_OS=system, MOCK_ARCH=machine)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout)
                self.assertIn(f"scanner:{self.pin}:{self.archive_sha}", result.stdout)
                self.assertEqual([p.name for p in self.app.iterdir()], ["App.java"])
        result = self.shell(self.command, GH_TOKEN="", MOCK_GH_LOGIN="1")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bootstrap_rejects_unapproved_or_inaccessible_artifacts(self):
        for command, environment, expected in [
            (self.command, {"MOCK_HTTP_CODE": "200"}, "Expected a private repository"),
            (self.command, {"GH_TOKEN": ""}, "Authenticate"),
            (self.command, {"MOCK_ARCHIVE_FAIL": "1"}, "Pinned archive download failed"),
            (self.command.replace(self.pin, "main"), {}, "both reviewed digests"),
            (self.command.replace(self.bootstrap_sha, "0" * 64), {}, "Bootstrap SHA-256 mismatch"),
            (self.command.replace(self.archive_sha, "0" * 64), {}, "Archive SHA-256 mismatch"),
        ]:
            with self.subTest(expected=expected):
                result = self.shell(command, **environment)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(expected, result.stderr)
                self.assertNotIn("scanner:", result.stdout)

    def test_bootstrap_detects_missing_prerequisites_and_unsupported_platform(self):
        for environment, expected in [
            ({"MOCK_CURL_VERSION": "7.82.0"}, "curl 7.83.1 or newer"),
            ({"MOCK_OS": "FreeBSD"}, "Unsupported operating system"),
            ({"MOCK_ARCH": "i686"}, "Unsupported processor architecture"),
        ]:
            with self.subTest(expected=expected):
                result = self.shell(self.command, **environment)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(expected, result.stderr)
        result = self.shell(f'PATH= "$BASH" "{self.posix(self.bootstrap)}"')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("uname is required", result.stderr)

    def test_direct_bootstrap_uses_kit_origin_and_rejects_unsupported_origin(self):
        command = (f'bash "{self.posix(self.bootstrap)}" --commit {self.pin} '
                   f'--archive-sha256 {self.archive_sha} -- --dry-run')
        result = self.shell(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("scanner:", result.stdout)
        result = self.shell(command, MOCK_ORIGIN="https://example.invalid/team/other")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Confirm the private GitHub repository", result.stderr)

    def test_private_release_download_uses_commit_tag_and_validates_asset(self):
        result = self.shell(self.release_command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"scanner:{self.pin}:{self.archive_sha}", result.stdout)
        result = self.shell(self.release_command.replace(self.archive_sha, "0" * 64))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Archive SHA-256 mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
