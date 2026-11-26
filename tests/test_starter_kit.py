import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import starter_findings as findings
import starter_install
import starter_kit as kit


def host_bash():
    if os.name != "nt":
        return shutil.which("bash")
    git = shutil.which("git")
    if git:
        git_tools = Path(subprocess.check_output([git, "--exec-path"], text=True).strip())
        if len(git_tools.parents) >= 3:
            bash = git_tools.parents[2] / "bin/bash.exe"
            if bash.is_file():
                return str(bash)
    return None


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
            self.assertEqual(starter_install.package_command("linux", "git", lambda _: True, family="debian")[0],
                             "apt-get")
            self.assertEqual(starter_install.package_command("linux", "docker", lambda _: True, family="fedora"),
                             ["dnf", "install", "-y", "moby-engine"])
            self.assertEqual(starter_install.package_command("linux", "docker", lambda tool: tool == "yum",
                                                               family="rhel"),
                             ["yum", "install", "-y", "docker-ce"])
        with patch.object(starter_install.os, "geteuid", create=True, return_value=1000):
            with self.assertRaises(PermissionError):
                starter_install.package_command("linux", "git", lambda _: True)
        with self.assertRaises(ValueError):
            starter_install.detect("FreeBSD", "amd64")

    def test_linux_distribution_identification(self):
        for release, family in [
            ({"ID": "ubuntu", "ID_LIKE": "debian"}, "debian"),
            ({"ID": "debian"}, "debian"),
            ({"ID": "fedora"}, "fedora"),
            ({"ID": "rocky", "ID_LIKE": "rhel centos fedora"}, "rhel"),
            ({"ID": "rhel", "ID_LIKE": "fedora"}, "rhel"),
        ]:
            with self.subTest(release=release), patch.object(
                starter_install.platform, "freedesktop_os_release", return_value=release
            ):
                self.assertEqual(starter_install.linux_family(), family)

    def test_missing_arm_package_is_reported_without_download(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(starter_install, "fetch") as fetch:
            installer = starter_install.Installer("windows", "arm64", Path(directory), True, None)
            with self.assertRaisesRegex(RuntimeError, r"No verified upstream grype .* windows/arm64"):
                installer.install_archive("grype")
            fetch.assert_not_called()

    def test_intel_macos_semgrep_uses_verified_wheel_and_versioned_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            installer = starter_install.Installer("macos", "amd64", cache, True, None)
            base = cache / f"semgrep-1.182.1-{sys.version_info.major}.{sys.version_info.minor}"
            script = base / "bin/semgrep"
            script.parent.mkdir(parents=True)
            script.touch()
            with patch.object(starter_install, "run", return_value="pip 25.3") as run:
                installer.install_pypi("semgrep")
            command = run.call_args.args[0]
            self.assertEqual(command[0], base / "bin/python")
            self.assertIn("--only-binary=:all:", command)
            self.assertRegex(command[-1], r"^https://files\.pythonhosted\.org/.*/semgrep-1\.182\.1-"
                                          r".*-macosx_10_14_x86_64\.whl#sha256=[0-9a-f]{64}$")
            self.assertEqual(installer.managed("semgrep"), [str(script)])
            for system, arch in (("macos", "arm64"), ("windows", "amd64"), ("linux", "amd64"), ("linux", "arm64")):
                other = starter_install.Installer(system, arch, cache, True, None)
                self.assertEqual(other.pypi_package("semgrep"), ("1.186.0", "semgrep==1.186.0"))

    def test_pinned_release_rejects_checksum_mismatch_without_api_request(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(starter_install, "fetch", return_value="0" * 64) as fetch:
            installer = starter_install.Installer("macos", "arm64", Path(directory), True, None)
            with self.assertRaisesRegex(RuntimeError, r"Download checksum mismatch"):
                installer.install_archive("gitleaks")
            fetch.assert_called_once()
            url, _, algorithm = fetch.call_args.args
            self.assertTrue(url.startswith("https://github.com/gitleaks/gitleaks/releases/download/"))
            self.assertEqual(algorithm, "sha256")

    def test_native_launcher_and_private_report_directory(self):
        bash = host_bash()
        if not bash:
            if os.environ.get("ACCIDION_EXPECT_SYSTEM"):
                self.fail("The runner needs Bash, or Git Bash on Windows")
            self.skipTest("Bash or Git Bash unavailable")
        system, arch = kit.detect()
        self.assertEqual(system, os.getenv("ACCIDION_EXPECT_SYSTEM", system))
        self.assertEqual(arch, os.getenv("ACCIDION_EXPECT_ARCH", arch))
        if family := os.getenv("ACCIDION_EXPECT_DISTRO"):
            self.assertEqual(starter_install.linux_family(), family)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "Fresh Java"
            app.mkdir()
            (app / "pom.xml").write_text("<project><name>Compatibility App</name></project>")
            (app / "Main.java").touch()
            (app / "Dockerfile").write_text("FROM scratch\n")
            for script in ("bootstrap.sh", "security-scan.sh"):
                subprocess.run([bash, "-n", str(kit.KIT / script)], check=True, timeout=30)
            result = subprocess.run([bash, str(kit.KIT / "security-scan.sh"), "--dry-run"],
                                    cwd=app, text=True, capture_output=True, check=True, timeout=30,
                                    env={**os.environ, "ACCIDION_HOME": str(root / "home"),
                                         "PYTHONDONTWRITEBYTECODE": "1"})
            plan = json.loads(result.stdout)
            self.assertEqual((plan["platform"], plan["architecture"]), (system, arch))
            self.assertEqual(plan["reportApplicationDirectory"], "compatibility-app")
            self.assertTrue(all(reason is None for reason in plan["scanners"].values()))
            run_dir = kit.private_run_path(root / "reports" / plan["reportApplicationDirectory"])
            self.assertRegex(run_dir.name, r"^scan-\d{8}T\d{6}Z-")
            kit.write_json(run_dir / "fixture.json", {"smoke": True})
            self.assertEqual(json.loads((run_dir / "fixture.json").read_text()), {"smoke": True})

    def test_launcher_rejects_invalid_requests_before_python_bootstrap(self):
        bash = host_bash()
        if not bash:
            self.skipTest("Bash or Git Bash unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "Application with spaces"
            project.mkdir()
            bundle = root / "kit"
            bundle.mkdir()
            script = bundle / "security-scan.sh"
            shutil.copyfile(kit.KIT / script.name, script)
            for filename in kit.TOOLKIT_FILES:
                (bundle / filename).touch()
            def launch(*arguments):
                # Hide Python and make any package manager call observable.
                return subprocess.run(
                    [bash, "-c", 'cd -- "$1" || exit; shift; export PATH=./missing-bin ACCIDION_HOME=./home UV_PYTHON_INSTALL_DIR=./unused-python; '
                     'uname() { case "$1" in -s) echo Darwin ;; -m) echo x86_64 ;; esac; }; '
                     'dirname() { printf "%s\\n" "${2%/*}"; }; '
                     'brew() { echo "bootstrap attempted" >&2; return 1; }; '
                     'source kit/security-scan.sh "$@"',
                     "launcher-test", str(root), *arguments],
                    capture_output=True, text=True, timeout=30,
                )

            arguments = ("--project-path=./Application with spaces",)
            self.assertIn("bootstrap attempted", launch(*arguments).stderr)
            for extra, message in [
                (("--dry-r",), "Unknown argument"),
                (("--report-dir", "--no-install"), "requires a value"),
                (("--image=",), "non-empty value"),
                (("--image", "local:tag", "--build-image"), "cannot be combined"),
                (("--setup-only", "--dry-run"), "cannot be combined"),
                (("--project-path=./missing",), "accessible directory"),
                (("--report-dir=./Application with spaces/reports",), "outside the application"),
            ]:
                with self.subTest(arguments=extra):
                    result = launch(*arguments, *extra)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(message, result.stderr)
                    self.assertNotIn("bootstrap attempted", result.stderr)
            preview = launch(*arguments, "--dry-run", "--no-install")
            self.assertEqual(preview.returncode, 0, preview.stderr)
            self.assertIn("Python 3.10+ is missing", preview.stdout)
            self.assertNotIn("bootstrap attempted", preview.stderr)
            setup = launch(*arguments, "--setup-only", "--no-install")
            self.assertEqual(setup.returncode, 2, setup.stderr)
            self.assertIn("installation disabled", setup.stderr)
            self.assertNotIn("bootstrap attempted", setup.stderr)
            (bundle / "semgrep.yml").unlink()
            incomplete = launch(*arguments)
            self.assertEqual(incomplete.returncode, 2, incomplete.stderr)
            self.assertIn("semgrep.yml", incomplete.stderr)
            self.assertNotIn("bootstrap attempted", incomplete.stderr)
            self.assertEqual(launch("--help").returncode, 0)

    def test_runner_validates_report_and_image_paths_before_provisioning(self):
        for arguments in (["--ima", "local:tag"], ["--image"], ["--image= "],
                          ["--report-dir="], ["--dry-run", "--setup-only"],
                          ["--image", "local:tag", "--build-image"]):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    kit.args_for(arguments)
                self.assertEqual(error.exception.code, 2)
        for mode in ("--setup-only", "--dry-run"):
            self.assertTrue(kit.args_for([mode, "--no-install"]).no_install)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "project"
            project.mkdir()
            file = root / "file"
            file.touch()
            with patch.dict(os.environ, {"ACCIDION_HOME": str(root / "home")}), \
                 patch.object(kit, "Installer") as installer:
                arguments = ["--project-path", str(project)]
                for mode in ([], ["--dry-run"]):
                    for extra, error in [
                        (["--report-dir", str(project / "reports")], "outside the application"),
                        (["--report-dir", str(file / "output")], "must be a directory"),
                        (["--build-image"], "requires a root Dockerfile"),
                    ]:
                        with self.subTest(mode=mode, arguments=extra), self.assertRaisesRegex(ValueError, error):
                            kit.execute(kit.args_for([*arguments, *mode, *extra]), *kit.detect())
                for name in ("one", "two"):
                    (project / name).mkdir()
                    (project / name / "Dockerfile").touch()
                with self.assertRaisesRegex(ValueError, "exactly one discovered Dockerfile"):
                    kit.execute(kit.args_for([*arguments, "--build-image"]), *kit.detect())
                installer.assert_not_called()
                self.assertFalse((root / "home").exists())

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

    def test_debian_recovers_partially_created_scanner_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            installer = starter_install.Installer("linux", "amd64", cache, True, None)
            base = cache / f"semgrep-{starter_install.PYPI['semgrep']}-{sys.version_info.major}.{sys.version_info.minor}"
            base.mkdir()
            with patch.object(starter_install, "linux_family", return_value="debian"), \
                 patch.object(starter_install, "run", side_effect=[RuntimeError("pip missing"),
                              RuntimeError("ensurepip missing"), "", "pip 25.3", ""]) as runner, \
                 patch.object(installer, "bootstrap_pip") as bootstrap:
                installer.install_pypi("semgrep")
            self.assertEqual(runner.call_args_list[2].args[0],
                             [sys.executable, "-m", "venv", "--without-pip", base])
            bootstrap.assert_called_once_with(base / "bin/python")
            self.assertEqual(installer.records["pip:semgrep"]["status"], "installed")

    @staticmethod
    def populate(project):
        paths = ["src/main/java/example/Main.java", "pom.xml", "module/pom.xml", "mvnw", "mvnw.cmd",
                 "sidecar/build.gradle.kts", "sidecar/gradlew", "sidecar/gradlew.bat",
                 "target/app.jar", "Dockerfile", "deploy/main.tf", ".git/Hidden.java"]
        for name in paths:
            path = project / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        (project / "pom.xml").write_text("""<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId>
    <version>3.4.1</version>
  </parent>
  <groupId>example</groupId><artifactId>fixture-app</artifactId><version>1.0.0</version>
  <name>External Java App</name>
  <dependencies>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
  </dependencies>
</project>
""")
        (project / "src/main/java/example/Main.java").write_text("""package example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }

    String buildFixtureQuery(String input) {
        String query = "SELECT name FROM demo WHERE name = " + input;
        return query;
    }
}
""")
        (project / "fixture.env").write_text("token=FAKE_FIXTURE_VALUE_ONLY\n")
        (project / "Dockerfile").write_text("FROM eclipse-temurin:21-jre\nWORKDIR /app\nUSER root\nCOPY target/app.jar app.jar\n")
        (project / "deploy/main.tf").write_text('resource "aws_s3_bucket" "fixture" {\n  bucket = "synthetic-never-deploy"\n}\n')
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
                     "File": "fixture.env", "StartLine": index, "EndLine": index}
                    for index in range(1, 7)]
            print(StarterKitTests.SECRET, file=kwargs["log"])
        elif name == "semgrep":
            out = Path(args[args.index("--output") + 1])
            data = {"results": [{"check_id": "java-sql-injection", "path": "src/main/java/example/Main.java",
                                 "start": {"line": 12}, "end": {"line": 14},
                                 "extra": {"severity": "ERROR", "message": StarterKitTests.SECRET,
                                           "lines": "Source code", "metadata": {
                                               "issue_name": "SQL Injection", "cwe": "CWE-89",
                                               "security_impact": "The query can be altered.",
                                               "remediation": "Bind query parameters."}}}], "errors": []}
        elif name == "dependency-check":
            out = Path(args[args.index("--out") + 1]) / kit.REPORTS[name]
            data = {"dependencies": [{"fileName": "test.jar", "packages": [{"id": "pkg:maven/test/test@1.0"}],
                                      "vulnerabilities": [{"name": "CVE-2025-12345", "severity": "HIGH"}]}]}
        elif name == "syft":
            out = Path(args[-1].split("=", 1)[1])
            data = {"bomFormat": "CycloneDX", "components": [{"name": "test", "bom-ref": "test", "type": "library",
                                                          "version": "1.0", "purl": "pkg:maven/test/test@1.0"}]}
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
                project = Path(root).resolve() / "external app"
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

                home = Path(root).resolve() / "kit-data"
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
                    options = kit.args_for(["--project-path", str(project), "--build-image", "--details", "--verbose"])
                    self.assertEqual(kit.execute(options, system, arch), 0)
                actual_order = [call.args[0][0] for call in runner.call_args_list
                                if call.args[0][0] in kit.REPORTS]
                self.assertEqual(actual_order, ["gitleaks", "semgrep", "dependency-check",
                                                "syft", "syft", "grype", "grype", "checkov"])
                application_reports = home / "reports/external-java-app"
                reports = sorted(application_reports.iterdir())[-1]
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
                self.assertEqual(issues[0]["issue_name"], "Hardcoded API key")
                self.assertEqual(issues[6]["issue_name"], "SQL Injection")
                self.assertEqual(issues[6]["source_file"], "src/main/java/example/Main.java")
                self.assertEqual(issues[6]["affected_filename"], "Main.java")
                self.assertEqual(issues[6]["relative_file_path"], "src/main/java/example/Main.java")
                self.assertEqual({key: row["nativeFindingCount"] for key, row in summary["scanners"].items()},
                                 summary["findingsByScanner"])
                self.assertEqual((issues[6]["start_line"], issues[6]["end_line"]), (12, 14))
                self.assertEqual(issues[6]["cwe_id"], ["CWE-89"])
                self.assertEqual(issues[6]["severity"], "ERROR")
                self.assertEqual(issues[6]["security_impact"], "The query can be altered.")
                self.assertEqual(issues[6]["recommended_remediation"], "Bind query parameters.")
                self.assertEqual(issues[7]["installed_version"], "1.0")
                self.assertEqual(issues[7]["affected_filename"], "test.jar")
                self.assertIsNone(issues[7]["relative_file_path"])
                self.assertIsNone(issues[7]["fixed_version"])
                self.assertIn("fixed_version", issues[7]["evidence_limitations"])
                self.assertEqual(issues[8]["fixed_version"], ["2.0"])
                self.assertEqual([x["scan_target"] for x in issues[8:10]], ["sbom", "container"])
                self.assertEqual(issues[10]["issue_name"], "Container Running as Root")
                self.assertEqual(issues[10]["source_file"], "Dockerfile")
                for path in reports.iterdir():
                    self.assertNotIn(self.SECRET, path.read_text(encoding="utf-8"))
                    if path.suffix == ".json":
                        self.assertIsInstance(json.loads(path.read_text(encoding="utf-8")), (dict, list))
                self.assertNotIn(self.SECRET, terminal.getvalue())
                output = terminal.getvalue()
                self.assertIn("Report finding #11 | Checkov", output)
                self.assertRegex(output, r"Syft: success \| \d+\.\d+s \| 1 component")
                self.assertIn("Scanner execution: completed", output)
                self.assertIn("Security validation: findings require review", output)
                self.assertIn("CRITICAL 2 | HIGH 2 | MEDIUM 0 | LOW 0 | UNKNOWN 7", output)
                self.assertRegex(output, r"Reported severity +Semgrep ERROR")
                self.assertRegex(output, r"Application +External Java App")
                self.assertIn(str(project), output)
                self.assertRegex(output, r"Operating system +(?:Windows|Linux|macOS) \(")
                self.assertRegex(output, r"Build system +Maven, Gradle")
                self.assertRegex(output, r"Started \(UTC\) +\d{4}-\d{2}-\d{2}")
                self.assertRegex(output, r"Applicable scanners +Gitleaks, Semgrep, OWASP Dependency-Check, Syft, Grype, Checkov")
                self.assertLess(output.index("=== Accidion Security Scan ==="), output.index("Gitleaks: running"))
                self.assertIn("Severity (grouped findings, deduplicated across scanners):", output)
                self.assertIn("Scanning in progress", output)
                self.assertRegex(output, r"(?m)^  library +maven +1$")
                self.assertRegex(output, r"Component examples +test 1\.0")
                headings = [output.rindex(f"=== {kit.NAMES.get(key, 'Syft')} - {title} ===")
                            for key, title in findings.SCANNER_SECTIONS]
                self.assertEqual(headings, sorted(headings))
                self.assertGreater(output.index("=== Security Summary ===", headings[-1]), headings[-1])
                self.assertRegex(output, r"JSON reports: .*security-summary\.json.*syft-sbom\.json")
                self.assertNotIn("Related issue", output)
                ends = headings[1:] + [output.index("=== Security Summary ===", headings[-1])]
                sections = [output[start:end] for start, end in zip(headings, ends)]
                for section, expected in zip(sections, ([1, 2, 3, 4, 5, 6], [1], [1], [], [1, 2], [1])):
                    self.assertEqual([int(n) for n in re.findall(r"(?m)^Issue (\d+)$", section)], expected)
                self.assertIn("Diagnostics", output)
                self.assertLess(output.index("Semgrep: running"), output.index("Semgrep: success"))
                original = json.loads((reports / "gitleaks-report.json").read_text())
                self.assertEqual(original[0]["Secret"], "[REDACTED]")
                self.assertEqual(original[0]["StartLine"], 1)
                self.assertEqual(len(list(application_reports.iterdir())), 2)
                wrappers = [wrapper for name, wrapper in calls if name in {"mvn", "gradle"}]
                self.assertTrue(wrappers)
                self.assertTrue(all((len(cmd) == 1) == (system == "windows") for cmd in wrappers))

    @staticmethod
    def fake_private(parent):
        parent.mkdir(parents=True, exist_ok=True)
        path = parent / str(len(list(parent.iterdir())))
        path.mkdir()
        return path

    def test_vulnerability_caches_persist_across_separate_runs(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root).resolve() / "data"
            project = Path(root) / "app"
            self.populate(project)
            cache_marker_seen = {"dependency-check": [], "grype": []}

            def ensure(installer, name, **kwargs):
                installer.records[name] = {"status": "reused", "version": "123.4"}
                return [name]

            def mock_run(args, **kwargs):
                name = args[0]
                if name in cache_marker_seen:
                    path = (Path(args[args.index("--data") + 1]) if name == "dependency-check"
                            else Path(kwargs["env"]["GRYPE_DB_CACHE_DIR"]))
                    self.assertEqual(path.parent, home)
                    marker = path / "fake-database"
                    cache_marker_seen[name].append(marker.is_file())
                    marker.touch()
                return self.mock_run(args, **kwargs)

            with patch.dict(os.environ, {"ACCIDION_HOME": str(home), "GRYPE_DB_CACHE_DIR": ""}), \
                 patch.object(kit.Installer, "ensure", ensure), \
                 patch.object(kit, "run", side_effect=mock_run), \
                 patch.object(kit, "refresh_windows_path"), \
                 patch.object(kit, "private_run_path", side_effect=self.fake_private), \
                 contextlib.redirect_stdout(io.StringIO()):
                arguments = ["--project-path", str(project)]
                self.assertEqual(kit.execute(kit.args_for(arguments), "windows", "amd64"), 0)
                self.assertEqual(kit.execute(kit.args_for([*arguments, "--no-install"]), "windows", "amd64"), 0)
            self.assertEqual(cache_marker_seen, {"dependency-check": [False, True], "grype": [False, True]})
            runs = sorted((home / "reports/external-java-app").iterdir())
            self.assertEqual(len(runs), 2)
            for index, run_directory in enumerate(runs):
                summary = json.loads((run_directory / "security-summary.json").read_text())
                self.assertEqual({key: info["presentBeforeScan"] for key, info in summary["vulnerabilityCaches"].items()},
                                 {"dependency-check": bool(index), "grype": bool(index)})

    def test_large_maven_scan_shares_index_and_declaration_cache(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / "data"
            project = Path(root).resolve() / "app"
            self.populate(project)
            original = (project / "pom.xml").read_text()
            (project / "pom.xml").unlink()
            (project / "module/pom.xml").unlink()
            for number in range(24):
                module = project / f"module-{number:02}"
                module.mkdir()
                (module / "pom.xml").write_text(
                    f"<project><groupId>test</groupId><artifactId>module-{number}</artifactId></project>"
                )
            pom = project / "module-00" / "pom.xml"
            declaration = (
                "<dependency><groupId>test</groupId><artifactId>parent</artifactId>"
                "<version>1.0</version></dependency>"
            )
            pom.write_text(original.replace("example</groupId><artifactId>fixture-app", "test</groupId><artifactId>module-0")
                           .replace("<dependencies>", "<dependencies>\n    " + declaration))
            parent_line = next(number for number, line in enumerate(pom.read_text().splitlines(), 1)
                               if declaration in line)

            def node(artifact, version="1.0", children=()):
                return dict(groupId="test", artifactId=artifact, version=version, children=list(children))

            def resolve(_project, builds, deps, _log, _diagnostic, *, timeout=3600):
                for number, (family, _, _) in enumerate(builds):
                    if family != "maven":
                        continue
                    target = deps / str(number)
                    target.mkdir(exist_ok=True)
                    previous = node(f"prior-{number}")
                    padding = [node(f"library-{number}-{index}") for index in range(200)]
                    children = [*padding]
                    if number == 0:
                        bridge = node("bridge", f"1.{run}", children=[node("test")])
                        children.append(node("parent", children=[bridge]))
                    tree = node(f"module-{number}", children=children)
                    (target / "maven-dependency-tree.json").write_text(json.dumps(previous) + json.dumps(tree))

            def ensure(installer, name, **kwargs):
                installer.records[name] = {"status": "reused", "version": "123.4"}
                return [name]

            def scanner(args, **kwargs):
                if args[0] == "dependency-check":
                    out = Path(args[args.index("--out") + 1]) / kit.REPORTS["dependency-check"]
                    package = {"id": "pkg:maven/test/test@1.0"}
                    vulnerability = {"name": "CVE-2025-12345", "severity": "HIGH"}
                    kit.write_json(out, {"dependencies": [
                        {"fileName": "test.jar", "packages": [package], "vulnerabilities": [vulnerability]}
                    ] * finding_count})
                elif args[0] == "grype":
                    out = Path(args[args.index("--file") + 1])
                    artifact = {"name": "test", "version": "1.0", "type": "java-archive",
                                "metadata": {"pomGroupID": "test", "pomArtifactID": "test"}}
                    kit.write_json(out, {"matches": [
                        {"vulnerability": {"id": "CVE-2025-12345", "severity": "High"}, "artifact": artifact}
                    ] * finding_count})
                else:
                    return self.mock_run(args, **kwargs)

            with patch.dict(os.environ, {"ACCIDION_HOME": str(home), "GRYPE_DB_CACHE_DIR": ""}), \
                 patch.object(kit.Installer, "ensure", ensure), \
                 patch.object(kit, "run", side_effect=scanner), \
                 patch.object(kit, "resolve_dependencies", side_effect=resolve), \
                 patch.object(kit, "maven_trees", wraps=kit.maven_trees) as load_trees, \
                 patch.object(kit, "index_maven_dependencies", wraps=kit.index_maven_dependencies) as index_trees, \
                 patch.object(kit, "find_maven_declaration", wraps=kit.find_maven_declaration) as declare, \
                 patch.object(kit, "refresh_windows_path"), \
                 patch.object(kit, "private_run_path", side_effect=self.fake_private), \
                 contextlib.redirect_stdout(io.StringIO()) as terminal:
                options = kit.args_for(["--project-path", str(project)])
                for run, finding_count in enumerate((1001, 1)):
                    # Move the declaration between runs to verify that cached line numbers expire.
                    if run:
                        pom.write_text("\n" + pom.read_text())
                    self.assertEqual(kit.execute(options, "linux", "amd64"), 0)
                    summary_path = home / "reports" / "app" / str(run) / "security-summary.json"
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                    self.assertEqual(set(summary["scanners"]), set(kit.REPORTS))
                    self.assertTrue(all(row["status"] == "success" for row in summary["scanners"].values()))
                    self.assertIsNotNone(summary["mavenIndexDurationSeconds"])
                    for name in ("dependency-check", "grype"):
                        result = summary["scanners"][name]
                        self.assertEqual(result["status"], "success")
                        self.assertEqual(result["nativeFindingCount"], finding_count)
                        self.assertEqual(result["findingCount"], finding_count)
                        timing = result["reportProcessing"][0]
                        for stage in ("loadSeconds", "sanitizeAndWriteSeconds", "normalizeSeconds",
                                      "mavenEnrichmentSeconds", "totalSeconds"):
                            self.assertGreaterEqual(timing[stage], 0)
                        for issue in result["findings"]:
                            self.assertEqual(issue["dependency_chains"], [
                                f"test:module-0:1.0 -> test:parent:1.0 -> test:bridge:1.{run} -> test:test:1.0"
                            ])
                            self.assertEqual(issue["dependency_type"], "Transitive")
                            self.assertEqual(issue["parent_dependency"], "test:bridge")
                            self.assertEqual(issue["direct_dependency"], "test:parent")
                            self.assertEqual(issue["direct_dependency_source_file"], "module-00/pom.xml")
                            self.assertEqual(issue["direct_dependency_start_line"], parent_line + run)
                            self.assertEqual(issue["direct_dependency_end_line"], parent_line + run)
                            self.assertIn("Review and update test:parent", issue["dependency_remediation"])
                    self.assertEqual(load_trees.call_count, 24 * (run + 1))
                    self.assertEqual(index_trees.call_count, run + 1)
                    for component in ("test:test", "test:parent"):
                        # Global lookups include both a miss for the vulnerable transitive
                        # dependency and a hit for its direct ancestor.
                        self.assertEqual(sum(call.args == (project, component, "1.0")
                                             and "declaration_pom" not in call.kwargs
                                             for call in declare.call_args_list), run + 1)
            rendered = terminal.getvalue()
            scanner_stages = [rendered.index(f"OWASP Dependency-Check | {message}") for message in (
                "Loading dependency-check-report.json", "Sanitizing dependency-check-report.json",
                "Normalizing 1001 findings", "Enriching Maven dependency evidence", "Processed 1000/1001 findings",
            )]
            self.assertEqual(scanner_stages, sorted(scanner_stages))
            self.assertIn("Grype | Processed 1000/1001 findings", rendered)
            self.assertLess(rendered.index("OWASP Dependency-Check: success"), rendered.index("Syft: running"))

    def test_maven_index_preserves_order_classification_and_versions(self):
        leaf = {"groupId": "test", "artifactId": "leaf", "version": "1"}
        parent = {"groupId": "test", "artifactId": "parent", "version": "2", "children": [leaf]}
        root = {"groupId": "test", "artifactId": "first", "version": "1", "children": [leaf, parent, parent]}
        other = dict(root, artifactId="second", children=[parent, dict(leaf, version="2")])
        index = kit.index_maven_dependencies([root, other, root])
        issue = {"maven_coordinate": "test:leaf:1", "installed_version": "1"}
        kit.enrich_maven_finding(issue, Path.cwd(), index)
        self.assertEqual(issue["dependency_type"], "Direct and Transitive")
        self.assertEqual(issue["dependency_chains"], [
            "test:first:1 -> test:leaf:1",
            "test:first:1 -> test:parent:2 -> test:leaf:1",
            "test:second:1 -> test:parent:2 -> test:leaf:1",
        ])
        self.assertNotIn("direct_dependency", issue)
        other_version = {"affected_dependency": "test:leaf", "installed_version": "2"}
        kit.enrich_maven_finding(other_version, Path.cwd(), index)
        self.assertEqual(other_version["dependency_type"], "Direct")
        self.assertEqual(other_version["dependency_chains"], ["test:second:1 -> test:leaf:2"])

    def test_application_report_directory_is_safe(self):
        self.assertEqual(kit.report_application_directory("..\\CON"), "app-con")
        self.assertEqual(kit.report_application_directory("Acme / Orders"), "acme-orders")
        self.assertEqual(kit.report_application_directory(".."), "application")

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

            actual_normalizer = kit.NORMALIZE["gitleaks"]
            with patch.dict(os.environ, {"ACCIDION_HOME": str(home)}), \
                 patch.dict(kit.NORMALIZE, {"gitleaks": lambda report, folder: actual_normalizer(report[:-1], folder)}), \
                 patch.object(kit.Installer, "ensure", ensure), \
                 patch.object(kit, "run", side_effect=mock_run), \
                 patch.object(kit, "refresh_windows_path"), \
                 patch.object(kit, "private_run_path", side_effect=self.fake_private), \
                 contextlib.redirect_stdout(io.StringIO()) as terminal:
                self.assertEqual(kit.execute(kit.args_for(["--project-path", str(project)]), "linux", "amd64"), 1)
            summary = json.loads((home / "reports/app/0/security-summary.json").read_text())
            self.assertEqual(summary["scanners"]["gitleaks"]["status"], "failed")
            self.assertEqual(summary["scanners"]["gitleaks"]["nativeFindingCount"], 6)
            self.assertEqual(summary["scanners"]["gitleaks"]["findingCount"], 5)
            self.assertIn("differ from normalized findings", summary["scanners"]["gitleaks"]["reason"])
            self.assertEqual(summary["scanners"]["semgrep"]["status"], "failed")
            self.assertEqual(summary["scanners"]["semgrep"]["findingCount"], 1)
            self.assertIn("simulated network or permission failure", summary["scanners"]["semgrep"]["reason"])
            self.assertTrue((home / "reports/app/0/semgrep-report.json").exists())
            self.assertEqual(summary["scanners"]["grype"]["status"], "success")
            self.assertEqual(summary["scanners"]["checkov"]["status"], "skipped")
            self.assertEqual(summary["installations"]["checkov"]["status"], "skipped")
            self.assertRegex(terminal.getvalue(), r"Semgrep: failed \| \d+\.\d+s \| 1 finding")
            self.assertIn("Security validation: incomplete coverage; findings require review", terminal.getvalue())
            self.assertIn("SQL Injection", terminal.getvalue())

    def test_terminal_groups_aliases_without_merging_distinct_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            cve = "CVE-2025-12345"
            ghsa = "GHSA-abcd-1234-efgh"
            package = "pkg:maven/example/library@1.0"
            pom = project / "pom.xml"
            pom.write_text("""<project>
    <dependencies>
        <dependency>
            <groupId>example</groupId><artifactId>library</artifactId><version>1.0</version>
        </dependency>
    </dependencies>
</project>
""", encoding="utf-8")
            owasp = {"dependencies": [
                {"fileName": path, "packages": [{"id": purl}],
                 "vulnerabilities": [{"name": cve, "severity": "HIGH"}]}
                for path, purl in (("library.jar", package), ("pom.xml", package + "?type=pom"),
                                   ("other.jar", "pkg:maven/other/library@1.0"),
                                   ("new.jar", "pkg:maven/example/library@1.1"))
            ]}
            grype = {"matches": [
                {"vulnerability": {"id": identifier, "severity": severity, "fix": {"versions": [fix]}},
                 "relatedVulnerabilities": related,
                 "artifact": {"name": "library", "version": "1.0", "purl": purl,
                              "locations": [{"path": "/temporary/dependencies/library.jar"}]}}
                for identifier, severity, fix, related, purl in (
                    (ghsa, "Critical", "1.2", [{"id": cve}], package),
                    ("CVE-2025-67890", "Medium", "2.0", [], package),
                    (cve, "Low", "2.0", [], package + "?classifier=tests"),
                )
            ]}
            rows = [*findings.dependency_issues(owasp, project, terminal=True),
                    *findings.grype_issues(grype, project, terminal=True)]
            metadata = [row.pop("_terminal") for row in rows]
            for index, row in enumerate(rows, 1):
                row["issue_number"] = index
            groups, counts = findings.terminal_groups(rows, metadata)
            self.assertEqual(len(groups), 4)
            self.assertEqual(counts, {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 1})
            self.assertEqual(sum(len(evidence) for _, group in groups for evidence, _ in group), 7)
            self.assertEqual(groups[0][1][0][1], {cve, ghsa})
            output = []
            _, unique, grouped = findings.terminal_summary(rows, metadata, project, {}, output.append)
            self.assertEqual((unique, grouped), (4, 6))
            rendered = "\n".join(output)
            self.assertRegex(rendered, r"Source file +pom\.xml")
            self.assertRegex(rendered, r"Line number\(s\) +3-5")
            self.assertRegex(rendered, r"Dependency type +Direct")
            self.assertIn(cve, rendered)
            self.assertNotIn(ghsa, rendered)
            self.assertNotIn("Reported fixed versions", rendered)
            self.assertIn("Confirm the resolved version against each advisory", rendered)
            self.assertNotIn("Related issue", rendered)
            owasp, grype = rendered.split("=== Grype - Package Vulnerability Scanning ===")
            self.assertRegex(owasp, r"(?m)^Issue 1$")
            self.assertRegex(grype, r"(?m)^Issue 1$")
            self.assertRegex(grype, r"Scanner +Grype")
            self.assertEqual(rendered.count("Issue name          Vulnerable package: example:library\n"), 3)
            output.clear()
            findings.terminal_summary(rows, metadata, project, {}, output.append, details=True)
            detail = "\n".join(output)
            self.assertIn(cve, detail)
            self.assertIn(ghsa, detail)
            self.assertIn("Reported fixed versions: 1.2", detail)
            self.assertIn("Reported fixed versions: 2.0", detail)
            self.assertNotIn("/temporary/", rendered)
            self.assertNotIn("Finding #", rendered)

    def test_dependency_paths_include_direct_and_multiple_transitive_parents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            project = root / "app"
            project.mkdir()
            pom = project / "pom.xml"
            pom.write_text("""<project>
    <dependencies>
        <dependency><groupId>example</groupId><artifactId>starter</artifactId></dependency>
    </dependencies>
</project>
""", encoding="utf-8")
            (project / "build.gradle").write_text(
                "dependencies {\n    implementation 'example:gradle-starter:2.1'\n}\n", encoding="utf-8")
            deps = root / "dependencies"
            (deps / "0").mkdir(parents=True)

            def node(artifact, *children):
                return {"groupId": "example", "artifactId": artifact, "version": "1.0", "children": children}

            maven_tree = deps / "0/maven-dependency-tree.json"
            maven_tree.write_text(
                json.dumps(node("app", node("starter", node("intermediate", node("library")))))
                + "\n" + json.dumps(node("app", node("second", node("library")), node("library"))),
                encoding="utf-8",
            )
            (root / "gradle-dependency-paths-1.json").write_text(json.dumps([{
                "component": "example:library", "version": "1.0", "kind": "Transitive",
                "source": "build.gradle", "direct": "example:gradle-starter", "directVersion": "2.1",
            }]), encoding="utf-8")
            paths = kit.dependency_contexts(
                project, [("maven", project, ["mvn"]), ("gradle", project, ["gradle"])],
                deps, self.fail, [pom],
            )
            output = []
            issue = findings.new_issue("dependency-check", affected_dependency="example:library",
                                       installed_version="1.0")
            findings.terminal_summary([issue], [{"package": "pkg:maven/example/library@1.0"}],
                                      project, paths, output.append)
            rendered = "\n".join(output)
            self.assertRegex(rendered, r"Dependency type +Direct / Transitive")
            self.assertRegex(rendered, r"Source file +pom\.xml")
            self.assertRegex(rendered, r"Source file +build\.gradle")
            self.assertRegex(rendered, r"Line number\(s\) +2")
            for parent in ("example:starter:1.0", "example:second:1.0", "example:gradle-starter:2.1"):
                self.assertIn(parent, rendered)
            self.assertNotIn("example:intermediate", rendered)
            self.assertIn("update the version, property, or imported BOM", rendered)
            self.assertIn("update its declaration or version catalog", rendered)
            self.assertRegex(rendered, r"(?m)^  Command +gradle dependencyInsight --dependency library")
            self.assertRegex(rendered, r"(?m)^  Working directory +\. \(project directory\)\n  Command +mvn")
            self.assertRegex(rendered, r"Severity +UNKNOWN")

    def test_remediation_keeps_source_tools_visible_and_consolidates_matching_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            rows = [findings.new_issue("grype", affected_dependency=f"example:library-{index}",
                                      installed_version="1.0", severity="MEDIUM",
                                      issue_description="Detailed advisory jargon")
                    for index in range(12)]
            metadata = [{"package": f"pkg:maven/example/library-{index}@1.0"} for index in range(12)]
            rows.extend([
                findings.new_issue("semgrep", affected_dependency="example:library-0", installed_version="1.0",
                                   severity="ERROR", source_file="App.java", start_line=10, cwe_id=["CWE-89"],
                                   cve_id=["CVE-2025-11111"]),
                findings.new_issue("gitleaks", rule_id="hardcoded-token", source_file="app.properties", start_line=5),
                findings.new_issue("gitleaks", rule_id="hardcoded-token", source_file="app.properties", start_line=9),
                findings.new_issue("checkov", issue_name="Container Running as Root",
                                   rule_id="CKV_DOCKER_3", source_file="Dockerfile", start_line=4),
            ])
            metadata.extend([{}, {}, {}, {}])
            for number, row in enumerate(rows, 1):
                row["issue_number"] = number
            output = []
            findings.terminal_summary(rows, metadata, project, {}, output.append)
            rendered = "\n".join(output)
            self.assertEqual(rendered.count("Issue name          Vulnerable package: example:library-0"), 2)
            self.assertEqual(rendered.count("Hardcoded authentication token"), 2)
            self.assertRegex(rendered, r"Source file +App\.java")
            self.assertRegex(rendered, r"(?m)Line number\(s\) +5$")
            self.assertRegex(rendered, r"(?m)Line number\(s\) +9$")
            self.assertRegex(rendered, r"Source file +Dockerfile")
            self.assertIn("Set USER to that account", rendered)
            self.assertIn("docker exec <container> id -u", rendered)
            self.assertIn("Check revocation if applicable", rendered)
            self.assertRegex(rendered, r"Severity +UNKNOWN")
            self.assertIn("CVE-2025-11111", rendered)
            output.clear()
            findings.terminal_summary(rows, metadata, project, {}, output.append, details=True)
            self.assertIn("Advisory: CVE-2025-11111", "\n".join(output))

    def test_technology_specific_issue_guidance(self):
        rows = [
            findings.new_issue("semgrep", issue_name="SQL injection", source_file="Query.java",
                               start_line=12, rule_id="java-sql-injection", severity="ERROR"),
            findings.new_issue("semgrep", issue_name="Unsafe dynamic SQL", source_file="deploy.sql",
                               start_line=6, rule_id="insecure-dynamic-sql", severity="ERROR"),
            findings.new_issue("checkov", issue_name="Unrestricted egress", source_file="main.tf",
                               start_line=4, end_line=8, rule_id="CKV_AWS_382"),
            findings.new_issue("gitleaks", issue_name="Hardcoded token", source_file="tests/fixture.env",
                               rule_id="hardcoded-token"),
            findings.new_issue("gitleaks", issue_name="Hardcoded token", source_file="deployment.env",
                               rule_id="hardcoded-token"),
        ]
        output = []
        findings.terminal_summary(rows, [{} for _ in rows], Path.cwd(), {}, output.append)
        text = "\n".join(output)
        java, sql = text.split("Unsafe dynamic SQL", 1)
        self.assertIn("JDBC PreparedStatement", java)
        self.assertNotIn("PreparedStatement", sql)
        self.assertIn("sp_executesql", sql)
        self.assertRegex(sql, r"Line number\(s\) +4-8")
        self.assertIn("Replace the unrestricted egress rule", sql)
        self.assertIn("Possible test credential based on the path", java)
        self.assertIn("Potential credential. Validity is unverified.", java)

    def test_issue_numbers_restart_and_equivalent_rows_remain_in_details(self):
        rows, metadata = [], []
        for scanner in ("gitleaks", "semgrep", "dependency-check", "grype", "checkov"):
            for number in (1, 1, 2):
                dependency = scanner in {"dependency-check", "grype"}
                rows.append(findings.new_issue(
                    scanner, issue_number=len(rows) + 1, issue_name="Test rule",
                    source_file="sample.txt", start_line=number, rule_id=f"rule-{number}",
                    affected_dependency=f"example:lib-{number}" if dependency else None,
                    installed_version="1" if dependency else None,
                ))
                metadata.append({"package": f"pkg:maven/example/lib-{number}@1",
                                 "aliases": [f"CVE-2025-1000{number}"]} if dependency else {})
        output = []
        _, unique, grouped = findings.terminal_summary(
            rows, metadata, Path.cwd(), {}, output.append, details=True)
        self.assertEqual((unique, grouped), (8, 10))
        rendered = "\n".join(output)
        for key, title in findings.SCANNER_SECTIONS:
            if key == "syft":
                continue
            label = kit.NAMES[key]
            section = rendered.split(f"=== {label} - {title} ===", 1)[1].split("===", 1)[0]
            self.assertEqual(re.findall(r"(?m)^Issue (\d+)$", section), ["1", "2"])
            self.assertRegex(section, r"Raw findings +3")
            self.assertRegex(section, r"Grouped findings +2")
            self.assertEqual(section.count("Report finding #"), 3)
            self.assertRegex(section, rf"Scanner +{re.escape(label)}")
        self.assertNotIn("Related issue", rendered)

    def test_infrastructure_rules_provide_resource_edits_and_verification(self):
        cases = {
            "CKV2_AWS_6": "aws_s3_bucket_public_access_block",
            "CKV_AWS_53": "block_public_acls = true",
            "CKV_AWS_54": "block_public_policy = true",
            "CKV_AWS_55": "ignore_public_acls = true",
            "CKV_AWS_56": "restrict_public_buckets = true",
            "CKV_AWS_18": "aws_s3_bucket_logging",
            "CKV_AWS_19": "aws_s3_bucket_server_side_encryption_configuration",
            "CKV_AWS_145": "aws:kms",
            "CKV_AWS_21": "aws_s3_bucket_versioning",
            "CKV2_AWS_61": "aws_s3_bucket_lifecycle_configuration",
            "CKV_AWS_300": "abort_incomplete_multipart_upload",
            "CKV_AWS_144": "aws_s3_bucket_replication_configuration",
            "CKV2_AWS_62": "aws_s3_bucket_notification",
            "CKV_AWS_24": "approved CIDRs",
            "CKV_AWS_382": "Replace the unrestricted egress rule",
            "CKV2_AWS_5": "Remove the group from configuration if it is unused",
            "CKV_DOCKER_2": "Add a HEALTHCHECK",
            "CKV_DOCKER_3": "Set USER",
            "CKV_DOCKER_8": "Set USER",
        }
        for rule, edit in cases.items():
            with self.subTest(rule=rule):
                filename = "Dockerfile" if rule.startswith("CKV_DOCKER") else "main.tf"
                issue = findings.new_issue("checkov", rule_id=rule, issue_name=rule, source_file=filename)
                _, problem, risk, steps, verify = findings.source_remediation(issue)
                self.assertTrue(problem)
                self.assertTrue(risk)
                self.assertIn(edit, " ".join(steps))
                commands = findings.verification_commands(Path.cwd(), [(filename, None, None)], None, rule)
                self.assertTrue(any(command.startswith("docker " if filename == "Dockerfile" else "terraform validate")
                                    for _, command in commands))
                self.assertTrue(verify)

    def test_dependency_titles_risks_and_fix_status_use_scanner_evidence(self):
        package = {"name": "library", "version": "1.0", "purl": "pkg:maven/example/library@1.0"}
        long_detail = "Advisory detail " * 24
        report = {"matches": [
            {"artifact": package, "vulnerability": {"id": "CVE-2025-10001",
                "title": "Authentication bypass in library",
                "description": "An attacker can bypass authentication. " + long_detail,
                "fix": {"state": "fixed", "versions": ["1.2"]}}},
            {"artifact": package, "vulnerability": {"id": "CVE-2025-10002",
                "description": "An attacker can bypass authentication. " + long_detail,
                "fix": {"state": "not-fixed"}}},
            {"artifact": package, "vulnerability": {"id": "CVE-2025-10003",
                "description": long_detail}},
        ]}
        rows = list(findings.grype_issues(report, Path.cwd(), terminal=True))
        evidence = [row.pop("_terminal") for row in rows]
        output = []
        findings.terminal_summary(rows, evidence, Path.cwd(), {}, output.append)
        rendered = "\n".join(output)
        self.assertIn("Authentication bypass in library", rendered)
        self.assertEqual(rendered.count("An attacker can bypass authentication."), 1)
        self.assertNotIn(long_detail.strip(), rendered)
        self.assertRegex(rendered, r"Installed version +1\.0")
        self.assertRegex(rendered, r"Reported fixes +1\.2")
        for status in ("1 fix reported", "1 reported unfixed", "1 availability unknown"):
            self.assertIn(status, rendered)
        output.clear()
        findings.terminal_summary(rows, evidence, Path.cwd(), {}, output.append, details=True)
        self.assertIn(long_detail.strip(), "\n".join(output))
        self.assertIn("Reported fix state: not-fixed", "\n".join(output))

    def test_verification_commands_use_manifest_directories(self):
        with tempfile.TemporaryDirectory() as root:
            project = Path(root)
            for filename in ("gradlew", "gradlew.bat"):
                (project / filename).touch()
            locations = [("java/module/pom.xml", 3, 5), ("modules/service/build.gradle.kts", 7, 8)]
            commands = findings.verification_commands(
                project, locations, ("maven", "example:library", "1", ()), None)
            self.assertIn(("java/module", "mvn dependency:tree -Dincludes=example:library"), commands)
            wrapper = "gradlew.bat" if os.name == "nt" else "gradlew"
            self.assertIn(("modules/service", f"../../{wrapper} dependencyInsight --dependency library "
                           "--configuration runtimeClasspath"), commands)
            commands = findings.verification_commands(project, [("infra/main.tf", 4, 8)], None, "CKV2_AWS_5")
            self.assertIn(("infra", "terraform validate"), commands)
            self.assertIn(("infra if standalone, otherwise run from its Terraform calling root", "terraform plan"), commands)

    def test_no_findings_and_optional_skips(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "app"
            project.mkdir()

            def ensure(installer, name, **kwargs):
                installer.records[name] = {"status": "reused", "version": "1.0"}
                return [name]

            def empty_report(cmd, **kwargs):
                self.assertEqual(cmd[0], "gitleaks")
                Path(cmd[cmd.index("--report-path") + 1]).write_text("[]", encoding="utf-8")

            with patch.dict(os.environ, {"ACCIDION_HOME": str(root / "data")}), \
                 patch.object(kit.Installer, "ensure", ensure), \
                 patch.object(kit, "run", side_effect=empty_report), \
                 patch.object(kit, "refresh_windows_path"), \
                 patch.object(kit, "private_run_path", side_effect=self.fake_private), \
                 contextlib.redirect_stdout(io.StringIO()) as terminal:
                self.assertEqual(kit.execute(kit.args_for(["--project-path", str(project)]), "linux", "amd64"), 0)
            rendered = terminal.getvalue()
            self.assertIn("Semgrep: skipped", rendered)
            self.assertIn("Security validation: no findings reported by completed scans", rendered)
            self.assertIn("CRITICAL 0 | HIGH 0 | MEDIUM 0 | LOW 0 | UNKNOWN 0", rendered)
            self.assertNotIn("Diagnostics", rendered)


class BootstrapTests(unittest.TestCase):
    pin = "0123456789abcdef" * 2 + "01234567"
    repo = "example-team/private-kit"
    token = "test_mock_token"

    def setUp(self):
        self.bash = host_bash()
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
            'printf "scanner:%s:%s\\n" "$ACCIDION_KIT_COMMIT" "$ACCIDION_KIT_ARCHIVE_SHA256"\n'
            'exit "${MOCK_SCANNER_STATUS:-0}"\n',
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
            'if [[ " $* " != *" --config "* && ( " $* " == *" -w "* || " $* " == *" --write-out "* ) ]]; then printf "%s" "$MOCK_HTTP_CODE"; exit; fi\n'
            '[[ " $* " != *"$MOCK_TOKEN"* && -z "${GH_TOKEN+x}${GITHUB_TOKEN+x}" ]] || { echo "credential exposed to curl" >&2; exit 10; }\n'
            '[[ " $* " == *" --config - "* ]] || { echo "missing stdin config" >&2; exit 10; }\n'
            'read -r auth\n[[ $auth == "header = \\"Authorization: Bearer $MOCK_TOKEN\\"" ]] || { echo "unexpected bearer" >&2; exit 10; }\n'
            'case " $* " in\n'
            '  *"https://api.github.com/user "*) [[ ${MOCK_USER_DENIED:-0} == 0 ]] || exit 22; printf 200; exit ;;\n'
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
            '  auth) [[ ${MOCK_GH_LOGIN:-0} == 1 ]] || exit 1; printf "%s\\n" "$MOCK_TOKEN" ;;\n'
            '  repo) [[ " $* " == *" $MOCK_REPO "* && $MOCK_HTTP_CODE == 404 ]]; echo true ;;\n'
            '  api) [[ " $* " == *"repos/$MOCK_REPO/contents/bootstrap.sh?ref=$MOCK_PIN " ]]; cat -- "$MOCK_BOOTSTRAP" ;;\n'
            '  release) [[ " $* " == *" kit-$MOCK_PIN "* && " $* " == *" $MOCK_REPO "* &&'
            ' " $* " == *" accidion-kit.tar.gz "* && $GH_TOKEN == "$MOCK_TOKEN" ]]; cat -- "$MOCK_ARCHIVE" ;;\n'
            '  *) exit 12 ;;\nesac\n')
        self.mock_script(mock / "git",
            '#!/usr/bin/env bash\nset -eu\n'
            'if [[ $1 == -C && $3 == credential && $4 == fill ]]; then\n'
            '  [[ ${MOCK_CREDENTIAL_LOGIN:-0} == 1 && $GIT_TERMINAL_PROMPT == 0 && $GCM_INTERACTIVE == Never ]] || exit 1\n'
            '  [[ $GIT_CEILING_DIRECTORIES == "${2%/*}" && ! "$2" -ef "$MOCK_KIT" ]]\n'
            '  read -r protocol; read -r host; read -r path\n'
            '  [[ $protocol == protocol=https && $host == host=github.com && $path == path=*.git ]]\n'
            '  printf "username=fixture\\npassword=%s\\n" "$MOCK_TOKEN"; exit\n'
            'fi\n'
            '[[ $1 == -C && $2 -ef "$MOCK_KIT" ]] || exit 3\n'
            'case "$3" in rev-parse) printf "%s\\n" "$MOCK_KIT" ;;\n'
            '    remote) printf "%s\\n" "$MOCK_ORIGIN" ;; *) exit 4 ;; esac\n')
        self.env = {**os.environ, "GH_TOKEN": self.token, "GITHUB_TOKEN": "", "MOCK_TOKEN": self.token,
                    "MOCK_PIN": self.pin, "MOCK_HTTP_CODE": "404", "MOCK_CURL_VERSION": "8.12.0",
                    "MOCK_OS": "MINGW64_NT", "MOCK_ARCH": "x86_64", "MOCK_BIN": self.posix(mock),
                    "MOCK_ARCHIVE": self.posix(archive), "MOCK_BOOTSTRAP": self.posix(self.bootstrap),
                    "TMPDIR": self.posix(self.root), "MOCK_KIT": self.posix(kit.KIT),
                    "MOCK_ORIGIN": f"git@github.com:{self.repo}.git", "MOCK_REPO": self.repo}
        commands = Path(__file__).resolve().parent / "fixtures" / "bootstrap"
        pins = "FULL_COMMIT_SHA BOOTSTRAP_SHA256 KIT_ARCHIVE_SHA256"
        values = f"{self.pin} {self.bootstrap_sha} {self.archive_sha} --dry-run"

        def load_command(filename, placeholders, arguments):
            return (commands / filename).read_text(encoding="utf-8").replace(placeholders, arguments, 1)

        self.command = load_command("private-archive.sh", f"OWNER/PRIVATE_REPO {pins}", f"{self.repo} {values}")
        self.release_command = load_command("private-release.sh", f"OWNER/PRIVATE_REPO {pins}", f"{self.repo} {values}")
        self.public_command = load_command("public-archive.sh", pins, values)

    @staticmethod
    def posix(path):
        return path.as_posix() if os.name != "nt" else "/" + path.drive[0].lower() + path.as_posix()[2:]

    @staticmethod
    def mock_script(path, body):
        path.write_text(body, newline="\n")
        path.chmod(0o700)

    def shell(self, command, **environment):
        prefix = 'export MOCK_REAL_RM="$(command -v rm)"\nexport PATH="$MOCK_BIN:$PATH"\n'
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
        self.assertIn("Confirm the GitHub repository", result.stderr)

    def test_private_release_download_uses_commit_tag_and_validates_asset(self):
        result = self.shell(self.release_command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"scanner:{self.pin}:{self.archive_sha}", result.stdout)
        result = self.shell(self.release_command.replace(self.archive_sha, "0" * 64))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Archive SHA-256 mismatch", result.stderr)

    def test_public_bootstrap_authenticates_downloads_and_rejects_tampering(self):
        result = self.shell(self.public_command, MOCK_HTTP_CODE="200")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"scanner:{self.pin}:{self.archive_sha}", result.stdout)
        for value, reason in ((self.bootstrap_sha, "Bootstrap SHA-256 mismatch"),
                              (self.archive_sha, "Archive SHA-256 mismatch")):
            with self.subTest(reason=reason):
                result = self.shell(self.public_command.replace(value, "0" * 64), MOCK_HTTP_CODE="200")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(reason, result.stderr)
                self.assertNotIn("scanner:", result.stdout)

    def test_public_bootstrap_uses_cached_credentials_and_fails_closed(self):
        result = self.shell(self.public_command, GH_TOKEN="", MOCK_CREDENTIAL_LOGIN="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"scanner:{self.pin}:{self.archive_sha}", result.stdout)
        result = self.shell(self.public_command, GH_TOKEN="")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("cached Git credential-manager entry", result.stderr)
        self.assertNotIn("scanner:", result.stdout)
        result = self.shell(self.public_command, MOCK_USER_DENIED="1")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("GitHub rejected the user credential", result.stderr)
        self.assertNotIn("scanner:", result.stdout)

    def test_public_cleanup_retries_and_preserves_scanner_exit_status(self):
        self.mock_script(self.root / "bin/sleep", "#!/usr/bin/env bash\nexit 0\n")
        self.mock_script(self.root / "bin/rm",
            '#!/usr/bin/env bash\nset -eu\n'
            'target=${@: -1}\n'
            'case "$target" in */accidion-kit.*|*/accidion-public.*)\n'
            '  marker="$MOCK_STATE/${target##*/}"; count=0\n'
            '  if [[ -f $marker ]]; then read -r count < "$marker"; fi\n'
            '  count=$((count+1)); printf "%s\\n" "$count" > "$marker"\n'
            '  if [[ $MOCK_CLEANUP == blocked || $count -le 2 ]]; then exit 1; fi ;;\n'
            'esac\nexec "$MOCK_REAL_RM" "$@"\n')
        for mode, scanner_status, attempts in (("transient", 0, "3"), ("blocked", 0, "5"),
                                                ("blocked", 1, "5"), ("transient", 7, "3")):
            with self.subTest(mode=mode, scanner_status=scanner_status):
                state = self.root / f"{mode}-{scanner_status}"
                state.mkdir()
                result = self.shell(self.public_command, MOCK_STATE=self.posix(state),
                                    MOCK_CLEANUP=mode, MOCK_SCANNER_STATUS=str(scanner_status))
                self.assertEqual(result.returncode, scanner_status, result.stderr)
                self.assertIn("scanner:", result.stdout)
                self.assertEqual(sorted(path.name.split(".")[0] for path in state.iterdir()),
                                 ["accidion-kit", "accidion-public"])
                self.assertTrue(all(path.read_text().strip() == attempts for path in state.iterdir()))
                self.assertEqual(result.stderr.count("Warning: could not remove temporary Accidion files"),
                                 2 if mode == "blocked" else 0)


if __name__ == "__main__":
    unittest.main()
