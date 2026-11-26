"""Offline checks for the generated, single-file distribution."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

import starter_kit as kit
from starter_install import Installer, recover_dependency_check_lock, run
from test_starter_kit import host_bash

ROOT = Path(__file__).resolve().parents[1]


class StandaloneTests(unittest.TestCase):
    def test_reproducible_distribution(self):
        subprocess.run([sys.executable, ROOT / "scripts/build_standalone.py", "--check"], check=True)
        self.assertNotIn(b"\r", (ROOT / "dist/security-scan.sh").read_bytes())

    def test_copy_only_with_properties_and_cli_overrides(self):
        bash = host_bash()
        if not bash:
            self.skipTest("Bash unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "app with spaces"
            output = root / "output with spaces"
            private_temp = root / "private temp"
            app.mkdir()
            private_temp.mkdir()
            launcher = app / "security-scan.sh"
            shutil.copyfile(ROOT / "dist/security-scan.sh", launcher)
            env = {**os.environ, "ACCIDION_HOME": str(root / "home"), "TMPDIR": str(private_temp)}
            if os.name == "nt":
                env["TMPDIR"] = private_temp.as_posix()

            def invoke(*args):
                return subprocess.run([bash, launcher.name, *args], cwd=app, env=env,
                                      capture_output=True, text=True, timeout=60)

            self.assertIn("--setup-only", invoke("--help").stdout)
            empty = invoke("--dry-run", "--no-install")
            self.assertEqual(empty.returncode, 0, empty.stderr)
            self.assertEqual(json.loads(empty.stdout)["scanners"]["syft"],
                             "No supported package manifests or Java inputs")
            for name in ("package-lock.json", "requirements.txt", "go.mod", "Sample.csproj", "tsconfig.json"):
                (app / name).touch()
            properties = app / "security-scan.properties"
            properties.write_text("SCANNERS=checkov\nDOCKER_IMAGE=unused\n", encoding="utf-8")
            run = invoke("--dry-run", "--no-install", "--report-dir", str(output),
                         "--project-path", str(app), "--scanner=syft,grype", "--image=example:latest",
                         "--details", "--verbose")
            self.assertEqual(run.returncode, 0, run.stderr)
            plan = json.loads(run.stdout)
            for ecosystem in ("javascript", "typescript", "dotnet", "go", "python"):
                self.assertEqual(plan["discovery"][ecosystem], 1)
            self.assertEqual(plan["selectedScanners"], ["grype", "syft"])
            self.assertFalse(plan["installMissing"])
            self.assertFalse(output.exists())
            self.assertEqual(list(private_temp.iterdir()), [])
            self.assertEqual(invoke("--dry-run", "--setup-only").returncode, 2)

    def test_properties_lifecycle_and_policy(self):
        bash = host_bash()
        if not bash:
            self.skipTest("Bash unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "app with spaces"
            temp = root / "temporary files"
            app.mkdir()
            temp.mkdir()
            launcher = app / "security-scan.sh"
            shutil.copyfile(ROOT / "dist/security-scan.sh", launcher)
            source = app / "hello.txt"
            source.write_bytes(b"Existing application content")
            properties = app / "security-scan.properties"
            cache = root / "cache"
            env = {**os.environ, "ACCIDION_HOME": str(cache), "TMPDIR": temp.as_posix(), "ACCIDION_SCAN_TIMEOUT": "30"}
            env.pop("ACCIDION_REQUIRED_SCANNERS", None)

            def invoke(*args, **overrides):
                return subprocess.run([bash, launcher.as_posix(), *args], cwd=app,
                                      env={**env, **overrides}, capture_output=True, text=True, timeout=90)

            self.assertEqual(invoke("--help", "--config=missing").returncode, 0)
            preview = invoke("--dry-run", TMPDIR=app.as_posix())
            self.assertEqual(preview.returncode, 0, preview.stderr)
            self.assertFalse(properties.exists())
            self.assertFalse(cache.exists())

            first = invoke("--no-install", "--scanner=dependency-check")
            self.assertEqual(first.returncode, 0, first.stderr + first.stdout)
            self.assertEqual(properties.read_bytes(),
                             b"# Security scan configuration\nPROJECT_ROOT=.\nOUTPUT_DIR=\n"
                             b"SCANNERS=all\nDOCKER_IMAGE=\nBUILD_IMAGE=false\n")
            self.assertTrue(list((cache / "reports").rglob("security-summary.json")))
            self.assertEqual(list(temp.iterdir()), [])

            revised = b"# keep this comment\r\nPROJECT_ROOT=.\r\nSCANNERS=dependency-check\r\nOUTPUT_DIR=../custom output\r\n"
            properties.write_bytes(revised)
            before = properties.stat().st_mtime_ns
            second = invoke("--no-install")
            self.assertEqual(second.returncode, 0, second.stderr + second.stdout)
            self.assertEqual(properties.read_bytes(), revised)
            self.assertEqual(properties.stat().st_mtime_ns, before)
            self.assertTrue(list((root / "custom output").rglob("security-summary.json")))
            self.assertEqual(source.read_bytes(), b"Existing application content")
            self.assertEqual(list(temp.iterdir()), [])

            config = root / "explicit config.properties"
            config.write_text("PROJECT_ROOT=app with spaces\nOUTPUT_DIR=custom output\nSCANNERS=checkov\n",
                              encoding="utf-8")
            plan = invoke("--dry-run", "--config", str(config), "--scanner", "gitleaks",
                          "--report-dir", str(root / "other output"))
            self.assertEqual(plan.returncode, 0, plan.stderr)
            data = json.loads(plan.stdout)
            self.assertEqual(Path(data["project"]), app)
            self.assertEqual(data["selectedScanners"], ["gitleaks"])
            self.assertFalse((root / "other output").exists())
            self.assertEqual(invoke("--dry-run", "--config=missing").returncode, 2)

            policy = {"ACCIDION_REQUIRED_SCANNERS": "gitleaks"}
            denied = invoke("--no-install", **policy)
            self.assertEqual(denied.returncode, 2)
            self.assertIn("required", denied.stderr)
            bypass = invoke("--dry-run", "--scanner=all", **policy)
            self.assertEqual(bypass.returncode, 2)
            self.assertEqual(invoke("--help", **policy).returncode, 2)
            unmet = invoke("--no-install", ACCIDION_REQUIRED_SCANNERS="dependency-check")
            self.assertEqual(unmet.returncode, 1)
            self.assertIn("Required scanners did not complete", unmet.stdout)

            config.write_text("SCANNERS=checkov\nSCANNERS=gitleaks\n", encoding="utf-8")
            self.assertIn("Duplicate property", invoke("--config", str(config)).stderr)
            config.write_text("PASSWORD=fixture-only\n", encoding="utf-8")
            invalid = invoke("--config", str(config))
            self.assertEqual(invalid.returncode, 2)
            self.assertNotIn("fixture-only", invalid.stderr)

    @unittest.skipIf(os.name == "nt", "Native Git Bash supplies Windows prerequisites")
    def test_bootstrap_missing_python_and_offline(self):
        bash = host_bash()
        if not bash:
            self.skipTest("Bash unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "app"
            app.mkdir()
            launcher = app / "security-scan.sh"
            shutil.copyfile(ROOT / "dist/security-scan.sh", launcher)
            binaries = root / "minimal path"
            binaries.mkdir()
            for name in ("uname", "dirname", "cat", "mktemp", "rm"):
                (binaries / name).symlink_to(shutil.which(name))
            curl = binaries / "curl"
            curl.write_text("#!/bin/sh\necho 'simulated network failure' >&2\nexit 7\n")
            curl.chmod(0o700)
            env = {**os.environ, "PATH": str(binaries), "ACCIDION_HOME": str(root / "home"), "TMPDIR": str(root)}
            env["UV_PYTHON_INSTALL_DIR"] = str(root / "managed python")
            env.pop("BASH_ENV", None)
            for options, expected in (
                (["--no-install"], "installation disabled"),
                ([], "Automatic Python installation failed"),
            ):
                result = subprocess.run([bash, launcher.name, *options], cwd=app, env=env,
                                        capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)
                if not options:
                    self.assertIn("simulated network failure", result.stderr)
                self.assertEqual(list(root.glob("accidion-kit.*")), [])

    def test_grype_catalogs_directory_when_syft_is_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "app"
            project.mkdir()
            (project / "requirements.txt").write_text("requests==2.32.5\n", encoding="utf-8")
            args = kit.args_for(["--project-path", str(project), "--scanner", "grype", "--no-install"])
            targets = []
            scratch_paths = []

            def ensure(installer, name, **kwargs):
                if name == "syft":
                    installer.records[name] = {"status": "unavailable", "reason": "Test fixture"}
                    return None
                installer.records[name] = {"status": "reused", "version": "1.2.3"}
                return [name]

            native_run = kit.run

            def run(command, **kwargs):
                if command[0] != "grype":
                    return native_run(command, **kwargs)
                targets.append(command[1])
                env = kwargs["env"]
                scratch = Path(env["SQLITE_TMPDIR"])
                self.assertEqual(scratch.parent, Path(env["GRYPE_DB_CACHE_DIR"]))
                self.assertTrue(scratch.is_dir())
                for name in ("TMPDIR", "TEMP", "TMP"):
                    self.assertEqual(Path(env[name]), scratch)
                scratch_paths.append(scratch)
                report = Path(command[command.index("--file") + 1])
                kit.write_json(report, {"matches": []})

            with patch.dict(os.environ, {"ACCIDION_HOME": str(root / "cache"),
                                        "ACCIDION_REQUIRED_SCANNERS": "",
                                        "GRYPE_DB_CACHE_DIR": str(root / "cache" / "grype-db")}):
                with patch.object(Installer, "ensure", ensure), patch.object(kit, "run", run):
                    result = kit.execute(args, *kit.detect())
            self.assertEqual(result, 1)
            report = next((root / "cache").rglob("security-summary.json"))
            statuses = json.loads(report.read_text(encoding="utf-8"))["scanners"]
            self.assertEqual(statuses["syft"]["status"], "unavailable")
            self.assertEqual(statuses["grype"]["status"], "success")
            self.assertEqual(targets, [f"dir:{project}"])
            self.assertTrue(all(not path.exists() for path in scratch_paths))

    @unittest.skipUnless(os.name == "nt", "Uses Windows file sharing")
    def test_dependency_check_recovers_only_orphaned_update_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory)
            lock = database / "odc.update.lock"
            data = database / "odc.mv.db"
            data.write_bytes(b"database fixture")
            self.assertFalse(recover_dependency_check_lock(database))
            for marker in (b"", b"unknown format"):
                lock.write_bytes(marker)
                self.assertFalse(recover_dependency_check_lock(database))
                self.assertEqual(lock.read_bytes(), marker)
            marker = b"0123456789abcdef" * 2
            lock.write_bytes(marker)
            with lock.open("rb"):
                self.assertFalse(recover_dependency_check_lock(database))
                self.assertEqual(lock.read_bytes(), marker)
            self.assertTrue(recover_dependency_check_lock(database))
            self.assertFalse(lock.exists())
            self.assertEqual(data.read_bytes(), b"database fixture")

    def test_timeout_stops_scanner_children(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "child-survived"
            child = "import pathlib, sys, time; time.sleep(2); pathlib.Path(sys.argv[1]).touch()"
            parent = ("import subprocess, sys; "
                      "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]).wait()")
            with self.assertRaisesRegex(RuntimeError, "timeout"):
                run([sys.executable, "-c", parent, child, marker], timeout=1, capture=True)
            # The captured stream remains open while a surviving child runs.
            self.assertFalse(marker.exists())

    def test_scanner_download_network_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            installer = Installer("linux", "amd64", Path(directory), True, None)
            with patch("starter_install.shutil.which", return_value=None), patch(
                "starter_install.fetch", side_effect=URLError("network denied")
            ):
                self.assertIsNone(installer.ensure("gitleaks"))
            self.assertEqual(installer.records["gitleaks"]["status"], "installation_failed")
            self.assertFalse(list(Path(directory).rglob(".complete")))
