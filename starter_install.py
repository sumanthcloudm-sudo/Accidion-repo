"""Platform adapters and verified, user-local tool provisioning."""
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

RELEASES = {
    "gitleaks": ("gitleaks/gitleaks", "8.30.1"),
    "syft": ("anchore/syft", "1.57.1"),
    "grype": ("anchore/grype", "0.121.3"),
    "dependency-check": ("dependency-check/DependencyCheck", "12.2.2"),
}
PYPI = {"semgrep": "1.186.0", "checkov": "3.2.495"}
MINIMUM = {
    "git": (2, 30), "java": (11,), "mvn": (3, 6), "gradle": (7,),
    "docker": (20, 10), "gitleaks": (8, 19), "syft": (1, 57),
    "grype": (0, 121), "semgrep": (1, 150), "checkov": (3, 2),
    "dependency-check": (12, 1),
}


def detect(system=None, machine=None):
    os_name = {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}.get(
        system or platform.system()
    )
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(
        (machine or platform.machine()).lower()
    )
    if not os_name or not arch:
        raise ValueError("Unsupported operating system or processor architecture")
    return os_name, arch


def release_asset(name, version, system, arch):
    if name == "dependency-check":
        return f"dependency-check-{version}-release.zip"
    os_name = "darwin" if system == "macos" else system
    extension = "zip" if system == "windows" else "tar.gz"
    if name == "gitleaks":
        arch = {"amd64": "x64", "arm64": "arm64"}[arch]
        return f"{name}_{version}_{os_name}_{arch}.{extension}"
    return f"{name}_{version}_{os_name}_{arch}.{extension}"


def run(args, *, cwd=None, capture=False, log=None, timeout=3600, accepted=(0,), env=None):
    args = [str(arg) for arg in args]
    if os.name == "nt":
        args[0] = shutil.which(args[0]) or args[0]
        if Path(args[0]).suffix.lower() in {".bat", ".cmd"}:
            if any(re.search(r'[%!\"&|<>^\r\n]', arg) for arg in args):
                raise RuntimeError("A Windows batch argument contains an unsafe shell character")
            quoted = " ".join(f'"{arg}"' for arg in args)
            args = f'"{os.environ["COMSPEC"]}" /d /v:off /s /c "{quoted}"'
    result = subprocess.run(
        args, cwd=cwd, env=env, stdin=subprocess.DEVNULL, text=True,
        stdout=subprocess.PIPE if capture else log, stderr=subprocess.STDOUT,
        timeout=timeout, encoding="utf-8", errors="replace",
    )
    if result.returncode not in accepted:
        if capture and log is not None and result.stdout:
            log.write(result.stdout + "\n")
            log.flush()
        raise RuntimeError(f"Command exited with status {result.returncode}")
    return result.stdout or ""


def fetch(url, output=None, algorithm="sha256"):
    headers = {"User-Agent": "accidion-starter-kit"}
    # Use the CI token only for GitHub release metadata, never package downloads.
    if url.startswith("https://api.github.com/repos/") and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        if output is None:
            return response.read(4 * 1024 * 1024 + 1)
        digest = hashlib.new(algorithm)
        with output.open("wb") as target:
            for chunk in iter(lambda: response.read(1024 * 1024), b""):
                digest.update(chunk)
                target.write(chunk)
        return digest.hexdigest()


def unpack(archive, destination):
    # Copy regular files only. Release archives cannot install links or escape the cache.
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as source:
            for item in source.infolist():
                if not item.is_dir():
                    with source.open(item) as stream:
                        copy_member(destination, item.filename, stream)
    else:
        with tarfile.open(archive, "r:*") as source:
            for item in source:
                if item.isfile():
                    with source.extractfile(item) as stream:
                        copy_member(destination, item.name, stream)


def copy_member(destination, name, source):
    target = (destination / name).resolve()
    if not target.is_relative_to(destination.resolve()):
        raise ValueError("Archive member escapes the install directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as output:
        shutil.copyfileobj(source, output)
    if target.suffix in {"", ".sh"} and os.name != "nt":
        target.chmod(0o700)


def linux_family():
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        return None
    identity = release.get("ID", "").lower()
    relatives = set(release.get("ID_LIKE", "").lower().split())
    if identity in {"ubuntu", "debian"} or relatives & {"ubuntu", "debian"}:
        return "debian"
    if identity == "fedora":
        return "fedora"
    if {identity, *relatives} & {"rhel", "centos", "rocky", "almalinux", "ol", "fedora"}:
        return "rhel"
    return None


def package_command(system, name, lookup=shutil.which, *, family=None):
    if system == "windows" and lookup("winget"):
        ids = {"git": "Git.Git", "java": "EclipseAdoptium.Temurin.21.JDK", "docker": "Docker.DockerDesktop"}
        return ["winget", "install", "--exact", "--id", ids[name], "--source", "winget", "--disable-interactivity"]
    if system == "macos" and lookup("brew"):
        packages = {"git": ["git"], "java": ["--cask", "temurin@21"], "docker": ["--cask", "docker"]}
        return ["brew", "install", *packages[name]]
    if system == "linux":
        if os.geteuid() != 0:
            raise PermissionError(f"{name} needs installation through an approved Linux package manager; sudo is not invoked")
        family = family or linux_family()
        python = f"python{sys.version_info.major}.{sys.version_info.minor}"
        if family in {None, "debian"} and lookup("apt-get"):
            packages = {"git": "git", "java": "default-jdk", "docker": "docker.io", "pip": f"{python}-venv"}
            return ["apt-get", "install", "-y", packages[name]]
        rpm_manager = next((command for command in ("dnf", "yum") if lookup(command)), None)
        if family in {None, "fedora", "rhel"} and rpm_manager:
            packages = {"git": "git", "java": "java-21-openjdk-devel",
                        "docker": "docker-ce" if family == "rhel" else "moby-engine",
                        "pip": f"{python}-pip" if family == "rhel" else "python3-pip"}
            return [rpm_manager, "install", "-y", packages[name]]
    raise RuntimeError(f"No approved package manager is available for {name}")


def refresh_windows_path():
    if os.name != "nt":
        return
    import winreg

    paths = [os.environ.get("PATH", "")]
    for hive, key in ((winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
                      (winreg.HKEY_CURRENT_USER, "Environment")):
        try:
            with winreg.OpenKey(hive, key) as registry:
                paths.append(os.path.expandvars(winreg.QueryValueEx(registry, "Path")[0]))
        except OSError:
            continue
    roots = dict.fromkeys(os.environ[key] for key in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)")
                          if os.environ.get(key))
    for root in map(Path, roots):
        jdks = sorted((root / "Eclipse Adoptium").glob("jdk-21*/bin"), reverse=True)
        paths.extend(str(path) for path in [*jdks, root / "Git/cmd", root / "Docker/Docker/resources/bin"]
                     if path.is_dir())
    unique = {}
    for path in os.pathsep.join(paths).split(os.pathsep):
        if path:
            unique.setdefault(os.path.normcase(os.path.normpath(path)), path)
    os.environ["PATH"] = os.pathsep.join(unique.values())


class Installer:
    def __init__(self, system, arch, cache, allow, log):
        self.system, self.arch, self.cache, self.allow, self.log = system, arch, cache, allow, log
        self.records = {}

    def version(self, name, cmd, cwd=None):
        flag = {"gitleaks": "version", "syft": "version", "grype": "version"}.get(name, "--version")
        if name == "java":
            flag = "-version"
            java = Path(shutil.which(str(cmd[0])) or cmd[0]).resolve()
            javac = java.with_name("javac.exe" if os.name == "nt" else "javac")
            if not javac.exists():
                raise RuntimeError("A JDK with javac is required")
            run([javac, "-version"], capture=True, timeout=30)
        output = run([*cmd, flag], cwd=cwd, capture=True, log=self.log, timeout=180)
        match = re.search(r"\b(\d+\.\d+(?:\.\d+)?)\b", output)
        if not match or tuple(map(int, match[1].split("."))) < MINIMUM[name]:
            raise RuntimeError("Version is missing or below the supported minimum")
        if name == "java":
            java_home = java.parent.parent
            if self.system == "macos" and java == Path("/usr/bin/java"):
                java_home = Path(run(["/usr/libexec/java_home"], capture=True, timeout=30).strip())
                if not (java_home / "bin/javac").is_file():
                    raise RuntimeError("macOS Java shim did not resolve to a JDK")
            os.environ["JAVA_HOME"] = str(java_home)
            os.environ["PATH"] = f"{java.parent}{os.pathsep}{os.environ['PATH']}"
        return match[1]

    def ensure(self, name, wrapper=None, cwd=None):
        import time
        from datetime import datetime, timezone
        ensure_started = time.perf_counter()
        ensure_started_at = datetime.now(timezone.utc).isoformat()
        status = "unavailable"
        try:
            existing = shutil.which(name)
            java_home = os.environ.get("JAVA_HOME") if name == "java" else None
            java = Path(java_home) / ("bin/java.exe" if os.name == "nt" else "bin/java") if java_home else None
            candidates = ([wrapper] if wrapper else
                          [[java] if java and java.is_file() else None, [existing] if existing else None, self.managed(name)])
            for cmd in filter(None, candidates):
                try:
                    version = self.version(name, cmd, cwd)
                except (OSError, RuntimeError, subprocess.SubprocessError):
                    if wrapper:
                        raise
                    continue
                self.records[name] = {"status": "reused", "version": version}
                return cmd
            if not self.allow:
                raise RuntimeError("Missing or incompatible; installation disabled")
            status = "installation_failed"
            cmd = self.install(name)
            self.records[name] = {"status": "installed", "version": self.version(name, cmd, cwd)}
            return cmd
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            self.records[name] = {"status": status, "reason": str(error)}
            return None
        finally:
            if name in self.records:
                self.records[name]["startedAt"] = ensure_started_at
                self.records[name]["completedAt"] = datetime.now(timezone.utc).isoformat()
                self.records[name]["durationSeconds"] = round(time.perf_counter() - ensure_started, 2)

    def pypi_version(self, name):
        # 1.182 is the final upstream native Intel macOS release.
        if name == "semgrep" and self.system == "macos" and self.arch == "amd64":
            return "1.182.0"
        return PYPI[name]

    def managed(self, name):
        suffix = ".exe" if self.system == "windows" else ""
        if name in PYPI:
            base = self.cache / f"{name}-{self.pypi_version(name)}-{sys.version_info.major}.{sys.version_info.minor}"
            path = base / ("Scripts" if suffix else "bin") / (name + suffix)
            if name == "checkov" and suffix and not path.is_file():
                interpreter = base / "Scripts/python.exe"
                if interpreter.is_file():
                    return [str(interpreter), "-c", "from checkov.main import run; raise SystemExit(run())"]
        elif name in RELEASES or name in {"mvn", "gradle"}:
            base = self.cache / f"{name}-{self.release_version(name)}-{self.system}-{self.arch}"
            if not (base / ".complete").exists():
                return None
            if name in {"mvn", "gradle", "dependency-check"}:
                ext = (".bat" if name != "mvn" else ".cmd") if suffix else (".sh" if name == "dependency-check" else "")
                path = next(base.glob(f"*/bin/{name}{ext}"), base / "missing")
            else:
                path = base / (name + suffix)
        else:
            return None
        return [str(path)] if path.is_file() else None

    @staticmethod
    def release_version(name):
        return {"mvn": "3.9.11", "gradle": "8.14.3"}.get(name) or RELEASES[name][1]

    def install(self, name):
        if name in PYPI:
            self.cache.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.install_pypi(name)
        elif name in RELEASES or name in {"mvn", "gradle"}:
            self.cache.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.install_archive(name)
        else:
            run(package_command(self.system, name), log=self.log, timeout=1800)
            refresh_windows_path()
            if self.system == "macos" and name == "java":
                home = run(["/usr/libexec/java_home", "-v", "21"], capture=True, timeout=30).strip()
                return [str(Path(home) / "bin/java")]
            path = shutil.which(name)
            if path:
                return [path]
            raise RuntimeError("Installation completed but executable is unavailable; restart the terminal")
        cmd = self.managed(name)
        if not cmd:
            raise RuntimeError("Installed package did not contain the expected executable")
        return cmd

    def install_pypi(self, name):
        base = self.cache / f"{name}-{self.pypi_version(name)}-{sys.version_info.major}.{sys.version_info.minor}"
        created = not base.exists()
        if base.is_symlink():
            raise RuntimeError("Refusing to modify a symlinked scanner cache")
        try:
            run([sys.executable, "-m", "venv", "--clear", base], log=self.log)
        except RuntimeError:
            if self.system != "linux":
                raise
            run(package_command(self.system, "pip"), log=self.log)
            run([sys.executable, "-m", "venv", "--clear", base], log=self.log)
        python = base / ("Scripts/python.exe" if self.system == "windows" else "bin/python")
        pip = run([python, "-m", "pip", "--version"], capture=True, timeout=60)
        self.records[f"pip:{name}"] = {"status": "installed" if created else "reused", "version": pip.split()[1]}
        try:
            run([python, "-m", "pip", "--disable-pip-version-check", "install", "--only-binary=:all:",
                 "--retries", "2", f"{name}=={self.pypi_version(name)}"], log=self.log)
        except RuntimeError as error:
            raise RuntimeError(f"Could not install {name} {self.pypi_version(name)} wheels for {self.system}/{self.arch} "
                               f"with Python {sys.version_info.major}.{sys.version_info.minor}. "
                               "Check wheel availability and the approved package index in run.log.") from error

    def install_archive(self, name):
        version = self.release_version(name)
        if name in RELEASES:
            repo, _ = RELEASES[name]
            asset_name = release_asset(name, version, self.system, self.arch)
            release = json.loads(fetch(f"https://api.github.com/repos/{repo}/releases/tags/v{version}"))
            asset = next((item for item in release["assets"] if item["name"] == asset_name), None)
            if not asset:
                raise RuntimeError(f"No upstream {name} {version} package for {self.system}/{self.arch} "
                                   f"({asset_name}); install a compatible approved binary if available")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest") or ""):
                raise RuntimeError(f"No SHA-256 published for {asset_name}")
            url = f"https://github.com/{repo}/releases/download/v{version}/{asset_name}"
            algorithm, expected = asset["digest"].split(":")
        else:
            if name == "mvn":
                url = f"https://archive.apache.org/dist/maven/maven-3/{version}/binaries/apache-maven-{version}-bin.zip"
                algorithm = "sha512"
            else:
                url = f"https://services.gradle.org/distributions/gradle-{version}-bin.zip"
                algorithm = "sha256"
            expected = fetch(f"{url}.{algorithm}").decode("ascii").split()[0]
        destination = self.cache / f"{name}-{version}-{self.system}-{self.arch}"
        with tempfile.TemporaryDirectory(dir=self.cache) as temporary:
            archive = Path(temporary) / "download"
            if fetch(url, archive, algorithm).lower() != expected.lower():
                raise RuntimeError(f"Download checksum mismatch for {name}")
            extracted = Path(temporary) / "extracted"
            extracted.mkdir()
            unpack(archive, extracted)
            (extracted / ".complete").touch()
            # Recover interrupted archive installations only after verification.
            if destination.is_symlink():
                raise RuntimeError("Refusing to modify a symlinked scanner cache")
            if destination.is_dir() and not (destination / ".complete").is_file():
                shutil.rmtree(destination)
            try:
                extracted.rename(destination)
            except OSError:
                if not (destination / ".complete").exists():
                    raise
