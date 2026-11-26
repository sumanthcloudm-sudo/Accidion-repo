"""Platform adapters and verified, user-local tool provisioning."""
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
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
LINUX_JDK = "21.0.11+10"
BOOTSTRAP_PIP = "25.3"
MINIMUM = {
    "git": (2, 30), "java": (11,), "mvn": (3, 6), "gradle": (7,),
    "docker": (20, 10), "gitleaks": (8, 19), "syft": (1, 55),
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


class CommandTimeout(RuntimeError):
    pass


def run(args, *, cwd=None, capture=False, log=None, timeout=3600, accepted=(0,), env=None):
    args = [str(arg) for arg in args]
    if os.name == "nt":
        args[0] = shutil.which(args[0]) or args[0]
        if Path(args[0]).suffix.lower() in {".bat", ".cmd"}:
            if any(re.search(r'[%!\"&|<>^\r\n]', arg) for arg in args):
                raise RuntimeError("A Windows batch argument contains an unsafe shell character")
            quoted = " ".join(f'"{arg}"' for arg in args)
            args = f'"{os.environ["COMSPEC"]}" /d /v:off /s /c "{quoted}"'
    with subprocess.Popen(
        args, cwd=cwd, env=env, stdin=subprocess.DEVNULL, text=True,
        stdout=subprocess.PIPE if capture else log, stderr=subprocess.STDOUT,
        encoding="utf-8", errors="replace", start_new_session=os.name != "nt",
    ) as process:
        job = windows_process_job(process) if os.name == "nt" else None
        try:
            output, _ = process.communicate(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
            stop_process_tree(process, job)
            process.communicate()
            if isinstance(error, KeyboardInterrupt):
                raise
            raise CommandTimeout(f"Command exceeded the {timeout}-second timeout") from error
        finally:
            if job:
                kernel, handle = job
                kernel.CloseHandle(handle)
        if process.returncode not in accepted:
            if capture and log is not None:
                print(output, file=log, flush=True)
            raise RuntimeError(f"Command exited with status {process.returncode}")
    return output or ""


def windows_process_job(process):
    # Group Windows batch launchers with their child scanner processes.
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateJobObjectW(None, None)
    if handle:
        if kernel.AssignProcessToJobObject(handle, process._handle):
            return kernel, handle
        kernel.CloseHandle(handle)
    return None


def stop_process_tree(process, job):
    if job:
        kernel, handle = job
        if kernel.TerminateJobObject(handle, 1):
            return
    if os.name == "nt":
        system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        try:
            subprocess.run(
                [system / "taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False, timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            pass
        if process.poll() is None:
            process.kill()
    else:
        try:
            # Give scanner shutdown hooks a chance to release database locks.
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=3)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def recover_dependency_check_lock(database, *, wait_for_release=False):
    if os.name != "nt":
        return False

    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                               ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                  ctypes.c_void_p, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    read_and_delete = 0x80000000 | 0x00010000
    open_existing, open_reparse_point = 3, 0x00200000
    path = str(database / "odc.update.lock")
    # Dependency-Check holds a file handle for the lifetime of its update lock.
    # Open with no sharing and delete by handle to avoid a check/unlink race.
    invalid_handle = ctypes.c_void_p(-1).value
    sharing_violation = 32
    deadline = time.monotonic() + (2 if wait_for_release else 0)
    while True:
        handle = kernel.CreateFileW(path, read_and_delete, 0, None, open_existing, open_reparse_point, None)
        if handle != invalid_handle:
            break
        if ctypes.get_last_error() != sharing_violation or time.monotonic() >= deadline:
            return False
        # Windows may still be releasing the Java process's handles after termination.
        time.sleep(0.05)
    try:
        marker = ctypes.create_string_buffer(33)
        count = wintypes.DWORD()
        if not kernel.ReadFile(handle, marker, len(marker), ctypes.byref(count), None):
            return False
        # Dependency-Check writes the marker only after taking the native lock.
        # An empty file may belong to a process that is still acquiring it.
        if not re.fullmatch(rb"[0-9a-fA-F]{32}", marker.raw[:count.value]):
            return False
        disposition = ctypes.c_ubyte(1)
        file_disposition_info = 4
        return bool(kernel.SetFileInformationByHandle(
            handle, file_disposition_info, ctypes.byref(disposition), ctypes.sizeof(disposition)
        ))
    finally:
        kernel.CloseHandle(handle)


def fetch(url, output=None, algorithm="sha256"):
    if not url.startswith("https://"):
        raise ValueError("Tool downloads require HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "accidion-starter-kit"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                if not response.geturl().startswith("https://"):
                    raise ValueError("Tool download redirected to a non-HTTPS URL")
                if output is None:
                    content = response.read(4 * 1024 * 1024 + 1)
                    if len(content) > 4 * 1024 * 1024:
                        raise ValueError("Release metadata exceeds the download limit")
                    return content
                digest = hashlib.new(algorithm)
                with output.open("wb") as target:
                    for chunk in iter(lambda: response.read(1024 * 1024), b""):
                        digest.update(chunk)
                        target.write(chunk)
                return digest.hexdigest()
        except urllib.error.HTTPError as error:
            if error.code not in {408, 500, 502, 503, 504} or attempt == 2:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
            cause = getattr(error, "reason", error)
            if not isinstance(cause, (TimeoutError, ConnectionError)) or attempt == 2:
                raise
        time.sleep(2 ** attempt)


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
        self.scratch_env = {}
        self.semgrep_env = {}

    def version(self, name, cmd, cwd=None):
        flag = {"gitleaks": "version", "syft": "version", "grype": "version"}.get(name, "--version")
        if name == "java":
            flag = "-version"
            java = Path(shutil.which(str(cmd[0])) or cmd[0]).resolve()
            if self.system == "macos" and java == Path("/usr/bin/java"):
                java_home = Path(run(["/usr/libexec/java_home"], capture=True, timeout=30).strip())
                java = java_home / "bin/java"
                cmd[0] = str(java)
            javac = java.with_name("javac.exe" if os.name == "nt" else "javac")
            if not javac.exists():
                raise RuntimeError("A JDK with javac is required")
            run([javac, "-version"], capture=True, timeout=30)
        if self.log is not None:
            print(f"\n--- {name} version check ---", file=self.log, flush=True)
        tool_env = self.semgrep_env if name == "semgrep" else self.scratch_env
        env = {**os.environ, **tool_env} if tool_env else None
        output = run([*cmd, flag], cwd=cwd, capture=True, log=self.log, timeout=180, env=env)
        pattern = (r"(?mi)^Version:\s*(\d+\.\d+(?:\.\d+)?)"
                   if name in {"syft", "grype"} and "Version:" in output
                   else r"\b(\d+\.\d+(?:\.\d+)?)\b")
        match = re.search(pattern, output)
        if not match or tuple(map(int, match[1].split("."))) < MINIMUM[name]:
            raise RuntimeError("Version is missing or below the supported minimum")
        if name == "java":
            java_home = java.parent.parent
            os.environ["JAVA_HOME"] = str(java_home)
            os.environ["PATH"] = f"{java.parent}{os.pathsep}{os.environ['PATH']}"
        return match[1]

    def ensure(self, name, wrapper=None, cwd=None):
        import time
        from datetime import datetime, timezone
        ensure_started = time.perf_counter()
        ensure_started_at = datetime.now(timezone.utc).isoformat()
        status = "unavailable"
        probe_error = None
        try:
            existing = shutil.which(name)
            java_home = os.environ.get("JAVA_HOME") if name == "java" else None
            java = Path(java_home) / ("bin/java.exe" if os.name == "nt" else "bin/java") if java_home else None
            candidates = [wrapper, [java] if java and java.is_file() else None,
                          [existing] if existing else None, self.managed(name)]
            if name == "semgrep" and self.system == "windows":
                candidates = [candidate for cmd in filter(None, candidates)
                              for candidate in (cmd, [*cmd, "--legacy"])]
            if name == "checkov" and self.system == "windows":
                if existing:
                    scripts = Path(existing).parent
                    for python in (scripts / "python.exe", scripts.parent / "python.exe"):
                        if python.is_file():
                            candidates.append([python, "-I", "-m", "checkov.main"])
                candidates.append([sys.executable, "-I", "-m", "checkov.main"])
            for cmd in filter(None, candidates):
                try:
                    version = self.version(name, cmd, cwd)
                except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                    probe_error = error
                    if self.log is not None:
                        print(f"{name} version check failed: {error}", file=self.log, flush=True)
                    continue
                self.records[name] = {"status": "reused", "version": version}
                return cmd
            if not self.allow:
                detail = f" Last version check: {probe_error}" if probe_error else ""
                raise RuntimeError(f"Missing or incompatible; installation disabled.{detail}")
            if name == "semgrep" and (self.system, self.arch) in {
                ("macos", "amd64"), ("windows", "arm64"),
            }:
                raise RuntimeError(f"Semgrep {PYPI[name]} publishes no native wheel for "
                                   f"{self.system}/{self.arch}; use an approved compatible installation")
            status = "installation_failed"
            cmd = self.install(name)
            try:
                version = self.version(name, cmd, cwd)
            except RuntimeError:
                if name != "semgrep" or self.system != "windows":
                    raise
                cmd = [*cmd, "--legacy"]
                version = self.version(name, cmd, cwd)
            self.records[name] = {"status": "installed", "version": version}
            return cmd
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            self.records[name] = {"status": status, "reason": str(error)}
            return None
        finally:
            if name in self.records:
                self.records[name]["startedAt"] = ensure_started_at
                self.records[name]["completedAt"] = datetime.now(timezone.utc).isoformat()
                self.records[name]["durationSeconds"] = round(time.perf_counter() - ensure_started, 2)

    def managed(self, name):
        suffix = ".exe" if self.system == "windows" else ""
        if name in PYPI:
            base = self.cache / f"{name}-{PYPI[name]}-{sys.version_info.major}.{sys.version_info.minor}"
            path = base / ("Scripts" if suffix else "bin") / (name + suffix)
            if name == "checkov" and not suffix:
                interpreter = base / "bin/python"
                if interpreter.is_file() and path.is_file():
                    return [str(interpreter), "-I", str(path)]
        elif name == "java" and self.system == "linux":
            base = self.cache / f"{name}-{LINUX_JDK}-{self.system}-{self.arch}"
            if not (base / ".complete").is_file():
                return None
            path = next(base.glob("*/bin/java"), base / "missing")
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
        elif name in RELEASES or name in {"mvn", "gradle"} or (name == "java" and self.system == "linux"):
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
        base = self.cache / f"{name}-{PYPI[name]}-{sys.version_info.major}.{sys.version_info.minor}"
        python = base / ("Scripts/python.exe" if self.system == "windows" else "bin/python")
        try:
            pip = run([python, "-m", "pip", "--version"], capture=True, timeout=60)
        except (OSError, RuntimeError):
            try:
                run([sys.executable, "-m", "venv", base], log=self.log)
            except RuntimeError:
                if self.system != "linux":
                    raise
                if linux_family() == "debian":
                    # Debian can ship the system interpreter without ensurepip.
                    run([sys.executable, "-m", "venv", "--without-pip", base], log=self.log)
                    self.bootstrap_pip(python)
                else:
                    run(package_command(self.system, "pip"), log=self.log)
                    run([sys.executable, "-m", "venv", base], log=self.log)
            pip = run([python, "-m", "pip", "--version"], capture=True, log=self.log, timeout=60)
            status = "installed"
        else:
            status = "reused"
        self.records[f"pip:{name}"] = {"status": status, "version": pip.split()[1]}
        try:
            run([python, "-m", "pip", "--disable-pip-version-check", "install", "--only-binary=:all:",
                 "--retries", "2", f"{name}=={PYPI[name]}"], log=self.log)
        except RuntimeError as error:
            raise RuntimeError(f"Could not install {name} {PYPI[name]} wheels for {self.system}/{self.arch} "
                               f"with Python {sys.version_info.major}.{sys.version_info.minor}. "
                               "Check wheel availability and the approved package index in run.log.") from error

    def bootstrap_pip(self, python):
        filename = f"pip-{BOOTSTRAP_PIP}-py3-none-any.whl"
        release = json.loads(fetch(f"https://pypi.org/pypi/pip/{BOOTSTRAP_PIP}/json"))
        wheel = next((item for item in release.get("urls", []) if item["filename"] == filename), None)
        if not wheel or not wheel["url"].startswith("https://files.pythonhosted.org/"):
            raise RuntimeError(f"PyPI did not publish the expected pip wheel ({filename})")
        with tempfile.TemporaryDirectory(dir=self.cache) as temporary:
            archive = Path(temporary) / filename
            if fetch(wheel["url"], archive) != wheel["digests"]["sha256"]:
                raise RuntimeError("Download checksum mismatch for pip")
            launch = "import runpy, sys; sys.path.insert(0, sys.argv.pop(1)); runpy.run_module('pip', run_name='__main__')"
            run([python, "-I", "-c", launch, archive, "--disable-pip-version-check", "install",
                 "--no-index", "--no-deps", archive], log=self.log, timeout=120)

    def install_archive(self, name):
        version = LINUX_JDK if name == "java" else self.release_version(name)
        if name == "java":
            arch = {"amd64": "x64", "arm64": "aarch64"}[self.arch]
            asset = f"OpenJDK21U-jdk_{arch}_linux_hotspot_{version.replace('+', '_')}.tar.gz"
            url = f"https://github.com/adoptium/temurin21-binaries/releases/download/jdk-{version.replace('+', '%2B')}/{asset}"
            algorithm = "sha256"
            checksum = fetch(url + ".sha256.txt").decode("ascii").split()
            if not checksum or not re.fullmatch(r"[0-9a-fA-F]{64}", checksum[0]):
                raise RuntimeError("Invalid JDK checksum")
            expected = checksum[0]
        elif name in RELEASES:
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
            try:
                extracted.rename(destination)
            except OSError:
                if not (destination / ".complete").exists():
                    raise
