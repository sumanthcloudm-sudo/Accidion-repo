#!/usr/bin/env bash
set -euo pipefail
umask 077
kit_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
case "$(uname -s)" in
  MINGW*|MSYS*) system=windows ;;
  Darwin) system=macos ;;
  Linux) system=linux ;;
  *) printf 'Unsupported operating system: %s\n' "$(uname -s)" >&2; exit 2 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) printf 'Unsupported architecture: %s\n' "$(uname -m)" >&2; exit 2 ;;
esac

find_python() {
  local candidate
  for candidate in python3.12 python3.13 python3.11 python3 python; do
    if command -v "$candidate" >/dev/null &&
       "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
      python_cmd=("$candidate")
      return
    fi
  done
  if [[ $system == windows ]]; then
    if command -v py >/dev/null; then
      for candidate in -3.12 -3.13 -3; do
        if py "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
          python_cmd=(py "$candidate")
          return
        fi
      done
    fi
    if [[ -n ${LOCALAPPDATA:-} ]]; then
      candidate="$(cygpath -u "$LOCALAPPDATA")/Programs/Python/Python312/python.exe"
      if [[ -x $candidate ]]; then python_cmd=("$candidate"); return; fi
    fi
  fi
  return 1
}

dry=false
install=true
for arg in "$@"; do
  case "$arg" in
    --dry-run) dry=true ;;
    --no-install) install=false ;;
    -h|--help)
      printf '%s\n' 'Usage: security-scan.sh [--project-path PATH] [--dry-run | --setup-only]' \
        '       [--no-install] [--report-dir PATH] [--image IMAGE | --build-image]'
      exit 0 ;;
  esac
done
if ! find_python; then
  if $dry; then
    printf 'Dry run (%s/%s): Python 3.10+ is missing. Project discovery needs Python.\n' "$system" "$arch"
    exit 0
  fi
  if ! $install; then printf 'Python 3.10+ is required; installation disabled.\n' >&2; exit 2; fi
  case "$system" in
    windows) installer=(winget install --exact --id Python.Python.3.12 --source winget --scope user --disable-interactivity) ;;
    macos) installer=(brew install python@3.12) ;;
    linux)
      if [[ $EUID != 0 ]]; then
        printf 'Python 3.10+ requires an approved installation on Linux. This kit does not invoke sudo.\n' >&2
        exit 2
      fi
      if command -v apt-get >/dev/null; then installer=(apt-get install -y python3 python3-venv)
      elif command -v dnf >/dev/null; then installer=(dnf install -y python3 python3-pip)
      else printf 'Install Python 3.10+ through your approved package manager.\n' >&2; exit 2
      fi ;;
  esac
  if ! command -v "${installer[0]}" >/dev/null || ! "${installer[@]}" || ! find_python; then
    printf 'Python bootstrap failed. Check permissions, package sources, and PATH, then retry.\n' >&2
    exit 2
  fi
  export ACCIDION_PYTHON_BOOTSTRAPPED=1
fi

runner="$kit_dir/starter_kit.py"
if [[ $system == windows ]]; then runner="$(cygpath -am "$runner")"; fi
exec "${python_cmd[@]}" "$runner" "$@"
