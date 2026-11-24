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

usable_python() {
  "$@" -c 'import os, sys; sys.exit(sys.version_info < (3, 10) or (sys.argv[1] == "windows" and os.name != "nt"))' \
    "$system" >/dev/null 2>&1
}

find_python() {
  local candidate
  for candidate in python3.12 python3.13 python3.11 python3.10 python3.14 python3 python; do
    if command -v "$candidate" >/dev/null && usable_python "$candidate"; then
      python_cmd=("$candidate")
      return
    fi
  done
  if [[ $system == windows ]]; then
    if command -v py >/dev/null; then
      for candidate in -3.12 -3.13 -3; do
        if usable_python py "$candidate"; then
          python_cmd=(py "$candidate")
          return
        fi
      done
    fi
    if [[ -n ${LOCALAPPDATA:-} ]]; then
      candidate="$(cygpath -u "$LOCALAPPDATA")/Programs/Python/Python312/python.exe"
      if [[ -x $candidate ]] && usable_python "$candidate"; then python_cmd=("$candidate"); return; fi
    fi
  fi
  return 1
}

linux_identity() {
  local file line id= family=
  for file in /etc/os-release /usr/lib/os-release; do
    [[ -r $file ]] || continue
    while IFS= read -r line; do
      case "$line" in
        ID=*) id=${line#ID=} ;;
        ID_LIKE=*) family=${line#ID_LIKE=} ;;
      esac
    done < "$file"
    break
  done
  id=${id//\"/}
  family=${family//\"/}
  printf '%s\n' "$id $family"
}

usage_error() {
  printf 'security-scan.sh: %s\nSee --help for usage.\n' "$1" >&2
  exit 2
}

parse_args() {
  local option value
  while (( $# )); do
    option=$1
    case "$option" in
      -h|--help) help=true ;;
      --dry-run) dry=true ;;
      --setup-only) setup=true ;;
      --no-install) install=false ;;
      --build-image) build_image=true ;;
      --project-path|--report-dir|--image)
        if [[ $# -lt 2 || $2 == -* && $2 != - && ! $2 =~ ^-([0-9]+|[0-9]*\.[0-9]+)$ ]]; then
          usage_error "$option requires a value. Use $option=VALUE for a value beginning with '-'."
        fi
        value=$2
        shift ;;
      --project-path=*|--report-dir=*|--image=*)
        value=${option#*=}
        option=${option%%=*} ;;
      *) usage_error "Unknown argument: $option" ;;
    esac
    case "$option" in
      --project-path|--report-dir|--image)
        [[ $value =~ [^[:space:]] ]] || usage_error "$option requires a non-empty value."
        case "$option" in
          --project-path) project=$value ;;
          --report-dir) report=$value ;;
          --image) image=true ;;
        esac ;;
    esac
    shift
  done
}

# Resolve existing ancestors physically without creating the requested directory.
resolve_directory() {
  local path=$1 parent leaf
  if [[ -d $path ]]; then
    (cd -P -- "$path" 2>/dev/null && pwd -P)
  elif [[ -e $path || -L $path ]]; then
    return 1
  else
    leaf=${path##*/}
    parent=${path%/*}
    parent=$(resolve_directory "${parent:-/}") || return 1
    case "$leaf" in
      ''|.) printf '%s\n' "$parent" ;;
      ..) parent=${parent%/*}; printf '%s\n' "${parent:-/}" ;;
      *) printf '%s/%s\n' "${parent%/}" "$leaf" ;;
    esac
  fi
}

validate_output_path() (
  local label=$1 path=$2 ancestor
  if [[ $system == windows ]]; then
    path="$(cygpath -au -- "$path")" || usage_error "Invalid $label path: $2"
    shopt -s nocasematch
  elif [[ $path != /* ]]; then
    path="$PWD/$path"
  fi
  path=${path%/}
  path="$(resolve_directory "${path:-/}")" || usage_error "$label must use an accessible directory path: $2"
  if [[ $path == "$project" || $path == "${project%/}/"* ]]; then
    usage_error "$label must be outside the application: $path"
  fi
  ancestor=$path
  while [[ ! -d $ancestor ]]; do
    ancestor=${ancestor%/*}
    ancestor=${ancestor:-/}
  done
  [[ -w $ancestor && -x $ancestor ]] || usage_error "$label requires a writable directory: $ancestor"
)

help=false
dry=false
setup=false
install=true
build_image=false
image=false
project=.
report=
parse_args "$@"
if $dry && $setup; then usage_error "--dry-run and --setup-only cannot be combined."; fi
if $image && $build_image; then usage_error "--image and --build-image cannot be combined."; fi
if $help; then
  printf '%s\n' 'Usage: security-scan.sh [--project-path PATH] [--dry-run | --setup-only]' \
    '       [--no-install] [--report-dir PATH] [--image IMAGE | --build-image]' \
    '  --project-path PATH  Application directory (default: current directory).' \
    '  --report-dir PATH    Private report parent outside the application.' \
    '  --dry-run            Preview the scan without installing tools or writing reports.' \
    '  --setup-only         Verify or install tools without running scans.' \
    '  --no-install         Use existing tools. Can be combined with either mode.' \
    '  --image IMAGE        Scan an existing local Docker image.' \
    '  --build-image        Build and scan the selected application Dockerfile.'
  exit 0
fi

for file in starter_kit.py starter_install.py starter_findings.py .gitleaks.toml semgrep.yml \
  .checkov.yml accidion-dependencies.gradle; do
  if [[ ! -f $kit_dir/$file || ! -r $kit_dir/$file ]]; then
    usage_error "Required toolkit file is missing or unreadable: $kit_dir/$file. Restore the complete kit and retry."
  fi
done

if [[ $system == windows ]]; then
  project="$(cygpath -au -- "$project")" || usage_error "Invalid application path."
elif [[ $project != /* ]]; then
  project="$PWD/$project"
fi
[[ -d $project && -r $project && -x $project ]] &&
  project="$(cd -P -- "$project" && pwd -P)" ||
  usage_error "Application path must be an accessible directory: $project"
default_home=${HOME:-}
if [[ $system == windows ]]; then default_home=${USERPROFILE:-}; fi
if [[ -n $report ]]; then
  validate_output_path 'Private report directory' "$report"
elif [[ ${ACCIDION_HOME+x} ]]; then
  validate_output_path 'Private report directory' "${ACCIDION_HOME:-.}/reports"
elif [[ -n $default_home ]]; then
  validate_output_path 'Private report directory' "$default_home/.accidion/reports"
fi

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
      if command -v apt-get >/dev/null; then
        installer=(apt-get install -y python3 python3-venv)
      else
        manager=
        if command -v dnf >/dev/null; then manager=dnf
        elif command -v yum >/dev/null; then manager=yum; fi
        if [[ -z $manager ]]; then
          printf 'Install Python 3.10+ through your approved package manager.\n' >&2
          exit 2
        fi
        case " $(linux_identity) " in
          " fedora "*) installer=("$manager" install -y python3 python3-pip) ;;
          *" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*)
            installer=("$manager" install -y python3.12 python3.12-pip) ;;
          *) installer=("$manager" install -y python3 python3-pip) ;;
        esac
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
