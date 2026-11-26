#!/usr/bin/env bash
set -euo pipefail
umask 077
case "$(uname -s)" in
  MINGW*|MSYS*) system=windows ;;
  Darwin) system=macos ;;
  Linux) system=linux ;;
  *) printf 'Unsupported operating system: %s\n' "$(uname -s)" >&2; exit 2 ;;
esac
launcher_source=${BASH_SOURCE[0]}
if [[ $system == windows ]]; then launcher_source="$(cygpath -u -- "$launcher_source")"; fi
kit_dir="$(cd -- "$(dirname -- "$launcher_source")" && pwd -P)"
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
  local candidate suffix=bin/python3.12
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
  if [[ -n $managed_python_root ]]; then
    if [[ $system == windows ]]; then suffix=python.exe; fi
    for candidate in "$managed_python_root"/cpython-3.12.*/"$suffix"; do
      if [[ -x $candidate ]] && usable_python "$candidate"; then
        python_cmd=("$candidate")
        return
      fi
    done
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
      --details) details=true ;;
      --verbose) verbose=true ;;
      --project-path|--report-dir|--image|--scanner|--config)
        if [[ $# -lt 2 || $2 == -* && $2 != - && ! $2 =~ ^-([0-9]+|[0-9]*\.[0-9]+)$ ]]; then
          usage_error "$option requires a value. Use $option=VALUE for a value beginning with '-'."
        fi
        value=$2
        shift ;;
      --project-path=*|--report-dir=*|--image=*|--scanner=*|--config=*)
        value=${option#*=}
        option=${option%%=*} ;;
      *) usage_error "Unknown argument: $option" ;;
    esac
    case "$option" in
      --project-path|--report-dir|--image|--scanner|--config)
        [[ $value =~ [^[:space:]] ]] || usage_error "$option requires a non-empty value."
        [[ ! $value =~ [[:cntrl:]] ]] || usage_error "$option contains a control character."
        case "$option" in
          --project-path) project=$value ;;
          --report-dir) report=$value ;;
          --image) image=$value ;;
          --config) config=$value ;;
          --scanner) scanner=$value ;;
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

# Properties are data. Resolve their relative paths from the configuration directory.
property_path() {
  local path=$1 base=$2
  case "$path" in
    /*) printf '%s\n' "$path" ;;
    *)
      if [[ $system == windows && ( $path == [a-zA-Z]:* || $path == \\* ) ]]; then
        printf '%s\n' "$path"
      else
        printf '%s/%s\n' "$base" "$path"
      fi ;;
  esac
}

load_scan_properties() {
  local file=$1 line key value base seen=,
  [[ -f $file && -r $file ]] || usage_error "Cannot read configuration file: $file"
  base="$(cd -- "$(dirname -- "$file")" && pwd -P)"
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    [[ $line == *=* ]] || usage_error "Expected KEY=VALUE in the properties file."
    key=${line%%=*}
    value=${line#*=}
    [[ $seen != *",$key,"* ]] || usage_error "Duplicate property: $key"
    seen="$seen$key,"
    if [[ -n $value && ( ! $value =~ [^[:space:]] || $value =~ [[:cntrl:]] ) ]]; then
      usage_error "Invalid value for $key."
    fi
    case "$key" in
      PROJECT_ROOT) prop_project=$value; if [[ -n $value ]]; then prop_project="$(property_path "$value" "$base")"; fi ;;
      OUTPUT_DIR) prop_report=$value; if [[ -n $value ]]; then prop_report="$(property_path "$value" "$base")"; fi ;;
      SCANNERS) prop_scanner=$value ;;
      DOCKER_IMAGE) prop_image=$value ;;
      BUILD_IMAGE)
        case "$value" in
          true|false) prop_build=$value ;;
          '') prop_build=false ;;
          *) usage_error "BUILD_IMAGE must be true or false." ;;
        esac ;;
      *) usage_error "Unknown property. Use only PROJECT_ROOT, OUTPUT_DIR, SCANNERS, DOCKER_IMAGE and BUILD_IMAGE." ;;
    esac
  done < "$file"
}

valid_scanners() {
  [[ $1 == all || $1 =~ ^(gitleaks|semgrep|dependency-check|syft|grype|checkov)(,(gitleaks|semgrep|dependency-check|syft|grype|checkov))*$ ]]
}

valid_image() {
  [[ -z $1 || $1 =~ ^[a-zA-Z0-9][a-zA-Z0-9._:/@-]*$ ]]
}

help=false dry=false setup=false install=true build_image=false details=false verbose=false
project= report= scanner= image= config=
cli_args=("$@")
parse_args "$@"

if $help; then
  [[ -z ${ACCIDION_REQUIRED_SCANNERS:-} ]] || usage_error "Configured policy requires a full scan execution."
  printf '%s\n' 'Usage: security-scan.sh [--project-path PATH] [--dry-run | --setup-only]' \
    '       [--config PATH] [--no-install] [--report-dir PATH] [--image IMAGE | --build-image] [--scanner NAME[,NAME...]] [--details] [--verbose]' \
    '  --scanner NAMES     Select all or comma-separated scanner names.' \
    '                      gitleaks, semgrep, dependency-check, syft, grype, checkov.' \
    '  --config PATH        Read the specified properties file.' \
    '  --project-path PATH  Application directory (default: current directory).' \
    '  --report-dir PATH    Private report parent outside the application.' \
    '                      Full scans also refresh JSON in the application reports/ folder.' \
    '  --dry-run            Preview the scan without installing tools or writing reports.' \
    '  --setup-only         Verify or install tools without running scans.' \
    '  --no-install         Use existing tools. Can be combined with either mode.' \
    '  --details            Show all findings and per-scanner evidence.' \
    '  --verbose            Show scanner and dependency-resolution diagnostics.' \
    '  --image IMAGE        Scan an existing local Docker image.' \
    '  --build-image        Build and scan the selected application Dockerfile.'
  exit 0
fi

prop_project= prop_report= prop_scanner= prop_image= prop_build=false
default_config=
if [[ -n $config ]]; then
  if [[ $system == windows ]]; then
    config="$(cygpath -au -- "$config")" || usage_error "Invalid configuration path."
  fi
  load_scan_properties "$config"
else
  initial_project=${project:-.}
  if [[ $system == windows ]]; then
    initial_project="$(cygpath -au -- "$initial_project")"
  elif [[ $initial_project != /* ]]; then
    initial_project="$PWD/$initial_project"
  fi
  initial_project="$(resolve_directory "${initial_project}")" || usage_error "Application path must be an accessible directory."
  default_config="$initial_project/security-scan.properties"
  if [[ -e $default_config || -L $default_config ]]; then
    load_scan_properties "$default_config"
  elif [[ -z $project ]] && ! declare -F extract_payload >/dev/null &&
       [[ -f $kit_dir/security-scan.properties ]]; then
    load_scan_properties "$kit_dir/security-scan.properties"
  fi
fi

valid_scanners "${prop_scanner:-all}" || usage_error "Invalid SCANNERS property."
valid_image "$prop_image" || usage_error "Invalid DOCKER_IMAGE property. Use a local image reference without credentials."
project=${project:-${prop_project:-.}}
report=${report:-$prop_report}
scanner=${scanner:-${prop_scanner:-all}}
if [[ -z $image ]] && ! $build_image; then
  image=$prop_image
  build_image=$prop_build
fi

valid_scanners "$scanner" || usage_error "Invalid scanner selection."
valid_image "$image" || usage_error "Invalid Docker image reference."
if $dry && $setup; then usage_error "--dry-run and --setup-only cannot be combined."; fi
if [[ -n $image ]] && $build_image; then usage_error "--image and --build-image cannot be combined."; fi
if [[ -n $image ]] || $build_image; then
  if [[ $scanner != all && ",$scanner," != *,grype,* ]]; then
    usage_error "Docker image scanning requires Grype."
  fi
fi

# A managed caller can require coverage independent of the application configuration.
if [[ -n ${ACCIDION_REQUIRED_SCANNERS:-} ]]; then
  valid_scanners "$ACCIDION_REQUIRED_SCANNERS" || usage_error "Invalid ACCIDION_REQUIRED_SCANNERS."
  if $dry || $setup; then usage_error "Configured policy requires a full scan execution."; fi
  if [[ $scanner != all ]]; then
    IFS=, read -r -a required_scanners <<< "$ACCIDION_REQUIRED_SCANNERS"
    for required in "${required_scanners[@]}"; do
      [[ ",$scanner," == *",$required,"* ]] ||
        usage_error "Scanner selection omits scanners required by ACCIDION_REQUIRED_SCANNERS."
    done
  fi
fi
if [[ ${ACCIDION_SCAN_TIMEOUT+x} && ! ${ACCIDION_SCAN_TIMEOUT:-} =~ ^0*[1-9][0-9]*$ ]]; then
  usage_error "ACCIDION_SCAN_TIMEOUT must be a positive number of seconds."
fi

if [[ $system == windows ]]; then
  project="$(cygpath -au -- "$project")" || usage_error "Invalid application path."
elif [[ $project != /* ]]; then
  project="$PWD/$project"
fi
[[ -d $project && -r $project && -x $project ]] &&
  project="$(cd -P -- "$project" && pwd -P)" ||
  usage_error "Application path must be an accessible directory: $project"
default_home=${HOME:-}
if [[ $system == windows && -n ${USERPROFILE:-} ]]; then
  default_home="$(cygpath -au -- "$USERPROFILE")"
fi
if [[ -n $report ]]; then
  validate_output_path 'Private report directory' "$report"
elif [[ ${ACCIDION_HOME+x} ]]; then
  validate_output_path 'Private report directory' "${ACCIDION_HOME:-.}/reports"
elif [[ -n $default_home ]]; then
  validate_output_path 'Private report directory' "$default_home/.accidion/reports"
fi

embedded=false
source_dir="$kit_dir"
if declare -F extract_payload >/dev/null; then embedded=true; fi

# Normalize the effective arguments once. The Python runner receives no unparsed configuration.
runner_project=$project
runner_report=$report
if [[ $system == windows ]]; then
  runner_project="$(cygpath -am -- "$project")"
  if [[ -n $report ]]; then runner_report="$(cygpath -am -- "$report")"; fi
fi
set -- "--project-path=$runner_project" "--scanner=$scanner"
if [[ -n $runner_report ]]; then set -- "$@" "--report-dir=$runner_report"; fi
if [[ -n $image ]]; then set -- "$@" "--image=$image"; fi
if $build_image; then set -- "$@" --build-image; fi
if $dry; then set -- "$@" --dry-run; fi
if $setup; then set -- "$@" --setup-only; fi
if ! $install; then set -- "$@" --no-install; fi
if $details; then set -- "$@" --details; fi
if $verbose; then set -- "$@" --verbose; fi

managed_python_root=${UV_PYTHON_INSTALL_DIR:-}
if [[ -z $managed_python_root ]]; then
  if [[ $system == windows && -n ${APPDATA:-} ]]; then
    managed_python_root="$(cygpath -au -- "$APPDATA")/uv/data/python"
  elif [[ $system != windows && -n ${XDG_DATA_HOME:-${HOME:-}} ]]; then
    managed_python_root="${XDG_DATA_HOME:-$HOME/.local/share}/uv/python"
  fi
fi
if [[ -n $managed_python_root ]]; then
  if [[ $system == windows ]]; then
    managed_python_root="$(cygpath -au -- "$managed_python_root")"
  elif [[ $managed_python_root != /* ]]; then
    managed_python_root="$PWD/$managed_python_root"
  fi
  # Only reuse managed runtimes outside the project.
  if ! validate_output_path 'Managed Python directory' "$managed_python_root" 2>/dev/null; then
    managed_python_root=
  fi
fi

launcher="$source_dir/${launcher_source##*/}"
if [[ $system == windows ]]; then launcher="$(cygpath -am -- "$launcher")"; fi

if $dry && $embedded; then
  if ! find_python; then
    printf 'Dry run (%s/%s): Python 3.10+ is missing. Project discovery needs Python.\n' "$system" "$arch"
    exit 0
  fi
  preview_payload "$@"
  exit
fi

if ! $dry && ! $setup && [[ -z $config ]]; then
  default_config="$project/security-scan.properties"
  if [[ ! -e $default_config && ! -L $default_config ]]; then
    if ! (set -o noclobber; printf '%s\n' '# Security scan configuration' 'PROJECT_ROOT=.' \
        'OUTPUT_DIR=' 'SCANNERS=all' 'DOCKER_IMAGE=' 'BUILD_IMAGE=false' > "$default_config"); then
      [[ -f $default_config && -r $default_config ]] ||
        usage_error "Cannot create application properties file: $default_config"
    fi
    if [[ $project == "$initial_project" && ${BASH_SOURCE[0]} == "$0" ]]; then
      # Apply the same validation and precedence as a subsequent invocation.
      exec "$BASH" "$launcher" ${cli_args[@]+"${cli_args[@]}"}
    fi
    load_scan_properties "$default_config"
  fi
fi

# Only the generated distribution defines the fixed-file payload.
if $embedded; then
  temp_parent="${TMPDIR:-/tmp}"
  if [[ $system == windows ]]; then
    temp_parent="$(cygpath -au -- "$temp_parent")"
  elif [[ $temp_parent != /* ]]; then
    temp_parent="$PWD/$temp_parent"
  fi
  validate_output_path 'Toolkit temporary directory' "$temp_parent"
  kit_dir="$(mktemp -d "${temp_parent%/}/accidion-kit.XXXXXXXX")"
  trap 'rm -rf -- "$kit_dir"' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  extract_payload "$kit_dir"
fi

for file in starter_kit.py starter_install.py starter_findings.py .gitleaks.toml semgrep.yml \
  .checkov.yml accidion-dependencies.gradle; do
  if [[ ! -f $kit_dir/$file || ! -r $kit_dir/$file ]]; then
    usage_error "Required toolkit file is missing or unreadable: $kit_dir/$file. Restore the complete kit and retry."
  fi
done

if ! find_python; then
  if $dry; then
    printf 'Dry run (%s/%s): Python 3.10+ is missing. Project discovery needs Python.\n' "$system" "$arch"
    exit 0
  fi
  if ! $install; then printf 'Python 3.10+ is required; installation disabled.\n' >&2; exit 2; fi
  installer=()

  case "$system" in
    windows)
      installer=(winget install --exact --id Python.Python.3.12 --source winget --scope user --disable-interactivity)
      ;;
    macos)
      installer=(brew install python@3.12)
      ;;
    linux)
      if [[ $EUID == 0 ]]; then
        if command -v apt-get >/dev/null; then
          installer=(apt-get install -y python3 python3-venv)
        elif command -v dnf >/dev/null; then
          installer=(dnf install -y python3.12 python3.12-pip)
        elif command -v yum >/dev/null; then
          installer=(yum install -y python3.12 python3.12-pip)
        fi
      fi
      ;;
  esac

  if [[ ${installer[0]+set} ]] &&
     command -v "${installer[0]}" >/dev/null 2>&1; then
    if "${installer[@]}"; then
      hash -r
    fi
  fi

  if ! find_python; then
    printf 'Trying user-level Python installation...\n' >&2

    [[ -r "$kit_dir/python-bootstrap.sh" ]] ||
      usage_error "Python bootstrap script is missing."

    source "$kit_dir/python-bootstrap.sh"

    if [[ -z $managed_python_root ]]; then
      usage_error "Automatic Python installation needs a writable UV_PYTHON_INSTALL_DIR outside the application."
    fi
    UV_PYTHON_INSTALL_DIR="$managed_python_root"
    if [[ $system == windows ]]; then
      UV_PYTHON_INSTALL_DIR="$(cygpath -am -- "$managed_python_root")"
    fi
    export UV_PYTHON_INSTALL_DIR
    if managed_python="$(cd -- "$kit_dir" && bootstrap_managed_python)"; then
      managed_python="${managed_python%$'\r'}"

      if [[ $system == windows ]]; then
        managed_python="$(cygpath -u "$managed_python")"
      fi

      if usable_python "$managed_python"; then
        python_cmd=("$managed_python")
      else
        usage_error "Managed Python validation failed."
      fi
    else
      usage_error "Automatic Python installation failed. Check network access and installation permissions."
    fi
  fi

  export ACCIDION_PYTHON_BOOTSTRAPPED=1
fi

runner="$kit_dir/starter_kit.py"
if [[ $system == windows ]]; then runner="$(cygpath -am "$runner")"; fi
if $embedded; then
  ACCIDION_STANDALONE_LAUNCHER="$launcher" "${python_cmd[@]}" -E -s -B "$runner" "$@"
else
  exec "${python_cmd[@]}" -B "$runner" "$@"
fi
