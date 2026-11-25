#!/usr/bin/env bash

bootstrap_managed_python() (
  set -euo pipefail
  umask 077

  version=0.13.10
  case "$arch" in
    amd64) cpu=x86_64 ;;
    arm64) cpu=aarch64 ;;
    *) exit 1 ;;
  esac

  case "$system" in
    windows) asset="uv-${cpu}-pc-windows-msvc.zip" ;;
    macos) asset="uv-${cpu}-apple-darwin.tar.gz" ;;
    linux) asset="uv-${cpu}-unknown-linux-gnu.tar.gz" ;;
    *) exit 1 ;;
  esac

  command -v curl >/dev/null || exit 1

  tmp="$(mktemp -d)"
  trap 'rm -rf -- "$tmp"' EXIT

  url="https://github.com/astral-sh/uv/releases/download/$version/$asset"

  curl --proto '=https' --tlsv1.2 -fsSL \
    --retry 3 "$url" -o "$tmp/$asset"

  curl --proto '=https' --tlsv1.2 -fsSL \
    --retry 3 "$url.sha256" -o "$tmp/checksum"

  expected="$(awk 'NR==1 {print $1}' "$tmp/checksum")"
  [[ $expected =~ ^[a-fA-F0-9]{64}$ ]] || exit 1

  if command -v sha256sum >/dev/null; then
    actual="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
  elif command -v shasum >/dev/null; then
    actual="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
  else
    echo "SHA-256 verification unavailable." >&2
    exit 1
  fi

  [[ $actual == "$expected" ]] || {
    echo "Python bootstrap checksum mismatch." >&2
    exit 1
  }

  mkdir -p "$tmp/extracted"

  case "$asset" in
    *.zip)
      unzip -q "$tmp/$asset" -d "$tmp/extracted"
      executable=uv.exe ;;
    *)
      tar -xzf "$tmp/$asset" -C "$tmp/extracted"
      executable=uv ;;
  esac

  uv_bin="$(find "$tmp/extracted" -type f \
    -name "$executable" -print -quit)"

  [[ -n $uv_bin ]] || exit 1
  chmod +x "$uv_bin"

  "$uv_bin" python install 3.12 --no-bin >&2
  "$uv_bin" python find --managed-python 3.12
)
