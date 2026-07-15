#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/build-linux-collectors.sh [--output-dir DIR] [--python PYTHON] [--skip-runtime]

Build mini-peas and ai-peas as native, StaticX-wrapped Linux executables for
the current x86_64 or arm64 machine, then verify and checksum the artifacts.
EOF
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${repo_root}/dist"
python_bin="${PYTHON:-python3}"
skip_runtime=0

while (($#)); do
  case "$1" in
    --output-dir)
      [[ $# -ge 2 ]] || { echo "[!] --output-dir requires a value" >&2; exit 2; }
      output_dir="$2"
      shift 2
      ;;
    --python)
      [[ $# -ge 2 ]] || { echo "[!] --python requires a value" >&2; exit 2; }
      python_bin="$2"
      shift 2
      ;;
    --skip-runtime)
      skip_runtime=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[!] Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ "$(uname -s)" == "Linux" ]] || { echo "[!] Linux is required." >&2; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) artifact_arch="x86_64" ;;
  aarch64|arm64) artifact_arch="arm64" ;;
  *) echo "[!] Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

command -v "$python_bin" >/dev/null || { echo "[!] Python not found: $python_bin" >&2; exit 1; }
command -v staticx >/dev/null || { echo "[!] staticx is not installed." >&2; exit 1; }
"$python_bin" -m PyInstaller --version >/dev/null || {
  echo "[!] PyInstaller is not installed for $python_bin." >&2
  exit 1
}

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
build_root="$(mktemp -d "${TMPDIR:-/tmp}/pathfinder-collectors.XXXXXX")"
trap 'rm -rf "$build_root"' EXIT

export LC_ALL=C
export PYTHONHASHSEED=0
if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH="$(git -C "$repo_root" show -s --format=%ct HEAD 2>/dev/null || true)"
  export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-315532800}"
fi

for collector in mini-peas ai-peas; do
  echo "[*] Building ${collector} for linux-${artifact_arch}"
  collector_root="${build_root}/${collector}"
  mkdir -p "${collector_root}/dist" "${collector_root}/work" "${collector_root}/spec"
  "$python_bin" -m PyInstaller \
    --noconfirm \
    --clean \
    --onefile \
    --console \
    --noupx \
    --name "$collector" \
    --distpath "${collector_root}/dist" \
    --workpath "${collector_root}/work" \
    --specpath "${collector_root}/spec" \
    "${repo_root}/tools/${collector}.py"
  staticx --strip \
    "${collector_root}/dist/${collector}" \
    "${output_dir}/${collector}-linux-${artifact_arch}"
  chmod 0755 "${output_dir}/${collector}-linux-${artifact_arch}"
done

verify_args=(
  "${repo_root}/tools/verify_collector_artifacts.py"
  --arch "$artifact_arch"
  --artifact-dir "$output_dir"
)
if ((skip_runtime)); then
  verify_args+=(--skip-runtime)
fi
"$python_bin" "${verify_args[@]}"
