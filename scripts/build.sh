#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/build/dependencies.env"
component="all"
configuration="Release"
while [[ $# -gt 0 ]]; do
  case "$1" in
    native|godot|all) component="$1"; shift ;;
    --configuration) [[ $# -ge 2 ]] || { echo "--configuration needs a value" >&2; exit 2; }; configuration="$2"; shift 2 ;;
    --configuration=*) configuration="${1#*=}"; shift ;;
    *) echo "usage: ./scripts/build.sh [native|godot|all] [--configuration Release]" >&2; exit 2 ;;
  esac
done
case "$configuration" in
  Release|release) ;;
  *) echo "Only Release source builds are supported for Certael 1.0." >&2; exit 2 ;;
esac
target=""
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) target="aarch64-apple-darwin" ;;
  Darwin-x86_64) target="x86_64-apple-darwin" ;;
  Linux-x86_64) target="x86_64-unknown-linux-gnu" ;;
  *) echo "Unsupported source-build host. Use a prebuilt Certael package." >&2; exit 2 ;;
esac

require() { command -v "$1" >/dev/null || { echo "Missing required tool: $1" >&2; exit 2; }; }
require git; require rustup; require cargo
rustup toolchain install "$RUST_TOOLCHAIN" --profile minimal
rustup target add "$target" --toolchain "$RUST_TOOLCHAIN"

fetch_godot_cpp() {
  local path="$root/engines/godot/godot-cpp"
  if [[ ! -d "$path/.git" ]]; then
    git clone --filter=blob:none "$GODOT_CPP_REPOSITORY" "$path"
  fi
  git -C "$path" fetch --depth 1 origin "$GODOT_CPP_COMMIT"
  git -C "$path" checkout --detach "$GODOT_CPP_COMMIT"
  [[ "$(git -C "$path" rev-parse HEAD)" == "$GODOT_CPP_COMMIT" ]] || { echo "godot-cpp pin mismatch" >&2; exit 3; }
}

build_native() {
  cargo "+$RUST_TOOLCHAIN" build --locked --release -p certael-c-api \
    --target "$target" --target-dir "$root/target"
  local library="$root/target/$target/release/libcertael_c_api.a"
  [[ -f "$library" ]] || { echo "Real Certael native library was not produced: $library" >&2; exit 3; }
}

build_godot() {
  require scons; fetch_godot_cpp
  scons --version | grep -Fq "$SCONS_VERSION" || {
    echo "Certael requires SCons $SCONS_VERSION. Install it with: python3 -m pip install scons==$SCONS_VERSION" >&2
    exit 2
  }
  local platform
  case "$(uname -s)" in Darwin) platform=macos ;; Linux) platform=linux ;; esac
  local arch="$(uname -m)"
  [[ "$arch" == "aarch64" ]] && arch="arm64"
  (cd "$root/engines/godot" && CERTAEL_NATIVE_DIR="$root/target/$target/release" \
    scons platform="$platform" arch="$arch" target=template_release -j"${CERTAEL_JOBS:-4}")
}

case "$component" in
  native) build_native ;;
  godot) build_native; build_godot ;;
  all) build_native; build_godot ;;
  *) echo "usage: ./scripts/build.sh [native|godot|all]" >&2; exit 2 ;;
esac

echo "Certael $component build completed ($configuration, $target)."
