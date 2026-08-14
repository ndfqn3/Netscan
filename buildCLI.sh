#!/usr/bin/env bash
# NetScan CLI 构建脚本(Linux / macOS)
# 用法: chmod +x buildCLI.sh && ./buildCLI.sh
# 仅编译 CLI(纯 Go, 可交叉编译), 不编译 GUI。
# 命名: x64 = 64位(amd64), x86 = 32位(386), arm64 = ARM 64位。

set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
dist="$root/dist"
mkdir -p "$dist"

version="$(git -C "$root" describe --tags --always --dirty 2>/dev/null || echo dev)"
echo "版本: $version"

arch_name() {
  case "$1" in
    amd64) echo "x64" ;;
    386)   echo "x86" ;;
    arm64) echo "arm64" ;;
    *)     echo "$1" ;;
  esac
}

cli_targets=(
  "windows amd64"
  "windows 386"
  "windows arm64"
  "linux amd64"
  "linux 386"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
  "freebsd amd64"
  "freebsd 386"
  "freebsd arm64"
  "netbsd amd64"
  "netbsd 386"
  "netbsd arm64"
  "openbsd amd64"
  "openbsd 386"
  "openbsd arm64"
)

export CGO_ENABLED=0
for t in "${cli_targets[@]}"; do
  os="${t%% *}"
  arch="${t##* }"
  name="$(arch_name "$arch")"
  ext=""
  [ "$os" = "windows" ] && ext=".exe"
  out="$dist/netscan-$os-$name$ext"
  echo "编译 CLI: $os/$name -> $(basename "$out")"
  GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out" ./cmd/cli
done

echo ""
echo "CLI 构建完成, 产物目录: $dist"
ls -lh "$dist" | grep -v gui || true
