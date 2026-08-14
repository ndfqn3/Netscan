#!/usr/bin/env bash
# NetScan 构建脚本(Linux / macOS)
# 用法: chmod +x build.sh && ./build.sh
# CLI 为纯 Go 程序, 可交叉编译; GUI 依赖 CGO 与图形库, 在本机平台编译。
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

unset GOOS
unset GOARCH
export CGO_ENABLED=1
os="$(go env GOOS)"
arch="$(go env GOARCH)"
name="$(arch_name "$arch")"
ext=""
[ "$os" = "windows" ] && ext=".exe"
out="$dist/netscan-gui-$os-$name$ext"
echo "编译 GUI: $os/$name -> $(basename "$out")"
ldflags="-s -w"
[ "$os" = "windows" ] && ldflags="-s -w -H windowsgui"
go build -trimpath -ldflags "$ldflags" -o "$out" ./cmd/gui

echo ""
echo "构建完成, 产物目录: $dist"
ls -lh "$dist"
