#!/bin/bash
# NetScan CLI 构建脚本(Unix: Linux/macOS/BSD)
# 用法: ./buildcli.sh
# 仅编译 CLI(纯 Go, 可交叉编译到所有主流平台), 不编译 GUI。
# 命名: x64 = 64位(amd64), x86 = 32位(386), arm64 = ARM 64位。

set -e
root="$(cd "$(dirname "$0")" && pwd)"
dist="$root/dist"
mkdir -p "$dist"

# 版本号: 从 git tag 自动注入, 无 tag 时用 commit hash
version="dev"
if v=$(git -C "$root" describe --tags --always --dirty 2>/dev/null); then
  [ -n "$v" ] && version="$v"
fi
echo "版本: $version"

archname() {
  case "$1" in
    amd64) echo x64 ;;
    386)   echo x86 ;;
    *)     echo "$1" ;;
  esac
}

targets="
windows/amd64 windows/386 windows/arm64
linux/amd64 linux/386 linux/arm64
darwin/amd64 darwin/arm64
freebsd/amd64 freebsd/386 freebsd/arm64
netbsd/amd64 netbsd/386 netbsd/arm64
openbsd/amd64 openbsd/386 openbsd/arm64
"

export CGO_ENABLED=0
for t in $targets; do
  os="${t%/*}"
  arch="${t#*/}"
  a="$(archname "$arch")"
  ext=""
  [ "$os" = "windows" ] && ext=".exe"
  out="$dist/netscan-$os-$a$ext"
  echo "编译 CLI: $os/$a -> $(basename "$out")"
  GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out" ./cmd/cli
done

echo ""
echo "CLI 构建完成, 产物目录: $dist"
